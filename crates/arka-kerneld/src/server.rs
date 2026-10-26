//! ARKA Kernel IPC Unix Domain Socket Service Daemon.
//!
//! Enforces:
//! - ADR-007: Standalone OS daemon with strict process boundaries
//! - Barrier 1: Socket file DAC mode 0660
//! - Barrier 2: OS-level SO_PEERCRED verification
//! - Barrier 3: Cryptographic Ed25519 Token verification (KeyDomain::TokenSigning)
//! - Barrier 4: Strict JSON validation (<=64KB, depth <=8, no duplicate keys)
//! - Barrier 5: Canonical Normalization (ActionNormalizer)
//! - Barrier 6: Policy Authorization & Atomic SQLite commit
//! - Barrier 7: Encapsulated internal Execution Broker dispatch (DEC-10)

use crate::errors::KernelServiceError;
use crate::protocol::{
    KernelExecutionResult, KernelRequest, KernelResponse, DEFAULT_MAX_FRAME_SIZE,
};
use arka_core_types::clock::MockClock;
use arka_core_types::errors::ExternalSecurityError;
use arka_core_types::id::{AgentId, TokenId};
use arka_core_types::scope::ScopeDefinition;
use arka_core_types::subject::{AuthenticatedContext, Subject};
use arka_crypto::json_strict::StrictJsonParser;
use arka_crypto::token::SignedToken;
use arka_execution_broker::{BrokerConfig, ExecutionBroker, InMemoryBrokerStorage, NoOpWorker};
use arka_kernel::auth::AuthenticationService;
use arka_kernel::policy::{AuthorizationDecision, AuthorizationEngine};
use arka_kernel::ActionNormalizer;
use arka_storage_sqlite::SqliteStorage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct KernelServerConfig {
    pub socket_path: PathBuf,
    pub max_frame_size: usize,
    pub max_concurrency: usize,
    pub enforce_peer_auth: bool,
    pub allowed_uid: Option<u32>,
    pub enforce_token_auth: bool,
}

impl Default for KernelServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/arka/kernel.sock"),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_concurrency: 16,
            enforce_peer_auth: false, // Default false for unprivileged tests; true in production
            allowed_uid: None,
            enforce_token_auth: true,
        }
    }
}

pub struct KernelServer {
    config: KernelServerConfig,
    normalizer: Arc<ActionNormalizer>,
    auth_engine: Arc<AuthorizationEngine>,
    auth_service: Arc<AuthenticationService>,
    storage: Arc<SqliteStorage>,
    clock: Arc<MockClock>,
    broker: Arc<ExecutionBroker<SqliteStorage, InMemoryBrokerStorage, NoOpWorker, MockClock>>,
    scopes: Arc<RwLock<HashMap<String, ScopeDefinition>>>,
    concurrency_limiter: Arc<Semaphore>,
}

impl KernelServer {
    pub fn new(
        config: KernelServerConfig,
        normalizer: Arc<ActionNormalizer>,
        auth_engine: Arc<AuthorizationEngine>,
        auth_service: Arc<AuthenticationService>,
        storage: Arc<SqliteStorage>,
        clock: Arc<MockClock>,
    ) -> Self {
        let broker_storage = Arc::new(InMemoryBrokerStorage::new());
        let dispatcher = Arc::new(NoOpWorker::new());
        let broker_config = BrokerConfig {
            max_concurrent_executions: 16,
            default_timeout_seconds: 30,
        };
        let broker = Arc::new(ExecutionBroker::new(
            storage.clone(),
            broker_storage,
            dispatcher,
            clock.clone(),
            broker_config,
        ));

        let concurrency_limiter = Arc::new(Semaphore::new(config.max_concurrency));

        Self {
            config,
            normalizer,
            auth_engine,
            auth_service,
            storage,
            clock,
            broker,
            scopes: Arc::new(RwLock::new(HashMap::new())),
            concurrency_limiter,
        }
    }

    /// Register a scope definition in memory for mission policy checking.
    pub async fn register_scope(&self, scope_id: &str, scope: ScopeDefinition) {
        let mut map = self.scopes.write().await;
        map.insert(scope_id.to_string(), scope);
    }

    /// Access the underlying storage instance.
    pub fn storage(&self) -> Arc<SqliteStorage> {
        self.storage.clone()
    }

    /// Access the underlying clock instance.
    pub fn clock(&self) -> Arc<MockClock> {
        self.clock.clone()
    }

    /// Runs the kernel daemon listening on the configured Unix Domain Socket.
    pub async fn run(
        &self,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), KernelServiceError> {
        // Clean up stale socket file if it exists
        if self.config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }

        if let Some(parent) = self.config.socket_path.parent() {
            if !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let listener = UnixListener::bind(&self.config.socket_path).map_err(|e| {
            KernelServiceError::IoError(format!(
                "Failed to bind kernel Unix domain socket at {:?}: {}",
                self.config.socket_path, e
            ))
        })?;

        // Enforce mode 0660 on Unix socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&self.config.socket_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o660);
                let _ = std::fs::set_permissions(&self.config.socket_path, perms);
            }
        }

        info!(
            "arka-kerneld listening on {:?} (max_frame: {} bytes, max_concurrency: {})",
            self.config.socket_path, self.config.max_frame_size, self.config.max_concurrency
        );

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let permit = match self.concurrency_limiter.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("Kernel concurrency ceiling reached; rejecting connection");
                                    continue;
                                }
                            };

                            let normalizer = self.normalizer.clone();
                            let auth_engine = self.auth_engine.clone();
                            let auth_service = self.auth_service.clone();
                            let broker = self.broker.clone();
                            let scopes = self.scopes.clone();
                            let config = self.config.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    normalizer,
                                    auth_engine,
                                    auth_service,
                                    broker,
                                    scopes,
                                    &config,
                                ).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept failed on kernel socket: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received. Draining kernel connections...");
                    break;
                }
            }
        }

        // Clean up socket file
        if self.config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: UnixStream,
        normalizer: Arc<ActionNormalizer>,
        auth_engine: Arc<AuthorizationEngine>,
        auth_service: Arc<AuthenticationService>,
        broker: Arc<ExecutionBroker<SqliteStorage, InMemoryBrokerStorage, NoOpWorker, MockClock>>,
        scopes: Arc<RwLock<HashMap<String, ScopeDefinition>>>,
        config: &KernelServerConfig,
    ) -> Result<(), KernelServiceError> {
        // Barrier 2: OS-level SO_PEERCRED Verification
        if config.enforce_peer_auth {
            #[cfg(target_os = "linux")]
            {
                let peer_cred = stream.peer_cred().map_err(|e| {
                    KernelServiceError::PeerAuthFailed(format!("Cannot obtain SO_PEERCRED: {}", e))
                })?;

                match config.allowed_uid {
                    Some(expected_uid) => {
                        if peer_cred.uid() != expected_uid {
                            return Err(KernelServiceError::PeerAuthFailed(format!(
                                "Caller UID {} does not match expected UID {}",
                                peer_cred.uid(),
                                expected_uid
                            )));
                        }
                    }
                    None => {
                        return Err(KernelServiceError::PeerAuthFailed(
                            "Peer authentication is enabled but allowed_uid is not configured (fail-closed)"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Barrier 4: Length-Prefixed Frame Ingestion
        let mut len_header = [0u8; 4];
        if stream.read_exact(&mut len_header).await.is_err() {
            return Ok(()); // Connection closed cleanly by client
        }

        let payload_len = u32::from_be_bytes(len_header) as usize;
        if payload_len > config.max_frame_size {
            return Err(KernelServiceError::FrameTooLarge(
                payload_len,
                config.max_frame_size,
            ));
        }

        let mut payload_buf = vec![0u8; payload_len];
        stream
            .read_exact(&mut payload_buf)
            .await
            .map_err(|e| KernelServiceError::IoError(format!("Incomplete payload read: {}", e)))?;

        // Barrier 4: Strict JSON Parser
        let payload_str = std::str::from_utf8(&payload_buf).map_err(|e| {
            KernelServiceError::InvalidJson(format!("Payload is not valid UTF-8: {}", e))
        })?;

        let parsed_val = match StrictJsonParser::parse(payload_str) {
            Ok(v) => v,
            Err(e) => {
                let resp = KernelResponse::deny(
                    "unknown".to_string(),
                    "ERR_INVALID_PAYLOAD",
                    e.to_string(),
                    false,
                );
                Self::send_response(&mut stream, &resp).await?;
                return Ok(());
            }
        };

        let req: KernelRequest = match serde_json::from_value(parsed_val) {
            Ok(r) => r,
            Err(e) => {
                let resp = KernelResponse::deny(
                    "unknown".to_string(),
                    "ERR_INVALID_PAYLOAD",
                    format!("Strict schema validation failed: {}", e),
                    false,
                );
                Self::send_response(&mut stream, &resp).await?;
                return Ok(());
            }
        };

        // Process request through security kernel pipeline
        let resp = Self::process_request(
            req,
            normalizer,
            auth_engine,
            auth_service,
            broker,
            scopes,
            config,
        )
        .await;

        Self::send_response(&mut stream, &resp).await
    }

    async fn process_request(
        req: KernelRequest,
        normalizer: Arc<ActionNormalizer>,
        auth_engine: Arc<AuthorizationEngine>,
        auth_service: Arc<AuthenticationService>,
        broker: Arc<ExecutionBroker<SqliteStorage, InMemoryBrokerStorage, NoOpWorker, MockClock>>,
        scopes: Arc<RwLock<HashMap<String, ScopeDefinition>>>,
        config: &KernelServerConfig,
    ) -> KernelResponse {
        let request_id = req.request_id.clone();

        // Barrier 3: Cryptographic Token Verification
        let auth_context = if let Some(ref token_str) = req.auth_token {
            let signed_token: SignedToken = match serde_json::from_str(token_str) {
                Ok(t) => t,
                Err(e) => {
                    return KernelResponse::deny(
                        request_id,
                        "ERR_UNAUTHORIZED_TOKEN",
                        format!("Malformed signed token JSON: {}", e),
                        false,
                    );
                }
            };

            match auth_service.authenticate(&signed_token) {
                Ok(ctx) => ctx,
                Err(e) => {
                    let ext = ExternalSecurityError::from(e);
                    return KernelResponse::deny(request_id, ext.code, ext.message, false);
                }
            }
        } else if !config.enforce_token_auth {
            // Unauthenticated test fallback context (disabled in production)
            AuthenticatedContext {
                token_id: TokenId::new(format!("tok-{}", Uuid::new_v4().simple())).unwrap(),
                subject: Subject::Agent(AgentId::new("agent-unauthenticated").unwrap()),
                mission_id: req.proposal.mission_id.clone(),
                parent_task_id: req.proposal.parent_task_id.clone(),
                capabilities: vec![req.proposal.capability_id.clone()],
                scope_ref: "scope-default".to_string(),
                issued_at_unix: 0,
                expires_at_unix: u64::MAX,
                parent_token_id: None,
            }
        } else {
            return KernelResponse::deny(
                request_id,
                "ERR_UNAUTHORIZED_TOKEN",
                "Authentication token is required by security policy.",
                false,
            );
        };

        // Barrier 5: Action Normalization
        let canonical_action = match normalizer.normalize_proposal(req.proposal, &auth_context) {
            Ok(act) => act,
            Err(e) => {
                let ext = ExternalSecurityError::from(e);
                return KernelResponse::deny(request_id, ext.code, ext.message, false);
            }
        };

        // Resolve active Scope Definition (VULN-002: Fail-closed on missing scope)
        let scope = {
            let scopes_lock = scopes.read().await;
            match scopes_lock.get(&auth_context.scope_ref).cloned() {
                Some(s) => s,
                None => {
                    return KernelResponse::deny(
                        request_id,
                        "ERR_SCOPE_NOT_FOUND",
                        format!(
                            "Scope reference '{}' is not registered in the active security kernel (fail-closed)",
                            auth_context.scope_ref
                        ),
                        false,
                    );
                }
            }
        };

        // Barrier 6: Deterministic Policy Authorization & Atomic Commit
        let decision = match auth_engine
            .authorize(canonical_action.clone(), &scope, &auth_context, None)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                let ext = ExternalSecurityError::from(e);
                return KernelResponse::deny(request_id, ext.code, ext.message, false);
            }
        };

        match decision {
            AuthorizationDecision::Allow { action } => {
                let exec_result = if req.operation == "AUTHORIZE_AND_EXECUTE" {
                    // Barrier 7: Encapsulated Internal Broker Dispatch
                    match broker.execute_action(&action, None).await {
                        Ok(envelope) => Some(KernelExecutionResult {
                            state: format!("{:?}", envelope.state).to_uppercase(),
                            evidence_hashes: envelope.evidence_hashes,
                            execution_id: envelope.execution_id.to_string(),
                        }),
                        Err(e) => {
                            return KernelResponse::deny(
                                request_id,
                                "ERR_BROKER_EXECUTION",
                                e.to_string(),
                                false,
                            );
                        }
                    }
                } else {
                    None
                };

                KernelResponse::allow(
                    request_id,
                    action.action_id.to_string(),
                    action.action_hash,
                    exec_result,
                )
            }
            AuthorizationDecision::RequireApproval {
                action,
                action_hash,
                ..
            } => KernelResponse::require_approval(
                request_id,
                action.action_id.to_string(),
                action_hash,
            ),
            AuthorizationDecision::Deny { error } => {
                let ext = ExternalSecurityError::from(error);
                KernelResponse::deny(request_id, ext.code, ext.message, false)
            }
        }
    }

    async fn send_response(
        stream: &mut UnixStream,
        resp: &KernelResponse,
    ) -> Result<(), KernelServiceError> {
        let resp_bytes = serde_json::to_vec(resp).map_err(|e| {
            KernelServiceError::Internal(format!("Failed to serialize kernel response: {}", e))
        })?;

        let header = (resp_bytes.len() as u32).to_be_bytes();
        stream.write_all(&header).await.map_err(|e| {
            KernelServiceError::IoError(format!("Failed to write response header: {}", e))
        })?;
        stream.write_all(&resp_bytes).await.map_err(|e| {
            KernelServiceError::IoError(format!("Failed to write response payload: {}", e))
        })?;
        stream.flush().await.map_err(|e| {
            KernelServiceError::IoError(format!("Failed to flush response stream: {}", e))
        })?;

        Ok(())
    }
}
