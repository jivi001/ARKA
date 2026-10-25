//! Standalone LLM Gateway Unix Domain Socket Server.

use crate::credentials::CredentialStore;
use crate::dlp::DlpFilter;
use crate::errors::GatewayError;
use crate::protocol::{
    GatewayInferenceRequest, GatewayInferenceResponse, DEFAULT_MAX_FRAME_SIZE, DEFAULT_TIMEOUT_MS,
};
use crate::provider::LlmProvider;
use arka_crypto::json_strict::StrictJsonParser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Semaphore};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct GatewayServerConfig {
    pub socket_path: PathBuf,
    pub max_frame_size: usize,
    pub max_concurrency: usize,
    pub enforce_peer_auth: bool,
    pub allowed_uid: Option<u32>,
}

impl Default for GatewayServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/arka/gateway.sock"),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_concurrency: 16,
            enforce_peer_auth: false, // Default false for unprivileged tests; enabled in prod
            allowed_uid: None,
        }
    }
}

pub struct GatewayServer {
    config: GatewayServerConfig,
    provider: Arc<dyn LlmProvider>,
    dlp_filter: DlpFilter,
    credentials: Arc<CredentialStore>,
    concurrency_limiter: Arc<Semaphore>,
}

impl GatewayServer {
    pub fn new(config: GatewayServerConfig, provider: Arc<dyn LlmProvider>) -> Self {
        let concurrency_limiter = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            config,
            provider,
            dlp_filter: DlpFilter::new(),
            credentials: Arc::new(CredentialStore::new()),
            concurrency_limiter,
        }
    }

    pub fn with_dlp(mut self, dlp_filter: DlpFilter) -> Self {
        self.dlp_filter = dlp_filter;
        self
    }

    pub fn with_credentials(mut self, credentials: Arc<CredentialStore>) -> Self {
        self.credentials = credentials;
        self
    }

    pub fn credentials(&self) -> Arc<CredentialStore> {
        self.credentials.clone()
    }

    /// Runs the gateway server loop until a shutdown signal is received.
    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<(), GatewayError> {
        let path = &self.config.socket_path;
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let listener = UnixListener::bind(path).map_err(|e| {
            GatewayError::IoError(format!("Failed to bind UDS at {}: {}", path.display(), e))
        })?;

        info!("arka-gatewayd listening on {}", path.display());

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let permit = match self.concurrency_limiter.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("Gateway concurrency ceiling reached; rejecting incoming connection");
                                    continue;
                                }
                            };

                            let provider = self.provider.clone();
                            let dlp = self.dlp_filter.clone();
                            let credentials = self.credentials.clone();
                            let config = self.config.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(stream, provider, dlp, credentials, config).await {
                                    debug!("Connection finished with: {:?}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error on UDS: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("arka-gatewayd received shutdown signal, draining...");
                    break;
                }
            }
        }

        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: UnixStream,
        provider: Arc<dyn LlmProvider>,
        dlp: DlpFilter,
        credentials: Arc<CredentialStore>,
        config: GatewayServerConfig,
    ) -> Result<(), GatewayError> {
        // 1. Peer Credential Verification (SO_PEERCRED)
        #[cfg(target_os = "linux")]
        if config.enforce_peer_auth {
            if let Ok(ucred) = stream.peer_cred() {
                if let Some(expected_uid) = config.allowed_uid {
                    if ucred.uid() != expected_uid {
                        warn!(
                            "Peer UID mismatch: expected {}, got {}",
                            expected_uid,
                            ucred.uid()
                        );
                        return Err(GatewayError::PeerAuthFailed(format!(
                            "Peer UID {} not authorized",
                            ucred.uid()
                        )));
                    }
                }
            } else {
                return Err(GatewayError::PeerAuthFailed(
                    "Could not retrieve peer credentials via SO_PEERCRED".to_string(),
                ));
            }
        }

        // Loop to allow multiple requests on a persistent connection
        loop {
            // Read 4-byte length prefix
            let frame = match Self::read_frame(&mut stream, config.max_frame_size).await {
                Ok(f) => f,
                Err(GatewayError::IoError(ref e))
                    if e.contains("early eof") || e.contains("unexpected end") =>
                {
                    break; // Clean disconnect
                }
                Err(e) => return Err(e),
            };

            let response = Self::process_payload(&frame, &provider, &dlp, &credentials).await;
            let resp_bytes = serde_json::to_vec(&response).map_err(|e| {
                GatewayError::Internal(format!("Failed to serialize response: {}", e))
            })?;

            Self::write_frame(&mut stream, &resp_bytes).await?;
        }

        Ok(())
    }

    pub async fn process_payload(
        raw_bytes: &[u8],
        provider: &Arc<dyn LlmProvider>,
        dlp: &DlpFilter,
        credentials: &Arc<CredentialStore>,
    ) -> GatewayInferenceResponse {
        let raw_str = match std::str::from_utf8(raw_bytes) {
            Ok(s) => s,
            Err(_) => {
                return GatewayInferenceResponse::error(
                    "unknown".to_string(),
                    "ERR_INVALID_UTF8".to_string(),
                    "Payload bytes are not valid UTF-8.".to_string(),
                    false,
                );
            }
        };

        // 2. Strict JSON Pre-Parser (size, depth, duplicate keys)
        let val = match StrictJsonParser::parse(raw_str) {
            Ok(v) => v,
            Err(e) => {
                return GatewayInferenceResponse::error(
                    "unknown".to_string(),
                    "ERR_INVALID_JSON".to_string(),
                    e.to_string(),
                    false,
                );
            }
        };

        // 3. Deserialize GatewayInferenceRequest
        let mut req: GatewayInferenceRequest = match serde_json::from_value(val) {
            Ok(r) => r,
            Err(e) => {
                return GatewayInferenceResponse::error(
                    "unknown".to_string(),
                    "ERR_SCHEMA_VIOLATION".to_string(),
                    format!("Request schema violation: {}", e),
                    false,
                );
            }
        };

        let request_id = req.request_id.clone();

        // 4. Outbound DLP Inspection
        let outbound_sanitized =
            match dlp.inspect_outbound(&mut req.messages, req.sensitivity, &req.provider) {
                Ok(sanitized) => sanitized,
                Err(e) => {
                    return GatewayInferenceResponse::error(
                        request_id,
                        e.sanitized_code().to_string(),
                        e.sanitized_message(),
                        false,
                    );
                }
            };

        // 5. Credential Resolution & Provider Status Verification (Scenario 2 & 3)
        if req.provider != "mock" && req.provider != "local" {
            if credentials.is_disabled(&req.provider).await {
                return GatewayInferenceResponse::error(
                    request_id,
                    "ERR_PROVIDER_UNAVAILABLE".to_string(),
                    format!(
                        "LLM Provider '{}' has been disabled / revoked by operator policy.",
                        req.provider
                    ),
                    false,
                );
            }
            if let Err(e) = credentials.get_key(&req.provider).await {
                return GatewayInferenceResponse::error(
                    request_id,
                    e.sanitized_code().to_string(),
                    e.sanitized_message(),
                    false,
                );
            }
        }

        // 6. Bounded Inference Execution with Timeout
        let timeout_duration = Duration::from_millis(req.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        let completion_res = match timeout(timeout_duration, provider.complete(&req)).await {
            Ok(inner_res) => inner_res,
            Err(_) => Err(GatewayError::Timeout(timeout_duration.as_millis() as u64)),
        };

        match completion_res {
            Ok(mut output) => {
                // 6. Inbound Content Sanitization
                let (cleaned_content, inbound_sanitized) = dlp.inspect_inbound(&output.content);
                output.content = cleaned_content;
                let was_sanitized = outbound_sanitized || inbound_sanitized;

                GatewayInferenceResponse::success(request_id, output, was_sanitized)
            }
            Err(e) => {
                let (sanitized_msg, _) = dlp.inspect_inbound(&e.sanitized_message());
                GatewayInferenceResponse::error(
                    request_id,
                    e.sanitized_code().to_string(),
                    sanitized_msg,
                    e.is_retryable(),
                )
            }
        }
    }

    pub async fn read_frame<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        max_size: usize,
    ) -> Result<Vec<u8>, GatewayError> {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| GatewayError::IoError(e.to_string()))?;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > max_size {
            return Err(GatewayError::FrameTooLarge(len, max_size));
        }

        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| GatewayError::IoError(e.to_string()))?;

        Ok(buf)
    }

    pub async fn write_frame<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        data: &[u8],
    ) -> Result<(), GatewayError> {
        let len = data.len() as u32;
        writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        writer
            .write_all(data)
            .await
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        Ok(())
    }
}
