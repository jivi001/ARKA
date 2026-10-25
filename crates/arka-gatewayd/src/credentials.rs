//! LLM Provider Credential Isolation, Memory Zeroization, and Lifecycle Management.

use crate::errors::GatewayError;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSourceType {
    Environment,
    File,
    Keyring,
    Static,
}

/// Strongly typed container for raw provider credentials.
/// Implements automatic memory zeroization upon drop and redact-on-display.
#[derive(Clone)]
pub struct ProviderKey {
    pub provider: String,
    pub key_id: String,
    pub secret: Zeroizing<String>,
    pub source: CredentialSourceType,
    pub created_at_unix: u64,
}

impl ProviderKey {
    pub fn new(
        provider: impl Into<String>,
        key_id: impl Into<String>,
        secret: String,
        source: CredentialSourceType,
        created_at_unix: u64,
    ) -> Self {
        Self {
            provider: provider.into(),
            key_id: key_id.into(),
            secret: Zeroizing::new(secret),
            source,
            created_at_unix,
        }
    }

    pub fn raw_secret(&self) -> &str {
        &self.secret
    }
}

// Invariant INV-011 & Scenario 1: Never print raw secrets in debug, logs, or error formatting
impl fmt::Debug for ProviderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderKey")
            .field("provider", &self.provider)
            .field("key_id", &self.key_id)
            .field("secret", &"[REDACTED:KEY_MATERIAL]")
            .field("source", &self.source)
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

impl fmt::Display for ProviderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProviderKey(provider={}, key_id={}, secret=[REDACTED])",
            self.provider, self.key_id
        )
    }
}

/// Authoritative in-memory credential vault for arka-gatewayd.
/// Holds zeroizing provider secrets, enforces endpoint allowlists, and manages rotation.
pub struct CredentialStore {
    keys: Arc<RwLock<HashMap<String, ProviderKey>>>,
    disabled_providers: Arc<RwLock<HashSet<String>>>,
    allowed_endpoints: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    pub fn new() -> Self {
        let mut default_endpoints = HashMap::new();
        default_endpoints.insert("openai".to_string(), vec!["api.openai.com:443".to_string()]);
        default_endpoints.insert(
            "anthropic".to_string(),
            vec!["api.anthropic.com:443".to_string()],
        );

        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            disabled_providers: Arc::new(RwLock::new(HashSet::new())),
            allowed_endpoints: Arc::new(RwLock::new(default_endpoints)),
        }
    }

    /// Configures allowed outbound host:port destinations for a provider.
    pub async fn set_allowed_endpoints(&self, provider: &str, endpoints: Vec<String>) {
        let mut map = self.allowed_endpoints.write().await;
        map.insert(provider.to_string(), endpoints);
    }

    /// Validates that an outbound destination matches the registered endpoint allowlist (Scenario 4).
    pub async fn validate_endpoint(
        &self,
        provider: &str,
        target: &str,
    ) -> Result<(), GatewayError> {
        let map = self.allowed_endpoints.read().await;
        if let Some(allowed) = map.get(provider) {
            if allowed.iter().any(|e| e == target) {
                return Ok(());
            }
        }

        Err(GatewayError::DlpViolation(format!(
            "Target endpoint '{}' is not in the operator allowlist for provider '{}' (INV-001, DEC-07)",
            target, provider
        )))
    }

    /// Registers a provider key directly into memory with zeroization guarantees.
    pub async fn register_key(&self, key: ProviderKey) {
        let mut map = self.keys.write().await;
        map.insert(key.provider.clone(), key);
    }

    /// Ingests credentials from Gateway-only environment variables (Scenario 2).
    pub async fn load_from_env(&self) -> usize {
        let mut loaded = 0;
        let providers = ["openai", "anthropic", "ollama"];

        for p in providers {
            let env_var = format!("ARKA_PROVIDER_KEY_{}", p.to_uppercase());
            if let Ok(val) = std::env::var(&env_var) {
                if !val.trim().is_empty() {
                    let key = ProviderKey::new(
                        p,
                        format!("env_{}", p),
                        val,
                        CredentialSourceType::Environment,
                        0,
                    );
                    self.register_key(key).await;
                    loaded += 1;
                }
            }
        }
        loaded
    }

    /// Loads credentials from a secure configuration file, enforcing 0600 permissions on POSIX systems.
    pub async fn load_from_file(&self, path: &Path) -> Result<usize, GatewayError> {
        if !path.exists() {
            return Err(GatewayError::ProviderUnavailable(format!(
                "Credential file does not exist: {}",
                path.display()
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).map_err(|e| {
                GatewayError::IoError(format!("Cannot inspect file permissions: {}", e))
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            // Enforce mode 0600 or 0400 (owner read/write only)
            if mode != 0o600 && mode != 0o400 {
                return Err(GatewayError::DlpViolation(format!(
                    "Insecure credential file permissions ({:#o} on {}). Must be 0600 or 0400.",
                    mode,
                    path.display()
                )));
            }
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| GatewayError::IoError(format!("Failed to read credential file: {}", e)))?;

        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((provider, secret)) = line.split_once('=') {
                let p = provider.trim().to_lowercase();
                let s = secret.trim().to_string();
                if !s.is_empty() {
                    let key = ProviderKey::new(
                        p,
                        format!("file_{}", count),
                        s,
                        CredentialSourceType::File,
                        0,
                    );
                    self.register_key(key).await;
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Resolves a provider credential in memory, returning a zeroizing buffer copy.
    pub async fn get_key(&self, provider: &str) -> Result<Zeroizing<String>, GatewayError> {
        // 1. Check if provider has been revoked / disabled (Scenario 3)
        let disabled = self.disabled_providers.read().await;
        if disabled.contains(provider) {
            return Err(GatewayError::ProviderUnavailable(format!(
                "LLM Provider '{}' has been disabled / revoked by operator policy.",
                provider
            )));
        }

        // 2. Fetch key from active vault
        let keys = self.keys.read().await;
        if let Some(key) = keys.get(provider) {
            // Return zeroizing clone
            Ok(Zeroizing::new(key.secret.to_string()))
        } else {
            Err(GatewayError::ProviderUnavailable(format!(
                "No active credential configured for provider '{}'.",
                provider
            )))
        }
    }

    /// Dynamically rotates a provider key in memory (Scenario 3).
    /// The previous key is dropped and zeroized immediately.
    pub async fn rotate_key(
        &self,
        provider: &str,
        new_secret: String,
        new_key_id: String,
        now_unix: u64,
    ) {
        let mut keys = self.keys.write().await;
        let new_key = ProviderKey::new(
            provider,
            new_key_id,
            new_secret,
            CredentialSourceType::Static,
            now_unix,
        );
        keys.insert(provider.to_string(), new_key);
    }

    /// Immediately disables a provider and wipes its keys from memory (Scenario 3).
    pub async fn disable_provider(&self, provider: &str) {
        let mut disabled = self.disabled_providers.write().await;
        disabled.insert(provider.to_string());

        let mut keys = self.keys.write().await;
        if let Some(mut old_key) = keys.remove(provider) {
            old_key.secret.zeroize();
        }
    }

    /// Checks if a provider is currently disabled.
    pub async fn is_disabled(&self, provider: &str) -> bool {
        let disabled = self.disabled_providers.read().await;
        disabled.contains(provider)
    }
}
