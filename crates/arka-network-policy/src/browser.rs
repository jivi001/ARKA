//! Headless Browser Proxy Mediation Boundary.
//!
//! Enforces:
//! - GATE-BROWSER-SANDBOX-001 / CTRL-BROWSER-SANDBOX-001
//! - TEST-PROXY-BYPASS-001: Execution Broker Outbound Proxy Enforcement Contract
//! - TEST-SANDBOX-NET-001: Sandbox Network Namespace Isolation Contract
//! - Invariants:
//!   - Browser engines (Playwright / headless Chromium) run in dedicated sandbox network namespaces
//!   - Zero direct raw socket connections permitted from browser processes
//!   - 100% of outbound browser HTTP/HTTPS/WebSocket egress must flow through broker-mediated proxy
//!   - All proxied requests are subject to connection-time ScopeGuard validation and IP pinning

use crate::dns::DnsResolver;
use crate::errors::NetworkPolicyError;
use crate::params::ParameterValidator;
use crate::validator::{PinnedDestination, ScopeGuard};
use arka_core_types::scope::ScopeDefinition;
use std::sync::Arc;
use url::Url;

/// Configuration governing browser sandbox network mediation.
#[derive(Debug, Clone)]
pub struct BrowserMediationConfig {
    /// Host of the broker-controlled mediation proxy (e.g. "127.0.0.1").
    pub proxy_host: String,
    /// Port of the broker-controlled mediation proxy.
    pub proxy_port: u16,
    /// Whether to strictly enforce broker proxy routing (default: true).
    pub enforce_broker_proxy: bool,
    /// Whether to require an isolated network namespace (default: true).
    pub require_isolated_netns: bool,
}

impl Default for BrowserMediationConfig {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 8080,
            enforce_broker_proxy: true,
            require_isolated_netns: true,
        }
    }
}

impl BrowserMediationConfig {
    pub fn new(proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            proxy_host: proxy_host.into(),
            proxy_port,
            enforce_broker_proxy: true,
            require_isolated_netns: true,
        }
    }
}

/// Authoritative guardian enforcing proxy mediation and network namespace boundaries
/// on headless browser processes.
pub struct BrowserMediationGuard {
    config: BrowserMediationConfig,
}

impl BrowserMediationGuard {
    /// Constructs a new `BrowserMediationGuard` with the given configuration.
    pub fn new(config: BrowserMediationConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the active configuration.
    pub fn config(&self) -> &BrowserMediationConfig {
        &self.config
    }

    /// Constructs authoritative Chromium / Playwright launch flags ensuring
    /// all network traffic is forced through the broker proxy and background networking is disabled.
    pub fn build_chromium_args(&self) -> Vec<String> {
        vec![
            format!(
                "--proxy-server=http://{}:{}",
                self.config.proxy_host, self.config.proxy_port
            ),
            // Ensure loopback is not exempted from the proxy
            "--proxy-bypass-list=<-loopback>".to_string(),
            "--disable-background-networking".to_string(),
            "--disable-sync".to_string(),
            "--disable-default-apps".to_string(),
            "--disable-extensions".to_string(),
            "--no-default-browser-check".to_string(),
            "--disable-component-update".to_string(),
            "--headless=new".to_string(),
        ]
    }

    /// Verifies the sandbox network namespace isolation contract (TEST-SANDBOX-NET-001).
    ///
    /// Ensures that:
    /// 1. The browser process is contained in an isolated network namespace (`--unshare-net`).
    /// 2. The host network namespace is NOT exposed to the browser process.
    pub fn verify_network_isolation(
        &self,
        in_isolated_netns: bool,
        host_netns_exposed: bool,
    ) -> Result<(), NetworkPolicyError> {
        if host_netns_exposed {
            return Err(NetworkPolicyError::BrowserMediationBypass(
                "Host network namespace is exposed to browser sandbox".to_string(),
            ));
        }

        if self.config.require_isolated_netns && !in_isolated_netns {
            return Err(NetworkPolicyError::BrowserMediationBypass(
                "Browser process is not contained within isolated network namespace".to_string(),
            ));
        }

        Ok(())
    }

    /// Verifies that an outbound egress attempt from the browser complies with the
    /// broker proxy mediation contract (TEST-PROXY-BYPASS-001).
    pub fn verify_egress_routing(
        &self,
        is_proxied: bool,
        target_destination: &str,
    ) -> Result<(), NetworkPolicyError> {
        if self.config.enforce_broker_proxy && !is_proxied {
            return Err(NetworkPolicyError::BrowserMediationBypass(format!(
                "Direct socket egress to '{}' violates broker mediation boundary (all browser egress must route via proxy)",
                target_destination
            )));
        }

        Ok(())
    }

    /// Mediates an HTTP/HTTPS request initiated by the browser through the broker proxy,
    /// enforcing strict scope rules, SSRF defense, and destination IP pinning.
    pub async fn mediate_proxied_request<R: DnsResolver>(
        &self,
        scope_guard: &Arc<ScopeGuard<R>>,
        raw_url: &str,
        is_proxied: bool,
        scope: Option<&ScopeDefinition>,
    ) -> Result<PinnedDestination, NetworkPolicyError> {
        // Enforce proxy routing contract
        self.verify_egress_routing(is_proxied, raw_url)?;

        let parsed = Url::parse(raw_url)
            .map_err(|e| NetworkPolicyError::InvalidRedirectUrl(format!("{}: {}", raw_url, e)))?;

        let scheme = parsed.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
            return Err(NetworkPolicyError::UnsupportedScheme(scheme));
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(NetworkPolicyError::CredentialsInUrlForbidden);
        }

        let host = parsed.host_str().ok_or_else(|| {
            NetworkPolicyError::InvalidRedirectUrl("Missing host in browser URL".to_string())
        })?;

        ParameterValidator::validate_host(host)?;

        let port = parsed
            .port_or_known_default()
            .unwrap_or(match scheme.as_str() {
                "https" | "wss" => 443,
                _ => 80,
            });

        ParameterValidator::validate_port(port)?;

        // Execute authoritative ScopeGuard validation & IP pinning
        scope_guard.validate_and_pin(host, port, scope).await
    }
}
