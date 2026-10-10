//! HTTP Redirect Interception Layer and ScopeGuard Re-Validation Engine.
//!
//! Enforces:
//! - INV-003: Discovered != Authorized
//! - INV-015: Redirect Scope Re-Evaluation Contract
//! - Section 11 & P2-E Architecture:
//!   - Automatic redirect following is strictly disabled in raw transports
//!   - Every redirect hop MUST call the exact same single destination-validation function
//!     (`ScopeGuard::validate_and_pin`) and pinned-dial path used for the initial request
//!   - Trust is completely reset at every hop
//!   - Revalidates scheme, hostname, effective port, resolved IP, scope inclusions/exclusions
//!   - Fail-closed defense against:
//!     - Private RFC 1918 addresses
//!     - Loopback (127.0.0.0/8, ::1)
//!     - Link-local and cloud metadata (169.254.169.254, fd00:ec2::254)
//!     - Insecure protocol downgrade (HTTPS -> HTTP)
//!     - Unsupported or dangerous schemes (file://, gopher://, javascript:, data:)
//!     - Embedded URL credentials (userinfo)
//!     - Redirect loops (cycle detection)
//!     - Excessive redirect chains (hop count ceiling)

use crate::dns::DnsResolver;
use crate::errors::NetworkPolicyError;
use crate::params::ParameterValidator;
use crate::validator::{PinnedDestination, ScopeGuard};
use arka_core_types::scope::ScopeDefinition;
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

/// Configuration governing HTTP redirect evaluation.
#[derive(Debug, Clone)]
pub struct RedirectConfig {
    /// Maximum allowed redirect hops before failing closed (default: 5).
    pub max_redirects: usize,
    /// Whether to allow HTTPS to HTTP scheme downgrades (default: false, strictly forbidden).
    pub allow_downgrade: bool,
    /// Permitted URL schemes (default: "http", "https").
    pub allowed_schemes: HashSet<String>,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("http".to_string());
        allowed.insert("https".to_string());
        Self {
            max_redirects: 5,
            allow_downgrade: false,
            allowed_schemes: allowed,
        }
    }
}

impl RedirectConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }
}

/// The outcome of evaluating an HTTP response for redirects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectDecision {
    /// The response was a valid, in-scope redirect to follow.
    Follow {
        /// The normalized, resolved target URL.
        target_url: String,
        /// The cryptographically pinned and policy-verified destination.
        pinned: PinnedDestination,
        /// The current hop index (1-indexed).
        hop_number: usize,
    },
    /// The response is terminal (not a redirect, or body is ready to consume).
    Terminal { status_code: u16 },
}

/// Authoritative HTTP redirect handler and hop-by-hop re-evaluation engine.
pub struct RedirectHandler<R: DnsResolver> {
    scope_guard: Arc<ScopeGuard<R>>,
    config: RedirectConfig,
    visited_urls: Vec<String>,
    seen_https: bool,
}

impl<R: DnsResolver> RedirectHandler<R> {
    /// Constructs a new `RedirectHandler` bound to the given `ScopeGuard`.
    pub fn new(scope_guard: Arc<ScopeGuard<R>>, config: RedirectConfig) -> Self {
        Self {
            scope_guard,
            config,
            visited_urls: Vec::new(),
            seen_https: false,
        }
    }

    /// Resets the redirect state for a new request chain.
    pub fn reset(&mut self) {
        self.visited_urls.clear();
        self.seen_https = false;
    }

    /// Returns the number of redirect hops traversed so far.
    pub fn hop_count(&self) -> usize {
        self.visited_urls.len()
    }

    /// Returns the redirect chain history.
    pub fn history(&self) -> &[String] {
        &self.visited_urls
    }

    /// Authoritatively validates and pins an initial URL prior to making the first HTTP request.
    pub async fn validate_initial_url(
        &mut self,
        initial_url_str: &str,
        scope: Option<&ScopeDefinition>,
    ) -> Result<(String, PinnedDestination), NetworkPolicyError> {
        self.reset();

        let parsed = Url::parse(initial_url_str).map_err(|e| {
            NetworkPolicyError::InvalidRedirectUrl(format!("{}: {}", initial_url_str, e))
        })?;

        let (target_url, pinned) = self.validate_target_url(&parsed, scope).await?;

        if parsed.scheme().eq_ignore_ascii_case("https") {
            self.seen_https = true;
        }

        self.visited_urls.push(target_url.clone());
        Ok((target_url, pinned))
    }

    /// Evaluates an HTTP response status code and `Location` header to determine whether
    /// a redirect should be followed, subject to strict scope, SSRF, scheme, and loop checks.
    pub async fn evaluate_redirect(
        &mut self,
        current_url_str: &str,
        status_code: u16,
        location_header: Option<&str>,
        scope: Option<&ScopeDefinition>,
    ) -> Result<RedirectDecision, NetworkPolicyError> {
        // 1. Check if status code represents an HTTP redirect (301, 302, 303, 307, 308)
        if !Self::is_redirect_status(status_code) {
            return Ok(RedirectDecision::Terminal { status_code });
        }

        let location = location_header.ok_or_else(|| {
            NetworkPolicyError::InvalidRedirectUrl(
                "HTTP redirect status code present without Location header".to_string(),
            )
        })?;

        // 2. Enforce hop count ceiling
        if self.visited_urls.len() >= self.config.max_redirects {
            return Err(NetworkPolicyError::RedirectLimitExceeded(
                self.config.max_redirects,
            ));
        }

        // 3. Resolve target URL (handles absolute and relative Location headers)
        let base_url = Url::parse(current_url_str).map_err(|e| {
            NetworkPolicyError::InvalidRedirectUrl(format!(
                "Invalid base URL {}: {}",
                current_url_str, e
            ))
        })?;

        let resolved_url = base_url.join(location).map_err(|e| {
            NetworkPolicyError::InvalidRedirectUrl(format!(
                "Failed to resolve Location '{}' against base '{}': {}",
                location, current_url_str, e
            ))
        })?;

        let resolved_url_str = resolved_url.to_string();

        // 4. Cycle / loop detection
        if self
            .visited_urls
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&resolved_url_str))
        {
            return Err(NetworkPolicyError::RedirectLoopDetected(resolved_url_str));
        }

        // 5. Authoritatively re-validate destination through ScopeGuard and policy checks
        let (target_url, pinned) = self.validate_target_url(&resolved_url, scope).await?;

        // 6. Record hop in history
        self.visited_urls.push(target_url.clone());
        let hop_number = self.visited_urls.len();

        Ok(RedirectDecision::Follow {
            target_url,
            pinned,
            hop_number,
        })
    }

    /// Internal validation pipeline executing all mandatory checks on a parsed URL.
    async fn validate_target_url(
        &mut self,
        url: &Url,
        scope: Option<&ScopeDefinition>,
    ) -> Result<(String, PinnedDestination), NetworkPolicyError> {
        let scheme = url.scheme().to_ascii_lowercase();

        // 1. Check allowed schemes (reject file://, gopher://, javascript:, ftp://, etc.)
        if !self.config.allowed_schemes.contains(&scheme) {
            return Err(NetworkPolicyError::UnsupportedScheme(scheme));
        }

        // 2. Check for HTTPS -> HTTP downgrade
        if !self.config.allow_downgrade && self.seen_https && scheme == "http" {
            return Err(NetworkPolicyError::SchemeDowngradeForbidden {
                from: "https".to_string(),
                to: "http".to_string(),
            });
        }

        if scheme == "https" {
            self.seen_https = true;
        }

        // 3. Reject embedded credentials in URL (userinfo)
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NetworkPolicyError::CredentialsInUrlForbidden);
        }

        // 4. Extract and validate host
        let host = url.host_str().ok_or_else(|| {
            NetworkPolicyError::InvalidRedirectUrl("Missing host in URL".to_string())
        })?;

        ParameterValidator::validate_host(host)?;

        // 5. Extract and validate effective port
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        ParameterValidator::validate_port(port)?;

        // 6. Execute ScopeGuard connection-time destination validation & DNS IP pinning
        // This validates:
        // - Canonical IP representation (rejection of octal, hex, integer, zone ID)
        // - Domain exclusions
        // - DNS resolution and checking of ALL returned IPs
        // - SSRF and private address blocks (RFC 1918, loopback, link-local, cloud metadata)
        // - Scope inclusions and exclusions
        let pinned = self.scope_guard.validate_and_pin(host, port, scope).await?;

        Ok((url.to_string(), pinned))
    }

    /// Checks if an HTTP status code indicates a redirect that can be followed.
    pub fn is_redirect_status(status_code: u16) -> bool {
        matches!(status_code, 301 | 302 | 303 | 307 | 308)
    }
}
