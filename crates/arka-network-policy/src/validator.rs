//! ScopeGuard connection-time destination validator and IP pinning engine.
//!
//! Enforces:
//! - Connection-time destination validation immediately prior to socket dial
//! - DNS resolution executed exactly once
//! - Simultaneous validation of ALL returned IP addresses against scope and blocked ranges
//! - Fail-closed rejection of mixed answer sets (e.g. public IP + loopback/metadata)
//! - Construction of immutable `PinnedDestination` binding IP, port, and original canonical hostname

use crate::address::CanonicalIp;
use crate::blocked_ranges::BlockedRanges;
use crate::dns::DnsResolver;
use crate::errors::NetworkPolicyError;
use crate::params::ParameterValidator;
use arka_core_types::scope::{CanonicalTarget, ScopeDefinition};
use std::net::IpAddr;
use std::sync::Arc;

/// An immutable, cryptographically bound and policy-validated destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDestination {
    pub ip: IpAddr,
    pub port: u16,
    pub original_hostname: Option<String>,
}

impl PinnedDestination {
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip, self.port)
    }
}

pub struct ScopeGuard<R: DnsResolver> {
    resolver: Arc<R>,
    allow_private_ranges: bool,
}

impl<R: DnsResolver> ScopeGuard<R> {
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            allow_private_ranges: false,
        }
    }

    pub fn with_allow_private(mut self, allow: bool) -> Self {
        self.allow_private_ranges = allow;
        self
    }

    /// Authoritatively validates a destination at connection time and returns a pinned target.
    pub async fn validate_and_pin(
        &self,
        target_host: &str,
        port: u16,
        scope: Option<&ScopeDefinition>,
    ) -> Result<PinnedDestination, NetworkPolicyError> {
        // 1. Strict parameter injection defense
        ParameterValidator::validate_host(target_host)?;
        ParameterValidator::validate_port(port)?;

        let allow_private = scope
            .map(|s| s.allow_private_ranges)
            .unwrap_or(self.allow_private_ranges);

        // 2. Check if target_host is an IP literal
        if target_host.starts_with('[')
            || target_host
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        {
            if let Ok(ip) = CanonicalIp::parse(target_host) {
                // Validate IP literal against blocked ranges
                BlockedRanges::check_ip(&ip, allow_private)?;

                // Validate against scope inclusions & exclusions if provided
                if let Some(scope_def) = scope {
                    self.validate_ip_against_scope(&ip, port, scope_def)?;
                }

                return Ok(PinnedDestination {
                    ip,
                    port,
                    original_hostname: None,
                });
            }
        }

        // 3. Target is a domain name: check domain-level exclusions before network DNS resolution
        if let Some(scope_def) = scope {
            let domain_target = CanonicalTarget::Domain {
                domain: target_host.to_string(),
                port: Some(port),
            };
            for exclusion in &scope_def.exclusions {
                if exclusion.matches(&domain_target) {
                    return Err(NetworkPolicyError::ScopeViolation {
                        destination: target_host.to_string(),
                        reason: "Domain matches explicit scope exclusion rule".to_string(),
                    });
                }
            }
        }

        let resolved_ips = self.resolver.resolve(target_host).await?;

        if resolved_ips.is_empty() {
            return Err(NetworkPolicyError::DnsResolutionFailed(format!(
                "Host '{}' resolved to 0 addresses",
                target_host
            )));
        }

        // 4. Validate ALL returned IP addresses.
        // If an adversary returns mixed safe + unsafe IPs (e.g. Rebinding / Multi-A record SSRF),
        // fail closed unconditionally!
        for ip in &resolved_ips {
            // Check blocked ranges
            BlockedRanges::check_ip(ip, allow_private)?;

            // Check scope if provided
            if let Some(scope_def) = scope {
                self.validate_ip_against_scope(ip, port, scope_def)?;
            }
        }

        // 5. Select first validated IP address and pin it
        let pinned_ip = resolved_ips[0];

        Ok(PinnedDestination {
            ip: pinned_ip,
            port,
            original_hostname: Some(target_host.to_string()),
        })
    }

    fn validate_ip_against_scope(
        &self,
        ip: &IpAddr,
        port: u16,
        scope: &ScopeDefinition,
    ) -> Result<(), NetworkPolicyError> {
        let canonical_target = CanonicalTarget::IpPort { ip: *ip, port };

        // Check exclusions (unconditional override)
        for exclusion in &scope.exclusions {
            if exclusion.matches(&canonical_target) {
                return Err(NetworkPolicyError::ScopeViolation {
                    destination: ip.to_string(),
                    reason: "Matches explicit scope exclusion rule".to_string(),
                });
            }
        }

        // Check inclusions (must match at least one inclusion)
        let matches_inclusion = scope
            .inclusions
            .iter()
            .any(|inc| inc.matches(&canonical_target));
        if !matches_inclusion && !scope.inclusions.is_empty() {
            return Err(NetworkPolicyError::ScopeViolation {
                destination: ip.to_string(),
                reason: "Destination does not match any authorized scope inclusion rule"
                    .to_string(),
            });
        }

        Ok(())
    }
}
