//! Asynchronous DNS Resolution Abstraction and Rebinding Defense.
//!
//! Enforces:
//! - Single-resolution contract: DNS query executed once per connection attempt
//! - All returned IP addresses evaluated simultaneously against policy
//! - Deterministic mock resolver for unit, rebinding, and adversarial testing

use crate::errors::NetworkPolicyError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolves a hostname to a list of IP addresses.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkPolicyError>;
}

/// System DNS resolver using standard OS resolution via Tokio.
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkPolicyError> {
        // tokio::net::lookup_host requires host:port
        let lookup_target = format!("{}:80", host);
        let addrs = tokio::net::lookup_host(&lookup_target)
            .await
            .map_err(|e| NetworkPolicyError::DnsResolutionFailed(e.to_string()))?;

        let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
        if ips.is_empty() {
            return Err(NetworkPolicyError::DnsResolutionFailed(format!(
                "No DNS records found for host '{}'",
                host
            )));
        }

        Ok(ips)
    }
}

/// Programmable in-memory DNS resolver for deterministic testing and rebinding simulations.
pub struct MockDnsResolver {
    responses: RwLock<HashMap<String, Vec<Vec<IpAddr>>>>,
    query_counts: RwLock<HashMap<String, Arc<AtomicUsize>>>,
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            responses: RwLock::new(HashMap::new()),
            query_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a fixed list of IP addresses returned for `host`.
    pub async fn set_response(&self, host: impl Into<String>, ips: Vec<IpAddr>) {
        let mut map = self.responses.write().await;
        map.insert(host.into(), vec![ips]);
    }

    /// Registers an ordered sequence of IP responses simulating DNS rebinding.
    ///
    /// (e.g. 1st query returns public IP, 2nd query returns 127.0.0.1).
    pub async fn set_rebinding_sequence(
        &self,
        host: impl Into<String>,
        sequence: Vec<Vec<IpAddr>>,
    ) {
        let mut map = self.responses.write().await;
        map.insert(host.into(), sequence);
    }

    /// Returns the number of times `host` was queried.
    pub async fn query_count(&self, host: &str) -> usize {
        let counts = self.query_counts.read().await;
        if let Some(counter) = counts.get(host) {
            counter.load(Ordering::SeqCst)
        } else {
            0
        }
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkPolicyError> {
        // Track query count
        let counter = {
            let mut counts = self.query_counts.write().await;
            counts
                .entry(host.to_string())
                .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                .clone()
        };
        let call_idx = counter.fetch_add(1, Ordering::SeqCst);

        let map = self.responses.read().await;
        if let Some(seq) = map.get(host) {
            if seq.is_empty() {
                return Err(NetworkPolicyError::DnsResolutionFailed(format!(
                    "No configured records for host '{}'",
                    host
                )));
            }
            // Return element at call_idx, or repeat last element
            let idx = call_idx.min(seq.len() - 1);
            Ok(seq[idx].clone())
        } else {
            Err(NetworkPolicyError::DnsResolutionFailed(format!(
                "Host '{}' not found in MockDnsResolver",
                host
            )))
        }
    }
}
