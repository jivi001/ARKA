//! Error types for ARKA Network Policy and ScopeGuard.

use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkPolicyError {
    #[error("SSRF Protection: Connection to private RFC 1918 address {0} is forbidden")]
    SsrfBlocked(IpAddr),

    #[error("SSRF Protection: Connection to loopback address {0} is forbidden")]
    LoopbackBlocked(IpAddr),

    #[error("Metadata Protection: Connection to cloud metadata endpoint {0} is hard-blocked")]
    MetadataBlocked(IpAddr),

    #[error(
        "IPv6 Policy Violation: Connection to IPv6 destination {0} is not permitted by policy"
    )]
    Ipv6PolicyViolation(IpAddr),

    #[error("Link-Local Protection: Connection to link-local address {0} is forbidden")]
    LinkLocalBlocked(IpAddr),

    #[error("DNS Resolution Failed: {0}")]
    DnsResolutionFailed(String),

    #[error("DNS Rebinding Detected: Resolved address set contains out-of-policy address {0}")]
    DnsRebindingDetected(IpAddr),

    #[error("Socket Peer Address Mismatch: Connected peer {actual} does not match pinned address {expected}")]
    PeerMismatch { expected: String, actual: String },

    #[error("Ambiguous or Invalid IP Representation Rejected: {0}")]
    AmbiguousIpFormat(String),

    #[error("Capability Parameter Injection Rejected: {0}")]
    InvalidParameter(String),

    #[error(
        "Scope Policy Violation: Destination {destination} is denied by scope rules: {reason}"
    )]
    ScopeViolation { destination: String, reason: String },

    #[error("Network Connection Failure: {0}")]
    ConnectionFailed(String),

    #[error("Connection Timeout: Dial attempt to {0} timed out after {1}ms")]
    Timeout(String, u64),
}
