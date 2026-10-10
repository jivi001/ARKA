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

    #[error("HTTP Redirect Policy Violation: Redirect chain exceeded maximum limit of {0} hops")]
    RedirectLimitExceeded(usize),

    #[error("HTTP Redirect Policy Violation: Cyclic redirect loop detected for URL '{0}'")]
    RedirectLoopDetected(String),

    #[error(
        "HTTP Redirect Policy Violation: Insecure scheme downgrade from {from} to {to} is forbidden"
    )]
    SchemeDowngradeForbidden { from: String, to: String },

    #[error(
        "HTTP Redirect Policy Violation: Unsupported URL scheme '{0}'. Only HTTP and HTTPS are permitted"
    )]
    UnsupportedScheme(String),

    #[error(
        "HTTP Redirect Policy Violation: Embedded credentials (userinfo) in URL are forbidden"
    )]
    CredentialsInUrlForbidden,

    #[error("HTTP Redirect Policy Violation: Malformed redirect Location URL: {0}")]
    InvalidRedirectUrl(String),

    #[error(
        "Browser Mediation Boundary Violation: Direct connection attempt to '{0}' bypasses broker proxy"
    )]
    BrowserMediationBypass(String),

    #[error("Browser Mediation Boundary Violation: Invalid proxy configuration: {0}")]
    ProxyConfigurationInvalid(String),
}
