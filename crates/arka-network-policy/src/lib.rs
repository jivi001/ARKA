//! ARKA Network Policy and ScopeGuard Subsystem.
//!
//! Enforces:
//! - Connection-time destination validation immediately prior to socket dial
//! - DNS resolution executed once per connection attempt with strict IP pinning
//! - SSRF and private address blocking (RFC 1918, loopback, link-local)
//! - Cloud instance metadata access hard-blocking (169.254.169.254, fd00:ec2::254)
//! - IPv6 unscoped / local access policy enforcement
//! - Negative bypass rejection (octal, hex, decimal integer IP representations, zone IDs)
//! - Direct-IP dialing with post-connect socket peer verification
//! - Capability parameter injection defense (shell metacharacters, control characters)

#![forbid(unsafe_code)]

pub mod address;
pub mod blocked_ranges;
pub mod browser;
pub mod connector;
pub mod dns;
pub mod errors;
pub mod params;
pub mod redirect;
pub mod validator;

pub use address::CanonicalIp;
pub use blocked_ranges::BlockedRanges;
pub use browser::{BrowserMediationConfig, BrowserMediationGuard};
pub use connector::DirectIpConnector;
pub use dns::{DnsResolver, MockDnsResolver, SystemDnsResolver};
pub use errors::NetworkPolicyError;
pub use params::ParameterValidator;
pub use redirect::{RedirectConfig, RedirectDecision, RedirectHandler};
pub use validator::{PinnedDestination, ScopeGuard};
