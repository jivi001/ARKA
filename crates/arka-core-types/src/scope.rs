//! Canonical Scope Data Model and Scope Rule Representation.
//!
//! Enforces:
//! - INV-003: Discovered != Authorized
//! - Section 9 & 10: Canonical representation for IP, CIDR, DNS, and URL origins.
//! - Section 11: Scope Invariants (Exclusions override Inclusions, Default-Deny).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Strongly typed CIDR block for IPv4 and IPv6.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CidrBlock {
    V4 { network: Ipv4Addr, prefix: u8 },
    V6 { network: Ipv6Addr, prefix: u8 },
}

impl CidrBlock {
    pub fn new_v4(network: Ipv4Addr, prefix: u8) -> Result<Self, &'static str> {
        if prefix > 32 {
            return Err("IPv4 prefix must be between 0 and 32");
        }
        let mask = if prefix == 0 {
            0
        } else {
            !((1u64 << (32 - prefix)) - 1) as u32
        };
        let net_u32 = u32::from(network) & mask;
        Ok(Self::V4 {
            network: Ipv4Addr::from(net_u32),
            prefix,
        })
    }

    pub fn new_v6(network: Ipv6Addr, prefix: u8) -> Result<Self, &'static str> {
        if prefix > 128 {
            return Err("IPv6 prefix must be between 0 and 128");
        }
        let mask = if prefix == 0 {
            0
        } else {
            !((1u128.checked_shl(128 - prefix as u32).unwrap_or(0)) - 1)
        };
        let net_u128 = u128::from(network) & mask;
        Ok(Self::V6 {
            network: Ipv6Addr::from(net_u128),
            prefix,
        })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (CidrBlock::V4 { network, prefix }, IpAddr::V4(target_v4)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    !((1u64 << (32 - prefix)) - 1) as u32
                };
                (u32::from(*network) & mask) == (u32::from(*target_v4) & mask)
            }
            (CidrBlock::V6 { network, prefix }, IpAddr::V6(target_v6)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    !((1u128.checked_shl(128 - *prefix as u32).unwrap_or(0)) - 1)
                };
                (u128::from(*network) & mask) == (u128::from(*target_v6) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrBlock::V4 { network, prefix } => write!(f, "{}/{}", network, prefix),
            CidrBlock::V6 { network, prefix } => write!(f, "{}/{}", network, prefix),
        }
    }
}

/// Canonical Target representation parsed and normalized by the Security Kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "target")]
pub enum CanonicalTarget {
    Ip(IpAddr),
    IpPort {
        ip: IpAddr,
        port: u16,
    },
    Cidr(CidrBlock),
    Domain {
        domain: String,
        port: Option<u16>,
    },
    UrlOrigin {
        scheme: String,
        host: String,
        port: u16,
        path_prefix: Option<String>,
    },
}

impl CanonicalTarget {
    /// Extracts the effective IP address if available.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            CanonicalTarget::Ip(ip) => Some(*ip),
            CanonicalTarget::IpPort { ip, .. } => Some(*ip),
            _ => None,
        }
    }

    /// Checks if target is a private, loopback, link-local, or cloud metadata address.
    pub fn is_restricted_address(&self) -> bool {
        if let Some(ip) = self.as_ip() {
            match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback() // 127.0.0.0/8
                        || v4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                        || v4.is_link_local() // 169.254.0.0/16
                        || v4.is_broadcast()
                        || v4 == Ipv4Addr::new(169, 254, 169, 254) // AWS/GCP/Azure Metadata
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback() // ::1
                        || v6.is_unspecified() // ::
                        || (v6.segments()[0] & 0xfe00) == 0xfc00 // Unique local (fc00::/7)
                        || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-local (fe80::/10)
                }
            }
        } else {
            false
        }
    }
}

/// A scope rule for matching targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeRule {
    IpExact(IpAddr),
    IpRange(CidrBlock),
    DomainExact(String),
    DomainWildcard(String), // e.g. "*.example.com"
    UrlPrefix {
        scheme: String,
        host: String,
        port: u16,
        path_prefix: String,
    },
}

impl ScopeRule {
    pub fn matches(&self, target: &CanonicalTarget) -> bool {
        match (self, target) {
            (ScopeRule::IpExact(rule_ip), CanonicalTarget::Ip(t_ip)) => rule_ip == t_ip,
            (ScopeRule::IpExact(rule_ip), CanonicalTarget::IpPort { ip: t_ip, .. }) => {
                rule_ip == t_ip
            }

            (ScopeRule::IpRange(cidr), CanonicalTarget::Ip(t_ip)) => cidr.contains(t_ip),
            (ScopeRule::IpRange(cidr), CanonicalTarget::IpPort { ip: t_ip, .. }) => {
                cidr.contains(t_ip)
            }
            (ScopeRule::IpRange(cidr), CanonicalTarget::Cidr(t_cidr)) => {
                // Target CIDR must be completely contained within rule CIDR
                match (cidr, t_cidr) {
                    (
                        CidrBlock::V4 {
                            network: _,
                            prefix: r_p,
                        },
                        CidrBlock::V4 {
                            network: t_net,
                            prefix: t_p,
                        },
                    ) => *r_p <= *t_p && cidr.contains(&IpAddr::V4(*t_net)),
                    (
                        CidrBlock::V6 {
                            network: _,
                            prefix: r_p,
                        },
                        CidrBlock::V6 {
                            network: t_net,
                            prefix: t_p,
                        },
                    ) => *r_p <= *t_p && cidr.contains(&IpAddr::V6(*t_net)),
                    _ => false,
                }
            }

            (ScopeRule::DomainExact(r_dom), CanonicalTarget::Domain { domain: t_dom, .. }) => {
                r_dom.eq_ignore_ascii_case(t_dom)
            }
            (ScopeRule::DomainExact(r_dom), CanonicalTarget::UrlOrigin { host: t_host, .. }) => {
                r_dom.eq_ignore_ascii_case(t_host)
            }

            (ScopeRule::DomainWildcard(suffix), CanonicalTarget::Domain { domain: t_dom, .. }) => {
                matches_domain_wildcard(suffix, t_dom)
            }
            (
                ScopeRule::DomainWildcard(suffix),
                CanonicalTarget::UrlOrigin { host: t_host, .. },
            ) => matches_domain_wildcard(suffix, t_host),

            (
                ScopeRule::UrlPrefix {
                    scheme: r_s,
                    host: r_h,
                    port: r_p,
                    path_prefix: r_path,
                },
                CanonicalTarget::UrlOrigin {
                    scheme: t_s,
                    host: t_h,
                    port: t_p,
                    path_prefix: t_path,
                },
            ) => {
                r_s.eq_ignore_ascii_case(t_s)
                    && r_h.eq_ignore_ascii_case(t_h)
                    && *r_p == *t_p
                    && match (r_path.as_str(), t_path) {
                        ("", _) => true,
                        (prefix, Some(target_p)) => target_p.starts_with(prefix),
                        _ => false,
                    }
            }

            _ => false,
        }
    }
}

fn matches_domain_wildcard(wildcard: &str, target_domain: &str) -> bool {
    // wildcard e.g. "*.example.com"
    let base = if let Some(stripped) = wildcard.strip_prefix("*.") {
        stripped
    } else {
        wildcard
    };

    if target_domain.eq_ignore_ascii_case(base) {
        return false; // *.example.com does not match example.com itself
    }

    if let Some(prefix) = target_domain.strip_suffix(base) {
        prefix.ends_with('.') && !prefix.is_empty()
    } else {
        false
    }
}

/// The formal definition of an assessment scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDefinition {
    pub inclusions: Vec<ScopeRule>,
    pub exclusions: Vec<ScopeRule>,
    pub allow_private_ranges: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    Allowed,
    Denied(&'static str),
}

impl ScopeDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ScopeDecision::Allowed)
    }
}
