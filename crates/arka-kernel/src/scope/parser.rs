//! Target Parser with Negative Bypass Defense.
//!
//! Enforces:
//! - Section 10: Strict rejection of ambiguous IP formats (octal, hex, decimal integers).
//! - IPv4-mapped IPv6 normalization to prevent IPv4 policy evasion.
//! - DNS normalization (case-folding, trailing-dot removal, homoglyph rejection).
//! - URL parsing security (strict rejection of userinfo `@`, host confusion, non-HTTP schemes).

use arka_core_types::errors::KernelSecurityError;
use arka_core_types::scope::{CanonicalTarget, CidrBlock};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct TargetParser;

impl TargetParser {
    /// Parses an untrusted target string into a validated, normalized CanonicalTarget.
    pub fn parse(raw: &str) -> Result<CanonicalTarget, KernelSecurityError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(KernelSecurityError::ScopeDenied(
                "Target cannot be empty".to_string(),
            ));
        }

        // Check for forbidden control characters or whitespace
        if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(KernelSecurityError::ScopeDenied(
                "Target contains control characters or whitespace".to_string(),
            ));
        }

        // Check for URL scheme prefix
        if trimmed.contains("://") {
            return Self::parse_url(trimmed);
        }

        // Check for CIDR notation
        if let Some((net_str, prefix_str)) = trimmed.split_once('/') {
            return Self::parse_cidr(net_str, prefix_str);
        }

        let (host_part, _) = Self::split_host_port(trimmed)?;

        // Hexadecimal IP detection (0x7f000001, 0x7f.0.0.1)
        if host_part.starts_with("0x") || host_part.starts_with("0X") {
            return Err(KernelSecurityError::ScopeDenied(
                "Ambiguous hexadecimal IP representation rejected".to_string(),
            ));
        }

        // Integer IP detection (2130706433)
        if host_part.chars().all(|c| c.is_ascii_digit()) {
            return Err(KernelSecurityError::ScopeDenied(
                "Ambiguous decimal integer IP representation rejected".to_string(),
            ));
        }

        // IPv6 (bracketed or containing multiple colons)
        if host_part.starts_with('[') || host_part.contains(':') {
            return Self::parse_ip_or_socket(trimmed);
        }

        // If the last label is all digits (e.g. 127.0.0.1 or 0177.0.0.1 or 1.2.3),
        // it cannot be a valid domain name (ICANN/RFC forbids all-numeric TLDs).
        // It is an IPv4 attempt and must strictly adhere to IPv4 canonical format.
        if let Some(last_label) = host_part.split('.').next_back() {
            if !last_label.is_empty() && last_label.chars().all(|c| c.is_ascii_digit()) {
                return Self::parse_ip_or_socket(trimmed);
            }
        }

        // Parse as DNS Domain / Domain:Port
        Self::parse_domain(trimmed)
    }

    /// Parses URL origins with strict bypass defense against userinfo, host confusion, and bad schemes.
    fn parse_url(raw: &str) -> Result<CanonicalTarget, KernelSecurityError> {
        let (scheme, rest) = raw.split_once("://").ok_or_else(|| {
            KernelSecurityError::ScopeDenied("Malformed URL missing scheme separator".to_string())
        })?;

        let scheme_lower = scheme.to_ascii_lowercase();
        if scheme_lower != "http" && scheme_lower != "https" {
            return Err(KernelSecurityError::ScopeDenied(format!(
                "Unsupported URL scheme '{}'; only http and https are permitted",
                scheme
            )));
        }

        // Host and authority part
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let path_and_query = &rest[authority_end..];

        // Section 10: Reject URL userinfo bypass attempts (e.g. http://attacker.com@target.com)
        if authority.contains('@') {
            return Err(KernelSecurityError::ScopeDenied(
                "URL userinfo (containing '@') is strictly forbidden for security".to_string(),
            ));
        }

        // Reject backslash in authority (host confusion bypass)
        if authority.contains('\\') {
            return Err(KernelSecurityError::ScopeDenied(
                "Host confusion attack detected: authority contains backslash '\\'".to_string(),
            ));
        }

        let (host_str, port_opt) = Self::split_host_port(authority)?;

        let port = match port_opt {
            Some(p) => p,
            None => {
                if scheme_lower == "https" {
                    443
                } else {
                    80
                }
            }
        };

        // Normalize host (case-insensitive, trailing dot stripped)
        let normalized_host = Self::normalize_host(host_str)?;

        let path_prefix = if path_and_query.is_empty() || path_and_query == "/" {
            None
        } else {
            // Path normalization
            let path_part = path_and_query.split(['?', '#']).next().unwrap_or("/");
            Some(Self::normalize_path(path_part))
        };

        Ok(CanonicalTarget::UrlOrigin {
            scheme: scheme_lower,
            host: normalized_host,
            port,
            path_prefix,
        })
    }

    /// Parses IP addresses and SocketAddrs, enforcing non-canonical IP bypass rejection.
    fn parse_ip_or_socket(raw: &str) -> Result<CanonicalTarget, KernelSecurityError> {
        // Handle [IPv6]:port or IPv4:port
        let (host_part, port_opt) = Self::split_host_port(raw)?;

        // Validate IPv4 for octal/hex/decimal integer representations
        if host_part.contains('.') && !host_part.contains(':') {
            let v4 = Self::parse_strict_ipv4(host_part)?;
            return Ok(match port_opt {
                Some(p) => CanonicalTarget::IpPort {
                    ip: IpAddr::V4(v4),
                    port: p,
                },
                None => CanonicalTarget::Ip(IpAddr::V4(v4)),
            });
        }

        // Validate IPv6
        if host_part.contains(':') {
            let v6 = Ipv6Addr::from_str(host_part).map_err(|_| {
                KernelSecurityError::ScopeDenied("Malformed IPv6 address".to_string())
            })?;

            // Section 10: Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                // Canonicalize to IPv4 so it cannot evade IPv4 scope checks!
                return Ok(match port_opt {
                    Some(p) => CanonicalTarget::IpPort {
                        ip: IpAddr::V4(mapped_v4),
                        port: p,
                    },
                    None => CanonicalTarget::Ip(IpAddr::V4(mapped_v4)),
                });
            }

            return Ok(match port_opt {
                Some(p) => CanonicalTarget::IpPort {
                    ip: IpAddr::V6(v6),
                    port: p,
                },
                None => CanonicalTarget::Ip(IpAddr::V6(v6)),
            });
        }

        Err(KernelSecurityError::ScopeDenied(
            "Not an IP address".to_string(),
        ))
    }

    /// Strict IPv4 parser rejecting leading zeros (octal), hex, and non-canonical forms.
    fn parse_strict_ipv4(s: &str) -> Result<Ipv4Addr, KernelSecurityError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(KernelSecurityError::ScopeDenied(
                "IPv4 address must contain exactly 4 dotted-decimal octets".to_string(),
            ));
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(KernelSecurityError::ScopeDenied(
                    "Empty octet in IPv4 address".to_string(),
                ));
            }

            // Section 10: Reject leading zeros to prevent octal interpretation confusion
            if part.len() > 1 && part.starts_with('0') {
                return Err(KernelSecurityError::ScopeDenied(format!(
                    "Ambiguous octal IP representation rejected: '{}'",
                    part
                )));
            }

            // Reject non-numeric (hex '0x', signs '+', '-')
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return Err(KernelSecurityError::ScopeDenied(format!(
                    "Non-canonical characters in IPv4 octet: '{}'",
                    part
                )));
            }

            let num: u8 = part.parse().map_err(|_| {
                KernelSecurityError::ScopeDenied(format!(
                    "IPv4 octet '{}' out of range [0, 255]",
                    part
                ))
            })?;
            octets[i] = num;
        }

        Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    }

    /// Parses CIDR notation.
    fn parse_cidr(net_str: &str, prefix_str: &str) -> Result<CanonicalTarget, KernelSecurityError> {
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| KernelSecurityError::ScopeDenied("Malformed CIDR prefix".to_string()))?;

        if net_str.contains('.') && !net_str.contains(':') {
            let v4 = Self::parse_strict_ipv4(net_str)?;
            let cidr = CidrBlock::new_v4(v4, prefix)
                .map_err(|e| KernelSecurityError::ScopeDenied(e.to_string()))?;
            Ok(CanonicalTarget::Cidr(cidr))
        } else if net_str.contains(':') {
            let v6 = Ipv6Addr::from_str(net_str).map_err(|_| {
                KernelSecurityError::ScopeDenied("Malformed IPv6 in CIDR".to_string())
            })?;
            let cidr = CidrBlock::new_v6(v6, prefix)
                .map_err(|e| KernelSecurityError::ScopeDenied(e.to_string()))?;
            Ok(CanonicalTarget::Cidr(cidr))
        } else {
            Err(KernelSecurityError::ScopeDenied(
                "Invalid network in CIDR notation".to_string(),
            ))
        }
    }

    /// Parses and normalizes domain names.
    fn parse_domain(raw: &str) -> Result<CanonicalTarget, KernelSecurityError> {
        let (host_part, port_opt) = Self::split_host_port(raw)?;
        let normalized = Self::normalize_host(host_part)?;
        Ok(CanonicalTarget::Domain {
            domain: normalized,
            port: port_opt,
        })
    }

    fn split_host_port(raw: &str) -> Result<(&str, Option<u16>), KernelSecurityError> {
        // [IPv6]:port
        if raw.starts_with('[') {
            if let Some(close_bracket) = raw.find(']') {
                let host = &raw[1..close_bracket];
                let remainder = &raw[close_bracket + 1..];
                if remainder.is_empty() {
                    return Ok((host, None));
                }
                if let Some(port_str) = remainder.strip_prefix(':') {
                    let port = port_str.parse::<u16>().map_err(|_| {
                        KernelSecurityError::ScopeDenied(
                            "Invalid port in socket address".to_string(),
                        )
                    })?;
                    return Ok((host, Some(port)));
                }
            }
            return Err(KernelSecurityError::ScopeDenied(
                "Unclosed IPv6 bracket".to_string(),
            ));
        }

        // Host:port (for IPv4 or Domain)
        if let Some((h, p_str)) = raw.rsplit_once(':') {
            // Ensure this is not an unbracketed IPv6 address (which contains multiple colons)
            if !h.contains(':') {
                if let Ok(port) = p_str.parse::<u16>() {
                    return Ok((h, Some(port)));
                }
            }
        }

        Ok((raw, None))
    }

    fn normalize_host(host: &str) -> Result<String, KernelSecurityError> {
        // Strip trailing dot (DNS root)
        let s = host.strip_suffix('.').unwrap_or(host);
        if s.is_empty() {
            return Err(KernelSecurityError::ScopeDenied(
                "Host cannot be empty".to_string(),
            ));
        }

        // Check for ASCII compliance & homoglyphs
        if !s.is_ascii() {
            return Err(KernelSecurityError::ScopeDenied(
                "Non-ASCII / IDNA homoglyph characters are strictly forbidden in target host"
                    .to_string(),
            ));
        }

        let lower = s.to_ascii_lowercase();

        let labels: Vec<&str> = lower.split('.').collect();
        if let Some(tld) = labels.last() {
            if !tld.is_empty() && tld.chars().all(|c| c.is_ascii_digit()) {
                return Err(KernelSecurityError::ScopeDenied(
                    "Top-level domain (TLD) cannot be all-numeric".to_string(),
                ));
            }
        }

        // Validate DNS label constraints
        for label in &labels {
            if label.is_empty() {
                return Err(KernelSecurityError::ScopeDenied(
                    "Empty label in domain name".to_string(),
                ));
            }
            if label.len() > 63 {
                return Err(KernelSecurityError::ScopeDenied(
                    "Domain label exceeds maximum 63 characters".to_string(),
                ));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(KernelSecurityError::ScopeDenied(
                    "Domain label contains invalid characters".to_string(),
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(KernelSecurityError::ScopeDenied(
                    "Domain label cannot start or end with a hyphen".to_string(),
                ));
            }
        }

        Ok(lower)
    }

    fn normalize_path(path: &str) -> String {
        let mut segments = Vec::new();
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                normal => segments.push(normal),
            }
        }
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4_parsing() {
        let t = TargetParser::parse("192.168.1.1").unwrap();
        assert_eq!(
            t,
            CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_ambiguous_ip_octal_rejected() {
        let res = TargetParser::parse("0177.0.0.1");
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_normalized_to_ipv4() {
        let t = TargetParser::parse("::ffff:127.0.0.1").unwrap();
        assert_eq!(
            t,
            CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[test]
    fn test_dns_trailing_dot_and_case_normalization() {
        let t = TargetParser::parse("ExAmPLe.CoM.").unwrap();
        assert_eq!(
            t,
            CanonicalTarget::Domain {
                domain: "example.com".to_string(),
                port: None,
            }
        );
    }

    #[test]
    fn test_url_userinfo_rejected() {
        let res = TargetParser::parse("http://attacker.com@target.com/");
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }

    #[test]
    fn test_url_host_confusion_backslash_rejected() {
        let res = TargetParser::parse("http://target.com\\attacker.com/");
        assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
    }

    #[test]
    fn test_url_path_traversal_normalized() {
        let t = TargetParser::parse("http://example.com/a/b/../c").unwrap();
        assert_eq!(
            t,
            CanonicalTarget::UrlOrigin {
                scheme: "http".to_string(),
                host: "example.com".to_string(),
                port: 80,
                path_prefix: Some("/a/c".to_string()),
            }
        );
    }
}
