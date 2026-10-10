//! Canonical IP Address Parsing and Negative Bypass Rejection.
//!
//! Enforces:
//! - Strict rejection of octal notation (e.g. `0177.0.0.1`, leading zeros)
//! - Strict rejection of hexadecimal notation (e.g. `0x7f000001`, `0x7f.0.0.1`)
//! - Strict rejection of pure decimal integer representations (e.g. `2130706433`)
//! - Strict rejection of IPv6 zone identifiers / scoped literals (e.g. `fe80::1%eth0`)
//! - Unconditional normalization of IPv4-mapped IPv6 (`::ffff:127.0.0.1` -> `127.0.0.1`)

use crate::errors::NetworkPolicyError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct CanonicalIp;

impl CanonicalIp {
    /// Parses an untrusted IP address string into a validated canonical `IpAddr`.
    ///
    /// Rejects evasion forms before standard OS socket ingestion.
    pub fn parse(raw: &str) -> Result<IpAddr, NetworkPolicyError> {
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err(NetworkPolicyError::AmbiguousIpFormat(
                "IP string cannot be empty".to_string(),
            ));
        }

        // 1. Reject IPv6 Zone Identifiers / Scoped Literals (%interface)
        if trimmed.contains('%') {
            return Err(NetworkPolicyError::AmbiguousIpFormat(
                "IPv6 zone identifiers / scoped interface literals (%...) are strictly forbidden"
                    .to_string(),
            ));
        }

        // 2. Reject Hexadecimal representations (0x7f..., 0X...)
        if trimmed.starts_with("0x")
            || trimmed.starts_with("0X")
            || trimmed.contains(".0x")
            || trimmed.contains(".0X")
        {
            return Err(NetworkPolicyError::AmbiguousIpFormat(
                "Hexadecimal IP representations are strictly forbidden".to_string(),
            ));
        }

        // 3. Reject Pure Decimal Integer IP representations (e.g. 2130706433)
        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(NetworkPolicyError::AmbiguousIpFormat(
                "Decimal integer IP representations are strictly forbidden".to_string(),
            ));
        }

        // 4. Check for Dotted IPv4 notation evasion (leading zeros / octal notation)
        if trimmed.contains('.') && !trimmed.contains(':') {
            let segments: Vec<&str> = trimmed.split('.').collect();
            if segments.len() != 4 {
                return Err(NetworkPolicyError::AmbiguousIpFormat(
                    "IPv4 must contain exactly 4 dotted segments".to_string(),
                ));
            }

            for seg in &segments {
                if seg.is_empty() {
                    return Err(NetworkPolicyError::AmbiguousIpFormat(
                        "Empty segment in IPv4 address".to_string(),
                    ));
                }
                // Reject leading zeros in multi-digit segments (octal representation)
                if seg.len() > 1 && seg.starts_with('0') {
                    return Err(NetworkPolicyError::AmbiguousIpFormat(format!(
                        "Ambiguous octal leading-zero representation in segment '{}' rejected",
                        seg
                    )));
                }
                // Ensure all characters in segment are ascii digits
                if !seg.chars().all(|c| c.is_ascii_digit()) {
                    return Err(NetworkPolicyError::AmbiguousIpFormat(format!(
                        "Non-numeric character in IPv4 segment '{}'",
                        seg
                    )));
                }
            }

            let ipv4 = Ipv4Addr::from_str(trimmed).map_err(|e| {
                NetworkPolicyError::AmbiguousIpFormat(format!("Failed to parse IPv4: {}", e))
            })?;
            return Ok(IpAddr::V4(ipv4));
        }

        // 5. Parse IPv6 (or bracketed IPv6)
        let cleaned_ipv6 = trimmed.trim_start_matches('[').trim_end_matches(']');
        let parsed = IpAddr::from_str(cleaned_ipv6).map_err(|e| {
            NetworkPolicyError::AmbiguousIpFormat(format!("Invalid IP format '{}': {}", trimmed, e))
        })?;

        // 6. Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1) to standard IPv4
        match parsed {
            IpAddr::V4(v4) => Ok(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                if let Some(v4) = Self::extract_ipv4_mapped(&v6) {
                    Ok(IpAddr::V4(v4))
                } else {
                    Ok(IpAddr::V6(v6))
                }
            }
        }
    }

    /// Extracts mapped IPv4 address from an IPv6 address if it represents `::ffff:x.x.x.x`
    fn extract_ipv4_mapped(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
        let segments = v6.segments();
        // ::ffff:a.b.c.d has segments [0, 0, 0, 0, 0, 0xffff, high, low]
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0xffff
        {
            let high = segments[6];
            let low = segments[7];
            let octets = [
                (high >> 8) as u8,
                (high & 0xff) as u8,
                (low >> 8) as u8,
                (low & 0xff) as u8,
            ];
            Some(Ipv4Addr::from(octets))
        } else {
            None
        }
    }
}
