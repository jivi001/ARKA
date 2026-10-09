//! Blocked IP range predicates and SSRF/Metadata defenses.
//!
//! Enforces:
//! - GATE-SSRF-001 (CTRL-SSRF-001): Private RFC 1918 and loopback blocked by default.
//! - GATE-METADATA-BLOCK-001 (CTRL-METADATA-BLOCK-001): Cloud instance metadata blocked.
//! - GATE-IPV6-POLICY-001 (CTRL-IPV6-POLICY-001): Unscoped/link-local IPv6 blocked.

use crate::errors::NetworkPolicyError;
use std::net::{IpAddr, Ipv6Addr};

pub struct BlockedRanges;

impl BlockedRanges {
    /// Evaluates an IP address against authoritative platform security boundaries.
    ///
    /// If `allow_private` is true, RFC 1918 addresses are permitted (subject to explicit mission scope),
    pub fn check_ip(ip: &IpAddr, allow_private: bool) -> Result<(), NetworkPolicyError> {
        Self::check_ip_with_options(ip, allow_private, false)
    }

    pub fn check_ip_with_options(
        ip: &IpAddr,
        allow_private: bool,
        allow_loopback: bool,
    ) -> Result<(), NetworkPolicyError> {
        // 1. Cloud Metadata Hard-Block (Highest Priority: Non-Bypassable)
        if Self::is_cloud_metadata(ip) {
            return Err(NetworkPolicyError::MetadataBlocked(*ip));
        }

        // 2. Loopback Block (unless explicitly allowed for local testing)
        if !allow_loopback && Self::is_loopback(ip) {
            return Err(NetworkPolicyError::LoopbackBlocked(*ip));
        }

        // 3. Link-Local Block (169.254.0.0/16 or fe80::/10)
        if Self::is_link_local(ip) {
            return Err(NetworkPolicyError::LinkLocalBlocked(*ip));
        }

        // 4. RFC 1918 Private Address Block (SSRF Protection)
        if !allow_private && Self::is_private(ip) {
            return Err(NetworkPolicyError::SsrfBlocked(*ip));
        }

        // 5. IPv6 Policy Checks
        if let IpAddr::V6(v6) = ip {
            if Self::is_disallowed_ipv6(v6) {
                return Err(NetworkPolicyError::Ipv6PolicyViolation(*ip));
            }
        }

        // 6. Broadcast, Unspecified, or Multicast
        if Self::is_unspecified_or_multicast(ip) {
            return Err(NetworkPolicyError::AmbiguousIpFormat(format!(
                "Unspecified or multicast address {} cannot be an execution destination",
                ip
            )));
        }

        Ok(())
    }

    pub fn is_cloud_metadata(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                // AWS/GCP/Azure/DigitalOcean metadata IP: 169.254.169.254
                // GCP metadata server internal alias: 169.254.169.253, 169.254.169.252
                let octets = v4.octets();
                octets[0] == 169 && octets[1] == 254 && octets[2] == 169 && octets[3] >= 250
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                // AWS IPv6 metadata: fd00:ec2::254
                (seg[0] == 0xfd00 && seg[1] == 0x0ec2 && seg[7] == 0x0254)
                    // General ULA metadata probe
                    || (seg[0] == 0xfd00 && seg[1] == 0x0ec2)
            }
        }
    }

    pub fn is_loopback(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 127,
            IpAddr::V6(v6) => v6.is_loopback() || *v6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        }
    }

    pub fn is_link_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => {
                // fe80::/10 (segments[0] & 0xffc0 == 0xfe80)
                (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    pub fn is_private(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                // 10.0.0.0/8
                oct[0] == 10
                // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
                || (oct[0] == 172 && oct[1] >= 16 && oct[1] <= 31)
                // 192.168.0.0/16
                || (oct[0] == 192 && oct[1] == 168)
            }
            IpAddr::V6(v6) => {
                // Unique Local Address (fc00::/7)
                (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    pub fn is_disallowed_ipv6(v6: &Ipv6Addr) -> bool {
        let seg = v6.segments();
        // Disallow Documentation prefixes (2001:db8::/32)
        (seg[0] == 0x2001 && seg[1] == 0x0db8)
        // Disallow Discard prefix (100::/64)
        || (seg[0] == 0x0100 && seg[1] == 0)
        // Disallow Teredo (2001::/32)
        || (seg[0] == 0x2001 && seg[1] == 0)
        // Disallow 6to4 (2002::/16)
        || (seg[0] == 0x2002)
    }

    pub fn is_unspecified_or_multicast(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
        }
    }
}
