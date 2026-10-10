//! Checkpoint P2-D: Connection-Time Network Enforcement & Pinned-Dialing Tests.
//!
//! Validates:
//! - GATE-SSRF-001 (CTRL-SSRF-001 / TEST-SSRF-001)
//! - GATE-DNS-REBIND-001 (CTRL-DNS-PINNING-001 / TEST-DNS-REBIND-001)
//! - GATE-METADATA-BLOCK-001 (CTRL-METADATA-BLOCK-001 / TEST-METADATA-001)
//! - GATE-IPV6-POLICY-001 (CTRL-IPV6-POLICY-001 / TEST-IPV6-BYPASS-001)

use arka_core_types::scope::{ScopeDefinition, ScopeRule};
use arka_network_policy::address::CanonicalIp;
use arka_network_policy::connector::DirectIpConnector;
use arka_network_policy::dns::MockDnsResolver;
use arka_network_policy::errors::NetworkPolicyError;
use arka_network_policy::params::ParameterValidator;
use arka_network_policy::validator::{PinnedDestination, ScopeGuard};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::net::TcpListener;

// -----------------------------------------------------------------------------
// GATE-SSRF-001 / TEST-SSRF-001: Private & Loopback IP Blocking
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_ssrf_loopback_denied_by_default() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let guard = ScopeGuard::new(mock_dns);

    // IPv4 Loopback literals
    let loopbacks = ["127.0.0.1", "127.0.0.2", "127.10.20.30"];
    for ip in loopbacks {
        let result = guard.validate_and_pin(ip, 80, None).await;
        assert!(
            matches!(result, Err(NetworkPolicyError::LoopbackBlocked(_))),
            "Expected LoopbackBlocked for {}",
            ip
        );
    }
}

#[tokio::test]
async fn test_ssrf_rfc1918_private_ips_denied_by_default() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let guard = ScopeGuard::new(mock_dns);

    let privates = [
        "10.0.0.1",
        "10.254.1.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.100.50",
    ];
    for ip in privates {
        let result = guard.validate_and_pin(ip, 80, None).await;
        assert!(
            matches!(result, Err(NetworkPolicyError::SsrfBlocked(_))),
            "Expected SsrfBlocked for RFC 1918 address {}",
            ip
        );
    }
}

#[tokio::test]
async fn test_ssrf_ambiguous_ip_representations_rejected() {
    // Octal representation (leading zeros)
    assert!(CanonicalIp::parse("0177.0.0.1").is_err());
    assert!(CanonicalIp::parse("127.0.0.01").is_err());

    // Hexadecimal representation
    assert!(CanonicalIp::parse("0x7f000001").is_err());
    assert!(CanonicalIp::parse("0x7f.0.0.1").is_err());
    assert!(CanonicalIp::parse("127.0.0.0x1").is_err());

    // Decimal integer representation
    assert!(CanonicalIp::parse("2130706433").is_err());
}

#[tokio::test]
async fn test_ssrf_ipv4_mapped_ipv6_normalized_and_denied() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let guard = ScopeGuard::new(mock_dns);

    // ::ffff:127.0.0.1 -> loopback
    let res1 = guard.validate_and_pin("::ffff:127.0.0.1", 80, None).await;
    assert!(matches!(res1, Err(NetworkPolicyError::LoopbackBlocked(_))));

    // ::ffff:10.0.0.1 -> RFC 1918 private
    let res2 = guard.validate_and_pin("::ffff:10.0.0.1", 80, None).await;
    assert!(matches!(res2, Err(NetworkPolicyError::SsrfBlocked(_))));
}

// -----------------------------------------------------------------------------
// GATE-METADATA-BLOCK-001 / TEST-METADATA-001: Cloud Instance Metadata Access
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_metadata_endpoint_hard_blocked() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let guard = ScopeGuard::new(mock_dns.clone());

    // AWS/GCP/Azure metadata literal
    let res = guard.validate_and_pin("169.254.169.254", 80, None).await;
    assert!(matches!(res, Err(NetworkPolicyError::MetadataBlocked(_))));

    // GCP internal metadata alias
    let res_gcp = guard.validate_and_pin("169.254.169.253", 80, None).await;
    assert!(matches!(
        res_gcp,
        Err(NetworkPolicyError::MetadataBlocked(_))
    ));

    // AWS IPv6 metadata
    let res_v6 = guard.validate_and_pin("fd00:ec2::254", 80, None).await;
    assert!(matches!(
        res_v6,
        Err(NetworkPolicyError::MetadataBlocked(_))
    ));

    // Domain name resolving to cloud metadata IP
    mock_dns
        .set_response(
            "instance-data.internal",
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        )
        .await;

    let res_domain = guard
        .validate_and_pin("instance-data.internal", 80, None)
        .await;
    assert!(matches!(
        res_domain,
        Err(NetworkPolicyError::MetadataBlocked(_))
    ));
}

// -----------------------------------------------------------------------------
// GATE-IPV6-POLICY-001 / TEST-IPV6-BYPASS-001: IPv6 Policy Alignment
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_loopback_and_link_local_denied() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let guard = ScopeGuard::new(mock_dns);

    // IPv6 Loopback
    let res_lo = guard.validate_and_pin("::1", 80, None).await;
    assert!(matches!(
        res_lo,
        Err(NetworkPolicyError::LoopbackBlocked(_))
    ));

    // IPv6 Link-Local
    let res_ll = guard.validate_and_pin("fe80::1", 80, None).await;
    assert!(matches!(
        res_ll,
        Err(NetworkPolicyError::LinkLocalBlocked(_))
    ));

    // IPv6 Documentation prefix
    let res_doc = guard.validate_and_pin("2001:db8::1", 80, None).await;
    assert!(matches!(
        res_doc,
        Err(NetworkPolicyError::Ipv6PolicyViolation(_))
    ));
}

#[tokio::test]
async fn test_ipv6_zone_identifier_rejected() {
    // Scoped literals (%eth0, %1) must be rejected
    let res = CanonicalIp::parse("fe80::1%eth0");
    assert!(matches!(res, Err(NetworkPolicyError::AmbiguousIpFormat(_))));
}

// -----------------------------------------------------------------------------
// GATE-DNS-REBIND-001 / TEST-DNS-REBIND-001: DNS Pinning & Rebinding Defense
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_pinning_single_resolution() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let target_host = "authorized.target.com";
    let target_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example public IP

    mock_dns.set_response(target_host, vec![target_ip]).await;
    let guard = ScopeGuard::new(mock_dns.clone());

    let pinned = guard
        .validate_and_pin(target_host, 443, None)
        .await
        .expect("Public domain should be validated and pinned");

    assert_eq!(pinned.ip, target_ip);
    assert_eq!(pinned.port, 443);
    assert_eq!(pinned.original_hostname.as_deref(), Some(target_host));

    // Assert resolver was queried exactly once
    assert_eq!(mock_dns.query_count(target_host).await, 1);
}

#[tokio::test]
async fn test_dns_multi_answer_mixed_private_fails_closed() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    let target_host = "mixed-rebind.target.com";

    // Adversary returns BOTH a public IP and 127.0.0.1 or 169.254.169.254
    mock_dns
        .set_response(
            target_host,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ],
        )
        .await;

    let guard = ScopeGuard::new(mock_dns);
    let result = guard.validate_and_pin(target_host, 80, None).await;

    // Must fail closed because one answer violates loopback policy
    assert!(
        matches!(result, Err(NetworkPolicyError::LoopbackBlocked(_))),
        "Multi-A record answer containing loopback must fail closed"
    );
}

#[tokio::test]
async fn test_direct_ip_connector_peer_verification() {
    // Bind a real local TCP listener on ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let pinned = PinnedDestination {
        ip: local_addr.ip(),
        port: local_addr.port(),
        original_hostname: Some("local.fixture".to_string()),
    };

    // Accept in background
    tokio::spawn(async move {
        if let Ok((_sock, _)) = listener.accept().await {
            // Keep socket alive briefly
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    });

    let stream = DirectIpConnector::connect(&pinned, 1000)
        .await
        .expect("Direct-IP connect must succeed");

    // Invariant: stream peer_addr must equal pinned IP
    assert_eq!(stream.peer_addr().unwrap().ip(), pinned.ip);
    assert_eq!(stream.peer_addr().unwrap().port(), pinned.port);
}

// -----------------------------------------------------------------------------
// Capability Parameter Injection Defense
// -----------------------------------------------------------------------------

#[test]
fn test_capability_parameter_injection_rejection() {
    // NUL byte injection
    assert!(ParameterValidator::validate_host("target.com\0evil.com").is_err());

    // CR / LF injection
    assert!(ParameterValidator::validate_host("target.com\r\nevil.com").is_err());

    // Shell metacharacters
    let shell_injections = [
        "target.com; rm -rf /",
        "target.com | cat /etc/passwd",
        "target.com & echo pwned",
        "target.com `id`",
        "$(whoami).target.com",
        "target.com > /tmp/out",
        "target.com < /dev/null",
        "target.com \\ evil",
    ];
    for inj in shell_injections {
        assert!(
            ParameterValidator::validate_host(inj).is_err(),
            "Shell injection '{}' should be rejected",
            inj
        );
    }

    // Invalid port 0
    assert!(ParameterValidator::validate_port(0).is_err());
    assert!(ParameterValidator::validate_port(80).is_ok());
    assert!(ParameterValidator::validate_port(65535).is_ok());
}

// -----------------------------------------------------------------------------
// Scope Inclusions & Exclusions Integration
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scope_exclusions_override_inclusions_at_dial_time() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "partner.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;

    let guard = ScopeGuard::new(mock_dns);

    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34,
        )))],
        exclusions: vec![ScopeRule::DomainExact("excluded.example.com".to_string())],
        allow_private_ranges: false,
    };

    // Excluded domain matches explicit exclusion -> denied
    let res = guard
        .validate_and_pin("excluded.example.com", 443, Some(&scope))
        .await;
    assert!(matches!(
        res,
        Err(NetworkPolicyError::ScopeViolation { .. })
    ));

    // partner.example.com matches inclusion -> allowed
    let res_ok = guard
        .validate_and_pin("partner.example.com", 80, Some(&scope))
        .await;
    assert!(res_ok.is_ok());
}
