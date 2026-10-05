//! Checkpoint P1-B Security Test Suite: Scope Engine & Bypass Defense
//!
//! Validates:
//! - Canonical Scope Representation & Evaluation (TEST-SCOPE-*)
//! - Ambiguous IP Format Rejection (Octal, Hex, Decimal Integer)
//! - IPv4-Mapped IPv6 Normalization
//! - DNS Normalization & Homoglyph Defense
//! - URL Userinfo & Host Confusion Bypass Defense
//! - Scope Precedence: Exclusions Override Inclusions
//! - SSRF and Cloud Metadata Protection

use arka_core_types::errors::KernelSecurityError;
use arka_core_types::scope::{CanonicalTarget, CidrBlock, ScopeDefinition, ScopeRule};
use arka_kernel::scope::{ScopeEngine, TargetParser};
use std::net::{IpAddr, Ipv4Addr};

// ---------------------------------------------------------------------------
// TEST-SCOPE-IP-* : IP & CIDR Bypass Tests
// ---------------------------------------------------------------------------

#[test]
fn test_scope_ip_001_canonical_cidr_matching() {
    let cidr = CidrBlock::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpRange(cidr)],
        exclusions: vec![],
        allow_private_ranges: true,
    };

    let target_in = TargetParser::parse("192.168.1.50").unwrap();
    let target_out = TargetParser::parse("192.168.2.50").unwrap();

    assert!(ScopeEngine::evaluate(&scope, &target_in).is_ok());
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &target_out),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_ip_002_ambiguous_ip_representations_rejected() {
    // Octal representations
    assert!(matches!(
        TargetParser::parse("0177.0.0.1"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("127.000.000.001"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Hex representations
    assert!(matches!(
        TargetParser::parse("0x7f.0.0.1"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("0x7f000001"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Decimal integer
    assert!(matches!(
        TargetParser::parse("2130706433"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Overflow / invalid octets
    assert!(matches!(
        TargetParser::parse("256.0.0.1"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("1.2.3"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_ip_003_ipv4_mapped_ipv6_normalized_against_evasion() {
    // If an exclusion blocks 127.0.0.1, ::ffff:127.0.0.1 MUST NOT bypass it
    let target = TargetParser::parse("::ffff:127.0.0.1").unwrap();
    assert_eq!(
        target,
        CanonicalTarget::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );

    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpRange(
            CidrBlock::new_v4(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        )],
        exclusions: vec![ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))],
        allow_private_ranges: true,
    };

    // Must be DENIED because it was normalized to 127.0.0.1 which matches the exclusion
    let res = ScopeEngine::evaluate(&scope, &target);
    assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
}

// ---------------------------------------------------------------------------
// TEST-SCOPE-DNS-* : DNS Normalization & Bypass Tests
// ---------------------------------------------------------------------------

#[test]
fn test_scope_dns_001_normalization_case_and_trailing_dot() {
    let t1 = TargetParser::parse("TaRgEt.ExAmPlE.CoM.").unwrap();
    let t2 = TargetParser::parse("target.example.com").unwrap();

    assert_eq!(t1, t2);

    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::DomainExact("target.example.com".to_string())],
        exclusions: vec![],
        allow_private_ranges: false,
    };

    assert!(ScopeEngine::evaluate(&scope, &t1).is_ok());
    assert!(ScopeEngine::evaluate(&scope, &t2).is_ok());
}

#[test]
fn test_scope_dns_002_wildcard_matching() {
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::DomainWildcard("*.corp.internal".to_string())],
        exclusions: vec![ScopeRule::DomainExact("secret.corp.internal".to_string())],
        allow_private_ranges: false,
    };

    let allowed = TargetParser::parse("api.corp.internal").unwrap();
    let allowed_nested = TargetParser::parse("sub.api.corp.internal").unwrap();
    let excluded = TargetParser::parse("secret.corp.internal").unwrap();
    let sibling = TargetParser::parse("evilcorp.internal").unwrap();

    assert!(ScopeEngine::evaluate(&scope, &allowed).is_ok());
    assert!(ScopeEngine::evaluate(&scope, &allowed_nested).is_ok());

    // Excluded matches exclusion -> DENY
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &excluded),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Sibling is not a subdomain -> DENY
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &sibling),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_dns_003_homoglyphs_and_invalid_labels_rejected() {
    // Non-ASCII Cyrillic homoglyph (looks like 'apple.com' but 'а' is U+0430 Cyrillic small letter a)
    let homoglyph = "\u{0430}pple.com";
    assert!(matches!(
        TargetParser::parse(homoglyph),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Whitespace and control chars
    assert!(matches!(
        TargetParser::parse("example .com"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("example\0.com"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Label starting with hyphen
    assert!(matches!(
        TargetParser::parse("-bad.example.com"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

// ---------------------------------------------------------------------------
// TEST-SCOPE-URL-* : URL Origin Bypass Tests
// ---------------------------------------------------------------------------

#[test]
fn test_scope_url_001_userinfo_rejected() {
    // Host spoofing via userinfo (e.g. http://google.com@attacker.com)
    assert!(matches!(
        TargetParser::parse("http://authorized.com@evil.com/"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Embedded credentials
    assert!(matches!(
        TargetParser::parse("https://admin:pass@authorized.com/api"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_url_002_host_confusion_rejected() {
    // Backslash tricks
    assert!(matches!(
        TargetParser::parse("http://authorized.com\\evil.com"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Non-HTTP schemes
    assert!(matches!(
        TargetParser::parse("gopher://target.com/"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("file:///etc/passwd"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        TargetParser::parse("javascript:alert(1)"),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_url_003_port_and_path_normalization() {
    let t_default = TargetParser::parse("https://api.example.com/v1").unwrap();
    let t_explicit = TargetParser::parse("https://api.example.com:443/v1").unwrap();

    assert_eq!(t_default, t_explicit);

    // Path traversal normalization
    let t_traversal = TargetParser::parse("https://api.example.com/v1/../v2/endpoint").unwrap();
    if let CanonicalTarget::UrlOrigin { path_prefix, .. } = t_traversal {
        assert_eq!(path_prefix, Some("/v2/endpoint".to_string()));
    } else {
        panic!("Expected UrlOrigin");
    }
}

// ---------------------------------------------------------------------------
// TEST-SCOPE-INVARIANTS-* : Invariants & Security Boundaries
// ---------------------------------------------------------------------------

#[test]
fn test_scope_invariant_exclusions_override_inclusions() {
    let scope = ScopeDefinition {
        inclusions: vec![
            ScopeRule::DomainWildcard("*.example.com".to_string()),
            ScopeRule::IpRange(CidrBlock::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()),
        ],
        exclusions: vec![
            ScopeRule::DomainExact("admin.example.com".to_string()),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        ],
        allow_private_ranges: true,
    };

    let allowed_domain = TargetParser::parse("app.example.com").unwrap();
    let excluded_domain = TargetParser::parse("admin.example.com").unwrap();
    let allowed_ip = TargetParser::parse("10.5.5.5").unwrap();
    let excluded_ip = TargetParser::parse("10.1.2.3").unwrap();

    assert!(ScopeEngine::evaluate(&scope, &allowed_domain).is_ok());
    assert!(ScopeEngine::evaluate(&scope, &allowed_ip).is_ok());

    assert!(matches!(
        ScopeEngine::evaluate(&scope, &excluded_domain),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &excluded_ip),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_invariant_cloud_metadata_and_ssrf_blocked_by_default() {
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::IpRange(
            CidrBlock::new_v4(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
        )],
        exclusions: vec![],
        allow_private_ranges: false, // Default deny restricted addresses
    };

    // AWS/GCP/Azure Metadata 169.254.169.254
    let metadata_target = TargetParser::parse("169.254.169.254").unwrap();
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &metadata_target),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // Loopback 127.0.0.1
    let loopback = TargetParser::parse("127.0.0.1").unwrap();
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &loopback),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // IPv6 Loopback ::1
    let loopback_v6 = TargetParser::parse("::1").unwrap();
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &loopback_v6),
        Err(KernelSecurityError::ScopeDenied(_))
    ));

    // RFC 1918 Private IP
    let private_v4 = TargetParser::parse("10.0.0.1").unwrap();
    assert!(matches!(
        ScopeEngine::evaluate(&scope, &private_v4),
        Err(KernelSecurityError::ScopeDenied(_))
    ));
}

#[test]
fn test_scope_invariant_discovered_not_authorized() {
    // An asset discovered during testing is NOT authorized unless scope explicitly includes it
    let scope = ScopeDefinition {
        inclusions: vec![ScopeRule::DomainExact("authorized-target.com".to_string())],
        exclusions: vec![],
        allow_private_ranges: false,
    };

    let discovered_pivot = TargetParser::parse("internal-db.corp").unwrap();
    let res = ScopeEngine::evaluate(&scope, &discovered_pivot);
    assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
}
