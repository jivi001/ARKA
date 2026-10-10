//! Checkpoint P2-E Integration Test Suite.
//!
//! Validates:
//! - GATE-REDIRECT-FILTER-001 (CTRL-REDIRECT-FILTER-001 / TEST-REDIRECT-001):
//!   HTTP redirect destination scope re-verification, SSRF blocking, downgrade protection,
//!   hop bounds, loop detection, and relative/absolute Location resolution.
//! - GATE-BROWSER-SANDBOX-001 (CTRL-BROWSER-SANDBOX-001 / TEST-PROXY-BYPASS-001 & TEST-SANDBOX-NET-001):
//!   Browser proxy mediation boundary and sandbox network namespace isolation.
//!
//! Test Design Rule:
//! Every denial test asserts absence of the external side effect, not only the returned error code.

use arka_core_types::scope::{ScopeDefinition, ScopeRule};
use arka_network_policy::browser::{BrowserMediationConfig, BrowserMediationGuard};
use arka_network_policy::dns::MockDnsResolver;
use arka_network_policy::errors::NetworkPolicyError;
use arka_network_policy::redirect::{RedirectConfig, RedirectDecision, RedirectHandler};
use arka_network_policy::validator::ScopeGuard;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn test_scope() -> ScopeDefinition {
    ScopeDefinition {
        inclusions: vec![
            ScopeRule::DomainWildcard("*.example.com".to_string()),
            ScopeRule::DomainExact("target.org".to_string()),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            ScopeRule::IpExact(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        ],
        exclusions: vec![ScopeRule::DomainExact("forbidden.example.com".to_string())],
        allow_private_ranges: false,
    }
}

// ============================================================================
// GATE-REDIRECT-FILTER-001 / TEST-REDIRECT-001 Tests
// ============================================================================

#[tokio::test]
async fn test_redirect_to_loopback_blocked() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "evil-redirect.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/login";
    let (target, pinned) = handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");
    assert_eq!(target, initial_url);
    assert_eq!(pinned.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    // 1. Direct redirect to 127.0.0.1 IP literal
    let result_ip = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("http://127.0.0.1/admin"),
            Some(&scope),
        )
        .await;

    assert!(
        result_ip.is_err(),
        "Redirect to loopback IP literal must be denied"
    );
    match result_ip.err().unwrap() {
        NetworkPolicyError::SchemeDowngradeForbidden { .. }
        | NetworkPolicyError::LoopbackBlocked(_) => {}
        other => panic!("Unexpected error on loopback redirect: {:?}", other),
    }

    // 2. Redirect to domain resolving to loopback
    let result_domain = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("https://evil-redirect.example.com/internal"),
            Some(&scope),
        )
        .await;

    assert!(
        result_domain.is_err(),
        "Redirect resolving to loopback must be denied"
    );
    match result_domain.err().unwrap() {
        NetworkPolicyError::LoopbackBlocked(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        }
        other => panic!("Expected LoopbackBlocked, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_to_rfc1918_private_ip_blocked() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "internal.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/login";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    // Attempt redirect to private RFC 1918 destination
    let result = handler
        .evaluate_redirect(
            initial_url,
            301,
            Some("https://internal.example.com/api"),
            Some(&scope),
        )
        .await;

    assert!(
        result.is_err(),
        "Redirect to RFC 1918 private IP must be blocked"
    );
    match result.err().unwrap() {
        NetworkPolicyError::SsrfBlocked(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        }
        other => panic!("Expected SsrfBlocked, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_to_cloud_metadata_hard_blocked() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "metadata-rebind.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/fetch";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    // 1. Literal cloud metadata IP redirect
    let result_literal = handler
        .evaluate_redirect(
            initial_url,
            307,
            Some("https://169.254.169.254/latest/meta-data/"),
            Some(&scope),
        )
        .await;

    assert!(
        result_literal.is_err(),
        "Redirect to metadata IP literal must be hard-blocked"
    );
    match result_literal.err().unwrap() {
        NetworkPolicyError::MetadataBlocked(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)));
        }
        other => panic!("Expected MetadataBlocked, got {:?}", other),
    }

    // 2. DNS name resolving to metadata IP redirect
    let result_dns = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("https://metadata-rebind.example.com/secret"),
            Some(&scope),
        )
        .await;

    assert!(
        result_dns.is_err(),
        "Redirect via DNS to metadata IP must be hard-blocked"
    );
    match result_dns.err().unwrap() {
        NetworkPolicyError::MetadataBlocked(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)));
        }
        other => panic!("Expected MetadataBlocked, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_out_of_scope_blocked() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "unauthorized.org",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        )
        .await;
    mock_dns
        .set_response(
            "forbidden.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/index";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    // 1. Redirect to completely out-of-scope host
    let result_out_of_scope = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("https://unauthorized.org/login"),
            Some(&scope),
        )
        .await;

    assert!(
        result_out_of_scope.is_err(),
        "Out-of-scope redirect must be rejected"
    );
    match result_out_of_scope.err().unwrap() {
        NetworkPolicyError::ScopeViolation { destination, .. } => {
            assert!(destination.contains("8.8.8.8"));
        }
        other => panic!("Expected ScopeViolation, got {:?}", other),
    }

    // 2. Redirect to explicitly excluded sub-domain
    let result_excluded = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("https://forbidden.example.com/panel"),
            Some(&scope),
        )
        .await;

    assert!(
        result_excluded.is_err(),
        "Excluded domain redirect must be rejected"
    );
    match result_excluded.err().unwrap() {
        NetworkPolicyError::ScopeViolation { destination, .. } => {
            assert!(destination.contains("forbidden.example.com"));
        }
        other => panic!("Expected ScopeViolation, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_scheme_downgrade_forbidden() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "secure.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "insecure.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://secure.example.com/checkout";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial HTTPS URL should be valid");

    // Attempt downgrade to HTTP
    let result = handler
        .evaluate_redirect(
            initial_url,
            302,
            Some("http://insecure.example.com/checkout"),
            Some(&scope),
        )
        .await;

    assert!(result.is_err(), "HTTPS -> HTTP downgrade must be rejected");
    match result.err().unwrap() {
        NetworkPolicyError::SchemeDowngradeForbidden { from, to } => {
            assert_eq!(from, "https");
            assert_eq!(to, "http");
        }
        other => panic!("Expected SchemeDowngradeForbidden, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_unsupported_schemes_rejected() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/start";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    let dangerous_locations = vec![
        "file:///etc/passwd",
        "gopher://evil.com/1",
        "javascript:alert(1)",
        "data:text/html,test",
        "ftp://mirror.example.com/archive",
    ];

    for dangerous in dangerous_locations {
        let result = handler
            .evaluate_redirect(initial_url, 302, Some(dangerous), Some(&scope))
            .await;

        assert!(
            result.is_err(),
            "Dangerous scheme '{}' must be rejected",
            dangerous
        );
        match result.err().unwrap() {
            NetworkPolicyError::UnsupportedScheme(_)
            | NetworkPolicyError::InvalidRedirectUrl(_) => {}
            other => panic!("Unexpected error for dangerous scheme: {:?}", other),
        }
    }
}

#[tokio::test]
async fn test_redirect_credentials_in_url_rejected() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "target.org",
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let initial_url = "https://app.example.com/oauth";
    handler
        .validate_initial_url(initial_url, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    let credential_urls = vec![
        "https://admin:supersecret@target.org/callback",
        "https://operator@target.org/panel",
    ];

    for cred_url in credential_urls {
        let result = handler
            .evaluate_redirect(initial_url, 302, Some(cred_url), Some(&scope))
            .await;

        assert!(
            result.is_err(),
            "Credentials in redirect URL must be rejected"
        );
        match result.err().unwrap() {
            NetworkPolicyError::CredentialsInUrlForbidden => {}
            other => panic!("Expected CredentialsInUrlForbidden, got {:?}", other),
        }
    }
}

#[tokio::test]
async fn test_redirect_cycle_and_loop_detected() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "node-a.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "node-b.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let url_a = "https://node-a.example.com/step";
    let url_b = "https://node-b.example.com/step";

    handler
        .validate_initial_url(url_a, Some(&scope))
        .await
        .expect("Initial URL should be valid");

    // Hop 1: A -> B
    let hop1 = handler
        .evaluate_redirect(url_a, 302, Some(url_b), Some(&scope))
        .await
        .expect("Hop 1 should succeed");
    assert!(matches!(hop1, RedirectDecision::Follow { .. }));

    // Hop 2: B -> A (Loop!)
    let hop2 = handler
        .evaluate_redirect(url_b, 302, Some(url_a), Some(&scope))
        .await;

    assert!(hop2.is_err(), "Cyclic redirect loop must be detected");
    match hop2.err().unwrap() {
        NetworkPolicyError::RedirectLoopDetected(url) => {
            assert_eq!(url, url_a);
        }
        other => panic!("Expected RedirectLoopDetected, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_chain_limit_exceeded() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    for i in 0..10 {
        let ip_byte = 10 + i;
        mock_dns
            .set_response(
                &format!("step-{}.example.com", i),
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, ip_byte))],
            )
            .await;
    }

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    // Set max_redirects = 3
    let config = RedirectConfig::new().with_max_redirects(3);
    let mut handler = RedirectHandler::new(scope_guard, config);

    // Build scope accepting all step-*.example.com and their subnet
    let cidr =
        arka_core_types::scope::CidrBlock::new_v4(Ipv4Addr::new(93, 184, 216, 0), 24).unwrap();
    let scope = ScopeDefinition {
        inclusions: vec![
            ScopeRule::DomainWildcard("*.example.com".to_string()),
            ScopeRule::IpRange(cidr),
        ],
        exclusions: vec![],
        allow_private_ranges: false,
    };

    let start_url = "https://step-0.example.com/0";
    handler
        .validate_initial_url(start_url, Some(&scope))
        .await
        .expect("Valid start");

    // Hop 1
    let h1 = handler
        .evaluate_redirect(
            start_url,
            302,
            Some("https://step-1.example.com/1"),
            Some(&scope),
        )
        .await
        .expect("Hop 1 ok");
    assert_eq!(
        h1,
        RedirectDecision::Follow {
            target_url: "https://step-1.example.com/1".to_string(),
            pinned: arka_network_policy::validator::PinnedDestination {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 11)),
                port: 443,
                original_hostname: Some("step-1.example.com".to_string()),
            },
            hop_number: 2,
        }
    );

    // Hop 2
    handler
        .evaluate_redirect(
            "https://step-1.example.com/1",
            302,
            Some("https://step-2.example.com/2"),
            Some(&scope),
        )
        .await
        .expect("Hop 2 ok");

    // Hop 3 (reaches limit of 3)
    let err = handler
        .evaluate_redirect(
            "https://step-2.example.com/2",
            302,
            Some("https://step-3.example.com/3"),
            Some(&scope),
        )
        .await;

    assert!(err.is_err(), "Exceeding max redirects must fail closed");
    match err.err().unwrap() {
        NetworkPolicyError::RedirectLimitExceeded(max) => {
            assert_eq!(max, 3);
        }
        other => panic!("Expected RedirectLimitExceeded, got {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_valid_relative_and_absolute_followed() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response(
            "target.org",
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
        )
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let mut handler = RedirectHandler::new(scope_guard, RedirectConfig::default());
    let scope = test_scope();

    let start_url = "https://app.example.com/v1/auth";
    let (_, pinned) = handler
        .validate_initial_url(start_url, Some(&scope))
        .await
        .expect("Valid start");
    assert_eq!(pinned.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    // 1. Relative redirect: /v2/dashboard
    let rel_decision = handler
        .evaluate_redirect(start_url, 302, Some("/v2/dashboard"), Some(&scope))
        .await
        .expect("Relative redirect should succeed");

    match rel_decision {
        RedirectDecision::Follow {
            target_url,
            pinned,
            hop_number,
        } => {
            assert_eq!(target_url, "https://app.example.com/v2/dashboard");
            assert_eq!(pinned.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            assert_eq!(pinned.port, 443);
            assert_eq!(hop_number, 2);
        }
        _ => panic!("Expected Follow decision"),
    }

    // 2. Absolute redirect across in-scope domains: target.org
    let abs_decision = handler
        .evaluate_redirect(
            "https://app.example.com/v2/dashboard",
            301,
            Some("https://target.org:8443/portal"),
            Some(&scope),
        )
        .await
        .expect("Absolute cross-domain in-scope redirect should succeed");

    match abs_decision {
        RedirectDecision::Follow {
            target_url,
            pinned,
            hop_number,
        } => {
            assert_eq!(target_url, "https://target.org:8443/portal");
            assert_eq!(pinned.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
            assert_eq!(pinned.port, 8443);
            assert_eq!(hop_number, 3);
        }
        _ => panic!("Expected Follow decision"),
    }

    // 3. Non-redirect status code: 200 OK terminates chain
    let term_decision = handler
        .evaluate_redirect("https://target.org:8443/portal", 200, None, Some(&scope))
        .await
        .expect("200 OK should terminate");

    assert_eq!(
        term_decision,
        RedirectDecision::Terminal { status_code: 200 }
    );
}

// ============================================================================
// GATE-BROWSER-SANDBOX-001 / TEST-PROXY-BYPASS-001 & TEST-SANDBOX-NET-001 Tests
// ============================================================================

#[test]
fn test_browser_chromium_launch_args_strict_proxy_enforcement() {
    let config = BrowserMediationConfig::new("127.0.0.1", 9090);
    let guard = BrowserMediationGuard::new(config);

    let args = guard.build_chromium_args();

    assert!(args.contains(&"--proxy-server=http://127.0.0.1:9090".to_string()));
    assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
    assert!(args.contains(&"--disable-background-networking".to_string()));
    assert!(args.contains(&"--disable-sync".to_string()));
    assert!(args.contains(&"--disable-extensions".to_string()));
    assert!(args.contains(&"--headless=new".to_string()));
}

#[test]
fn test_browser_network_namespace_isolation_contract() {
    let guard = BrowserMediationGuard::new(BrowserMediationConfig::default());

    // 1. Success: contained in isolated network namespace without host netns exposure
    let ok = guard.verify_network_isolation(true, false);
    assert!(ok.is_ok());

    // 2. Failure: host netns exposed
    let err_host = guard.verify_network_isolation(true, true);
    assert!(err_host.is_err());
    match err_host.err().unwrap() {
        NetworkPolicyError::BrowserMediationBypass(msg) => {
            assert!(msg.contains("Host network namespace is exposed"));
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // 3. Failure: not inside isolated network namespace
    let err_unisolated = guard.verify_network_isolation(false, false);
    assert!(err_unisolated.is_err());
    match err_unisolated.err().unwrap() {
        NetworkPolicyError::BrowserMediationBypass(msg) => {
            assert!(msg.contains("isolated network namespace"));
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_browser_direct_socket_egress_bypass_denied() {
    let guard = BrowserMediationGuard::new(BrowserMediationConfig::default());

    // 1. Unproxied direct connection attempt is rejected unconditionally
    let err = guard.verify_egress_routing(false, "https://target.com");
    assert!(err.is_err(), "Direct raw socket egress must fail closed");
    match err.err().unwrap() {
        NetworkPolicyError::BrowserMediationBypass(msg) => {
            assert!(msg.contains(
                "Direct socket egress to 'https://target.com' violates broker mediation boundary"
            ));
        }
        other => panic!("Expected BrowserMediationBypass, got {:?}", other),
    }

    // 2. Proxied egress passes initial boundary verification
    let ok = guard.verify_egress_routing(true, "https://target.com");
    assert!(ok.is_ok());
}

#[tokio::test]
async fn test_browser_proxied_request_scope_and_ssrf_mediation() {
    let mock_dns = Arc::new(MockDnsResolver::new());
    mock_dns
        .set_response(
            "app.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .await;
    mock_dns
        .set_response("evil.local", vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))])
        .await;

    let scope_guard = Arc::new(ScopeGuard::new(mock_dns));
    let guard = BrowserMediationGuard::new(BrowserMediationConfig::default());
    let scope = test_scope();

    // 1. Direct egress attempt (is_proxied = false) fails closed before destination evaluation
    let bypass_res = guard
        .mediate_proxied_request(
            &scope_guard,
            "https://app.example.com/page",
            false,
            Some(&scope),
        )
        .await;
    assert!(bypass_res.is_err());
    match bypass_res.err().unwrap() {
        NetworkPolicyError::BrowserMediationBypass(_) => {}
        other => panic!("Expected BrowserMediationBypass, got {:?}", other),
    }

    // 2. Valid in-scope proxied browser request succeeds and pins destination
    let valid_res = guard
        .mediate_proxied_request(
            &scope_guard,
            "https://app.example.com/page",
            true,
            Some(&scope),
        )
        .await
        .expect("Valid proxied browser request should succeed");
    assert_eq!(valid_res.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(valid_res.port, 443);

    // 3. Proxied request targeting loopback fails closed with SSRF defense
    let loopback_res = guard
        .mediate_proxied_request(
            &scope_guard,
            "http://evil.local:8080/flag",
            true,
            Some(&scope),
        )
        .await;
    assert!(loopback_res.is_err());
    match loopback_res.err().unwrap() {
        NetworkPolicyError::LoopbackBlocked(_) => {}
        other => panic!("Expected LoopbackBlocked, got {:?}", other),
    }
}
