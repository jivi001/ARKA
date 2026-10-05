//! Checkpoint P1-C Security Test Suite: Capabilities, Actions & Normalization Boundary
//!
//! Validates:
//! - Authoritative Risk Derivation (INV-005)
//! - Capability Registry & Unrestricted SHELL Prohibition (TRD Section 8)
//! - Canonical Action Construction & Hash Determinism (INV-006, Section 13)
//! - Strict JSON Validation: Duplicate Keys, Depth, Unknown Fields, Size Limits (Section 14)
//! - Single Normalization Boundary & Mission Binding (Section 15, INV-004)

use arka_core_types::capabilities::{CapabilityMetadata, RiskClass, TargetClass};
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::{CapabilityId, MissionId, OperatorId, TaskId, TokenId};
use arka_core_types::subject::{AuthenticatedContext, Subject};
use arka_kernel::actions::ActionNormalizer;
use arka_kernel::capabilities::StandardCapabilityRegistry;
use serde_json::json;
use std::sync::Arc;

fn create_test_context(mission: &str, caps: Vec<&str>) -> AuthenticatedContext {
    AuthenticatedContext {
        token_id: TokenId::new("tok-p1c-01").unwrap(),
        subject: Subject::Operator(OperatorId::new("opr-analyst").unwrap()),
        mission_id: MissionId::new(mission).unwrap(),
        parent_task_id: Some(TaskId::new("tsk-parent-01").unwrap()),
        capabilities: caps
            .into_iter()
            .map(|c| CapabilityId::new(c).unwrap())
            .collect(),
        scope_ref: "scope-p1c".to_string(),
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        parent_token_id: None,
    }
}

// ---------------------------------------------------------------------------
// TEST-CAP-* : Capability Registry & Risk Derivation
// ---------------------------------------------------------------------------

#[test]
fn test_cap_001_authoritative_risk_derivation() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-cap-01", vec!["PORT_SCAN"]);

    // Raw proposal omitting risk -> risk is derived as MODERATE from registry
    let proposal_json = json!({
        "proposal_id": "prp-001",
        "mission_id": "mis-cap-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": { "ports": [80, 443] },
        "nonce": "abcdef0123456789abcdef0123456789"
    })
    .to_string();

    let action = normalizer
        .normalize_from_json(&proposal_json, &ctx)
        .unwrap();
    assert_eq!(action.risk_class, RiskClass::Moderate);

    // Proposal attempting to lower risk to OBSERVATION (INV-005) -> must be REJECTED!
    let tampered_risk_json = json!({
        "proposal_id": "prp-002",
        "mission_id": "mis-cap-01",
        "capability_id": "PORT_SCAN",
        "target": "192.168.1.1",
        "parameters": { "ports": [80, 443] },
        "declared_risk": "OBSERVATION",
        "nonce": "abcdef0123456789abcdef0123456789"
    })
    .to_string();

    let res = normalizer.normalize_from_json(&tampered_risk_json, &ctx);
    assert!(matches!(
        res,
        Err(KernelSecurityError::RiskOverrideForbidden)
    ));
}

#[test]
fn test_cap_002_unknown_capability_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-cap-02", vec!["NON_EXISTENT_TOOL"]);

    let json_str = json!({
        "proposal_id": "prp-003",
        "mission_id": "mis-cap-02",
        "capability_id": "NON_EXISTENT_TOOL",
        "target": "10.0.0.1",
        "parameters": {},
        "nonce": "abcdef0123456789abcdef0123456789"
    })
    .to_string();

    let res = normalizer.normalize_from_json(&json_str, &ctx);
    assert!(matches!(
        res,
        Err(KernelSecurityError::CapabilityNotFound(_))
    ));
}

#[test]
fn test_cap_003_generic_unrestricted_shell_forbidden() {
    let mut registry = StandardCapabilityRegistry::new();

    // Invariant TRD Section 8: There is no generic unrestricted SHELL capability
    let shell_cap = CapabilityMetadata {
        id: CapabilityId::new("SHELL").unwrap(),
        name: "Generic Shell".to_string(),
        description: "Arbitrary shell execution".to_string(),
        risk_class: RiskClass::Critical,
        requires_approval: true,
        allowed_target_classes: vec![TargetClass::Ip],
        network_required: true,
        timeout_seconds: 60,
        sandbox_profile: "none".to_string(),
    };

    let res = registry.register(shell_cap);
    assert!(matches!(
        res,
        Err(KernelSecurityError::CapabilityNotFound(_))
    ));
}

#[test]
fn test_cap_004_target_class_mismatch_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-cap-04", vec!["HTTP_REQUEST"]);

    // HTTP_REQUEST requires Url target class. Passing a raw IP address must fail!
    let json_str = json!({
        "proposal_id": "prp-004",
        "mission_id": "mis-cap-04",
        "capability_id": "HTTP_REQUEST",
        "target": "192.168.1.1",
        "parameters": {},
        "nonce": "abcdef0123456789abcdef0123456789"
    })
    .to_string();

    let res = normalizer.normalize_from_json(&json_str, &ctx);
    assert!(matches!(res, Err(KernelSecurityError::ScopeDenied(_))));
}

// ---------------------------------------------------------------------------
// TEST-ACTION-* : Normalization Boundary, Hashes & Strict Deserialization
// ---------------------------------------------------------------------------

#[test]
fn test_action_001_canonical_hashes_deterministic() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-act-01", vec!["PORT_SCAN"]);

    // Two proposals with differently ordered parameter keys must produce the EXACT same parameter hash!
    let p1_json = json!({
        "proposal_id": "prp-101",
        "mission_id": "mis-act-01",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": { "b": 2, "a": 1 },
        "nonce": "00000000000000000000000000000001"
    })
    .to_string();

    let p2_json = json!({
        "proposal_id": "prp-101",
        "mission_id": "mis-act-01",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": { "a": 1, "b": 2 },
        "nonce": "00000000000000000000000000000001"
    })
    .to_string();

    let a1 = normalizer.normalize_from_json(&p1_json, &ctx).unwrap();
    let a2 = normalizer.normalize_from_json(&p2_json, &ctx).unwrap();

    assert_eq!(a1.parameter_hash, a2.parameter_hash);
    assert_eq!(a1.action_hash, a2.action_hash);
    assert_eq!(a1.parameter_hash.len(), 64);
    assert_eq!(a1.action_hash.len(), 64);
}

#[test]
fn test_action_002_duplicate_json_keys_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-act-02", vec!["PORT_SCAN"]);

    // Proposal containing duplicate key in parameters
    let duplicate_key_json = r#"{
        "proposal_id": "prp-102",
        "mission_id": "mis-act-02",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": {
            "rate_limit": 100,
            "rate_limit": 1000000
        },
        "nonce": "00000000000000000000000000000002"
    }"#;

    let res = normalizer.normalize_from_json(duplicate_key_json, &ctx);
    assert!(res.is_err(), "Duplicate keys must trigger strict rejection");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("duplicate JSON key"));
}

#[test]
fn test_action_003_unknown_fields_in_proposal_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-act-03", vec!["PORT_SCAN"]);

    // Proposal with unexpected field 'bypass_safety: true'
    let unknown_field_json = json!({
        "proposal_id": "prp-103",
        "mission_id": "mis-act-03",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": {},
        "nonce": "00000000000000000000000000000003",
        "bypass_safety": true
    })
    .to_string();

    let res = normalizer.normalize_from_json(&unknown_field_json, &ctx);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("unknown field `bypass_safety`"));
}

#[test]
fn test_action_004_oversized_proposal_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-act-04", vec!["PORT_SCAN"]);

    // Exceeding 64KB limit
    let huge_param = "X".repeat(70000);
    let huge_json = format!(
        r#"{{"proposal_id":"prp-104","mission_id":"mis-act-04","capability_id":"PORT_SCAN","target":"10.0.0.1","parameters":{{"huge":"{}"}},"nonce":"123"}}"#,
        huge_param
    );

    let res = normalizer.normalize_from_json(&huge_json, &ctx);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum limit"));
}

#[test]
fn test_action_005_deep_nesting_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);
    let ctx = create_test_context("mis-act-05", vec!["PORT_SCAN"]);

    let mut deep_param = String::new();
    for _ in 0..12 {
        deep_param.push_str("{\"n\":");
    }
    deep_param.push('1');
    for _ in 0..12 {
        deep_param.push('}');
    }

    let deep_json = format!(
        r#"{{"proposal_id":"prp-105","mission_id":"mis-act-05","capability_id":"PORT_SCAN","target":"10.0.0.1","parameters":{},"nonce":"123"}}"#,
        deep_param
    );

    let res = normalizer.normalize_from_json(&deep_json, &ctx);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("nesting depth"));
}

#[test]
fn test_action_006_cross_mission_proposal_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);

    // Context is for mis-tenant-alpha
    let ctx = create_test_context("mis-tenant-alpha", vec!["PORT_SCAN"]);

    // Proposal claims to be for mis-tenant-beta
    let cross_mission_json = json!({
        "proposal_id": "prp-106",
        "mission_id": "mis-tenant-beta",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": {},
        "nonce": "00000000000000000000000000000006"
    })
    .to_string();

    let res = normalizer.normalize_from_json(&cross_mission_json, &ctx);
    assert!(matches!(
        res,
        Err(KernelSecurityError::CrossMissionAccessDenied { .. })
    ));
}

#[test]
fn test_action_007_context_lacking_capability_rejected() {
    let registry = Arc::new(StandardCapabilityRegistry::new());
    let normalizer = ActionNormalizer::new(registry);

    // Context only has DNS_LOOKUP
    let ctx = create_test_context("mis-act-07", vec!["DNS_LOOKUP"]);

    // Proposal attempts to request PORT_SCAN
    let proposal_json = json!({
        "proposal_id": "prp-107",
        "mission_id": "mis-act-07",
        "capability_id": "PORT_SCAN",
        "target": "10.0.0.1",
        "parameters": {},
        "nonce": "00000000000000000000000000000007"
    })
    .to_string();

    let res = normalizer.normalize_from_json(&proposal_json, &ctx);
    assert!(matches!(
        res,
        Err(KernelSecurityError::CapabilityNotFound(_))
    ));
}
