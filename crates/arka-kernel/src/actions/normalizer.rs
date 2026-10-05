//! Single Canonical Normalization Boundary.
//!
//! Enforces:
//! - Section 13: Construction of CanonicalAction.
//! - Section 14: Strict input validation, size limits (64KB), depth limits, duplicate key rejection.
//! - Section 15: Exactly one normalization entry point for all proposals (agents, LLMs, API).
//! - Invariant INV-004: Identity and mission bound to AuthenticatedContext.
//! - Invariant INV-005: Risk is derived from registry, self-declared risk mismatch triggers DENY.
//! - Invariant INV-006: RFC 8785 JCS canonicalization with domain-separated SHA-256.

use crate::capabilities::CapabilityRegistry;
use crate::scope::TargetParser;
use arka_core_types::actions::{CanonicalAction, RawActionProposal};
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::ActionId;
use arka_core_types::subject::AuthenticatedContext;
use arka_crypto::canonical::canonicalize_json;
use arka_crypto::hashing::{sha256_hex, DOMAIN_ACTION, DOMAIN_PARAM};
use arka_crypto::json_strict::StrictJsonParser;
use serde_json::json;
use std::sync::Arc;

pub const CURRENT_POLICY_VERSION: &str = "v2.2";

pub struct ActionNormalizer {
    registry: Arc<dyn CapabilityRegistry>,
}

impl ActionNormalizer {
    pub fn new(registry: Arc<dyn CapabilityRegistry>) -> Self {
        Self { registry }
    }

    /// Primary normalization entry point taking raw JSON bytes from untrusted agents or LLMs.
    pub fn normalize_from_json(
        &self,
        raw_json: &str,
        context: &AuthenticatedContext,
    ) -> Result<CanonicalAction, KernelSecurityError> {
        // 1. Strict JSON Pre-Parser: enforces 64KB max size, max depth 8, and duplicate key rejection
        let val = StrictJsonParser::parse(raw_json)?;

        // 2. Deserialize into RawActionProposal (enforcing deny_unknown_fields)
        let proposal: RawActionProposal = serde_json::from_value(val).map_err(|e| {
            KernelSecurityError::InternalFailure(format!(
                "Proposal schema validation failed: {}",
                e
            ))
        })?;

        self.normalize_proposal(proposal, context)
    }

    /// Normalizes a parsed proposal against capability registry, target parser, and security invariants.
    pub fn normalize_proposal(
        &self,
        proposal: RawActionProposal,
        context: &AuthenticatedContext,
    ) -> Result<CanonicalAction, KernelSecurityError> {
        // Invariant INV-004 & INV-009: Action proposal MUST match AuthenticatedContext mission
        if proposal.mission_id != context.mission_id {
            return Err(KernelSecurityError::CrossMissionAccessDenied {
                requester_mission: context.mission_id.clone(),
                target_mission: proposal.mission_id,
            });
        }

        // 3. Resolve capability from authoritative registry
        let cap_meta = self.registry.get(&proposal.capability_id).ok_or_else(|| {
            KernelSecurityError::CapabilityNotFound(format!(
                "Capability '{}' is not registered in security kernel",
                proposal.capability_id
            ))
        })?;

        // 4. Verify context has capability permission
        if !context.has_capability(&proposal.capability_id) {
            return Err(KernelSecurityError::CapabilityNotFound(format!(
                "Authenticated identity '{}' lacks capability '{}'",
                context.subject.identifier(),
                proposal.capability_id
            )));
        }

        // Invariant INV-005: Risk is derived, not self-declared.
        // If untrusted proposal attempts to declare a different risk, immediately DENY!
        if let Some(declared_risk) = proposal.declared_risk {
            if declared_risk != cap_meta.risk_class {
                return Err(KernelSecurityError::RiskOverrideForbidden);
            }
        }

        // 5. Parse and normalize target
        let canonical_target = TargetParser::parse(&proposal.target)?;

        // Validate target class is allowed for this capability
        if !cap_meta.allows_target(&canonical_target) {
            return Err(KernelSecurityError::ScopeDenied(format!(
                "Capability '{}' does not permit target class for '{}'",
                proposal.capability_id, proposal.target
            )));
        }

        // 6. Parameter canonicalization via RFC 8785 JCS
        let canon_params_str = canonicalize_json(&proposal.parameters).map_err(|e| {
            KernelSecurityError::InternalFailure(format!(
                "Parameter canonicalization failed: {}",
                e
            ))
        })?;

        let normalized_params: serde_json::Value = serde_json::from_str(&canon_params_str)
            .map_err(|e| {
                KernelSecurityError::InternalFailure(format!(
                    "Canonical parameter reload failed: {}",
                    e
                ))
            })?;

        // Compute parameter hash with DOMAIN_PARAM
        let parameter_hash = sha256_hex(DOMAIN_PARAM, canon_params_str.as_bytes());

        // 7. Generate deterministic / unique action ID based on proposal ID
        let action_id =
            ActionId::new(format!("act_{}", proposal.proposal_id.as_str())).map_err(|e| {
                KernelSecurityError::InternalFailure(format!("Action ID generation failed: {}", e))
            })?;

        // 8. Compute action hash with DOMAIN_ACTION over canonical security-relevant fields
        let action_hash_payload = json!({
            "action_id": action_id.as_str(),
            "capability_id": proposal.capability_id.as_str(),
            "mission_id": proposal.mission_id.as_str(),
            "nonce": proposal.nonce,
            "parameter_hash": parameter_hash,
            "policy_version": CURRENT_POLICY_VERSION,
            "target": canonical_target,
        });

        let canon_action_str = canonicalize_json(&action_hash_payload).map_err(|e| {
            KernelSecurityError::InternalFailure(format!("Action canonicalization failed: {}", e))
        })?;

        let action_hash = sha256_hex(DOMAIN_ACTION, canon_action_str.as_bytes());

        Ok(CanonicalAction {
            action_id,
            proposal_id: proposal.proposal_id,
            mission_id: proposal.mission_id,
            parent_task_id: proposal.parent_task_id,
            capability_id: proposal.capability_id,
            target: canonical_target,
            normalized_parameters: normalized_params,
            parameter_hash,
            action_hash,
            risk_class: cap_meta.risk_class,
            requires_approval: cap_meta.requires_approval,
            policy_version: CURRENT_POLICY_VERSION.to_string(),
            authorization_context_ref: context.token_id.as_str().to_string(),
            nonce: proposal.nonce,
        })
    }
}
