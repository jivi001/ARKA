//! Audit Chain Engine implementing dual hash chains and cryptographic signing.
//!
//! Enforces:
//! - Section 23: Per-Mission Audit Chain
//! - Section 24: Global System Audit Chain
//! - INV-011: Cryptographic chaining and non-repudiation

use arka_core_types::audit::{AuditPayload, AuditRecord};
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::MissionId;
use arka_crypto::canonical::canonicalize_json;
use arka_crypto::hashing::sha256_hex;
use arka_crypto::provider::{DevKeyProvider, KeyDomain, KeyProvider};
use std::sync::Arc;

pub const DOMAIN_AUDIT: &str = "ARKA-AUDIT-v1";
pub const DOMAIN_AUDIT_GENESIS: &str = "ARKA-AUDIT-GENESIS";
pub const DEFAULT_AUDIT_KID: &str = "AUDIT-SIGNING-dev-01";

#[derive(Clone)]
pub struct AuditChainEngine {
    key_provider: Arc<DevKeyProvider>,
    kid: String,
}

impl AuditChainEngine {
    pub fn new(key_provider: Arc<DevKeyProvider>) -> Self {
        Self {
            key_provider,
            kid: DEFAULT_AUDIT_KID.to_string(),
        }
    }

    /// Computes the genesis hash for the global system audit log.
    pub fn system_genesis_hash() -> String {
        sha256_hex(DOMAIN_AUDIT_GENESIS, b"SYSTEM")
    }

    /// Computes the genesis hash for a mission audit log.
    pub fn mission_genesis_hash(mission_id: &MissionId) -> String {
        sha256_hex(
            DOMAIN_AUDIT_GENESIS,
            format!("MISSION:{}", mission_id.as_str()).as_bytes(),
        )
    }

    /// Creates and signs a new audit record extending an existing chain (or genesis).
    #[allow(clippy::too_many_arguments)]
    pub fn create_record(
        &self,
        event_id: &str,
        previous_record: Option<&AuditRecord>,
        mission_id: Option<&MissionId>,
        event_type: &str,
        actor_id: &str,
        details: serde_json::Value,
        now_unix: u64,
    ) -> Result<AuditRecord, KernelSecurityError> {
        let (sequence_number, previous_hash) = match previous_record {
            Some(prev) => (prev.sequence_number + 1, prev.current_hash.clone()),
            None => {
                let genesis = match mission_id {
                    Some(m) => Self::mission_genesis_hash(m),
                    None => Self::system_genesis_hash(),
                };
                (1, genesis)
            }
        };

        let payload = AuditPayload {
            event_id: event_id.to_string(),
            sequence_number,
            timestamp_unix: now_unix,
            mission_id: mission_id.map(|m| m.as_str().to_string()),
            event_type: event_type.to_string(),
            actor_id: actor_id.to_string(),
            details: details.clone(),
            previous_hash: previous_hash.clone(),
        };

        let payload_json = serde_json::to_value(&payload).map_err(|e| {
            KernelSecurityError::InternalFailure(format!(
                "Failed to serialize audit payload: {}",
                e
            ))
        })?;
        let canonical_bytes = canonicalize_json(&payload_json).map_err(|e| {
            KernelSecurityError::InternalFailure(format!(
                "Failed to canonicalize audit payload: {}",
                e
            ))
        })?;

        let current_hash = sha256_hex(DOMAIN_AUDIT, canonical_bytes.as_bytes());

        let sig_result = self
            .key_provider
            .sign(KeyDomain::AuditSigning, &self.kid, current_hash.as_bytes())
            .map_err(|e| {
                KernelSecurityError::InternalFailure(format!("Audit signing failed: {}", e))
            })?;

        let signature_hex = hex::encode(sig_result.signature);

        Ok(AuditRecord {
            event_id: event_id.to_string(),
            sequence_number,
            timestamp_unix: now_unix,
            mission_id: mission_id.cloned(),
            event_type: event_type.to_string(),
            actor_id: actor_id.to_string(),
            details,
            previous_hash,
            current_hash,
            signature: signature_hex,
        })
    }

    /// Verifies the cryptographic and structural integrity of an audit chain from genesis to tip.
    pub fn verify_chain(
        &self,
        records: &[AuditRecord],
        expected_mission_id: Option<&MissionId>,
    ) -> Result<(), KernelSecurityError> {
        let expected_genesis = match expected_mission_id {
            Some(m) => Self::mission_genesis_hash(m),
            None => Self::system_genesis_hash(),
        };

        for (idx, record) in records.iter().enumerate() {
            let expected_seq = (idx + 1) as u64;
            if record.sequence_number != expected_seq {
                return Err(KernelSecurityError::AuditChainTampered(format!(
                    "Sequence gap detected: expected {}, found {}",
                    expected_seq, record.sequence_number
                )));
            }

            if idx == 0 {
                if record.previous_hash != expected_genesis {
                    return Err(KernelSecurityError::AuditChainTampered(format!(
                        "Genesis hash mismatch: expected {}, found {}",
                        expected_genesis, record.previous_hash
                    )));
                }
            } else {
                let prev_record = &records[idx - 1];
                if record.previous_hash != prev_record.current_hash {
                    return Err(KernelSecurityError::AuditChainTampered(format!(
                        "Hash chain break at event {}: previous_hash {} != parent current_hash {}",
                        record.event_id, record.previous_hash, prev_record.current_hash
                    )));
                }
            }

            // Verify mission_id matches
            if record.mission_id.as_ref() != expected_mission_id {
                return Err(KernelSecurityError::AuditChainTampered(format!(
                    "Mission ID mismatch in audit record {}: expected {:?}, found {:?}",
                    record.event_id, expected_mission_id, record.mission_id
                )));
            }

            // Recompute payload hash
            let payload = AuditPayload {
                event_id: record.event_id.clone(),
                sequence_number: record.sequence_number,
                timestamp_unix: record.timestamp_unix,
                mission_id: record.mission_id.as_ref().map(|m| m.as_str().to_string()),
                event_type: record.event_type.clone(),
                actor_id: record.actor_id.clone(),
                details: record.details.clone(),
                previous_hash: record.previous_hash.clone(),
            };

            let payload_json = serde_json::to_value(&payload).map_err(|e| {
                KernelSecurityError::InternalFailure(format!(
                    "Failed to serialize audit payload: {}",
                    e
                ))
            })?;
            let canonical_bytes = canonicalize_json(&payload_json).map_err(|e| {
                KernelSecurityError::InternalFailure(format!(
                    "Failed to canonicalize audit payload: {}",
                    e
                ))
            })?;

            let expected_hash = sha256_hex(DOMAIN_AUDIT, canonical_bytes.as_bytes());

            if record.current_hash != expected_hash {
                return Err(KernelSecurityError::AuditChainTampered(format!(
                    "Record content hash tampered at event {}: expected {}, found {}",
                    record.event_id, expected_hash, record.current_hash
                )));
            }

            // Verify signature
            let sig_bytes = hex::decode(&record.signature).map_err(|e| {
                KernelSecurityError::AuditChainTampered(format!("Invalid signature hex: {}", e))
            })?;

            let valid = self
                .key_provider
                .verify(
                    KeyDomain::AuditSigning,
                    &self.kid,
                    record.current_hash.as_bytes(),
                    &sig_bytes,
                )
                .map_err(|e| {
                    KernelSecurityError::AuditChainTampered(format!(
                        "Signature verification error: {}",
                        e
                    ))
                })?;

            if !valid {
                return Err(KernelSecurityError::AuditChainTampered(format!(
                    "Invalid cryptographic signature on audit event {}",
                    record.event_id
                )));
            }
        }

        Ok(())
    }
}
