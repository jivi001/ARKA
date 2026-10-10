//! Bounded Evidence Capture, Content Hashing, and Provenance Pipeline.
//!
//! Enforces:
//! - GATE-EVIDENCE-INTEGRITY-001 (CTRL-EVIDENCE-INTEGRITY-001 / TEST-EVIDENCE-INTEGRITY-001)
//! - Invariant INV-012: Evidence Provenance and Content-Addressable Integrity
//! - Invariant INV-016: Untrusted Output Invariant (tool outputs cannot grant authority)
//! - Cryptographic SHA-256 domain-separated content hashing (`DOMAIN_EVIDENCE`)

use crate::errors::BrokerError;
use arka_core_types::id::{ActionId, CapabilityId, ExecutionId, MissionId};
use arka_crypto::{sha256_hex, DOMAIN_EVIDENCE};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Enumeration of structured evidence artifact types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    Stdout,
    Stderr,
    StructuredOutput,
    RawNetworkResponse,
    Custom(String),
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::Stdout => write!(f, "STDOUT"),
            EvidenceType::Stderr => write!(f, "STDERR"),
            EvidenceType::StructuredOutput => write!(f, "STRUCTURED_OUTPUT"),
            EvidenceType::RawNetworkResponse => write!(f, "RAW_NETWORK_RESPONSE"),
            EvidenceType::Custom(s) => write!(f, "CUSTOM({})", s),
        }
    }
}

/// Provenance metadata bound to an evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    pub mission_id: MissionId,
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub capability_id: CapabilityId,
    pub worker_profile: String,
    pub target: serde_json::Value,
}

/// A tamper-evident, content-addressed evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub evidence_id: String,
    pub provenance: EvidenceProvenance,
    pub evidence_type: String,
    pub content_bytes: Vec<u8>,
    pub content_hash: String,
    pub size_bytes: usize,
    pub truncated: bool,
    pub created_at_unix: u64,
}

/// Pipeline for collecting, bounding, hashing, and verifying evidence artifacts.
pub struct EvidenceCollector {
    max_artifact_bytes: usize,
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 1024 * 1024, // 1 MB default ceiling
        }
    }
}

impl EvidenceCollector {
    pub fn new(max_artifact_bytes: usize) -> Self {
        Self { max_artifact_bytes }
    }

    /// Ingests raw untrusted output, enforces byte limits, computes domain-separated SHA-256,
    /// and constructs an immutable `EvidenceArtifact`.
    pub fn collect(
        &self,
        provenance: EvidenceProvenance,
        evidence_type: EvidenceType,
        raw_bytes: &[u8],
        now_unix: u64,
    ) -> Result<EvidenceArtifact, BrokerError> {
        let (content_bytes, truncated) = if raw_bytes.len() > self.max_artifact_bytes {
            (raw_bytes[..self.max_artifact_bytes].to_vec(), true)
        } else {
            (raw_bytes.to_vec(), false)
        };

        let content_hash = sha256_hex(DOMAIN_EVIDENCE, &content_bytes);
        let evidence_id = format!("evi-{}", Uuid::new_v4().simple());
        let size_bytes = content_bytes.len();

        Ok(EvidenceArtifact {
            evidence_id,
            provenance,
            evidence_type: evidence_type.to_string(),
            content_bytes,
            content_hash,
            size_bytes,
            truncated,
            created_at_unix: now_unix,
        })
    }

    /// Verifies the cryptographic integrity of an evidence artifact.
    /// Fails closed if the stored hash does not match the recomputed content hash.
    pub fn verify_integrity(&self, artifact: &EvidenceArtifact) -> Result<(), BrokerError> {
        let recomputed_hash = sha256_hex(DOMAIN_EVIDENCE, &artifact.content_bytes);
        if recomputed_hash != artifact.content_hash {
            return Err(BrokerError::EvidenceTampered {
                expected: artifact.content_hash.clone(),
                actual: recomputed_hash,
            });
        }
        Ok(())
    }
}
