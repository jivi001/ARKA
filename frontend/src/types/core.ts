/**
 * ARKA Core Domain Models and Invariant Types.
 * Matches Rust definitions in `crates/arka-core-types`.
 * Governing Invariants:
 * - INV-001: Zero direct execution authority in agent/LLM plane.
 * - INV-003: DISCOVERED != AUTHORIZED.
 * - INV-005: Approval bound to normalized parameter hash.
 * - INV-010: Emergency Stop fails closed monotonically.
 */

export type MissionState = 'CREATED' | 'ACTIVE' | 'PAUSED' | 'COMPLETED' | 'TERMINATED';

export interface Mission {
  id: string; // TypeID: mis_<crockford>
  name: string;
  state: MissionState;
  scope_ref: string;
  created_at_unix: number;
  updated_at_unix: number;
  created_by: string; // TypeID: opr_<crockford>
  mode: 'LAB_CTF' | 'AUTHORIZED_PROFESSIONAL';
  description?: string;
}

export type RiskClass = 'OBSERVATION' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export type StandardCapability =
  | 'DNS_LOOKUP'
  | 'TCP_CONNECT'
  | 'PORT_SCAN'
  | 'HTTP_REQUEST'
  | 'WEB_DISCOVERY'
  | 'BROWSER_AUTOMATION'
  | 'OSINT_LOOKUP'
  | 'PCAP_CAPTURE'
  | 'SERVICE_ENUMERATION'
  | 'CREDENTIAL_VALIDATION'
  | 'CONTROLLED_EXPLOITATION';

export interface ScopeDefinition {
  inclusions: {
    cidr_blocks: string[];
    hostnames: string[];
    url_origins: string[];
    ports: number[];
  };
  exclusions: {
    cidr_blocks: string[];
    hostnames: string[];
    ports: number[];
    rationale: string;
  };
  policy_version: string;
  canonical_hash: string; // SHA-256
}

export type ProposalDecision =
  | 'ALLOW'
  | 'DENY'
  | 'REQUIRE_APPROVAL'
  | 'INVALID_PROPOSAL'
  | 'EXPIRED_PROPOSAL'
  | 'UNAVAILABLE_DEPENDENCY';

export interface ActionProposal {
  proposal_id: string; // prp_<crockford>
  mission_id: string; // mis_<crockford>
  parent_task_id?: string;
  requesting_agent: string;
  capability_id: StandardCapability;
  target: string;
  raw_parameters: Record<string, unknown>;
  normalized_parameters: Record<string, unknown>;
  parameter_hash: string; // sha256:...
  action_hash: string; // sha256:...
  declared_risk?: RiskClass;
  true_risk: RiskClass;
  decision: ProposalDecision;
  decision_reason?: string;
  evidence_refs: string[];
  rationale: string;
  nonce: string;
  timestamp_unix: number;
  expires_at_unix: number;
}

export interface Approval {
  approval_id: string; // app_<crockford>
  mission_id: string;
  action_hash: string; // Exact match to CanonicalAction.action_hash
  approver: string; // Operator ID (approver != requesting agent)
  status: 'PENDING' | 'APPROVED' | 'CONSUMED' | 'REVOKED' | 'EXPIRED';
  issued_at_unix: number;
  expires_at_unix: number;
  consumed_at_unix?: number;
  rejection_reason?: string;
}

export interface EmergencyStopStatus {
  active: boolean;
  triggered_at_unix?: number;
  triggered_by?: string;
  reason?: string;
  cleared_at_unix?: number;
  cleared_by?: string;
  clear_reason?: string;
}

export interface AuditRecord {
  event_id: string; // evt_<crockford>
  sequence_number: number;
  timestamp_unix: number;
  mission_id?: string;
  event_type:
    | 'MISSION_CREATED'
    | 'MISSION_TRANSITION'
    | 'PROPOSAL_SUBMITTED'
    | 'PROPOSAL_EVALUATED'
    | 'APPROVAL_REQUESTED'
    | 'ACTION_AUTHORIZED'
    | 'APPROVAL_CONSUMED'
    | 'APPROVAL_REVOKED'
    | 'ACTION_DISPATCHED'
    | 'EXECUTION_COMPLETED'
    | 'EVIDENCE_RECORDED'
    | 'EMERGENCY_STOP_TRIGGERED'
    | 'EMERGENCY_STOP_CLEARED';
  actor_id: string;
  details: Record<string, unknown>;
  previous_hash: string;
  current_hash: string;
  signature: string; // Ed25519 signature under KeyDomain::AuditSigning
}

export interface EvidenceRecord {
  evidence_id: string; // evd_<crockford>
  mission_id: string;
  originating_action_id: string;
  originating_capability: StandardCapability;
  content_hash: string; // sha256:...
  timestamp_unix: number;
  provenance: {
    agent_id: string;
    broker_sandbox: string;
    kernel_ticket_receipt: string;
  };
  payload_preview: string;
  payload_type: 'HTTP_RESPONSE' | 'PORT_SURVEY' | 'PCAP_HEADER' | 'BANNER_GRAB' | 'SERVICE_PROBE';
  trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT' | 'KERNEL_VERIFIED_SIGNATURE';
}
