/**
 * ARKA Agent Findings Trace — Domain Types & Data Contracts.
 *
 * Implements:
 * - 7-Stage Finding Lifecycle: Discovery -> Evidence Collection -> Validation ->
 *   Risk Scoring -> Kernel Policy Check -> Human Approval -> Final Finding.
 * - Invariant: DISCOVERED != AUTHORIZED.
 * - Independent validation status vs authoritative kernel policy decision.
 * - Cryptographic evidence and dual-signed audit binding.
 */

import type { StandardCapability, ProposalDecision } from './core.ts';

export type FindingSeverity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingConfidence = 'CONFIRMED_EXPLOIT' | 'OBSERVED_ANOMALY' | 'THEORETICAL_MATCH';

export type LifecycleStageId =
  | 'discovery'
  | 'evidence_collection'
  | 'validation'
  | 'risk_scoring'
  | 'kernel_policy_check'
  | 'human_approval'
  | 'final_finding';

export type LifecycleStageStatus =
  | 'COMPLETED'
  | 'ACTIVE'
  | 'PENDING'
  | 'DENIED'
  | 'FAILED'
  | 'NOT_REQUIRED'
  | 'STALE'
  | 'UNKNOWN';

export interface LifecycleStageInfo {
  id: LifecycleStageId;
  stageNumber: number; // 1 to 7
  title: string;
  shortDesc: string;
  status: LifecycleStageStatus;
  timestamp_unix?: number;
  eventRef?: string;
  details?: string;
}

export interface FindingEvidenceArtifact {
  id: string; // evd_...
  filename: string;
  size_bytes: number;
  content_hash: string; // sha256:...
  capability: StandardCapability | string;
  mime_type: string;
  provenance: {
    agent_id: string;
    sandbox: string;
    kernel_ticket_receipt: string;
  };
  sanitized_preview: string;
  trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT' | 'KERNEL_VERIFIED_SIGNATURE';
}

export interface FindingAuditEvent {
  event_id: string; // evt_...
  sequence_number: number;
  timestamp_unix: number;
  event_type: string;
  actor_id: string;
  action_hash?: string;
  previous_hash: string;
  current_hash: string;
  signature: string;
  verified: boolean;
  summary: string;
}

export type ValidationState = 'VALIDATED' | 'PENDING' | 'INVALID' | 'ANOMALOUS';

export interface FindingTraceItem {
  finding_id: string; // find_01J9Y7QX...
  mission_id: string;
  title: string;
  severity: FindingSeverity;
  risk_score: number; // e.g. 9.1
  risk_score_scale: string; // e.g. "9.1 / 10 — Critical"
  scoring_source: string;
  confidence: FindingConfidence;
  confidence_percentage: number; // e.g. 94%
  source_agent: string; // e.g. "ReconAgent-01"
  agent_role: string; // e.g. "Perimeter Surface Discovery"
  target: string; // e.g. "10.42.18.104:8443"
  target_scope_status: 'IN_SCOPE' | 'EXCLUDED_TARGET' | 'DISCOVERED_UNAUTHORIZED';
  validation_state: ValidationState;
  validation_summary: string;
  policy_decision: ProposalDecision;
  policy_reason: string;
  policy_rule_id: string;
  scope_ref: string;
  kernel_version: string;
  policy_evaluation_time_unix: number;
  human_approval_state: 'NOT_REQUIRED' | 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  approval_id?: string;
  bound_action_hash?: string;
  detected_at_unix: number;
  lifecycle_stages: LifecycleStageInfo[];
  evidence_artifacts: FindingEvidenceArtifact[];
  audit_events: FindingAuditEvent[];
  factual_description: string;
  remediation_guidance: string;
  cve_id?: string;
}
