/**
 * Security Findings and Assessment Reports.
 * Distinguishes observed facts from inferred conclusions.
 */

import type { FindingSeverity, FindingConfidence } from './findingsTrace';
export * from './findingsTrace';

export type { FindingSeverity, FindingConfidence };

export interface Finding {
  finding_id: string; // fnd_<crockford>
  mission_id: string;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  affected_asset: string;
  affected_port?: number;
  cve_id?: string;
  description_factual: string; // Observed facts
  inference_narrative: string; // LLM/Agent reasoning
  reproduction_steps?: string[];
  remediation_guidance: string;
  evidence_refs: string[]; // evd_...
  originating_action_id: string;
  discovered_at_unix: number;
  status: 'OPEN' | 'VERIFIED' | 'FALSE_POSITIVE' | 'REMEDIATED';
}

export interface AssessmentReport {
  report_id: string; // rep_<crockford>
  mission_id: string;
  generated_at_unix: number;
  format: 'JSON_LD' | 'STANDALONE_MARKDOWN' | 'PDF_RECEIPT';
  executive_summary: string;
  scope_digest: string;
  findings_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  audit_chain_verified: boolean;
  tamper_evident_signature: string;
}

