/**
 * ARKA Backend Contract Registry & Implementation Phase Map.
 *
 * Current Phase: Phase 2 Complete, Phase 3 Module A (Architecture & Contracts Baseline).
 * Authoritative Backend: Rust Security Kernel (`arka-kerneld`) + SQLite WAL + Gatewayd UDS.
 *
 * Status Definitions:
 * - REAL_BACKEND: The endpoint exists and is genuinely served by a backend daemon.
 * - PROPOSED_SPEC: The OpenAPI/REST contract is formally specified for `arka-apid` (TRD Section 29),
 *   but the HTTP daemon is not yet compiled or deployed in this environment.
 * - MOCK_DEVELOPMENT_ONLY: Verified test fixtures strictly designated as sample development data.
 *   MUST NOT be represented as live production security telemetry.
 * - FAIL_CLOSED_DISABLED: Dangerous workflows (direct execution, unsanctioned token changes)
 *   that are strictly disabled at the presentation layer.
 */

export interface EndpointContractInfo {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  status: 'REAL_BACKEND' | 'PROPOSED_SPEC' | 'MOCK_DEVELOPMENT_ONLY' | 'FAIL_CLOSED_DISABLED';
  governingSection: string;
  notes: string;
}

export const BACKEND_CONTRACTS: Record<string, EndpointContractInfo> = {
  GET_MISSIONS: {
    path: '/api/v1/missions',
    method: 'GET',
    status: 'PROPOSED_SPEC',
    governingSection: 'TRD Section 29, PRD Section 7.1',
    notes: 'Lists active, paused, and completed missions. Bound to operator session.',
  },
  POST_MISSION: {
    path: '/api/v1/missions',
    method: 'POST',
    status: 'PROPOSED_SPEC',
    governingSection: 'TRD Section 29, Section 10',
    notes: 'Creates mission with explicit scope manifest. Validates CIDR, FQDN, exclusions.',
  },
  TRANSITION_MISSION: {
    path: '/api/v1/missions/:id/transition',
    method: 'POST',
    status: 'PROPOSED_SPEC',
    governingSection: 'arka-core-types::mission::MissionState',
    notes: 'Transitions state (e.g. CREATED -> ACTIVE). Operator-only. Fails if E-Stop active.',
  },
  GET_PROPOSALS: {
    path: '/api/v1/proposals',
    method: 'GET',
    status: 'PROPOSED_SPEC',
    governingSection: 'PHASE_3_MODULE_A_CONTRACTS Section 2',
    notes: 'Returns unreviewed and historic proposals with RFC 8785 canonical hashes.',
  },
  POST_APPROVE_PROPOSAL: {
    path: '/api/v1/approvals',
    method: 'POST',
    status: 'PROPOSED_SPEC',
    governingSection: 'INV-005, arka-core-types::approval::Approval',
    notes: 'Requires exact action_hash match. Approver != Requester. Single use.',
  },
  POST_EMERGENCY_STOP: {
    path: '/api/v1/emergency-stop',
    method: 'POST',
    status: 'PROPOSED_SPEC',
    governingSection: 'INV-010, Section 25, arka-core-types::emergency_stop',
    notes: 'Monotonically halts all agent execution and broker workers immediately.',
  },
  GET_EMERGENCY_STOP_STATUS: {
    path: '/api/v1/emergency-stop/status',
    method: 'GET',
    status: 'PROPOSED_SPEC',
    governingSection: 'Section 26',
    notes: 'Persistent emergency stop active state from SQLite/Kernel state.',
  },
  GET_AUDIT_RECORDS: {
    path: '/api/v1/audit/records',
    method: 'GET',
    status: 'PROPOSED_SPEC',
    governingSection: 'INV-011, Section 23, Section 24',
    notes: 'Fetches dual-chain append-only signed audit ledger.',
  },
  POST_VERIFY_AUDIT_CHAIN: {
    path: '/api/v1/audit/verify',
    method: 'POST',
    status: 'PROPOSED_SPEC',
    governingSection: 'Section 24',
    notes: 'Triggers backend cryptographic verification of Merkle/hash chains. Never trusted client-side.',
  },
  DIRECT_EXECUTION: {
    path: '/client/direct-exec',
    method: 'POST',
    status: 'FAIL_CLOSED_DISABLED',
    governingSection: 'INV-001: Zero direct execution authority',
    notes: 'Frontend CANNOT run bash, sockets, tools, or workers directly. Intentionally impossible.',
  },
};

export const BACKEND_ENDPOINTS: EndpointContractInfo[] = Object.values(BACKEND_CONTRACTS);

