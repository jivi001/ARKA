import test from 'node:test';
import assert from 'node:assert';
import type { ActionProposal, Approval } from '../src/types/core.ts';

/**
 * Validates whether an operator approval can be applied to an action proposal.
 * Enforces TRD Section 11 & Section 15 invariant:
 * - Exact byte-for-byte action hash match (TOCTOU protection).
 * - Requesting agent cannot self-approve.
 * - Approval must not be expired.
 */
function validateApprovalBinding(
  proposal: ActionProposal,
  approval: Approval,
  currentTimestampUnix: number
): { valid: boolean; reason?: string } {
  // Invariant 1: Action hash must match byte-for-byte
  if (approval.action_hash !== proposal.action_hash) {
    return {
      valid: false,
      reason: `TOCTOU Action Hash Mismatch: Approval hash (${approval.action_hash}) does not match proposal hash (${proposal.action_hash}).`,
    };
  }

  // Invariant 2: Approver cannot be the requesting agent
  if (approval.approver === proposal.requesting_agent) {
    return {
      valid: false,
      reason: `Two-Person Integrity Violation: Approver (${approval.approver}) cannot approve their own action proposal.`,
    };
  }

  // Invariant 3: Expiration check
  if (approval.expires_at_unix <= currentTimestampUnix) {
    return {
      valid: false,
      reason: `Approval Expired: Approval validity window expired at ${approval.expires_at_unix} (current: ${currentTimestampUnix}).`,
    };
  }

  // Invariant 4: Status must be PENDING or APPROVED
  if (approval.status === 'CONSUMED' || approval.status === 'REVOKED' || approval.status === 'EXPIRED') {
    return {
      valid: false,
      reason: `Approval Replay Prohibited: Approval is already ${approval.status}.`,
    };
  }

  return { valid: true };
}

test('Approval Binding — Valid Approval Binds Correctly', () => {
  const proposal: ActionProposal = {
    proposal_id: 'prp_01J9Y70TEST1',
    mission_id: 'mis_01J9Y70MIS1',
    requesting_agent: 'ExploitAgent-01',
    capability_id: 'CONTROLLED_EXPLOITATION',
    target: '10.42.18.104:8443',
    raw_parameters: { port: 8443, exploit_id: 'CVE-2024-38819' },
    normalized_parameters: { exploit_id: 'CVE-2024-38819', port: 8443 },
    parameter_hash: 'sha256:d4e1a6c8901b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829341c2',
    action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
    true_risk: 'CRITICAL',
    decision: 'REQUIRE_APPROVAL',
    evidence_refs: [],
    rationale: 'Safe PoC verification',
    nonce: 'c4b3a291f8e7d6c5b4a3928170e6f5d4',
    timestamp_unix: 1774022000,
    expires_at_unix: 1774022600,
  };

  const approval: Approval = {
    approval_id: 'app_01J9Y70APP1',
    mission_id: 'mis_01J9Y70MIS1',
    action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
    approver: 'opr_01J9Y70OPERATOR1',
    status: 'PENDING',
    issued_at_unix: 1774022010,
    expires_at_unix: 1774022600,
  };

  const result = validateApprovalBinding(proposal, approval, 1774022050);
  assert.strictEqual(result.valid, true);
});

test('Approval Binding — Rejects Hash Mismatch (TOCTOU Attack Protection)', () => {
  const proposal: ActionProposal = {
    proposal_id: 'prp_01J9Y70TEST2',
    mission_id: 'mis_01J9Y70MIS1',
    requesting_agent: 'ExploitAgent-01',
    capability_id: 'CONTROLLED_EXPLOITATION',
    target: '10.42.18.104:8443',
    raw_parameters: { port: 8443, exploit_id: 'CVE-2024-38819' },
    normalized_parameters: { exploit_id: 'CVE-2024-38819', port: 8443 },
    parameter_hash: 'sha256:d4e1a6c8901b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829341c2',
    action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
    true_risk: 'CRITICAL',
    decision: 'REQUIRE_APPROVAL',
    evidence_refs: [],
    rationale: 'Safe PoC verification',
    nonce: 'c4b3a291f8e7d6c5b4a3928170e6f5d4',
    timestamp_unix: 1774022000,
    expires_at_unix: 1774022600,
  };

  // Attacker attempts to substitute action parameters or target
  const tamperedApproval: Approval = {
    approval_id: 'app_01J9Y70APP2',
    mission_id: 'mis_01J9Y70MIS1',
    action_hash: 'sha256:TAMPERED_HASH_DOES_NOT_MATCH_PROPOSAL_ACTION_HASH_000000000000',
    approver: 'opr_01J9Y70OPERATOR1',
    status: 'PENDING',
    issued_at_unix: 1774022010,
    expires_at_unix: 1774022600,
  };

  const result = validateApprovalBinding(proposal, tamperedApproval, 1774022050);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason || '', /TOCTOU Action Hash Mismatch/);
});

test('Approval Binding — Forbids Self-Approval by Requesting Agent', () => {
  const proposal: ActionProposal = {
    proposal_id: 'prp_01J9Y70TEST3',
    mission_id: 'mis_01J9Y70MIS1',
    requesting_agent: 'agent_rogue_recon_01',
    capability_id: 'PORT_SCAN',
    target: '10.42.18.10:80',
    raw_parameters: {},
    normalized_parameters: {},
    parameter_hash: 'sha256:1111',
    action_hash: 'sha256:2222',
    true_risk: 'MODERATE',
    decision: 'REQUIRE_APPROVAL',
    evidence_refs: [],
    rationale: 'Scan target',
    nonce: 'nonce123',
    timestamp_unix: 1774022000,
    expires_at_unix: 1774022600,
  };

  const selfApproval: Approval = {
    approval_id: 'app_01J9Y70APP3',
    mission_id: 'mis_01J9Y70MIS1',
    action_hash: 'sha256:2222',
    approver: 'agent_rogue_recon_01', // Agent trying to approve its own proposal!
    status: 'PENDING',
    issued_at_unix: 1774022010,
    expires_at_unix: 1774022600,
  };

  const result = validateApprovalBinding(proposal, selfApproval, 1774022050);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason || '', /Two-Person Integrity Violation/);
});

test('Approval Binding — Rejects Expired Approval', () => {
  const proposal: ActionProposal = {
    proposal_id: 'prp_01J9Y70TEST4',
    mission_id: 'mis_01J9Y70MIS1',
    requesting_agent: 'ExploitAgent-01',
    capability_id: 'CONTROLLED_EXPLOITATION',
    target: '10.42.18.104:8443',
    raw_parameters: {},
    normalized_parameters: {},
    parameter_hash: 'sha256:aaa',
    action_hash: 'sha256:bbb',
    true_risk: 'CRITICAL',
    decision: 'REQUIRE_APPROVAL',
    evidence_refs: [],
    rationale: 'Exploit validation',
    nonce: 'nonce456',
    timestamp_unix: 1774020000,
    expires_at_unix: 1774020600,
  };

  const expiredApproval: Approval = {
    approval_id: 'app_01J9Y70APP4',
    mission_id: 'mis_01J9Y70MIS1',
    action_hash: 'sha256:bbb',
    approver: 'opr_01J9Y70OPERATOR1',
    status: 'PENDING',
    issued_at_unix: 1774020010,
    expires_at_unix: 1774020600,
  };

  const result = validateApprovalBinding(proposal, expiredApproval, 1774021000);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason || '', /Approval Expired/);
});
