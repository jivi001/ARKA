import test from 'node:test';
import assert from 'node:assert';
import { SAMPLE_FINDING_TRACE_ITEMS } from '../src/api/traceData.ts';
import type { FindingTraceItem, LifecycleStageId, LifecycleStageStatus } from '../src/types/findingsTrace.ts';

test('Agent Findings Trace — Dataset Completeness (24 Structured Findings)', () => {
  assert.strictEqual(SAMPLE_FINDING_TRACE_ITEMS.length, 24);

  // Each finding must have valid identifiers, severities, and targets
  for (const item of SAMPLE_FINDING_TRACE_ITEMS) {
    assert.ok(item.finding_id.startsWith('find_'), `Invalid finding ID format: ${item.finding_id}`);
    assert.ok(item.title.length > 0, `Missing title on ${item.finding_id}`);
    assert.ok(item.target.length > 0, `Missing target on ${item.finding_id}`);
    assert.ok(item.risk_score >= 0 && item.risk_score <= 10, `Invalid risk score on ${item.finding_id}`);
    assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(item.severity));
    assert.ok(['ALLOW', 'DENY', 'REQUIRE_APPROVAL'].includes(item.policy_decision));
  }
});

test('Agent Findings Trace — Invariant: DISCOVERED != AUTHORIZED', () => {
  // A finding can be high severity and structurally validated, yet strictly DENIED by the Security Kernel
  const deniedFindings = SAMPLE_FINDING_TRACE_ITEMS.filter((f) => f.policy_decision === 'DENY');
  assert.ok(deniedFindings.length > 0, 'Must contain kernel-denied findings');

  // Verify find_01J9Y7QX1A (Exposed Management Port)
  const mgmtPort = SAMPLE_FINDING_TRACE_ITEMS.find((f) => f.finding_id === 'find_01J9Y7QX1A');
  assert.ok(mgmtPort, 'Exposed management port finding must exist');
  assert.strictEqual(mgmtPort.severity, 'CRITICAL');
  assert.strictEqual(mgmtPort.validation_state, 'VALIDATED');
  assert.strictEqual(mgmtPort.policy_decision, 'DENY');
  assert.strictEqual(mgmtPort.target_scope_status, 'EXCLUDED_TARGET');
  assert.ok(
    mgmtPort.policy_reason.toLowerCase().includes('exclusion'),
    'Policy reason must explain that exclusion overrides inclusion'
  );
});

test('Agent Findings Trace — Seven Sequential Stages Lifecycle Completeness', () => {
  const expectedStages: LifecycleStageId[] = [
    'discovery',
    'evidence_collection',
    'validation',
    'risk_scoring',
    'kernel_policy_check',
    'human_approval',
    'final_finding',
  ];

  for (const item of SAMPLE_FINDING_TRACE_ITEMS) {
    assert.strictEqual(item.lifecycle_stages.length, 7, `Finding ${item.finding_id} must have 7 stages`);
    const stageIds = item.lifecycle_stages.map((s) => s.id);
    assert.deepStrictEqual(stageIds, expectedStages, `Stage order mismatch on ${item.finding_id}`);

    // Verification: if kernel decision is DENY, stage 5 must be DENIED
    if (item.policy_decision === 'DENY') {
      const stage5 = item.lifecycle_stages.find((s) => s.id === 'kernel_policy_check');
      assert.strictEqual(stage5?.status, 'DENIED');
    }

    // Terminal outcome: a denied finding still produces a final record with DENIED outcome
    if (item.policy_decision === 'DENY') {
      const stage7 = item.lifecycle_stages.find((s) => s.id === 'final_finding');
      assert.strictEqual(stage7?.status, 'DENIED');
    }
  }
});

test('Agent Findings Trace — Search Filter Matching', () => {
  const query = 'CVE-2024-38819';
  const matches = SAMPLE_FINDING_TRACE_ITEMS.filter(
    (f) =>
      f.title.includes(query) ||
      (f.cve_id && f.cve_id.includes(query)) ||
      f.finding_id.includes(query)
  );

  assert.ok(matches.length > 0, 'Must match Spring Boot CVE finding');
  assert.strictEqual(matches[0].finding_id, 'find_01J9Y7QX1E');
  assert.strictEqual(matches[0].severity, 'CRITICAL');
});

test('Agent Findings Trace — Filter by Source Agent & Severity', () => {
  const reconFindings = SAMPLE_FINDING_TRACE_ITEMS.filter((f) => f.source_agent === 'ReconAgent-01');
  assert.ok(reconFindings.length >= 10, 'ReconAgent-01 should have multiple findings');

  const criticalFindings = SAMPLE_FINDING_TRACE_ITEMS.filter((f) => f.severity === 'CRITICAL');
  assert.ok(criticalFindings.length >= 5, 'Should have critical findings categorized');

  for (const crit of criticalFindings) {
    assert.ok(crit.risk_score >= 9.0, 'Critical findings must have risk score >= 9.0');
  }
});

test('Agent Findings Trace — Filter by Policy Decision & Scope Status', () => {
  const allowed = SAMPLE_FINDING_TRACE_ITEMS.filter((f) => f.policy_decision === 'ALLOW');
  const denied = SAMPLE_FINDING_TRACE_ITEMS.filter((f) => f.policy_decision === 'DENY');
  const requireApproval = SAMPLE_FINDING_TRACE_ITEMS.filter(
    (f) => f.policy_decision === 'REQUIRE_APPROVAL'
  );

  assert.ok(allowed.length > 0, 'Must have allowed findings');
  assert.ok(denied.length > 0, 'Must have denied findings');
  assert.ok(requireApproval.length > 0, 'Must have require_approval findings');

  // Verify sum equals total dataset
  assert.strictEqual(allowed.length + denied.length + requireApproval.length, 24);
});

test('Agent Findings Trace — Evidence Cryptographic Integrity & Sanitization', () => {
  for (const item of SAMPLE_FINDING_TRACE_ITEMS) {
    assert.ok(item.evidence_artifacts.length > 0, `Finding ${item.finding_id} must have evidence artifacts`);

    for (const art of item.evidence_artifacts) {
      assert.ok(art.id.startsWith('evd_'), `Invalid evidence ID: ${art.id}`);
      assert.ok(art.content_hash.startsWith('sha256:'), `Missing sha256 prefix on ${art.id}`);
      assert.strictEqual(art.content_hash.length, 71, 'SHA-256 hash length must be 71 (sha256: + 64 hex chars)');
      assert.ok(art.size_bytes > 0, `Evidence artifact ${art.id} must have non-zero size`);
      assert.ok(
        art.sanitized_preview.length > 0,
        `Evidence artifact ${art.id} must provide sanitized preview`
      );
      assert.ok(
        !art.sanitized_preview.includes('<script>'),
        `Sanitized preview in ${art.id} must not contain raw script tags`
      );
    }
  }
});

test('Agent Findings Trace — Dual-Signed Cryptographic Audit Verification', () => {
  for (const item of SAMPLE_FINDING_TRACE_ITEMS) {
    assert.ok(item.audit_events.length > 0, `Finding ${item.finding_id} must have audit events`);

    for (const evt of item.audit_events) {
      assert.ok(evt.event_id.startsWith('evt_'), `Invalid event ID: ${evt.event_id}`);
      assert.ok(evt.sequence_number > 0, `Sequence number must be positive in ${evt.event_id}`);
      assert.ok(evt.signature.startsWith('ed25519:'), `Signature must use ed25519 domain on ${evt.event_id}`);
      assert.strictEqual(evt.verified, true, `Audit event ${evt.event_id} must be cryptographically verified`);
    }
  }
});

test('Agent Findings Trace — Two-Person Integrity Approval Gate Binding', () => {
  // Findings requiring human approval must have an approval ticket and bound action hash
  const pendingApprovals = SAMPLE_FINDING_TRACE_ITEMS.filter(
    (f) => f.policy_decision === 'REQUIRE_APPROVAL'
  );

  for (const item of pendingApprovals) {
    assert.ok(item.approval_id?.startsWith('app_'), `Missing approval ticket on ${item.finding_id}`);
    assert.ok(item.bound_action_hash?.startsWith('sha256:'), `Missing bound action hash on ${item.finding_id}`);
    assert.strictEqual(item.human_approval_state, 'PENDING');
  }
});

test('Agent Findings Trace — Pagination Math & Bounds', () => {
  const pageSize = 10;
  const totalFindings = SAMPLE_FINDING_TRACE_ITEMS.length; // 24
  const expectedTotalPages = Math.ceil(totalFindings / pageSize); // 3

  assert.strictEqual(expectedTotalPages, 3);

  // Page 1: items 0 to 9 (10 items)
  const page1 = SAMPLE_FINDING_TRACE_ITEMS.slice(0, 10);
  assert.strictEqual(page1.length, 10);

  // Page 2: items 10 to 19 (10 items)
  const page2 = SAMPLE_FINDING_TRACE_ITEMS.slice(10, 20);
  assert.strictEqual(page2.length, 10);

  // Page 3: items 20 to 24 (4 items)
  const page3 = SAMPLE_FINDING_TRACE_ITEMS.slice(20, 30);
  assert.strictEqual(page3.length, 4);
});
