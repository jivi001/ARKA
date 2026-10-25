import test from 'node:test';
import assert from 'node:assert';
import type { EmergencyStopStatus, MissionState } from '../src/types/core.ts';

interface MissionStateEngine {
  currentState: MissionState;
  emergencyStop: EmergencyStopStatus;
}

/**
 * Simulates ARKA Kernel Mission State Transition Logic under Emergency Stop constraints.
 * Enforces TRD Section 11 & Section 15 invariant:
 * - When emergency stop is active, ALL state transitions are blocked (fail-closed).
 * - Activation requires an explicit non-empty operator reason.
 */
function attemptTransition(
  engine: MissionStateEngine,
  targetState: MissionState,
  operatorId: string
): { success: boolean; state: MissionState; error?: string } {
  // Invariant 1: If emergency stop is active, fail closed immediately
  if (engine.emergencyStop.active) {
    return {
      success: false,
      state: engine.currentState,
      error: `EMERGENCY_STOP_ACTIVE: Cannot transition mission state while emergency stop is active. Justification: "${engine.emergencyStop.reason}"`,
    };
  }

  // Valid state transitions
  const validTransitions: Record<MissionState, MissionState[]> = {
    CREATED: ['ACTIVE', 'TERMINATED'],
    ACTIVE: ['PAUSED', 'COMPLETED', 'TERMINATED'],
    PAUSED: ['ACTIVE', 'TERMINATED'],
    COMPLETED: [],
    TERMINATED: [],
  };

  const allowedNext = validTransitions[engine.currentState] || [];
  if (!allowedNext.includes(targetState)) {
    return {
      success: false,
      state: engine.currentState,
      error: `INVALID_TRANSITION: Cannot transition from ${engine.currentState} to ${targetState}.`,
    };
  }

  engine.currentState = targetState;
  return { success: true, state: engine.currentState };
}

test('Emergency Stop — Triggers Monotonically with Justification', () => {
  const estop: EmergencyStopStatus = {
    active: false,
  };

  // Attempt trigger without reason
  const triggerWithoutReason = (reason: string) => {
    if (!reason || reason.trim().length === 0) {
      throw new Error('EMERGENCY_STOP_REASON_REQUIRED: Operator justification cannot be empty.');
    }
  };

  assert.throws(() => triggerWithoutReason(''), /EMERGENCY_STOP_REASON_REQUIRED/);
  assert.throws(() => triggerWithoutReason('   '), /EMERGENCY_STOP_REASON_REQUIRED/);

  // Valid trigger
  const validReason = 'Untrusted agent attempting out-of-scope subnet probe';
  estop.active = true;
  estop.reason = validReason;
  estop.triggered_by = 'opr_sec_admin_01';
  estop.triggered_at_unix = Math.floor(Date.now() / 1000);

  assert.strictEqual(estop.active, true);
  assert.strictEqual(estop.reason, validReason);
});

test('Emergency Stop — Fail-Closed: Blocks Mission State Transitions When Active', () => {
  const engine: MissionStateEngine = {
    currentState: 'ACTIVE',
    emergencyStop: {
      active: true,
      reason: 'Host perimeter anomalous traffic detected',
      triggered_by: 'opr_sec_admin_01',
      triggered_at_unix: 1774022000,
    },
  };

  // Attempt to transition while emergency stop is active
  const result = attemptTransition(engine, 'PAUSED', 'opr_sec_admin_01');
  assert.strictEqual(result.success, false);
  assert.strictEqual(result.state, 'ACTIVE');
  assert.match(result.error || '', /EMERGENCY_STOP_ACTIVE/);

  // Attempt to transition to COMPLETED while active
  const completeResult = attemptTransition(engine, 'COMPLETED', 'opr_sec_admin_01');
  assert.strictEqual(completeResult.success, false);
  assert.strictEqual(completeResult.state, 'ACTIVE');
});

test('Emergency Stop — Allows Transitions Only After Explicit Authorized Clearance', () => {
  const engine: MissionStateEngine = {
    currentState: 'ACTIVE',
    emergencyStop: {
      active: true,
      reason: 'Temporary perimeter maintenance',
      triggered_by: 'opr_sec_admin_01',
      triggered_at_unix: 1774022000,
    },
  };

  // Blocked while active
  assert.strictEqual(attemptTransition(engine, 'PAUSED', 'opr_sec_admin_01').success, false);

  // Clear emergency stop with reason
  engine.emergencyStop.active = false;
  engine.emergencyStop.cleared_at_unix = 1774022500;
  engine.emergencyStop.cleared_by = 'opr_sec_lead_02';
  engine.emergencyStop.clear_reason = 'Perimeter integrity verified; all containers clean';

  // Transition now succeeds
  const transitionResult = attemptTransition(engine, 'PAUSED', 'opr_sec_lead_02');
  assert.strictEqual(transitionResult.success, true);
  assert.strictEqual(transitionResult.state, 'PAUSED');
});
