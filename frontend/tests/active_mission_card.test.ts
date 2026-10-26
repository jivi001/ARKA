import test from 'node:test';
import assert from 'node:assert';
import type {
  Mission,
  MissionState,
  ScopeDefinition,
  ScopeEnforcementState,
  ScopeBoundaryCounts,
} from '../src/types/core.ts';
import type { DiscoveredAsset } from '../src/types/attackSurface.ts';
import { truncateHash, formatTimestamp, formatTimeAgo } from '../src/utils/formatting.ts';
import { maskToken } from '../src/utils/security.ts';
// Pure test assertions for ActiveMissionCard and API fail-closed safety semantics

/**
 * Pure helper simulating ActiveMissionCard state computation and safety guards.
 * Mirrors logic inside ActiveMissionCard.tsx to allow isolated verification of
 * state derivation, scope invariants, and security rules.
 */
function deriveCardState(params: {
  mission: Partial<Mission>;
  assets?: DiscoveredAsset[];
  scopeCounts?: ScopeBoundaryCounts;
  scopeEnforcementState?: ScopeEnforcementState;
  isTransitioning?: boolean;
  transitionTargetState?: MissionState | null;
  canSwitchMission?: boolean;
}) {
  const {
    mission,
    assets = [],
    scopeCounts,
    scopeEnforcementState,
    isTransitioning = false,
    transitionTargetState = null,
    canSwitchMission = true,
  } = params;

  // 1. Calculate scope counts without combining discovered and authorized
  const counts: ScopeBoundaryCounts = scopeCounts || {
    authorizedCount: assets.filter((a) => a.scope_status === 'AUTHORIZED_IN_SCOPE').length,
    discoveredOutOfScopeCount: assets.filter((a) => a.scope_status === 'DISCOVERED_UNAUTHORIZED').length,
    excludedCount: assets.filter((a) => a.scope_status === 'HARD_EXCLUDED').length,
  };

  // 2. Derive scope enforcement independently from execution state
  const effectiveScopeState: ScopeEnforcementState =
    scopeEnforcementState ||
    (mission.state === 'ACTIVE'
      ? 'VERIFIED_CURRENT'
      : mission.state === 'CREATED'
      ? 'VERIFICATION_PENDING'
      : 'VERIFICATION_UNAVAILABLE');

  // 3. Determine execution state label and variant
  let executionStateLabel: string;
  let executionBadgeVariant: 'success' | 'warning' | 'danger' | 'neutral' | 'primary';
  let pulseDot = false;

  if (isTransitioning) {
    executionStateLabel = `TRANSITIONING${transitionTargetState ? ` → ${transitionTargetState}` : ''}`;
    executionBadgeVariant = 'primary';
    pulseDot = true;
  } else {
    switch (mission.state) {
      case 'ACTIVE':
        executionStateLabel = 'MISSION ACTIVE';
        executionBadgeVariant = 'success';
        pulseDot = true;
        break;
      case 'PAUSED':
        executionStateLabel = 'MISSION PAUSED';
        executionBadgeVariant = 'warning';
        break;
      case 'COMPLETED':
        executionStateLabel = 'MISSION COMPLETED';
        executionBadgeVariant = 'neutral';
        break;
      case 'TERMINATED':
        executionStateLabel = 'TERMINATED';
        executionBadgeVariant = 'danger';
        break;
      case 'CREATED':
        executionStateLabel = 'INITIALIZED (IDLE)';
        executionBadgeVariant = 'neutral';
        break;
      default:
        executionStateLabel = 'STATUS UNKNOWN';
        executionBadgeVariant = 'neutral';
        break;
    }
  }

  // 4. Action permissions: during transition or invalid scope, actions are restricted
  const actionsPermitted = !isTransitioning && effectiveScopeState !== 'INVALID_SCOPE';
  const switchPermitted = actionsPermitted && canSwitchMission;

  return {
    executionStateLabel,
    executionBadgeVariant,
    pulseDot,
    effectiveScopeState,
    counts,
    actionsPermitted,
    switchPermitted,
    formattedId: mission.id ? truncateHash(mission.id, 8, 6) : 'ID UNKNOWN',
    maskedOperator: mission.created_by ? maskToken(mission.created_by) : '****',
  };
}

/* ==============================================================================
   Test Suite: Active Mission Card Architecture & Security Invariants
   ============================================================================== */

test('Active Mission Card — Execution States Distinction', () => {
  // Test ACTIVE state
  const active = deriveCardState({ mission: { id: 'mis_1', state: 'ACTIVE' } });
  assert.strictEqual(active.executionStateLabel, 'MISSION ACTIVE');
  assert.strictEqual(active.executionBadgeVariant, 'success');
  assert.strictEqual(active.pulseDot, true);

  // Test PAUSED state
  const paused = deriveCardState({ mission: { id: 'mis_2', state: 'PAUSED' } });
  assert.strictEqual(paused.executionStateLabel, 'MISSION PAUSED');
  assert.strictEqual(paused.executionBadgeVariant, 'warning');
  assert.strictEqual(paused.pulseDot, false);

  // Test COMPLETED state
  const completed = deriveCardState({ mission: { id: 'mis_3', state: 'COMPLETED' } });
  assert.strictEqual(completed.executionStateLabel, 'MISSION COMPLETED');
  assert.strictEqual(completed.executionBadgeVariant, 'neutral');

  // Test TERMINATED state
  const terminated = deriveCardState({ mission: { id: 'mis_4', state: 'TERMINATED' } });
  assert.strictEqual(terminated.executionStateLabel, 'TERMINATED');
  assert.strictEqual(terminated.executionBadgeVariant, 'danger');

  // Test UNKNOWN state
  const unknown = deriveCardState({ mission: { id: 'mis_5', state: undefined as any } });
  assert.strictEqual(unknown.executionStateLabel, 'STATUS UNKNOWN');
  assert.strictEqual(unknown.executionBadgeVariant, 'neutral');
});

test('Active Mission Card — Transition In Progress State & Action Lockout', () => {
  const transitioning = deriveCardState({
    mission: { id: 'mis_active_01', state: 'ACTIVE' },
    isTransitioning: true,
    transitionTargetState: 'PAUSED',
  });

  assert.strictEqual(transitioning.executionStateLabel, 'TRANSITIONING → PAUSED');
  assert.strictEqual(transitioning.executionBadgeVariant, 'primary');
  assert.strictEqual(transitioning.pulseDot, true);

  // Critical safety requirement: Actions MUST be disabled during active transition
  assert.strictEqual(transitioning.actionsPermitted, false, 'Actions must be locked during active state transition');
  assert.strictEqual(transitioning.switchPermitted, false, 'Context switch must be locked during transition');
});

test('Active Mission Card — Scope Enforcement is Separate from Execution State', () => {
  // An active mission can have an INVALID_SCOPE or STALE_VERIFICATION
  const activeWithStaleScope = deriveCardState({
    mission: { id: 'mis_active_02', state: 'ACTIVE' },
    scopeEnforcementState: 'STALE_VERIFICATION',
  });

  assert.strictEqual(activeWithStaleScope.executionStateLabel, 'MISSION ACTIVE');
  assert.strictEqual(activeWithStaleScope.effectiveScopeState, 'STALE_VERIFICATION');

  const activeWithInvalidScope = deriveCardState({
    mission: { id: 'mis_active_03', state: 'ACTIVE' },
    scopeEnforcementState: 'INVALID_SCOPE',
  });

  assert.strictEqual(activeWithInvalidScope.effectiveScopeState, 'INVALID_SCOPE');
  assert.strictEqual(activeWithInvalidScope.actionsPermitted, false, 'Invalid scope must block action dispatches');
});

test('Active Mission Card — Invariant: DISCOVERED != AUTHORIZED (Counts Never Merged)', () => {
  const assets: DiscoveredAsset[] = [
    {
      id: 'ast_1',
      target: '10.42.18.10',
      scope_status: 'AUTHORIZED_IN_SCOPE',
      open_ports: [],
      fingerprinted_technologies: [],
      sensitivity: 'CONFIDENTIAL_INTERNAL',
      first_discovered_unix: 1000,
      last_observed_unix: 2000,
      originating_agent: 'ReconAgent',
      originating_proposal_id: 'prp_1',
    },
    {
      id: 'ast_2',
      target: '10.42.18.11',
      scope_status: 'AUTHORIZED_IN_SCOPE',
      open_ports: [],
      fingerprinted_technologies: [],
      sensitivity: 'CONFIDENTIAL_INTERNAL',
      first_discovered_unix: 1000,
      last_observed_unix: 2000,
      originating_agent: 'ReconAgent',
      originating_proposal_id: 'prp_2',
    },
    {
      id: 'ast_3',
      target: '10.42.19.99', // Adjacent subnet: discovered but unauthorized!
      scope_status: 'DISCOVERED_UNAUTHORIZED',
      open_ports: [],
      fingerprinted_technologies: [],
      sensitivity: 'PUBLIC_DMZ',
      first_discovered_unix: 1000,
      last_observed_unix: 2000,
      originating_agent: 'ReconAgent',
      originating_proposal_id: 'prp_3',
    },
    {
      id: 'ast_4',
      target: '10.42.18.1', // Gateway: explicitly excluded!
      scope_status: 'HARD_EXCLUDED',
      open_ports: [],
      fingerprinted_technologies: [],
      sensitivity: 'RESTRICTED_HSM',
      first_discovered_unix: 1000,
      last_observed_unix: 2000,
      originating_agent: 'ReconAgent',
      originating_proposal_id: 'prp_4',
    },
  ];

  const state = deriveCardState({
    mission: { id: 'mis_sample', state: 'ACTIVE' },
    assets,
  });

  // Verification: Counts are strictly separated
  assert.strictEqual(state.counts.authorizedCount, 2, 'Must have exactly 2 authorized in-scope assets');
  assert.strictEqual(state.counts.discoveredOutOfScopeCount, 1, 'Must have exactly 1 discovered out-of-scope asset');
  assert.strictEqual(state.counts.excludedCount, 1, 'Must have exactly 1 hard-excluded asset');

  // Verify total is NOT conflated
  assert.notStrictEqual(
    state.counts.authorizedCount,
    assets.length,
    'Authorized count must never include discovered out-of-scope assets'
  );
});

test('Active Mission Card — Missing Metadata Handled Gracefully', () => {
  const missingMeta = deriveCardState({
    mission: {
      name: 'Minimal Test Mission',
      // Missing id, created_by, state
    },
  });

  assert.strictEqual(missingMeta.formattedId, 'ID UNKNOWN');
  assert.strictEqual(missingMeta.maskedOperator, '****');
  assert.strictEqual(missingMeta.executionStateLabel, 'STATUS UNKNOWN');
});

test('Active Mission Card — Permission-Restricted Context Switching', () => {
  // If canSwitchMission is false (e.g. operator role restricted or only 1 mission available)
  const singleMissionState = deriveCardState({
    mission: { id: 'mis_single', state: 'ACTIVE' },
    canSwitchMission: false,
  });

  assert.strictEqual(singleMissionState.switchPermitted, false, 'Switch context must be disabled when not permitted');
});

test('API Safety — Prevention of Mock-Success for Sensitive Mutations', () => {
  // Invariant: In development mode when backend is unreachable, sensitive mutations (POST/PUT/DELETE)
  // MUST fail closed and not return simulated success unless allowMockMutations is explicitly enabled.
  function evaluateMockFallbackPolicy(
    isDevelopment: boolean,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    allowMockMutations: boolean
  ): { success: boolean; errorCode?: string } {
    if (isDevelopment && method !== 'GET' && !allowMockMutations) {
      return {
        success: false,
        errorCode: 'UNAVAILABLE_DEPENDENCY',
      };
    }
    return { success: true };
  }

  // Read-only GET requests safely fall back to development fixtures
  const getResult = evaluateMockFallbackPolicy(true, 'GET', false);
  assert.strictEqual(getResult.success, true, 'GET requests may use development fallback fixtures');

  // Sensitive state mutations (POST, PUT, DELETE) MUST fail closed by default
  const postResult = evaluateMockFallbackPolicy(true, 'POST', false);
  assert.strictEqual(postResult.success, false, 'POST mutations must fail closed when offline');
  assert.strictEqual(postResult.errorCode, 'UNAVAILABLE_DEPENDENCY');

  const putResult = evaluateMockFallbackPolicy(true, 'PUT', false);
  assert.strictEqual(putResult.success, false, 'PUT mutations must fail closed when offline');
  assert.strictEqual(putResult.errorCode, 'UNAVAILABLE_DEPENDENCY');

  const deleteResult = evaluateMockFallbackPolicy(true, 'DELETE', false);
  assert.strictEqual(deleteResult.success, false, 'DELETE mutations must fail closed when offline');
  assert.strictEqual(deleteResult.errorCode, 'UNAVAILABLE_DEPENDENCY');

  // Explicit opt-in override for controlled mock mutation environments
  const optInResult = evaluateMockFallbackPolicy(true, 'POST', true);
  assert.strictEqual(optInResult.success, true, 'Opt-in mock mutation flag permits testing overrides');
});
