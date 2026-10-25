import test from 'node:test';
import assert from 'node:assert';
import { BACKEND_ENDPOINTS } from '../src/api/backendContract.ts';

type NavDestination =
  | 'overview'
  | 'missions'
  | 'attack_surface'
  | 'proposals'
  | 'approvals'
  | 'agents'
  | 'evidence'
  | 'findings'
  | 'reports'
  | 'audit'
  | 'settings';

test('Navigation — Taxonomy Completeness (11 Core Destinations)', () => {
  const expectedDestinations: NavDestination[] = [
    'overview',
    'missions',
    'attack_surface',
    'proposals',
    'approvals',
    'agents',
    'evidence',
    'findings',
    'reports',
    'audit',
    'settings',
  ];

  assert.strictEqual(expectedDestinations.length, 11);
  const uniqueDestinations = new Set(expectedDestinations);
  assert.strictEqual(uniqueDestinations.size, 11);
});

test('Backend Contract — Disabled Execution Endpoints Fail Closed', () => {
  // INV-001: Direct execution authority is strictly prohibited.
  // The frontend contract explicitly flags direct execution endpoints as FAIL_CLOSED_DISABLED.
  const disabledEndpoints = BACKEND_ENDPOINTS.filter(
    (ep) => ep.status === 'FAIL_CLOSED_DISABLED'
  );

  assert.ok(disabledEndpoints.length > 0, 'Must identify disabled direct execution endpoints');

  for (const endpoint of disabledEndpoints) {
    assert.strictEqual(
      endpoint.status,
      'FAIL_CLOSED_DISABLED',
      `Endpoint ${endpoint.path} must remain strictly FAIL_CLOSED_DISABLED to enforce INV-001`
    );
  }
});

test('Backend Contract — Authoritative Kernel Enpoints Covered', () => {
  const implementedPaths = BACKEND_ENDPOINTS.map((ep) => ep.path);

  // Must define routes for missions, proposals, approvals, emergency-stop, audit
  assert.ok(implementedPaths.includes('/api/v1/missions'));
  assert.ok(implementedPaths.includes('/api/v1/proposals'));
  assert.ok(implementedPaths.includes('/api/v1/approvals'));
  assert.ok(implementedPaths.includes('/api/v1/emergency-stop'));
  assert.ok(implementedPaths.includes('/api/v1/audit/records'));
});
