import test from 'node:test';
import assert from 'node:assert';
import {
  isValidIpv4Cidr,
  isValidHostname,
  isValidPort,
  isTargetExcluded,
} from '../src/utils/validation.ts';
import type { ScopeDefinition } from '../src/types/core.ts';

test('Scope Rules — IPv4 CIDR Validation', () => {
  // Valid CIDR blocks
  assert.strictEqual(isValidIpv4Cidr('10.42.0.0/16'), true);
  assert.strictEqual(isValidIpv4Cidr('192.168.1.0/24'), true);
  assert.strictEqual(isValidIpv4Cidr('172.16.0.1/32'), true);
  assert.strictEqual(isValidIpv4Cidr('0.0.0.0/0'), true);

  // Invalid CIDR blocks
  assert.strictEqual(isValidIpv4Cidr('256.0.0.0/16'), false);
  assert.strictEqual(isValidIpv4Cidr('10.42.0.0/33'), false);
  assert.strictEqual(isValidIpv4Cidr('10.42.0.0'), false); // Missing prefix
  assert.strictEqual(isValidIpv4Cidr('invalid-ip/24'), false);
  assert.strictEqual(isValidIpv4Cidr(''), false);
});

test('Scope Rules — Hostname Validation', () => {
  // Valid Hostnames
  assert.strictEqual(isValidHostname('api.corp.internal'), true);
  assert.strictEqual(isValidHostname('staging-k8s.arka.sec'), true);
  assert.strictEqual(isValidHostname('backend.prod'), true);

  // Invalid Hostnames
  assert.strictEqual(isValidHostname(''), false);
  assert.strictEqual(isValidHostname('-badprefix.com'), false);
  assert.strictEqual(isValidHostname('badsuffix-.com'), false);
  assert.strictEqual(isValidHostname('has space.com'), false);
  assert.strictEqual(isValidHostname('special$char.com'), false);
});

test('Scope Rules — Port Number Validation', () => {
  // Valid Ports
  assert.strictEqual(isValidPort(1), true);
  assert.strictEqual(isValidPort(80), true);
  assert.strictEqual(isValidPort(443), true);
  assert.strictEqual(isValidPort(65535), true);

  // Invalid Ports
  assert.strictEqual(isValidPort(0), false);
  assert.strictEqual(isValidPort(-1), false);
  assert.strictEqual(isValidPort(65536), false);
  assert.strictEqual(isValidPort(80.5), false);
});

test('Scope Rules — Invariant: Exclusions Strictly Override Inclusions', () => {
  const scope: ScopeDefinition = {
    inclusions: {
      cidr_blocks: ['10.42.18.0/24'],
      hostnames: ['api.staging.internal'],
      url_origins: ['https://api.staging.internal'],
      ports: [80, 443, 8080],
    },
    exclusions: {
      cidr_blocks: ['10.42.18.1/32', '10.42.18.254/32'], // Gateway and broadcast/switch
      hostnames: ['admin.staging.internal'],
      ports: [22], // Never scan SSH
      rationale: 'Critical cluster infrastructure and production gateway protection',
    },
    policy_version: 'v2.2.0',
    canonical_hash: 'sha256:d8c11e74...',
  };

  // Target 10.42.18.10 is in inclusion CIDR and NOT in exclusion
  assert.strictEqual(isTargetExcluded('10.42.18.10', scope).excluded, false);

  // Target 10.42.18.1 is in inclusion CIDR 10.42.18.0/24, BUT explicitly listed in exclusions:
  // MUST BE EXCLUDED (Exclusion strictly overrides inclusion)
  assert.strictEqual(isTargetExcluded('10.42.18.1', scope).excluded, true);

  // Target 10.42.18.254 is in inclusion CIDR, BUT in exclusions:
  assert.strictEqual(isTargetExcluded('10.42.18.254', scope).excluded, true);

  // Target with excluded hostname:
  assert.strictEqual(isTargetExcluded('admin.staging.internal', scope).excluded, true);

  // Target with excluded port:
  assert.strictEqual(isTargetExcluded('10.42.18.10:22', scope).excluded, true);
});

test('Scope Rules — Invariant: DISCOVERED != AUTHORIZED', () => {
  // A newly discovered network asset cannot be assumed authorized
  const authorizedScope: ScopeDefinition = {
    inclusions: {
      cidr_blocks: ['10.42.18.0/24'],
      hostnames: ['api.staging.internal'],
      url_origins: ['https://api.staging.internal'],
      ports: [443],
    },
    exclusions: {
      cidr_blocks: ['10.42.18.1/32'],
      hostnames: [],
      ports: [],
      rationale: 'Gateway protection',
    },
    policy_version: 'v2.2.0',
    canonical_hash: 'sha256:test',
  };

  // Asset 1: Discovered on adjacent subnet 10.42.19.50 (outside inclusion range)
  const discoveredAdjacentIp = '10.42.19.50';
  const isInInclusionCidr = authorizedScope.inclusions.cidr_blocks.some((cidr) =>
    discoveredAdjacentIp.startsWith(cidr.replace('/24', ''))
  );
  assert.strictEqual(isInInclusionCidr, false, 'Discovered IP on adjacent subnet must not be in authorized scope');

  // Asset 2: Discovered on protected gateway 10.42.18.1 (inside CIDR, but explicitly excluded)
  const discoveredGatewayIp = '10.42.18.1';
  const isExcluded = isTargetExcluded(discoveredGatewayIp, authorizedScope).excluded;
  assert.strictEqual(isExcluded, true, 'Discovered gateway IP must be marked excluded even if observed responding');
});
