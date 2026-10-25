/**
 * Client-Side Validation Utilities.
 * NOTE: Client-side validation exists strictly for UX and early error feedback.
 * The Rust Security Kernel is the authoritative decision maker.
 */

export function isValidIpv4Cidr(cidr: string): boolean {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return false;
  const ip = parts[0];
  const prefix = parseInt(parts[1], 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const octets = ip.split('.');
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    const num = parseInt(octet, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && octet === num.toString();
  });
}

export function isValidHostname(host: string): boolean {
  const clean = host.trim();
  if (clean.length === 0 || clean.length > 253) return false;
  const pattern = /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return pattern.test(clean) || clean === 'localhost';
}

export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Evaluates whether an IP address is contained in a CIDR block.
 */
function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits = '32'] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
    const ip2long = (addr: string) =>
      addr.split('.').reduce((long, octet) => ((long << 8) + parseInt(octet, 10)) >>> 0, 0);
    return (ip2long(ip) & mask) === (ip2long(range) & mask);
  } catch {
    return false;
  }
}

export interface ExclusionRules {
  cidr_blocks?: string[];
  hostnames?: string[];
  ports?: number[];
  rationale?: string;
}

/**
 * Checks whether a candidate target violates an exclusion rule.
 * Invariant: Exclusions strictly override inclusions.
 */
export function isTargetExcluded(
  target: string,
  scopeOrExclusions: ExclusionRules | { exclusions: ExclusionRules },
  explicitPort?: number
): { excluded: boolean; reason?: string } {
  // Normalize exclusions argument whether passed as scope or directly as exclusions object
  const rules: ExclusionRules =
    'exclusions' in scopeOrExclusions && scopeOrExclusions.exclusions
      ? scopeOrExclusions.exclusions
      : (scopeOrExclusions as ExclusionRules);

  const excludedCidrs = rules.cidr_blocks || [];
  const excludedHosts = rules.hostnames || [];
  const excludedPorts = rules.ports || [];

  let cleanTarget = target.trim().toLowerCase();
  let portToCheck = explicitPort;

  // Extract port if formatted like '10.42.18.1:22' or 'example.com:443'
  if (!portToCheck && cleanTarget.includes(':') && !cleanTarget.startsWith('[')) {
    const lastColonIdx = cleanTarget.lastIndexOf(':');
    const portPart = cleanTarget.slice(lastColonIdx + 1);
    const parsedPort = parseInt(portPart, 10);
    if (!isNaN(parsedPort) && isValidPort(parsedPort)) {
      portToCheck = parsedPort;
      cleanTarget = cleanTarget.slice(0, lastColonIdx);
    }
  }

  // 1. Port exclusion check
  if (portToCheck && excludedPorts.includes(portToCheck)) {
    return {
      excluded: true,
      reason: `Port ${portToCheck} matches explicit exclusion rule (sensitive/protected service).`,
    };
  }

  // 2. Exact hostname or wildcard exclusion
  for (const excludedHost of excludedHosts) {
    const cleanExcluded = excludedHost.trim().toLowerCase();
    if (cleanExcluded.startsWith('*.')) {
      const suffix = cleanExcluded.slice(1); // e.g. '.arka.internal'
      if (cleanTarget.endsWith(suffix) || cleanTarget === cleanExcluded.slice(2)) {
        return {
          excluded: true,
          reason: `Hostname '${target}' matches wildcard exclusion '${excludedHost}'.`,
        };
      }
    } else if (cleanTarget === cleanExcluded) {
      return {
        excluded: true,
        reason: `Hostname '${target}' matches exact exclusion rule.`,
      };
    }
  }

  // 3. CIDR block exclusion
  for (const cidr of excludedCidrs) {
    if (ipInCidr(cleanTarget, cidr)) {
      return {
        excluded: true,
        reason: `Target IP '${cleanTarget}' is within excluded subnet ${cidr}.`,
      };
    }
  }

  return { excluded: false };
}
