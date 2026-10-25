/**
 * Attack Surface and Asset Discovery Types.
 * Principle: DISCOVERED != AUTHORIZED.
 */

export type ScopeStatus = 'AUTHORIZED_IN_SCOPE' | 'DISCOVERED_UNAUTHORIZED' | 'HARD_EXCLUDED';

export interface DiscoveredAsset {
  id: string;
  target: string; // IP or FQDN
  scope_status: ScopeStatus;
  open_ports: {
    port: number;
    protocol: 'TCP' | 'UDP';
    service: string;
    state: 'OPEN' | 'FILTERED' | 'CLOSED';
    banner?: string;
  }[];
  fingerprinted_technologies: string[];
  sensitivity: 'PUBLIC_DMZ' | 'CONFIDENTIAL_INTERNAL' | 'RESTRICTED_HSM';
  first_discovered_unix: number;
  last_observed_unix: number;
  originating_agent: string;
  originating_proposal_id: string;
  evidence_ref?: string;
}
