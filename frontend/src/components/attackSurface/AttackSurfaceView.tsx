import React, { useState } from 'react';
import { DiscoveredAsset } from '../../types/attackSurface';
import { Badge } from '../common/Badge';
import { AlertBanner } from '../common/AlertBanner';
import { formatTimestamp } from '../../utils/formatting';
import { Search, Filter, ShieldCheck, ShieldAlert, AlertTriangle, Layers, ExternalLink, Lock } from 'lucide-react';

export interface AttackSurfaceViewProps {
  assets: DiscoveredAsset[];
  onSelectEvidence?: (evidenceId: string) => void;
}

export const AttackSurfaceView: React.FC<AttackSurfaceViewProps> = ({
  assets,
  onSelectEvidence,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [scopeFilter, setScopeFilter] = useState<'ALL' | 'AUTHORIZED_IN_SCOPE' | 'DISCOVERED_UNAUTHORIZED' | 'HARD_EXCLUDED'>('ALL');
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');

  const filteredAssets = assets.filter((asset) => {
    const matchesScope = scopeFilter === 'ALL' || asset.scope_status === scopeFilter;
    const matchesSearch =
      searchTerm.trim() === '' ||
      asset.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.fingerprinted_technologies.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase())) ||
      asset.open_ports.some((p) => p.service.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesScope && matchesSearch;
  });

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const authorizedCount = assets.filter((a) => a.scope_status === 'AUTHORIZED_IN_SCOPE').length;
  const discoveredCount = assets.filter((a) => a.scope_status === 'DISCOVERED_UNAUTHORIZED').length;
  const excludedCount = assets.filter((a) => a.scope_status === 'HARD_EXCLUDED').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Scope Invariant Banner */}
      <AlertBanner variant="warning" title="GOVERNANCE INVARIANT: DISCOVERED ≠ AUTHORIZED">
        Network reconnaissance and port discovery identify potential assets, but discovered assets remain strictly inert and UNAUTHORIZED until explicitly added to the authorized scope manifest by an authenticated operator.
      </AlertBanner>

      {/* Filter and Metric Bar */}
      <div className="panel" style={{ padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        {/* Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 260 }}>
          <Search size={14} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="form-input"
            style={{ fontSize: 12, padding: '4px 8px' }}
            placeholder="Search by IP, hostname, service, or technology..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: 6 }}>
          {[
            { id: 'ALL', label: `All Assets (${assets.length})` },
            { id: 'AUTHORIZED_IN_SCOPE', label: `Authorized (${authorizedCount})` },
            { id: 'DISCOVERED_UNAUTHORIZED', label: `Discovered (${discoveredCount})` },
            { id: 'HARD_EXCLUDED', label: `Excluded (${excludedCount})` },
          ].map((pill) => (
            <button
              key={pill.id}
              onClick={() => setScopeFilter(pill.id as any)}
              style={{
                fontSize: 11,
                fontFamily: 'var(--font-mono)',
                padding: '3px 8px',
                borderRadius: 'var(--radius-xs)',
                border: scopeFilter === pill.id ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                backgroundColor: scopeFilter === pill.id ? 'var(--accent-primary-dim)' : 'transparent',
                color: scopeFilter === pill.id ? 'var(--accent-primary)' : 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Split View: Asset Table + Asset Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 14, minHeight: 520 }}>
        {/* Asset Table */}
        <div className="table-container">
          <table className="arka-table">
            <thead>
              <tr>
                <th>TARGET / ASSET</th>
                <th>SCOPE STATUS</th>
                <th>OPEN SERVICES & PORTS</th>
                <th>TECHNOLOGIES</th>
                <th>SENSITIVITY</th>
                <th>LAST OBSERVED</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                    No assets matching the current filter.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => {
                  const isSelected = asset.id === selectedAssetId;
                  const isAuthorized = asset.scope_status === 'AUTHORIZED_IN_SCOPE';
                  const isExcluded = asset.scope_status === 'HARD_EXCLUDED';

                  return (
                    <tr
                      key={asset.id}
                      className={isSelected ? 'selected' : ''}
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSelectedAssetId(asset.id)}
                    >
                      <td className="mono-cell" style={{ fontWeight: 600 }}>
                        {asset.target}
                      </td>
                      <td>
                        <Badge
                          variant={isAuthorized ? 'success' : isExcluded ? 'danger' : 'warning'}
                          pulseDot={isAuthorized}
                        >
                          {isAuthorized ? 'AUTHORIZED' : isExcluded ? 'EXCLUDED' : 'DISCOVERED (INERT)'}
                        </Badge>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {asset.open_ports.map((p) => (
                            <span
                              key={p.port}
                              className="badge badge-neutral font-mono"
                              style={{ fontSize: 9 }}
                              title={`${p.service} (${p.banner || 'no banner'})`}
                            >
                              {p.port}/{p.protocol.toLowerCase()}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {asset.fingerprinted_technologies.slice(0, 2).join(', ')}
                          {asset.fingerprinted_technologies.length > 2 ? ` (+${asset.fingerprinted_technologies.length - 2})` : ''}
                        </span>
                      </td>
                      <td>
                        <Badge variant={asset.sensitivity === 'RESTRICTED_HSM' ? 'danger' : 'neutral'}>
                          {asset.sensitivity.replace('_', ' ')}
                        </Badge>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-subtle)' }}>
                        {formatTimestamp(asset.last_observed_unix)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Right Asset Detail Pane */}
        {selectedAsset ? (
          <div className="panel" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 10 }}>
              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                ASSET INSPECTOR
              </span>
              <h3 className="font-mono text-primary" style={{ fontSize: 14, fontWeight: 700, marginTop: 2 }}>
                {selectedAsset.target}
              </h3>
              <div style={{ marginTop: 4 }}>
                <Badge
                  variant={
                    selectedAsset.scope_status === 'AUTHORIZED_IN_SCOPE'
                      ? 'success'
                      : selectedAsset.scope_status === 'HARD_EXCLUDED'
                      ? 'danger'
                      : 'warning'
                  }
                >
                  {selectedAsset.scope_status}
                </Badge>
              </div>

              {selectedAsset.scope_status === 'DISCOVERED_UNAUTHORIZED' && (
                <div
                  style={{
                    marginTop: 8,
                    padding: '8px 10px',
                    backgroundColor: 'var(--status-amber-dim)',
                    border: '1px solid var(--status-amber-border)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: 11,
                    color: 'var(--text-primary)',
                    display: 'flex',
                    gap: 6,
                    alignItems: 'flex-start',
                  }}
                >
                  <Lock size={14} style={{ color: 'var(--status-amber)', flexShrink: 0, marginTop: 1 }} />
                  <div>
                    <strong style={{ color: 'var(--status-amber)' }}>DISCOVERED ≠ AUTHORIZED:</strong>{' '}
                    Observed during reconnaissance, but not authorized for active assessment. Targeting is blocked by kernel policy.
                  </div>
                </div>
              )}

              {selectedAsset.scope_status === 'HARD_EXCLUDED' && (
                <div
                  style={{
                    marginTop: 8,
                    padding: '8px 10px',
                    backgroundColor: 'var(--status-coral-dim)',
                    border: '1px solid var(--status-coral-border)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: 11,
                    color: 'var(--text-primary)',
                    display: 'flex',
                    gap: 6,
                    alignItems: 'flex-start',
                  }}
                >
                  <ShieldAlert size={14} style={{ color: 'var(--status-coral)', flexShrink: 0, marginTop: 1 }} />
                  <div>
                    <strong style={{ color: 'var(--status-coral)' }}>EXPLICITLY EXCLUDED:</strong>{' '}
                    Matches mission exclusion boundary. All automated interactions are strictly denied.
                  </div>
                </div>
              )}
            </div>

            {/* Ports and Service Detail */}
            <div>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Open Ports & Banners
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {selectedAsset.open_ports.map((port) => (
                  <div key={port.port} className="well" style={{ padding: 8, fontSize: 11 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                      <span className="font-mono text-primary">{port.port}/{port.protocol}</span>
                      <span className="badge badge-neutral" style={{ fontSize: 9 }}>{port.service}</span>
                    </div>
                    {port.banner && (
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                        {port.banner}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Fingerprinted Technology Stack */}
            <div>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Technology Stack
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {selectedAsset.fingerprinted_technologies.map((tech, idx) => (
                  <span key={idx} className="badge badge-neutral font-mono" style={{ fontSize: 10 }}>
                    {tech}
                  </span>
                ))}
              </div>
            </div>

            {/* Discovery Provenance */}
            <div className="well" style={{ padding: 10, fontSize: 11, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Provenance & Lineage
              </span>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Discovered By: </span>
                <span className="font-mono">{selectedAsset.originating_agent}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Action: </span>
                <span className="font-mono">{selectedAsset.originating_proposal_id}</span>
              </div>
              {selectedAsset.evidence_ref && onSelectEvidence && (
                <button
                  onClick={() => onSelectEvidence(selectedAsset.evidence_ref!)}
                  className="btn btn-secondary"
                  style={{ marginTop: 6, fontSize: 10, padding: '3px 6px' }}
                >
                  <ExternalLink size={10} /> View Originating Evidence
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="panel" style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
            Select an asset to view ports, banners, and provenance.
          </div>
        )}
      </div>
    </div>
  );
};
