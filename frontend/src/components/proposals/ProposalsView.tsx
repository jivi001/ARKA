import React, { useState } from 'react';
import { ActionProposal, RiskClass } from '../../types/core';
import { Badge } from '../common/Badge';
import { getRiskBadgeClass, truncateHash, formatTimeAgo, formatCountdown } from '../../utils/formatting';
import { redactSensitiveData } from '../../utils/security';
import { FileCode2, Copy, Check, ExternalLink, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export interface ProposalsViewProps {
  proposals: ActionProposal[];
  onSelectApprovalTab?: () => void;
}

export const ProposalsView: React.FC<ProposalsViewProps> = ({
  proposals,
  onSelectApprovalTab,
}) => {
  const [selectedProposalId, setSelectedProposalId] = useState<string>(
    proposals[0]?.proposal_id || ''
  );
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const selectedProposal = proposals.find((p) => p.proposal_id === selectedProposalId) || proposals[0];

  const filteredProposals = proposals.filter((p) => {
    if (filterDecision === 'ALL') return true;
    return p.decision === filterDecision;
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 14, minHeight: 600 }}>
      {/* Left List Pane */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Header & Filter */}
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600 }}>Action Proposals</h3>
            <span className="badge badge-neutral">{proposals.length} TOTAL</span>
          </div>

          <div style={{ display: 'flex', gap: 4, overflowX: 'auto', paddingBottom: 2 }}>
            {['ALL', 'REQUIRE_APPROVAL', 'ALLOW', 'DENY'].map((dec) => (
              <button
                key={dec}
                onClick={() => setFilterDecision(dec)}
                style={{
                  fontSize: 10,
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-xs)',
                  border: filterDecision === dec ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                  backgroundColor: filterDecision === dec ? 'var(--accent-primary-dim)' : 'transparent',
                  color: filterDecision === dec ? 'var(--accent-primary)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                {dec.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        {/* Proposals List */}
        <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {filteredProposals.map((prop) => {
            const isSelected = prop.proposal_id === selectedProposalId;
            const isCritical = prop.true_risk === 'CRITICAL';
            const isDeny = prop.decision === 'DENY';
            const isReqApp = prop.decision === 'REQUIRE_APPROVAL';

            return (
              <div
                key={prop.proposal_id}
                onClick={() => setSelectedProposalId(prop.proposal_id)}
                style={{
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isSelected ? 'var(--bg-surface-base)' : 'var(--bg-surface-low)',
                  border: isSelected
                    ? '1px solid var(--accent-primary)'
                    : isDeny
                    ? '1px solid var(--status-coral-border)'
                    : isReqApp
                    ? '1px solid var(--status-amber-border)'
                    : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                  transition: 'background-color 0.1s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
                    {prop.capability_id}
                  </span>
                  <Badge variant={isCritical ? 'danger' : isReqApp ? 'warning' : isDeny ? 'danger' : 'success'}>
                    {prop.decision}
                  </Badge>
                </div>

                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Target: <span className="font-mono text-primary">{prop.target}</span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-subtle)', marginTop: 2 }}>
                  <span>Agent: {prop.requesting_agent}</span>
                  <span>{formatTimeAgo(prop.timestamp_unix)}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Detail Inspector Pane */}
      {selectedProposal ? (
        <div className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Header Banner */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h2 style={{ fontSize: 15, fontWeight: 700 }}>{selectedProposal.capability_id}</h2>
                <Badge variant={getRiskBadgeClass(selectedProposal.true_risk) as any}>
                  {selectedProposal.true_risk} RISK
                </Badge>
                <Badge
                  variant={
                    selectedProposal.decision === 'ALLOW'
                      ? 'success'
                      : selectedProposal.decision === 'REQUIRE_APPROVAL'
                      ? 'warning'
                      : 'danger'
                  }
                >
                  {selectedProposal.decision}
                </Badge>
              </div>
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                Proposal ID: {selectedProposal.proposal_id} | Mission: {selectedProposal.mission_id}
              </div>
            </div>

            {selectedProposal.decision === 'REQUIRE_APPROVAL' && onSelectApprovalTab && (
              <button onClick={onSelectApprovalTab} className="btn btn-primary" style={{ fontSize: 11 }}>
                Open in Approval Gate →
              </button>
            )}
          </div>

          {/* Decision Rationale */}
          {selectedProposal.decision_reason && (
            <div
              style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: selectedProposal.decision === 'DENY' ? 'var(--status-coral-dim)' : 'var(--bg-surface-base)',
                border: `1px solid ${selectedProposal.decision === 'DENY' ? 'var(--status-coral-border)' : 'var(--border-subtle)'}`,
                fontSize: 12,
              }}
            >
              <strong style={{ color: selectedProposal.decision === 'DENY' ? 'var(--status-coral)' : 'var(--text-secondary)' }}>
                Kernel Evaluation Verdict:
              </strong>{' '}
              {selectedProposal.decision_reason}
            </div>
          )}

          {/* Untrusted Agent Rationale Banner */}
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: 'var(--bg-surface-base)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              fontSize: 11,
            }}
          >
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--status-amber)', textTransform: 'uppercase', marginBottom: 2 }}>
              Untrusted Agent Claim & Rationale ({selectedProposal.requesting_agent})
            </div>
            <div style={{ color: 'var(--text-primary)', fontStyle: 'italic' }}>
              "{selectedProposal.rationale}"
            </div>
          </div>

          {/* Cryptographic Hashes Strip */}
          <div className="well" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Cryptographic TOCTOU Action Binding Hashes
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Action Hash (Canonical SHA-256):</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="font-mono text-primary">{selectedProposal.action_hash}</span>
                <button
                  className="btn-ghost"
                  style={{ padding: 2, border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                  onClick={() => handleCopy(selectedProposal.action_hash)}
                  title="Copy action hash"
                >
                  {copiedHash === selectedProposal.action_hash ? <Check size={12} color="var(--status-emerald)" /> : <Copy size={12} />}
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Parameter Hash:</span>
              <span className="font-mono text-muted">{selectedProposal.parameter_hash}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Deterministic Nonce:</span>
              <span className="font-mono text-subtle">{selectedProposal.nonce}</span>
            </div>
          </div>

          {/* Normalized Parameters Code Box (RFC 8785) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                Normalized Action Parameters (RFC 8785 Canonical JSON)
              </span>
              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
                Safe redactions applied
              </span>
            </div>
            <pre
              className="well font-mono"
              style={{
                padding: 12,
                fontSize: 11,
                overflowX: 'auto',
                backgroundColor: 'var(--bg-well)',
                color: 'var(--text-primary)',
                lineHeight: 1.45,
                maxHeight: 280,
              }}
            >
              {JSON.stringify(redactSensitiveData(selectedProposal.normalized_parameters), null, 2)}
            </pre>
          </div>
        </div>
      ) : (
        <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
          Select an action proposal from the queue to view canonical parameters and cryptographic hashes.
        </div>
      )}
    </div>
  );
};
