import React, { useState } from 'react';
import { Finding } from '../../types/findings';
import { Badge } from '../common/Badge';
import { ShieldAlert, CheckCircle2, AlertTriangle, FileText, ExternalLink } from 'lucide-react';
import { formatTimestamp } from '../../utils/formatting';

export interface FindingsViewProps {
  findings: Finding[];
  onSelectEvidence?: (evidenceId: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onSelectEvidence,
}) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    findings[0]?.finding_id || ''
  );

  const selected = findings.find((f) => f.finding_id === selectedFindingId) || findings[0];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 14, minHeight: 600 }}>
      {/* Findings List */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 13, fontWeight: 600 }}>Validated Security Findings</h3>
            <span className="badge badge-neutral">{findings.length} RECORDS</span>
          </div>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {findings.map((f) => {
            const isSelected = f.finding_id === selectedFindingId;
            const isCrit = f.severity === 'CRITICAL';

            return (
              <div
                key={f.finding_id}
                onClick={() => setSelectedFindingId(f.finding_id)}
                style={{
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isSelected ? 'var(--bg-surface-base)' : 'var(--bg-surface-low)',
                  border: isSelected
                    ? '1px solid var(--accent-primary)'
                    : isCrit
                    ? '1px solid var(--status-coral-border)'
                    : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-mono text-primary" style={{ fontSize: 11, fontWeight: 600 }}>
                    {f.cve_id || f.finding_id}
                  </span>
                  <Badge variant={isCrit ? 'danger' : 'warning'}>{f.severity}</Badge>
                </div>

                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }} className="truncate">
                  {f.title}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  <span>Asset: {f.affected_asset}</span>
                  <span className="font-mono">{f.confidence}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail Pane */}
      {selected ? (
        <div className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h2 style={{ fontSize: 15, fontWeight: 700 }}>{selected.title}</h2>
                <Badge variant={selected.severity === 'CRITICAL' ? 'danger' : 'warning'}>
                  {selected.severity}
                </Badge>
                <Badge variant="neutral">
                  CONFIDENCE: {selected.confidence.replace('_', ' ')}
                </Badge>
              </div>
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                ID: {selected.finding_id} | CVE: {selected.cve_id || 'N/A'} | Target: {selected.affected_asset}:{selected.affected_port}
              </div>
            </div>

            <Badge variant="success">STATUS: {selected.status}</Badge>
          </div>

          {/* Section 1: Observed Factual Evidence */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
              1. Observed Factual Evidence (Verified)
            </span>
            <div className="well" style={{ padding: 12, fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.5 }}>
              {selected.description_factual}
            </div>
          </div>

          {/* Section 2: Inferred Analysis & Hypothesis */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
              2. Agent Reasoning & Threat Hypothesis (Untrusted Inference)
            </span>
            <div
              style={{
                padding: 12,
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-surface-base)',
                border: '1px solid var(--border-subtle)',
                fontSize: 12,
                color: 'var(--text-secondary)',
                fontStyle: 'italic',
                lineHeight: 1.5,
              }}
            >
              "{selected.inference_narrative}"
            </div>
          </div>

          {/* Section 3: Remediation Guidance */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--status-emerald)' }}>
              3. Recommended Remediation & Containment
            </span>
            <div className="well" style={{ padding: 12, fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.5 }}>
              {selected.remediation_guidance}
            </div>
          </div>

          {/* Evidence References */}
          {selected.evidence_refs.length > 0 && onSelectEvidence && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
              <span style={{ color: 'var(--text-muted)' }}>Cryptographic Evidence Anchors:</span>
              {selected.evidence_refs.map((ref, idx) => (
                <button
                  key={idx}
                  onClick={() => onSelectEvidence(ref)}
                  className="btn btn-secondary"
                  style={{ fontSize: 10, padding: '2px 8px' }}
                >
                  <ExternalLink size={10} /> View Evidence Record
                </button>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
          Select a finding to inspect factual observations, agent reasoning, and remediation.
        </div>
      )}
    </div>
  );
};
