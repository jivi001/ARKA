import React, { useState } from 'react';
import { EvidenceRecord } from '../../types/core';
import { Badge } from '../common/Badge';
import { truncateHash, formatTimestamp } from '../../utils/formatting';
import { Database, ShieldCheck, AlertCircle, Copy, Check, Terminal } from 'lucide-react';

export interface EvidenceViewProps {
  evidenceList: EvidenceRecord[];
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ evidenceList }) => {
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>(
    evidenceList[0]?.evidence_id || ''
  );
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const selected = evidenceList.find((e) => e.evidence_id === selectedEvidenceId) || evidenceList[0];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 14, minHeight: 600 }}>
      {/* Evidence List */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 13, fontWeight: 600 }}>Cryptographic Evidence Ledger</h3>
            <span className="badge badge-neutral">{evidenceList.length} VAULT ITEMS</span>
          </div>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {evidenceList.map((ev) => {
            const isSelected = ev.evidence_id === selectedEvidenceId;
            const isVerified = ev.trust_level === 'KERNEL_VERIFIED_SIGNATURE';

            return (
              <div
                key={ev.evidence_id}
                onClick={() => setSelectedEvidenceId(ev.evidence_id)}
                style={{
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: isSelected ? 'var(--bg-surface-base)' : 'var(--bg-surface-low)',
                  border: isSelected ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="font-mono text-primary" style={{ fontSize: 11, fontWeight: 600 }}>
                    {ev.payload_type}
                  </span>
                  <Badge variant={isVerified ? 'success' : 'neutral'}>
                    {isVerified ? 'SIGNED' : 'RAW TARGET'}
                  </Badge>
                </div>

                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Cap: <span className="font-mono">{ev.originating_capability}</span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-subtle)' }}>
                  <span className="font-mono">{truncateHash(ev.content_hash, 6, 4)}</span>
                  <span>{formatTimestamp(ev.timestamp_unix).split(' ')[1]}</span>
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
                <h2 style={{ fontSize: 15, fontWeight: 700 }}>{selected.payload_type}</h2>
                <Badge variant={selected.trust_level === 'KERNEL_VERIFIED_SIGNATURE' ? 'success' : 'neutral'}>
                  {selected.trust_level}
                </Badge>
              </div>
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                Evidence ID: {selected.evidence_id} | Mission: {selected.mission_id}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="badge badge-success font-mono">TAMPER-PROOF LEDGER SEAL</span>
            </div>
          </div>

          {/* Provenance Strip */}
          <div className="well" style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, fontSize: 11 }}>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>ORIGINATING AGENT</span>
              <span className="font-mono text-primary">{selected.provenance.agent_id}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>BROKER SANDBOX</span>
              <span className="font-mono">{selected.provenance.broker_sandbox}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>KERNEL RECEIPT TICKET</span>
              <span className="font-mono">{selected.provenance.kernel_ticket_receipt}</span>
            </div>
          </div>

          {/* Hash Strip */}
          <div className="well" style={{ padding: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
            <span style={{ color: 'var(--text-muted)' }}>Content SHA-256 Digest:</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="font-mono text-primary">{selected.content_hash}</span>
              <button
                className="btn-ghost"
                style={{ padding: 2, border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                onClick={() => handleCopy(selected.content_hash)}
                title="Copy hash"
              >
                {copiedHash === selected.content_hash ? <Check size={12} color="var(--status-emerald)" /> : <Copy size={12} />}
              </button>
            </div>
          </div>

          {/* Raw Payload Stream Viewer */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                Captured Evidence Output Stream
              </span>
              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
                Immutable Payload
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
                maxHeight: 320,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {selected.payload_preview}
            </pre>
          </div>
        </div>
      ) : (
        <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
          Select an evidence record from the vault.
        </div>
      )}
    </div>
  );
};
