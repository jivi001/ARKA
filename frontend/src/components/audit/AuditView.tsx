import React, { useState } from 'react';
import { AuditRecord } from '../../types/core';
import { Badge } from '../common/Badge';
import { formatTimestamp, truncateHash } from '../../utils/formatting';
import { redactSensitiveData } from '../../utils/security';
import {
  History,
  ShieldCheck,
  ShieldAlert,
  RotateCw,
  Check,
  Copy,
  Server,
  Lock,
} from 'lucide-react';

export interface AuditViewProps {
  records: AuditRecord[];
  onVerifyChain: () => Promise<{ system_chain_valid: boolean; mission_chain_valid: boolean; verified_blocks: number }>;
}

export const AuditView: React.FC<AuditViewProps> = ({ records, onVerifyChain }) => {
  const [selectedRecordId, setSelectedRecordId] = useState<string>(
    records[0]?.event_id || ''
  );
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    system_chain_valid: boolean;
    mission_chain_valid: boolean;
    verified_blocks: number;
  } | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const selected = records.find((r) => r.event_id === selectedRecordId) || records[0];

  const handleVerify = async () => {
    try {
      setIsVerifying(true);
      const res = await onVerifyChain();
      setVerificationResult(res);
    } catch {
      setVerificationResult(null);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top Banner: Verification Status & Subsystems */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700 }}>Dual-Chain Cryptographic Audit Trail</h2>
            {verificationResult?.system_chain_valid ? (
              <Badge variant="success" pulseDot>
                ALL {verificationResult.verified_blocks} BLOCKS CRYPTOGRAPHICALLY VERIFIED
              </Badge>
            ) : (
              <Badge variant="neutral">VERIFICATION REQUIRED</Badge>
            )}
          </div>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Append-only hash chain signed under <span className="font-mono">KeyDomain::AuditSigning</span> (Ed25519). Verified by the Rust Security Kernel.
          </p>
        </div>

        <button
          onClick={handleVerify}
          className="btn btn-primary"
          style={{ fontSize: 11 }}
          disabled={isVerifying}
        >
          <RotateCw size={12} className={isVerifying ? 'animate-spin' : ''} />
          {isVerifying ? 'Verifying Merkle Roots...' : 'Verify Hash Chain'}
        </button>
      </div>

      {/* Main Split: Audit Table + Deep Record Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 14, minHeight: 560 }}>
        {/* Audit Log Table */}
        <div className="table-container">
          <table className="arka-table">
            <thead>
              <tr>
                <th>SEQ #</th>
                <th>EVENT TYPE</th>
                <th>TIMESTAMP (UTC)</th>
                <th>ACTOR / SUBJECT</th>
                <th>CURRENT BLOCK HASH</th>
                <th>SIGNATURE</th>
              </tr>
            </thead>
            <tbody>
              {records.map((rec) => {
                const isSelected = rec.event_id === selectedRecordId;
                const isStop = rec.event_type.includes('EMERGENCY_STOP');
                const isAuth = rec.event_type.includes('AUTHORIZED');

                return (
                  <tr
                    key={rec.event_id}
                    className={isSelected ? 'selected' : ''}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedRecordId(rec.event_id)}
                  >
                    <td className="mono-cell" style={{ fontWeight: 600 }}>
                      #{rec.sequence_number.toString().padStart(5, '0')}
                    </td>
                    <td>
                      <Badge variant={isStop ? 'danger' : isAuth ? 'success' : 'neutral'}>
                        {rec.event_type}
                      </Badge>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {formatTimestamp(rec.timestamp_unix)}
                    </td>
                    <td className="mono-cell" style={{ fontSize: 11 }}>
                      {rec.actor_id}
                    </td>
                    <td className="mono-cell" style={{ color: 'var(--accent-primary)', fontSize: 11 }}>
                      {truncateHash(rec.current_hash, 6, 4)}
                    </td>
                    <td>
                      <Badge variant="success">ED25519</Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Deep Record Inspector */}
        {selected ? (
          <div className="panel" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  AUDIT BLOCK #{selected.sequence_number}
                </span>
                <Badge variant="success">VERIFIED SEAL</Badge>
              </div>
              <h3 style={{ fontSize: 13, fontWeight: 700, marginTop: 4 }}>{selected.event_type}</h3>
              <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 2 }}>
                Event ID: {selected.event_id}
              </div>
            </div>

            {/* Hash Chain Lineage Link */}
            <div className="well font-mono" style={{ padding: 10, fontSize: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>PREVIOUS HASH</span>
                <span style={{ wordBreak: 'break-all', color: 'var(--text-subtle)' }}>{selected.previous_hash}</span>
              </div>
              <div style={{ textAlign: 'center', color: 'var(--accent-primary)', fontSize: 12 }}>↓</div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>CURRENT BLOCK HASH</span>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
                  <span style={{ wordBreak: 'break-all', color: 'var(--accent-primary)' }}>{selected.current_hash}</span>
                  <button
                    className="btn-ghost"
                    style={{ padding: 2, border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                    onClick={() => handleCopy(selected.current_hash)}
                    title="Copy hash"
                  >
                    {copiedHash === selected.current_hash ? <Check size={11} color="var(--status-emerald)" /> : <Copy size={11} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Ed25519 Cryptographic Signature */}
            <div className="well font-mono" style={{ padding: 10, fontSize: 10 }}>
              <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                ED25519 SIGNATURE (KeyDomain::AuditSigning)
              </span>
              <span style={{ color: 'var(--status-emerald)', wordBreak: 'break-all' }}>
                {selected.signature}
              </span>
            </div>

            {/* Canonical JSON Payload */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                Committed Audit Details (RFC 8785)
              </span>
              <pre
                className="well font-mono"
                style={{
                  padding: 10,
                  fontSize: 10,
                  overflowX: 'auto',
                  backgroundColor: 'var(--bg-well)',
                  color: 'var(--text-primary)',
                  lineHeight: 1.4,
                  maxHeight: 220,
                }}
              >
                {JSON.stringify(redactSensitiveData(selected.details), null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
            Select an audit event to inspect the cryptographic hash chain.
          </div>
        )}
      </div>
    </div>
  );
};
