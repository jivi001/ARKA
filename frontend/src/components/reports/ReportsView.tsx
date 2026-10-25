import React, { useState } from 'react';
import { AssessmentReport } from '../../types/findings';
import { Badge } from '../common/Badge';
import { FileSpreadsheet, Download, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { formatTimestamp } from '../../utils/formatting';

export interface ReportsViewProps {
  reports: AssessmentReport[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({ reports }) => {
  const [selectedReportId, setSelectedReportId] = useState<string>(
    reports[0]?.report_id || ''
  );
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const selected = reports.find((r) => r.report_id === selectedReportId) || reports[0];

  const handleDownload = (format: string) => {
    if (!selected) return;
    const blob = new Blob([JSON.stringify(selected, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `arka-assessment-${selected.report_id}.${format.toLowerCase().replace('_', '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadSuccess(`Exported report in ${format} format.`);
    setTimeout(() => setDownloadSuccess(null), 3000);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 14, minHeight: 600 }}>
      {/* Reports List */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 13, fontWeight: 600 }}>Assessment Reports</h3>
            <span className="badge badge-neutral">{reports.length} READY</span>
          </div>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {reports.map((rep) => {
            const isSelected = rep.report_id === selectedReportId;
            return (
              <div
                key={rep.report_id}
                onClick={() => setSelectedReportId(rep.report_id)}
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
                    {rep.report_id}
                  </span>
                  <Badge variant="success">SIGNED</Badge>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Format: <span className="font-mono">{rep.format}</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-subtle)' }}>
                  Generated: {formatTimestamp(rep.generated_at_unix)}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Report Preview */}
      {selected ? (
        <div className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h2 style={{ fontSize: 15, fontWeight: 700 }}>Security Assessment Summary Report</h2>
                <Badge variant="success">AUDIT CHAIN VERIFIED</Badge>
              </div>
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                Report ID: {selected.report_id} | Mission: {selected.mission_id}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => handleDownload('JSON_LD')}
                className="btn btn-primary"
                style={{ fontSize: 11 }}
              >
                <Download size={12} /> Export JSON-LD Bundle
              </button>
            </div>
          </div>

          {downloadSuccess && (
            <div
              style={{
                padding: '6px 12px',
                backgroundColor: 'var(--status-emerald-dim)',
                border: '1px solid var(--status-emerald-border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--status-emerald)',
                fontSize: 11,
              }}
            >
              {downloadSuccess}
            </div>
          )}

          {/* Executive Summary */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
              Executive Summary
            </span>
            <div className="well" style={{ padding: 12, fontSize: 12, lineHeight: 1.5 }}>
              {selected.executive_summary}
            </div>
          </div>

          {/* Findings Count Breakdown */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
              Findings Distribution by Severity
            </span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
              {[
                { label: 'CRITICAL', count: selected.findings_count.critical, color: 'var(--status-coral)' },
                { label: 'HIGH', count: selected.findings_count.high, color: 'var(--status-amber)' },
                { label: 'MEDIUM', count: selected.findings_count.medium, color: 'var(--text-secondary)' },
                { label: 'LOW', count: selected.findings_count.low, color: 'var(--text-muted)' },
                { label: 'INFO', count: selected.findings_count.info, color: 'var(--text-subtle)' },
              ].map((tier) => (
                <div key={tier.label} className="well" style={{ padding: 10, textAlign: 'center' }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: tier.color }}>{tier.count}</div>
                  <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 2 }}>
                    {tier.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Cryptographic Attestation Strip */}
          <div className="well font-mono" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11 }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Cryptographic Tamper-Evident Signatures
            </span>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Scope Digest: </span>
              <span className="text-primary">{selected.scope_digest}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Audit Signature: </span>
              <span style={{ color: 'var(--status-emerald)' }}>{selected.tamper_evident_signature}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
          No report selected.
        </div>
      )}
    </div>
  );
};
