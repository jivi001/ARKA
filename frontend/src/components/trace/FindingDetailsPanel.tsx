import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  FileText,
  Database,
  History,
  Shield,
  Clock,
  Download,
  CheckCircle2,
  XCircle,
  Copy,
  ExternalLink,
  Lock,
  FileCode,
  AlertTriangle,
} from 'lucide-react';
import {
  FindingTraceItem,
  FindingEvidenceArtifact,
  FindingAuditEvent,
} from '../../types/findingsTrace';
import { formatTimestamp } from '../../utils/formatting';
import { maskToken } from '../../utils/security';

export interface FindingDetailsPanelProps {
  finding: FindingTraceItem | null;
  onClose?: () => void;
  onNavigateToAudit?: () => void;
}

type DetailsTab = 'overview' | 'evidence' | 'policy' | 'audit';

export const FindingDetailsPanel: React.FC<FindingDetailsPanelProps> = ({
  finding,
  onClose,
  onNavigateToAudit,
}) => {
  const [activeTab, setActiveTab] = useState<DetailsTab>('overview');
  const [selectedArtifact, setSelectedArtifact] = useState<FindingEvidenceArtifact | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (!finding) {
    return (
      <aside
        className="panel"
        style={{
          width: 340,
          minWidth: 320,
          backgroundColor: 'var(--bg-surface-base)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-card)',
          boxShadow: 'var(--shadow-subtle)',
          padding: 24,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          color: 'var(--text-muted)',
          height: '100%',
          minHeight: 480,
        }}
        aria-label="Finding Details Panel (Empty)"
      >
        <div
          style={{
            width: 44,
            height: 44,
            borderRadius: '50%',
            backgroundColor: 'var(--bg-well)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 12,
            color: 'var(--accent-primary)',
          }}
        >
          <FileText size={20} />
        </div>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          No Finding Selected
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 220, lineHeight: 1.4 }}>
          Select any finding row from the table to trace its evidence, policy decision, and cryptographic audit records.
        </div>
      </aside>
    );
  }

  const isDenied = finding.policy_decision === 'DENY';
  const isReqApproval = finding.policy_decision === 'REQUIRE_APPROVAL';

  return (
    <aside
      className="panel"
      style={{
        width: 350,
        minWidth: 320,
        maxWidth: 380,
        backgroundColor: 'var(--bg-surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-card)',
        boxShadow: 'var(--shadow-surface)',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        minHeight: 600,
        overflow: 'hidden',
      }}
      aria-label={`Finding Details for ${finding.finding_id}`}
    >
      {/* Panel Top Header */}
      <div
        style={{
          padding: '14px 16px',
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-low)',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* Severity Pill */}
            <span
              style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                padding: '2px 7px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor:
                  finding.severity === 'CRITICAL'
                    ? 'var(--status-coral-dim)'
                    : finding.severity === 'HIGH'
                    ? 'var(--status-amber-dim)'
                    : 'var(--accent-primary-dim)',
                color:
                  finding.severity === 'CRITICAL'
                    ? 'var(--status-coral)'
                    : finding.severity === 'HIGH'
                    ? 'var(--status-amber)'
                    : 'var(--accent-primary)',
                border: `1px solid ${
                  finding.severity === 'CRITICAL'
                    ? 'var(--status-coral-border)'
                    : finding.severity === 'HIGH'
                    ? 'var(--status-amber-border)'
                    : 'var(--border-highlight)'
                }`,
              }}
            >
              {finding.severity}
            </span>

            <span
              className="font-mono"
              style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}
            >
              {finding.finding_id}
            </span>
          </div>

          {onClose && (
            <button
              onClick={onClose}
              className="btn-ghost"
              style={{
                padding: 4,
                color: 'var(--text-muted)',
                cursor: 'pointer',
                border: 'none',
              }}
              aria-label="Close details panel"
            >
              <X size={15} />
            </button>
          )}
        </div>

        {/* Title */}
        <h3
          style={{
            fontSize: 14,
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '-0.01em',
            lineHeight: 1.3,
            marginTop: 2,
          }}
        >
          {finding.title}
        </h3>

        <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          {finding.target_scope_status === 'EXCLUDED_TARGET' ? (
            <span style={{ color: 'var(--status-coral)', fontWeight: 600 }}>
              Target matches explicit exclusion rule.
            </span>
          ) : (
            <span>Target verified in active scope.</span>
          )}{' '}
          {finding.cve_id && <span className="font-mono">({finding.cve_id})</span>}
        </div>
      </div>

      {/* Tabs navigation */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-lowest)',
        }}
        role="tablist"
      >
        {(['overview', 'evidence', 'policy', 'audit'] as DetailsTab[]).map((tabKey) => {
          const isActive = activeTab === tabKey;
          const labels: Record<DetailsTab, string> = {
            overview: 'Overview',
            evidence: `Evidence (${finding.evidence_artifacts.length})`,
            policy: 'Policy',
            audit: `Audit (${finding.audit_events.length})`,
          };

          return (
            <button
              key={tabKey}
              onClick={() => {
                setActiveTab(tabKey);
                setSelectedArtifact(null);
              }}
              style={{
                padding: '8px 4px',
                fontSize: 11,
                fontWeight: isActive ? 600 : 400,
                textAlign: 'center',
                backgroundColor: isActive ? 'var(--bg-surface-base)' : 'transparent',
                color: isActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                borderTop: 'none',
                borderLeft: 'none',
                borderRight: 'none',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              role="tab"
              aria-selected={isActive}
            >
              {labels[tabKey]}
            </button>
          );
        })}
      </div>

      {/* Tab Content Body */}
      <div
        style={{
          padding: 14,
          overflowY: 'auto',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}
      >
        {/* ===================== TAB 1: OVERVIEW ===================== */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Key-Value Metrics Grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 8,
              }}
            >
              <div
                style={{
                  padding: 8,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-well)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Source Agent</div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
                  {finding.source_agent}
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{finding.agent_role}</div>
              </div>

              <div
                style={{
                  padding: 8,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-well)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Target Host</div>
                <div
                  className="font-mono"
                  style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}
                >
                  {finding.target}
                </div>
                <div
                  style={{
                    fontSize: 9,
                    color:
                      finding.target_scope_status === 'EXCLUDED_TARGET'
                        ? 'var(--status-coral)'
                        : 'var(--status-emerald)',
                    fontWeight: 600,
                  }}
                >
                  {finding.target_scope_status}
                </div>
              </div>

              <div
                style={{
                  padding: 8,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-well)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Risk Score</div>
                <div
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color:
                      finding.risk_score >= 8.5
                        ? 'var(--status-coral)'
                        : finding.risk_score >= 6
                        ? 'var(--status-amber)'
                        : 'var(--accent-primary)',
                    marginTop: 2,
                  }}
                >
                  {finding.risk_score_scale}
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-secondary)' }}>{finding.scoring_source}</div>
              </div>

              <div
                style={{
                  padding: 8,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-well)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Kernel Decision</div>
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: isDenied
                      ? 'var(--status-coral)'
                      : isReqApproval
                      ? 'var(--status-amber)'
                      : 'var(--status-emerald)',
                    marginTop: 2,
                  }}
                >
                  {finding.policy_decision}
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-secondary)' }}>
                  Evaluated: {formatTimestamp(finding.policy_evaluation_time_unix)}
                </div>
              </div>
            </div>

            {/* Factual Description */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                Factual Evidence Description
              </div>
              <div
                style={{
                  fontSize: 11,
                  lineHeight: 1.45,
                  color: 'var(--text-secondary)',
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-surface-low)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {finding.factual_description}
              </div>
            </div>

            {/* Remediation Guidance */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                Recommended Remediation
              </div>
              <div
                style={{
                  fontSize: 11,
                  lineHeight: 1.45,
                  color: 'var(--text-secondary)',
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-surface-low)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {finding.remediation_guidance}
              </div>
            </div>
          </div>
        )}

        {/* ===================== TAB 2: EVIDENCE ===================== */}
        {activeTab === 'evidence' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Raw network artifacts collected in rootless sandbox with SHA-256 integrity verification:
            </div>

            {/* Artifact list */}
            {finding.evidence_artifacts.map((artifact) => {
              const isSelected = selectedArtifact?.id === artifact.id;

              return (
                <div
                  key={artifact.id}
                  onClick={() => setSelectedArtifact(artifact)}
                  style={{
                    padding: 10,
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: isSelected
                      ? 'var(--accent-primary-dim)'
                      : 'var(--bg-surface-low)',
                    border: isSelected
                      ? '1px solid var(--accent-primary)'
                      : '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                  }}
                  role="button"
                  tabIndex={0}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <FileCode size={14} style={{ color: 'var(--accent-primary)' }} />
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {artifact.filename}
                      </span>
                    </div>

                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                      {(artifact.size_bytes / 1024).toFixed(1)} KB
                    </span>
                  </div>

                  <div
                    className="font-mono"
                    style={{ fontSize: 9, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}
                  >
                    <span>{artifact.content_hash.slice(0, 24)}...</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopy(artifact.content_hash);
                      }}
                      className="btn-ghost"
                      style={{ padding: 2, cursor: 'pointer', border: 'none', color: 'var(--text-muted)' }}
                      title="Copy full SHA-256 hash"
                      aria-label="Copy SHA-256 hash"
                    >
                      <Copy size={10} />
                    </button>
                    {copiedHash === artifact.content_hash && (
                      <span style={{ color: 'var(--status-emerald)', fontSize: 8 }}>COPIED</span>
                    )}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 2 }}>
                    <span
                      style={{
                        fontSize: 9,
                        fontFamily: 'var(--font-mono)',
                        padding: '1px 5px',
                        borderRadius: 'var(--radius-xs)',
                        backgroundColor: 'var(--bg-well)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {artifact.capability}
                    </span>

                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 600,
                        color:
                          artifact.trust_level === 'KERNEL_VERIFIED_SIGNATURE'
                            ? 'var(--status-emerald)'
                            : 'var(--status-amber)',
                      }}
                    >
                      {artifact.trust_level === 'KERNEL_VERIFIED_SIGNATURE'
                        ? 'VERIFIED'
                        : 'RAW UNTRUSTED'}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Sanitized Preview Drawer */}
            {selectedArtifact && (
              <div
                style={{
                  marginTop: 6,
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-well)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Sanitized Preview: {selectedArtifact.filename}
                  </div>
                  <button
                    onClick={() => setSelectedArtifact(null)}
                    className="btn-ghost"
                    style={{ fontSize: 10, color: 'var(--text-muted)', cursor: 'pointer', border: 'none' }}
                  >
                    Close
                  </button>
                </div>

                <div
                  style={{
                    fontSize: 9,
                    color: 'var(--status-amber)',
                    marginBottom: 6,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <AlertTriangle size={11} />
                  <span>Rendered in quarantined read-only sandbox. Script execution disabled.</span>
                </div>

                <pre
                  className="font-mono"
                  style={{
                    fontSize: 10,
                    lineHeight: 1.4,
                    color: 'var(--text-secondary)',
                    backgroundColor: 'var(--bg-surface-lowest)',
                    padding: 8,
                    borderRadius: 'var(--radius-xs)',
                    overflowX: 'auto',
                    maxHeight: 180,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}
                >
                  {selectedArtifact.sanitized_preview}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* ===================== TAB 3: POLICY ===================== */}
        {activeTab === 'policy' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {/* Policy Decision Banner */}
            <div
              style={{
                padding: 10,
                borderRadius: 'var(--radius-sm)',
                backgroundColor: isDenied
                  ? 'var(--status-coral-dim)'
                  : isReqApproval
                  ? 'var(--status-amber-dim)'
                  : 'var(--status-emerald-dim)',
                border: `1px solid ${
                  isDenied
                    ? 'var(--status-coral-border)'
                    : isReqApproval
                    ? 'var(--status-amber-border)'
                    : 'var(--status-emerald-border)'
                }`,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {isDenied ? (
                  <XCircle size={15} style={{ color: 'var(--status-coral)' }} />
                ) : isReqApproval ? (
                  <Clock size={15} style={{ color: 'var(--status-amber)' }} />
                ) : (
                  <ShieldCheck size={15} style={{ color: 'var(--status-emerald)' }} />
                )}
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color: isDenied
                      ? 'var(--status-coral)'
                      : isReqApproval
                      ? 'var(--status-amber)'
                      : 'var(--status-emerald)',
                  }}
                >
                  {isDenied
                    ? 'AUTHORITATIVE KERNEL DENIAL'
                    : isReqApproval
                    ? 'TWO-PERSON INTEGRITY APPROVAL REQUIRED'
                    : 'AUTHORIZED BY SECURITY KERNEL'}
                </span>
              </div>
              <div
                style={{
                  fontSize: 11,
                  lineHeight: 1.4,
                  marginTop: 6,
                  color: 'var(--text-primary)',
                }}
              >
                {finding.policy_reason}
              </div>
            </div>

            {/* Policy Parameters */}
            <div
              style={{
                padding: 10,
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-surface-low)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
                fontSize: 11,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Policy Rule ID:</span>
                <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                  {finding.policy_rule_id}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Active Scope:</span>
                <span className="font-mono" style={{ color: 'var(--accent-primary)' }}>
                  {finding.scope_ref}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Enforcing Daemon:</span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                  {finding.kernel_version}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Evaluation Timestamp:</span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                  {formatTimestamp(finding.policy_evaluation_time_unix)}
                </span>
              </div>

              {finding.approval_id && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Approval Ticket:</span>
                  <span className="font-mono" style={{ color: 'var(--status-amber)', fontWeight: 600 }}>
                    {finding.approval_id}
                  </span>
                </div>
              )}
            </div>

            <div
              style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                lineHeight: 1.4,
                padding: 8,
                backgroundColor: 'var(--bg-well)',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              INVARIANT CHECK: Target scope boundary evaluation is evaluated deterministically in Rust.
              No frontend client or LLM agent can override kernel scope rules.
            </div>
          </div>
        )}

        {/* ===================== TAB 4: AUDIT TRAIL ===================== */}
        {activeTab === 'audit' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                Append-only cryptographic audit records:
              </span>
              {onNavigateToAudit && (
                <button
                  onClick={onNavigateToAudit}
                  className="btn-ghost"
                  style={{
                    fontSize: 11,
                    color: 'var(--accent-primary)',
                    fontWeight: 600,
                    cursor: 'pointer',
                    padding: 0,
                    border: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 3,
                  }}
                >
                  <span>Full Ledger</span>
                  <ExternalLink size={11} />
                </button>
              )}
            </div>

            {finding.audit_events.map((evt) => (
              <div
                key={evt.event_id}
                style={{
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-surface-low)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      color: 'var(--accent-primary)',
                    }}
                  >
                    #{evt.sequence_number} · {evt.event_type}
                  </span>

                  <span
                    style={{
                      fontSize: 9,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--status-emerald)',
                      fontWeight: 700,
                    }}
                  >
                    ED25519 VERIFIED
                  </span>
                </div>

                <div style={{ fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.35 }}>
                  {evt.summary}
                </div>

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: 9,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)',
                    marginTop: 4,
                  }}
                >
                  <span>Actor: {evt.actor_id}</span>
                  <span>{formatTimestamp(evt.timestamp_unix)}</span>
                </div>

                <div
                  className="font-mono"
                  style={{
                    fontSize: 8,
                    color: 'var(--text-subtle)',
                    backgroundColor: 'var(--bg-well)',
                    padding: '3px 6px',
                    borderRadius: 'var(--radius-xs)',
                    wordBreak: 'break-all',
                    marginTop: 2,
                  }}
                >
                  Sig: {evt.signature.slice(0, 36)}...
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Panel Sticky Footer */}
      <div
        style={{
          padding: '8px 14px',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-low)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)',
        }}
      >
        <span>ARKA SEC-KERNEL v2.2</span>
        <span style={{ color: 'var(--accent-primary)' }}>FAIL-CLOSED VERIFIED</span>
      </div>
    </aside>
  );
};
