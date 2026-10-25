import React, { useState } from 'react';
import { Approval, ActionProposal } from '../../types/core';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';
import { AlertBanner } from '../common/AlertBanner';
import { truncateHash, formatTimestamp, formatCountdown } from '../../utils/formatting';
import { redactSensitiveData } from '../../utils/security';
import {
  CheckSquare,
  AlertTriangle,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ExternalLink,
} from 'lucide-react';

export interface ApprovalsViewProps {
  approvals: Approval[];
  proposals: ActionProposal[];
  operatorId: string;
  onApprove: (approvalId: string, actionHash: string) => Promise<void>;
  onReject: (approvalId: string, reason: string) => Promise<void>;
}

export const ApprovalsView: React.FC<ApprovalsViewProps> = ({
  approvals,
  proposals,
  operatorId,
  onApprove,
  onReject,
}) => {
  const [selectedApprovalId, setSelectedApprovalId] = useState<string>(
    approvals[0]?.approval_id || ''
  );
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
  const [isRejectModalOpen, setIsRejectModalOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const selectedApproval =
    approvals.find((a) => a.approval_id === selectedApprovalId) || approvals[0];

  const boundProposal = selectedApproval
    ? proposals.find((p) => p.action_hash === selectedApproval.action_hash)
    : null;

  const handleConfirmApproval = async () => {
    if (!selectedApproval) return;
    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      await onApprove(selectedApproval.approval_id, selectedApproval.action_hash);
      setIsConfirmModalOpen(false);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Approval failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConfirmRejection = async () => {
    if (!selectedApproval || !rejectionReason.trim()) return;
    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      await onReject(selectedApproval.approval_id, rejectionReason.trim());
      setIsRejectModalOpen(false);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Rejection failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top Banner */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 14, fontWeight: 700 }}>Two-Person Integrity Human Approval Barrier</h2>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Critical-risk and controlled exploitation operations require explicit cryptographic approval binding to the canonical action hash.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="badge badge-warning">{approvals.filter((a) => a.status === 'PENDING').length} PENDING</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 14, minHeight: 600 }}>
        {/* Left Queue Pane */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>Approval Queue</span>
          </div>

          <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {approvals.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
                No active or pending approvals in mission queue.
              </div>
            ) : (
              approvals.map((app) => {
                const prop = proposals.find((p) => p.action_hash === app.action_hash);
                const isSelected = app.approval_id === selectedApprovalId;
                const isPending = app.status === 'PENDING';

                return (
                  <div
                    key={app.approval_id}
                    onClick={() => setSelectedApprovalId(app.approval_id)}
                    style={{
                      padding: 10,
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: isSelected ? 'var(--bg-surface-base)' : 'var(--bg-surface-low)',
                      border: isSelected
                        ? '1px solid var(--accent-primary)'
                        : isPending
                        ? '1px solid var(--status-amber-border)'
                        : '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 4,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="font-mono" style={{ fontSize: 11, fontWeight: 600 }}>
                        {prop?.capability_id || 'UNKNOWN_CAPABILITY'}
                      </span>
                      <Badge variant={isPending ? 'warning' : app.status === 'CONSUMED' ? 'success' : 'danger'}>
                        {app.status}
                      </Badge>
                    </div>

                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      Target: <span className="font-mono text-primary">{prop?.target || '—'}</span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-subtle)', marginTop: 2 }}>
                      <span>Hash: {truncateHash(app.action_hash, 6, 4)}</span>
                      <span className="font-mono" style={{ color: isPending ? 'var(--status-amber)' : 'inherit' }}>
                        {formatCountdown(app.expires_at_unix)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Detail & Action Pane */}
        {selectedApproval ? (
          <div className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Header Status */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700 }}>
                    {boundProposal?.capability_id || 'Authorization Required'}
                  </h3>
                  <Badge variant="danger">CRITICAL RISK</Badge>
                  <Badge variant={selectedApproval.status === 'PENDING' ? 'warning' : 'neutral'}>
                    {selectedApproval.status}
                  </Badge>
                </div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                  Approval ID: {selectedApproval.approval_id} | Expires:{' '}
                  <span className="text-primary font-mono">{formatCountdown(selectedApproval.expires_at_unix)}</span>
                </div>
              </div>

              {/* Action Buttons */}
              {selectedApproval.status === 'PENDING' && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    onClick={() => {
                      setRejectionReason('');
                      setIsRejectModalOpen(true);
                    }}
                    className="btn btn-secondary"
                    style={{ fontSize: 11, color: 'var(--status-coral)' }}
                  >
                    Reject
                  </button>
                  <button
                    onClick={() => setIsConfirmModalOpen(true)}
                    className="btn btn-primary"
                    style={{ fontSize: 11 }}
                  >
                    <KeyRound size={12} /> Sign & Authorize
                  </button>
                </div>
              )}
            </div>

            {/* Invariant Warning Banner */}
            <AlertBanner variant="warning" title="IMMUTABLE PARAMETER HASH BINDING (INV-005)">
              Authorization is bound byte-for-byte to the canonical action hash{' '}
              <span className="font-mono">{truncateHash(selectedApproval.action_hash, 8, 6)}</span>. If any parameter, target, or timeout is modified by the agent, this approval is automatically invalidated and execution is blocked.
            </AlertBanner>

            {/* Target and Action Context */}
            <div className="well" style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, fontSize: 11 }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Target: </span>
                <span className="font-mono text-primary font-bold">{boundProposal?.target || '—'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Requesting Agent: </span>
                <span className="font-mono">{boundProposal?.requesting_agent || '—'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Action Hash: </span>
                <span className="font-mono">{truncateHash(selectedApproval.action_hash)}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Approving Operator: </span>
                <span className="font-mono text-primary">{operatorId} (Lead)</span>
              </div>
            </div>

            {/* Untrusted Agent Rationale */}
            {boundProposal?.rationale && (
              <div style={{ fontSize: 11, padding: 10, backgroundColor: 'var(--bg-surface-base)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: 10, color: 'var(--status-amber)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 2 }}>
                  Agent Stated Operational Rationale (Untrusted Input)
                </div>
                <div style={{ fontStyle: 'italic', color: 'var(--text-secondary)' }}>
                  "{boundProposal.rationale}"
                </div>
              </div>
            )}

            {/* Normalized Parameters Viewer */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
              <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                Authoritative Bound Action Payload (RFC 8785)
              </span>
              <pre
                className="well font-mono"
                style={{
                  padding: 12,
                  fontSize: 11,
                  overflowX: 'auto',
                  backgroundColor: 'var(--bg-well)',
                  color: 'var(--text-primary)',
                  lineHeight: 1.45,
                  maxHeight: 240,
                }}
              >
                {boundProposal
                  ? JSON.stringify(redactSensitiveData(boundProposal.normalized_parameters), null, 2)
                  : '// No canonical parameter payload resolved'}
              </pre>
            </div>
          </div>
        ) : (
          <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
            Select an approval request to inspect parameters and authorize execution.
          </div>
        )}
      </div>

      {/* Confirmation Modal */}
      {selectedApproval && (
        <Modal
          isOpen={isConfirmModalOpen}
          onClose={() => !isSubmitting && setIsConfirmModalOpen(false)}
          title="AUTHORIZE ACTION PROPOSAL"
          description="Two-Person Integrity Cryptographic Signature Required"
          maxWidth="460px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              You are certifying that the proposal parameters for{' '}
              <strong className="font-mono text-primary">{boundProposal?.capability_id}</strong> against target{' '}
              <strong className="font-mono text-primary">{boundProposal?.target}</strong> are verified, contained, and within the mission rules of engagement.
            </p>

            <div className="well font-mono" style={{ padding: 8, fontSize: 10, color: 'var(--text-muted)' }}>
              Bound Action Hash: {selectedApproval.action_hash}
            </div>

            {errorMessage && <span className="form-error">{errorMessage}</span>}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 8 }}>
              <button
                className="btn btn-secondary"
                onClick={() => setIsConfirmModalOpen(false)}
                disabled={isSubmitting}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleConfirmApproval}
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Verifying with Kernel...' : 'Sign with Token & Authorize'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Reject Modal */}
      {selectedApproval && (
        <Modal
          isOpen={isRejectModalOpen}
          onClose={() => !isSubmitting && setIsRejectModalOpen(false)}
          title="REJECT ACTION PROPOSAL"
          description="Document reason for operator denial"
          maxWidth="460px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="form-group">
              <label className="form-label" htmlFor="reject-reason">
                Rejection Reason (Logged to Audit Trail)
              </label>
              <textarea
                id="reject-reason"
                className="form-textarea"
                rows={3}
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="e.g. Risk exceeds engagement threshold; target service is sensitive..."
                required
              />
            </div>

            {errorMessage && <span className="form-error">{errorMessage}</span>}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 8 }}>
              <button
                className="btn btn-secondary"
                onClick={() => setIsRejectModalOpen(false)}
                disabled={isSubmitting}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={handleConfirmRejection}
                disabled={isSubmitting || !rejectionReason.trim()}
              >
                {isSubmitting ? 'Revoking...' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
