import React, { useState } from 'react';
import { OctagonAlert, RotateCcw, AlertTriangle, ShieldCheck } from 'lucide-react';
import { EmergencyStopStatus } from '../../types/core';
import { Modal } from '../common/Modal';

export interface EmergencyStopControlProps {
  status: EmergencyStopStatus;
  operatorId: string;
  onTrigger: (reason: string) => Promise<void>;
  onClear: (clearReason: string) => Promise<void>;
}

export const EmergencyStopControl: React.FC<EmergencyStopControlProps> = ({
  status,
  operatorId,
  onTrigger,
  onClear,
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'TRIGGER' | 'CLEAR'>('TRIGGER');
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleOpenTrigger = () => {
    setModalMode('TRIGGER');
    setReason('');
    setError(null);
    setIsModalOpen(true);
  };

  const handleOpenClear = () => {
    setModalMode('CLEAR');
    setReason('');
    setError(null);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) {
      setError('A mandatory reason is required for emergency stop state mutations.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      if (modalMode === 'TRIGGER') {
        await onTrigger(reason.trim());
      } else {
        await onClear(reason.trim());
      }
      setIsModalOpen(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Operation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      {status.active ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button
            onClick={handleOpenClear}
            className="btn btn-danger"
            style={{
              padding: '4px 10px',
              fontSize: 11,
              backgroundColor: 'var(--status-coral)',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
            title="Emergency Stop is currently ACTIVE. Click to resume operations."
            aria-label="Resume Operations"
          >
            <RotateCcw size={13} />
            <span>E-STOP ACTIVE (RESUME)</span>
          </button>
        </div>
      ) : (
        <button
          onClick={handleOpenTrigger}
          className="btn btn-danger-outline"
          style={{
            padding: '4px 9px',
            fontSize: 11,
            display: 'flex',
            alignItems: 'center',
            gap: 5,
          }}
          title="Monotonically halt all agents and execution sandboxes"
          aria-label="Trigger Emergency Stop"
        >
          <OctagonAlert size={13} />
          <span>HALT ALL AGENTS</span>
        </button>
      )}

      {/* Confirmation Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => !isSubmitting && setIsModalOpen(false)}
        title={
          modalMode === 'TRIGGER'
            ? 'CONFIRM PLATFORM EMERGENCY STOP'
            : 'CLEAR EMERGENCY STOP & RESUME'
        }
        description={
          modalMode === 'TRIGGER'
            ? 'Monotonically terminates active execution, blocks pending approvals, and locks mission dispatch.'
            : 'Restores the security kernel dispatch engine. Requires audit justification.'
        }
        maxWidth="480px"
      >
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {modalMode === 'TRIGGER' ? (
            <div
              style={{
                display: 'flex',
                gap: 10,
                padding: '10px 12px',
                backgroundColor: 'var(--status-coral-dim)',
                border: '1px solid var(--status-coral-border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: 12,
              }}
            >
              <AlertTriangle size={18} style={{ color: 'var(--status-coral)', flexShrink: 0 }} />
              <div>
                <strong>Immediate Deterministic Halt:</strong> All agent reasoning loops, sandbox network sockets, and browser automation sessions will be instantly severed. This action is permanently committed to the dual audit chain.
              </div>
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                gap: 10,
                padding: '10px 12px',
                backgroundColor: 'var(--status-emerald-dim)',
                border: '1px solid var(--status-emerald-border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: 12,
              }}
            >
              <ShieldCheck size={18} style={{ color: 'var(--status-emerald)', flexShrink: 0 }} />
              <div>
                <strong>Re-arming Control Plane:</strong> Missions will resume only upon explicit operator reactivation. Ensure target network boundaries and sandboxes have been inspected.
              </div>
            </div>
          )}

          <div className="form-group">
            <label className="form-label" htmlFor="estop-reason">
              Operator Justification & Reason (Mandatory)
            </label>
            <textarea
              id="estop-reason"
              className="form-textarea"
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={
                modalMode === 'TRIGGER'
                  ? 'e.g. Target out-of-scope traffic detected, or manual assessment pause...'
                  : 'e.g. Scope boundaries verified, resumption approved by Lead Operator...'
              }
              disabled={isSubmitting}
              required
            />
            {error && <span className="form-error">{error}</span>}
          </div>

          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Signing Operator: <span className="font-mono">{operatorId}</span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 6 }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsModalOpen(false)}
              disabled={isSubmitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className={modalMode === 'TRIGGER' ? 'btn btn-danger' : 'btn btn-primary'}
              disabled={isSubmitting}
            >
              {isSubmitting
                ? 'Committing to Audit...'
                : modalMode === 'TRIGGER'
                ? 'Confirm & Execute Halt'
                : 'Clear & Resume Platform'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
