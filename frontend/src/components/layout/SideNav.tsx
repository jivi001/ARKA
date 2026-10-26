import React, { useState } from 'react';
import {
  LayoutDashboard,
  Target,
  Radar,
  FileCode2,
  CheckSquare,
  Bot,
  Database,
  ShieldAlert,
  GitFork,
  FileSpreadsheet,
  History,
  Settings,
  Shield,
  OctagonAlert,
  X,
  AlertTriangle,
} from 'lucide-react';

export type NavDestination =
  | 'overview'
  | 'missions'
  | 'attack_surface'
  | 'proposals'
  | 'approvals'
  | 'agents'
  | 'evidence'
  | 'findings'
  | 'findings_trace'
  | 'reports'
  | 'audit'
  | 'settings';

export interface SideNavProps {
  currentTab: NavDestination;
  onSelectTab: (tab: NavDestination) => void;
  pendingApprovalsCount: number;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
  onTriggerEmergencyStop?: (reason: string) => Promise<void>;
  emergencyStopActive?: boolean;
}

export const SideNav: React.FC<SideNavProps> = ({
  currentTab,
  onSelectTab,
  pendingApprovalsCount,
  isOpenMobile = false,
  onCloseMobile,
  onTriggerEmergencyStop,
  emergencyStopActive = false,
}) => {
  const [showHaltModal, setShowHaltModal] = useState<boolean>(false);
  const [haltReason, setHaltReason] = useState<string>('Operator manual halt initiated from navigation sidebar');
  const [isSubmittingHalt, setIsSubmittingHalt] = useState<boolean>(false);

  const navItems: { id: NavDestination; label: string; icon: React.ElementType; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'missions', label: 'Missions', icon: Target },
    { id: 'attack_surface', label: 'Attack Surface', icon: Radar },
    { id: 'proposals', label: 'Action Proposals', icon: FileCode2 },
    {
      id: 'approvals',
      label: 'Approvals',
      icon: CheckSquare,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
    },
    { id: 'agents', label: 'Agents & Tasks', icon: Bot },
    { id: 'evidence', label: 'Evidence', icon: Database },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'findings_trace', label: 'Agent Findings Trace', icon: GitFork },
    { id: 'reports', label: 'Reports', icon: FileSpreadsheet },
    { id: 'audit', label: 'Audit Trail', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  const handleConfirmHalt = async () => {
    if (!onTriggerEmergencyStop) return;
    setIsSubmittingHalt(true);
    try {
      await onTriggerEmergencyStop(haltReason);
      setShowHaltModal(false);
    } catch (err) {
      console.error('Failed to trigger emergency halt from sidebar:', err);
    } finally {
      setIsSubmittingHalt(false);
    }
  };

  return (
    <>
      <aside
        className={`sidebar-nav ${isOpenMobile ? 'mobile-open' : ''}`}
        style={{
          width: 244,
          backgroundColor: 'var(--bg-surface-lowest)',
          borderRight: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          flexShrink: 0,
          userSelect: 'none',
        }}
        aria-label="Main Navigation"
      >
        <div>
          {/* Brand identity */}
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <div
              style={{
                width: 26,
                height: 26,
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-surface-high)',
                border: '1px solid var(--border-highlight)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-primary)',
              }}
            >
              <Shield size={15} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                ARKA
              </div>
              <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                SECURITY OPERATIONS
              </div>
            </div>
          </div>

          {/* Navigation destinations */}
          <nav style={{ padding: '8px 8px', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    onSelectTab(item.id);
                    if (onCloseMobile) onCloseMobile();
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    width: '100%',
                    padding: '7px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: isActive ? 'var(--accent-primary-dim)' : 'transparent',
                    color: isActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
                    border: '1px solid transparent',
                    fontSize: 12,
                    fontWeight: isActive ? 600 : 400,
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s cubic-bezier(0.16, 1, 0.3, 1)',
                  }}
                  className={isActive ? 'nav-item-active' : 'nav-item'}
                  aria-current={isActive ? 'page' : undefined}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <Icon size={14} style={{ flexShrink: 0 }} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && (
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        fontWeight: 700,
                        backgroundColor: 'var(--status-amber-dim)',
                        color: 'var(--status-amber)',
                        border: '1px solid var(--status-amber-border)',
                        borderRadius: 10,
                        padding: '0 5px',
                        minWidth: 16,
                        textAlign: 'center',
                        lineHeight: '15px',
                      }}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Lower Sidebar: Kernel Status Card & Emergency Halt */}
        <div
          style={{
            padding: '12px 14px',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-surface-lowest)',
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
          }}
        >
          {/* Security Kernel Status Card */}
          <div
            style={{
              padding: '8px 10px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface-base)',
              border: '1px solid var(--border-subtle)',
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
            }}
          >
            <div style={{ color: 'var(--text-muted)', fontWeight: 600 }}>SECURITY KERNEL</div>
            <div
              style={{
                color: emergencyStopActive ? 'var(--status-coral)' : 'var(--status-emerald)',
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                marginTop: 3,
                fontWeight: 700,
              }}
            >
              <span
                style={{
                  width: 5,
                  height: 5,
                  borderRadius: '50%',
                  backgroundColor: 'currentColor',
                }}
              />
              <span>{emergencyStopActive ? 'HALTED · LOCKDOWN' : 'ACTIVE · ENFORCING'}</span>
            </div>
          </div>

          {/* Emergency Stop Action Button */}
          {onTriggerEmergencyStop && !emergencyStopActive && (
            <button
              onClick={() => setShowHaltModal(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                padding: '7px 10px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--status-coral-dim)',
                color: 'var(--status-coral)',
                border: '1px solid var(--status-coral-border)',
                fontSize: 11,
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              title="Halt all autonomous agent activity immediately"
            >
              <OctagonAlert size={13} />
              <span>Halt All Agents</span>
            </button>
          )}

          {emergencyStopActive && (
            <div
              style={{
                fontSize: 10,
                fontWeight: 700,
                color: 'var(--status-coral)',
                textAlign: 'center',
                padding: '4px',
                backgroundColor: 'var(--status-coral-dim)',
                borderRadius: 'var(--radius-xs)',
                border: '1px solid var(--status-coral-border)',
              }}
            >
              FAIL-CLOSED ACTIVE
            </div>
          )}
        </div>
      </aside>

      {/* Deliberate Confirmation Modal for Halt All Agents */}
      {showHaltModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            backdropFilter: 'blur(3px)',
          }}
          role="dialog"
          aria-modal="true"
          aria-labelledby="halt-modal-title"
        >
          <div
            style={{
              width: 420,
              backgroundColor: 'var(--bg-surface-base)',
              border: '1px solid var(--status-coral-border)',
              borderRadius: 'var(--radius-card)',
              boxShadow: 'var(--shadow-surface)',
              padding: 20,
              display: 'flex',
              flexDirection: 'column',
              gap: 14,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <OctagonAlert size={18} style={{ color: 'var(--status-coral)' }} />
                <h3 id="halt-modal-title" style={{ fontSize: 14, fontWeight: 700, color: 'var(--status-coral)' }}>
                  Confirm Emergency Stop Halt
                </h3>
              </div>
              <button
                onClick={() => setShowHaltModal(false)}
                className="btn-ghost"
                style={{ padding: 2, cursor: 'pointer', border: 'none', color: 'var(--text-muted)' }}
              >
                <X size={15} />
              </button>
            </div>

            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              This will engage the Rust Security Kernel emergency stop monotonic barrier. All active sandbox
              containers, network sockets, and autonomous agent tasks across all missions will be terminated immediately.
            </p>

            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: 4 }}>
                Operator Justification (Required for Audit Record):
              </label>
              <textarea
                value={haltReason}
                onChange={(e) => setHaltReason(e.target.value)}
                style={{
                  width: '100%',
                  minHeight: 60,
                  padding: 8,
                  fontSize: 11,
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  backgroundColor: 'var(--bg-well)',
                  color: 'var(--text-primary)',
                  resize: 'vertical',
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setShowHaltModal(false)}
                disabled={isSubmittingHalt}
                className="btn-ghost"
                style={{
                  padding: '6px 12px',
                  fontSize: 12,
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  color: 'var(--text-primary)',
                }}
              >
                Cancel
              </button>

              <button
                onClick={handleConfirmHalt}
                disabled={isSubmittingHalt || !haltReason.trim()}
                style={{
                  padding: '6px 14px',
                  fontSize: 12,
                  fontWeight: 700,
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--status-coral)',
                  color: '#ffffff',
                  border: 'none',
                  cursor: isSubmittingHalt ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <OctagonAlert size={14} />
                <span>{isSubmittingHalt ? 'Halting...' : 'Engage Halt Monotonically'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
