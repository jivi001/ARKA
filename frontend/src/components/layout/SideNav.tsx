import React from 'react';
import {
  LayoutDashboard,
  Target,
  Radar,
  FileCode2,
  CheckSquare,
  Bot,
  Database,
  ShieldAlert,
  FileSpreadsheet,
  History,
  Settings,
  Shield,
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
  | 'reports'
  | 'audit'
  | 'settings';

export interface SideNavProps {
  currentTab: NavDestination;
  onSelectTab: (tab: NavDestination) => void;
  pendingApprovalsCount: number;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
}

export const SideNav: React.FC<SideNavProps> = ({
  currentTab,
  onSelectTab,
  pendingApprovalsCount,
  isOpenMobile = false,
  onCloseMobile,
}) => {
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
    { id: 'reports', label: 'Reports', icon: FileSpreadsheet },
    { id: 'audit', label: 'Audit Trail', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside
      className={`sidebar-nav ${isOpenMobile ? 'mobile-open' : ''}`}
      style={{
        width: 210,
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
            padding: '12px 14px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <div
            style={{
              width: 24,
              height: 24,
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface-high)',
              border: '1px solid var(--border-highlight)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
            }}
          >
            <Shield size={14} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
              ARKA
            </div>
            <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              SEC-OPS v2.2
            </div>
          </div>
        </div>

        {/* Navigation destinations */}
        <nav style={{ padding: '8px 6px', display: 'flex', flexDirection: 'column', gap: 2 }}>
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
                  padding: '6px 10px',
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
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
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

      {/* Footer / session */}
      <div
        style={{
          padding: '10px 12px',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-lowest)',
        }}
      >
        <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
          <div>SECURITY KERNEL: ACTIVE</div>
          <div style={{ color: 'var(--status-emerald)', display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
            <span style={{ width: 4, height: 4, borderRadius: '50%', backgroundColor: 'currentColor' }} />
            FAIL-CLOSED ENFORCED
          </div>
        </div>
      </div>
    </aside>
  );
};
