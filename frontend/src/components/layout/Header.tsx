import React from 'react';
import { Menu, Sun, Moon, KeyRound, Wifi, WifiOff } from 'lucide-react';
import { EmergencyStopStatus, Mission } from '../../types/core';
import { EmergencyStopControl } from './EmergencyStopControl';
import { maskToken } from '../../utils/security';

export interface HeaderProps {
  missions: Mission[];
  selectedMissionId: string;
  onSelectMission: (id: string) => void;
  emergencyStopStatus: EmergencyStopStatus;
  operatorId: string;
  isBackendConnected: boolean;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onTriggerEmergencyStop: (reason: string) => Promise<void>;
  onClearEmergencyStop: (reason: string) => Promise<void>;
  onOpenMobileNav: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  missions,
  selectedMissionId,
  onSelectMission,
  emergencyStopStatus,
  operatorId,
  isBackendConnected,
  theme,
  onToggleTheme,
  onTriggerEmergencyStop,
  onClearEmergencyStop,
  onOpenMobileNav,
}) => {
  return (
    <header
      style={{
        height: 44,
        backgroundColor: 'var(--bg-surface-lowest)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 14px',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        boxShadow: 'var(--inset-highlight)',
      }}
    >
      {/* Left: Mobile Toggle & Mission Context */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button
          onClick={onOpenMobileNav}
          className="btn-ghost mobile-menu-btn"
          style={{
            display: 'none',
            padding: 4,
            border: 'none',
            color: 'var(--text-secondary)',
          }}
          aria-label="Toggle navigation drawer"
        >
          <Menu size={18} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Mission:
          </span>
          <select
            value={selectedMissionId}
            onChange={(e) => onSelectMission(e.target.value)}
            className="form-select"
            style={{
              padding: '2px 8px',
              fontSize: 12,
              fontWeight: 500,
              width: 'auto',
              maxWidth: 240,
              backgroundColor: 'var(--bg-surface-low)',
              color: 'var(--text-primary)',
              borderColor: 'var(--border-subtle)',
            }}
          >
            {missions.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name} [{m.state}]
              </option>
            ))}
          </select>
        </div>

        {/* Backend Connection status */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 10,
            fontFamily: 'var(--font-mono)',
            padding: '2px 6px',
            borderRadius: 'var(--radius-xs)',
            backgroundColor: isBackendConnected ? 'var(--status-emerald-dim)' : 'var(--status-amber-dim)',
            color: isBackendConnected ? 'var(--status-emerald)' : 'var(--status-amber)',
            border: `1px solid ${isBackendConnected ? 'var(--status-emerald-border)' : 'var(--status-amber-border)'}`,
          }}
          title={
            isBackendConnected
              ? 'Authoritative Kernel Backend: CONNECTED'
              : 'Local Dev Mode: Using verified sample data fixtures'
          }
        >
          {isBackendConnected ? <Wifi size={11} /> : <WifiOff size={11} />}
          <span>{isBackendConnected ? 'KERNEL ONLINE' : 'DEV SAMPLE MODE'}</span>
        </div>
      </div>

      {/* Right: Actions, Emergency Stop, Operator, Theme */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {/* Persistent Emergency Stop Control */}
        <EmergencyStopControl
          status={emergencyStopStatus}
          operatorId={operatorId}
          onTrigger={onTriggerEmergencyStop}
          onClear={onClearEmergencyStop}
        />

        {/* Operator Hardware Token Badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            padding: '3px 8px',
            backgroundColor: 'var(--bg-surface-low)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 11,
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
          }}
          title="FIDO2 Hardware Key Authenticated Session"
        >
          <KeyRound size={12} style={{ color: 'var(--accent-primary)' }} />
          <span>{maskToken(operatorId)}</span>
        </div>

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="btn-ghost"
          style={{
            padding: 4,
            border: 'none',
            borderRadius: 'var(--radius-sm)',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
          }}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label="Toggle visual theme"
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
      </div>
    </header>
  );
};
