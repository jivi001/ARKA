import React, { useEffect, useRef } from 'react';
import { Menu, Sun, Moon, KeyRound, Wifi, WifiOff, Search, Bell } from 'lucide-react';
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
  currentTabLabel?: string;
  onGlobalSearch?: (query: string) => void;
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
  currentTabLabel = 'Security Operations',
  onGlobalSearch,
}) => {
  const searchInputRef = useRef<HTMLInputElement>(null);
  const isMac = typeof window !== 'undefined' && navigator.platform?.toUpperCase().indexOf('MAC') >= 0;

  // Global keyboard shortcut: Cmd+K / Ctrl+K focuses search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <header
      style={{
        height: 46,
        backgroundColor: 'var(--bg-surface-lowest)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        boxShadow: 'var(--inset-highlight)',
      }}
    >
      {/* Left: Mobile Toggle, Mission Context & Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
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
          <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Mission:
          </span>
          <select
            value={selectedMissionId}
            onChange={(e) => onSelectMission(e.target.value)}
            className="form-select"
            style={{
              padding: '2px 8px',
              fontSize: 12,
              fontWeight: 600,
              width: 'auto',
              maxWidth: 240,
              backgroundColor: 'var(--bg-surface-low)',
              color: 'var(--text-primary)',
              borderColor: 'var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
            }}
            aria-label="Active assessment mission"
          >
            {missions.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name} [{m.state}]
              </option>
            ))}
          </select>
        </div>

        {/* Current Destination Breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
          <span>/</span>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{currentTabLabel}</span>
        </div>

        {/* Backend Connection / Dev Sample Mode Indicator */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 10,
            fontFamily: 'var(--font-mono)',
            padding: '2px 7px',
            borderRadius: 'var(--radius-xs)',
            backgroundColor: isBackendConnected ? 'var(--status-emerald-dim)' : 'var(--status-amber-dim)',
            color: isBackendConnected ? 'var(--status-emerald)' : 'var(--status-amber)',
            border: `1px solid ${isBackendConnected ? 'var(--status-emerald-border)' : 'var(--status-amber-border)'}`,
            fontWeight: 700,
          }}
          title={
            isBackendConnected
              ? 'Authoritative Kernel Backend: CONNECTED & ENFORCING'
              : 'Local Dev Mode: Using verified sample data fixtures'
          }
        >
          {isBackendConnected ? <Wifi size={11} /> : <WifiOff size={11} />}
          <span>{isBackendConnected ? 'KERNEL ONLINE' : 'DEV SAMPLE MODE'}</span>
        </div>
      </div>

      {/* Center: Global Search Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          position: 'relative',
          width: 280,
          maxWidth: '30vw',
        }}
        className="header-search-container"
      >
        <Search
          size={13}
          style={{
            position: 'absolute',
            left: 9,
            color: 'var(--text-muted)',
            pointerEvents: 'none',
          }}
        />
        <input
          ref={searchInputRef}
          type="text"
          placeholder="Global search assets, findings..."
          onChange={(e) => onGlobalSearch && onGlobalSearch(e.target.value)}
          style={{
            width: '100%',
            padding: '4px 44px 4px 28px',
            fontSize: 11,
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-surface-low)',
            color: 'var(--text-primary)',
          }}
          aria-label="Global search"
        />
        <div
          style={{
            position: 'absolute',
            right: 6,
            display: 'flex',
            alignItems: 'center',
            fontSize: 9,
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
            backgroundColor: 'var(--bg-well)',
            padding: '1px 4px',
            borderRadius: 'var(--radius-xs)',
            border: '1px solid var(--border-subtle)',
            pointerEvents: 'none',
          }}
        >
          {isMac ? '⌘K' : 'Ctrl+K'}
        </div>
      </div>

      {/* Right: Actions, Notifications, Emergency Stop, Operator, Theme */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {/* Notifications Icon Button */}
        <button
          className="btn-ghost"
          style={{
            position: 'relative',
            padding: 5,
            border: 'none',
            borderRadius: 'var(--radius-sm)',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
          }}
          title="Operator notifications"
          aria-label="Operator notifications"
        >
          <Bell size={15} />
          <span
            style={{
              position: 'absolute',
              top: 3,
              right: 3,
              width: 6,
              height: 6,
              borderRadius: '50%',
              backgroundColor: 'var(--accent-primary)',
            }}
          />
        </button>

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
            padding: 5,
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
