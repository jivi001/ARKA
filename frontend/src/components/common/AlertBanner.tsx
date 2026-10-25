import React from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, Info, X } from 'lucide-react';

export interface AlertBannerProps {
  variant?: 'warning' | 'danger' | 'info' | 'success';
  title?: string;
  children: React.ReactNode;
  action?: {
    label: string;
    onClick: () => void;
  };
  onDismiss?: () => void;
}

export const AlertBanner: React.FC<AlertBannerProps> = ({
  variant = 'warning',
  title,
  children,
  action,
  onDismiss,
}) => {
  const getColors = () => {
    switch (variant) {
      case 'danger':
        return {
          bg: 'var(--status-coral-dim)',
          border: 'var(--status-coral-border)',
          color: 'var(--status-coral)',
          Icon: ShieldAlert,
        };
      case 'warning':
        return {
          bg: 'var(--status-amber-dim)',
          border: 'var(--status-amber-border)',
          color: 'var(--status-amber)',
          Icon: AlertTriangle,
        };
      case 'success':
        return {
          bg: 'var(--status-emerald-dim)',
          border: 'var(--status-emerald-border)',
          color: 'var(--status-emerald)',
          Icon: CheckCircle2,
        };
      case 'info':
      default:
        return {
          bg: 'var(--accent-primary-dim)',
          border: 'var(--border-highlight)',
          color: 'var(--accent-primary)',
          Icon: Info,
        };
    }
  };

  const { bg, border, color, Icon } = getColors();

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        padding: '8px 12px',
        backgroundColor: bg,
        border: `1px solid ${border}`,
        borderRadius: 'var(--radius-sm)',
        fontSize: 12,
        lineHeight: 1.4,
      }}
      role={variant === 'danger' || variant === 'warning' ? 'alert' : 'status'}
    >
      <Icon size={16} style={{ color, flexShrink: 0, marginTop: 1 }} />
      <div style={{ flex: 1, color: 'var(--text-primary)' }}>
        {title && (
          <div style={{ fontWeight: 600, color, marginBottom: 2 }}>
            {title}
          </div>
        )}
        <div>{children}</div>
      </div>
      {action && (
        <button
          onClick={action.onClick}
          className="btn btn-secondary"
          style={{ fontSize: 11, padding: '3px 8px', alignSelf: 'center' }}
        >
          {action.label}
        </button>
      )}
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="btn-ghost"
          style={{
            border: 'none',
            padding: 2,
            color: 'var(--text-muted)',
            cursor: 'pointer',
            alignSelf: 'flex-start',
          }}
          aria-label="Dismiss banner"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
};
