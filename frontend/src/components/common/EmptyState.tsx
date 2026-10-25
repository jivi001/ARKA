import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = Inbox,
  title,
  description,
  action,
}) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '36px 16px',
        textAlign: 'center',
        color: 'var(--text-muted)',
        border: '1px dashed var(--border-subtle)',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: 'var(--bg-surface-lowest)',
      }}
    >
      <Icon size={24} style={{ color: 'var(--text-subtle)', marginBottom: 8 }} />
      <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>
        {title}
      </h3>
      <p style={{ fontSize: 11, maxWidth: 360, lineHeight: 1.4, color: 'var(--text-subtle)' }}>
        {description}
      </p>
      {action && (
        <button
          onClick={action.onClick}
          className="btn btn-secondary"
          style={{ marginTop: 12, fontSize: 11 }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
};
