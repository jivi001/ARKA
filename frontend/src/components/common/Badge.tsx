import React from 'react';

export interface BadgeProps {
  variant?: 'neutral' | 'primary' | 'success' | 'warning' | 'danger';
  children: React.ReactNode;
  pulseDot?: boolean;
  className?: string;
  style?: React.CSSProperties;
  title?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'neutral',
  children,
  pulseDot = false,
  className = '',
  style,
  title,
}) => {
  const variantClass = `badge-${variant}`;

  return (
    <span className={`badge ${variantClass} ${className}`} style={style} title={title}>
      {pulseDot && (
        <span
          className="badge-dot"
          style={{
            width: 5,
            height: 5,
            borderRadius: '50%',
            backgroundColor: 'currentColor',
            display: 'inline-block',
          }}
          aria-hidden="true"
        />
      )}
      {children}
    </span>
  );
};
