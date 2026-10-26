import React from 'react';
import {
  Search,
  Database,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  UserCheck,
  FileCheck2,
  XCircle,
  Clock,
  MinusCircle,
} from 'lucide-react';
import {
  LifecycleStageId,
  LifecycleStageInfo,
  LifecycleStageStatus,
} from '../../types/findingsTrace';
import { formatTimestamp } from '../../utils/formatting';

export interface FindingLifecycleTimelineProps {
  stages?: LifecycleStageInfo[];
  selectedStageId?: LifecycleStageId | null;
  onSelectStage?: (stageId: LifecycleStageId) => void;
  findingTitle?: string;
  findingId?: string;
}

const STAGE_ICONS: Record<LifecycleStageId, React.ElementType> = {
  discovery: Search,
  evidence_collection: Database,
  validation: CheckCircle2,
  risk_scoring: AlertTriangle,
  kernel_policy_check: ShieldCheck,
  human_approval: UserCheck,
  final_finding: FileCheck2,
};

function getStatusBadgeStyle(status: LifecycleStageStatus): {
  color: string;
  bg: string;
  border: string;
  label: string;
  icon: React.ElementType;
} {
  switch (status) {
    case 'COMPLETED':
      return {
        color: 'var(--status-emerald)',
        bg: 'var(--status-emerald-dim)',
        border: 'var(--status-emerald-border)',
        label: 'VERIFIED',
        icon: CheckCircle2,
      };
    case 'ACTIVE':
      return {
        color: 'var(--accent-primary)',
        bg: 'var(--accent-primary-dim)',
        border: 'var(--border-highlight)',
        label: 'IN PROGRESS',
        icon: Clock,
      };
    case 'DENIED':
      return {
        color: 'var(--status-coral)',
        bg: 'var(--status-coral-dim)',
        border: 'var(--status-coral-border)',
        label: 'POLICY DENIED',
        icon: XCircle,
      };
    case 'FAILED':
      return {
        color: 'var(--status-coral)',
        bg: 'var(--status-coral-dim)',
        border: 'var(--status-coral-border)',
        label: 'REJECTED',
        icon: XCircle,
      };
    case 'NOT_REQUIRED':
      return {
        color: 'var(--text-muted)',
        bg: 'var(--bg-surface-high)',
        border: 'var(--border-subtle)',
        label: 'NOT REQUIRED',
        icon: MinusCircle,
      };
    case 'PENDING':
    default:
      return {
        color: 'var(--status-amber)',
        bg: 'var(--status-amber-dim)',
        border: 'var(--status-amber-border)',
        label: 'AWAITING EVAL',
        icon: Clock,
      };
  }
}

export const FindingLifecycleTimeline: React.FC<FindingLifecycleTimelineProps> = ({
  stages,
  selectedStageId,
  onSelectStage,
  findingTitle,
  findingId,
}) => {
  // Default stages if none provided
  const displayStages: LifecycleStageInfo[] = stages && stages.length > 0
    ? stages
    : [
        { id: 'discovery', stageNumber: 1, title: 'Discovery', shortDesc: 'Agent candidate finding', status: 'COMPLETED' },
        { id: 'evidence_collection', stageNumber: 2, title: 'Evidence Collection', shortDesc: 'Normalized raw artifacts', status: 'COMPLETED' },
        { id: 'validation', stageNumber: 3, title: 'Validation', shortDesc: 'Structural verification', status: 'COMPLETED' },
        { id: 'risk_scoring', stageNumber: 4, title: 'Risk Scoring', shortDesc: 'Deterministic severity model', status: 'COMPLETED' },
        { id: 'kernel_policy_check', stageNumber: 5, title: 'Kernel Policy Check', shortDesc: 'Scope & exclusion rules', status: 'DENIED' },
        { id: 'human_approval', stageNumber: 6, title: 'Human Approval', shortDesc: 'Two-person integrity gate', status: 'NOT_REQUIRED' },
        { id: 'final_finding', stageNumber: 7, title: 'Final Finding', shortDesc: 'Dual-signed audit commit', status: 'COMPLETED' },
      ];

  return (
    <section
      aria-label="Finding Lifecycle Timeline"
      className="panel"
      style={{
        padding: '16px 18px',
        backgroundColor: 'var(--bg-surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-card)',
        boxShadow: 'var(--shadow-subtle)',
      }}
    >
      {/* Header bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 16,
          paddingBottom: 10,
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: 'var(--accent-primary)',
            }}
          />
          <div>
            <h2
              style={{
                fontSize: 13,
                fontWeight: 700,
                letterSpacing: '-0.01em',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-display)',
              }}
            >
              Seven-Stage Finding Lifecycle
            </h2>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              {findingId ? (
                <>
                  Tracking lifecycle for{' '}
                  <span className="font-mono" style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>
                    {findingId}
                  </span>
                  {findingTitle ? ` — ${findingTitle}` : ''}
                </>
              ) : (
                'Select a finding row below to trace its verified state across all 7 enforcement gates'
              )}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              padding: '3px 8px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--bg-well)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-muted)',
            }}
          >
            DETERMINISTIC PIPELINE
          </span>
        </div>
      </div>

      {/* Horizontal timeline container */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(7, 1fr)',
          gap: 8,
          position: 'relative',
        }}
        className="timeline-grid"
      >
        {displayStages.map((stage, idx) => {
          const Icon = STAGE_ICONS[stage.id] || CheckCircle2;
          const badge = getStatusBadgeStyle(stage.status);
          const isSelected = selectedStageId === stage.id;
          const isLast = idx === displayStages.length - 1;

          return (
            <div
              key={stage.id}
              onClick={() => onSelectStage && onSelectStage(stage.id)}
              style={{
                position: 'relative',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                padding: '10px 10px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: isSelected
                  ? 'var(--accent-primary-dim)'
                  : 'var(--bg-surface-low)',
                border: isSelected
                  ? '1.5px solid var(--accent-primary)'
                  : '1px solid var(--border-subtle)',
                cursor: onSelectStage ? 'pointer' : 'default',
                transition: 'all 0.15s ease',
              }}
              role="button"
              tabIndex={0}
              aria-label={`Stage ${stage.stageNumber}: ${stage.title} (${badge.label})`}
              onKeyDown={(e) => {
                if ((e.key === 'Enter' || e.key === ' ') && onSelectStage) {
                  e.preventDefault();
                  onSelectStage(stage.id);
                }
              }}
            >
              {/* Stage number & circle icon */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  width: '100%',
                  marginBottom: 6,
                }}
              >
                <div
                  style={{
                    width: 28,
                    height: 28,
                    borderRadius: '50%',
                    backgroundColor: badge.bg,
                    border: `1px solid ${badge.border}`,
                    color: badge.color,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    boxShadow: 'var(--shadow-subtle)',
                  }}
                >
                  <Icon size={14} />
                </div>

                <span
                  style={{
                    fontSize: 10,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)',
                    fontWeight: 600,
                  }}
                >
                  0{stage.stageNumber}
                </span>
              </div>

              {/* Title & short description */}
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: isSelected ? 'var(--accent-primary)' : 'var(--text-primary)',
                  marginBottom: 2,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  width: '100%',
                }}
              >
                {stage.title}
              </div>

              <div
                style={{
                  fontSize: 10,
                  color: 'var(--text-secondary)',
                  lineHeight: 1.35,
                  minHeight: 26,
                  marginBottom: 8,
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                  overflow: 'hidden',
                }}
              >
                {stage.shortDesc}
              </div>

              {/* Status pill & timestamp */}
              <div style={{ marginTop: 'auto', width: '100%' }}>
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 3,
                    fontSize: 9,
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    padding: '2px 5px',
                    borderRadius: 'var(--radius-xs)',
                    backgroundColor: badge.bg,
                    color: badge.color,
                    border: `1px solid ${badge.border}`,
                    marginBottom: 4,
                  }}
                >
                  <badge.icon size={9} />
                  <span>{badge.label}</span>
                </div>

                <div
                  style={{
                    fontSize: 9,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)',
                  }}
                >
                  {stage.timestamp_unix ? formatTimestamp(stage.timestamp_unix) : '—'}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};
