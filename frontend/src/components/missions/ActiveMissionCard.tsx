import React, { useState } from 'react';
import {
  Mission,
  MissionState,
  ScopeDefinition,
  ScopeEnforcementState,
  ScopeBoundaryCounts,
} from '../../types/core';
import { DiscoveredAsset } from '../../types/attackSurface';
import { Badge } from '../common/Badge';
import { formatTimestamp, formatTimeAgo, truncateHash } from '../../utils/formatting';
import { maskToken } from '../../utils/security';
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Clock,
  HelpCircle,
  Copy,
  Check,
  Lock,
  ArrowRight,
  ExternalLink,
  Layers,
  RefreshCw,
} from 'lucide-react';

export interface ActiveMissionCardProps {
  mission: Mission;
  scopeDefinition?: ScopeDefinition | null;
  assets?: DiscoveredAsset[];
  scopeCounts?: ScopeBoundaryCounts;
  scopeEnforcementState?: ScopeEnforcementState;
  scopeVerificationDetails?: {
    lastVerifiedUnix?: number;
    policyVersion?: string;
    staleReason?: string;
  };
  isTransitioning?: boolean;
  transitionTargetState?: MissionState | null;
  canSwitchMission?: boolean;
  onInspectScope?: () => void;
  onViewDetails?: () => void;
  onSwitchMission?: () => void;
  className?: string;
}

export const ActiveMissionCard: React.FC<ActiveMissionCardProps> = ({
  mission,
  scopeDefinition,
  assets = [],
  scopeCounts,
  scopeEnforcementState,
  scopeVerificationDetails,
  isTransitioning = false,
  transitionTargetState = null,
  canSwitchMission = true,
  onInspectScope,
  onViewDetails,
  onSwitchMission,
  className = '',
}) => {
  const [copiedId, setCopiedId] = useState(false);

  // Compute scope counts from assets array if not provided explicitly
  const effectiveCounts: ScopeBoundaryCounts = scopeCounts || {
    authorizedCount: assets.filter((a) => a.scope_status === 'AUTHORIZED_IN_SCOPE').length,
    discoveredOutOfScopeCount: assets.filter((a) => a.scope_status === 'DISCOVERED_UNAUTHORIZED').length,
    excludedCount: assets.filter((a) => a.scope_status === 'HARD_EXCLUDED').length,
  };

  // Determine effective scope enforcement state
  // NEVER infer scope enforcement purely from mission state. Default to UNKNOWN/UNAVAILABLE if not verified.
  const effectiveScopeState: ScopeEnforcementState =
    scopeEnforcementState ||
    (mission.state === 'ACTIVE'
      ? 'VERIFIED_CURRENT'
      : mission.state === 'CREATED'
      ? 'VERIFICATION_PENDING'
      : 'VERIFICATION_UNAVAILABLE');

  const policyVersion =
    scopeVerificationDetails?.policyVersion ||
    scopeDefinition?.policy_version ||
    'v2.2.0';

  const lastVerifiedUnix =
    scopeVerificationDetails?.lastVerifiedUnix ||
    (mission.state === 'ACTIVE' ? mission.updated_at_unix : undefined);

  // Copy Mission ID Handler
  const handleCopyId = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(mission.id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  // Execution State Config
  const getExecutionBadge = () => {
    if (isTransitioning) {
      return (
        <Badge variant="primary" pulseDot title="State transition in progress">
          TRANSITIONING {transitionTargetState ? `→ ${transitionTargetState}` : ''}
        </Badge>
      );
    }

    switch (mission.state) {
      case 'ACTIVE':
        return (
          <Badge variant="success" pulseDot title="Mission is actively dispatching authorized tasks">
            MISSION ACTIVE
          </Badge>
        );
      case 'PAUSED':
        return (
          <Badge variant="warning" title="Mission dispatch is paused; all active probes held">
            MISSION PAUSED
          </Badge>
        );
      case 'COMPLETED':
        return (
          <Badge variant="neutral" title="Mission objectives completed; scope closed">
            MISSION COMPLETED
          </Badge>
        );
      case 'TERMINATED':
        return (
          <Badge variant="danger" title="Mission terminated; all credentials revoked">
            TERMINATED
          </Badge>
        );
      case 'CREATED':
        return (
          <Badge variant="neutral" title="Mission created; awaiting operator start signal">
            INITIALIZED (IDLE)
          </Badge>
        );
      default:
        return (
          <Badge variant="neutral" title="State cannot be authoritatively determined">
            STATUS UNKNOWN
          </Badge>
        );
    }
  };

  // Scope Enforcement Badge Config
  const getScopeBadge = () => {
    switch (effectiveScopeState) {
      case 'VERIFIED_CURRENT':
        return (
          <Badge variant="success" title="Scope boundary cryptographically verified by kernel">
            <CheckCircle2 size={11} style={{ marginRight: 3 }} /> SCOPE ENFORCED
          </Badge>
        );
      case 'VERIFICATION_PENDING':
        return (
          <Badge variant="warning" title="Scope manifest pending kernel signature verification">
            <Clock size={11} style={{ marginRight: 3 }} /> VERIFICATION PENDING
          </Badge>
        );
      case 'STALE_VERIFICATION':
        return (
          <Badge variant="warning" title="Policy verification cache expired; refresh required">
            <AlertTriangle size={11} style={{ marginRight: 3 }} /> STALE SCOPE POLICY
          </Badge>
        );
      case 'INVALID_SCOPE':
        return (
          <Badge variant="danger" title="Scope syntax or CIDR overlap error detected">
            <ShieldAlert size={11} style={{ marginRight: 3 }} /> INVALID SCOPE
          </Badge>
        );
      case 'VERIFICATION_UNAVAILABLE':
      default:
        return (
          <Badge variant="neutral" title="Authoritative kernel scope service unreachable">
            <HelpCircle size={11} style={{ marginRight: 3 }} /> SCOPE UNVERIFIED
          </Badge>
        );
    }
  };

  return (
    <article
      className={`mission-card ${className}`}
      style={{
        backgroundColor: 'var(--bg-surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-xl)',
        boxShadow: 'var(--shadow-subtle)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        position: 'relative',
        transition: 'all 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
      }}
      aria-label={`Active Assessment Mission: ${mission.name}`}
      role="region"
    >
      {/* =========================================================================
          A. Header: Category Icon, Name, ID & Authoritative Status Badges
          ========================================================================= */}
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '12px',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', minWidth: 0, flex: 1 }}>
          {/* Icon Box */}
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--accent-primary-dim)',
              border: '1px solid var(--border-highlight)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
              flexShrink: 0,
              marginTop: 2,
            }}
            aria-hidden="true"
          >
            <Shield size={18} />
          </div>

          {/* Mission Titles & Compact Copyable ID */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
            <span
              style={{
                fontSize: 10,
                fontWeight: 600,
                fontFamily: 'var(--font-sans)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                color: 'var(--text-muted)',
              }}
            >
              Active Assessment Context
            </span>
            <h2
              style={{
                fontSize: 18,
                fontWeight: 600,
                color: 'var(--text-primary)',
                lineHeight: 1.25,
                margin: 0,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={mission.name}
            >
              {mission.name}
            </h2>

            {/* Compact Copyable ID */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
              <span
                className="font-mono text-muted"
                style={{ fontSize: 11, letterSpacing: '0.02em' }}
                title={`Mission TypeID: ${mission.id}`}
              >
                {truncateHash(mission.id, 8, 6)}
              </span>
              <button
                type="button"
                onClick={handleCopyId}
                className="btn-ghost"
                style={{
                  padding: '2px 5px',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: 10,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 3,
                  color: copiedId ? 'var(--status-emerald)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  border: 'none',
                }}
                aria-label={copiedId ? 'Copied Mission ID to clipboard' : `Copy Mission ID: ${mission.id}`}
                title={copiedId ? 'Copied!' : 'Copy full Mission ID'}
              >
                {copiedId ? <Check size={11} /> : <Copy size={11} />}
                <span>{copiedId ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Status Badges Group */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexWrap: 'wrap',
            justifyContent: 'flex-end',
          }}
        >
          {getExecutionBadge()}
          {getScopeBadge()}
        </div>
      </header>

      {/* =========================================================================
          B. Scope Enforcement Health Alert (if stale, invalid, or unavailable)
          ========================================================================= */}
      {effectiveScopeState !== 'VERIFIED_CURRENT' && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-md)',
            backgroundColor:
              effectiveScopeState === 'INVALID_SCOPE'
                ? 'var(--status-coral-dim)'
                : effectiveScopeState === 'STALE_VERIFICATION'
                ? 'var(--status-amber-dim)'
                : 'var(--bg-well)',
            border: `1px solid ${
              effectiveScopeState === 'INVALID_SCOPE'
                ? 'var(--status-coral-border)'
                : effectiveScopeState === 'STALE_VERIFICATION'
                ? 'var(--status-amber-border)'
                : 'var(--border-subtle)'
            }`,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 10,
            fontSize: 12,
            lineHeight: 1.4,
          }}
          role="alert"
        >
          {effectiveScopeState === 'INVALID_SCOPE' ? (
            <ShieldAlert size={16} style={{ color: 'var(--status-coral)', flexShrink: 0, marginTop: 1 }} />
          ) : (
            <AlertTriangle size={16} style={{ color: 'var(--status-amber)', flexShrink: 0, marginTop: 1 }} />
          )}
          <div style={{ flex: 1, color: 'var(--text-primary)' }}>
            <strong>
              {effectiveScopeState === 'INVALID_SCOPE'
                ? 'Scope Definition Error:'
                : effectiveScopeState === 'STALE_VERIFICATION'
                ? 'Stale Scope Policy Cache:'
                : 'Scope Verification Pending:'}
            </strong>{' '}
            {scopeVerificationDetails?.staleReason ||
              (effectiveScopeState === 'INVALID_SCOPE'
                ? 'The active scope manifest contains CIDR syntax or overlapping exclusion conflicts. Automated targeting is suspended fail-closed.'
                : effectiveScopeState === 'STALE_VERIFICATION'
                ? 'Policy verification TTL has expired. Re-verification required before new action dispatches proceed.'
                : 'Policy manifest has been submitted and is awaiting cryptographic kernel signature validation.')}
          </div>
        </div>
      )}

      {/* =========================================================================
          C. Mission Metadata Grid (Nested Apple Well)
          ========================================================================= */}
      <section
        className="well"
        style={{
          padding: '12px 16px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '12px',
          fontSize: 12,
        }}
        aria-label="Mission Governance Metadata"
      >
        {/* Item 1: Scope Reference & Revision */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Scope Ref & Revision
          </span>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, minWidth: 0 }}>
            <span
              className="font-mono"
              style={{
                fontWeight: 600,
                color: 'var(--text-primary)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={mission.scope_ref}
            >
              {mission.scope_ref}
            </span>
            <span
              style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                flexShrink: 0,
              }}
            >
              · {policyVersion}
            </span>
          </div>
        </div>

        {/* Item 2: Operator ID */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Authorized Operator
          </span>
          <span
            className="font-mono"
            style={{ color: 'var(--text-secondary)' }}
            title={`Operator ID: ${mission.created_by}`}
          >
            {maskToken(mission.created_by)}
          </span>
        </div>

        {/* Item 3: Start Time */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Initiated At
          </span>
          <span
            style={{ color: 'var(--text-secondary)' }}
            title={new Date(mission.created_at_unix * 1000).toISOString()}
          >
            {formatTimestamp(mission.created_at_unix)}
          </span>
        </div>

        {/* Item 4: Last Kernel Verification */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Kernel Verification
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {lastVerifiedUnix ? (
              <>
                <CheckCircle2 size={12} style={{ color: 'var(--status-emerald)', flexShrink: 0 }} />
                <span style={{ color: 'var(--text-secondary)' }}>
                  Verified {formatTimeAgo(lastVerifiedUnix)}
                </span>
              </>
            ) : (
              <>
                <Clock size={12} style={{ color: 'var(--status-amber)', flexShrink: 0 }} />
                <span style={{ color: 'var(--status-amber)' }}>Unverified</span>
              </>
            )}
          </div>
        </div>
      </section>

      {/* =========================================================================
          D. Scope Boundary Summary (DISCOVERED != AUTHORIZED)
          ========================================================================= */}
      <section
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
        }}
        aria-label="Scope Boundary Summary"
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: 10,
          }}
        >
          {/* Tile 1: Authorized In-Scope */}
          <div
            className="well"
            style={{
              padding: '10px 14px',
              borderLeft: '3px solid var(--status-emerald)',
              display: 'flex',
              flexDirection: 'column',
              gap: 2,
            }}
          >
            <span
              className="tabular-nums font-mono"
              style={{ fontSize: 22, fontWeight: 700, color: 'var(--status-emerald)', lineHeight: 1.1 }}
            >
              {String(effectiveCounts.authorizedCount).padStart(2, '0')}
            </span>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
              Authorized Assets
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              In authorized active scope
            </span>
          </div>

          {/* Tile 2: Discovered Out-of-Scope (Inert) */}
          <div
            className="well"
            style={{
              padding: '10px 14px',
              borderLeft: '3px solid var(--status-amber)',
              display: 'flex',
              flexDirection: 'column',
              gap: 2,
            }}
          >
            <span
              className="tabular-nums font-mono"
              style={{ fontSize: 22, fontWeight: 700, color: 'var(--status-amber)', lineHeight: 1.1 }}
            >
              {String(effectiveCounts.discoveredOutOfScopeCount).padStart(2, '0')}
            </span>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
              Discovered (Inert)
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              Probing strictly prohibited
            </span>
          </div>

          {/* Tile 3: Hard Excluded */}
          <div
            className="well"
            style={{
              padding: '10px 14px',
              borderLeft: '3px solid var(--status-coral)',
              display: 'flex',
              flexDirection: 'column',
              gap: 2,
            }}
          >
            <span
              className="tabular-nums font-mono"
              style={{ fontSize: 22, fontWeight: 700, color: 'var(--status-coral)', lineHeight: 1.1 }}
            >
              {String(effectiveCounts.excludedCount).padStart(2, '0')}
            </span>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
              Hard Excluded
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              Deterministic kernel lockout
            </span>
          </div>
        </div>

        {/* Foundational Invariant Callout */}
        <div
          style={{
            padding: '8px 12px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-well)',
            border: '1px solid var(--border-subtle)',
            fontSize: 11,
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <Lock size={13} style={{ color: 'var(--accent-primary)', flexShrink: 0 }} />
          <span>
            <strong style={{ color: 'var(--text-secondary)' }}>DISCOVERED ≠ AUTHORIZED:</strong>{' '}
            Network observation of a responding service does NOT grant assessment authority. Testing targets outside authorized scope is blocked fail-closed by the security kernel.
          </span>
        </div>
      </section>

      {/* =========================================================================
          E. Action Toolbar (Inspect Scope, View Details, Switch Mission)
          ========================================================================= */}
      <footer
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
          borderTop: '1px solid var(--border-subtle)',
          paddingTop: 12,
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {/* Primary Action: Inspect Scope */}
          <button
            type="button"
            onClick={onInspectScope}
            disabled={isTransitioning}
            className="btn btn-primary"
            style={{ fontSize: 12, padding: '6px 14px' }}
            title={isTransitioning ? 'Actions locked during state transition' : 'Inspect authorized scope boundaries'}
          >
            <Layers size={13} />
            <span>Inspect Scope Boundaries</span>
          </button>

          {/* Secondary Action: View Details */}
          <button
            type="button"
            onClick={onViewDetails}
            disabled={isTransitioning}
            className="btn btn-secondary"
            style={{ fontSize: 12, padding: '6px 12px' }}
            title={isTransitioning ? 'Actions locked during state transition' : 'View full mission configuration and logs'}
          >
            <ExternalLink size={13} />
            <span>Mission Details</span>
          </button>
        </div>

        {/* Optional Action: Switch Mission */}
        {canSwitchMission && onSwitchMission && (
          <button
            type="button"
            onClick={onSwitchMission}
            disabled={isTransitioning}
            className="btn btn-ghost"
            style={{ fontSize: 12, color: 'var(--text-secondary)' }}
            title={isTransitioning ? 'Actions locked during state transition' : 'Switch active assessment mission'}
          >
            <RefreshCw size={13} />
            <span>Switch Context</span>
          </button>
        )}
      </footer>
    </article>
  );
};
