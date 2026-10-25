import React from 'react';
import {
  Mission,
  ActionProposal,
  Approval,
  EmergencyStopStatus,
  AuditRecord,
} from '../../types/core';
import { DiscoveredAsset } from '../../types/attackSurface';
import { AgentInstance, AgentTask } from '../../types/agents';
import { Finding } from '../../types/findings';
import { Badge } from '../common/Badge';
import { AlertBanner } from '../common/AlertBanner';
import { formatTimeAgo, formatTimestamp, truncateHash } from '../../utils/formatting';
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Server,
  Activity,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react';
import { NavDestination } from '../layout/SideNav';

export interface MissionOverviewProps {
  currentMission: Mission;
  allMissions: Mission[];
  proposals: ActionProposal[];
  approvals: Approval[];
  assets: DiscoveredAsset[];
  agents: AgentInstance[];
  tasks: AgentTask[];
  findings: Finding[];
  auditRecords: AuditRecord[];
  emergencyStopStatus: EmergencyStopStatus;
  isDevMode: boolean;
  onNavigate: (tab: NavDestination) => void;
}

export const MissionOverviewView: React.FC<MissionOverviewProps> = ({
  currentMission,
  allMissions,
  proposals,
  approvals,
  assets,
  agents,
  tasks,
  findings,
  auditRecords,
  emergencyStopStatus,
  isDevMode,
  onNavigate,
}) => {
  const pendingApprovals = approvals.filter((a) => a.status === 'PENDING');
  const authorizedAssets = assets.filter((a) => a.scope_status === 'AUTHORIZED_IN_SCOPE');
  const discoveredUnauthorized = assets.filter((a) => a.scope_status === 'DISCOVERED_UNAUTHORIZED');
  const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
  const deniedProposals = proposals.filter((p) => p.decision === 'DENY');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Dev Mode Notice */}
      {isDevMode && (
        <AlertBanner
          variant="info"
          title="DEVELOPMENT MODE TELEMETRY NOTICE"
        >
          Viewing verified local development test fixtures. Operational metrics and findings represent simulated test envelopes, not production targets. Authoritative security policies remain enforced by the Rust Security Kernel.
        </AlertBanner>
      )}

      {/* Emergency Stop Banner if active */}
      {emergencyStopStatus.active && (
        <AlertBanner
          variant="danger"
          title="PLATFORM EMERGENCY STOP ACTIVE"
        >
          All autonomous agent proposals, execution broker workers, and network dispatches are monotonically blocked. Triggered by <span className="font-mono">{emergencyStopStatus.triggered_by}</span>: {emergencyStopStatus.reason}
        </AlertBanner>
      )}

      {/* Primary KPI Strip */}
      <section
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: 10,
        }}
        aria-label="Operational Telemetry Summary"
      >
        {/* Metric 1: Mission State */}
        <div className="panel" style={{ padding: '10px 14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              MISSION STATUS
            </span>
            <Activity size={12} style={{ color: 'var(--accent-primary)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
              {currentMission.state}
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }} className="truncate">
            Mode: {currentMission.mode === 'AUTHORIZED_PROFESSIONAL' ? 'Professional' : 'CTF Lab'}
          </div>
        </div>

        {/* Metric 2: Pending Approvals */}
        <div
          className="panel"
          style={{
            padding: '10px 14px',
            borderLeft: pendingApprovals.length > 0 ? '2px solid var(--status-amber)' : undefined,
            cursor: 'pointer',
          }}
          onClick={() => onNavigate('approvals')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigate('approvals')}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              PENDING APPROVALS
            </span>
            <AlertTriangle size={12} style={{ color: 'var(--status-amber)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--status-amber)' }}>
              {pendingApprovals.length}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--status-amber)' }}>
              ACTION REQ
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Two-Person Integrity Gate
          </div>
        </div>

        {/* Metric 3: Authorized In-Scope Assets */}
        <div
          className="panel"
          style={{ padding: '10px 14px', cursor: 'pointer' }}
          onClick={() => onNavigate('attack_surface')}
          role="button"
          tabIndex={0}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              AUTHORIZED ASSETS
            </span>
            <CheckCircle2 size={12} style={{ color: 'var(--status-emerald)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
              {authorizedAssets.length}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--status-emerald)' }}>
              IN-SCOPE
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Discovered: {discoveredUnauthorized.length} (Inert)
          </div>
        </div>

        {/* Metric 4: Active Agents */}
        <div
          className="panel"
          style={{ padding: '10px 14px', cursor: 'pointer' }}
          onClick={() => onNavigate('agents')}
          role="button"
          tabIndex={0}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              ACTIVE AGENTS
            </span>
            <Server size={12} style={{ color: 'var(--accent-primary)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
              {agents.filter((a) => a.status !== 'TERMINATED').length}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              / {agents.length} PROFILES
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Tasks: {tasks.filter((t) => t.state === 'IN_PROGRESS').length} running
          </div>
        </div>

        {/* Metric 5: Validated Findings */}
        <div
          className="panel"
          style={{ padding: '10px 14px', cursor: 'pointer' }}
          onClick={() => onNavigate('findings')}
          role="button"
          tabIndex={0}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              VALIDATED FINDINGS
            </span>
            <ShieldAlert size={12} style={{ color: 'var(--status-coral)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
              {findings.length}
            </span>
            {criticalFindings.length > 0 && (
              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--status-coral)', fontWeight: 600 }}>
                {criticalFindings.length} CRITICAL
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Observed & Proven
          </div>
        </div>
      </section>

      {/* Main Two-Column Operational Split */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 14 }}>
        {/* Left Column: Mission Lifecycle & Pending Approvals */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Active Mission Details */}
          <div className="panel" style={{ padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Layers size={14} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: 13, fontWeight: 600 }}>Active Assessment Mission</h3>
              </div>
              <Badge variant={currentMission.state === 'ACTIVE' ? 'success' : 'neutral'} pulseDot={currentMission.state === 'ACTIVE'}>
                {currentMission.state}
              </Badge>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Name: </span>
                <span style={{ fontWeight: 600 }}>{currentMission.name}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Mission ID: </span>
                <span className="font-mono text-muted">{currentMission.id}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Scope Ref: </span>
                <span className="font-mono">{currentMission.scope_ref}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Created By: </span>
                <span className="font-mono">{currentMission.created_by}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Started: </span>
                <span>{formatTimestamp(currentMission.created_at_unix)}</span>
              </div>
            </div>

            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              <button onClick={() => onNavigate('missions')} className="btn btn-secondary" style={{ fontSize: 11 }}>
                Switch Mission
              </button>
              <button onClick={() => onNavigate('attack_surface')} className="btn btn-secondary" style={{ fontSize: 11 }}>
                Inspect Scope Boundaries
              </button>
            </div>
          </div>

          {/* Pending Approvals Review Box */}
          <div className="panel" style={{ padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={14} style={{ color: 'var(--status-amber)' }} />
                <h3 style={{ fontSize: 13, fontWeight: 600 }}>Pending Action Approvals</h3>
              </div>
              <span className="badge badge-warning">{pendingApprovals.length} QUEUED</span>
            </div>

            {pendingApprovals.length === 0 ? (
              <div style={{ padding: '16px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                No actions currently waiting for operator approval.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {pendingApprovals.map((app) => {
                  const prop = proposals.find((p) => p.action_hash === app.action_hash);
                  return (
                    <div
                      key={app.approval_id}
                      className="well"
                      style={{
                        padding: 10,
                        borderLeft: '2px solid var(--status-amber)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 600, fontSize: 12 }}>
                          {prop ? prop.capability_id : 'Sensitive Operation'}
                        </span>
                        <Badge variant="danger">CRITICAL</Badge>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        Target: <span className="font-mono text-primary">{prop?.target || '—'}</span>
                      </div>
                      <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
                        Action Hash: {truncateHash(app.action_hash)}
                      </div>
                      <button
                        onClick={() => onNavigate('approvals')}
                        className="btn btn-secondary"
                        style={{ alignSelf: 'flex-start', fontSize: 11, padding: '3px 8px', marginTop: 4 }}
                      >
                        Review Parameters & Sign <ArrowRight size={11} />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Recent Activity & Denied Operations */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Denied / Blocked Operations Audit */}
          <div className="panel" style={{ padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Shield size={14} style={{ color: 'var(--status-coral)' }} />
                <h3 style={{ fontSize: 13, fontWeight: 600 }}>Deterministic Kernel Enforcements (Denied)</h3>
              </div>
              <Badge variant="neutral">{deniedProposals.length} DENIED</Badge>
            </div>

            {deniedProposals.length === 0 ? (
              <div style={{ padding: '14px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                No proposals rejected by policy engine.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {deniedProposals.map((dp) => (
                  <div key={dp.proposal_id} className="well" style={{ padding: 10, borderLeft: '2px solid var(--status-coral)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--status-coral)' }}>
                        DENY: {dp.capability_id}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {formatTimeAgo(dp.timestamp_unix)}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, marginTop: 4, color: 'var(--text-secondary)' }}>
                      {dp.decision_reason || 'Out of authorized scope.'}
                    </div>
                    <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)', marginTop: 4 }}>
                      Target: {dp.target} | Agent: {dp.requesting_agent}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent Audit Timeline */}
          <div className="panel" style={{ padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600 }}>Recent Cryptographic Audit Records</h3>
              <button
                onClick={() => onNavigate('audit')}
                className="btn-ghost"
                style={{ fontSize: 11, color: 'var(--accent-primary)', border: 'none', cursor: 'pointer' }}
              >
                Full Trail →
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {auditRecords.slice(0, 4).map((record) => (
                <div
                  key={record.event_id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '6px 8px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--bg-surface-base)',
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="font-mono" style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                      #{record.sequence_number}
                    </span>
                    <Badge variant="neutral" style={{ fontSize: 9 }}>
                      {record.event_type}
                    </Badge>
                    <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                      {truncateHash(record.current_hash, 6, 4)}
                    </span>
                  </div>
                  <span style={{ color: 'var(--text-subtle)', fontSize: 10 }}>
                    {formatTimeAgo(record.timestamp_unix)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
