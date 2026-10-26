import React, { useState, useEffect, useCallback } from 'react';
import {
  RotateCcw,
  Clock,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Layers,
} from 'lucide-react';
import { FindingTraceItem, LifecycleStageId } from '../../types/findingsTrace';
import { Mission } from '../../types/core';
import { apiClient } from '../../api/client';
import { FindingLifecycleTimeline } from './FindingLifecycleTimeline';
import { FindingLifecycleFlow } from './FindingLifecycleFlow';
import { FindingsTraceTable } from './FindingsTraceTable';
import { FindingDetailsPanel } from './FindingDetailsPanel';

export interface AgentFindingsTraceViewProps {
  currentMission?: Mission;
  allMissions?: Mission[];
  onSelectMission?: (missionId: string) => void;
  onNavigate?: (tab: any) => void;
  isBackendConnected?: boolean;
}

export type TimeRangeFilter = '24h' | '7d' | '30d' | 'all';

export const AgentFindingsTraceView: React.FC<AgentFindingsTraceViewProps> = ({
  currentMission,
  allMissions = [],
  onSelectMission,
  onNavigate,
  isBackendConnected = false,
}) => {
  const [findings, setFindings] = useState<FindingTraceItem[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedStageFilter, setSelectedStageFilter] = useState<LifecycleStageId | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [timeRange, setTimeRange] = useState<TimeRangeFilter>('24h');

  // Filter states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAgent, setSelectedAgent] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedDecision, setSelectedDecision] = useState<string>('ALL');

  // Load findings from API client
  const loadTraceData = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiClient.getFindingTraceItems(currentMission?.id);
      if (res.data) {
        setFindings(res.data);
        // Default select first finding if none selected
        if (!selectedFindingId && res.data.length > 0) {
          setSelectedFindingId(res.data[0].finding_id);
        }
      }
    } catch (err) {
      console.error('Failed to load agent findings trace data:', err);
    } finally {
      setIsLoading(false);
    }
  }, [currentMission?.id, selectedFindingId]);

  useEffect(() => {
    loadTraceData();
  }, [loadTraceData]);

  // When mission changes, reset selected finding
  useEffect(() => {
    if (findings.length > 0) {
      const exists = findings.some((f) => f.finding_id === selectedFindingId);
      if (!exists) {
        setSelectedFindingId(findings[0].finding_id);
      }
    }
  }, [currentMission?.id, findings, selectedFindingId]);

  const selectedFinding = findings.find((f) => f.finding_id === selectedFindingId) || null;

  // KPI calculations
  const totalCount = findings.length;
  const validatedCount = findings.filter((f) => f.validation_state === 'VALIDATED').length;
  const deniedCount = findings.filter((f) => f.policy_decision === 'DENY').length;
  const allowedCount = findings.filter((f) => f.policy_decision === 'ALLOW').length;
  const approvalReqCount = findings.filter((f) => f.policy_decision === 'REQUIRE_APPROVAL').length;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
        maxWidth: 1600,
        width: '100%',
      }}
      className="findings-trace-page"
    >
      {/* Page Header Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <h1
              style={{
                fontSize: 20,
                fontWeight: 700,
                letterSpacing: '-0.02em',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-display)',
              }}
            >
              Agent Findings Trace
            </h1>
            <span
              style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--status-emerald-dim)',
                color: 'var(--status-emerald)',
                border: '1px solid var(--status-emerald-border)',
              }}
            >
              LIVE KERNEL ENFORCING
            </span>
          </div>

          <p
            style={{
              fontSize: 12,
              color: 'var(--text-secondary)',
              marginTop: 4,
              maxWidth: 720,
              lineHeight: 1.45,
            }}
          >
            End-to-end lifecycle of findings from discovery to final authorization. All actions are enforced
            by the Rust Security Kernel.
          </p>
        </div>

        {/* Header Right Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {/* Time range selector */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface-base)',
              border: '1px solid var(--border-subtle)',
              padding: 2,
            }}
            role="group"
            aria-label="Filter by time range"
          >
            {(['24h', '7d', '30d', 'all'] as TimeRangeFilter[]).map((range) => {
              const active = timeRange === range;
              return (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  style={{
                    padding: '4px 10px',
                    fontSize: 11,
                    fontWeight: active ? 600 : 400,
                    borderRadius: 'var(--radius-xs)',
                    border: 'none',
                    backgroundColor: active ? 'var(--accent-primary)' : 'transparent',
                    color: active ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  aria-pressed={active}
                >
                  {range === '24h'
                    ? 'Last 24h'
                    : range === '7d'
                    ? 'Last 7d'
                    : range === '30d'
                    ? 'Last 30d'
                    : 'All Time'}
                </button>
              );
            })}
          </div>

          {/* Refresh Button */}
          <button
            onClick={loadTraceData}
            disabled={isLoading}
            className="btn-ghost"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              fontSize: 12,
              fontWeight: 600,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              backgroundColor: 'var(--bg-surface-base)',
              color: 'var(--text-primary)',
              cursor: isLoading ? 'not-allowed' : 'pointer',
            }}
            aria-label="Refresh findings and lifecycle trace"
          >
            <RotateCcw size={13} className={isLoading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Invariant Alert Banner */}
      <div
        style={{
          padding: '10px 14px',
          borderRadius: 'var(--radius-md)',
          backgroundColor: 'var(--bg-surface-base)',
          border: '1px solid var(--border-highlight)',
          boxShadow: 'var(--shadow-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-dim)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-primary)',
            }}
          >
            <Lock size={15} />
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
              Non-Negotiable Invariant: DISCOVERED ≠ AUTHORIZED
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Findings represent verified attack surface observations. Validation confirms structural evidence, but does not grant execution permission.
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-muted)' }}>Active Scope:</span>
          <span style={{ fontWeight: 600, color: 'var(--accent-primary)' }}>
            {currentMission?.scope_ref || 'scope-vpc-east-v2.1'}
          </span>
        </div>
      </div>

      {/* KPI Metrics Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 10,
        }}
      >
        <div
          className="panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'var(--bg-surface-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>Total Findings</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
            {totalCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
            Observed across active mission
          </div>
        </div>

        <div
          className="panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'var(--bg-surface-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>Validated Evidence</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--status-emerald)', marginTop: 2 }}>
            {validatedCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
            Payload bounds & hashes verified
          </div>
        </div>

        <div
          className="panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'var(--bg-surface-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>Kernel Policy Denied</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--status-coral)', marginTop: 2 }}>
            {deniedCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
            Target scope & exclusion blocks
          </div>
        </div>

        <div
          className="panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'var(--bg-surface-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>Kernel Authorized</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-primary)', marginTop: 2 }}>
            {allowedCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
            Permitted by scope inclusions
          </div>
        </div>

        <div
          className="panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'var(--bg-surface-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>Awaiting Human Gate</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--status-amber)', marginTop: 2 }}>
            {approvalReqCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
            Two-Person Integrity required
          </div>
        </div>
      </div>

      {/* 1. Seven-Stage Lifecycle Timeline */}
      <FindingLifecycleTimeline
        stages={selectedFinding?.lifecycle_stages}
        selectedStageId={selectedStageFilter}
        onSelectStage={(stageId) => {
          setSelectedStageFilter((prev) => (prev === stageId ? null : stageId));
        }}
        findingId={selectedFinding?.finding_id}
        findingTitle={selectedFinding?.title}
      />

      {/* 2. Process View: Lifecycle Flow Visualizer */}
      <FindingLifecycleFlow
        selectedStageId={selectedStageFilter}
        onSelectNode={(stageId) => {
          setSelectedStageFilter((prev) => (prev === stageId ? null : stageId));
        }}
        onNavigateToAudit={onNavigate ? () => onNavigate('audit') : undefined}
      />

      {/* 3. Main Investigation Workspace: Table (Left) + Details Panel (Right) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) 350px',
          gap: 16,
          alignItems: 'start',
        }}
        className="trace-workspace-split"
      >
        {/* Table column */}
        <div style={{ minWidth: 0 }}>
          <FindingsTraceTable
            findings={findings}
            selectedFindingId={selectedFindingId}
            onSelectFinding={(f) => setSelectedFindingId(f.finding_id)}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            selectedAgent={selectedAgent}
            onAgentChange={setSelectedAgent}
            selectedSeverity={selectedSeverity}
            onSeverityChange={setSelectedSeverity}
            selectedDecision={selectedDecision}
            onDecisionChange={setSelectedDecision}
          />
        </div>

        {/* Details Panel column */}
        <div>
          <FindingDetailsPanel
            finding={selectedFinding}
            onClose={() => setSelectedFindingId(null)}
            onNavigateToAudit={onNavigate ? () => onNavigate('audit') : undefined}
          />
        </div>
      </div>
    </div>
  );
};
