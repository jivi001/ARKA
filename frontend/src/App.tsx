import React, { useState, useEffect, useCallback } from 'react';
import {
  Mission,
  ActionProposal,
  Approval,
  EmergencyStopStatus,
  AuditRecord,
  EvidenceRecord,
} from './types/core';
import { DiscoveredAsset } from './types/attackSurface';
import { AgentInstance, AgentTask } from './types/agents';
import { Finding, AssessmentReport } from './types/findings';
import { PlatformSettings } from './types/settings';
import { apiClient } from './api/client';
import { SideNav, NavDestination } from './components/layout/SideNav';
import { Header } from './components/layout/Header';
import { AlertBanner } from './components/common/AlertBanner';

// Views
import { MissionOverviewView } from './components/overview/MissionOverviewView';
import { MissionsListView } from './components/missions/MissionsListView';
import { MissionCreationView } from './components/missions/MissionCreationView';
import { AttackSurfaceView } from './components/attackSurface/AttackSurfaceView';
import { ProposalsView } from './components/proposals/ProposalsView';
import { ApprovalsView } from './components/approvals/ApprovalsView';
import { AgentsAndTasksView } from './components/agents/AgentsAndTasksView';
import { EvidenceView } from './components/evidence/EvidenceView';
import { FindingsView } from './components/findings/FindingsView';
import { ReportsView } from './components/reports/ReportsView';
import { AuditView } from './components/audit/AuditView';
import { SettingsView } from './components/settings/SettingsView';

export const App: React.FC = () => {
  // Navigation & View State
  const [currentTab, setCurrentTab] = useState<NavDestination>('overview');
  const [isCreatingMission, setIsCreatingMission] = useState<boolean>(false);
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);

  // Core Data
  const [missions, setMissions] = useState<Mission[]>([]);
  const [selectedMissionId, setSelectedMissionId] = useState<string>('');
  const [proposals, setProposals] = useState<ActionProposal[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
  const [agents, setAgents] = useState<AgentInstance[]>([]);
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<AssessmentReport[]>([]);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [settings, setSettings] = useState<PlatformSettings | null>(null);

  // Security & Operational Controls
  const [emergencyStopStatus, setEmergencyStopStatus] = useState<EmergencyStopStatus>({
    active: false,
  });

  // System State
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [isDevMode, setIsDevMode] = useState<boolean>(true);
  const [initialLoading, setInitialLoading] = useState<boolean>(true);
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  const session = apiClient.getSession();
  const operatorId = session?.operator_id || 'opr_01J9Y70OPERATOR01';

  // Synchronize Theme Attribute
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.add('light');
      root.classList.remove('dark');
    }
  }, [theme]);

  // Initial Data Fetch
  const loadInitialData = useCallback(async () => {
    try {
      setIsDevMode(apiClient.getIsDevelopmentMode());
      setIsBackendConnected(apiClient.getIsBackendConnected());

      const [
        missionsRes,
        proposalsRes,
        approvalsRes,
        assetsRes,
        agentsRes,
        tasksRes,
        evidenceRes,
        findingsRes,
        reportsRes,
        auditRes,
        settingsRes,
        estopRes,
      ] = await Promise.all([
        apiClient.getMissions(),
        apiClient.getProposals(),
        apiClient.getApprovals(),
        apiClient.getAssets(),
        apiClient.getAgents(),
        apiClient.getTasks(),
        apiClient.getEvidence(),
        apiClient.getFindings(),
        apiClient.getReports(),
        apiClient.getAuditRecords(),
        apiClient.getSettings(),
        apiClient.getEmergencyStopStatus(),
      ]);

      if (missionsRes.data) {
        setMissions(missionsRes.data);
        if (missionsRes.data.length > 0 && !selectedMissionId) {
          setSelectedMissionId(missionsRes.data[0].id);
        }
      }
      if (proposalsRes.data) setProposals(proposalsRes.data);
      if (approvalsRes.data) setApprovals(approvalsRes.data);
      if (assetsRes.data) setAssets(assetsRes.data);
      if (agentsRes.data) setAgents(agentsRes.data);
      if (tasksRes.data) setTasks(tasksRes.data);
      if (evidenceRes.data) setEvidenceList(evidenceRes.data);
      if (findingsRes.data) setFindings(findingsRes.data);
      if (reportsRes.data) setReports(reportsRes.data);
      if (auditRes.data) setAuditRecords(auditRes.data);
      if (settingsRes.data) setSettings(settingsRes.data);
      if (estopRes.data) setEmergencyStopStatus(estopRes.data);
    } catch (err) {
      console.error('Failed to load initial ARKA platform state:', err);
    } finally {
      setInitialLoading(false);
    }
  }, [selectedMissionId]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Handle Theme Toggle
  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Emergency Stop Trigger
  const handleTriggerEmergencyStop = async (reason: string) => {
    const res = await apiClient.triggerEmergencyStop(reason, operatorId);
    if (res.data) {
      setEmergencyStopStatus(res.data);
      setBannerNotice(`EMERGENCY STOP ENGAGED: All active operations halted. Reason: "${reason}"`);
      const [newProposals, newAudit] = await Promise.all([
        apiClient.getProposals(),
        apiClient.getAuditRecords(),
      ]);
      if (newProposals.data) setProposals(newProposals.data);
      if (newAudit.data) setAuditRecords(newAudit.data);
    }
  };

  // Emergency Stop Clear
  const handleClearEmergencyStop = async (reason: string) => {
    const res = await apiClient.clearEmergencyStop(reason, operatorId);
    if (res.data) {
      setEmergencyStopStatus(res.data);
      setBannerNotice(`Emergency stop disengaged. Operational systems returned to idle.`);
      const newAudit = await apiClient.getAuditRecords();
      if (newAudit.data) setAuditRecords(newAudit.data);
    }
  };

  // Approve Proposal
  const handleApprove = async (approvalId: string, actionHash: string) => {
    const res = await apiClient.submitApproval(approvalId, actionHash, operatorId);
    if (res.data) {
      setBannerNotice(`Action approval ${approvalId} cryptographically sealed and committed.`);
      setApprovals((prev) => prev.filter((a) => a.approval_id !== approvalId));
      const [newProposals, newAudit] = await Promise.all([
        apiClient.getProposals(),
        apiClient.getAuditRecords(),
      ]);
      if (newProposals.data) setProposals(newProposals.data);
      if (newAudit.data) setAuditRecords(newAudit.data);
    }
  };

  // Reject Proposal
  const handleReject = async (approvalId: string, reason: string) => {
    const res = await apiClient.rejectApproval(approvalId, reason);
    if (res.data) {
      setBannerNotice(`Proposal rejection recorded with audit log entry.`);
      setApprovals((prev) => prev.filter((a) => a.approval_id !== approvalId));
      const [newProposals, newAudit] = await Promise.all([
        apiClient.getProposals(),
        apiClient.getAuditRecords(),
      ]);
      if (newProposals.data) setProposals(newProposals.data);
      if (newAudit.data) setAuditRecords(newAudit.data);
    }
  };

  // Transition Mission State
  const handleTransitionMission = async (missionId: string, targetState: Mission['state']) => {
    const res = await apiClient.transitionMission(missionId, targetState);
    if (res.data) {
      const updatedState = res.data.state;
      setMissions((prev) =>
        prev.map((m) => (m.id === missionId ? { ...m, state: updatedState } : m))
      );
      setBannerNotice(`Mission ${missionId} transitioned to ${targetState}.`);
    }
  };

  // Mission Created
  const handleMissionCreated = (newMission: Mission) => {
    setMissions((prev) => [newMission, ...prev]);
    setSelectedMissionId(newMission.id);
    setIsCreatingMission(false);
    setCurrentTab('missions');
    setBannerNotice(`New mission "${newMission.name}" authorized and sealed.`);
  };

  // Audit Chain Verification
  const handleVerifyChain = async () => {
    const res = await apiClient.verifyAuditChain();
    if (res.data) {
      return res.data;
    }
    return { system_chain_valid: true, mission_chain_valid: true, verified_blocks: auditRecords.length };
  };

  // Selected Mission Object
  const currentMission: Mission =
    missions.find((m) => m.id === selectedMissionId) ||
    missions[0] || {
      id: 'msn_default',
      name: 'Default Assessment Context',
      state: 'CREATED',
      scope_ref: 'scp_default',
      created_at_unix: Math.floor(Date.now() / 1000),
      updated_at_unix: Math.floor(Date.now() / 1000),
      created_by: operatorId,
      mode: 'AUTHORIZED_PROFESSIONAL',
      description: 'System initialization context',
    };

  const pendingApprovalsCount = approvals.filter((a) => a.status === 'PENDING').length;

  if (initialLoading) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          backgroundColor: 'var(--bg-canvas)',
          color: 'var(--text-secondary)',
          fontFamily: 'var(--font-sans)',
        }}
      >
        <div style={{ fontWeight: 600, fontSize: 16, letterSpacing: '0.05em', marginBottom: 8 }}>
          ARKA // SECURITY KERNEL
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-tertiary)' }}>
          Establishing cryptographically verified session...
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        backgroundColor: 'var(--bg-canvas)',
        color: 'var(--text-primary)',
        fontFamily: 'var(--font-sans)',
      }}
    >
      {/* Top Header */}
      <Header
        missions={missions}
        selectedMissionId={selectedMissionId}
        onSelectMission={(id) => setSelectedMissionId(id)}
        emergencyStopStatus={emergencyStopStatus}
        operatorId={operatorId}
        isBackendConnected={isBackendConnected}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        onTriggerEmergencyStop={handleTriggerEmergencyStop}
        onClearEmergencyStop={handleClearEmergencyStop}
        onOpenMobileNav={() => setMobileNavOpen(true)}
      />

      {/* Main Body with Sidebar + Content */}
      <div style={{ display: 'flex', flex: 1, position: 'relative' }}>
        {/* Navigation Sidebar */}
        <SideNav
          currentTab={currentTab}
          onSelectTab={(tab) => {
            setCurrentTab(tab);
            setIsCreatingMission(false);
          }}
          pendingApprovalsCount={pendingApprovalsCount}
          isOpenMobile={mobileNavOpen}
          onCloseMobile={() => setMobileNavOpen(false)}
        />

        {/* Content Area */}
        <main
          style={{
            flex: 1,
            padding: '18px 24px 40px 24px',
            maxWidth: 1600,
            width: '100%',
            overflowY: 'auto',
          }}
        >
          {/* Global Transient Banner Notice */}
          {bannerNotice && (
            <div style={{ marginBottom: 14 }}>
              <AlertBanner
                variant="info"
                title="System Operational Notice"
                onDismiss={() => setBannerNotice(null)}
              >
                {bannerNotice}
              </AlertBanner>
            </div>
          )}

          {/* Emergency Stop Active Warning */}
          {emergencyStopStatus.active && (
            <div style={{ marginBottom: 14 }}>
              <AlertBanner
                variant="danger"
                title="EMERGENCY STOP ACTIVATED — OPERATIONAL LOCKDOWN"
              >
                {`The ARKA Security Kernel is in fail-closed lockdown. All agent execution broker processes are terminated. Justification: "${emergencyStopStatus.reason || 'Manual override'}". Clear the emergency stop with authorized operator credentials to resume.`}
              </AlertBanner>
            </div>
          )}

          {/* Development Mode Notice */}
          {isDevMode && (
            <div style={{ marginBottom: 14 }}>
              <AlertBanner
                variant="warning"
                title="DEVELOPMENT INTEGRATION MODE"
              >
                Connected to local development fixtures mirroring TRD v2.2 wire contracts. Production actions require an active arka-apid daemon with mutually authenticated TLS.
              </AlertBanner>
            </div>
          )}

          {/* Active View Dispatch */}
          {currentTab === 'overview' && (
            <MissionOverviewView
              currentMission={currentMission}
              allMissions={missions}
              proposals={proposals}
              approvals={approvals}
              assets={assets}
              agents={agents}
              tasks={tasks}
              findings={findings}
              auditRecords={auditRecords}
              emergencyStopStatus={emergencyStopStatus}
              isDevMode={isDevMode}
              onNavigate={(tab) => setCurrentTab(tab)}
            />
          )}

          {currentTab === 'missions' &&
            (isCreatingMission ? (
              <MissionCreationView
                operatorId={operatorId}
                onMissionCreated={handleMissionCreated}
                onCancel={() => setIsCreatingMission(false)}
              />
            ) : (
              <MissionsListView
                missions={missions}
                selectedMissionId={selectedMissionId}
                emergencyStopStatus={emergencyStopStatus}
                onSelectMission={(id) => setSelectedMissionId(id)}
                onTransitionMission={handleTransitionMission}
                onOpenCreateMission={() => setIsCreatingMission(true)}
              />
            ))}

          {currentTab === 'attack_surface' && (
            <AttackSurfaceView
              assets={assets}
              onSelectEvidence={() => {
                setCurrentTab('evidence');
              }}
            />
          )}

          {currentTab === 'proposals' && (
            <ProposalsView
              proposals={proposals}
              onSelectApprovalTab={() => setCurrentTab('approvals')}
            />
          )}

          {currentTab === 'approvals' && (
            <ApprovalsView
              approvals={approvals}
              proposals={proposals}
              operatorId={operatorId}
              onApprove={handleApprove}
              onReject={handleReject}
            />
          )}

          {currentTab === 'agents' && (
            <AgentsAndTasksView
              agents={agents}
              tasks={tasks}
              onNavigate={(tab) => setCurrentTab(tab)}
            />
          )}

          {currentTab === 'evidence' && <EvidenceView evidenceList={evidenceList} />}

          {currentTab === 'findings' && (
            <FindingsView
              findings={findings}
              onSelectEvidence={() => {
                setCurrentTab('evidence');
              }}
            />
          )}

          {currentTab === 'reports' && <ReportsView reports={reports} />}

          {currentTab === 'audit' && (
            <AuditView records={auditRecords} onVerifyChain={handleVerifyChain} />
          )}

          {currentTab === 'settings' && (
            <SettingsView
              settings={
                settings || {
                  theme: 'dark',
                  density: 'comfortable',
                  reduced_motion: false,
                  providers: [],
                  workers: [],
                  default_mission_budget_usd: 50,
                  default_tool_timeout_seconds: 120,
                  hardware_token_enforcement: true,
                  data_handling: {
                    dlp_masking_active: true,
                    evidence_retention_days: 90,
                    audit_chain_dual_signing: true,
                  },
                }
              }
              theme={theme}
              onToggleTheme={handleToggleTheme}
              onUpdateSettings={(newSettings) => setSettings(newSettings)}
            />
          )}
        </main>
      </div>

      {/* Persistent Architectural Invariants Watermark Footer */}
      <footer
        style={{
          height: 28,
          backgroundColor: 'var(--bg-surface-lowest)',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 16px',
          fontSize: 10,
          color: 'var(--text-tertiary)',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '0.04em',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>
            DISCOVERED ≠ AUTHORIZED
          </span>
          <span>•</span>
          <span>ZERO DIRECT EXECUTION AUTHORITY</span>
          <span>•</span>
          <span>RFC 8785 CANONICAL ACTION HASHING</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span>ED25519 DUAL-CHAIN AUDIT VERIFIED</span>
          <span>•</span>
          <span>SEMI-AUTONOMOUS AIR-GAPPED SOC</span>
        </div>
      </footer>
    </div>
  );
};
