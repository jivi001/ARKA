import React, { useState } from 'react';
import { AgentInstance, AgentTask } from '../../types/agents';
import { Badge } from '../common/Badge';
import { getRiskBadgeClass, formatNumber } from '../../utils/formatting';
import { Bot, CheckCircle2, AlertTriangle, Clock, ArrowRight, Shield, Layers } from 'lucide-react';
import { NavDestination } from '../layout/SideNav';

export interface AgentsAndTasksViewProps {
  agents: AgentInstance[];
  tasks: AgentTask[];
  onNavigate?: (tab: NavDestination) => void;
}

export const AgentsAndTasksView: React.FC<AgentsAndTasksViewProps> = ({
  agents,
  tasks,
  onNavigate,
}) => {
  const [selectedAgentId, setSelectedAgentId] = useState<string>(agents[0]?.agent_id || '');

  const selectedAgent = agents.find((a) => a.agent_id === selectedAgentId) || agents[0];
  const agentTasks = selectedAgent
    ? tasks.filter((t) => t.assigned_agent_id === selectedAgent.agent_id)
    : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Header Banner */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 14, fontWeight: 700 }}>Autonomous Agents & Task Delegation Plane</h2>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Agents operate strictly under Child Monotonicity. Sub-delegated child agents cannot exceed parent authority or capabilities.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span className="badge badge-primary">{agents.length} AGENT PROFILES</span>
          <span className="badge badge-neutral">{tasks.length} TASKS</span>
        </div>
      </div>

      {/* Main Split: Agent Cards Grid + Selected Agent & Tasks Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 14, minHeight: 600 }}>
        {/* Left: Agent Roles & Instances */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-surface-lowest)' }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>Active Agent Instances</span>
          </div>

          <div style={{ overflowY: 'auto', flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {agents.map((agent) => {
              const isSelected = agent.agent_id === selectedAgentId;
              const isBlocked = agent.status === 'BLOCKED' || agent.status === 'AWAITING_AUTHORIZATION';

              return (
                <div
                  key={agent.agent_id}
                  onClick={() => setSelectedAgentId(agent.agent_id)}
                  style={{
                    padding: 10,
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: isSelected ? 'var(--bg-surface-base)' : 'var(--bg-surface-low)',
                    border: isSelected
                      ? '1px solid var(--accent-primary)'
                      : isBlocked
                      ? '1px solid var(--status-amber-border)'
                      : '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {agent.role}
                    </span>
                    <Badge variant={agent.status === 'EXECUTING' ? 'success' : isBlocked ? 'warning' : 'neutral'}>
                      {agent.status}
                    </Badge>
                  </div>

                  <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    ID: {agent.agent_id}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-subtle)', marginTop: 2 }}>
                    <span>Max Risk: {agent.max_risk_class}</span>
                    <span>Tokens: {formatNumber(agent.resource_usage.llm_tokens_consumed)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Selected Agent Capability Profile & Task Execution Ledger */}
        {selectedAgent ? (
          <div className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700 }}>{selectedAgent.role}</h3>
                  <Badge variant={getRiskBadgeClass(selectedAgent.max_risk_class) as any}>
                    MAX RISK: {selectedAgent.max_risk_class}
                  </Badge>
                  <Badge variant="neutral">{selectedAgent.status}</Badge>
                </div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 4 }}>
                  Agent ID: {selectedAgent.agent_id} | Mission: {selectedAgent.mission_id}
                  {selectedAgent.parent_agent_id ? ` | Parent: ${selectedAgent.parent_agent_id}` : ' | Root Agent'}
                </div>
              </div>
            </div>

            {/* Capability Profile */}
            <div>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Assigned Capability Profile (Standard Capability Registry)
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {selectedAgent.permitted_capabilities.map((cap) => (
                  <span key={cap} className="badge badge-primary font-mono" style={{ padding: '3px 8px' }}>
                    {cap}
                  </span>
                ))}
              </div>
            </div>

            {/* Token Budget Consumption Meter */}
            <div className="well" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                <span style={{ color: 'var(--text-muted)' }}>LLM Context Token Expenditure</span>
                <span className="font-mono">
                  {formatNumber(selectedAgent.resource_usage.llm_tokens_consumed)} / {formatNumber(selectedAgent.resource_usage.llm_tokens_budget)} tokens
                </span>
              </div>
              <div style={{ width: '100%', height: 6, backgroundColor: 'var(--bg-surface-high)', borderRadius: 3, overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    backgroundColor: 'var(--accent-primary)',
                    width: `${Math.min(100, (selectedAgent.resource_usage.llm_tokens_consumed / selectedAgent.resource_usage.llm_tokens_budget) * 100)}%`,
                  }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-subtle)', marginTop: 2 }}>
                <span>Actions Proposed: {selectedAgent.resource_usage.actions_proposed}</span>
                <span>Authorized: {selectedAgent.resource_usage.actions_authorized}</span>
                <span>Denied: {selectedAgent.resource_usage.actions_denied}</span>
              </div>
            </div>

            {/* Assigned Tasks Ledger */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1 }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Agent Assigned Tasks
              </span>
              {agentTasks.length === 0 ? (
                <div className="well" style={{ padding: 16, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
                  No tasks currently bound to this agent.
                </div>
              ) : (
                agentTasks.map((t) => (
                  <div key={t.task_id} className="well" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {t.title}
                      </span>
                      <Badge variant={t.state === 'COMPLETED' ? 'success' : t.state === 'BLOCKED_ON_APPROVAL' ? 'warning' : 'neutral'}>
                        {t.state}
                      </Badge>
                    </div>
                    <p style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {t.description}
                    </p>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: 6, fontSize: 10, color: 'var(--text-subtle)' }}>
                      <span className="font-mono">Task ID: {t.task_id}</span>
                      {t.produced_proposals.length > 0 && onNavigate && (
                        <button
                          onClick={() => onNavigate('proposals')}
                          className="btn btn-secondary"
                          style={{ fontSize: 10, padding: '2px 6px' }}
                        >
                          View {t.produced_proposals.length} Action Proposals <ArrowRight size={10} />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        ) : (
          <div className="panel" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
            Select an agent to view its capability profile and task ledger.
          </div>
        )}
      </div>
    </div>
  );
};
