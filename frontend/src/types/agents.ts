/**
 * Agent Roles, Task Lifecycles, and Resource Governance.
 * Strictly mirrors AGENTS.md taxonomy.
 */

import { RiskClass, StandardCapability } from './core';

export type AgentRoleName =
  | 'Orchestrator Agent'
  | 'Reconnaissance Agent'
  | 'Vulnerability Analysis Agent'
  | 'Exploitation Validation Agent'
  | 'Reporting & Evidence Agent';

export type AgentStatus =
  | 'IDLE'
  | 'PLANNING'
  | 'AWAITING_AUTHORIZATION'
  | 'EXECUTING'
  | 'BLOCKED'
  | 'TERMINATED';

export interface AgentInstance {
  agent_id: string; // agt_<crockford>
  role: AgentRoleName;
  mission_id: string;
  parent_agent_id?: string;
  status: AgentStatus;
  max_risk_class: RiskClass;
  permitted_capabilities: StandardCapability[];
  resource_usage: {
    llm_tokens_consumed: number;
    llm_tokens_budget: number;
    actions_proposed: number;
    actions_authorized: number;
    actions_denied: number;
  };
  active_task_id?: string;
  uptime_seconds: number;
}

export type TaskLifecycleState =
  | 'ASSIGNED'
  | 'IN_PROGRESS'
  | 'BLOCKED_ON_APPROVAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export interface AgentTask {
  task_id: string; // tsk_<crockford>
  mission_id: string;
  assigned_agent_id: string;
  parent_task_id?: string;
  title: string;
  description: string;
  state: TaskLifecycleState;
  created_at_unix: number;
  updated_at_unix: number;
  produced_proposals: string[]; // prp_...
  produced_evidence: string[]; // evd_...
  produced_findings: string[]; // fnd_...
}
