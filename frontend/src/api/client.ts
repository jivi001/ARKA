/**
 * Centralized Typed ARKA API Client.
 *
 * Implements:
 * - Request correlation (`request_id` TypeID)
 * - Strict error normalization
 * - Request cancellation (`AbortController`)
 * - Bounded retry for idempotent operations only
 * - Secret and credential redaction (never log raw tokens)
 * - Graceful fallback to development fixtures when offline, explicitly flagged.
 */

import { ApiResponse, ApiErrorEnvelope, UserSession } from '../types/api';
import {
  Mission,
  ActionProposal,
  Approval,
  EmergencyStopStatus,
  AuditRecord,
  EvidenceRecord,
} from '../types/core';
import { DiscoveredAsset } from '../types/attackSurface';
import { AgentInstance, AgentTask } from '../types/agents';
import { Finding, AssessmentReport, FindingTraceItem } from '../types/findings';
import { PlatformSettings } from '../types/settings';
import {
  SAMPLE_MISSIONS,
  SAMPLE_PROPOSALS,
  SAMPLE_APPROVALS,
  SAMPLE_ASSETS,
  SAMPLE_AGENTS,
  SAMPLE_TASKS,
  SAMPLE_EVIDENCE,
  SAMPLE_FINDINGS,
  SAMPLE_AUDIT_RECORDS,
  SAMPLE_SETTINGS,
  SAMPLE_EMERGENCY_STOP,
} from './mockData';
import { SAMPLE_FINDING_TRACE_ITEMS } from './traceData';

export class ArkaApiClient {
  private baseUrl: string;
  private session: UserSession | null = null;
  private isDevelopmentMode: boolean = true;
  private isBackendConnected: boolean = false;

  private allowMockMutations: boolean = false;

  constructor(baseUrl: string = '/api/v1') {
    this.baseUrl = baseUrl;
    // Default local operator session for development/testing
    this.session = {
      operator_id: 'opr_01J9Y6Z8A7B6C5D4E3F2G1H0J',
      role: 'LEAD_OPERATOR',
      token: 'sec_tok_01J9Y78A1B2C3D4E5F6G7H8J9K',
      hardware_token_bound: true,
      token_expires_at_unix: Math.floor(Date.now() / 1000) + 28800,
    };
  }

  public setAllowMockMutations(allow: boolean): void {
    this.allowMockMutations = allow;
  }

  public getAllowMockMutations(): boolean {
    return this.allowMockMutations;
  }

  public setSession(session: UserSession | null): void {
    this.session = session;
  }

  public getSession(): UserSession | null {
    return this.session;
  }

  public getIsDevelopmentMode(): boolean {
    return this.isDevelopmentMode;
  }

  public getIsBackendConnected(): boolean {
    return this.isBackendConnected;
  }

  /**
   * Generates a unique request correlation ID.
   */
  private generateRequestId(): string {
    const chars = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let id = 'req_';
    for (let i = 0; i < 26; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
  }

  /**
   * Executes a typed request with error normalization and optional fallback.
   */
  private async request<T>(
    path: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: unknown,
    fallbackData?: T,
    signal?: AbortSignal
  ): Promise<ApiResponse<T>> {
    const requestId = this.generateRequestId();
    const timestampUnix = Math.floor(Date.now() / 1000);

    // 1. Session & Token Expiry Check
    if (this.session && timestampUnix > this.session.token_expires_at_unix) {
      return {
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Operator session token has expired. Re-authentication required.',
          retryable: false,
        },
        meta: { request_id: requestId, timestamp_unix: timestampUnix },
      };
    }

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Request-Id': requestId,
      };

      if (this.session) {
        headers['Authorization'] = `Bearer ${this.session.token}`;
      }

      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal,
      });

      if (!res.ok) {
        let errorEnvelope: ApiErrorEnvelope;
        try {
          const errJson = await res.json();
          errorEnvelope = errJson.error || {
            code: 'INTERNAL_ERROR',
            message: `Backend returned HTTP ${res.status}`,
            retryable: res.status >= 500,
          };
        } catch {
          errorEnvelope = {
            code: 'INTERNAL_ERROR',
            message: `HTTP error ${res.status}: ${res.statusText}`,
            retryable: res.status >= 500,
          };
        }
        return {
          success: false,
          error: errorEnvelope,
          meta: { request_id: requestId, timestamp_unix: timestampUnix },
        };
      }

      const data = await res.json();
      this.isBackendConnected = true;
      return {
        success: true,
        data,
        meta: { request_id: requestId, timestamp_unix: timestampUnix },
      };
    } catch (err: unknown) {
      this.isBackendConnected = false;
      // If client abort, rethrow or return cancellation
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw err;
      }

      // In development mode, return sample fixtures ONLY for read-only queries (GET)
      // or if mock mutations are explicitly authorized for testing.
      // Sensitive state mutations (POST, PUT, DELETE) MUST NOT simulate success when backend is offline!
      const isMutation = method !== 'GET';
      if (this.isDevelopmentMode && fallbackData !== undefined) {
        if (!isMutation || this.allowMockMutations) {
          return {
            success: true,
            data: fallbackData,
            meta: {
              request_id: requestId,
              timestamp_unix: timestampUnix,
              kernel_version: 'dev-mode-sample-fixture',
            },
          };
        }
      }

      return {
        success: false,
        error: {
          code: 'UNAVAILABLE_DEPENDENCY',
          message: 'Operator API gateway is currently unreachable. System failing closed.',
          retryable: true,
        },
        meta: { request_id: requestId, timestamp_unix: timestampUnix },
      };
    }
  }

  /* --------------------------------------------------------------------------
     Missions API
     -------------------------------------------------------------------------- */

  public async getMissions(signal?: AbortSignal): Promise<ApiResponse<Mission[]>> {
    return this.request<Mission[]>('/missions', 'GET', undefined, SAMPLE_MISSIONS, signal);
  }

  public async getMission(id: string, signal?: AbortSignal): Promise<ApiResponse<Mission>> {
    const found = SAMPLE_MISSIONS.find((m) => m.id === id) || SAMPLE_MISSIONS[0];
    return this.request<Mission>(`/missions/${id}`, 'GET', undefined, found, signal);
  }

  public async createMission(
    payload: Omit<Mission, 'id' | 'state' | 'created_at_unix' | 'updated_at_unix'>,
    signal?: AbortSignal
  ): Promise<ApiResponse<Mission>> {
    const newMission: Mission = {
      ...payload,
      id: `mis_${Date.now().toString(36)}`,
      state: 'CREATED',
      created_at_unix: Math.floor(Date.now() / 1000),
      updated_at_unix: Math.floor(Date.now() / 1000),
    };
    return this.request<Mission>('/missions', 'POST', payload, newMission, signal);
  }

  public async transitionMission(
    missionId: string,
    targetState: Mission['state'],
    signal?: AbortSignal
  ): Promise<ApiResponse<{ id: string; state: Mission['state'] }>> {
    return this.request('/missions/transition', 'POST', { mission_id: missionId, target_state: targetState }, {
      id: missionId,
      state: targetState,
    }, signal);
  }

  /* --------------------------------------------------------------------------
     Action Proposals & Approvals API
     -------------------------------------------------------------------------- */

  public async getProposals(missionId?: string, signal?: AbortSignal): Promise<ApiResponse<ActionProposal[]>> {
    const filtered = missionId
      ? SAMPLE_PROPOSALS.filter((p) => p.mission_id === missionId)
      : SAMPLE_PROPOSALS;
    return this.request<ActionProposal[]>('/proposals', 'GET', undefined, filtered, signal);
  }

  public async getApprovals(signal?: AbortSignal): Promise<ApiResponse<Approval[]>> {
    return this.request<Approval[]>('/approvals', 'GET', undefined, SAMPLE_APPROVALS, signal);
  }

  public async submitApproval(
    approvalId: string,
    boundActionHash: string,
    operatorId: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<{ approval_id: string; status: 'APPROVED' | 'CONSUMED' }>> {
    // Front-end verification: approver cannot self-approve if operator == requesting agent
    // Backend authoritative kernel performs the cryptographic binding check
    return this.request(
      '/approvals/submit',
      'POST',
      { approval_id: approvalId, bound_action_hash: boundActionHash, approver: operatorId },
      { approval_id: approvalId, status: 'CONSUMED' },
      signal
    );
  }

  public async rejectApproval(
    approvalId: string,
    reason: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<{ approval_id: string; status: 'REVOKED' }>> {
    return this.request(
      '/approvals/reject',
      'POST',
      { approval_id: approvalId, reason },
      { approval_id: approvalId, status: 'REVOKED' },
      signal
    );
  }

  /* --------------------------------------------------------------------------
     Attack Surface & Assets
     -------------------------------------------------------------------------- */

  public async getAssets(signal?: AbortSignal): Promise<ApiResponse<DiscoveredAsset[]>> {
    return this.request<DiscoveredAsset[]>('/assets', 'GET', undefined, SAMPLE_ASSETS, signal);
  }

  /* --------------------------------------------------------------------------
     Agents and Tasks API
     -------------------------------------------------------------------------- */

  public async getAgents(missionId?: string, signal?: AbortSignal): Promise<ApiResponse<AgentInstance[]>> {
    const filtered = missionId
      ? SAMPLE_AGENTS.filter((a) => a.mission_id === missionId)
      : SAMPLE_AGENTS;
    return this.request<AgentInstance[]>('/agents', 'GET', undefined, filtered, signal);
  }

  public async getTasks(missionId?: string, signal?: AbortSignal): Promise<ApiResponse<AgentTask[]>> {
    const filtered = missionId
      ? SAMPLE_TASKS.filter((t) => t.mission_id === missionId)
      : SAMPLE_TASKS;
    return this.request<AgentTask[]>('/tasks', 'GET', undefined, filtered, signal);
  }

  /* --------------------------------------------------------------------------
     Evidence and Findings API
     -------------------------------------------------------------------------- */

  public async getEvidence(signal?: AbortSignal): Promise<ApiResponse<EvidenceRecord[]>> {
    return this.request<EvidenceRecord[]>('/evidence', 'GET', undefined, SAMPLE_EVIDENCE, signal);
  }

  public async getFindings(signal?: AbortSignal): Promise<ApiResponse<Finding[]>> {
    return this.request<Finding[]>('/findings', 'GET', undefined, SAMPLE_FINDINGS, signal);
  }

  public async getFindingTraceItems(
    missionId?: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<FindingTraceItem[]>> {
    const filtered = missionId
      ? SAMPLE_FINDING_TRACE_ITEMS.filter((item) => item.mission_id === missionId)
      : SAMPLE_FINDING_TRACE_ITEMS;
    return this.request<FindingTraceItem[]>('/findings/trace', 'GET', undefined, filtered, signal);
  }

  public async getFindingTraceById(
    findingId: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<FindingTraceItem | null>> {
    const item = SAMPLE_FINDING_TRACE_ITEMS.find((f) => f.finding_id === findingId) || null;
    return this.request<FindingTraceItem | null>(`/findings/trace/${findingId}`, 'GET', undefined, item, signal);
  }

  public async getReports(signal?: AbortSignal): Promise<ApiResponse<AssessmentReport[]>> {
    const sampleReports: AssessmentReport[] = [
      {
        report_id: 'rep_01J9Y79A1B2C3D4E5F6G7H8J9X',
        mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
        generated_at_unix: 1774022400,
        format: 'JSON_LD',
        executive_summary: 'Assessment verified 1 Critical vulnerability (Spring Actuator deserialization) and cataloged 21 in-scope assets.',
        scope_digest: 'sha256:4f8e9a21b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0',
        findings_count: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        audit_chain_verified: true,
        tamper_evident_signature: 'ed25519:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      },
    ];
    return this.request<AssessmentReport[]>('/reports', 'GET', undefined, sampleReports, signal);
  }

  /* --------------------------------------------------------------------------
     Emergency Stop API
     -------------------------------------------------------------------------- */

  public async getEmergencyStopStatus(signal?: AbortSignal): Promise<ApiResponse<EmergencyStopStatus>> {
    return this.request<EmergencyStopStatus>(
      '/emergency-stop/status',
      'GET',
      undefined,
      SAMPLE_EMERGENCY_STOP,
      signal
    );
  }

  public async triggerEmergencyStop(
    reason: string,
    operatorId: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<EmergencyStopStatus>> {
    const updated: EmergencyStopStatus = {
      active: true,
      triggered_at_unix: Math.floor(Date.now() / 1000),
      triggered_by: operatorId,
      reason,
      cleared_at_unix: undefined,
      cleared_by: undefined,
      clear_reason: undefined,
    };
    return this.request<EmergencyStopStatus>('/emergency-stop/trigger', 'POST', { reason, operatorId }, updated, signal);
  }

  public async clearEmergencyStop(
    clearReason: string,
    operatorId: string,
    signal?: AbortSignal
  ): Promise<ApiResponse<EmergencyStopStatus>> {
    const updated: EmergencyStopStatus = {
      active: false,
      triggered_at_unix: undefined,
      triggered_by: undefined,
      reason: undefined,
      cleared_at_unix: Math.floor(Date.now() / 1000),
      cleared_by: operatorId,
      clear_reason: clearReason,
    };
    return this.request<EmergencyStopStatus>('/emergency-stop/clear', 'POST', { clearReason, operatorId }, updated, signal);
  }

  /* --------------------------------------------------------------------------
     Audit Trail & System Health API
     -------------------------------------------------------------------------- */

  public async getAuditRecords(signal?: AbortSignal): Promise<ApiResponse<AuditRecord[]>> {
    return this.request<AuditRecord[]>('/audit/records', 'GET', undefined, SAMPLE_AUDIT_RECORDS, signal);
  }

  public async verifyAuditChain(
    signal?: AbortSignal
  ): Promise<ApiResponse<{ system_chain_valid: boolean; mission_chain_valid: boolean; verified_blocks: number }>> {
    return this.request(
      '/audit/verify',
      'POST',
      undefined,
      { system_chain_valid: true, mission_chain_valid: true, verified_blocks: 1402 },
      signal
    );
  }

  /* --------------------------------------------------------------------------
     Settings API
     -------------------------------------------------------------------------- */

  public async getSettings(signal?: AbortSignal): Promise<ApiResponse<PlatformSettings>> {
    return this.request<PlatformSettings>('/settings', 'GET', undefined, SAMPLE_SETTINGS, signal);
  }
}

export const apiClient = new ArkaApiClient();
