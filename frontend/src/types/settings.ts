/**
 * Platform Settings and Provider Configuration Types.
 * Strictly forbids storing raw secrets in client-side storage.
 */

export interface LlmProviderConfig {
  provider_id: 'anthropic' | 'openai' | 'ollama_local' | 'mock_dev';
  display_name: string;
  model_identifier: string;
  endpoint_url: string;
  has_credential_enclave: boolean; // True if stored in OS vault / arka-gatewayd
  status: 'ONLINE' | 'DEGRADED' | 'DISCONNECTED' | 'UNCONFIGURED';
  temperature: number;
  max_context_tokens: number;
}

export interface WorkerHealth {
  worker_id: string;
  runtime_profile: 'gVisor_L2' | 'Rootless_Podman' | 'Wasm_Edge';
  status: 'HEALTHY' | 'DRAINING' | 'OFFLINE';
  concurrency_active: number;
  concurrency_limit: number;
  network_containment: 'ISOLATED_DEFAULT_DENY';
}

export interface PlatformSettings {
  theme: 'dark' | 'light' | 'system';
  density: 'compact' | 'comfortable';
  reduced_motion: boolean;
  providers: LlmProviderConfig[];
  workers: WorkerHealth[];
  default_mission_budget_usd: number;
  default_tool_timeout_seconds: number;
  hardware_token_enforcement: boolean;
  data_handling: {
    dlp_masking_active: boolean;
    evidence_retention_days: number;
    audit_chain_dual_signing: boolean;
  };
}
