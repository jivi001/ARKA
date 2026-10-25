/**
 * Centralized API Contracts and Error Models.
 * Enforces sanitization and fails closed on authorization/security failures.
 */

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiErrorEnvelope;
  meta: {
    request_id: string;
    timestamp_unix: number;
    kernel_version?: string;
  };
}

export interface ApiErrorEnvelope {
  code:
    | 'AUTHENTICATION_REQUIRED'
    | 'PERMISSION_DENIED'
    | 'EMERGENCY_STOP_ACTIVE'
    | 'SCOPE_VIOLATION'
    | 'REPLAY_DETECTED'
    | 'APPROVAL_REQUIRED'
    | 'APPROVAL_EXPIRED'
    | 'ACTION_HASH_MISMATCH'
    | 'SELF_APPROVAL_FORBIDDEN'
    | 'UNAVAILABLE_DEPENDENCY'
    | 'NETWORK_ERROR'
    | 'INTERNAL_ERROR';
  message: string;
  safe_details?: Record<string, unknown>;
  retryable: boolean;
}

export interface UserSession {
  operator_id: string;
  role: 'LEAD_OPERATOR' | 'SECURITY_OPERATOR' | 'AUDITOR';
  token: string;
  hardware_token_bound: boolean;
  token_expires_at_unix: number;
}
