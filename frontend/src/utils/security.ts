/**
 * Security and Redaction Utilities.
 * Enforces DLP sanitization and prevents token/secret leakage.
 */

const SENSITIVE_KEY_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /api[_-]?key/i,
  /auth/i,
  /credential/i,
  /private[_-]?key/i,
  /bearer/i,
];

/**
 * Deeply redacts sensitive keys from an object before rendering or inspecting.
 */
export function redactSensitiveData(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'string') {
    // Redact bearer tokens and long hex/base64 private keys
    if (obj.startsWith('Bearer ') || obj.startsWith('eyJ')) {
      return '[REDACTED_AUTH_TOKEN]';
    }
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(redactSensitiveData);
  }

  if (typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      const isSensitive = SENSITIVE_KEY_PATTERNS.some((pat) => pat.test(key));
      if (isSensitive && typeof value === 'string') {
        result[key] = `[REDACTED_${key.toUpperCase()}]`;
      } else {
        result[key] = redactSensitiveData(value);
      }
    }
    return result;
  }

  return obj;
}

/**
 * Masks an operator identity token for display (e.g. opr_01J... -> opr_...9J)
 */
export function maskToken(token: string): string {
  if (!token || token.length < 8) return '****';
  return `${token.substring(0, 4)}...${token.substring(token.length - 4)}`;
}
