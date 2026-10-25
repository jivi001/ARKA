import test from 'node:test';
import assert from 'node:assert';
import { maskToken, redactSensitiveData } from '../src/utils/security.ts';

test('Redaction — Operator Token Masking', () => {
  // Typical Ed25519 or Crockford TypeID tokens
  const longToken = 'opr_01J9Y70X9Y8Z7W6V5U4T3S2R1Q_SEC_KEY_84920';
  const maskedLong = maskToken(longToken);
  assert.strictEqual(maskedLong, 'opr_...4920');

  // Short tokens
  const shortToken = 'opr_short';
  const maskedShort = maskToken(shortToken);
  assert.strictEqual(maskedShort, 'opr_...hort');

  // Less than 8 chars
  assert.strictEqual(maskToken('short'), '****');
  assert.strictEqual(maskToken(''), '****');
});

test('Redaction — Deep Object Sensitive Key Redaction', () => {
  const sensitivePayload = {
    target: '10.42.18.104',
    port: 8443,
    auth_token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret_payload',
    api_key: 'sk-live-93840294829384920384920',
    nested_config: {
      client_secret: 'top_secret_client_pass',
      public_name: 'payment-gateway',
      private_key: 'top_secret_rsa_key',
      session: {
        password: 'Password123!',
        user: 'admin',
      },
    },
  };

  const sanitized = redactSensitiveData(sensitivePayload) as Record<string, any>;

  // Public/non-sensitive fields preserved
  assert.strictEqual(sanitized.target, '10.42.18.104');
  assert.strictEqual(sanitized.port, 8443);
  assert.strictEqual(sanitized.nested_config.public_name, 'payment-gateway');
  assert.strictEqual(sanitized.nested_config.session.user, 'admin');

  // Sensitive fields redacted
  assert.strictEqual(sanitized.auth_token, '[REDACTED_AUTH_TOKEN]');
  assert.strictEqual(sanitized.api_key, '[REDACTED_API_KEY]');
  assert.strictEqual(sanitized.nested_config.client_secret, '[REDACTED_CLIENT_SECRET]');
  assert.strictEqual(sanitized.nested_config.private_key, '[REDACTED_PRIVATE_KEY]');
  assert.strictEqual(sanitized.nested_config.session.password, '[REDACTED_PASSWORD]');
});

test('Redaction — String Value Pattern Masking in Bearer Tokens', () => {
  const bearerToken = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.some_jwt_signature';
  const redacted = redactSensitiveData(bearerToken) as string;

  assert.strictEqual(redacted, '[REDACTED_AUTH_TOKEN]');
});
