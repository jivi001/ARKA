//! Data Loss Prevention (DLP) and Content Sanitization for LLM Gateway.

use crate::errors::GatewayError;
use crate::protocol::{GatewayMessage, SensitivityClass};

#[derive(Debug, Clone, Default)]
pub struct DlpFilter;

impl DlpFilter {
    pub fn new() -> Self {
        Self
    }

    /// Enforces outbound DLP policies on request messages and sensitivity class.
    pub fn inspect_outbound(
        &self,
        messages: &mut [GatewayMessage],
        sensitivity: SensitivityClass,
        provider: &str,
    ) -> Result<bool, GatewayError> {
        // Enforce Sensitivity Invariant: Confidential and Secret data cannot egress to external providers
        if sensitivity >= SensitivityClass::Confidential
            && provider != "local"
            && provider != "mock"
        {
            return Err(GatewayError::DlpViolation(
                "Confidential or Secret data cannot be transmitted to external LLM providers (INV-011, DEC-08)"
                    .to_string(),
            ));
        }

        let mut sanitized_any = false;
        for msg in messages.iter_mut() {
            let (cleaned, was_cleaned) = self.redact_string(&msg.content);
            if was_cleaned {
                msg.content = cleaned;
                sanitized_any = true;
            }
        }

        Ok(sanitized_any)
    }

    /// Inspects and sanitizes inbound completions received from providers before returning to agents.
    pub fn inspect_inbound(&self, content: &str) -> (String, bool) {
        self.redact_string(content)
    }

    /// Redacts known secret patterns from a string.
    /// Neutralizes VULN-004 by scanning and redacting every occurrence of sensitive patterns.
    pub fn redact_string(&self, input: &str) -> (String, bool) {
        let mut output = input.to_string();
        let mut modified = false;

        // 1. Anthropic Key Pattern (evaluate before generic sk- to prevent prefix truncation)
        let mut search_start = 0;
        while let Some(rel_idx) = output[search_start..].find("sk-ant-") {
            let idx = search_start + rel_idx;
            let tail = &output[idx + 7..];
            let count = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .count();
            if count >= 20 {
                let end = idx + 7 + count;
                output.replace_range(idx..end, "[REDACTED:API_KEY]");
                modified = true;
                search_start = idx + "[REDACTED:API_KEY]".len();
            } else {
                search_start = idx + 7;
            }
        }

        // 2. OpenAI Key Pattern
        let mut search_start = 0;
        while let Some(rel_idx) = output[search_start..].find("sk-") {
            let idx = search_start + rel_idx;
            let tail = &output[idx + 3..];
            let count = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .count();
            if count >= 20 {
                let end = idx + 3 + count;
                output.replace_range(idx..end, "[REDACTED:API_KEY]");
                modified = true;
                search_start = idx + "[REDACTED:API_KEY]".len();
            } else {
                search_start = idx + 3;
            }
        }

        // 3. Private Key Pattern (-----BEGIN ... KEY-----)
        let mut search_start = 0;
        while let Some(rel_start) = output[search_start..].find("-----BEGIN") {
            let start = search_start + rel_start;
            if let Some(rel_end) = output[start..].find("KEY-----") {
                let total_end = start + rel_end + 8;
                output.replace_range(start..total_end, "[REDACTED:PRIVATE_KEY]");
                modified = true;
                search_start = start + "[REDACTED:PRIVATE_KEY]".len();
            } else {
                search_start = start + "-----BEGIN".len();
            }
        }

        // 4. Internal token prefix (tok_...)
        let mut search_start = 0;
        while let Some(rel_idx) = output[search_start..].find("tok_") {
            let idx = search_start + rel_idx;
            let tail = &output[idx + 4..];
            let count = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .count();
            if count >= 20 {
                let end = idx + 4 + count;
                output.replace_range(idx..end, "[REDACTED:INTERNAL_TOKEN]");
                modified = true;
                search_start = idx + "[REDACTED:INTERNAL_TOKEN]".len();
            } else {
                search_start = idx + 4;
            }
        }

        // 5. AWS Access Key Pattern (AKIA...)
        let mut search_start = 0;
        while let Some(rel_idx) = output[search_start..].find("AKIA") {
            let idx = search_start + rel_idx;
            let tail = &output[idx + 4..];
            let count = tail
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .count();
            if count == 16 {
                let end = idx + 4 + count;
                output.replace_range(idx..end, "[REDACTED:AWS_KEY]");
                modified = true;
                search_start = idx + "[REDACTED:AWS_KEY]".len();
            } else {
                search_start = idx + 4;
            }
        }

        (output, modified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlp_blocks_confidential_outbound() {
        let filter = DlpFilter::new();
        let mut messages = vec![GatewayMessage {
            role: "user".to_string(),
            content: "Hello target".to_string(),
            name: None,
        }];

        let result =
            filter.inspect_outbound(&mut messages, SensitivityClass::Confidential, "openai");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::DlpViolation(_)));
    }

    #[test]
    fn test_dlp_allows_public_outbound() {
        let filter = DlpFilter::new();
        let mut messages = vec![GatewayMessage {
            role: "user".to_string(),
            content: "Hello target".to_string(),
            name: None,
        }];

        let result = filter.inspect_outbound(&mut messages, SensitivityClass::Public, "openai");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_dlp_redacts_api_keys() {
        let filter = DlpFilter::new();
        let text = "Here is my secret sk-proj12345678901234567890abcdef for testing";
        let (cleaned, modified) = filter.redact_string(text);
        assert!(modified);
        assert!(cleaned.contains("[REDACTED:API_KEY]"));
        assert!(!cleaned.contains("sk-proj"));
    }

    #[test]
    fn test_dlp_redacts_private_keys() {
        let filter = DlpFilter::new();
        let text = "Certificate: -----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA";
        let (cleaned, modified) = filter.redact_string(text);
        assert!(modified);
        assert!(cleaned.contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn test_dlp_redacts_multiple_keys_in_single_payload() {
        let filter = DlpFilter::new();
        let text = "Key 1: sk-proj111111111111111111111111 and Key 2: sk-proj222222222222222222222222 in one string";
        let (cleaned, modified) = filter.redact_string(text);
        assert!(modified);
        assert_eq!(cleaned.matches("[REDACTED:API_KEY]").count(), 2);
        assert!(!cleaned.contains("sk-proj111111111111111111111111"));
        assert!(!cleaned.contains("sk-proj222222222222222222222222"));
    }

    #[test]
    fn test_dlp_redacts_mixed_patterns_and_false_candidates() {
        let filter = DlpFilter::new();
        let text = "sk-short sk-ant-realant12345678901234567890abc sk-projreal98765432109876543210 AKIAIOSFODNN7EXAMPLE";
        let (cleaned, modified) = filter.redact_string(text);
        assert!(modified);
        // sk-short is not redacted (too short)
        assert!(cleaned.contains("sk-short"));
        // Real keys are all redacted
        assert!(cleaned.contains("[REDACTED:API_KEY]"));
        assert!(cleaned.contains("[REDACTED:AWS_KEY]"));
        assert!(!cleaned.contains("sk-ant-realant"));
        assert!(!cleaned.contains("sk-projreal"));
        assert!(!cleaned.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
