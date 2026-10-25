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
    pub fn redact_string(&self, input: &str) -> (String, bool) {
        let mut output = input.to_string();
        let mut modified = false;

        // Pattern matching without heavy regex compilation overhead
        // 1. OpenAI Key Pattern
        if let Some(idx) = output.find("sk-") {
            if idx + 23 <= output.len() {
                let tail = &output[idx + 3..];
                let count = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .count();
                if count >= 20 {
                    let end = idx + 3 + count;
                    output.replace_range(idx..end, "[REDACTED:API_KEY]");
                    modified = true;
                }
            }
        }

        // 2. Anthropic Key Pattern
        if let Some(idx) = output.find("sk-ant-") {
            if idx + 27 <= output.len() {
                let tail = &output[idx + 7..];
                let count = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .count();
                if count >= 20 {
                    let end = idx + 7 + count;
                    output.replace_range(idx..end, "[REDACTED:API_KEY]");
                    modified = true;
                }
            }
        }

        // 3. Private Key Pattern
        if let Some(start) = output.find("-----BEGIN") {
            if let Some(end_marker) = output.find("KEY-----") {
                if end_marker > start {
                    let total_end = end_marker + 8;
                    output.replace_range(start..total_end, "[REDACTED:PRIVATE_KEY]");
                    modified = true;
                }
            }
        }

        // 4. Internal token prefix
        if let Some(idx) = output.find("tok_") {
            let tail = &output[idx + 4..];
            let count = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .count();
            if count >= 20 {
                let end = idx + 4 + count;
                output.replace_range(idx..end, "[REDACTED:INTERNAL_TOKEN]");
                modified = true;
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
}
