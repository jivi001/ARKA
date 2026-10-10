//! Capability parameter sanitization and injection defense.
//!
//! Enforces:
//! - Strict rejection of shell metacharacters, command substitution, and pipelining
//! - Rejection of embedded NUL, CR, LF, and control characters
//! - Strict port boundary verification (1..=65535)
//! - RFC 1123 compliant hostname lengths and label constraints

use crate::errors::NetworkPolicyError;

pub struct ParameterValidator;

impl ParameterValidator {
    /// Validates a raw hostname or domain string against injection attacks.
    pub fn validate_host(host: &str) -> Result<(), NetworkPolicyError> {
        let trimmed = host.trim();

        if trimmed.is_empty() {
            return Err(NetworkPolicyError::InvalidParameter(
                "Host cannot be empty".to_string(),
            ));
        }

        if trimmed.len() > 253 {
            return Err(NetworkPolicyError::InvalidParameter(format!(
                "Hostname length {} exceeds RFC maximum of 253 characters",
                trimmed.len()
            )));
        }

        // Check for NUL or control characters
        for (idx, ch) in trimmed.chars().enumerate() {
            if ch == '\0' {
                return Err(NetworkPolicyError::InvalidParameter(format!(
                    "Embedded NUL byte detected at position {}",
                    idx
                )));
            }
            if ch == '\r' || ch == '\n' {
                return Err(NetworkPolicyError::InvalidParameter(
                    "Carriage return or newline detected in hostname".to_string(),
                ));
            }
            if ch.is_control() {
                return Err(NetworkPolicyError::InvalidParameter(format!(
                    "Illegal control character U+{:04X} in hostname",
                    ch as u32
                )));
            }
        }

        // Check for shell metacharacters
        const FORBIDDEN_SHELL_CHARS: &[char] = &[
            ';', '&', '|', '`', '$', '<', '>', '\\', '!', '(', ')', '{', '}', '*', '?', '"', '\'',
            '~', '[', ']',
        ];
        for ch in FORBIDDEN_SHELL_CHARS {
            if trimmed.contains(*ch) {
                return Err(NetworkPolicyError::InvalidParameter(format!(
                    "Dangerous shell metacharacter '{}' rejected in hostname",
                    ch
                )));
            }
        }

        // For domain labels (non-IP) check RFC 1123 label boundaries
        if !trimmed.contains(':') && !trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
            for label in trimmed.split('.') {
                if label.is_empty() {
                    continue; // Trailing dot or leading dot handled by standard normalization
                }
                if label.len() > 63 {
                    return Err(NetworkPolicyError::InvalidParameter(format!(
                        "DNS label '{}' exceeds maximum length of 63 characters",
                        label
                    )));
                }
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(NetworkPolicyError::InvalidParameter(format!(
                        "DNS label '{}' cannot start or end with a hyphen",
                        label
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validates a network port number.
    pub fn validate_port(port: u16) -> Result<(), NetworkPolicyError> {
        if port == 0 {
            return Err(NetworkPolicyError::InvalidParameter(
                "Port 0 is reserved and invalid for capability connections".to_string(),
            ));
        }
        Ok(())
    }
}
