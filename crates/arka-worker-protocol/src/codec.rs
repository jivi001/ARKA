//! Strict JSON serialization and deserialization codec for Worker protocol messages.
//!
//! Enforces:
//! - RFC 8785 strict canonical parsing rules
//! - Rejection of payloads > 64 KB (MAX_MESSAGE_BYTES)
//! - Rejection of excessive nesting depth > 8
//! - Rejection of unknown fields
//! - Validation of protocol version and bounded field sizes

use crate::errors::ProtocolError;
use crate::messages::{
    WorkerMessage, MAX_FIELD_STRING_BYTES, MAX_MESSAGE_BYTES, MAX_NONCE_BYTES, MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES, PROTOCOL_VERSION,
};
use arka_crypto::json_strict::StrictJsonParser;

pub struct ProtocolCodec;

impl ProtocolCodec {
    /// Serializes a WorkerMessage into a strictly bounded JSON string.
    pub fn encode(msg: &WorkerMessage) -> Result<String, ProtocolError> {
        let serialized = serde_json::to_string(msg)
            .map_err(|e| ProtocolError::SerializationFailure(e.to_string()))?;

        if serialized.len() > MAX_MESSAGE_BYTES {
            return Err(ProtocolError::OversizedMessage {
                size: serialized.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }

        Ok(serialized)
    }

    /// Deserializes and validates a WorkerMessage from an untrusted JSON string.
    pub fn decode(payload: &str) -> Result<WorkerMessage, ProtocolError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(ProtocolError::OversizedMessage {
                size: payload.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }

        // Validate strictly through StrictJsonParser (max depth 8, reject duplicates/oversized)
        StrictJsonParser::parse(payload)
            .map_err(|e| ProtocolError::MalformedJson(e.to_string()))?;

        // Deserialize with deny_unknown_fields enforcement
        let msg: WorkerMessage = serde_json::from_str(payload)
            .map_err(|e| ProtocolError::MalformedJson(e.to_string()))?;

        // Semantic invariant checks on fields
        Self::validate_semantics(&msg)?;

        Ok(msg)
    }

    fn validate_semantics(msg: &WorkerMessage) -> Result<(), ProtocolError> {
        match msg {
            WorkerMessage::WorkerHello(hello) => {
                if hello.protocol_version != PROTOCOL_VERSION {
                    return Err(ProtocolError::UnsupportedProtocolVersion {
                        version: hello.protocol_version,
                        expected: PROTOCOL_VERSION,
                    });
                }
                if hello.nonce.is_empty() || hello.nonce.len() > MAX_NONCE_BYTES {
                    return Err(ProtocolError::FieldTooLong {
                        field: "nonce",
                        length: hello.nonce.len(),
                        max: MAX_NONCE_BYTES,
                    });
                }
            }
            WorkerMessage::BrokerHandshake(resp) => {
                if resp.protocol_version != PROTOCOL_VERSION {
                    return Err(ProtocolError::UnsupportedProtocolVersion {
                        version: resp.protocol_version,
                        expected: PROTOCOL_VERSION,
                    });
                }
                if let Some(reason) = &resp.rejection_reason {
                    if reason.len() > MAX_FIELD_STRING_BYTES {
                        return Err(ProtocolError::FieldTooLong {
                            field: "rejection_reason",
                            length: reason.len(),
                            max: MAX_FIELD_STRING_BYTES,
                        });
                    }
                }
            }
            WorkerMessage::ExecuteTask(req) => {
                if req.action_hash.is_empty() || req.action_hash.len() > 128 {
                    return Err(ProtocolError::FieldTooLong {
                        field: "action_hash",
                        length: req.action_hash.len(),
                        max: 128,
                    });
                }
            }
            WorkerMessage::TaskResponse(resp) => {
                if let Some(stdout) = &resp.stdout_truncated {
                    if stdout.len() > MAX_STDOUT_BYTES {
                        return Err(ProtocolError::FieldTooLong {
                            field: "stdout_truncated",
                            length: stdout.len(),
                            max: MAX_STDOUT_BYTES,
                        });
                    }
                }
                if let Some(stderr) = &resp.stderr_truncated {
                    if stderr.len() > MAX_STDERR_BYTES {
                        return Err(ProtocolError::FieldTooLong {
                            field: "stderr_truncated",
                            length: stderr.len(),
                            max: MAX_STDERR_BYTES,
                        });
                    }
                }
            }
            WorkerMessage::CancelTask(cancel) => {
                if cancel.reason.len() > MAX_FIELD_STRING_BYTES {
                    return Err(ProtocolError::FieldTooLong {
                        field: "reason",
                        length: cancel.reason.len(),
                        max: MAX_FIELD_STRING_BYTES,
                    });
                }
            }
            WorkerMessage::Heartbeat(_) => {}
        }
        Ok(())
    }
}
