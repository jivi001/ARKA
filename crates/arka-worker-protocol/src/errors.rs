//! Error types for the ARKA Worker Protocol.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Message payload length {size} bytes exceeds maximum allowed {max} bytes")]
    OversizedMessage { size: usize, max: usize },

    #[error("Protocol version {version} is unsupported (expected {expected})")]
    UnsupportedProtocolVersion { version: u32, expected: u32 },

    #[error("JSON structure nesting depth {depth} exceeds maximum allowed {max}")]
    ExcessiveDepth { depth: usize, max: usize },

    #[error("Field '{field}' length {length} exceeds maximum allowed {max}")]
    FieldTooLong {
        field: &'static str,
        length: usize,
        max: usize,
    },

    #[error("Malformed JSON or strict syntax violation: {0}")]
    MalformedJson(String),

    #[error("Protocol identity validation failure: {0}")]
    InvalidIdentity(String),

    #[error("Serialization failure: {0}")]
    SerializationFailure(String),

    #[error("Protocol state sequence error: {0}")]
    InvalidStateSequence(String),
}
