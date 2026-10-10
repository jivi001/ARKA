//! Strongly typed identity primitives with strict validation.
//!
//! Enforces:
//! - Non-empty, safe string constraints (no control characters, whitespace, traversal chars)
//! - Bounded lengths (3 to 64 bytes)
//! - Domain-specific prefix validation where applicable
//! - Private construction forcing validation through parse() / new()

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdValidationError {
    #[error("Identifier cannot be empty")]
    Empty,
    #[error("Identifier length {length} exceeds maximum allowed length {max}")]
    TooLong { length: usize, max: usize },
    #[error("Identifier length {length} is below minimum allowed length {min}")]
    TooShort { length: usize, min: usize },
    #[error("Identifier contains forbidden character: '{char}'")]
    ForbiddenCharacter { char: char },
    #[error("Identifier does not start with expected prefix '{expected}'")]
    PrefixMismatch { expected: &'static str },
}

fn validate_id_str(s: &str, min: usize, max: usize) -> Result<(), IdValidationError> {
    if s.is_empty() {
        return Err(IdValidationError::Empty);
    }
    if s.len() < min {
        return Err(IdValidationError::TooShort {
            length: s.len(),
            min,
        });
    }
    if s.len() > max {
        return Err(IdValidationError::TooLong {
            length: s.len(),
            max,
        });
    }
    for c in s.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':') {
            return Err(IdValidationError::ForbiddenCharacter { char: c });
        }
    }
    Ok(())
}

macro_rules! define_id {
    ($name:ident, $min:expr, $max:expr, $prefix:expr) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(val: impl AsRef<str>) -> Result<Self, IdValidationError> {
                let s = val.as_ref();
                validate_id_str(s, $min, $max)?;
                if let Some(prefix) = $prefix {
                    if !s.starts_with(prefix) {
                        return Err(IdValidationError::PrefixMismatch { expected: prefix });
                    }
                }
                Ok(Self(s.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::new(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(MissionId, 3, 64, None);
define_id!(OperatorId, 3, 64, None);
define_id!(AgentId, 3, 64, None);
define_id!(TaskId, 3, 64, None);
define_id!(WorkerId, 3, 64, None);
define_id!(CapabilityId, 3, 64, None);
define_id!(ActionId, 3, 64, None);
define_id!(ProposalId, 3, 64, None);
define_id!(ApprovalId, 3, 64, None);
define_id!(EvidenceId, 3, 64, None);
define_id!(TokenId, 3, 64, None);
define_id!(ExecutionId, 3, 64, None);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ids() {
        assert!(MissionId::new("mis-12345").is_ok());
        assert!(OperatorId::new("opr_sec_admin").is_ok());
        assert!(AgentId::new("agt.recon.01").is_ok());
        assert!(CapabilityId::new("CAP:PORT_SCAN").is_ok());
    }

    #[test]
    fn test_id_validation_rejects_empty() {
        assert_eq!(MissionId::new(""), Err(IdValidationError::Empty));
    }

    #[test]
    fn test_id_validation_rejects_short() {
        assert!(matches!(
            MissionId::new("ab"),
            Err(IdValidationError::TooShort { .. })
        ));
    }

    #[test]
    fn test_id_validation_rejects_forbidden_chars() {
        assert!(matches!(
            MissionId::new("mis/123"),
            Err(IdValidationError::ForbiddenCharacter { char: '/' })
        ));
        assert!(matches!(
            MissionId::new("mis 123"),
            Err(IdValidationError::ForbiddenCharacter { char: ' ' })
        ));
        assert!(matches!(
            MissionId::new("mis\x00123"),
            Err(IdValidationError::ForbiddenCharacter { char: '\x00' })
        ));
    }

    #[test]
    fn test_id_serde_roundtrip() {
        let id = MissionId::new("mis-99999").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"mis-99999\"");
        let parsed: MissionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }
}
