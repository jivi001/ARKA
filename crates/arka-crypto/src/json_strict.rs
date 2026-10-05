//! Strict JSON Deserialization and Security Parser.
//!
//! Enforces:
//! - Section 14: Strict size limits (max 64KB)
//! - Maximum nesting depth limits (max depth 8)
//! - Duplicate JSON key rejection (preventing parser differential vulnerabilities)

use arka_core_types::errors::KernelSecurityError;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

pub const MAX_PAYLOAD_SIZE: usize = 65536; // 64 KB
pub const MAX_NESTING_DEPTH: usize = 8;

pub struct StrictJsonParser;

impl StrictJsonParser {
    /// Parses JSON with strict depth limits and explicit rejection of duplicate keys.
    pub fn parse(raw: &str) -> Result<Value, KernelSecurityError> {
        if raw.len() > MAX_PAYLOAD_SIZE {
            return Err(KernelSecurityError::InternalFailure(format!(
                "Payload size {} bytes exceeds maximum limit of {} bytes",
                raw.len(),
                MAX_PAYLOAD_SIZE
            )));
        }

        let mut deserializer = serde_json::Deserializer::from_str(raw);
        let seed = StrictValueSeed { depth: 0 };
        seed.deserialize(&mut deserializer).map_err(|e| {
            KernelSecurityError::InternalFailure(format!("Strict JSON validation failed: {}", e))
        })
    }
}

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_NESTING_DEPTH {
            return Err(de::Error::custom(format!(
                "JSON nesting depth exceeds maximum allowed limit of {}",
                MAX_NESTING_DEPTH
            )));
        }
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value adhering to strict security constraints")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("Invalid floating point number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seed = StrictValueSeed { depth: self.depth };
        seed.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::new();
        let next_seed = StrictValueSeed {
            depth: self.depth + 1,
        };
        while let Some(elem) = seq.next_element_seed(next_seed.clone())? {
            vec.push(elem);
        }
        Ok(Value::Array(vec))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = serde_json::Map::new();
        let mut seen_keys = HashSet::new();
        let next_seed = StrictValueSeed {
            depth: self.depth + 1,
        };

        while let Some(key) = access.next_key::<String>()? {
            // Section 14: Reject duplicate keys
            if !seen_keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "Security violation: duplicate JSON key detected: '{}'",
                    key
                )));
            }
            let val = access.next_value_seed(next_seed.clone())?;
            map.insert(key, val);
        }

        Ok(Value::Object(map))
    }
}

impl Clone for StrictValueSeed {
    fn clone(&self) -> Self {
        Self { depth: self.depth }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_keys_rejected() {
        let json = r#"{"target": "10.0.0.1", "target": "10.0.0.2"}"#;
        let res = StrictJsonParser::parse(json);
        assert!(res.is_err(), "Duplicate keys must be rejected");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("duplicate JSON key"));
    }

    #[test]
    fn test_valid_json_accepted() {
        let json = r#"{"target": "10.0.0.1", "port": 80, "nested": {"safe": true}}"#;
        let val = StrictJsonParser::parse(json).unwrap();
        assert_eq!(val["target"], "10.0.0.1");
        assert_eq!(val["port"], 80);
    }

    #[test]
    fn test_oversized_payload_rejected() {
        let huge = "a".repeat(MAX_PAYLOAD_SIZE + 1);
        let res = StrictJsonParser::parse(&huge);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Payload size"));
    }

    #[test]
    fn test_deep_nesting_rejected() {
        let mut deep = String::new();
        for _ in 0..10 {
            deep.push_str("{\"nested\":");
        }
        deep.push('1');
        for _ in 0..10 {
            deep.push('}');
        }

        let res = StrictJsonParser::parse(&deep);
        assert!(res.is_err(), "Deep nesting > 8 must be rejected");
        assert!(res.unwrap_err().to_string().contains("nesting depth"));
    }
}
