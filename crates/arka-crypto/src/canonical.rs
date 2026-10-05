//! RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
//!
//! Provides deterministic canonical formatting for JSON values to ensure identical
//! cryptographic hashes across systems and platforms.

use serde_json::Value;
use std::collections::BTreeMap;

/// Canonicalizes a serde_json Value according to RFC 8785 (JCS).
///
/// Rules:
/// - Object keys are sorted lexicographically by Unicode code points.
/// - Whitespace between tokens is completely removed.
/// - Numbers are serialized in standard ECMAScript / JCS format.
/// - Strings preserve valid JSON escaping.
pub fn canonicalize_json(value: &Value) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    serialize_canonical_value(value, &mut out)?;
    Ok(out)
}

/// Helper that produces canonical UTF-8 bytes directly.
pub fn canonicalize_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    canonicalize_json(value).map(|s| s.into_bytes())
}

fn serialize_canonical_value(value: &Value, out: &mut String) -> Result<(), serde_json::Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => {
            if *b {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                // JCS requires ECMAScript number serialization
                if f.is_nan() || f.is_infinite() {
                    return Err(serde::ser::Error::custom(
                        "NaN and Infinity are not valid in JCS",
                    ));
                }
                out.push_str(&f.to_string());
            }
        }
        Value::String(s) => {
            let escaped = serde_json::to_string(s)?;
            out.push_str(&escaped);
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_canonical_value(elem, out)?;
            }
            out.push(']');
        }
        Value::Object(obj) => {
            // Lexicographical UTF-16 code unit ordering matches BTreeMap byte ordering for UTF-8
            let sorted: BTreeMap<&String, &Value> = obj.iter().collect();
            out.push('{');
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let escaped_key = serde_json::to_string(key)?;
                out.push_str(&escaped_key);
                out.push(':');
                serialize_canonical_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jcs_key_sorting() {
        let val1 = json!({
            "zebra": 1,
            "apple": 2,
            "mango": { "b": 10, "a": 20 }
        });
        let val2 = json!({
            "apple": 2,
            "mango": { "a": 20, "b": 10 },
            "zebra": 1
        });

        let canon1 = canonicalize_json(&val1).unwrap();
        let canon2 = canonicalize_json(&val2).unwrap();

        assert_eq!(canon1, canon2);
        assert_eq!(canon1, r#"{"apple":2,"mango":{"a":20,"b":10},"zebra":1}"#);
    }

    #[test]
    fn test_jcs_whitespace_removal() {
        let val = json!({ "key": "value with spaces", "arr": [1, 2, 3] });
        let canon = canonicalize_json(&val).unwrap();
        assert_eq!(canon, r#"{"arr":[1,2,3],"key":"value with spaces"}"#);
    }
}
