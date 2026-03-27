//! Deterministic serialization module with schema-hash prefix validation.
//!
//! Produces a single canonical byte representation for security-critical
//! objects. Every serialized payload is prefixed with a 32-byte schema hash
//! that binds the encoding format to its schema version.
//!
//! Canonical encoding rules:
//! - Deterministic field ordering (lexicographic for maps, declaration order
//!   for structs).
//! - Length-prefixed byte/string fields (u32 big-endian length prefix).
//! - Minimal integer encoding (u64 big-endian, no overlong forms).
//! - No indefinite-length encodings.
//! - No optional-field omission: absent values serialize as explicit tag.
//!
//! Plan references: Section 10.10 item 3, 9E.2 (deterministic serialization
//! and signature preimage contracts).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

/// Schema identifier: a 32-byte content-addressed hash of the schema
/// definition. Acts as a magic number and version discriminator in all
/// wire and storage formats.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaHash(pub [u8; 32]);

impl SchemaHash {
    /// Derive a schema hash from the schema definition bytes.
    pub fn from_definition(definition: &[u8]) -> Self {
        let hash = ContentHash::compute(definition);
        Self(*hash.as_bytes())
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CanonicalValue — typed values in the canonical encoding
// ---------------------------------------------------------------------------

/// A typed value in the canonical encoding format. All security-critical
/// objects are decomposed into these primitives for deterministic
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalValue {
    /// Unsigned 64-bit integer (big-endian).
    U64(u64),
    /// Signed 64-bit integer (big-endian).
    I64(i64),
    /// Boolean (0x00 = false, 0x01 = true).
    Bool(bool),
    /// Byte string (length-prefixed).
    Bytes(Vec<u8>),
    /// UTF-8 string (length-prefixed).
    String(String),
    /// Ordered sequence of values.
    Array(Vec<CanonicalValue>),
    /// Ordered map with string keys (lexicographic key ordering enforced).
    Map(BTreeMap<String, CanonicalValue>),
    /// Explicit null (distinct from absent field).
    Null,
}

// Tag bytes for each variant to ensure unambiguous decoding.
const TAG_U64: u8 = 0x01;
const TAG_I64: u8 = 0x02;
const TAG_BOOL: u8 = 0x03;
const TAG_BYTES: u8 = 0x04;
const TAG_STRING: u8 = 0x05;
const TAG_ARRAY: u8 = 0x06;
const TAG_MAP: u8 = 0x07;
const TAG_NULL: u8 = 0x08;

// ---------------------------------------------------------------------------
// SerdeError
// ---------------------------------------------------------------------------

/// Errors during deterministic serialization/deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerdeError {
    /// Schema hash mismatch: expected vs actual.
    SchemaMismatch {
        expected: SchemaHash,
        actual: SchemaHash,
    },
    /// Unknown schema hash (not in registry).
    UnknownSchema { schema_hash: SchemaHash },
    /// Input buffer too short.
    BufferTooShort { expected: usize, actual: usize },
    /// Invalid tag byte encountered.
    InvalidTag { tag: u8, offset: usize },
    /// Invalid boolean encoding byte encountered.
    InvalidBoolEncoding { value: u8, offset: usize },
    /// String decoding failed.
    InvalidUtf8 { offset: usize },
    /// Duplicate key in map.
    DuplicateKey { key: String },
    /// Map keys not in lexicographic order.
    NonLexicographicKeys {
        prev_key: String,
        current_key: String,
    },
    /// Recursion limit exceeded (stack overflow protection).
    RecursionLimitExceeded { offset: usize },
    /// Trailing bytes after deserialization.
    TrailingBytes { count: usize },
}

impl fmt::Display for SerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => {
                write!(f, "schema mismatch: expected {expected}, got {actual}")
            }
            Self::UnknownSchema { schema_hash } => {
                write!(f, "unknown schema: {schema_hash}")
            }
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: need {expected}, got {actual}")
            }
            Self::InvalidTag { tag, offset } => {
                write!(f, "invalid tag 0x{tag:02x} at offset {offset}")
            }
            Self::InvalidBoolEncoding { value, offset } => {
                write!(f, "invalid bool encoding 0x{value:02x} at offset {offset}")
            }
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {offset}"),
            Self::DuplicateKey { key } => write!(f, "duplicate key: {key}"),
            Self::NonLexicographicKeys {
                prev_key,
                current_key,
            } => write!(f, "non-lexicographic keys: {prev_key} > {current_key}"),
            Self::RecursionLimitExceeded { offset } => {
                write!(f, "recursion limit exceeded at offset {offset}")
            }
            Self::TrailingBytes { count } => write!(f, "{count} trailing bytes"),
        }
    }
}

impl std::error::Error for SerdeError {}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Serialize a `CanonicalValue` to deterministic bytes (without schema prefix).
pub fn encode_value(value: &CanonicalValue) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(&mut buf, value);
    buf
}

fn encode_into(buf: &mut Vec<u8>, value: &CanonicalValue) {
    match value {
        CanonicalValue::U64(v) => {
            buf.push(TAG_U64);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        CanonicalValue::I64(v) => {
            buf.push(TAG_I64);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        CanonicalValue::Bool(v) => {
            buf.push(TAG_BOOL);
            buf.push(if *v { 0x01 } else { 0x00 });
        }
        CanonicalValue::Bytes(v) => {
            buf.push(TAG_BYTES);
            buf.extend_from_slice(&(u32::try_from(v.len()).unwrap_or(u32::MAX)).to_be_bytes());
            buf.extend_from_slice(v);
        }
        CanonicalValue::String(v) => {
            buf.push(TAG_STRING);
            buf.extend_from_slice(&(u32::try_from(v.len()).unwrap_or(u32::MAX)).to_be_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
        CanonicalValue::Array(items) => {
            buf.push(TAG_ARRAY);
            buf.extend_from_slice(&(u32::try_from(items.len()).unwrap_or(u32::MAX)).to_be_bytes());
            for item in items {
                encode_into(buf, item);
            }
        }
        CanonicalValue::Map(entries) => {
            buf.push(TAG_MAP);
            // BTreeMap guarantees lexicographic ordering.
            buf.extend_from_slice(
                &(u32::try_from(entries.len()).unwrap_or(u32::MAX)).to_be_bytes(),
            );
            for (key, val) in entries {
                buf.extend_from_slice(
                    &(u32::try_from(key.len()).unwrap_or(u32::MAX)).to_be_bytes(),
                );
                buf.extend_from_slice(key.as_bytes());
                encode_into(buf, val);
            }
        }
        CanonicalValue::Null => {
            buf.push(TAG_NULL);
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Deserialize a `CanonicalValue` from deterministic bytes (without schema prefix).
pub fn decode_value(data: &[u8]) -> Result<CanonicalValue, SerdeError> {
    let (value, consumed) = decode_at(data, 0, 0)?;
    if consumed < data.len() {
        return Err(SerdeError::TrailingBytes {
            count: data.len() - consumed,
        });
    }
    Ok(value)
}

fn decode_at(
    data: &[u8],
    offset: usize,
    depth: usize,
) -> Result<(CanonicalValue, usize), SerdeError> {
    if depth > 128 {
        return Err(SerdeError::RecursionLimitExceeded { offset });
    }

    if offset >= data.len() {
        return Err(SerdeError::BufferTooShort {
            expected: offset + 1,
            actual: data.len(),
        });
    }

    let tag = data[offset];
    let pos = offset + 1;

    match tag {
        TAG_U64 => {
            need_bytes(data, pos, 8)?;
            let v = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((CanonicalValue::U64(v), pos + 8))
        }
        TAG_I64 => {
            need_bytes(data, pos, 8)?;
            let v = i64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((CanonicalValue::I64(v), pos + 8))
        }
        TAG_BOOL => {
            need_bytes(data, pos, 1)?;
            let v = match data[pos] {
                0x00 => false,
                0x01 => true,
                value => {
                    return Err(SerdeError::InvalidBoolEncoding { value, offset: pos });
                }
            };
            Ok((CanonicalValue::Bool(v), pos + 1))
        }
        TAG_BYTES => {
            need_bytes(data, pos, 4)?;
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let start = pos + 4;
            need_bytes(data, start, len)?;
            let v = data[start..start + len].to_vec();
            Ok((CanonicalValue::Bytes(v), start + len))
        }
        TAG_STRING => {
            need_bytes(data, pos, 4)?;
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let start = pos + 4;
            need_bytes(data, start, len)?;
            let s = std::str::from_utf8(&data[start..start + len])
                .map_err(|_| SerdeError::InvalidUtf8 { offset: start })?;
            Ok((CanonicalValue::String(s.to_string()), start + len))
        }
        TAG_ARRAY => {
            need_bytes(data, pos, 4)?;
            let count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let mut cur = pos + 4;

            // Mitigate OOM: each element requires at least 1 byte (the tag).
            need_bytes(data, cur, count)?;

            let mut items = Vec::with_capacity(std::cmp::min(count, 4096));
            for _ in 0..count {
                let (val, next) = decode_at(data, cur, depth + 1)?;
                items.push(val);
                cur = next;
            }
            Ok((CanonicalValue::Array(items), cur))
        }
        TAG_MAP => {
            need_bytes(data, pos, 4)?;
            let count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let mut cur = pos + 4;
            let mut map = BTreeMap::new();
            let mut prev_key: Option<String> = None;
            for _ in 0..count {
                need_bytes(data, cur, 4)?;
                let key_len = u32::from_be_bytes(data[cur..cur + 4].try_into().unwrap()) as usize;
                cur += 4;
                need_bytes(data, cur, key_len)?;
                let key = std::str::from_utf8(&data[cur..cur + key_len])
                    .map_err(|_| SerdeError::InvalidUtf8 { offset: cur })?
                    .to_string();
                cur += key_len;

                // Enforce lexicographic ordering.
                if let Some(ref prev) = prev_key
                    && key <= *prev
                {
                    if key == *prev {
                        return Err(SerdeError::DuplicateKey { key });
                    }
                    return Err(SerdeError::NonLexicographicKeys {
                        prev_key: prev.clone(),
                        current_key: key,
                    });
                }
                prev_key = Some(key.clone());

                let (val, next) = decode_at(data, cur, depth + 1)?;
                map.insert(key, val);
                cur = next;
            }
            Ok((CanonicalValue::Map(map), cur))
        }
        TAG_NULL => Ok((CanonicalValue::Null, pos)),
        _ => Err(SerdeError::InvalidTag { tag, offset }),
    }
}

fn need_bytes(data: &[u8], offset: usize, count: usize) -> Result<(), SerdeError> {
    let end = offset
        .checked_add(count)
        .ok_or(SerdeError::BufferTooShort {
            expected: usize::MAX,
            actual: data.len(),
        })?;
    if end > data.len() {
        return Err(SerdeError::BufferTooShort {
            expected: end,
            actual: data.len(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema-prefixed encoding
// ---------------------------------------------------------------------------

/// Serialize a value with a 32-byte schema-hash prefix.
pub fn serialize_with_schema(schema: &SchemaHash, value: &CanonicalValue) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(schema.as_bytes());
    encode_into(&mut buf, value);
    buf
}

/// Deserialize a schema-prefixed payload, verifying the schema hash matches.
pub fn deserialize_with_schema(
    expected_schema: &SchemaHash,
    data: &[u8],
) -> Result<CanonicalValue, SerdeError> {
    if data.len() < 32 {
        return Err(SerdeError::BufferTooShort {
            expected: 32,
            actual: data.len(),
        });
    }

    let actual_schema = SchemaHash(data[..32].try_into().unwrap());
    if actual_schema != *expected_schema {
        return Err(SerdeError::SchemaMismatch {
            expected: expected_schema.clone(),
            actual: actual_schema,
        });
    }

    let (value, consumed) = decode_at(data, 32, 0)?;
    if consumed < data.len() {
        return Err(SerdeError::TrailingBytes {
            count: data.len() - consumed,
        });
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// SchemaRegistry
// ---------------------------------------------------------------------------

/// Registry of known schema hashes and their definitions.
///
/// Prevents deserialization of payloads with unknown schemas.
#[derive(Debug, Default)]
pub struct SchemaRegistry {
    schemas: BTreeMap<[u8; 32], SchemaDefinition>,
}

/// A registered schema definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Human-readable name for the schema.
    pub name: String,
    /// Version of the schema.
    pub version: u32,
    /// The schema hash (derived from definition bytes).
    pub schema_hash: SchemaHash,
}

impl SchemaRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema. Returns the schema hash.
    pub fn register(&mut self, name: &str, version: u32, definition: &[u8]) -> SchemaHash {
        let hash = SchemaHash::from_definition(definition);
        self.schemas.insert(
            hash.0,
            SchemaDefinition {
                name: name.to_string(),
                version,
                schema_hash: hash.clone(),
            },
        );
        hash
    }

    /// Look up a schema by its hash.
    pub fn lookup(&self, hash: &SchemaHash) -> Option<&SchemaDefinition> {
        self.schemas.get(&hash.0)
    }

    /// Check if a schema hash is registered.
    pub fn is_known(&self, hash: &SchemaHash) -> bool {
        self.schemas.contains_key(&hash.0)
    }

    /// Number of registered schemas.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Deserialize with registry validation: verifies the schema prefix is
    /// known before attempting to decode.
    pub fn deserialize_checked(
        &self,
        data: &[u8],
    ) -> Result<(SchemaDefinition, CanonicalValue), SerdeError> {
        if data.len() < 32 {
            return Err(SerdeError::BufferTooShort {
                expected: 32,
                actual: data.len(),
            });
        }

        let schema_hash = SchemaHash(data[..32].try_into().unwrap());
        let def = self
            .lookup(&schema_hash)
            .ok_or_else(|| SerdeError::UnknownSchema {
                schema_hash: schema_hash.clone(),
            })?
            .clone();

        let (value, consumed) = decode_at(data, 32, 0)?;
        if consumed < data.len() {
            return Err(SerdeError::TrailingBytes {
                count: data.len() - consumed,
            });
        }

        Ok((def, value))
    }
}

// ---------------------------------------------------------------------------
// Content hash for canonical values
// ---------------------------------------------------------------------------

/// Compute the content hash of a canonical value (for use in signatures,
/// evidence chains, etc.).
pub fn canonical_hash(schema: &SchemaHash, value: &CanonicalValue) -> ContentHash {
    let bytes = serialize_with_schema(schema, value);
    ContentHash::compute(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schema() -> SchemaHash {
        SchemaHash::from_definition(b"test-schema-v1")
    }

    // -- Encode/decode round-trip for each value type --

    #[test]
    fn round_trip_u64() {
        let val = CanonicalValue::U64(42);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_u64_max() {
        let val = CanonicalValue::U64(u64::MAX);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_i64() {
        let val = CanonicalValue::I64(-12345);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bool_true() {
        let val = CanonicalValue::Bool(true);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bool_false() {
        let val = CanonicalValue::Bool(false);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bytes() {
        let val = CanonicalValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_bytes() {
        let val = CanonicalValue::Bytes(vec![]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_string() {
        let val = CanonicalValue::String("hello world".to_string());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_string() {
        let val = CanonicalValue::String(String::new());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_null() {
        let val = CanonicalValue::Null;
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_array() {
        let val = CanonicalValue::Array(vec![
            CanonicalValue::U64(1),
            CanonicalValue::String("two".to_string()),
            CanonicalValue::Bool(true),
        ]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_array() {
        let val = CanonicalValue::Array(vec![]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_map() {
        let mut map = BTreeMap::new();
        map.insert("alpha".to_string(), CanonicalValue::U64(1));
        map.insert("beta".to_string(), CanonicalValue::String("b".to_string()));
        map.insert("gamma".to_string(), CanonicalValue::Null);
        let val = CanonicalValue::Map(map);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_nested() {
        let inner_map = BTreeMap::from([
            ("key".to_string(), CanonicalValue::U64(99)),
            ("nested".to_string(), CanonicalValue::Bool(false)),
        ]);
        let val = CanonicalValue::Array(vec![
            CanonicalValue::Map(inner_map),
            CanonicalValue::Bytes(vec![1, 2, 3]),
        ]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    // -- Determinism --

    #[test]
    fn encoding_is_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), CanonicalValue::U64(1));
        map.insert("a".to_string(), CanonicalValue::U64(2));
        let val = CanonicalValue::Map(map);
        let bytes1 = encode_value(&val);
        let bytes2 = encode_value(&val);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn map_keys_are_lexicographically_ordered_in_output() {
        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), CanonicalValue::Null);
        map.insert("apple".to_string(), CanonicalValue::Null);
        map.insert("mango".to_string(), CanonicalValue::Null);
        let bytes = encode_value(&CanonicalValue::Map(map));

        // Decode and verify key order.
        let decoded = decode_value(&bytes).unwrap();
        if let CanonicalValue::Map(m) = decoded {
            let keys: Vec<&String> = m.keys().collect();
            assert_eq!(keys, vec!["apple", "mango", "zebra"]);
        } else {
            panic!("expected map");
        }
    }

    // -- Schema-prefixed round-trip --

    #[test]
    fn schema_prefixed_round_trip() {
        let schema = test_schema();
        let val = CanonicalValue::U64(42);
        let bytes = serialize_with_schema(&schema, &val);
        assert_eq!(bytes.len(), 32 + 1 + 8); // schema + tag + u64
        let decoded = deserialize_with_schema(&schema, &bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_mismatch_rejected() {
        let schema = test_schema();
        let wrong_schema = SchemaHash::from_definition(b"wrong-schema");
        let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
        assert!(matches!(
            deserialize_with_schema(&wrong_schema, &bytes),
            Err(SerdeError::SchemaMismatch { .. })
        ));
    }

    // -- Schema registry --

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = SchemaRegistry::new();
        let hash = reg.register("TestObject", 1, b"test-schema-def");
        assert!(reg.is_known(&hash));
        let def = reg.lookup(&hash).unwrap();
        assert_eq!(def.name, "TestObject");
        assert_eq!(def.version, 1);
    }

    #[test]
    fn registry_rejects_unknown_schema() {
        let reg = SchemaRegistry::new();
        let schema = test_schema();
        let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
        assert!(matches!(
            reg.deserialize_checked(&bytes),
            Err(SerdeError::UnknownSchema { .. })
        ));
    }

    #[test]
    fn registry_accepts_known_schema() {
        let mut reg = SchemaRegistry::new();
        let hash = reg.register("TestObj", 1, b"test-schema-v1");
        let bytes = serialize_with_schema(&hash, &CanonicalValue::U64(123));
        let (def, val) = reg.deserialize_checked(&bytes).unwrap();
        assert_eq!(def.name, "TestObj");
        assert_eq!(val, CanonicalValue::U64(123));
    }

    // -- Error cases --

    #[test]
    fn buffer_too_short() {
        assert!(matches!(
            decode_value(&[]),
            Err(SerdeError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn invalid_tag() {
        assert!(matches!(
            decode_value(&[0xFF]),
            Err(SerdeError::InvalidTag { tag: 0xFF, .. })
        ));
    }

    #[test]
    fn invalid_bool_encoding_rejected() {
        assert!(matches!(
            decode_value(&[TAG_BOOL, 0x02]),
            Err(SerdeError::InvalidBoolEncoding {
                value: 0x02,
                offset: 1
            })
        ));
    }

    #[test]
    fn truncated_u64() {
        let mut bytes = encode_value(&CanonicalValue::U64(42));
        bytes.truncate(5); // tag + 4 of 8 bytes
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = encode_value(&CanonicalValue::Null);
        bytes.push(0x00);
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::TrailingBytes { count: 1 })
        ));
    }

    #[test]
    fn non_lexicographic_map_rejected() {
        // Manually construct a map with out-of-order keys.
        let mut bytes = vec![TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

        // Key "z" first (wrong order).
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'z');
        bytes.push(TAG_NULL);

        // Key "a" second.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::NonLexicographicKeys { .. })
        ));
    }

    #[test]
    fn duplicate_map_key_rejected() {
        let mut bytes = vec![TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes());

        // Key "a" twice.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn invalid_utf8_rejected() {
        let mut bytes = vec![TAG_STRING];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn recursion_limit_exceeded_rejected() {
        // Construct an array nested 129 times to trigger recursion limit (limit is 128).
        let mut bytes = Vec::new();
        for _ in 0..129 {
            bytes.push(TAG_ARRAY);
            bytes.extend_from_slice(&1u32.to_be_bytes());
        }
        bytes.push(TAG_NULL);
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::RecursionLimitExceeded { .. })
        ));
    }

    // -- Content hash --

    #[test]
    fn canonical_hash_is_deterministic() {
        let schema = test_schema();
        let val = CanonicalValue::U64(42);
        let h1 = canonical_hash(&schema, &val);
        let h2 = canonical_hash(&schema, &val);
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_differs_for_different_values() {
        let schema = test_schema();
        let h1 = canonical_hash(&schema, &CanonicalValue::U64(1));
        let h2 = canonical_hash(&schema, &CanonicalValue::U64(2));
        assert_ne!(h1, h2);
    }

    #[test]
    fn canonical_hash_differs_for_different_schemas() {
        let s1 = SchemaHash::from_definition(b"schema-a");
        let s2 = SchemaHash::from_definition(b"schema-b");
        let val = CanonicalValue::U64(42);
        assert_ne!(canonical_hash(&s1, &val), canonical_hash(&s2, &val));
    }

    // -- Serialization of types --

    #[test]
    fn schema_hash_serialization_round_trip() {
        let hash = test_schema();
        let json = serde_json::to_string(&hash).expect("serialize");
        let restored: SchemaHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hash, restored);
    }

    #[test]
    fn serde_error_serialization_round_trip() {
        let errors = vec![
            SerdeError::BufferTooShort {
                expected: 10,
                actual: 5,
            },
            SerdeError::InvalidTag {
                tag: 0xFF,
                offset: 0,
            },
            SerdeError::InvalidBoolEncoding {
                value: 0x02,
                offset: 1,
            },
            SerdeError::DuplicateKey {
                key: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SerdeError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn schema_hash_display() {
        let hash = SchemaHash([0u8; 32]);
        assert_eq!(hash.to_string().len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn error_display() {
        assert!(
            SerdeError::BufferTooShort {
                expected: 10,
                actual: 5
            }
            .to_string()
            .contains("10")
        );

        assert!(
            SerdeError::DuplicateKey {
                key: "x".to_string()
            }
            .to_string()
            .contains("x")
        );
    }

    // -- Minimal encoding --

    #[test]
    fn u64_encoding_is_fixed_size() {
        // All u64 values use exactly 9 bytes (1 tag + 8 data).
        assert_eq!(encode_value(&CanonicalValue::U64(0)).len(), 9);
        assert_eq!(encode_value(&CanonicalValue::U64(u64::MAX)).len(), 9);
    }

    #[test]
    fn string_encoding_includes_length_prefix() {
        let val = CanonicalValue::String("abc".to_string());
        let bytes = encode_value(&val);
        // 1 tag + 4 length + 3 chars = 8
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn serde_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SerdeError::SchemaMismatch {
                expected: SchemaHash([1; 32]),
                actual: SchemaHash([2; 32]),
            }),
            Box::new(SerdeError::UnknownSchema {
                schema_hash: SchemaHash([3; 32]),
            }),
            Box::new(SerdeError::BufferTooShort {
                expected: 10,
                actual: 5,
            }),
            Box::new(SerdeError::InvalidTag {
                tag: 0xFF,
                offset: 0,
            }),
            Box::new(SerdeError::InvalidBoolEncoding {
                value: 0x02,
                offset: 1,
            }),
            Box::new(SerdeError::InvalidUtf8 { offset: 3 }),
            Box::new(SerdeError::DuplicateKey { key: "k".into() }),
            Box::new(SerdeError::NonLexicographicKeys {
                prev_key: "b".into(),
                current_key: "a".into(),
            }),
            Box::new(SerdeError::RecursionLimitExceeded { offset: 99 }),
            Box::new(SerdeError::TrailingBytes { count: 4 }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 10);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: edge cases, nested maps, schema registry, Display
    // -----------------------------------------------------------------------

    #[test]
    fn schema_hash_display_nonzero_bytes() {
        let hash = SchemaHash([0xAB; 32]);
        let display = hash.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
        // Each byte 0xAB -> "ab"
        assert!(display.starts_with("abab"));
    }

    #[test]
    fn schema_hash_from_definition_deterministic() {
        let h1 = SchemaHash::from_definition(b"same-input");
        let h2 = SchemaHash::from_definition(b"same-input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn schema_hash_from_definition_differs_on_input() {
        let h1 = SchemaHash::from_definition(b"input-a");
        let h2 = SchemaHash::from_definition(b"input-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn round_trip_i64_boundaries() {
        for v in [i64::MIN, -1, 0, 1, i64::MAX] {
            let val = CanonicalValue::I64(v);
            let bytes = encode_value(&val);
            assert_eq!(decode_value(&bytes).unwrap(), val);
        }
    }

    #[test]
    fn round_trip_nested_map_in_map() {
        let inner = BTreeMap::from([("inner_key".to_string(), CanonicalValue::Bool(true))]);
        let outer = BTreeMap::from([("outer_key".to_string(), CanonicalValue::Map(inner))]);
        let val = CanonicalValue::Map(outer);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn registry_len_and_is_empty() {
        let mut reg = SchemaRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        reg.register("A", 1, b"def-a");
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
        reg.register("B", 2, b"def-b");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn schema_definition_serde_roundtrip() {
        let def = SchemaDefinition {
            name: "TestObj".to_string(),
            version: 3,
            schema_hash: SchemaHash::from_definition(b"schema-def"),
        };
        let json = serde_json::to_string(&def).unwrap();
        let back: SchemaDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(def, back);
    }

    #[test]
    fn canonical_value_serde_all_variants() {
        let values = vec![
            CanonicalValue::U64(999),
            CanonicalValue::I64(-999),
            CanonicalValue::Bool(false),
            CanonicalValue::Bytes(vec![1, 2, 3]),
            CanonicalValue::String("test".to_string()),
            CanonicalValue::Array(vec![CanonicalValue::Null]),
            CanonicalValue::Map(BTreeMap::from([("k".to_string(), CanonicalValue::U64(1))])),
            CanonicalValue::Null,
        ];
        for val in &values {
            let json = serde_json::to_string(val).unwrap();
            let back: CanonicalValue = serde_json::from_str(&json).unwrap();
            assert_eq!(*val, back);
        }
    }

    #[test]
    fn empty_map_round_trip() {
        let val = CanonicalValue::Map(BTreeMap::new());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON field presence, serde roundtrip,
    // Display uniqueness, boundary conditions, Ord determinism, Error::source
    // -----------------------------------------------------------------------

    // -- Clone equality tests (5) --

    #[test]
    fn clone_eq_schema_hash() {
        let original = SchemaHash::from_definition(b"clone-test-schema");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_schema_definition() {
        let original = SchemaDefinition {
            name: "CloneTest".to_string(),
            version: 7,
            schema_hash: SchemaHash::from_definition(b"clone-def"),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_canonical_value_u64() {
        let original = CanonicalValue::U64(123_456_789);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_canonical_value_map() {
        let mut map = BTreeMap::new();
        map.insert("alpha".to_string(), CanonicalValue::I64(-42));
        map.insert("beta".to_string(), CanonicalValue::Bytes(vec![0xCA, 0xFE]));
        let original = CanonicalValue::Map(map);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_serde_error() {
        let original = SerdeError::NonLexicographicKeys {
            prev_key: "z".to_string(),
            current_key: "a".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // -- JSON field presence tests (3) --

    #[test]
    fn json_field_presence_schema_definition() {
        let def = SchemaDefinition {
            name: "FieldTest".to_string(),
            version: 5,
            schema_hash: SchemaHash([0xAA; 32]),
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"schema_hash\""));
    }

    #[test]
    fn json_field_presence_serde_error_buffer_too_short() {
        let err = SerdeError::BufferTooShort {
            expected: 64,
            actual: 12,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"expected\""));
        assert!(json.contains("\"actual\""));
        assert!(json.contains("BufferTooShort"));
    }

    #[test]
    fn json_field_presence_serde_error_non_lexicographic() {
        let err = SerdeError::NonLexicographicKeys {
            prev_key: "beta".to_string(),
            current_key: "alpha".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"prev_key\""));
        assert!(json.contains("\"current_key\""));
        assert!(json.contains("NonLexicographicKeys"));
    }

    // -- Serde roundtrip for deeply nested structure --

    #[test]
    fn serde_roundtrip_deeply_nested_array() {
        // Build a 10-deep nested array: Array([Array([Array([...U64(1)...])])])
        let mut val = CanonicalValue::U64(1);
        for _ in 0..10 {
            val = CanonicalValue::Array(vec![val]);
        }
        let bytes = encode_value(&val);
        let decoded = decode_value(&bytes).unwrap();
        assert_eq!(decoded, val);
    }

    // -- Display uniqueness across all SerdeError variants --

    #[test]
    fn display_uniqueness_all_serde_error_variants() {
        let variants = vec![
            SerdeError::SchemaMismatch {
                expected: SchemaHash([0; 32]),
                actual: SchemaHash([1; 32]),
            },
            SerdeError::UnknownSchema {
                schema_hash: SchemaHash([2; 32]),
            },
            SerdeError::BufferTooShort {
                expected: 100,
                actual: 50,
            },
            SerdeError::InvalidTag {
                tag: 0xAA,
                offset: 10,
            },
            SerdeError::InvalidBoolEncoding {
                value: 0x02,
                offset: 11,
            },
            SerdeError::InvalidUtf8 { offset: 20 },
            SerdeError::DuplicateKey {
                key: "dup".to_string(),
            },
            SerdeError::NonLexicographicKeys {
                prev_key: "z".to_string(),
                current_key: "a".to_string(),
            },
            SerdeError::RecursionLimitExceeded { offset: 500 },
            SerdeError::TrailingBytes { count: 7 },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
            displays.insert(s);
        }
        // All 10 variants produce distinct Display output.
        assert_eq!(displays.len(), variants.len());
    }

    // -- Ord determinism for SchemaHash --

    #[test]
    fn schema_hash_ord_determinism() {
        let h_low = SchemaHash([0x00; 32]);
        let h_mid = SchemaHash([0x80; 32]);
        let h_high = SchemaHash([0xFF; 32]);
        assert!(h_low < h_mid);
        assert!(h_mid < h_high);
        // Sorting a vec should be stable and deterministic.
        let mut v = vec![h_high.clone(), h_low.clone(), h_mid.clone()];
        v.sort();
        assert_eq!(v, vec![h_low, h_mid, h_high]);
    }

    // -- std::error::Error::source returns None for all variants --

    #[test]
    fn serde_error_source_is_none() {
        let err = SerdeError::InvalidTag {
            tag: 0x99,
            offset: 0,
        };
        // SerdeError has no source (no #[from] or source field).
        assert!(std::error::Error::source(&err).is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: edge cases, stress, clone independence, encoding
    // sizes, registry edge cases, hash collision resistance
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_u64_zero() {
        let val = CanonicalValue::U64(0);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_i64_zero() {
        let val = CanonicalValue::I64(0);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_large_bytes_payload() {
        let val = CanonicalValue::Bytes(vec![0xAB; 1024]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_unicode_string() {
        let val = CanonicalValue::String("\u{1F600}\u{1F4A9}\u{00E9}\u{2603}".to_string());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_many_map_keys() {
        let mut map = BTreeMap::new();
        for i in 0..50 {
            map.insert(format!("key_{i:04}"), CanonicalValue::U64(i));
        }
        let val = CanonicalValue::Map(map);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_mixed_array() {
        let val = CanonicalValue::Array(vec![
            CanonicalValue::U64(0),
            CanonicalValue::I64(i64::MIN),
            CanonicalValue::Bool(true),
            CanonicalValue::Bytes(vec![]),
            CanonicalValue::String(String::new()),
            CanonicalValue::Array(vec![]),
            CanonicalValue::Map(BTreeMap::new()),
            CanonicalValue::Null,
        ]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn schema_prefixed_complex_value() {
        let schema = SchemaHash::from_definition(b"complex-schema");
        let mut map = BTreeMap::new();
        map.insert(
            "arr".to_string(),
            CanonicalValue::Array(vec![CanonicalValue::I64(-1), CanonicalValue::Bool(false)]),
        );
        map.insert("data".to_string(), CanonicalValue::Bytes(vec![0xFF; 16]));
        let val = CanonicalValue::Map(map);
        let bytes = serialize_with_schema(&schema, &val);
        let decoded = deserialize_with_schema(&schema, &bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_prefix_too_short_buffer() {
        let schema = test_schema();
        // Only 31 bytes — less than the 32-byte schema prefix
        let data = vec![0u8; 31];
        assert!(matches!(
            deserialize_with_schema(&schema, &data),
            Err(SerdeError::BufferTooShort {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn registry_overwrite_same_definition() {
        let mut reg = SchemaRegistry::new();
        let h1 = reg.register("First", 1, b"same-def");
        let h2 = reg.register("Second", 2, b"same-def");
        // Same definition bytes → same hash, second overwrites first
        assert_eq!(h1, h2);
        assert_eq!(reg.len(), 1);
        let def = reg.lookup(&h1).unwrap();
        assert_eq!(def.name, "Second");
        assert_eq!(def.version, 2);
    }

    #[test]
    fn registry_multiple_schemas_deserialize() {
        let mut reg = SchemaRegistry::new();
        let h1 = reg.register("TypeA", 1, b"def-type-a");
        let h2 = reg.register("TypeB", 1, b"def-type-b");
        assert_ne!(h1, h2);

        let bytes1 = serialize_with_schema(&h1, &CanonicalValue::U64(100));
        let bytes2 = serialize_with_schema(&h2, &CanonicalValue::I64(-200));

        let (d1, v1) = reg.deserialize_checked(&bytes1).unwrap();
        assert_eq!(d1.name, "TypeA");
        assert_eq!(v1, CanonicalValue::U64(100));

        let (d2, v2) = reg.deserialize_checked(&bytes2).unwrap();
        assert_eq!(d2.name, "TypeB");
        assert_eq!(v2, CanonicalValue::I64(-200));
    }

    #[test]
    fn encoding_size_null() {
        // Null is a single tag byte
        assert_eq!(encode_value(&CanonicalValue::Null).len(), 1);
    }

    #[test]
    fn encoding_size_bool() {
        // Bool is 1 tag + 1 data
        assert_eq!(encode_value(&CanonicalValue::Bool(true)).len(), 2);
        assert_eq!(encode_value(&CanonicalValue::Bool(false)).len(), 2);
    }

    #[test]
    fn encoding_size_i64() {
        // Same as u64: 1 tag + 8 data
        assert_eq!(encode_value(&CanonicalValue::I64(0)).len(), 9);
        assert_eq!(encode_value(&CanonicalValue::I64(i64::MIN)).len(), 9);
    }

    #[test]
    fn encoding_size_bytes_prefix() {
        // Bytes: 1 tag + 4 length + N data
        let val = CanonicalValue::Bytes(vec![0; 10]);
        assert_eq!(encode_value(&val).len(), 1 + 4 + 10);
    }

    #[test]
    fn encoding_size_empty_array() {
        // Empty array: 1 tag + 4 count(=0)
        assert_eq!(encode_value(&CanonicalValue::Array(vec![])).len(), 5);
    }

    #[test]
    fn encoding_size_empty_map() {
        // Empty map: 1 tag + 4 count(=0)
        assert_eq!(encode_value(&CanonicalValue::Map(BTreeMap::new())).len(), 5);
    }

    #[test]
    fn canonical_hash_collision_resistance_type_tags() {
        // U64(0) vs I64(0) must hash differently (different type tags)
        let schema = test_schema();
        let h_u64 = canonical_hash(&schema, &CanonicalValue::U64(0));
        let h_i64 = canonical_hash(&schema, &CanonicalValue::I64(0));
        assert_ne!(h_u64, h_i64);
    }

    #[test]
    fn canonical_hash_collision_resistance_null_vs_empty() {
        let schema = test_schema();
        let h_null = canonical_hash(&schema, &CanonicalValue::Null);
        let h_empty_bytes = canonical_hash(&schema, &CanonicalValue::Bytes(vec![]));
        let h_empty_str = canonical_hash(&schema, &CanonicalValue::String(String::new()));
        let h_empty_arr = canonical_hash(&schema, &CanonicalValue::Array(vec![]));
        let h_empty_map = canonical_hash(&schema, &CanonicalValue::Map(BTreeMap::new()));
        let all = [h_null, h_empty_bytes, h_empty_str, h_empty_arr, h_empty_map];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "hash collision between idx {i} and {j}");
            }
        }
    }

    #[test]
    fn clone_independence_canonical_value_bytes() {
        let mut original = CanonicalValue::Bytes(vec![1, 2, 3]);
        let cloned = original.clone();
        // Mutate original
        if let CanonicalValue::Bytes(ref mut v) = original {
            v.push(4);
        }
        // Clone should not be affected
        assert_eq!(cloned, CanonicalValue::Bytes(vec![1, 2, 3]));
        assert_ne!(original, cloned);
    }

    #[test]
    fn clone_independence_schema_definition() {
        let mut original = SchemaDefinition {
            name: "Original".to_string(),
            version: 1,
            schema_hash: SchemaHash::from_definition(b"orig"),
        };
        let cloned = original.clone();
        original.name = "Mutated".to_string();
        original.version = 99;
        assert_eq!(cloned.name, "Original");
        assert_eq!(cloned.version, 1);
        assert_ne!(original, cloned);
    }

    #[test]
    fn display_schema_mismatch_contains_both_hashes() {
        let expected = SchemaHash([0xAA; 32]);
        let actual = SchemaHash([0xBB; 32]);
        let err = SerdeError::SchemaMismatch {
            expected: expected.clone(),
            actual: actual.clone(),
        };
        let msg = err.to_string();
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&actual.to_string()));
    }

    #[test]
    fn display_unknown_schema_contains_hash() {
        let hash = SchemaHash([0xCC; 32]);
        let err = SerdeError::UnknownSchema {
            schema_hash: hash.clone(),
        };
        let msg = err.to_string();
        assert!(msg.contains(&hash.to_string()));
    }

    #[test]
    fn display_invalid_tag_contains_hex() {
        let err = SerdeError::InvalidTag {
            tag: 0xDE,
            offset: 42,
        };
        let msg = err.to_string();
        assert!(msg.contains("de")); // hex of 0xDE
        assert!(msg.contains("42"));
    }

    #[test]
    fn display_invalid_bool_encoding_contains_hex() {
        let err = SerdeError::InvalidBoolEncoding {
            value: 0x02,
            offset: 17,
        };
        let msg = err.to_string();
        assert!(msg.contains("02"));
        assert!(msg.contains("17"));
    }

    #[test]
    fn display_non_lexicographic_keys_contains_keys() {
        let err = SerdeError::NonLexicographicKeys {
            prev_key: "zebra".to_string(),
            current_key: "apple".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("zebra"));
        assert!(msg.contains("apple"));
    }

    #[test]
    fn display_recursion_limit_contains_offset() {
        let err = SerdeError::RecursionLimitExceeded { offset: 1234 };
        let msg = err.to_string();
        assert!(msg.contains("1234"));
    }

    #[test]
    fn display_trailing_bytes_contains_count() {
        let err = SerdeError::TrailingBytes { count: 99 };
        let msg = err.to_string();
        assert!(msg.contains("99"));
    }

    #[test]
    fn schema_hash_btreeset_insertion() {
        let mut set = std::collections::BTreeSet::new();
        let h1 = SchemaHash([0x00; 32]);
        let h2 = SchemaHash([0x01; 32]);
        let h3 = SchemaHash([0x00; 32]); // duplicate of h1
        set.insert(h1);
        set.insert(h2);
        set.insert(h3); // should not increase size
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn registry_checked_deserialize_trailing_bytes() {
        let mut reg = SchemaRegistry::new();
        let h = reg.register("T", 1, b"test-trailing");
        let mut bytes = serialize_with_schema(&h, &CanonicalValue::Null);
        bytes.push(0xFF); // extra trailing byte
        assert!(matches!(
            reg.deserialize_checked(&bytes),
            Err(SerdeError::TrailingBytes { count: 1 })
        ));
    }

    #[test]
    fn registry_checked_deserialize_short_buffer() {
        let reg = SchemaRegistry::new();
        assert!(matches!(
            reg.deserialize_checked(&[0u8; 10]),
            Err(SerdeError::BufferTooShort {
                expected: 32,
                actual: 10
            })
        ));
    }

    #[test]
    fn stress_encode_decode_many_values() {
        let mut arr = Vec::new();
        for i in 0..100 {
            arr.push(CanonicalValue::U64(i));
        }
        let val = CanonicalValue::Array(arr);
        let bytes = encode_value(&val);
        let decoded = decode_value(&bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn stress_nested_maps_3_deep() {
        let inner = BTreeMap::from([("leaf".to_string(), CanonicalValue::I64(42))]);
        let mid = BTreeMap::from([("mid_key".to_string(), CanonicalValue::Map(inner))]);
        let outer = BTreeMap::from([("top_key".to_string(), CanonicalValue::Map(mid))]);
        let val = CanonicalValue::Map(outer);
        let bytes = encode_value(&val);
        let decoded = decode_value(&bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn determinism_repeated_serializations() {
        let val = CanonicalValue::Array(vec![
            CanonicalValue::String("deterministic".to_string()),
            CanonicalValue::Bytes(vec![0xDE, 0xAD]),
            CanonicalValue::Map(BTreeMap::from([
                ("a".to_string(), CanonicalValue::U64(1)),
                ("b".to_string(), CanonicalValue::U64(2)),
            ])),
        ]);
        let first = encode_value(&val);
        for _ in 0..10 {
            assert_eq!(encode_value(&val), first);
        }
    }

    #[test]
    fn schema_hash_as_bytes_returns_inner() {
        let bytes = [0x42; 32];
        let hash = SchemaHash(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
    }

    #[test]
    fn canonical_value_debug_not_empty() {
        let variants = vec![
            CanonicalValue::U64(1),
            CanonicalValue::I64(-1),
            CanonicalValue::Bool(true),
            CanonicalValue::Bytes(vec![]),
            CanonicalValue::String("s".into()),
            CanonicalValue::Array(vec![]),
            CanonicalValue::Map(BTreeMap::new()),
            CanonicalValue::Null,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }
}
