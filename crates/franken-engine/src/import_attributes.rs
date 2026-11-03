//! Bounded, deterministic static import attributes shared by syntax and loading.
//!
//! Attribute spelling is retained until resolution: a loader must reject an
//! unsupported key or type, never silently discard it while authorizing a cache hit.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::deterministic_serde::CanonicalValue;

pub const MAX_IMPORT_ATTRIBUTES: usize = 16;
pub const MAX_IMPORT_ATTRIBUTE_KEY_BYTES: usize = 128;
pub const MAX_IMPORT_ATTRIBUTE_VALUE_BYTES: usize = 1024;
pub const MAX_IMPORT_ATTRIBUTE_TOTAL_BYTES: usize = 4096;

/// Exact, well-formed UTF-8 keys and values, ordered independently of spelling
/// order. Parsing checks duplicate keys before constructing this map. Nonempty
/// maps share immutable storage across AST, IR and request clones; empty maps
/// allocate nothing and serialize as the same ordinary empty map.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportAttributes(Option<Arc<BTreeMap<String, String>>>);

static EMPTY_IMPORT_ATTRIBUTES: BTreeMap<String, String> = BTreeMap::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportAttributesError {
    TooMany { actual: usize, limit: usize },
    KeyTooLong { bytes: usize, limit: usize },
    ValueTooLong { bytes: usize, limit: usize },
    TotalTooLarge { bytes: usize, limit: usize },
    DuplicateKey { key: String },
}

impl fmt::Display for ImportAttributesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany { actual, limit } => {
                write!(
                    f,
                    "import attributes contain {actual} entries; maximum is {limit}"
                )
            }
            Self::KeyTooLong { bytes, limit } => {
                write!(
                    f,
                    "import attribute key has {bytes} bytes; maximum is {limit}"
                )
            }
            Self::ValueTooLong { bytes, limit } => {
                write!(
                    f,
                    "import attribute value has {bytes} bytes; maximum is {limit}"
                )
            }
            Self::TotalTooLarge { bytes, limit } => {
                write!(
                    f,
                    "import attributes contain {bytes} bytes; maximum is {limit}"
                )
            }
            Self::DuplicateKey { key } => write!(f, "duplicate import attribute key '{key}'"),
        }
    }
}

impl std::error::Error for ImportAttributesError {}

impl ImportAttributes {
    pub fn new(values: BTreeMap<String, String>) -> Result<Self, ImportAttributesError> {
        let attributes = Self((!values.is_empty()).then(|| Arc::new(values)));
        attributes.validate()?;
        Ok(attributes)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn len(&self) -> usize {
        self.as_map().len()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.as_map().get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.as_map().iter()
    }

    pub fn as_map(&self) -> &BTreeMap<String, String> {
        self.0.as_deref().unwrap_or(&EMPTY_IMPORT_ATTRIBUTES)
    }

    pub fn validate(&self) -> Result<(), ImportAttributesError> {
        if self.len() > MAX_IMPORT_ATTRIBUTES {
            return Err(ImportAttributesError::TooMany {
                actual: self.len(),
                limit: MAX_IMPORT_ATTRIBUTES,
            });
        }
        let mut total = 0usize;
        for (key, value) in self.as_map() {
            validate_entry(key, value)?;
            total = total.saturating_add(key.len()).saturating_add(value.len());
            if total > MAX_IMPORT_ATTRIBUTE_TOTAL_BYTES {
                return Err(ImportAttributesError::TotalTooLarge {
                    bytes: total,
                    limit: MAX_IMPORT_ATTRIBUTE_TOTAL_BYTES,
                });
            }
        }
        Ok(())
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::map_from_entries(
            self.iter()
                .map(|(key, value)| (key.clone(), CanonicalValue::str(value.clone()))),
        )
    }
}

impl Serialize for ImportAttributes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_map().serialize(serializer)
    }
}

fn validate_entry(key: &str, value: &str) -> Result<(), ImportAttributesError> {
    if key.len() > MAX_IMPORT_ATTRIBUTE_KEY_BYTES {
        return Err(ImportAttributesError::KeyTooLong {
            bytes: key.len(),
            limit: MAX_IMPORT_ATTRIBUTE_KEY_BYTES,
        });
    }
    if value.len() > MAX_IMPORT_ATTRIBUTE_VALUE_BYTES {
        return Err(ImportAttributesError::ValueTooLong {
            bytes: value.len(),
            limit: MAX_IMPORT_ATTRIBUTE_VALUE_BYTES,
        });
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ImportAttributes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AttributesVisitor;

        impl<'de> Visitor<'de> for AttributesVisitor {
            type Value = ImportAttributes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded map of unique string import attributes")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut values = BTreeMap::new();
                let mut total = 0usize;
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    validate_entry(&key, &value).map_err(serde::de::Error::custom)?;
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(
                            ImportAttributesError::DuplicateKey { key },
                        ));
                    }
                    if values.len() == MAX_IMPORT_ATTRIBUTES {
                        return Err(serde::de::Error::custom(ImportAttributesError::TooMany {
                            actual: values.len() + 1,
                            limit: MAX_IMPORT_ATTRIBUTES,
                        }));
                    }
                    total = total.saturating_add(key.len()).saturating_add(value.len());
                    if total > MAX_IMPORT_ATTRIBUTE_TOTAL_BYTES {
                        return Err(serde::de::Error::custom(
                            ImportAttributesError::TotalTooLarge {
                                bytes: total,
                                limit: MAX_IMPORT_ATTRIBUTE_TOTAL_BYTES,
                            },
                        ));
                    }
                    values.insert(key, value);
                }
                ImportAttributes::new(values).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_map(AttributesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_unknown_attributes_survive_ordered_roundtrip() {
        let attributes: ImportAttributes =
            serde_json::from_str(r#"{"type":"json","integrity":"opaque"}"#).unwrap();
        assert_eq!(attributes.get("type"), Some("json"));
        assert_eq!(attributes.get("integrity"), Some("opaque"));
        assert_eq!(
            serde_json::to_string(&attributes).unwrap(),
            r#"{"integrity":"opaque","type":"json"}"#
        );
        let reordered: ImportAttributes =
            serde_json::from_str(r#"{"integrity":"opaque","type":"json"}"#).unwrap();
        assert_eq!(attributes.canonical_value(), reordered.canonical_value());
        assert!(ImportAttributes::default().is_empty());
        assert_eq!(
            serde_json::to_string(&ImportAttributes::default()).unwrap(),
            "{}"
        );
        assert!(std::ptr::eq(
            attributes.as_map(),
            attributes.clone().as_map()
        ));
    }

    #[test]
    fn construction_and_deserialization_enforce_the_same_limits() {
        for map in [
            BTreeMap::from([("x".repeat(MAX_IMPORT_ATTRIBUTE_KEY_BYTES + 1), "v".into())]),
            BTreeMap::from([(
                "key".into(),
                "v".repeat(MAX_IMPORT_ATTRIBUTE_VALUE_BYTES + 1),
            )]),
            (0..=MAX_IMPORT_ATTRIBUTES)
                .map(|index| (index.to_string(), String::new()))
                .collect(),
            (0..5)
                .map(|index| (index.to_string(), "v".repeat(1024)))
                .collect(),
        ] {
            assert!(ImportAttributes::new(map.clone()).is_err());
            assert!(
                serde_json::from_str::<ImportAttributes>(&serde_json::to_string(&map).unwrap())
                    .is_err()
            );
        }
        let boundary = BTreeMap::from([(
            "k".repeat(MAX_IMPORT_ATTRIBUTE_KEY_BYTES),
            "v".repeat(MAX_IMPORT_ATTRIBUTE_VALUE_BYTES),
        )]);
        assert!(ImportAttributes::new(boundary).is_ok());
    }

    #[test]
    fn serialized_duplicates_and_non_strings_are_not_normalized_away() {
        for source in [
            r#"{"type":"json","type":"javascript"}"#,
            r#"{"type":null}"#,
            r#"{"type":42}"#,
            r#"{"type":{"name":"json"}}"#,
        ] {
            assert!(
                serde_json::from_str::<ImportAttributes>(source).is_err(),
                "{source}"
            );
        }
    }
}
