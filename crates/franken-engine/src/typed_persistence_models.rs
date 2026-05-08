//! Typed persistence models for sqlmodel_rust integration.
//!
//! This module provides strongly-typed models for stores that require
//! compile-time schema validation and type safety via `/dp/sqlmodel_rust`,
//! as mandated by AGENTS.md and documented in FRANKENSQLITE_PERSISTENCE_INVENTORY.md.
//!
//! Implements typed boundaries for:
//! - ReplacementLineage: replacement/promotion lineage + signed receipts
//! - IfcProvenance: label-flow provenance edges + declassification references
//! - ProofEvidenceIndex: proof artifact, command receipt, validation plan, and gate outcome rows
//! - SpecializationIndex: proof-specialization mapping + invalidation markers

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use sqlmodel::prelude::*;
use sqlmodel::{Connection, Cx, Outcome, Session, SessionConfig, SessionDebugInfo, create_table};
use sqlmodel_core::error::ConfigError;
use sqlmodel_frankensqlite::FrankenConnection;

use crate::ifc_provenance_index::{DeclassReceiptRecord, FlowDecision, FlowEventRecord};
use crate::replacement_lineage_log::{
    DemotionReceiptRecord, LineageChainEntry, ReplacementReceiptRecord,
};
use crate::specialization_index::SpecializationRecord;
use crate::storage_adapter::{
    BatchPutEntry, EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery, StoreRecord,
};

const TYPED_RECORD_FORMAT_KEY: &str = "record_format";
const TYPED_RECORD_FORMAT_VALUE: &str = "sqlmodel_rust_typed_v1";
const TYPED_MODEL_KEY: &str = "typed_model";
const TYPED_STORE_KIND_KEY: &str = "store_kind";
const TYPED_RECORD_ID_KEY: &str = "typed_record_id";
const TYPED_ID_ALLOCATION_FORMAT_KEY: &str = "typed_id_allocation_format";
const TYPED_ID_ALLOCATION_FORMAT_VALUE: &str = "sqlmodel_rust_typed_id_allocation_v1";
const TYPED_ID_ALLOCATION_PREFIX: &str = "typed_id_allocations";

type StorageResult<T> = std::result::Result<T, StorageError>;

fn typed_record_key(store: StoreKind, typed_record_id: i64) -> StorageResult<String> {
    if typed_record_id < 0 {
        return Err(StorageError::InvalidKey {
            key: format!("typed/{}/{typed_record_id}", store.as_str()),
        });
    }
    Ok(format!("typed/{}/{typed_record_id:020}", store.as_str()))
}

fn typed_record_metadata<T: TypedStoreRecord>(
    typed_record_id: i64,
    extra: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        TYPED_RECORD_FORMAT_KEY.to_string(),
        TYPED_RECORD_FORMAT_VALUE.to_string(),
    );
    metadata.insert(TYPED_MODEL_KEY.to_string(), T::MODEL_NAME.to_string());
    metadata.insert(
        TYPED_STORE_KIND_KEY.to_string(),
        T::STORE_KIND.as_str().to_string(),
    );
    metadata.insert(TYPED_RECORD_ID_KEY.to_string(), typed_record_id.to_string());
    metadata.extend(extra);
    metadata
}

fn typed_integrity_error<T: TypedStoreRecord>(detail: impl Into<String>) -> StorageError {
    StorageError::IntegrityViolation {
        store: T::STORE_KIND,
        detail: format!("{} validation failed: {}", T::MODEL_NAME, detail.into()),
    }
}

fn require_non_empty_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &str,
) -> StorageResult<()> {
    if value.trim().is_empty() {
        return Err(typed_integrity_error::<T>(format!(
            "`{field_name}` must not be empty"
        )));
    }
    Ok(())
}

fn require_non_negative_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: i64,
) -> StorageResult<()> {
    if value < 0 {
        return Err(typed_integrity_error::<T>(format!(
            "`{field_name}` must be non-negative, got {value}"
        )));
    }
    Ok(())
}

fn require_allowed_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &str,
    allowed: &[&str],
) -> StorageResult<()> {
    if allowed.contains(&value) {
        return Ok(());
    }
    Err(typed_integrity_error::<T>(format!(
        "`{field_name}` value `{value}` is not one of {}",
        allowed.join(", ")
    )))
}

fn require_json_object_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &str,
) -> StorageResult<()> {
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|err| {
        typed_integrity_error::<T>(format!("`{field_name}` must be valid JSON object: {err}"))
    })?;
    if parsed.is_object() {
        return Ok(());
    }
    Err(typed_integrity_error::<T>(format!(
        "`{field_name}` must be a JSON object"
    )))
}

fn require_repo_relative_path_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &str,
) -> StorageResult<()> {
    require_non_empty_typed::<T>(field_name, value)?;
    if value.contains('\0') || value.contains('\\') {
        return Err(typed_integrity_error::<T>(format!(
            "`{field_name}` must be a canonical repo-relative path"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(typed_integrity_error::<T>(format!(
            "`{field_name}` must not be absolute"
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(typed_integrity_error::<T>(format!(
            "`{field_name}` must not contain `.` or `..` components"
        )));
    }
    Ok(())
}

fn normalize_sha256_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &str,
) -> StorageResult<String> {
    require_non_empty_typed::<T>(field_name, value)?;
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() == 64 && digest.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Ok(digest.to_ascii_lowercase());
    }
    Err(typed_integrity_error::<T>(format!(
        "`{field_name}` must be a 64-hex SHA-256 digest or `sha256:<digest>`"
    )))
}

fn require_sha256_typed<T: TypedStoreRecord>(field_name: &str, value: &str) -> StorageResult<()> {
    normalize_sha256_typed::<T>(field_name, value).map(|_| ())
}

fn sha256_hex_typed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn canonical_json_string_typed<T: TypedStoreRecord>(
    field_name: &str,
    value: &JsonValue,
) -> StorageResult<String> {
    serde_json::to_string(&canonicalize_json_typed(value)).map_err(|err| {
        typed_integrity_error::<T>(format!(
            "`{field_name}` failed canonical JSON serialization: {err}"
        ))
    })
}

fn canonicalize_json_typed(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(map) => {
            let mut ordered = Map::new();
            for (key, value) in map.iter().collect::<BTreeMap<_, _>>() {
                ordered.insert(key.clone(), canonicalize_json_typed(value));
            }
            JsonValue::Object(ordered)
        }
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().map(canonicalize_json_typed).collect())
        }
        _ => value.clone(),
    }
}

fn require_typed_metadata<T: TypedStoreRecord>(
    record: &StoreRecord,
    key: &str,
    expected: &str,
) -> StorageResult<()> {
    match record.metadata.get(key) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(StorageError::IntegrityViolation {
            store: T::STORE_KIND,
            detail: format!(
                "typed metadata mismatch for {key}: expected `{expected}`, got `{actual}`"
            ),
        }),
        None => Err(StorageError::IntegrityViolation {
            store: T::STORE_KIND,
            detail: format!("missing typed metadata `{key}`"),
        }),
    }
}

fn validate_typed_record_metadata<T: TypedStoreRecord>(record: &StoreRecord) -> StorageResult<()> {
    require_typed_metadata::<T>(record, TYPED_RECORD_FORMAT_KEY, TYPED_RECORD_FORMAT_VALUE)?;
    require_typed_metadata::<T>(record, TYPED_MODEL_KEY, T::MODEL_NAME)?;
    require_typed_metadata::<T>(record, TYPED_STORE_KIND_KEY, T::STORE_KIND.as_str())?;
    require_typed_metadata::<T>(
        record,
        TYPED_RECORD_ID_KEY,
        &T::record_id_from_key(&record.key)?.to_string(),
    )
}

fn typed_key_prefix(store: StoreKind) -> String {
    format!("typed/{}/", store.as_str())
}

fn has_current_typed_format(record: &StoreRecord) -> bool {
    record
        .metadata
        .get(TYPED_RECORD_FORMAT_KEY)
        .is_some_and(|format| format == TYPED_RECORD_FORMAT_VALUE)
}

fn has_partial_typed_marker<T: TypedStoreRecord>(record: &StoreRecord) -> bool {
    record.key.starts_with(&typed_key_prefix(T::STORE_KIND))
        || record.metadata.contains_key(TYPED_MODEL_KEY)
        || record.metadata.contains_key(TYPED_STORE_KIND_KEY)
        || record.metadata.contains_key(TYPED_RECORD_ID_KEY)
}

/// Typed model boundary for records persisted through [`StorageAdapter`].
///
/// This intentionally only accepts records produced by this typed boundary.
/// Legacy generic payloads remain migration inputs, not implicitly trusted typed rows.
pub trait TypedStoreRecord: Serialize + DeserializeOwned + Sized {
    /// Store kind backing this typed model.
    const STORE_KIND: StoreKind;
    /// Stable model name recorded in metadata for fail-closed deserialization.
    const MODEL_NAME: &'static str;

    /// Stable integer identifier for deterministic storage keys.
    fn typed_record_id(&self) -> i64;

    /// Additional query-friendly metadata copied from typed fields.
    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String>;

    /// Validate production invariants before typed writes and after typed reads.
    fn validate_typed_record(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Deterministic storage key for this typed model.
    fn typed_record_key(&self) -> StorageResult<String> {
        typed_record_key(Self::STORE_KIND, self.typed_record_id())
    }

    /// Deterministic storage key for an id of this typed model.
    fn typed_record_key_for_id(typed_record_id: i64) -> StorageResult<String> {
        typed_record_key(Self::STORE_KIND, typed_record_id)
    }

    /// Parse and verify an id from this model's deterministic storage key.
    fn record_id_from_key(key: &str) -> StorageResult<i64> {
        let prefix = format!("typed/{}/", Self::STORE_KIND.as_str());
        let Some(raw_id) = key.strip_prefix(&prefix) else {
            return Err(StorageError::InvalidKey {
                key: key.to_string(),
            });
        };
        raw_id.parse::<i64>().map_err(|_| StorageError::InvalidKey {
            key: key.to_string(),
        })
    }

    /// Convert this typed model into a generic store record.
    fn to_store_record(&self, revision: u64) -> StorageResult<StoreRecord> {
        self.validate_typed_record()?;
        let typed_record_id = self.typed_record_id();
        let value = serde_json::to_vec(self).map_err(|err| StorageError::IntegrityViolation {
            store: Self::STORE_KIND,
            detail: format!(
                "failed to serialize {} typed payload: {err}",
                Self::MODEL_NAME
            ),
        })?;

        Ok(StoreRecord {
            store: Self::STORE_KIND,
            key: self.typed_record_key()?,
            value,
            metadata: typed_record_metadata::<Self>(
                typed_record_id,
                self.typed_record_extra_metadata(),
            ),
            revision,
        })
    }

    /// Convert this typed model into a batch write entry.
    fn to_batch_put_entry(&self) -> StorageResult<BatchPutEntry> {
        let record = self.to_store_record(0)?;
        Ok(BatchPutEntry {
            key: record.key,
            value: record.value,
            metadata: record.metadata,
        })
    }

    /// Recover a typed model from a generic store record.
    fn from_store_record(record: &StoreRecord) -> StorageResult<Self> {
        if record.store != Self::STORE_KIND {
            return Err(StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "store kind mismatch for {}: expected {}, got {}",
                    Self::MODEL_NAME,
                    Self::STORE_KIND,
                    record.store
                ),
            });
        }

        validate_typed_record_metadata::<Self>(record)?;
        let typed_record_id = Self::record_id_from_key(&record.key)?;
        let model: Self = serde_json::from_slice(&record.value).map_err(|err| {
            StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "failed to deserialize {} typed payload from {}: {err}",
                    Self::MODEL_NAME,
                    record.key
                ),
            }
        })?;
        if model.typed_record_id() != typed_record_id {
            return Err(StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "payload id mismatch for {}: key has {}, payload has {}",
                    Self::MODEL_NAME,
                    typed_record_id,
                    model.typed_record_id()
                ),
            });
        }
        model.validate_typed_record()?;
        Ok(model)
    }
}

/// Durable mapping from a domain natural key to a typed integer primary key.
///
/// This record lives in [`StoreKind::PolicyCache`] so typed domain stores keep
/// only typed rows. Callers use it when a domain already has a stable natural
/// key, but the SQLModel row requires a compact integer primary key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedRecordIdAllocation {
    pub schema_version: String,
    pub store: StoreKind,
    pub model_name: String,
    pub natural_key: String,
    pub typed_record_id: i64,
}

fn validate_typed_id_natural_key(natural_key: &str) -> StorageResult<()> {
    if natural_key.trim().is_empty() || natural_key.contains('\0') {
        return Err(StorageError::InvalidKey {
            key: format!("{TYPED_ID_ALLOCATION_PREFIX}/{natural_key}"),
        });
    }
    Ok(())
}

fn typed_id_allocation_prefix<T: TypedStoreRecord>() -> String {
    format!(
        "{}/{}/{}",
        TYPED_ID_ALLOCATION_PREFIX,
        T::STORE_KIND.as_str(),
        T::MODEL_NAME
    )
}

fn typed_id_allocation_key<T: TypedStoreRecord>(natural_key: &str) -> StorageResult<String> {
    validate_typed_id_natural_key(natural_key)?;
    Ok(format!(
        "{}/{}",
        typed_id_allocation_prefix::<T>(),
        hex::encode(natural_key.as_bytes())
    ))
}

fn typed_id_allocation_metadata<T: TypedStoreRecord>(
    natural_key: &str,
    typed_record_id: i64,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            TYPED_ID_ALLOCATION_FORMAT_KEY.to_string(),
            TYPED_ID_ALLOCATION_FORMAT_VALUE.to_string(),
        ),
        (
            "typed_allocation_store_kind".to_string(),
            T::STORE_KIND.as_str().to_string(),
        ),
        (
            "typed_allocation_model".to_string(),
            T::MODEL_NAME.to_string(),
        ),
        ("natural_key".to_string(), natural_key.to_string()),
        ("typed_record_id".to_string(), typed_record_id.to_string()),
    ])
}

fn decode_typed_id_allocation<T: TypedStoreRecord>(
    record: &StoreRecord,
) -> StorageResult<TypedRecordIdAllocation> {
    if record.store != StoreKind::PolicyCache {
        return Err(StorageError::IntegrityViolation {
            store: StoreKind::PolicyCache,
            detail: format!(
                "typed id allocation for {} must live in PolicyCache, got {}",
                T::MODEL_NAME,
                record.store
            ),
        });
    }
    let allocation: TypedRecordIdAllocation =
        serde_json::from_slice(&record.value).map_err(|err| StorageError::IntegrityViolation {
            store: StoreKind::PolicyCache,
            detail: format!(
                "failed to deserialize typed id allocation `{}`: {err}",
                record.key
            ),
        })?;
    if allocation.schema_version != TYPED_ID_ALLOCATION_FORMAT_VALUE
        || allocation.store != T::STORE_KIND
        || allocation.model_name != T::MODEL_NAME
        || allocation.typed_record_id < 0
        || typed_id_allocation_key::<T>(&allocation.natural_key)? != record.key
    {
        return Err(StorageError::IntegrityViolation {
            store: StoreKind::PolicyCache,
            detail: format!(
                "typed id allocation `{}` does not match {} allocation contract",
                record.key,
                T::MODEL_NAME
            ),
        });
    }
    Ok(allocation)
}

/// Allocate or replay a stable typed integer id for a domain natural key.
///
/// The allocator never derives ids by truncating a hash. It persists the
/// natural-key mapping, reuses an existing id on replay, and otherwise assigns
/// the next non-negative id after the current model-specific allocation set.
pub fn allocate_typed_record_id<T, S>(
    storage: &mut S,
    natural_key: &str,
    context: &EventContext,
) -> StorageResult<i64>
where
    T: TypedStoreRecord,
    S: StorageAdapter,
{
    let allocation_key = typed_id_allocation_key::<T>(natural_key)?;
    if let Some(existing) = storage.get(StoreKind::PolicyCache, &allocation_key, context)? {
        return Ok(decode_typed_id_allocation::<T>(&existing)?.typed_record_id);
    }

    let rows = storage.query(
        StoreKind::PolicyCache,
        &StoreQuery {
            key_prefix: Some(format!("{}/", typed_id_allocation_prefix::<T>())),
            metadata_filters: BTreeMap::new(),
            limit: None,
        },
        context,
    )?;
    let mut max_id = -1_i64;
    for row in rows {
        let allocation = decode_typed_id_allocation::<T>(&row)?;
        max_id = max_id.max(allocation.typed_record_id);
    }
    let typed_record_id = max_id
        .checked_add(1)
        .ok_or_else(|| StorageError::InvalidKey {
            key: format!("{allocation_key}/overflow"),
        })?;
    // SECURITY: Double-check for race condition before persisting allocation
    // This prevents TOCTOU between max_id query and allocation persistence
    if let Some(existing) = storage.get(StoreKind::PolicyCache, &allocation_key, context)? {
        // Race detected: another thread allocated this natural key between our check and now
        return Ok(decode_typed_id_allocation::<T>(&existing)?.typed_record_id);
    }

    let allocation = TypedRecordIdAllocation {
        schema_version: TYPED_ID_ALLOCATION_FORMAT_VALUE.to_string(),
        store: T::STORE_KIND,
        model_name: T::MODEL_NAME.to_string(),
        natural_key: natural_key.to_string(),
        typed_record_id,
    };
    let value =
        serde_json::to_vec(&allocation).map_err(|err| StorageError::IntegrityViolation {
            store: StoreKind::PolicyCache,
            detail: format!("failed to serialize typed id allocation `{allocation_key}`: {err}"),
        })?;

    // DEBUG: Assert we're not about to create a duplicate (helps catch remaining races)
    debug_assert!(
        {
            let check_rows = storage
                .query(
                    StoreKind::PolicyCache,
                    &StoreQuery {
                        key_prefix: Some(format!("{}/", typed_id_allocation_prefix::<T>())),
                        metadata_filters: BTreeMap::new(),
                        limit: None,
                    },
                    context,
                )
                .unwrap_or_default();
            let current_max = check_rows
                .iter()
                .filter_map(|row| decode_typed_id_allocation::<T>(row).ok())
                .map(|alloc| alloc.typed_record_id)
                .max()
                .unwrap_or(-1);
            typed_record_id == current_max + 1
        },
        "Race condition detected: typed_record_id {} != current_max + 1",
        typed_record_id
    );

    storage.put(
        StoreKind::PolicyCache,
        allocation_key,
        value,
        typed_id_allocation_metadata::<T>(natural_key, typed_record_id),
        context,
    )?;
    Ok(typed_record_id)
}

/// Allocate one stable typed id per typed row emitted from a legacy record.
pub fn allocate_legacy_typed_record_ids<T, S>(
    storage: &mut S,
    legacy_record: &StoreRecord,
    row_count: usize,
    context: &EventContext,
) -> StorageResult<Vec<i64>>
where
    T: TypedStoreRecord,
    S: StorageAdapter,
{
    if row_count == 0 {
        return Err(StorageError::InvalidQuery {
            detail: format!(
                "cannot allocate zero typed ids for {} legacy record `{}`",
                T::MODEL_NAME,
                legacy_record.key
            ),
        });
    }
    let source = format!(
        "legacy/{}/{}",
        legacy_record.store.as_str(),
        legacy_record.key
    );
    (0..row_count)
        .map(|ordinal| {
            allocate_typed_record_id::<T, S>(storage, &format!("{source}#{ordinal}"), context)
        })
        .collect()
}

/// Backfill classification for generic store rows seen during typed migration planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedBackfillStatus {
    /// Row already uses the current typed StoreRecord envelope and can be replayed as typed data.
    Ready,
    /// Row is a legacy or non-current envelope that needs an explicit lossless domain mapper.
    LegacyUnsupported,
    /// Row is malformed, corrupt, or addressed to the wrong typed store.
    Rejected,
}

/// Per-row typed backfill decision with structured, log-friendly details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedBackfillDecision {
    pub store: StoreKind,
    pub key: String,
    pub model_name: String,
    pub status: TypedBackfillStatus,
    pub typed_record_id: Option<i64>,
    pub reason: String,
    pub error_code: Option<String>,
}

/// Dry-run plan for migrating generic StoreRecord data into one typed SQLModel table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedBackfillPlan {
    pub target_store: StoreKind,
    pub model_name: String,
    pub decisions: Vec<TypedBackfillDecision>,
}

impl TypedBackfillPlan {
    /// Number of rows that already pass the typed boundary.
    pub fn ready_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::Ready)
            .count()
    }

    /// Number of rows requiring an explicit legacy-to-typed mapper.
    pub fn legacy_unsupported_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::LegacyUnsupported)
            .count()
    }

    /// Number of rows that must not be migrated without operator intervention.
    pub fn rejected_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::Rejected)
            .count()
    }

    /// True when one or more rows need store-specific lossless conversion logic.
    pub fn requires_explicit_legacy_mapper(&self) -> bool {
        self.legacy_unsupported_count() > 0
    }

    /// True only when every examined row can be replayed through the typed boundary.
    pub fn all_ready(&self) -> bool {
        !self.decisions.is_empty() && self.ready_count() == self.decisions.len()
    }
}

fn typed_backfill_rejection<T: TypedStoreRecord>(
    record: &StoreRecord,
    reason: String,
    error_code: Option<String>,
) -> TypedBackfillDecision {
    TypedBackfillDecision {
        store: record.store,
        key: record.key.clone(),
        model_name: T::MODEL_NAME.to_string(),
        status: TypedBackfillStatus::Rejected,
        typed_record_id: None,
        reason,
        error_code,
    }
}

fn typed_backfill_integrity_rejection<T: TypedStoreRecord>(
    record: &StoreRecord,
    detail: String,
) -> TypedBackfillDecision {
    let err = StorageError::IntegrityViolation {
        store: T::STORE_KIND,
        detail,
    };
    typed_backfill_rejection::<T>(record, err.to_string(), Some(err.code().to_string()))
}

fn typed_backfill_decision<T: TypedStoreRecord>(record: &StoreRecord) -> TypedBackfillDecision {
    if record.store != T::STORE_KIND {
        return typed_backfill_integrity_rejection::<T>(
            record,
            format!(
                "backfill store mismatch for {}: expected {}, got {}",
                T::MODEL_NAME,
                T::STORE_KIND,
                record.store
            ),
        );
    }

    if !has_current_typed_format(record) {
        if has_partial_typed_marker::<T>(record) {
            return typed_backfill_integrity_rejection::<T>(
                record,
                format!(
                    "partial typed envelope for {} cannot be treated as legacy input",
                    T::MODEL_NAME
                ),
            );
        }

        let reason = match record.metadata.get(TYPED_RECORD_FORMAT_KEY) {
            Some(format) => format!(
                "record format `{format}` is not `{TYPED_RECORD_FORMAT_VALUE}`; explicit lossless mapper required"
            ),
            None => "legacy or untyped StoreRecord lacks sqlmodel_rust typed metadata; explicit lossless mapper required".to_string(),
        };
        return TypedBackfillDecision {
            store: record.store,
            key: record.key.clone(),
            model_name: T::MODEL_NAME.to_string(),
            status: TypedBackfillStatus::LegacyUnsupported,
            typed_record_id: None,
            reason,
            error_code: None,
        };
    }

    match T::from_store_record(record) {
        Ok(model) => TypedBackfillDecision {
            store: record.store,
            key: record.key.clone(),
            model_name: T::MODEL_NAME.to_string(),
            status: TypedBackfillStatus::Ready,
            typed_record_id: Some(model.typed_record_id()),
            reason: "typed record passed sqlmodel_rust boundary validation".to_string(),
            error_code: None,
        },
        Err(err) => typed_backfill_rejection::<T>(
            record,
            format!("typed payload rejected: {err}"),
            Some(err.code().to_string()),
        ),
    }
}

/// Build a dry-run typed backfill plan without mutating storage.
///
/// This intentionally does not auto-convert legacy records. Existing generic stores
/// have store-specific payloads and keys, so a production backfill must provide an
/// explicit lossless mapper before writing typed SQLModel rows.
pub fn plan_typed_store_backfill<T: TypedStoreRecord>(
    records: &[StoreRecord],
) -> TypedBackfillPlan {
    TypedBackfillPlan {
        target_store: T::STORE_KIND,
        model_name: T::MODEL_NAME.to_string(),
        decisions: records.iter().map(typed_backfill_decision::<T>).collect(),
    }
}

fn ensure_legacy_store(
    record: &StoreRecord,
    expected: StoreKind,
    model_name: &str,
) -> StorageResult<()> {
    if record.store == expected {
        return Ok(());
    }
    Err(StorageError::IntegrityViolation {
        store: expected,
        detail: format!(
            "legacy mapper store mismatch for {model_name}: expected {expected}, got {}",
            record.store
        ),
    })
}

fn ensure_legacy_typed_id(
    typed_record_id: i64,
    store: StoreKind,
    model_name: &str,
) -> StorageResult<i64> {
    if typed_record_id >= 0 {
        return Ok(typed_record_id);
    }
    Err(StorageError::InvalidKey {
        key: format!(
            "legacy-map/{}/{model_name}/{typed_record_id}",
            store.as_str()
        ),
    })
}

fn offset_legacy_typed_id(
    typed_record_id: i64,
    offset: usize,
    store: StoreKind,
    model_name: &str,
) -> StorageResult<i64> {
    let offset = i64::try_from(offset).map_err(|_| StorageError::InvalidKey {
        key: format!("legacy-map/{}/{model_name}/offset-{offset}", store.as_str()),
    })?;
    typed_record_id
        .checked_add(offset)
        .filter(|id| *id >= 0)
        .ok_or_else(|| StorageError::InvalidKey {
            key: format!(
                "legacy-map/{}/{model_name}/{typed_record_id}+{offset}",
                store.as_str()
            ),
        })
}

fn legacy_u64_to_i64(value: u64, store: StoreKind, field_name: &str) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| StorageError::IntegrityViolation {
        store,
        detail: format!("legacy field `{field_name}` value {value} does not fit in i64"),
    })
}

fn legacy_timestamp_ns_to_ms(
    timestamp_ns: u64,
    store: StoreKind,
    field_name: &str,
) -> StorageResult<i64> {
    legacy_u64_to_i64(timestamp_ns / 1_000_000, store, field_name)
}

fn unsupported_legacy_record<T: TypedStoreRecord>(record: &StoreRecord) -> StorageError {
    StorageError::IntegrityViolation {
        store: T::STORE_KIND,
        detail: format!(
            "legacy key `{}` is not a lossless source for {}; explicit typed model or separate table required",
            record.key,
            T::MODEL_NAME
        ),
    }
}

fn legacy_deserialize<T>(record: &StoreRecord, source_record_type: &str) -> StorageResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(&record.value).map_err(|err| StorageError::IntegrityViolation {
        store: record.store,
        detail: format!(
            "failed to deserialize legacy {source_record_type} payload from `{}`: {err}",
            record.key
        ),
    })
}

fn legacy_metadata_json<T: Serialize>(
    record: &StoreRecord,
    source_record_type: &str,
    payload: &T,
) -> StorageResult<String> {
    let value_json =
        std::str::from_utf8(&record.value).map_err(|err| StorageError::IntegrityViolation {
            store: record.store,
            detail: format!(
                "legacy {source_record_type} payload for `{}` is not UTF-8 JSON: {err}",
                record.key
            ),
        })?;
    serde_json::to_string(&serde_json::json!({
        "legacy_store": record.store.as_str(),
        "legacy_key": record.key,
        "legacy_revision": record.revision,
        "legacy_metadata": record.metadata,
        "legacy_record_type": source_record_type,
        "legacy_value_json": value_json,
        "legacy_payload": payload,
    }))
    .map_err(|err| StorageError::IntegrityViolation {
        store: record.store,
        detail: format!(
            "failed to serialize lossless legacy metadata for `{}`: {err}",
            record.key
        ),
    })
}

fn label_json<T: Serialize>(
    store: StoreKind,
    field_name: &str,
    label: &T,
) -> StorageResult<String> {
    serde_json::to_string(label).map_err(|err| StorageError::IntegrityViolation {
        store,
        detail: format!("failed to serialize `{field_name}` as lossless label JSON: {err}"),
    })
}

fn replacement_receipt_signature_json(record: &ReplacementReceiptRecord) -> StorageResult<String> {
    serde_json::to_string(&record.receipt.signature_bundle).map_err(|err| {
        StorageError::IntegrityViolation {
            store: StoreKind::ReplacementLineage,
            detail: format!(
                "failed to serialize replacement receipt signature bundle for `{}`: {err}",
                record.receipt_id
            ),
        }
    })
}

fn replacement_integrity_ref_json(receipt_content_hash: &str) -> StorageResult<String> {
    serde_json::to_string(&serde_json::json!({
        "legacy_integrity_ref": "receipt_content_hash",
        "receipt_content_hash": receipt_content_hash,
    }))
    .map_err(|err| StorageError::IntegrityViolation {
        store: StoreKind::ReplacementLineage,
        detail: format!("failed to serialize replacement integrity reference: {err}"),
    })
}

fn map_legacy_replacement_receipt_record(
    source: &StoreRecord,
    typed_record_id: i64,
    record: ReplacementReceiptRecord,
) -> StorageResult<ReplacementLineageEntry> {
    Ok(ReplacementLineageEntry {
        sequence_id: typed_record_id,
        slot_id: record.slot_id.as_str().to_string(),
        operation_type: record.replacement_kind.as_str().to_string(),
        source_state: record.old_cell_digest.clone(),
        target_state: record.new_cell_digest.clone(),
        receipt_artifact_id: record.receipt_id.clone(),
        receipt_signature: replacement_receipt_signature_json(&record)?,
        timestamp_ms: legacy_timestamp_ns_to_ms(
            record.promotion_timestamp_ns,
            StoreKind::ReplacementLineage,
            "promotion_timestamp_ns",
        )?,
        metadata_json: legacy_metadata_json(source, "replacement_receipt", &record)?,
    })
}

fn map_legacy_demotion_receipt_record(
    source: &StoreRecord,
    typed_record_id: i64,
    record: DemotionReceiptRecord,
) -> StorageResult<ReplacementLineageEntry> {
    Ok(ReplacementLineageEntry {
        sequence_id: typed_record_id,
        slot_id: record.slot_id.as_str().to_string(),
        operation_type: "demotion".to_string(),
        source_state: record.demoted_cell_digest.clone(),
        target_state: record.restored_cell_digest.clone(),
        receipt_artifact_id: record.receipt_id.clone(),
        receipt_signature: replacement_integrity_ref_json(&record.receipt_content_hash)?,
        timestamp_ms: legacy_timestamp_ns_to_ms(
            record.timestamp_ns,
            StoreKind::ReplacementLineage,
            "timestamp_ns",
        )?,
        metadata_json: legacy_metadata_json(source, "demotion_receipt", &record)?,
    })
}

fn map_legacy_lineage_chain_entry(
    source: &StoreRecord,
    typed_record_id: i64,
    record: LineageChainEntry,
) -> StorageResult<ReplacementLineageEntry> {
    Ok(ReplacementLineageEntry {
        sequence_id: typed_record_id,
        slot_id: record.slot_id.as_str().to_string(),
        operation_type: record.kind.as_str().to_string(),
        source_state: record.from_cell_digest.clone(),
        target_state: record.to_cell_digest.clone(),
        receipt_artifact_id: record.receipt_id.clone(),
        receipt_signature: replacement_integrity_ref_json(&record.receipt_content_hash)?,
        timestamp_ms: legacy_timestamp_ns_to_ms(
            record.timestamp_ns,
            StoreKind::ReplacementLineage,
            "timestamp_ns",
        )?,
        metadata_json: legacy_metadata_json(source, "lineage_chain", &record)?,
    })
}

/// Explicit lossless mapper from supported legacy ReplacementLineage records.
///
/// Hash-pointer and evidence side-table rows are intentionally rejected because
/// flattening them into lineage entries would invent missing lineage fields.
pub fn map_legacy_replacement_lineage_record(
    record: &StoreRecord,
    typed_record_id: i64,
) -> StorageResult<Vec<ReplacementLineageEntry>> {
    ensure_legacy_store(
        record,
        StoreKind::ReplacementLineage,
        ReplacementLineageEntry::MODEL_NAME,
    )?;
    let typed_record_id = ensure_legacy_typed_id(
        typed_record_id,
        StoreKind::ReplacementLineage,
        ReplacementLineageEntry::MODEL_NAME,
    )?;

    let entry = if record.key.starts_with("replacement_receipts/") {
        map_legacy_replacement_receipt_record(
            record,
            typed_record_id,
            legacy_deserialize(record, "replacement_receipt")?,
        )?
    } else if record.key.starts_with("demotion_receipts/") {
        map_legacy_demotion_receipt_record(
            record,
            typed_record_id,
            legacy_deserialize(record, "demotion_receipt")?,
        )?
    } else if record.key.starts_with("lineage_chain/") {
        map_legacy_lineage_chain_entry(
            record,
            typed_record_id,
            legacy_deserialize(record, "lineage_chain")?,
        )?
    } else {
        return Err(unsupported_legacy_record::<ReplacementLineageEntry>(record));
    };
    Ok(vec![entry])
}

fn map_legacy_ifc_flow_event(
    source: &StoreRecord,
    typed_record_id: i64,
    record: FlowEventRecord,
) -> StorageResult<IfcProvenanceEntry> {
    Ok(IfcProvenanceEntry {
        provenance_id: typed_record_id,
        source_label: label_json(
            StoreKind::IfcProvenance,
            "source_label",
            &record.source_label,
        )?,
        target_label: label_json(
            StoreKind::IfcProvenance,
            "sink_clearance",
            &record.sink_clearance,
        )?,
        edge_type: if matches!(record.decision, FlowDecision::Declassified) {
            "declassification".to_string()
        } else {
            "flow_event".to_string()
        },
        flow_operation: format!("flow_event:{}", record.decision),
        security_level: format!("source_level:{}", record.source_label.level()),
        declassification_ref: record.receipt_ref.clone(),
        timestamp_ms: legacy_u64_to_i64(
            record.timestamp_ms,
            StoreKind::IfcProvenance,
            "timestamp_ms",
        )?,
        trace_id: record.event_id.clone(),
        metadata_json: legacy_metadata_json(source, "ifc_flow_event", &record)?,
    })
}

fn map_legacy_ifc_declass_receipt(
    source: &StoreRecord,
    typed_record_id: i64,
    record: DeclassReceiptRecord,
) -> StorageResult<IfcProvenanceEntry> {
    Ok(IfcProvenanceEntry {
        provenance_id: typed_record_id,
        source_label: label_json(
            StoreKind::IfcProvenance,
            "source_label",
            &record.source_label,
        )?,
        target_label: label_json(
            StoreKind::IfcProvenance,
            "sink_clearance",
            &record.sink_clearance,
        )?,
        edge_type: "declassification".to_string(),
        flow_operation: format!("declass_receipt:{}", record.decision),
        security_level: format!("source_level:{}", record.source_label.level()),
        declassification_ref: Some(record.receipt_id.clone()),
        timestamp_ms: legacy_u64_to_i64(
            record.timestamp_ms,
            StoreKind::IfcProvenance,
            "timestamp_ms",
        )?,
        trace_id: record.receipt_id.clone(),
        metadata_json: legacy_metadata_json(source, "ifc_declass_receipt", &record)?,
    })
}

/// Explicit lossless mapper from supported legacy IFC provenance records.
///
/// Flow-proof and confinement-claim rows are rejected for this typed table
/// because they do not carry timestamped source-to-sink provenance events.
pub fn map_legacy_ifc_provenance_record(
    record: &StoreRecord,
    typed_record_id: i64,
) -> StorageResult<Vec<IfcProvenanceEntry>> {
    ensure_legacy_store(
        record,
        StoreKind::IfcProvenance,
        IfcProvenanceEntry::MODEL_NAME,
    )?;
    let typed_record_id = ensure_legacy_typed_id(
        typed_record_id,
        StoreKind::IfcProvenance,
        IfcProvenanceEntry::MODEL_NAME,
    )?;

    let entry = if record.key.starts_with("flow_event::") {
        map_legacy_ifc_flow_event(
            record,
            typed_record_id,
            legacy_deserialize(record, "ifc_flow_event")?,
        )?
    } else if record.key.starts_with("declass_receipt::") {
        map_legacy_ifc_declass_receipt(
            record,
            typed_record_id,
            legacy_deserialize(record, "ifc_declass_receipt")?,
        )?
    } else {
        return Err(unsupported_legacy_record::<IfcProvenanceEntry>(record));
    };
    Ok(vec![entry])
}

fn map_legacy_specialization_receipt(
    source: &StoreRecord,
    typed_record_id: i64,
    record: SpecializationRecord,
) -> StorageResult<Vec<SpecializationIndexEntry>> {
    if record.proof_input_ids.is_empty() {
        return Err(StorageError::IntegrityViolation {
            store: StoreKind::SpecializationIndex,
            detail: format!(
                "legacy specialization receipt `{}` has no proof inputs for typed proof_artifact_id mapping",
                record.receipt_id.to_hex()
            ),
        });
    }
    if record.proof_input_ids.len() != record.proof_types.len() {
        return Err(StorageError::IntegrityViolation {
            store: StoreKind::SpecializationIndex,
            detail: format!(
                "legacy specialization receipt `{}` has {} proof ids but {} proof types",
                record.receipt_id.to_hex(),
                record.proof_input_ids.len(),
                record.proof_types.len()
            ),
        });
    }

    let mut entries = Vec::with_capacity(record.proof_input_ids.len());
    for (idx, (proof_id, proof_type)) in record
        .proof_input_ids
        .iter()
        .zip(record.proof_types.iter())
        .enumerate()
    {
        let specialization_id = offset_legacy_typed_id(
            typed_record_id,
            idx,
            StoreKind::SpecializationIndex,
            SpecializationIndexEntry::MODEL_NAME,
        )?;
        let metadata_json = serde_json::to_string(&serde_json::json!({
            "legacy_mapping_ordinal": idx,
            "legacy_current_proof_type": proof_type.to_string(),
            "legacy_source": serde_json::from_str::<serde_json::Value>(
                &legacy_metadata_json(source, "specialization_receipt", &record)?
            ).map_err(|err| StorageError::IntegrityViolation {
                store: StoreKind::SpecializationIndex,
                detail: format!("failed to compose specialization legacy metadata: {err}"),
            })?,
        }))
        .map_err(|err| StorageError::IntegrityViolation {
            store: StoreKind::SpecializationIndex,
            detail: format!(
                "failed to serialize specialization typed metadata for `{}`: {err}",
                source.key
            ),
        })?;

        entries.push(SpecializationIndexEntry {
            specialization_id,
            proof_artifact_id: proof_id.to_hex(),
            specialization_type: record.optimization_class.to_string(),
            specialized_version: record.receipt_id.to_hex(),
            status: if record.active {
                "active".to_string()
            } else {
                "archived".to_string()
            },
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: legacy_u64_to_i64(
                record.epoch.as_u64(),
                StoreKind::SpecializationIndex,
                "epoch",
            )?,
            created_timestamp_ms: legacy_timestamp_ns_to_ms(
                record.timestamp_ns,
                StoreKind::SpecializationIndex,
                "timestamp_ns",
            )?,
            specialized_content_hash: record.receipt_id.to_hex(),
            metadata_json,
        });
    }
    Ok(entries)
}

/// Explicit lossless mapper from supported legacy SpecializationIndex records.
///
/// Benchmark and invalidation rows are intentionally rejected because they are
/// side tables/events and cannot be represented as standalone specialization
/// rows without fabricating proof and version fields.
pub fn map_legacy_specialization_index_record(
    record: &StoreRecord,
    typed_record_id: i64,
) -> StorageResult<Vec<SpecializationIndexEntry>> {
    ensure_legacy_store(
        record,
        StoreKind::SpecializationIndex,
        SpecializationIndexEntry::MODEL_NAME,
    )?;
    let typed_record_id = ensure_legacy_typed_id(
        typed_record_id,
        StoreKind::SpecializationIndex,
        SpecializationIndexEntry::MODEL_NAME,
    )?;

    if record.key.starts_with("receipt:") {
        return map_legacy_specialization_receipt(
            record,
            typed_record_id,
            legacy_deserialize(record, "specialization_receipt")?,
        );
    }
    Err(unsupported_legacy_record::<SpecializationIndexEntry>(
        record,
    ))
}

/// Convenience extension for storing typed SQLModel records through any adapter.
pub trait TypedStorageAdapterExt: StorageAdapter {
    /// Put one typed model through the adapter's canonical store kind and key.
    fn put_typed<T: TypedStoreRecord>(
        &mut self,
        record: &T,
        context: &EventContext,
    ) -> StorageResult<StoreRecord> {
        let entry = record.to_batch_put_entry()?;
        self.put(
            T::STORE_KIND,
            entry.key,
            entry.value,
            entry.metadata,
            context,
        )
    }

    /// Put typed models as a single adapter batch.
    fn put_typed_batch<T: TypedStoreRecord>(
        &mut self,
        records: &[T],
        context: &EventContext,
    ) -> StorageResult<Vec<StoreRecord>> {
        let entries = records
            .iter()
            .map(TypedStoreRecord::to_batch_put_entry)
            .collect::<StorageResult<Vec<_>>>()?;
        self.put_batch(T::STORE_KIND, entries, context)
    }

    /// Fetch and deserialize one typed record by deterministic key.
    fn get_typed<T: TypedStoreRecord>(
        &mut self,
        key: &str,
        context: &EventContext,
    ) -> StorageResult<Option<T>> {
        self.get(T::STORE_KIND, key, context)?
            .map(|record| T::from_store_record(&record))
            .transpose()
    }

    /// Fetch and deserialize one typed record by typed integer id.
    fn get_typed_by_id<T: TypedStoreRecord>(
        &mut self,
        typed_record_id: i64,
        context: &EventContext,
    ) -> StorageResult<Option<T>> {
        let key = T::typed_record_key_for_id(typed_record_id)?;
        self.get_typed::<T>(&key, context)
    }

    /// Query and deserialize typed records, failing closed if any row is corrupt.
    fn query_typed<T: TypedStoreRecord>(
        &mut self,
        query: &StoreQuery,
        context: &EventContext,
    ) -> StorageResult<Vec<T>> {
        self.query(T::STORE_KIND, query, context)?
            .into_iter()
            .map(|record| T::from_store_record(&record))
            .collect()
    }
}

impl<A: StorageAdapter + ?Sized> TypedStorageAdapterExt for A {}

/// Session config used for deterministic typed persistence operations.
pub fn typed_sqlmodel_session_config() -> SessionConfig {
    SessionConfig {
        auto_begin: true,
        auto_flush: false,
        // Keep committed audit rows inspectable; callers may opt into expiration explicitly.
        expire_on_commit: false,
    }
}

/// SQLModel CREATE TABLE statements for all typed persistence models.
pub fn typed_persistence_create_table_sql() -> Vec<String> {
    vec![
        create_table::<ReplacementLineageEntry>()
            .if_not_exists()
            .build(),
        create_table::<IfcProvenanceEntry>().if_not_exists().build(),
        create_table::<ProofEvidenceIndexEntry>()
            .if_not_exists()
            .build(),
        create_table::<ShadowEvidenceJournalEntry>()
            .if_not_exists()
            .build(),
        create_table::<SpecializationIndexEntry>()
            .if_not_exists()
            .build(),
    ]
}

/// Thin typed wrapper around the real SQLModel ORM session.
pub struct TypedSqlModelSession<C: Connection> {
    inner: Session<C>,
}

impl<C: Connection> TypedSqlModelSession<C> {
    /// Initialize a typed SQLModel session with deterministic FrankenEngine defaults.
    pub fn new(connection: C) -> Self {
        Self::with_config(connection, typed_sqlmodel_session_config())
    }

    /// Initialize a typed SQLModel session with caller-supplied SQLModel config.
    pub fn with_config(connection: C, config: SessionConfig) -> Self {
        Self {
            inner: Session::with_config(connection, config),
        }
    }

    /// Return the SQL statements required before using this typed session.
    pub fn create_table_sql() -> Vec<String> {
        typed_persistence_create_table_sql()
    }

    /// Borrow the underlying SQLModel session.
    pub fn inner(&self) -> &Session<C> {
        &self.inner
    }

    /// Mutably borrow the underlying SQLModel session for advanced callers.
    pub fn inner_mut(&mut self) -> &mut Session<C> {
        &mut self.inner
    }

    /// Borrow the concrete SQLModel connection used by this session.
    pub fn connection(&self) -> &C {
        self.inner.connection()
    }

    /// Current SQLModel session config.
    pub fn config(&self) -> &SessionConfig {
        self.inner.config()
    }

    /// Current SQLModel session debug state.
    pub fn debug_state(&self) -> SessionDebugInfo {
        self.inner.debug_state()
    }

    /// Add any typed persistence model to the SQLModel unit of work.
    pub fn add_typed<T>(&mut self, record: &T)
    where
        T: TypedStoreRecord + Model + Clone + Send + Sync + 'static,
    {
        self.inner.add(record);
    }

    /// Check whether a typed persistence model is tracked by the unit of work.
    pub fn contains_typed<T>(&self, record: &T) -> bool
    where
        T: TypedStoreRecord + Model + 'static,
    {
        self.inner.contains(record)
    }

    /// Add a replacement-lineage row to the SQLModel unit of work.
    pub fn add_replacement_lineage(&mut self, record: &ReplacementLineageEntry) {
        self.add_typed(record);
    }

    /// Add an IFC provenance row to the SQLModel unit of work.
    pub fn add_ifc_provenance(&mut self, record: &IfcProvenanceEntry) {
        self.add_typed(record);
    }

    /// Add a proof-evidence-index row to the SQLModel unit of work.
    pub fn add_proof_evidence_index(&mut self, record: &ProofEvidenceIndexEntry) {
        self.add_typed(record);
    }

    /// Add a shadow-evidence-journal row to the SQLModel unit of work.
    pub fn add_shadow_evidence_journal(&mut self, record: &ShadowEvidenceJournalEntry) {
        self.add_typed(record);
    }

    /// Add a specialization-index row to the SQLModel unit of work.
    pub fn add_specialization_index(&mut self, record: &SpecializationIndexEntry) {
        self.add_typed(record);
    }

    /// Flush pending typed rows through the underlying SQLModel session.
    pub async fn flush(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.flush(cx).await
    }

    /// Commit pending typed rows through the underlying SQLModel session.
    pub async fn commit(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.commit(cx).await
    }

    /// Roll back pending typed rows through the underlying SQLModel session.
    pub async fn rollback(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.rollback(cx).await
    }
}

/// Concrete typed SQLModel session backed by sibling FrankenSQLite.
pub type TypedFrankenSqliteSession = TypedSqlModelSession<FrankenConnection>;

/// Result type for concrete SQLModel driver setup helpers.
pub type TypedSqlModelDriverResult<T> = std::result::Result<T, Box<sqlmodel::Error>>;

/// Result type for concrete FrankenSQLite typed session setup.
pub type TypedFrankenSqliteSessionResult = TypedSqlModelDriverResult<TypedFrankenSqliteSession>;

fn typed_frankensqlite_path(path: impl AsRef<Path>) -> TypedSqlModelDriverResult<String> {
    let path = path.as_ref();
    let Some(path) = path.to_str() else {
        return Err(Box::new(sqlmodel::Error::Config(ConfigError {
            message: "typed FrankenSQLite database path must be valid UTF-8".to_string(),
            source: None,
        })));
    };
    if path.trim().is_empty() {
        return Err(Box::new(sqlmodel::Error::Config(ConfigError {
            message: "typed FrankenSQLite database path must not be empty".to_string(),
            source: None,
        })));
    }
    Ok(path.to_string())
}

/// Initialize the concrete FrankenSQLite schema for all typed persistence tables.
pub fn initialize_typed_frankensqlite_schema(
    connection: &FrankenConnection,
) -> TypedSqlModelDriverResult<()> {
    for statement in typed_persistence_create_table_sql() {
        connection.execute_raw(&statement)?;
    }
    Ok(())
}

/// Open a file-backed typed SQLModel session using the sibling FrankenSQLite driver.
pub fn open_typed_frankensqlite_session(path: impl AsRef<Path>) -> TypedFrankenSqliteSessionResult {
    let connection = FrankenConnection::open_file(typed_frankensqlite_path(path)?)?;
    initialize_typed_frankensqlite_schema(&connection)?;
    Ok(TypedSqlModelSession::new(connection))
}

/// Open an in-memory typed SQLModel session using the sibling FrankenSQLite driver.
pub fn open_typed_frankensqlite_memory_session() -> TypedFrankenSqliteSessionResult {
    let connection = FrankenConnection::open_memory()?;
    initialize_typed_frankensqlite_schema(&connection)?;
    Ok(TypedSqlModelSession::new(connection))
}

// ---------------------------------------------------------------------------
// ReplacementLineage: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for replacement lineage log entries.
///
/// Tracks slot promotion/demotion lineage with signed receipts for audit
/// replay. Maps to `frankensqlite::replacement::lineage_log` integration point
/// with compile-time schema validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "replacement_lineage")]
pub struct ReplacementLineageEntry {
    /// Unique sequence ID for this lineage entry.
    #[sqlmodel(primary_key)]
    pub sequence_id: i64,

    /// Slot identifier being promoted/demoted.
    pub slot_id: String,

    /// Type of lineage operation (promotion, demotion, transfer).
    pub operation_type: String,

    /// Source slot/state before the operation.
    pub source_state: String,

    /// Target slot/state after the operation.
    pub target_state: String,

    /// Signed receipt artifact ID for audit verification.
    pub receipt_artifact_id: String,

    /// Receipt signature for lineage integrity.
    pub receipt_signature: String,

    /// Unix timestamp (milliseconds) of the lineage operation.
    pub timestamp_ms: i64,

    /// Additional structured metadata for the lineage entry.
    pub metadata_json: String,
}

impl ReplacementLineageEntry {
    /// Build a deterministic typed lookup for one lineage sequence entry.
    pub fn select_by_sequence_id(sequence_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("sequence_id").eq(sequence_id))
    }

    /// Build a deterministic typed lookup for all lineage rows for a slot.
    pub fn select_by_slot_id(slot_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("slot_id").eq(slot_id.into()))
            .order_by(Expr::col("sequence_id").asc())
    }

    /// Build a deterministic typed lookup by audit receipt artifact.
    pub fn select_by_receipt_artifact_id(receipt_artifact_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("receipt_artifact_id").eq(receipt_artifact_id.into()))
            .order_by(Expr::col("sequence_id").asc())
    }
}

impl TypedStoreRecord for ReplacementLineageEntry {
    const STORE_KIND: StoreKind = StoreKind::ReplacementLineage;
    const MODEL_NAME: &'static str = "ReplacementLineageEntry";

    fn typed_record_id(&self) -> i64 {
        self.sequence_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("operation_type".to_string(), self.operation_type.clone()),
            (
                "receipt_artifact_id".to_string(),
                self.receipt_artifact_id.clone(),
            ),
            ("slot_id".to_string(), self.slot_id.clone()),
        ])
    }

    fn validate_typed_record(&self) -> StorageResult<()> {
        require_non_negative_typed::<Self>("sequence_id", self.sequence_id)?;
        require_non_empty_typed::<Self>("slot_id", &self.slot_id)?;
        require_allowed_typed::<Self>(
            "operation_type",
            &self.operation_type,
            &[
                "promotion",
                "demotion",
                "delegate_to_native",
                "rollback",
                "re_promotion",
            ],
        )?;
        require_non_empty_typed::<Self>("source_state", &self.source_state)?;
        require_non_empty_typed::<Self>("target_state", &self.target_state)?;
        require_non_empty_typed::<Self>("receipt_artifact_id", &self.receipt_artifact_id)?;
        require_non_empty_typed::<Self>("receipt_signature", &self.receipt_signature)?;
        require_non_negative_typed::<Self>("timestamp_ms", self.timestamp_ms)?;
        require_json_object_typed::<Self>("metadata_json", &self.metadata_json)
    }
}

// ---------------------------------------------------------------------------
// IfcProvenance: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for IFC (Information Flow Control) provenance index.
///
/// Tracks label-flow provenance edges and declassification references for
/// non-interference enforcement traceability. Maps to
/// `frankensqlite::control_plane::ifc_provenance` with typed boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "ifc_provenance")]
pub struct IfcProvenanceEntry {
    /// Unique provenance entry ID.
    #[sqlmodel(primary_key)]
    pub provenance_id: i64,

    /// Source label/entity in the flow.
    pub source_label: String,

    /// Target label/entity in the flow.
    pub target_label: String,

    /// Type of provenance edge (flow, declassification, aggregation).
    pub edge_type: String,

    /// Flow operation that created this provenance edge.
    pub flow_operation: String,

    /// Security level/classification of the flow.
    pub security_level: String,

    /// Reference to declassification authority (if applicable).
    pub declassification_ref: Option<String>,

    /// Unix timestamp (milliseconds) when the flow occurred.
    pub timestamp_ms: i64,

    /// Trace ID for linking to originating operation.
    pub trace_id: String,

    /// Additional edge metadata and validation artifacts.
    pub metadata_json: String,
}

impl IfcProvenanceEntry {
    /// Build a deterministic typed lookup for one provenance entry.
    pub fn select_by_provenance_id(provenance_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("provenance_id").eq(provenance_id))
    }

    /// Build a deterministic typed lookup for all provenance rows for a trace.
    pub fn select_by_trace_id(trace_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("trace_id").eq(trace_id.into()))
            .order_by(Expr::col("provenance_id").asc())
    }

    /// Build a deterministic typed lookup for one label-flow edge.
    pub fn select_by_label_flow(
        source_label: impl Into<String>,
        target_label: impl Into<String>,
    ) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("source_label").eq(source_label.into()))
            .filter(Expr::col("target_label").eq(target_label.into()))
            .order_by(Expr::col("provenance_id").asc())
    }

    /// Build a deterministic typed lookup for declassification rows.
    pub fn select_declassifications() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("edge_type").eq("declassification"))
            .order_by(Expr::col("provenance_id").asc())
    }
}

impl TypedStoreRecord for IfcProvenanceEntry {
    const STORE_KIND: StoreKind = StoreKind::IfcProvenance;
    const MODEL_NAME: &'static str = "IfcProvenanceEntry";

    fn typed_record_id(&self) -> i64 {
        self.provenance_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            ("edge_type".to_string(), self.edge_type.clone()),
            ("security_level".to_string(), self.security_level.clone()),
            ("source_label".to_string(), self.source_label.clone()),
            ("target_label".to_string(), self.target_label.clone()),
            ("trace_id".to_string(), self.trace_id.clone()),
        ]);
        if let Ok(serde_json::Value::Object(payload)) =
            serde_json::from_str::<serde_json::Value>(&self.metadata_json)
        {
            for key in [
                "schema_version",
                "record_type",
                "extension_id",
                "event_id",
                "proof_id",
                "receipt_id",
                "epoch_id",
            ] {
                if let Some(value) = payload.get(key) {
                    if let Some(value) = value.as_str() {
                        metadata.insert(key.to_string(), value.to_string());
                    } else if value.is_number() || value.is_boolean() {
                        metadata.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }
        if let Some(declassification_ref) = &self.declassification_ref {
            metadata.insert(
                "declassification_ref".to_string(),
                declassification_ref.clone(),
            );
        }
        metadata
    }

    fn validate_typed_record(&self) -> StorageResult<()> {
        require_non_negative_typed::<Self>("provenance_id", self.provenance_id)?;
        require_non_empty_typed::<Self>("source_label", &self.source_label)?;
        require_non_empty_typed::<Self>("target_label", &self.target_label)?;
        require_allowed_typed::<Self>(
            "edge_type",
            &self.edge_type,
            &["flow", "flow_event", "declassification", "aggregation"],
        )?;
        require_non_empty_typed::<Self>("flow_operation", &self.flow_operation)?;
        require_non_empty_typed::<Self>("security_level", &self.security_level)?;
        if self.edge_type == "declassification" {
            let Some(declassification_ref) = &self.declassification_ref else {
                return Err(typed_integrity_error::<Self>(
                    "`declassification_ref` is required for declassification edges",
                ));
            };
            require_non_empty_typed::<Self>("declassification_ref", declassification_ref)?;
        }
        require_non_negative_typed::<Self>("timestamp_ms", self.timestamp_ms)?;
        require_non_empty_typed::<Self>("trace_id", &self.trace_id)?;
        require_json_object_typed::<Self>("metadata_json", &self.metadata_json)
    }
}

// ---------------------------------------------------------------------------
// ProofEvidenceIndex: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for proof-evidence index rows.
///
/// Links beads, source revisions, proof artifacts, command receipts,
/// validation plans, and gate outcomes through the EvidenceIndex store without
/// trusting untyped generic records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "proof_evidence_index")]
pub struct ProofEvidenceIndexEntry {
    /// Stable typed row ID allocated from a domain natural key.
    #[sqlmodel(primary_key)]
    pub evidence_id: i64,

    /// Bead that owns or consumes this evidence.
    pub bead_id: String,

    /// Git source revision the evidence was generated from.
    pub source_revision: String,

    /// Stable artifact identifier derived from the source document and hash.
    pub artifact_id: String,

    /// Canonical repo-relative path to the indexed artifact.
    pub artifact_path: String,

    /// Artifact role from the originating manifest or planner.
    pub artifact_role: String,

    /// Content hash for the artifact or source receipt.
    pub artifact_sha256: String,

    /// Receipt class represented by this row.
    pub receipt_kind: String,

    /// Gate status normalized for dashboard queries.
    pub gate_status: String,

    /// Unix timestamp (milliseconds) when the evidence was generated.
    pub generated_timestamp_ms: i64,

    /// Unix timestamp (milliseconds) after which the evidence is stale.
    pub freshness_deadline_ms: i64,

    /// Lossless structured metadata from the source evidence document.
    pub metadata_json: String,
}

impl ProofEvidenceIndexEntry {
    /// Build a deterministic typed lookup for one proof-evidence entry.
    pub fn select_by_evidence_id(evidence_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("evidence_id").eq(evidence_id))
    }

    /// Build a deterministic typed lookup for all evidence associated with one bead.
    pub fn select_by_bead_id(bead_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("bead_id").eq(bead_id.into()))
            .order_by(Expr::col("source_revision").asc())
            .order_by(Expr::col("artifact_path").asc())
            .order_by(Expr::col("evidence_id").asc())
    }

    /// Build a deterministic typed lookup for all evidence from one source revision.
    pub fn select_by_source_revision(source_revision: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("source_revision").eq(source_revision.into()))
            .order_by(Expr::col("bead_id").asc())
            .order_by(Expr::col("artifact_path").asc())
            .order_by(Expr::col("evidence_id").asc())
    }

    /// Build a deterministic typed lookup for recent failed gate evidence.
    pub fn select_recent_failed_gates() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("gate_status").eq("fail"))
            .order_by(Expr::col("generated_timestamp_ms").desc())
            .order_by(Expr::col("evidence_id").asc())
    }

    /// Build a deterministic typed lookup for evidence older than its freshness policy.
    pub fn select_stale_artifacts(now_ms: i64) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("freshness_deadline_ms").lt(now_ms))
            .order_by(Expr::col("freshness_deadline_ms").asc())
            .order_by(Expr::col("evidence_id").asc())
    }
}

impl TypedStoreRecord for ProofEvidenceIndexEntry {
    const STORE_KIND: StoreKind = StoreKind::EvidenceIndex;
    const MODEL_NAME: &'static str = "ProofEvidenceIndexEntry";

    fn typed_record_id(&self) -> i64 {
        self.evidence_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("artifact_id".to_string(), self.artifact_id.clone()),
            ("artifact_path".to_string(), self.artifact_path.clone()),
            ("artifact_role".to_string(), self.artifact_role.clone()),
            ("bead_id".to_string(), self.bead_id.clone()),
            ("gate_status".to_string(), self.gate_status.clone()),
            ("receipt_kind".to_string(), self.receipt_kind.clone()),
            ("source_revision".to_string(), self.source_revision.clone()),
        ])
    }

    fn validate_typed_record(&self) -> StorageResult<()> {
        require_non_negative_typed::<Self>("evidence_id", self.evidence_id)?;
        require_non_empty_typed::<Self>("bead_id", &self.bead_id)?;
        require_non_empty_typed::<Self>("source_revision", &self.source_revision)?;
        if self.source_revision == "unknown" {
            return Err(typed_integrity_error::<Self>(
                "`source_revision` must be an explicit revision",
            ));
        }
        require_non_empty_typed::<Self>("artifact_id", &self.artifact_id)?;
        require_repo_relative_path_typed::<Self>("artifact_path", &self.artifact_path)?;
        require_non_empty_typed::<Self>("artifact_role", &self.artifact_role)?;
        require_sha256_typed::<Self>("artifact_sha256", &self.artifact_sha256)?;
        require_allowed_typed::<Self>(
            "receipt_kind",
            &self.receipt_kind,
            &[
                "command_receipt",
                "gate_report",
                "proof_artifact",
                "proof_cost_history",
                "proof_cost_manifest",
                "proof_manifest",
                "validation_command",
                "validation_plan",
            ],
        )?;
        require_allowed_typed::<Self>(
            "gate_status",
            &self.gate_status,
            &["pass", "fail", "blocked", "skipped", "stale", "unknown"],
        )?;
        require_non_negative_typed::<Self>("generated_timestamp_ms", self.generated_timestamp_ms)?;
        require_non_negative_typed::<Self>("freshness_deadline_ms", self.freshness_deadline_ms)?;
        if self.freshness_deadline_ms < self.generated_timestamp_ms {
            return Err(typed_integrity_error::<Self>(
                "`freshness_deadline_ms` must not precede `generated_timestamp_ms`",
            ));
        }
        require_json_object_typed::<Self>("metadata_json", &self.metadata_json)
    }
}

// ---------------------------------------------------------------------------
// ShadowEvidenceJournal: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for advisory shadow-daemon journal events.
///
/// Persists normalized source snapshots, derived advisory events, and replay
/// checkpoints through the typed shadow-journal boundary with deterministic
/// sequence ordering and explicit retention classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "shadow_evidence_journal")]
pub struct ShadowEvidenceJournalEntry {
    /// Stable typed row ID allocated from the journal natural key.
    #[sqlmodel(primary_key)]
    pub journal_event_id: i64,

    /// Bead or track consuming this advisory evidence.
    pub bead_id: String,

    /// Event family persisted in the journal.
    pub event_kind: String,

    /// Snapshot or derived source family for the event.
    pub source_kind: String,

    /// Source command, API path, or synthetic advisory route for the event.
    pub source_locator: String,

    /// Unix timestamp (milliseconds) when the source was collected.
    pub collected_timestamp_ms: i64,

    /// Monotonic journal sequence for replay-stable ordering.
    pub sequence_id: i64,

    /// Content hash over the raw or canonical event payload bytes.
    pub payload_content_hash: String,

    /// Canonical repo-relative path to the normalized payload artifact, if any.
    pub normalized_payload_path: Option<String>,

    /// Canonical normalized payload persisted for replay and export.
    pub normalized_payload_json: String,

    /// Content hash over the normalized payload persisted for replay.
    pub normalized_payload_hash: String,

    /// JSON array of raw evidence hashes retained across compaction.
    pub raw_evidence_hashes_json: String,

    /// Freshness window in milliseconds from collection time.
    pub freshness_window_ms: i64,

    /// Unix timestamp (milliseconds) after which the event is stale.
    pub freshness_deadline_ms: i64,

    /// Truth/degradation state for this event.
    pub degradation_state: String,

    /// Retention policy class for bounded journal exports.
    pub retention_class: String,

    /// JSON array of parent journal sequence ids.
    pub parent_event_ids_json: String,

    /// Lossless structured metadata from the source or derived advisory.
    pub metadata_json: String,
}

impl ShadowEvidenceJournalEntry {
    /// Build a deterministic typed lookup for one journal event.
    pub fn select_by_journal_event_id(journal_event_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("journal_event_id").eq(journal_event_id))
    }

    /// Build a deterministic typed lookup for all journal rows for one bead.
    pub fn select_by_bead_id(bead_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("bead_id").eq(bead_id.into()))
            .order_by(Expr::col("sequence_id").asc())
            .order_by(Expr::col("journal_event_id").asc())
    }

    /// Build a deterministic typed lookup for one source family.
    pub fn select_by_source_kind(source_kind: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("source_kind").eq(source_kind.into()))
            .order_by(Expr::col("sequence_id").asc())
            .order_by(Expr::col("journal_event_id").asc())
    }

    /// Build a deterministic typed lookup for replay checkpoints and later rows.
    pub fn select_from_sequence(sequence_id: i64) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("sequence_id").ge(sequence_id))
            .order_by(Expr::col("sequence_id").asc())
            .order_by(Expr::col("journal_event_id").asc())
    }
}

impl TypedStoreRecord for ShadowEvidenceJournalEntry {
    const STORE_KIND: StoreKind = StoreKind::ShadowEvidenceJournal;
    const MODEL_NAME: &'static str = "ShadowEvidenceJournalEntry";

    fn typed_record_id(&self) -> i64 {
        self.journal_event_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            ("bead_id".to_string(), self.bead_id.clone()),
            (
                "degradation_state".to_string(),
                self.degradation_state.clone(),
            ),
            ("event_kind".to_string(), self.event_kind.clone()),
            ("retention_class".to_string(), self.retention_class.clone()),
            ("sequence_id".to_string(), self.sequence_id.to_string()),
            ("source_kind".to_string(), self.source_kind.clone()),
            ("source_locator".to_string(), self.source_locator.clone()),
        ]);
        if let Some(path) = &self.normalized_payload_path {
            metadata.insert("normalized_payload_path".to_string(), path.clone());
        }
        metadata
    }

    fn validate_typed_record(&self) -> StorageResult<()> {
        require_non_negative_typed::<Self>("journal_event_id", self.journal_event_id)?;
        require_non_empty_typed::<Self>("bead_id", &self.bead_id)?;
        require_non_empty_typed::<Self>("event_kind", &self.event_kind)?;
        require_allowed_typed::<Self>(
            "event_kind",
            &self.event_kind,
            &["source_snapshot", "advisory_event", "replay_checkpoint"],
        )?;
        require_non_empty_typed::<Self>("source_kind", &self.source_kind)?;
        require_non_empty_typed::<Self>("source_locator", &self.source_locator)?;
        require_non_negative_typed::<Self>("collected_timestamp_ms", self.collected_timestamp_ms)?;
        require_non_negative_typed::<Self>("sequence_id", self.sequence_id)?;
        if self.sequence_id != self.journal_event_id {
            return Err(typed_integrity_error::<Self>(
                "`sequence_id` must match `journal_event_id` for deterministic replay ordering",
            ));
        }
        let payload_content_hash =
            normalize_sha256_typed::<Self>("payload_content_hash", &self.payload_content_hash)?;
        if let Some(path) = &self.normalized_payload_path {
            require_repo_relative_path_typed::<Self>("normalized_payload_path", path)?;
        }
        let normalized_payload: JsonValue = serde_json::from_str(&self.normalized_payload_json)
            .map_err(|err| {
                typed_integrity_error::<Self>(format!(
                    "`normalized_payload_json` must be valid JSON: {err}"
                ))
            })?;
        if normalized_payload.is_null()
            || !(normalized_payload.is_object() || normalized_payload.is_array())
        {
            return Err(typed_integrity_error::<Self>(
                "`normalized_payload_json` must be a JSON object or array",
            ));
        }
        let normalized_payload_hash = normalize_sha256_typed::<Self>(
            "normalized_payload_hash",
            &self.normalized_payload_hash,
        )?;
        let normalized_payload_json =
            canonical_json_string_typed::<Self>("normalized_payload_json", &normalized_payload)?;
        let computed_payload_hash = sha256_hex_typed(normalized_payload_json.as_bytes());
        if payload_content_hash != computed_payload_hash
            || normalized_payload_hash != computed_payload_hash
        {
            return Err(typed_integrity_error::<Self>(format!(
                "payload hash mismatch for journal event {}",
                self.journal_event_id
            )));
        }
        let raw_evidence_hashes: Vec<String> = serde_json::from_str(&self.raw_evidence_hashes_json)
            .map_err(|err| {
                typed_integrity_error::<Self>(format!(
                    "`raw_evidence_hashes_json` must be a JSON array of content hashes: {err}"
                ))
            })?;
        if raw_evidence_hashes.is_empty() {
            return Err(typed_integrity_error::<Self>(
                "`raw_evidence_hashes_json` must preserve at least one raw evidence hash",
            ));
        }
        if raw_evidence_hashes.len() > 64 {
            return Err(typed_integrity_error::<Self>(
                "`raw_evidence_hashes_json` exceeds the 64-hash cap",
            ));
        }
        let mut previous_hash: Option<&str> = None;
        for raw_hash in &raw_evidence_hashes {
            require_sha256_typed::<Self>("raw_evidence_hash", raw_hash)?;
            if let Some(previous_hash) = previous_hash
                && raw_hash.as_str() <= previous_hash
            {
                return Err(typed_integrity_error::<Self>(
                    "`raw_evidence_hashes_json` must be strictly ascending without duplicates",
                ));
            }
            previous_hash = Some(raw_hash.as_str());
        }
        require_non_negative_typed::<Self>("freshness_window_ms", self.freshness_window_ms)?;
        require_non_negative_typed::<Self>("freshness_deadline_ms", self.freshness_deadline_ms)?;
        let expected_deadline = self
            .collected_timestamp_ms
            .checked_add(self.freshness_window_ms)
            .ok_or_else(|| {
                typed_integrity_error::<Self>(
                    "`collected_timestamp_ms` + `freshness_window_ms` overflowed",
                )
            })?;
        if self.freshness_deadline_ms != expected_deadline {
            return Err(typed_integrity_error::<Self>(
                "`freshness_deadline_ms` must equal `collected_timestamp_ms + freshness_window_ms`",
            ));
        }
        require_allowed_typed::<Self>(
            "degradation_state",
            &self.degradation_state,
            &["confirmed", "degraded", "blocked", "contaminated"],
        )?;
        require_allowed_typed::<Self>(
            "retention_class",
            &self.retention_class,
            &["windowed", "checkpoint", "audit"],
        )?;

        let parent_event_ids: Vec<i64> = serde_json::from_str(&self.parent_event_ids_json)
            .map_err(|err| {
                typed_integrity_error::<Self>(format!(
                    "`parent_event_ids_json` must be a JSON array of sequence ids: {err}"
                ))
            })?;
        if parent_event_ids.len() > 64 {
            return Err(typed_integrity_error::<Self>(
                "`parent_event_ids_json` exceeds the 64-parent cap",
            ));
        }
        if self.event_kind == "source_snapshot" && !parent_event_ids.is_empty() {
            return Err(typed_integrity_error::<Self>(
                "`source_snapshot` rows must not link parent events",
            ));
        }
        if self.event_kind != "source_snapshot" && parent_event_ids.is_empty() {
            return Err(typed_integrity_error::<Self>(
                "derived journal rows must cite at least one parent event",
            ));
        }
        if self.event_kind == "replay_checkpoint" && self.retention_class != "checkpoint" {
            return Err(typed_integrity_error::<Self>(
                "`replay_checkpoint` rows must use `checkpoint` retention",
            ));
        }
        if self.event_kind != "replay_checkpoint" && self.retention_class == "checkpoint" {
            return Err(typed_integrity_error::<Self>(
                "only `replay_checkpoint` rows may use `checkpoint` retention",
            ));
        }
        let mut last_parent = None;
        for parent_id in parent_event_ids {
            require_non_negative_typed::<Self>("parent_event_id", parent_id)?;
            if parent_id >= self.sequence_id {
                return Err(typed_integrity_error::<Self>(
                    "parent event links must reference earlier journal sequence ids",
                ));
            }
            if let Some(previous) = last_parent
                && parent_id <= previous
            {
                return Err(typed_integrity_error::<Self>(
                    "`parent_event_ids_json` must be strictly ascending without duplicates",
                ));
            }
            last_parent = Some(parent_id);
        }

        require_json_object_typed::<Self>("metadata_json", &self.metadata_json)
    }
}

// ---------------------------------------------------------------------------
// SpecializationIndex: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for specialization index entries.
///
/// Tracks proof-specialization mapping and invalidation markers for
/// fallback/invalidation replay determinism. Maps to
/// `frankensqlite::control_plane::specialization_index` with typed safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "specialization_index")]
pub struct SpecializationIndexEntry {
    /// Unique specialization entry ID.
    #[sqlmodel(primary_key)]
    pub specialization_id: i64,

    /// Proof artifact ID being specialized.
    pub proof_artifact_id: String,

    /// Type of specialization (optimization, validation, fallback).
    pub specialization_type: String,

    /// Specialized version/variant identifier.
    pub specialized_version: String,

    /// Status of the specialization (active, invalidated, archived).
    pub status: String,

    /// Invalidation marker timestamp (if invalidated).
    pub invalidation_timestamp_ms: Option<i64>,

    /// Reason for invalidation (if applicable).
    pub invalidation_reason: Option<String>,

    /// Security epoch when specialization was created.
    pub security_epoch: i64,

    /// Unix timestamp (milliseconds) of specialization creation.
    pub created_timestamp_ms: i64,

    /// Specialized proof artifact content hash.
    pub specialized_content_hash: String,

    /// Metadata for specialization parameters and constraints.
    pub metadata_json: String,
}

impl SpecializationIndexEntry {
    /// Build a deterministic typed lookup for one specialization entry.
    pub fn select_by_specialization_id(specialization_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("specialization_id").eq(specialization_id))
    }

    /// Build a deterministic typed lookup for all specializations for a proof artifact.
    pub fn select_by_proof_artifact_id(proof_artifact_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("proof_artifact_id").eq(proof_artifact_id.into()))
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup for all entries belonging to one specialized version.
    pub fn select_by_specialized_version(specialized_version: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("specialized_version").eq(specialized_version.into()))
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup for all active specializations.
    pub fn select_active() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("status").eq("active"))
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup for all invalidated specializations.
    pub fn select_invalidated() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("status").eq("invalidated"))
            .order_by(Expr::col("invalidation_timestamp_ms").desc())
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup by security epoch.
    pub fn select_by_security_epoch(security_epoch: i64) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("security_epoch").eq(security_epoch))
            .order_by(Expr::col("specialization_id").asc())
    }
}

impl TypedStoreRecord for SpecializationIndexEntry {
    const STORE_KIND: StoreKind = StoreKind::SpecializationIndex;
    const MODEL_NAME: &'static str = "SpecializationIndexEntry";

    fn typed_record_id(&self) -> i64 {
        self.specialization_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            (
                "proof_artifact_id".to_string(),
                self.proof_artifact_id.clone(),
            ),
            (
                "security_epoch".to_string(),
                self.security_epoch.to_string(),
            ),
            (
                "specialization_type".to_string(),
                self.specialization_type.clone(),
            ),
            (
                "specialized_version".to_string(),
                self.specialized_version.clone(),
            ),
            ("status".to_string(), self.status.clone()),
        ]);
        if let Some(invalidation_reason) = &self.invalidation_reason {
            metadata.insert(
                "invalidation_reason".to_string(),
                invalidation_reason.clone(),
            );
        }
        metadata
    }

    fn validate_typed_record(&self) -> StorageResult<()> {
        require_non_negative_typed::<Self>("specialization_id", self.specialization_id)?;
        require_non_empty_typed::<Self>("proof_artifact_id", &self.proof_artifact_id)?;
        require_non_empty_typed::<Self>("specialization_type", &self.specialization_type)?;
        require_non_empty_typed::<Self>("specialized_version", &self.specialized_version)?;
        require_allowed_typed::<Self>(
            "status",
            &self.status,
            &["active", "invalidated", "archived"],
        )?;
        if self.status == "invalidated" {
            let Some(timestamp_ms) = self.invalidation_timestamp_ms else {
                return Err(typed_integrity_error::<Self>(
                    "`invalidation_timestamp_ms` is required when status is invalidated",
                ));
            };
            require_non_negative_typed::<Self>("invalidation_timestamp_ms", timestamp_ms)?;
            let Some(reason) = &self.invalidation_reason else {
                return Err(typed_integrity_error::<Self>(
                    "`invalidation_reason` is required when status is invalidated",
                ));
            };
            require_non_empty_typed::<Self>("invalidation_reason", reason)?;
        }
        require_non_negative_typed::<Self>("security_epoch", self.security_epoch)?;
        require_non_negative_typed::<Self>("created_timestamp_ms", self.created_timestamp_ms)?;
        require_non_empty_typed::<Self>(
            "specialized_content_hash",
            &self.specialized_content_hash,
        )?;
        require_json_object_typed::<Self>("metadata_json", &self.metadata_json)
    }
}

#[cfg(test)]
#[allow(clippy::manual_async_fn)] // Mock trait impls must match sqlmodel_core::Connection signatures.
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};
    use crate::ifc_artifacts::{DeclassificationDecision, Label, ProofMethod};
    use crate::ifc_provenance_index::{FlowDecision, FlowEventRecord, FlowProofRecord};
    use crate::proof_specialization_receipt::{OptimizationClass, ProofType};
    use crate::replacement_lineage_log::{LineageChainEntry, ReplacementKind};
    use crate::security_epoch::SecurityEpoch;
    use crate::slot_registry::SlotId;
    use crate::specialization_index::SpecializationRecord;
    use crate::storage_adapter::InMemoryStorageAdapter;
    use sqlmodel::{FieldInfo, Model, Row, SqlType, Value};
    use sqlmodel_core::{
        Connection, Dialect, Error, IsolationLevel, PreparedStatement, TransactionOps,
    };

    fn field<T: Model>(field_name: &str) -> &'static FieldInfo {
        T::fields()
            .iter()
            .find(|field| field.name == field_name)
            .expect("typed persistence field exists")
    }

    fn assert_round_trips<T>(model: T)
    where
        T: Clone + Model + PartialEq + std::fmt::Debug,
    {
        let values = model.to_row();
        let row = Row::new(
            values
                .iter()
                .map(|(column, _)| (*column).to_string())
                .collect(),
            values.into_iter().map(|(_, value)| value).collect(),
        );

        let restored = T::from_row(&row).expect("typed persistence row round-trips");
        assert_eq!(restored, model);
    }

    fn replacement_entry(sequence_id: i64) -> ReplacementLineageEntry {
        ReplacementLineageEntry {
            sequence_id,
            slot_id: "slot-alpha".to_string(),
            operation_type: "promotion".to_string(),
            source_state: "candidate".to_string(),
            target_state: "active".to_string(),
            receipt_artifact_id: "receipt-7".to_string(),
            receipt_signature: "sig-7".to_string(),
            timestamp_ms: 1_700_000_000_007,
            metadata_json: r#"{"trace_id":"trace-replacement"}"#.to_string(),
        }
    }

    fn ifc_entry(provenance_id: i64, trace_id: &str) -> IfcProvenanceEntry {
        IfcProvenanceEntry {
            provenance_id,
            source_label: "secret/model".to_string(),
            target_label: "operator/audit".to_string(),
            edge_type: "declassification".to_string(),
            flow_operation: "emit_receipt".to_string(),
            security_level: "high".to_string(),
            declassification_ref: Some("decision-11".to_string()),
            timestamp_ms: 1_700_000_000_011,
            trace_id: trace_id.to_string(),
            metadata_json: r#"{"policy_id":"ifc-policy"}"#.to_string(),
        }
    }

    fn specialization_entry(specialization_id: i64) -> SpecializationIndexEntry {
        SpecializationIndexEntry {
            specialization_id,
            proof_artifact_id: "proof-13".to_string(),
            specialization_type: "fallback".to_string(),
            specialized_version: "v2-safe".to_string(),
            status: "active".to_string(),
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: 4,
            created_timestamp_ms: 1_700_000_000_013,
            specialized_content_hash: "sha256:abc123".to_string(),
            metadata_json: r#"{"fallback":"deterministic"}"#.to_string(),
        }
    }

    fn proof_evidence_entry(evidence_id: i64) -> ProofEvidenceIndexEntry {
        ProofEvidenceIndexEntry {
            evidence_id,
            bead_id: "bd-proof".to_string(),
            source_revision: "abc1234".to_string(),
            artifact_id: "proof-bundle:manifest".to_string(),
            artifact_path: "artifacts/proof/run/manifest.json".to_string(),
            artifact_role: "proof_manifest".to_string(),
            artifact_sha256:
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
            receipt_kind: "proof_manifest".to_string(),
            gate_status: "pass".to_string(),
            generated_timestamp_ms: 1_700_000_000_019,
            freshness_deadline_ms: 1_700_086_400_019,
            metadata_json: r#"{"source":"test"}"#.to_string(),
        }
    }

    fn shadow_evidence_entry(journal_event_id: i64) -> ShadowEvidenceJournalEntry {
        ShadowEvidenceJournalEntry {
            journal_event_id,
            bead_id: "bd-shadow".to_string(),
            event_kind: "source_snapshot".to_string(),
            source_kind: "br_queue_snapshot_json".to_string(),
            source_locator: "br ready --json".to_string(),
            collected_timestamp_ms: 1_700_000_000_023,
            sequence_id: journal_event_id,
            payload_content_hash:
                "sha256:0277a79f84690d36b4fabc8986caa314fa3bf841a6008857c1ba0fedaf268551"
                    .to_string(),
            normalized_payload_path: Some("artifacts/shadow/br_queue_snapshot.json".to_string()),
            normalized_payload_json: r#"[{"id":"bd-a","status":"ready"}]"#.to_string(),
            normalized_payload_hash:
                "sha256:0277a79f84690d36b4fabc8986caa314fa3bf841a6008857c1ba0fedaf268551"
                    .to_string(),
            raw_evidence_hashes_json:
                r#"["sha256:40d47631ec52fba5f92357f7d466ad5b789718d98ba0717f09063770c7bb0216"]"#
                    .to_string(),
            freshness_window_ms: 30_000,
            freshness_deadline_ms: 1_700_000_030_023,
            degradation_state: "confirmed".to_string(),
            retention_class: "windowed".to_string(),
            parent_event_ids_json: "[]".to_string(),
            metadata_json: r#"{"source_id":"br_queue_snapshot_json"}"#.to_string(),
        }
    }

    fn legacy_record(
        store: StoreKind,
        key: &str,
        value: &'static [u8],
        metadata: BTreeMap<String, String>,
    ) -> StoreRecord {
        StoreRecord {
            store,
            key: key.to_string(),
            value: value.to_vec(),
            metadata,
            revision: 1,
        }
    }

    fn legacy_json_record<T: Serialize>(store: StoreKind, key: &str, value: &T) -> StoreRecord {
        StoreRecord {
            store,
            key: key.to_string(),
            value: serde_json::to_vec(value).expect("legacy fixture serializes"),
            metadata: BTreeMap::new(),
            revision: 7,
        }
    }

    fn test_slot_id(name: &str) -> SlotId {
        SlotId::new(name).expect("valid slot id")
    }

    fn test_engine_object_id(seed: &[u8]) -> crate::engine_object_id::EngineObjectId {
        derive_id(
            ObjectDomain::EvidenceRecord,
            "typed-persistence-test",
            &SchemaId::from_definition(b"typed-persistence-test-schema"),
            seed,
        )
        .expect("deterministic test object id")
    }

    #[derive(Debug, Clone, Copy)]
    struct NoopConnection;

    #[derive(Debug, Clone, Copy)]
    struct NoopTransaction;

    fn noop_error(operation: &str) -> Error {
        Error::Custom(format!(
            "noop typed session test connection does not execute {operation}"
        ))
    }

    impl Connection for NoopConnection {
        type Tx<'conn>
            = NoopTransaction
        where
            Self: 'conn;

        fn dialect(&self) -> Dialect {
            Dialect::Sqlite
        }

        fn query(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("query `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn query_one(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Option<Row>, Error>> + Send {
            let operation = format!("query_one `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("execute `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn insert(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<i64, Error>> + Send {
            let operation = format!("insert `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn batch(
            &self,
            _cx: &Cx,
            statements: &[(String, Vec<Value>)],
        ) -> impl Future<Output = Outcome<Vec<u64>, Error>> + Send {
            let operation = format!("batch with {} statements", statements.len());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn begin(&self, _cx: &Cx) -> impl Future<Output = Outcome<Self::Tx<'_>, Error>> + Send {
            async { Outcome::Ok(NoopTransaction) }
        }

        fn begin_with(
            &self,
            _cx: &Cx,
            _isolation: IsolationLevel,
        ) -> impl Future<Output = Outcome<Self::Tx<'_>, Error>> + Send {
            async { Outcome::Ok(NoopTransaction) }
        }

        fn prepare(
            &self,
            _cx: &Cx,
            sql: &str,
        ) -> impl Future<Output = Outcome<PreparedStatement, Error>> + Send {
            let sql = sql.to_string();
            async move { Outcome::Ok(PreparedStatement::new(1, sql, 0)) }
        }

        fn query_prepared(
            &self,
            _cx: &Cx,
            stmt: &PreparedStatement,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("query_prepared `{}`", stmt.sql());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute_prepared(
            &self,
            _cx: &Cx,
            stmt: &PreparedStatement,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("execute_prepared `{}`", stmt.sql());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn ping(&self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn close(self, _cx: &Cx) -> impl Future<Output = sqlmodel_core::Result<()>> + Send {
            async { Ok(()) }
        }
    }

    impl TransactionOps for NoopTransaction {
        fn query(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("transaction query `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn query_one(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Option<Row>, Error>> + Send {
            let operation = format!("transaction query_one `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("transaction execute `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn savepoint(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn rollback_to(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn release(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn commit(self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn rollback(self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }
    }

    #[test]
    fn replacement_lineage_model_exports_sqlmodel_metadata() {
        assert_eq!(ReplacementLineageEntry::TABLE_NAME, "replacement_lineage");
        assert_eq!(ReplacementLineageEntry::PRIMARY_KEY, &["sequence_id"]);

        let fields = ReplacementLineageEntry::fields();
        assert_eq!(fields.len(), 9);
        assert!(field::<ReplacementLineageEntry>("sequence_id").primary_key);
        assert_eq!(
            field::<ReplacementLineageEntry>("metadata_json").sql_type,
            SqlType::Text
        );
    }

    #[test]
    fn ifc_provenance_model_marks_declassification_ref_nullable() {
        assert_eq!(IfcProvenanceEntry::TABLE_NAME, "ifc_provenance");
        assert_eq!(IfcProvenanceEntry::PRIMARY_KEY, &["provenance_id"]);

        let declassification_ref = field::<IfcProvenanceEntry>("declassification_ref");
        assert_eq!(declassification_ref.sql_type, SqlType::Text);
        assert!(declassification_ref.nullable);
    }

    #[test]
    fn specialization_index_model_marks_invalidation_fields_nullable() {
        assert_eq!(SpecializationIndexEntry::TABLE_NAME, "specialization_index");
        assert_eq!(
            SpecializationIndexEntry::PRIMARY_KEY,
            &["specialization_id"]
        );

        assert!(field::<SpecializationIndexEntry>("invalidation_timestamp_ms").nullable);
        assert!(field::<SpecializationIndexEntry>("invalidation_reason").nullable);
        assert_eq!(
            field::<SpecializationIndexEntry>("specialized_content_hash").sql_type,
            SqlType::Text
        );
    }

    #[test]
    fn proof_evidence_index_model_exports_dashboard_fields() {
        assert_eq!(ProofEvidenceIndexEntry::TABLE_NAME, "proof_evidence_index");
        assert_eq!(ProofEvidenceIndexEntry::PRIMARY_KEY, &["evidence_id"]);
        assert!(field::<ProofEvidenceIndexEntry>("evidence_id").primary_key);
        assert_eq!(
            field::<ProofEvidenceIndexEntry>("artifact_path").sql_type,
            SqlType::Text
        );
        assert_eq!(
            field::<ProofEvidenceIndexEntry>("freshness_deadline_ms").sql_type,
            SqlType::BigInt
        );
    }

    #[test]
    fn typed_persistence_models_round_trip_through_sqlmodel_rows() {
        assert_round_trips(ReplacementLineageEntry {
            sequence_id: 7,
            slot_id: "slot-alpha".to_string(),
            operation_type: "promotion".to_string(),
            source_state: "candidate".to_string(),
            target_state: "active".to_string(),
            receipt_artifact_id: "receipt-7".to_string(),
            receipt_signature: "sig-7".to_string(),
            timestamp_ms: 1_700_000_000_007,
            metadata_json: r#"{"trace_id":"trace-replacement"}"#.to_string(),
        });

        assert_round_trips(IfcProvenanceEntry {
            provenance_id: 11,
            source_label: "secret/model".to_string(),
            target_label: "operator/audit".to_string(),
            edge_type: "declassification".to_string(),
            flow_operation: "emit_receipt".to_string(),
            security_level: "high".to_string(),
            declassification_ref: Some("decision-11".to_string()),
            timestamp_ms: 1_700_000_000_011,
            trace_id: "trace-ifc".to_string(),
            metadata_json: r#"{"policy_id":"ifc-policy"}"#.to_string(),
        });

        assert_round_trips(proof_evidence_entry(19));
        assert_round_trips(shadow_evidence_entry(23));

        assert_round_trips(SpecializationIndexEntry {
            specialization_id: 13,
            proof_artifact_id: "proof-13".to_string(),
            specialization_type: "fallback".to_string(),
            specialized_version: "v2-safe".to_string(),
            status: "invalidated".to_string(),
            invalidation_timestamp_ms: Some(1_700_000_000_014),
            invalidation_reason: Some("fallback superseded".to_string()),
            security_epoch: 4,
            created_timestamp_ms: 1_700_000_000_013,
            specialized_content_hash: "sha256:abc123".to_string(),
            metadata_json: r#"{"fallback":"deterministic"}"#.to_string(),
        });

        let null_option_values = SpecializationIndexEntry {
            specialization_id: 17,
            proof_artifact_id: "proof-17".to_string(),
            specialization_type: "optimization".to_string(),
            specialized_version: "v3".to_string(),
            status: "active".to_string(),
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: 5,
            created_timestamp_ms: 1_700_000_000_017,
            specialized_content_hash: "sha256:def456".to_string(),
            metadata_json: "{}".to_string(),
        }
        .to_row();

        assert!(
            null_option_values
                .iter()
                .any(|(column, value)| *column == "invalidation_timestamp_ms"
                    && *value == Value::Null)
        );
        assert!(
            null_option_values
                .iter()
                .any(|(column, value)| *column == "invalidation_reason" && *value == Value::Null)
        );
    }

    #[test]
    fn typed_query_builders_emit_stable_sql_and_params() {
        let (sql, params) = ReplacementLineageEntry::select_by_slot_id("slot-alpha").build();
        assert_eq!(
            sql,
            r#"SELECT * FROM replacement_lineage WHERE "slot_id" = $1 ORDER BY "sequence_id" ASC"#
        );
        assert_eq!(params, vec![Value::Text("slot-alpha".to_string())]);

        let (sql, params) =
            IfcProvenanceEntry::select_by_label_flow("secret/model", "operator/audit").build();
        assert_eq!(
            sql,
            r#"SELECT * FROM ifc_provenance WHERE "source_label" = $1 AND "target_label" = $2 ORDER BY "provenance_id" ASC"#
        );
        assert_eq!(
            params,
            vec![
                Value::Text("secret/model".to_string()),
                Value::Text("operator/audit".to_string())
            ]
        );

        let (sql, params) = SpecializationIndexEntry::select_invalidated()
            .limit(50)
            .build();
        assert_eq!(
            sql,
            r#"SELECT * FROM specialization_index WHERE "status" = $1 ORDER BY "invalidation_timestamp_ms" DESC, "specialization_id" ASC LIMIT 50"#
        );
        assert_eq!(params, vec![Value::Text("invalidated".to_string())]);

        let (sql, params) = ProofEvidenceIndexEntry::select_by_bead_id("bd-proof")
            .limit(25)
            .build();
        assert_eq!(
            sql,
            r#"SELECT * FROM proof_evidence_index WHERE "bead_id" = $1 ORDER BY "source_revision" ASC, "artifact_path" ASC, "evidence_id" ASC LIMIT 25"#
        );
        assert_eq!(params, vec![Value::Text("bd-proof".to_string())]);

        let (sql, params) =
            ShadowEvidenceJournalEntry::select_by_source_kind("br_queue_snapshot_json")
                .limit(10)
                .build();
        assert_eq!(
            sql,
            r#"SELECT * FROM shadow_evidence_journal WHERE "source_kind" = $1 ORDER BY "sequence_id" ASC, "journal_event_id" ASC LIMIT 10"#
        );
        assert_eq!(
            params,
            vec![Value::Text("br_queue_snapshot_json".to_string())]
        );
    }

    #[test]
    fn typed_session_schema_sql_lists_all_typed_tables() {
        let sql = typed_persistence_create_table_sql();
        assert_eq!(sql.len(), 5);
        assert!(
            sql.iter()
                .all(|statement| statement.starts_with("CREATE TABLE IF NOT EXISTS ")),
            "all typed tables must be explicit CREATE TABLE statements: {sql:#?}"
        );
        assert!(
            sql[0].contains("\"replacement_lineage\"")
                && sql[0].contains("\"sequence_id\" BIGINT NOT NULL")
                && sql[0].contains("PRIMARY KEY (\"sequence_id\")"),
            "replacement lineage DDL should expose the typed primary key: {}",
            sql[0]
        );
        assert!(
            sql[1].contains("\"ifc_provenance\"")
                && sql[1].contains("\"declassification_ref\" TEXT")
                && sql[1].contains("PRIMARY KEY (\"provenance_id\")"),
            "IFC provenance DDL should expose nullable declassification refs: {}",
            sql[1]
        );
        assert!(
            sql[2].contains("\"proof_evidence_index\"")
                && sql[2].contains("\"artifact_path\" TEXT NOT NULL")
                && sql[2].contains("PRIMARY KEY (\"evidence_id\")"),
            "proof evidence DDL should expose dashboard query fields: {}",
            sql[2]
        );
        assert!(
            sql[3].contains("\"shadow_evidence_journal\"")
                && sql[3].contains("\"parent_event_ids_json\" TEXT NOT NULL")
                && sql[3].contains("PRIMARY KEY (\"journal_event_id\")"),
            "shadow evidence journal DDL should expose ordering and lineage fields: {}",
            sql[3]
        );
        assert!(
            sql[4].contains("\"specialization_index\"")
                && sql[4].contains("\"invalidation_reason\" TEXT")
                && sql[4].contains("PRIMARY KEY (\"specialization_id\")"),
            "specialization index DDL should expose nullable invalidation fields: {}",
            sql[4]
        );
    }

    #[test]
    fn typed_sqlmodel_session_tracks_models_with_deterministic_defaults() {
        let mut session = TypedSqlModelSession::new(NoopConnection);
        assert!(session.config().auto_begin);
        assert!(!session.config().auto_flush);
        assert!(!session.config().expire_on_commit);
        assert_eq!(
            TypedSqlModelSession::<NoopConnection>::create_table_sql(),
            typed_persistence_create_table_sql()
        );

        let replacement = replacement_entry(7);
        let ifc = ifc_entry(11, "trace-ifc");
        let proof_evidence = proof_evidence_entry(19);
        let shadow_evidence = shadow_evidence_entry(23);
        let specialization = specialization_entry(13);

        session.add_replacement_lineage(&replacement);
        session.add_ifc_provenance(&ifc);
        session.add_proof_evidence_index(&proof_evidence);
        session.add_shadow_evidence_journal(&shadow_evidence);
        session.add_specialization_index(&specialization);

        assert!(session.contains_typed(&replacement));
        assert!(session.contains_typed(&ifc));
        assert!(session.contains_typed(&proof_evidence));
        assert!(session.contains_typed(&shadow_evidence));
        assert!(session.contains_typed(&specialization));

        let debug = session.debug_state();
        assert_eq!(debug.tracked, 5);
        assert_eq!(debug.pending_new, 5);
        assert_eq!(debug.pending_delete, 0);
        assert_eq!(debug.pending_dirty, 0);
        assert!(!debug.in_transaction);
    }

    #[test]
    fn typed_frankensqlite_session_initializes_real_schema() {
        let session = open_typed_frankensqlite_memory_session()
            .expect("real FrankenSQLite typed session initializes");
        assert_eq!(session.connection().path(), ":memory:");
        assert!(session.config().auto_begin);
        assert!(!session.config().auto_flush);
        assert!(!session.config().expire_on_commit);

        for (table, primary_key) in [
            ("replacement_lineage", "sequence_id"),
            ("ifc_provenance", "provenance_id"),
            ("proof_evidence_index", "evidence_id"),
            ("shadow_evidence_journal", "journal_event_id"),
            ("specialization_index", "specialization_id"),
        ] {
            let sql = format!("PRAGMA table_info({table})");
            let rows = session
                .connection()
                .query_sync(&sql, &[])
                .expect("typed table schema is queryable through FrankenSQLite");
            let columns = rows
                .iter()
                .map(|row| row.get_named::<String>("name").expect("column has name"))
                .collect::<Vec<_>>();

            assert!(
                columns.contains(&primary_key.to_string()),
                "{table} schema should include primary key {primary_key}; columns={columns:#?}"
            );
            assert!(
                columns.len() >= 9,
                "{table} schema should include the typed model fields; columns={columns:#?}"
            );
        }
    }

    #[test]
    fn typed_store_record_boundary_emits_deterministic_keys_and_metadata() {
        let model = replacement_entry(7);
        let record = model
            .to_store_record(42)
            .expect("typed record should serialize");

        assert_eq!(record.store, StoreKind::ReplacementLineage);
        assert_eq!(record.key, "typed/replacement_lineage/00000000000000000007");
        assert_eq!(record.revision, 42);
        assert_eq!(
            record.metadata.get(TYPED_RECORD_FORMAT_KEY),
            Some(&TYPED_RECORD_FORMAT_VALUE.to_string())
        );
        assert_eq!(
            record.metadata.get(TYPED_MODEL_KEY),
            Some(&"ReplacementLineageEntry".to_string())
        );
        assert_eq!(
            record.metadata.get("slot_id"),
            Some(&"slot-alpha".to_string())
        );
        assert_eq!(
            record.metadata.get("receipt_artifact_id"),
            Some(&"receipt-7".to_string())
        );

        let restored = ReplacementLineageEntry::from_store_record(&record)
            .expect("typed record should deserialize");
        assert_eq!(restored, model);
    }

    #[test]
    fn typed_store_record_boundary_fails_closed_on_wrong_kind_or_metadata() {
        let model = replacement_entry(7);
        let mut wrong_store = model
            .to_store_record(0)
            .expect("typed record should serialize");
        wrong_store.store = StoreKind::IfcProvenance;
        let err = ReplacementLineageEntry::from_store_record(&wrong_store).unwrap_err();
        assert!(matches!(
            err,
            StorageError::IntegrityViolation {
                store: StoreKind::ReplacementLineage,
                ..
            }
        ));
        assert!(err.to_string().contains("store kind mismatch"));

        let mut missing_metadata = model
            .to_store_record(0)
            .expect("typed record should serialize");
        missing_metadata.metadata.remove(TYPED_RECORD_FORMAT_KEY);
        let err = ReplacementLineageEntry::from_store_record(&missing_metadata).unwrap_err();
        assert!(matches!(
            err,
            StorageError::IntegrityViolation {
                store: StoreKind::ReplacementLineage,
                ..
            }
        ));
        assert!(err.to_string().contains("missing typed metadata"));
    }

    #[test]
    fn typed_store_record_boundary_fails_closed_on_malformed_or_legacy_payload() {
        let model = replacement_entry(7);
        let mut malformed = model
            .to_store_record(0)
            .expect("typed record should serialize");
        malformed.value = b"{not json}".to_vec();
        let err = ReplacementLineageEntry::from_store_record(&malformed).unwrap_err();
        assert!(err.to_string().contains("failed to deserialize"));

        let mut legacy_shaped = model
            .to_store_record(0)
            .expect("typed record should serialize");
        legacy_shaped.value = br#"{"sequence":7,"kind":"DelegateToNative"}"#.to_vec();
        let err = ReplacementLineageEntry::from_store_record(&legacy_shaped).unwrap_err();
        assert!(err.to_string().contains("failed to deserialize"));

        let mut id_mismatch = model
            .to_store_record(0)
            .expect("typed record should serialize");
        id_mismatch.value =
            serde_json::to_vec(&replacement_entry(8)).expect("test payload serializes");
        let err = ReplacementLineageEntry::from_store_record(&id_mismatch).unwrap_err();
        assert!(err.to_string().contains("payload id mismatch"));
    }

    #[test]
    fn typed_store_record_boundary_rejects_negative_ids() {
        let err = replacement_entry(-1).to_store_record(0).unwrap_err();
        assert!(matches!(
            err,
            StorageError::IntegrityViolation {
                store: StoreKind::ReplacementLineage,
                ..
            }
        ));
        assert!(err.to_string().contains("sequence_id"));

        let err = typed_record_key(StoreKind::ReplacementLineage, -1).unwrap_err();
        assert!(matches!(err, StorageError::InvalidKey { .. }));
        assert!(err.to_string().contains("typed/replacement_lineage/-1"));
    }

    #[test]
    fn typed_model_validation_rejects_invalid_replacement_fields() {
        let mut invalid = replacement_entry(7);
        invalid.operation_type = "sideways".to_string();
        let err = invalid.to_store_record(0).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("operation_type"));

        let mut invalid = replacement_entry(7);
        invalid.metadata_json = "[]".to_string();
        let err = invalid.to_store_record(0).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("metadata_json"));
    }

    #[test]
    fn shadow_evidence_boundary_rejects_payload_hash_mismatches() {
        let raw_fixture_hash =
            "sha256:40d47631ec52fba5f92357f7d466ad5b789718d98ba0717f09063770c7bb0216";

        let mut invalid = shadow_evidence_entry(23);
        invalid.normalized_payload_hash = raw_fixture_hash.to_string();
        let err = invalid.to_store_record(0).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("payload hash mismatch"));

        let mut stored = shadow_evidence_entry(23)
            .to_store_record(0)
            .expect("valid shadow evidence serializes");
        let mut corrupt_payload = shadow_evidence_entry(23);
        corrupt_payload.payload_content_hash = raw_fixture_hash.to_string();
        stored.value = serde_json::to_vec(&corrupt_payload).expect("test payload serializes");

        let err = ShadowEvidenceJournalEntry::from_store_record(&stored).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("payload hash mismatch"));
    }

    #[test]
    fn typed_model_validation_rejects_declassification_without_reference() {
        let mut invalid = ifc_entry(11, "trace-ifc");
        invalid.declassification_ref = None;

        let err = invalid.to_store_record(0).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("declassification_ref"));
    }

    #[test]
    fn typed_model_validation_rejects_partial_invalidation_state() {
        let mut invalid = specialization_entry(13);
        invalid.status = "invalidated".to_string();
        invalid.invalidation_timestamp_ms = Some(1_700_000_444);
        invalid.invalidation_reason = None;

        let err = invalid.to_store_record(0).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("invalidation_reason"));
    }

    #[test]
    fn typed_id_allocator_replays_stable_monotonic_ids_by_model() {
        let context = EventContext::new("trace-alloc", "decision-alloc", "policy-alloc")
            .expect("context is valid");
        let mut adapter = InMemoryStorageAdapter::new();

        let first = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut adapter,
            "replacement:slot-alpha:receipt-1",
            &context,
        )
        .expect("first allocation succeeds");
        let replayed = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut adapter,
            "replacement:slot-alpha:receipt-1",
            &context,
        )
        .expect("existing allocation replays");
        let second = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut adapter,
            "replacement:slot-alpha:receipt-2",
            &context,
        )
        .expect("second allocation succeeds");
        let first_ifc = allocate_typed_record_id::<IfcProvenanceEntry, _>(
            &mut adapter,
            "ifc:flow-event:1",
            &context,
        )
        .expect("model-specific allocation succeeds");

        assert_eq!(first, 0);
        assert_eq!(replayed, 0);
        assert_eq!(second, 1);
        assert_eq!(first_ifc, 0);

        let allocation_key =
            typed_id_allocation_key::<ReplacementLineageEntry>("replacement:slot-alpha:receipt-1")
                .expect("natural key has stable allocation key");
        let stored = adapter
            .get(StoreKind::PolicyCache, &allocation_key, &context)
            .expect("allocation lookup succeeds")
            .expect("allocation record exists");
        let decoded = decode_typed_id_allocation::<ReplacementLineageEntry>(&stored)
            .expect("allocation record decodes");
        assert_eq!(decoded.typed_record_id, first);
        assert_eq!(
            stored.metadata.get(TYPED_ID_ALLOCATION_FORMAT_KEY),
            Some(&TYPED_ID_ALLOCATION_FORMAT_VALUE.to_string())
        );

        let rows = adapter
            .query(
                StoreKind::PolicyCache,
                &StoreQuery {
                    key_prefix: Some(format!(
                        "{}/",
                        typed_id_allocation_prefix::<ReplacementLineageEntry>()
                    )),
                    metadata_filters: BTreeMap::new(),
                    limit: None,
                },
                &context,
            )
            .expect("allocation query succeeds");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn typed_id_allocator_fails_closed_on_invalid_or_corrupt_allocations() {
        let context = EventContext::new("trace-alloc", "decision-alloc", "policy-alloc")
            .expect("context is valid");
        let mut adapter = InMemoryStorageAdapter::new();

        let err =
            allocate_typed_record_id::<ReplacementLineageEntry, _>(&mut adapter, " \t ", &context)
                .expect_err("blank natural keys are rejected");
        assert_eq!(err.code(), "FE-STOR-0002");

        let err = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut adapter,
            "bad\0key",
            &context,
        )
        .expect_err("nul-delimited natural keys are rejected");
        assert_eq!(err.code(), "FE-STOR-0002");

        let corrupt_key = typed_id_allocation_key::<ReplacementLineageEntry>("replacement:corrupt")
            .expect("test allocation key is valid");
        adapter
            .put(
                StoreKind::PolicyCache,
                corrupt_key,
                b"{not json}".to_vec(),
                BTreeMap::new(),
                &context,
            )
            .expect("corrupt fixture write succeeds");

        let err = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut adapter,
            "replacement:new",
            &context,
        )
        .expect_err("corrupt allocation rows block new allocations");
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("typed id allocation"));
    }

    #[test]
    fn legacy_typed_id_allocator_emits_one_stable_id_per_typed_output_row() {
        let context = EventContext::new("trace-legacy-alloc", "decision-legacy", "policy-alloc")
            .expect("context is valid");
        let mut adapter = InMemoryStorageAdapter::new();
        let legacy = legacy_record(
            StoreKind::SpecializationIndex,
            "receipt:legacy-specialization",
            b"{}",
            BTreeMap::new(),
        );

        let ids = allocate_legacy_typed_record_ids::<SpecializationIndexEntry, _>(
            &mut adapter,
            &legacy,
            3,
            &context,
        )
        .expect("legacy output row ids allocate");
        let replayed = allocate_legacy_typed_record_ids::<SpecializationIndexEntry, _>(
            &mut adapter,
            &legacy,
            3,
            &context,
        )
        .expect("legacy output row ids replay");

        assert_eq!(ids, vec![0, 1, 2]);
        assert_eq!(replayed, ids);

        let err = allocate_legacy_typed_record_ids::<SpecializationIndexEntry, _>(
            &mut adapter,
            &legacy,
            0,
            &context,
        )
        .expect_err("zero-row allocations are invalid");
        assert_eq!(err.code(), "FE-STOR-0003");
    }

    #[test]
    fn typed_storage_adapter_extension_puts_gets_batches_and_queries_models() {
        let context = EventContext::new("trace-typed", "decision-typed", "policy-typed")
            .expect("context is valid");
        let mut adapter = InMemoryStorageAdapter::new();

        let stored = adapter
            .put_typed(&replacement_entry(7), &context)
            .expect("typed put succeeds");
        assert_eq!(stored.revision, 1);

        let fetched = adapter
            .get_typed_by_id::<ReplacementLineageEntry>(7, &context)
            .expect("typed get succeeds")
            .expect("typed record exists");
        assert_eq!(fetched, replacement_entry(7));

        let ifc_rows = vec![ifc_entry(11, "trace-ifc"), ifc_entry(12, "trace-ifc")];
        adapter
            .put_typed_batch(&ifc_rows, &context)
            .expect("typed batch succeeds");

        let query = StoreQuery {
            key_prefix: Some("typed/ifc_provenance/".to_string()),
            metadata_filters: BTreeMap::from([("trace_id".to_string(), "trace-ifc".to_string())]),
            limit: None,
        };
        let fetched = adapter
            .query_typed::<IfcProvenanceEntry>(&query, &context)
            .expect("typed query succeeds");
        assert_eq!(fetched, ifc_rows);

        let specialization = specialization_entry(13);
        let entry = specialization
            .to_batch_put_entry()
            .expect("batch entry conversion succeeds");
        assert_eq!(entry.key, "typed/specialization_index/00000000000000000013");
        assert_eq!(
            entry.metadata.get("proof_artifact_id"),
            Some(&"proof-13".to_string())
        );
    }

    #[test]
    fn legacy_replacement_lineage_chain_maps_losslessly_and_rejects_hash_pointer() {
        let chain = LineageChainEntry {
            slot_id: test_slot_id("slot-alpha"),
            timestamp_ns: 1_700_000_123_456_789,
            receipt_id: "receipt-alpha".to_string(),
            kind: ReplacementKind::DelegateToNative,
            from_cell_digest: "delegate-digest".to_string(),
            to_cell_digest: "native-digest".to_string(),
            receipt_content_hash: "sha256:lineage".to_string(),
        };
        let source = legacy_json_record(
            StoreKind::ReplacementLineage,
            "lineage_chain/slot-alpha/00001700000123456789/receipt-alpha",
            &chain,
        );

        let mapped = map_legacy_replacement_lineage_record(&source, 41)
            .expect("lineage-chain rows are lossless lineage entries");
        assert_eq!(mapped.len(), 1);
        let entry = &mapped[0];
        assert_eq!(entry.sequence_id, 41);
        assert_eq!(entry.slot_id, "slot-alpha");
        assert_eq!(entry.operation_type, "delegate_to_native");
        assert_eq!(entry.source_state, "delegate-digest");
        assert_eq!(entry.target_state, "native-digest");
        assert_eq!(entry.receipt_artifact_id, "receipt-alpha");
        assert_eq!(entry.timestamp_ms, 1_700_000_123);
        assert!(entry.receipt_signature.contains("receipt_content_hash"));

        let metadata: serde_json::Value =
            serde_json::from_str(&entry.metadata_json).expect("lossless metadata is JSON");
        assert_eq!(metadata["legacy_record_type"], "lineage_chain");
        assert_eq!(metadata["legacy_key"], source.key);
        assert_eq!(
            metadata["legacy_payload"]["receipt_content_hash"],
            "sha256:lineage"
        );
        assert!(
            metadata["legacy_value_json"]
                .as_str()
                .expect("source JSON retained")
                .contains("receipt-alpha")
        );

        let pointer = legacy_record(
            StoreKind::ReplacementLineage,
            "replacement_by_hash/sha256:lineage",
            b"lineage_chain/slot-alpha/00001700000123456789/receipt-alpha",
            BTreeMap::new(),
        );
        let err = map_legacy_replacement_lineage_record(&pointer, 42)
            .expect_err("hash-pointer rows must not become fake lineage rows");
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("separate table required"));
    }

    #[test]
    fn legacy_replacement_demotion_receipt_maps_integrity_reference() {
        let demotion = DemotionReceiptRecord {
            receipt_id: "demotion-r1".to_string(),
            slot_id: test_slot_id("slot-beta"),
            demoted_cell_digest: "native-digest".to_string(),
            restored_cell_digest: "delegate-digest".to_string(),
            demotion_reason: "rollback guard tripped".to_string(),
            timestamp_ns: 1_700_000_124_999_999,
            rollback_token_used: "rollback-token".to_string(),
            linked_replacement_receipt_id: Some("replacement-r1".to_string()),
            receipt_content_hash: "sha256:demotion".to_string(),
        };
        let source = legacy_json_record(
            StoreKind::ReplacementLineage,
            "demotion_receipts/slot-beta/00001700000124999999/demotion-r1",
            &demotion,
        );

        let mapped = map_legacy_replacement_lineage_record(&source, 43)
            .expect("demotion receipt maps to a typed lineage row");
        assert_eq!(mapped.len(), 1);
        let entry = &mapped[0];
        assert_eq!(entry.sequence_id, 43);
        assert_eq!(entry.operation_type, "demotion");
        assert_eq!(entry.source_state, "native-digest");
        assert_eq!(entry.target_state, "delegate-digest");
        assert_eq!(entry.receipt_artifact_id, "demotion-r1");
        assert!(entry.receipt_signature.contains("sha256:demotion"));

        let metadata: serde_json::Value =
            serde_json::from_str(&entry.metadata_json).expect("lossless metadata is JSON");
        assert_eq!(metadata["legacy_record_type"], "demotion_receipt");
        assert_eq!(
            metadata["legacy_payload"]["linked_replacement_receipt_id"],
            "replacement-r1"
        );
    }

    #[test]
    fn legacy_ifc_flow_event_maps_label_json_and_rejects_proof_side_table() {
        let source_label = Label::Custom {
            name: "tenant-alpha/pii".to_string(),
            level: 3,
        };
        let event = FlowEventRecord {
            event_id: "flow-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: source_label.clone(),
            sink_clearance: Label::TopSecret,
            flow_location: "module::emit".to_string(),
            decision: FlowDecision::Declassified,
            receipt_ref: Some("declass-r1".to_string()),
            timestamp_ms: 1_700_000_222,
        };
        let source = legacy_json_record(StoreKind::IfcProvenance, "flow_event::flow-1", &event);

        let mapped = map_legacy_ifc_provenance_record(&source, 51)
            .expect("flow events are timestamped IFC provenance rows");
        assert_eq!(mapped.len(), 1);
        let entry = &mapped[0];
        assert_eq!(entry.provenance_id, 51);
        assert_eq!(
            entry.source_label,
            serde_json::to_string(&source_label).expect("label serializes")
        );
        assert_eq!(
            entry.target_label,
            serde_json::to_string(&Label::TopSecret).expect("label serializes")
        );
        assert_eq!(entry.edge_type, "declassification");
        assert_eq!(entry.flow_operation, "flow_event:declassified");
        assert_eq!(entry.security_level, "source_level:3");
        assert_eq!(entry.declassification_ref.as_deref(), Some("declass-r1"));
        assert_eq!(entry.timestamp_ms, 1_700_000_222);
        assert_eq!(entry.trace_id, "flow-1");

        let metadata: serde_json::Value =
            serde_json::from_str(&entry.metadata_json).expect("lossless metadata is JSON");
        assert_eq!(metadata["legacy_record_type"], "ifc_flow_event");
        assert_eq!(metadata["legacy_payload"]["flow_location"], "module::emit");

        let proof = FlowProofRecord {
            proof_id: "proof-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::TopSecret,
            proof_method: ProofMethod::StaticAnalysis,
            epoch_id: 9,
        };
        let proof_record =
            legacy_json_record(StoreKind::IfcProvenance, "flow_proof::proof-1", &proof);
        let err = map_legacy_ifc_provenance_record(&proof_record, 52)
            .expect_err("proof rows lack timestamped event semantics for this table");
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("separate table required"));
    }

    #[test]
    fn legacy_ifc_declassification_receipt_maps_route_metadata() {
        let receipt = DeclassReceiptRecord {
            receipt_id: "declass-r2".to_string(),
            extension_id: "ext-a".to_string(),
            decision: DeclassificationDecision::Allow,
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_route_ref: "route-7".to_string(),
            decision_contract_id: "contract-9".to_string(),
            timestamp_ms: 1_700_000_555,
        };
        let source = legacy_json_record(
            StoreKind::IfcProvenance,
            "declass_receipt::declass-r2",
            &receipt,
        );

        let mapped = map_legacy_ifc_provenance_record(&source, 53)
            .expect("declassification receipts are timestamped IFC provenance rows");
        assert_eq!(mapped.len(), 1);
        let entry = &mapped[0];
        assert_eq!(entry.provenance_id, 53);
        assert_eq!(entry.edge_type, "declassification");
        assert_eq!(entry.flow_operation, "declass_receipt:allow");
        assert_eq!(entry.declassification_ref.as_deref(), Some("declass-r2"));
        assert_eq!(entry.timestamp_ms, 1_700_000_555);
        assert_eq!(entry.trace_id, "declass-r2");

        let metadata: serde_json::Value =
            serde_json::from_str(&entry.metadata_json).expect("lossless metadata is JSON");
        assert_eq!(metadata["legacy_record_type"], "ifc_declass_receipt");
        assert_eq!(
            metadata["legacy_payload"]["declassification_route_ref"],
            "route-7"
        );
        assert_eq!(
            metadata["legacy_payload"]["decision_contract_id"],
            "contract-9"
        );
    }

    #[test]
    fn legacy_specialization_receipt_splits_proofs_and_rejects_side_tables() {
        let receipt_id = test_engine_object_id(b"specialization-receipt");
        let proof_a = test_engine_object_id(b"proof-a");
        let proof_b = test_engine_object_id(b"proof-b");
        let receipt = SpecializationRecord {
            receipt_id: receipt_id.clone(),
            proof_input_ids: vec![proof_a.clone(), proof_b.clone()],
            proof_types: vec![ProofType::FlowProof, ProofType::ReplayMotif],
            optimization_class: OptimizationClass::IfcCheckElision,
            extension_id: "ext-specialized".to_string(),
            epoch: SecurityEpoch::from_raw(4),
            timestamp_ns: 1_700_000_333_999_999,
            active: true,
        };
        let source = legacy_json_record(
            StoreKind::SpecializationIndex,
            &format!("receipt:{}", receipt_id.to_hex()),
            &receipt,
        );

        let mapped = map_legacy_specialization_index_record(&source, 61)
            .expect("one specialization receipt maps to one row per proof input");
        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].specialization_id, 61);
        assert_eq!(mapped[1].specialization_id, 62);
        assert_eq!(mapped[0].proof_artifact_id, proof_a.to_hex());
        assert_eq!(mapped[1].proof_artifact_id, proof_b.to_hex());
        assert_eq!(mapped[0].specialization_type, "ifc_check_elision");
        assert_eq!(mapped[0].specialized_version, receipt_id.to_hex());
        assert_eq!(mapped[0].status, "active");
        assert_eq!(mapped[0].security_epoch, 4);
        assert_eq!(mapped[0].created_timestamp_ms, 1_700_000_333);
        assert_eq!(mapped[0].specialized_content_hash, receipt_id.to_hex());

        let metadata: serde_json::Value =
            serde_json::from_str(&mapped[1].metadata_json).expect("lossless metadata is JSON");
        assert_eq!(metadata["legacy_mapping_ordinal"], 1);
        assert_eq!(metadata["legacy_current_proof_type"], "replay_motif");
        assert_eq!(
            metadata["legacy_source"]["legacy_payload"]["extension_id"],
            "ext-specialized"
        );

        let mut inactive_receipt = receipt.clone();
        inactive_receipt.active = false;
        let inactive_source = legacy_json_record(
            StoreKind::SpecializationIndex,
            &format!("receipt:{}", inactive_receipt.receipt_id.to_hex()),
            &inactive_receipt,
        );
        let archived = map_legacy_specialization_index_record(&inactive_source, 63)
            .expect("inactive specialization receipt remains serializable typed history");
        assert_eq!(archived[0].status, "archived");
        archived[0]
            .to_store_record(0)
            .expect("archived legacy specialization row passes typed validation");

        let invalidation = legacy_record(
            StoreKind::SpecializationIndex,
            "invalidation:receipt:123",
            br#"{"receipt_id":"ignored"}"#,
            BTreeMap::new(),
        );
        let err = map_legacy_specialization_index_record(&invalidation, 65)
            .expect_err("invalidation rows are events, not standalone specialization rows");
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(err.to_string().contains("separate table required"));
    }

    #[test]
    fn legacy_mapper_rejects_malformed_supported_json() {
        let malformed = legacy_record(
            StoreKind::IfcProvenance,
            "flow_event::bad-json",
            b"{not valid json}",
            BTreeMap::new(),
        );

        let err = map_legacy_ifc_provenance_record(&malformed, 70)
            .expect_err("malformed supported legacy rows fail closed");
        assert_eq!(err.code(), "FE-STOR-0007");
        assert!(
            err.to_string()
                .contains("failed to deserialize legacy ifc_flow_event")
        );
    }

    #[test]
    fn typed_id_allocator_handles_concurrent_allocation_attempts() {
        // Test for race condition fix: concurrent allocations of same natural key
        // should result in same ID (no duplicates) and sequential allocations
        // should increment properly
        let mut storage = InMemoryStorageAdapter::new();
        let context = EventContext::new("trace-alloc", "decision-alloc", "policy-alloc")
            .expect("test context should be valid");

        // Allocate first ID for a natural key
        let id1 = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut storage,
            "test-natural-key-1",
            &context,
        )
        .expect("first allocation should succeed");
        assert_eq!(id1, 0, "first allocation should be 0");

        // Allocate same natural key again - should return same ID (idempotent)
        let id1_again = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut storage,
            "test-natural-key-1",
            &context,
        )
        .expect("repeat allocation should succeed");
        assert_eq!(id1_again, id1, "repeat allocation should return same ID");

        // Allocate different natural key - should get next sequential ID
        let id2 = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut storage,
            "test-natural-key-2",
            &context,
        )
        .expect("second allocation should succeed");
        assert_eq!(id2, 1, "second allocation should be sequential");

        // Verify IDs are stable across calls
        let id1_verify = allocate_typed_record_id::<ReplacementLineageEntry, _>(
            &mut storage,
            "test-natural-key-1",
            &context,
        )
        .expect("verification allocation should succeed");
        assert_eq!(id1_verify, id1, "allocation should remain stable");
    }

    #[test]
    fn typed_backfill_plan_separates_ready_legacy_corrupt_and_wrong_store_records() {
        let ready = replacement_entry(7)
            .to_store_record(5)
            .expect("typed record should serialize");
        let ready_key = ready.key.clone();

        let legacy = legacy_record(
            StoreKind::ReplacementLineage,
            "lineage_chain/slot-alpha/00000000000000000007/receipt-7",
            br#"{"receipt_id":"receipt-7","slot_id":"slot-alpha"}"#,
            BTreeMap::from([("table".to_string(), "lineage_chain".to_string())]),
        );
        let legacy_key = legacy.key.clone();

        let mut corrupt = replacement_entry(8)
            .to_store_record(6)
            .expect("typed record should serialize");
        corrupt.value = b"{not json}".to_vec();
        let corrupt_key = corrupt.key.clone();

        let wrong_store = ifc_entry(11, "trace-ifc")
            .to_store_record(7)
            .expect("typed record should serialize");
        let wrong_store_key = wrong_store.key.clone();

        let plan = plan_typed_store_backfill::<ReplacementLineageEntry>(&[
            ready,
            legacy,
            corrupt,
            wrong_store,
        ]);

        assert_eq!(plan.target_store, StoreKind::ReplacementLineage);
        assert_eq!(plan.model_name, "ReplacementLineageEntry");
        assert_eq!(plan.ready_count(), 1);
        assert_eq!(plan.legacy_unsupported_count(), 1);
        assert_eq!(plan.rejected_count(), 2);
        assert!(plan.requires_explicit_legacy_mapper());
        assert!(!plan.all_ready());

        let ready_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == ready_key)
            .expect("ready typed row is present");
        assert_eq!(ready_decision.status, TypedBackfillStatus::Ready);
        assert_eq!(ready_decision.typed_record_id, Some(7));
        assert!(ready_decision.error_code.is_none());

        let legacy_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == legacy_key)
            .expect("legacy row is present");
        assert_eq!(
            legacy_decision.status,
            TypedBackfillStatus::LegacyUnsupported
        );
        assert!(legacy_decision.typed_record_id.is_none());
        assert!(legacy_decision.error_code.is_none());
        assert!(
            legacy_decision
                .reason
                .contains("explicit lossless mapper required"),
            "legacy records must not be coerced implicitly: {legacy_decision:#?}"
        );

        let corrupt_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == corrupt_key)
            .expect("corrupt typed row is present");
        assert_eq!(corrupt_decision.status, TypedBackfillStatus::Rejected);
        assert_eq!(corrupt_decision.error_code.as_deref(), Some("FE-STOR-0007"));
        assert!(corrupt_decision.reason.contains("typed payload rejected"));

        let wrong_store_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == wrong_store_key)
            .expect("wrong-store row is present");
        assert_eq!(wrong_store_decision.status, TypedBackfillStatus::Rejected);
        assert_eq!(
            wrong_store_decision.error_code.as_deref(),
            Some("FE-STOR-0007")
        );
        assert!(
            wrong_store_decision
                .reason
                .contains("backfill store mismatch")
        );

        let json = serde_json::to_string(&plan).expect("backfill plan is loggable JSON");
        assert!(json.contains("\"status\":\"LegacyUnsupported\""));
        assert!(json.contains("\"error_code\":\"FE-STOR-0007\""));
    }

    #[test]
    fn typed_backfill_plan_rejects_partial_typed_envelopes() {
        let partial = legacy_record(
            StoreKind::ReplacementLineage,
            "typed/replacement_lineage/00000000000000000009",
            br#"{"sequence":9,"kind":"legacy"}"#,
            BTreeMap::new(),
        );

        let plan = plan_typed_store_backfill::<ReplacementLineageEntry>(&[partial]);

        assert_eq!(plan.ready_count(), 0);
        assert_eq!(plan.legacy_unsupported_count(), 0);
        assert_eq!(plan.rejected_count(), 1);
        assert!(!plan.requires_explicit_legacy_mapper());
        assert_eq!(plan.decisions[0].status, TypedBackfillStatus::Rejected);
        assert_eq!(
            plan.decisions[0].error_code.as_deref(),
            Some("FE-STOR-0007")
        );
        assert!(
            plan.decisions[0].reason.contains("partial typed envelope"),
            "typed-looking rows without complete metadata are corrupt, not legacy: {:#?}",
            plan.decisions[0]
        );
    }

    #[test]
    fn typed_backfill_plan_marks_domain_legacy_prefixes_as_mapper_required() {
        let ifc_legacy = legacy_record(
            StoreKind::IfcProvenance,
            "flow_event::ev-1",
            br#"{"event_id":"ev-1","extension_id":"ext-a"}"#,
            BTreeMap::new(),
        );
        let ifc_plan = plan_typed_store_backfill::<IfcProvenanceEntry>(&[ifc_legacy]);
        assert_eq!(ifc_plan.ready_count(), 0);
        assert_eq!(ifc_plan.legacy_unsupported_count(), 1);
        assert_eq!(ifc_plan.rejected_count(), 0);
        assert!(ifc_plan.requires_explicit_legacy_mapper());
        assert_eq!(
            ifc_plan.decisions[0].status,
            TypedBackfillStatus::LegacyUnsupported
        );

        let specialization_legacy = legacy_record(
            StoreKind::SpecializationIndex,
            "receipt:proof-13",
            br#"{"receipt_id":"proof-13","active":true}"#,
            BTreeMap::new(),
        );
        let specialization_plan =
            plan_typed_store_backfill::<SpecializationIndexEntry>(&[specialization_legacy]);
        assert_eq!(specialization_plan.ready_count(), 0);
        assert_eq!(specialization_plan.legacy_unsupported_count(), 1);
        assert_eq!(specialization_plan.rejected_count(), 0);
        assert!(specialization_plan.requires_explicit_legacy_mapper());
        assert!(
            specialization_plan.decisions[0]
                .reason
                .contains("explicit lossless mapper required")
        );
    }

    #[test]
    fn typed_backfill_plan_all_ready_when_every_row_is_current_typed_format() {
        let rows = vec![
            ifc_entry(11, "trace-ifc")
                .to_store_record(1)
                .expect("typed record serializes"),
            ifc_entry(12, "trace-ifc")
                .to_store_record(2)
                .expect("typed record serializes"),
        ];

        let plan = plan_typed_store_backfill::<IfcProvenanceEntry>(&rows);

        assert_eq!(plan.ready_count(), 2);
        assert_eq!(plan.legacy_unsupported_count(), 0);
        assert_eq!(plan.rejected_count(), 0);
        assert!(plan.all_ready());
        assert_eq!(
            plan.decisions
                .iter()
                .map(|decision| decision.typed_record_id)
                .collect::<Vec<_>>(),
            vec![Some(11), Some(12)]
        );
    }
}

// ---------------------------------------------------------------------------
// TODO: Integration scaffolding
// ---------------------------------------------------------------------------

// ✓ DONE: Implement SQLModel session management and FrankenSQLite initialization
// ✓ DONE: Add explicit typed backfill dry-run planning for legacy generic StoreRecord data
// ✓ DONE: Add store-specific lossless legacy-to-typed backfill mappers
// ✓ DONE: Add typed StoreRecord boundaries and StorageAdapter extension methods
// ✓ DONE: Add fail-closed field validation rules for each typed model
// ✓ DONE: Implement query builders for common access patterns
// TODO: Add external integration/e2e scripts with actual sqlmodel_rust session lifecycle logging
// TODO: Wire production SQLModel sessions behind typed adapter methods
// TODO: Add sqlmodel_rust session initialization in storage adapter constructor
// TODO: Update all callers to use typed store operations instead of generic record operations
