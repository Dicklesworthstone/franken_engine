//! Typed shadow-daemon evidence journal over the frankensqlite storage adapter.
//!
//! The journal persists normalized source snapshots, derived advisory events,
//! and replay checkpoints with deterministic sequence ordering. It fails
//! closed on malformed payloads, parent-link contradictions, content-hash
//! mismatches, and non-replay-stable imports.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::storage_adapter::{EventContext, StorageAdapter, StorageError, StoreQuery};
use crate::typed_persistence_models::{
    ShadowEvidenceJournalEntry, TypedStorageAdapterExt, TypedStoreRecord,
};

/// Stable export/import schema for shadow journal bundles.
pub const SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION: &str =
    "franken-engine.shadow-evidence-journal.v1";

const TYPED_SHADOW_KEY_PREFIX: &str = "typed/shadow_evidence_journal/";
const MAX_PARENT_EVENT_LINKS: usize = 64;
const MAX_NORMALIZED_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;

type StorageResult<T> = Result<T, StorageError>;

/// Append request for one shadow-journal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvidenceJournalAppend {
    pub bead_id: String,
    pub event_kind: String,
    pub source_kind: String,
    pub source_locator: String,
    pub collected_timestamp_ms: i64,
    pub payload_content_hash: String,
    pub normalized_payload_path: Option<String>,
    pub normalized_payload: Value,
    pub freshness_window_ms: i64,
    pub degradation_state: String,
    pub retention_class: String,
    pub parent_event_ids: Vec<i64>,
    pub raw_evidence_hashes: Vec<String>,
    pub metadata: Value,
}

/// Deterministic export envelope for replay/test imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvidenceJournalExport {
    pub schema_version: String,
    pub rows: Vec<ShadowEvidenceJournalExportRow>,
}

/// Lossless export row for one journal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvidenceJournalExportRow {
    pub journal_event_id: i64,
    pub bead_id: String,
    pub event_kind: String,
    pub source_kind: String,
    pub source_locator: String,
    pub collected_timestamp_ms: i64,
    pub sequence_id: i64,
    pub payload_content_hash: String,
    pub normalized_payload_path: Option<String>,
    pub normalized_payload: Value,
    pub normalized_payload_hash: String,
    pub raw_evidence_hashes: Vec<String>,
    pub freshness_window_ms: i64,
    pub freshness_deadline_ms: i64,
    pub degradation_state: String,
    pub retention_class: String,
    pub parent_event_ids: Vec<i64>,
    pub metadata: Value,
}

/// Append one or more journal events through the typed storage boundary.
pub fn append_journal_events<S>(
    storage: &mut S,
    events: &[ShadowEvidenceJournalAppend],
    context: &EventContext,
) -> StorageResult<Vec<ShadowEvidenceJournalEntry>>
where
    S: StorageAdapter,
{
    let mut ordered = Vec::with_capacity(events.len());
    for event in events {
        validate_append_seed(event)?;
        ordered.push(event.clone());
    }

    let existing_ids = existing_sequence_ids(storage, context)?;
    let mut entries = Vec::with_capacity(ordered.len());
    let mut alloc_seen = existing_ids.clone();
    let mut next_sequence_id = match alloc_seen.iter().next_back().copied() {
        Some(value) => value
            .checked_add(1)
            .ok_or_else(|| integrity("journal sequence id overflow"))?,
        None => 0,
    };
    for event in ordered {
        let entry = append_to_entry(event, next_sequence_id)?;
        validate_parent_links(&entry, &alloc_seen)?;
        alloc_seen.insert(entry.sequence_id);
        entries.push(entry);
        next_sequence_id = next_sequence_id
            .checked_add(1)
            .ok_or_else(|| integrity("journal sequence id overflow"))?;
    }

    entries.sort_by(entry_order);
    storage.put_typed_batch(&entries, context)?;
    Ok(entries)
}

/// Read every journal event in replay-stable order.
pub fn read_all_events<S>(
    storage: &mut S,
    context: &EventContext,
) -> StorageResult<Vec<ShadowEvidenceJournalEntry>>
where
    S: StorageAdapter,
{
    let query = StoreQuery {
        key_prefix: Some(TYPED_SHADOW_KEY_PREFIX.to_string()),
        metadata_filters: BTreeMap::new(),
        limit: None,
    };
    let mut rows = storage.query_typed::<ShadowEvidenceJournalEntry>(&query, context)?;
    rows.sort_by(entry_order);
    validate_stored_journal_rows(&rows)?;
    Ok(rows)
}

/// Read all journal events for one bead in replay-stable order.
pub fn read_events_for_bead<S>(
    storage: &mut S,
    bead_id: &str,
    context: &EventContext,
) -> StorageResult<Vec<ShadowEvidenceJournalEntry>>
where
    S: StorageAdapter,
{
    require_non_empty("bead_id", bead_id)?;
    let known_sequence_ids = existing_sequence_ids(storage, context)?;
    let query = StoreQuery {
        key_prefix: Some(TYPED_SHADOW_KEY_PREFIX.to_string()),
        metadata_filters: BTreeMap::from([("bead_id".to_string(), bead_id.to_string())]),
        limit: None,
    };
    let mut rows = storage.query_typed::<ShadowEvidenceJournalEntry>(&query, context)?;
    rows.sort_by(entry_order);
    validate_stored_journal_rows_against(&rows, &known_sequence_ids)?;
    Ok(rows)
}

/// Export the journal, preserving checkpoints and audit rows below the floor.
pub fn export_journal<S>(
    storage: &mut S,
    retention_floor_sequence_id: Option<i64>,
    context: &EventContext,
) -> StorageResult<ShadowEvidenceJournalExport>
where
    S: StorageAdapter,
{
    if let Some(floor) = retention_floor_sequence_id
        && floor < 0
    {
        return Err(integrity(format!(
            "retention floor must be non-negative, got {floor}"
        )));
    }

    let rows = read_all_events(storage, context)?;
    let rows = rows
        .into_iter()
        .filter(|row| retained_by_floor(row, retention_floor_sequence_id))
        .map(export_row_from_entry)
        .collect::<StorageResult<Vec<_>>>()?;

    Ok(ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    })
}

/// Import a deterministic journal export, preserving exact sequence ids.
pub fn import_journal_export<S>(
    storage: &mut S,
    export: &ShadowEvidenceJournalExport,
    context: &EventContext,
) -> StorageResult<Vec<ShadowEvidenceJournalEntry>>
where
    S: StorageAdapter,
{
    if export.schema_version != SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION {
        return Err(integrity(format!(
            "unsupported shadow journal schema_version `{}`; expected `{}`",
            export.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION
        )));
    }

    let mut staged = Vec::with_capacity(export.rows.len());
    let mut seen_sequences = existing_sequence_ids(storage, context)?;
    let mut previous_sequence = None;

    for row in &export.rows {
        if let Some(previous_sequence) = previous_sequence
            && row.sequence_id <= previous_sequence
        {
            return Err(integrity(
                "journal export rows must be strictly ascending by `sequence_id`",
            ));
        }
        previous_sequence = Some(row.sequence_id);

        let entry = export_row_to_entry(row.clone())?;
        validate_parent_links(&entry, &seen_sequences)?;

        let should_insert = if let Some(existing) = storage
            .get_typed_by_id::<ShadowEvidenceJournalEntry>(entry.journal_event_id, context)?
        {
            if existing != entry {
                return Err(integrity(format!(
                    "existing journal row {} does not match replay import payload",
                    entry.journal_event_id
                )));
            }
            false
        } else {
            true
        };

        seen_sequences.insert(entry.sequence_id);
        staged.push((entry, should_insert));
    }

    let mut imported = Vec::with_capacity(staged.len());
    for (entry, should_insert) in staged {
        if should_insert {
            storage.put_typed(&entry, context)?;
        }
        imported.push(entry);
    }

    imported.sort_by(entry_order);
    Ok(imported)
}

fn append_to_entry(
    append: ShadowEvidenceJournalAppend,
    journal_event_id: i64,
) -> StorageResult<ShadowEvidenceJournalEntry> {
    let normalized_payload_json = canonical_json_string(&append.normalized_payload)?;
    if normalized_payload_json.len() > MAX_NORMALIZED_PAYLOAD_BYTES {
        return Err(integrity(format!(
            "normalized payload exceeds byte cap of {MAX_NORMALIZED_PAYLOAD_BYTES}"
        )));
    }
    let computed_hash = sha256_hex(normalized_payload_json.as_bytes());
    let expected_hash = normalize_sha256(&append.payload_content_hash)?;
    if expected_hash != computed_hash {
        return Err(integrity(format!(
            "payload_content_hash mismatch: expected {expected_hash}, computed {computed_hash}"
        )));
    }

    let raw_evidence_hashes = normalize_hashes(append.raw_evidence_hashes)?;
    let raw_evidence_hashes_json = serde_json::to_string(&raw_evidence_hashes)
        .map_err(|err| integrity(format!("failed to serialize raw evidence hashes: {err}")))?;
    let metadata_json = canonical_metadata_json(append.metadata)?;
    if metadata_json.len() > MAX_METADATA_BYTES {
        return Err(integrity(format!(
            "metadata exceeds byte cap of {MAX_METADATA_BYTES}"
        )));
    }

    let freshness_deadline_ms = append
        .collected_timestamp_ms
        .checked_add(append.freshness_window_ms)
        .ok_or_else(|| integrity("freshness deadline overflow"))?;

    let entry = ShadowEvidenceJournalEntry {
        journal_event_id,
        bead_id: append.bead_id,
        event_kind: append.event_kind,
        source_kind: append.source_kind,
        source_locator: append.source_locator,
        collected_timestamp_ms: append.collected_timestamp_ms,
        sequence_id: journal_event_id,
        payload_content_hash: format!("sha256:{computed_hash}"),
        normalized_payload_path: append.normalized_payload_path,
        normalized_payload_json,
        normalized_payload_hash: format!("sha256:{computed_hash}"),
        raw_evidence_hashes_json,
        freshness_window_ms: append.freshness_window_ms,
        freshness_deadline_ms,
        degradation_state: append.degradation_state,
        retention_class: append.retention_class,
        parent_event_ids_json: serialize_parent_event_ids(&append.parent_event_ids)?,
        metadata_json,
    };
    entry.validate_typed_record()?;
    Ok(entry)
}

fn export_row_from_entry(
    entry: ShadowEvidenceJournalEntry,
) -> StorageResult<ShadowEvidenceJournalExportRow> {
    let normalized_payload = validated_payload_from_entry(&entry)?;
    Ok(ShadowEvidenceJournalExportRow {
        journal_event_id: entry.journal_event_id,
        bead_id: entry.bead_id,
        event_kind: entry.event_kind,
        source_kind: entry.source_kind,
        source_locator: entry.source_locator,
        collected_timestamp_ms: entry.collected_timestamp_ms,
        sequence_id: entry.sequence_id,
        payload_content_hash: entry.payload_content_hash,
        normalized_payload_path: entry.normalized_payload_path,
        normalized_payload,
        normalized_payload_hash: entry.normalized_payload_hash,
        raw_evidence_hashes: parse_hash_array(&entry.raw_evidence_hashes_json)?,
        freshness_window_ms: entry.freshness_window_ms,
        freshness_deadline_ms: entry.freshness_deadline_ms,
        degradation_state: entry.degradation_state,
        retention_class: entry.retention_class,
        parent_event_ids: parse_parent_event_ids(&entry.parent_event_ids_json)?,
        metadata: parse_json_value(&entry.metadata_json, "metadata_json")?,
    })
}

fn export_row_to_entry(
    row: ShadowEvidenceJournalExportRow,
) -> StorageResult<ShadowEvidenceJournalEntry> {
    validate_export_row(&row)?;
    let normalized_payload_json = canonical_json_string(&row.normalized_payload)?;
    let computed_hash = sha256_hex(normalized_payload_json.as_bytes());
    let expected_payload_hash = normalize_sha256(&row.payload_content_hash)?;
    let expected_normalized_hash = normalize_sha256(&row.normalized_payload_hash)?;
    if expected_payload_hash != computed_hash || expected_normalized_hash != computed_hash {
        return Err(integrity(format!(
            "exported payload hash mismatch for journal event {}",
            row.journal_event_id
        )));
    }

    let entry = ShadowEvidenceJournalEntry {
        journal_event_id: row.journal_event_id,
        bead_id: row.bead_id,
        event_kind: row.event_kind,
        source_kind: row.source_kind,
        source_locator: row.source_locator,
        collected_timestamp_ms: row.collected_timestamp_ms,
        sequence_id: row.sequence_id,
        payload_content_hash: format!("sha256:{computed_hash}"),
        normalized_payload_path: row.normalized_payload_path,
        normalized_payload_json,
        normalized_payload_hash: format!("sha256:{computed_hash}"),
        raw_evidence_hashes_json: serde_json::to_string(&normalize_hashes(
            row.raw_evidence_hashes,
        )?)
        .map_err(|err| integrity(format!("failed to serialize raw evidence hashes: {err}")))?,
        freshness_window_ms: row.freshness_window_ms,
        freshness_deadline_ms: row.freshness_deadline_ms,
        degradation_state: row.degradation_state,
        retention_class: row.retention_class,
        parent_event_ids_json: serialize_parent_event_ids(&row.parent_event_ids)?,
        metadata_json: canonical_metadata_json(row.metadata)?,
    };
    entry.validate_typed_record()?;
    Ok(entry)
}

fn validate_export_row(row: &ShadowEvidenceJournalExportRow) -> StorageResult<()> {
    require_non_empty("bead_id", &row.bead_id)?;
    require_non_empty("event_kind", &row.event_kind)?;
    require_non_empty("source_kind", &row.source_kind)?;
    require_non_empty("source_locator", &row.source_locator)?;
    if row.sequence_id != row.journal_event_id {
        return Err(integrity(
            "exported `sequence_id` must match `journal_event_id`",
        ));
    }
    if row.freshness_deadline_ms
        != row
            .collected_timestamp_ms
            .checked_add(row.freshness_window_ms)
            .ok_or_else(|| integrity("freshness deadline overflow"))?
    {
        return Err(integrity(
            "exported freshness deadline does not match collection time + freshness window",
        ));
    }
    Ok(())
}

fn validate_append_seed(seed: &ShadowEvidenceJournalAppend) -> StorageResult<()> {
    require_non_empty("bead_id", &seed.bead_id)?;
    require_allowed(
        "event_kind",
        &seed.event_kind,
        &["source_snapshot", "advisory_event", "replay_checkpoint"],
    )?;
    require_non_empty("source_kind", &seed.source_kind)?;
    require_non_empty("source_locator", &seed.source_locator)?;
    if seed.collected_timestamp_ms < 0 {
        return Err(integrity(format!(
            "collected_timestamp_ms must be non-negative, got {}",
            seed.collected_timestamp_ms
        )));
    }
    normalize_sha256(&seed.payload_content_hash)?;
    if let Some(path) = &seed.normalized_payload_path {
        require_repo_relative_path("normalized_payload_path", path)?;
    }
    if seed.freshness_window_ms < 0 {
        return Err(integrity(format!(
            "freshness_window_ms must be non-negative, got {}",
            seed.freshness_window_ms
        )));
    }
    require_allowed(
        "degradation_state",
        &seed.degradation_state,
        &["confirmed", "degraded", "blocked", "contaminated"],
    )?;
    require_allowed(
        "retention_class",
        &seed.retention_class,
        &["windowed", "checkpoint", "audit"],
    )?;
    validate_parent_ids(
        &seed.event_kind,
        &seed.retention_class,
        &seed.parent_event_ids,
    )?;
    normalize_hashes(seed.raw_evidence_hashes.clone())?;
    ensure_metadata_object(&seed.metadata)?;
    ensure_canonical_payload_shape(&seed.normalized_payload)?;
    Ok(())
}

fn validate_parent_links(
    entry: &ShadowEvidenceJournalEntry,
    known_sequence_ids: &BTreeSet<i64>,
) -> StorageResult<()> {
    for parent_id in parse_parent_event_ids(&entry.parent_event_ids_json)? {
        if !known_sequence_ids.contains(&parent_id) {
            return Err(integrity(format!(
                "parent event {} does not exist for journal row {}",
                parent_id, entry.journal_event_id
            )));
        }
    }
    Ok(())
}

fn validate_parent_ids(
    event_kind: &str,
    retention_class: &str,
    parent_event_ids: &[i64],
) -> StorageResult<()> {
    if parent_event_ids.len() > MAX_PARENT_EVENT_LINKS {
        return Err(integrity(format!(
            "parent_event_ids exceeds cap of {MAX_PARENT_EVENT_LINKS}"
        )));
    }
    if event_kind == "source_snapshot" && !parent_event_ids.is_empty() {
        return Err(integrity(
            "source_snapshot append rows must not include parent_event_ids",
        ));
    }
    if event_kind != "source_snapshot" && parent_event_ids.is_empty() {
        return Err(integrity(
            "derived append rows must include parent_event_ids",
        ));
    }
    if event_kind == "replay_checkpoint" && retention_class != "checkpoint" {
        return Err(integrity(
            "replay_checkpoint rows must use checkpoint retention",
        ));
    }
    if event_kind != "replay_checkpoint" && retention_class == "checkpoint" {
        return Err(integrity(
            "only replay_checkpoint rows may use checkpoint retention",
        ));
    }
    let mut previous = None;
    for parent_id in parent_event_ids {
        if *parent_id < 0 {
            return Err(integrity(format!(
                "parent_event_id must be non-negative, got {parent_id}"
            )));
        }
        if let Some(previous) = previous
            && *parent_id <= previous
        {
            return Err(integrity(
                "parent_event_ids must be strictly ascending without duplicates",
            ));
        }
        previous = Some(*parent_id);
    }
    Ok(())
}

fn retained_by_floor(entry: &ShadowEvidenceJournalEntry, floor: Option<i64>) -> bool {
    let Some(floor) = floor else {
        return true;
    };
    entry.sequence_id >= floor || matches!(entry.retention_class.as_str(), "checkpoint" | "audit")
}

fn existing_sequence_ids<S>(storage: &mut S, context: &EventContext) -> StorageResult<BTreeSet<i64>>
where
    S: StorageAdapter,
{
    Ok(read_all_events(storage, context)?
        .into_iter()
        .map(|row| row.sequence_id)
        .collect())
}

fn parse_parent_event_ids(input: &str) -> StorageResult<Vec<i64>> {
    serde_json::from_str(input)
        .map_err(|err| integrity(format!("failed to parse parent event ids: {err}")))
}

fn parse_hash_array(input: &str) -> StorageResult<Vec<String>> {
    let hashes: Vec<String> = serde_json::from_str(input)
        .map_err(|err| integrity(format!("failed to parse raw evidence hashes: {err}")))?;
    normalize_hashes(hashes)
}

fn serialize_parent_event_ids(parent_event_ids: &[i64]) -> StorageResult<String> {
    let mut previous = None;
    for parent_id in parent_event_ids {
        if *parent_id < 0 {
            return Err(integrity(format!(
                "parent_event_id must be non-negative, got {parent_id}"
            )));
        }
        if let Some(previous) = previous
            && *parent_id <= previous
        {
            return Err(integrity(
                "parent_event_ids must be strictly ascending without duplicates",
            ));
        }
        previous = Some(*parent_id);
    }
    serde_json::to_string(parent_event_ids)
        .map_err(|err| integrity(format!("failed to serialize parent event ids: {err}")))
}

fn normalize_hashes(mut hashes: Vec<String>) -> StorageResult<Vec<String>> {
    if hashes.is_empty() {
        return Err(integrity(
            "raw_evidence_hashes must preserve at least one source digest",
        ));
    }
    for hash in &mut hashes {
        *hash = format!("sha256:{}", normalize_sha256(hash)?);
    }
    hashes.sort();
    hashes.dedup();
    if hashes.len() > MAX_PARENT_EVENT_LINKS {
        return Err(integrity(format!(
            "raw_evidence_hashes exceeds cap of {MAX_PARENT_EVENT_LINKS}"
        )));
    }
    Ok(hashes)
}

fn normalize_sha256(value: &str) -> StorageResult<String> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() == 64 && digest.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        Ok(digest.to_ascii_lowercase())
    } else {
        Err(integrity(format!(
            "expected 64-hex SHA-256 digest, got `{value}`"
        )))
    }
}

fn require_non_empty(field: &str, value: &str) -> StorageResult<()> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(integrity(format!(
            "`{field}` must be non-empty and NUL-free"
        )));
    }
    Ok(())
}

fn require_allowed(field: &str, value: &str, allowed: &[&str]) -> StorageResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(integrity(format!(
            "`{field}` value `{value}` is not one of {}",
            allowed.join(", ")
        )))
    }
}

fn require_repo_relative_path(field: &str, value: &str) -> StorageResult<()> {
    require_non_empty(field, value)?;
    if value.contains('\\') || value.contains('\0') {
        return Err(integrity(format!(
            "`{field}` must be a canonical repo-relative path"
        )));
    }
    let path = std::path::Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(integrity(format!(
            "`{field}` must not contain absolute or relative traversal components"
        )));
    }
    Ok(())
}

fn ensure_metadata_object(metadata: &Value) -> StorageResult<()> {
    let Some(object) = metadata.as_object() else {
        return Err(integrity("metadata must be a JSON object"));
    };
    if object.contains_key("raw_evidence_hashes") {
        return Err(integrity(
            "metadata must not shadow the dedicated raw_evidence_hashes field",
        ));
    }
    Ok(())
}

fn ensure_canonical_payload_shape(payload: &Value) -> StorageResult<()> {
    if payload.is_null() || !(payload.is_object() || payload.is_array()) {
        return Err(integrity(
            "normalized_payload must be a JSON object or array",
        ));
    }
    let payload_json = canonical_json_string(payload)?;
    if payload_json.len() > MAX_NORMALIZED_PAYLOAD_BYTES {
        return Err(integrity(format!(
            "normalized payload exceeds byte cap of {MAX_NORMALIZED_PAYLOAD_BYTES}"
        )));
    }
    Ok(())
}

fn canonical_metadata_json(metadata: Value) -> StorageResult<String> {
    ensure_metadata_object(&metadata)?;
    let metadata_json = canonical_json_string(&metadata)?;
    Ok(metadata_json)
}

fn canonical_json_string(value: &Value) -> StorageResult<String> {
    serde_json::to_string(&canonicalize_json(value))
        .map_err(|err| integrity(format!("failed to serialize canonical JSON: {err}")))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = Map::new();
            for (key, value) in map.iter().collect::<BTreeMap<_, _>>() {
                ordered.insert(key.clone(), canonicalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

fn parse_json_value(input: &str, field: &str) -> StorageResult<Value> {
    serde_json::from_str(input).map_err(|err| integrity(format!("failed to parse {field}: {err}")))
}

fn validated_payload_from_entry(entry: &ShadowEvidenceJournalEntry) -> StorageResult<Value> {
    let normalized_payload =
        parse_json_value(&entry.normalized_payload_json, "normalized_payload_json")?;
    let normalized_payload_json = canonical_json_string(&normalized_payload)?;
    let computed_hash = sha256_hex(normalized_payload_json.as_bytes());
    let payload_hash = normalize_sha256(&entry.payload_content_hash)?;
    let normalized_hash = normalize_sha256(&entry.normalized_payload_hash)?;
    if payload_hash != computed_hash || normalized_hash != computed_hash {
        return Err(integrity(format!(
            "stored payload hash mismatch for journal event {}",
            entry.journal_event_id
        )));
    }
    Ok(normalized_payload)
}

fn validate_stored_journal_rows(rows: &[ShadowEvidenceJournalEntry]) -> StorageResult<()> {
    let mut seen_sequence_ids = BTreeSet::new();
    for row in rows {
        validated_payload_from_entry(row)?;
        validate_parent_links(row, &seen_sequence_ids)?;
        if !seen_sequence_ids.insert(row.sequence_id) {
            return Err(integrity(format!(
                "duplicate journal sequence id {}",
                row.sequence_id
            )));
        }
    }
    Ok(())
}

fn validate_stored_journal_rows_against(
    rows: &[ShadowEvidenceJournalEntry],
    known_sequence_ids: &BTreeSet<i64>,
) -> StorageResult<()> {
    let mut seen_sequence_ids = BTreeSet::new();
    for row in rows {
        validated_payload_from_entry(row)?;
        validate_parent_links(row, known_sequence_ids)?;
        if !seen_sequence_ids.insert(row.sequence_id) {
            return Err(integrity(format!(
                "duplicate journal sequence id {}",
                row.sequence_id
            )));
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn entry_order(
    a: &ShadowEvidenceJournalEntry,
    b: &ShadowEvidenceJournalEntry,
) -> std::cmp::Ordering {
    a.sequence_id
        .cmp(&b.sequence_id)
        .then(a.journal_event_id.cmp(&b.journal_event_id))
        .then(a.source_locator.cmp(&b.source_locator))
}

fn integrity(detail: impl Into<String>) -> StorageError {
    StorageError::IntegrityViolation {
        store: crate::storage_adapter::StoreKind::ShadowEvidenceJournal,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_adapter::InMemoryStorageAdapter;
    use serde_json::json;

    fn ctx() -> EventContext {
        EventContext::new("trace-shadow", "decision-shadow", "policy-shadow").expect("ctx")
    }

    fn source_seed() -> ShadowEvidenceJournalAppend {
        let payload = json!({
            "schema_version": "franken-engine.shadow-source.v1",
            "beads": [{"id": "bd-ready", "status": "ready"}],
        });
        let payload_hash = format!(
            "sha256:{}",
            sha256_hex(canonical_json_string(&payload).unwrap().as_bytes())
        );
        ShadowEvidenceJournalAppend {
            bead_id: "bd-djejh.2".to_string(),
            event_kind: "source_snapshot".to_string(),
            source_kind: "br_queue_snapshot_json".to_string(),
            source_locator: "br ready --json".to_string(),
            collected_timestamp_ms: 1_700_000_000_000,
            payload_content_hash: payload_hash,
            normalized_payload_path: Some("artifacts/shadow/br_queue_snapshot.json".to_string()),
            normalized_payload: payload,
            freshness_window_ms: 30_000,
            degradation_state: "confirmed".to_string(),
            retention_class: "windowed".to_string(),
            parent_event_ids: vec![],
            raw_evidence_hashes: vec![
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ],
            metadata: json!({"source_id": "br_queue_snapshot_json"}),
        }
    }

    fn advisory_seed(parent_event_id: i64) -> ShadowEvidenceJournalAppend {
        let payload = json!({
            "schema_version": "franken-engine.shadow-advisory.v1",
            "recommendation": "preserve_remote_capacity",
        });
        let payload_hash = format!(
            "sha256:{}",
            sha256_hex(canonical_json_string(&payload).unwrap().as_bytes())
        );
        ShadowEvidenceJournalAppend {
            bead_id: "bd-djejh.2".to_string(),
            event_kind: "advisory_event".to_string(),
            source_kind: "recommendation_bundle".to_string(),
            source_locator: "shadow://recommendation_bundle".to_string(),
            collected_timestamp_ms: 1_700_000_000_500,
            payload_content_hash: payload_hash,
            normalized_payload_path: None,
            normalized_payload: payload,
            freshness_window_ms: 60_000,
            degradation_state: "degraded".to_string(),
            retention_class: "audit".to_string(),
            parent_event_ids: vec![parent_event_id],
            raw_evidence_hashes: vec![
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            ],
            metadata: json!({"reason": "agent_mail_read_only"}),
        }
    }

    fn checkpoint_seed(parent_event_id: i64) -> ShadowEvidenceJournalAppend {
        let payload = json!({
            "schema_version": "franken-engine.shadow-checkpoint.v1",
            "checkpoint": "replay-floor-1",
        });
        let payload_hash = format!(
            "sha256:{}",
            sha256_hex(canonical_json_string(&payload).unwrap().as_bytes())
        );
        ShadowEvidenceJournalAppend {
            bead_id: "bd-djejh.2".to_string(),
            event_kind: "replay_checkpoint".to_string(),
            source_kind: "shadow_status_report".to_string(),
            source_locator: "shadow://checkpoint/replay-floor-1".to_string(),
            collected_timestamp_ms: 1_700_000_001_000,
            payload_content_hash: payload_hash,
            normalized_payload_path: None,
            normalized_payload: payload,
            freshness_window_ms: 120_000,
            degradation_state: "confirmed".to_string(),
            retention_class: "checkpoint".to_string(),
            parent_event_ids: vec![parent_event_id],
            raw_evidence_hashes: vec![
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            ],
            metadata: json!({"checkpoint_kind": "retention_floor"}),
        }
    }

    #[test]
    fn append_read_export_import_round_trips_deterministically() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let source = append_journal_events(&mut adapter, &[source_seed()], &context)
            .expect("source append should succeed");
        let advisory = append_journal_events(
            &mut adapter,
            &[advisory_seed(source[0].journal_event_id)],
            &context,
        )
        .expect("advisory append should succeed");
        let checkpoint = append_journal_events(
            &mut adapter,
            &[checkpoint_seed(advisory[0].journal_event_id)],
            &context,
        )
        .expect("checkpoint append should succeed");

        let rows = read_all_events(&mut adapter, &context).expect("journal should read");
        assert_eq!(
            rows.iter().map(|row| row.sequence_id).collect::<Vec<_>>(),
            vec![
                source[0].sequence_id,
                advisory[0].sequence_id,
                checkpoint[0].sequence_id
            ]
        );

        let export = export_journal(&mut adapter, None, &context).expect("journal exports");
        let mut replay_adapter = InMemoryStorageAdapter::new();
        let imported = import_journal_export(&mut replay_adapter, &export, &context)
            .expect("journal import should succeed");
        let replay_rows =
            read_all_events(&mut replay_adapter, &context).expect("replayed journal reads");

        assert_eq!(imported, replay_rows);
        assert_eq!(rows, replay_rows);
    }

    #[test]
    fn append_refuses_payload_hash_mismatch() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let mut seed = source_seed();
        seed.payload_content_hash =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let err = append_journal_events(&mut adapter, &[seed], &context)
            .expect_err("payload hash mismatch must fail closed");
        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(err.to_string().contains("payload_content_hash mismatch"));
    }

    #[test]
    fn export_preserves_checkpoints_below_retention_floor() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let source = append_journal_events(&mut adapter, &[source_seed()], &context)
            .expect("source append should succeed");
        let checkpoint = append_journal_events(
            &mut adapter,
            &[checkpoint_seed(source[0].journal_event_id)],
            &context,
        )
        .expect("checkpoint append should succeed");
        let later = append_journal_events(
            &mut adapter,
            &[advisory_seed(checkpoint[0].journal_event_id)],
            &context,
        )
        .expect("later append should succeed");

        let export = export_journal(&mut adapter, Some(later[0].sequence_id), &context)
            .expect("retention export should succeed");
        let kept = export
            .rows
            .iter()
            .map(|row| row.sequence_id)
            .collect::<Vec<_>>();
        assert_eq!(kept, vec![checkpoint[0].sequence_id, later[0].sequence_id]);
    }

    #[test]
    fn import_refuses_out_of_order_sequence_rows() {
        let mut export = ShadowEvidenceJournalExport {
            schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
            rows: Vec::new(),
        };
        let mut source = export_row_from_entry(append_to_entry(source_seed(), 1).unwrap()).unwrap();
        let mut advisory = export_row_from_entry(
            export_row_to_entry(
                export_row_from_entry(append_to_entry(advisory_seed(1), 2).unwrap()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        source.sequence_id = 2;
        source.journal_event_id = 2;
        advisory.sequence_id = 1;
        advisory.journal_event_id = 1;
        export.rows = vec![source, advisory];

        let mut adapter = InMemoryStorageAdapter::new();
        let err = import_journal_export(&mut adapter, &export, &ctx())
            .expect_err("out-of-order import must fail closed");
        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(
            err.to_string()
                .contains("strictly ascending by `sequence_id`")
        );
        assert!(
            read_all_events(&mut adapter, &ctx())
                .expect("failed import should leave readable storage")
                .is_empty(),
            "failed imports must not partially persist earlier rows"
        );
    }

    #[test]
    fn append_refuses_unknown_parent_links() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let err = append_journal_events(&mut adapter, &[advisory_seed(42)], &context)
            .expect_err("unknown parent links must fail closed");
        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(err.to_string().contains("parent event 42 does not exist"));
    }

    #[test]
    fn read_refuses_stored_payload_hash_mismatch() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let mut entry = append_to_entry(source_seed(), 0).expect("source entry should build");
        entry.normalized_payload_json = canonical_json_string(
            &json!({"schema_version": "franken-engine.shadow-source.v1", "beads": []}),
        )
        .expect("alternate payload should serialize");

        adapter
            .put_typed(&entry, &context)
            .expect("typed shape validation should allow the corrupted fixture");
        let err = read_all_events(&mut adapter, &context)
            .expect_err("stored content-hash mismatches must fail closed");

        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(
            err.to_string()
                .contains("stored payload hash mismatch for journal event 0")
        );
    }

    #[test]
    fn read_refuses_missing_stored_parent_link() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let entry = append_to_entry(advisory_seed(42), 100).expect("advisory entry should build");

        adapter
            .put_typed(&entry, &context)
            .expect("typed shape validation should allow the missing-parent fixture");
        let err =
            read_all_events(&mut adapter, &context).expect_err("missing stored parent must fail");

        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(
            err.to_string()
                .contains("parent event 42 does not exist for journal row 100")
        );
    }
}
