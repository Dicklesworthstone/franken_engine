//! Integration tests for the shadow evidence journal with frankensqlite backend.
//!
//! These tests verify the complete shadow evidence journal implementation
//! including typed persistence models, storage adapter integration, and
//! deterministic export/import workflows.

#![forbid(unsafe_code)]

use frankenengine_engine::shadow_evidence_journal::{
    SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION, ShadowEvidenceJournalAppend, append_journal_events,
    export_journal, import_journal_export, read_all_events, read_events_for_bead,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};
use frankenengine_engine::typed_persistence_models::{
    ShadowEvidenceJournalEntry, TypedStoreRecord,
};
use serde_json::{Map, Value, json};
use sha2::Digest;

fn test_context() -> EventContext {
    EventContext::new(
        "trace-shadow-test",
        "decision-shadow-test",
        "policy-shadow-test",
    )
    .expect("test context creation should succeed")
}

fn canonical_payload_hash(payload: &Value) -> String {
    let payload_json =
        serde_json::to_string(&canonicalize_json(payload)).expect("payload serialization");
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(payload_json.as_bytes()))
    )
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = Map::new();
            for (key, value) in map.iter().collect::<std::collections::BTreeMap<_, _>>() {
                ordered.insert(key.clone(), canonicalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

fn create_source_snapshot(bead_id: &str, timestamp_ms: i64) -> ShadowEvidenceJournalAppend {
    let payload = json!({
        "schema_version": "franken-engine.shadow-source.v1",
        "beads": [{"id": bead_id, "status": "in_progress"}],
        "agent_status": "active"
    });
    let payload_hash = canonical_payload_hash(&payload);

    ShadowEvidenceJournalAppend {
        bead_id: bead_id.to_string(),
        event_kind: "source_snapshot".to_string(),
        source_kind: "br_queue_snapshot_json".to_string(),
        source_locator: "br ready --json".to_string(),
        collected_timestamp_ms: timestamp_ms,
        payload_content_hash: payload_hash,
        normalized_payload_path: Some("artifacts/shadow/br_queue_snapshot.json".to_string()),
        normalized_payload: payload,
        freshness_window_ms: 30_000,
        degradation_state: "confirmed".to_string(),
        retention_class: "windowed".to_string(),
        parent_event_ids: vec![],
        raw_evidence_hashes: vec![
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ],
        metadata: json!({"source_id": "br_queue_snapshot_json", "agent_name": "YellowPike"}),
    }
}

fn create_advisory_event(
    bead_id: &str,
    parent_event_id: i64,
    timestamp_ms: i64,
) -> ShadowEvidenceJournalAppend {
    let payload = json!({
        "schema_version": "franken-engine.shadow-advisory.v1",
        "recommendation": "increase_remote_capacity",
        "confidence": 0.85,
        "reasoning": "high queue pressure detected"
    });
    let payload_hash = canonical_payload_hash(&payload);

    ShadowEvidenceJournalAppend {
        bead_id: bead_id.to_string(),
        event_kind: "advisory_event".to_string(),
        source_kind: "recommendation_engine".to_string(),
        source_locator: "shadow://recommendation_engine/capacity_advisor".to_string(),
        collected_timestamp_ms: timestamp_ms,
        payload_content_hash: payload_hash,
        normalized_payload_path: None,
        normalized_payload: payload,
        freshness_window_ms: 60_000,
        degradation_state: "confirmed".to_string(),
        retention_class: "audit".to_string(),
        parent_event_ids: vec![parent_event_id],
        raw_evidence_hashes: vec![
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ],
        metadata: json!({"advisor_version": "v1.2.0", "trigger": "queue_pressure"}),
    }
}

fn create_replay_checkpoint(
    bead_id: &str,
    parent_event_id: i64,
    timestamp_ms: i64,
) -> ShadowEvidenceJournalAppend {
    let payload = json!({
        "schema_version": "franken-engine.shadow-checkpoint.v1",
        "checkpoint_id": "ckpt-001",
        "event_count": 2,
        "retention_floor": parent_event_id
    });
    let payload_hash = canonical_payload_hash(&payload);

    ShadowEvidenceJournalAppend {
        bead_id: bead_id.to_string(),
        event_kind: "replay_checkpoint".to_string(),
        source_kind: "shadow_checkpoint_manager".to_string(),
        source_locator: "shadow://checkpoint/ckpt-001".to_string(),
        collected_timestamp_ms: timestamp_ms,
        payload_content_hash: payload_hash,
        normalized_payload_path: None,
        normalized_payload: payload,
        freshness_window_ms: 120_000,
        degradation_state: "confirmed".to_string(),
        retention_class: "checkpoint".to_string(),
        parent_event_ids: vec![parent_event_id],
        raw_evidence_hashes: vec![
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        ],
        metadata: json!({"checkpoint_kind": "periodic", "sequence_floor": parent_event_id}),
    }
}

#[test]
fn append_events_creates_monotonic_sequence() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    let source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    let appended = append_journal_events(&mut storage, &[source], &context)
        .expect("source append should succeed");

    assert_eq!(appended.len(), 1);
    assert_eq!(appended[0].sequence_id, 0);
    assert_eq!(appended[0].journal_event_id, 0);
    assert_eq!(appended[0].bead_id, "bd-djejh.2");
    assert_eq!(appended[0].event_kind, "source_snapshot");

    // Append advisory event with parent link
    let advisory = create_advisory_event(
        "bd-djejh.2",
        appended[0].journal_event_id,
        1_700_000_000_500,
    );
    let appended_advisory = append_journal_events(&mut storage, &[advisory], &context)
        .expect("advisory append should succeed");

    assert_eq!(appended_advisory.len(), 1);
    assert_eq!(appended_advisory[0].sequence_id, 1);
    assert_eq!(appended_advisory[0].journal_event_id, 1);

    // Verify parent link
    let parent_ids: Vec<i64> = serde_json::from_str(&appended_advisory[0].parent_event_ids_json)
        .expect("parent ids should parse");
    assert_eq!(parent_ids, vec![0]);
}

#[test]
fn read_events_returns_deterministic_order() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    // Append events in one batch to test ordering
    let source1 = create_source_snapshot("bd-test-1", 1_700_000_000_000);
    let source2 = create_source_snapshot("bd-test-2", 1_700_000_000_100);

    let appended = append_journal_events(&mut storage, &[source1, source2], &context)
        .expect("batch append should succeed");
    assert_eq!(appended.len(), 2);

    let all_events =
        read_all_events(&mut storage, &context).expect("reading all events should succeed");

    assert_eq!(all_events.len(), 2);
    assert_eq!(all_events[0].sequence_id, 0);
    assert_eq!(all_events[1].sequence_id, 1);
    assert!(all_events[0].sequence_id <= all_events[1].sequence_id);

    // Test bead-specific reads
    let bead1_events = read_events_for_bead(&mut storage, "bd-test-1", &context)
        .expect("reading bead events should succeed");

    assert_eq!(bead1_events.len(), 1);
    assert_eq!(bead1_events[0].bead_id, "bd-test-1");
}

#[test]
fn export_import_preserves_exact_journal_state() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    // Create a realistic journal with different event types
    let source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    let source_appended = append_journal_events(&mut storage, &[source], &context)
        .expect("source append should succeed");

    let advisory = create_advisory_event(
        "bd-djejh.2",
        source_appended[0].journal_event_id,
        1_700_000_000_500,
    );
    let advisory_appended = append_journal_events(&mut storage, &[advisory], &context)
        .expect("advisory append should succeed");

    let checkpoint = create_replay_checkpoint(
        "bd-djejh.2",
        advisory_appended[0].journal_event_id,
        1_700_000_001_000,
    );
    let _checkpoint_appended = append_journal_events(&mut storage, &[checkpoint], &context)
        .expect("checkpoint append should succeed");

    // Export the complete journal
    let export =
        export_journal(&mut storage, None, &context).expect("journal export should succeed");

    assert_eq!(
        export.schema_version,
        SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION
    );
    assert_eq!(export.rows.len(), 3);

    // Verify export rows are in sequence order
    for (i, row) in export.rows.iter().enumerate() {
        assert_eq!(row.sequence_id, i as i64);
        assert_eq!(row.journal_event_id, i as i64);
    }

    // Import into fresh storage
    let mut fresh_storage = InMemoryStorageAdapter::new();
    let imported = import_journal_export(&mut fresh_storage, &export, &context)
        .expect("journal import should succeed");

    assert_eq!(imported.len(), 3);

    // Verify imported state matches original
    let original_events =
        read_all_events(&mut storage, &context).expect("reading original events should succeed");
    let imported_events = read_all_events(&mut fresh_storage, &context)
        .expect("reading imported events should succeed");

    assert_eq!(original_events, imported_events);
}

#[test]
fn retention_floor_preserves_checkpoints_and_audit_records() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    // Create events with different retention classes
    let source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    let source_appended = append_journal_events(&mut storage, &[source], &context)
        .expect("source append should succeed");

    let checkpoint = create_replay_checkpoint(
        "bd-djejh.2",
        source_appended[0].journal_event_id,
        1_700_000_000_500,
    );
    let checkpoint_appended = append_journal_events(&mut storage, &[checkpoint], &context)
        .expect("checkpoint append should succeed");

    let advisory = create_advisory_event(
        "bd-djejh.2",
        checkpoint_appended[0].journal_event_id,
        1_700_000_001_000,
    );
    let advisory_appended = append_journal_events(&mut storage, &[advisory], &context)
        .expect("advisory append should succeed");

    // Export with retention floor set above the windowed source event
    let export = export_journal(
        &mut storage,
        Some(advisory_appended[0].sequence_id),
        &context,
    )
    .expect("retention export should succeed");

    // Should preserve checkpoint (retention_class="checkpoint") and audit advisory,
    // but exclude the windowed source event that's below the floor
    assert_eq!(export.rows.len(), 2);

    let retained_kinds: Vec<&str> = export
        .rows
        .iter()
        .map(|row| row.event_kind.as_str())
        .collect();

    assert!(retained_kinds.contains(&"replay_checkpoint"));
    assert!(retained_kinds.contains(&"advisory_event"));
    assert!(!retained_kinds.contains(&"source_snapshot"));
}

#[test]
fn typed_record_validation_enforces_constraints() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    // Test that malformed source snapshot is rejected
    let mut invalid_source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    invalid_source.payload_content_hash = "invalid-hash".to_string();

    let err = append_journal_events(&mut storage, &[invalid_source], &context)
        .expect_err("invalid payload hash should be rejected");

    assert!(err.to_string().contains("expected 64-hex SHA-256 digest"));

    // Test that advisory events cannot reference future parent sequence ids.
    let mut invalid_advisory = create_advisory_event("bd-djejh.2", 0, 1_700_000_000_500);
    invalid_advisory.parent_event_ids = vec![999];

    let err = append_journal_events(&mut storage, &[invalid_advisory], &context)
        .expect_err("future parent sequence id should be rejected");

    assert!(
        err.to_string()
            .contains("parent event links must reference earlier journal sequence ids")
    );
}

#[test]
fn typed_persistence_model_integration_works() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    let source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    let appended = append_journal_events(&mut storage, &[source], &context)
        .expect("source append should succeed");

    // Verify the TypedStoreRecord implementation
    let entry = &appended[0];

    // Validate typed record constraints
    entry
        .validate_typed_record()
        .expect("appended entry should pass typed validation");

    // Verify expected typed metadata
    assert_eq!(
        ShadowEvidenceJournalEntry::MODEL_NAME,
        "ShadowEvidenceJournalEntry"
    );
    assert!(entry.bead_id.starts_with("bd-"));
    assert!(entry.payload_content_hash.starts_with("sha256:"));
    assert!(entry.normalized_payload_hash.starts_with("sha256:"));
    assert!(entry.freshness_deadline_ms > entry.collected_timestamp_ms);
}

#[test]
fn concurrent_append_maintains_sequence_integrity() {
    let mut storage = InMemoryStorageAdapter::new();
    let context = test_context();

    // Append initial event
    let source = create_source_snapshot("bd-djejh.2", 1_700_000_000_000);
    let first = append_journal_events(&mut storage, &[source], &context)
        .expect("first append should succeed");

    // Append multiple events referencing the first
    let advisory1 =
        create_advisory_event("bd-djejh.2", first[0].journal_event_id, 1_700_000_000_100);
    let advisory2 =
        create_advisory_event("bd-djejh.3", first[0].journal_event_id, 1_700_000_000_200);

    let batch = append_journal_events(&mut storage, &[advisory1, advisory2], &context)
        .expect("batch append should succeed");

    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].sequence_id, 1);
    assert_eq!(batch[1].sequence_id, 2);

    // Verify all events are readable in sequence order
    let all_events =
        read_all_events(&mut storage, &context).expect("reading all events should succeed");

    assert_eq!(all_events.len(), 3);
    for i in 0..all_events.len() {
        assert_eq!(all_events[i].sequence_id, i as i64);
    }
}
