//! Deterministic fixtures for shadow daemon replay verification testing.
//!
//! This module provides test fixtures for various journal states including
//! healthy, degraded, contaminated, and stale-source scenarios to validate
//! replay functionality and drift detection capabilities.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::hash_tiers::ContentHash;
use crate::shadow_evidence_journal::{
    ShadowEvidenceJournalExport, ShadowEvidenceJournalExportRow,
    SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION,
};

/// Creates a deterministic healthy journal fixture for replay testing.
pub fn create_healthy_journal_fixture() -> ShadowEvidenceJournalExport {
    let base_timestamp = 1704067200000; // 2024-01-01 00:00:00 UTC

    let mut rows = Vec::new();
    let mut event_id_counter = 1000i64;

    // Create a sequence of healthy events with proper parent links
    for i in 0..5 {
        let journal_event_id = event_id_counter + i as i64;
        let parent_event_ids = if i > 0 {
            vec![journal_event_id - 1]
        } else {
            vec![]
        };

        let payload = create_healthy_event_payload(i);
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_hash_content = ContentHash::compute(&payload_bytes);
        let payload_hash = hex_encode(payload_hash_content.as_bytes());

        let mut metadata_map = BTreeMap::new();
        metadata_map.insert("event_index".to_string(), Value::Number(i.into()));
        metadata_map.insert("journal_state".to_string(), Value::String("healthy".to_string()));
        metadata_map.insert(
            "expected_decision_hash".to_string(),
            Value::String(compute_expected_decision_hash(&payload)),
        );

        let row = ShadowEvidenceJournalExportRow {
            journal_event_id,
            bead_id: format!("healthy_bead_{}", i),
            event_kind: "healthy_event".to_string(),
            source_kind: "test_fixture".to_string(),
            source_locator: format!("fixture://healthy/event_{}", i),
            collected_timestamp_ms: base_timestamp + (i * 1000) as i64,
            sequence_id: journal_event_id,
            payload_content_hash: payload_hash.clone(),
            normalized_payload_path: None,
            normalized_payload: payload,
            normalized_payload_hash: payload_hash,
            raw_evidence_hashes: vec![],
            freshness_window_ms: 300_000, // 5 minutes
            freshness_deadline_ms: base_timestamp + (i * 1000) as i64 + 300_000,
            degradation_state: "healthy".to_string(),
            retention_class: "normal".to_string(),
            parent_event_ids,
            metadata: Value::Object(metadata_map.into_iter().collect()),
        };

        rows.push(row);
    }

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

/// Creates a deterministic degraded journal fixture with performance issues.
pub fn create_degraded_journal_fixture() -> ShadowEvidenceJournalExport {
    let base_timestamp = 1704067200000;

    let mut rows = Vec::new();
    let mut event_id_counter = 2000i64;

    // Create events with degraded performance characteristics
    for i in 0..4 {
        let journal_event_id = event_id_counter + i as i64;
        let parent_event_ids = if i > 0 {
            vec![journal_event_id - 1]
        } else {
            vec![]
        };

        let payload = create_degraded_event_payload(i);
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_hash_content = ContentHash::compute(&payload_bytes);
        let payload_hash = hex_encode(payload_hash_content.as_bytes());

        let mut metadata_map = BTreeMap::new();
        metadata_map.insert("event_index".to_string(), Value::Number(i.into()));
        metadata_map.insert("journal_state".to_string(), Value::String("degraded".to_string()));
        metadata_map.insert("performance_warning".to_string(), Value::String("high_latency".to_string()));
        metadata_map.insert(
            "expected_decision_hash".to_string(),
            Value::String(compute_expected_decision_hash(&payload)),
        );

        let row = ShadowEvidenceJournalExportRow {
            journal_event_id,
            bead_id: format!("degraded_bead_{}", i),
            event_kind: "degraded_event".to_string(),
            source_kind: "test_fixture".to_string(),
            source_locator: format!("fixture://degraded/event_{}", i),
            collected_timestamp_ms: base_timestamp + (i * 5000) as i64, // Longer intervals indicate degradation
            sequence_id: journal_event_id,
            payload_content_hash: payload_hash.clone(),
            normalized_payload_path: None,
            normalized_payload: payload,
            normalized_payload_hash: payload_hash,
            raw_evidence_hashes: vec![],
            freshness_window_ms: 600_000, // Extended window due to degradation
            freshness_deadline_ms: base_timestamp + (i * 5000) as i64 + 600_000,
            degradation_state: "degraded".to_string(),
            retention_class: "extended".to_string(),
            parent_event_ids,
            metadata: Value::Object(metadata_map.into_iter().collect()),
        };

        rows.push(row);
    }

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

/// Creates a deterministic contaminated journal fixture with corruption.
pub fn create_contaminated_journal_fixture() -> ShadowEvidenceJournalExport {
    let base_timestamp = 1704067200000;

    let mut rows = Vec::new();
    let mut event_id_counter = 3000i64;

    // Create events with intentional contamination for drift testing
    for i in 0..3 {
        let journal_event_id = event_id_counter + i as i64;
        let parent_event_ids = if i > 0 {
            vec![journal_event_id - 1]
        } else {
            vec![]
        };

        let payload = create_contaminated_event_payload(i);
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Intentionally corrupt the payload hash for drift detection
        let correct_hash = ContentHash::compute(&payload_bytes);
        let correct_hex = hex_encode(correct_hash.as_bytes());

        // Create corrupted hash by modifying the hex string
        let mut corrupt_hex = correct_hex.clone();
        if let Some(first_char) = corrupt_hex.chars().next() {
            let corrupted_char = if first_char == '0' { '1' } else { '0' };
            corrupt_hex.replace_range(0..1, &corrupted_char.to_string());
        }

        let mut metadata_map = BTreeMap::new();
        metadata_map.insert("event_index".to_string(), Value::Number(i.into()));
        metadata_map.insert("journal_state".to_string(), Value::String("contaminated".to_string()));
        metadata_map.insert("contamination_type".to_string(), Value::String("payload_hash_corruption".to_string()));
        metadata_map.insert(
            "expected_decision_hash".to_string(),
            Value::String(compute_expected_decision_hash(&payload)),
        );

        let row = ShadowEvidenceJournalExportRow {
            journal_event_id,
            bead_id: format!("contaminated_bead_{}", i),
            event_kind: "contaminated_event".to_string(),
            source_kind: "test_fixture".to_string(),
            source_locator: format!("fixture://contaminated/event_{}", i),
            collected_timestamp_ms: base_timestamp + (i * 2000) as i64,
            sequence_id: journal_event_id,
            payload_content_hash: correct_hex.clone(), // Store correct hash in content_hash
            normalized_payload_path: None,
            normalized_payload: payload,
            normalized_payload_hash: corrupt_hex, // Use corrupted hash here for drift detection
            raw_evidence_hashes: vec![],
            freshness_window_ms: 300_000,
            freshness_deadline_ms: base_timestamp + (i * 2000) as i64 + 300_000,
            degradation_state: "contaminated".to_string(),
            retention_class: "quarantine".to_string(),
            parent_event_ids,
            metadata: Value::Object(metadata_map.into_iter().collect()),
        };

        rows.push(row);
    }

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

/// Creates a deterministic stale-source journal fixture.
pub fn create_stale_source_journal_fixture() -> ShadowEvidenceJournalExport {
    let base_timestamp = 1704067200000 - 86_400_000; // 1 day ago

    let mut rows = Vec::new();
    let mut event_id_counter = 4000i64;

    // Create events from stale sources that should trigger freshness warnings
    for i in 0..6 {
        let journal_event_id = event_id_counter + i as i64;
        let parent_event_ids = if i > 0 {
            vec![journal_event_id - 1]
        } else {
            vec![]
        };

        let payload = create_stale_event_payload(i);
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_hash_content = ContentHash::compute(&payload_bytes);
        let payload_hash = hex_encode(payload_hash_content.as_bytes());

        let mut metadata_map = BTreeMap::new();
        metadata_map.insert("event_index".to_string(), Value::Number(i.into()));
        metadata_map.insert("journal_state".to_string(), Value::String("stale_source".to_string()));
        metadata_map.insert("source_age_hours".to_string(), Value::Number(24.into()));
        metadata_map.insert(
            "expected_decision_hash".to_string(),
            Value::String(compute_expected_decision_hash(&payload)),
        );

        let row = ShadowEvidenceJournalExportRow {
            journal_event_id,
            bead_id: format!("stale_bead_{}", i),
            event_kind: "stale_event".to_string(),
            source_kind: "test_fixture".to_string(),
            source_locator: format!("fixture://stale/event_{}", i),
            collected_timestamp_ms: base_timestamp + (i * 1000) as i64,
            sequence_id: journal_event_id,
            payload_content_hash: payload_hash.clone(),
            normalized_payload_path: None,
            normalized_payload: payload,
            normalized_payload_hash: payload_hash,
            raw_evidence_hashes: vec![],
            freshness_window_ms: 60_000, // Short window to trigger staleness
            freshness_deadline_ms: base_timestamp + (i * 1000) as i64 + 60_000,
            degradation_state: "stale".to_string(),
            retention_class: "archived".to_string(),
            parent_event_ids,
            metadata: Value::Object(metadata_map.into_iter().collect()),
        };

        rows.push(row);
    }

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

/// Creates a deterministic mixed-state journal for comprehensive drift testing.
pub fn create_mixed_state_journal_fixture() -> ShadowEvidenceJournalExport {
    let base_timestamp = 1704067200000;

    let mut rows = Vec::new();
    let mut event_id_counter = 5000i64;

    // Mix of healthy, degraded, and edge case events
    let states = vec![
        ("healthy", "normal"),
        ("degraded", "extended"),
        ("healthy", "normal"),
        ("stale", "archived"),
        ("degraded", "extended"),
    ];

    for (i, (state, retention)) in states.iter().enumerate() {
        let journal_event_id = event_id_counter + i as i64;
        let parent_event_ids = if i > 0 {
            vec![journal_event_id - 1]
        } else {
            vec![]
        };

        let payload = match *state {
            "healthy" => create_healthy_event_payload(i),
            "degraded" => create_degraded_event_payload(i),
            "stale" => create_stale_event_payload(i),
            _ => create_healthy_event_payload(i),
        };

        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_hash_content = ContentHash::compute(&payload_bytes);
        let payload_hash = hex_encode(payload_hash_content.as_bytes());

        let mut metadata_map = BTreeMap::new();
        metadata_map.insert("event_index".to_string(), Value::Number(i.into()));
        metadata_map.insert("journal_state".to_string(), Value::String(state.to_string()));
        metadata_map.insert("mixed_fixture".to_string(), Value::Bool(true));
        metadata_map.insert(
            "expected_decision_hash".to_string(),
            Value::String(compute_expected_decision_hash(&payload)),
        );

        let freshness_window_ms = match *state {
            "stale" => 60_000,
            "degraded" => 600_000,
            _ => 300_000,
        };

        let row = ShadowEvidenceJournalExportRow {
            journal_event_id,
            bead_id: format!("mixed_bead_{}_{}", i, state),
            event_kind: format!("{}_event", state),
            source_kind: "test_fixture".to_string(),
            source_locator: format!("fixture://mixed/event_{}_{}", i, state),
            collected_timestamp_ms: base_timestamp + (i * 1500) as i64,
            sequence_id: journal_event_id,
            payload_content_hash: payload_hash.clone(),
            normalized_payload_path: None,
            normalized_payload: payload,
            normalized_payload_hash: payload_hash,
            raw_evidence_hashes: vec![],
            freshness_window_ms,
            freshness_deadline_ms: base_timestamp + (i * 1500) as i64 + freshness_window_ms,
            degradation_state: state.to_string(),
            retention_class: retention.to_string(),
            parent_event_ids,
            metadata: Value::Object(metadata_map.into_iter().collect()),
        };

        rows.push(row);
    }

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

/// Helper function to create healthy event payload.
fn create_healthy_event_payload(index: usize) -> Value {
    json!({
        "event_type": "healthy_operation",
        "index": index,
        "operation_id": format!("healthy_op_{}", index),
        "resource_utilization": {
            "cpu_usage": 0.25,
            "memory_usage": 0.15,
            "disk_usage": 0.05
        },
        "latency_metrics": {
            "p50_ms": 12,
            "p95_ms": 28,
            "p99_ms": 45
        },
        "status": "success",
        "timestamp": format!("2024-01-01T00:00:{:02}Z", index),
        "checksum": format!("healthy_{}_checksum", index)
    })
}

/// Helper function to create degraded event payload.
fn create_degraded_event_payload(index: usize) -> Value {
    json!({
        "event_type": "degraded_operation",
        "index": index,
        "operation_id": format!("degraded_op_{}", index),
        "resource_utilization": {
            "cpu_usage": 0.85, // High CPU usage
            "memory_usage": 0.90, // High memory usage
            "disk_usage": 0.75 // High disk usage
        },
        "latency_metrics": {
            "p50_ms": 250, // Degraded latency
            "p95_ms": 1200,
            "p99_ms": 3400
        },
        "status": "degraded",
        "warnings": ["high_resource_usage", "elevated_latency"],
        "timestamp": format!("2024-01-01T00:00:{:02}Z", index * 5),
        "checksum": format!("degraded_{}_checksum", index)
    })
}

/// Helper function to create contaminated event payload.
fn create_contaminated_event_payload(index: usize) -> Value {
    json!({
        "event_type": "contaminated_operation",
        "index": index,
        "operation_id": format!("contaminated_op_{}", index),
        "resource_utilization": {
            "cpu_usage": -0.5, // Invalid negative value
            "memory_usage": null, // Missing required field
            "disk_usage": "invalid_type" // Wrong type
        },
        "latency_metrics": {
            "p50_ms": 15,
            "p95_ms": 32,
            "p99_ms": 48,
            "invalid_metric": "should_not_exist"
        },
        "status": "contaminated",
        "errors": ["data_corruption", "schema_violation"],
        "timestamp": format!("2024-01-01T00:00:{:02}Z", index * 2),
        "checksum": format!("contaminated_{}_CORRUPTED", index),
        "malformed_field": {"nested": {"too": {"deep": "value"}}}
    })
}

/// Helper function to create stale event payload.
fn create_stale_event_payload(index: usize) -> Value {
    json!({
        "event_type": "stale_operation",
        "index": index,
        "operation_id": format!("stale_op_{}", index),
        "resource_utilization": {
            "cpu_usage": 0.20,
            "memory_usage": 0.10,
            "disk_usage": 0.03
        },
        "latency_metrics": {
            "p50_ms": 10,
            "p95_ms": 25,
            "p99_ms": 40
        },
        "status": "stale",
        "source_timestamp": "2023-12-31T00:00:00Z", // Stale source
        "data_age_hours": 24,
        "timestamp": format!("2023-12-31T23:59:{:02}Z", index),
        "checksum": format!("stale_{}_checksum", index)
    })
}

/// Computes expected decision hash for replay verification.
fn compute_expected_decision_hash(payload: &Value) -> String {
    let decision_data = json!({
        "decision_type": "test_decision",
        "payload_summary": payload.get("operation_id").unwrap_or(&json!("unknown")),
        "status": payload.get("status").unwrap_or(&json!("unknown")),
        "deterministic_seed": "replay_fixture_v1"
    });

    let decision_bytes = serde_json::to_vec(&decision_data).unwrap();
    let hash = ContentHash::compute(&decision_bytes);
    hex_encode(hash.as_bytes())
}

/// Helper function to encode bytes as hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_journal_fixture() {
        let fixture = create_healthy_journal_fixture();

        assert_eq!(fixture.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION);
        assert_eq!(fixture.rows.len(), 5);

        // Verify proper parent linkage
        assert!(fixture.rows[0].parent_event_ids.is_empty());
        for i in 1..fixture.rows.len() {
            assert!(!fixture.rows[i].parent_event_ids.is_empty());
        }

        // Verify all events are in healthy state
        for row in &fixture.rows {
            assert_eq!(row.degradation_state, "healthy");
            assert_eq!(row.event_kind, "healthy_event");
        }
    }

    #[test]
    fn test_degraded_journal_fixture() {
        let fixture = create_degraded_journal_fixture();

        assert_eq!(fixture.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION);
        assert_eq!(fixture.rows.len(), 4);

        // Verify degraded characteristics
        for row in &fixture.rows {
            assert_eq!(row.degradation_state, "degraded");
            assert_eq!(row.retention_class, "extended");
            assert_eq!(row.freshness_window_ms, 600_000);
        }
    }

    #[test]
    fn test_contaminated_journal_fixture() {
        let fixture = create_contaminated_journal_fixture();

        assert_eq!(fixture.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION);
        assert_eq!(fixture.rows.len(), 3);

        // Verify contaminated characteristics
        for row in &fixture.rows {
            assert_eq!(row.degradation_state, "contaminated");
            assert_eq!(row.retention_class, "quarantine");

            // Verify that payload hash should be corrupted (different from computed hash)
            let payload_bytes = serde_json::to_vec(&row.normalized_payload).unwrap();
            let computed_hash = ContentHash::compute(&payload_bytes);
            let computed_hex = hex_encode(computed_hash.as_bytes());
            assert_ne!(row.normalized_payload_hash, computed_hex);
        }
    }

    #[test]
    fn test_stale_source_journal_fixture() {
        let fixture = create_stale_source_journal_fixture();

        assert_eq!(fixture.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION);
        assert_eq!(fixture.rows.len(), 6);

        // Verify stale characteristics
        for row in &fixture.rows {
            assert_eq!(row.degradation_state, "stale");
            assert_eq!(row.retention_class, "archived");
            assert_eq!(row.freshness_window_ms, 60_000);
        }
    }

    #[test]
    fn test_mixed_state_journal_fixture() {
        let fixture = create_mixed_state_journal_fixture();

        assert_eq!(fixture.schema_version, SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION);
        assert_eq!(fixture.rows.len(), 5);

        // Verify mixed states
        let states: Vec<&str> = fixture.rows.iter()
            .map(|r| r.degradation_state.as_str())
            .collect();
        assert_eq!(states, vec!["healthy", "degraded", "healthy", "stale", "degraded"]);
    }

    #[test]
    fn test_event_payload_structures() {
        let healthy = create_healthy_event_payload(0);
        assert_eq!(healthy["event_type"], "healthy_operation");
        assert_eq!(healthy["status"], "success");

        let degraded = create_degraded_event_payload(0);
        assert_eq!(degraded["event_type"], "degraded_operation");
        assert_eq!(degraded["status"], "degraded");

        let contaminated = create_contaminated_event_payload(0);
        assert_eq!(contaminated["event_type"], "contaminated_operation");
        assert_eq!(contaminated["status"], "contaminated");

        let stale = create_stale_event_payload(0);
        assert_eq!(stale["event_type"], "stale_operation");
        assert_eq!(stale["status"], "stale");
    }

    #[test]
    fn test_deterministic_hashing() {
        let payload1 = create_healthy_event_payload(0);
        let payload2 = create_healthy_event_payload(0);

        let hash1 = compute_expected_decision_hash(&payload1);
        let hash2 = compute_expected_decision_hash(&payload2);

        assert_eq!(hash1, hash2); // Should be deterministic
        assert_eq!(hash1.len(), 64); // SHA-256 hex string
    }

    #[test]
    fn test_parent_link_integrity() {
        let fixtures = vec![
            create_healthy_journal_fixture(),
            create_degraded_journal_fixture(),
            create_contaminated_journal_fixture(),
            create_stale_source_journal_fixture(),
            create_mixed_state_journal_fixture(),
        ];

        for fixture in fixtures {
            // First event should have no parent
            assert!(fixture.events[0].parent_id.is_none());

            // Subsequent events should link to previous events
            for i in 1..fixture.events.len() {
                assert!(fixture.events[i].parent_id.is_some());
                let parent_id = fixture.events[i].parent_id.as_ref().unwrap();
                let expected_parent_id = &fixture.events[i - 1].id;
                assert_eq!(parent_id, expected_parent_id);
            }
        }
    }
}