//! Integration tests for FrankenTUI Similar Incidents panel (NN.3).
//!
//! Tests the Wasserstein distance-based similar incidents finder functionality
//! for the frankentui operator interface.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    SimilarIncidentsView, SimilarIncidentEntry, SimilarityAnalysisMetadata,
    find_similar_incidents, FrankentuiViewPayload, AdapterStream, AdapterEnvelope, UpdateKind,
};
use frankenengine_engine::persistence_homology::{
    PersistenceDiagram, PersistenceBar, FilterValue, FeatureRepresentative, ComputationMetadata,
};
use frankenengine_engine::causation_graph_schema::{InfluenceWeight, NodeId};
use frankenengine_engine::hash_tiers::{ContentHash, AuthenticityHash};

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

/// Create a test persistence diagram with given bars.
fn create_test_diagram(bars: Vec<(u64, Option<u64>, u8)>) -> PersistenceDiagram {
    let persistence_bars: Vec<PersistenceBar> = bars
        .into_iter()
        .enumerate()
        .map(|(i, (birth, death, dimension))| PersistenceBar {
            birth: FilterValue { millionths: birth },
            death: death.map(|d| FilterValue { millionths: d }),
            dimension,
            representative: FeatureRepresentative::NodeSet(vec![
                NodeId { id: format!("node-{}", i) }
            ]),
            feature_weight: InfluenceWeight::from_millionths(500_000),
        })
        .collect();

    PersistenceDiagram {
        schema_version: "franken-engine.persistence-diagram.v1".to_string(),
        bars: persistence_bars,
        source_graph_hash: ContentHash::compute(b"test-graph"),
        content_hash: ContentHash::compute(b"test-diagram"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"test-diagram", b"test-key"),
        computation_metadata: ComputationMetadata {
            algorithm_version: "test-v1".to_string(),
            computation_time_ms: 100,
            node_count: 10,
            edge_count: 15,
            filter_type: frankenengine_engine::persistence_homology::FilterType::Distance,
        },
    }
}

/// Create a test incident corpus.
fn create_test_corpus() -> Vec<(String, String, PersistenceDiagram)> {
    vec![
        (
            "incident-1".to_string(),
            "auth-failure".to_string(),
            create_test_diagram(vec![
                (100_000, Some(500_000), 0), // Component birth at 0.1, death at 0.5
                (200_000, Some(800_000), 1), // Cycle birth at 0.2, death at 0.8
            ]),
        ),
        (
            "incident-2".to_string(),
            "permission-escalation".to_string(),
            create_test_diagram(vec![
                (150_000, Some(450_000), 0), // Similar component, slightly different timing
                (250_000, Some(750_000), 1), // Similar cycle
            ]),
        ),
        (
            "incident-3".to_string(),
            "network-timeout".to_string(),
            create_test_diagram(vec![
                (300_000, Some(900_000), 0), // Different component timing
                (400_000, None, 1),          // Infinite cycle (very different)
            ]),
        ),
        (
            "incident-4".to_string(),
            "memory-corruption".to_string(),
            create_test_diagram(vec![
                (50_000, Some(300_000), 0),  // Early component
                (100_000, Some(600_000), 0), // Second component
                (250_000, Some(700_000), 1), // Cycle
            ]),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_find_similar_incidents_basic() {
    let reference_diagram = create_test_diagram(vec![
        (120_000, Some(480_000), 0), // Component similar to incident-1 and incident-2
        (220_000, Some(780_000), 1), // Cycle similar to incident-1 and incident-2
    ]);

    let corpus = create_test_corpus();
    let result = find_similar_incidents(
        &reference_diagram,
        "reference-incident".to_string(),
        "test-scenario".to_string(),
        &corpus,
        3, // Max 3 results
        2, // L2 distance
    );

    assert!(result.is_ok());
    let view = result.unwrap();

    assert_eq!(view.reference_incident_id, "reference-incident");
    assert_eq!(view.reference_scenario, "test-scenario");
    assert_eq!(view.analysis_metadata.candidates_analyzed, 4);
    assert_eq!(view.analysis_metadata.corpus_size, 4);
    assert_eq!(view.analysis_metadata.distance_order, 2);
    assert_eq!(view.analysis_metadata.algorithm_version, "NN.3-v1.0");

    // Should have at most 3 results
    assert!(view.similar_incidents.len() <= 3);

    // Results should be sorted by distance (ascending)
    for i in 1..view.similar_incidents.len() {
        assert!(
            view.similar_incidents[i - 1].wasserstein_distance_millionths
                <= view.similar_incidents[i].wasserstein_distance_millionths
        );
    }

    // Should not include self-reference
    assert!(view
        .similar_incidents
        .iter()
        .all(|incident| incident.incident_id != "reference-incident"));
}

#[test]
fn test_find_similar_incidents_identical_reference() {
    // Use incident-1 from corpus as reference to test self-exclusion
    let corpus = create_test_corpus();
    let reference_diagram = corpus[0].2.clone();

    let result = find_similar_incidents(
        &reference_diagram,
        "incident-1".to_string(), // Same as first corpus entry
        "auth-failure".to_string(),
        &corpus,
        5,
        2,
    );

    assert!(result.is_ok());
    let view = result.unwrap();

    // Should exclude self from results
    assert!(view
        .similar_incidents
        .iter()
        .all(|incident| incident.incident_id != "incident-1"));

    // Should have corpus size - 1 results (excluding self)
    assert_eq!(view.similar_incidents.len(), 3);
}

#[test]
fn test_similar_incidents_view_methods() {
    let similar_incidents = vec![
        SimilarIncidentEntry {
            incident_id: "incident-1".to_string(),
            scenario_name: "auth-failure".to_string(),
            wasserstein_distance_millionths: 50_000, // Very similar
            similarity_score_millionths: 950_000,
            shared_features_count: 2,
            replay_bundle_ref: "bundle-incident-1".to_string(),
            incident_timestamp_unix_ms: 1_000,
        },
        SimilarIncidentEntry {
            incident_id: "incident-2".to_string(),
            scenario_name: "permission-escalation".to_string(),
            wasserstein_distance_millionths: 200_000, // Moderately similar
            similarity_score_millionths: 800_000,
            shared_features_count: 1,
            replay_bundle_ref: "bundle-incident-2".to_string(),
            incident_timestamp_unix_ms: 2_000,
        },
    ];

    let metadata = SimilarityAnalysisMetadata {
        candidates_analyzed: 10,
        corpus_size: 10,
        distance_order: 2,
        algorithm_version: "NN.3-v1.0".to_string(),
        computation_time_ms: 150,
    };

    let view = SimilarIncidentsView::new(
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        similar_incidents,
        metadata,
        1_000_000,
    );

    // Test top_k_similar method
    let top_1 = view.top_k_similar(1);
    assert_eq!(top_1.len(), 1);
    assert_eq!(top_1[0].incident_id, "incident-1");

    let top_5 = view.top_k_similar(5);
    assert_eq!(top_5.len(), 2); // Limited by available incidents

    // Test has_highly_similar_incidents method
    assert!(view.has_highly_similar_incidents(100_000)); // threshold 0.1
    assert!(!view.has_highly_similar_incidents(10_000)); // threshold 0.01
}

#[test]
fn test_similar_incidents_view_serialization() {
    let similar_incidents = vec![SimilarIncidentEntry {
        incident_id: "incident-1".to_string(),
        scenario_name: "auth-failure".to_string(),
        wasserstein_distance_millionths: 50_000,
        similarity_score_millionths: 950_000,
        shared_features_count: 2,
        replay_bundle_ref: "bundle-incident-1".to_string(),
        incident_timestamp_unix_ms: 1_000,
    }];

    let metadata = SimilarityAnalysisMetadata {
        candidates_analyzed: 5,
        corpus_size: 5,
        distance_order: 2,
        algorithm_version: "NN.3-v1.0".to_string(),
        computation_time_ms: 100,
    };

    let view = SimilarIncidentsView::new(
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        similar_incidents,
        metadata,
        1_000_000,
    );

    // Test serialization/deserialization
    let json = serde_json::to_string(&view).expect("serialize should succeed");
    let deserialized: SimilarIncidentsView =
        serde_json::from_str(&json).expect("deserialize should succeed");

    assert_eq!(view, deserialized);
}

#[test]
fn test_frankentui_adapter_envelope_with_similar_incidents() {
    let similar_incidents = vec![];
    let metadata = SimilarityAnalysisMetadata {
        candidates_analyzed: 0,
        corpus_size: 0,
        distance_order: 2,
        algorithm_version: "NN.3-v1.0".to_string(),
        computation_time_ms: 50,
    };

    let view = SimilarIncidentsView::new(
        "ref-incident".to_string(),
        "empty-scenario".to_string(),
        similar_incidents,
        metadata,
        1_000_000,
    );

    let payload = FrankentuiViewPayload::SimilarIncidents(view);

    let envelope = AdapterEnvelope::new(
        "trace-123",
        1_000_000,
        AdapterStream::SimilarIncidents,
        UpdateKind::Snapshot,
        payload,
    );

    // Test envelope serialization
    let encoded = envelope.encode_json().expect("encode should succeed");
    let json_str = String::from_utf8(encoded).expect("valid UTF-8");

    // Should contain the similar incidents payload
    assert!(json_str.contains("similar_incidents"));
    assert!(json_str.contains("SimilarIncidents"));
    assert!(json_str.contains("ref-incident"));
    assert!(json_str.contains("empty-scenario"));
}

#[test]
fn test_find_similar_incidents_empty_corpus() {
    let reference_diagram = create_test_diagram(vec![(100_000, Some(500_000), 0)]);
    let empty_corpus = vec![];

    let result = find_similar_incidents(
        &reference_diagram,
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        &empty_corpus,
        5,
        2,
    );

    assert!(result.is_ok());
    let view = result.unwrap();

    assert_eq!(view.similar_incidents.len(), 0);
    assert_eq!(view.analysis_metadata.candidates_analyzed, 0);
    assert_eq!(view.analysis_metadata.corpus_size, 0);
}

#[test]
fn test_find_similar_incidents_different_distance_orders() {
    let reference_diagram = create_test_diagram(vec![(100_000, Some(500_000), 0)]);
    let corpus = create_test_corpus();

    // Test L1 distance
    let result_l1 = find_similar_incidents(
        &reference_diagram,
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        &corpus,
        5,
        1,
    );

    // Test L2 distance
    let result_l2 = find_similar_incidents(
        &reference_diagram,
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        &corpus,
        5,
        2,
    );

    assert!(result_l1.is_ok());
    assert!(result_l2.is_ok());

    let view_l1 = result_l1.unwrap();
    let view_l2 = result_l2.unwrap();

    assert_eq!(view_l1.analysis_metadata.distance_order, 1);
    assert_eq!(view_l2.analysis_metadata.distance_order, 2);

    // Both should find the same incidents but potentially in different order
    assert_eq!(view_l1.similar_incidents.len(), view_l2.similar_incidents.len());
}

#[test]
fn test_similar_incidents_computation_metadata() {
    let reference_diagram = create_test_diagram(vec![(100_000, Some(500_000), 0)]);
    let corpus = create_test_corpus();

    let start = std::time::Instant::now();
    let result = find_similar_incidents(
        &reference_diagram,
        "ref-incident".to_string(),
        "test-scenario".to_string(),
        &corpus,
        5,
        2,
    );
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    let view = result.unwrap();

    // Verify metadata is reasonable
    assert_eq!(view.analysis_metadata.candidates_analyzed, 4);
    assert_eq!(view.analysis_metadata.corpus_size, 4);
    assert_eq!(view.analysis_metadata.distance_order, 2);
    assert_eq!(view.analysis_metadata.algorithm_version, "NN.3-v1.0");

    // Computation time should be reasonable (less than total elapsed time)
    assert!(view.analysis_metadata.computation_time_ms <= elapsed.as_millis() as u64);

    // Generated timestamp should be recent
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(view.generated_at_unix_ms <= now);
    assert!(view.generated_at_unix_ms > now - 10_000); // Within last 10 seconds
}