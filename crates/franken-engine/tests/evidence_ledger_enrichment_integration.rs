//! Enrichment integration tests for evidence_ledger.
//!
//! Covers gaps not addressed by the base integration test file:
//! serde roundtrips for graph/stitching sub-types, display uniqueness,
//! EvidenceGraphNodeKind/EdgeKind serde, ArtifactRecord builder pattern,
//! DecisionSemanticsAnnotations default/serde, render_stitching_summary
//! edge cases, EvidenceQuerySurfaceSnapshot by_decision, constants, and
//! StitchingArtifactContext defaults.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::evidence_ledger::{
    ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION, ArtifactLineageRecord, ArtifactRecord, CandidateAction,
    ChosenAction, Constraint, DECISION_SEMANTICS_LOG_SCHEMA_VERSION, DecisionSemanticsAnnotations,
    DecisionSemanticsRecord, DecisionType, EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION,
    EVIDENCE_LEDGER_STITCHING_BEAD_ID, EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION,
    EVIDENCE_LEDGER_STITCHING_COMPONENT, EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION,
    EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION, EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION,
    EvidenceEmitter, EvidenceEntry, EvidenceEntryBuilder, EvidenceGraphEdge, EvidenceGraphEdgeKind,
    EvidenceGraphNode, EvidenceGraphNodeKind, EvidenceLedgerGraph, EvidenceLedgerStitchingBundle,
    EvidenceQueryRecord, EvidenceQuerySurfaceSnapshot, InMemoryLedger, LedgerError,
    SchemaVersionExt, StitchingArtifactContext, StitchingStructuredLogEvent,
    StitchingTraceIdsArtifact, Witness, current_schema_version, render_stitching_summary,
};
use frankenengine_engine::hindsight_boundary_capture::{
    BoundaryCaptureRecord, BoundaryCaptureSession, BoundaryContext,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_entry_for_stitch(trace: &str, decision: &str, policy: &str) -> EvidenceEntry {
    EvidenceEntryBuilder::new(
        trace,
        decision,
        policy,
        SecurityEpoch::from_raw(1),
        DecisionType::SecurityAction,
    )
    .candidate(CandidateAction::new("sandbox", 100_000))
    .candidate(CandidateAction::filtered(
        "terminate",
        500_000,
        "too severe",
    ))
    .constraint(Constraint {
        constraint_id: "c1".to_string(),
        description: "rate limit".to_string(),
        active: true,
    })
    .witness(Witness {
        witness_id: "w1".to_string(),
        witness_type: "sensor".to_string(),
        value: "42".to_string(),
    })
    .chosen(ChosenAction {
        action_name: "sandbox".to_string(),
        expected_loss_millionths: 100_000,
        rationale: "lowest loss".to_string(),
    })
    .build()
    .expect("build entry")
}

fn make_boundary_records(trace: &str, decision: &str, policy: &str) -> Vec<BoundaryCaptureRecord> {
    let mut session = BoundaryCaptureSession::default_v1();
    let context = BoundaryContext::new(trace, decision, policy, "test-component", 64);
    let scheduling = session
        .capture_scheduling_decision(&context, "hot-lane", "task-1", "digest-1", None)
        .expect("capture scheduling");
    let override_rec = session
        .capture_controller_override(&context, "safety-router", "force-sandbox", "digest-2", None)
        .expect("capture override");
    vec![scheduling, override_rec]
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    assert!(!EVIDENCE_LEDGER_STITCHING_BEAD_ID.is_empty());
    assert!(!EVIDENCE_LEDGER_STITCHING_COMPONENT.is_empty());
    assert!(!EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION.is_empty());
    assert!(!DECISION_SEMANTICS_LOG_SCHEMA_VERSION.is_empty());
    assert!(!ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION.is_empty());
    assert!(!EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.is_empty());
    assert!(!EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION.is_empty());
    assert!(!EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_constants_have_franken_engine_prefix() {
    for c in [
        EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION,
        DECISION_SEMANTICS_LOG_SCHEMA_VERSION,
        ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION,
        EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION,
    ] {
        assert!(c.starts_with("franken-engine."), "missing prefix: {c}");
    }
}

#[test]
fn enrichment_schema_version_constants_all_unique() {
    let versions: BTreeSet<&str> = [
        EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION,
        DECISION_SEMANTICS_LOG_SCHEMA_VERSION,
        ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION,
        EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION,
        EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION,
    ]
    .into_iter()
    .collect();
    assert_eq!(versions.len(), 7);
}

// ---------------------------------------------------------------------------
// Display uniqueness for DecisionType
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_type_display_all_unique() {
    let types = [
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::EpochTransition,
        DecisionType::Revocation,
        DecisionType::ExtensionLifecycle,
        DecisionType::CapabilityDecision,
        DecisionType::ContractEvaluation,
        DecisionType::RemoteAuthorization,
    ];
    let displays: BTreeSet<String> = types.iter().map(|t| format!("{t}")).collect();
    assert_eq!(displays.len(), types.len());
}

// ---------------------------------------------------------------------------
// EvidenceGraphNodeKind serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_graph_node_kind_all_variants() {
    let kinds = [
        EvidenceGraphNodeKind::BoundaryCapture,
        EvidenceGraphNodeKind::DecisionEntry,
        EvidenceGraphNodeKind::Artifact,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: EvidenceGraphNodeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_graph_node_kind_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&EvidenceGraphNodeKind::BoundaryCapture).unwrap(),
        "\"boundary_capture\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceGraphNodeKind::DecisionEntry).unwrap(),
        "\"decision_entry\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceGraphNodeKind::Artifact).unwrap(),
        "\"artifact\""
    );
}

// ---------------------------------------------------------------------------
// EvidenceGraphEdgeKind serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_graph_edge_kind_all_variants() {
    let kinds = [
        EvidenceGraphEdgeKind::BoundaryInformsDecision,
        EvidenceGraphEdgeKind::DecisionProducesArtifact,
        EvidenceGraphEdgeKind::BoundarySupportsArtifact,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: EvidenceGraphEdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_graph_edge_kind_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&EvidenceGraphEdgeKind::BoundaryInformsDecision).unwrap(),
        "\"boundary_informs_decision\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceGraphEdgeKind::DecisionProducesArtifact).unwrap(),
        "\"decision_produces_artifact\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceGraphEdgeKind::BoundarySupportsArtifact).unwrap(),
        "\"boundary_supports_artifact\""
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrips for graph types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_evidence_graph_node_roundtrip() {
    let node = EvidenceGraphNode {
        node_id: "dnode-abc123".to_string(),
        node_kind: EvidenceGraphNodeKind::DecisionEntry,
        label: "sandbox".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: Some("decision-001".to_string()),
        policy_id: Some("policy-v1".to_string()),
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("decision_type".to_string(), "security_action".to_string());
            m
        },
    };
    let json = serde_json::to_string(&node).unwrap();
    let restored: EvidenceGraphNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

#[test]
fn enrichment_serde_evidence_graph_node_no_optional_fields() {
    let node = EvidenceGraphNode {
        node_id: "bnode-xyz".to_string(),
        node_kind: EvidenceGraphNodeKind::BoundaryCapture,
        label: "clock_read".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: None,
        policy_id: None,
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&node).unwrap();
    let restored: EvidenceGraphNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

#[test]
fn enrichment_serde_evidence_graph_edge_roundtrip() {
    let edge = EvidenceGraphEdge {
        edge_id: "edge-abc".to_string(),
        edge_kind: EvidenceGraphEdgeKind::BoundaryInformsDecision,
        from_node_id: "bnode-1".to_string(),
        to_node_id: "dnode-1".to_string(),
    };
    let json = serde_json::to_string(&edge).unwrap();
    let restored: EvidenceGraphEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, restored);
}

#[test]
fn enrichment_serde_evidence_ledger_graph_roundtrip() {
    let graph = EvidenceLedgerGraph {
        schema_version: EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        nodes: vec![EvidenceGraphNode {
            node_id: "dnode-1".to_string(),
            node_kind: EvidenceGraphNodeKind::DecisionEntry,
            label: "sandbox".to_string(),
            trace_id: "trace-001".to_string(),
            decision_id: Some("decision-001".to_string()),
            policy_id: Some("policy-v1".to_string()),
            metadata: BTreeMap::new(),
        }],
        edges: vec![],
    };
    let json = serde_json::to_string(&graph).unwrap();
    let restored: EvidenceLedgerGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, restored);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for decision semantics types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_decision_semantics_annotations_default() {
    let ann = DecisionSemanticsAnnotations::default();
    assert!(ann.confidence_tier.is_none());
    assert!(ann.fallback_reason.is_none());
    assert!(ann.regret_summary.is_none());
    assert!(ann.scope_limits.is_empty());
    assert!(ann.assumptions.is_empty());
    assert!(ann.linked_boundary_correlation_keys.is_empty());
}

#[test]
fn enrichment_serde_decision_semantics_annotations_roundtrip() {
    let mut ann = DecisionSemanticsAnnotations::default();
    ann.confidence_tier = Some("high".to_string());
    ann.fallback_reason = Some("primary unavailable".to_string());
    ann.regret_summary = Some("0.02 regret".to_string());
    ann.scope_limits = vec!["scope-a".to_string(), "scope-b".to_string()];
    ann.assumptions.insert("k1".to_string(), "v1".to_string());
    ann.linked_boundary_correlation_keys = vec!["corr-1".to_string()];
    let json = serde_json::to_string(&ann).unwrap();
    let restored: DecisionSemanticsAnnotations = serde_json::from_str(&json).unwrap();
    assert_eq!(ann, restored);
}

#[test]
fn enrichment_serde_decision_semantics_record_roundtrip() {
    let record = DecisionSemanticsRecord {
        schema_version: DECISION_SEMANTICS_LOG_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        evidence_entry_id: "ev-abc123".to_string(),
        evidence_hash: "deadbeef".to_string(),
        decision_type: DecisionType::SecurityAction,
        chosen_action: "sandbox".to_string(),
        expected_loss_millionths: 100_000,
        filtered_candidates: vec!["terminate".to_string()],
        active_constraints: vec!["c1".to_string()],
        witness_ids: vec!["w1".to_string()],
        boundary_correlation_keys: vec!["corr-1".to_string()],
        confidence_tier: Some("high".to_string()),
        fallback_reason: None,
        regret_summary: None,
        scope_limits: Vec::new(),
        assumptions: BTreeMap::new(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: DecisionSemanticsRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for artifact types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_artifact_record_roundtrip() {
    let artifact = ArtifactRecord::new("art-1", "report", "/artifacts/report.json", "sha256:abc");
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: ArtifactRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

#[test]
fn enrichment_artifact_record_builder_pattern() {
    let artifact = ArtifactRecord::new("art-1", "report", "/artifacts/report.json", "sha256:abc")
        .supporting_boundary("corr-1")
        .supporting_boundary("corr-2");
    assert_eq!(artifact.supporting_boundary_correlation_keys.len(), 2);
    assert_eq!(artifact.supporting_boundary_correlation_keys[0], "corr-1");
    assert_eq!(artifact.supporting_boundary_correlation_keys[1], "corr-2");
}

#[test]
fn enrichment_artifact_record_new_has_empty_boundaries() {
    let artifact = ArtifactRecord::new("art-1", "report", "/path", "hash");
    assert!(artifact.supporting_boundary_correlation_keys.is_empty());
}

#[test]
fn enrichment_serde_artifact_lineage_record_roundtrip() {
    let record = ArtifactLineageRecord {
        schema_version: ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        artifact_id: "art-1".to_string(),
        artifact_kind: "report".to_string(),
        artifact_locator: "/artifacts/report.json".to_string(),
        artifact_hash: "sha256:abc".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        evidence_entry_id: "ev-abc".to_string(),
        boundary_correlation_keys: vec!["corr-1".to_string()],
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: ArtifactLineageRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for query surface types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_evidence_query_record_roundtrip() {
    let record = EvidenceQueryRecord {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        evidence_entry_id: "ev-abc".to_string(),
        chosen_action: "sandbox".to_string(),
        boundary_correlation_keys: vec!["corr-1".to_string()],
        artifact_ids: vec!["art-1".to_string()],
        witness_ids: vec!["w1".to_string()],
        confidence_tier: Some("high".to_string()),
        fallback_reason: None,
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: EvidenceQueryRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn enrichment_serde_evidence_query_surface_snapshot_roundtrip() {
    let snapshot = EvidenceQuerySurfaceSnapshot {
        schema_version: EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        decisions: vec![EvidenceQueryRecord {
            trace_id: "trace-001".to_string(),
            decision_id: "decision-001".to_string(),
            policy_id: "policy-v1".to_string(),
            evidence_entry_id: "ev-abc".to_string(),
            chosen_action: "sandbox".to_string(),
            boundary_correlation_keys: Vec::new(),
            artifact_ids: Vec::new(),
            witness_ids: Vec::new(),
            confidence_tier: None,
            fallback_reason: None,
        }],
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: EvidenceQuerySurfaceSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot, restored);
}

#[test]
fn enrichment_query_surface_by_decision_found() {
    let snapshot = EvidenceQuerySurfaceSnapshot {
        schema_version: EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        decisions: vec![
            EvidenceQueryRecord {
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                evidence_entry_id: "ev-1".to_string(),
                chosen_action: "sandbox".to_string(),
                boundary_correlation_keys: Vec::new(),
                artifact_ids: Vec::new(),
                witness_ids: Vec::new(),
                confidence_tier: None,
                fallback_reason: None,
            },
            EvidenceQueryRecord {
                trace_id: "t2".to_string(),
                decision_id: "d2".to_string(),
                policy_id: "p2".to_string(),
                evidence_entry_id: "ev-2".to_string(),
                chosen_action: "terminate".to_string(),
                boundary_correlation_keys: Vec::new(),
                artifact_ids: Vec::new(),
                witness_ids: Vec::new(),
                confidence_tier: None,
                fallback_reason: None,
            },
        ],
    };
    let found = snapshot.by_decision("d2").unwrap();
    assert_eq!(found.chosen_action, "terminate");
}

#[test]
fn enrichment_query_surface_by_decision_not_found() {
    let snapshot = EvidenceQuerySurfaceSnapshot {
        schema_version: EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        decisions: Vec::new(),
    };
    assert!(snapshot.by_decision("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// Serde roundtrips for stitching sub-types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_stitching_trace_ids_artifact_roundtrip() {
    let artifact = StitchingTraceIdsArtifact {
        schema_version: EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-001".to_string(), "trace-002".to_string()],
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: StitchingTraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

#[test]
fn enrichment_serde_stitching_structured_log_event_roundtrip() {
    let event = StitchingStructuredLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "evidence_ledger".to_string(),
        event: "stitch_complete".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        artifact_id: Some("art-1".to_string()),
        detail: "stitching completed in 3ms".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: StitchingStructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_serde_stitching_log_event_with_error() {
    let event = StitchingStructuredLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "evidence_ledger".to_string(),
        event: "stitch_failed".to_string(),
        outcome: "error".to_string(),
        error_code: Some("EL-001".to_string()),
        artifact_id: None,
        detail: "boundary mismatch".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: StitchingStructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// StitchingArtifactContext defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stitching_artifact_context_defaults() {
    let ctx = StitchingArtifactContext::new("/tmp/test-artifacts");
    assert_eq!(
        ctx.artifact_dir,
        std::path::PathBuf::from("/tmp/test-artifacts")
    );
    assert!(ctx.run_id.starts_with("run-"));
    assert!(ctx.run_id.contains(EVIDENCE_LEDGER_STITCHING_COMPONENT));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(!ctx.generated_at_utc.is_empty());
    assert_eq!(ctx.source_commit, "unknown");
    assert!(!ctx.toolchain.is_empty());
    assert!(ctx.command_invocation.contains("cargo"));
}

// ---------------------------------------------------------------------------
// Stitching bundle via stitch()
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stitch_produces_valid_bundle() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let artifact = ArtifactRecord::new("art-1", "report", "/artifacts/report.json", "sha256:abc")
        .supporting_boundary(boundaries[0].correlation_key.clone());
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[artifact], annotations)
            .unwrap();
    assert_eq!(
        bundle.schema_version,
        EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION
    );
    assert_eq!(bundle.bead_id, EVIDENCE_LEDGER_STITCHING_BEAD_ID);
    // Graph should have: 1 decision + 2 boundary + 1 artifact = 4 nodes.
    assert_eq!(bundle.evidence_ledger_graph.nodes.len(), 4);
    // Edges: 2 boundary→decision + 1 decision→artifact + 1 boundary→artifact = 4.
    assert!(bundle.evidence_ledger_graph.edges.len() >= 3);
    assert_eq!(bundle.decision_semantics_log.len(), 1);
    assert_eq!(bundle.artifact_lineage_index.len(), 1);
    assert_eq!(bundle.evidence_query_surface_snapshot.decisions.len(), 1);
}

#[test]
fn enrichment_stitch_serde_roundtrip() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], annotations).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: EvidenceLedgerStitchingBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

#[test]
fn enrichment_stitch_no_boundaries_no_artifacts() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    // Only the decision node.
    assert_eq!(bundle.evidence_ledger_graph.nodes.len(), 1);
    assert!(bundle.evidence_ledger_graph.edges.is_empty());
}

#[test]
fn enrichment_stitch_mismatched_boundary_identity_fails() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let bad_boundaries = make_boundary_records("trace-999", "decision-999", "policy-v99");
    let annotations = DecisionSemanticsAnnotations::default();
    let result = EvidenceLedgerStitchingBundle::stitch(&entry, &bad_boundaries, &[], annotations);
    assert!(result.is_err());
    if let Err(LedgerError::SchemaValidationFailed { reason }) = result {
        assert!(reason.contains("does not match"));
    }
}

#[test]
fn enrichment_stitch_empty_artifact_id_fails() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let bad_artifact = ArtifactRecord::new("", "report", "/path", "hash");
    let annotations = DecisionSemanticsAnnotations::default();
    let result = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[bad_artifact], annotations);
    assert!(result.is_err());
}

#[test]
fn enrichment_stitch_empty_artifact_kind_fails() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let bad_artifact = ArtifactRecord::new("art-1", "", "/path", "hash");
    let annotations = DecisionSemanticsAnnotations::default();
    let result = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[bad_artifact], annotations);
    assert!(result.is_err());
}

#[test]
fn enrichment_stitch_duplicate_artifact_ids_fails() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let art1 = ArtifactRecord::new("art-dup", "report", "/path1", "hash1");
    let art2 = ArtifactRecord::new("art-dup", "summary", "/path2", "hash2");
    let annotations = DecisionSemanticsAnnotations::default();
    let result = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[art1, art2], annotations);
    assert!(result.is_err());
}

#[test]
fn enrichment_stitch_with_annotations_populates_semantics() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let mut annotations = DecisionSemanticsAnnotations::default();
    annotations.confidence_tier = Some("high".to_string());
    annotations.fallback_reason = Some("fallback occurred".to_string());
    annotations.regret_summary = Some("0.01 regret".to_string());
    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], annotations).unwrap();
    let sem = &bundle.decision_semantics_log[0];
    assert_eq!(sem.confidence_tier.as_deref(), Some("high"));
    assert_eq!(sem.fallback_reason.as_deref(), Some("fallback occurred"));
    assert_eq!(sem.regret_summary.as_deref(), Some("0.01 regret"));
}

// ---------------------------------------------------------------------------
// render_stitching_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_stitching_summary_contains_key_sections() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let artifact = ArtifactRecord::new("art-1", "report", "/artifacts/report.json", "sha256:abc")
        .supporting_boundary(boundaries[0].correlation_key.clone());
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[artifact], annotations)
            .unwrap();
    let summary = render_stitching_summary(&bundle);
    assert!(summary.contains("Evidence Ledger Stitching Summary"));
    assert!(summary.contains("bead_id"));
    assert!(summary.contains("component"));
    assert!(summary.contains("trace_id"));
    assert!(summary.contains("Query Surface"));
    assert!(summary.contains("Artifact Lineage"));
    assert!(summary.contains("sandbox"));
}

#[test]
fn enrichment_render_stitching_summary_no_artifacts() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let summary = render_stitching_summary(&bundle);
    assert!(summary.contains("stitched_artifacts: `0`"));
}

#[test]
fn enrichment_render_stitching_summary_with_confidence_and_fallback() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let mut annotations = DecisionSemanticsAnnotations::default();
    annotations.confidence_tier = Some("medium".to_string());
    annotations.fallback_reason = Some("timeout".to_string());
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let summary = render_stitching_summary(&bundle);
    assert!(summary.contains("medium"));
    assert!(summary.contains("timeout"));
}

#[test]
fn enrichment_render_stitching_summary_none_defaults() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let summary = render_stitching_summary(&bundle);
    assert!(summary.contains("unspecified"));
    assert!(summary.contains("none"));
}

// ---------------------------------------------------------------------------
// LedgerError display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ledger_error_display_all_unique() {
    let errors = [
        LedgerError::MissingChosenAction,
        LedgerError::SchemaValidationFailed {
            reason: "test".to_string(),
        },
        LedgerError::IncompatibleSchema {
            entry_version: current_schema_version(),
            reader_version: current_schema_version(),
        },
        LedgerError::DuplicateEntryId {
            entry_id: "ev-test".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// SchemaVersionExt
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_ext_major_minor() {
    let v = current_schema_version();
    assert_eq!(v.major_val(), 1);
    assert_eq!(v.minor_val(), 0);
}

// ---------------------------------------------------------------------------
// InMemoryLedger additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_in_memory_ledger_by_decision_type_all_variants() {
    let mut ledger = InMemoryLedger::new();
    let types = [
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::EpochTransition,
        DecisionType::Revocation,
        DecisionType::ExtensionLifecycle,
        DecisionType::CapabilityDecision,
        DecisionType::ContractEvaluation,
        DecisionType::RemoteAuthorization,
    ];
    for (i, dt) in types.iter().enumerate() {
        let entry = EvidenceEntryBuilder::new(
            &format!("trace-{i}"),
            &format!("decision-{i}"),
            "policy-v1",
            SecurityEpoch::from_raw(1),
            *dt,
        )
        .chosen(ChosenAction {
            action_name: "default".to_string(),
            expected_loss_millionths: 0,
            rationale: "test".to_string(),
        })
        .build()
        .unwrap();
        ledger.emit(entry).unwrap();
    }
    assert_eq!(ledger.len(), 8);
    for dt in &types {
        let filtered = ledger.by_decision_type(*dt);
        assert_eq!(filtered.len(), 1);
    }
}

#[test]
fn enrichment_in_memory_ledger_is_empty_tracks() {
    let mut ledger = InMemoryLedger::new();
    assert!(ledger.is_empty());
    let entry = EvidenceEntryBuilder::new(
        "trace",
        "decision",
        "policy",
        SecurityEpoch::from_raw(1),
        DecisionType::SecurityAction,
    )
    .chosen(ChosenAction {
        action_name: "a".to_string(),
        expected_loss_millionths: 0,
        rationale: "r".to_string(),
    })
    .build()
    .unwrap();
    ledger.emit(entry).unwrap();
    assert!(!ledger.is_empty());
}

// ---------------------------------------------------------------------------
// EvidenceEntry builder: filtered candidates in semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stitch_filtered_candidates_in_semantics() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let sem = &bundle.decision_semantics_log[0];
    // "terminate" was filtered in make_entry_for_stitch.
    assert!(sem.filtered_candidates.contains(&"terminate".to_string()));
    // "sandbox" was not filtered.
    assert!(!sem.filtered_candidates.contains(&"sandbox".to_string()));
}

#[test]
fn enrichment_stitch_active_constraints_in_semantics() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let sem = &bundle.decision_semantics_log[0];
    assert!(sem.active_constraints.contains(&"c1".to_string()));
}

#[test]
fn enrichment_stitch_witness_ids_in_semantics() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let annotations = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &[], &[], annotations).unwrap();
    let sem = &bundle.decision_semantics_log[0];
    assert!(sem.witness_ids.contains(&"w1".to_string()));
}

// ---------------------------------------------------------------------------
// Graph node ID determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_graph_node_ids_deterministic() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let ann = DecisionSemanticsAnnotations::default();
    let b1 = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann.clone()).unwrap();
    let b2 = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann).unwrap();
    assert_eq!(
        b1.evidence_ledger_graph.nodes.len(),
        b2.evidence_ledger_graph.nodes.len(),
    );
    for (n1, n2) in b1
        .evidence_ledger_graph
        .nodes
        .iter()
        .zip(b2.evidence_ledger_graph.nodes.iter())
    {
        assert_eq!(n1.node_id, n2.node_id);
    }
}

#[test]
fn enrichment_graph_edge_ids_deterministic() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let ann = DecisionSemanticsAnnotations::default();
    let b1 = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann.clone()).unwrap();
    let b2 = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann).unwrap();
    for (e1, e2) in b1
        .evidence_ledger_graph
        .edges
        .iter()
        .zip(b2.evidence_ledger_graph.edges.iter())
    {
        assert_eq!(e1.edge_id, e2.edge_id);
    }
}

// ---------------------------------------------------------------------------
// Graph node kinds per position
// ---------------------------------------------------------------------------

#[test]
fn enrichment_graph_first_node_is_decision() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let ann = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann).unwrap();
    assert_eq!(
        bundle.evidence_ledger_graph.nodes[0].node_kind,
        EvidenceGraphNodeKind::DecisionEntry,
    );
}

#[test]
fn enrichment_graph_boundary_nodes_are_boundary_capture() {
    let entry = make_entry_for_stitch("trace-001", "decision-001", "policy-v1");
    let boundaries = make_boundary_records("trace-001", "decision-001", "policy-v1");
    let ann = DecisionSemanticsAnnotations::default();
    let bundle = EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &[], ann).unwrap();
    // Nodes 1 and 2 should be BoundaryCapture.
    for node in &bundle.evidence_ledger_graph.nodes[1..] {
        assert_eq!(node.node_kind, EvidenceGraphNodeKind::BoundaryCapture);
    }
}
