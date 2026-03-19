//! Enrichment integration tests for the `seqlock_candidate_inventory` module.
//!
//! Deep coverage of all public types, constants, enums, structs, functions,
//! serde round-trips, and the default_candidate_inventory builder.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::seqlock_candidate_inventory::{
    ArtifactContext, BASELINE_COMPARATOR_SCHEMA_VERSION, BEAD_ID, BaselineStrategy, COMPONENT,
    CandidateCounts, CandidateDisposition, CandidateInventoryEntry, FallbackReason,
    INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION, INVENTORY_SCHEMA_VERSION, IncumbentFallbackMatrixRow,
    ManifestArtifactReference, PREDECESSOR_BEAD_ID, READER_WRITER_CONTRACT_SCHEMA_VERSION,
    RETRY_BUDGET_POLICY_SCHEMA_VERSION, RETRY_SAFETY_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION,
    RetryBudgetPolicyRow, RetrySafetyMatrixRow, SeqlockCandidateInventoryArtifact,
    SeqlockReaderWriterContractRow, SnapshotBaselineComparatorRow, StructuredLogEvent, SurfaceArea,
    TRACE_IDS_SCHEMA_VERSION, TearingRisk, TraceIdsArtifact, WriteProfile,
    default_candidate_inventory, render_summary,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_bead_id_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrich_predecessor_bead_id_non_empty() {
    assert!(!PREDECESSOR_BEAD_ID.is_empty());
    assert!(PREDECESSOR_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrich_component_correct() {
    assert_eq!(COMPONENT, "seqlock_candidate_inventory");
}

#[test]
fn enrich_all_schema_versions_distinct() {
    let versions = [
        INVENTORY_SCHEMA_VERSION,
        RETRY_SAFETY_SCHEMA_VERSION,
        BASELINE_COMPARATOR_SCHEMA_VERSION,
        READER_WRITER_CONTRACT_SCHEMA_VERSION,
        RETRY_BUDGET_POLICY_SCHEMA_VERSION,
        INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<_> = versions.iter().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn enrich_all_schema_versions_start_with_franken_engine() {
    let versions = [
        INVENTORY_SCHEMA_VERSION,
        RETRY_SAFETY_SCHEMA_VERSION,
        BASELINE_COMPARATOR_SCHEMA_VERSION,
        READER_WRITER_CONTRACT_SCHEMA_VERSION,
        RETRY_BUDGET_POLICY_SCHEMA_VERSION,
        INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    for v in &versions {
        assert!(
            v.starts_with("franken-engine."),
            "version {v} missing prefix"
        );
    }
}

// ---------------------------------------------------------------------------
// CandidateDisposition — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_candidate_disposition_serde_all() {
    let variants = [
        CandidateDisposition::Accept,
        CandidateDisposition::Conditional,
        CandidateDisposition::Reject,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CandidateDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrich_candidate_disposition_ordering() {
    assert!(CandidateDisposition::Accept < CandidateDisposition::Conditional);
    assert!(CandidateDisposition::Conditional < CandidateDisposition::Reject);
}

// ---------------------------------------------------------------------------
// SurfaceArea — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_surface_area_serde_all() {
    let variants = [
        SurfaceArea::GovernanceState,
        SurfaceArea::OfflineArtifact,
        SurfaceArea::OperatorProjection,
        SurfaceArea::PolicyState,
        SurfaceArea::RuntimeMetadata,
        SurfaceArea::Telemetry,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SurfaceArea = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// BaselineStrategy — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_baseline_strategy_serde_all() {
    let variants = [
        BaselineStrategy::CloneSnapshot,
        BaselineStrategy::ExternalJoinProjection,
        BaselineStrategy::ImmutableValueObject,
        BaselineStrategy::MutableSnapshotSideEffect,
        BaselineStrategy::OfflineSummary,
        BaselineStrategy::QueryAppendOnly,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BaselineStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// TearingRisk — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_tearing_risk_serde_all() {
    let variants = [
        TearingRisk::None,
        TearingRisk::Low,
        TearingRisk::Medium,
        TearingRisk::High,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TearingRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrich_tearing_risk_ordering() {
    assert!(TearingRisk::None < TearingRisk::Low);
    assert!(TearingRisk::Low < TearingRisk::Medium);
    assert!(TearingRisk::Medium < TearingRisk::High);
}

// ---------------------------------------------------------------------------
// WriteProfile — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_write_profile_serde_all() {
    let variants = [
        WriteProfile::Rare,
        WriteProfile::Moderate,
        WriteProfile::Bursty,
        WriteProfile::HotPath,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: WriteProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// FallbackReason — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_reason_serde_all() {
    let variants = [
        FallbackReason::UnsupportedCandidate,
        FallbackReason::WriterActive,
        FallbackReason::RetryBudgetExhausted,
        FallbackReason::ExternalJoinBoundary,
        FallbackReason::ImmutableValueObject,
        FallbackReason::HotPathWritePressure,
        FallbackReason::NonRetrySafeRead,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CandidateInventoryEntry — construction and serde
// ---------------------------------------------------------------------------

fn make_entry() -> CandidateInventoryEntry {
    CandidateInventoryEntry {
        candidate_id: "test-candidate".to_string(),
        surface_name: "test_surface".to_string(),
        module_path: "crate::test_mod".to_string(),
        api_path: "TestMod::read".to_string(),
        surface_area: SurfaceArea::GovernanceState,
        baseline_path: "crate::test_mod::baseline".to_string(),
        incumbent_baseline: "Arc<RwLock<T>>".to_string(),
        baseline_strategy: BaselineStrategy::CloneSnapshot,
        disposition: CandidateDisposition::Accept,
        shared_mutable_state: true,
        read_side_effect_free: true,
        retry_safe_read: true,
        requires_atomic_multi_structure_view: false,
        requires_external_input_join: false,
        immutable_value_object: false,
        write_profile: WriteProfile::Rare,
        tearing_risk: TearingRisk::Low,
        classification_rationale: vec!["side-effect free reads".to_string()],
        exact_fallback_conditions: vec!["retry_budget_exhausted".to_string()],
        notes: vec![],
    }
}

#[test]
fn enrich_candidate_entry_construction() {
    let entry = make_entry();
    assert_eq!(entry.candidate_id, "test-candidate");
    assert_eq!(entry.disposition, CandidateDisposition::Accept);
    assert!(entry.read_side_effect_free);
}

#[test]
fn enrich_candidate_entry_serde() {
    let entry = make_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let back: CandidateInventoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrich_candidate_entry_clone() {
    let entry = make_entry();
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ---------------------------------------------------------------------------
// CandidateCounts — Default and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_candidate_counts_default_zeros() {
    let counts = CandidateCounts::default();
    assert_eq!(counts.accept, 0);
    assert_eq!(counts.conditional, 0);
    assert_eq!(counts.reject, 0);
}

#[test]
fn enrich_candidate_counts_serde() {
    let counts = CandidateCounts {
        accept: 3,
        conditional: 2,
        reject: 1,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let back: CandidateCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(counts, back);
}

// ---------------------------------------------------------------------------
// RetrySafetyMatrixRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_retry_safety_row_serde() {
    let row = RetrySafetyMatrixRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        read_side_effect_free: true,
        retry_safe_read: true,
        requires_atomic_multi_structure_view: false,
        requires_external_input_join: false,
        write_profile: WriteProfile::Rare,
        tearing_risk: TearingRisk::None,
        exact_fallback_conditions: vec!["retry_budget_exhausted".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: RetrySafetyMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// SnapshotBaselineComparatorRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_baseline_comparator_row_serde() {
    let row = SnapshotBaselineComparatorRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        baseline_path: "crate::test".to_string(),
        baseline_strategy: BaselineStrategy::CloneSnapshot,
        incumbent_baseline: "RwLock".to_string(),
        proposed_strategy: "seqlock_optimistic_read".to_string(),
        expected_read_side_benefit: "lower contention".to_string(),
        migration_risk: TearingRisk::Low,
        exact_fallback_conditions: vec![],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: SnapshotBaselineComparatorRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// SeqlockReaderWriterContractRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_rw_contract_row_serde() {
    let row = SeqlockReaderWriterContractRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        optimistic_reads_enabled: true,
        writer_exclusive: true,
        reader_retry_safe: true,
        publication_boundary: "full_snapshot".to_string(),
        fallback_target: "RwLock".to_string(),
        telemetry_fields: vec!["retry_count".to_string(), "fallback_count".to_string()],
        contract_notes: vec!["note1".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: SeqlockReaderWriterContractRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicyRow (sci module) — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_retry_budget_policy_row_serde() {
    let row = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 3,
        fallback_target: "RwLock".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Rare,
        policy_rationale: vec!["bounded retry".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// IncumbentFallbackMatrixRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_matrix_row_serde() {
    let row = IncumbentFallbackMatrixRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        baseline_path: "crate::test".to_string(),
        incumbent_baseline: "RwLock".to_string(),
        immediate_fallback: false,
        fallback_target: "RwLock".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        fallback_conditions: vec!["retry_budget_exhausted".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: IncumbentFallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// TraceIdsArtifact — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_trace_ids_serde() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace.1".to_string(), "trace.2".to_string()],
        decision_id: "decision.1".to_string(),
        policy_id: "policy.1".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ---------------------------------------------------------------------------
// StructuredLogEvent — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_structured_log_event_serde() {
    let event = StructuredLogEvent {
        trace_id: "trace.1".to_string(),
        decision_id: "decision.1".to_string(),
        policy_id: "policy.1".to_string(),
        component: COMPONENT.to_string(),
        event: "candidate_evaluated".to_string(),
        outcome: "accept".to_string(),
        error_code: None,
        candidate_id: Some("test-candidate".to_string()),
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrich_structured_log_event_with_error_code() {
    let event = StructuredLogEvent {
        trace_id: "trace.1".to_string(),
        decision_id: "decision.1".to_string(),
        policy_id: "policy.1".to_string(),
        component: COMPONENT.to_string(),
        event: "error".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("ERR_001".to_string()),
        candidate_id: None,
        detail: "".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("ERR_001".to_string()));
    assert!(back.candidate_id.is_none());
}

// ---------------------------------------------------------------------------
// ManifestArtifactReference — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_manifest_ref_serde() {
    let r = ManifestArtifactReference {
        path: "inventory.json".to_string(),
        sha256: "sha256:abc123".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ManifestArtifactReference = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ArtifactContext — construction
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_context_construction() {
    let ctx = ArtifactContext::new("/tmp/test-dir");
    assert_eq!(ctx.artifact_dir.to_str().unwrap(), "/tmp/test-dir");
    assert!(ctx.run_id.contains(COMPONENT));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(!ctx.generated_at_utc.is_empty());
    assert_eq!(ctx.source_commit, "unknown");
}

#[test]
fn enrich_artifact_context_serde() {
    let ctx = ArtifactContext::new("/tmp/test-dir");
    let json = serde_json::to_string(&ctx).unwrap();
    let back: ArtifactContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

// ---------------------------------------------------------------------------
// default_candidate_inventory — builder
// ---------------------------------------------------------------------------

#[test]
fn enrich_default_inventory_non_empty() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert!(!inv.candidates.is_empty());
}

#[test]
fn enrich_default_inventory_has_schema_version() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert_eq!(inv.schema_version, INVENTORY_SCHEMA_VERSION);
}

#[test]
fn enrich_default_inventory_has_bead_id() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert_eq!(inv.bead_id, BEAD_ID);
}

#[test]
fn enrich_default_inventory_candidates_sorted() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    for w in inv.candidates.windows(2) {
        assert!(w[0].candidate_id <= w[1].candidate_id);
    }
}

#[test]
fn enrich_default_inventory_counts_sum() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let total = inv.counts.accept + inv.counts.conditional + inv.counts.reject;
    assert_eq!(total, inv.candidates.len());
}

#[test]
fn enrich_default_inventory_hash_non_empty() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert!(!inv.inventory_hash.is_empty());
}

#[test]
fn enrich_default_inventory_deterministic() {
    let inv1 = default_candidate_inventory("2026-03-06T00:00:00Z");
    let inv2 = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
    assert_eq!(inv1.candidates.len(), inv2.candidates.len());
}

#[test]
fn enrich_default_inventory_serde_roundtrip() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let json = serde_json::to_string(&inv).unwrap();
    let back: SeqlockCandidateInventoryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn enrich_render_summary_non_empty() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let summary = render_summary(&inv);
    assert!(!summary.is_empty());
}

#[test]
fn enrich_render_summary_contains_bead_id() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let summary = render_summary(&inv);
    assert!(summary.contains(BEAD_ID));
}

#[test]
fn enrich_render_summary_contains_component() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let summary = render_summary(&inv);
    assert!(summary.contains(COMPONENT));
}

#[test]
fn enrich_render_summary_is_markdown() {
    let inv = default_candidate_inventory("2026-03-06T00:00:00Z");
    let summary = render_summary(&inv);
    assert!(summary.starts_with('#'));
}
