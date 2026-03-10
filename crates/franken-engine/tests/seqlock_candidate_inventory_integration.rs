#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::seqlock_candidate_inventory::{
    ArtifactContext, BASELINE_COMPARATOR_SCHEMA_VERSION, BEAD_ID, BaselineStrategy, COMPONENT,
    CandidateCounts, CandidateDisposition, FallbackReason,
    INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION, INVENTORY_SCHEMA_VERSION, IncumbentFallbackMatrixRow,
    ManifestArtifactReference, PREDECESSOR_BEAD_ID, READER_WRITER_CONTRACT_SCHEMA_VERSION,
    RETRY_BUDGET_POLICY_SCHEMA_VERSION, RETRY_SAFETY_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION,
    RetryBudgetPolicyRow, RetrySafetyMatrixRow, SeqlockCandidateInventoryArtifact,
    SeqlockReaderWriterContractRow, SnapshotBaselineComparatorRow, StructuredLogEvent, SurfaceArea,
    TRACE_IDS_SCHEMA_VERSION, TearingRisk, TraceIdsArtifact, WriteProfile,
    default_candidate_inventory, emit_default_inventory_bundle, render_summary,
};

use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    path.push(format!(
        "franken-engine-sci-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn make_artifact_context(dir: &PathBuf) -> ArtifactContext {
    let mut ctx = ArtifactContext::new(dir);
    ctx.run_id = "run-test-001".to_string();
    ctx.generated_at_utc = "2026-03-10T00:00:00Z".to_string();
    ctx.source_commit = "cafebabe".to_string();
    ctx.toolchain = "nightly".to_string();
    ctx
}

fn make_accept_retry_policy(candidate_id: &str) -> RetryBudgetPolicyRow {
    RetryBudgetPolicyRow {
        candidate_id: candidate_id.to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 3,
        fallback_target: "incumbent-path".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Moderate,
        policy_rationale: vec!["deterministic candidate".to_string()],
    }
}

fn make_reject_retry_policy(candidate_id: &str, reason: FallbackReason) -> RetryBudgetPolicyRow {
    RetryBudgetPolicyRow {
        candidate_id: candidate_id.to_string(),
        disposition: CandidateDisposition::Reject,
        max_retries: 0,
        fallback_target: "incumbent-path".to_string(),
        fallback_reason: reason,
        write_pressure_limit: WriteProfile::Rare,
        policy_rationale: vec!["rejected candidate stays on incumbent".to_string()],
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn bead_id_constant_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.21.2");
}

#[test]
fn predecessor_bead_id_constant_value() {
    assert_eq!(PREDECESSOR_BEAD_ID, "bd-1lsy.7.21.1");
}

#[test]
fn component_constant_value() {
    assert_eq!(COMPONENT, "seqlock_candidate_inventory");
}

#[test]
fn inventory_schema_version_nonempty_and_prefixed() {
    assert!(!INVENTORY_SCHEMA_VERSION.is_empty());
    assert!(INVENTORY_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn retry_safety_schema_version_nonempty_and_prefixed() {
    assert!(!RETRY_SAFETY_SCHEMA_VERSION.is_empty());
    assert!(RETRY_SAFETY_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn baseline_comparator_schema_version_nonempty_and_prefixed() {
    assert!(!BASELINE_COMPARATOR_SCHEMA_VERSION.is_empty());
    assert!(BASELINE_COMPARATOR_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn reader_writer_contract_schema_version_nonempty_and_prefixed() {
    assert!(!READER_WRITER_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(READER_WRITER_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn retry_budget_policy_schema_version_nonempty_and_prefixed() {
    assert!(!RETRY_BUDGET_POLICY_SCHEMA_VERSION.is_empty());
    assert!(RETRY_BUDGET_POLICY_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn incumbent_fallback_matrix_schema_version_nonempty_and_prefixed() {
    assert!(!INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn trace_ids_schema_version_nonempty_and_prefixed() {
    assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn run_manifest_schema_version_nonempty_and_prefixed() {
    assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn all_schema_version_constants_are_distinct() {
    use std::collections::BTreeSet;
    let versions: BTreeSet<&str> = [
        INVENTORY_SCHEMA_VERSION,
        RETRY_SAFETY_SCHEMA_VERSION,
        BASELINE_COMPARATOR_SCHEMA_VERSION,
        READER_WRITER_CONTRACT_SCHEMA_VERSION,
        RETRY_BUDGET_POLICY_SCHEMA_VERSION,
        INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        versions.len(),
        8,
        "schema version constants must all be distinct"
    );
}

// ---------------------------------------------------------------------------
// CandidateDisposition serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn candidate_disposition_accept_serde_roundtrip() {
    let v = CandidateDisposition::Accept;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#""accept""#);
    let recovered: CandidateDisposition = serde_json::from_str(&json).unwrap();
    assert_eq!(v, recovered);
}

#[test]
fn candidate_disposition_conditional_serde_roundtrip() {
    let v = CandidateDisposition::Conditional;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#""conditional""#);
    let recovered: CandidateDisposition = serde_json::from_str(&json).unwrap();
    assert_eq!(v, recovered);
}

#[test]
fn candidate_disposition_reject_serde_roundtrip() {
    let v = CandidateDisposition::Reject;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#""reject""#);
    let recovered: CandidateDisposition = serde_json::from_str(&json).unwrap();
    assert_eq!(v, recovered);
}

#[test]
fn candidate_disposition_ordering() {
    assert!(CandidateDisposition::Accept < CandidateDisposition::Conditional);
    assert!(CandidateDisposition::Conditional < CandidateDisposition::Reject);
}

// ---------------------------------------------------------------------------
// SurfaceArea serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn surface_area_all_variants_serde_roundtrip() {
    let variants = [
        SurfaceArea::GovernanceState,
        SurfaceArea::OfflineArtifact,
        SurfaceArea::OperatorProjection,
        SurfaceArea::PolicyState,
        SurfaceArea::RuntimeMetadata,
        SurfaceArea::Telemetry,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let recovered: SurfaceArea = serde_json::from_str(&json).unwrap();
        assert_eq!(v, recovered);
    }
}

#[test]
fn surface_area_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&SurfaceArea::GovernanceState).unwrap(),
        r#""governance_state""#
    );
    assert_eq!(
        serde_json::to_string(&SurfaceArea::RuntimeMetadata).unwrap(),
        r#""runtime_metadata""#
    );
    assert_eq!(
        serde_json::to_string(&SurfaceArea::OfflineArtifact).unwrap(),
        r#""offline_artifact""#
    );
}

// ---------------------------------------------------------------------------
// BaselineStrategy serde
// ---------------------------------------------------------------------------

#[test]
fn baseline_strategy_all_variants_serde_roundtrip() {
    let variants = [
        BaselineStrategy::CloneSnapshot,
        BaselineStrategy::ExternalJoinProjection,
        BaselineStrategy::ImmutableValueObject,
        BaselineStrategy::MutableSnapshotSideEffect,
        BaselineStrategy::OfflineSummary,
        BaselineStrategy::QueryAppendOnly,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let recovered: BaselineStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(v, recovered);
    }
}

#[test]
fn baseline_strategy_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&BaselineStrategy::CloneSnapshot).unwrap(),
        r#""clone_snapshot""#
    );
    assert_eq!(
        serde_json::to_string(&BaselineStrategy::ExternalJoinProjection).unwrap(),
        r#""external_join_projection""#
    );
    assert_eq!(
        serde_json::to_string(&BaselineStrategy::ImmutableValueObject).unwrap(),
        r#""immutable_value_object""#
    );
}

// ---------------------------------------------------------------------------
// TearingRisk serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn tearing_risk_all_variants_serde_roundtrip() {
    let variants = [
        TearingRisk::None,
        TearingRisk::Low,
        TearingRisk::Medium,
        TearingRisk::High,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let recovered: TearingRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(v, recovered);
    }
}

#[test]
fn tearing_risk_ordering() {
    assert!(TearingRisk::None < TearingRisk::Low);
    assert!(TearingRisk::Low < TearingRisk::Medium);
    assert!(TearingRisk::Medium < TearingRisk::High);
}

#[test]
fn tearing_risk_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&TearingRisk::None).unwrap(),
        r#""none""#
    );
    assert_eq!(
        serde_json::to_string(&TearingRisk::High).unwrap(),
        r#""high""#
    );
}

// ---------------------------------------------------------------------------
// WriteProfile serde + ordering
// ---------------------------------------------------------------------------

#[test]
fn write_profile_all_variants_serde_roundtrip() {
    let variants = [
        WriteProfile::Rare,
        WriteProfile::Moderate,
        WriteProfile::Bursty,
        WriteProfile::HotPath,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let recovered: WriteProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(v, recovered);
    }
}

#[test]
fn write_profile_ordering() {
    assert!(WriteProfile::Rare < WriteProfile::Moderate);
    assert!(WriteProfile::Moderate < WriteProfile::Bursty);
    assert!(WriteProfile::Bursty < WriteProfile::HotPath);
}

#[test]
fn write_profile_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&WriteProfile::Rare).unwrap(),
        r#""rare""#
    );
    assert_eq!(
        serde_json::to_string(&WriteProfile::HotPath).unwrap(),
        r#""hot_path""#
    );
}

// ---------------------------------------------------------------------------
// FallbackReason serde
// ---------------------------------------------------------------------------

#[test]
fn fallback_reason_all_variants_serde_roundtrip() {
    let variants = [
        FallbackReason::UnsupportedCandidate,
        FallbackReason::WriterActive,
        FallbackReason::RetryBudgetExhausted,
        FallbackReason::ExternalJoinBoundary,
        FallbackReason::ImmutableValueObject,
        FallbackReason::HotPathWritePressure,
        FallbackReason::NonRetrySafeRead,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let recovered: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(v, recovered);
    }
}

#[test]
fn fallback_reason_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&FallbackReason::UnsupportedCandidate).unwrap(),
        r#""unsupported_candidate""#
    );
    assert_eq!(
        serde_json::to_string(&FallbackReason::RetryBudgetExhausted).unwrap(),
        r#""retry_budget_exhausted""#
    );
    assert_eq!(
        serde_json::to_string(&FallbackReason::HotPathWritePressure).unwrap(),
        r#""hot_path_write_pressure""#
    );
    assert_eq!(
        serde_json::to_string(&FallbackReason::NonRetrySafeRead).unwrap(),
        r#""non_retry_safe_read""#
    );
}

// ---------------------------------------------------------------------------
// CandidateCounts
// ---------------------------------------------------------------------------

#[test]
fn candidate_counts_default_all_zero() {
    let counts = CandidateCounts::default();
    assert_eq!(counts.accept, 0);
    assert_eq!(counts.conditional, 0);
    assert_eq!(counts.reject, 0);
}

#[test]
fn candidate_counts_serde_roundtrip() {
    let counts = CandidateCounts {
        accept: 3,
        conditional: 4,
        reject: 2,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let recovered: CandidateCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(counts, recovered);
}

#[test]
fn candidate_counts_sum() {
    let counts = CandidateCounts {
        accept: 3,
        conditional: 4,
        reject: 2,
    };
    assert_eq!(counts.accept + counts.conditional + counts.reject, 9);
}

// ---------------------------------------------------------------------------
// ArtifactContext
// ---------------------------------------------------------------------------

#[test]
fn artifact_context_new_sets_artifact_dir() {
    let dir = std::env::temp_dir().join("sci-ctx-test");
    let ctx = ArtifactContext::new(&dir);
    assert_eq!(ctx.artifact_dir, dir);
}

#[test]
fn artifact_context_new_run_id_starts_with_component() {
    let dir = std::env::temp_dir().join("sci-run-id");
    let ctx = ArtifactContext::new(&dir);
    assert!(ctx.run_id.starts_with("run-seqlock_candidate_inventory-"));
}

#[test]
fn artifact_context_new_trace_id_is_expected() {
    let dir = std::env::temp_dir().join("sci-trace-id");
    let ctx = ArtifactContext::new(&dir);
    assert_eq!(ctx.trace_id, "trace.rgc.621b");
}

#[test]
fn artifact_context_new_decision_id_is_expected() {
    let dir = std::env::temp_dir().join("sci-decision-id");
    let ctx = ArtifactContext::new(&dir);
    assert_eq!(ctx.decision_id, "decision.rgc.621b");
}

#[test]
fn artifact_context_new_policy_id_is_expected() {
    let dir = std::env::temp_dir().join("sci-policy-id");
    let ctx = ArtifactContext::new(&dir);
    assert_eq!(ctx.policy_id, "policy.rgc.621b");
}

#[test]
fn artifact_context_new_generated_at_ends_with_z() {
    let dir = std::env::temp_dir().join("sci-gen-at");
    let ctx = ArtifactContext::new(&dir);
    assert!(ctx.generated_at_utc.ends_with('Z'));
}

#[test]
fn artifact_context_serde_roundtrip() {
    let dir = std::env::temp_dir().join("sci-ctx-serde");
    let ctx = ArtifactContext::new(&dir);
    let json = serde_json::to_string(&ctx).unwrap();
    let recovered: ArtifactContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx.trace_id, recovered.trace_id);
    assert_eq!(ctx.decision_id, recovered.decision_id);
    assert_eq!(ctx.policy_id, recovered.policy_id);
    assert_eq!(ctx.artifact_dir, recovered.artifact_dir);
}

// ---------------------------------------------------------------------------
// default_candidate_inventory
// ---------------------------------------------------------------------------

#[test]
fn default_candidate_inventory_has_nine_candidates() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert_eq!(inventory.candidates.len(), 9);
}

#[test]
fn default_candidate_inventory_counts_sum_to_total() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let total = inventory.counts.accept + inventory.counts.conditional + inventory.counts.reject;
    assert_eq!(total, inventory.candidates.len());
}

#[test]
fn default_candidate_inventory_schema_version_matches_constant() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert_eq!(inventory.schema_version, INVENTORY_SCHEMA_VERSION);
}

#[test]
fn default_candidate_inventory_bead_id_matches_constant() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert_eq!(inventory.bead_id, BEAD_ID);
}

#[test]
fn default_candidate_inventory_component_matches_constant() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert_eq!(inventory.component, COMPONENT);
}

#[test]
fn default_candidate_inventory_hash_is_deterministic() {
    let a = default_candidate_inventory("2026-03-10T00:00:00Z");
    let b = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert_eq!(a.inventory_hash, b.inventory_hash);
}

#[test]
fn default_candidate_inventory_hash_stable_across_timestamps() {
    // Hash depends only on counts+candidates, not the timestamp field
    let a = default_candidate_inventory("2026-03-10T00:00:00Z");
    let b = default_candidate_inventory("2026-01-01T00:00:00Z");
    assert_eq!(a.inventory_hash, b.inventory_hash);
}

#[test]
fn default_candidate_inventory_generated_at_preserved() {
    let ts = "2026-03-10T12:34:56Z";
    let inventory = default_candidate_inventory(ts);
    assert_eq!(inventory.generated_at_utc, ts);
}

#[test]
fn default_candidate_inventory_hash_is_nonempty() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    assert!(!inventory.inventory_hash.is_empty());
}

#[test]
fn default_candidate_inventory_candidates_are_sorted_by_id() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let ids: Vec<&str> = inventory
        .candidates
        .iter()
        .map(|c| c.candidate_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "candidates should be sorted by candidate_id");
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_ids() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(!c.candidate_id.is_empty(), "candidate_id must not be empty");
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_surface_names() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(!c.surface_name.is_empty(), "surface_name must not be empty");
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_module_paths() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(!c.module_path.is_empty(), "module_path must not be empty");
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_api_paths() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(!c.api_path.is_empty(), "api_path must not be empty");
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_baseline_paths() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(
            !c.baseline_path.is_empty(),
            "baseline_path must not be empty"
        );
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_nonempty_incumbent_baselines() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(
            !c.incumbent_baseline.is_empty(),
            "incumbent_baseline must not be empty"
        );
    }
}

#[test]
fn default_candidate_inventory_all_candidates_have_rationale() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    for c in &inventory.candidates {
        assert!(
            !c.classification_rationale.is_empty(),
            "candidate {} must have classification_rationale",
            c.candidate_id
        );
    }
}

#[test]
fn default_candidate_inventory_serde_roundtrip() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let json = serde_json::to_string(&inventory).unwrap();
    let recovered: SeqlockCandidateInventoryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, recovered);
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_has_title() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("# Seqlock Candidate Inventory Summary"));
}

#[test]
fn render_summary_has_accepted_section() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("## Accepted"));
}

#[test]
fn render_summary_has_conditional_section() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("## Conditional"));
}

#[test]
fn render_summary_has_rejected_section() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("## Rejected"));
}

#[test]
fn render_summary_contains_bead_id() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("bead_id"));
    assert!(summary.contains(BEAD_ID));
}

#[test]
fn render_summary_contains_component() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("component"));
    assert!(summary.contains(COMPONENT));
}

#[test]
fn render_summary_contains_inventory_hash() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("inventory_hash"));
    assert!(summary.contains(&inventory.inventory_hash));
}

#[test]
fn render_summary_contains_predecessor_bead_id() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("predecessor_bead_id"));
    assert!(summary.contains(PREDECESSOR_BEAD_ID));
}

#[test]
fn render_summary_is_deterministic() {
    let inventory = default_candidate_inventory("2026-03-10T00:00:00Z");
    let a = render_summary(&inventory);
    let b = render_summary(&inventory);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// StructuredLogEvent serde
// ---------------------------------------------------------------------------

#[test]
fn structured_log_event_serde_roundtrip_no_error_code() {
    let event = StructuredLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        component: COMPONENT.to_string(),
        event: "candidate_evaluated".to_string(),
        outcome: "accept".to_string(),
        error_code: None,
        candidate_id: Some("module-cache-snapshot".to_string()),
        detail: "side-effect-free, retry-safe, rare writes".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let recovered: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
}

#[test]
fn structured_log_event_serde_roundtrip_with_error_code() {
    let event = StructuredLogEvent {
        trace_id: "trace-002".to_string(),
        decision_id: "decision-002".to_string(),
        policy_id: "policy-002".to_string(),
        component: COMPONENT.to_string(),
        event: "candidate_rejected".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("E_HOT_PATH".to_string()),
        candidate_id: Some("hot-path-candidate".to_string()),
        detail: "hot path write pressure".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let recovered: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
}

#[test]
fn structured_log_event_serde_roundtrip_no_candidate_id() {
    let event = StructuredLogEvent {
        trace_id: "trace-003".to_string(),
        decision_id: "decision-003".to_string(),
        policy_id: "policy-003".to_string(),
        component: COMPONENT.to_string(),
        event: "inventory_summary".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        candidate_id: None,
        detail: "accept=3 conditional=3 reject=3".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let recovered: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
    assert!(recovered.candidate_id.is_none());
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicyRow serde
// ---------------------------------------------------------------------------

#[test]
fn retry_budget_policy_row_serde_roundtrip_accept() {
    let row = make_accept_retry_policy("test-candidate");
    let json = serde_json::to_string(&row).unwrap();
    let recovered: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

#[test]
fn retry_budget_policy_row_serde_roundtrip_reject() {
    let row = make_reject_retry_policy("reject-candidate", FallbackReason::HotPathWritePressure);
    let json = serde_json::to_string(&row).unwrap();
    let recovered: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

#[test]
fn retry_budget_policy_row_max_retries_zero_for_reject() {
    let row = make_reject_retry_policy("r", FallbackReason::UnsupportedCandidate);
    assert_eq!(row.max_retries, 0);
}

// ---------------------------------------------------------------------------
// ManifestArtifactReference serde
// ---------------------------------------------------------------------------

#[test]
fn manifest_artifact_reference_serde_roundtrip() {
    let r = ManifestArtifactReference {
        path: "seqlock_candidate_inventory.json".to_string(),
        sha256: "sha256:deadbeefdeadbeef".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let recovered: ManifestArtifactReference = serde_json::from_str(&json).unwrap();
    assert_eq!(r, recovered);
}

// ---------------------------------------------------------------------------
// TraceIdsArtifact serde
// ---------------------------------------------------------------------------

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace.rgc.621b".to_string()],
        decision_id: "decision.rgc.621b".to_string(),
        policy_id: "policy.rgc.621b".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let recovered: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, recovered);
}

// ---------------------------------------------------------------------------
// SnapshotBaselineComparatorRow serde
// ---------------------------------------------------------------------------

#[test]
fn snapshot_baseline_comparator_row_serde_roundtrip() {
    let row = SnapshotBaselineComparatorRow {
        candidate_id: "module-cache-snapshot".to_string(),
        disposition: CandidateDisposition::Accept,
        baseline_path: "crates/franken-engine/src/module_cache.rs".to_string(),
        baseline_strategy: BaselineStrategy::CloneSnapshot,
        incumbent_baseline: "ModuleCache::snapshot()".to_string(),
        proposed_strategy: "seqlock_optimistic_read".to_string(),
        expected_read_side_benefit: "eliminate clone on hot path".to_string(),
        migration_risk: TearingRisk::Low,
        exact_fallback_conditions: vec!["writer_active".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: SnapshotBaselineComparatorRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

// ---------------------------------------------------------------------------
// RetrySafetyMatrixRow serde
// ---------------------------------------------------------------------------

#[test]
fn retry_safety_matrix_row_serde_roundtrip() {
    let row = RetrySafetyMatrixRow {
        candidate_id: "policy-state-snapshot".to_string(),
        disposition: CandidateDisposition::Conditional,
        read_side_effect_free: true,
        retry_safe_read: false,
        requires_atomic_multi_structure_view: true,
        requires_external_input_join: false,
        write_profile: WriteProfile::Bursty,
        tearing_risk: TearingRisk::Medium,
        exact_fallback_conditions: vec!["multi-structure view required".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: RetrySafetyMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

// ---------------------------------------------------------------------------
// IncumbentFallbackMatrixRow serde
// ---------------------------------------------------------------------------

#[test]
fn incumbent_fallback_matrix_row_serde_roundtrip_immediate() {
    let row = IncumbentFallbackMatrixRow {
        candidate_id: "runtime-metadata-snapshot".to_string(),
        disposition: CandidateDisposition::Reject,
        baseline_path: "crates/franken-engine/src/runtime_metadata.rs".to_string(),
        incumbent_baseline: "RuntimeMetadata::snapshot()".to_string(),
        immediate_fallback: true,
        fallback_target: "RuntimeMetadata::snapshot()".to_string(),
        fallback_reason: FallbackReason::HotPathWritePressure,
        fallback_conditions: vec!["hot path write pressure exceeds budget".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: IncumbentFallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

#[test]
fn incumbent_fallback_matrix_row_serde_roundtrip_deferred() {
    let row = IncumbentFallbackMatrixRow {
        candidate_id: "governance-state-snapshot".to_string(),
        disposition: CandidateDisposition::Accept,
        baseline_path: "crates/franken-engine/src/governance.rs".to_string(),
        incumbent_baseline: "Governance::snapshot()".to_string(),
        immediate_fallback: false,
        fallback_target: "Governance::snapshot()".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        fallback_conditions: vec!["fallback after 3 retries if writer unstable".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: IncumbentFallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

// ---------------------------------------------------------------------------
// SeqlockReaderWriterContractRow serde
// ---------------------------------------------------------------------------

#[test]
fn seqlock_reader_writer_contract_row_serde_roundtrip_optimistic() {
    let row = SeqlockReaderWriterContractRow {
        candidate_id: "module-cache-snapshot".to_string(),
        disposition: CandidateDisposition::Accept,
        optimistic_reads_enabled: true,
        writer_exclusive: true,
        reader_retry_safe: true,
        publication_boundary: "single writer sequence gate".to_string(),
        fallback_target: "ModuleCache::snapshot()".to_string(),
        telemetry_fields: vec!["retry_count".to_string(), "fallback_count".to_string()],
        contract_notes: vec!["optimistic reads enabled".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: SeqlockReaderWriterContractRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

#[test]
fn seqlock_reader_writer_contract_row_serde_roundtrip_fallback_only() {
    let row = SeqlockReaderWriterContractRow {
        candidate_id: "runtime-metadata-snapshot".to_string(),
        disposition: CandidateDisposition::Reject,
        optimistic_reads_enabled: false,
        writer_exclusive: false,
        reader_retry_safe: false,
        publication_boundary: "no seqlock boundary".to_string(),
        fallback_target: "RuntimeMetadata::snapshot()".to_string(),
        telemetry_fields: vec!["fallback_count".to_string()],
        contract_notes: vec!["fallback only; optimistic reads disabled".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let recovered: SeqlockReaderWriterContractRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, recovered);
}

// ---------------------------------------------------------------------------
// emit_default_inventory_bundle (filesystem integration)
// ---------------------------------------------------------------------------

#[test]
fn emit_bundle_creates_inventory_json() {
    let dir = temp_dir("emit-inv");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("seqlock_candidate_inventory.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_retry_safety_matrix_json() {
    let dir = temp_dir("emit-rsm");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("retry_safety_matrix.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_snapshot_baseline_comparator_json() {
    let dir = temp_dir("emit-sbc");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("snapshot_baseline_comparator.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_reader_writer_contract_json() {
    let dir = temp_dir("emit-rwc");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("seqlock_reader_writer_contract.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_retry_budget_policy_json() {
    let dir = temp_dir("emit-rbp");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("retry_budget_policy.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_incumbent_fallback_matrix_json() {
    let dir = temp_dir("emit-ifm");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("incumbent_fallback_matrix.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_trace_ids_json() {
    let dir = temp_dir("emit-tid");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("trace_ids.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_manifest_json() {
    let dir = temp_dir("emit-mfst");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("manifest.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_run_manifest_json() {
    let dir = temp_dir("emit-rmfst");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("run_manifest.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_events_jsonl() {
    let dir = temp_dir("emit-evts");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("events.jsonl").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_summary_md() {
    let dir = temp_dir("emit-summ");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("summary.md").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_commands_txt() {
    let dir = temp_dir("emit-cmds");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("commands.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_repro_lock() {
    let dir = temp_dir("emit-repro");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("repro.lock").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_creates_env_json() {
    let dir = temp_dir("emit-env");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(dir.join("env.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_report_has_nine_candidates() {
    let dir = temp_dir("emit-cnt");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(bundle.inventory.candidates.len(), 9);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_report_reader_writer_contract_has_nine_rows() {
    let dir = temp_dir("emit-rwcr");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(bundle.reader_writer_contract.rows.len(), 9);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_report_retry_budget_policy_has_nine_rows() {
    let dir = temp_dir("emit-rbpr");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(bundle.retry_budget_policy.rows.len(), 9);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_report_incumbent_fallback_matrix_has_nine_rows() {
    let dir = temp_dir("emit-ifmr");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(bundle.incumbent_fallback_matrix.rows.len(), 9);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_inventory_json_is_valid_json_and_matches_report() {
    let dir = temp_dir("emit-invj");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let bytes = fs::read(dir.join("seqlock_candidate_inventory.json")).unwrap();
    let parsed: SeqlockCandidateInventoryArtifact = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.inventory_hash, bundle.inventory.inventory_hash);
    assert_eq!(parsed.candidates.len(), bundle.inventory.candidates.len());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_trace_ids_json_contains_trace_id() {
    let dir = temp_dir("emit-trac");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let bytes = fs::read(dir.join("trace_ids.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ids = parsed["trace_ids"].as_array().unwrap();
    assert!(ids.iter().any(|v| v == "trace.rgc.621b"));
    assert_eq!(bundle.trace_ids_path, dir.join("trace_ids.json"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_run_manifest_json_has_candidate_count() {
    let dir = temp_dir("emit-runc");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let bytes = fs::read(dir.join("run_manifest.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        parsed["candidate_count"].as_u64(),
        Some(bundle.inventory.candidates.len() as u64)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_run_manifest_json_has_contract_hash() {
    let dir = temp_dir("emit-runhash");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let bytes = fs::read(dir.join("run_manifest.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        parsed["reader_writer_contract_hash"].as_str(),
        Some(bundle.reader_writer_contract.contract_hash.as_str())
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_written_files_includes_all_primary_artifacts() {
    let dir = temp_dir("emit-writ");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let must_have = [
        "seqlock_candidate_inventory.json",
        "retry_safety_matrix.json",
        "snapshot_baseline_comparator.json",
        "seqlock_reader_writer_contract.json",
        "retry_budget_policy.json",
        "incumbent_fallback_matrix.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "summary.md",
        "env.json",
        "repro.lock",
        "manifest.json",
    ];
    for name in must_have {
        assert!(
            bundle.written_files.contains_key(name),
            "written_files must include `{name}`"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_written_files_sha256_entries_start_with_prefix() {
    let dir = temp_dir("emit-sha");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for (name, sha) in &bundle.written_files {
        assert!(
            sha.starts_with("sha256:"),
            "written_files entry `{name}` has sha `{sha}` not starting with `sha256:`"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_lock_file_absent_after_write() {
    let dir = temp_dir("emit-lock");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert!(
        !dir.join(".seqlock_candidate_inventory.lock").exists(),
        "write lock must be cleaned up after publication"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_report_artifact_dir_matches_context() {
    let dir = temp_dir("emit-artdir");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(bundle.artifact_dir, dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_retry_safety_matrix_schema_matches_constant() {
    let dir = temp_dir("emit-rsms");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(
        bundle.retry_safety.schema_version,
        RETRY_SAFETY_SCHEMA_VERSION
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_baseline_comparator_schema_matches_constant() {
    let dir = temp_dir("emit-bcsc");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(
        bundle.baseline_comparator.schema_version,
        BASELINE_COMPARATOR_SCHEMA_VERSION
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_reader_writer_contract_schema_matches_constant() {
    let dir = temp_dir("emit-rwcs");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(
        bundle.reader_writer_contract.schema_version,
        READER_WRITER_CONTRACT_SCHEMA_VERSION
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_retry_budget_policy_schema_matches_constant() {
    let dir = temp_dir("emit-rbps");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(
        bundle.retry_budget_policy.schema_version,
        RETRY_BUDGET_POLICY_SCHEMA_VERSION
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_incumbent_fallback_matrix_schema_matches_constant() {
    let dir = temp_dir("emit-ifms");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    assert_eq!(
        bundle.incumbent_fallback_matrix.schema_version,
        INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_accepted_candidates_have_optimistic_reads_enabled() {
    let dir = temp_dir("emit-opt");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for row in &bundle.reader_writer_contract.rows {
        if row.disposition == CandidateDisposition::Accept {
            assert!(
                row.optimistic_reads_enabled,
                "accepted candidate `{}` must have optimistic_reads_enabled=true",
                row.candidate_id
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_rejected_candidates_have_optimistic_reads_disabled() {
    let dir = temp_dir("emit-noopt");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for row in &bundle.reader_writer_contract.rows {
        if row.disposition == CandidateDisposition::Reject {
            assert!(
                !row.optimistic_reads_enabled,
                "rejected candidate `{}` must have optimistic_reads_enabled=false",
                row.candidate_id
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_rejected_candidates_have_zero_max_retries() {
    let dir = temp_dir("emit-zret");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for row in &bundle.retry_budget_policy.rows {
        if row.disposition == CandidateDisposition::Reject {
            assert_eq!(
                row.max_retries, 0,
                "rejected candidate `{}` must have max_retries=0",
                row.candidate_id
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_accepted_candidates_have_positive_max_retries() {
    let dir = temp_dir("emit-posret");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for row in &bundle.retry_budget_policy.rows {
        if row.disposition == CandidateDisposition::Accept {
            assert!(
                row.max_retries > 0,
                "accepted candidate `{}` must have max_retries>0",
                row.candidate_id
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_incumbent_fallback_rows_immediate_for_zero_retry() {
    let dir = temp_dir("emit-immfall");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for ifm_row in &bundle.incumbent_fallback_matrix.rows {
        let rbp_row = bundle
            .retry_budget_policy
            .rows
            .iter()
            .find(|r| r.candidate_id == ifm_row.candidate_id)
            .expect("retry budget policy row must exist for every fallback matrix row");
        if rbp_row.max_retries == 0 {
            assert!(
                ifm_row.immediate_fallback,
                "candidate `{}` with max_retries=0 must have immediate_fallback=true",
                ifm_row.candidate_id
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_reader_writer_contract_telemetry_fields_contain_retry_count() {
    let dir = temp_dir("emit-telf");
    let ctx = make_artifact_context(&dir);
    let bundle = emit_default_inventory_bundle(&ctx).expect("bundle should write");
    for row in &bundle.reader_writer_contract.rows {
        assert!(
            row.telemetry_fields.contains(&"retry_count".to_string()),
            "candidate `{}` must have retry_count in telemetry_fields",
            row.candidate_id
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_events_jsonl_has_valid_lines() {
    let dir = temp_dir("emit-evlines");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let contents = fs::read_to_string(dir.join("events.jsonl")).unwrap();
    for line in contents.lines() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each events.jsonl line must be valid JSON");
        assert!(
            parsed.get("event").is_some(),
            "each event line must have 'event' field"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_summary_md_is_nonempty() {
    let dir = temp_dir("emit-summmd");
    let ctx = make_artifact_context(&dir);
    emit_default_inventory_bundle(&ctx).expect("bundle should write");
    let contents = fs::read_to_string(dir.join("summary.md")).unwrap();
    assert!(!contents.is_empty());
    assert!(contents.contains("# Seqlock Candidate Inventory Summary"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_is_idempotent_for_same_context() {
    let dir_a = temp_dir("emit-idemp-a");
    let dir_b = temp_dir("emit-idemp-b");

    let mut ctx_a = make_artifact_context(&dir_a);
    ctx_a.generated_at_utc = "2026-03-10T00:00:00Z".to_string();
    let mut ctx_b = make_artifact_context(&dir_b);
    ctx_b.generated_at_utc = "2026-03-10T00:00:00Z".to_string();

    let bundle_a = emit_default_inventory_bundle(&ctx_a).expect("bundle a should write");
    let bundle_b = emit_default_inventory_bundle(&ctx_b).expect("bundle b should write");

    // Hashes derived from content are equal; generated_at_utc does not affect inventory hash
    assert_eq!(
        bundle_a.inventory.inventory_hash,
        bundle_b.inventory.inventory_hash
    );
    assert_eq!(
        bundle_a.reader_writer_contract.contract_hash,
        bundle_b.reader_writer_contract.contract_hash
    );
    assert_eq!(
        bundle_a.retry_budget_policy.policy_hash,
        bundle_b.retry_budget_policy.policy_hash
    );

    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
}
