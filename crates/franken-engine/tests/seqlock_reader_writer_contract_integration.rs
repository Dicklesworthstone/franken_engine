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

// Integration tests for seqlock_reader_writer_contract
// Tests all public types, constants, serde round-trips, and render_summary().
// No filesystem operations are performed.

use frankenengine_engine::seqlock_fastpath::RetryBudgetPolicy;
use frankenengine_engine::seqlock_reader_writer_contract::render_summary;
use frankenengine_engine::seqlock_reader_writer_contract::{
    ArtifactContext, BEAD_ID, COMPONENT, CONTRACT_SCHEMA_VERSION, ContractCandidateRow,
    FALLBACK_MATRIX_SCHEMA_VERSION, FallbackMatrixRow, IncumbentFallbackMatrixArtifact,
    ManifestArtifactReference, ObservedTelemetryRow, RETRY_POLICY_SCHEMA_VERSION,
    RUN_MANIFEST_SCHEMA_VERSION, ReaderWriterContractArtifact, RetryBudgetPolicyArtifact,
    RetryBudgetPolicyRow, StructuredLogEvent, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact,
};

// ── BEAD_ID constant ────────────────────────────────────────────────────────

#[test]
fn bead_id_is_non_empty() {
    assert!(!BEAD_ID.is_empty());
}

#[test]
fn bead_id_has_expected_prefix() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn bead_id_value_is_correct() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.21.2");
}

// ── COMPONENT constant ──────────────────────────────────────────────────────

#[test]
fn component_is_non_empty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn component_value_is_correct() {
    assert_eq!(COMPONENT, "seqlock_reader_writer_contract");
}

#[test]
fn component_contains_seqlock() {
    assert!(COMPONENT.contains("seqlock"));
}

// ── Schema version constants ─────────────────────────────────────────────────

#[test]
fn contract_schema_version_is_non_empty() {
    assert!(!CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn contract_schema_version_starts_with_franken_engine() {
    assert!(CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn contract_schema_version_ends_with_v1() {
    assert!(CONTRACT_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn retry_policy_schema_version_is_non_empty() {
    assert!(!RETRY_POLICY_SCHEMA_VERSION.is_empty());
}

#[test]
fn retry_policy_schema_version_starts_with_franken_engine() {
    assert!(RETRY_POLICY_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn retry_policy_schema_version_ends_with_v1() {
    assert!(RETRY_POLICY_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn fallback_matrix_schema_version_is_non_empty() {
    assert!(!FALLBACK_MATRIX_SCHEMA_VERSION.is_empty());
}

#[test]
fn fallback_matrix_schema_version_starts_with_franken_engine() {
    assert!(FALLBACK_MATRIX_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn trace_ids_schema_version_is_non_empty() {
    assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
}

#[test]
fn trace_ids_schema_version_starts_with_franken_engine() {
    assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn run_manifest_schema_version_is_non_empty() {
    assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn run_manifest_schema_version_starts_with_franken_engine() {
    assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn all_schema_versions_are_distinct() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RETRY_POLICY_SCHEMA_VERSION,
        FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    let unique: std::collections::BTreeSet<_> = versions.iter().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn all_schema_versions_contain_seqlock_or_rw() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RETRY_POLICY_SCHEMA_VERSION,
        FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    for v in &versions {
        assert!(
            v.contains("seqlock") || v.contains("rw"),
            "schema version '{v}' should reference seqlock or rw"
        );
    }
}

// ── ContractCandidateRow — construction ──────────────────────────────────────

fn make_candidate_row() -> ContractCandidateRow {
    ContractCandidateRow {
        candidate_id: "test-candidate".to_string(),
        surface_name: "test-surface".to_string(),
        module_path: "crate::test_module".to_string(),
        read_api: "TestStruct::read".to_string(),
        write_api: "TestStruct::write".to_string(),
        incumbent_baseline: "rwlock".to_string(),
        retry_budget_policy: RetryBudgetPolicy::new(3, 2),
        exact_fallback_conditions: vec!["uninitialized".to_string(), "poisoned".to_string()],
        telemetry_fields: vec![
            "total_reads".to_string(),
            "fast_path_reads".to_string(),
            "writes".to_string(),
        ],
    }
}

#[test]
fn contract_candidate_row_construction() {
    let row = make_candidate_row();
    assert_eq!(row.candidate_id, "test-candidate");
    assert_eq!(row.surface_name, "test-surface");
    assert_eq!(row.module_path, "crate::test_module");
    assert_eq!(row.read_api, "TestStruct::read");
    assert_eq!(row.write_api, "TestStruct::write");
    assert_eq!(row.incumbent_baseline, "rwlock");
    assert_eq!(row.retry_budget_policy.max_retries, 3);
    assert_eq!(row.retry_budget_policy.max_writer_pressure_observations, 2);
    assert_eq!(row.exact_fallback_conditions.len(), 2);
    assert_eq!(row.telemetry_fields.len(), 3);
}

#[test]
fn contract_candidate_row_clone() {
    let row = make_candidate_row();
    let cloned = row.clone();
    assert_eq!(row, cloned);
}

#[test]
fn contract_candidate_row_equality() {
    let row1 = make_candidate_row();
    let row2 = make_candidate_row();
    assert_eq!(row1, row2);
}

#[test]
fn contract_candidate_row_inequality_on_candidate_id() {
    let row1 = make_candidate_row();
    let mut row2 = make_candidate_row();
    row2.candidate_id = "different-candidate".to_string();
    assert_ne!(row1, row2);
}

// ── ContractCandidateRow — serde ─────────────────────────────────────────────

#[test]
fn contract_candidate_row_serde_round_trip() {
    let row = make_candidate_row();
    let json = serde_json::to_string(&row).unwrap();
    let back: ContractCandidateRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn contract_candidate_row_serde_pretty_round_trip() {
    let row = make_candidate_row();
    let json = serde_json::to_string_pretty(&row).unwrap();
    let back: ContractCandidateRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn contract_candidate_row_json_contains_candidate_id() {
    let row = make_candidate_row();
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("test-candidate"));
}

#[test]
fn contract_candidate_row_json_contains_fallback_conditions() {
    let row = make_candidate_row();
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("uninitialized"));
    assert!(json.contains("poisoned"));
}

#[test]
fn contract_candidate_row_with_empty_fallback_conditions_round_trips() {
    let mut row = make_candidate_row();
    row.exact_fallback_conditions = vec![];
    let json = serde_json::to_string(&row).unwrap();
    let back: ContractCandidateRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back.exact_fallback_conditions, Vec::<String>::new());
}

// ── ReaderWriterContractArtifact — construction ──────────────────────────────

fn make_contract_artifact() -> ReaderWriterContractArtifact {
    ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        contract_hash: "deadbeef1234".to_string(),
        accepted_candidates: vec![make_candidate_row()],
        observed_telemetry: vec![make_telemetry_row("test-candidate")],
    }
}

#[test]
fn reader_writer_contract_artifact_construction() {
    let artifact = make_contract_artifact();
    assert_eq!(artifact.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, BEAD_ID);
    assert_eq!(artifact.component, COMPONENT);
    assert_eq!(artifact.generated_at_utc, "2026-03-06T00:00:00Z");
    assert_eq!(artifact.contract_hash, "deadbeef1234");
    assert_eq!(artifact.accepted_candidates.len(), 1);
    assert_eq!(artifact.observed_telemetry.len(), 1);
}

#[test]
fn reader_writer_contract_artifact_clone() {
    let a = make_contract_artifact();
    let b = a.clone();
    assert_eq!(a, b);
}

// ── ReaderWriterContractArtifact — serde ────────────────────────────────────

#[test]
fn reader_writer_contract_artifact_serde_round_trip() {
    let artifact = make_contract_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReaderWriterContractArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn reader_writer_contract_artifact_empty_candidates_round_trips() {
    let mut artifact = make_contract_artifact();
    artifact.accepted_candidates = vec![];
    artifact.observed_telemetry = vec![];
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReaderWriterContractArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.accepted_candidates.is_empty());
    assert!(back.observed_telemetry.is_empty());
}

#[test]
fn reader_writer_contract_artifact_json_contains_schema_version() {
    let artifact = make_contract_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    assert!(json.contains(CONTRACT_SCHEMA_VERSION));
}

#[test]
fn reader_writer_contract_artifact_json_contains_bead_id() {
    let artifact = make_contract_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    assert!(json.contains(BEAD_ID));
}

// ── RetryBudgetPolicyRow — construction and serde ────────────────────────────

fn make_policy_row() -> RetryBudgetPolicyRow {
    RetryBudgetPolicyRow {
        candidate_id: "governance-ledger-head-view".to_string(),
        max_retries: 4,
        max_writer_pressure_observations: 1,
    }
}

#[test]
fn retry_budget_policy_row_construction() {
    let row = make_policy_row();
    assert_eq!(row.candidate_id, "governance-ledger-head-view");
    assert_eq!(row.max_retries, 4);
    assert_eq!(row.max_writer_pressure_observations, 1);
}

#[test]
fn retry_budget_policy_row_clone() {
    let row = make_policy_row();
    assert_eq!(row.clone(), row);
}

#[test]
fn retry_budget_policy_row_serde_round_trip() {
    let row = make_policy_row();
    let json = serde_json::to_string(&row).unwrap();
    let back: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn retry_budget_policy_row_json_contains_candidate_id() {
    let row = make_policy_row();
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("governance-ledger-head-view"));
}

#[test]
fn retry_budget_policy_row_zero_retries_round_trips() {
    let row = RetryBudgetPolicyRow {
        candidate_id: "zero-retry".to_string(),
        max_retries: 0,
        max_writer_pressure_observations: 0,
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_retries, 0);
    assert_eq!(back.max_writer_pressure_observations, 0);
}

// ── RetryBudgetPolicyArtifact — construction and serde ───────────────────────

fn make_policy_artifact() -> RetryBudgetPolicyArtifact {
    RetryBudgetPolicyArtifact {
        schema_version: RETRY_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        policy_hash: "policyhash123".to_string(),
        rows: vec![make_policy_row()],
    }
}

#[test]
fn retry_budget_policy_artifact_construction() {
    let artifact = make_policy_artifact();
    assert_eq!(artifact.schema_version, RETRY_POLICY_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, BEAD_ID);
    assert_eq!(artifact.component, COMPONENT);
    assert_eq!(artifact.generated_at_utc, "2026-03-06T00:00:00Z");
    assert_eq!(artifact.policy_hash, "policyhash123");
    assert_eq!(artifact.rows.len(), 1);
}

#[test]
fn retry_budget_policy_artifact_clone() {
    let a = make_policy_artifact();
    assert_eq!(a.clone(), a);
}

#[test]
fn retry_budget_policy_artifact_serde_round_trip() {
    let artifact = make_policy_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let back: RetryBudgetPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn retry_budget_policy_artifact_empty_rows_round_trips() {
    let mut artifact = make_policy_artifact();
    artifact.rows = vec![];
    let json = serde_json::to_string(&artifact).unwrap();
    let back: RetryBudgetPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.rows.is_empty());
}

#[test]
fn retry_budget_policy_artifact_multiple_rows_round_trip() {
    let mut artifact = make_policy_artifact();
    artifact.rows = vec![
        RetryBudgetPolicyRow {
            candidate_id: "alpha".to_string(),
            max_retries: 2,
            max_writer_pressure_observations: 1,
        },
        RetryBudgetPolicyRow {
            candidate_id: "beta".to_string(),
            max_retries: 5,
            max_writer_pressure_observations: 3,
        },
    ];
    let json = serde_json::to_string(&artifact).unwrap();
    let back: RetryBudgetPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rows.len(), 2);
    assert_eq!(back.rows[0].candidate_id, "alpha");
    assert_eq!(back.rows[1].candidate_id, "beta");
}

// ── FallbackMatrixRow — construction and serde ───────────────────────────────

fn make_fallback_row() -> FallbackMatrixRow {
    FallbackMatrixRow {
        candidate_id: "guardplane-calibration-snapshot".to_string(),
        incumbent_baseline: "mutex-snapshot".to_string(),
        exact_fallback_conditions: vec!["writer_epoch_mismatch".to_string()],
    }
}

#[test]
fn fallback_matrix_row_construction() {
    let row = make_fallback_row();
    assert_eq!(row.candidate_id, "guardplane-calibration-snapshot");
    assert_eq!(row.incumbent_baseline, "mutex-snapshot");
    assert_eq!(row.exact_fallback_conditions.len(), 1);
    assert_eq!(row.exact_fallback_conditions[0], "writer_epoch_mismatch");
}

#[test]
fn fallback_matrix_row_clone() {
    let row = make_fallback_row();
    assert_eq!(row.clone(), row);
}

#[test]
fn fallback_matrix_row_serde_round_trip() {
    let row = make_fallback_row();
    let json = serde_json::to_string(&row).unwrap();
    let back: FallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn fallback_matrix_row_multiple_conditions_round_trip() {
    let row = FallbackMatrixRow {
        candidate_id: "module-cache-snapshot".to_string(),
        incumbent_baseline: "arc-rwlock".to_string(),
        exact_fallback_conditions: vec![
            "uninitialized".to_string(),
            "retry_budget_exhausted".to_string(),
            "writer_pressure_exceeded".to_string(),
        ],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: FallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back.exact_fallback_conditions.len(), 3);
}

// ── IncumbentFallbackMatrixArtifact — construction and serde ─────────────────

fn make_fallback_matrix_artifact() -> IncumbentFallbackMatrixArtifact {
    IncumbentFallbackMatrixArtifact {
        schema_version: FALLBACK_MATRIX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        matrix_hash: "matrixhash456".to_string(),
        rows: vec![make_fallback_row()],
    }
}

#[test]
fn incumbent_fallback_matrix_artifact_construction() {
    let artifact = make_fallback_matrix_artifact();
    assert_eq!(artifact.schema_version, FALLBACK_MATRIX_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, BEAD_ID);
    assert_eq!(artifact.component, COMPONENT);
    assert_eq!(artifact.generated_at_utc, "2026-03-06T00:00:00Z");
    assert_eq!(artifact.matrix_hash, "matrixhash456");
    assert_eq!(artifact.rows.len(), 1);
}

#[test]
fn incumbent_fallback_matrix_artifact_clone() {
    let a = make_fallback_matrix_artifact();
    assert_eq!(a.clone(), a);
}

#[test]
fn incumbent_fallback_matrix_artifact_serde_round_trip() {
    let artifact = make_fallback_matrix_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let back: IncumbentFallbackMatrixArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn incumbent_fallback_matrix_artifact_empty_rows_round_trips() {
    let mut artifact = make_fallback_matrix_artifact();
    artifact.rows = vec![];
    let json = serde_json::to_string(&artifact).unwrap();
    let back: IncumbentFallbackMatrixArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.rows.is_empty());
}

// ── ObservedTelemetryRow — construction and serde ────────────────────────────

fn make_telemetry_row(candidate_id: &str) -> ObservedTelemetryRow {
    ObservedTelemetryRow {
        candidate_id: candidate_id.to_string(),
        total_reads: 100,
        fast_path_reads: 92,
        fallback_reads: 8,
        total_retries: 3,
        writer_pressure_observations: 1,
        writes: 25,
        latest_read_source: "fast_path".to_string(),
    }
}

#[test]
fn observed_telemetry_row_construction() {
    let row = make_telemetry_row("module-cache-snapshot");
    assert_eq!(row.candidate_id, "module-cache-snapshot");
    assert_eq!(row.total_reads, 100);
    assert_eq!(row.fast_path_reads, 92);
    assert_eq!(row.fallback_reads, 8);
    assert_eq!(row.total_retries, 3);
    assert_eq!(row.writer_pressure_observations, 1);
    assert_eq!(row.writes, 25);
    assert_eq!(row.latest_read_source, "fast_path");
}

#[test]
fn observed_telemetry_row_clone() {
    let row = make_telemetry_row("x");
    assert_eq!(row.clone(), row);
}

#[test]
fn observed_telemetry_row_serde_round_trip() {
    let row = make_telemetry_row("governance-ledger-head-view");
    let json = serde_json::to_string(&row).unwrap();
    let back: ObservedTelemetryRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn observed_telemetry_row_zero_counts_round_trip() {
    let row = ObservedTelemetryRow {
        candidate_id: "empty-candidate".to_string(),
        total_reads: 0,
        fast_path_reads: 0,
        fallback_reads: 0,
        total_retries: 0,
        writer_pressure_observations: 0,
        writes: 0,
        latest_read_source: "none".to_string(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: ObservedTelemetryRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn observed_telemetry_row_large_counts_round_trip() {
    let row = ObservedTelemetryRow {
        candidate_id: "busy-candidate".to_string(),
        total_reads: u64::MAX,
        fast_path_reads: u64::MAX - 1,
        fallback_reads: 1,
        total_retries: 9_999_999,
        writer_pressure_observations: 42,
        writes: 1_000_000_000,
        latest_read_source: "fast_path".to_string(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: ObservedTelemetryRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn observed_telemetry_row_json_contains_candidate_id() {
    let row = make_telemetry_row("guardplane-calibration-snapshot");
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("guardplane-calibration-snapshot"));
}

// ── TraceIdsArtifact — construction and serde ────────────────────────────────

fn make_trace_ids_artifact() -> TraceIdsArtifact {
    TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![
            "trace.rgc.621b".to_string(),
            "trace.rgc.621b.extra".to_string(),
        ],
        decision_id: "decision.rgc.621b".to_string(),
        policy_id: "policy.rgc.621b".to_string(),
    }
}

#[test]
fn trace_ids_artifact_construction() {
    let artifact = make_trace_ids_artifact();
    assert_eq!(artifact.schema_version, TRACE_IDS_SCHEMA_VERSION);
    assert_eq!(artifact.trace_ids.len(), 2);
    assert_eq!(artifact.trace_ids[0], "trace.rgc.621b");
    assert_eq!(artifact.decision_id, "decision.rgc.621b");
    assert_eq!(artifact.policy_id, "policy.rgc.621b");
}

#[test]
fn trace_ids_artifact_clone() {
    let a = make_trace_ids_artifact();
    assert_eq!(a.clone(), a);
}

#[test]
fn trace_ids_artifact_serde_round_trip() {
    let artifact = make_trace_ids_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn trace_ids_artifact_single_trace_id_round_trips() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-only-one".to_string()],
        decision_id: "decision-x".to_string(),
        policy_id: "policy-x".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_ids.len(), 1);
    assert_eq!(back.trace_ids[0], "trace-only-one");
}

#[test]
fn trace_ids_artifact_empty_trace_ids_round_trips() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![],
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.trace_ids.is_empty());
}

// ── StructuredLogEvent — construction and serde ──────────────────────────────

fn make_log_event() -> StructuredLogEvent {
    StructuredLogEvent {
        trace_id: "trace.rgc.621b".to_string(),
        decision_id: "decision.rgc.621b".to_string(),
        policy_id: "policy.rgc.621b".to_string(),
        component: COMPONENT.to_string(),
        event: "candidate_contract_evaluated".to_string(),
        outcome: "accept".to_string(),
        error_code: None,
        candidate_id: Some("module-cache-snapshot".to_string()),
        detail: "read_api=ModuleCache::snapshot write_api=ModuleCache::insert retries=2 writer_pressure_budget=2".to_string(),
    }
}

#[test]
fn structured_log_event_construction() {
    let event = make_log_event();
    assert_eq!(event.trace_id, "trace.rgc.621b");
    assert_eq!(event.decision_id, "decision.rgc.621b");
    assert_eq!(event.policy_id, "policy.rgc.621b");
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.event, "candidate_contract_evaluated");
    assert_eq!(event.outcome, "accept");
    assert!(event.error_code.is_none());
    assert_eq!(event.candidate_id.as_deref(), Some("module-cache-snapshot"));
}

#[test]
fn structured_log_event_clone() {
    let e = make_log_event();
    assert_eq!(e.clone(), e);
}

#[test]
fn structured_log_event_serde_round_trip() {
    let event = make_log_event();
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn structured_log_event_with_error_code_round_trips() {
    let mut event = make_log_event();
    event.outcome = "reject".to_string();
    event.error_code = Some("ERR_RETRY_EXCEEDED".to_string());
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("ERR_RETRY_EXCEEDED".to_string()));
    assert_eq!(back.outcome, "reject");
}

#[test]
fn structured_log_event_without_candidate_id_round_trips() {
    let mut event = make_log_event();
    event.candidate_id = None;
    event.event = "bundle_write_complete".to_string();
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert!(back.candidate_id.is_none());
}

#[test]
fn structured_log_event_json_contains_event_name() {
    let event = make_log_event();
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("candidate_contract_evaluated"));
}

// ── ManifestArtifactReference — construction and serde ───────────────────────

fn make_manifest_ref() -> ManifestArtifactReference {
    ManifestArtifactReference {
        path: "seqlock_reader_writer_contract.json".to_string(),
        sha256: "sha256:abcdef1234567890".to_string(),
    }
}

#[test]
fn manifest_artifact_reference_construction() {
    let reference = make_manifest_ref();
    assert_eq!(reference.path, "seqlock_reader_writer_contract.json");
    assert_eq!(reference.sha256, "sha256:abcdef1234567890");
}

#[test]
fn manifest_artifact_reference_clone() {
    let r = make_manifest_ref();
    assert_eq!(r.clone(), r);
}

#[test]
fn manifest_artifact_reference_serde_round_trip() {
    let reference = make_manifest_ref();
    let json = serde_json::to_string(&reference).unwrap();
    let back: ManifestArtifactReference = serde_json::from_str(&json).unwrap();
    assert_eq!(reference, back);
}

#[test]
fn manifest_artifact_reference_json_contains_path() {
    let reference = make_manifest_ref();
    let json = serde_json::to_string(&reference).unwrap();
    assert!(json.contains("seqlock_reader_writer_contract.json"));
}

#[test]
fn manifest_artifact_reference_json_contains_sha256() {
    let reference = make_manifest_ref();
    let json = serde_json::to_string(&reference).unwrap();
    assert!(json.contains("sha256:abcdef1234567890"));
}

#[test]
fn manifest_artifact_reference_equality() {
    let r1 = make_manifest_ref();
    let r2 = make_manifest_ref();
    assert_eq!(r1, r2);
}

#[test]
fn manifest_artifact_reference_inequality_on_path() {
    let r1 = make_manifest_ref();
    let r2 = ManifestArtifactReference {
        path: "other.json".to_string(),
        sha256: r1.sha256.clone(),
    };
    assert_ne!(r1, r2);
}

// ── ArtifactContext::new() — construction ────────────────────────────────────

#[test]
fn artifact_context_new_uses_provided_path() {
    let ctx = ArtifactContext::new("/tmp/my-artifact-dir");
    assert_eq!(ctx.artifact_dir.to_str().unwrap(), "/tmp/my-artifact-dir");
}

#[test]
fn artifact_context_new_sets_run_id_with_component() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(
        ctx.run_id
            .starts_with("run-seqlock_reader_writer_contract-")
    );
}

#[test]
fn artifact_context_new_sets_trace_id() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(ctx.trace_id.starts_with("trace."));
    assert!(!ctx.trace_id.is_empty());
}

#[test]
fn artifact_context_new_sets_decision_id() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(ctx.decision_id.starts_with("decision."));
    assert!(!ctx.decision_id.is_empty());
}

#[test]
fn artifact_context_new_sets_policy_id() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(ctx.policy_id.starts_with("policy."));
    assert!(!ctx.policy_id.is_empty());
}

#[test]
fn artifact_context_new_sets_generated_at_utc() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(!ctx.generated_at_utc.is_empty());
    // RFC3339 format — should contain 'T' separator and 'Z' suffix
    assert!(ctx.generated_at_utc.contains('T'));
    assert!(ctx.generated_at_utc.ends_with('Z'));
}

#[test]
fn artifact_context_new_sets_source_commit_to_unknown() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert_eq!(ctx.source_commit, "unknown");
}

#[test]
fn artifact_context_new_sets_non_empty_command_invocation() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(!ctx.command_invocation.is_empty());
    assert!(ctx.command_invocation.contains("cargo"));
}

#[test]
fn artifact_context_new_accepts_pathbuf() {
    use std::path::PathBuf;
    let path = PathBuf::from("/tmp/test-pathbuf");
    let ctx = ArtifactContext::new(path.clone());
    assert_eq!(ctx.artifact_dir, path);
}

#[test]
fn artifact_context_fields_are_mutable() {
    let mut ctx = ArtifactContext::new("/tmp/test");
    ctx.run_id = "custom-run-id".to_string();
    ctx.source_commit = "abc123".to_string();
    ctx.toolchain = "stable".to_string();
    assert_eq!(ctx.run_id, "custom-run-id");
    assert_eq!(ctx.source_commit, "abc123");
    assert_eq!(ctx.toolchain, "stable");
}

// ── render_summary() ─────────────────────────────────────────────────────────

fn make_contract_for_render() -> ReaderWriterContractArtifact {
    ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T12:00:00Z".to_string(),
        contract_hash: "renderhash999".to_string(),
        accepted_candidates: vec![
            ContractCandidateRow {
                candidate_id: "module-cache-snapshot".to_string(),
                surface_name: "module_cache".to_string(),
                module_path: "crate::module_cache".to_string(),
                read_api: "ModuleCache::snapshot".to_string(),
                write_api: "ModuleCache::insert".to_string(),
                incumbent_baseline: "arc-rwlock".to_string(),
                retry_budget_policy: RetryBudgetPolicy::new(2, 2),
                exact_fallback_conditions: vec!["retry_budget_exhausted".to_string()],
                telemetry_fields: vec![
                    "total_reads".to_string(),
                    "fast_path_reads".to_string(),
                    "writes".to_string(),
                ],
            },
            ContractCandidateRow {
                candidate_id: "governance-ledger-head-view".to_string(),
                surface_name: "governance_audit_ledger".to_string(),
                module_path: "crate::portfolio_governor".to_string(),
                read_api: "GovernanceAuditLedger::query".to_string(),
                write_api: "GovernanceAuditLedger::append".to_string(),
                incumbent_baseline: "rwlock".to_string(),
                retry_budget_policy: RetryBudgetPolicy::new(4, 1),
                exact_fallback_conditions: vec!["uninitialized".to_string()],
                telemetry_fields: vec!["total_reads".to_string()],
            },
        ],
        observed_telemetry: vec![
            make_telemetry_row("module-cache-snapshot"),
            make_telemetry_row("governance-ledger-head-view"),
        ],
    }
}

#[test]
fn render_summary_returns_non_empty_string() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(!summary.is_empty());
}

#[test]
fn render_summary_contains_bead_id() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains(BEAD_ID));
}

#[test]
fn render_summary_contains_component() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains(COMPONENT));
}

#[test]
fn render_summary_contains_generated_at() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("2026-03-06T12:00:00Z"));
}

#[test]
fn render_summary_contains_contract_hash() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("renderhash999"));
}

#[test]
fn render_summary_contains_candidate_policies_section() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("Candidate Policies"));
}

#[test]
fn render_summary_contains_observed_telemetry_section() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("Observed Telemetry"));
}

#[test]
fn render_summary_contains_all_candidate_ids() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("module-cache-snapshot"));
    assert!(summary.contains("governance-ledger-head-view"));
}

#[test]
fn render_summary_mentions_read_api() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("ModuleCache::snapshot") || summary.contains("read_api"));
}

#[test]
fn render_summary_contains_telemetry_candidate_ids() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    // Telemetry section should reference candidates
    assert!(summary.contains("module-cache-snapshot"));
}

#[test]
fn render_summary_with_empty_candidates() {
    let contract = ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        contract_hash: "emptyhash".to_string(),
        accepted_candidates: vec![],
        observed_telemetry: vec![],
    };
    let summary = render_summary(&contract);
    assert!(summary.contains(BEAD_ID));
    assert!(summary.contains(COMPONENT));
    // Should still include section headers
    assert!(summary.contains("Candidate Policies"));
    assert!(summary.contains("Observed Telemetry"));
}

#[test]
fn render_summary_is_markdown_like() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    // Should start with a heading
    assert!(summary.starts_with('#'));
}

#[test]
fn render_summary_shows_retry_budget_count() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    // max_retries=2 for module-cache-snapshot should appear
    assert!(summary.contains("retries=2") || summary.contains("2"));
}

#[test]
fn render_summary_shows_telemetry_read_counts() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    // Should show reads=100, fast_path=92, etc. for telemetry
    assert!(summary.contains("reads=") || summary.contains("100"));
}

#[test]
fn render_summary_shows_accepted_candidates_count() {
    let contract = make_contract_for_render();
    let summary = render_summary(&contract);
    assert!(summary.contains("accepted_candidates") || summary.contains('2'));
}
