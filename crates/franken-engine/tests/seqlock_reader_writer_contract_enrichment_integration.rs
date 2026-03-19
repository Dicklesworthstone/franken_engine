//! Enrichment integration tests for the `seqlock_reader_writer_contract` module.
//!
//! Deep coverage of all public types, constants, serde round-trips,
//! render_summary, ArtifactContext construction, and type interactions.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::seqlock_fastpath::RetryBudgetPolicy;
use frankenengine_engine::seqlock_reader_writer_contract::{
    ArtifactContext, BEAD_ID, COMPONENT, CONTRACT_SCHEMA_VERSION, ContractCandidateRow,
    FALLBACK_MATRIX_SCHEMA_VERSION, FallbackMatrixRow, IncumbentFallbackMatrixArtifact,
    ManifestArtifactReference, ObservedTelemetryRow, RETRY_POLICY_SCHEMA_VERSION,
    RUN_MANIFEST_SCHEMA_VERSION, ReaderWriterContractArtifact, RetryBudgetPolicyArtifact,
    RetryBudgetPolicyRow, StructuredLogEvent, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact,
    render_summary,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_candidate() -> ContractCandidateRow {
    ContractCandidateRow {
        candidate_id: "enrich-candidate".to_string(),
        surface_name: "enrich_surface".to_string(),
        module_path: "crate::enrich_module".to_string(),
        read_api: "EnrichStruct::read".to_string(),
        write_api: "EnrichStruct::write".to_string(),
        incumbent_baseline: "rwlock".to_string(),
        retry_budget_policy: RetryBudgetPolicy::new(4, 2),
        exact_fallback_conditions: vec!["uninitialized".to_string(), "retry_exhausted".to_string()],
        telemetry_fields: vec!["total_reads".to_string(), "writes".to_string()],
    }
}

fn make_telemetry(id: &str) -> ObservedTelemetryRow {
    ObservedTelemetryRow {
        candidate_id: id.to_string(),
        total_reads: 200,
        fast_path_reads: 180,
        fallback_reads: 20,
        total_retries: 5,
        writer_pressure_observations: 2,
        writes: 50,
        latest_read_source: "fast_path".to_string(),
    }
}

fn make_contract() -> ReaderWriterContractArtifact {
    ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
        contract_hash: "enrichhash123".to_string(),
        accepted_candidates: vec![make_candidate()],
        observed_telemetry: vec![make_telemetry("enrich-candidate")],
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_bead_id_correct() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.21.2");
}

#[test]
fn enrich_component_correct() {
    assert_eq!(COMPONENT, "seqlock_reader_writer_contract");
}

#[test]
fn enrich_all_schema_versions_unique() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RETRY_POLICY_SCHEMA_VERSION,
        FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<_> = versions.iter().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn enrich_all_schema_versions_prefix() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RETRY_POLICY_SCHEMA_VERSION,
        FALLBACK_MATRIX_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    for v in &versions {
        assert!(v.starts_with("franken-engine."), "missing prefix in {v}");
    }
}

#[test]
fn enrich_schema_versions_contain_seqlock_or_rw() {
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
            "{v} should reference seqlock or rw"
        );
    }
}

// ---------------------------------------------------------------------------
// ContractCandidateRow — construction, serde, equality
// ---------------------------------------------------------------------------

#[test]
fn enrich_candidate_row_fields() {
    let row = make_candidate();
    assert_eq!(row.candidate_id, "enrich-candidate");
    assert_eq!(row.surface_name, "enrich_surface");
    assert_eq!(row.read_api, "EnrichStruct::read");
    assert_eq!(row.write_api, "EnrichStruct::write");
    assert_eq!(row.retry_budget_policy.max_retries, 4);
    assert_eq!(row.exact_fallback_conditions.len(), 2);
    assert_eq!(row.telemetry_fields.len(), 2);
}

#[test]
fn enrich_candidate_row_serde() {
    let row = make_candidate();
    let json = serde_json::to_string(&row).unwrap();
    let back: ContractCandidateRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn enrich_candidate_row_clone_eq() {
    let row = make_candidate();
    let cloned = row.clone();
    assert_eq!(row, cloned);
}

#[test]
fn enrich_candidate_row_ne_different_id() {
    let mut r1 = make_candidate();
    let mut r2 = make_candidate();
    r2.candidate_id = "different".to_string();
    assert_ne!(r1, r2);
    r1.candidate_id = "different".to_string();
    assert_eq!(r1, r2);
}

#[test]
fn enrich_candidate_row_empty_conditions() {
    let mut row = make_candidate();
    row.exact_fallback_conditions = vec![];
    let json = serde_json::to_string(&row).unwrap();
    let back: ContractCandidateRow = serde_json::from_str(&json).unwrap();
    assert!(back.exact_fallback_conditions.is_empty());
}

// ---------------------------------------------------------------------------
// ReaderWriterContractArtifact — construction, serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_contract_artifact_fields() {
    let a = make_contract();
    assert_eq!(a.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(a.bead_id, BEAD_ID);
    assert_eq!(a.component, COMPONENT);
    assert_eq!(a.accepted_candidates.len(), 1);
    assert_eq!(a.observed_telemetry.len(), 1);
}

#[test]
fn enrich_contract_artifact_serde() {
    let a = make_contract();
    let json = serde_json::to_string(&a).unwrap();
    let back: ReaderWriterContractArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrich_contract_artifact_clone_eq() {
    let a = make_contract();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrich_contract_artifact_empty_candidates() {
    let mut a = make_contract();
    a.accepted_candidates = vec![];
    a.observed_telemetry = vec![];
    let json = serde_json::to_string(&a).unwrap();
    let back: ReaderWriterContractArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.accepted_candidates.is_empty());
    assert!(back.observed_telemetry.is_empty());
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicyRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_policy_row_serde() {
    let row = RetryBudgetPolicyRow {
        candidate_id: "enrich-policy".to_string(),
        max_retries: 3,
        max_writer_pressure_observations: 1,
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn enrich_policy_row_zero_values() {
    let row = RetryBudgetPolicyRow {
        candidate_id: "zero".to_string(),
        max_retries: 0,
        max_writer_pressure_observations: 0,
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: RetryBudgetPolicyRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_retries, 0);
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicyArtifact — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_policy_artifact_serde() {
    let artifact = RetryBudgetPolicyArtifact {
        schema_version: RETRY_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
        policy_hash: "policyhash456".to_string(),
        rows: vec![RetryBudgetPolicyRow {
            candidate_id: "test".to_string(),
            max_retries: 5,
            max_writer_pressure_observations: 2,
        }],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: RetryBudgetPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn enrich_policy_artifact_empty_rows() {
    let artifact = RetryBudgetPolicyArtifact {
        schema_version: RETRY_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
        policy_hash: "empty".to_string(),
        rows: vec![],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: RetryBudgetPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert!(back.rows.is_empty());
}

// ---------------------------------------------------------------------------
// FallbackMatrixRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_row_serde() {
    let row = FallbackMatrixRow {
        candidate_id: "enrich-fallback".to_string(),
        incumbent_baseline: "mutex".to_string(),
        exact_fallback_conditions: vec!["writer_pressure".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: FallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn enrich_fallback_row_multiple_conditions() {
    let row = FallbackMatrixRow {
        candidate_id: "multi".to_string(),
        incumbent_baseline: "rwlock".to_string(),
        exact_fallback_conditions: vec![
            "uninitialized".to_string(),
            "retry_exhausted".to_string(),
            "writer_pressure".to_string(),
        ],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: FallbackMatrixRow = serde_json::from_str(&json).unwrap();
    assert_eq!(back.exact_fallback_conditions.len(), 3);
}

// ---------------------------------------------------------------------------
// IncumbentFallbackMatrixArtifact — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_matrix_artifact_serde() {
    let artifact = IncumbentFallbackMatrixArtifact {
        schema_version: FALLBACK_MATRIX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
        matrix_hash: "matrixhash789".to_string(),
        rows: vec![FallbackMatrixRow {
            candidate_id: "test".to_string(),
            incumbent_baseline: "rwlock".to_string(),
            exact_fallback_conditions: vec!["test".to_string()],
        }],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: IncumbentFallbackMatrixArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ---------------------------------------------------------------------------
// ObservedTelemetryRow — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_telemetry_row_serde() {
    let row = make_telemetry("test-candidate");
    let json = serde_json::to_string(&row).unwrap();
    let back: ObservedTelemetryRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

#[test]
fn enrich_telemetry_row_zero_counts() {
    let row = ObservedTelemetryRow {
        candidate_id: "zero".to_string(),
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
fn enrich_telemetry_row_large_counts() {
    let row = ObservedTelemetryRow {
        candidate_id: "big".to_string(),
        total_reads: u64::MAX,
        fast_path_reads: u64::MAX - 1,
        fallback_reads: 1,
        total_retries: 999_999,
        writer_pressure_observations: 42,
        writes: 1_000_000_000,
        latest_read_source: "fast_path".to_string(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: ObservedTelemetryRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, back);
}

// ---------------------------------------------------------------------------
// TraceIdsArtifact — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_trace_ids_serde() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace.enrich.1".to_string()],
        decision_id: "decision.enrich.1".to_string(),
        policy_id: "policy.enrich.1".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn enrich_trace_ids_empty() {
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

// ---------------------------------------------------------------------------
// StructuredLogEvent — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_log_event_serde() {
    let event = StructuredLogEvent {
        trace_id: "trace.1".to_string(),
        decision_id: "decision.1".to_string(),
        policy_id: "policy.1".to_string(),
        component: COMPONENT.to_string(),
        event: "enrich_event".to_string(),
        outcome: "accept".to_string(),
        error_code: None,
        candidate_id: Some("enrich-candidate".to_string()),
        detail: "enrichment test".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrich_log_event_with_error() {
    let event = StructuredLogEvent {
        trace_id: "trace.err".to_string(),
        decision_id: "decision.err".to_string(),
        policy_id: "policy.err".to_string(),
        component: COMPONENT.to_string(),
        event: "error_event".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("ERR_ENRICH".to_string()),
        candidate_id: None,
        detail: "test error".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("ERR_ENRICH".to_string()));
    assert!(back.candidate_id.is_none());
}

// ---------------------------------------------------------------------------
// ManifestArtifactReference — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_manifest_ref_serde() {
    let r = ManifestArtifactReference {
        path: "enrich_contract.json".to_string(),
        sha256: "sha256:enrich123".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ManifestArtifactReference = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrich_manifest_ref_ne_different_path() {
    let r1 = ManifestArtifactReference {
        path: "a.json".to_string(),
        sha256: "sha256:same".to_string(),
    };
    let r2 = ManifestArtifactReference {
        path: "b.json".to_string(),
        sha256: "sha256:same".to_string(),
    };
    assert_ne!(r1, r2);
}

// ---------------------------------------------------------------------------
// ArtifactContext — construction
// ---------------------------------------------------------------------------

#[test]
fn enrich_artifact_context_construction() {
    let ctx = ArtifactContext::new("/tmp/enrich-test");
    assert_eq!(ctx.artifact_dir.to_str().unwrap(), "/tmp/enrich-test");
    assert!(
        ctx.run_id
            .starts_with("run-seqlock_reader_writer_contract-")
    );
    assert!(ctx.trace_id.starts_with("trace."));
    assert!(ctx.decision_id.starts_with("decision."));
    assert!(ctx.policy_id.starts_with("policy."));
    assert!(!ctx.generated_at_utc.is_empty());
    assert_eq!(ctx.source_commit, "unknown");
}

#[test]
fn enrich_artifact_context_utc_format() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(ctx.generated_at_utc.contains('T'));
    assert!(ctx.generated_at_utc.ends_with('Z'));
}

#[test]
fn enrich_artifact_context_command_invocation() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert!(!ctx.command_invocation.is_empty());
    assert!(ctx.command_invocation.contains("cargo"));
}

#[test]
fn enrich_artifact_context_mutable_fields() {
    let mut ctx = ArtifactContext::new("/tmp/test");
    ctx.run_id = "custom-run".to_string();
    ctx.source_commit = "abc123".to_string();
    assert_eq!(ctx.run_id, "custom-run");
    assert_eq!(ctx.source_commit, "abc123");
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn enrich_render_summary_non_empty() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(!summary.is_empty());
}

#[test]
fn enrich_render_summary_starts_with_heading() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.starts_with('#'));
}

#[test]
fn enrich_render_summary_contains_bead_id() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.contains(BEAD_ID));
}

#[test]
fn enrich_render_summary_contains_component() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.contains(COMPONENT));
}

#[test]
fn enrich_render_summary_contains_candidate_id() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.contains("enrich-candidate"));
}

#[test]
fn enrich_render_summary_contains_sections() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.contains("Candidate Policies"));
    assert!(summary.contains("Observed Telemetry"));
}

#[test]
fn enrich_render_summary_contains_hash() {
    let contract = make_contract();
    let summary = render_summary(&contract);
    assert!(summary.contains("enrichhash123"));
}

#[test]
fn enrich_render_summary_empty_candidates() {
    let contract = ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
        contract_hash: "empty".to_string(),
        accepted_candidates: vec![],
        observed_telemetry: vec![],
    };
    let summary = render_summary(&contract);
    assert!(summary.contains(BEAD_ID));
    assert!(summary.contains("Candidate Policies"));
    assert!(summary.contains("Observed Telemetry"));
}
