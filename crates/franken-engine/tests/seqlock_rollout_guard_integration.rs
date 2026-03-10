#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;

use frankenengine_engine::seqlock_candidate_inventory::CandidateDisposition;
use frankenengine_engine::seqlock_fastpath::{
    FastPathFallbackReason, FastPathReadSource, FastPathTelemetry, RetryBudgetPolicy,
};
use frankenengine_engine::seqlock_rollout_guard::{
    ArtifactContext, BEAD_ID, COMPONENT, CandidateRolloutInput, DOCS_CONTRACT_SCHEMA_VERSION,
    DocsContractFixture, GuardEvidenceVerdict, LOOM_COVERAGE_SCHEMA_VERSION,
    LoomScheduleCoverageReportArtifact, LoomScheduleCoverageRow, ManifestArtifactReference,
    PREDECESSOR_BEAD_ID, ROLLOUT_GUARD_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION,
    SAFETY_CASE_SCHEMA_VERSION, STARVATION_REPORT_SCHEMA_VERSION, SeqlockRolloutGuardArtifact,
    SeqlockRolloutGuardRow, SeqlockSafetyCaseArtifact, SeqlockSafetyCaseRow,
    StarvationBurstObservation, StarvationMicrobenchReportArtifact, StarvationMicrobenchRow,
    StructuredLogEvent, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact, build_docs_contract_fixture,
    render_summary, required_artifact_names,
};

// ─── helper constructors ────────────────────────────────────────────────────

fn make_telemetry_zeros() -> FastPathTelemetry {
    FastPathTelemetry {
        total_reads: 0,
        fast_path_reads: 0,
        fallback_reads: 0,
        total_retries: 0,
        writer_pressure_observations: 0,
        retry_budget_fallbacks: 0,
        uninitialized_fallbacks: 0,
        writer_pressure_fallbacks: 0,
        writes: 0,
    }
}

fn make_telemetry_pass(burst_writes: u64) -> FastPathTelemetry {
    FastPathTelemetry {
        total_reads: burst_writes * 2,
        fast_path_reads: burst_writes,
        fallback_reads: burst_writes,
        total_retries: 0,
        writer_pressure_observations: burst_writes,
        retry_budget_fallbacks: 0,
        uninitialized_fallbacks: 0,
        writer_pressure_fallbacks: burst_writes,
        writes: burst_writes,
    }
}

fn make_burst_obs(burst_index: u32, committed_value: u64) -> StarvationBurstObservation {
    StarvationBurstObservation {
        burst_index,
        committed_value,
        during_write_source: FastPathReadSource::Fallback,
        during_write_fallback_reason: Some(FastPathFallbackReason::WriterPressure),
        during_write_writer_pressure_observations: 1,
        post_publish_source: FastPathReadSource::FastPath,
        post_publish_value: committed_value,
    }
}

fn make_passing_starvation_row(candidate_id: &str) -> StarvationMicrobenchRow {
    StarvationMicrobenchRow {
        candidate_id: candidate_id.to_string(),
        retry_budget_policy: RetryBudgetPolicy::new(3, 1),
        burst_writes: 3,
        observations: vec![
            make_burst_obs(0, 2),
            make_burst_obs(1, 3),
            make_burst_obs(2, 4),
        ],
        telemetry: make_telemetry_pass(3),
        verdict: GuardEvidenceVerdict::Pass,
        notes: vec!["Test notes.".to_string()],
    }
}

fn make_failing_starvation_row(candidate_id: &str) -> StarvationMicrobenchRow {
    StarvationMicrobenchRow {
        candidate_id: candidate_id.to_string(),
        retry_budget_policy: RetryBudgetPolicy::new(3, 1),
        burst_writes: 3,
        observations: vec![],
        telemetry: make_telemetry_zeros(),
        verdict: GuardEvidenceVerdict::Fail,
        notes: vec!["Simulated failure.".to_string()],
    }
}

fn make_missing_loom_row(candidate_id: &str) -> LoomScheduleCoverageRow {
    LoomScheduleCoverageRow {
        candidate_id: candidate_id.to_string(),
        manual_schedule_cases: vec![
            "writer_pressure_fallback".to_string(),
            "post_publish_visibility".to_string(),
        ],
        loom_schedule_count: 0,
        verdict: GuardEvidenceVerdict::Missing,
        notes: vec!["Model check not yet wired.".to_string()],
    }
}

fn make_passing_loom_row(candidate_id: &str) -> LoomScheduleCoverageRow {
    LoomScheduleCoverageRow {
        candidate_id: candidate_id.to_string(),
        manual_schedule_cases: vec!["writer_pressure_fallback".to_string()],
        loom_schedule_count: 100,
        verdict: GuardEvidenceVerdict::Pass,
        notes: vec![],
    }
}

fn make_safety_case_row_disabled(candidate_id: &str) -> SeqlockSafetyCaseRow {
    SeqlockSafetyCaseRow {
        candidate_id: candidate_id.to_string(),
        surface_name: "test-surface".to_string(),
        inventory_disposition: CandidateDisposition::Accept,
        starvation_verdict: GuardEvidenceVerdict::Pass,
        model_check_verdict: GuardEvidenceVerdict::Missing,
        rollout_allowed: false,
        disable_reasons: vec!["model_check_evidence_missing".to_string()],
        incumbent_baseline: "rwlock".to_string(),
    }
}

fn make_safety_case_row_enabled(candidate_id: &str) -> SeqlockSafetyCaseRow {
    SeqlockSafetyCaseRow {
        candidate_id: candidate_id.to_string(),
        surface_name: "test-surface".to_string(),
        inventory_disposition: CandidateDisposition::Accept,
        starvation_verdict: GuardEvidenceVerdict::Pass,
        model_check_verdict: GuardEvidenceVerdict::Pass,
        rollout_allowed: true,
        disable_reasons: vec![],
        incumbent_baseline: "rwlock".to_string(),
    }
}

fn make_all_disabled_safety_artifact() -> SeqlockSafetyCaseArtifact {
    SeqlockSafetyCaseArtifact {
        schema_version: SAFETY_CASE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        safety_case_hash: "abc123hash".to_string(),
        rows: vec![
            make_safety_case_row_disabled("governance-ledger-head-view"),
            make_safety_case_row_disabled("guardplane-calibration-snapshot"),
        ],
    }
}

fn make_guard_artifact_all_disabled() -> SeqlockRolloutGuardArtifact {
    SeqlockRolloutGuardArtifact {
        schema_version: ROLLOUT_GUARD_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        guard_hash: "def456hash".to_string(),
        all_candidates_disabled: true,
        rows: vec![
            SeqlockRolloutGuardRow {
                candidate_id: "governance-ledger-head-view".to_string(),
                enabled: false,
                fallback_target: "rwlock".to_string(),
                required_artifacts: vec![
                    "seqlock_safety_case.json".to_string(),
                    "starvation_microbench_report.json".to_string(),
                    "loom_schedule_coverage_report.json".to_string(),
                ],
                disable_reasons: vec!["model_check_evidence_missing".to_string()],
            },
            SeqlockRolloutGuardRow {
                candidate_id: "guardplane-calibration-snapshot".to_string(),
                enabled: false,
                fallback_target: "mutex".to_string(),
                required_artifacts: vec![
                    "seqlock_safety_case.json".to_string(),
                    "starvation_microbench_report.json".to_string(),
                    "loom_schedule_coverage_report.json".to_string(),
                ],
                disable_reasons: vec!["model_check_evidence_missing".to_string()],
            },
        ],
    }
}

fn make_guard_artifact_one_enabled() -> SeqlockRolloutGuardArtifact {
    SeqlockRolloutGuardArtifact {
        schema_version: ROLLOUT_GUARD_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        guard_hash: "enabled123hash".to_string(),
        all_candidates_disabled: false,
        rows: vec![SeqlockRolloutGuardRow {
            candidate_id: "module-cache-snapshot".to_string(),
            enabled: true,
            fallback_target: "rwlock".to_string(),
            required_artifacts: vec!["seqlock_safety_case.json".to_string()],
            disable_reasons: vec![],
        }],
    }
}

fn make_safety_artifact_one_enabled() -> SeqlockSafetyCaseArtifact {
    SeqlockSafetyCaseArtifact {
        schema_version: SAFETY_CASE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        safety_case_hash: "enabled_sc_hash".to_string(),
        rows: vec![make_safety_case_row_enabled("module-cache-snapshot")],
    }
}

// ─── constants ────────────────────────────────────────────────────────────

#[test]
fn bead_id_has_expected_prefix() {
    assert!(BEAD_ID.starts_with("bd-"), "BEAD_ID should start with bd-");
}

#[test]
fn predecessor_bead_id_has_expected_prefix() {
    assert!(
        PREDECESSOR_BEAD_ID.starts_with("bd-"),
        "PREDECESSOR_BEAD_ID should start with bd-"
    );
}

#[test]
fn bead_id_and_predecessor_are_distinct() {
    assert_ne!(
        BEAD_ID, PREDECESSOR_BEAD_ID,
        "BEAD_ID and PREDECESSOR_BEAD_ID must differ"
    );
}

#[test]
fn bead_id_is_non_empty() {
    assert!(!BEAD_ID.is_empty());
}

#[test]
fn predecessor_bead_id_is_non_empty() {
    assert!(!PREDECESSOR_BEAD_ID.is_empty());
}

#[test]
fn component_constant_equals_module_name() {
    assert_eq!(COMPONENT, "seqlock_rollout_guard");
}

#[test]
fn safety_case_schema_version_format() {
    assert!(SAFETY_CASE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SAFETY_CASE_SCHEMA_VERSION.ends_with(".v1"));
    assert!(SAFETY_CASE_SCHEMA_VERSION.contains("safety-case"));
}

#[test]
fn starvation_report_schema_version_format() {
    assert!(STARVATION_REPORT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(STARVATION_REPORT_SCHEMA_VERSION.ends_with(".v1"));
    assert!(STARVATION_REPORT_SCHEMA_VERSION.contains("starvation"));
}

#[test]
fn loom_coverage_schema_version_format() {
    assert!(LOOM_COVERAGE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(LOOM_COVERAGE_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn rollout_guard_schema_version_format() {
    assert!(ROLLOUT_GUARD_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ROLLOUT_GUARD_SCHEMA_VERSION.ends_with(".v1"));
    assert!(ROLLOUT_GUARD_SCHEMA_VERSION.contains("rollout-guard"));
}

#[test]
fn trace_ids_schema_version_format() {
    assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TRACE_IDS_SCHEMA_VERSION.ends_with(".v1"));
    assert!(TRACE_IDS_SCHEMA_VERSION.contains("trace-ids"));
}

#[test]
fn run_manifest_schema_version_format() {
    assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(RUN_MANIFEST_SCHEMA_VERSION.ends_with(".v1"));
    assert!(RUN_MANIFEST_SCHEMA_VERSION.contains("run-manifest"));
}

#[test]
fn docs_contract_schema_version_format() {
    assert!(DOCS_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(DOCS_CONTRACT_SCHEMA_VERSION.ends_with(".v1"));
    assert!(DOCS_CONTRACT_SCHEMA_VERSION.contains("docs"));
}

#[test]
fn all_schema_version_constants_are_pairwise_distinct() {
    let versions = [
        SAFETY_CASE_SCHEMA_VERSION,
        STARVATION_REPORT_SCHEMA_VERSION,
        LOOM_COVERAGE_SCHEMA_VERSION,
        ROLLOUT_GUARD_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
        DOCS_CONTRACT_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "all schema version constants must be distinct"
    );
}

// ─── GuardEvidenceVerdict ───────────────────────────────────────────────────

#[test]
fn guard_evidence_verdict_pass_serde_roundtrip() {
    let v = GuardEvidenceVerdict::Pass;
    let json = serde_json::to_string(&v).expect("serialize Pass");
    assert_eq!(json, "\"pass\"");
    let back: GuardEvidenceVerdict = serde_json::from_str(&json).expect("deserialize Pass");
    assert_eq!(v, back);
}

#[test]
fn guard_evidence_verdict_missing_serde_roundtrip() {
    let v = GuardEvidenceVerdict::Missing;
    let json = serde_json::to_string(&v).expect("serialize Missing");
    assert_eq!(json, "\"missing\"");
    let back: GuardEvidenceVerdict = serde_json::from_str(&json).expect("deserialize Missing");
    assert_eq!(v, back);
}

#[test]
fn guard_evidence_verdict_fail_serde_roundtrip() {
    let v = GuardEvidenceVerdict::Fail;
    let json = serde_json::to_string(&v).expect("serialize Fail");
    assert_eq!(json, "\"fail\"");
    let back: GuardEvidenceVerdict = serde_json::from_str(&json).expect("deserialize Fail");
    assert_eq!(v, back);
}

#[test]
fn guard_evidence_verdict_all_variants_roundtrip() {
    for v in [
        GuardEvidenceVerdict::Pass,
        GuardEvidenceVerdict::Missing,
        GuardEvidenceVerdict::Fail,
    ] {
        let json = serde_json::to_string(&v).expect("serialize");
        let back: GuardEvidenceVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, back);
    }
}

#[test]
fn guard_evidence_verdict_equality() {
    assert_eq!(GuardEvidenceVerdict::Pass, GuardEvidenceVerdict::Pass);
    assert_eq!(GuardEvidenceVerdict::Missing, GuardEvidenceVerdict::Missing);
    assert_eq!(GuardEvidenceVerdict::Fail, GuardEvidenceVerdict::Fail);
    assert_ne!(GuardEvidenceVerdict::Pass, GuardEvidenceVerdict::Fail);
    assert_ne!(GuardEvidenceVerdict::Pass, GuardEvidenceVerdict::Missing);
    assert_ne!(GuardEvidenceVerdict::Missing, GuardEvidenceVerdict::Fail);
}

#[test]
fn guard_evidence_verdict_clone() {
    let v = GuardEvidenceVerdict::Pass;
    let cloned = v;
    assert_eq!(v, cloned);
}

// ─── CandidateRolloutInput ─────────────────────────────────────────────────

#[test]
fn candidate_rollout_input_construction() {
    let input = CandidateRolloutInput {
        candidate_id: "governance-ledger-head-view".to_string(),
        surface_name: "governance-state".to_string(),
        module_path: "crate::seqlock_fastpath".to_string(),
        incumbent_baseline: "rwlock".to_string(),
        disposition: CandidateDisposition::Accept,
        retry_budget_policy: RetryBudgetPolicy::new(4, 1),
    };
    assert_eq!(input.candidate_id, "governance-ledger-head-view");
    assert_eq!(input.surface_name, "governance-state");
    assert_eq!(input.incumbent_baseline, "rwlock");
    assert_eq!(input.disposition, CandidateDisposition::Accept);
    assert_eq!(input.retry_budget_policy.max_retries, 4);
    assert_eq!(
        input.retry_budget_policy.max_writer_pressure_observations,
        1
    );
}

#[test]
fn candidate_rollout_input_serde_roundtrip() {
    let input = CandidateRolloutInput {
        candidate_id: "module-cache-snapshot".to_string(),
        surface_name: "module-cache".to_string(),
        module_path: "crate::module_cache".to_string(),
        incumbent_baseline: "mutex".to_string(),
        disposition: CandidateDisposition::Accept,
        retry_budget_policy: RetryBudgetPolicy::new(2, 2),
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let back: CandidateRolloutInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, back);
}

#[test]
fn candidate_rollout_input_clone_equality() {
    let input = CandidateRolloutInput {
        candidate_id: "test-candidate".to_string(),
        surface_name: "surface".to_string(),
        module_path: "crate::test".to_string(),
        incumbent_baseline: "rwlock".to_string(),
        disposition: CandidateDisposition::Accept,
        retry_budget_policy: RetryBudgetPolicy::new(3, 1),
    };
    let cloned = input.clone();
    assert_eq!(input, cloned);
}

// ─── StarvationBurstObservation ────────────────────────────────────────────

#[test]
fn starvation_burst_observation_construction() {
    let obs = make_burst_obs(0, 42);
    assert_eq!(obs.burst_index, 0);
    assert_eq!(obs.committed_value, 42);
    assert_eq!(obs.during_write_source, FastPathReadSource::Fallback);
    assert_eq!(
        obs.during_write_fallback_reason,
        Some(FastPathFallbackReason::WriterPressure)
    );
    assert_eq!(obs.post_publish_source, FastPathReadSource::FastPath);
    assert_eq!(obs.post_publish_value, 42);
}

#[test]
fn starvation_burst_observation_serde_roundtrip() {
    let obs = make_burst_obs(1, 100);
    let json = serde_json::to_string_pretty(&obs).expect("serialize");
    let back: StarvationBurstObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, back);
}

#[test]
fn starvation_burst_observation_with_no_fallback_reason() {
    let obs = StarvationBurstObservation {
        burst_index: 2,
        committed_value: 7,
        during_write_source: FastPathReadSource::FastPath,
        during_write_fallback_reason: None,
        during_write_writer_pressure_observations: 0,
        post_publish_source: FastPathReadSource::FastPath,
        post_publish_value: 7,
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let back: StarvationBurstObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, back);
    assert!(back.during_write_fallback_reason.is_none());
}

// ─── StarvationMicrobenchRow ───────────────────────────────────────────────

#[test]
fn starvation_microbench_row_construction() {
    let row = make_passing_starvation_row("governance-ledger-head-view");
    assert_eq!(row.candidate_id, "governance-ledger-head-view");
    assert_eq!(row.burst_writes, 3);
    assert_eq!(row.verdict, GuardEvidenceVerdict::Pass);
    assert_eq!(row.observations.len(), 3);
    assert!(!row.notes.is_empty());
}

#[test]
fn starvation_microbench_row_serde_roundtrip() {
    let row = make_passing_starvation_row("module-cache-snapshot");
    let json = serde_json::to_string_pretty(&row).expect("serialize");
    let back: StarvationMicrobenchRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
}

#[test]
fn starvation_microbench_row_fail_serde_roundtrip() {
    let row = make_failing_starvation_row("guardplane-calibration-snapshot");
    let json = serde_json::to_string(&row).expect("serialize");
    let back: StarvationMicrobenchRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
    assert_eq!(back.verdict, GuardEvidenceVerdict::Fail);
}

// ─── StarvationMicrobenchReportArtifact ────────────────────────────────────

#[test]
fn starvation_report_artifact_construction() {
    let artifact = StarvationMicrobenchReportArtifact {
        schema_version: STARVATION_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        report_hash: "abc123".to_string(),
        rows: vec![make_passing_starvation_row("governance-ledger-head-view")],
    };
    assert_eq!(artifact.schema_version, STARVATION_REPORT_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, BEAD_ID);
    assert_eq!(artifact.component, COMPONENT);
    assert_eq!(artifact.rows.len(), 1);
}

#[test]
fn starvation_report_artifact_serde_roundtrip() {
    let artifact = StarvationMicrobenchReportArtifact {
        schema_version: STARVATION_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        report_hash: "deadbeef".to_string(),
        rows: vec![
            make_passing_starvation_row("governance-ledger-head-view"),
            make_failing_starvation_row("guardplane-calibration-snapshot"),
        ],
    };
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: StarvationMicrobenchReportArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ─── LoomScheduleCoverageRow ───────────────────────────────────────────────

#[test]
fn loom_schedule_coverage_row_missing_construction() {
    let row = make_missing_loom_row("governance-ledger-head-view");
    assert_eq!(row.candidate_id, "governance-ledger-head-view");
    assert_eq!(row.loom_schedule_count, 0);
    assert_eq!(row.verdict, GuardEvidenceVerdict::Missing);
    assert!(!row.manual_schedule_cases.is_empty());
    assert!(!row.notes.is_empty());
}

#[test]
fn loom_schedule_coverage_row_pass_construction() {
    let row = make_passing_loom_row("module-cache-snapshot");
    assert_eq!(row.verdict, GuardEvidenceVerdict::Pass);
    assert_eq!(row.loom_schedule_count, 100);
    assert!(row.notes.is_empty());
}

#[test]
fn loom_schedule_coverage_row_serde_roundtrip() {
    let row = make_missing_loom_row("module-cache-snapshot");
    let json = serde_json::to_string_pretty(&row).expect("serialize");
    let back: LoomScheduleCoverageRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
}

#[test]
fn loom_schedule_coverage_row_pass_serde_roundtrip() {
    let row = make_passing_loom_row("governance-ledger-head-view");
    let json = serde_json::to_string(&row).expect("serialize");
    let back: LoomScheduleCoverageRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
}

// ─── LoomScheduleCoverageReportArtifact ───────────────────────────────────

#[test]
fn loom_coverage_report_artifact_construction() {
    let artifact = LoomScheduleCoverageReportArtifact {
        schema_version: LOOM_COVERAGE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        report_hash: "loom_hash_abc".to_string(),
        rows: vec![
            make_missing_loom_row("governance-ledger-head-view"),
            make_missing_loom_row("module-cache-snapshot"),
        ],
    };
    assert_eq!(artifact.schema_version, LOOM_COVERAGE_SCHEMA_VERSION);
    assert_eq!(artifact.rows.len(), 2);
    assert!(
        artifact
            .rows
            .iter()
            .all(|r| r.verdict == GuardEvidenceVerdict::Missing)
    );
}

#[test]
fn loom_coverage_report_artifact_serde_roundtrip() {
    let artifact = LoomScheduleCoverageReportArtifact {
        schema_version: LOOM_COVERAGE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        report_hash: "loom_hash_xyz".to_string(),
        rows: vec![make_missing_loom_row("guardplane-calibration-snapshot")],
    };
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: LoomScheduleCoverageReportArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ─── SeqlockSafetyCaseRow ─────────────────────────────────────────────────

#[test]
fn seqlock_safety_case_row_disabled_construction() {
    let row = make_safety_case_row_disabled("governance-ledger-head-view");
    assert!(!row.rollout_allowed);
    assert!(
        row.disable_reasons
            .contains(&"model_check_evidence_missing".to_string())
    );
    assert_eq!(row.starvation_verdict, GuardEvidenceVerdict::Pass);
    assert_eq!(row.model_check_verdict, GuardEvidenceVerdict::Missing);
}

#[test]
fn seqlock_safety_case_row_enabled_construction() {
    let row = make_safety_case_row_enabled("module-cache-snapshot");
    assert!(row.rollout_allowed);
    assert!(row.disable_reasons.is_empty());
    assert_eq!(row.starvation_verdict, GuardEvidenceVerdict::Pass);
    assert_eq!(row.model_check_verdict, GuardEvidenceVerdict::Pass);
}

#[test]
fn seqlock_safety_case_row_serde_roundtrip() {
    let row = make_safety_case_row_disabled("governance-ledger-head-view");
    let json = serde_json::to_string_pretty(&row).expect("serialize");
    let back: SeqlockSafetyCaseRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
}

// ─── SeqlockSafetyCaseArtifact ────────────────────────────────────────────

#[test]
fn seqlock_safety_case_artifact_construction() {
    let artifact = make_all_disabled_safety_artifact();
    assert_eq!(artifact.schema_version, SAFETY_CASE_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, BEAD_ID);
    assert_eq!(artifact.predecessor_bead_id, PREDECESSOR_BEAD_ID);
    assert_eq!(artifact.component, COMPONENT);
    assert_eq!(artifact.rows.len(), 2);
}

#[test]
fn seqlock_safety_case_artifact_serde_roundtrip() {
    let artifact = make_all_disabled_safety_artifact();
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: SeqlockSafetyCaseArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ─── SeqlockRolloutGuardRow ───────────────────────────────────────────────

#[test]
fn seqlock_rollout_guard_row_disabled_construction() {
    let row = SeqlockRolloutGuardRow {
        candidate_id: "governance-ledger-head-view".to_string(),
        enabled: false,
        fallback_target: "rwlock".to_string(),
        required_artifacts: vec!["seqlock_safety_case.json".to_string()],
        disable_reasons: vec!["model_check_evidence_missing".to_string()],
    };
    assert!(!row.enabled);
    assert!(!row.disable_reasons.is_empty());
    assert!(!row.required_artifacts.is_empty());
}

#[test]
fn seqlock_rollout_guard_row_serde_roundtrip() {
    let row = SeqlockRolloutGuardRow {
        candidate_id: "module-cache-snapshot".to_string(),
        enabled: true,
        fallback_target: "rwlock".to_string(),
        required_artifacts: vec![
            "seqlock_safety_case.json".to_string(),
            "starvation_microbench_report.json".to_string(),
        ],
        disable_reasons: vec![],
    };
    let json = serde_json::to_string_pretty(&row).expect("serialize");
    let back: SeqlockRolloutGuardRow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(row, back);
}

// ─── SeqlockRolloutGuardArtifact ──────────────────────────────────────────

#[test]
fn seqlock_rollout_guard_artifact_all_disabled_construction() {
    let artifact = make_guard_artifact_all_disabled();
    assert_eq!(artifact.schema_version, ROLLOUT_GUARD_SCHEMA_VERSION);
    assert!(artifact.all_candidates_disabled);
    assert!(artifact.rows.iter().all(|r| !r.enabled));
}

#[test]
fn seqlock_rollout_guard_artifact_serde_roundtrip() {
    let artifact = make_guard_artifact_all_disabled();
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: SeqlockRolloutGuardArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

#[test]
fn seqlock_rollout_guard_artifact_one_enabled_serde_roundtrip() {
    let artifact = make_guard_artifact_one_enabled();
    assert!(!artifact.all_candidates_disabled);
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: SeqlockRolloutGuardArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ─── TraceIdsArtifact ─────────────────────────────────────────────────────

#[test]
fn trace_ids_artifact_construction() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace.rgc.001".to_string(), "trace.rgc.002".to_string()],
        decision_id: "decision.rgc.001".to_string(),
        policy_id: "policy.rgc.001".to_string(),
    };
    assert_eq!(artifact.schema_version, TRACE_IDS_SCHEMA_VERSION);
    assert_eq!(artifact.trace_ids.len(), 2);
    assert!(!artifact.decision_id.is_empty());
    assert!(!artifact.policy_id.is_empty());
}

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-a".to_string(), "trace-b".to_string()],
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
    };
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let back: TraceIdsArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

#[test]
fn trace_ids_artifact_with_single_trace() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace.rgc.621c".to_string()],
        decision_id: "decision.rgc.621c".to_string(),
        policy_id: "policy.rgc.621c".to_string(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let back: TraceIdsArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ─── StructuredLogEvent ───────────────────────────────────────────────────

#[test]
fn structured_log_event_with_all_fields() {
    let event = StructuredLogEvent {
        trace_id: "trace.1".to_string(),
        decision_id: "dec.1".to_string(),
        policy_id: "pol.1".to_string(),
        component: COMPONENT.to_string(),
        event: "starvation_microbench_evaluated".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        candidate_id: Some("governance-ledger-head-view".to_string()),
        detail: "burst_writes=3 fallback_reads=3".to_string(),
    };
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.outcome, "pass");
    assert!(event.candidate_id.is_some());
    assert!(event.error_code.is_none());
}

#[test]
fn structured_log_event_serde_roundtrip_with_error_code() {
    let event = StructuredLogEvent {
        trace_id: "trace.2".to_string(),
        decision_id: "dec.2".to_string(),
        policy_id: "pol.2".to_string(),
        component: COMPONENT.to_string(),
        event: "model_check_evidence_evaluated".to_string(),
        outcome: "missing".to_string(),
        error_code: Some("FE-SEQLOCK-ROLL-0001".to_string()),
        candidate_id: Some("module-cache-snapshot".to_string()),
        detail: "no loom coverage wired".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let back: StructuredLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, back);
    assert_eq!(back.error_code.as_deref(), Some("FE-SEQLOCK-ROLL-0001"));
}

#[test]
fn structured_log_event_serde_roundtrip_no_optional_fields() {
    let event = StructuredLogEvent {
        trace_id: "trace.3".to_string(),
        decision_id: "dec.3".to_string(),
        policy_id: "pol.3".to_string(),
        component: COMPONENT.to_string(),
        event: "gate_completed".to_string(),
        outcome: "disabled_pending_model_check".to_string(),
        error_code: None,
        candidate_id: None,
        detail: "candidate_count=3 all_candidates_disabled=true".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let back: StructuredLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, back);
    assert!(back.error_code.is_none());
    assert!(back.candidate_id.is_none());
}

// ─── ArtifactContext::new ──────────────────────────────────────────────────

#[test]
fn artifact_context_new_sets_artifact_dir() {
    let ctx = ArtifactContext::new("/tmp/seqlock-test-context");
    assert_eq!(
        ctx.artifact_dir.to_str().unwrap(),
        "/tmp/seqlock-test-context"
    );
}

#[test]
fn artifact_context_new_run_id_has_component_prefix() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx");
    assert!(
        ctx.run_id.starts_with("run-seqlock_rollout_guard-"),
        "run_id should start with run-seqlock_rollout_guard-, got: {}",
        ctx.run_id
    );
}

#[test]
fn artifact_context_new_trace_id_is_populated() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx2");
    assert!(!ctx.trace_id.is_empty());
    assert!(ctx.trace_id.contains("rgc"));
}

#[test]
fn artifact_context_new_decision_id_is_populated() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx3");
    assert!(!ctx.decision_id.is_empty());
    assert!(ctx.decision_id.contains("rgc"));
}

#[test]
fn artifact_context_new_policy_id_is_populated() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx4");
    assert!(!ctx.policy_id.is_empty());
    assert!(ctx.policy_id.contains("rgc"));
}

#[test]
fn artifact_context_new_source_commit_defaults_to_unknown() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx5");
    assert_eq!(ctx.source_commit, "unknown");
}

#[test]
fn artifact_context_new_toolchain_is_non_empty() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx6");
    assert!(!ctx.toolchain.is_empty());
}

#[test]
fn artifact_context_new_command_invocation_references_binary() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx7");
    assert!(
        ctx.command_invocation
            .contains("franken_seqlock_rollout_guard"),
        "command_invocation should reference the binary"
    );
}

#[test]
fn artifact_context_new_generated_at_utc_is_non_empty() {
    let ctx = ArtifactContext::new("/tmp/rollout-ctx8");
    assert!(!ctx.generated_at_utc.is_empty());
}

#[test]
fn artifact_context_fields_are_mutable_after_construction() {
    let mut ctx = ArtifactContext::new("/tmp/rollout-ctx-mut");
    ctx.run_id = "run-test-override".to_string();
    ctx.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
    ctx.source_commit = "deadbeef".to_string();
    assert_eq!(ctx.run_id, "run-test-override");
    assert_eq!(ctx.generated_at_utc, "2026-03-06T00:00:00Z");
    assert_eq!(ctx.source_commit, "deadbeef");
}

// ─── ManifestArtifactReference ────────────────────────────────────────────

#[test]
fn manifest_artifact_reference_construction() {
    let reference = ManifestArtifactReference {
        path: "seqlock_rollout_guard.json".to_string(),
        sha256: "sha256:abc123deadbeef".to_string(),
    };
    assert_eq!(reference.path, "seqlock_rollout_guard.json");
    assert!(reference.sha256.starts_with("sha256:"));
}

#[test]
fn manifest_artifact_reference_serde_roundtrip() {
    let reference = ManifestArtifactReference {
        path: "summary.md".to_string(),
        sha256: "sha256:0011223344556677".to_string(),
    };
    let json = serde_json::to_string(&reference).expect("serialize");
    let back: ManifestArtifactReference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reference, back);
}

#[test]
fn manifest_artifact_reference_clone_equality() {
    let reference = ManifestArtifactReference {
        path: "run_manifest.json".to_string(),
        sha256: "sha256:aabbccdd".to_string(),
    };
    let cloned = reference.clone();
    assert_eq!(reference, cloned);
}

// ─── DocsContractFixture ──────────────────────────────────────────────────

#[test]
fn docs_contract_fixture_construction() {
    let fixture = DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        default_disabled_candidates: vec!["candidate-a".to_string()],
        required_artifacts: vec!["summary.md".to_string()],
    };
    assert_eq!(fixture.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
    assert_eq!(fixture.bead_id, BEAD_ID);
    assert_eq!(fixture.default_disabled_candidates.len(), 1);
}

#[test]
fn docs_contract_fixture_serde_roundtrip() {
    let fixture = DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        default_disabled_candidates: vec![
            "governance-ledger-head-view".to_string(),
            "module-cache-snapshot".to_string(),
        ],
        required_artifacts: required_artifact_names(),
    };
    let json = serde_json::to_string_pretty(&fixture).expect("serialize");
    let back: DocsContractFixture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fixture, back);
}

// ─── build_docs_contract_fixture() ────────────────────────────────────────

#[test]
fn build_docs_contract_fixture_has_correct_schema_version() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
}

#[test]
fn build_docs_contract_fixture_bead_id_matches_constant() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture.bead_id, BEAD_ID);
}

#[test]
fn build_docs_contract_fixture_has_three_disabled_candidates() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(
        fixture.default_disabled_candidates.len(),
        3,
        "should have exactly 3 disabled candidates"
    );
}

#[test]
fn build_docs_contract_fixture_includes_known_candidates() {
    let fixture = build_docs_contract_fixture();
    let candidates: BTreeSet<&str> = fixture
        .default_disabled_candidates
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(
        candidates.contains("governance-ledger-head-view"),
        "should include governance-ledger-head-view"
    );
    assert!(
        candidates.contains("guardplane-calibration-snapshot"),
        "should include guardplane-calibration-snapshot"
    );
    assert!(
        candidates.contains("module-cache-snapshot"),
        "should include module-cache-snapshot"
    );
}

#[test]
fn build_docs_contract_fixture_candidates_are_sorted() {
    let fixture = build_docs_contract_fixture();
    let mut sorted = fixture.default_disabled_candidates.clone();
    sorted.sort();
    assert_eq!(
        fixture.default_disabled_candidates, sorted,
        "default_disabled_candidates should be in sorted order"
    );
}

#[test]
fn build_docs_contract_fixture_required_artifacts_match_function() {
    let fixture = build_docs_contract_fixture();
    let expected = required_artifact_names();
    assert_eq!(
        fixture.required_artifacts, expected,
        "fixture required_artifacts must match required_artifact_names()"
    );
}

#[test]
fn build_docs_contract_fixture_required_artifacts_non_empty() {
    let fixture = build_docs_contract_fixture();
    assert!(!fixture.required_artifacts.is_empty());
}

#[test]
fn build_docs_contract_fixture_is_idempotent() {
    let fixture1 = build_docs_contract_fixture();
    let fixture2 = build_docs_contract_fixture();
    assert_eq!(
        fixture1, fixture2,
        "build_docs_contract_fixture must be deterministic"
    );
}

// ─── required_artifact_names() ────────────────────────────────────────────

#[test]
fn required_artifact_names_has_twelve_entries() {
    let names = required_artifact_names();
    assert_eq!(names.len(), 12, "expected 12 required artifact names");
}

#[test]
fn required_artifact_names_are_sorted() {
    let names = required_artifact_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        names, sorted,
        "required artifact names must be in sorted order"
    );
}

#[test]
fn required_artifact_names_are_unique() {
    let names = required_artifact_names();
    let unique: BTreeSet<&str> = names.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "all artifact names must be distinct"
    );
}

#[test]
fn required_artifact_names_includes_seqlock_safety_case() {
    let names = required_artifact_names();
    assert!(names.contains(&"seqlock_safety_case.json".to_string()));
}

#[test]
fn required_artifact_names_includes_seqlock_rollout_guard() {
    let names = required_artifact_names();
    assert!(names.contains(&"seqlock_rollout_guard.json".to_string()));
}

#[test]
fn required_artifact_names_includes_starvation_microbench_report() {
    let names = required_artifact_names();
    assert!(names.contains(&"starvation_microbench_report.json".to_string()));
}

#[test]
fn required_artifact_names_includes_loom_schedule_coverage_report() {
    let names = required_artifact_names();
    assert!(names.contains(&"loom_schedule_coverage_report.json".to_string()));
}

#[test]
fn required_artifact_names_includes_manifest() {
    let names = required_artifact_names();
    assert!(names.contains(&"manifest.json".to_string()));
}

#[test]
fn required_artifact_names_includes_run_manifest() {
    let names = required_artifact_names();
    assert!(names.contains(&"run_manifest.json".to_string()));
}

#[test]
fn required_artifact_names_includes_summary_md() {
    let names = required_artifact_names();
    assert!(names.contains(&"summary.md".to_string()));
}

#[test]
fn required_artifact_names_includes_trace_ids() {
    let names = required_artifact_names();
    assert!(names.contains(&"trace_ids.json".to_string()));
}

#[test]
fn required_artifact_names_includes_events_jsonl() {
    let names = required_artifact_names();
    assert!(names.contains(&"events.jsonl".to_string()));
}

#[test]
fn required_artifact_names_includes_env_json() {
    let names = required_artifact_names();
    assert!(names.contains(&"env.json".to_string()));
}

#[test]
fn required_artifact_names_includes_commands_txt() {
    let names = required_artifact_names();
    assert!(names.contains(&"commands.txt".to_string()));
}

#[test]
fn required_artifact_names_includes_repro_lock() {
    let names = required_artifact_names();
    assert!(names.contains(&"repro.lock".to_string()));
}

// ─── render_summary() ─────────────────────────────────────────────────────

#[test]
fn render_summary_contains_header() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.starts_with("# Seqlock Rollout Guard Summary"),
        "summary must start with expected H1 heading"
    );
}

#[test]
fn render_summary_contains_enabled_section() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("## Enabled"),
        "summary must have Enabled section"
    );
}

#[test]
fn render_summary_contains_disabled_section() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("## Disabled"),
        "summary must have Disabled section"
    );
}

#[test]
fn render_summary_shows_fail_closed_message_when_all_disabled() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("none (fail-closed until model-check evidence is positive)"),
        "should show fail-closed message when no candidates are enabled"
    );
}

#[test]
fn render_summary_includes_bead_id() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(summary.contains(BEAD_ID), "summary should include BEAD_ID");
}

#[test]
fn render_summary_includes_component() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains(COMPONENT),
        "summary should include COMPONENT name"
    );
}

#[test]
fn render_summary_includes_safety_case_hash() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains(&safety.safety_case_hash),
        "summary should include the safety_case_hash"
    );
}

#[test]
fn render_summary_includes_guard_hash() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains(&guard.guard_hash),
        "summary should include the guard_hash"
    );
}

#[test]
fn render_summary_includes_all_candidates_disabled_flag() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("all_candidates_disabled"),
        "summary should mention all_candidates_disabled"
    );
    assert!(
        summary.contains("true"),
        "should show true when all are disabled"
    );
}

#[test]
fn render_summary_lists_disabled_candidates_by_name() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("governance-ledger-head-view"),
        "should list governance-ledger-head-view as disabled"
    );
    assert!(
        summary.contains("guardplane-calibration-snapshot"),
        "should list guardplane-calibration-snapshot as disabled"
    );
}

#[test]
fn render_summary_lists_enabled_candidate_when_one_is_enabled() {
    let safety = make_safety_artifact_one_enabled();
    let guard = make_guard_artifact_one_enabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("module-cache-snapshot"),
        "enabled candidate should appear in summary"
    );
    assert!(
        !summary.contains("none (fail-closed"),
        "should not show fail-closed message when a candidate is enabled"
    );
}

#[test]
fn render_summary_generated_at_in_output() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("2026-03-06T00:00:00Z"),
        "summary should contain the generated_at_utc timestamp"
    );
}

#[test]
fn render_summary_is_deterministic() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let s1 = render_summary(&safety, &guard);
    let s2 = render_summary(&safety, &guard);
    assert_eq!(s1, s2, "render_summary must be deterministic");
}

#[test]
fn render_summary_disable_reasons_appear_for_disabled_candidates() {
    let safety = make_all_disabled_safety_artifact();
    let guard = make_guard_artifact_all_disabled();
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("model_check_evidence_missing"),
        "disable reason should appear in summary"
    );
}

#[test]
fn render_summary_shows_unknown_when_safety_row_missing_for_disabled_candidate() {
    // Guard references a candidate not in safety rows — fallback to "unknown"
    let safety = SeqlockSafetyCaseArtifact {
        schema_version: SAFETY_CASE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        safety_case_hash: "orphan_hash".to_string(),
        rows: vec![],
    };
    let guard = SeqlockRolloutGuardArtifact {
        schema_version: ROLLOUT_GUARD_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-06T00:00:00Z".to_string(),
        guard_hash: "orphan_guard_hash".to_string(),
        all_candidates_disabled: true,
        rows: vec![SeqlockRolloutGuardRow {
            candidate_id: "ghost-candidate".to_string(),
            enabled: false,
            fallback_target: "rwlock".to_string(),
            required_artifacts: vec![],
            disable_reasons: vec![],
        }],
    };
    let summary = render_summary(&safety, &guard);
    assert!(
        summary.contains("ghost-candidate"),
        "disabled candidate should appear even if missing from safety rows"
    );
    assert!(
        summary.contains("unknown"),
        "should show 'unknown' when safety row is absent"
    );
}
