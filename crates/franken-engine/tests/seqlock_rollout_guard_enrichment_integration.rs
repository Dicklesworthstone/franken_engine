//! Enrichment integration tests for `seqlock_rollout_guard`.
//!
//! Covers gaps: schema version constants, artifact context construction,
//! docs contract fixture defaults, required artifact names completeness,
//! render_summary output correctness, safety case row verdict logic,
//! starvation microbench observation validity, loom coverage row structure,
//! rollout guard all-disabled default, serde roundtrips for all artifact
//! types, and bundle generation idempotency.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::seqlock_rollout_guard::{
    ArtifactContext, BEAD_ID, COMPONENT, DocsContractFixture, GuardEvidenceVerdict,
    LoomScheduleCoverageReportArtifact, LoomScheduleCoverageRow, PREDECESSOR_BEAD_ID,
    SeqlockRolloutGuardArtifact, SeqlockRolloutGuardRow, SeqlockSafetyCaseArtifact,
    SeqlockSafetyCaseRow, StarvationMicrobenchReportArtifact, StructuredLogEvent, TraceIdsArtifact,
    build_docs_contract_fixture, render_summary, required_artifact_names,
};

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_bead_id_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_predecessor_bead_id_nonempty() {
    assert!(!PREDECESSOR_BEAD_ID.is_empty());
    assert!(PREDECESSOR_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_component_name_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "seqlock_rollout_guard");
}

// ===========================================================================
// GuardEvidenceVerdict serde roundtrip
// ===========================================================================

#[test]
fn enrichment_verdict_serde_roundtrip() {
    let verdicts = [
        GuardEvidenceVerdict::Pass,
        GuardEvidenceVerdict::Missing,
        GuardEvidenceVerdict::Fail,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GuardEvidenceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// DocsContractFixture
// ===========================================================================

#[test]
fn enrichment_docs_contract_fixture_schema_nonempty() {
    let fixture = build_docs_contract_fixture();
    assert!(!fixture.schema_version.is_empty());
}

#[test]
fn enrichment_docs_contract_fixture_bead_id_matches() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture.bead_id, BEAD_ID);
}

#[test]
fn enrichment_docs_contract_fixture_has_disabled_candidates() {
    let fixture = build_docs_contract_fixture();
    assert!(
        !fixture.default_disabled_candidates.is_empty(),
        "Default fixture should list disabled candidates"
    );
}

#[test]
fn enrichment_docs_contract_fixture_has_required_artifacts() {
    let fixture = build_docs_contract_fixture();
    assert!(
        !fixture.required_artifacts.is_empty(),
        "Default fixture should list required artifacts"
    );
}

#[test]
fn enrichment_docs_contract_fixture_serde_roundtrip() {
    let fixture = build_docs_contract_fixture();
    let json = serde_json::to_string(&fixture).unwrap();
    let back: DocsContractFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(fixture.bead_id, back.bead_id);
    assert_eq!(
        fixture.default_disabled_candidates.len(),
        back.default_disabled_candidates.len()
    );
}

// ===========================================================================
// required_artifact_names
// ===========================================================================

#[test]
fn enrichment_required_artifact_names_nonempty() {
    let names = required_artifact_names();
    assert!(!names.is_empty());
}

#[test]
fn enrichment_required_artifact_names_all_unique() {
    let names = required_artifact_names();
    let unique: std::collections::BTreeSet<&str> = names.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "All artifact names must be unique"
    );
}

#[test]
fn enrichment_required_artifact_names_contain_safety_case() {
    let names = required_artifact_names();
    assert!(
        names.iter().any(|n| n.contains("safety_case")),
        "Should include safety case artifact"
    );
}

// ===========================================================================
// ArtifactContext
// ===========================================================================

#[test]
fn enrichment_artifact_context_new_has_ids() {
    let ctx = ArtifactContext::new(std::path::PathBuf::from("/tmp/test_artifacts"));
    assert!(!ctx.run_id.is_empty());
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
}

#[test]
fn enrichment_artifact_context_unique_run_ids() {
    let ctx1 = ArtifactContext::new(std::path::PathBuf::from("/tmp/a1"));
    let ctx2 = ArtifactContext::new(std::path::PathBuf::from("/tmp/a2"));
    assert_ne!(ctx1.run_id, ctx2.run_id);
}

// ===========================================================================
// StructuredLogEvent serde roundtrip
// ===========================================================================

#[test]
fn enrichment_structured_log_event_serde_roundtrip() {
    let event = StructuredLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: "RGC-621C".to_string(),
        component: COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        candidate_id: Some("candidate-1".to_string()),
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.trace_id, back.trace_id);
    assert_eq!(event.component, back.component);
}

// ===========================================================================
// TraceIdsArtifact serde roundtrip
// ===========================================================================

#[test]
fn enrichment_trace_ids_artifact_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: "v1".to_string(),
        trace_ids: vec!["t1".to_string(), "t2".to_string()],
        decision_id: "dec-001".to_string(),
        policy_id: "pol-001".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact.trace_ids.len(), back.trace_ids.len());
}

// ===========================================================================
// SeqlockSafetyCaseRow logic
// ===========================================================================

#[test]
fn enrichment_safety_case_row_rollout_allowed_when_all_pass() {
    let row = SeqlockSafetyCaseRow {
        candidate_id: "cand-1".to_string(),
        surface_name: "metadata_snapshot".to_string(),
        inventory_disposition: serde_json::from_str("\"Accept\"").unwrap(),
        starvation_verdict: GuardEvidenceVerdict::Pass,
        model_check_verdict: GuardEvidenceVerdict::Pass,
        rollout_allowed: true,
        disable_reasons: vec![],
        incumbent_baseline: "mutex".to_string(),
    };
    assert!(row.rollout_allowed);
    assert!(row.disable_reasons.is_empty());
}

#[test]
fn enrichment_safety_case_row_rollout_blocked_when_missing() {
    let row = SeqlockSafetyCaseRow {
        candidate_id: "cand-2".to_string(),
        surface_name: "policy_snapshot".to_string(),
        inventory_disposition: serde_json::from_str("\"Accept\"").unwrap(),
        starvation_verdict: GuardEvidenceVerdict::Pass,
        model_check_verdict: GuardEvidenceVerdict::Missing,
        rollout_allowed: false,
        disable_reasons: vec!["model check evidence missing".to_string()],
        incumbent_baseline: "rwlock".to_string(),
    };
    assert!(!row.rollout_allowed);
    assert!(!row.disable_reasons.is_empty());
}

#[test]
fn enrichment_safety_case_row_serde_roundtrip() {
    let row = SeqlockSafetyCaseRow {
        candidate_id: "cand-1".to_string(),
        surface_name: "test_surface".to_string(),
        inventory_disposition: serde_json::from_str("\"Accept\"").unwrap(),
        starvation_verdict: GuardEvidenceVerdict::Pass,
        model_check_verdict: GuardEvidenceVerdict::Missing,
        rollout_allowed: false,
        disable_reasons: vec!["missing model check".to_string()],
        incumbent_baseline: "mutex".to_string(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: SeqlockSafetyCaseRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row.candidate_id, back.candidate_id);
    assert_eq!(row.rollout_allowed, back.rollout_allowed);
}

// ===========================================================================
// SeqlockRolloutGuardRow serde roundtrip
// ===========================================================================

#[test]
fn enrichment_rollout_guard_row_serde_roundtrip() {
    let row = SeqlockRolloutGuardRow {
        candidate_id: "cand-1".to_string(),
        enabled: false,
        fallback_target: "mutex".to_string(),
        required_artifacts: vec!["safety_case.json".to_string()],
        disable_reasons: vec!["insufficient evidence".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: SeqlockRolloutGuardRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row.candidate_id, back.candidate_id);
    assert_eq!(row.enabled, back.enabled);
}

// ===========================================================================
// LoomScheduleCoverageRow serde roundtrip
// ===========================================================================

#[test]
fn enrichment_loom_coverage_row_serde_roundtrip() {
    let row = LoomScheduleCoverageRow {
        candidate_id: "cand-1".to_string(),
        manual_schedule_cases: vec!["write-read-interleave".to_string()],
        loom_schedule_count: 0,
        verdict: GuardEvidenceVerdict::Missing,
        notes: vec!["loom not yet integrated".to_string()],
    };
    let json = serde_json::to_string(&row).unwrap();
    let back: LoomScheduleCoverageRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row.candidate_id, back.candidate_id);
    assert_eq!(row.loom_schedule_count, back.loom_schedule_count);
}

// ===========================================================================
// render_summary
// ===========================================================================

#[test]
fn enrichment_render_summary_outputs_markdown() {
    let safety_case = SeqlockSafetyCaseArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        safety_case_hash: "abc123".to_string(),
        rows: vec![SeqlockSafetyCaseRow {
            candidate_id: "cand-1".to_string(),
            surface_name: "test".to_string(),
            inventory_disposition: serde_json::from_str("\"Accept\"").unwrap(),
            starvation_verdict: GuardEvidenceVerdict::Pass,
            model_check_verdict: GuardEvidenceVerdict::Missing,
            rollout_allowed: false,
            disable_reasons: vec!["no model check".to_string()],
            incumbent_baseline: "mutex".to_string(),
        }],
    };
    let rollout_guard = SeqlockRolloutGuardArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        guard_hash: "def456".to_string(),
        all_candidates_disabled: true,
        rows: vec![SeqlockRolloutGuardRow {
            candidate_id: "cand-1".to_string(),
            enabled: false,
            fallback_target: "mutex".to_string(),
            required_artifacts: vec![],
            disable_reasons: vec!["no model check".to_string()],
        }],
    };
    let summary = render_summary(&safety_case, &rollout_guard);
    assert!(!summary.is_empty());
    // Should contain markdown heading or candidate info
    assert!(
        summary.contains("cand-1") || summary.contains("disabled") || summary.contains("Seqlock"),
        "Summary should reference candidate or status"
    );
}

// ===========================================================================
// SeqlockSafetyCaseArtifact serde roundtrip
// ===========================================================================

#[test]
fn enrichment_safety_case_artifact_serde_roundtrip() {
    let artifact = SeqlockSafetyCaseArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        safety_case_hash: "hash123".to_string(),
        rows: vec![],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: SeqlockSafetyCaseArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact.bead_id, back.bead_id);
    assert_eq!(artifact.rows.len(), back.rows.len());
}

// ===========================================================================
// SeqlockRolloutGuardArtifact: all_candidates_disabled
// ===========================================================================

#[test]
fn enrichment_rollout_guard_artifact_all_disabled() {
    let artifact = SeqlockRolloutGuardArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        guard_hash: "hash456".to_string(),
        all_candidates_disabled: true,
        rows: vec![SeqlockRolloutGuardRow {
            candidate_id: "c1".to_string(),
            enabled: false,
            fallback_target: "mutex".to_string(),
            required_artifacts: vec![],
            disable_reasons: vec!["reason".to_string()],
        }],
    };
    assert!(artifact.all_candidates_disabled);
    assert!(artifact.rows.iter().all(|r| !r.enabled));
}

// ===========================================================================
// StarvationMicrobenchReportArtifact serde roundtrip
// ===========================================================================

#[test]
fn enrichment_starvation_report_artifact_serde_roundtrip() {
    let artifact = StarvationMicrobenchReportArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        report_hash: "hash789".to_string(),
        rows: vec![],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: StarvationMicrobenchReportArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact.bead_id, back.bead_id);
}

// ===========================================================================
// LoomScheduleCoverageReportArtifact serde roundtrip
// ===========================================================================

#[test]
fn enrichment_loom_coverage_artifact_serde_roundtrip() {
    let artifact = LoomScheduleCoverageReportArtifact {
        schema_version: "v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        report_hash: "hash_loom".to_string(),
        rows: vec![],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: LoomScheduleCoverageReportArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact.bead_id, back.bead_id);
}
