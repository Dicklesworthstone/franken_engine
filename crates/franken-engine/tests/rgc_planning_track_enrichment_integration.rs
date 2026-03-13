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
    clippy::identity_op
)]

use std::io;
use std::path::PathBuf;

use frankenengine_engine::rgc_planning_track::{
    BEAD_ID, BlockerClassSource, BundleManifest, CiGateSource, COMPONENT,
    DependentTrackEvidence, EVENT_SCHEMA_VERSION, MILESTONE_GATEBOOK_SCHEMA_VERSION,
    MilestoneEvidenceLink, PassPredicateSource,
    PlanningMilestoneGatebook, PlanningTrackContractBundle, PlanningTrackEvent,
    RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION, RgcPlanningTrackBundleArtifacts,
    RgcPlanningTrackError, RiskAcceptanceEntry, RiskAcceptanceLedger, RiskAcceptanceStatus,
    RollbackTriggerSource, SCHEMA_VERSION, SCOPE_CONTRACT_SCHEMA_VERSION,
    ScopeContractSnapshot, TrackRef, ValidationState, WAVE_HANDOFF_MATRIX_SCHEMA_VERSION,
    WaveHandoffMatrix, build_rgc_planning_track_bundle_with_generated_at,
};

// =========================================================================
// Helper: build a bundle at a known timestamp (before risk expiry)
// =========================================================================

fn bundle_before_expiry() -> PlanningTrackContractBundle {
    // 2026-03-01T00:00:00Z
    build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build bundle")
}

// =========================================================================
// A. Constants verification
// =========================================================================

#[test]
fn enrichment_schema_version_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!SCOPE_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!MILESTONE_GATEBOOK_SCHEMA_VERSION.is_empty());
    assert!(!RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION.is_empty());
    assert!(!WAVE_HANDOFF_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(!EVENT_SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_schema_version_constants_distinct() {
    let versions = [
        SCHEMA_VERSION,
        SCOPE_CONTRACT_SCHEMA_VERSION,
        MILESTONE_GATEBOOK_SCHEMA_VERSION,
        RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION,
        WAVE_HANDOFF_MATRIX_SCHEMA_VERSION,
        EVENT_SCHEMA_VERSION,
    ];
    let set: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(set.len(), versions.len(), "schema versions must be distinct");
}

// =========================================================================
// B. RgcPlanningTrackError Display all variants
// =========================================================================

#[test]
fn enrichment_error_display_io() {
    let err = RgcPlanningTrackError::Io {
        path: PathBuf::from("/tmp/test"),
        source: io::Error::new(io::ErrorKind::NotFound, "no such file"),
    };
    let display = err.to_string();
    assert!(display.contains("/tmp/test"));
    assert!(display.contains("no such file"));
}

#[test]
fn enrichment_error_display_json_parse() {
    let err = RgcPlanningTrackError::JsonParse {
        path: PathBuf::from("test.json"),
        reason: "expected comma".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("test.json"));
    assert!(display.contains("expected comma"));
}

#[test]
fn enrichment_error_display_timestamp_parse() {
    let err = RgcPlanningTrackError::TimestampParse {
        field: "generated_at",
        value: "not-a-date".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("generated_at"));
    assert!(display.contains("not-a-date"));
}

#[test]
fn enrichment_error_display_coordination_validation() {
    let err = RgcPlanningTrackError::CoordinationValidation {
        reason: "protocol mismatch".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("protocol mismatch"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err = RgcPlanningTrackError::CoordinationValidation {
        reason: "test".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// C. RiskAcceptanceStatus ordering and serde
// =========================================================================

#[test]
fn enrichment_risk_acceptance_status_serde_current() {
    let json = serde_json::to_string(&RiskAcceptanceStatus::Current).unwrap();
    let back: RiskAcceptanceStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, RiskAcceptanceStatus::Current);
}

#[test]
fn enrichment_risk_acceptance_status_serde_expired() {
    let json = serde_json::to_string(&RiskAcceptanceStatus::Expired).unwrap();
    let back: RiskAcceptanceStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, RiskAcceptanceStatus::Expired);
}

#[test]
fn enrichment_risk_acceptance_status_snake_case() {
    let json = serde_json::to_string(&RiskAcceptanceStatus::Current).unwrap();
    assert_eq!(json, "\"current\"");
    let json2 = serde_json::to_string(&RiskAcceptanceStatus::Expired).unwrap();
    assert_eq!(json2, "\"expired\"");
}

// =========================================================================
// D. TrackRef serde roundtrip
// =========================================================================

#[test]
fn enrichment_track_ref_serde_roundtrip() {
    let track = TrackRef {
        id: "RGC-010".to_string(),
        name: "Planning Track".to_string(),
    };
    let json = serde_json::to_string(&track).unwrap();
    let back: TrackRef = serde_json::from_str(&json).unwrap();
    assert_eq!(track, back);
}

#[test]
fn enrichment_track_ref_eq() {
    let a = TrackRef {
        id: "A".to_string(),
        name: "AA".to_string(),
    };
    let b = TrackRef {
        id: "A".to_string(),
        name: "AA".to_string(),
    };
    let c = TrackRef {
        id: "B".to_string(),
        name: "BB".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// =========================================================================
// E. ValidationState serde
// =========================================================================

#[test]
fn enrichment_validation_state_valid_serde() {
    let state = ValidationState {
        valid: true,
        detail: None,
    };
    let json = serde_json::to_string(&state).unwrap();
    let back: ValidationState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
    assert!(back.valid);
    assert!(back.detail.is_none());
}

#[test]
fn enrichment_validation_state_invalid_with_detail() {
    let state = ValidationState {
        valid: false,
        detail: Some("protocol mismatch".to_string()),
    };
    let json = serde_json::to_string(&state).unwrap();
    let back: ValidationState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
    assert!(!back.valid);
    assert_eq!(back.detail.as_deref(), Some("protocol mismatch"));
}

// =========================================================================
// F. PlanningTrackEvent serde
// =========================================================================

#[test]
fn enrichment_planning_track_event_serde_roundtrip() {
    let event = PlanningTrackEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        artifact_ref: Some("/tmp/artifact.json".to_string()),
        detail: Some("detail text".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: PlanningTrackEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_planning_track_event_with_error_code() {
    let event = PlanningTrackEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: COMPONENT.to_string(),
        event: "fail_event".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-RGC-010-RISK-0001".to_string()),
        artifact_ref: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: PlanningTrackEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("FE-RGC-010-RISK-0001".to_string()));
}

// =========================================================================
// G. DependentTrackEvidence serde
// =========================================================================

#[test]
fn enrichment_dependent_track_evidence_serde_roundtrip() {
    let dte = DependentTrackEvidence {
        bead_id: "bd-test".to_string(),
        evidence_ref: "artifact.json".to_string(),
        verification_command: "rch exec -- cargo test".to_string(),
    };
    let json = serde_json::to_string(&dte).unwrap();
    let back: DependentTrackEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(dte, back);
}

// =========================================================================
// H. MilestoneEvidenceLink serde
// =========================================================================

#[test]
fn enrichment_milestone_evidence_link_serde_roundtrip() {
    let link = MilestoneEvidenceLink {
        milestone: "M1".to_string(),
        description: "test milestone".to_string(),
        required_beads: vec!["bd-1".to_string()],
        gate_id: "gate-1".to_string(),
        gate_command: "rch exec -- cargo test".to_string(),
        required_artifacts: vec!["artifact.json".to_string()],
        dependent_track_evidence: vec!["evidence".to_string()],
        stop_go_rule: "all pass".to_string(),
    };
    let json = serde_json::to_string(&link).unwrap();
    let back: MilestoneEvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(link, back);
}

// =========================================================================
// I. RiskAcceptanceEntry serde
// =========================================================================

#[test]
fn enrichment_risk_acceptance_entry_serde_roundtrip() {
    let entry = RiskAcceptanceEntry {
        risk_id: "RGC-RISK-001".to_string(),
        title: "test risk".to_string(),
        domain: "testing".to_string(),
        risk_level: "high".to_string(),
        owner_role: "engineer".to_string(),
        mitigation_beads: vec!["bd-1".to_string()],
        mitigation_summary: "mitigated".to_string(),
        rollback_plan: "rollback".to_string(),
        last_reviewed_utc: "2026-03-01T00:00:00Z".to_string(),
        accepted_until_utc: "2026-03-12T00:00:00Z".to_string(),
        acceptance_status: RiskAcceptanceStatus::Current,
        review_gate_ids: vec!["gate-1".to_string()],
        review_required_evidence_fields: vec!["field1".to_string()],
        milestones_pending: vec!["M1".to_string()],
        open_actions: vec![],
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RiskAcceptanceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// =========================================================================
// J. BlockerClassSource serde
// =========================================================================

#[test]
fn enrichment_blocker_class_source_serde_roundtrip() {
    let blocker = BlockerClassSource {
        class_id: "BC-001".to_string(),
        required_evidence: vec!["evidence1".to_string(), "evidence2".to_string()],
    };
    let json = serde_json::to_string(&blocker).unwrap();
    let back: BlockerClassSource = serde_json::from_str(&json).unwrap();
    assert_eq!(blocker, back);
}

// =========================================================================
// K. PassPredicateSource serde
// =========================================================================

#[test]
fn enrichment_pass_predicate_source_serde_roundtrip() {
    let pred = PassPredicateSource {
        predicate_id: "PP-001".to_string(),
        description: "test predicate".to_string(),
        metric: "test_pass_rate".to_string(),
        comparator: ">=".to_string(),
        threshold: serde_json::json!(95),
        unit: "percent".to_string(),
        source_beads: vec!["bd-1".to_string()],
        evaluation_command: "rch exec -- cargo test".to_string(),
    };
    let json = serde_json::to_string(&pred).unwrap();
    let back: PassPredicateSource = serde_json::from_str(&json).unwrap();
    assert_eq!(pred, back);
}

// =========================================================================
// L. RollbackTriggerSource serde
// =========================================================================

#[test]
fn enrichment_rollback_trigger_source_serde_roundtrip() {
    let trigger = RollbackTriggerSource {
        trigger_id: "RT-001".to_string(),
        condition_expression: "fail_rate > 10%".to_string(),
        required_probe_command: "rch exec -- cargo test".to_string(),
        rollback_action: "revert to baseline".to_string(),
    };
    let json = serde_json::to_string(&trigger).unwrap();
    let back: RollbackTriggerSource = serde_json::from_str(&json).unwrap();
    assert_eq!(trigger, back);
}

// =========================================================================
// M. CiGateSource serde
// =========================================================================

#[test]
fn enrichment_ci_gate_source_serde_roundtrip() {
    let gate = CiGateSource {
        workflow_id: "WF-001".to_string(),
        command: "rch exec -- cargo check".to_string(),
        report_only_until_utc: "2026-03-01T00:00:00Z".to_string(),
        fail_closed_after_utc: "2026-03-12T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&gate).unwrap();
    let back: CiGateSource = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

// =========================================================================
// N. Bundle hash determinism
// =========================================================================

#[test]
fn enrichment_bundle_hash_deterministic() {
    let b1 = bundle_before_expiry();
    let b2 = bundle_before_expiry();
    assert_eq!(b1.report_hash, b2.report_hash);
    assert!(!b1.report_hash.is_empty());
}

#[test]
fn enrichment_bundle_hash_changes_with_timestamp() {
    let b1 = build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).unwrap();
    let b2 = build_rgc_planning_track_bundle_with_generated_at(1_772_467_201_000).unwrap();
    assert_ne!(b1.report_hash, b2.report_hash);
}

// =========================================================================
// O. Bundle generated_at fields
// =========================================================================

#[test]
fn enrichment_bundle_generated_at_matches_input() {
    let ts = 1_772_467_200_000;
    let bundle = build_rgc_planning_track_bundle_with_generated_at(ts).unwrap();
    assert_eq!(bundle.generated_at_unix_ms, ts);
    assert!(!bundle.generated_at_utc.is_empty());
    assert!(bundle.generated_at_utc.contains("2026"));
}

// =========================================================================
// P. Bundle sub-artifacts have correct schema versions
// =========================================================================

#[test]
fn enrichment_bundle_scope_contract_schema() {
    let bundle = bundle_before_expiry();
    assert_eq!(
        bundle.scope_contract_snapshot.schema_version,
        SCOPE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(bundle.scope_contract_snapshot.bead_id, BEAD_ID);
}

#[test]
fn enrichment_bundle_milestone_gatebook_schema() {
    let bundle = bundle_before_expiry();
    assert_eq!(
        bundle.milestone_gatebook.schema_version,
        MILESTONE_GATEBOOK_SCHEMA_VERSION
    );
    assert_eq!(bundle.milestone_gatebook.bead_id, BEAD_ID);
}

#[test]
fn enrichment_bundle_risk_acceptance_ledger_schema() {
    let bundle = bundle_before_expiry();
    assert_eq!(
        bundle.risk_acceptance_ledger.schema_version,
        RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(bundle.risk_acceptance_ledger.bead_id, BEAD_ID);
}

#[test]
fn enrichment_bundle_wave_handoff_matrix_schema() {
    let bundle = bundle_before_expiry();
    assert_eq!(
        bundle.wave_handoff_matrix.schema_version,
        WAVE_HANDOFF_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(bundle.wave_handoff_matrix.bead_id, BEAD_ID);
}

// =========================================================================
// Q. Scope contract snapshot structure
// =========================================================================

#[test]
fn enrichment_scope_contract_snapshot_has_track() {
    let bundle = bundle_before_expiry();
    let scope = &bundle.scope_contract_snapshot;
    assert!(!scope.track.id.is_empty());
    assert!(!scope.track.name.is_empty());
}

#[test]
fn enrichment_scope_contract_snapshot_has_evidence_links() {
    let bundle = bundle_before_expiry();
    assert!(
        !bundle
            .scope_contract_snapshot
            .milestone_evidence_links
            .is_empty()
    );
    for link in &bundle.scope_contract_snapshot.milestone_evidence_links {
        assert!(!link.milestone.is_empty());
        assert!(!link.gate_id.is_empty());
        assert!(!link.gate_command.is_empty());
    }
}

#[test]
fn enrichment_scope_contract_snapshot_open_beads_sorted() {
    let bundle = bundle_before_expiry();
    let beads = &bundle.scope_contract_snapshot.open_bead_ids;
    for window in beads.windows(2) {
        assert!(
            window[0] < window[1],
            "open_bead_ids not sorted: {:?} >= {:?}",
            window[0],
            window[1]
        );
    }
}

// =========================================================================
// R. Milestone gatebook structure
// =========================================================================

#[test]
fn enrichment_milestone_gatebook_dependency_order() {
    let bundle = bundle_before_expiry();
    assert!(bundle.milestone_gatebook.dependency_order_preserved);
    let milestone_names: Vec<&str> = bundle
        .milestone_gatebook
        .milestones
        .iter()
        .map(|m| m.milestone.as_str())
        .collect();
    assert_eq!(milestone_names, ["M1", "M2", "M3", "M4", "M5"]);
}

#[test]
fn enrichment_milestone_gatebook_rch_backed() {
    let bundle = bundle_before_expiry();
    assert!(bundle.milestone_gatebook.all_cargo_commands_rch_backed);
    for milestone in &bundle.milestone_gatebook.milestones {
        assert!(milestone.cargo_commands_rch_backed);
    }
}

#[test]
fn enrichment_milestone_gatebook_has_blocker_classes() {
    let bundle = bundle_before_expiry();
    assert!(!bundle.milestone_gatebook.blocker_classes.is_empty());
    for bc in &bundle.milestone_gatebook.blocker_classes {
        assert!(!bc.class_id.is_empty());
    }
}

#[test]
fn enrichment_milestones_have_pass_predicates() {
    let bundle = bundle_before_expiry();
    for milestone in &bundle.milestone_gatebook.milestones {
        assert!(
            !milestone.pass_predicates.is_empty(),
            "milestone {} has no pass predicates",
            milestone.milestone
        );
        for pred in &milestone.pass_predicates {
            assert!(!pred.predicate_id.is_empty());
            assert!(!pred.evaluation_command.is_empty());
        }
    }
}

#[test]
fn enrichment_milestones_have_ci_gates() {
    let bundle = bundle_before_expiry();
    for milestone in &bundle.milestone_gatebook.milestones {
        assert!(!milestone.ci_gate.workflow_id.is_empty());
        assert!(!milestone.ci_gate.command.is_empty());
    }
}

// =========================================================================
// S. Risk acceptance ledger structure
// =========================================================================

#[test]
fn enrichment_risk_ledger_all_current_before_expiry() {
    let bundle = bundle_before_expiry();
    assert!(bundle.risk_acceptance_ledger.all_acceptances_current);
    assert!(bundle.risk_acceptance_ledger.expired_risk_ids.is_empty());
    for entry in &bundle.risk_acceptance_ledger.entries {
        assert_eq!(entry.acceptance_status, RiskAcceptanceStatus::Current);
    }
}

#[test]
fn enrichment_risk_ledger_has_entries() {
    let bundle = bundle_before_expiry();
    assert!(!bundle.risk_acceptance_ledger.entries.is_empty());
    for entry in &bundle.risk_acceptance_ledger.entries {
        assert!(!entry.risk_id.is_empty());
        assert!(!entry.title.is_empty());
        assert!(!entry.domain.is_empty());
    }
}

#[test]
fn enrichment_risk_ledger_fail_closed_on_stale() {
    let bundle = bundle_before_expiry();
    assert!(bundle.risk_acceptance_ledger.fail_closed_on_stale_review);
}

#[test]
fn enrichment_risk_ledger_expired_after_due() {
    // 2026-03-13T00:00:00Z
    let bundle = build_rgc_planning_track_bundle_with_generated_at(1_773_504_000_000).unwrap();
    assert!(!bundle.risk_acceptance_ledger.all_acceptances_current);
    assert!(!bundle.risk_acceptance_ledger.expired_risk_ids.is_empty());
    let has_expired_entry = bundle
        .risk_acceptance_ledger
        .entries
        .iter()
        .any(|e| e.acceptance_status == RiskAcceptanceStatus::Expired);
    assert!(has_expired_entry);
}

// =========================================================================
// T. Wave handoff matrix structure
// =========================================================================

#[test]
fn enrichment_wave_handoff_matrix_validations_pass() {
    let bundle = bundle_before_expiry();
    assert!(bundle.wave_handoff_matrix.protocol_validation.valid);
    assert!(bundle.wave_handoff_matrix.handoff_validation.valid);
    assert!(bundle.wave_handoff_matrix.transition_validation.valid);
}

#[test]
fn enrichment_wave_handoff_matrix_has_dry_run_events() {
    let bundle = bundle_before_expiry();
    assert!(
        !bundle
            .wave_handoff_matrix
            .coordination_dry_run
            .events
            .is_empty()
    );
}

#[test]
fn enrichment_wave_handoff_matrix_has_dependent_evidence() {
    let bundle = bundle_before_expiry();
    assert!(!bundle.wave_handoff_matrix.dependent_track_evidence.is_empty());
}

// =========================================================================
// U. BundleManifest serde
// =========================================================================

#[test]
fn enrichment_bundle_manifest_serde_roundtrip() {
    let manifest = BundleManifest {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        generated_at_unix_ms: 1_000,
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        report_hash: "abc123".to_string(),
        scope_contract_snapshot: "scope_contract_snapshot.json".to_string(),
        milestone_gatebook: "milestone_gatebook.json".to_string(),
        risk_acceptance_ledger: "risk_acceptance_ledger.json".to_string(),
        wave_handoff_matrix: "wave_handoff_matrix.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
        summary_md: "summary.md".to_string(),
        trace_ids: "trace_ids".to_string(),
        dependency_order_preserved: true,
        all_gate_commands_rch_backed: true,
        all_risk_acceptances_current: true,
        expired_risk_count: 0,
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: BundleManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// =========================================================================
// V. PlanningTrackContractBundle serde roundtrip
// =========================================================================

#[test]
fn enrichment_contract_bundle_serde_roundtrip() {
    let bundle = bundle_before_expiry();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: PlanningTrackContractBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.schema_version, back.schema_version);
    assert_eq!(bundle.bead_id, back.bead_id);
    assert_eq!(bundle.generated_at_unix_ms, back.generated_at_unix_ms);
    assert_eq!(bundle.report_hash, back.report_hash);
}

// =========================================================================
// W. RgcPlanningTrackBundleArtifacts Eq
// =========================================================================

#[test]
fn enrichment_bundle_artifacts_eq() {
    let a = RgcPlanningTrackBundleArtifacts {
        out_dir: PathBuf::from("/tmp/a"),
        scope_contract_snapshot_path: PathBuf::from("/tmp/a/scope.json"),
        milestone_gatebook_path: PathBuf::from("/tmp/a/gates.json"),
        risk_acceptance_ledger_path: PathBuf::from("/tmp/a/risk.json"),
        wave_handoff_matrix_path: PathBuf::from("/tmp/a/wave.json"),
        run_manifest_path: PathBuf::from("/tmp/a/manifest.json"),
        events_path: PathBuf::from("/tmp/a/events.jsonl"),
        commands_path: PathBuf::from("/tmp/a/commands.txt"),
        summary_path: PathBuf::from("/tmp/a/summary.md"),
        trace_ids_path: PathBuf::from("/tmp/a/trace_ids"),
        report_hash: "hash1".to_string(),
        expired_risk_count: 0,
        all_gate_commands_rch_backed: true,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// X. Debug formatting nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_error() {
    let err = RgcPlanningTrackError::CoordinationValidation {
        reason: "test".to_string(),
    };
    let dbg = format!("{err:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("CoordinationValidation"));
}

#[test]
fn enrichment_debug_nonempty_track_ref() {
    let track = TrackRef {
        id: "T1".to_string(),
        name: "Track One".to_string(),
    };
    let dbg = format!("{track:?}");
    assert!(dbg.contains("TrackRef"));
}

#[test]
fn enrichment_debug_nonempty_validation_state() {
    let state = ValidationState {
        valid: true,
        detail: None,
    };
    let dbg = format!("{state:?}");
    assert!(dbg.contains("ValidationState"));
}

#[test]
fn enrichment_debug_nonempty_risk_acceptance_status() {
    let current = format!("{:?}", RiskAcceptanceStatus::Current);
    let expired = format!("{:?}", RiskAcceptanceStatus::Expired);
    assert!(current.contains("Current"));
    assert!(expired.contains("Expired"));
}

#[test]
fn enrichment_debug_nonempty_bundle() {
    let bundle = bundle_before_expiry();
    let dbg = format!("{bundle:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PlanningTrackContractBundle"));
}

// =========================================================================
// Y. ScopeContractSnapshot serde roundtrip
// =========================================================================

#[test]
fn enrichment_scope_contract_snapshot_serde_roundtrip() {
    let bundle = bundle_before_expiry();
    let json = serde_json::to_string(&bundle.scope_contract_snapshot).unwrap();
    let back: ScopeContractSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.scope_contract_snapshot, back);
}

// =========================================================================
// Z. RiskAcceptanceLedger serde roundtrip
// =========================================================================

#[test]
fn enrichment_risk_acceptance_ledger_serde_roundtrip() {
    let bundle = bundle_before_expiry();
    let json = serde_json::to_string(&bundle.risk_acceptance_ledger).unwrap();
    let back: RiskAcceptanceLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.risk_acceptance_ledger, back);
}

// =========================================================================
// AA. WaveHandoffMatrix serde roundtrip
// =========================================================================

#[test]
fn enrichment_wave_handoff_matrix_serde_roundtrip() {
    let bundle = bundle_before_expiry();
    let json = serde_json::to_string(&bundle.wave_handoff_matrix).unwrap();
    let back: WaveHandoffMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.wave_handoff_matrix, back);
}

// =========================================================================
// AB. PlanningMilestoneGatebook serde roundtrip
// =========================================================================

#[test]
fn enrichment_milestone_gatebook_serde_roundtrip() {
    let bundle = bundle_before_expiry();
    let json = serde_json::to_string(&bundle.milestone_gatebook).unwrap();
    let back: PlanningMilestoneGatebook = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.milestone_gatebook, back);
}
