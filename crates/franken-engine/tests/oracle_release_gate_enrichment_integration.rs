//! Enrichment integration tests for `oracle_release_gate`.
//!
//! Focuses on: threshold direction edge cases, GateVerdict semantics,
//! report integrity, triage bundle remediation completeness, event structure,
//! default condition coverage, serde roundtrips for all types,
//! deterministic hashing, and fail-closed semantics.

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

use std::collections::BTreeSet;

use frankenengine_engine::oracle_release_gate::{
    BEAD_ID, BlockerThreshold, COMPONENT, DEFAULT_MAX_REGRESSION, DEFAULT_MAX_UNRESOLVED,
    DEFAULT_MIN_PASS_RATE, GateEvaluation, GateVerdict, OracleGateCondition, OracleKind,
    OracleReleaseGateEvent, OracleReleaseGateReport, POLICY_ID, SCHEMA_VERSION, ThresholdDirection,
    TriageBundle, TriageBundleEntry, TriageSeverity, build_gate_event, build_report,
    build_triage_bundle, default_gate_conditions, evaluate_condition,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLIONTHS: u64 = 1_000_000;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_condition(
    id: &str,
    kind: OracleKind,
    direction: ThresholdDirection,
    threshold: u64,
    hard: bool,
) -> OracleGateCondition {
    OracleGateCondition {
        condition_id: id.to_string(),
        description: format!("Enrichment test: {id}"),
        oracle_kind: kind,
        threshold: BlockerThreshold {
            name: format!("threshold_{id}"),
            threshold_value: threshold,
            direction,
            is_hard_blocker: hard,
        },
        policy_ref: POLICY_ID.to_string(),
        bead_ref: None,
    }
}

fn pass_eval(id: &str, value: u64) -> GateEvaluation {
    GateEvaluation {
        condition_id: id.to_string(),
        observed_value: value,
        threshold_value: value,
        verdict: GateVerdict::Pass,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: 0,
    }
}

fn fail_eval(id: &str, observed: u64, threshold: u64) -> GateEvaluation {
    GateEvaluation {
        condition_id: id.to_string(),
        observed_value: observed,
        threshold_value: threshold,
        verdict: GateVerdict::Fail,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: observed as i64 - threshold as i64,
    }
}

// ===========================================================================
// Section 1: OracleKind enrichment
// ===========================================================================

#[test]
fn enrichment_oracle_kind_count_is_six() {
    assert_eq!(OracleKind::all().len(), 6);
}

#[test]
fn enrichment_oracle_kind_as_str_unique() {
    let strs: BTreeSet<&str> = OracleKind::all().iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_oracle_kind_display_matches_as_str() {
    for kind in OracleKind::all() {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_oracle_kind_ord_deterministic() {
    let mut v1: Vec<OracleKind> = OracleKind::all().to_vec();
    let mut v2 = v1.clone();
    v2.reverse();
    v2.sort();
    v1.sort();
    assert_eq!(v1, v2);
}

#[test]
fn enrichment_oracle_kind_debug_non_empty() {
    for kind in OracleKind::all() {
        assert!(!format!("{kind:?}").is_empty());
    }
}

// ===========================================================================
// Section 2: ThresholdDirection enrichment
// ===========================================================================

#[test]
fn enrichment_threshold_direction_as_str_values() {
    assert_eq!(ThresholdDirection::AtLeast.as_str(), "at_least");
    assert_eq!(ThresholdDirection::AtMost.as_str(), "at_most");
    assert_eq!(ThresholdDirection::Exactly.as_str(), "exactly");
}

#[test]
fn enrichment_threshold_direction_display_matches_as_str() {
    for dir in [
        ThresholdDirection::AtLeast,
        ThresholdDirection::AtMost,
        ThresholdDirection::Exactly,
    ] {
        assert_eq!(dir.to_string(), dir.as_str());
    }
}

#[test]
fn enrichment_threshold_at_least_u64_max() {
    assert!(ThresholdDirection::AtLeast.passes(u64::MAX, u64::MAX));
    assert!(!ThresholdDirection::AtLeast.passes(u64::MAX - 1, u64::MAX));
}

#[test]
fn enrichment_threshold_at_most_u64_max() {
    assert!(ThresholdDirection::AtMost.passes(u64::MAX, u64::MAX));
    assert!(ThresholdDirection::AtMost.passes(0, u64::MAX));
}

#[test]
fn enrichment_threshold_exactly_zero() {
    assert!(ThresholdDirection::Exactly.passes(0, 0));
    assert!(!ThresholdDirection::Exactly.passes(1, 0));
}

// ===========================================================================
// Section 3: BlockerThreshold enrichment
// ===========================================================================

#[test]
fn enrichment_blocker_threshold_evaluate_at_most() {
    let t = BlockerThreshold {
        name: "test".to_string(),
        threshold_value: 100,
        direction: ThresholdDirection::AtMost,
        is_hard_blocker: true,
    };
    assert!(t.evaluate(50));
    assert!(t.evaluate(100));
    assert!(!t.evaluate(101));
}

#[test]
fn enrichment_blocker_threshold_evaluate_exactly() {
    let t = BlockerThreshold {
        name: "exact".to_string(),
        threshold_value: 42,
        direction: ThresholdDirection::Exactly,
        is_hard_blocker: false,
    };
    assert!(t.evaluate(42));
    assert!(!t.evaluate(43));
    assert!(!t.evaluate(41));
}

#[test]
fn enrichment_blocker_threshold_serde_all_directions() {
    for dir in [
        ThresholdDirection::AtLeast,
        ThresholdDirection::AtMost,
        ThresholdDirection::Exactly,
    ] {
        let t = BlockerThreshold {
            name: "serde_test".to_string(),
            threshold_value: 999,
            direction: dir,
            is_hard_blocker: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: BlockerThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ===========================================================================
// Section 4: evaluate_condition enrichment
// ===========================================================================

#[test]
fn enrichment_evaluate_condition_pass_margin_at_least() {
    let cond = make_condition("margin", OracleKind::Contract, ThresholdDirection::AtLeast, 100, true);
    let eval = evaluate_condition(&cond, 200, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 100);
}

#[test]
fn enrichment_evaluate_condition_fail_margin_at_least() {
    let cond = make_condition("fail_margin", OracleKind::Scenario, ThresholdDirection::AtLeast, 100, true);
    let eval = evaluate_condition(&cond, 50, None, None);
    assert_eq!(eval.verdict, GateVerdict::Fail);
    assert_eq!(eval.margin_millionths, -50);
}

#[test]
fn enrichment_evaluate_condition_pass_margin_at_most() {
    let cond = make_condition("at_most_pass", OracleKind::Metric, ThresholdDirection::AtMost, 100, false);
    let eval = evaluate_condition(&cond, 50, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 50);
}

#[test]
fn enrichment_evaluate_condition_advisory_when_soft() {
    let cond = make_condition("soft_fail", OracleKind::Metric, ThresholdDirection::AtMost, 50, false);
    let eval = evaluate_condition(&cond, 100, None, None);
    assert_eq!(eval.verdict, GateVerdict::Advisory);
    assert!(eval.margin_millionths < 0);
}

#[test]
fn enrichment_evaluate_condition_exactly_pass_zero_margin() {
    let cond = make_condition("exact_pass", OracleKind::Replay, ThresholdDirection::Exactly, 0, true);
    let eval = evaluate_condition(&cond, 0, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 0);
}

#[test]
fn enrichment_evaluate_condition_evidence_refs_propagated() {
    let cond = make_condition("refs", OracleKind::Evidence, ThresholdDirection::AtLeast, 0, true);
    let eval = evaluate_condition(&cond, 100, Some("ev-abc"), Some("replay-xyz"));
    assert_eq!(eval.evidence_ref.as_deref(), Some("ev-abc"));
    assert_eq!(eval.replay_ref.as_deref(), Some("replay-xyz"));
}

// ===========================================================================
// Section 5: GateVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_gate_verdict_as_str_all_variants() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::Fail.as_str(), "fail");
    assert_eq!(GateVerdict::Advisory.as_str(), "advisory");
    assert_eq!(GateVerdict::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn enrichment_gate_verdict_display_matches_as_str() {
    for v in [GateVerdict::Pass, GateVerdict::Fail, GateVerdict::Advisory, GateVerdict::Inconclusive] {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_gate_verdict_blocks_release_semantics() {
    assert!(!GateVerdict::Pass.blocks_release());
    assert!(GateVerdict::Fail.blocks_release());
    assert!(!GateVerdict::Advisory.blocks_release());
    assert!(GateVerdict::Inconclusive.blocks_release());
}

// ===========================================================================
// Section 6: build_report enrichment
// ===========================================================================

#[test]
fn enrichment_report_all_pass_does_not_block() {
    let evals = vec![pass_eval("a", 100), pass_eval("b", 200)];
    let report = build_report(epoch(), "rc-enr-pass", evals);
    assert!(!report.blocks_release());
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert_eq!(report.pass_count, 2);
    assert_eq!(report.fail_count, 0);
}

#[test]
fn enrichment_report_single_fail_blocks() {
    let evals = vec![pass_eval("a", 100), fail_eval("b", 50, 100)];
    let report = build_report(epoch(), "rc-enr-fail", evals);
    assert!(report.blocks_release());
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert_eq!(report.blockers().len(), 1);
}

#[test]
fn enrichment_report_inconclusive_blocks() {
    let evals = vec![GateEvaluation {
        condition_id: "inc".to_string(),
        observed_value: 0,
        threshold_value: 0,
        verdict: GateVerdict::Inconclusive,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: 0,
    }];
    let report = build_report(epoch(), "rc-enr-inc", evals);
    assert!(report.blocks_release());
    assert_eq!(report.inconclusive_count, 1);
}

#[test]
fn enrichment_report_advisory_only_does_not_block() {
    let evals = vec![GateEvaluation {
        condition_id: "adv".to_string(),
        observed_value: 100,
        threshold_value: 50,
        verdict: GateVerdict::Advisory,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: -50,
    }];
    let report = build_report(epoch(), "rc-enr-adv", evals);
    assert!(!report.blocks_release());
    assert_eq!(report.overall_verdict, GateVerdict::Advisory);
}

#[test]
fn enrichment_report_empty_evaluations_pass() {
    let report = build_report(epoch(), "rc-empty", vec![]);
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert_eq!(report.total_evaluations(), 0);
}

#[test]
fn enrichment_report_integrity_valid() {
    let report = build_report(epoch(), "rc-int", vec![pass_eval("x", 42)]);
    assert!(report.verify_integrity());
}

#[test]
fn enrichment_report_integrity_detects_tampering() {
    let mut report = build_report(epoch(), "rc-int", vec![pass_eval("x", 42)]);
    report.pass_count = 999;
    // pass_count change doesn't affect hash, but rc_id change does
    assert!(report.verify_integrity());
    report.release_candidate_id = "tampered".to_string();
    assert!(!report.verify_integrity());
}

#[test]
fn enrichment_report_different_epochs_different_hash() {
    let evals = vec![pass_eval("x", 1)];
    let r1 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals.clone());
    let r2 = build_report(SecurityEpoch::from_raw(2), "rc-1", evals);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_report_metadata_correct() {
    let report = build_report(epoch(), "rc-meta", vec![]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let evals = vec![pass_eval("a", 1), fail_eval("b", 0, 1)];
    let report = build_report(epoch(), "rc-serde", evals);
    let json = serde_json::to_string(&report).unwrap();
    let back: OracleReleaseGateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Section 7: TriageSeverity enrichment
// ===========================================================================

#[test]
fn enrichment_triage_severity_as_str() {
    assert_eq!(TriageSeverity::Blocker.as_str(), "blocker");
    assert_eq!(TriageSeverity::Warning.as_str(), "warning");
    assert_eq!(TriageSeverity::Info.as_str(), "info");
}

#[test]
fn enrichment_triage_severity_display_matches_as_str() {
    for sev in [TriageSeverity::Blocker, TriageSeverity::Warning, TriageSeverity::Info] {
        assert_eq!(sev.to_string(), sev.as_str());
    }
}

#[test]
fn enrichment_triage_severity_ord() {
    assert!(TriageSeverity::Blocker < TriageSeverity::Warning);
    assert!(TriageSeverity::Warning < TriageSeverity::Info);
}

// ===========================================================================
// Section 8: build_triage_bundle enrichment
// ===========================================================================

#[test]
fn enrichment_triage_clean_report_empty_bundle() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, None, None))
        .collect();
    let report = build_report(epoch(), "rc-clean", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.total_entries(), 0);
    assert!(!bundle.has_blockers());
}

#[test]
fn enrichment_triage_fail_maps_to_blocker() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 0, None, None)];
    let report = build_report(epoch(), "rc-fail", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Blocker);
}

#[test]
fn enrichment_triage_advisory_maps_to_warning() {
    let conditions = default_gate_conditions();
    let metric_cond = conditions.iter().find(|c| c.oracle_kind == OracleKind::Metric).unwrap();
    let evals = vec![evaluate_condition(metric_cond, 200_000, None, None)];
    let report = build_report(epoch(), "rc-warn", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.warning_count, 1);
}

#[test]
fn enrichment_triage_bundle_integrity() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 0, None, None)];
    let report = build_report(epoch(), "rc-integ", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.verify_integrity());
}

#[test]
fn enrichment_triage_bundle_integrity_detects_tampering() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 0, None, None)];
    let report = build_report(epoch(), "rc-integ", evals);
    let mut bundle = build_triage_bundle(&report, &conditions);
    bundle.release_candidate_id = "tampered".to_string();
    assert!(!bundle.verify_integrity());
}

#[test]
fn enrichment_triage_bundle_serde_roundtrip() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 0, Some("ev"), Some("rp"))];
    let report = build_report(epoch(), "rc-serde", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: TriageBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_triage_remediation_per_oracle_kind_distinct() {
    let conditions = vec![
        make_condition("s", OracleKind::Scenario, ThresholdDirection::AtLeast, 100, true),
        make_condition("r", OracleKind::Replay, ThresholdDirection::Exactly, 0, true),
        make_condition("c", OracleKind::Contract, ThresholdDirection::AtLeast, 100, true),
        make_condition("m", OracleKind::Metric, ThresholdDirection::AtMost, 10, true),
        make_condition("e", OracleKind::Evidence, ThresholdDirection::Exactly, 0, true),
        make_condition("o", OracleKind::Obligation, ThresholdDirection::AtMost, 0, true),
    ];
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, 50, None, None))
        .collect();
    let report = build_report(epoch(), "rc-rem", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    let remediations: BTreeSet<&str> = bundle.entries.iter().map(|e| e.remediation.as_str()).collect();
    assert!(remediations.len() >= 4);
}

// ===========================================================================
// Section 9: build_gate_event enrichment
// ===========================================================================

#[test]
fn enrichment_gate_event_pass_verdict() {
    let report = build_report(epoch(), "rc-ev", vec![pass_eval("a", 1)]);
    let event = build_gate_event("t-1", "d-1", &report);
    assert_eq!(event.overall_verdict, "pass");
    assert_eq!(event.blockers, 0);
    assert_eq!(event.conditions_evaluated, 1);
}

#[test]
fn enrichment_gate_event_fail_verdict() {
    let report = build_report(epoch(), "rc-ev", vec![fail_eval("a", 0, 1)]);
    let event = build_gate_event("t-1", "d-1", &report);
    assert_eq!(event.overall_verdict, "fail");
    assert_eq!(event.blockers, 1);
}

#[test]
fn enrichment_gate_event_metadata() {
    let report = build_report(epoch(), "rc-ev", vec![]);
    let event = build_gate_event("trace-id", "dec-id", &report);
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.trace_id, "trace-id");
    assert_eq!(event.decision_id, "dec-id");
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.event, "oracle_release_gate_evaluated");
}

#[test]
fn enrichment_gate_event_seed_contains_bead_id() {
    let report = build_report(epoch(), "rc-1", vec![]);
    let event = build_gate_event("t", "d", &report);
    assert!(event.seed.contains(BEAD_ID));
}

#[test]
fn enrichment_gate_event_serde_roundtrip() {
    let report = build_report(epoch(), "rc-1", vec![pass_eval("x", 1)]);
    let event = build_gate_event("t", "d", &report);
    let json = serde_json::to_string(&event).unwrap();
    let back: OracleReleaseGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Section 10: default_gate_conditions enrichment
// ===========================================================================

#[test]
fn enrichment_default_conditions_unique_ids() {
    let conditions = default_gate_conditions();
    let ids: BTreeSet<&str> = conditions.iter().map(|c| c.condition_id.as_str()).collect();
    assert_eq!(ids.len(), conditions.len());
}

#[test]
fn enrichment_default_conditions_cover_all_oracle_kinds() {
    let conditions = default_gate_conditions();
    let kinds: BTreeSet<OracleKind> = conditions.iter().map(|c| c.oracle_kind).collect();
    for kind in OracleKind::all() {
        assert!(kinds.contains(kind), "missing: {kind}");
    }
}

#[test]
fn enrichment_default_conditions_all_have_policy_ref() {
    for cond in &default_gate_conditions() {
        assert_eq!(cond.policy_ref, POLICY_ID);
    }
}

#[test]
fn enrichment_default_conditions_scenario_hard_blocker() {
    let conditions = default_gate_conditions();
    let scenario = conditions.iter().find(|c| c.oracle_kind == OracleKind::Scenario).unwrap();
    assert!(scenario.threshold.is_hard_blocker);
    assert_eq!(scenario.threshold.threshold_value, DEFAULT_MIN_PASS_RATE);
}

#[test]
fn enrichment_default_conditions_metric_is_advisory() {
    let conditions = default_gate_conditions();
    let metric = conditions.iter().find(|c| c.oracle_kind == OracleKind::Metric).unwrap();
    assert!(!metric.threshold.is_hard_blocker);
    assert_eq!(metric.threshold.threshold_value, DEFAULT_MAX_REGRESSION);
}

// ===========================================================================
// Section 11: End-to-end lifecycle
// ===========================================================================

#[test]
fn enrichment_e2e_all_defaults_passing() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, Some("ev"), Some("rp")))
        .collect();
    let report = build_report(epoch(), "rc-e2e", evals);
    assert!(!report.blocks_release());
    assert!(report.verify_integrity());

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.has_blockers());
    assert!(bundle.verify_integrity());

    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.overall_verdict, "pass");
    assert_eq!(event.blockers, 0);
}

#[test]
fn enrichment_e2e_mixed_failures() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| match c.oracle_kind {
            OracleKind::Scenario => evaluate_condition(c, 0, None, None),
            _ => evaluate_condition(c, c.threshold.threshold_value, None, None),
        })
        .collect();
    let report = build_report(epoch(), "rc-mixed", evals);
    assert!(report.blocks_release());
    assert_eq!(report.fail_count, 1);

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.blocker_count, 1);
}

#[test]
fn enrichment_e2e_deterministic_report_hash() {
    let conditions = default_gate_conditions();
    let make_evals = || -> Vec<GateEvaluation> {
        conditions
            .iter()
            .map(|c| evaluate_condition(c, c.threshold.threshold_value, None, None))
            .collect()
    };
    let r1 = build_report(epoch(), "rc-det", make_evals());
    let r2 = build_report(epoch(), "rc-det", make_evals());
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// Section 12: Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.oracle-release-gate.v1");
    assert_eq!(BEAD_ID, "bd-3nr.1.4.3");
    assert_eq!(POLICY_ID, "10.13X.D3");
    assert_eq!(COMPONENT, "oracle_release_gate");
    assert_eq!(DEFAULT_MIN_PASS_RATE, MILLIONTHS);
    assert_eq!(DEFAULT_MAX_REGRESSION, 50_000);
    assert_eq!(DEFAULT_MAX_UNRESOLVED, 0);
}
