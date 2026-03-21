//! Integration tests for oracle_release_gate module (bd-3nr.1.4.3).
//!
//! Validates end-to-end oracle-backed release gating: gate condition evaluation,
//! threshold directions, report building, triage bundle generation, event structure,
//! serde roundtrips, determinism, boundary cases, and fail-closed semantics.

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
        description: format!("Test condition: {id}"),
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

fn make_pass_eval(id: &str, value: u64) -> GateEvaluation {
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_stable() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.oracle-release-gate.v1");
    assert_eq!(BEAD_ID, "bd-3nr.1.4.3");
    assert_eq!(POLICY_ID, "10.13X.D3");
    assert_eq!(COMPONENT, "oracle_release_gate");
}

#[test]
fn default_thresholds_sensible() {
    assert_eq!(DEFAULT_MIN_PASS_RATE, MILLIONTHS);
    assert_eq!(DEFAULT_MAX_REGRESSION, 50_000);
    assert_eq!(DEFAULT_MAX_UNRESOLVED, 0);
}

// ---------------------------------------------------------------------------
// OracleKind
// ---------------------------------------------------------------------------

#[test]
fn oracle_kind_all_six_variants() {
    let all = OracleKind::all();
    assert_eq!(all.len(), 6);
    let names: BTreeSet<&str> = all.iter().map(|k| k.as_str()).collect();
    assert!(names.contains("scenario"));
    assert!(names.contains("replay"));
    assert!(names.contains("contract"));
    assert!(names.contains("metric"));
    assert!(names.contains("evidence"));
    assert!(names.contains("obligation"));
}

#[test]
fn oracle_kind_display_roundtrip() {
    for kind in OracleKind::all() {
        let s = kind.to_string();
        assert_eq!(s, kind.as_str());
        assert!(!s.is_empty());
    }
}

#[test]
fn oracle_kind_serde_roundtrip() {
    for kind in OracleKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let parsed: OracleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, parsed);
    }
}

#[test]
fn oracle_kind_ordering_is_deterministic() {
    let mut v: Vec<OracleKind> = OracleKind::all().to_vec();
    v.sort();
    let mut v2 = v.clone();
    v2.sort();
    assert_eq!(v, v2);
}

// ---------------------------------------------------------------------------
// ThresholdDirection
// ---------------------------------------------------------------------------

#[test]
fn threshold_direction_at_least_boundary() {
    assert!(ThresholdDirection::AtLeast.passes(100, 100));
    assert!(ThresholdDirection::AtLeast.passes(101, 100));
    assert!(!ThresholdDirection::AtLeast.passes(99, 100));
}

#[test]
fn threshold_direction_at_most_boundary() {
    assert!(ThresholdDirection::AtMost.passes(100, 100));
    assert!(ThresholdDirection::AtMost.passes(99, 100));
    assert!(!ThresholdDirection::AtMost.passes(101, 100));
}

#[test]
fn threshold_direction_exactly_boundary() {
    assert!(ThresholdDirection::Exactly.passes(42, 42));
    assert!(!ThresholdDirection::Exactly.passes(41, 42));
    assert!(!ThresholdDirection::Exactly.passes(43, 42));
}

#[test]
fn threshold_direction_at_least_zero() {
    assert!(ThresholdDirection::AtLeast.passes(0, 0));
    assert!(ThresholdDirection::AtLeast.passes(1, 0));
}

#[test]
fn threshold_direction_at_most_zero() {
    assert!(ThresholdDirection::AtMost.passes(0, 0));
    assert!(!ThresholdDirection::AtMost.passes(1, 0));
}

#[test]
fn threshold_direction_at_least_max() {
    assert!(ThresholdDirection::AtLeast.passes(u64::MAX, u64::MAX));
    assert!(!ThresholdDirection::AtLeast.passes(u64::MAX - 1, u64::MAX));
}

#[test]
fn threshold_direction_serde_roundtrip() {
    for dir in [
        ThresholdDirection::AtLeast,
        ThresholdDirection::AtMost,
        ThresholdDirection::Exactly,
    ] {
        let json = serde_json::to_string(&dir).unwrap();
        let parsed: ThresholdDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, parsed);
    }
}

// ---------------------------------------------------------------------------
// BlockerThreshold
// ---------------------------------------------------------------------------

#[test]
fn blocker_threshold_evaluate_delegates_correctly() {
    let t = BlockerThreshold {
        name: "test".to_string(),
        threshold_value: 500,
        direction: ThresholdDirection::AtLeast,
        is_hard_blocker: true,
    };
    assert!(t.evaluate(500));
    assert!(t.evaluate(1000));
    assert!(!t.evaluate(499));
}

#[test]
fn blocker_threshold_serde_roundtrip() {
    let t = BlockerThreshold {
        name: "test_threshold".to_string(),
        threshold_value: 123_456,
        direction: ThresholdDirection::AtMost,
        is_hard_blocker: false,
    };
    let json = serde_json::to_string(&t).unwrap();
    let parsed: BlockerThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, parsed);
}

// ---------------------------------------------------------------------------
// evaluate_condition
// ---------------------------------------------------------------------------

#[test]
fn evaluate_condition_pass_at_least() {
    let cond = make_condition(
        "c1",
        OracleKind::Scenario,
        ThresholdDirection::AtLeast,
        MILLIONTHS,
        true,
    );
    let eval = evaluate_condition(&cond, MILLIONTHS, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 0);
    assert_eq!(eval.condition_id, "c1");
}

#[test]
fn evaluate_condition_fail_hard_blocker() {
    let cond = make_condition(
        "c2",
        OracleKind::Scenario,
        ThresholdDirection::AtLeast,
        MILLIONTHS,
        true,
    );
    let eval = evaluate_condition(&cond, 500_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Fail);
    assert_eq!(eval.margin_millionths, -500_000);
}

#[test]
fn evaluate_condition_fail_advisory() {
    let cond = make_condition(
        "c3",
        OracleKind::Metric,
        ThresholdDirection::AtMost,
        50_000,
        false,
    );
    let eval = evaluate_condition(&cond, 100_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Advisory);
    assert!(eval.margin_millionths < 0);
}

#[test]
fn evaluate_condition_with_evidence_and_replay() {
    let cond = make_condition(
        "c4",
        OracleKind::Replay,
        ThresholdDirection::Exactly,
        0,
        true,
    );
    let eval = evaluate_condition(&cond, 0, Some("ev-abc"), Some("replay-xyz"));
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.evidence_ref.as_deref(), Some("ev-abc"));
    assert_eq!(eval.replay_ref.as_deref(), Some("replay-xyz"));
}

#[test]
fn evaluate_condition_exactly_fail_positive_diff() {
    let cond = make_condition(
        "c5",
        OracleKind::Evidence,
        ThresholdDirection::Exactly,
        0,
        true,
    );
    let eval = evaluate_condition(&cond, 3, None, None);
    assert_eq!(eval.verdict, GateVerdict::Fail);
    assert!(eval.margin_millionths < 0);
}

#[test]
fn evaluate_condition_at_most_pass_margin() {
    let cond = make_condition(
        "c6",
        OracleKind::Metric,
        ThresholdDirection::AtMost,
        100,
        true,
    );
    let eval = evaluate_condition(&cond, 70, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 30);
}

#[test]
fn evaluate_condition_at_least_pass_margin() {
    let cond = make_condition(
        "c7",
        OracleKind::Contract,
        ThresholdDirection::AtLeast,
        100,
        true,
    );
    let eval = evaluate_condition(&cond, 150, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 50);
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn gate_verdict_blocks_release_classification() {
    assert!(!GateVerdict::Pass.blocks_release());
    assert!(GateVerdict::Fail.blocks_release());
    assert!(!GateVerdict::Advisory.blocks_release());
    assert!(GateVerdict::Inconclusive.blocks_release());
}

#[test]
fn gate_verdict_display_strings() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::Fail.as_str(), "fail");
    assert_eq!(GateVerdict::Advisory.as_str(), "advisory");
    assert_eq!(GateVerdict::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn gate_verdict_serde_roundtrip() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Advisory,
        GateVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }
}

// ---------------------------------------------------------------------------
// build_report
// ---------------------------------------------------------------------------

#[test]
fn build_report_all_pass() {
    let evals = vec![make_pass_eval("a", MILLIONTHS), make_pass_eval("b", 0)];
    let report = build_report(epoch(), "rc-1", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert_eq!(report.pass_count, 2);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.advisory_count, 0);
    assert_eq!(report.inconclusive_count, 0);
    assert!(!report.blocks_release());
    assert_eq!(report.total_evaluations(), 2);
}

#[test]
fn build_report_with_single_failure() {
    let evals = vec![
        make_pass_eval("a", MILLIONTHS),
        GateEvaluation {
            condition_id: "b".to_string(),
            observed_value: 500_000,
            threshold_value: MILLIONTHS,
            verdict: GateVerdict::Fail,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -500_000,
        },
    ];
    let report = build_report(epoch(), "rc-2", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert!(report.blocks_release());
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.blockers().len(), 1);
    assert_eq!(report.blockers()[0].condition_id, "b");
}

#[test]
fn build_report_advisory_only_does_not_block() {
    let evals = vec![
        make_pass_eval("a", MILLIONTHS),
        GateEvaluation {
            condition_id: "b".to_string(),
            observed_value: 80_000,
            threshold_value: 50_000,
            verdict: GateVerdict::Advisory,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -30_000,
        },
    ];
    let report = build_report(epoch(), "rc-3", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Advisory);
    assert!(!report.blocks_release());
    assert_eq!(report.advisory_count, 1);
}

#[test]
fn build_report_inconclusive_blocks() {
    let evals = vec![GateEvaluation {
        condition_id: "oracle-down".to_string(),
        observed_value: 0,
        threshold_value: 0,
        verdict: GateVerdict::Inconclusive,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: 0,
    }];
    let report = build_report(epoch(), "rc-4", evals);
    assert!(report.blocks_release());
    assert_eq!(report.inconclusive_count, 1);
}

#[test]
fn build_report_empty_evaluations_pass() {
    let report = build_report(epoch(), "rc-empty", vec![]);
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert_eq!(report.total_evaluations(), 0);
    assert!(!report.blocks_release());
}

#[test]
fn build_report_metadata_populated() {
    let report = build_report(epoch(), "rc-meta", vec![]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.release_candidate_id, "rc-meta");
}

#[test]
fn build_report_integrity_passes() {
    let evals = vec![make_pass_eval("x", 42)];
    let report = build_report(epoch(), "rc-int", evals);
    assert!(report.verify_integrity());
}

#[test]
fn build_report_integrity_detects_tampering() {
    let evals = vec![make_pass_eval("x", 42)];
    let mut report = build_report(epoch(), "rc-int", evals);
    report.release_candidate_id = "tampered".to_string();
    assert!(!report.verify_integrity());
}

#[test]
fn build_report_integrity_detects_evidence_ref_tampering() {
    let mut eval = make_pass_eval("x", 42);
    eval.evidence_ref = Some("ev-1".to_string());
    eval.replay_ref = Some("replay-1".to_string());
    let mut report = build_report(epoch(), "rc-int", vec![eval]);
    assert!(report.verify_integrity());
    report.evaluations[0].evidence_ref = Some("ev-2".to_string());
    assert!(!report.verify_integrity());
}

#[test]
fn build_report_serde_roundtrip() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let observed = if i % 2 == 0 {
                c.threshold.threshold_value
            } else {
                c.threshold.threshold_value.saturating_add(1)
            };
            evaluate_condition(c, observed, Some("ev"), Some("replay"))
        })
        .collect();
    let report = build_report(epoch(), "rc-serde", evals);
    let json = serde_json::to_string(&report).unwrap();
    let parsed: OracleReleaseGateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);
}

#[test]
fn build_report_deterministic() {
    let evals1 = vec![make_pass_eval("a", 100), make_pass_eval("b", 200)];
    let evals2 = evals1.clone();
    let r1 = build_report(epoch(), "rc-det", evals1);
    let r2 = build_report(epoch(), "rc-det", evals2);
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1, r2);
}

#[test]
fn build_report_different_inputs_different_hash() {
    let r1 = build_report(epoch(), "rc-a", vec![make_pass_eval("x", 1)]);
    let r2 = build_report(epoch(), "rc-b", vec![make_pass_eval("x", 1)]);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn build_report_different_epoch_different_hash() {
    let evals1 = vec![make_pass_eval("x", 1)];
    let evals2 = evals1.clone();
    let r1 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals1);
    let r2 = build_report(SecurityEpoch::from_raw(2), "rc-1", evals2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// default_gate_conditions
// ---------------------------------------------------------------------------

#[test]
fn default_conditions_cover_all_oracle_kinds() {
    let conditions = default_gate_conditions();
    let kinds: BTreeSet<OracleKind> = conditions.iter().map(|c| c.oracle_kind).collect();
    for kind in OracleKind::all() {
        assert!(kinds.contains(kind), "missing condition for {kind}");
    }
}

#[test]
fn default_conditions_have_unique_ids() {
    let conditions = default_gate_conditions();
    let ids: BTreeSet<&str> = conditions.iter().map(|c| c.condition_id.as_str()).collect();
    assert_eq!(ids.len(), conditions.len());
}

#[test]
fn default_conditions_all_have_policy_ref() {
    for cond in &default_gate_conditions() {
        assert_eq!(cond.policy_ref, POLICY_ID);
    }
}

#[test]
fn default_conditions_scenario_is_hard_blocker() {
    let conditions = default_gate_conditions();
    let scenario = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Scenario)
        .expect("scenario condition");
    assert!(scenario.threshold.is_hard_blocker);
    assert_eq!(scenario.threshold.threshold_value, DEFAULT_MIN_PASS_RATE);
}

#[test]
fn default_conditions_metric_is_advisory() {
    let conditions = default_gate_conditions();
    let metric = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Metric)
        .expect("metric condition");
    assert!(!metric.threshold.is_hard_blocker);
    assert_eq!(metric.threshold.threshold_value, DEFAULT_MAX_REGRESSION);
}

#[test]
fn default_conditions_obligation_threshold() {
    let conditions = default_gate_conditions();
    let obligation = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Obligation)
        .expect("obligation condition");
    assert!(obligation.threshold.is_hard_blocker);
    assert_eq!(obligation.threshold.threshold_value, DEFAULT_MAX_UNRESOLVED);
}

// ---------------------------------------------------------------------------
// TriageSeverity
// ---------------------------------------------------------------------------

#[test]
fn triage_severity_display() {
    assert_eq!(TriageSeverity::Blocker.to_string(), "blocker");
    assert_eq!(TriageSeverity::Warning.to_string(), "warning");
    assert_eq!(TriageSeverity::Info.to_string(), "info");
}

#[test]
fn triage_severity_serde_roundtrip() {
    for sev in [
        TriageSeverity::Blocker,
        TriageSeverity::Warning,
        TriageSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let parsed: TriageSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, parsed);
    }
}

// ---------------------------------------------------------------------------
// build_triage_bundle
// ---------------------------------------------------------------------------

#[test]
fn triage_bundle_clean_report_empty() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, None, None))
        .collect();
    let report = build_report(epoch(), "rc-clean", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.total_entries(), 0);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.blocker_count, 0);
    assert_eq!(bundle.warning_count, 0);
    assert_eq!(bundle.info_count, 0);
}

#[test]
fn triage_bundle_single_failure_has_blocker() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(
        &conditions[0],
        500_000,
        Some("ev-1"),
        None,
    )];
    let report = build_report(epoch(), "rc-fail", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.blocker_count, 1);
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Blocker);
}

#[test]
fn triage_bundle_advisory_becomes_warning() {
    let conditions = default_gate_conditions();
    let metric_cond = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Metric)
        .unwrap();
    let evals = vec![evaluate_condition(metric_cond, 100_000, None, None)];
    let report = build_report(epoch(), "rc-adv", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.warning_count, 1);
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Warning);
}

#[test]
fn triage_bundle_remediation_per_oracle_kind() {
    let conditions = default_gate_conditions();
    // Fail the scenario condition
    let scenario_cond = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Scenario)
        .unwrap();
    let evals = vec![evaluate_condition(scenario_cond, 0, None, None)];
    let report = build_report(epoch(), "rc-rem", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.entries[0].remediation.is_empty());
    assert!(bundle.entries[0].remediation.contains("frankenlab"));
}

#[test]
fn triage_bundle_evidence_ref_propagated() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(
        &conditions[0],
        500_000,
        Some("evidence-abc"),
        Some("replay-xyz"),
    )];
    let report = build_report(epoch(), "rc-refs", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(
        bundle.entries[0].evidence_ref.as_deref(),
        Some("evidence-abc")
    );
    assert_eq!(bundle.entries[0].replay_ref.as_deref(), Some("replay-xyz"));
}

#[test]
fn triage_bundle_integrity_passes() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
    let report = build_report(epoch(), "rc-int", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.verify_integrity());
}

#[test]
fn triage_bundle_integrity_detects_tampering() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
    let report = build_report(epoch(), "rc-int", evals);
    let mut bundle = build_triage_bundle(&report, &conditions);
    bundle.release_candidate_id = "tampered".to_string();
    assert!(!bundle.verify_integrity());
}

#[test]
fn triage_bundle_integrity_detects_remediation_tampering() {
    let cond = make_condition(
        "x",
        OracleKind::Replay,
        ThresholdDirection::Exactly,
        0,
        true,
    );
    let evals = vec![evaluate_condition(
        &cond,
        1,
        Some("ev-ref"),
        Some("replay-ref"),
    )];
    let report = build_report(epoch(), "rc-int", evals);
    let mut bundle = build_triage_bundle(&report, &[cond]);
    assert!(bundle.verify_integrity());
    bundle.entries[0].remediation = "tampered remediation".to_string();
    assert!(!bundle.verify_integrity());
}

#[test]
fn triage_bundle_serde_roundtrip() {
    let conditions = default_gate_conditions();
    let evals = vec![
        evaluate_condition(&conditions[0], 500_000, Some("ev"), None),
        evaluate_condition(&conditions[1], 3, None, Some("rp")),
    ];
    let report = build_report(epoch(), "rc-serde", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: TriageBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, parsed);
}

#[test]
fn triage_bundle_deterministic() {
    let conditions = default_gate_conditions();
    let evals1 = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
    let evals2 = evals1.clone();
    let r1 = build_report(epoch(), "rc-det", evals1);
    let r2 = build_report(epoch(), "rc-det", evals2);
    let b1 = build_triage_bundle(&r1, &conditions);
    let b2 = build_triage_bundle(&r2, &conditions);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn triage_bundle_metadata() {
    let conditions = default_gate_conditions();
    let evals = vec![evaluate_condition(&conditions[0], 0, None, None)];
    let report = build_report(epoch(), "rc-meta", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    assert_eq!(bundle.release_candidate_id, "rc-meta");
}

// ---------------------------------------------------------------------------
// build_gate_event
// ---------------------------------------------------------------------------

#[test]
fn gate_event_metadata() {
    let report = build_report(epoch(), "rc-ev", vec![make_pass_eval("a", 1)]);
    let event = build_gate_event("trace-1", "dec-1", &report);
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.trace_id, "trace-1");
    assert_eq!(event.decision_id, "dec-1");
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.event, "oracle_release_gate_evaluated");
}

#[test]
fn gate_event_verdict_matches_report() {
    let report = build_report(epoch(), "rc-1", vec![make_pass_eval("a", 1)]);
    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.overall_verdict, "pass");

    let fail_evals = vec![GateEvaluation {
        condition_id: "f".to_string(),
        observed_value: 0,
        threshold_value: 1,
        verdict: GateVerdict::Fail,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: -1,
    }];
    let fail_report = build_report(epoch(), "rc-2", fail_evals);
    let fail_event = build_gate_event("t", "d", &fail_report);
    assert_eq!(fail_event.overall_verdict, "fail");
}

#[test]
fn gate_event_conditions_count() {
    let evals = vec![
        make_pass_eval("a", 1),
        make_pass_eval("b", 2),
        make_pass_eval("c", 3),
    ];
    let report = build_report(epoch(), "rc-cnt", evals);
    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.conditions_evaluated, 3);
}

#[test]
fn gate_event_blocker_count() {
    let evals = vec![
        GateEvaluation {
            condition_id: "f1".to_string(),
            observed_value: 0,
            threshold_value: 1,
            verdict: GateVerdict::Fail,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -1,
        },
        GateEvaluation {
            condition_id: "f2".to_string(),
            observed_value: 0,
            threshold_value: 1,
            verdict: GateVerdict::Inconclusive,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        },
        make_pass_eval("p", 1),
    ];
    let report = build_report(epoch(), "rc-blk", evals);
    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.blockers, 2);
}

#[test]
fn gate_event_serde_roundtrip() {
    let report = build_report(epoch(), "rc-ev", vec![make_pass_eval("a", 1)]);
    let event = build_gate_event("trace-1", "dec-1", &report);
    let json = serde_json::to_string(&event).unwrap();
    let parsed: OracleReleaseGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn gate_event_seed_stable() {
    let r1 = build_report(epoch(), "rc-1", vec![]);
    let r2 = build_report(epoch(), "rc-2", vec![]);
    let e1 = build_gate_event("t1", "d1", &r1);
    let e2 = build_gate_event("t2", "d2", &r2);
    assert_eq!(e1.seed, e2.seed);
    assert!(e1.seed.contains(BEAD_ID));
}

// ---------------------------------------------------------------------------
// End-to-end pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_all_defaults_passing() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, Some("ev"), Some("rp")))
        .collect();
    let report = build_report(epoch(), "rc-e2e-pass", evals);
    assert!(!report.blocks_release());
    assert!(report.verify_integrity());

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.total_entries(), 0);
    assert!(bundle.verify_integrity());

    let event = build_gate_event("trace-e2e", "dec-e2e", &report);
    assert_eq!(event.overall_verdict, "pass");
    assert_eq!(event.conditions_evaluated, conditions.len() as u64);
    assert_eq!(event.blockers, 0);
}

#[test]
fn end_to_end_mixed_failures() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| {
            // Fail scenario (hard), advisory on metric (soft), pass the rest
            match c.oracle_kind {
                OracleKind::Scenario => evaluate_condition(c, 0, Some("ev-s"), None),
                OracleKind::Metric => evaluate_condition(c, 200_000, Some("ev-m"), None),
                _ => evaluate_condition(c, c.threshold.threshold_value, None, None),
            }
        })
        .collect();
    let report = build_report(epoch(), "rc-e2e-mixed", evals);
    assert!(report.blocks_release());
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.advisory_count, 1);

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.blocker_count, 1);
    assert_eq!(bundle.warning_count, 1);

    let event = build_gate_event("trace-mix", "dec-mix", &report);
    assert_eq!(event.overall_verdict, "fail");
    assert_eq!(event.blockers, 1);
}

#[test]
fn end_to_end_all_defaults_failing() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| {
            // Provide a value that always fails
            let bad_value = match c.threshold.direction {
                ThresholdDirection::AtLeast => 0,
                ThresholdDirection::AtMost => u64::MAX,
                ThresholdDirection::Exactly => c.threshold.threshold_value.wrapping_add(1),
            };
            evaluate_condition(c, bad_value, None, None)
        })
        .collect();
    let report = build_report(epoch(), "rc-e2e-fail", evals);
    assert!(report.blocks_release());
    // Metric is advisory (not hard blocker) so it's advisory not fail
    assert!(report.fail_count >= 4);

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert!(bundle.total_entries() > 0);
}

// ---------------------------------------------------------------------------
// Boundary / adversarial
// ---------------------------------------------------------------------------

#[test]
fn evaluate_condition_zero_threshold_at_least() {
    let cond = make_condition(
        "z",
        OracleKind::Scenario,
        ThresholdDirection::AtLeast,
        0,
        true,
    );
    let eval = evaluate_condition(&cond, 0, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
}

#[test]
fn evaluate_condition_max_value() {
    let cond = make_condition(
        "m",
        OracleKind::Metric,
        ThresholdDirection::AtMost,
        u64::MAX,
        true,
    );
    let eval = evaluate_condition(&cond, u64::MAX, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
}

#[test]
fn oracle_gate_condition_serde_roundtrip() {
    let cond = make_condition(
        "serde-test",
        OracleKind::Evidence,
        ThresholdDirection::Exactly,
        42,
        true,
    );
    let json = serde_json::to_string(&cond).unwrap();
    let parsed: OracleGateCondition = serde_json::from_str(&json).unwrap();
    assert_eq!(cond, parsed);
}

#[test]
fn gate_evaluation_serde_roundtrip() {
    let eval = GateEvaluation {
        condition_id: "serde".to_string(),
        observed_value: 999,
        threshold_value: 1000,
        verdict: GateVerdict::Fail,
        evidence_ref: Some("ev".to_string()),
        replay_ref: Some("rp".to_string()),
        margin_millionths: -1,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let parsed: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, parsed);
}

#[test]
fn triage_bundle_entry_serde_roundtrip() {
    let entry = TriageBundleEntry {
        condition_id: "test".to_string(),
        oracle_kind: OracleKind::Obligation,
        severity: TriageSeverity::Blocker,
        summary: "test summary".to_string(),
        remediation: "fix it".to_string(),
        evidence_ref: Some("ev".to_string()),
        replay_ref: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: TriageBundleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
}

#[test]
fn report_blockers_returns_only_blocking_verdicts() {
    let evals = vec![
        make_pass_eval("pass", 1),
        GateEvaluation {
            condition_id: "fail".to_string(),
            observed_value: 0,
            threshold_value: 1,
            verdict: GateVerdict::Fail,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -1,
        },
        GateEvaluation {
            condition_id: "adv".to_string(),
            observed_value: 2,
            threshold_value: 1,
            verdict: GateVerdict::Advisory,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -1,
        },
        GateEvaluation {
            condition_id: "inc".to_string(),
            observed_value: 0,
            threshold_value: 0,
            verdict: GateVerdict::Inconclusive,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        },
    ];
    let report = build_report(epoch(), "rc-mix", evals);
    let blockers = report.blockers();
    assert_eq!(blockers.len(), 2);
    let ids: BTreeSet<&str> = blockers.iter().map(|b| b.condition_id.as_str()).collect();
    assert!(ids.contains("fail"));
    assert!(ids.contains("inc"));
    assert!(!ids.contains("pass"));
    assert!(!ids.contains("adv"));
}

#[test]
fn triage_bundle_multiple_oracle_kinds_have_distinct_remediation() {
    // Build conditions covering different oracle kinds and fail them all
    let conditions = vec![
        make_condition(
            "s",
            OracleKind::Scenario,
            ThresholdDirection::AtLeast,
            100,
            true,
        ),
        make_condition(
            "r",
            OracleKind::Replay,
            ThresholdDirection::Exactly,
            0,
            true,
        ),
        make_condition(
            "c",
            OracleKind::Contract,
            ThresholdDirection::AtLeast,
            100,
            true,
        ),
        make_condition(
            "m",
            OracleKind::Metric,
            ThresholdDirection::AtMost,
            10,
            true,
        ),
        make_condition(
            "e",
            OracleKind::Evidence,
            ThresholdDirection::Exactly,
            0,
            true,
        ),
        make_condition(
            "o",
            OracleKind::Obligation,
            ThresholdDirection::AtMost,
            0,
            true,
        ),
    ];
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, 50, None, None))
        .collect();
    let report = build_report(epoch(), "rc-rem", evals);
    let bundle = build_triage_bundle(&report, &conditions);

    let remediations: BTreeSet<&str> = bundle
        .entries
        .iter()
        .map(|e| e.remediation.as_str())
        .collect();
    // Each oracle kind should produce a distinct remediation message
    assert!(remediations.len() >= 4);
}
