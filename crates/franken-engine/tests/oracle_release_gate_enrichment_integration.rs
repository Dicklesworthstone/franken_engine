//! Enrichment integration tests for `oracle_release_gate`.
//!
//! Covers: OracleKind (Display, serde, all()), ThresholdDirection (passes, serde,
//! boundary values), BlockerThreshold evaluate(), evaluate_condition() (pass/fail/
//! advisory paths, margin calculation), build_report() (all-pass, mixed, all-fail,
//! empty, integrity), GateVerdict (blocks_release, serde), TriageBundle
//! (build, severity classification, integrity), build_gate_event(), deterministic
//! hashing, serde roundtrips, and edge cases.

#![allow(clippy::needless_borrows_for_generic_args, clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::oracle_release_gate::{
    BEAD_ID, BlockerThreshold, COMPONENT, DEFAULT_MAX_REGRESSION, DEFAULT_MAX_UNRESOLVED,
    DEFAULT_MIN_PASS_RATE, GateEvaluation, GateVerdict, OracleGateCondition, OracleKind,
    OracleReleaseGateEvent, OracleReleaseGateReport, POLICY_ID, SCHEMA_VERSION, ThresholdDirection,
    TriageBundle, TriageBundleEntry, TriageSeverity, build_gate_event, build_report,
    build_triage_bundle, default_gate_conditions, evaluate_condition,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

/// Fixed-point one (1.0 in millionths).
const MILLIONTHS: u64 = 1_000_000;

fn make_condition(
    id: &str,
    kind: OracleKind,
    threshold_value: u64,
    direction: ThresholdDirection,
    hard: bool,
) -> OracleGateCondition {
    OracleGateCondition {
        condition_id: id.to_string(),
        description: format!("condition {id}"),
        oracle_kind: kind,
        threshold: BlockerThreshold {
            name: format!("threshold_{id}"),
            threshold_value,
            direction,
            is_hard_blocker: hard,
        },
        policy_ref: POLICY_ID.to_string(),
        bead_ref: Some(format!("bd-{id}")),
    }
}

fn make_eval(id: &str, observed: u64, threshold: u64, verdict: GateVerdict) -> GateEvaluation {
    GateEvaluation {
        condition_id: id.to_string(),
        observed_value: observed,
        threshold_value: threshold,
        verdict,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: observed as i64 - threshold as i64,
    }
}

// ===========================================================================
// 1. OracleKind
// ===========================================================================

#[test]
fn enrichment_oracle_kind_all_returns_six_variants() {
    assert_eq!(OracleKind::all().len(), 6);
}

#[test]
fn enrichment_oracle_kind_all_as_str_unique() {
    let strs: BTreeSet<&str> = OracleKind::all().iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_oracle_kind_as_str_values() {
    assert_eq!(OracleKind::Scenario.as_str(), "scenario");
    assert_eq!(OracleKind::Replay.as_str(), "replay");
    assert_eq!(OracleKind::Contract.as_str(), "contract");
    assert_eq!(OracleKind::Metric.as_str(), "metric");
    assert_eq!(OracleKind::Evidence.as_str(), "evidence");
    assert_eq!(OracleKind::Obligation.as_str(), "obligation");
}

#[test]
fn enrichment_oracle_kind_display_matches_as_str() {
    for kind in OracleKind::all() {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_oracle_kind_serde_roundtrip_all() {
    for kind in OracleKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let restored: OracleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_oracle_kind_serde_snake_case_format() {
    let json = serde_json::to_string(&OracleKind::Scenario).unwrap();
    assert_eq!(json, "\"scenario\"");
    let json = serde_json::to_string(&OracleKind::Evidence).unwrap();
    assert_eq!(json, "\"evidence\"");
}

#[test]
fn enrichment_oracle_kind_ordering_is_deterministic() {
    let mut kinds: Vec<OracleKind> = OracleKind::all().to_vec();
    kinds.sort();
    let mut kinds2 = kinds.clone();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ===========================================================================
// 2. ThresholdDirection
// ===========================================================================

#[test]
fn enrichment_threshold_direction_at_least_passes_equal() {
    assert!(ThresholdDirection::AtLeast.passes(100, 100));
}

#[test]
fn enrichment_threshold_direction_at_least_passes_above() {
    assert!(ThresholdDirection::AtLeast.passes(101, 100));
}

#[test]
fn enrichment_threshold_direction_at_least_fails_below() {
    assert!(!ThresholdDirection::AtLeast.passes(99, 100));
}

#[test]
fn enrichment_threshold_direction_at_most_passes_equal() {
    assert!(ThresholdDirection::AtMost.passes(100, 100));
}

#[test]
fn enrichment_threshold_direction_at_most_passes_below() {
    assert!(ThresholdDirection::AtMost.passes(50, 100));
}

#[test]
fn enrichment_threshold_direction_at_most_fails_above() {
    assert!(!ThresholdDirection::AtMost.passes(101, 100));
}

#[test]
fn enrichment_threshold_direction_exactly_passes_equal() {
    assert!(ThresholdDirection::Exactly.passes(42, 42));
}

#[test]
fn enrichment_threshold_direction_exactly_fails_below() {
    assert!(!ThresholdDirection::Exactly.passes(41, 42));
}

#[test]
fn enrichment_threshold_direction_exactly_fails_above() {
    assert!(!ThresholdDirection::Exactly.passes(43, 42));
}

#[test]
fn enrichment_threshold_direction_boundary_zero() {
    assert!(ThresholdDirection::AtLeast.passes(0, 0));
    assert!(ThresholdDirection::AtMost.passes(0, 0));
    assert!(ThresholdDirection::Exactly.passes(0, 0));
}

#[test]
fn enrichment_threshold_direction_boundary_max() {
    assert!(ThresholdDirection::AtLeast.passes(u64::MAX, u64::MAX));
    assert!(ThresholdDirection::AtMost.passes(u64::MAX, u64::MAX));
    assert!(ThresholdDirection::Exactly.passes(u64::MAX, u64::MAX));
}

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
fn enrichment_threshold_direction_serde_roundtrip() {
    for dir in [
        ThresholdDirection::AtLeast,
        ThresholdDirection::AtMost,
        ThresholdDirection::Exactly,
    ] {
        let json = serde_json::to_string(&dir).unwrap();
        let restored: ThresholdDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, restored);
    }
}

// ===========================================================================
// 3. BlockerThreshold evaluate()
// ===========================================================================

#[test]
fn enrichment_blocker_threshold_hard_at_least_pass() {
    let t = BlockerThreshold {
        name: "pass_rate".to_string(),
        threshold_value: MILLIONTHS,
        direction: ThresholdDirection::AtLeast,
        is_hard_blocker: true,
    };
    assert!(t.evaluate(MILLIONTHS));
    assert!(t.evaluate(MILLIONTHS + 1));
}

#[test]
fn enrichment_blocker_threshold_hard_at_least_fail() {
    let t = BlockerThreshold {
        name: "pass_rate".to_string(),
        threshold_value: MILLIONTHS,
        direction: ThresholdDirection::AtLeast,
        is_hard_blocker: true,
    };
    assert!(!t.evaluate(MILLIONTHS - 1));
    assert!(!t.evaluate(0));
}

#[test]
fn enrichment_blocker_threshold_soft_at_most() {
    let t = BlockerThreshold {
        name: "regression".to_string(),
        threshold_value: 50_000,
        direction: ThresholdDirection::AtMost,
        is_hard_blocker: false,
    };
    assert!(t.evaluate(50_000));
    assert!(t.evaluate(0));
    assert!(!t.evaluate(50_001));
}

#[test]
fn enrichment_blocker_threshold_exactly_zero() {
    let t = BlockerThreshold {
        name: "divergences".to_string(),
        threshold_value: 0,
        direction: ThresholdDirection::Exactly,
        is_hard_blocker: true,
    };
    assert!(t.evaluate(0));
    assert!(!t.evaluate(1));
}

#[test]
fn enrichment_blocker_threshold_serde_roundtrip() {
    let t = BlockerThreshold {
        name: "test_threshold".to_string(),
        threshold_value: 42_000,
        direction: ThresholdDirection::AtLeast,
        is_hard_blocker: true,
    };
    let json = serde_json::to_string(&t).unwrap();
    let restored: BlockerThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, restored);
}

// ===========================================================================
// 4. evaluate_condition()
// ===========================================================================

#[test]
fn enrichment_evaluate_condition_pass_at_least() {
    let cond = make_condition(
        "sc",
        OracleKind::Scenario,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, MILLIONTHS, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 0);
    assert_eq!(eval.condition_id, "sc");
}

#[test]
fn enrichment_evaluate_condition_fail_hard_blocker() {
    let cond = make_condition(
        "sc",
        OracleKind::Scenario,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, 500_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Fail);
    assert_eq!(eval.margin_millionths, -500_000);
}

#[test]
fn enrichment_evaluate_condition_advisory_soft_blocker() {
    let cond = make_condition(
        "perf",
        OracleKind::Metric,
        50_000,
        ThresholdDirection::AtMost,
        false,
    );
    let eval = evaluate_condition(&cond, 100_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Advisory);
    // AtMost margin = threshold - observed = 50_000 - 100_000 = -50_000
    assert_eq!(eval.margin_millionths, -50_000);
}

#[test]
fn enrichment_evaluate_condition_at_most_pass() {
    let cond = make_condition(
        "reg",
        OracleKind::Metric,
        50_000,
        ThresholdDirection::AtMost,
        true,
    );
    let eval = evaluate_condition(&cond, 30_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    // margin = threshold - observed = 50_000 - 30_000 = 20_000
    assert_eq!(eval.margin_millionths, 20_000);
}

#[test]
fn enrichment_evaluate_condition_exactly_pass() {
    let cond = make_condition(
        "div",
        OracleKind::Replay,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let eval = evaluate_condition(&cond, 0, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 0);
}

#[test]
fn enrichment_evaluate_condition_exactly_fail_nonzero() {
    let cond = make_condition(
        "div",
        OracleKind::Replay,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let eval = evaluate_condition(&cond, 5, None, None);
    assert_eq!(eval.verdict, GateVerdict::Fail);
    assert_eq!(eval.margin_millionths, -5);
}

#[test]
fn enrichment_evaluate_condition_evidence_ref_propagated() {
    let cond = make_condition(
        "ev",
        OracleKind::Evidence,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let eval = evaluate_condition(&cond, 0, Some("ev-abc-123"), Some("replay-cmd-xyz"));
    assert_eq!(eval.evidence_ref, Some("ev-abc-123".to_string()));
    assert_eq!(eval.replay_ref, Some("replay-cmd-xyz".to_string()));
}

#[test]
fn enrichment_evaluate_condition_no_evidence_ref() {
    let cond = make_condition(
        "n",
        OracleKind::Scenario,
        100,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, 200, None, None);
    assert_eq!(eval.evidence_ref, None);
    assert_eq!(eval.replay_ref, None);
}

#[test]
fn enrichment_evaluate_condition_at_least_positive_margin() {
    let cond = make_condition(
        "m",
        OracleKind::Contract,
        100,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, 250, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 150);
}

#[test]
fn enrichment_evaluate_condition_threshold_stored_in_result() {
    let cond = make_condition(
        "t",
        OracleKind::Obligation,
        42,
        ThresholdDirection::AtMost,
        true,
    );
    let eval = evaluate_condition(&cond, 10, None, None);
    assert_eq!(eval.threshold_value, 42);
    assert_eq!(eval.observed_value, 10);
}

// ===========================================================================
// 5. GateVerdict
// ===========================================================================

#[test]
fn enrichment_gate_verdict_pass_does_not_block() {
    assert!(!GateVerdict::Pass.blocks_release());
}

#[test]
fn enrichment_gate_verdict_fail_blocks() {
    assert!(GateVerdict::Fail.blocks_release());
}

#[test]
fn enrichment_gate_verdict_advisory_does_not_block() {
    assert!(!GateVerdict::Advisory.blocks_release());
}

#[test]
fn enrichment_gate_verdict_inconclusive_blocks() {
    assert!(GateVerdict::Inconclusive.blocks_release());
}

#[test]
fn enrichment_gate_verdict_as_str_values() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::Fail.as_str(), "fail");
    assert_eq!(GateVerdict::Advisory.as_str(), "advisory");
    assert_eq!(GateVerdict::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn enrichment_gate_verdict_display_matches_as_str() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Advisory,
        GateVerdict::Inconclusive,
    ] {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip_all() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Advisory,
        GateVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// ===========================================================================
// 6. build_report()
// ===========================================================================

#[test]
fn enrichment_build_report_all_pass() {
    let evals = vec![
        make_eval("a", MILLIONTHS, MILLIONTHS, GateVerdict::Pass),
        make_eval("b", 0, 0, GateVerdict::Pass),
        make_eval("c", 50, 100, GateVerdict::Pass),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-all-pass", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert!(!report.blocks_release());
    assert_eq!(report.pass_count, 3);
    assert_eq!(report.fail_count, 0);
    assert_eq!(report.advisory_count, 0);
    assert_eq!(report.inconclusive_count, 0);
    assert_eq!(report.total_evaluations(), 3);
}

#[test]
fn enrichment_build_report_mixed_verdicts() {
    let evals = vec![
        make_eval("a", 100, 100, GateVerdict::Pass),
        make_eval("b", 50, 100, GateVerdict::Fail),
        make_eval("c", 80, 70, GateVerdict::Advisory),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-mixed", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert!(report.blocks_release());
    assert_eq!(report.pass_count, 1);
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.advisory_count, 1);
    assert_eq!(report.total_evaluations(), 3);
}

#[test]
fn enrichment_build_report_all_fail() {
    let evals = vec![
        make_eval("a", 0, 100, GateVerdict::Fail),
        make_eval("b", 0, 100, GateVerdict::Fail),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-all-fail", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert!(report.blocks_release());
    assert_eq!(report.fail_count, 2);
    assert_eq!(report.blockers().len(), 2);
}

#[test]
fn enrichment_build_report_empty_evaluations() {
    let report = build_report(SecurityEpoch::from_raw(1), "rc-empty", vec![]);
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert!(!report.blocks_release());
    assert_eq!(report.total_evaluations(), 0);
    assert!(report.blockers().is_empty());
}

#[test]
fn enrichment_build_report_advisory_only_does_not_block() {
    let evals = vec![
        make_eval("a", 100, 50, GateVerdict::Advisory),
        make_eval("b", 200, 100, GateVerdict::Advisory),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-advisory", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Advisory);
    assert!(!report.blocks_release());
    assert_eq!(report.advisory_count, 2);
}

#[test]
fn enrichment_build_report_inconclusive_blocks() {
    let evals = vec![make_eval("a", 0, 0, GateVerdict::Inconclusive)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-inc", evals);
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert!(report.blocks_release());
    assert_eq!(report.inconclusive_count, 1);
    assert_eq!(report.blockers().len(), 1);
}

#[test]
fn enrichment_build_report_schema_fields() {
    let report = build_report(SecurityEpoch::from_raw(42), "rc-schema", vec![]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(report.release_candidate_id, "rc-schema");
}

#[test]
fn enrichment_build_report_verify_integrity_passes() {
    let evals = vec![make_eval("x", 100, 100, GateVerdict::Pass)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-integrity", evals);
    assert!(report.verify_integrity());
}

#[test]
fn enrichment_build_report_integrity_detects_tampered_rc_id() {
    let evals = vec![make_eval("x", 100, 100, GateVerdict::Pass)];
    let mut report = build_report(SecurityEpoch::from_raw(1), "rc-orig", evals);
    assert!(report.verify_integrity());
    report.release_candidate_id = "rc-tampered".to_string();
    assert!(!report.verify_integrity());
}

#[test]
fn enrichment_build_report_integrity_detects_tampered_evaluation() {
    let evals = vec![make_eval("x", 100, 100, GateVerdict::Pass)];
    let mut report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
    assert!(report.verify_integrity());
    report.evaluations[0].observed_value = 999;
    assert!(!report.verify_integrity());
}

#[test]
fn enrichment_build_report_blockers_returns_only_blocking() {
    let evals = vec![
        make_eval("pass", 100, 100, GateVerdict::Pass),
        make_eval("fail", 50, 100, GateVerdict::Fail),
        make_eval("adv", 80, 50, GateVerdict::Advisory),
        make_eval("inc", 0, 0, GateVerdict::Inconclusive),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-blockers", evals);
    let blockers = report.blockers();
    assert_eq!(blockers.len(), 2);
    let blocker_ids: BTreeSet<&str> = blockers.iter().map(|e| e.condition_id.as_str()).collect();
    assert!(blocker_ids.contains("fail"));
    assert!(blocker_ids.contains("inc"));
}

#[test]
fn enrichment_build_report_serde_roundtrip() {
    let evals = vec![
        make_eval("a", MILLIONTHS, MILLIONTHS, GateVerdict::Pass),
        make_eval("b", 500_000, MILLIONTHS, GateVerdict::Fail),
    ];
    let report = build_report(SecurityEpoch::from_raw(7), "rc-serde", evals);
    let json = serde_json::to_string(&report).unwrap();
    let restored: OracleReleaseGateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// ===========================================================================
// 7. Deterministic hashing
// ===========================================================================

#[test]
fn enrichment_deterministic_report_hash_same_inputs() {
    let evals1 = vec![
        make_eval("a", 100, 100, GateVerdict::Pass),
        make_eval("b", 50, 100, GateVerdict::Fail),
    ];
    let evals2 = evals1.clone();
    let r1 = build_report(SecurityEpoch::from_raw(1), "rc-det", evals1);
    let r2 = build_report(SecurityEpoch::from_raw(1), "rc-det", evals2);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_different_epoch_different_hash() {
    let evals1 = vec![make_eval("a", 100, 100, GateVerdict::Pass)];
    let evals2 = evals1.clone();
    let r1 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals1);
    let r2 = build_report(SecurityEpoch::from_raw(2), "rc-1", evals2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_different_rc_id_different_hash() {
    let evals1 = vec![make_eval("a", 100, 100, GateVerdict::Pass)];
    let evals2 = evals1.clone();
    let r1 = build_report(SecurityEpoch::from_raw(1), "rc-alpha", evals1);
    let r2 = build_report(SecurityEpoch::from_raw(1), "rc-beta", evals2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_different_observed_value_different_hash() {
    let r1 = build_report(
        SecurityEpoch::from_raw(1),
        "rc-1",
        vec![make_eval("a", 100, 100, GateVerdict::Pass)],
    );
    let r2 = build_report(
        SecurityEpoch::from_raw(1),
        "rc-1",
        vec![make_eval("a", 101, 100, GateVerdict::Pass)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_different_condition_id_different_hash() {
    let r1 = build_report(
        SecurityEpoch::from_raw(1),
        "rc-1",
        vec![make_eval("alpha", 100, 100, GateVerdict::Pass)],
    );
    let r2 = build_report(
        SecurityEpoch::from_raw(1),
        "rc-1",
        vec![make_eval("beta", 100, 100, GateVerdict::Pass)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// 8. TriageBundle
// ===========================================================================

#[test]
fn enrichment_triage_bundle_from_clean_report() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, None, None))
        .collect();
    let report = build_report(SecurityEpoch::from_raw(1), "rc-clean", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.total_entries(), 0);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_triage_bundle_from_failing_report() {
    let conditions = default_gate_conditions();
    // Scenario condition requires AtLeast 1_000_000 pass rate; give it 500_000 to fail
    let evals = vec![evaluate_condition(
        &conditions[0],
        500_000,
        Some("ev-fail"),
        None,
    )];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-fail", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.blocker_count, 1);
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Blocker);
    assert_eq!(bundle.entries[0].evidence_ref, Some("ev-fail".to_string()));
}

#[test]
fn enrichment_triage_bundle_advisory_entry() {
    // Use the metric condition which is a soft blocker
    let conditions = default_gate_conditions();
    let metric_cond = conditions
        .iter()
        .find(|c| c.oracle_kind == OracleKind::Metric)
        .unwrap();
    let evals = vec![evaluate_condition(metric_cond, 100_000, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-advisory", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.warning_count, 1);
    assert_eq!(bundle.blocker_count, 0);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Warning);
}

#[test]
fn enrichment_triage_bundle_replay_remediation_contains_hint() {
    let replay_cond = make_condition(
        "replay-div",
        OracleKind::Replay,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let evals = vec![evaluate_condition(
        &replay_cond,
        3,
        None,
        Some("replay-ref"),
    )];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-replay", evals);
    let bundle = build_triage_bundle(&report, &[replay_cond]);
    assert_eq!(bundle.entries.len(), 1);
    assert!(
        bundle.entries[0]
            .remediation
            .contains("frankenctl replay run")
    );
}

#[test]
fn enrichment_triage_bundle_evidence_remediation() {
    let ev_cond = make_condition(
        "ev-gap",
        OracleKind::Evidence,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let evals = vec![evaluate_condition(&ev_cond, 2, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-ev", evals);
    let bundle = build_triage_bundle(&report, &[ev_cond]);
    assert!(bundle.entries[0].remediation.contains("evidence pipeline"));
}

#[test]
fn enrichment_triage_bundle_obligation_remediation() {
    let ob_cond = make_condition(
        "ob-unresolved",
        OracleKind::Obligation,
        0,
        ThresholdDirection::AtMost,
        true,
    );
    let evals = vec![evaluate_condition(&ob_cond, 5, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-ob", evals);
    let bundle = build_triage_bundle(&report, &[ob_cond]);
    assert!(bundle.entries[0].remediation.contains("obligation"));
}

#[test]
fn enrichment_triage_bundle_contract_remediation() {
    let ct_cond = make_condition(
        "ct-rate",
        OracleKind::Contract,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let evals = vec![evaluate_condition(&ct_cond, 900_000, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-ct", evals);
    let bundle = build_triage_bundle(&report, &[ct_cond]);
    assert!(bundle.entries[0].remediation.contains("contract test"));
}

#[test]
fn enrichment_triage_bundle_metric_remediation_includes_values() {
    let mt_cond = make_condition(
        "mt-perf",
        OracleKind::Metric,
        50_000,
        ThresholdDirection::AtMost,
        true,
    );
    let evals = vec![evaluate_condition(&mt_cond, 100_000, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-mt", evals);
    let bundle = build_triage_bundle(&report, &[mt_cond]);
    assert!(bundle.entries[0].remediation.contains("100000"));
    assert!(bundle.entries[0].remediation.contains("50000"));
}

#[test]
fn enrichment_triage_bundle_scenario_remediation() {
    let sc_cond = make_condition(
        "sc-fail",
        OracleKind::Scenario,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let evals = vec![evaluate_condition(&sc_cond, 800_000, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-sc", evals);
    let bundle = build_triage_bundle(&report, &[sc_cond]);
    assert!(bundle.entries[0].remediation.contains("frankenlab"));
}

#[test]
fn enrichment_triage_bundle_unknown_condition_defaults_to_scenario() {
    let conditions = default_gate_conditions();
    let evals = vec![make_eval("unknown-cond", 0, 100, GateVerdict::Fail)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-unknown", evals);
    let bundle = build_triage_bundle(&report, &conditions);
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].oracle_kind, OracleKind::Scenario);
    assert!(bundle.entries[0].summary.contains("Unknown"));
}

#[test]
fn enrichment_triage_bundle_verify_integrity() {
    let cond = make_condition(
        "x",
        OracleKind::Scenario,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let evals = vec![evaluate_condition(&cond, 500_000, None, None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-int", evals);
    let bundle = build_triage_bundle(&report, &[cond]);
    assert!(bundle.verify_integrity());
}

#[test]
fn enrichment_triage_bundle_serde_roundtrip() {
    let cond = make_condition(
        "s",
        OracleKind::Evidence,
        0,
        ThresholdDirection::Exactly,
        true,
    );
    let evals = vec![evaluate_condition(&cond, 2, Some("ev-ref"), None)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-serde", evals);
    let bundle = build_triage_bundle(&report, &[cond]);
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: TriageBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

#[test]
fn enrichment_triage_bundle_empty_integrity() {
    let report = build_report(SecurityEpoch::from_raw(1), "rc-empty", vec![]);
    let bundle = build_triage_bundle(&report, &[]);
    assert!(bundle.verify_integrity());
    assert_eq!(bundle.total_entries(), 0);
}

#[test]
fn enrichment_triage_bundle_multiple_severities() {
    let hard_cond = make_condition(
        "h",
        OracleKind::Scenario,
        100,
        ThresholdDirection::AtLeast,
        true,
    );
    let soft_cond = make_condition(
        "s",
        OracleKind::Metric,
        50,
        ThresholdDirection::AtMost,
        false,
    );
    let evals = vec![
        evaluate_condition(&hard_cond, 50, None, None),
        evaluate_condition(&soft_cond, 100, None, None),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-multi", evals);
    let bundle = build_triage_bundle(&report, &[hard_cond, soft_cond]);
    assert_eq!(bundle.blocker_count, 1);
    assert_eq!(bundle.warning_count, 1);
    assert_eq!(bundle.total_entries(), 2);
}

// ===========================================================================
// 9. TriageSeverity
// ===========================================================================

#[test]
fn enrichment_triage_severity_as_str_values() {
    assert_eq!(TriageSeverity::Blocker.as_str(), "blocker");
    assert_eq!(TriageSeverity::Warning.as_str(), "warning");
    assert_eq!(TriageSeverity::Info.as_str(), "info");
}

#[test]
fn enrichment_triage_severity_display_matches_as_str() {
    for sev in [
        TriageSeverity::Blocker,
        TriageSeverity::Warning,
        TriageSeverity::Info,
    ] {
        assert_eq!(sev.to_string(), sev.as_str());
    }
}

#[test]
fn enrichment_triage_severity_serde_roundtrip() {
    for sev in [
        TriageSeverity::Blocker,
        TriageSeverity::Warning,
        TriageSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let restored: TriageSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, restored);
    }
}

// ===========================================================================
// 10. build_gate_event()
// ===========================================================================

#[test]
fn enrichment_gate_event_fields_from_report() {
    let evals = vec![
        make_eval("a", 100, 100, GateVerdict::Pass),
        make_eval("b", 0, 100, GateVerdict::Fail),
    ];
    let report = build_report(SecurityEpoch::from_raw(5), "rc-event", evals);
    let event = build_gate_event("trace-42", "decision-99", &report);
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.trace_id, "trace-42");
    assert_eq!(event.decision_id, "decision-99");
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.event, "oracle_release_gate_evaluated");
    assert_eq!(event.release_candidate_id, "rc-event");
    assert_eq!(event.overall_verdict, "fail");
    assert_eq!(event.conditions_evaluated, 2);
    assert_eq!(event.blockers, 1);
}

#[test]
fn enrichment_gate_event_all_pass_zero_blockers() {
    let evals = vec![make_eval("a", 100, 100, GateVerdict::Pass)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.overall_verdict, "pass");
    assert_eq!(event.blockers, 0);
    assert_eq!(event.conditions_evaluated, 1);
}

#[test]
fn enrichment_gate_event_inconclusive_counted_as_blocker() {
    let evals = vec![
        make_eval("a", 0, 0, GateVerdict::Inconclusive),
        make_eval("b", 0, 100, GateVerdict::Fail),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.blockers, 2);
}

#[test]
fn enrichment_gate_event_serde_roundtrip() {
    let report = build_report(SecurityEpoch::from_raw(1), "rc-1", vec![]);
    let event = build_gate_event("trace-1", "dec-1", &report);
    let json = serde_json::to_string(&event).unwrap();
    let restored: OracleReleaseGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_gate_event_seed_contains_bead_id() {
    let report = build_report(SecurityEpoch::from_raw(1), "rc-1", vec![]);
    let event = build_gate_event("t", "d", &report);
    assert!(event.seed.contains(BEAD_ID));
}

// ===========================================================================
// 11. default_gate_conditions()
// ===========================================================================

#[test]
fn enrichment_default_conditions_cover_all_oracle_kinds() {
    let conditions = default_gate_conditions();
    let kinds: BTreeSet<OracleKind> = conditions.iter().map(|c| c.oracle_kind).collect();
    for kind in OracleKind::all() {
        assert!(
            kinds.contains(kind),
            "default conditions missing oracle kind: {kind}"
        );
    }
}

#[test]
fn enrichment_default_conditions_unique_ids() {
    let conditions = default_gate_conditions();
    let ids: BTreeSet<&str> = conditions.iter().map(|c| c.condition_id.as_str()).collect();
    assert_eq!(ids.len(), conditions.len());
}

#[test]
fn enrichment_default_conditions_all_have_policy_ref() {
    for c in &default_gate_conditions() {
        assert!(!c.policy_ref.is_empty());
    }
}

#[test]
fn enrichment_default_conditions_metric_is_soft_blocker() {
    let metric = default_gate_conditions()
        .into_iter()
        .find(|c| c.oracle_kind == OracleKind::Metric)
        .unwrap();
    assert!(!metric.threshold.is_hard_blocker);
}

#[test]
fn enrichment_default_conditions_scenario_is_hard_blocker() {
    let scenario = default_gate_conditions()
        .into_iter()
        .find(|c| c.oracle_kind == OracleKind::Scenario)
        .unwrap();
    assert!(scenario.threshold.is_hard_blocker);
}

// ===========================================================================
// 12. Constants
// ===========================================================================

#[test]
fn enrichment_constants_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_constants_values() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.oracle-release-gate.v1");
    assert_eq!(BEAD_ID, "bd-3nr.1.4.3");
    assert_eq!(POLICY_ID, "10.13X.D3");
    assert_eq!(COMPONENT, "oracle_release_gate");
}

#[test]
fn enrichment_default_min_pass_rate_is_one_million() {
    assert_eq!(DEFAULT_MIN_PASS_RATE, 1_000_000);
}

#[test]
fn enrichment_default_max_regression_is_five_percent() {
    assert_eq!(DEFAULT_MAX_REGRESSION, 50_000);
}

#[test]
fn enrichment_default_max_unresolved_is_zero() {
    assert_eq!(DEFAULT_MAX_UNRESOLVED, 0);
}

// ===========================================================================
// 13. OracleGateCondition serde
// ===========================================================================

#[test]
fn enrichment_oracle_gate_condition_serde_roundtrip() {
    let cond = make_condition(
        "cond-1",
        OracleKind::Contract,
        MILLIONTHS,
        ThresholdDirection::AtLeast,
        true,
    );
    let json = serde_json::to_string(&cond).unwrap();
    let restored: OracleGateCondition = serde_json::from_str(&json).unwrap();
    assert_eq!(cond, restored);
}

#[test]
fn enrichment_oracle_gate_condition_bead_ref_none() {
    let cond = OracleGateCondition {
        condition_id: "no-bead".to_string(),
        description: "test".to_string(),
        oracle_kind: OracleKind::Metric,
        threshold: BlockerThreshold {
            name: "t".to_string(),
            threshold_value: 0,
            direction: ThresholdDirection::Exactly,
            is_hard_blocker: false,
        },
        policy_ref: POLICY_ID.to_string(),
        bead_ref: None,
    };
    let json = serde_json::to_string(&cond).unwrap();
    let restored: OracleGateCondition = serde_json::from_str(&json).unwrap();
    assert_eq!(cond, restored);
    assert!(restored.bead_ref.is_none());
}

// ===========================================================================
// 14. GateEvaluation serde
// ===========================================================================

#[test]
fn enrichment_gate_evaluation_serde_roundtrip() {
    let eval = GateEvaluation {
        condition_id: "test-eval".to_string(),
        observed_value: 42,
        threshold_value: 100,
        verdict: GateVerdict::Fail,
        evidence_ref: Some("ev-42".to_string()),
        replay_ref: Some("replay-42".to_string()),
        margin_millionths: -58,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let restored: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
}

#[test]
fn enrichment_gate_evaluation_optional_refs_none() {
    let eval = GateEvaluation {
        condition_id: "no-refs".to_string(),
        observed_value: 0,
        threshold_value: 0,
        verdict: GateVerdict::Pass,
        evidence_ref: None,
        replay_ref: None,
        margin_millionths: 0,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let restored: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
}

// ===========================================================================
// 15. TriageBundleEntry serde
// ===========================================================================

#[test]
fn enrichment_triage_bundle_entry_serde_roundtrip() {
    let entry = TriageBundleEntry {
        condition_id: "entry-1".to_string(),
        oracle_kind: OracleKind::Replay,
        severity: TriageSeverity::Blocker,
        summary: "replay diverged".to_string(),
        remediation: "fix the replay".to_string(),
        evidence_ref: Some("ev-entry".to_string()),
        replay_ref: Some("replay-cmd".to_string()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: TriageBundleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// ===========================================================================
// 16. End-to-end integration: full pipeline
// ===========================================================================

#[test]
fn enrichment_full_pipeline_all_default_conditions_pass() {
    let conditions = default_gate_conditions();
    let evals: Vec<GateEvaluation> = conditions
        .iter()
        .map(|c| evaluate_condition(c, c.threshold.threshold_value, Some("ev"), Some("rp")))
        .collect();
    let report = build_report(SecurityEpoch::from_raw(10), "rc-full-pass", evals);

    // Report assertions
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert!(!report.blocks_release());
    assert!(report.verify_integrity());
    assert_eq!(report.total_evaluations(), conditions.len() as u64);

    // Triage bundle should be empty
    let bundle = build_triage_bundle(&report, &conditions);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.total_entries(), 0);
    assert!(bundle.verify_integrity());

    // Event should reflect passing
    let event = build_gate_event("trace-full", "dec-full", &report);
    assert_eq!(event.overall_verdict, "pass");
    assert_eq!(event.blockers, 0);
}

#[test]
fn enrichment_full_pipeline_mixed_failures() {
    let conditions = default_gate_conditions();

    // Make scenario fail (needs AtLeast 1_000_000, give 800_000)
    // Make metric fail (needs AtMost 50_000, give 100_000 -- this is advisory since soft)
    let mut evals = Vec::new();
    for c in &conditions {
        let observed = match c.oracle_kind {
            OracleKind::Scenario => 800_000,
            OracleKind::Metric => 100_000,
            _ => c.threshold.threshold_value,
        };
        evals.push(evaluate_condition(c, observed, None, None));
    }
    let report = build_report(SecurityEpoch::from_raw(1), "rc-mixed-pipe", evals);

    assert!(report.blocks_release());
    assert!(report.fail_count >= 1);

    let bundle = build_triage_bundle(&report, &conditions);
    assert!(bundle.has_blockers());
    assert!(bundle.warning_count >= 1); // metric advisory

    let event = build_gate_event("t", "d", &report);
    assert_eq!(event.overall_verdict, "fail");
    assert!(event.blockers >= 1);
}

// ===========================================================================
// 17. ContentHash determinism
// ===========================================================================

#[test]
fn enrichment_content_hash_from_compute_is_deterministic() {
    let h1 = ContentHash::compute(b"oracle-release-gate-test");
    let h2 = ContentHash::compute(b"oracle-release-gate-test");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_inputs_differ() {
    let h1 = ContentHash::compute(b"input-a");
    let h2 = ContentHash::compute(b"input-b");
    assert_ne!(h1, h2);
}

// ===========================================================================
// 18. Edge cases
// ===========================================================================

#[test]
fn enrichment_evaluate_condition_zero_threshold_at_least_zero_observed() {
    let cond = make_condition(
        "z",
        OracleKind::Scenario,
        0,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, 0, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 0);
}

#[test]
fn enrichment_evaluate_condition_large_margin() {
    let cond = make_condition(
        "lg",
        OracleKind::Scenario,
        1_000,
        ThresholdDirection::AtLeast,
        true,
    );
    let eval = evaluate_condition(&cond, 1_000_000, None, None);
    assert_eq!(eval.verdict, GateVerdict::Pass);
    assert_eq!(eval.margin_millionths, 999_000);
}

#[test]
fn enrichment_report_many_evaluations() {
    let evals: Vec<GateEvaluation> = (0..100)
        .map(|i| make_eval(&format!("cond-{i}"), 100, 100, GateVerdict::Pass))
        .collect();
    let report = build_report(SecurityEpoch::from_raw(1), "rc-many", evals);
    assert_eq!(report.total_evaluations(), 100);
    assert_eq!(report.pass_count, 100);
    assert!(report.verify_integrity());
}

#[test]
fn enrichment_triage_bundle_passes_are_skipped() {
    let evals = vec![
        make_eval("pass1", 100, 100, GateVerdict::Pass),
        make_eval("pass2", 50, 50, GateVerdict::Pass),
        make_eval("fail1", 0, 100, GateVerdict::Fail),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-skip", evals);
    let bundle = build_triage_bundle(&report, &[]);
    // Only the Fail entry should appear; Pass entries are skipped
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].condition_id, "fail1");
}

#[test]
fn enrichment_report_total_evaluations_matches_sum() {
    let evals = vec![
        make_eval("a", 0, 0, GateVerdict::Pass),
        make_eval("b", 0, 0, GateVerdict::Fail),
        make_eval("c", 0, 0, GateVerdict::Advisory),
        make_eval("d", 0, 0, GateVerdict::Inconclusive),
    ];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-sum", evals);
    assert_eq!(
        report.total_evaluations(),
        report.pass_count + report.fail_count + report.advisory_count + report.inconclusive_count
    );
    assert_eq!(report.total_evaluations(), 4);
}

#[test]
fn enrichment_triage_bundle_inconclusive_is_blocker_severity() {
    let evals = vec![make_eval("inc", 0, 0, GateVerdict::Inconclusive)];
    let report = build_report(SecurityEpoch::from_raw(1), "rc-inc", evals);
    let bundle = build_triage_bundle(&report, &[]);
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].severity, TriageSeverity::Blocker);
    assert!(bundle.has_blockers());
}
