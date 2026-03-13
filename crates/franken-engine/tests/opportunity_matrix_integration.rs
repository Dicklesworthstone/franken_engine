#![forbid(unsafe_code)]

//! Integration tests for the `opportunity_matrix` module.
//!
//! Covers: constructors, scoring pipeline, validation, error paths, serde round-trips,
//! hotspot profiling from flamegraphs, benchmark pressure derivation,
//! candidate derivation, event generation, historical tracking, Display/Debug,
//! and determinism guarantees.

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

use frankenengine_engine::benchmark_denominator::BenchmarkCase;
use frankenengine_engine::flamegraph_pipeline::{
    FlamegraphArtifact, FlamegraphEvidenceLink, FlamegraphKind, FlamegraphMetadata,
    FoldedStackSample,
};
use frankenengine_engine::opportunity_matrix::*;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_candidate(id: &str, module: &str, function: &str) -> OptimizationCandidateInput {
    OptimizationCandidateInput {
        opportunity_id: id.to_string(),
        target_module: module.to_string(),
        target_function: function.to_string(),
        estimated_speedup_millionths: 2_500_000,
        implementation_complexity: 2,
        regression_risk_millionths: 250_000,
        security_clearance_millionths: 1_000_000,
        engineering_effort_hours_millionths: 1_000_000,
        hotpath_weight_override_millionths: None,
    }
}

fn base_request() -> OpportunityMatrixRequest {
    OpportunityMatrixRequest {
        trace_id: "trace-int".to_string(),
        decision_id: "decision-int".to_string(),
        policy_id: "policy-int".to_string(),
        optimization_run_id: "run-int-001".to_string(),
        benchmark_pressure_millionths: 1_250_000,
        hotspots: vec![
            HotspotProfileEntry {
                module: "vm".to_string(),
                function: "dispatch".to_string(),
                sample_count: 90,
            },
            HotspotProfileEntry {
                module: "vm".to_string(),
                function: "gc_tick".to_string(),
                sample_count: 10,
            },
        ],
        candidates: vec![
            make_candidate("opp-vm-dispatch", "vm", "dispatch"),
            make_candidate("opp-vm-gc", "vm", "gc_tick"),
        ],
        historical_outcomes: vec![OpportunityOutcomeObservation {
            opportunity_id: "opp-vm-dispatch".to_string(),
            predicted_gain_millionths: 400_000,
            actual_gain_millionths: 350_000,
            completed_at_utc: "2026-02-22T12:30:00Z".to_string(),
        }],
    }
}

fn make_flamegraph(kind: FlamegraphKind, stacks: Vec<(&str, u64)>) -> FlamegraphArtifact {
    FlamegraphArtifact {
        schema_version: "v1".into(),
        artifact_id: "art-int-1".into(),
        kind,
        metadata: FlamegraphMetadata {
            benchmark_run_id: "br-int".into(),
            baseline_benchmark_run_id: None,
            workload_id: "w-int".into(),
            benchmark_profile: "profile".into(),
            config_fingerprint: "fp".into(),
            git_commit: "abc123".into(),
            generated_at_utc: "2026-01-01T00:00:00Z".into(),
        },
        evidence_link: FlamegraphEvidenceLink {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            benchmark_run_id: "br-int".into(),
            optimization_decision_id: "od".into(),
            evidence_node_id: "en".into(),
        },
        folded_stacks: stacks
            .into_iter()
            .map(|(stack, count)| FoldedStackSample {
                stack: stack.to_string(),
                sample_count: count,
            })
            .collect(),
        folded_stacks_text: String::new(),
        svg: String::new(),
        total_samples: 0,
        diff_from_artifact_id: None,
        diff_entries: Vec::new(),
        warnings: Vec::new(),
        storage_integration_point: String::new(),
    }
}

fn make_benchmark_case(workload: &str, franken_tps: f64, baseline_tps: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload.to_string(),
        throughput_franken_tps: franken_tps,
        throughput_baseline_tps: baseline_tps,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

// ── Section 1: Constants ─────────────────────────────────────────────

#[test]
fn constants_have_expected_values() {
    assert_eq!(OPPORTUNITY_MATRIX_COMPONENT, "opportunity_matrix");
    assert_eq!(
        OPPORTUNITY_MATRIX_SCHEMA_VERSION,
        "franken-engine.opportunity-matrix.v1"
    );
    assert_eq!(OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
}

// ── Section 2: HotspotProfileEntry ───────────────────────────────────

#[test]
fn hotspot_profile_entry_key_format() {
    let entry = HotspotProfileEntry {
        module: "parser".into(),
        function: "tokenize".into(),
        sample_count: 42,
    };
    assert_eq!(entry.key(), "parser::tokenize");
}

#[test]
fn hotspot_profile_entry_serde_roundtrip() {
    let entry = HotspotProfileEntry {
        module: "vm".into(),
        function: "dispatch".into(),
        sample_count: 1000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: HotspotProfileEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn hotspot_profile_entry_debug_contains_fields() {
    let entry = HotspotProfileEntry {
        module: "gc".into(),
        function: "sweep".into(),
        sample_count: 77,
    };
    let debug = format!("{entry:?}");
    assert!(debug.contains("gc"));
    assert!(debug.contains("sweep"));
    assert!(debug.contains("77"));
}

// ── Section 3: OptimizationCandidateInput ────────────────────────────

#[test]
fn candidate_target_key_format() {
    let c = make_candidate("opp-1", "vm", "dispatch");
    assert_eq!(c.target_key(), "vm::dispatch");
}

#[test]
fn candidate_serde_roundtrip() {
    let c = make_candidate("opp-serde", "parser", "lex");
    let json = serde_json::to_string(&c).unwrap();
    let back: OptimizationCandidateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn candidate_with_hotpath_override_serde() {
    let mut c = make_candidate("opp-override", "gc", "collect");
    c.hotpath_weight_override_millionths = Some(750_000);
    let json = serde_json::to_string(&c).unwrap();
    let back: OptimizationCandidateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.hotpath_weight_override_millionths, Some(750_000));
}

// ── Section 4: OpportunityStatus serde ───────────────────────────────

#[test]
fn opportunity_status_snake_case_serde() {
    let pairs = [
        (OpportunityStatus::Selected, "\"selected\""),
        (
            OpportunityStatus::RejectedLowScore,
            "\"rejected_low_score\"",
        ),
        (
            OpportunityStatus::RejectedSecurityClearance,
            "\"rejected_security_clearance\"",
        ),
        (
            OpportunityStatus::RejectedMissingHotspot,
            "\"rejected_missing_hotspot\"",
        ),
    ];
    for (variant, expected_json) in &pairs {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(&json, expected_json);
        let back: OpportunityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, variant);
    }
}

// ── Section 5: OpportunityMatrixError ────────────────────────────────

#[test]
fn error_stable_codes_are_distinct() {
    let e1 = OpportunityMatrixError::InvalidRequest {
        field: "f".into(),
        detail: "d".into(),
    };
    let e2 = OpportunityMatrixError::DuplicateOpportunityId {
        opportunity_id: "x".into(),
    };
    let e3 = OpportunityMatrixError::InvalidTimestamp {
        value: "bad".into(),
    };
    let codes: BTreeSet<&str> = [e1.stable_code(), e2.stable_code(), e3.stable_code()]
        .into_iter()
        .collect();
    assert_eq!(codes.len(), 3);
    assert_eq!(e1.stable_code(), "FE-OPPM-1001");
    assert_eq!(e2.stable_code(), "FE-OPPM-1002");
    assert_eq!(e3.stable_code(), "FE-OPPM-1003");
}

#[test]
fn error_display_contains_field_info() {
    let e = OpportunityMatrixError::InvalidRequest {
        field: "trace_id".into(),
        detail: "must not be empty".into(),
    };
    let msg = e.to_string();
    assert!(msg.contains("trace_id"));
    assert!(msg.contains("must not be empty"));
}

#[test]
fn error_display_duplicate_id_contains_id() {
    let e = OpportunityMatrixError::DuplicateOpportunityId {
        opportunity_id: "opp-dup".into(),
    };
    assert!(e.to_string().contains("opp-dup"));
}

#[test]
fn error_display_invalid_timestamp_contains_value() {
    let e = OpportunityMatrixError::InvalidTimestamp {
        value: "not-a-date".into(),
    };
    assert!(e.to_string().contains("not-a-date"));
}

#[test]
fn error_implements_std_error() {
    let e = OpportunityMatrixError::InvalidRequest {
        field: "f".into(),
        detail: "d".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn error_clone_and_eq() {
    let e = OpportunityMatrixError::DuplicateOpportunityId {
        opportunity_id: "abc".into(),
    };
    let e2 = e.clone();
    assert_eq!(e, e2);
}

// ── Section 6: Validation errors (via run_opportunity_matrix_scoring) ─

#[test]
fn validation_empty_trace_id() {
    let mut req = base_request();
    req.trace_id = "  ".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_empty_decision_id() {
    let mut req = base_request();
    req.decision_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_empty_policy_id() {
    let mut req = base_request();
    req.policy_id = "  \t ".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_empty_optimization_run_id() {
    let mut req = base_request();
    req.optimization_run_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_empty_candidates_list() {
    let mut req = base_request();
    req.candidates.clear();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_zero_benchmark_pressure() {
    let mut req = base_request();
    req.benchmark_pressure_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_negative_benchmark_pressure() {
    let mut req = base_request();
    req.benchmark_pressure_millionths = -500;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_empty_opportunity_id_on_candidate() {
    let mut req = base_request();
    req.candidates[0].opportunity_id = "   ".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn validation_duplicate_opportunity_id() {
    let mut req = base_request();
    req.candidates[1].opportunity_id = req.candidates[0].opportunity_id.clone();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1002"));
}

#[test]
fn validation_invalid_historical_timestamp() {
    let mut req = base_request();
    req.historical_outcomes[0].completed_at_utc = "not-rfc3339".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1003"));
}

// ── Section 7: Scoring pipeline — determinism ────────────────────────

#[test]
fn scoring_is_deterministic_across_runs() {
    let req = base_request();
    let a = run_opportunity_matrix_scoring(&req);
    let b = run_opportunity_matrix_scoring(&req);
    assert_eq!(a.matrix_id, b.matrix_id);
    assert_eq!(a.ranked_opportunities, b.ranked_opportunities);
    assert_eq!(a.selected_opportunity_ids, b.selected_opportunity_ids);
    assert_eq!(a.historical_tracking, b.historical_tracking);
}

#[test]
fn scoring_allow_outcome_when_threshold_met() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "allow");
    assert!(d.has_selected_opportunities());
    assert!(!d.selected_opportunity_ids.is_empty());
    assert!(d.error_code.is_none());
}

#[test]
fn scoring_deny_outcome_when_all_below_threshold() {
    let mut req = base_request();
    // Make both candidates very low scoring
    for c in &mut req.candidates {
        c.estimated_speedup_millionths = 1_050_000;
        c.engineering_effort_hours_millionths = 20_000_000;
        c.regression_risk_millionths = 900_000;
        c.implementation_complexity = 5;
    }
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "deny");
    assert!(!d.has_selected_opportunities());
    assert!(d.selected_opportunity_ids.is_empty());
    for opp in &d.ranked_opportunities {
        assert!(!opp.threshold_met);
    }
}

// ── Section 8: Scoring — status classification ───────────────────────

#[test]
fn security_clearance_zero_rejects_candidate() {
    let mut req = base_request();
    req.candidates[0].security_clearance_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.status, OpportunityStatus::RejectedSecurityClearance);
    assert_eq!(
        opp.rejection_reason.as_deref(),
        Some("SECURITY_CLEARANCE_ZERO")
    );
}

#[test]
fn negative_security_clearance_rejects_candidate() {
    let mut req = base_request();
    req.candidates[0].security_clearance_millionths = -100;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.status, OpportunityStatus::RejectedSecurityClearance);
}

#[test]
fn missing_hotspot_weight_rejects_candidate() {
    let mut req = base_request();
    req.hotspots.clear();
    req.candidates[0].hotpath_weight_override_millionths = None;
    req.candidates[1].hotpath_weight_override_millionths = None;
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        assert_eq!(opp.status, OpportunityStatus::RejectedMissingHotspot);
        assert_eq!(
            opp.rejection_reason.as_deref(),
            Some("MISSING_HOTSPOT_WEIGHT")
        );
    }
}

#[test]
fn low_score_candidate_has_score_below_threshold_reason() {
    let mut req = base_request();
    req.candidates[0].estimated_speedup_millionths = 1_050_000;
    req.candidates[0].engineering_effort_hours_millionths = 20_000_000;
    req.candidates[0].regression_risk_millionths = 900_000;
    req.candidates[0].implementation_complexity = 5;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.status, OpportunityStatus::RejectedLowScore);
    assert_eq!(
        opp.rejection_reason.as_deref(),
        Some("SCORE_BELOW_THRESHOLD")
    );
}

#[test]
fn selected_candidate_has_no_rejection_reason() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    let selected = d
        .ranked_opportunities
        .iter()
        .find(|o| o.status == OpportunityStatus::Selected)
        .unwrap();
    assert!(selected.rejection_reason.is_none());
}

// ── Section 9: Scoring — edge cases ──────────────────────────────────

#[test]
fn zero_complexity_floored_to_one() {
    let mut req = base_request();
    req.candidates[0].implementation_complexity = 0;
    let d = run_opportunity_matrix_scoring(&req);
    // Should not panic; score still computed
    assert!(!d.ranked_opportunities.is_empty());
}

#[test]
fn zero_risk_floored_to_minimum() {
    let mut req = base_request();
    req.candidates[0].regression_risk_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert!(!d.ranked_opportunities.is_empty());
}

#[test]
fn zero_effort_floored_to_minimum() {
    let mut req = base_request();
    req.candidates[0].engineering_effort_hours_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert!(!d.ranked_opportunities.is_empty());
}

#[test]
fn negative_speedup_clamped_to_zero_in_output() {
    let mut req = base_request();
    req.candidates[0].estimated_speedup_millionths = -1_000_000;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.estimated_speedup_millionths, 0);
}

#[test]
fn hotpath_weight_override_used_instead_of_profile() {
    let mut req = base_request();
    req.candidates[0].hotpath_weight_override_millionths = Some(500_000);
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.hotpath_weight_millionths, 500_000);
}

#[test]
fn hotpath_weight_override_clamped_to_million() {
    let mut req = base_request();
    req.candidates[0].hotpath_weight_override_millionths = Some(5_000_000);
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.hotpath_weight_millionths, 1_000_000);
}

// ── Section 10: Ranked output ordering ───────────────────────────────

#[test]
fn ranked_opportunities_sorted_by_score_descending() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for window in d.ranked_opportunities.windows(2) {
        assert!(window[0].score_millionths >= window[1].score_millionths);
    }
}

#[test]
fn tied_scores_break_by_opportunity_id_ascending() {
    let mut req = base_request();
    // Make both candidates identical in parameters
    req.candidates[0] = make_candidate("opp-b-second", "vm", "dispatch");
    req.candidates[0].hotpath_weight_override_millionths = Some(500_000);
    req.candidates[1] = make_candidate("opp-a-first", "vm", "gc_tick");
    req.candidates[1].hotpath_weight_override_millionths = Some(500_000);
    let d = run_opportunity_matrix_scoring(&req);
    // With identical parameters and identical override weights, scores should be equal
    // so tiebreak is by opportunity_id ascending
    if d.ranked_opportunities.len() >= 2
        && d.ranked_opportunities[0].score_millionths == d.ranked_opportunities[1].score_millionths
    {
        assert!(
            d.ranked_opportunities[0].opportunity_id < d.ranked_opportunities[1].opportunity_id
        );
    }
}

// ── Section 11: Decision metadata ────────────────────────────────────

#[test]
fn decision_schema_version_matches_constant() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.schema_version, OPPORTUNITY_MATRIX_SCHEMA_VERSION);
}

#[test]
fn decision_matrix_id_starts_with_opm_prefix() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert!(d.matrix_id.starts_with("opm-"));
}

#[test]
fn decision_matrix_id_changes_with_different_trace() {
    let req1 = base_request();
    let d1 = run_opportunity_matrix_scoring(&req1);
    let mut req2 = base_request();
    req2.trace_id = "different-trace-id".into();
    let d2 = run_opportunity_matrix_scoring(&req2);
    assert_ne!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn decision_optimization_run_id_preserved() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.optimization_run_id, "run-int-001");
}

#[test]
fn decision_benchmark_pressure_preserved() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.benchmark_pressure_millionths, 1_250_000);
}

#[test]
fn decision_score_threshold_matches_constant() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(
        d.score_threshold_millionths,
        OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS
    );
}

// ── Section 12: Events ───────────────────────────────────────────────

#[test]
fn events_include_start_and_completion() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let event_names: Vec<&str> = d.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"opportunity_matrix_started"));
    assert!(event_names.contains(&"opportunity_matrix_completed"));
}

#[test]
fn events_include_per_candidate_scored() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    let scored_count = d
        .events
        .iter()
        .filter(|e| e.event == "opportunity_scored")
        .count();
    assert_eq!(scored_count, req.candidates.len());
}

#[test]
fn events_carry_request_ids() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for event in &d.events {
        assert_eq!(event.trace_id, req.trace_id);
        assert_eq!(event.decision_id, req.decision_id);
        assert_eq!(event.policy_id, req.policy_id);
        assert_eq!(event.component, OPPORTUNITY_MATRIX_COMPONENT);
    }
}

#[test]
fn failure_events_contain_error_code() {
    let mut req = base_request();
    req.trace_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    let completion = d
        .events
        .iter()
        .find(|e| e.event == "opportunity_matrix_completed")
        .unwrap();
    assert_eq!(completion.outcome, "fail");
    assert!(completion.error_code.is_some());
}

#[test]
fn failure_decision_has_empty_collections() {
    let mut req = base_request();
    req.decision_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert!(d.ranked_opportunities.is_empty());
    assert!(d.selected_opportunity_ids.is_empty());
    assert!(d.historical_tracking.is_empty());
}

// ── Section 13: Historical tracking ──────────────────────────────────

#[test]
fn historical_tracking_computes_signed_and_absolute_error() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.historical_tracking.len(), 1);
    let h = &d.historical_tracking[0];
    assert_eq!(h.predicted_gain_millionths, 400_000);
    assert_eq!(h.actual_gain_millionths, 350_000);
    assert_eq!(h.signed_error_millionths, -50_000);
    assert_eq!(h.absolute_error_millionths, 50_000);
}

#[test]
fn historical_tracking_sorted_by_timestamp_then_id() {
    let mut req = base_request();
    req.historical_outcomes.push(OpportunityOutcomeObservation {
        opportunity_id: "opp-earlier".into(),
        predicted_gain_millionths: 100_000,
        actual_gain_millionths: 200_000,
        completed_at_utc: "2026-01-01T00:00:00Z".into(),
    });
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.historical_tracking.len(), 2);
    assert!(d.historical_tracking[0].completed_at_utc <= d.historical_tracking[1].completed_at_utc);
}

#[test]
fn historical_tracking_positive_overperformance() {
    let mut req = base_request();
    req.historical_outcomes[0].predicted_gain_millionths = 100_000;
    req.historical_outcomes[0].actual_gain_millionths = 300_000;
    let d = run_opportunity_matrix_scoring(&req);
    let h = &d.historical_tracking[0];
    assert_eq!(h.signed_error_millionths, 200_000);
    assert_eq!(h.absolute_error_millionths, 200_000);
}

// ── Section 14: hotspot_profile_from_flamegraphs ─────────────────────

#[test]
fn hotspot_profile_from_cpu_flamegraph() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![("vm;dispatch", 80), ("vm;gc_tick", 20)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 2);
    assert_eq!(profile[0].function, "dispatch");
    assert_eq!(profile[0].sample_count, 80);
    assert_eq!(profile[1].function, "gc_tick");
}

#[test]
fn hotspot_profile_aggregates_across_multiple_artifacts() {
    let fg1 = make_flamegraph(FlamegraphKind::Cpu, vec![("vm;dispatch", 50)]);
    let fg2 = make_flamegraph(
        FlamegraphKind::Allocation,
        vec![("vm;dispatch", 30), ("gc;collect", 20)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg1, fg2]);
    let dispatch = profile.iter().find(|e| e.function == "dispatch").unwrap();
    assert_eq!(dispatch.sample_count, 80);
    assert_eq!(profile.len(), 2);
}

#[test]
fn hotspot_profile_skips_empty_stacks() {
    let fg = make_flamegraph(FlamegraphKind::Cpu, vec![("  ", 100), ("vm;run", 50)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].function, "run");
}

#[test]
fn hotspot_profile_sorted_by_sample_count_descending() {
    let fg = make_flamegraph(
        FlamegraphKind::DiffCpu,
        vec![("a;low", 10), ("b;high", 90), ("c;mid", 50)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile[0].sample_count, 90);
    assert_eq!(profile[1].sample_count, 50);
    assert_eq!(profile[2].sample_count, 10);
}

#[test]
fn hotspot_profile_empty_artifacts_returns_empty() {
    let profile = hotspot_profile_from_flamegraphs(&[]);
    assert!(profile.is_empty());
}

#[test]
fn hotspot_profile_diff_allocation_kind_included() {
    let fg = make_flamegraph(FlamegraphKind::DiffAllocation, vec![("alloc;malloc", 100)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].function, "malloc");
}

// ── Section 15: benchmark_pressure_from_cases ────────────────────────

#[test]
fn benchmark_pressure_neutral_when_above_target() {
    // 4x speedup > 3x target => neutral
    let fast = make_benchmark_case("w1", 400.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[fast], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn benchmark_pressure_increases_when_below_target() {
    // 1.5x and 4x average = 2.75x < 3x target => pressure > 1.0
    let slow = make_benchmark_case("w1", 150.0, 100.0);
    let fast = make_benchmark_case("w2", 400.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[slow], &[fast]);
    assert!(pressure > 1_000_000);
    assert!(pressure <= 2_000_000);
}

#[test]
fn benchmark_pressure_empty_cases_returns_neutral() {
    assert_eq!(benchmark_pressure_from_cases(&[], &[]), 1_000_000);
}

#[test]
fn benchmark_pressure_zero_baseline_skipped() {
    let bad = make_benchmark_case("w1", 100.0, 0.0);
    assert_eq!(benchmark_pressure_from_cases(&[bad], &[]), 1_000_000);
}

#[test]
fn benchmark_pressure_clamped_at_2x() {
    // 1x speedup => shortfall 2_000_000 => pressure = 1 + 2/3 = 1.667
    let very_slow = make_benchmark_case("w1", 100.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[very_slow], &[]);
    assert!(pressure > 1_000_000);
    assert!(pressure <= 2_000_000);
}

#[test]
fn benchmark_pressure_negative_baseline_skipped() {
    let bad = make_benchmark_case("w1", 100.0, -50.0);
    assert_eq!(benchmark_pressure_from_cases(&[bad], &[]), 1_000_000);
}

// ── Section 16: derive_candidates_from_hotspots ──────────────────────

#[test]
fn derive_candidates_respects_max_candidates() {
    let hotspots: Vec<HotspotProfileEntry> = (0..10)
        .map(|i| HotspotProfileEntry {
            module: format!("mod{i}"),
            function: "f".into(),
            sample_count: 100 - i as u64,
        })
        .collect();
    let derived =
        derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 3);
    assert_eq!(derived.len(), 3);
}

#[test]
fn derive_candidates_sole_hotspot_gets_full_weight() {
    let hotspots = vec![HotspotProfileEntry {
        module: "a".into(),
        function: "f".into(),
        sample_count: 100,
    }];
    let derived =
        derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10);
    assert_eq!(derived.len(), 1);
    assert_eq!(
        derived[0].hotpath_weight_override_millionths,
        Some(1_000_000)
    );
}

#[test]
fn derive_candidates_sanitizes_opportunity_id() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm-core".into(),
        function: "dispatch.loop".into(),
        sample_count: 100,
    }];
    let derived =
        derive_candidates_from_hotspots(&hotspots, 1_300_000, 2, 200_000, 1_000_000, 2_000_000, 5);
    assert_eq!(derived[0].opportunity_id, "opp:vm-core:dispatch_loop");
}

#[test]
fn derive_candidates_empty_hotspots_returns_empty() {
    let derived =
        derive_candidates_from_hotspots(&[], 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10);
    assert!(derived.is_empty());
}

#[test]
fn derive_candidates_propagates_default_parameters() {
    let hotspots = vec![HotspotProfileEntry {
        module: "x".into(),
        function: "y".into(),
        sample_count: 50,
    }];
    let derived =
        derive_candidates_from_hotspots(&hotspots, 1_500_000, 3, 200_000, 800_000, 4_000_000, 10);
    assert_eq!(derived[0].implementation_complexity, 3);
    assert_eq!(derived[0].regression_risk_millionths, 200_000);
    assert_eq!(derived[0].security_clearance_millionths, 800_000);
    assert_eq!(derived[0].engineering_effort_hours_millionths, 4_000_000);
}

// ── Section 17: Serde round-trips ────────────────────────────────────

#[test]
fn scored_opportunity_serde_roundtrip() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for opp in &d.ranked_opportunities {
        let json = serde_json::to_string(opp).unwrap();
        let back: ScoredOpportunity = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, opp);
    }
}

#[test]
fn history_record_serde_roundtrip() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for h in &d.historical_tracking {
        let json = serde_json::to_string(h).unwrap();
        let back: OpportunityHistoryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, h);
    }
}

#[test]
fn decision_serde_roundtrip() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let json = serde_json::to_string(&d).unwrap();
    let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.matrix_id, d.matrix_id);
    assert_eq!(back.ranked_opportunities, d.ranked_opportunities);
    assert_eq!(back.selected_opportunity_ids, d.selected_opportunity_ids);
    assert_eq!(back.historical_tracking, d.historical_tracking);
    assert_eq!(back.events, d.events);
}

#[test]
fn event_serde_roundtrip() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for event in &d.events {
        let json = serde_json::to_string(event).unwrap();
        let back: OpportunityMatrixEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, event);
    }
}

#[test]
fn request_serde_roundtrip() {
    let req = base_request();
    let json = serde_json::to_string(&req).unwrap();
    let back: OpportunityMatrixRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, req.trace_id);
    assert_eq!(back.candidates.len(), req.candidates.len());
    assert_eq!(
        back.historical_outcomes.len(),
        req.historical_outcomes.len()
    );
}

#[test]
fn outcome_observation_serde_roundtrip() {
    let obs = OpportunityOutcomeObservation {
        opportunity_id: "opp-rt".into(),
        predicted_gain_millionths: 123_456,
        actual_gain_millionths: 654_321,
        completed_at_utc: "2026-03-01T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: OpportunityOutcomeObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, obs);
}

// ── Section 18: OpportunityMatrixDecision::has_selected_opportunities ─

#[test]
fn has_selected_opportunities_true_when_some_selected() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert!(d.has_selected_opportunities());
}

#[test]
fn has_selected_opportunities_false_when_all_rejected() {
    let mut req = base_request();
    req.candidates[0].security_clearance_millionths = 0;
    req.candidates[1].security_clearance_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert!(!d.has_selected_opportunities());
}

// ── Section 19: Multi-candidate mixed scoring ────────────────────────

#[test]
fn mixed_selection_some_selected_some_rejected() {
    let mut req = base_request();
    // First candidate: high score (should be selected)
    req.candidates[0].estimated_speedup_millionths = 5_000_000;
    req.candidates[0].hotpath_weight_override_millionths = Some(900_000);
    // Second candidate: security zero (rejected)
    req.candidates[1].security_clearance_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "allow");
    assert_eq!(d.selected_opportunity_ids.len(), 1);
    assert_eq!(d.selected_opportunity_ids[0], "opp-vm-dispatch");
}

// ── Section 20: End-to-end pipeline with derived candidates ──────────

#[test]
fn end_to_end_derive_then_score() {
    let hotspots = vec![
        HotspotProfileEntry {
            module: "parser".into(),
            function: "lex".into(),
            sample_count: 80,
        },
        HotspotProfileEntry {
            module: "gc".into(),
            function: "sweep".into(),
            sample_count: 20,
        },
    ];

    let pressure = 1_300_000;
    let derived =
        derive_candidates_from_hotspots(&hotspots, pressure, 2, 200_000, 1_000_000, 1_000_000, 10);

    let req = OpportunityMatrixRequest {
        trace_id: "trace-e2e".into(),
        decision_id: "decision-e2e".into(),
        policy_id: "policy-e2e".into(),
        optimization_run_id: "run-e2e".into(),
        benchmark_pressure_millionths: pressure,
        hotspots: hotspots.clone(),
        candidates: derived,
        historical_outcomes: Vec::new(),
    };

    let d = run_opportunity_matrix_scoring(&req);
    // Should produce a valid decision
    assert!(d.outcome == "allow" || d.outcome == "deny");
    assert_eq!(d.ranked_opportunities.len(), 2);
    // Ranked by score descending
    assert!(
        d.ranked_opportunities[0].score_millionths >= d.ranked_opportunities[1].score_millionths
    );
}

// ── Enrichment: hotspot_profile_from_flamegraphs deep coverage ───────

#[test]
fn enrichment_hotspot_profile_single_stack_frame_uses_same_module_and_function() {
    let fg = make_flamegraph(FlamegraphKind::Cpu, vec![("runtime", 200)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].module, "runtime");
    assert_eq!(profile[0].function, "runtime");
    assert_eq!(profile[0].sample_count, 200);
}

#[test]
fn enrichment_hotspot_profile_three_level_stack_uses_leaf_function() {
    let fg = make_flamegraph(FlamegraphKind::Cpu, vec![("vm;compiler;optimize", 150)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].module, "vm");
    assert_eq!(profile[0].function, "optimize");
}

#[test]
fn enrichment_hotspot_profile_deeply_nested_stack() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![("a;b;c;d;e;f;leaf_fn", 75)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile[0].module, "a");
    assert_eq!(profile[0].function, "leaf_fn");
    assert_eq!(profile[0].sample_count, 75);
}

#[test]
fn enrichment_hotspot_profile_multiple_modules_sorted_descending() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![
            ("alpha;run", 10),
            ("beta;exec", 50),
            ("gamma;init", 30),
        ],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 3);
    assert_eq!(profile[0].function, "exec");
    assert_eq!(profile[0].sample_count, 50);
    assert_eq!(profile[1].function, "init");
    assert_eq!(profile[1].sample_count, 30);
    assert_eq!(profile[2].function, "run");
    assert_eq!(profile[2].sample_count, 10);
}

#[test]
fn enrichment_hotspot_profile_zero_sample_count_included() {
    let fg = make_flamegraph(FlamegraphKind::Cpu, vec![("vm;dispatch", 0)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].sample_count, 0);
}

#[test]
fn enrichment_hotspot_profile_whitespace_only_stack_skipped() {
    let fg = make_flamegraph(FlamegraphKind::Cpu, vec![("   \t  ", 100), ("vm;run", 50)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].function, "run");
}

#[test]
fn enrichment_hotspot_profile_aggregation_preserves_total_across_three_artifacts() {
    let fg1 = make_flamegraph(FlamegraphKind::Cpu, vec![("vm;dispatch", 100)]);
    let fg2 = make_flamegraph(FlamegraphKind::Allocation, vec![("vm;dispatch", 200)]);
    let fg3 = make_flamegraph(FlamegraphKind::DiffCpu, vec![("vm;dispatch", 300)]);
    let profile = hotspot_profile_from_flamegraphs(&[fg1, fg2, fg3]);
    let dispatch = profile.iter().find(|e| e.function == "dispatch").unwrap();
    assert_eq!(dispatch.sample_count, 600);
}

#[test]
fn enrichment_hotspot_profile_tiebreak_by_module_name() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![("beta;fn1", 50), ("alpha;fn2", 50)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 2);
    // Both have same count, so BTreeMap ordering by module name applies then sort is stable
    // After sort_by sample_count desc, tiebreak is by module asc then function asc
    assert_eq!(profile[0].module, "alpha");
    assert_eq!(profile[1].module, "beta");
}

#[test]
fn enrichment_hotspot_profile_large_sample_counts() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![("vm;dispatch", u64::MAX / 2)],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile[0].sample_count, u64::MAX / 2);
}

// ── Enrichment: benchmark_pressure_from_cases deep coverage ──────────

#[test]
fn enrichment_benchmark_pressure_exactly_at_3x_returns_neutral() {
    let case = make_benchmark_case("w1", 300.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_above_3x_returns_neutral() {
    let case = make_benchmark_case("w1", 500.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_at_1x_computes_shortfall() {
    let case = make_benchmark_case("w1", 100.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    // shortfall = 3_000_000 - 1_000_000 = 2_000_000
    // pressure = 1_000_000 + 2_000_000 * 1_000_000 / 3_000_000 = 1_666_666
    assert!(pressure > 1_600_000);
    assert!(pressure < 1_700_000);
}

#[test]
fn enrichment_benchmark_pressure_at_2x() {
    let case = make_benchmark_case("w1", 200.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    // shortfall = 3_000_000 - 2_000_000 = 1_000_000
    // pressure = 1_000_000 + 1_000_000 * 1_000_000 / 3_000_000 = 1_333_333
    assert!(pressure > 1_300_000);
    assert!(pressure < 1_400_000);
}

#[test]
fn enrichment_benchmark_pressure_both_node_and_bun_combined() {
    let node = make_benchmark_case("w1", 200.0, 100.0);
    let bun = make_benchmark_case("w2", 400.0, 100.0);
    // average speedup = (2.0 + 4.0) / 2 = 3.0 => neutral
    let pressure = benchmark_pressure_from_cases(&[node], &[bun]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_very_fast_returns_neutral() {
    let case = make_benchmark_case("w1", 10000.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_nan_throughput_skipped() {
    let mut case = make_benchmark_case("w1", 100.0, 100.0);
    case.throughput_franken_tps = f64::NAN;
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_infinity_skipped() {
    let case = make_benchmark_case("w1", f64::INFINITY, 100.0);
    let pressure = benchmark_pressure_from_cases(&[case], &[]);
    // infinity / 100.0 = infinity, which is not finite => skipped
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_multiple_slow_cases_stack() {
    let c1 = make_benchmark_case("w1", 100.0, 100.0);
    let c2 = make_benchmark_case("w2", 100.0, 100.0);
    let c3 = make_benchmark_case("w3", 100.0, 100.0);
    let pressure = benchmark_pressure_from_cases(&[c1, c2, c3], &[]);
    // All are 1x, shortfall = 2_000_000, pressure = 1_666_666
    assert!(pressure > 1_600_000);
    assert!(pressure <= 2_000_000);
}

// ── Enrichment: derive_candidates_from_hotspots deep coverage ────────

#[test]
fn enrichment_derive_candidates_weight_proportional_to_samples() {
    let hotspots = vec![
        HotspotProfileEntry { module: "a".into(), function: "f".into(), sample_count: 75 },
        HotspotProfileEntry { module: "b".into(), function: "g".into(), sample_count: 25 },
    ];
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10);
    assert_eq!(derived[0].hotpath_weight_override_millionths, Some(750_000));
    assert_eq!(derived[1].hotpath_weight_override_millionths, Some(250_000));
}

#[test]
fn enrichment_derive_candidates_estimated_speedup_formula() {
    let hotspots = vec![
        HotspotProfileEntry { module: "x".into(), function: "y".into(), sample_count: 100 },
    ];
    let pressure = 1_500_000;
    let derived = derive_candidates_from_hotspots(&hotspots, pressure, 1, 100_000, 1_000_000, 1_000_000, 10);
    // weight = 1_000_000 (sole hotspot), speedup = 1_000_000 + (1_500_000 * 1_000_000) / 1_000_000 = 2_500_000
    assert_eq!(derived[0].estimated_speedup_millionths, 2_500_000);
}

#[test]
fn enrichment_derive_candidates_max_candidates_zero_returns_empty() {
    let hotspots = vec![
        HotspotProfileEntry { module: "a".into(), function: "f".into(), sample_count: 100 },
    ];
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 0);
    assert!(derived.is_empty());
}

#[test]
fn enrichment_derive_candidates_sanitizes_special_chars() {
    let hotspots = vec![
        HotspotProfileEntry { module: "my.module".into(), function: "fn@2!".into(), sample_count: 10 },
    ];
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10);
    assert_eq!(derived[0].opportunity_id, "opp:my_module:fn_2_");
}

#[test]
fn enrichment_derive_candidates_preserves_target_module_and_function() {
    let hotspots = vec![
        HotspotProfileEntry { module: "parser".into(), function: "tokenize".into(), sample_count: 50 },
    ];
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 2, 200_000, 800_000, 3_000_000, 10);
    assert_eq!(derived[0].target_module, "parser");
    assert_eq!(derived[0].target_function, "tokenize");
}

#[test]
fn enrichment_derive_candidates_many_hotspots_capped() {
    let hotspots: Vec<HotspotProfileEntry> = (0..100)
        .map(|i| HotspotProfileEntry {
            module: format!("m{i}"),
            function: format!("f{i}"),
            sample_count: 1000 - i as u64,
        })
        .collect();
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 5);
    assert_eq!(derived.len(), 5);
    // First candidate should have highest weight
    assert!(derived[0].hotpath_weight_override_millionths.unwrap() >= derived[4].hotpath_weight_override_millionths.unwrap());
}

#[test]
fn enrichment_derive_candidates_equal_samples_equal_weight() {
    let hotspots = vec![
        HotspotProfileEntry { module: "a".into(), function: "f".into(), sample_count: 50 },
        HotspotProfileEntry { module: "b".into(), function: "g".into(), sample_count: 50 },
    ];
    let derived = derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10);
    assert_eq!(derived[0].hotpath_weight_override_millionths, derived[1].hotpath_weight_override_millionths);
    assert_eq!(derived[0].hotpath_weight_override_millionths, Some(500_000));
}

// ── Enrichment: scoring formula edge cases ───────────────────────────

#[test]
fn enrichment_score_increases_with_higher_speedup() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-low", "vm", "dispatch")];
    req.candidates[0].estimated_speedup_millionths = 2_000_000;
    let d_low = run_opportunity_matrix_scoring(&req);

    req.candidates[0].estimated_speedup_millionths = 5_000_000;
    let d_high = run_opportunity_matrix_scoring(&req);

    assert!(d_high.ranked_opportunities[0].score_millionths > d_low.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_score_decreases_with_higher_effort() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-a", "vm", "dispatch")];
    req.candidates[0].engineering_effort_hours_millionths = 1_000_000;
    let d_low_effort = run_opportunity_matrix_scoring(&req);

    req.candidates[0].engineering_effort_hours_millionths = 10_000_000;
    let d_high_effort = run_opportunity_matrix_scoring(&req);

    assert!(d_low_effort.ranked_opportunities[0].score_millionths > d_high_effort.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_score_decreases_with_higher_risk() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-a", "vm", "dispatch")];
    req.candidates[0].regression_risk_millionths = 100_000;
    let d_low_risk = run_opportunity_matrix_scoring(&req);

    req.candidates[0].regression_risk_millionths = 900_000;
    let d_high_risk = run_opportunity_matrix_scoring(&req);

    assert!(d_low_risk.ranked_opportunities[0].score_millionths > d_high_risk.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_score_decreases_with_higher_complexity() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-a", "vm", "dispatch")];
    req.candidates[0].implementation_complexity = 1;
    let d_simple = run_opportunity_matrix_scoring(&req);

    req.candidates[0].implementation_complexity = 5;
    let d_complex = run_opportunity_matrix_scoring(&req);

    assert!(d_simple.ranked_opportunities[0].score_millionths > d_complex.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_score_increases_with_higher_benchmark_pressure() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-a", "vm", "dispatch")];
    req.benchmark_pressure_millionths = 1_000_000;
    let d_low_pressure = run_opportunity_matrix_scoring(&req);

    req.benchmark_pressure_millionths = 2_000_000;
    let d_high_pressure = run_opportunity_matrix_scoring(&req);

    assert!(d_high_pressure.ranked_opportunities[0].score_millionths > d_low_pressure.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_score_increases_with_higher_security_clearance() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-a", "vm", "dispatch")];
    req.candidates[0].security_clearance_millionths = 200_000;
    let d_low_sec = run_opportunity_matrix_scoring(&req);

    req.candidates[0].security_clearance_millionths = 1_000_000;
    let d_high_sec = run_opportunity_matrix_scoring(&req);

    assert!(d_high_sec.ranked_opportunities[0].score_millionths > d_low_sec.ranked_opportunities[0].score_millionths);
}

#[test]
fn enrichment_voi_nonnegative_for_valid_inputs() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        assert!(opp.voi_millionths >= 0, "VOI should be non-negative for standard inputs");
    }
}

#[test]
fn enrichment_score_nonnegative_when_all_inputs_positive() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        assert!(opp.score_millionths >= 0);
    }
}

// ── Enrichment: validation error exhaustive ──────────────────────────

#[test]
fn enrichment_validation_whitespace_only_trace_id_rejected() {
    let mut req = base_request();
    req.trace_id = "   \n\t  ".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn enrichment_validation_whitespace_only_optimization_run_id_rejected() {
    let mut req = base_request();
    req.optimization_run_id = "  \t ".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn enrichment_validation_candidate_empty_target_module_still_valid() {
    // Target module/function are not currently validated as non-empty
    let mut req = base_request();
    req.candidates[0].target_module = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    // Should still process (no validation on target_module emptiness)
    assert!(d.outcome == "allow" || d.outcome == "deny");
}

#[test]
fn enrichment_validation_multiple_duplicates_first_detected() {
    let mut req = base_request();
    req.candidates.push(make_candidate("opp-vm-dispatch", "vm", "dispatch"));
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1002"));
}

#[test]
fn enrichment_validation_historical_valid_timestamps_pass() {
    let mut req = base_request();
    req.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp-1".into(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 200_000,
            completed_at_utc: "2026-01-15T08:30:00Z".into(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp-2".into(),
            predicted_gain_millionths: 300_000,
            actual_gain_millionths: 250_000,
            completed_at_utc: "2026-02-20T16:45:00+00:00".into(),
        },
    ];
    let d = run_opportunity_matrix_scoring(&req);
    assert_ne!(d.outcome, "fail");
}

#[test]
fn enrichment_validation_historical_partial_date_rejected() {
    let mut req = base_request();
    req.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp-1".into(),
        predicted_gain_millionths: 100_000,
        actual_gain_millionths: 200_000,
        completed_at_utc: "2026-01-15".into(),
    }];
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1003"));
}

#[test]
fn enrichment_validation_benchmark_pressure_one_is_valid() {
    let mut req = base_request();
    req.benchmark_pressure_millionths = 1;
    let d = run_opportunity_matrix_scoring(&req);
    assert_ne!(d.outcome, "fail");
}

// ── Enrichment: decision metadata ────────────────────────────────────

#[test]
fn enrichment_decision_matrix_id_deterministic() {
    let req = base_request();
    let d1 = run_opportunity_matrix_scoring(&req);
    let d2 = run_opportunity_matrix_scoring(&req);
    assert_eq!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_decision_matrix_id_differs_for_different_candidates() {
    let req1 = base_request();
    let d1 = run_opportunity_matrix_scoring(&req1);

    let mut req2 = base_request();
    req2.candidates[0].estimated_speedup_millionths = 9_000_000;
    let d2 = run_opportunity_matrix_scoring(&req2);
    assert_ne!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_decision_matrix_id_differs_for_different_hotspots() {
    let req1 = base_request();
    let d1 = run_opportunity_matrix_scoring(&req1);

    let mut req2 = base_request();
    req2.hotspots[0].sample_count = 999;
    let d2 = run_opportunity_matrix_scoring(&req2);
    assert_ne!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_decision_matrix_id_differs_for_different_pressure() {
    let req1 = base_request();
    let d1 = run_opportunity_matrix_scoring(&req1);

    let mut req2 = base_request();
    req2.benchmark_pressure_millionths = 1_999_999;
    let d2 = run_opportunity_matrix_scoring(&req2);
    assert_ne!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_decision_error_code_none_on_allow() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.outcome, "allow");
    assert!(d.error_code.is_none());
}

#[test]
fn enrichment_decision_error_code_present_on_fail() {
    let mut req = base_request();
    req.trace_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert!(d.error_code.is_some());
}

// ── Enrichment: events ───────────────────────────────────────────────

#[test]
fn enrichment_events_started_is_first() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.events[0].event, "opportunity_matrix_started");
}

#[test]
fn enrichment_events_completed_is_last() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.events.last().unwrap().event, "opportunity_matrix_completed");
}

#[test]
fn enrichment_events_scored_between_start_and_end() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let first_scored = d.events.iter().position(|e| e.event == "opportunity_scored").unwrap();
    let completed = d.events.iter().position(|e| e.event == "opportunity_matrix_completed").unwrap();
    assert!(first_scored > 0);
    assert!(first_scored < completed);
}

#[test]
fn enrichment_events_scored_carry_opportunity_id() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for event in d.events.iter().filter(|e| e.event == "opportunity_scored") {
        assert!(event.opportunity_id.is_some());
    }
}

#[test]
fn enrichment_events_start_and_complete_have_no_opportunity_id() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let start = d.events.iter().find(|e| e.event == "opportunity_matrix_started").unwrap();
    assert!(start.opportunity_id.is_none());
    let complete = d.events.iter().find(|e| e.event == "opportunity_matrix_completed").unwrap();
    assert!(complete.opportunity_id.is_none());
}

#[test]
fn enrichment_events_successful_completion_outcome_is_allow_or_deny() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let complete = d.events.iter().find(|e| e.event == "opportunity_matrix_completed").unwrap();
    assert!(complete.outcome == "allow" || complete.outcome == "deny");
    assert!(complete.error_code.is_none());
}

#[test]
fn enrichment_events_count_equals_2_plus_candidates() {
    let req = base_request();
    let n_candidates = req.candidates.len();
    let d = run_opportunity_matrix_scoring(&req);
    // start + n_candidates scored + completed = 2 + n_candidates
    assert_eq!(d.events.len(), 2 + n_candidates);
}

#[test]
fn enrichment_events_on_failure_only_start_and_complete() {
    let mut req = base_request();
    req.trace_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.events.len(), 2);
    assert_eq!(d.events[0].event, "opportunity_matrix_started");
    assert_eq!(d.events[1].event, "opportunity_matrix_completed");
}

// ── Enrichment: historical tracking edge cases ───────────────────────

#[test]
fn enrichment_historical_tracking_zero_error_when_predicted_equals_actual() {
    let mut req = base_request();
    req.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp-exact".into(),
        predicted_gain_millionths: 500_000,
        actual_gain_millionths: 500_000,
        completed_at_utc: "2026-03-01T00:00:00Z".into(),
    }];
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.historical_tracking[0].signed_error_millionths, 0);
    assert_eq!(d.historical_tracking[0].absolute_error_millionths, 0);
}

#[test]
fn enrichment_historical_tracking_negative_gains_handled() {
    let mut req = base_request();
    req.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp-neg".into(),
        predicted_gain_millionths: -100_000,
        actual_gain_millionths: -200_000,
        completed_at_utc: "2026-03-01T00:00:00Z".into(),
    }];
    let d = run_opportunity_matrix_scoring(&req);
    let h = &d.historical_tracking[0];
    assert_eq!(h.signed_error_millionths, -100_000);
    assert_eq!(h.absolute_error_millionths, 100_000);
}

#[test]
fn enrichment_historical_tracking_large_overperformance() {
    let mut req = base_request();
    req.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp-wow".into(),
        predicted_gain_millionths: 100_000,
        actual_gain_millionths: 10_000_000,
        completed_at_utc: "2026-03-01T00:00:00Z".into(),
    }];
    let d = run_opportunity_matrix_scoring(&req);
    let h = &d.historical_tracking[0];
    assert_eq!(h.signed_error_millionths, 9_900_000);
    assert_eq!(h.absolute_error_millionths, 9_900_000);
}

#[test]
fn enrichment_historical_tracking_sorted_by_timestamp() {
    let mut req = base_request();
    req.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp-late".into(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 200_000,
            completed_at_utc: "2026-03-10T00:00:00Z".into(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp-early".into(),
            predicted_gain_millionths: 50_000,
            actual_gain_millionths: 60_000,
            completed_at_utc: "2026-01-05T00:00:00Z".into(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp-mid".into(),
            predicted_gain_millionths: 200_000,
            actual_gain_millionths: 180_000,
            completed_at_utc: "2026-02-15T00:00:00Z".into(),
        },
    ];
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.historical_tracking.len(), 3);
    assert_eq!(d.historical_tracking[0].opportunity_id, "opp-early");
    assert_eq!(d.historical_tracking[1].opportunity_id, "opp-mid");
    assert_eq!(d.historical_tracking[2].opportunity_id, "opp-late");
}

#[test]
fn enrichment_historical_tracking_same_timestamp_sorted_by_id() {
    let mut req = base_request();
    req.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp-z".into(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 200_000,
            completed_at_utc: "2026-03-01T00:00:00Z".into(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp-a".into(),
            predicted_gain_millionths: 50_000,
            actual_gain_millionths: 60_000,
            completed_at_utc: "2026-03-01T00:00:00Z".into(),
        },
    ];
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.historical_tracking[0].opportunity_id, "opp-a");
    assert_eq!(d.historical_tracking[1].opportunity_id, "opp-z");
}

#[test]
fn enrichment_historical_tracking_preserves_opportunity_id() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.historical_tracking[0].opportunity_id, "opp-vm-dispatch");
}

// ── Enrichment: multi-candidate scoring scenarios ────────────────────

#[test]
fn enrichment_three_candidates_ranked_correctly() {
    let mut req = base_request();
    req.hotspots = vec![
        HotspotProfileEntry { module: "vm".into(), function: "dispatch".into(), sample_count: 70 },
        HotspotProfileEntry { module: "gc".into(), function: "sweep".into(), sample_count: 20 },
        HotspotProfileEntry { module: "net".into(), function: "poll".into(), sample_count: 10 },
    ];
    req.candidates = vec![
        make_candidate("opp-vm", "vm", "dispatch"),
        make_candidate("opp-gc", "gc", "sweep"),
        make_candidate("opp-net", "net", "poll"),
    ];
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.ranked_opportunities.len(), 3);
    // Higher hotpath weight => higher score (other params equal)
    assert!(d.ranked_opportunities[0].score_millionths >= d.ranked_opportunities[1].score_millionths);
    assert!(d.ranked_opportunities[1].score_millionths >= d.ranked_opportunities[2].score_millionths);
}

#[test]
fn enrichment_candidate_with_no_matching_hotspot_rejected() {
    let mut req = base_request();
    req.hotspots = vec![
        HotspotProfileEntry { module: "vm".into(), function: "dispatch".into(), sample_count: 100 },
    ];
    req.candidates = vec![
        make_candidate("opp-missing", "nonexistent", "module"),
    ];
    req.candidates[0].hotpath_weight_override_millionths = None;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.ranked_opportunities[0].status, OpportunityStatus::RejectedMissingHotspot);
}

#[test]
fn enrichment_all_candidates_security_rejected_means_deny() {
    let mut req = base_request();
    for c in &mut req.candidates {
        c.security_clearance_millionths = 0;
    }
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "deny");
    assert!(!d.has_selected_opportunities());
}

#[test]
fn enrichment_mixed_statuses_in_ranked_output() {
    let mut req = base_request();
    // Candidate 0: security rejected
    req.candidates[0].security_clearance_millionths = 0;
    // Candidate 1: should be selected (high score)
    req.candidates[1].estimated_speedup_millionths = 5_000_000;
    let d = run_opportunity_matrix_scoring(&req);
    let statuses: Vec<OpportunityStatus> = d.ranked_opportunities.iter().map(|o| o.status.clone()).collect();
    assert!(statuses.contains(&OpportunityStatus::RejectedSecurityClearance));
    assert!(statuses.contains(&OpportunityStatus::Selected) || statuses.contains(&OpportunityStatus::RejectedLowScore));
}

#[test]
fn enrichment_selected_ids_only_contain_selected_candidates() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let selected_set: BTreeSet<&str> = d.selected_opportunity_ids.iter().map(|s| s.as_str()).collect();
    for opp in &d.ranked_opportunities {
        if opp.status == OpportunityStatus::Selected {
            assert!(selected_set.contains(opp.opportunity_id.as_str()));
        } else {
            assert!(!selected_set.contains(opp.opportunity_id.as_str()));
        }
    }
}

// ── Enrichment: hotpath weight override interaction ──────────────────

#[test]
fn enrichment_override_weight_negative_clamped_to_zero() {
    let mut req = base_request();
    req.candidates[0].hotpath_weight_override_millionths = Some(-500_000);
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d.ranked_opportunities.iter().find(|o| o.opportunity_id == "opp-vm-dispatch").unwrap();
    assert_eq!(opp.hotpath_weight_millionths, 0);
}

#[test]
fn enrichment_override_weight_exactly_one_million() {
    let mut req = base_request();
    req.candidates[0].hotpath_weight_override_millionths = Some(1_000_000);
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d.ranked_opportunities.iter().find(|o| o.opportunity_id == "opp-vm-dispatch").unwrap();
    assert_eq!(opp.hotpath_weight_millionths, 1_000_000);
}

#[test]
fn enrichment_override_weight_zero_means_missing_hotspot() {
    let mut req = base_request();
    req.candidates[0].hotpath_weight_override_millionths = Some(0);
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d.ranked_opportunities.iter().find(|o| o.opportunity_id == "opp-vm-dispatch").unwrap();
    assert_eq!(opp.status, OpportunityStatus::RejectedMissingHotspot);
}

// ── Enrichment: serde stability and roundtrips ───────────────────────

#[test]
fn enrichment_scored_opportunity_json_deterministic() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let json1 = serde_json::to_string(&d.ranked_opportunities).unwrap();
    let json2 = serde_json::to_string(&d.ranked_opportunities).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_decision_json_contains_schema_version() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains(OPPORTUNITY_MATRIX_SCHEMA_VERSION));
}

#[test]
fn enrichment_decision_json_contains_matrix_id() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains(&d.matrix_id));
}

#[test]
fn enrichment_error_serde_roundtrip_invalid_request() {
    let err = OpportunityMatrixError::InvalidRequest {
        field: "benchmark_pressure_millionths".into(),
        detail: "must be positive".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("benchmark_pressure_millionths"));
    assert!(msg.contains("must be positive"));
    let clone = err.clone();
    assert_eq!(err, clone);
}

#[test]
fn enrichment_error_serde_roundtrip_duplicate_id() {
    let err = OpportunityMatrixError::DuplicateOpportunityId {
        opportunity_id: "opp-dup-test".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("opp-dup-test"));
    let clone = err.clone();
    assert_eq!(err, clone);
}

#[test]
fn enrichment_error_serde_roundtrip_invalid_timestamp() {
    let err = OpportunityMatrixError::InvalidTimestamp {
        value: "20260301".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("20260301"));
    let clone = err.clone();
    assert_eq!(err, clone);
}

#[test]
fn enrichment_hotspot_profile_entry_clone_eq() {
    let entry = HotspotProfileEntry {
        module: "vm".into(),
        function: "dispatch".into(),
        sample_count: 42,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_optimization_candidate_input_clone_eq() {
    let c = make_candidate("opp-clone", "vm", "dispatch");
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn enrichment_opportunity_outcome_observation_clone_eq() {
    let obs = OpportunityOutcomeObservation {
        opportunity_id: "opp-clone-obs".into(),
        predicted_gain_millionths: 500_000,
        actual_gain_millionths: 400_000,
        completed_at_utc: "2026-03-01T00:00:00Z".into(),
    };
    let cloned = obs.clone();
    assert_eq!(obs, cloned);
}

// ── Enrichment: end-to-end pipeline variants ─────────────────────────

#[test]
fn enrichment_e2e_flamegraph_to_scoring_pipeline() {
    let fg = make_flamegraph(
        FlamegraphKind::Cpu,
        vec![
            ("compiler;optimize", 60),
            ("compiler;parse", 30),
            ("io;read", 10),
        ],
    );
    let profile = hotspot_profile_from_flamegraphs(&[fg]);
    assert_eq!(profile.len(), 3);

    let pressure = benchmark_pressure_from_cases(
        &[make_benchmark_case("w1", 200.0, 100.0)],
        &[make_benchmark_case("w2", 250.0, 100.0)],
    );
    assert!(pressure > 1_000_000);

    let candidates = derive_candidates_from_hotspots(&profile, pressure, 2, 200_000, 1_000_000, 2_000_000, 10);
    assert_eq!(candidates.len(), 3);

    let req = OpportunityMatrixRequest {
        trace_id: "trace-e2e-full".into(),
        decision_id: "decision-e2e-full".into(),
        policy_id: "policy-e2e-full".into(),
        optimization_run_id: "run-e2e-full".into(),
        benchmark_pressure_millionths: pressure,
        hotspots: profile,
        candidates,
        historical_outcomes: Vec::new(),
    };

    let d = run_opportunity_matrix_scoring(&req);
    assert!(d.outcome == "allow" || d.outcome == "deny");
    assert_eq!(d.ranked_opportunities.len(), 3);
    assert_eq!(d.schema_version, OPPORTUNITY_MATRIX_SCHEMA_VERSION);
    assert!(d.matrix_id.starts_with("opm-"));
}

#[test]
fn enrichment_e2e_single_candidate_selected() {
    let mut req = base_request();
    req.candidates = vec![make_candidate("opp-solo", "vm", "dispatch")];
    req.candidates[0].estimated_speedup_millionths = 5_000_000;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "allow");
    assert_eq!(d.selected_opportunity_ids.len(), 1);
    assert_eq!(d.selected_opportunity_ids[0], "opp-solo");
}

#[test]
fn enrichment_e2e_ten_candidates_all_scored() {
    let mut req = base_request();
    req.hotspots = (0..10)
        .map(|i| HotspotProfileEntry {
            module: format!("mod{i}"),
            function: format!("fn{i}"),
            sample_count: 100 - i as u64,
        })
        .collect();
    req.candidates = (0..10)
        .map(|i| make_candidate(&format!("opp-{i}"), &format!("mod{i}"), &format!("fn{i}")))
        .collect();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.ranked_opportunities.len(), 10);
    // Verify descending score order
    for w in d.ranked_opportunities.windows(2) {
        assert!(w[0].score_millionths >= w[1].score_millionths);
    }
}

#[test]
fn enrichment_e2e_deny_outcome_with_historical_tracking() {
    let mut req = base_request();
    for c in &mut req.candidates {
        c.estimated_speedup_millionths = 1_050_000;
        c.engineering_effort_hours_millionths = 20_000_000;
        c.regression_risk_millionths = 900_000;
        c.implementation_complexity = 5;
    }
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "deny");
    // Historical tracking is still computed even for deny
    assert_eq!(d.historical_tracking.len(), 1);
}

// ── Enrichment: HotspotProfileEntry key edge cases ───────────────────

#[test]
fn enrichment_hotspot_key_empty_module_and_function() {
    let entry = HotspotProfileEntry {
        module: "".into(),
        function: "".into(),
        sample_count: 0,
    };
    assert_eq!(entry.key(), "::");
}

#[test]
fn enrichment_hotspot_key_special_chars() {
    let entry = HotspotProfileEntry {
        module: "my.mod".into(),
        function: "fn<T>".into(),
        sample_count: 1,
    };
    assert_eq!(entry.key(), "my.mod::fn<T>");
}

// ── Enrichment: OptimizationCandidateInput target_key edge cases ─────

#[test]
fn enrichment_candidate_target_key_empty_module() {
    let c = make_candidate("opp-1", "", "func");
    assert_eq!(c.target_key(), "::func");
}

#[test]
fn enrichment_candidate_target_key_empty_function() {
    let c = make_candidate("opp-2", "mod", "");
    assert_eq!(c.target_key(), "mod::");
}

// ── Enrichment: OpportunityStatus exhaustive ─────────────────────────

#[test]
fn enrichment_opportunity_status_debug_not_empty() {
    for status in [
        OpportunityStatus::Selected,
        OpportunityStatus::RejectedLowScore,
        OpportunityStatus::RejectedSecurityClearance,
        OpportunityStatus::RejectedMissingHotspot,
    ] {
        let debug = format!("{status:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn enrichment_opportunity_status_clone_eq() {
    let s = OpportunityStatus::RejectedSecurityClearance;
    let s2 = s.clone();
    assert_eq!(s, s2);
}

// ── Enrichment: ScoredOpportunity fields ─────────────────────────────

#[test]
fn enrichment_scored_opportunity_carries_benchmark_pressure() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        assert_eq!(opp.benchmark_pressure_millionths, req.benchmark_pressure_millionths);
    }
}

#[test]
fn enrichment_scored_opportunity_target_fields_match_candidate() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        let candidate = req.candidates.iter().find(|c| c.opportunity_id == opp.opportunity_id).unwrap();
        assert_eq!(opp.target_module, candidate.target_module);
        assert_eq!(opp.target_function, candidate.target_function);
    }
}

#[test]
fn enrichment_scored_opportunity_speedup_clamped_at_zero() {
    let mut req = base_request();
    req.candidates[0].estimated_speedup_millionths = -5_000_000;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d.ranked_opportunities.iter().find(|o| o.opportunity_id == "opp-vm-dispatch").unwrap();
    assert_eq!(opp.estimated_speedup_millionths, 0);
}

// ── Enrichment: OpportunityHistoryRecord fields ──────────────────────

#[test]
fn enrichment_history_record_debug_not_empty() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for h in &d.historical_tracking {
        let debug = format!("{h:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn enrichment_history_record_clone_eq() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for h in &d.historical_tracking {
        let cloned = h.clone();
        assert_eq!(h, &cloned);
    }
}

// ── Enrichment: OpportunityMatrixEvent fields ────────────────────────

#[test]
fn enrichment_event_component_always_opportunity_matrix() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for event in &d.events {
        assert_eq!(event.component, "opportunity_matrix");
    }
}

#[test]
fn enrichment_event_debug_not_empty() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for event in &d.events {
        let debug = format!("{event:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn enrichment_event_clone_eq() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for event in &d.events {
        let cloned = event.clone();
        assert_eq!(event, &cloned);
    }
}

// ── Enrichment: Decision serde with all fields ───────────────────────

#[test]
fn enrichment_full_decision_serde_roundtrip_with_history() {
    let mut req = base_request();
    req.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp-h1".into(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 150_000,
            completed_at_utc: "2026-01-01T00:00:00Z".into(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp-h2".into(),
            predicted_gain_millionths: 200_000,
            actual_gain_millionths: 180_000,
            completed_at_utc: "2026-02-01T00:00:00Z".into(),
        },
    ];
    let d = run_opportunity_matrix_scoring(&req);
    let json = serde_json::to_string(&d).unwrap();
    let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.outcome, d.outcome);
    assert_eq!(back.matrix_id, d.matrix_id);
    assert_eq!(back.ranked_opportunities.len(), d.ranked_opportunities.len());
    assert_eq!(back.historical_tracking.len(), d.historical_tracking.len());
    assert_eq!(back.events.len(), d.events.len());
    assert_eq!(back.selected_opportunity_ids, d.selected_opportunity_ids);
}

#[test]
fn enrichment_fail_decision_serde_roundtrip() {
    let mut req = base_request();
    req.trace_id = "".into();
    let d = run_opportunity_matrix_scoring(&req);
    let json = serde_json::to_string(&d).unwrap();
    let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.outcome, "fail");
    assert_eq!(back.error_code, d.error_code);
    assert!(back.ranked_opportunities.is_empty());
    assert!(back.selected_opportunity_ids.is_empty());
    assert!(back.historical_tracking.is_empty());
}
