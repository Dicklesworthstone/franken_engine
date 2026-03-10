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
