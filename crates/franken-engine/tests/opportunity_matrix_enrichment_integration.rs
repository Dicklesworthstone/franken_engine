//! Enrichment integration tests for `opportunity_matrix`.
//!
//! Focuses on: scoring determinism, validation edge cases, historical tracking
//! error math, hotspot profile aggregation, candidate derivation, benchmark
//! pressure boundaries, serde roundtrips for denied decisions, event audit
//! trail, status variant filtering, and Display/Debug coverage.

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

use frankenengine_engine::benchmark_denominator::BenchmarkCase;
use frankenengine_engine::opportunity_matrix::{
    HotspotProfileEntry, OPPORTUNITY_MATRIX_COMPONENT, OPPORTUNITY_MATRIX_SCHEMA_VERSION,
    OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS, OpportunityMatrixDecision, OpportunityMatrixError,
    OpportunityMatrixRequest, OpportunityOutcomeObservation, OpportunityStatus,
    OptimizationCandidateInput, benchmark_pressure_from_cases, derive_candidates_from_hotspots,
    run_opportunity_matrix_scoring,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn candidate(id: &str, module: &str, function: &str) -> OptimizationCandidateInput {
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
        trace_id: "trace-enrich".to_string(),
        decision_id: "decision-enrich".to_string(),
        policy_id: "policy-enrich".to_string(),
        optimization_run_id: "run-enrich".to_string(),
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
            candidate("opp-vm-dispatch", "vm", "dispatch"),
            candidate("opp-vm-gc", "vm", "gc_tick"),
        ],
        historical_outcomes: vec![OpportunityOutcomeObservation {
            opportunity_id: "opp-vm-dispatch".to_string(),
            predicted_gain_millionths: 400_000,
            actual_gain_millionths: 350_000,
            completed_at_utc: "2026-02-22T12:30:00Z".to_string(),
        }],
    }
}

fn make_benchmark_case(franken: f64, baseline: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: "w".to_string(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn enrichment_scoring_deterministic() {
    let req = base_request();
    let d1 = run_opportunity_matrix_scoring(&req);
    let d2 = run_opportunity_matrix_scoring(&req);
    assert_eq!(d1.ranked_opportunities, d2.ranked_opportunities);
    assert_eq!(d1.selected_opportunity_ids, d2.selected_opportunity_ids);
    assert_eq!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_ranked_opportunities_sorted_by_score_desc() {
    let d = run_opportunity_matrix_scoring(&base_request());
    for window in d.ranked_opportunities.windows(2) {
        assert!(window[0].score_millionths >= window[1].score_millionths);
    }
}

#[test]
fn enrichment_selected_ids_match_status_selected() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let selected_from_ranked: BTreeSet<String> = d
        .ranked_opportunities
        .iter()
        .filter(|o| matches!(o.status, OpportunityStatus::Selected))
        .map(|o| o.opportunity_id.clone())
        .collect();
    let selected_ids: BTreeSet<String> = d.selected_opportunity_ids.iter().cloned().collect();
    assert_eq!(selected_from_ranked, selected_ids);
}

#[test]
fn enrichment_security_clearance_zero_rejected() {
    let mut req = base_request();
    req.candidates[0].security_clearance_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    let opp = d
        .ranked_opportunities
        .iter()
        .find(|o| o.opportunity_id == "opp-vm-dispatch")
        .unwrap();
    assert_eq!(opp.status, OpportunityStatus::RejectedSecurityClearance);
    assert!(!opp.threshold_met);
}

#[test]
fn enrichment_negative_security_clearance_rejected() {
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
fn enrichment_missing_hotspot_rejected() {
    let mut req = base_request();
    req.hotspots.clear();
    req.candidates[0].hotpath_weight_override_millionths = None;
    req.candidates[1].hotpath_weight_override_millionths = None;
    let d = run_opportunity_matrix_scoring(&req);
    for opp in &d.ranked_opportunities {
        assert_eq!(opp.status, OpportunityStatus::RejectedMissingHotspot);
    }
}

#[test]
fn enrichment_negative_speedup_clamped_to_zero() {
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
fn enrichment_zero_complexity_floored() {
    let mut req = base_request();
    req.candidates[0].implementation_complexity = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "allow");
}

#[test]
fn enrichment_zero_effort_floored() {
    let mut req = base_request();
    req.candidates[0].engineering_effort_hours_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "allow");
}

#[test]
fn enrichment_validation_empty_trace_id() {
    let mut req = base_request();
    req.trace_id = "  ".to_string();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
}

#[test]
fn enrichment_validation_empty_candidates() {
    let mut req = base_request();
    req.candidates.clear();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
}

#[test]
fn enrichment_validation_zero_benchmark_pressure() {
    let mut req = base_request();
    req.benchmark_pressure_millionths = 0;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
}

#[test]
fn enrichment_validation_negative_benchmark_pressure() {
    let mut req = base_request();
    req.benchmark_pressure_millionths = -1;
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
}

#[test]
fn enrichment_validation_duplicate_opportunity_id() {
    let mut req = base_request();
    req.candidates[1].opportunity_id = req.candidates[0].opportunity_id.clone();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1002"));
}

#[test]
fn enrichment_validation_invalid_historical_timestamp() {
    let mut req = base_request();
    req.historical_outcomes[0].completed_at_utc = "invalid".to_string();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1003"));
}

#[test]
fn enrichment_historical_tracking_error_math() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.historical_tracking.len(), 1);
    let h = &d.historical_tracking[0];
    assert_eq!(
        h.signed_error_millionths,
        h.actual_gain_millionths - h.predicted_gain_millionths
    );
    assert_eq!(h.absolute_error_millionths, h.signed_error_millionths.abs());
}

#[test]
fn enrichment_historical_tracking_sorted_by_timestamp() {
    let mut req = base_request();
    req.historical_outcomes.push(OpportunityOutcomeObservation {
        opportunity_id: "h2".to_string(),
        predicted_gain_millionths: 100_000,
        actual_gain_millionths: 200_000,
        completed_at_utc: "2026-01-01T00:00:00Z".to_string(),
    });
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.historical_tracking.len(), 2);
    assert!(d.historical_tracking[0].completed_at_utc <= d.historical_tracking[1].completed_at_utc);
}

#[test]
fn enrichment_events_contain_start_scored_and_completed() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let event_names: Vec<&str> = d.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"opportunity_matrix_started"));
    assert!(event_names.contains(&"opportunity_matrix_completed"));
    let scored_count = event_names
        .iter()
        .filter(|&&n| n == "opportunity_scored")
        .count();
    assert_eq!(scored_count, 2);
}

#[test]
fn enrichment_events_carry_correct_ids() {
    let req = base_request();
    let d = run_opportunity_matrix_scoring(&req);
    for event in &d.events {
        assert_eq!(event.trace_id, req.trace_id);
        assert_eq!(event.decision_id, req.decision_id);
        assert_eq!(event.component, OPPORTUNITY_MATRIX_COMPONENT);
    }
}

#[test]
fn enrichment_failure_decision_has_empty_collections() {
    let mut req = base_request();
    req.trace_id = String::new();
    let d = run_opportunity_matrix_scoring(&req);
    assert_eq!(d.outcome, "fail");
    assert!(d.ranked_opportunities.is_empty());
    assert!(d.selected_opportunity_ids.is_empty());
    assert!(d.historical_tracking.is_empty());
}

#[test]
fn enrichment_benchmark_pressure_neutral_above_target() {
    let fast = make_benchmark_case(400.0, 100.0); // 4x speedup > 3x target
    let pressure = benchmark_pressure_from_cases(&[fast], &[]);
    assert_eq!(pressure, 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_elevated_below_target() {
    let slow = make_benchmark_case(150.0, 100.0); // 1.5x < 3x target
    let pressure = benchmark_pressure_from_cases(&[slow], &[]);
    assert!(pressure > 1_000_000);
    assert!(pressure <= 2_000_000);
}

#[test]
fn enrichment_benchmark_pressure_empty_cases_neutral() {
    assert_eq!(benchmark_pressure_from_cases(&[], &[]), 1_000_000);
}

#[test]
fn enrichment_benchmark_pressure_zero_baseline_skipped() {
    let bad = make_benchmark_case(100.0, 0.0);
    assert_eq!(benchmark_pressure_from_cases(&[bad], &[]), 1_000_000);
}

#[test]
fn enrichment_derive_candidates_max_limit() {
    let hotspots: Vec<HotspotProfileEntry> = (0..10)
        .map(|i| HotspotProfileEntry {
            module: format!("mod{i}"),
            function: "f".to_string(),
            sample_count: 100 - i as u64,
        })
        .collect();
    let derived =
        derive_candidates_from_hotspots(&hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 3);
    assert_eq!(derived.len(), 3);
}

#[test]
fn enrichment_derive_candidates_sole_hotspot_gets_full_weight() {
    let hotspots = vec![HotspotProfileEntry {
        module: "a".to_string(),
        function: "f".to_string(),
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
fn enrichment_hotspot_entry_key_format() {
    let e = HotspotProfileEntry {
        module: "engine".to_string(),
        function: "eval_loop".to_string(),
        sample_count: 42,
    };
    assert_eq!(e.key(), "engine::eval_loop");
}

#[test]
fn enrichment_candidate_target_key_format() {
    let c = candidate("opp-1", "runtime", "dispatch");
    assert_eq!(c.target_key(), "runtime::dispatch");
}

#[test]
fn enrichment_opportunity_status_serde_all_variants() {
    for status in [
        OpportunityStatus::Selected,
        OpportunityStatus::RejectedLowScore,
        OpportunityStatus::RejectedSecurityClearance,
        OpportunityStatus::RejectedMissingHotspot,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: OpportunityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn enrichment_opportunity_status_snake_case() {
    assert_eq!(
        serde_json::to_string(&OpportunityStatus::Selected).unwrap(),
        "\"selected\""
    );
    assert_eq!(
        serde_json::to_string(&OpportunityStatus::RejectedLowScore).unwrap(),
        "\"rejected_low_score\""
    );
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors: [OpportunityMatrixError; 3] = [
        OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        },
        OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "x".into(),
        },
        OpportunityMatrixError::InvalidTimestamp {
            value: "bad".into(),
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_error_stable_codes_unique() {
    let codes = [
        OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        }
        .stable_code(),
        OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "x".into(),
        }
        .stable_code(),
        OpportunityMatrixError::InvalidTimestamp { value: "v".into() }.stable_code(),
    ];
    let set: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_serde_roundtrip_full_decision() {
    let d = run_opportunity_matrix_scoring(&base_request());
    let json = serde_json::to_string(&d).unwrap();
    let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_decision_schema_version_and_threshold_stable() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.schema_version, OPPORTUNITY_MATRIX_SCHEMA_VERSION);
    assert_eq!(
        d.score_threshold_millionths,
        OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS
    );
}

#[test]
fn enrichment_matrix_id_deterministic() {
    let req = base_request();
    let d1 = run_opportunity_matrix_scoring(&req);
    let d2 = run_opportunity_matrix_scoring(&req);
    assert_eq!(d1.matrix_id, d2.matrix_id);
    assert!(d1.matrix_id.starts_with("opm-"));
}

#[test]
fn enrichment_matrix_id_changes_with_input() {
    let req1 = base_request();
    let mut req2 = base_request();
    req2.trace_id = "different-trace".to_string();
    let d1 = run_opportunity_matrix_scoring(&req1);
    let d2 = run_opportunity_matrix_scoring(&req2);
    assert_ne!(d1.matrix_id, d2.matrix_id);
}

#[test]
fn enrichment_has_selected_opportunities_true_on_allow() {
    let d = run_opportunity_matrix_scoring(&base_request());
    assert_eq!(d.outcome, "allow");
    assert!(d.has_selected_opportunities());
}

#[test]
fn enrichment_has_selected_opportunities_false_when_all_rejected() {
    let mut req = base_request();
    for c in &mut req.candidates {
        c.security_clearance_millionths = 0;
    }
    let d = run_opportunity_matrix_scoring(&req);
    assert!(!d.has_selected_opportunities());
}
