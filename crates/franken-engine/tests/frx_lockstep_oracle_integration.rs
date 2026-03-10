//! Integration tests for `frankenengine_engine::frx_lockstep_oracle`.
//!
//! Exercises the FRX lockstep oracle from the public crate boundary:
//! FrxObservableTrace, FrxTraceEvent, FrxDivergenceClass, evaluate_case,
//! FrxLockstepCaseResult, FrxLockstepSummary, FrxLockstepRunContext,
//! and FrxLockstepReport.

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

use std::collections::BTreeMap;

use frankenengine_engine::frx_lockstep_oracle::{
    FRX_LOCKSTEP_COMPONENT, FRX_LOCKSTEP_REPORT_SCHEMA_VERSION, FRX_LOCKSTEP_TRACE_SCHEMA_VERSION,
    FrxDivergenceClass, FrxDivergenceDetail, FrxLockstepCaseInput, FrxLockstepCaseResult,
    FrxLockstepRunContext, FrxLockstepSummary, FrxObservableTrace, FrxTraceEvent,
    FrxTraceEventSignature, evaluate_case,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn mk_event(seq: u64, timing_us: u64) -> FrxTraceEvent {
    FrxTraceEvent {
        seq,
        phase: "render".to_string(),
        actor: "Component".to_string(),
        event: "mount".to_string(),
        decision_path: "root/child".to_string(),
        timing_us,
        outcome: "ok".to_string(),
    }
}

fn mk_trace(trace_id: &str, events: Vec<FrxTraceEvent>) -> FrxObservableTrace {
    mk_trace_with(trace_id, "fixture-a", "scenario-a", events)
}

fn mk_trace_with(
    trace_id: &str,
    fixture_ref: &str,
    scenario_id: &str,
    events: Vec<FrxTraceEvent>,
) -> FrxObservableTrace {
    FrxObservableTrace {
        schema_version: FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "TestComponent".to_string(),
        scenario_id: scenario_id.to_string(),
        fixture_ref: fixture_ref.to_string(),
        seed: 42,
        events,
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn mk_matching_case() -> FrxLockstepCaseInput {
    let events = vec![mk_event(1, 100), mk_event(2, 200)];
    FrxLockstepCaseInput {
        fixture_ref: "fixture-a".to_string(),
        scenario_id: "scenario-a".to_string(),
        react_trace: mk_trace("react-1", events.clone()),
        franken_trace: mk_trace("franken-1", events),
        react_trace_path: None,
        franken_trace_path: None,
    }
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn schema_version_constants_not_empty() {
    assert!(!FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.is_empty());
    assert!(!FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.is_empty());
    assert!(!FRX_LOCKSTEP_COMPONENT.is_empty());
}

// ── FrxDivergenceClass ──────────────────────────────────────────────────

#[test]
fn divergence_class_all_variants() {
    let variants = [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ];
    assert_eq!(variants.len(), 6);
}

#[test]
fn divergence_class_as_str() {
    assert_eq!(
        FrxDivergenceClass::DomMutationTrace.as_str(),
        "dom_mutation_trace"
    );
    assert_eq!(
        FrxDivergenceClass::EffectInvocationOrder.as_str(),
        "effect_invocation_order"
    );
    assert_eq!(
        FrxDivergenceClass::StateTransition.as_str(),
        "state_transition"
    );
    assert_eq!(
        FrxDivergenceClass::HydrationOutcome.as_str(),
        "hydration_outcome"
    );
    assert_eq!(FrxDivergenceClass::EventSequence.as_str(), "event_sequence");
    assert_eq!(
        FrxDivergenceClass::SchemaViolation.as_str(),
        "schema_violation"
    );
}

#[test]
fn divergence_class_display_matches_as_str() {
    let class = FrxDivergenceClass::StateTransition;
    assert_eq!(format!("{}", class), class.as_str());
}

#[test]
fn divergence_class_serde_roundtrip() {
    let class = FrxDivergenceClass::HydrationOutcome;
    let json = serde_json::to_string(&class).unwrap();
    let back: FrxDivergenceClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, class);
}

// ── FrxTraceEvent ───────────────────────────────────────────────────────

#[test]
fn trace_event_serde_roundtrip() {
    let event = mk_event(1, 100);
    let json = serde_json::to_string(&event).unwrap();
    let back: FrxTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ── FrxObservableTrace ──────────────────────────────────────────────────

#[test]
fn observable_trace_serde_roundtrip() {
    let trace = mk_trace("t-1", vec![mk_event(1, 100)]);
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back, trace);
}

// ── FrxLockstepRunContext ───────────────────────────────────────────────

#[test]
fn run_context_with_defaults_has_non_empty_fields() {
    let ctx = FrxLockstepRunContext::with_defaults();
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
}

#[test]
fn run_context_deterministic() {
    let ctx = FrxLockstepRunContext::deterministic("trace-1", "dec-1", "pol-1");
    assert_eq!(ctx.trace_id, "trace-1");
    assert_eq!(ctx.decision_id, "dec-1");
    assert_eq!(ctx.policy_id, "pol-1");
}

// ── FrxTraceEventSignature ──────────────────────────────────────────────

#[test]
fn trace_event_signature_serde_roundtrip() {
    let sig = FrxTraceEventSignature {
        seq: 1,
        phase: "render".to_string(),
        event: "mount".to_string(),
        decision_path: "root/child".to_string(),
        outcome: "ok".to_string(),
    };
    let json = serde_json::to_string(&sig).unwrap();
    let back: FrxTraceEventSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sig);
}

// ── FrxDivergenceDetail ─────────────────────────────────────────────────

#[test]
fn divergence_detail_serde_roundtrip() {
    let detail = FrxDivergenceDetail {
        class: FrxDivergenceClass::DomMutationTrace,
        message: "dom mismatch at index 3".to_string(),
        event_index: Some(3),
        react_signature: Some(FrxTraceEventSignature {
            seq: 3,
            phase: "commit".to_string(),
            event: "dom_patch".to_string(),
            decision_path: "root".to_string(),
            outcome: "ok".to_string(),
        }),
        franken_signature: Some(FrxTraceEventSignature {
            seq: 3,
            phase: "commit".to_string(),
            event: "portal_render".to_string(),
            decision_path: "root".to_string(),
            outcome: "ok".to_string(),
        }),
    };
    let json = serde_json::to_string(&detail).unwrap();
    let back: FrxDivergenceDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(back, detail);
}

// ── FrxLockstepCaseResult ───────────────────────────────────────────────

#[test]
fn case_result_serde_roundtrip() {
    let result = FrxLockstepCaseResult {
        fixture_ref: "fixture-a".to_string(),
        scenario_id: "scenario-a".to_string(),
        react_trace_id: "react-1".to_string(),
        franken_trace_id: "franken-1".to_string(),
        pass: true,
        divergence: None,
        replay_command: "cargo test".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FrxLockstepCaseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ── FrxLockstepSummary ──────────────────────────────────────────────────

#[test]
fn lockstep_summary_serde_roundtrip() {
    let mut counts = BTreeMap::new();
    counts.insert("event_sequence".to_string(), 2);
    let summary = FrxLockstepSummary {
        total_cases: 5,
        pass_cases: 3,
        failed_cases: 2,
        divergence_counts_by_class: counts,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FrxLockstepSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ── evaluate_case ───────────────────────────────────────────────────────

#[test]
fn evaluate_case_matching_traces_pass() {
    let input = mk_matching_case();
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
    assert!(result.divergence.is_none());
    assert_eq!(result.fixture_ref, "fixture-a");
    assert_eq!(result.scenario_id, "scenario-a");
}

#[test]
fn evaluate_case_empty_fixture_ref_error() {
    let mut input = mk_matching_case();
    input.fixture_ref = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("fixture_ref"));
}

#[test]
fn evaluate_case_empty_scenario_id_error() {
    let mut input = mk_matching_case();
    input.scenario_id = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("scenario_id"));
}

#[test]
fn evaluate_case_fixture_ref_mismatch_react() {
    let mut input = mk_matching_case();
    input.react_trace.fixture_ref = "wrong-fixture".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("fixture_ref"));
}

#[test]
fn evaluate_case_fixture_ref_mismatch_franken() {
    let mut input = mk_matching_case();
    input.franken_trace.fixture_ref = "wrong-fixture".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("fixture_ref"));
}

#[test]
fn evaluate_case_scenario_id_mismatch() {
    let mut input = mk_matching_case();
    input.react_trace.scenario_id = "different".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("scenario_id"));
}

#[test]
fn evaluate_case_wrong_schema_version() {
    let mut input = mk_matching_case();
    input.react_trace.schema_version = "wrong-version".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("schema_version"));
}

#[test]
fn evaluate_case_empty_trace_id_error() {
    let mut input = mk_matching_case();
    input.react_trace.trace_id = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("trace_id"));
}

#[test]
fn evaluate_case_empty_events_error() {
    let mut input = mk_matching_case();
    input.react_trace.events.clear();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("events"));
}

#[test]
fn evaluate_case_different_event_counts_diverges() {
    let mut input = mk_matching_case();
    input.franken_trace.events.push(mk_event(3, 300));
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EventSequence);
    assert!(div.message.contains("count mismatch"));
}

#[test]
fn evaluate_case_different_outcomes_diverges() {
    let mut input = mk_matching_case();
    input.franken_trace.events[0].outcome = "fail".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    assert!(result.divergence.is_some());
}

#[test]
fn evaluate_case_outcome_mismatch_diverges() {
    let mut input = mk_matching_case();
    input.franken_trace.outcome = "fail".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EventSequence);
}

#[test]
fn evaluate_case_error_code_mismatch_diverges() {
    let mut input = mk_matching_case();
    input.react_trace.error_code = Some("E001".to_string());
    input.franken_trace.error_code = None;
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
}

#[test]
fn evaluate_case_hydration_keyword_classified() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "hydrate".to_string();
    input.franken_trace.events[0].phase = "hydrate".to_string();
    input.react_trace.events[0].event = "mismatch_detected:text".to_string();
    input.franken_trace.events[0].event = "client_render".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::HydrationOutcome);
}

#[test]
fn evaluate_case_effect_keyword_classified() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "passive_effect".to_string();
    input.franken_trace.events[0].phase = "layout_effect".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EffectInvocationOrder);
}

#[test]
fn evaluate_case_state_keyword_classified() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "dispatch".to_string();
    input.franken_trace.events[0].phase = "dispatch".to_string();
    input.react_trace.events[0].event = "state_update".to_string();
    input.franken_trace.events[0].event = "batch_update".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::StateTransition);
}

#[test]
fn evaluate_case_dom_keyword_classified() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "commit".to_string();
    input.franken_trace.events[0].phase = "commit".to_string();
    input.react_trace.events[0].event = "dom_patch".to_string();
    input.franken_trace.events[0].event = "portal_render".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::DomMutationTrace);
}

#[test]
fn evaluate_case_non_monotonic_seq_error() {
    let mut input = mk_matching_case();
    // Both trace events have seq=1, second should have seq=2, but we set to 1
    input.react_trace.events[1].seq = 1; // not strictly increasing
    input.franken_trace.events[1].seq = 1;
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{}", err).contains("strictly increasing"));
}

#[test]
fn evaluate_case_whitespace_trimmed() {
    let mut input = mk_matching_case();
    input.fixture_ref = "  fixture-a  ".to_string();
    input.scenario_id = "  scenario-a  ".to_string();
    input.react_trace.fixture_ref = "  fixture-a  ".to_string();
    input.franken_trace.fixture_ref = "  fixture-a  ".to_string();
    input.react_trace.scenario_id = "  scenario-a  ".to_string();
    input.franken_trace.scenario_id = "  scenario-a  ".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn evaluate_case_replay_command_present() {
    let input = mk_matching_case();
    let result = evaluate_case(input).unwrap();
    assert!(!result.replay_command.is_empty());
}

// ── Full Lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_matching_traces() {
    let events = vec![mk_event(1, 100), mk_event(2, 200), mk_event(3, 300)];
    let input = FrxLockstepCaseInput {
        fixture_ref: "lifecycle-fixture".to_string(),
        scenario_id: "lifecycle-scenario".to_string(),
        react_trace: mk_trace_with(
            "react-lifecycle",
            "lifecycle-fixture",
            "lifecycle-scenario",
            events.clone(),
        ),
        franken_trace: mk_trace_with(
            "franken-lifecycle",
            "lifecycle-fixture",
            "lifecycle-scenario",
            events,
        ),
        react_trace_path: None,
        franken_trace_path: None,
    };
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
    assert!(result.divergence.is_none());
    assert_eq!(result.react_trace_id, "react-lifecycle");
    assert_eq!(result.franken_trace_id, "franken-lifecycle");
}

#[test]
fn full_lifecycle_diverging_traces() {
    let react_events = vec![mk_event(1, 100), mk_event(2, 200)];
    let mut franken_events = react_events.clone();
    franken_events[1].event = "unmount".to_string(); // different event

    let input = FrxLockstepCaseInput {
        fixture_ref: "div-fixture".to_string(),
        scenario_id: "div-scenario".to_string(),
        react_trace: mk_trace_with("react-div", "div-fixture", "div-scenario", react_events),
        franken_trace: mk_trace_with("franken-div", "div-fixture", "div-scenario", franken_events),
        react_trace_path: None,
        franken_trace_path: None,
    };
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.event_index, Some(1));
    assert!(div.react_signature.is_some());
    assert!(div.franken_signature.is_some());
}
