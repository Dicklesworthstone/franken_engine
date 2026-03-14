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
    assert!(result.replay_command.starts_with("rch cargo test"));
}

#[test]
fn evaluate_case_replay_command_uses_rch_and_shell_escapes_fixture_ref() {
    let events = vec![mk_event(1, 100), mk_event(2, 200)];
    let fixture_ref = "fixture with spaces";
    let scenario_id = "scenario-a";
    let input = FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace: mk_trace_with("react-1", fixture_ref, scenario_id, events.clone()),
        franken_trace: mk_trace_with("franken-1", fixture_ref, scenario_id, events),
        react_trace_path: Some("/tmp/react traces/case.trace.json".into()),
        franken_trace_path: Some("/tmp/franken traces/case.trace.json".into()),
    };

    let result = evaluate_case(input).unwrap();
    assert!(
        result
            .replay_command
            .starts_with("rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle")
    );
    assert!(
        result
            .replay_command
            .contains("--react-traces-dir '/tmp/react traces'")
    );
    assert!(
        result
            .replay_command
            .contains("--franken-traces-dir '/tmp/franken traces'")
    );
    assert!(
        result
            .replay_command
            .contains("--fixture-ref 'fixture with spaces'")
    );
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

// ── New tests: error Display formatting ─────────────────────────────────

#[test]
fn test_error_invalid_input_display_contains_message() {
    use frankenengine_engine::frx_lockstep_oracle::FrxLockstepOracleError;
    let err = FrxLockstepOracleError::InvalidInput("fixture_ref must not be empty".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("invalid lockstep input"));
    assert!(msg.contains("fixture_ref must not be empty"));
}

#[test]
fn test_error_read_file_display_contains_path() {
    use frankenengine_engine::frx_lockstep_oracle::FrxLockstepOracleError;
    let source = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err = FrxLockstepOracleError::ReadFile {
        path: "/tmp/missing.trace.json".to_string(),
        source,
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/missing.trace.json"));
    assert!(msg.contains("failed to read"));
}

#[test]
fn test_error_parse_trace_display_contains_path() {
    use frankenengine_engine::frx_lockstep_oracle::FrxLockstepOracleError;
    let source = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
    let err = FrxLockstepOracleError::ParseTrace {
        path: "/tmp/bad.trace.json".to_string(),
        source,
    };
    let msg = format!("{err}");
    assert!(msg.contains("failed to parse trace JSON"));
    assert!(msg.contains("/tmp/bad.trace.json"));
}

// ── New tests: Clone/Debug/PartialEq on all public types ────────────────

#[test]
fn test_frx_trace_event_clone_and_debug() {
    let event = mk_event(7, 700);
    let cloned = event.clone();
    assert_eq!(event, cloned);
    let debug_str = format!("{event:?}");
    assert!(debug_str.contains("FrxTraceEvent"));
    assert!(debug_str.contains("700"));
}

#[test]
fn test_frx_observable_trace_clone_and_debug() {
    let trace = mk_trace("t-debug", vec![mk_event(1, 100)]);
    let cloned = trace.clone();
    assert_eq!(trace, cloned);
    let debug_str = format!("{trace:?}");
    assert!(debug_str.contains("FrxObservableTrace"));
}

#[test]
fn test_frx_divergence_class_clone_and_debug() {
    let class = FrxDivergenceClass::EffectInvocationOrder;
    let cloned = class.clone();
    assert_eq!(class, cloned);
    let debug_str = format!("{class:?}");
    assert!(debug_str.contains("EffectInvocationOrder"));
}

#[test]
fn test_frx_trace_event_signature_clone_and_debug() {
    let sig = FrxTraceEventSignature {
        seq: 5,
        phase: "commit".to_string(),
        event: "dom_patch".to_string(),
        decision_path: "root".to_string(),
        outcome: "ok".to_string(),
    };
    let cloned = sig.clone();
    assert_eq!(sig, cloned);
    let debug_str = format!("{sig:?}");
    assert!(debug_str.contains("FrxTraceEventSignature"));
}

#[test]
fn test_frx_divergence_detail_clone_and_debug() {
    let detail = FrxDivergenceDetail {
        class: FrxDivergenceClass::StateTransition,
        message: "state mismatch".to_string(),
        event_index: Some(2),
        react_signature: None,
        franken_signature: None,
    };
    let cloned = detail.clone();
    assert_eq!(detail, cloned);
    let debug_str = format!("{detail:?}");
    assert!(debug_str.contains("FrxDivergenceDetail"));
}

#[test]
fn test_frx_lockstep_case_result_clone_and_debug() {
    let result = FrxLockstepCaseResult {
        fixture_ref: "fix".to_string(),
        scenario_id: "scen".to_string(),
        react_trace_id: "r-1".to_string(),
        franken_trace_id: "f-1".to_string(),
        pass: true,
        divergence: None,
        replay_command: "rch cargo test".to_string(),
    };
    let cloned = result.clone();
    assert_eq!(result, cloned);
    let debug_str = format!("{result:?}");
    assert!(debug_str.contains("FrxLockstepCaseResult"));
}

#[test]
fn test_frx_lockstep_summary_clone_and_debug() {
    let summary = FrxLockstepSummary {
        total_cases: 10,
        pass_cases: 8,
        failed_cases: 2,
        divergence_counts_by_class: BTreeMap::new(),
    };
    let cloned = summary.clone();
    assert_eq!(summary, cloned);
    let debug_str = format!("{summary:?}");
    assert!(debug_str.contains("FrxLockstepSummary"));
}

#[test]
fn test_frx_lockstep_run_context_clone_and_debug() {
    let ctx = FrxLockstepRunContext::deterministic("t-1", "d-1", "p-1");
    let cloned = ctx.clone();
    assert_eq!(ctx, cloned);
    let debug_str = format!("{ctx:?}");
    assert!(debug_str.contains("FrxLockstepRunContext"));
}

// ── New tests: Serialize/Deserialize round-trips ─────────────────────────

#[test]
fn test_frx_lockstep_case_result_serde_with_divergence() {
    let result = FrxLockstepCaseResult {
        fixture_ref: "fix-a".to_string(),
        scenario_id: "scen-a".to_string(),
        react_trace_id: "r-1".to_string(),
        franken_trace_id: "f-1".to_string(),
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::DomMutationTrace,
            message: "dom mismatch".to_string(),
            event_index: Some(0),
            react_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "commit".to_string(),
                event: "dom_patch".to_string(),
                decision_path: "root".to_string(),
                outcome: "ok".to_string(),
            }),
            franken_signature: None,
        }),
        replay_command: "rch cargo test".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FrxLockstepCaseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn test_frx_lockstep_summary_serde_with_multiple_classes() {
    let mut counts = BTreeMap::new();
    counts.insert("dom_mutation_trace".to_string(), 3_u64);
    counts.insert("effect_invocation_order".to_string(), 1_u64);
    counts.insert("state_transition".to_string(), 2_u64);
    let summary = FrxLockstepSummary {
        total_cases: 10,
        pass_cases: 4,
        failed_cases: 6,
        divergence_counts_by_class: counts,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FrxLockstepSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
    // BTreeMap ordering: dom < effect < state
    assert_eq!(back.divergence_counts_by_class["dom_mutation_trace"], 3);
    assert_eq!(back.divergence_counts_by_class["state_transition"], 2);
}

#[test]
fn test_divergence_detail_serde_no_optional_fields_skipped() {
    // When event_index/signatures are None, they should be omitted from JSON
    let detail = FrxDivergenceDetail {
        class: FrxDivergenceClass::EventSequence,
        message: "count mismatch".to_string(),
        event_index: None,
        react_signature: None,
        franken_signature: None,
    };
    let json = serde_json::to_string(&detail).unwrap();
    assert!(!json.contains("event_index"));
    assert!(!json.contains("react_signature"));
    assert!(!json.contains("franken_signature"));
    let back: FrxDivergenceDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(back, detail);
}

#[test]
fn test_observable_trace_error_code_none_serde() {
    // error_code=None: serde default should handle absent field
    let trace = mk_trace("t-no-err", vec![mk_event(1, 100)]);
    assert!(trace.error_code.is_none());
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert!(back.error_code.is_none());
}

#[test]
fn test_observable_trace_error_code_some_serde() {
    let mut trace = mk_trace("t-with-err", vec![mk_event(1, 100)]);
    trace.error_code = Some("E404".to_string());
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("E404".to_string()));
}

// ── New tests: boundary values / edge cases ─────────────────────────────

#[test]
fn test_evaluate_case_single_event_passes() {
    // Minimal valid case: exactly one event per trace
    let _input = mk_matching_case();
    // mk_matching_case already has 2 events; rebuild with 1
    let events = vec![mk_event(1, 0)];
    let input = FrxLockstepCaseInput {
        fixture_ref: "fix-single".to_string(),
        scenario_id: "scen-single".to_string(),
        react_trace: mk_trace_with("r-single", "fix-single", "scen-single", events.clone()),
        franken_trace: mk_trace_with("f-single", "fix-single", "scen-single", events),
        react_trace_path: None,
        franken_trace_path: None,
    };
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn test_evaluate_case_large_seq_values_ok() {
    // u64::MAX - 1 / u64::MAX as timing values should be accepted
    let events = vec![
        FrxTraceEvent {
            seq: 1,
            phase: "render".to_string(),
            actor: "A".to_string(),
            event: "mount".to_string(),
            decision_path: "root".to_string(),
            timing_us: u64::MAX - 1,
            outcome: "ok".to_string(),
        },
        FrxTraceEvent {
            seq: 2,
            phase: "render".to_string(),
            actor: "A".to_string(),
            event: "update".to_string(),
            decision_path: "root".to_string(),
            timing_us: u64::MAX,
            outcome: "ok".to_string(),
        },
    ];
    let input = FrxLockstepCaseInput {
        fixture_ref: "fix-large".to_string(),
        scenario_id: "scen-large".to_string(),
        react_trace: mk_trace_with("r-large", "fix-large", "scen-large", events.clone()),
        franken_trace: mk_trace_with("f-large", "fix-large", "scen-large", events),
        react_trace_path: None,
        franken_trace_path: None,
    };
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn test_evaluate_case_timing_non_monotonic_error() {
    // timing_us going backward should trigger an error
    let events = vec![
        FrxTraceEvent {
            seq: 1,
            phase: "render".to_string(),
            actor: "A".to_string(),
            event: "mount".to_string(),
            decision_path: "root".to_string(),
            timing_us: 500,
            outcome: "ok".to_string(),
        },
        FrxTraceEvent {
            seq: 2,
            phase: "render".to_string(),
            actor: "A".to_string(),
            event: "update".to_string(),
            decision_path: "root".to_string(),
            timing_us: 100, // earlier than 500 — not monotonic
            outcome: "ok".to_string(),
        },
    ];
    let mut input = mk_matching_case();
    input.react_trace.events = events;
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("monotonic"));
}

#[test]
fn test_evaluate_case_empty_event_phase_error() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("phase"));
}

#[test]
fn test_evaluate_case_empty_event_actor_error() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].actor = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("actor"));
}

#[test]
fn test_evaluate_case_empty_event_event_field_error() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].event = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("event"));
}

#[test]
fn test_evaluate_case_empty_event_decision_path_error() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].decision_path = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("decision_path"));
}

#[test]
fn test_evaluate_case_empty_event_outcome_error() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].outcome = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("outcome"));
}

#[test]
fn test_evaluate_case_empty_decision_id_error() {
    let mut input = mk_matching_case();
    input.react_trace.decision_id = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("decision_id"));
}

#[test]
fn test_evaluate_case_empty_policy_id_error() {
    let mut input = mk_matching_case();
    input.react_trace.policy_id = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("policy_id"));
}

#[test]
fn test_evaluate_case_empty_component_error() {
    let mut input = mk_matching_case();
    input.react_trace.component = "".to_string();
    let err = evaluate_case(input).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("component"));
}

// ── New tests: divergence classification ─────────────────────────────────

#[test]
fn test_evaluate_case_cleanup_keyword_classified_effect() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "render".to_string();
    input.franken_trace.events[0].phase = "render".to_string();
    input.react_trace.events[0].event = "cleanup".to_string();
    input.franken_trace.events[0].event = "skip".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EffectInvocationOrder);
}

#[test]
fn test_evaluate_case_hook_keyword_classified_effect() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].event = "hook_call".to_string();
    input.franken_trace.events[0].event = "no_hook".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EffectInvocationOrder);
}

#[test]
fn test_evaluate_case_reducer_keyword_classified_state() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].event = "reducer_update".to_string();
    input.franken_trace.events[0].event = "other_update".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::StateTransition);
}

#[test]
fn test_evaluate_case_context_keyword_classified_state() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].event = "context_update".to_string();
    input.franken_trace.events[0].event = "no_update".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::StateTransition);
}

#[test]
fn test_evaluate_case_render_keyword_classified_dom() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "commit".to_string();
    input.franken_trace.events[0].phase = "commit".to_string();
    input.react_trace.events[0].event = "render_tree".to_string();
    input.franken_trace.events[0].event = "skip_render".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::DomMutationTrace);
}

#[test]
fn test_evaluate_case_server_keyword_classified_hydration() {
    let mut input = mk_matching_case();
    input.react_trace.events[0].decision_path = "server/root".to_string();
    input.franken_trace.events[0].decision_path = "client/root".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::HydrationOutcome);
}

#[test]
fn test_evaluate_case_generic_mismatch_classified_event_sequence() {
    // A mismatch with no matching keywords falls through to EventSequence
    let mut input = mk_matching_case();
    input.react_trace.events[0].phase = "alpha".to_string();
    input.franken_trace.events[0].phase = "beta".to_string();
    input.react_trace.events[0].event = "foo".to_string();
    input.franken_trace.events[0].event = "bar".to_string();
    input.react_trace.events[0].decision_path = "path/a".to_string();
    input.franken_trace.events[0].decision_path = "path/b".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EventSequence);
}

// ── New tests: divergence_counts_by_class ordering ───────────────────────

#[test]
fn test_divergence_counts_are_btreemap_sorted() {
    let mut counts = BTreeMap::new();
    counts.insert("z_last".to_string(), 1_u64);
    counts.insert("a_first".to_string(), 2_u64);
    counts.insert("m_middle".to_string(), 3_u64);
    let mut keys = counts.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    assert_eq!(keys[0], "a_first");
    assert_eq!(keys[1], "m_middle");
    assert_eq!(keys[2], "z_last");
}

// ── New tests: FrxDivergenceClass all serde values ──────────────────────

#[test]
fn test_divergence_class_serde_all_variants() {
    let variants = [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: FrxDivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, variant);
    }
}

#[test]
fn test_divergence_class_display_all_variants() {
    let pairs = [
        (FrxDivergenceClass::DomMutationTrace, "dom_mutation_trace"),
        (
            FrxDivergenceClass::EffectInvocationOrder,
            "effect_invocation_order",
        ),
        (FrxDivergenceClass::StateTransition, "state_transition"),
        (FrxDivergenceClass::HydrationOutcome, "hydration_outcome"),
        (FrxDivergenceClass::EventSequence, "event_sequence"),
        (FrxDivergenceClass::SchemaViolation, "schema_violation"),
    ];
    for (variant, expected) in &pairs {
        assert_eq!(format!("{variant}"), *expected);
    }
}

// ── New tests: FrxLockstepRunContext ─────────────────────────────────────

#[test]
fn test_run_context_with_defaults_unique_per_call() {
    // Two calls should produce different trace_ids (timestamp-based)
    // We can't guarantee this in fast execution, but we CAN verify format
    let ctx = FrxLockstepRunContext::with_defaults();
    assert!(ctx.trace_id.starts_with("trace-frx-lockstep-oracle-"));
    assert!(ctx.decision_id.starts_with("decision-frx-lockstep-oracle-"));
    assert_eq!(ctx.policy_id, "policy-frx-lockstep-oracle-v1");
}

#[test]
fn test_run_context_deterministic_preserves_all_fields() {
    let ctx = FrxLockstepRunContext::deterministic("my-trace", "my-decision", "my-policy");
    assert_eq!(ctx.trace_id, "my-trace");
    assert_eq!(ctx.decision_id, "my-decision");
    assert_eq!(ctx.policy_id, "my-policy");
}

// ── New tests: whitespace trimming / normalization ───────────────────────

#[test]
fn test_evaluate_case_whitespace_in_error_code_trimmed_to_match() {
    // If both sides have whitespace-only around same error code, they match
    let mut input = mk_matching_case();
    input.react_trace.error_code = Some("  E001  ".to_string());
    input.franken_trace.error_code = Some("E001".to_string());
    // After normalization, both should be "E001" => no divergence on error_code
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn test_evaluate_case_whitespace_only_error_code_treated_as_none() {
    // Whitespace-only error_code is treated as None
    let mut input = mk_matching_case();
    input.react_trace.error_code = Some("   ".to_string());
    input.franken_trace.error_code = None;
    // Both normalize to None => should pass (no error_code divergence)
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn test_evaluate_case_whitespace_only_fixture_ref_error() {
    let mut input = mk_matching_case();
    input.fixture_ref = "   ".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{err}").contains("fixture_ref"));
}

#[test]
fn test_evaluate_case_whitespace_only_scenario_id_error() {
    let mut input = mk_matching_case();
    input.scenario_id = "   ".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(format!("{err}").contains("scenario_id"));
}

// ── New tests: replay command format ─────────────────────────────────────

#[test]
fn test_replay_command_no_paths_is_test_form() {
    let input = mk_matching_case(); // react_trace_path / franken_trace_path are None
    let result = evaluate_case(input).unwrap();
    // Without paths, should fall back to the test form
    assert!(result.replay_command.starts_with("rch cargo test"));
    assert!(result.replay_command.contains("frx_lockstep_oracle"));
}

#[test]
fn test_replay_command_contains_scenario_fixture_refs() {
    let events = vec![mk_event(1, 100)];
    let input = FrxLockstepCaseInput {
        fixture_ref: "my-fixture".to_string(),
        scenario_id: "my-scenario".to_string(),
        react_trace: mk_trace_with("r", "my-fixture", "my-scenario", events.clone()),
        franken_trace: mk_trace_with("f", "my-fixture", "my-scenario", events),
        react_trace_path: Some("/data/react/traces".into()),
        franken_trace_path: Some("/data/franken/traces".into()),
    };
    let result = evaluate_case(input).unwrap();
    assert!(result.replay_command.contains("my-fixture"));
    assert!(result.replay_command.contains("/data/react/traces"));
    assert!(result.replay_command.contains("/data/franken/traces"));
}
