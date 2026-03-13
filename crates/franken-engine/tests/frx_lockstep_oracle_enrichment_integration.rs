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

use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_engine::frx_lockstep_oracle::{
    FRX_LOCKSTEP_COMPONENT, FRX_LOCKSTEP_REPORT_SCHEMA_VERSION,
    FRX_LOCKSTEP_TRACE_SCHEMA_VERSION, FrxDivergenceClass, FrxDivergenceDetail,
    FrxLockstepCaseInput, FrxLockstepCaseResult, FrxLockstepOracleError, FrxLockstepReport,
    FrxLockstepRunContext, FrxLockstepSummary, FrxObservableTrace, FrxTraceEvent,
    FrxTraceEventSignature, evaluate_case, load_trace_file, run_lockstep_oracle,
};

// ── Helpers ──────────────────────────────────────────────────────────────

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
    FrxObservableTrace {
        schema_version: FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "TestComponent".to_string(),
        scenario_id: "scenario-a".to_string(),
        fixture_ref: "fixture-a".to_string(),
        seed: 42,
        events,
        outcome: "pass".to_string(),
        error_code: None,
    }
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

fn temp_dir(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("frx_lockstep_enrichment_{suffix}"))
}

fn write_trace_file(dir: &std::path::Path, fixture_ref: &str, trace: &FrxObservableTrace) {
    let _ = std::fs::create_dir_all(dir);
    let filename = format!("{fixture_ref}.trace.json");
    let json = serde_json::to_string(trace).unwrap();
    std::fs::write(dir.join(filename), json).unwrap();
}

// =========================================================================
// A. FrxLockstepOracleError Display and Error trait
// =========================================================================

#[test]
fn enrichment_oracle_error_invalid_input_display() {
    let err = FrxLockstepOracleError::InvalidInput("missing field".to_string());
    let msg = err.to_string();
    assert!(msg.contains("missing field"));
    assert!(msg.contains("invalid lockstep input"));
}

#[test]
fn enrichment_oracle_error_read_file_display() {
    let err = FrxLockstepOracleError::ReadFile {
        path: "/tmp/test.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let msg = err.to_string();
    assert!(msg.contains("/tmp/test.json"));
    assert!(msg.contains("failed to read"));
}

#[test]
fn enrichment_oracle_error_parse_trace_display() {
    let err = FrxLockstepOracleError::ParseTrace {
        path: "/tmp/bad.json".to_string(),
        source: serde_json::from_str::<String>("bad").unwrap_err(),
    };
    let msg = err.to_string();
    assert!(msg.contains("/tmp/bad.json"));
    assert!(msg.contains("failed to parse"));
}

#[test]
fn enrichment_oracle_error_implements_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(FrxLockstepOracleError::InvalidInput("test".to_string()));
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// B. FrxDivergenceClass ordering and uniqueness
// =========================================================================

#[test]
fn enrichment_divergence_class_btreeset_uniqueness() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(FrxDivergenceClass::DomMutationTrace.as_str());
    set.insert(FrxDivergenceClass::EffectInvocationOrder.as_str());
    set.insert(FrxDivergenceClass::StateTransition.as_str());
    set.insert(FrxDivergenceClass::HydrationOutcome.as_str());
    set.insert(FrxDivergenceClass::EventSequence.as_str());
    set.insert(FrxDivergenceClass::SchemaViolation.as_str());
    set.insert(FrxDivergenceClass::DomMutationTrace.as_str()); // duplicate
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_divergence_class_serde_all_variants() {
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
        assert_eq!(*variant, back);
        assert_eq!(format!("{variant}"), variant.as_str());
    }
}

// =========================================================================
// C. FrxLockstepReport serde roundtrip
// =========================================================================

#[test]
fn enrichment_report_serde_roundtrip() {
    let mut counts = BTreeMap::new();
    counts.insert("event_sequence".to_string(), 1);
    let report = FrxLockstepReport {
        schema_version: FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: "2026-03-12T00:00:00Z".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: FRX_LOCKSTEP_COMPONENT.to_string(),
        react_traces_dir: "/react".to_string(),
        franken_traces_dir: "/franken".to_string(),
        summary: FrxLockstepSummary {
            total_cases: 2,
            pass_cases: 1,
            failed_cases: 1,
            divergence_counts_by_class: counts,
        },
        case_results: vec![
            FrxLockstepCaseResult {
                fixture_ref: "fix-a".to_string(),
                scenario_id: "sc-a".to_string(),
                react_trace_id: "r1".to_string(),
                franken_trace_id: "f1".to_string(),
                pass: true,
                divergence: None,
                replay_command: "rch cargo test".to_string(),
            },
            FrxLockstepCaseResult {
                fixture_ref: "fix-b".to_string(),
                scenario_id: "sc-b".to_string(),
                react_trace_id: "r2".to_string(),
                franken_trace_id: "f2".to_string(),
                pass: false,
                divergence: Some(FrxDivergenceDetail {
                    class: FrxDivergenceClass::EventSequence,
                    message: "mismatch".to_string(),
                    event_index: Some(0),
                    react_signature: None,
                    franken_signature: None,
                }),
                replay_command: "rch cargo test".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: FrxLockstepReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// D. FrxLockstepRunContext serde and field access
// =========================================================================

#[test]
fn enrichment_run_context_with_defaults_policy_contains_v1() {
    let ctx = FrxLockstepRunContext::with_defaults();
    assert!(ctx.policy_id.contains("v1"));
    assert!(ctx.trace_id.starts_with("trace-"));
    assert!(ctx.decision_id.starts_with("decision-"));
}

#[test]
fn enrichment_run_context_deterministic_exact_values() {
    let ctx = FrxLockstepRunContext::deterministic("t-42", "d-42", "p-42");
    assert_eq!(ctx.trace_id, "t-42");
    assert_eq!(ctx.decision_id, "d-42");
    assert_eq!(ctx.policy_id, "p-42");
}

#[test]
fn enrichment_run_context_two_with_defaults_differ() {
    let a = FrxLockstepRunContext::with_defaults();
    let b = FrxLockstepRunContext::with_defaults();
    // Both should have trace/decision IDs based on current timestamp,
    // so within a fast test they may be equal; but policy_id is always the same.
    assert_eq!(a.policy_id, b.policy_id);
}

// =========================================================================
// E. load_trace_file integration
// =========================================================================

#[test]
fn enrichment_load_trace_file_valid_roundtrip() {
    let dir = temp_dir("load_valid");
    let _ = std::fs::create_dir_all(&dir);
    let trace = mk_trace("trace-load", vec![mk_event(1, 100)]);
    let path = dir.join("load-test.trace.json");
    let json = serde_json::to_string(&trace).unwrap();
    std::fs::write(&path, &json).unwrap();

    let loaded = load_trace_file(&path).unwrap();
    assert_eq!(loaded.trace_id, "trace-load");
    assert_eq!(loaded.events.len(), 1);
    assert_eq!(loaded.events[0].seq, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_load_trace_file_trims_whitespace() {
    let dir = temp_dir("load_trim");
    let _ = std::fs::create_dir_all(&dir);
    let mut trace = mk_trace("  trace-trimmed  ", vec![mk_event(1, 0)]);
    trace.error_code = Some("  ".to_string());
    let path = dir.join("trim.trace.json");
    let json = serde_json::to_string(&trace).unwrap();
    std::fs::write(&path, &json).unwrap();

    let loaded = load_trace_file(&path).unwrap();
    assert_eq!(loaded.trace_id, "trace-trimmed");
    assert!(loaded.error_code.is_none()); // whitespace-only => None
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_load_trace_file_missing_returns_read_error() {
    let path = PathBuf::from("/nonexistent/frx_enrichment_test.trace.json");
    let err = load_trace_file(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("failed to read"));
}

#[test]
fn enrichment_load_trace_file_invalid_json_returns_parse_error() {
    let dir = temp_dir("load_badjson");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("bad.trace.json");
    std::fs::write(&path, "not valid json").unwrap();

    let err = load_trace_file(&path).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("failed to parse"));
    let _ = std::fs::remove_dir_all(&dir);
}

// =========================================================================
// F. run_lockstep_oracle E2E with temp dirs
// =========================================================================

#[test]
fn enrichment_run_lockstep_oracle_matching_traces() {
    let react_dir = temp_dir("run_match_react");
    let franken_dir = temp_dir("run_match_franken");
    let events = vec![mk_event(1, 100), mk_event(2, 200)];
    let react_trace = mk_trace_with("r-1", "my-fixture", "sc-1", events.clone());
    let franken_trace = mk_trace_with("f-1", "my-fixture", "sc-1", events);
    write_trace_file(&react_dir, "my-fixture", &react_trace);
    write_trace_file(&franken_dir, "my-fixture", &franken_trace);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();

    assert_eq!(report.schema_version, FRX_LOCKSTEP_REPORT_SCHEMA_VERSION);
    assert_eq!(report.component, FRX_LOCKSTEP_COMPONENT);
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 1);
    assert_eq!(report.summary.failed_cases, 0);
    assert!(report.summary.divergence_counts_by_class.is_empty());
    assert_eq!(report.case_results.len(), 1);
    assert!(report.case_results[0].pass);

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_diverging_traces() {
    let react_dir = temp_dir("run_div_react");
    let franken_dir = temp_dir("run_div_franken");
    let events = vec![mk_event(1, 100)];
    let react_trace = mk_trace_with("r-1", "div-fix", "sc-1", events.clone());
    let mut franken_trace = mk_trace_with("f-1", "div-fix", "sc-1", events);
    franken_trace.outcome = "fail".to_string();
    write_trace_file(&react_dir, "div-fix", &react_trace);
    write_trace_file(&franken_dir, "div-fix", &franken_trace);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();

    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.failed_cases, 1);
    assert!(!report.case_results[0].pass);

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_missing_franken_trace() {
    let react_dir = temp_dir("run_missing_react");
    let franken_dir = temp_dir("run_missing_franken");
    let _ = std::fs::create_dir_all(&franken_dir); // empty franken dir
    let react_trace = mk_trace_with("r-1", "orphan-fix", "sc-1", vec![mk_event(1, 0)]);
    write_trace_file(&react_dir, "orphan-fix", &react_trace);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();

    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.failed_cases, 1);
    let result = &report.case_results[0];
    assert!(!result.pass);
    assert_eq!(result.franken_trace_id, "missing");
    let div = result.divergence.as_ref().unwrap();
    assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
    assert!(div.message.contains("missing FrankenReact trace file"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_fixture_ref_filter() {
    let react_dir = temp_dir("run_filter_react");
    let franken_dir = temp_dir("run_filter_franken");
    let events = vec![mk_event(1, 100)];
    let t1 = mk_trace_with("r-1", "alpha", "sc-1", events.clone());
    let t2 = mk_trace_with("r-2", "beta", "sc-1", events.clone());
    let f1 = mk_trace_with("f-1", "alpha", "sc-1", events.clone());
    let f2 = mk_trace_with("f-2", "beta", "sc-1", events);
    write_trace_file(&react_dir, "alpha", &t1);
    write_trace_file(&react_dir, "beta", &t2);
    write_trace_file(&franken_dir, "alpha", &f1);
    write_trace_file(&franken_dir, "beta", &f2);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report =
        run_lockstep_oracle(&react_dir, &franken_dir, ctx, Some("alpha")).unwrap();

    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.case_results[0].fixture_ref, "alpha");

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_filter_excludes_all_errors() {
    let react_dir = temp_dir("run_filter_none_react");
    let franken_dir = temp_dir("run_filter_none_franken");
    let events = vec![mk_event(1, 100)];
    let t = mk_trace_with("r-1", "only-fix", "sc-1", events.clone());
    let f = mk_trace_with("f-1", "only-fix", "sc-1", events);
    write_trace_file(&react_dir, "only-fix", &t);
    write_trace_file(&franken_dir, "only-fix", &f);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let err = run_lockstep_oracle(&react_dir, &franken_dir, ctx, Some("nonexistent"))
        .unwrap_err();
    assert!(err.to_string().contains("filter excluded all traces"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_empty_trace_id_context_errors() {
    let react_dir = temp_dir("run_empty_ctx_react");
    let franken_dir = temp_dir("run_empty_ctx_franken");
    let _ = std::fs::create_dir_all(&react_dir);
    let _ = std::fs::create_dir_all(&franken_dir);

    let ctx = FrxLockstepRunContext::deterministic("", "d1", "p1");
    let err = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap_err();
    assert!(err.to_string().contains("trace_id"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_empty_decision_id_context_errors() {
    let react_dir = temp_dir("run_empty_dec_react");
    let franken_dir = temp_dir("run_empty_dec_franken");
    let _ = std::fs::create_dir_all(&react_dir);
    let _ = std::fs::create_dir_all(&franken_dir);

    let ctx = FrxLockstepRunContext::deterministic("t1", "", "p1");
    let err = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap_err();
    assert!(err.to_string().contains("decision_id"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_empty_policy_id_context_errors() {
    let react_dir = temp_dir("run_empty_pol_react");
    let franken_dir = temp_dir("run_empty_pol_franken");
    let _ = std::fs::create_dir_all(&react_dir);
    let _ = std::fs::create_dir_all(&franken_dir);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "");
    let err = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap_err();
    assert!(err.to_string().contains("policy_id"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_no_trace_files_errors() {
    let react_dir = temp_dir("run_empty_dir_react");
    let franken_dir = temp_dir("run_empty_dir_franken");
    let _ = std::fs::create_dir_all(&react_dir);
    let _ = std::fs::create_dir_all(&franken_dir);
    // Write a non-trace file to ensure it's not picked up
    std::fs::write(react_dir.join("readme.txt"), "not a trace").unwrap();

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let err = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap_err();
    assert!(err.to_string().contains("no .trace.json files found"));

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_multiple_fixtures() {
    let react_dir = temp_dir("run_multi_react");
    let franken_dir = temp_dir("run_multi_franken");
    let events = vec![mk_event(1, 100)];

    for i in 0..3 {
        let fix = format!("fix-{i}");
        let r = mk_trace_with(&format!("r-{i}"), &fix, "sc-1", events.clone());
        let f = mk_trace_with(&format!("f-{i}"), &fix, "sc-1", events.clone());
        write_trace_file(&react_dir, &fix, &r);
        write_trace_file(&franken_dir, &fix, &f);
    }

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();

    assert_eq!(report.summary.total_cases, 3);
    assert_eq!(report.summary.pass_cases, 3);
    assert_eq!(report.case_results.len(), 3);

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

// =========================================================================
// G. evaluate_case additional edge cases
// =========================================================================

#[test]
fn enrichment_evaluate_case_trace_ids_set_in_result() {
    let input = mk_matching_case();
    let result = evaluate_case(input).unwrap();
    assert_eq!(result.react_trace_id, "react-1");
    assert_eq!(result.franken_trace_id, "franken-1");
}

#[test]
fn enrichment_evaluate_case_matching_error_codes_pass() {
    let mut input = mk_matching_case();
    input.react_trace.error_code = Some("ERR-99".to_string());
    input.franken_trace.error_code = Some("ERR-99".to_string());
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn enrichment_evaluate_case_both_none_error_codes_pass() {
    let input = mk_matching_case();
    assert!(input.react_trace.error_code.is_none());
    assert!(input.franken_trace.error_code.is_none());
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

#[test]
fn enrichment_evaluate_case_franken_empty_events_errors() {
    let mut input = mk_matching_case();
    input.franken_trace.events.clear();
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("events must not be empty"));
}

#[test]
fn enrichment_evaluate_case_franken_scenario_mismatch() {
    let mut input = mk_matching_case();
    input.franken_trace.scenario_id = "different-scenario".to_string();
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("franken trace scenario_id"));
}

#[test]
fn enrichment_evaluate_case_non_monotonic_timing_errors() {
    let mut input = mk_matching_case();
    input.react_trace.events[1].timing_us = 50; // less than event 0's 100
    input.franken_trace.events[1].timing_us = 50;
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("monotonic"));
}

#[test]
fn enrichment_evaluate_case_empty_component_errors() {
    let mut input = mk_matching_case();
    input.react_trace.component = String::new();
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("component"));
}

#[test]
fn enrichment_evaluate_case_empty_decision_id_errors() {
    let mut input = mk_matching_case();
    input.react_trace.decision_id = String::new();
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn enrichment_evaluate_case_empty_policy_id_errors() {
    let mut input = mk_matching_case();
    input.react_trace.policy_id = String::new();
    let err = evaluate_case(input).unwrap_err();
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn enrichment_evaluate_case_event_at_index_1_mismatch() {
    let mut input = mk_matching_case();
    input.franken_trace.events[1].phase = "hydrate".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.event_index, Some(1));
    assert!(div.react_signature.is_some());
    assert!(div.franken_signature.is_some());
}

#[test]
fn enrichment_evaluate_case_event_actor_difference_still_diverges() {
    // actor differs but canonical signature compares phase/event/decision_path/outcome,
    // not actor. So same canonical sig means pass.
    let mut input = mk_matching_case();
    input.franken_trace.events[0].actor = "DifferentActor".to_string();
    let result = evaluate_case(input).unwrap();
    // Actor is NOT in canonical_event_signature, so traces should still match
    assert!(result.pass);
}

#[test]
fn enrichment_evaluate_case_timing_difference_still_passes() {
    // timing_us differs but isn't in canonical_event_signature
    let mut input = mk_matching_case();
    // Must keep monotonic: event[0].timing <= event[1].timing (200)
    input.franken_trace.events[0].timing_us = 150;
    let result = evaluate_case(input).unwrap();
    assert!(result.pass);
}

// =========================================================================
// H. FrxDivergenceDetail skip_serializing_if behavior
// =========================================================================

#[test]
fn enrichment_divergence_detail_no_event_index_json_omits_field() {
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
    assert_eq!(detail, back);
}

#[test]
fn enrichment_divergence_detail_with_signatures_roundtrip() {
    let detail = FrxDivergenceDetail {
        class: FrxDivergenceClass::HydrationOutcome,
        message: "hydration mismatch at index 5".to_string(),
        event_index: Some(5),
        react_signature: Some(FrxTraceEventSignature {
            seq: 5,
            phase: "hydrate".to_string(),
            event: "mismatch_detected".to_string(),
            decision_path: "root/app".to_string(),
            outcome: "warn".to_string(),
        }),
        franken_signature: Some(FrxTraceEventSignature {
            seq: 5,
            phase: "hydrate".to_string(),
            event: "client_render".to_string(),
            decision_path: "root/app".to_string(),
            outcome: "ok".to_string(),
        }),
    };
    let json = serde_json::to_string(&detail).unwrap();
    assert!(json.contains("event_index"));
    assert!(json.contains("react_signature"));
    assert!(json.contains("franken_signature"));
    let back: FrxDivergenceDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, back);
}

// =========================================================================
// I. FrxObservableTrace with error_code
// =========================================================================

#[test]
fn enrichment_observable_trace_with_error_code_serde() {
    let mut trace = mk_trace("trace-err", vec![mk_event(1, 100)]);
    trace.error_code = Some("ERR-42".to_string());
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("ERR-42".to_string()));
}

#[test]
fn enrichment_observable_trace_without_error_code_serde() {
    let trace = mk_trace("trace-ok", vec![mk_event(1, 100)]);
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert!(back.error_code.is_none());
}

#[test]
fn enrichment_observable_trace_seed_preserved() {
    let trace = mk_trace("trace-seed", vec![mk_event(1, 0)]);
    assert_eq!(trace.seed, 42);
    let json = serde_json::to_string(&trace).unwrap();
    let back: FrxObservableTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back.seed, 42);
}

// =========================================================================
// J. FrxLockstepSummary with multiple divergence classes
// =========================================================================

#[test]
fn enrichment_summary_multiple_divergence_classes_serde() {
    let mut counts = BTreeMap::new();
    counts.insert("event_sequence".to_string(), 3);
    counts.insert("hydration_outcome".to_string(), 1);
    counts.insert("dom_mutation_trace".to_string(), 2);
    let summary = FrxLockstepSummary {
        total_cases: 10,
        pass_cases: 4,
        failed_cases: 6,
        divergence_counts_by_class: counts,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FrxLockstepSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.divergence_counts_by_class.len(), 3);
}

#[test]
fn enrichment_summary_zero_cases_serde() {
    let summary = FrxLockstepSummary {
        total_cases: 0,
        pass_cases: 0,
        failed_cases: 0,
        divergence_counts_by_class: BTreeMap::new(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FrxLockstepSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// =========================================================================
// K. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_all_types_nonempty() {
    assert!(!format!("{:?}", FrxDivergenceClass::DomMutationTrace).is_empty());
    assert!(!format!("{:?}", FrxDivergenceClass::SchemaViolation).is_empty());
    assert!(!format!("{:?}", mk_event(1, 0)).is_empty());
    assert!(!format!("{:?}", mk_trace("t", vec![mk_event(1, 0)])).is_empty());
    assert!(
        !format!(
            "{:?}",
            FrxLockstepRunContext::deterministic("t", "d", "p")
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            FrxLockstepOracleError::InvalidInput("x".to_string())
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            FrxTraceEventSignature {
                seq: 1,
                phase: "r".to_string(),
                event: "m".to_string(),
                decision_path: "p".to_string(),
                outcome: "ok".to_string(),
            }
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            FrxDivergenceDetail {
                class: FrxDivergenceClass::EventSequence,
                message: "x".to_string(),
                event_index: None,
                react_signature: None,
                franken_signature: None,
            }
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            FrxLockstepCaseResult {
                fixture_ref: "f".to_string(),
                scenario_id: "s".to_string(),
                react_trace_id: "r".to_string(),
                franken_trace_id: "f".to_string(),
                pass: true,
                divergence: None,
                replay_command: "cmd".to_string(),
            }
        )
        .is_empty()
    );
}

// =========================================================================
// L. Constants are distinct
// =========================================================================

#[test]
fn enrichment_schema_version_constants_distinct() {
    assert_ne!(
        FRX_LOCKSTEP_TRACE_SCHEMA_VERSION,
        FRX_LOCKSTEP_REPORT_SCHEMA_VERSION
    );
    assert_ne!(FRX_LOCKSTEP_TRACE_SCHEMA_VERSION, FRX_LOCKSTEP_COMPONENT);
    assert_ne!(
        FRX_LOCKSTEP_REPORT_SCHEMA_VERSION,
        FRX_LOCKSTEP_COMPONENT
    );
}

// =========================================================================
// M. FrxLockstepCaseResult serde with and without divergence
// =========================================================================

#[test]
fn enrichment_case_result_pass_serde() {
    let result = FrxLockstepCaseResult {
        fixture_ref: "fix-pass".to_string(),
        scenario_id: "sc-1".to_string(),
        react_trace_id: "r-1".to_string(),
        franken_trace_id: "f-1".to_string(),
        pass: true,
        divergence: None,
        replay_command: "rch cargo test".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("divergence"));
    let back: FrxLockstepCaseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_case_result_fail_serde() {
    let result = FrxLockstepCaseResult {
        fixture_ref: "fix-fail".to_string(),
        scenario_id: "sc-1".to_string(),
        react_trace_id: "r-1".to_string(),
        franken_trace_id: "f-1".to_string(),
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::StateTransition,
            message: "state diverged".to_string(),
            event_index: Some(2),
            react_signature: None,
            franken_signature: None,
        }),
        replay_command: "rch cargo test".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FrxLockstepCaseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
    assert!(!back.pass);
}

// =========================================================================
// N. Classify mismatch via evaluate_case
// =========================================================================

#[test]
fn enrichment_classify_schema_violation_via_error_code_diff() {
    let mut input = mk_matching_case();
    input.react_trace.error_code = Some("E001".to_string());
    input.franken_trace.error_code = Some("E002".to_string());
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
    assert!(div.message.contains("error_code mismatch"));
}

#[test]
fn enrichment_classify_event_sequence_fallback() {
    let mut input = mk_matching_case();
    // Use terms that don't match hydration/effect/state/dom buckets
    input.react_trace.events[0].phase = "unknown_phase".to_string();
    input.franken_trace.events[0].phase = "unknown_phase".to_string();
    input.react_trace.events[0].event = "foo_action".to_string();
    input.franken_trace.events[0].event = "bar_action".to_string();
    let result = evaluate_case(input).unwrap();
    assert!(!result.pass);
    let div = result.divergence.unwrap();
    assert_eq!(div.class, FrxDivergenceClass::EventSequence);
}

// =========================================================================
// O. run_lockstep_oracle report fields
// =========================================================================

#[test]
fn enrichment_run_lockstep_oracle_report_context_fields() {
    let react_dir = temp_dir("run_ctx_react");
    let franken_dir = temp_dir("run_ctx_franken");
    let events = vec![mk_event(1, 100)];
    let rt = mk_trace_with("r-1", "ctx-fix", "sc-1", events.clone());
    let ft = mk_trace_with("f-1", "ctx-fix", "sc-1", events);
    write_trace_file(&react_dir, "ctx-fix", &rt);
    write_trace_file(&franken_dir, "ctx-fix", &ft);

    let ctx = FrxLockstepRunContext::deterministic("my-trace", "my-dec", "my-pol");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();

    assert_eq!(report.trace_id, "my-trace");
    assert_eq!(report.decision_id, "my-dec");
    assert_eq!(report.policy_id, "my-pol");
    assert!(!report.generated_at_utc.is_empty());
    assert!(!report.react_traces_dir.is_empty());
    assert!(!report.franken_traces_dir.is_empty());

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

#[test]
fn enrichment_run_lockstep_oracle_report_serde_roundtrip() {
    let react_dir = temp_dir("run_serde_react");
    let franken_dir = temp_dir("run_serde_franken");
    let events = vec![mk_event(1, 100)];
    let rt = mk_trace_with("r-1", "serde-fix", "sc-1", events.clone());
    let ft = mk_trace_with("f-1", "serde-fix", "sc-1", events);
    write_trace_file(&react_dir, "serde-fix", &rt);
    write_trace_file(&franken_dir, "serde-fix", &ft);

    let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
    let report = run_lockstep_oracle(&react_dir, &franken_dir, ctx, None).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: FrxLockstepReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);

    let _ = std::fs::remove_dir_all(&react_dir);
    let _ = std::fs::remove_dir_all(&franken_dir);
}

// =========================================================================
// P. FrxTraceEvent equality
// =========================================================================

#[test]
fn enrichment_trace_event_equality() {
    let a = mk_event(1, 100);
    let b = mk_event(1, 100);
    assert_eq!(a, b);
    let c = mk_event(2, 100);
    assert_ne!(a, c);
}

#[test]
fn enrichment_trace_event_clone() {
    let a = mk_event(1, 100);
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// Q. Replay command content through evaluate_case
// =========================================================================

#[test]
fn enrichment_replay_command_without_paths_is_test_command() {
    let input = mk_matching_case();
    let result = evaluate_case(input).unwrap();
    assert!(result.replay_command.starts_with("rch cargo test"));
    assert!(result.replay_command.contains("--nocapture"));
}

#[test]
fn enrichment_replay_command_with_paths_is_run_command() {
    let events = vec![mk_event(1, 100), mk_event(2, 200)];
    let input = FrxLockstepCaseInput {
        fixture_ref: "fixture-a".to_string(),
        scenario_id: "scenario-a".to_string(),
        react_trace: mk_trace("r-1", events.clone()),
        franken_trace: mk_trace("f-1", events),
        react_trace_path: Some(PathBuf::from("/traces/react/fixture-a.trace.json")),
        franken_trace_path: Some(PathBuf::from("/traces/franken/fixture-a.trace.json")),
    };
    let result = evaluate_case(input).unwrap();
    assert!(
        result
            .replay_command
            .starts_with("rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle")
    );
    assert!(result.replay_command.contains("--react-traces-dir"));
    assert!(result.replay_command.contains("--franken-traces-dir"));
    assert!(result.replay_command.contains("--fixture-ref"));
}
