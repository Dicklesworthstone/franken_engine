//! Enrichment integration tests for the `frankenlab_release_gate` module.
//!
//! Covers: GateKind, GateVerdict, OverallVerdict, GateConfig, GateEvent,
//! GateResult, GateReport, ReleaseGateRunner lifecycle, Display/Debug,
//! serde roundtrips, fail-closed semantics.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::frankenlab_release_gate::{
    GateConfig, GateEvent, GateKind, GateReport, GateResult, GateVerdict, OverallVerdict,
    ReleaseGateRunner,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(42), MockBudget::new(budget_ms))
}

// =========================================================================
// A. GateKind — Display, as_str, serde, ordering
// =========================================================================

#[test]
fn enrichment_gate_kind_as_str_all_distinct() {
    let strings: BTreeSet<&str> = GateKind::all().iter().map(|k| k.as_str()).collect();
    assert_eq!(strings.len(), 4);
}

#[test]
fn enrichment_gate_kind_display_matches_as_str() {
    for kind in GateKind::all() {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_gate_kind_serde_all_variants() {
    for kind in GateKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let restored: GateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_gate_kind_all_contains_four() {
    assert_eq!(GateKind::all().len(), 4);
    assert_eq!(GateKind::all()[0], GateKind::FrankenlabScenarios);
    assert_eq!(GateKind::all()[1], GateKind::ReplayDeterminism);
    assert_eq!(GateKind::all()[2], GateKind::ObligationResolution);
    assert_eq!(GateKind::all()[3], GateKind::EvidenceCompleteness);
}

#[test]
fn enrichment_gate_kind_copy() {
    let k = GateKind::FrankenlabScenarios;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn enrichment_gate_kind_ordering() {
    assert!(GateKind::FrankenlabScenarios < GateKind::ReplayDeterminism);
    assert!(GateKind::ReplayDeterminism < GateKind::ObligationResolution);
    assert!(GateKind::ObligationResolution < GateKind::EvidenceCompleteness);
}

// =========================================================================
// B. GateVerdict — Display, as_str, serde, is_pass
// =========================================================================

#[test]
fn enrichment_gate_verdict_pass_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "PASS");
}

#[test]
fn enrichment_gate_verdict_fail_display_contains_reason() {
    let v = GateVerdict::Fail {
        reason: "scenario X failed".into(),
    };
    let s = v.to_string();
    assert!(s.contains("FAIL"));
    assert!(s.contains("scenario X failed"));
}

#[test]
fn enrichment_gate_verdict_infra_error_display() {
    let v = GateVerdict::InfrastructureError {
        detail: "timeout".into(),
    };
    let s = v.to_string();
    assert!(s.contains("INFRASTRUCTURE_ERROR"));
    assert!(s.contains("timeout"));
}

#[test]
fn enrichment_gate_verdict_timeout_display() {
    let v = GateVerdict::Timeout {
        gate: "replay".into(),
        elapsed_ticks: 600,
    };
    let s = v.to_string();
    assert!(s.contains("TIMEOUT"));
    assert!(s.contains("600"));
}

#[test]
fn enrichment_gate_verdict_as_str_all_distinct() {
    let variants = [
        GateVerdict::Pass,
        GateVerdict::Fail { reason: "x".into() },
        GateVerdict::InfrastructureError { detail: "y".into() },
        GateVerdict::Timeout {
            gate: "z".into(),
            elapsed_ticks: 1,
        },
    ];
    let strings: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strings.len(), 4);
}

#[test]
fn enrichment_gate_verdict_is_pass_only_for_pass() {
    assert!(GateVerdict::Pass.is_pass());
    assert!(!GateVerdict::Fail { reason: "x".into() }.is_pass());
    assert!(!GateVerdict::InfrastructureError { detail: "x".into() }.is_pass());
    assert!(
        !GateVerdict::Timeout {
            gate: "x".into(),
            elapsed_ticks: 1,
        }
        .is_pass()
    );
}

#[test]
fn enrichment_gate_verdict_serde_all_variants() {
    let variants = [
        GateVerdict::Pass,
        GateVerdict::Fail {
            reason: "test".into(),
        },
        GateVerdict::InfrastructureError {
            detail: "broken".into(),
        },
        GateVerdict::Timeout {
            gate: "replay".into(),
            elapsed_ticks: 100,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// C. OverallVerdict — Display, as_str, serde
// =========================================================================

#[test]
fn enrichment_overall_verdict_released_display() {
    assert_eq!(OverallVerdict::Released.to_string(), "RELEASED");
}

#[test]
fn enrichment_overall_verdict_blocked_display() {
    let v = OverallVerdict::Blocked {
        failing_gates: vec![GateKind::FrankenlabScenarios, GateKind::ReplayDeterminism],
    };
    let s = v.to_string();
    assert!(s.contains("BLOCKED"));
    assert!(s.contains("frankenlab_scenarios"));
    assert!(s.contains("replay_determinism"));
}

#[test]
fn enrichment_overall_verdict_is_released() {
    assert!(OverallVerdict::Released.is_released());
    assert!(
        !OverallVerdict::Blocked {
            failing_gates: vec![GateKind::EvidenceCompleteness],
        }
        .is_released()
    );
}

#[test]
fn enrichment_overall_verdict_as_str() {
    assert_eq!(OverallVerdict::Released.as_str(), "released");
    assert_eq!(
        OverallVerdict::Blocked {
            failing_gates: vec![]
        }
        .as_str(),
        "blocked"
    );
}

#[test]
fn enrichment_overall_verdict_serde_roundtrip() {
    for v in [
        OverallVerdict::Released,
        OverallVerdict::Blocked {
            failing_gates: vec![GateKind::FrankenlabScenarios],
        },
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: OverallVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// =========================================================================
// D. GateConfig — defaults and serde
// =========================================================================

#[test]
fn enrichment_gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.seed, 42);
    assert_eq!(cfg.timeout_ticks, 600);
    assert!(cfg.check_replay);
    assert!(cfg.check_obligations);
    assert!(cfg.check_evidence);
    assert_eq!(cfg.replay_iterations, 10);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig {
        seed: 99,
        timeout_ticks: 300,
        check_replay: false,
        check_obligations: true,
        check_evidence: false,
        replay_iterations: 5,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// E. GateEvent — serde
// =========================================================================

#[test]
fn enrichment_gate_event_serde_roundtrip() {
    let event = GateEvent {
        component: "frankenlab_release_gate".into(),
        gate: "frankenlab_scenarios".into(),
        event: "gate_start".into(),
        outcome: "starting".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_gate_event_with_error_code_serde() {
    let event = GateEvent {
        component: "test".into(),
        gate: "replay_determinism".into(),
        event: "gate_fail".into(),
        outcome: "fail".into(),
        error_code: Some("replay_divergence".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// F. GateResult — serde
// =========================================================================

#[test]
fn enrichment_gate_result_serde_pass() {
    let result = GateResult {
        kind: GateKind::FrankenlabScenarios,
        verdict: GateVerdict::Pass,
        checks_performed: 10,
        checks_passed: 10,
        events: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_gate_result_serde_fail() {
    let result = GateResult {
        kind: GateKind::ReplayDeterminism,
        verdict: GateVerdict::Fail {
            reason: "diverged".into(),
        },
        checks_performed: 5,
        checks_passed: 4,
        events: vec![GateEvent {
            component: "test".into(),
            gate: "replay".into(),
            event: "gate_fail".into(),
            outcome: "fail".into(),
            error_code: Some("replay_divergence".into()),
        }],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// G. GateReport — serde
// =========================================================================

#[test]
fn enrichment_gate_report_serde_roundtrip() {
    let report = GateReport {
        seed: 42,
        gates: vec![GateResult {
            kind: GateKind::FrankenlabScenarios,
            verdict: GateVerdict::Pass,
            checks_performed: 10,
            checks_passed: 10,
            events: vec![],
        }],
        overall_verdict: OverallVerdict::Released,
        total_checks: 10,
        total_passed: 10,
        failure_summary: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// H. ReleaseGateRunner — full lifecycle
// =========================================================================

#[test]
fn enrichment_runner_config_accessor() {
    let cfg = GateConfig {
        seed: 99,
        ..GateConfig::default()
    };
    let runner = ReleaseGateRunner::new(cfg.clone());
    assert_eq!(runner.config().seed, 99);
}

#[test]
fn enrichment_runner_run_all_gates_produces_report() {
    let mut cx = mock_cx(10_000);
    let mut runner = ReleaseGateRunner::new(GateConfig::default());
    let report = runner.run(&mut cx);
    // Should have at least frankenlab_scenarios gate
    assert!(!report.gates.is_empty());
    assert_eq!(report.seed, 42);
    assert!(report.total_checks > 0);
}

#[test]
fn enrichment_runner_deterministic_reports() {
    let cfg = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..GateConfig::default()
    };
    let mut cx1 = mock_cx(10_000);
    let mut runner1 = ReleaseGateRunner::new(cfg.clone());
    let report1 = runner1.run(&mut cx1);

    let mut cx2 = mock_cx(10_000);
    let mut runner2 = ReleaseGateRunner::new(cfg);
    let report2 = runner2.run(&mut cx2);

    assert_eq!(report1.overall_verdict, report2.overall_verdict);
    assert_eq!(report1.total_checks, report2.total_checks);
    assert_eq!(report1.total_passed, report2.total_passed);
}

#[test]
fn enrichment_runner_events_populated_after_run() {
    let mut cx = mock_cx(10_000);
    let mut runner = ReleaseGateRunner::new(GateConfig::default());
    runner.run(&mut cx);
    let events = runner.events();
    assert!(!events.is_empty());
    // First event should be a gate_start
    assert_eq!(events[0].event, "gate_start");
    assert_eq!(events[0].component, "frankenlab_release_gate");
}

#[test]
fn enrichment_runner_disabled_gates_not_evaluated() {
    let cfg = GateConfig {
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        ..GateConfig::default()
    };
    let mut cx = mock_cx(10_000);
    let mut runner = ReleaseGateRunner::new(cfg);
    let report = runner.run(&mut cx);
    // Only frankenlab_scenarios gate should be in results
    assert_eq!(report.gates.len(), 1);
    assert_eq!(report.gates[0].kind, GateKind::FrankenlabScenarios);
}

#[test]
fn enrichment_runner_report_failure_summary_empty_on_pass() {
    let mut cx = mock_cx(10_000);
    let mut runner = ReleaseGateRunner::new(GateConfig::default());
    let report = runner.run(&mut cx);
    if report.overall_verdict.is_released() {
        assert!(report.failure_summary.is_empty());
    }
}

// =========================================================================
// I. Debug formatting — all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", GateKind::FrankenlabScenarios).is_empty());
    assert!(!format!("{:?}", GateVerdict::Pass).is_empty());
    assert!(!format!("{:?}", OverallVerdict::Released).is_empty());
    assert!(!format!("{:?}", GateConfig::default()).is_empty());
    let runner = ReleaseGateRunner::new(GateConfig::default());
    assert!(!format!("{:?}", runner).is_empty());
}

// =========================================================================
// J. Clone independence — mutate clone, original unaffected
// =========================================================================

#[test]
fn enrichment_clone_independence_gate_config() {
    let original = GateConfig::default();
    let mut cloned = original.clone();
    cloned.seed = 999;
    assert_eq!(original.seed, 42);
    assert_eq!(cloned.seed, 999);
    assert!(original.check_replay);
    assert_eq!(original.replay_iterations, 10);
}

#[test]
fn enrichment_clone_independence_gate_event() {
    let original = GateEvent {
        component: "frankenlab_release_gate".into(),
        gate: "frankenlab_scenarios".into(),
        event: "gate_start".into(),
        outcome: "starting".into(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.component = "modified".into();
    assert_eq!(original.component, "frankenlab_release_gate");
    assert_eq!(cloned.component, "modified");
    assert!(original.error_code.is_none());
}

#[test]
fn enrichment_clone_independence_gate_result() {
    let original = GateResult {
        kind: GateKind::FrankenlabScenarios,
        verdict: GateVerdict::Pass,
        checks_performed: 10,
        checks_passed: 10,
        events: vec![],
    };
    let mut cloned = original.clone();
    cloned.checks_performed = 99;
    cloned.events.push(GateEvent {
        component: "x".into(),
        gate: "x".into(),
        event: "x".into(),
        outcome: "x".into(),
        error_code: None,
    });
    assert_eq!(original.checks_performed, 10);
    assert!(original.events.is_empty());
}

#[test]
fn enrichment_clone_independence_overall_verdict() {
    let original = OverallVerdict::Blocked {
        failing_gates: vec![GateKind::FrankenlabScenarios],
    };
    let mut cloned = original.clone();
    if let OverallVerdict::Blocked {
        ref mut failing_gates,
    } = cloned
    {
        failing_gates.push(GateKind::ReplayDeterminism);
    }
    match &original {
        OverallVerdict::Blocked { failing_gates } => assert_eq!(failing_gates.len(), 1),
        _ => panic!("expected Blocked"),
    }
}

#[test]
fn enrichment_clone_independence_gate_report() {
    let original = GateReport {
        seed: 42,
        gates: vec![GateResult {
            kind: GateKind::FrankenlabScenarios,
            verdict: GateVerdict::Pass,
            checks_performed: 5,
            checks_passed: 5,
            events: vec![],
        }],
        overall_verdict: OverallVerdict::Released,
        total_checks: 5,
        total_passed: 5,
        failure_summary: vec![],
    };
    let mut cloned = original.clone();
    cloned.seed = 999;
    cloned.failure_summary.push("injected failure".into());
    assert_eq!(original.seed, 42);
    assert!(original.failure_summary.is_empty());
}

// =========================================================================
// K. Hash consistency — GateKind
// =========================================================================

#[test]
fn enrichment_gate_kind_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for kind in GateKind::all() {
        let mut h1 = DefaultHasher::new();
        kind.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "hash inconsistent for {kind}");
    }
}

#[test]
fn enrichment_gate_kind_hash_distinct() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hashes = BTreeSet::new();
    for kind in GateKind::all() {
        let mut h = DefaultHasher::new();
        kind.hash(&mut h);
        hashes.insert(h.finish());
    }
    assert_eq!(hashes.len(), 4, "expected 4 distinct hashes");
}

// =========================================================================
// L. GateVerdict timeout serde roundtrip
// =========================================================================

#[test]
fn enrichment_gate_verdict_timeout_serde() {
    let v = GateVerdict::Timeout {
        gate: "replay_determinism".into(),
        elapsed_ticks: 1200,
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
    assert!(!restored.is_pass());
    assert_eq!(restored.as_str(), "timeout");
}

// =========================================================================
// M. GateResult with timeout verdict
// =========================================================================

#[test]
fn enrichment_gate_result_timeout_verdict_serde() {
    let result = GateResult {
        kind: GateKind::ReplayDeterminism,
        verdict: GateVerdict::Timeout {
            gate: "replay_determinism".into(),
            elapsed_ticks: 600,
        },
        checks_performed: 0,
        checks_passed: 0,
        events: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// N. GateReport with blocked verdict serde roundtrip
// =========================================================================

#[test]
fn enrichment_gate_report_blocked_serde_roundtrip() {
    let report = GateReport {
        seed: 77,
        gates: vec![
            GateResult {
                kind: GateKind::FrankenlabScenarios,
                verdict: GateVerdict::Pass,
                checks_performed: 10,
                checks_passed: 10,
                events: vec![],
            },
            GateResult {
                kind: GateKind::ReplayDeterminism,
                verdict: GateVerdict::Fail {
                    reason: "divergence in iteration 3".into(),
                },
                checks_performed: 5,
                checks_passed: 4,
                events: vec![GateEvent {
                    component: "frankenlab_release_gate".into(),
                    gate: "replay_determinism".into(),
                    event: "gate_fail".into(),
                    outcome: "fail".into(),
                    error_code: Some("replay_divergence".into()),
                }],
            },
        ],
        overall_verdict: OverallVerdict::Blocked {
            failing_gates: vec![GateKind::ReplayDeterminism],
        },
        total_checks: 15,
        total_passed: 14,
        failure_summary: vec!["replay_determinism: FAIL: divergence in iteration 3".into()],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// O. Report invariants — total_checks >= total_passed
// =========================================================================

#[test]
fn enrichment_report_total_invariant() {
    let cfg = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..GateConfig::default()
    };
    let mut runner = ReleaseGateRunner::new(cfg);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);
    assert!(report.total_checks >= report.total_passed);
    for gate in &report.gates {
        assert!(gate.checks_performed >= gate.checks_passed);
    }
}

// =========================================================================
// P. OverallVerdict::Blocked with all 4 gates
// =========================================================================

#[test]
fn enrichment_overall_verdict_blocked_all_four_gates() {
    let v = OverallVerdict::Blocked {
        failing_gates: GateKind::all().to_vec(),
    };
    assert!(!v.is_released());
    let display = v.to_string();
    assert!(display.contains("BLOCKED"));
    for kind in GateKind::all() {
        assert!(display.contains(kind.as_str()), "missing {kind} in display");
    }
    // Serde roundtrip
    let json = serde_json::to_string(&v).unwrap();
    let restored: OverallVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// =========================================================================
// Q. Debug formatting contains variant/type names
// =========================================================================

#[test]
fn enrichment_gate_verdict_debug_contains_variant() {
    let pass_dbg = format!("{:?}", GateVerdict::Pass);
    assert!(pass_dbg.contains("Pass"));

    let fail_dbg = format!(
        "{:?}",
        GateVerdict::Fail {
            reason: "bad".into()
        }
    );
    assert!(fail_dbg.contains("Fail"));
    assert!(fail_dbg.contains("bad"));

    let infra_dbg = format!(
        "{:?}",
        GateVerdict::InfrastructureError {
            detail: "broken".into()
        }
    );
    assert!(infra_dbg.contains("InfrastructureError"));

    let timeout_dbg = format!(
        "{:?}",
        GateVerdict::Timeout {
            gate: "x".into(),
            elapsed_ticks: 42
        }
    );
    assert!(timeout_dbg.contains("Timeout"));
    assert!(timeout_dbg.contains("42"));
}

#[test]
fn enrichment_gate_kind_debug_contains_variant() {
    assert!(format!("{:?}", GateKind::FrankenlabScenarios).contains("FrankenlabScenarios"));
    assert!(format!("{:?}", GateKind::ReplayDeterminism).contains("ReplayDeterminism"));
    assert!(format!("{:?}", GateKind::ObligationResolution).contains("ObligationResolution"));
    assert!(format!("{:?}", GateKind::EvidenceCompleteness).contains("EvidenceCompleteness"));
}

// =========================================================================
// R. Runner events gate field matches GateKind::as_str
// =========================================================================

#[test]
fn enrichment_runner_events_gate_field_matches_kind() {
    let cfg = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..GateConfig::default()
    };
    let mut runner = ReleaseGateRunner::new(cfg);
    let mut cx = mock_cx(500_000);
    runner.run(&mut cx);

    let valid_gates: BTreeSet<&str> = GateKind::all().iter().map(|k| k.as_str()).collect();
    for event in runner.events() {
        assert!(
            valid_gates.contains(event.gate.as_str()),
            "event gate '{}' not in valid gate set",
            event.gate
        );
    }
}

// =========================================================================
// S. GateConfig all-false flags still runs frankenlab gate
// =========================================================================

#[test]
fn enrichment_all_optional_gates_disabled_still_runs_scenarios() {
    let cfg = GateConfig {
        seed: 42,
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        ..GateConfig::default()
    };
    let mut runner = ReleaseGateRunner::new(cfg);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);
    assert_eq!(report.gates.len(), 1);
    assert_eq!(report.gates[0].kind, GateKind::FrankenlabScenarios);
    assert!(report.gates[0].verdict.is_pass());
}

// =========================================================================
// T. GateResult infra_error has zero checks invariant
// =========================================================================

#[test]
fn enrichment_gate_result_infra_error_zero_checks() {
    let result = GateResult {
        kind: GateKind::FrankenlabScenarios,
        verdict: GateVerdict::InfrastructureError {
            detail: "harness not found".into(),
        },
        checks_performed: 0,
        checks_passed: 0,
        events: vec![],
    };
    assert_eq!(result.checks_performed, 0);
    assert_eq!(result.checks_passed, 0);
    assert!(!result.verdict.is_pass());
}

// =========================================================================
// U. GateConfig non-default fully-specified serde roundtrip
// =========================================================================

#[test]
fn enrichment_gate_config_all_nondefault_serde() {
    let cfg = GateConfig {
        seed: 12345,
        timeout_ticks: 1200,
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        replay_iterations: 100,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
    assert_eq!(restored.seed, 12345);
    assert_eq!(restored.timeout_ticks, 1200);
    assert!(!restored.check_replay);
    assert!(!restored.check_obligations);
    assert!(!restored.check_evidence);
    assert_eq!(restored.replay_iterations, 100);
}

// =========================================================================
// V. GateEvent all fields populated serde
// =========================================================================

#[test]
fn enrichment_gate_event_all_fields_serde() {
    let event = GateEvent {
        component: "frankenlab_release_gate".into(),
        gate: "evidence_completeness".into(),
        event: "gate_fail".into(),
        outcome: "fail".into(),
        error_code: Some("evidence_gap".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("evidence_completeness"));
    assert!(json.contains("evidence_gap"));
    let restored: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// W. GateReport mixed pass/fail with events serde
// =========================================================================

#[test]
fn enrichment_gate_report_mixed_with_events_serde() {
    let report = GateReport {
        seed: 55,
        gates: vec![
            GateResult {
                kind: GateKind::FrankenlabScenarios,
                verdict: GateVerdict::Pass,
                checks_performed: 20,
                checks_passed: 20,
                events: vec![
                    GateEvent {
                        component: "frankenlab_release_gate".into(),
                        gate: "frankenlab_scenarios".into(),
                        event: "gate_start".into(),
                        outcome: "starting".into(),
                        error_code: None,
                    },
                    GateEvent {
                        component: "frankenlab_release_gate".into(),
                        gate: "frankenlab_scenarios".into(),
                        event: "gate_pass".into(),
                        outcome: "pass".into(),
                        error_code: None,
                    },
                ],
            },
            GateResult {
                kind: GateKind::EvidenceCompleteness,
                verdict: GateVerdict::Fail {
                    reason: "2 gaps found".into(),
                },
                checks_performed: 8,
                checks_passed: 6,
                events: vec![GateEvent {
                    component: "frankenlab_release_gate".into(),
                    gate: "evidence_completeness".into(),
                    event: "gate_fail".into(),
                    outcome: "fail".into(),
                    error_code: Some("evidence_gap".into()),
                }],
            },
        ],
        overall_verdict: OverallVerdict::Blocked {
            failing_gates: vec![GateKind::EvidenceCompleteness],
        },
        total_checks: 28,
        total_passed: 26,
        failure_summary: vec!["evidence_completeness: FAIL: 2 gaps found".into()],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}
