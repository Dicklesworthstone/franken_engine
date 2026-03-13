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
        GateVerdict::Fail {
            reason: "x".into(),
        },
        GateVerdict::InfrastructureError {
            detail: "y".into(),
        },
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
    assert!(
        !GateVerdict::InfrastructureError {
            detail: "x".into()
        }
        .is_pass()
    );
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
