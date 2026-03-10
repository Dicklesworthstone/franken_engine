//! Integration tests for the frankenlab_release_gate module.
//!
//! Covers GateKind, GateVerdict, GateResult, GateEvent, GateReport,
//! OverallVerdict, GateConfig, and ReleaseGateRunner lifecycle including
//! full gate runs, selective gates, determinism, idempotency, events,
//! and structured report serde.

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

// ===========================================================================
// GateKind
// ===========================================================================

#[test]
fn gate_kind_display_all_variants() {
    let expected = [
        (GateKind::FrankenlabScenarios, "frankenlab_scenarios"),
        (GateKind::ReplayDeterminism, "replay_determinism"),
        (GateKind::ObligationResolution, "obligation_resolution"),
        (GateKind::EvidenceCompleteness, "evidence_completeness"),
    ];
    for (kind, s) in expected {
        assert_eq!(kind.as_str(), s);
        assert_eq!(kind.to_string(), s);
    }
}

#[test]
fn gate_kind_all_returns_four() {
    assert_eq!(GateKind::all().len(), 4);
}

#[test]
fn gate_kind_all_unique() {
    let all = GateKind::all();
    let unique: std::collections::BTreeSet<&GateKind> = all.iter().collect();
    assert_eq!(unique.len(), all.len());
}

#[test]
fn gate_kind_serde_round_trip() {
    for kind in GateKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let restored: GateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn gate_kind_ordering() {
    assert!(GateKind::FrankenlabScenarios < GateKind::ReplayDeterminism);
    assert!(GateKind::ReplayDeterminism < GateKind::ObligationResolution);
    assert!(GateKind::ObligationResolution < GateKind::EvidenceCompleteness);
}

// ===========================================================================
// GateVerdict
// ===========================================================================

#[test]
fn gate_verdict_pass_is_pass() {
    assert!(GateVerdict::Pass.is_pass());
}

#[test]
fn gate_verdict_fail_is_not_pass() {
    assert!(!GateVerdict::Fail { reason: "x".into() }.is_pass());
}

#[test]
fn gate_verdict_infra_error_is_not_pass() {
    assert!(!GateVerdict::InfrastructureError { detail: "x".into() }.is_pass());
}

#[test]
fn gate_verdict_timeout_is_not_pass() {
    assert!(
        !GateVerdict::Timeout {
            gate: "x".into(),
            elapsed_ticks: 1,
        }
        .is_pass()
    );
}

#[test]
fn gate_verdict_as_str() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::Fail { reason: "x".into() }.as_str(), "fail");
    assert_eq!(
        GateVerdict::InfrastructureError { detail: "x".into() }.as_str(),
        "infrastructure_error"
    );
    assert_eq!(
        GateVerdict::Timeout {
            gate: "x".into(),
            elapsed_ticks: 1,
        }
        .as_str(),
        "timeout"
    );
}

#[test]
fn gate_verdict_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "PASS");
    let fail = GateVerdict::Fail {
        reason: "bad".into(),
    };
    assert!(fail.to_string().contains("FAIL"));
    assert!(fail.to_string().contains("bad"));

    let infra = GateVerdict::InfrastructureError {
        detail: "broken".into(),
    };
    assert!(infra.to_string().contains("INFRASTRUCTURE_ERROR"));
    assert!(infra.to_string().contains("broken"));

    let timeout = GateVerdict::Timeout {
        gate: "replay".into(),
        elapsed_ticks: 99,
    };
    assert!(timeout.to_string().contains("TIMEOUT"));
    assert!(timeout.to_string().contains("99"));
}

#[test]
fn gate_verdict_serde_round_trip() {
    let verdicts = [
        GateVerdict::Pass,
        GateVerdict::Fail {
            reason: "scenario failed".into(),
        },
        GateVerdict::InfrastructureError {
            detail: "missing dep".into(),
        },
        GateVerdict::Timeout {
            gate: "replay".into(),
            elapsed_ticks: 600,
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let restored: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// OverallVerdict
// ===========================================================================

#[test]
fn overall_verdict_released() {
    let v = OverallVerdict::Released;
    assert!(v.is_released());
    assert_eq!(v.as_str(), "released");
    assert_eq!(v.to_string(), "RELEASED");
}

#[test]
fn overall_verdict_blocked() {
    let v = OverallVerdict::Blocked {
        failing_gates: vec![GateKind::ReplayDeterminism, GateKind::EvidenceCompleteness],
    };
    assert!(!v.is_released());
    assert_eq!(v.as_str(), "blocked");
    let display = v.to_string();
    assert!(display.contains("BLOCKED"));
    assert!(display.contains("replay_determinism"));
    assert!(display.contains("evidence_completeness"));
}

#[test]
fn overall_verdict_serde_round_trip() {
    for v in [
        OverallVerdict::Released,
        OverallVerdict::Blocked {
            failing_gates: vec![
                GateKind::FrankenlabScenarios,
                GateKind::ObligationResolution,
            ],
        },
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: OverallVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// ===========================================================================
// GateEvent
// ===========================================================================

#[test]
fn gate_event_serde_round_trip() {
    let event = GateEvent {
        component: "frankenlab_release_gate".to_string(),
        gate: "frankenlab_scenarios".to_string(),
        event: "gate_pass".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn gate_event_with_error_code_serde() {
    let event = GateEvent {
        component: "frankenlab_release_gate".to_string(),
        gate: "replay_determinism".to_string(),
        event: "gate_fail".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("replay_divergence".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// GateResult
// ===========================================================================

#[test]
fn gate_result_pass_serde_round_trip() {
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
fn gate_result_fail_serde_round_trip() {
    let result = GateResult {
        kind: GateKind::ReplayDeterminism,
        verdict: GateVerdict::Fail {
            reason: "divergence found".into(),
        },
        checks_performed: 10,
        checks_passed: 8,
        events: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn gate_result_infra_error_serde_round_trip() {
    let result = GateResult {
        kind: GateKind::EvidenceCompleteness,
        verdict: GateVerdict::InfrastructureError {
            detail: "missing".into(),
        },
        checks_performed: 0,
        checks_passed: 0,
        events: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// GateConfig
// ===========================================================================

#[test]
fn gate_config_defaults() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.seed, 42);
    assert_eq!(cfg.timeout_ticks, 600);
    assert!(cfg.check_replay);
    assert!(cfg.check_obligations);
    assert!(cfg.check_evidence);
    assert_eq!(cfg.replay_iterations, 10);
}

#[test]
fn gate_config_serde_round_trip() {
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

#[test]
fn gate_config_custom_values() {
    let cfg = GateConfig {
        seed: 12345,
        timeout_ticks: 1200,
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        replay_iterations: 1,
    };
    assert_eq!(cfg.seed, 12345);
    assert_eq!(cfg.timeout_ticks, 1200);
    assert!(!cfg.check_replay);
    assert!(!cfg.check_obligations);
    assert!(!cfg.check_evidence);
}

// ===========================================================================
// GateReport
// ===========================================================================

#[test]
fn gate_report_serde_round_trip_passing() {
    let report = GateReport {
        seed: 42,
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
                verdict: GateVerdict::Pass,
                checks_performed: 5,
                checks_passed: 5,
                events: vec![],
            },
        ],
        overall_verdict: OverallVerdict::Released,
        total_checks: 15,
        total_passed: 15,
        failure_summary: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn gate_report_serde_round_trip_failing() {
    let report = GateReport {
        seed: 42,
        gates: vec![GateResult {
            kind: GateKind::FrankenlabScenarios,
            verdict: GateVerdict::Fail {
                reason: "2 scenarios failed".into(),
            },
            checks_performed: 10,
            checks_passed: 8,
            events: vec![],
        }],
        overall_verdict: OverallVerdict::Blocked {
            failing_gates: vec![GateKind::FrankenlabScenarios],
        },
        total_checks: 10,
        total_passed: 8,
        failure_summary: vec!["frankenlab_scenarios: FAIL: 2 scenarios failed".into()],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn gate_report_machine_readable_json_fields() {
    let report = GateReport {
        seed: 42,
        gates: vec![],
        overall_verdict: OverallVerdict::Released,
        total_checks: 0,
        total_passed: 0,
        failure_summary: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("seed").is_some());
    assert!(parsed.get("gates").is_some());
    assert!(parsed.get("overall_verdict").is_some());
    assert!(parsed.get("total_checks").is_some());
    assert!(parsed.get("total_passed").is_some());
    assert!(parsed.get("failure_summary").is_some());
}

// ===========================================================================
// Partial success reporting
// ===========================================================================

#[test]
fn partial_success_reports_failing_gates() {
    let report = GateReport {
        seed: 42,
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
                    reason: "diverged".into(),
                },
                checks_performed: 5,
                checks_passed: 3,
                events: vec![],
            },
            GateResult {
                kind: GateKind::ObligationResolution,
                verdict: GateVerdict::Pass,
                checks_performed: 7,
                checks_passed: 7,
                events: vec![],
            },
            GateResult {
                kind: GateKind::EvidenceCompleteness,
                verdict: GateVerdict::Fail {
                    reason: "gap found".into(),
                },
                checks_performed: 7,
                checks_passed: 6,
                events: vec![],
            },
        ],
        overall_verdict: OverallVerdict::Blocked {
            failing_gates: vec![GateKind::ReplayDeterminism, GateKind::EvidenceCompleteness],
        },
        total_checks: 29,
        total_passed: 26,
        failure_summary: vec![
            "replay_determinism: FAIL: diverged".into(),
            "evidence_completeness: FAIL: gap found".into(),
        ],
    };

    assert!(!report.overall_verdict.is_released());
    assert_eq!(report.failure_summary.len(), 2);
    assert!(report.gates[0].verdict.is_pass());
    assert!(!report.gates[1].verdict.is_pass());
    assert!(report.gates[2].verdict.is_pass());
    assert!(!report.gates[3].verdict.is_pass());
}

// ===========================================================================
// ReleaseGateRunner — construction
// ===========================================================================

#[test]
fn runner_construction() {
    let config = GateConfig::default();
    let runner = ReleaseGateRunner::new(config.clone());
    assert_eq!(runner.config().seed, config.seed);
    assert_eq!(runner.config().timeout_ticks, config.timeout_ticks);
    assert!(runner.events().is_empty());
}

// ===========================================================================
// ReleaseGateRunner — full gate run
// ===========================================================================

#[test]
fn full_gate_run_passes() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 3,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    assert!(report.overall_verdict.is_released());
    assert_eq!(report.gates.len(), 4);
    assert!(report.failure_summary.is_empty());
    assert!(report.total_checks > 0);
    assert_eq!(report.total_checks, report.total_passed);
}

#[test]
fn full_gate_run_report_seed_matches_config() {
    let config = GateConfig {
        seed: 77,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);
    assert_eq!(report.seed, 77);
}

#[test]
fn full_gate_run_all_gate_kinds_present() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    let gate_kinds: Vec<GateKind> = report.gates.iter().map(|g| g.kind).collect();
    assert!(gate_kinds.contains(&GateKind::FrankenlabScenarios));
    assert!(gate_kinds.contains(&GateKind::ReplayDeterminism));
    assert!(gate_kinds.contains(&GateKind::ObligationResolution));
    assert!(gate_kinds.contains(&GateKind::EvidenceCompleteness));
}

// ===========================================================================
// ReleaseGateRunner — events
// ===========================================================================

#[test]
fn full_gate_run_emits_events() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    runner.run(&mut cx);

    // At least start + pass event per gate = 8 events.
    assert!(runner.events().len() >= 8);
    for event in runner.events() {
        assert_eq!(event.component, "frankenlab_release_gate");
    }
}

#[test]
fn events_include_gate_start() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    runner.run(&mut cx);

    let start_events: Vec<&GateEvent> = runner
        .events()
        .iter()
        .filter(|e| e.event == "gate_start")
        .collect();
    assert_eq!(start_events.len(), 4); // One per gate.
}

#[test]
fn events_include_gate_pass_on_success() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    runner.run(&mut cx);

    let pass_events: Vec<&GateEvent> = runner
        .events()
        .iter()
        .filter(|e| e.event == "gate_pass")
        .collect();
    assert_eq!(pass_events.len(), 4); // All pass.
    for e in &pass_events {
        assert!(e.error_code.is_none());
    }
}

// ===========================================================================
// ReleaseGateRunner — selective gates
// ===========================================================================

#[test]
fn run_only_scenarios_gate() {
    let config = GateConfig {
        seed: 42,
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    assert_eq!(report.gates.len(), 1);
    assert_eq!(report.gates[0].kind, GateKind::FrankenlabScenarios);
    assert!(report.overall_verdict.is_released());
}

#[test]
fn run_scenarios_and_evidence_only() {
    let config = GateConfig {
        seed: 42,
        check_replay: false,
        check_obligations: false,
        check_evidence: true,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    assert_eq!(report.gates.len(), 2);
    let kinds: Vec<GateKind> = report.gates.iter().map(|g| g.kind).collect();
    assert!(kinds.contains(&GateKind::FrankenlabScenarios));
    assert!(kinds.contains(&GateKind::EvidenceCompleteness));
}

#[test]
fn run_without_replay_is_faster() {
    let config_no_replay = GateConfig {
        seed: 42,
        check_replay: false,
        check_obligations: false,
        check_evidence: false,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config_no_replay);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    // Only 1 gate should be evaluated.
    assert_eq!(report.gates.len(), 1);
}

// ===========================================================================
// ReleaseGateRunner — determinism
// ===========================================================================

#[test]
fn gate_run_deterministic_across_runs() {
    let config = GateConfig {
        seed: 77,
        replay_iterations: 2,
        ..Default::default()
    };

    let mut runner1 = ReleaseGateRunner::new(config.clone());
    let mut cx1 = mock_cx(500_000);
    let report1 = runner1.run(&mut cx1);

    let mut runner2 = ReleaseGateRunner::new(config);
    let mut cx2 = mock_cx(500_000);
    let report2 = runner2.run(&mut cx2);

    assert_eq!(report1.overall_verdict, report2.overall_verdict);
    assert_eq!(report1.total_checks, report2.total_checks);
    assert_eq!(report1.total_passed, report2.total_passed);
    assert_eq!(report1.gates.len(), report2.gates.len());

    for (g1, g2) in report1.gates.iter().zip(report2.gates.iter()) {
        assert_eq!(g1.kind, g2.kind);
        assert_eq!(g1.verdict, g2.verdict);
        assert_eq!(g1.checks_performed, g2.checks_performed);
        assert_eq!(g1.checks_passed, g2.checks_passed);
    }
}

#[test]
fn gate_run_deterministic_50_times() {
    let config = GateConfig {
        seed: 55,
        replay_iterations: 2,
        check_replay: false,
        ..Default::default()
    };

    let mut first_report = None;
    for _ in 0..50 {
        let mut runner = ReleaseGateRunner::new(config.clone());
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        if let Some(ref first) = first_report {
            let f: &GateReport = first;
            assert_eq!(f.overall_verdict, report.overall_verdict);
            assert_eq!(f.total_checks, report.total_checks);
            assert_eq!(f.total_passed, report.total_passed);
        } else {
            first_report = Some(report);
        }
    }
}

// ===========================================================================
// ReleaseGateRunner — idempotency
// ===========================================================================

#[test]
fn gate_idempotent_same_runner() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        check_replay: false,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);

    let mut cx1 = mock_cx(500_000);
    let report1 = runner.run(&mut cx1);

    let mut cx2 = mock_cx(500_000);
    let report2 = runner.run(&mut cx2);

    assert_eq!(report1.overall_verdict, report2.overall_verdict);
    assert_eq!(report1.total_checks, report2.total_checks);
    assert_eq!(report1.total_passed, report2.total_passed);
}

// ===========================================================================
// ReleaseGateRunner — different seeds
// ===========================================================================

#[test]
fn different_seeds_all_pass() {
    for seed in [1, 42, 99, 255, 1000] {
        let config = GateConfig {
            seed,
            replay_iterations: 2,
            check_replay: false,
            ..Default::default()
        };
        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);
        assert!(
            report.overall_verdict.is_released(),
            "seed {seed} should release"
        );
    }
}

// ===========================================================================
// ReleaseGateRunner — report serde
// ===========================================================================

#[test]
fn gate_report_from_run_serde_round_trip() {
    let config = GateConfig {
        seed: 42,
        replay_iterations: 2,
        ..Default::default()
    };
    let mut runner = ReleaseGateRunner::new(config);
    let mut cx = mock_cx(500_000);
    let report = runner.run(&mut cx);

    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// ===========================================================================
// Infrastructure error (fail-closed)
// ===========================================================================

#[test]
fn infrastructure_error_verdict_blocks_release() {
    let gate = GateResult {
        kind: GateKind::FrankenlabScenarios,
        verdict: GateVerdict::InfrastructureError {
            detail: "harness not found".into(),
        },
        checks_performed: 0,
        checks_passed: 0,
        events: vec![],
    };
    assert!(!gate.verdict.is_pass());
    assert!(matches!(
        gate.verdict,
        GateVerdict::InfrastructureError { .. }
    ));
}

#[test]
fn timeout_verdict_blocks_release() {
    let gate = GateResult {
        kind: GateKind::ReplayDeterminism,
        verdict: GateVerdict::Timeout {
            gate: "replay_determinism".into(),
            elapsed_ticks: 700,
        },
        checks_performed: 0,
        checks_passed: 0,
        events: vec![],
    };
    assert!(!gate.verdict.is_pass());
}

// ===========================================================================
// Stress test
// ===========================================================================

#[test]
fn stress_many_runs_different_configs() {
    for i in 0..20 {
        let config = GateConfig {
            seed: i as u64,
            replay_iterations: 2,
            check_replay: i % 3 == 0,
            check_obligations: i % 2 == 0,
            check_evidence: i % 4 == 0,
            ..Default::default()
        };
        let expected_gates = 1
            + if config.check_replay { 1 } else { 0 }
            + if config.check_obligations { 1 } else { 0 }
            + if config.check_evidence { 1 } else { 0 };

        let mut runner = ReleaseGateRunner::new(config);
        let mut cx = mock_cx(500_000);
        let report = runner.run(&mut cx);

        assert_eq!(report.gates.len(), expected_gates, "iteration {i}");
        assert!(
            report.overall_verdict.is_released(),
            "iteration {i} should release"
        );
    }
}
