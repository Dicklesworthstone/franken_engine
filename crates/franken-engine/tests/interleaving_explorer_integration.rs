//! Integration tests for the `interleaving_explorer` module.
//!
//! Covers: OperationType, RaceSeverity, RaceSurface, RaceSurfaceCatalog,
//! ExplorationStrategy, InvariantResult, InvariantChecker, ExplorationFailure,
//! ExplorationReport, Scenario, ScenarioAction, InterleavingExplorer.

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

use frankenengine_engine::interleaving_explorer::{
    ExplorationFailure, ExplorationReport, ExplorationStrategy, InterleavingExplorer,
    InvariantChecker, InvariantResult, OperationType, RaceSeverity, RaceSurface,
    RaceSurfaceCatalog, Scenario, ScenarioAction,
};
use frankenengine_engine::lab_runtime::{
    FaultKind, LabEvent, LabRunResult, ScheduleTranscript, Verdict,
};

// ===========================================================================
// OperationType — serde + display + ord
// ===========================================================================

#[test]
fn operation_type_serde_roundtrip_all_variants() {
    let variants = [
        OperationType::CheckpointWrite,
        OperationType::RevocationPropagation,
        OperationType::PolicyUpdate,
        OperationType::EvidenceEmission,
        OperationType::RegionClose,
        OperationType::ObligationCommit,
        OperationType::TaskCompletion,
        OperationType::FaultInjection,
        OperationType::CancelInjection,
        OperationType::TimeAdvance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: OperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn operation_type_display_all_variants() {
    assert_eq!(
        OperationType::CheckpointWrite.to_string(),
        "checkpoint_write"
    );
    assert_eq!(
        OperationType::RevocationPropagation.to_string(),
        "revocation_propagation"
    );
    assert_eq!(OperationType::PolicyUpdate.to_string(), "policy_update");
    assert_eq!(
        OperationType::EvidenceEmission.to_string(),
        "evidence_emission"
    );
    assert_eq!(OperationType::RegionClose.to_string(), "region_close");
    assert_eq!(
        OperationType::ObligationCommit.to_string(),
        "obligation_commit"
    );
    assert_eq!(OperationType::TaskCompletion.to_string(), "task_completion");
    assert_eq!(OperationType::FaultInjection.to_string(), "fault_injection");
    assert_eq!(
        OperationType::CancelInjection.to_string(),
        "cancel_injection"
    );
    assert_eq!(OperationType::TimeAdvance.to_string(), "time_advance");
}

#[test]
fn operation_type_ordering() {
    assert!(OperationType::CheckpointWrite < OperationType::RevocationPropagation);
    assert!(OperationType::RevocationPropagation < OperationType::PolicyUpdate);
}

// ===========================================================================
// RaceSeverity — serde + display + ord
// ===========================================================================

#[test]
fn race_severity_serde_roundtrip() {
    for v in [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: RaceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn race_severity_display() {
    assert_eq!(RaceSeverity::Low.to_string(), "low");
    assert_eq!(RaceSeverity::Medium.to_string(), "medium");
    assert_eq!(RaceSeverity::High.to_string(), "high");
    assert_eq!(RaceSeverity::Critical.to_string(), "critical");
}

#[test]
fn race_severity_ordering() {
    assert!(RaceSeverity::Low < RaceSeverity::Medium);
    assert!(RaceSeverity::Medium < RaceSeverity::High);
    assert!(RaceSeverity::High < RaceSeverity::Critical);
}

// ===========================================================================
// RaceSurface — serde
// ===========================================================================

#[test]
fn race_surface_serde_roundtrip() {
    let surface = RaceSurface {
        race_id: "test-race".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "test invariant".to_string(),
        severity: RaceSeverity::High,
    };
    let json = serde_json::to_string(&surface).unwrap();
    let restored: RaceSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, restored);
}

// ===========================================================================
// RaceSurfaceCatalog — construction + default catalog
// ===========================================================================

#[test]
fn empty_catalog() {
    let catalog = RaceSurfaceCatalog::new();
    assert!(catalog.is_empty());
    assert_eq!(catalog.len(), 0);
}

#[test]
fn default_catalog_has_known_races() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    assert!(catalog.len() >= 5);
    assert!(
        catalog
            .surfaces
            .contains_key("race-checkpoint-vs-revocation")
    );
    assert!(catalog.surfaces.contains_key("race-policy-vs-evidence"));
    assert!(
        catalog
            .surfaces
            .contains_key("race-checkpoint-vs-region-close")
    );
    assert!(catalog.surfaces.contains_key("race-obligation-vs-cancel"));
    assert!(catalog.surfaces.contains_key("race-completion-vs-fault"));
}

#[test]
fn catalog_add_and_lookup() {
    let mut catalog = RaceSurfaceCatalog::new();
    catalog.add(RaceSurface {
        race_id: "test-race".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "test invariant".to_string(),
        severity: RaceSeverity::Medium,
    });
    assert_eq!(catalog.len(), 1);
    assert!(!catalog.is_empty());
    assert!(catalog.surfaces.contains_key("test-race"));
}

#[test]
fn catalog_add_replaces_existing() {
    let mut catalog = RaceSurfaceCatalog::new();
    catalog.add(RaceSurface {
        race_id: "r1".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "v1".to_string(),
        severity: RaceSeverity::Low,
    });
    catalog.add(RaceSurface {
        race_id: "r1".to_string(),
        operations: [OperationType::PolicyUpdate, OperationType::EvidenceEmission],
        invariant: "v2".to_string(),
        severity: RaceSeverity::High,
    });
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog.surfaces["r1"].invariant, "v2");
}

#[test]
fn catalog_serde_roundtrip() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let json = serde_json::to_string(&catalog).unwrap();
    let restored: RaceSurfaceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, restored);
}

#[test]
fn default_catalog_severity_levels() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let checkpoint_revocation = &catalog.surfaces["race-checkpoint-vs-revocation"];
    assert_eq!(checkpoint_revocation.severity, RaceSeverity::Critical);

    let policy_evidence = &catalog.surfaces["race-policy-vs-evidence"];
    assert_eq!(policy_evidence.severity, RaceSeverity::High);
}

// ===========================================================================
// ExplorationStrategy — serde + display
// ===========================================================================

#[test]
fn exploration_strategy_serde_roundtrip() {
    let strategies = [
        ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 100,
        },
        ExplorationStrategy::TargetedRace {
            race_ids: vec!["r1".to_string(), "r2".to_string()],
        },
    ];
    for s in &strategies {
        let json = serde_json::to_string(s).unwrap();
        let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn exploration_strategy_display() {
    assert_eq!(
        ExplorationStrategy::Exhaustive {
            max_permutations: 10
        }
        .to_string(),
        "exhaustive(max=10)"
    );
    assert_eq!(
        ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 100
        }
        .to_string(),
        "random_walk(seed=42, iters=100)"
    );
    assert!(
        ExplorationStrategy::TargetedRace {
            race_ids: vec!["r1".to_string()]
        }
        .to_string()
        .contains("r1")
    );
}

// ===========================================================================
// InvariantResult — serde
// ===========================================================================

#[test]
fn invariant_result_serde_roundtrip() {
    let results = [
        InvariantResult::Held,
        InvariantResult::Violated {
            description: "bad".to_string(),
        },
    ];
    for r in &results {
        let json = serde_json::to_string(r).unwrap();
        let restored: InvariantResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

// ===========================================================================
// InvariantChecker — serde + check
// ===========================================================================

#[test]
fn invariant_checker_serde_all_variants() {
    let checkers = [
        InvariantChecker::NoCompletedAndFaulted,
        InvariantChecker::AllTasksTerminal,
        InvariantChecker::FaultAfterCompletionForbidden,
        InvariantChecker::ForbiddenEventPattern {
            action: "test".to_string(),
            outcome: "fail".to_string(),
        },
    ];
    for c in &checkers {
        let json = serde_json::to_string(c).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

fn make_lab_result(events: Vec<LabEvent>) -> LabRunResult {
    LabRunResult {
        seed: 42,
        transcript: ScheduleTranscript::new(42),
        events,
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    }
}

fn make_event(step: u64, action: &str, task_id: Option<u64>, outcome: &str) -> LabEvent {
    LabEvent {
        virtual_time: 0,
        step_index: step,
        action: action.to_string(),
        task_id,
        region_id: None,
        outcome: outcome.to_string(),
    }
}

#[test]
fn no_completed_and_faulted_holds_on_clean_run() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![make_event(1, "complete_task", Some(1), "completed")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn no_completed_and_faulted_detects_violation() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![
        make_event(1, "complete_task", Some(1), "completed"),
        make_event(2, "inject_fault", Some(1), "fault=panic"),
    ]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn all_tasks_terminal_holds_on_completed() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "complete_task", Some(1), "completed")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_holds_on_cancelled() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "cancel", Some(1), "cancelled")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_holds_on_faulted() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "inject_fault", Some(1), "fault=panic")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_detects_non_terminal() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn forbidden_event_pattern_holds_when_absent() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn forbidden_event_pattern_detects_match() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = make_lab_result(vec![make_event(1, "inject_fault", Some(1), "fault=panic")]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

// ===========================================================================
// ScenarioAction — serde
// ===========================================================================

#[test]
fn scenario_action_serde_all_variants() {
    let actions = [
        ScenarioAction::RunTask { task_index: 0 },
        ScenarioAction::CompleteTask { task_index: 1 },
        ScenarioAction::AdvanceTime { ticks: 100 },
        ScenarioAction::InjectCancel {
            region_id: "r1".to_string(),
        },
        ScenarioAction::InjectFault {
            task_index: 0,
            fault: FaultKind::Panic,
        },
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, restored);
    }
}

// ===========================================================================
// Scenario — serde
// ===========================================================================

#[test]
fn scenario_serde_roundtrip() {
    let scenario = Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let restored: Scenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, restored);
}

// ===========================================================================
// ExplorationFailure — serde
// ===========================================================================

#[test]
fn exploration_failure_serde_roundtrip() {
    let failure = ExplorationFailure {
        transcript: ScheduleTranscript::new(42),
        violations: vec!["test violation".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["race-1".to_string()],
    };
    let json = serde_json::to_string(&failure).unwrap();
    let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(failure, restored);
}

// ===========================================================================
// ExplorationReport — serde + computed fields
// ===========================================================================

#[test]
fn exploration_report_serde_roundtrip() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 3,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: ExplorationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn coverage_millionths_calculation() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 3,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 600_000);
}

#[test]
fn coverage_zero_when_no_surfaces() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 0,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 0);
}

#[test]
fn report_all_passed_and_failure_count() {
    let passing = ExplorationReport {
        exploration_id: "pass".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert!(passing.all_passed());
    assert_eq!(passing.failure_count(), 0);

    let failing = ExplorationReport {
        exploration_id: "fail".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![ExplorationFailure {
            transcript: ScheduleTranscript::new(0),
            violations: vec!["bad".to_string()],
            minimized_transcript: None,
            related_race_ids: vec![],
        }],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert!(!failing.all_passed());
    assert_eq!(failing.failure_count(), 1);
}

// ===========================================================================
// InterleavingExplorer — exhaustive strategy
// ===========================================================================

#[test]
fn exhaustive_generates_correct_count_for_small_input() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::Exhaustive {
        max_permutations: 100,
    };
    let report = explorer.explore(&scenario, &strategy, "test-exhaustive");
    assert_eq!(report.total_explored, 6); // 3! = 6
}

#[test]
fn exhaustive_respects_max_bound() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::AdvanceTime { ticks: 20 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::Exhaustive {
        max_permutations: 5,
    };
    let report = explorer.explore(&scenario, &strategy, "test-bounded");
    assert!(report.total_explored <= 5);
}

// ===========================================================================
// InterleavingExplorer — random walk strategy
// ===========================================================================

#[test]
fn random_walk_respects_iteration_count() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 99,
        iterations: 7,
    };
    let report = explorer.explore(&scenario, &strategy, "test-rw");
    assert_eq!(report.total_explored, 7);
}

// ===========================================================================
// InterleavingExplorer — targeted race strategy
// ===========================================================================

#[test]
fn targeted_race_includes_identity_ordering() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectCancel {
                region_id: "r1".to_string(),
            },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let strategy = ExplorationStrategy::TargetedRace {
        race_ids: vec!["race-obligation-vs-cancel".to_string()],
    };
    let report = explorer.explore(&scenario, &strategy, "test-targeted");
    assert!(report.total_explored >= 1);
}

// ===========================================================================
// InterleavingExplorer — invariant-driven failure detection
// ===========================================================================

#[test]
fn explorer_finds_no_failures_on_clean_scenario() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "clean-test",
    );
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
}

#[test]
fn explorer_detects_failure_with_forbidden_pattern() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "fault-detection",
    );
    assert!(!report.all_passed());
    assert!(report.failure_count() >= 1);
}

#[test]
fn regression_transcripts_populated_from_failures() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "regression-test",
    );
    assert!(!report.regression_transcripts.is_empty());
}

// ===========================================================================
// InterleavingExplorer — determinism
// ===========================================================================

#[test]
fn exploration_is_deterministic() {
    let scenario = Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 5 },
            ScenarioAction::InjectCancel {
                region_id: "r".to_string(),
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 123,
        iterations: 10,
    };
    let report1 = explorer.explore(&scenario, &strategy, "det-1");
    let report2 = explorer.explore(&scenario, &strategy, "det-1");
    assert_eq!(report1.total_explored, report2.total_explored);
    assert_eq!(report1.failures, report2.failures);
}

// ===========================================================================
// InterleavingExplorer — minimization
// ===========================================================================

#[test]
fn minimization_produces_shorter_transcript() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
            ScenarioAction::AdvanceTime { ticks: 20 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 30,
        },
        "minimize-test",
    );
    assert!(!report.all_passed());
    let has_minimized = report
        .failures
        .iter()
        .any(|f| f.minimized_transcript.is_some());
    assert!(has_minimized);
}

// ===========================================================================
// InterleavingExplorer — multiple checkers
// ===========================================================================

#[test]
fn multiple_checkers_all_applied() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
            InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            },
        ],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "multi-checker",
    );
    // At least the ForbiddenEventPattern should trigger.
    assert!(!report.all_passed());
}

// ===========================================================================
// InterleavingExplorer — race surface coverage tracking
// ===========================================================================

#[test]
fn race_surface_coverage_tracked() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
        ],
        seed: 42,
    };
    let catalog = RaceSurfaceCatalog::default_catalog();
    let catalog_size = catalog.len();
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "coverage-test",
    );
    // With 2 actions, all races should be "exercised" per the implementation.
    assert_eq!(report.race_surfaces_covered, catalog_size);
    assert_eq!(report.race_surfaces_total, catalog_size);
}

// ===========================================================================
// Stress — larger scenario with random walk
// ===========================================================================

#[test]
fn stress_random_walk_many_iterations() {
    let scenario = Scenario {
        task_count: 3,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::RunTask { task_index: 2 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::InjectCancel {
                region_id: "region-a".to_string(),
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
        ],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::RandomWalk {
            seed: 777,
            iterations: 50,
        },
        "stress-rw",
    );
    assert_eq!(report.total_explored, 50);
    assert_eq!(report.exploration_id, "stress-rw");
}

// ===========================================================================
// Enrichment: PearlTower 2026-03-04
// ===========================================================================

// -- FaultAfterCompletionForbidden checker --

#[test]
fn fault_after_completion_forbidden_holds_on_clean_run() {
    let checker = InvariantChecker::FaultAfterCompletionForbidden;
    let result = make_lab_result(vec![
        make_event(1, "run_task", Some(1), "running"),
        make_event(2, "complete_task", Some(1), "completed"),
    ]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn fault_after_completion_forbidden_detects_violation() {
    let checker = InvariantChecker::FaultAfterCompletionForbidden;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![
            LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "complete_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "completed".to_string(),
            },
            LabEvent {
                virtual_time: 0,
                step_index: 2,
                action: "inject_fault".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "fault=panic".to_string(),
            },
        ],
        final_time: 0,
        tasks_completed: 1,
        tasks_faulted: 1,
        tasks_cancelled: 0,
        verdict: Verdict::Fail {
            reason: "faulted after completion".to_string(),
        },
    };
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("task 1"));
            assert!(description.contains("faulted at step 2"));
            assert!(description.contains("completion at step 1"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

#[test]
fn fault_after_completion_forbidden_holds_on_empty_events() {
    let checker = InvariantChecker::FaultAfterCompletionForbidden;
    let result = make_lab_result(vec![]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

// -- Empty events for all checkers --

#[test]
fn no_completed_and_faulted_holds_on_empty_events() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_holds_on_empty_events() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn forbidden_event_pattern_holds_on_empty_events() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = make_lab_result(vec![]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

// -- ForbiddenEventPattern violation description content --

#[test]
fn forbidden_event_pattern_violation_description_content() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "run_task".to_string(),
        outcome: "running".to_string(),
    };
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("forbidden event pattern"));
            assert!(description.contains("run_task"));
            assert!(description.contains("running"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

// -- Display uniqueness --

#[test]
fn operation_type_display_uniqueness() {
    use std::collections::BTreeSet;
    let displays: BTreeSet<String> = [
        OperationType::CheckpointWrite,
        OperationType::RevocationPropagation,
        OperationType::PolicyUpdate,
        OperationType::EvidenceEmission,
        OperationType::RegionClose,
        OperationType::ObligationCommit,
        OperationType::TaskCompletion,
        OperationType::FaultInjection,
        OperationType::CancelInjection,
        OperationType::TimeAdvance,
    ]
    .iter()
    .map(|o| o.to_string())
    .collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn race_severity_display_uniqueness() {
    use std::collections::BTreeSet;
    let displays: BTreeSet<String> = [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// -- Clone independence --

#[test]
fn race_surface_clone_independence() {
    let original = RaceSurface {
        race_id: "clone-ind".to_string(),
        operations: [OperationType::EvidenceEmission, OperationType::RegionClose],
        invariant: "evidence before close".to_string(),
        severity: RaceSeverity::High,
    };
    let mut cloned = original.clone();
    cloned.race_id = "mutated".to_string();
    cloned.severity = RaceSeverity::Low;
    assert_eq!(original.race_id, "clone-ind");
    assert_eq!(original.severity, RaceSeverity::High);
    assert_ne!(original, cloned);
}

#[test]
fn scenario_clone_independence() {
    let original = Scenario {
        task_count: 3,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 55,
    };
    let mut cloned = original.clone();
    cloned.task_count = 99;
    cloned
        .actions
        .push(ScenarioAction::CompleteTask { task_index: 0 });
    assert_eq!(original.task_count, 3);
    assert_eq!(original.actions.len(), 2);
}

#[test]
fn exploration_failure_clone_independence() {
    let original = ExplorationFailure {
        transcript: ScheduleTranscript::new(10),
        violations: vec!["v1".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["r-a".to_string()],
    };
    let mut cloned = original.clone();
    cloned.violations.push("v2".to_string());
    cloned.related_race_ids.clear();
    assert_eq!(original.violations.len(), 1);
    assert_eq!(original.related_race_ids.len(), 1);
}

#[test]
fn exploration_report_clone_independence() {
    let original = ExplorationReport {
        exploration_id: "ind-test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 2,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    let mut cloned = original.clone();
    cloned.exploration_id = "mutated".to_string();
    cloned.total_explored = 999;
    assert_eq!(original.exploration_id, "ind-test");
    assert_eq!(original.total_explored, 10);
}

#[test]
fn catalog_clone_independence() {
    let mut original = RaceSurfaceCatalog::new();
    original.add(RaceSurface {
        race_id: "s1".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::PolicyUpdate],
        invariant: "x".to_string(),
        severity: RaceSeverity::Medium,
    });
    let mut cloned = original.clone();
    cloned.add(RaceSurface {
        race_id: "s2".to_string(),
        operations: [OperationType::TimeAdvance, OperationType::FaultInjection],
        invariant: "y".to_string(),
        severity: RaceSeverity::Low,
    });
    assert_eq!(original.len(), 1);
    assert_eq!(cloned.len(), 2);
}

// -- InvariantResult equality edge cases --

#[test]
fn invariant_result_held_eq_held() {
    assert_eq!(InvariantResult::Held, InvariantResult::Held);
}

#[test]
fn invariant_result_violated_ne_held() {
    let v = InvariantResult::Violated {
        description: "oops".to_string(),
    };
    assert_ne!(v, InvariantResult::Held);
}

#[test]
fn invariant_result_violated_different_descriptions_ne() {
    let v1 = InvariantResult::Violated {
        description: "a".to_string(),
    };
    let v2 = InvariantResult::Violated {
        description: "b".to_string(),
    };
    assert_ne!(v1, v2);
}

// -- JSON field name contracts --

#[test]
fn race_surface_json_field_names() {
    let surface = RaceSurface {
        race_id: "json-test".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "test invariant".to_string(),
        severity: RaceSeverity::High,
    };
    let json = serde_json::to_string(&surface).unwrap();
    for field in &["race_id", "operations", "invariant", "severity"] {
        assert!(
            json.contains(field),
            "RaceSurface JSON missing field: {field}"
        );
    }
}

#[test]
fn scenario_json_field_names() {
    let scenario = Scenario {
        task_count: 2,
        actions: vec![ScenarioAction::RunTask { task_index: 0 }],
        seed: 42,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    for field in &["task_count", "actions", "seed"] {
        assert!(json.contains(field), "Scenario JSON missing field: {field}");
    }
}

#[test]
fn exploration_failure_json_field_names() {
    let failure = ExplorationFailure {
        transcript: ScheduleTranscript::new(1),
        violations: vec!["v1".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["r1".to_string()],
    };
    let json = serde_json::to_string(&failure).unwrap();
    for field in &[
        "transcript",
        "violations",
        "minimized_transcript",
        "related_race_ids",
    ] {
        assert!(
            json.contains(field),
            "ExplorationFailure JSON missing field: {field}"
        );
    }
}

#[test]
fn exploration_report_json_field_names() {
    let report = ExplorationReport {
        exploration_id: "json-fields".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 2,
        regression_transcripts: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "exploration_id",
        "strategy",
        "total_explored",
        "failures",
        "race_surfaces_covered",
        "race_surfaces_total",
        "regression_transcripts",
    ] {
        assert!(
            json.contains(field),
            "ExplorationReport JSON missing field: {field}"
        );
    }
}

// -- Coverage edge cases --

#[test]
fn coverage_full_when_all_surfaces_covered() {
    let report = ExplorationReport {
        exploration_id: "full-cov".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 5,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 1_000_000);
}

#[test]
fn coverage_partial_one_of_three() {
    let report = ExplorationReport {
        exploration_id: "partial".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 1,
        race_surfaces_total: 3,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 333_333);
}

#[test]
fn coverage_one_of_one() {
    let report = ExplorationReport {
        exploration_id: "one".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 1,
        race_surfaces_total: 1,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 1_000_000);
}

// -- Explorer edge cases --

#[test]
fn exhaustive_empty_actions_produces_one_permutation() {
    let scenario = Scenario {
        task_count: 0,
        actions: vec![],
        seed: 1,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 100,
        },
        "empty-actions",
    );
    assert_eq!(report.total_explored, 1);
}

#[test]
fn exhaustive_single_action_produces_one_permutation() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![ScenarioAction::RunTask { task_index: 0 }],
        seed: 1,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 100,
        },
        "single-action",
    );
    assert_eq!(report.total_explored, 1);
}

#[test]
fn random_walk_zero_iterations() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![ScenarioAction::RunTask { task_index: 0 }],
        seed: 1,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 0,
        },
        "zero-iters",
    );
    assert_eq!(report.total_explored, 0);
    assert!(report.all_passed());
}

#[test]
fn targeted_race_nonexistent_race_id() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 5 },
        ],
        seed: 1,
    };
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::TargetedRace {
            race_ids: vec!["nonexistent-race".to_string()],
        },
        "bad-race-id",
    );
    // At least the identity ordering is always included
    assert!(report.total_explored >= 1);
}

#[test]
fn scenario_with_out_of_bounds_task_index() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 99 },
            ScenarioAction::CompleteTask { task_index: 99 },
        ],
        seed: 1,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::new(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "oob-test",
    );
    assert!(report.all_passed());
}

// -- ExplorationReport serde with failures --

#[test]
fn exploration_report_serde_with_failures() {
    let report = ExplorationReport {
        exploration_id: "serde-fail".to_string(),
        strategy: ExplorationStrategy::RandomWalk {
            seed: 7,
            iterations: 3,
        },
        total_explored: 3,
        failures: vec![
            ExplorationFailure {
                transcript: ScheduleTranscript::new(7),
                violations: vec!["v1".to_string()],
                minimized_transcript: None,
                related_race_ids: vec!["r-1".to_string()],
            },
            ExplorationFailure {
                transcript: ScheduleTranscript::new(8),
                violations: vec!["v2".to_string(), "v3".to_string()],
                minimized_transcript: Some(ScheduleTranscript::new(8)),
                related_race_ids: vec![],
            },
        ],
        race_surfaces_covered: 1,
        race_surfaces_total: 5,
        regression_transcripts: vec![ScheduleTranscript::new(7)],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: ExplorationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// -- ExplorationFailure with minimized transcript serde --

#[test]
fn exploration_failure_with_minimized_transcript_serde() {
    let failure = ExplorationFailure {
        transcript: ScheduleTranscript::new(1),
        violations: vec!["v1".to_string()],
        minimized_transcript: Some(ScheduleTranscript::new(1)),
        related_race_ids: vec!["r1".to_string()],
    };
    let json = serde_json::to_string(&failure).unwrap();
    let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(failure, restored);
    assert!(restored.minimized_transcript.is_some());
}

// -- ExplorationFailure multiple violations --

#[test]
fn exploration_failure_multiple_violations() {
    let f = ExplorationFailure {
        transcript: ScheduleTranscript::new(1),
        violations: vec![
            "invariant_a broken".to_string(),
            "invariant_b broken".to_string(),
            "invariant_c broken".to_string(),
        ],
        minimized_transcript: None,
        related_race_ids: vec!["r-1".to_string(), "r-2".to_string()],
    };
    assert_eq!(f.violations.len(), 3);
    assert_eq!(f.related_race_ids.len(), 2);
    let json = serde_json::to_string(&f).unwrap();
    let back: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// -- failure_count matches failures vec --

#[test]
fn failure_count_matches_failures_vec() {
    let report = ExplorationReport {
        exploration_id: "count-test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 5,
        failures: vec![
            ExplorationFailure {
                transcript: ScheduleTranscript::new(1),
                violations: vec!["v".to_string()],
                minimized_transcript: None,
                related_race_ids: vec![],
            },
            ExplorationFailure {
                transcript: ScheduleTranscript::new(2),
                violations: vec!["v".to_string()],
                minimized_transcript: None,
                related_race_ids: vec![],
            },
        ],
        race_surfaces_covered: 1,
        race_surfaces_total: 3,
        regression_transcripts: vec![],
    };
    assert_eq!(report.failure_count(), 2);
    assert!(!report.all_passed());
}

// -- Targeted strategy with empty ids --

#[test]
fn targeted_race_strategy_with_empty_ids() {
    let strategy = ExplorationStrategy::TargetedRace { race_ids: vec![] };
    let json = serde_json::to_string(&strategy).unwrap();
    let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(strategy, restored);
}

// -- Default catalog properties --

#[test]
fn default_catalog_non_empty_invariants() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    for surface in catalog.surfaces.values() {
        assert!(!surface.invariant.is_empty());
        assert!(!surface.race_id.is_empty());
    }
}

#[test]
fn default_catalog_race_ids_sorted() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let keys: Vec<&String> = catalog.surfaces.keys().collect();
    for window in keys.windows(2) {
        assert!(window[0] <= window[1], "BTreeMap keys must be sorted");
    }
}

#[test]
fn default_catalog_all_severities_present() {
    use std::collections::BTreeSet;
    let catalog = RaceSurfaceCatalog::default_catalog();
    let severities: BTreeSet<RaceSeverity> =
        catalog.surfaces.values().map(|s| s.severity).collect();
    assert!(severities.contains(&RaceSeverity::Critical));
    assert!(severities.contains(&RaceSeverity::High));
    assert!(severities.contains(&RaceSeverity::Medium));
}

// -- BTreeSet insertion dedup --

#[test]
fn operation_type_btreeset_dedup() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(OperationType::PolicyUpdate);
    set.insert(OperationType::PolicyUpdate);
    set.insert(OperationType::RegionClose);
    assert_eq!(set.len(), 2);
}

#[test]
fn race_severity_btreeset_dedup() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for s in [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
        RaceSeverity::Low,
    ] {
        set.insert(s);
    }
    assert_eq!(set.len(), 4);
}

// -- ExplorationStrategy display edge cases --

#[test]
fn exploration_strategy_display_targeted_empty() {
    let s = ExplorationStrategy::TargetedRace { race_ids: vec![] };
    assert_eq!(s.to_string(), "targeted_race()");
}

#[test]
fn exploration_strategy_display_targeted_multiple() {
    let s = ExplorationStrategy::TargetedRace {
        race_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    assert_eq!(s.to_string(), "targeted_race(a,b,c)");
}

// -- Debug output presence --

#[test]
fn exploration_report_debug_not_empty() {
    let report = ExplorationReport {
        exploration_id: "dbg".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    let dbg = format!("{report:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ExplorationReport"));
}

// -- InvariantChecker clone equality --

#[test]
fn invariant_checker_clone_equality() {
    let checkers = [
        InvariantChecker::NoCompletedAndFaulted,
        InvariantChecker::AllTasksTerminal,
        InvariantChecker::FaultAfterCompletionForbidden,
        InvariantChecker::ForbiddenEventPattern {
            action: "x".to_string(),
            outcome: "y".to_string(),
        },
    ];
    for c in &checkers {
        assert_eq!(*c, c.clone());
    }
}

// -- LabEvent serde roundtrip --

#[test]
fn lab_event_serde_roundtrip() {
    let ev = LabEvent {
        virtual_time: 100,
        step_index: 3,
        action: "run_task".to_string(),
        task_id: Some(7),
        region_id: Some("r-42".to_string()),
        outcome: "completed".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LabEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// -- Verdict serde roundtrip --

#[test]
fn verdict_serde_roundtrip_all_variants() {
    let variants = vec![
        Verdict::Pass,
        Verdict::Fail {
            reason: "broken".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// -- FaultKind all variants through ScenarioAction serde --

#[test]
fn scenario_action_inject_fault_all_kinds_serde() {
    let faults = [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ];
    for fault in &faults {
        let action = ScenarioAction::InjectFault {
            task_index: 0,
            fault: fault.clone(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }
}

// -- Deterministic replay via random walk --

#[test]
fn exploration_deterministic_replay_random_walk() {
    let scenario = Scenario {
        task_count: 3,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::RunTask { task_index: 2 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 50 },
        ],
        seed: 77,
    };
    let catalog = RaceSurfaceCatalog::default_catalog();
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 999,
        iterations: 20,
    };
    let explorer = InterleavingExplorer::new(
        catalog,
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
        ],
    );
    let r1 = explorer.explore(&scenario, &strategy, "replay-a");
    let r2 = explorer.explore(&scenario, &strategy, "replay-a");
    assert_eq!(r1.total_explored, r2.total_explored);
    assert_eq!(r1.failures.len(), r2.failures.len());
    assert_eq!(r1.race_surfaces_covered, r2.race_surfaces_covered);
    for (f1, f2) in r1.failures.iter().zip(r2.failures.iter()) {
        assert_eq!(f1.violations, f2.violations);
        assert_eq!(f1.transcript, f2.transcript);
    }
}

// -- OperationType ord all variants in order --

#[test]
fn operation_type_ord_all_variants_in_order() {
    let variants = [
        OperationType::CheckpointWrite,
        OperationType::RevocationPropagation,
        OperationType::PolicyUpdate,
        OperationType::EvidenceEmission,
        OperationType::RegionClose,
        OperationType::ObligationCommit,
        OperationType::TaskCompletion,
        OperationType::FaultInjection,
        OperationType::CancelInjection,
        OperationType::TimeAdvance,
    ];
    for window in variants.windows(2) {
        assert!(
            window[0] <= window[1],
            "{:?} should <= {:?}",
            window[0],
            window[1]
        );
    }
}

// -- AllTasksTerminal with faulted state --

#[test]
fn all_tasks_terminal_holds_on_faulted_with_fault_prefix() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(
        1,
        "inject_fault",
        Some(1),
        "fault=channel_disconnect",
    )]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

// -- NoCompletedAndFaulted violation description --

#[test]
fn no_completed_and_faulted_violation_description() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![
        make_event(1, "complete_task", Some(1), "completed"),
        make_event(2, "inject_fault", Some(1), "fault=panic"),
    ]);
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("task 1"));
            assert!(description.contains("completed"));
            assert!(description.contains("faulted"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

// -- AllTasksTerminal violation description --

#[test]
fn all_tasks_terminal_violation_description() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("task 1"));
            assert!(description.contains("non-terminal"));
            assert!(description.contains("running"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}
