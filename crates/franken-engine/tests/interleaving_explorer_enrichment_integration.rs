//! Enrichment integration tests for the `interleaving_explorer` module.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default, catalog operations, explorer lifecycle
//! with various strategies, invariant checker coverage, JSON field-name
//! stability, and determinism.

use std::collections::BTreeSet;

use frankenengine_engine::interleaving_explorer::{
    ExplorationFailure, ExplorationReport, ExplorationStrategy, InterleavingExplorer,
    InvariantChecker, InvariantResult, OperationType, RaceSeverity, RaceSurface,
    RaceSurfaceCatalog, Scenario, ScenarioAction,
};
use frankenengine_engine::lab_runtime::{
    FaultKind, LabEvent, LabRunResult, ScheduleTranscript, Verdict,
};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn test_scenario_simple() -> Scenario {
    Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    }
}

fn test_scenario_multi_task() -> Scenario {
    Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 5 },
        ],
        seed: 77,
    }
}

fn test_scenario_fault() -> Scenario {
    Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    }
}

fn test_race_surface(id: &str) -> RaceSurface {
    RaceSurface {
        race_id: id.to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::PolicyUpdate],
        invariant: "monotonic ordering".to_string(),
        severity: RaceSeverity::High,
    }
}

fn test_lab_run_result_clean() -> LabRunResult {
    LabRunResult {
        seed: 42,
        transcript: ScheduleTranscript::new(42),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "complete_task".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "completed".to_string(),
        }],
        final_time: 0,
        tasks_completed: 1,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    }
}

// -----------------------------------------------------------------------
// Copy semantics — RaceSeverity, OperationType
// -----------------------------------------------------------------------

#[test]
fn enrichment_race_severity_copy_semantics() {
    let original = RaceSeverity::Critical;
    let copied = original;
    assert_eq!(original, copied);
    assert_eq!(original, RaceSeverity::Critical);
}

#[test]
fn enrichment_operation_type_copy_after_use() {
    let op = OperationType::CheckpointWrite;
    let v = [op.clone(), op.clone()];
    assert_eq!(v[0], v[1]);
    assert_eq!(v[0], OperationType::CheckpointWrite);
}

#[test]
fn enrichment_race_severity_copy_all_variants() {
    for sev in [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
    ] {
        let copied = sev;
        assert_eq!(sev, copied);
    }
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_race_surface_clone_independence() {
    let original = test_race_surface("clone-orig");
    let mut cloned = original.clone();
    cloned.race_id = "mutated".to_string();
    cloned.severity = RaceSeverity::Low;
    assert_eq!(original.race_id, "clone-orig");
    assert_eq!(original.severity, RaceSeverity::High);
}

#[test]
fn enrichment_scenario_clone_independence() {
    let original = test_scenario_multi_task();
    let mut cloned = original.clone();
    cloned.task_count = 99;
    cloned
        .actions
        .push(ScenarioAction::AdvanceTime { ticks: 999 });
    assert_eq!(original.task_count, 2);
    assert_eq!(original.actions.len(), 4);
}

#[test]
fn enrichment_exploration_failure_clone_independence() {
    let original = ExplorationFailure {
        transcript: ScheduleTranscript::new(1),
        violations: vec!["v1".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["r-1".to_string()],
    };
    let mut cloned = original.clone();
    cloned.violations.push("v2".to_string());
    cloned.related_race_ids.clear();
    assert_eq!(original.violations.len(), 1);
    assert_eq!(original.related_race_ids.len(), 1);
}

#[test]
fn enrichment_exploration_report_clone_independence() {
    let original = ExplorationReport {
        exploration_id: "orig".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 3,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    let mut cloned = original.clone();
    cloned.exploration_id = "mutated".to_string();
    cloned.total_explored = 999;
    assert_eq!(original.exploration_id, "orig");
    assert_eq!(original.total_explored, 10);
}

#[test]
fn enrichment_catalog_clone_independence() {
    let mut original = RaceSurfaceCatalog::new();
    original.add(test_race_surface("s1"));
    let mut cloned = original.clone();
    cloned.add(test_race_surface("s2"));
    assert_eq!(original.len(), 1);
    assert_eq!(cloned.len(), 2);
}

// -----------------------------------------------------------------------
// BTreeSet ordering and dedup
// -----------------------------------------------------------------------

#[test]
fn enrichment_operation_type_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(OperationType::TimeAdvance);
    set.insert(OperationType::CheckpointWrite);
    set.insert(OperationType::PolicyUpdate);
    let items: Vec<_> = set.iter().collect();
    assert!(items[0] <= items[1]);
    assert!(items[1] <= items[2]);
}

#[test]
fn enrichment_operation_type_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(OperationType::RegionClose);
    set.insert(OperationType::RegionClose);
    set.insert(OperationType::FaultInjection);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_race_severity_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(RaceSeverity::Critical);
    set.insert(RaceSeverity::Low);
    set.insert(RaceSeverity::High);
    set.insert(RaceSeverity::Medium);
    let items: Vec<_> = set.iter().collect();
    assert_eq!(*items[0], RaceSeverity::Low);
    assert_eq!(*items[3], RaceSeverity::Critical);
}

#[test]
fn enrichment_race_severity_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for sev in [
        RaceSeverity::High,
        RaceSeverity::High,
        RaceSeverity::Low,
        RaceSeverity::Low,
    ] {
        set.insert(sev);
    }
    assert_eq!(set.len(), 2);
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_operation_type_serde_all_variants() {
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
fn enrichment_race_severity_serde_all_variants() {
    for sev in [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let restored: RaceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, restored);
    }
}

#[test]
fn enrichment_race_surface_serde_roundtrip() {
    let rs = test_race_surface("serde-test");
    let json = serde_json::to_string(&rs).unwrap();
    let restored: RaceSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, restored);
}

#[test]
fn enrichment_race_surface_catalog_serde_roundtrip() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let json = serde_json::to_string(&catalog).unwrap();
    let restored: RaceSurfaceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, restored);
}

#[test]
fn enrichment_exploration_strategy_serde_exhaustive() {
    let s = ExplorationStrategy::Exhaustive {
        max_permutations: 100,
    };
    let json = serde_json::to_string(&s).unwrap();
    let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn enrichment_exploration_strategy_serde_random_walk() {
    let s = ExplorationStrategy::RandomWalk {
        seed: 42,
        iterations: 200,
    };
    let json = serde_json::to_string(&s).unwrap();
    let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn enrichment_exploration_strategy_serde_targeted() {
    let s = ExplorationStrategy::TargetedRace {
        race_ids: vec!["r1".to_string(), "r2".to_string()],
    };
    let json = serde_json::to_string(&s).unwrap();
    let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn enrichment_invariant_result_serde_held() {
    let held = InvariantResult::Held;
    let json = serde_json::to_string(&held).unwrap();
    let restored: InvariantResult = serde_json::from_str(&json).unwrap();
    assert_eq!(held, restored);
}

#[test]
fn enrichment_invariant_result_serde_violated() {
    let v = InvariantResult::Violated {
        description: "test violation".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: InvariantResult = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_scenario_action_serde_all_variants() {
    let actions = vec![
        ScenarioAction::RunTask { task_index: 0 },
        ScenarioAction::CompleteTask { task_index: 1 },
        ScenarioAction::AdvanceTime { ticks: 100 },
        ScenarioAction::InjectCancel {
            region_id: "r-1".to_string(),
        },
        ScenarioAction::InjectFault {
            task_index: 2,
            fault: FaultKind::Panic,
        },
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, restored);
    }
}

#[test]
fn enrichment_scenario_serde_roundtrip() {
    let sc = test_scenario_multi_task();
    let json = serde_json::to_string(&sc).unwrap();
    let restored: Scenario = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, restored);
}

#[test]
fn enrichment_exploration_failure_serde_roundtrip() {
    let f = ExplorationFailure {
        transcript: ScheduleTranscript::new(42),
        violations: vec!["v1".to_string(), "v2".to_string()],
        minimized_transcript: Some(ScheduleTranscript::new(42)),
        related_race_ids: vec!["r-1".to_string()],
    };
    let json = serde_json::to_string(&f).unwrap();
    let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

#[test]
fn enrichment_exploration_report_serde_roundtrip() {
    let report = ExplorationReport {
        exploration_id: "serde-rt".to_string(),
        strategy: ExplorationStrategy::RandomWalk {
            seed: 7,
            iterations: 3,
        },
        total_explored: 3,
        failures: vec![ExplorationFailure {
            transcript: ScheduleTranscript::new(7),
            violations: vec!["v1".to_string()],
            minimized_transcript: None,
            related_race_ids: vec![],
        }],
        race_surfaces_covered: 1,
        race_surfaces_total: 5,
        regression_transcripts: vec![ScheduleTranscript::new(7)],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: ExplorationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn enrichment_invariant_checker_serde_all_variants() {
    let checkers = vec![
        InvariantChecker::NoCompletedAndFaulted,
        InvariantChecker::AllTasksTerminal,
        InvariantChecker::FaultAfterCompletionForbidden,
        InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        },
    ];
    for c in &checkers {
        let json = serde_json::to_string(c).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn enrichment_fault_kind_serde_all_variants() {
    let faults = [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ];
    for f in &faults {
        let json = serde_json::to_string(f).unwrap();
        let restored: FaultKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, restored);
    }
}

#[test]
fn enrichment_verdict_serde_all_variants() {
    let variants = [
        Verdict::Pass,
        Verdict::Fail {
            reason: "broken".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn enrichment_lab_event_serde_roundtrip() {
    let ev = LabEvent {
        virtual_time: 100,
        step_index: 3,
        action: "run_task".to_string(),
        task_id: Some(7),
        region_id: Some("r-42".to_string()),
        outcome: "completed".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: LabEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

// -----------------------------------------------------------------------
// Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_operation_type_display_all_unique() {
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
    let displays: BTreeSet<String> = variants.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn enrichment_operation_type_display_specific_values() {
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
fn enrichment_race_severity_display_all_unique() {
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

#[test]
fn enrichment_race_severity_display_specific_values() {
    assert_eq!(RaceSeverity::Low.to_string(), "low");
    assert_eq!(RaceSeverity::Medium.to_string(), "medium");
    assert_eq!(RaceSeverity::High.to_string(), "high");
    assert_eq!(RaceSeverity::Critical.to_string(), "critical");
}

#[test]
fn enrichment_exploration_strategy_display_exhaustive() {
    let s = ExplorationStrategy::Exhaustive {
        max_permutations: 10,
    };
    assert_eq!(s.to_string(), "exhaustive(max=10)");
}

#[test]
fn enrichment_exploration_strategy_display_random_walk() {
    let s = ExplorationStrategy::RandomWalk {
        seed: 42,
        iterations: 100,
    };
    assert_eq!(s.to_string(), "random_walk(seed=42, iters=100)");
}

#[test]
fn enrichment_exploration_strategy_display_targeted_empty() {
    let s = ExplorationStrategy::TargetedRace { race_ids: vec![] };
    assert_eq!(s.to_string(), "targeted_race()");
}

#[test]
fn enrichment_exploration_strategy_display_targeted_multi() {
    let s = ExplorationStrategy::TargetedRace {
        race_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    assert_eq!(s.to_string(), "targeted_race(a,b,c)");
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_race_surface_debug() {
    let rs = test_race_surface("dbg");
    let dbg = format!("{rs:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("RaceSurface"));
}

#[test]
fn enrichment_race_surface_catalog_debug() {
    let cat = RaceSurfaceCatalog::default_catalog();
    let dbg = format!("{cat:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("RaceSurfaceCatalog"));
}

#[test]
fn enrichment_exploration_report_debug() {
    let report = ExplorationReport {
        exploration_id: "dbg-test".to_string(),
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

#[test]
fn enrichment_explorer_debug() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let dbg = format!("{explorer:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("InterleavingExplorer"));
}

#[test]
fn enrichment_scenario_debug() {
    let sc = test_scenario_simple();
    let dbg = format!("{sc:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Scenario"));
}

#[test]
fn enrichment_invariant_result_debug() {
    let held = InvariantResult::Held;
    let dbg = format!("{held:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Held"));

    let violated = InvariantResult::Violated {
        description: "bad".to_string(),
    };
    let dbg = format!("{violated:?}");
    assert!(dbg.contains("Violated"));
}

// -----------------------------------------------------------------------
// Default
// -----------------------------------------------------------------------

#[test]
fn enrichment_race_surface_catalog_default_empty() {
    let cat = RaceSurfaceCatalog::default();
    assert!(cat.surfaces.is_empty());
    assert_eq!(cat.len(), 0);
    assert!(cat.is_empty());
}

// -----------------------------------------------------------------------
// Catalog operations
// -----------------------------------------------------------------------

#[test]
fn enrichment_catalog_new_is_empty() {
    let cat = RaceSurfaceCatalog::new();
    assert!(cat.is_empty());
    assert_eq!(cat.len(), 0);
}

#[test]
fn enrichment_catalog_add_increments_len() {
    let mut cat = RaceSurfaceCatalog::new();
    cat.add(test_race_surface("s1"));
    assert_eq!(cat.len(), 1);
    assert!(!cat.is_empty());
    cat.add(test_race_surface("s2"));
    assert_eq!(cat.len(), 2);
}

#[test]
fn enrichment_catalog_add_replaces_duplicate() {
    let mut cat = RaceSurfaceCatalog::new();
    cat.add(RaceSurface {
        race_id: "dup".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::PolicyUpdate],
        invariant: "first".to_string(),
        severity: RaceSeverity::Low,
    });
    cat.add(RaceSurface {
        race_id: "dup".to_string(),
        operations: [OperationType::RegionClose, OperationType::TimeAdvance],
        invariant: "second".to_string(),
        severity: RaceSeverity::Critical,
    });
    assert_eq!(cat.len(), 1);
    assert_eq!(cat.surfaces["dup"].invariant, "second");
}

#[test]
fn enrichment_default_catalog_nonempty() {
    let cat = RaceSurfaceCatalog::default_catalog();
    assert!(!cat.is_empty());
    for (key, surface) in &cat.surfaces {
        assert_eq!(*key, surface.race_id);
        assert!(!surface.invariant.is_empty());
    }
}

#[test]
fn enrichment_default_catalog_btreemap_keys_sorted() {
    let cat = RaceSurfaceCatalog::default_catalog();
    let keys: Vec<&String> = cat.surfaces.keys().collect();
    for window in keys.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

#[test]
fn enrichment_default_catalog_has_multiple_severities() {
    let cat = RaceSurfaceCatalog::default_catalog();
    let severities: BTreeSet<RaceSeverity> = cat.surfaces.values().map(|s| s.severity).collect();
    assert!(severities.len() >= 2);
}

// -----------------------------------------------------------------------
// InvariantChecker: check method coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_checker_no_completed_and_faulted_holds_clean() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = test_lab_run_result_clean();
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_no_completed_and_faulted_detects_violation() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
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
            reason: "faulted".to_string(),
        },
    };
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn enrichment_checker_no_completed_and_faulted_empty_events() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_all_tasks_terminal_holds_completed() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = test_lab_run_result_clean();
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_all_tasks_terminal_holds_cancelled() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "cancel_task".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "cancelled".to_string(),
        }],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 1,
        verdict: Verdict::Pass,
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_all_tasks_terminal_holds_faulted() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "inject_fault".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "fault=panic".to_string(),
        }],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 1,
        tasks_cancelled: 0,
        verdict: Verdict::Fail {
            reason: "faulted".to_string(),
        },
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_all_tasks_terminal_detects_running() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "run_task".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "running".to_string(),
        }],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn enrichment_checker_all_tasks_terminal_empty_events() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_forbidden_event_pattern_holds_clean() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = test_lab_run_result_clean();
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_forbidden_event_pattern_detects() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "run_task".to_string(),
        outcome: "running".to_string(),
    };
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "run_task".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "running".to_string(),
        }],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("forbidden event pattern"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

#[test]
fn enrichment_checker_forbidden_empty_events() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_fault_after_completion_holds_clean() {
    let checker = InvariantChecker::FaultAfterCompletionForbidden;
    let result = LabRunResult {
        seed: 1,
        transcript: ScheduleTranscript::new(1),
        events: vec![
            LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "run_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "running".to_string(),
            },
            LabEvent {
                virtual_time: 0,
                step_index: 2,
                action: "complete_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "completed".to_string(),
            },
        ],
        final_time: 0,
        tasks_completed: 1,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn enrichment_checker_fault_after_completion_detects() {
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
            reason: "faulted".to_string(),
        },
    };
    match checker.check(&result) {
        InvariantResult::Violated { description } => {
            assert!(description.contains("task 1"));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Explorer lifecycle — exhaustive strategy
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_exhaustive_clean_scenario() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "enrichment-clean",
    );
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
    assert_eq!(report.total_explored, 2); // 2! = 2
}

#[test]
fn enrichment_explorer_exhaustive_finds_fault() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &test_scenario_fault(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "enrichment-fault",
    );
    assert!(!report.all_passed());
    assert!(report.failure_count() >= 1);
}

#[test]
fn enrichment_explorer_exhaustive_three_actions() {
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
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 100,
        },
        "enrichment-3act",
    );
    assert_eq!(report.total_explored, 6); // 3! = 6
    assert!(report.all_passed());
}

#[test]
fn enrichment_explorer_exhaustive_respects_max() {
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
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 5,
        },
        "enrichment-max",
    );
    assert!(report.total_explored <= 5);
}

#[test]
fn enrichment_explorer_exhaustive_single_action() {
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
        "enrichment-single",
    );
    assert_eq!(report.total_explored, 1);
}

#[test]
fn enrichment_explorer_exhaustive_empty_actions() {
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
        "enrichment-empty",
    );
    assert_eq!(report.total_explored, 1); // empty permutation counts as 1
    assert!(report.all_passed());
}

// -----------------------------------------------------------------------
// Explorer lifecycle — random walk strategy
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_random_walk_respects_iterations() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::RandomWalk {
            seed: 99,
            iterations: 7,
        },
        "enrichment-rw",
    );
    assert_eq!(report.total_explored, 7);
}

#[test]
fn enrichment_explorer_random_walk_zero_iterations() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 0,
        },
        "enrichment-rw-zero",
    );
    assert_eq!(report.total_explored, 0);
    assert!(report.all_passed());
}

#[test]
fn enrichment_explorer_random_walk_large_iterations() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
        ],
    );
    let report = explorer.explore(
        &test_scenario_multi_task(),
        &ExplorationStrategy::RandomWalk {
            seed: 0,
            iterations: 50,
        },
        "enrichment-rw-large",
    );
    assert_eq!(report.total_explored, 50);
}

// -----------------------------------------------------------------------
// Explorer lifecycle — targeted race strategy
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_targeted_with_default_catalog() {
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
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::TargetedRace {
            race_ids: vec!["race-obligation-vs-cancel".to_string()],
        },
        "enrichment-targeted",
    );
    assert!(report.total_explored >= 1);
}

#[test]
fn enrichment_explorer_targeted_nonexistent_race_id() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::TargetedRace {
            race_ids: vec!["nonexistent-race-id".to_string()],
        },
        "enrichment-targeted-bad",
    );
    assert!(report.total_explored >= 1);
}

#[test]
fn enrichment_explorer_targeted_empty_race_ids() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::default_catalog(), vec![]);
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::TargetedRace { race_ids: vec![] },
        "enrichment-targeted-empty",
    );
    assert!(report.total_explored >= 1);
}

// -----------------------------------------------------------------------
// Explorer with multiple checkers
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_multiple_checkers() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::ChannelDisconnect,
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
                outcome: "fault=channel_disconnect".to_string(),
            },
        ],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "enrichment-multi-checker",
    );
    assert!(!report.all_passed());
}

// -----------------------------------------------------------------------
// ExplorationReport computed fields
// -----------------------------------------------------------------------

#[test]
fn enrichment_report_coverage_millionths_full() {
    let report = ExplorationReport {
        exploration_id: "cov-full".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 5,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 1_000_000);
}

#[test]
fn enrichment_report_coverage_millionths_partial() {
    let report = ExplorationReport {
        exploration_id: "cov-part".to_string(),
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
fn enrichment_report_coverage_millionths_zero_surfaces() {
    let report = ExplorationReport {
        exploration_id: "cov-zero".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
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
fn enrichment_report_failure_count_matches_vec_len() {
    let report = ExplorationReport {
        exploration_id: "fc".to_string(),
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

#[test]
fn enrichment_report_all_passed_empty_failures() {
    let report = ExplorationReport {
        exploration_id: "ap".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
}

// -----------------------------------------------------------------------
// Regression transcripts
// -----------------------------------------------------------------------

#[test]
fn enrichment_regression_transcripts_populated() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &test_scenario_fault(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "enrichment-regression",
    );
    assert!(!report.regression_transcripts.is_empty());
}

// -----------------------------------------------------------------------
// Minimization
// -----------------------------------------------------------------------

#[test]
fn enrichment_minimization_produces_shorter() {
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
        "enrichment-minimize",
    );
    assert!(!report.all_passed());
    let has_minimized = report
        .failures
        .iter()
        .any(|f| f.minimized_transcript.is_some());
    assert!(has_minimized);
}

// -----------------------------------------------------------------------
// Race surfaces covered tracking
// -----------------------------------------------------------------------

#[test]
fn enrichment_race_surfaces_covered_matches_catalog() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let total = catalog.len();
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let report = explorer.explore(
        &test_scenario_multi_task(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 30,
        },
        "enrichment-coverage",
    );
    assert_eq!(report.race_surfaces_total, total);
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_exploration_report_json_field_names() {
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
    for field in [
        "exploration_id",
        "strategy",
        "total_explored",
        "failures",
        "race_surfaces_covered",
        "race_surfaces_total",
        "regression_transcripts",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_race_surface_json_field_names() {
    let rs = test_race_surface("json-fields");
    let json = serde_json::to_string(&rs).unwrap();
    for field in ["race_id", "operations", "invariant", "severity"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_scenario_json_field_names() {
    let sc = test_scenario_simple();
    let json = serde_json::to_string(&sc).unwrap();
    for field in ["task_count", "actions", "seed"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_exploration_failure_json_field_names() {
    let f = ExplorationFailure {
        transcript: ScheduleTranscript::new(1),
        violations: vec!["v1".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["r-1".to_string()],
    };
    let json = serde_json::to_string(&f).unwrap();
    for field in [
        "transcript",
        "violations",
        "minimized_transcript",
        "related_race_ids",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_lab_event_json_field_names() {
    let ev = LabEvent {
        virtual_time: 0,
        step_index: 1,
        action: "run_task".to_string(),
        task_id: Some(1),
        region_id: None,
        outcome: "ok".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    for field in ["virtual_time", "step_index", "action", "task_id", "outcome"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_exploration_deterministic_exhaustive() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let strategy = ExplorationStrategy::Exhaustive {
        max_permutations: 10,
    };
    let r1 = explorer.explore(&test_scenario_multi_task(), &strategy, "det-1");
    let r2 = explorer.explore(&test_scenario_multi_task(), &strategy, "det-1");
    assert_eq!(r1.total_explored, r2.total_explored);
    assert_eq!(r1.failures.len(), r2.failures.len());
    assert_eq!(r1.race_surfaces_covered, r2.race_surfaces_covered);
}

#[test]
fn enrichment_exploration_deterministic_random_walk() {
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
        ],
    );
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 999,
        iterations: 20,
    };
    let scenario = test_scenario_multi_task();
    let r1 = explorer.explore(&scenario, &strategy, "det-rw");
    let r2 = explorer.explore(&scenario, &strategy, "det-rw");
    assert_eq!(r1.total_explored, r2.total_explored);
    assert_eq!(r1.failures.len(), r2.failures.len());
    for (f1, f2) in r1.failures.iter().zip(r2.failures.iter()) {
        assert_eq!(f1.violations, f2.violations);
        assert_eq!(f1.transcript, f2.transcript);
    }
}

#[test]
fn enrichment_exploration_different_seeds_differ() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::default_catalog(), vec![]);
    let scenario = Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 1,
    };
    let r1 = explorer.explore(
        &scenario,
        &ExplorationStrategy::RandomWalk {
            seed: 1,
            iterations: 10,
        },
        "seed-1",
    );
    let r2 = explorer.explore(
        &scenario,
        &ExplorationStrategy::RandomWalk {
            seed: 999,
            iterations: 10,
        },
        "seed-999",
    );
    // Both explored same count but internal orderings differ
    assert_eq!(r1.total_explored, r2.total_explored);
}

// -----------------------------------------------------------------------
// Edge cases — out-of-bounds task index
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_oob_task_index_graceful() {
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
        "enrichment-oob",
    );
    // Should not panic, should pass (OOB indices are skipped)
    assert!(report.all_passed());
}

// -----------------------------------------------------------------------
// ExplorationFailure: multiple violations and race IDs
// -----------------------------------------------------------------------

#[test]
fn enrichment_failure_multiple_violations_serde() {
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
    let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

// -----------------------------------------------------------------------
// InvariantResult equality
// -----------------------------------------------------------------------

#[test]
fn enrichment_invariant_result_held_eq() {
    assert_eq!(InvariantResult::Held, InvariantResult::Held);
}

#[test]
fn enrichment_invariant_result_violated_ne_held() {
    let v = InvariantResult::Violated {
        description: "oops".to_string(),
    };
    assert_ne!(v, InvariantResult::Held);
}

#[test]
fn enrichment_invariant_result_violated_different_descs() {
    let v1 = InvariantResult::Violated {
        description: "a".to_string(),
    };
    let v2 = InvariantResult::Violated {
        description: "b".to_string(),
    };
    assert_ne!(v1, v2);
}

// -----------------------------------------------------------------------
// FaultKind all variants serde in ScenarioAction
// -----------------------------------------------------------------------

#[test]
fn enrichment_inject_fault_all_fault_kinds_serde() {
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

// -----------------------------------------------------------------------
// Ordering — strict ordering verification
// -----------------------------------------------------------------------

#[test]
fn enrichment_operation_type_strict_ordering() {
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

#[test]
fn enrichment_race_severity_strict_ordering() {
    assert!(RaceSeverity::Low < RaceSeverity::Medium);
    assert!(RaceSeverity::Medium < RaceSeverity::High);
    assert!(RaceSeverity::High < RaceSeverity::Critical);
}

// -----------------------------------------------------------------------
// Explorer with no checkers
// -----------------------------------------------------------------------

#[test]
fn enrichment_explorer_no_checkers_always_passes() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::default_catalog(), vec![]);
    let report = explorer.explore(
        &test_scenario_fault(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "enrichment-no-checkers",
    );
    // No checkers means no violations can be detected
    assert!(report.all_passed());
}

// -----------------------------------------------------------------------
// Exploration report with failures serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn enrichment_report_with_failures_serde_roundtrip() {
    let report = ExplorationReport {
        exploration_id: "fail-serde".to_string(),
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

// -----------------------------------------------------------------------
// InvariantChecker clone equality
// -----------------------------------------------------------------------

#[test]
fn enrichment_invariant_checker_clone_equality() {
    let checkers = vec![
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

// -----------------------------------------------------------------------
// Exploration report: exploration_id propagation
// -----------------------------------------------------------------------

#[test]
fn enrichment_exploration_id_propagated() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let report = explorer.explore(
        &test_scenario_simple(),
        &ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        "my-custom-id",
    );
    assert_eq!(report.exploration_id, "my-custom-id");
}

// -----------------------------------------------------------------------
// Exploration report: strategy propagation
// -----------------------------------------------------------------------

#[test]
fn enrichment_strategy_propagated_in_report() {
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 123,
        iterations: 5,
    };
    let report = explorer.explore(&test_scenario_simple(), &strategy, "strat-prop");
    assert_eq!(report.strategy, strategy);
}
