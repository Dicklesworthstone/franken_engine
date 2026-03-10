//! Integration tests for migration_contract (bd-29s).

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

use frankenengine_engine::migration_contract::{
    AppliedMigrationRecord, CutoverType, DryRunResult, MigrationContractError,
    MigrationDeclaration, MigrationEvent, MigrationRunner, MigrationState, MigrationStep,
    ObjectClass, VerificationResult,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
    MigrationDeclaration {
        migration_id: id.to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: vec![ObjectClass::SerializationSchema, ObjectClass::KeyFormat],
        cutover_type: cutover,
        description: format!("integration test migration {id}"),
        compatible_across: vec!["wire_format".to_string()],
        incompatible_across: vec!["storage_format".to_string()],
        transition_end_tick: if cutover == CutoverType::SoftMigration {
            Some(500)
        } else {
            None
        },
    }
}

fn pass_dry_run(mid: &str) -> DryRunResult {
    DryRunResult {
        migration_id: mid.to_string(),
        total_objects: 200,
        convertible: 200,
        unconvertible: 0,
        details: Vec::new(),
    }
}

fn pass_verify(mid: &str) -> VerificationResult {
    VerificationResult {
        migration_id: mid.to_string(),
        objects_checked: 200,
        discrepancies: 0,
        details: Vec::new(),
    }
}

fn run_full(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
    runner
        .declare(declaration(mid, cutover), "trace-int")
        .unwrap();
    runner.dry_run(mid, pass_dry_run(mid), "trace-int").unwrap();
    runner.create_checkpoint(mid, 100, "trace-int").unwrap();
    runner.complete_execution(mid, 200, "trace-int").unwrap();
    runner.verify(mid, pass_verify(mid), "trace-int").unwrap();
    runner.commit(mid, "trace-int").unwrap();
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_hard_cutover_lifecycle() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(10);
    run_full(&mut runner, "hc-1", CutoverType::HardCutover);

    assert_eq!(runner.state("hc-1"), Some(MigrationState::Committed));
    assert_eq!(runner.applied_count(), 1);

    let rec = &runner.applied_migrations()[0];
    assert_eq!(rec.migration_id, "hc-1");
    assert_eq!(rec.cutover_type, CutoverType::HardCutover);
    assert_eq!(rec.from_version, "v1");
    assert_eq!(rec.to_version, "v2");
}

#[test]
fn full_soft_migration_lifecycle() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "sm-1", CutoverType::SoftMigration);

    assert_eq!(runner.state("sm-1"), Some(MigrationState::Committed));

    // Old format still accepted during transition window.
    runner.set_tick(100);
    assert_eq!(runner.check_soft_migration_window("sm-1"), Some(true));

    // Old format rejected after transition window ends.
    runner.set_tick(500);
    assert_eq!(runner.check_soft_migration_window("sm-1"), Some(false));
}

#[test]
fn full_parallel_run_lifecycle() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "pr-1", CutoverType::ParallelRun);

    assert_eq!(runner.state("pr-1"), Some(MigrationState::Committed));
    assert_eq!(runner.applied_count(), 1);
}

// ---------------------------------------------------------------------------
// Format enforcement after hard cutover
// ---------------------------------------------------------------------------

#[test]
fn hard_cutover_rejects_old_format_for_affected_classes() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "hc-2", CutoverType::HardCutover);

    // Old format rejected for affected class.
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::OldFormatRejected { .. }
    ));

    // New format accepted.
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
        .unwrap();

    // Unaffected class still accepts old format.
    runner
        .check_format_acceptance(ObjectClass::TokenFormat, "v1")
        .unwrap();
}

// ---------------------------------------------------------------------------
// Rollback scenarios
// ---------------------------------------------------------------------------

#[test]
fn rollback_from_every_non_terminal_non_declared_state() {
    // Rollback from DryRunPassed
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("rb-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("rb-1", pass_dry_run("rb-1"), "t").unwrap();
    runner.rollback("rb-1", "t").unwrap();
    assert_eq!(runner.state("rb-1"), Some(MigrationState::RolledBack));

    // Rollback from Executing
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("rb-2", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("rb-2", pass_dry_run("rb-2"), "t").unwrap();
    runner.create_checkpoint("rb-2", 1, "t").unwrap();
    runner.rollback("rb-2", "t").unwrap();
    assert_eq!(runner.state("rb-2"), Some(MigrationState::RolledBack));

    // Rollback from Verifying
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("rb-3", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("rb-3", pass_dry_run("rb-3"), "t").unwrap();
    runner.create_checkpoint("rb-3", 1, "t").unwrap();
    runner.complete_execution("rb-3", 100, "t").unwrap();
    runner.rollback("rb-3", "t").unwrap();
    assert_eq!(runner.state("rb-3"), Some(MigrationState::RolledBack));

    // Rollback from Verified
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("rb-4", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("rb-4", pass_dry_run("rb-4"), "t").unwrap();
    runner.create_checkpoint("rb-4", 1, "t").unwrap();
    runner.complete_execution("rb-4", 100, "t").unwrap();
    runner.verify("rb-4", pass_verify("rb-4"), "t").unwrap();
    runner.rollback("rb-4", "t").unwrap();
    assert_eq!(runner.state("rb-4"), Some(MigrationState::RolledBack));
}

#[test]
fn rollback_blocked_from_terminal_and_declared() {
    // Cannot rollback from Declared.
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("blk-1", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(runner.rollback("blk-1", "t").is_err());

    // Cannot rollback from Committed.
    let mut runner2 = MigrationRunner::new();
    run_full(&mut runner2, "blk-2", CutoverType::HardCutover);
    assert!(runner2.rollback("blk-2", "t").is_err());
}

// ---------------------------------------------------------------------------
// Audit trail completeness
// ---------------------------------------------------------------------------

#[test]
fn audit_trail_covers_full_pipeline() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "audit-1", CutoverType::HardCutover);

    let events = runner.drain_events();
    assert!(events.len() >= 6);

    let names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(names.contains(&"migration_declared"));
    assert!(names.contains(&"dry_run_complete"));
    assert!(names.contains(&"checkpoint_created"));
    assert!(names.contains(&"execution_complete"));
    assert!(names.contains(&"verification_complete"));
    assert!(names.contains(&"migration_committed"));

    // All events have the correct component.
    assert!(events.iter().all(|e| e.component == "migration_contract"));
    // All events have trace_id set.
    assert!(events.iter().all(|e| !e.trace_id.is_empty()));
}

#[test]
fn rollback_events_in_audit_trail() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("rbe-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("rbe-1", pass_dry_run("rbe-1"), "t").unwrap();
    runner.create_checkpoint("rbe-1", 1, "t").unwrap();
    runner.rollback("rbe-1", "t").unwrap();

    let events = runner.drain_events();
    let names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(names.contains(&"rollback_started"));
    assert!(names.contains(&"rollback_complete"));
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_declaration() {
    let decl = declaration("serde-1", CutoverType::ParallelRun);
    let json = serde_json::to_string(&decl).unwrap();
    let de: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, de);
}

#[test]
fn serde_roundtrip_applied_record() {
    let rec = AppliedMigrationRecord {
        migration_id: "sr-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::HardCutover,
        affected_objects: vec![ObjectClass::KeyFormat, ObjectClass::TokenFormat],
        applied_at: DeterministicTimestamp(42),
        checkpoint_seq: 10,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let de: AppliedMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, de);
}

#[test]
fn serde_roundtrip_event_stream() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "evt-1", CutoverType::HardCutover);

    let events = runner.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let de: Vec<MigrationEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events, de);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_produces_identical_events() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full(&mut runner, "det-1", CutoverType::HardCutover);
        serde_json::to_string(&runner.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Chained migrations
// ---------------------------------------------------------------------------

#[test]
fn chained_migrations_v1_to_v2_to_v3() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);

    let mut d1 = declaration("chain-1", CutoverType::HardCutover);
    d1.from_version = "v1".to_string();
    d1.to_version = "v2".to_string();
    runner.declare(d1, "t").unwrap();
    runner
        .dry_run("chain-1", pass_dry_run("chain-1"), "t")
        .unwrap();
    runner.create_checkpoint("chain-1", 10, "t").unwrap();
    runner.complete_execution("chain-1", 100, "t").unwrap();
    runner
        .verify("chain-1", pass_verify("chain-1"), "t")
        .unwrap();
    runner.commit("chain-1", "t").unwrap();

    runner.set_tick(100);
    let mut d2 = declaration("chain-2", CutoverType::HardCutover);
    d2.from_version = "v2".to_string();
    d2.to_version = "v3".to_string();
    runner.declare(d2, "t").unwrap();
    runner
        .dry_run("chain-2", pass_dry_run("chain-2"), "t")
        .unwrap();
    runner.create_checkpoint("chain-2", 20, "t").unwrap();
    runner.complete_execution("chain-2", 100, "t").unwrap();
    runner
        .verify("chain-2", pass_verify("chain-2"), "t")
        .unwrap();
    runner.commit("chain-2", "t").unwrap();

    assert_eq!(runner.applied_count(), 2);
    assert_eq!(runner.applied_migrations()[0].to_version, "v2");
    assert_eq!(runner.applied_migrations()[1].to_version, "v3");

    // v1 rejected by first migration, v2 rejected by second.
    assert!(
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .is_err()
    );
    assert!(
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
            .is_err()
    );
    // v3 accepted.
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v3")
        .unwrap();
}

// ---------------------------------------------------------------------------
// Error codes stable
// ---------------------------------------------------------------------------

#[test]
fn error_codes_are_stable() {
    use frankenengine_engine::migration_contract::error_code;

    let cases: Vec<(MigrationContractError, &str)> = vec![
        (
            MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string(),
            },
            "MC_MIGRATION_NOT_FOUND",
        ),
        (
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            "MC_INVALID_TRANSITION",
        ),
        (
            MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 5,
                detail: "d".to_string(),
            },
            "MC_DRY_RUN_FAILED",
        ),
        (
            MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string(),
            },
            "MC_OLD_FORMAT_REJECTED",
        ),
        (
            MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            },
            "MC_DUPLICATE_MIGRATION",
        ),
        (
            MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            },
            "MC_ROLLBACK_FAILED",
        ),
        (
            MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "x".to_string(),
                discrepancy_count: 3,
            },
            "MC_PARALLEL_DISCREPANCY",
        ),
    ];

    for (err, expected) in &cases {
        assert_eq!(error_code(err), *expected, "error_code mismatch for {err}");
    }
}

// ---------------------------------------------------------------------------
// Migration step ordering
// ---------------------------------------------------------------------------

#[test]
fn migration_step_forward_pipeline_ordering() {
    let pipeline = MigrationStep::FORWARD_PIPELINE;
    assert_eq!(pipeline.len(), 5);
    assert_eq!(pipeline[0], MigrationStep::PreMigration);
    assert_eq!(pipeline[4], MigrationStep::Commit);

    // Each step's next() matches the pipeline order.
    for i in 0..pipeline.len() - 1 {
        assert_eq!(pipeline[i].next(), Some(pipeline[i + 1]));
    }
    assert_eq!(pipeline[4].next(), None);
}

// ---------------------------------------------------------------------------
// Summary accessor
// ---------------------------------------------------------------------------

#[test]
fn summary_reflects_all_migration_states() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("sum-1", CutoverType::HardCutover), "t")
        .unwrap();
    run_full(&mut runner, "sum-2", CutoverType::SoftMigration);

    let summary = runner.summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary["sum-1"], MigrationState::Declared);
    assert_eq!(summary["sum-2"], MigrationState::Committed);
}

// ---------------------------------------------------------------------------
// Object class exhaustive coverage
// ---------------------------------------------------------------------------

#[test]
fn all_object_classes_have_stable_display() {
    let expected = [
        "serialization_schema",
        "key_format",
        "token_format",
        "checkpoint_format",
        "revocation_format",
        "policy_structure",
        "evidence_format",
        "attestation_format",
    ];

    for (oc, exp) in ObjectClass::ALL.iter().zip(expected.iter()) {
        assert_eq!(oc.to_string(), *exp);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: enum serde, error display, state transitions
// ────────────────────────────────────────────────────────────

#[test]
fn cutover_type_serde_round_trip() {
    for ct in [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ] {
        let json = serde_json::to_string(&ct).unwrap();
        let recovered: CutoverType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, recovered);
    }
}

#[test]
fn migration_state_serde_round_trip() {
    for state in [
        MigrationState::Declared,
        MigrationState::DryRunPassed,
        MigrationState::Executing,
        MigrationState::Verifying,
        MigrationState::Verified,
        MigrationState::Committed,
        MigrationState::RolledBack,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let recovered: MigrationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, recovered);
    }
}

#[test]
fn object_class_serde_round_trip() {
    for oc in ObjectClass::ALL {
        let json = serde_json::to_string(&oc).unwrap();
        let recovered: ObjectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, recovered);
    }
}

#[test]
fn migration_contract_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(MigrationContractError::MigrationNotFound {
        migration_id: "x".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn migration_contract_error_display_all_unique() {
    let errors = [
        MigrationContractError::MigrationNotFound {
            migration_id: "a".to_string(),
        },
        MigrationContractError::DuplicateMigration {
            migration_id: "b".to_string(),
        },
        MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Committed,
        },
    ];
    let msgs: std::collections::BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(msgs.len(), errors.len());
}

#[test]
fn duplicate_declaration_rejected() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("dup-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .declare(declaration("dup-1", CutoverType::HardCutover), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::DuplicateMigration { .. }
    ));
}

#[test]
fn unknown_migration_returns_not_found() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.state("nonexistent"), None);
}

#[test]
fn dry_run_with_unconvertible_objects_fails() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("dry-fail", CutoverType::HardCutover), "t")
        .unwrap();
    let failed_dry = DryRunResult {
        migration_id: "dry-fail".to_string(),
        total_objects: 200,
        convertible: 190,
        unconvertible: 10,
        details: vec!["10 objects incompatible".to_string()],
    };
    let err = runner.dry_run("dry-fail", failed_dry, "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::DryRunFailed { .. }));
}

#[test]
fn migration_step_serde_round_trip() {
    for step in MigrationStep::FORWARD_PIPELINE {
        let json = serde_json::to_string(&step).unwrap();
        let recovered: MigrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, recovered);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: terminal states, declaration accessor, events accessor, verification failure
// ────────────────────────────────────────────────────────────

#[test]
fn migration_state_is_terminal_covers_all_terminal_and_non_terminal() {
    let terminal = [
        MigrationState::Committed,
        MigrationState::RolledBack,
        MigrationState::DryRunFailed,
    ];
    let non_terminal = [
        MigrationState::Declared,
        MigrationState::DryRunPassed,
        MigrationState::Executing,
        MigrationState::Verifying,
        MigrationState::Verified,
    ];
    for state in terminal {
        assert!(state.is_terminal(), "{state} should be terminal");
    }
    for state in non_terminal {
        assert!(!state.is_terminal(), "{state} should not be terminal");
    }
}

#[test]
fn declaration_accessor_returns_original_declaration() {
    let mut runner = MigrationRunner::new();
    let decl = declaration("acc-1", CutoverType::ParallelRun);
    runner.declare(decl.clone(), "t").unwrap();

    let retrieved = runner
        .declaration("acc-1")
        .expect("should find declaration");
    assert_eq!(retrieved.migration_id, "acc-1");
    assert_eq!(retrieved.cutover_type, CutoverType::ParallelRun);
    assert_eq!(retrieved.from_version, "v1");
    assert_eq!(retrieved.to_version, "v2");
    assert_eq!(retrieved.compatible_across, decl.compatible_across);
    assert_eq!(retrieved.incompatible_across, decl.incompatible_across);

    // Nonexistent migration returns None
    assert!(runner.declaration("nonexistent").is_none());
}

#[test]
fn events_accessor_returns_accumulated_events_without_drain() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("ev-1", CutoverType::HardCutover), "trace-ev")
        .unwrap();
    runner
        .dry_run("ev-1", pass_dry_run("ev-1"), "trace-ev")
        .unwrap();

    // events() should return accumulated events without consuming them
    let events_snapshot = runner.events().to_vec();
    assert!(events_snapshot.len() >= 2);
    assert!(
        events_snapshot
            .iter()
            .any(|e| e.event == "migration_declared")
    );
    assert!(
        events_snapshot
            .iter()
            .any(|e| e.event == "dry_run_complete")
    );

    // Calling events() again returns same data (not drained)
    assert_eq!(runner.events().len(), events_snapshot.len());

    // drain_events() consumes them
    let drained = runner.drain_events();
    assert_eq!(drained.len(), events_snapshot.len());
    assert!(runner.events().is_empty());
}

#[test]
fn verification_with_discrepancies_blocks_commit() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(declaration("vf-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("vf-1", pass_dry_run("vf-1"), "t").unwrap();
    runner.create_checkpoint("vf-1", 10, "t").unwrap();
    runner.complete_execution("vf-1", 100, "t").unwrap();

    let failed_verify = VerificationResult {
        migration_id: "vf-1".to_string(),
        objects_checked: 200,
        discrepancies: 7,
        details: vec!["7 objects mismatched after migration".to_string()],
    };
    assert!(!failed_verify.passed());

    let err = runner.verify("vf-1", failed_verify, "t").unwrap_err();
    assert!(
        matches!(
            err,
            MigrationContractError::VerificationFailed {
                discrepancy_count: 7,
                ..
            }
        ),
        "expected VerificationFailed with 7 discrepancies, got: {err}"
    );
}
