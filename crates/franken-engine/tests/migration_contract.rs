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

// ────────────────────────────────────────────────────────────────────────────
// Enrichment tests (~80 new tests)
// ────────────────────────────────────────────────────────────────────────────

// -- Helpers for enrichment -----------------------------------------------

fn decl_custom(
    id: &str,
    from: &str,
    to: &str,
    cutover: CutoverType,
    objects: Vec<ObjectClass>,
    end_tick: Option<u64>,
) -> MigrationDeclaration {
    MigrationDeclaration {
        migration_id: id.to_string(),
        from_version: from.to_string(),
        to_version: to.to_string(),
        affected_objects: objects,
        cutover_type: cutover,
        description: format!("enrichment migration {id}"),
        compatible_across: vec!["wire".to_string()],
        incompatible_across: vec!["storage".to_string()],
        transition_end_tick: end_tick,
    }
}

fn advance_to_executing(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
    runner
        .declare(declaration(mid, cutover), "t")
        .unwrap();
    runner.dry_run(mid, pass_dry_run(mid), "t").unwrap();
    runner.create_checkpoint(mid, 1, "t").unwrap();
}

fn advance_to_verifying(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
    advance_to_executing(runner, mid, cutover);
    runner.complete_execution(mid, 100, "t").unwrap();
}

fn advance_to_verified(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
    advance_to_verifying(runner, mid, cutover);
    runner.verify(mid, pass_verify(mid), "t").unwrap();
}

// ─── 1-10: State machine transition enforcement ─────────────────────────

#[test]
fn enrichment_cannot_dry_run_from_executing() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "e1", CutoverType::HardCutover);
    let err = runner.dry_run("e1", pass_dry_run("e1"), "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Executing, .. }));
}

#[test]
fn enrichment_cannot_checkpoint_from_executing() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "e2", CutoverType::HardCutover);
    let err = runner.create_checkpoint("e2", 99, "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Executing, .. }));
}

#[test]
fn enrichment_cannot_complete_execution_from_declared() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("e3", CutoverType::HardCutover), "t").unwrap();
    let err = runner.complete_execution("e3", 10, "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Declared, .. }));
}

#[test]
fn enrichment_cannot_verify_from_declared() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("e4", CutoverType::HardCutover), "t").unwrap();
    let err = runner.verify("e4", pass_verify("e4"), "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Declared, .. }));
}

#[test]
fn enrichment_cannot_commit_from_executing() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "e5", CutoverType::HardCutover);
    let err = runner.commit("e5", "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Executing, .. }));
}

#[test]
fn enrichment_cannot_commit_from_verifying() {
    let mut runner = MigrationRunner::new();
    advance_to_verifying(&mut runner, "e6", CutoverType::HardCutover);
    let err = runner.commit("e6", "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Verifying, .. }));
}

#[test]
fn enrichment_cannot_commit_from_dry_run_passed() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("e7", CutoverType::HardCutover), "t").unwrap();
    runner.dry_run("e7", pass_dry_run("e7"), "t").unwrap();
    let err = runner.commit("e7", "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::DryRunPassed, .. }));
}

#[test]
fn enrichment_rollback_from_dry_run_failed_is_blocked() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("e8", CutoverType::HardCutover), "t").unwrap();
    let failed = DryRunResult {
        migration_id: "e8".to_string(),
        total_objects: 50,
        convertible: 40,
        unconvertible: 10,
        details: vec!["bad".to_string()],
    };
    let _ = runner.dry_run("e8", failed, "t");
    assert_eq!(runner.state("e8"), Some(MigrationState::DryRunFailed));
    let err = runner.rollback("e8", "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { .. }));
}

#[test]
fn enrichment_rollback_from_rolled_back_is_blocked() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "e9", CutoverType::HardCutover);
    runner.rollback("e9", "t").unwrap();
    assert_eq!(runner.state("e9"), Some(MigrationState::RolledBack));
    let err = runner.rollback("e9", "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { .. }));
}

#[test]
fn enrichment_cannot_verify_from_executing() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "e10", CutoverType::HardCutover);
    let err = runner.verify("e10", pass_verify("e10"), "t").unwrap_err();
    assert!(matches!(err, MigrationContractError::InvalidTransition { from: MigrationState::Executing, .. }));
}

// ─── 11-20: Format enforcement edge cases ───────────────────────────────

#[test]
fn enrichment_soft_migration_check_format_acceptance_does_not_reject() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "sf1", CutoverType::SoftMigration);
    // Soft migrations do not reject via check_format_acceptance.
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v1").unwrap();
}

#[test]
fn enrichment_parallel_run_check_format_acceptance_does_not_reject() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "pr1", CutoverType::ParallelRun);
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v1").unwrap();
}

#[test]
fn enrichment_hard_cutover_rejects_all_affected_classes() {
    let objects = vec![
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyStructure,
    ];
    let mut runner = MigrationRunner::new();
    let d = decl_custom("hc-all", "v1", "v2", CutoverType::HardCutover, objects.clone(), None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("hc-all", pass_dry_run("hc-all"), "t").unwrap();
    runner.create_checkpoint("hc-all", 1, "t").unwrap();
    runner.complete_execution("hc-all", 50, "t").unwrap();
    runner.verify("hc-all", pass_verify("hc-all"), "t").unwrap();
    runner.commit("hc-all", "t").unwrap();

    for oc in &objects {
        assert!(runner.check_format_acceptance(*oc, "v1").is_err());
    }
}

#[test]
fn enrichment_hard_cutover_does_not_reject_unaffected_classes() {
    let objects = vec![ObjectClass::SerializationSchema];
    let mut runner = MigrationRunner::new();
    let d = decl_custom("hc-un", "v1", "v2", CutoverType::HardCutover, objects, None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("hc-un", pass_dry_run("hc-un"), "t").unwrap();
    runner.create_checkpoint("hc-un", 1, "t").unwrap();
    runner.complete_execution("hc-un", 50, "t").unwrap();
    runner.verify("hc-un", pass_verify("hc-un"), "t").unwrap();
    runner.commit("hc-un", "t").unwrap();

    // All classes NOT in affected_objects should be fine.
    let unaffected = [
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyStructure,
        ObjectClass::EvidenceFormat,
        ObjectClass::AttestationFormat,
    ];
    for oc in &unaffected {
        runner.check_format_acceptance(*oc, "v1").unwrap();
    }
}

#[test]
fn enrichment_hard_cutover_accepts_versions_other_than_from() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "hc-ov", CutoverType::HardCutover);
    // "v3" was never a from_version, so it should pass.
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v3").unwrap();
}

#[test]
fn enrichment_format_enforcement_stacks_across_chained_migrations() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d1 = decl_custom("ch1", "v1", "v2", CutoverType::HardCutover,
        vec![ObjectClass::SerializationSchema], None);
    runner.declare(d1, "t").unwrap();
    runner.dry_run("ch1", pass_dry_run("ch1"), "t").unwrap();
    runner.create_checkpoint("ch1", 1, "t").unwrap();
    runner.complete_execution("ch1", 50, "t").unwrap();
    runner.verify("ch1", pass_verify("ch1"), "t").unwrap();
    runner.commit("ch1", "t").unwrap();

    let d2 = decl_custom("ch2", "v2", "v3", CutoverType::HardCutover,
        vec![ObjectClass::SerializationSchema], None);
    runner.declare(d2, "t").unwrap();
    runner.dry_run("ch2", pass_dry_run("ch2"), "t").unwrap();
    runner.create_checkpoint("ch2", 2, "t").unwrap();
    runner.complete_execution("ch2", 50, "t").unwrap();
    runner.verify("ch2", pass_verify("ch2"), "t").unwrap();
    runner.commit("ch2", "t").unwrap();

    // Both v1 and v2 should be rejected.
    assert!(runner.check_format_acceptance(ObjectClass::SerializationSchema, "v1").is_err());
    assert!(runner.check_format_acceptance(ObjectClass::SerializationSchema, "v2").is_err());
    // Only v3 passes.
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v3").unwrap();
}

#[test]
fn enrichment_empty_affected_objects_hard_cutover_rejects_nothing() {
    let mut runner = MigrationRunner::new();
    let d = decl_custom("hc-empty", "v1", "v2", CutoverType::HardCutover, vec![], None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("hc-empty", pass_dry_run("hc-empty"), "t").unwrap();
    runner.create_checkpoint("hc-empty", 1, "t").unwrap();
    runner.complete_execution("hc-empty", 0, "t").unwrap();
    runner.verify("hc-empty", pass_verify("hc-empty"), "t").unwrap();
    runner.commit("hc-empty", "t").unwrap();

    for oc in ObjectClass::ALL {
        runner.check_format_acceptance(oc, "v1").unwrap();
    }
}

#[test]
fn enrichment_format_check_on_uncommitted_migration_passes() {
    let mut runner = MigrationRunner::new();
    advance_to_verified(&mut runner, "fcu", CutoverType::HardCutover);
    // Not yet committed, so format check should pass.
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v1").unwrap();
}

#[test]
fn enrichment_all_eight_object_classes_individually_enforced() {
    for oc in ObjectClass::ALL {
        let mut runner = MigrationRunner::new();
        let mid = format!("oc-{oc}");
        let d = decl_custom(&mid, "v1", "v2", CutoverType::HardCutover, vec![oc], None);
        runner.declare(d, "t").unwrap();
        runner.dry_run(&mid, pass_dry_run(&mid), "t").unwrap();
        runner.create_checkpoint(&mid, 1, "t").unwrap();
        runner.complete_execution(&mid, 10, "t").unwrap();
        runner.verify(&mid, pass_verify(&mid), "t").unwrap();
        runner.commit(&mid, "t").unwrap();
        assert!(runner.check_format_acceptance(oc, "v1").is_err());
        runner.check_format_acceptance(oc, "v2").unwrap();
    }
}

// ─── 21-30: Soft migration window edge cases ────────────────────────────

#[test]
fn enrichment_soft_window_exactly_at_end_tick_is_closed() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d = decl_custom("sw1", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], Some(100));
    runner.declare(d, "t").unwrap();
    runner.dry_run("sw1", pass_dry_run("sw1"), "t").unwrap();
    runner.create_checkpoint("sw1", 1, "t").unwrap();
    runner.complete_execution("sw1", 10, "t").unwrap();
    runner.verify("sw1", pass_verify("sw1"), "t").unwrap();
    runner.commit("sw1", "t").unwrap();

    runner.set_tick(100);
    // At exactly transition_end_tick, current_tick < end_tick is false.
    assert_eq!(runner.check_soft_migration_window("sw1"), Some(false));
}

#[test]
fn enrichment_soft_window_one_before_end_is_open() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d = decl_custom("sw2", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], Some(100));
    runner.declare(d, "t").unwrap();
    runner.dry_run("sw2", pass_dry_run("sw2"), "t").unwrap();
    runner.create_checkpoint("sw2", 1, "t").unwrap();
    runner.complete_execution("sw2", 10, "t").unwrap();
    runner.verify("sw2", pass_verify("sw2"), "t").unwrap();
    runner.commit("sw2", "t").unwrap();

    runner.set_tick(99);
    assert_eq!(runner.check_soft_migration_window("sw2"), Some(true));
}

#[test]
fn enrichment_soft_window_check_on_hard_cutover_returns_none() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "sw3", CutoverType::HardCutover);
    assert_eq!(runner.check_soft_migration_window("sw3"), None);
}

#[test]
fn enrichment_soft_window_check_on_parallel_run_returns_none() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "sw4", CutoverType::ParallelRun);
    assert_eq!(runner.check_soft_migration_window("sw4"), None);
}

#[test]
fn enrichment_soft_window_check_on_nonexistent_returns_none() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.check_soft_migration_window("no-such"), None);
}

#[test]
fn enrichment_soft_window_before_commit_returns_true() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d = decl_custom("sw5", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], Some(100));
    runner.declare(d, "t").unwrap();
    // Not committed yet.
    runner.set_tick(200);
    assert_eq!(runner.check_soft_migration_window("sw5"), Some(true));
}

#[test]
fn enrichment_soft_window_at_tick_zero_committed_at_zero() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d = decl_custom("sw6", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], Some(1));
    runner.declare(d, "t").unwrap();
    runner.dry_run("sw6", pass_dry_run("sw6"), "t").unwrap();
    runner.create_checkpoint("sw6", 1, "t").unwrap();
    runner.complete_execution("sw6", 10, "t").unwrap();
    runner.verify("sw6", pass_verify("sw6"), "t").unwrap();
    runner.commit("sw6", "t").unwrap();

    // At tick 0, 0 < 1 => window open.
    assert_eq!(runner.check_soft_migration_window("sw6"), Some(true));
    runner.set_tick(1);
    assert_eq!(runner.check_soft_migration_window("sw6"), Some(false));
}

#[test]
fn enrichment_soft_migration_no_end_tick_returns_none_after_commit() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    // Construct a soft migration with no transition_end_tick.
    let d = decl_custom("sw7", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("sw7", pass_dry_run("sw7"), "t").unwrap();
    runner.create_checkpoint("sw7", 1, "t").unwrap();
    runner.complete_execution("sw7", 10, "t").unwrap();
    runner.verify("sw7", pass_verify("sw7"), "t").unwrap();
    runner.commit("sw7", "t").unwrap();

    // With no end tick, `transition_end_tick?` returns None.
    assert_eq!(runner.check_soft_migration_window("sw7"), None);
}

#[test]
fn enrichment_soft_window_large_tick_values() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    let d = decl_custom("sw8", "v1", "v2", CutoverType::SoftMigration,
        vec![ObjectClass::SerializationSchema], Some(u64::MAX));
    runner.declare(d, "t").unwrap();
    runner.dry_run("sw8", pass_dry_run("sw8"), "t").unwrap();
    runner.create_checkpoint("sw8", 1, "t").unwrap();
    runner.complete_execution("sw8", 10, "t").unwrap();
    runner.verify("sw8", pass_verify("sw8"), "t").unwrap();
    runner.commit("sw8", "t").unwrap();

    runner.set_tick(u64::MAX - 1);
    assert_eq!(runner.check_soft_migration_window("sw8"), Some(true));

    runner.set_tick(u64::MAX);
    assert_eq!(runner.check_soft_migration_window("sw8"), Some(false));
}

#[test]
fn enrichment_soft_window_progression_through_time() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "sw9", CutoverType::SoftMigration);

    // Default declaration uses transition_end_tick = 500.
    for t in [0, 100, 200, 300, 400, 499] {
        runner.set_tick(t);
        assert_eq!(runner.check_soft_migration_window("sw9"), Some(true),
            "window should be open at tick {t}");
    }
    for t in [500, 501, 1000, u64::MAX] {
        runner.set_tick(t);
        assert_eq!(runner.check_soft_migration_window("sw9"), Some(false),
            "window should be closed at tick {t}");
    }
}

// ─── 31-40: DryRunResult and VerificationResult edge cases ──────────────

#[test]
fn enrichment_dry_run_zero_total_zero_unconvertible_passes() {
    let dr = DryRunResult {
        migration_id: "dr0".to_string(),
        total_objects: 0,
        convertible: 0,
        unconvertible: 0,
        details: vec![],
    };
    assert!(dr.passed());
}

#[test]
fn enrichment_dry_run_single_unconvertible_fails() {
    let dr = DryRunResult {
        migration_id: "dr1".to_string(),
        total_objects: 100,
        convertible: 99,
        unconvertible: 1,
        details: vec!["1 obj bad".to_string()],
    };
    assert!(!dr.passed());
}

#[test]
fn enrichment_verification_zero_checked_zero_disc_passes() {
    let vr = VerificationResult {
        migration_id: "vr0".to_string(),
        objects_checked: 0,
        discrepancies: 0,
        details: vec![],
    };
    assert!(vr.passed());
}

#[test]
fn enrichment_verification_single_discrepancy_fails() {
    let vr = VerificationResult {
        migration_id: "vr1".to_string(),
        objects_checked: 1000,
        discrepancies: 1,
        details: vec!["1 mismatch".to_string()],
    };
    assert!(!vr.passed());
}

#[test]
fn enrichment_dry_run_result_serde_roundtrip() {
    let dr = DryRunResult {
        migration_id: "dr-serde".to_string(),
        total_objects: 1234,
        convertible: 1200,
        unconvertible: 34,
        details: vec!["detail A".to_string(), "detail B".to_string()],
    };
    let json = serde_json::to_string(&dr).unwrap();
    let de: DryRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(dr, de);
}

#[test]
fn enrichment_verification_result_serde_roundtrip() {
    let vr = VerificationResult {
        migration_id: "vr-serde".to_string(),
        objects_checked: 5000,
        discrepancies: 42,
        details: vec!["mismatch".to_string()],
    };
    let json = serde_json::to_string(&vr).unwrap();
    let de: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(vr, de);
}

#[test]
fn enrichment_dry_run_with_details_joins_into_error() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("drj", CutoverType::HardCutover), "t").unwrap();
    let dr = DryRunResult {
        migration_id: "drj".to_string(),
        total_objects: 100,
        convertible: 90,
        unconvertible: 10,
        details: vec!["error-a".to_string(), "error-b".to_string()],
    };
    let err = runner.dry_run("drj", dr, "t").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("error-a; error-b"), "detail should be joined: {msg}");
}

#[test]
fn enrichment_verification_failure_with_details_joins_into_error() {
    let mut runner = MigrationRunner::new();
    advance_to_verifying(&mut runner, "vfj", CutoverType::HardCutover);
    let vr = VerificationResult {
        migration_id: "vfj".to_string(),
        objects_checked: 200,
        discrepancies: 3,
        details: vec!["disc-a".to_string(), "disc-b".to_string()],
    };
    let err = runner.verify("vfj", vr, "t").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("disc-a; disc-b"), "detail should be joined: {msg}");
}

#[test]
fn enrichment_dry_run_sets_state_to_dry_run_failed_on_failure() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("drf", CutoverType::HardCutover), "t").unwrap();
    let dr = DryRunResult {
        migration_id: "drf".to_string(),
        total_objects: 10,
        convertible: 5,
        unconvertible: 5,
        details: vec![],
    };
    let _ = runner.dry_run("drf", dr, "t");
    assert_eq!(runner.state("drf"), Some(MigrationState::DryRunFailed));
}

#[test]
fn enrichment_verification_failure_sets_verification_failed_state() {
    let mut runner = MigrationRunner::new();
    advance_to_verifying(&mut runner, "vff", CutoverType::HardCutover);
    let vr = VerificationResult {
        migration_id: "vff".to_string(),
        objects_checked: 200,
        discrepancies: 5,
        details: vec![],
    };
    let _ = runner.verify("vff", vr, "t");
    assert_eq!(runner.state("vff"), Some(MigrationState::VerificationFailed));
}

// ─── 41-50: Multiple concurrent migrations ──────────────────────────────

#[test]
fn enrichment_multiple_independent_migrations_coexist() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full(&mut runner, "mi1", CutoverType::HardCutover);
    run_full(&mut runner, "mi2", CutoverType::SoftMigration);
    run_full(&mut runner, "mi3", CutoverType::ParallelRun);
    assert_eq!(runner.applied_count(), 3);
    assert_eq!(runner.migration_count(), 3);
}

#[test]
fn enrichment_summary_shows_mixed_states() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("ms1", CutoverType::HardCutover), "t").unwrap();
    advance_to_executing(&mut runner, "ms2", CutoverType::HardCutover);
    advance_to_verifying(&mut runner, "ms3", CutoverType::HardCutover);
    advance_to_verified(&mut runner, "ms4", CutoverType::HardCutover);
    run_full(&mut runner, "ms5", CutoverType::HardCutover);

    let s = runner.summary();
    assert_eq!(s.len(), 5);
    assert_eq!(s["ms1"], MigrationState::Declared);
    assert_eq!(s["ms2"], MigrationState::Executing);
    assert_eq!(s["ms3"], MigrationState::Verifying);
    assert_eq!(s["ms4"], MigrationState::Verified);
    assert_eq!(s["ms5"], MigrationState::Committed);
}

#[test]
fn enrichment_migration_count_tracks_all_declared() {
    let mut runner = MigrationRunner::new();
    assert_eq!(runner.migration_count(), 0);
    runner.declare(declaration("mc1", CutoverType::HardCutover), "t").unwrap();
    assert_eq!(runner.migration_count(), 1);
    runner.declare(declaration("mc2", CutoverType::SoftMigration), "t").unwrap();
    assert_eq!(runner.migration_count(), 2);
}

#[test]
fn enrichment_applied_count_only_committed() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("ac1", CutoverType::HardCutover), "t").unwrap();
    assert_eq!(runner.applied_count(), 0);
    run_full(&mut runner, "ac2", CutoverType::HardCutover);
    assert_eq!(runner.applied_count(), 1);
    // ac1 is still declared, not applied.
    assert_eq!(runner.migration_count(), 2);
}

#[test]
fn enrichment_rollback_does_not_appear_in_applied() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "rb-app", CutoverType::HardCutover);
    runner.rollback("rb-app", "t").unwrap();
    assert_eq!(runner.applied_count(), 0);
    assert!(runner.applied_migrations().is_empty());
}

#[test]
fn enrichment_ten_sequential_migrations() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    for i in 0..10 {
        let from = format!("v{i}");
        let to = format!("v{}", i + 1);
        let mid = format!("seq-{i}");
        let d = decl_custom(&mid, &from, &to, CutoverType::HardCutover,
            vec![ObjectClass::SerializationSchema], None);
        runner.declare(d, "t").unwrap();
        runner.dry_run(&mid, pass_dry_run(&mid), "t").unwrap();
        runner.create_checkpoint(&mid, i as u64, "t").unwrap();
        runner.complete_execution(&mid, 10, "t").unwrap();
        runner.verify(&mid, pass_verify(&mid), "t").unwrap();
        runner.commit(&mid, "t").unwrap();
        runner.set_tick((i + 1) as u64 * 10);
    }
    assert_eq!(runner.applied_count(), 10);
    // All old versions rejected.
    for i in 0..10 {
        let ver = format!("v{i}");
        assert!(runner.check_format_acceptance(ObjectClass::SerializationSchema, &ver).is_err());
    }
    // Only latest accepted.
    runner.check_format_acceptance(ObjectClass::SerializationSchema, "v10").unwrap();
}

#[test]
fn enrichment_declaration_accessor_for_each_cutover_type() {
    let mut runner = MigrationRunner::new();
    for (mid, ct) in [
        ("da-h", CutoverType::HardCutover),
        ("da-s", CutoverType::SoftMigration),
        ("da-p", CutoverType::ParallelRun),
    ] {
        runner.declare(declaration(mid, ct), "t").unwrap();
        let d = runner.declaration(mid).unwrap();
        assert_eq!(d.cutover_type, ct);
        assert_eq!(d.migration_id, mid);
    }
}

#[test]
fn enrichment_declaration_preserves_compatible_incompatible_lists() {
    let d = MigrationDeclaration {
        migration_id: "dl-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: vec![ObjectClass::SerializationSchema],
        cutover_type: CutoverType::HardCutover,
        description: "test".to_string(),
        compatible_across: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        incompatible_across: vec!["x".to_string(), "y".to_string()],
        transition_end_tick: None,
    };
    let mut runner = MigrationRunner::new();
    runner.declare(d.clone(), "t").unwrap();
    let retrieved = runner.declaration("dl-1").unwrap();
    assert_eq!(retrieved.compatible_across, d.compatible_across);
    assert_eq!(retrieved.incompatible_across, d.incompatible_across);
}

#[test]
fn enrichment_declaration_preserves_description() {
    let mut runner = MigrationRunner::new();
    let d = decl_custom("desc-1", "v1", "v2", CutoverType::HardCutover,
        vec![ObjectClass::KeyFormat], None);
    runner.declare(d, "t").unwrap();
    let retrieved = runner.declaration("desc-1").unwrap();
    assert_eq!(retrieved.description, "enrichment migration desc-1");
}

#[test]
fn enrichment_applied_record_checkpoint_seq_matches() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("ck1", CutoverType::HardCutover), "t").unwrap();
    runner.dry_run("ck1", pass_dry_run("ck1"), "t").unwrap();
    runner.create_checkpoint("ck1", 42, "t").unwrap();
    runner.complete_execution("ck1", 100, "t").unwrap();
    runner.verify("ck1", pass_verify("ck1"), "t").unwrap();
    runner.commit("ck1", "t").unwrap();

    let rec = &runner.applied_migrations()[0];
    assert_eq!(rec.checkpoint_seq, 42);
}

// ─── 51-60: Event audit trail details ───────────────────────────────────

#[test]
fn enrichment_events_have_correct_trace_id() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("et1", CutoverType::HardCutover), "trace-alpha").unwrap();
    let events = runner.events();
    assert!(events.iter().all(|e| e.trace_id == "trace-alpha"));
}

#[test]
fn enrichment_events_carry_version_info() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("ev1", CutoverType::HardCutover), "t").unwrap();
    let events = runner.events();
    let decl_event = events.iter().find(|e| e.event == "migration_declared").unwrap();
    assert_eq!(decl_event.from_version.as_deref(), Some("v1"));
    assert_eq!(decl_event.to_version.as_deref(), Some("v2"));
}

#[test]
fn enrichment_events_carry_migration_id() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("ev2", CutoverType::HardCutover), "t").unwrap();
    let events = runner.events();
    assert!(events.iter().all(|e| e.migration_id.as_deref() == Some("ev2")));
}

#[test]
fn enrichment_event_timestamp_matches_tick() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(77);
    runner.declare(declaration("ev3", CutoverType::HardCutover), "t").unwrap();
    let events = runner.events();
    let decl_event = &events[0];
    assert_eq!(decl_event.timestamp, DeterministicTimestamp(77));
}

#[test]
fn enrichment_dry_run_failure_event_has_error_code() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("drf-ev", CutoverType::HardCutover), "t").unwrap();
    let dr = DryRunResult {
        migration_id: "drf-ev".to_string(),
        total_objects: 10,
        convertible: 5,
        unconvertible: 5,
        details: vec![],
    };
    let _ = runner.dry_run("drf-ev", dr, "t");
    let events = runner.events();
    let fail_event = events.iter().find(|e| e.event == "dry_run_complete" && e.outcome == "fail").unwrap();
    assert_eq!(fail_event.error_code.as_deref(), Some("MC_DRY_RUN_FAILED"));
}

#[test]
fn enrichment_verification_failure_event_has_error_code() {
    let mut runner = MigrationRunner::new();
    advance_to_verifying(&mut runner, "vf-ev", CutoverType::HardCutover);
    let vr = VerificationResult {
        migration_id: "vf-ev".to_string(),
        objects_checked: 200,
        discrepancies: 3,
        details: vec![],
    };
    let _ = runner.verify("vf-ev", vr, "t");
    let events = runner.events();
    let fail_event = events.iter().find(|e| e.event == "verification_complete" && e.outcome == "fail").unwrap();
    assert_eq!(fail_event.error_code.as_deref(), Some("MC_VERIFICATION_FAILED"));
}

#[test]
fn enrichment_successful_events_have_no_error_code() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "ok-ev", CutoverType::HardCutover);
    let events = runner.events();
    for ev in events {
        assert_eq!(ev.error_code, None, "event {} should have no error_code", ev.event);
    }
}

#[test]
fn enrichment_execution_event_carries_affected_count() {
    let mut runner = MigrationRunner::new();
    advance_to_executing(&mut runner, "aff-ev", CutoverType::HardCutover);
    runner.complete_execution("aff-ev", 777, "t").unwrap();
    let events = runner.events();
    let exec_event = events.iter().find(|e| e.event == "execution_complete").unwrap();
    assert_eq!(exec_event.affected_count, Some(777));
}

#[test]
fn enrichment_drain_events_clears_all() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("de1", CutoverType::HardCutover), "t").unwrap();
    assert!(!runner.events().is_empty());
    let drained = runner.drain_events();
    assert!(!drained.is_empty());
    assert!(runner.events().is_empty());
}

#[test]
fn enrichment_events_accumulate_across_migrations() {
    let mut runner = MigrationRunner::new();
    run_full(&mut runner, "acc1", CutoverType::HardCutover);
    let count_after_first = runner.events().len();
    run_full(&mut runner, "acc2", CutoverType::HardCutover);
    let count_after_second = runner.events().len();
    assert!(count_after_second > count_after_first);
}

// ─── 61-70: Serde roundtrips and determinism ────────────────────────────

#[test]
fn enrichment_serde_migration_declaration_with_all_fields() {
    let d = MigrationDeclaration {
        migration_id: "serde-full".to_string(),
        from_version: "v10".to_string(),
        to_version: "v11".to_string(),
        affected_objects: ObjectClass::ALL.to_vec(),
        cutover_type: CutoverType::SoftMigration,
        description: "comprehensive test".to_string(),
        compatible_across: vec!["wire".to_string(), "api".to_string()],
        incompatible_across: vec!["db".to_string()],
        transition_end_tick: Some(9999),
    };
    let json = serde_json::to_string(&d).unwrap();
    let de: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(d, de);
}

#[test]
fn enrichment_serde_applied_record_all_object_classes() {
    let rec = AppliedMigrationRecord {
        migration_id: "sr-all".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::ParallelRun,
        affected_objects: ObjectClass::ALL.to_vec(),
        applied_at: DeterministicTimestamp(u64::MAX),
        checkpoint_seq: u64::MAX,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let de: AppliedMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, de);
}

#[test]
fn enrichment_serde_event_with_all_optional_fields() {
    let event = MigrationEvent {
        trace_id: "t-all".to_string(),
        component: "migration_contract".to_string(),
        event: "test_event".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("MC_TEST".to_string()),
        migration_id: Some("m-all".to_string()),
        step: Some("pre_migration".to_string()),
        affected_count: Some(999),
        from_version: Some("v1".to_string()),
        to_version: Some("v2".to_string()),
        timestamp: DeterministicTimestamp(42),
    };
    let json = serde_json::to_string(&event).unwrap();
    let de: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, de);
}

#[test]
fn enrichment_serde_event_with_no_optional_fields() {
    let event = MigrationEvent {
        trace_id: "t-none".to_string(),
        component: "migration_contract".to_string(),
        event: "test_event".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        migration_id: None,
        step: None,
        affected_count: None,
        from_version: None,
        to_version: None,
        timestamp: DeterministicTimestamp(0),
    };
    let json = serde_json::to_string(&event).unwrap();
    let de: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, de);
}

#[test]
fn enrichment_deterministic_replay_soft_migration() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full(&mut runner, "det-s", CutoverType::SoftMigration);
        serde_json::to_string(&runner.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_replay_parallel_run() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full(&mut runner, "det-p", CutoverType::ParallelRun);
        serde_json::to_string(&runner.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_replay_with_rollback() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        advance_to_executing(&mut runner, "det-rb", CutoverType::HardCutover);
        runner.rollback("det-rb", "t").unwrap();
        serde_json::to_string(&runner.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_replay_with_dry_run_failure() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        runner.declare(declaration("det-drf", CutoverType::HardCutover), "t").unwrap();
        let dr = DryRunResult {
            migration_id: "det-drf".to_string(),
            total_objects: 10,
            convertible: 5,
            unconvertible: 5,
            details: vec!["fail".to_string()],
        };
        let _ = runner.dry_run("det-drf", dr, "t");
        serde_json::to_string(&runner.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let mut runner = MigrationRunner::new();
    runner.declare(declaration("sum-s1", CutoverType::HardCutover), "t").unwrap();
    run_full(&mut runner, "sum-s2", CutoverType::HardCutover);
    let summary = runner.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let de: std::collections::BTreeMap<String, MigrationState> = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, de);
}

#[test]
fn enrichment_serde_error_parallel_run_discrepancy() {
    let err = MigrationContractError::ParallelRunDiscrepancy {
        migration_id: "pr-serde".to_string(),
        discrepancy_count: 42,
    };
    let json = serde_json::to_string(&err).unwrap();
    let de: MigrationContractError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, de);
}

// ─── 71-80: Error display, error codes, edge cases ──────────────────────

#[test]
fn enrichment_error_display_migration_not_found_contains_id() {
    let err = MigrationContractError::MigrationNotFound {
        migration_id: "xyz-123".to_string(),
    };
    assert!(err.to_string().contains("xyz-123"));
}

#[test]
fn enrichment_error_display_invalid_transition_contains_states() {
    let err = MigrationContractError::InvalidTransition {
        from: MigrationState::Executing,
        to: MigrationState::Committed,
    };
    let msg = err.to_string();
    assert!(msg.contains("executing"), "should contain 'executing': {msg}");
    assert!(msg.contains("committed"), "should contain 'committed': {msg}");
}

#[test]
fn enrichment_error_display_dry_run_failed_contains_count() {
    let err = MigrationContractError::DryRunFailed {
        migration_id: "drf-disp".to_string(),
        unconvertible_count: 42,
        detail: "some detail".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("42"));
    assert!(msg.contains("some detail"));
}

#[test]
fn enrichment_error_display_old_format_rejected_contains_class() {
    let err = MigrationContractError::OldFormatRejected {
        migration_id: "ofr".to_string(),
        object_class: ObjectClass::AttestationFormat,
        detail: "rejected".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("attestation_format"));
}

#[test]
fn enrichment_error_display_rollback_failed_contains_detail() {
    let err = MigrationContractError::RollbackFailed {
        migration_id: "rb-disp".to_string(),
        detail: "checkpoint corrupted".to_string(),
    };
    assert!(err.to_string().contains("checkpoint corrupted"));
}

#[test]
fn enrichment_error_display_parallel_run_discrepancy_contains_count() {
    let err = MigrationContractError::ParallelRunDiscrepancy {
        migration_id: "pr-disp".to_string(),
        discrepancy_count: 7,
    };
    let msg = err.to_string();
    assert!(msg.contains("7"));
    assert!(msg.contains("pr-disp"));
}

#[test]
fn enrichment_error_code_verification_failed() {
    use frankenengine_engine::migration_contract::error_code;
    let err = MigrationContractError::VerificationFailed {
        migration_id: "vf-ec".to_string(),
        discrepancy_count: 1,
        detail: "d".to_string(),
    };
    assert_eq!(error_code(&err), "MC_VERIFICATION_FAILED");
}

#[test]
fn enrichment_all_error_codes_start_with_mc_prefix() {
    use frankenengine_engine::migration_contract::error_code;
    let errors = vec![
        MigrationContractError::MigrationNotFound { migration_id: "x".to_string() },
        MigrationContractError::InvalidTransition { from: MigrationState::Declared, to: MigrationState::Executing },
        MigrationContractError::DryRunFailed { migration_id: "x".to_string(), unconvertible_count: 1, detail: "d".to_string() },
        MigrationContractError::VerificationFailed { migration_id: "x".to_string(), discrepancy_count: 1, detail: "d".to_string() },
        MigrationContractError::OldFormatRejected { migration_id: "x".to_string(), object_class: ObjectClass::KeyFormat, detail: "d".to_string() },
        MigrationContractError::DuplicateMigration { migration_id: "x".to_string() },
        MigrationContractError::RollbackFailed { migration_id: "x".to_string(), detail: "d".to_string() },
        MigrationContractError::ParallelRunDiscrepancy { migration_id: "x".to_string(), discrepancy_count: 1 },
    ];
    for err in &errors {
        let code = error_code(err);
        assert!(code.starts_with("MC_"), "error code {code} should start with MC_");
    }
}

#[test]
fn enrichment_migration_runner_default_trait() {
    let runner = MigrationRunner::default();
    assert_eq!(runner.migration_count(), 0);
    assert_eq!(runner.applied_count(), 0);
    assert!(runner.events().is_empty());
}

#[test]
fn enrichment_operations_on_missing_migration_return_not_found() {
    let mut runner = MigrationRunner::new();
    let ops: Vec<Result<(), MigrationContractError>> = vec![
        runner.dry_run("nope", pass_dry_run("nope"), "t"),
        runner.create_checkpoint("nope", 1, "t"),
        runner.complete_execution("nope", 1, "t"),
        runner.verify("nope", pass_verify("nope"), "t"),
        runner.commit("nope", "t"),
        runner.rollback("nope", "t"),
    ];
    for op in ops {
        assert!(matches!(op, Err(MigrationContractError::MigrationNotFound { .. })));
    }
}

// ─── 81-85: MigrationStep and display coverage ─────────────────────────

#[test]
fn enrichment_migration_step_rollback_has_no_next() {
    assert_eq!(MigrationStep::Rollback.next(), None);
}

#[test]
fn enrichment_migration_step_display_all_variants() {
    let expected = [
        (MigrationStep::PreMigration, "pre_migration"),
        (MigrationStep::Checkpoint, "checkpoint"),
        (MigrationStep::Execute, "execute"),
        (MigrationStep::Verify, "verify"),
        (MigrationStep::Commit, "commit"),
        (MigrationStep::Rollback, "rollback"),
    ];
    for (step, exp) in &expected {
        assert_eq!(step.to_string(), *exp);
    }
}

#[test]
fn enrichment_migration_state_display_all_variants() {
    let expected = [
        (MigrationState::Declared, "declared"),
        (MigrationState::DryRunning, "dry_running"),
        (MigrationState::DryRunPassed, "dry_run_passed"),
        (MigrationState::DryRunFailed, "dry_run_failed"),
        (MigrationState::Executing, "executing"),
        (MigrationState::Verifying, "verifying"),
        (MigrationState::Verified, "verified"),
        (MigrationState::VerificationFailed, "verification_failed"),
        (MigrationState::Committed, "committed"),
        (MigrationState::RollingBack, "rolling_back"),
        (MigrationState::RolledBack, "rolled_back"),
    ];
    for (state, exp) in &expected {
        assert_eq!(state.to_string(), *exp);
    }
}

#[test]
fn enrichment_object_class_display_all_variants() {
    let expected = [
        (ObjectClass::SerializationSchema, "serialization_schema"),
        (ObjectClass::KeyFormat, "key_format"),
        (ObjectClass::TokenFormat, "token_format"),
        (ObjectClass::CheckpointFormat, "checkpoint_format"),
        (ObjectClass::RevocationFormat, "revocation_format"),
        (ObjectClass::PolicyStructure, "policy_structure"),
        (ObjectClass::EvidenceFormat, "evidence_format"),
        (ObjectClass::AttestationFormat, "attestation_format"),
    ];
    for (oc, exp) in &expected {
        assert_eq!(oc.to_string(), *exp);
    }
}

#[test]
fn enrichment_cutover_type_display_all_variants() {
    let expected = [
        (CutoverType::HardCutover, "hard_cutover"),
        (CutoverType::SoftMigration, "soft_migration"),
        (CutoverType::ParallelRun, "parallel_run"),
    ];
    for (ct, exp) in &expected {
        assert_eq!(ct.to_string(), *exp);
    }
}

#[test]
fn enrichment_applied_record_tick_matches_runner_tick() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(12345);
    run_full(&mut runner, "tick-rec", CutoverType::HardCutover);
    let rec = &runner.applied_migrations()[0];
    assert_eq!(rec.applied_at, DeterministicTimestamp(12345));
}

#[test]
fn enrichment_applied_record_preserves_affected_objects_order() {
    let objects = vec![
        ObjectClass::AttestationFormat,
        ObjectClass::EvidenceFormat,
        ObjectClass::KeyFormat,
    ];
    let mut runner = MigrationRunner::new();
    let d = decl_custom("ord-1", "v1", "v2", CutoverType::HardCutover, objects.clone(), None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("ord-1", pass_dry_run("ord-1"), "t").unwrap();
    runner.create_checkpoint("ord-1", 1, "t").unwrap();
    runner.complete_execution("ord-1", 10, "t").unwrap();
    runner.verify("ord-1", pass_verify("ord-1"), "t").unwrap();
    runner.commit("ord-1", "t").unwrap();

    assert_eq!(runner.applied_migrations()[0].affected_objects, objects);
}

#[test]
fn enrichment_applied_record_from_to_version_match_declaration() {
    let mut runner = MigrationRunner::new();
    let d = decl_custom("ver-match", "alpha", "beta", CutoverType::HardCutover,
        vec![ObjectClass::SerializationSchema], None);
    runner.declare(d, "t").unwrap();
    runner.dry_run("ver-match", pass_dry_run("ver-match"), "t").unwrap();
    runner.create_checkpoint("ver-match", 1, "t").unwrap();
    runner.complete_execution("ver-match", 10, "t").unwrap();
    runner.verify("ver-match", pass_verify("ver-match"), "t").unwrap();
    runner.commit("ver-match", "t").unwrap();

    let rec = &runner.applied_migrations()[0];
    assert_eq!(rec.from_version, "alpha");
    assert_eq!(rec.to_version, "beta");
}

#[test]
fn enrichment_verification_failed_is_not_terminal() {
    assert!(!MigrationState::VerificationFailed.is_terminal());
}

#[test]
fn enrichment_dry_running_is_not_terminal() {
    assert!(!MigrationState::DryRunning.is_terminal());
}

#[test]
fn enrichment_rolling_back_is_not_terminal() {
    assert!(!MigrationState::RollingBack.is_terminal());
}
