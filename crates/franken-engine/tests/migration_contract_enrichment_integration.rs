//! Enrichment integration tests for `migration_contract`.
//!
//! Covers: JSON field-name stability, serde roundtrips, Display exact values,
//! Debug distinctness, CutoverType/ObjectClass/MigrationStep/MigrationState
//! enums, MigrationContractError variants, error_code mapping,
//! MigrationDeclaration, DryRunResult, VerificationResult, AppliedMigrationRecord,
//! MigrationRunner full lifecycle (declare/dry_run/checkpoint/execute/verify/
//! commit/rollback), format acceptance, soft migration windows, and events.

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

use frankenengine_engine::migration_contract::*;

// ── helpers ────────────────────────────────────────────────────────────

fn test_declaration(id: &str) -> MigrationDeclaration {
    MigrationDeclaration {
        migration_id: id.to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: vec![ObjectClass::KeyFormat],
        cutover_type: CutoverType::HardCutover,
        description: "test migration".to_string(),
        compatible_across: vec!["api".to_string()],
        incompatible_across: vec!["wire-format".to_string()],
        transition_end_tick: None,
    }
}

fn passing_dry_run(id: &str) -> DryRunResult {
    DryRunResult {
        migration_id: id.to_string(),
        total_objects: 100,
        convertible: 100,
        unconvertible: 0,
        details: vec![],
    }
}

fn passing_verification(id: &str) -> VerificationResult {
    VerificationResult {
        migration_id: id.to_string(),
        objects_checked: 100,
        discrepancies: 0,
        details: vec![],
    }
}

// ── CutoverType ────────────────────────────────────────────────────────

#[test]
fn cutover_type_display_hard() {
    assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
}
#[test]
fn cutover_type_display_soft() {
    assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
}
#[test]
fn cutover_type_display_parallel() {
    assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
}

#[test]
fn cutover_type_debug_distinct() {
    let variants = [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn cutover_type_serde_roundtrip() {
    for ct in [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ] {
        let json = serde_json::to_vec(&ct).unwrap();
        let back: CutoverType = serde_json::from_slice(&json).unwrap();
        assert_eq!(ct, back);
    }
}

// ── ObjectClass ────────────────────────────────────────────────────────

#[test]
fn object_class_display_exact() {
    assert_eq!(
        ObjectClass::SerializationSchema.to_string(),
        "serialization_schema"
    );
    assert_eq!(ObjectClass::KeyFormat.to_string(), "key_format");
    assert_eq!(ObjectClass::TokenFormat.to_string(), "token_format");
    assert_eq!(
        ObjectClass::CheckpointFormat.to_string(),
        "checkpoint_format"
    );
    assert_eq!(
        ObjectClass::RevocationFormat.to_string(),
        "revocation_format"
    );
    assert_eq!(ObjectClass::PolicyStructure.to_string(), "policy_structure");
    assert_eq!(ObjectClass::EvidenceFormat.to_string(), "evidence_format");
    assert_eq!(
        ObjectClass::AttestationFormat.to_string(),
        "attestation_format"
    );
}

#[test]
fn object_class_all_has_eight() {
    assert_eq!(ObjectClass::ALL.len(), 8);
    let unique: BTreeSet<String> = ObjectClass::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn object_class_serde_roundtrip() {
    for oc in ObjectClass::ALL {
        let json = serde_json::to_vec(&oc).unwrap();
        let back: ObjectClass = serde_json::from_slice(&json).unwrap();
        assert_eq!(oc, back);
    }
}

// ── MigrationStep ──────────────────────────────────────────────────────

#[test]
fn migration_step_display_exact() {
    assert_eq!(MigrationStep::PreMigration.to_string(), "pre_migration");
    assert_eq!(MigrationStep::Checkpoint.to_string(), "checkpoint");
    assert_eq!(MigrationStep::Execute.to_string(), "execute");
    assert_eq!(MigrationStep::Verify.to_string(), "verify");
    assert_eq!(MigrationStep::Commit.to_string(), "commit");
    assert_eq!(MigrationStep::Rollback.to_string(), "rollback");
}

#[test]
fn migration_step_next_pipeline() {
    assert_eq!(
        MigrationStep::PreMigration.next(),
        Some(MigrationStep::Checkpoint)
    );
    assert_eq!(
        MigrationStep::Checkpoint.next(),
        Some(MigrationStep::Execute)
    );
    assert_eq!(MigrationStep::Execute.next(), Some(MigrationStep::Verify));
    assert_eq!(MigrationStep::Verify.next(), Some(MigrationStep::Commit));
    assert_eq!(MigrationStep::Commit.next(), None);
    assert_eq!(MigrationStep::Rollback.next(), None);
}

#[test]
fn migration_step_forward_pipeline_has_five() {
    assert_eq!(MigrationStep::FORWARD_PIPELINE.len(), 5);
}

#[test]
fn migration_step_serde_roundtrip() {
    for step in MigrationStep::FORWARD_PIPELINE {
        let json = serde_json::to_vec(&step).unwrap();
        let back: MigrationStep = serde_json::from_slice(&json).unwrap();
        assert_eq!(step, back);
    }
}

// ── MigrationState ─────────────────────────────────────────────────────

#[test]
fn migration_state_display_all() {
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
    for (state, expected_str) in expected {
        assert_eq!(state.to_string(), expected_str);
    }
}

#[test]
fn migration_state_terminal() {
    assert!(MigrationState::Committed.is_terminal());
    assert!(MigrationState::RolledBack.is_terminal());
    assert!(MigrationState::DryRunFailed.is_terminal());
    assert!(!MigrationState::Declared.is_terminal());
    assert!(!MigrationState::Executing.is_terminal());
    assert!(!MigrationState::Verified.is_terminal());
}

#[test]
fn migration_state_serde_roundtrip() {
    let states = [
        MigrationState::Declared,
        MigrationState::DryRunning,
        MigrationState::DryRunPassed,
        MigrationState::DryRunFailed,
        MigrationState::Executing,
        MigrationState::Verifying,
        MigrationState::Verified,
        MigrationState::VerificationFailed,
        MigrationState::Committed,
        MigrationState::RollingBack,
        MigrationState::RolledBack,
    ];
    for s in states {
        let json = serde_json::to_vec(&s).unwrap();
        let back: MigrationState = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── MigrationContractError ─────────────────────────────────────────────

#[test]
fn error_display_not_found() {
    let e = MigrationContractError::MigrationNotFound {
        migration_id: "m1".to_string(),
    };
    assert_eq!(e.to_string(), "migration not found: m1");
}

#[test]
fn error_display_invalid_transition() {
    let e = MigrationContractError::InvalidTransition {
        from: MigrationState::Declared,
        to: MigrationState::Executing,
    };
    assert_eq!(e.to_string(), "invalid transition: declared -> executing");
}

#[test]
fn error_display_dry_run_failed() {
    let e = MigrationContractError::DryRunFailed {
        migration_id: "m1".to_string(),
        unconvertible_count: 5,
        detail: "bad data".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "dry run failed for m1: 5 unconvertible: bad data"
    );
}

#[test]
fn error_display_verification_failed() {
    let e = MigrationContractError::VerificationFailed {
        migration_id: "m1".to_string(),
        discrepancy_count: 3,
        detail: "mismatch".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "verification failed for m1: 3 discrepancies: mismatch"
    );
}

#[test]
fn error_display_old_format_rejected() {
    let e = MigrationContractError::OldFormatRejected {
        migration_id: "m1".to_string(),
        object_class: ObjectClass::KeyFormat,
        detail: "old".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "old format key_format rejected after m1: old"
    );
}

#[test]
fn error_display_duplicate() {
    let e = MigrationContractError::DuplicateMigration {
        migration_id: "m1".to_string(),
    };
    assert_eq!(e.to_string(), "duplicate migration: m1");
}

#[test]
fn error_display_rollback_failed() {
    let e = MigrationContractError::RollbackFailed {
        migration_id: "m1".to_string(),
        detail: "io error".to_string(),
    };
    assert_eq!(e.to_string(), "rollback failed for m1: io error");
}

#[test]
fn error_display_parallel_discrepancy() {
    let e = MigrationContractError::ParallelRunDiscrepancy {
        migration_id: "m1".to_string(),
        discrepancy_count: 7,
    };
    assert_eq!(e.to_string(), "parallel run discrepancy for m1: 7");
}

#[test]
fn error_is_std_error() {
    let e = MigrationContractError::MigrationNotFound {
        migration_id: "x".to_string(),
    };
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip_all() {
    let variants = vec![
        MigrationContractError::MigrationNotFound {
            migration_id: "a".to_string(),
        },
        MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing,
        },
        MigrationContractError::DryRunFailed {
            migration_id: "b".to_string(),
            unconvertible_count: 5,
            detail: "x".to_string(),
        },
        MigrationContractError::VerificationFailed {
            migration_id: "c".to_string(),
            discrepancy_count: 3,
            detail: "y".to_string(),
        },
        MigrationContractError::OldFormatRejected {
            migration_id: "d".to_string(),
            object_class: ObjectClass::TokenFormat,
            detail: "z".to_string(),
        },
        MigrationContractError::DuplicateMigration {
            migration_id: "e".to_string(),
        },
        MigrationContractError::RollbackFailed {
            migration_id: "f".to_string(),
            detail: "w".to_string(),
        },
        MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "g".to_string(),
            discrepancy_count: 1,
        },
    ];
    for v in &variants {
        let json = serde_json::to_vec(v).unwrap();
        let back: MigrationContractError = serde_json::from_slice(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// ── error_code ─────────────────────────────────────────────────────────

#[test]
fn error_code_all_stable() {
    assert_eq!(
        error_code(&MigrationContractError::MigrationNotFound {
            migration_id: "x".to_string()
        }),
        "MC_MIGRATION_NOT_FOUND"
    );
    assert_eq!(
        error_code(&MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing
        }),
        "MC_INVALID_TRANSITION"
    );
    assert_eq!(
        error_code(&MigrationContractError::DryRunFailed {
            migration_id: "x".to_string(),
            unconvertible_count: 0,
            detail: "".to_string()
        }),
        "MC_DRY_RUN_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::VerificationFailed {
            migration_id: "x".to_string(),
            discrepancy_count: 0,
            detail: "".to_string()
        }),
        "MC_VERIFICATION_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::OldFormatRejected {
            migration_id: "x".to_string(),
            object_class: ObjectClass::KeyFormat,
            detail: "".to_string()
        }),
        "MC_OLD_FORMAT_REJECTED"
    );
    assert_eq!(
        error_code(&MigrationContractError::DuplicateMigration {
            migration_id: "x".to_string()
        }),
        "MC_DUPLICATE_MIGRATION"
    );
    assert_eq!(
        error_code(&MigrationContractError::RollbackFailed {
            migration_id: "x".to_string(),
            detail: "".to_string()
        }),
        "MC_ROLLBACK_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "x".to_string(),
            discrepancy_count: 0
        }),
        "MC_PARALLEL_DISCREPANCY"
    );
}

#[test]
fn error_codes_all_unique() {
    let codes: BTreeSet<&str> = vec![
        "MC_MIGRATION_NOT_FOUND",
        "MC_INVALID_TRANSITION",
        "MC_DRY_RUN_FAILED",
        "MC_VERIFICATION_FAILED",
        "MC_OLD_FORMAT_REJECTED",
        "MC_DUPLICATE_MIGRATION",
        "MC_ROLLBACK_FAILED",
        "MC_PARALLEL_DISCREPANCY",
    ]
    .into_iter()
    .collect();
    assert_eq!(codes.len(), 8);
}

// ── MigrationDeclaration ───────────────────────────────────────────────

#[test]
fn declaration_json_fields() {
    let d = test_declaration("m1");
    let v: serde_json::Value = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("migration_id"));
    assert!(obj.contains_key("from_version"));
    assert!(obj.contains_key("to_version"));
    assert!(obj.contains_key("affected_objects"));
    assert!(obj.contains_key("cutover_type"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("compatible_across"));
    assert!(obj.contains_key("incompatible_across"));
    assert!(obj.contains_key("transition_end_tick"));
}

#[test]
fn declaration_serde_roundtrip() {
    let d = test_declaration("m-rt");
    let json = serde_json::to_vec(&d).unwrap();
    let back: MigrationDeclaration = serde_json::from_slice(&json).unwrap();
    assert_eq!(d, back);
}

// ── DryRunResult ───────────────────────────────────────────────────────

#[test]
fn dry_run_passed() {
    let r = passing_dry_run("m1");
    assert!(r.passed());
}

#[test]
fn dry_run_failed() {
    let r = DryRunResult {
        migration_id: "m1".to_string(),
        total_objects: 100,
        convertible: 95,
        unconvertible: 5,
        details: vec!["bad".to_string()],
    };
    assert!(!r.passed());
}

#[test]
fn dry_run_serde_roundtrip() {
    let r = passing_dry_run("m1");
    let json = serde_json::to_vec(&r).unwrap();
    let back: DryRunResult = serde_json::from_slice(&json).unwrap();
    assert_eq!(r, back);
}

// ── VerificationResult ─────────────────────────────────────────────────

#[test]
fn verification_passed() {
    let r = passing_verification("m1");
    assert!(r.passed());
}

#[test]
fn verification_failed() {
    let r = VerificationResult {
        migration_id: "m1".to_string(),
        objects_checked: 100,
        discrepancies: 3,
        details: vec!["x".to_string()],
    };
    assert!(!r.passed());
}

#[test]
fn verification_serde_roundtrip() {
    let r = passing_verification("m1");
    let json = serde_json::to_vec(&r).unwrap();
    let back: VerificationResult = serde_json::from_slice(&json).unwrap();
    assert_eq!(r, back);
}

// ── MigrationRunner lifecycle ──────────────────────────────────────────

#[test]
fn runner_starts_empty() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.migration_count(), 0);
    assert_eq!(runner.applied_count(), 0);
}

#[test]
fn runner_declare_and_state() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    assert_eq!(runner.migration_count(), 1);
    assert_eq!(runner.state("m1"), Some(MigrationState::Declared));
}

#[test]
fn runner_declare_duplicate_error() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    let err = runner.declare(test_declaration("m1"), "t2").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::DuplicateMigration { .. }
    ));
}

#[test]
fn runner_full_success_pipeline() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(100);
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::DryRunPassed));
    runner.create_checkpoint("m1", 42, "t3").unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::Executing));
    runner.complete_execution("m1", 100, "t4").unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::Verifying));
    runner
        .verify("m1", passing_verification("m1"), "t5")
        .unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::Verified));
    runner.commit("m1", "t6").unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::Committed));
    assert_eq!(runner.applied_count(), 1);
}

#[test]
fn runner_dry_run_failure() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    let result = DryRunResult {
        migration_id: "m1".to_string(),
        total_objects: 100,
        convertible: 95,
        unconvertible: 5,
        details: vec!["bad".to_string()],
    };
    let err = runner.dry_run("m1", result, "t2").unwrap_err();
    assert!(matches!(err, MigrationContractError::DryRunFailed { .. }));
    assert_eq!(runner.state("m1"), Some(MigrationState::DryRunFailed));
}

#[test]
fn runner_verification_failure() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    runner.create_checkpoint("m1", 1, "t3").unwrap();
    runner.complete_execution("m1", 100, "t4").unwrap();
    let result = VerificationResult {
        migration_id: "m1".to_string(),
        objects_checked: 100,
        discrepancies: 2,
        details: vec!["off".to_string()],
    };
    let err = runner.verify("m1", result, "t5").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::VerificationFailed { .. }
    ));
    assert_eq!(runner.state("m1"), Some(MigrationState::VerificationFailed));
}

#[test]
fn runner_rollback_from_executing() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    runner.create_checkpoint("m1", 1, "t3").unwrap();
    runner.rollback("m1", "t4").unwrap();
    assert_eq!(runner.state("m1"), Some(MigrationState::RolledBack));
}

#[test]
fn runner_rollback_from_terminal_fails() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    runner.create_checkpoint("m1", 1, "t3").unwrap();
    runner.complete_execution("m1", 100, "t4").unwrap();
    runner
        .verify("m1", passing_verification("m1"), "t5")
        .unwrap();
    runner.commit("m1", "t6").unwrap();
    let err = runner.rollback("m1", "t7").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn runner_invalid_step_order() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    // Can't checkpoint before dry run
    let err = runner.create_checkpoint("m1", 1, "t2").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn runner_not_found() {
    let mut runner = MigrationRunner::new();
    let err = runner
        .dry_run("nonexistent", passing_dry_run("x"), "t1")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::MigrationNotFound { .. }
    ));
}

// ── Format acceptance ──────────────────────────────────────────────────

#[test]
fn format_acceptance_after_hard_cutover() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    runner.create_checkpoint("m1", 1, "t3").unwrap();
    runner.complete_execution("m1", 100, "t4").unwrap();
    runner
        .verify("m1", passing_verification("m1"), "t5")
        .unwrap();
    runner.commit("m1", "t6").unwrap();
    // Old format (v1 key_format) should be rejected
    let err = runner
        .check_format_acceptance(ObjectClass::KeyFormat, "v1")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::OldFormatRejected { .. }
    ));
    // Different object class is fine
    assert!(
        runner
            .check_format_acceptance(ObjectClass::TokenFormat, "v1")
            .is_ok()
    );
    // New version is fine
    assert!(
        runner
            .check_format_acceptance(ObjectClass::KeyFormat, "v2")
            .is_ok()
    );
}

#[test]
fn soft_migration_window() {
    let mut runner = MigrationRunner::new();
    let mut decl = test_declaration("soft-m1");
    decl.cutover_type = CutoverType::SoftMigration;
    decl.transition_end_tick = Some(200);
    runner.declare(decl, "t1").unwrap();
    // Before commit: window is open
    assert_eq!(runner.check_soft_migration_window("soft-m1"), Some(true));
    // Complete the pipeline
    runner
        .dry_run("soft-m1", passing_dry_run("soft-m1"), "t2")
        .unwrap();
    runner.create_checkpoint("soft-m1", 1, "t3").unwrap();
    runner.complete_execution("soft-m1", 50, "t4").unwrap();
    runner
        .verify("soft-m1", passing_verification("soft-m1"), "t5")
        .unwrap();
    runner.set_tick(100);
    runner.commit("soft-m1", "t6").unwrap();
    // After commit, tick < end_tick: window still open
    assert_eq!(runner.check_soft_migration_window("soft-m1"), Some(true));
    // Tick at end: window closed
    runner.set_tick(200);
    assert_eq!(runner.check_soft_migration_window("soft-m1"), Some(false));
}

// ── Events ─────────────────────────────────────────────────────────────

#[test]
fn runner_emits_events() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    assert!(!runner.events().is_empty());
    assert_eq!(runner.events()[0].component, "migration_contract");
}

#[test]
fn runner_drain_events() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    let events = runner.drain_events();
    assert!(!events.is_empty());
    assert!(runner.events().is_empty());
}

#[test]
fn migration_event_json_fields() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "trace-1").unwrap();
    let events = runner.drain_events();
    let v: serde_json::Value = serde_json::to_value(&events[0]).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("timestamp"));
}

#[test]
fn migration_event_serde_roundtrip() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "trace-1").unwrap();
    let events = runner.drain_events();
    let json = serde_json::to_vec(&events[0]).unwrap();
    let back: MigrationEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(events[0], back);
}

// ── Summary and declaration accessors ──────────────────────────────────

#[test]
fn runner_summary() {
    let mut runner = MigrationRunner::new();
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.declare(test_declaration("m2"), "t2").unwrap();
    let summary = runner.summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary["m1"], MigrationState::Declared);
    assert_eq!(summary["m2"], MigrationState::Declared);
}

#[test]
fn runner_declaration_accessor() {
    let mut runner = MigrationRunner::new();
    let decl = test_declaration("m1");
    runner.declare(decl.clone(), "t1").unwrap();
    let retrieved = runner.declaration("m1").unwrap();
    assert_eq!(retrieved.from_version, "v1");
    assert_eq!(retrieved.to_version, "v2");
    assert!(runner.declaration("nonexistent").is_none());
}

// ── AppliedMigrationRecord ─────────────────────────────────────────────

#[test]
fn applied_record_serde_roundtrip() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(42);
    runner.declare(test_declaration("m1"), "t1").unwrap();
    runner.dry_run("m1", passing_dry_run("m1"), "t2").unwrap();
    runner.create_checkpoint("m1", 7, "t3").unwrap();
    runner.complete_execution("m1", 100, "t4").unwrap();
    runner
        .verify("m1", passing_verification("m1"), "t5")
        .unwrap();
    runner.commit("m1", "t6").unwrap();
    let records = runner.applied_migrations();
    assert_eq!(records.len(), 1);
    let json = serde_json::to_vec(&records[0]).unwrap();
    let back: AppliedMigrationRecord = serde_json::from_slice(&json).unwrap();
    assert_eq!(records[0], back);
    assert_eq!(back.checkpoint_seq, 7);
}
