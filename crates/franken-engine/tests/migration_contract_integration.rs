#![forbid(unsafe_code)]

//! Integration tests for the `migration_contract` module.
//!
//! Covers: CutoverType, ObjectClass, MigrationDeclaration, MigrationStep,
//! MigrationState, MigrationContractError, error_code, MigrationEvent,
//! DryRunResult, VerificationResult, AppliedMigrationRecord, MigrationRunner.

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
    ObjectClass, VerificationResult, error_code,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
    MigrationDeclaration {
        migration_id: id.to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: vec![ObjectClass::SerializationSchema, ObjectClass::KeyFormat],
        cutover_type: cutover,
        description: format!("test migration {id}"),
        compatible_across: vec!["wire_format".to_string()],
        incompatible_across: vec!["storage_format".to_string()],
        transition_end_tick: if cutover == CutoverType::SoftMigration {
            Some(1000)
        } else {
            None
        },
    }
}

fn passing_dry_run(mid: &str) -> DryRunResult {
    DryRunResult {
        migration_id: mid.to_string(),
        total_objects: 100,
        convertible: 100,
        unconvertible: 0,
        details: Vec::new(),
    }
}

fn failing_dry_run(mid: &str) -> DryRunResult {
    DryRunResult {
        migration_id: mid.to_string(),
        total_objects: 100,
        convertible: 90,
        unconvertible: 10,
        details: vec!["10 objects have incompatible field X".to_string()],
    }
}

fn passing_verification(mid: &str) -> VerificationResult {
    VerificationResult {
        migration_id: mid.to_string(),
        objects_checked: 100,
        discrepancies: 0,
        details: Vec::new(),
    }
}

fn failing_verification(mid: &str) -> VerificationResult {
    VerificationResult {
        migration_id: mid.to_string(),
        objects_checked: 100,
        discrepancies: 5,
        details: vec!["5 objects failed conformance".to_string()],
    }
}

fn run_full_pipeline(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
    runner
        .declare(make_declaration(mid, cutover), "trace-1")
        .unwrap();
    runner
        .dry_run(mid, passing_dry_run(mid), "trace-1")
        .unwrap();
    runner.create_checkpoint(mid, 42, "trace-1").unwrap();
    runner.complete_execution(mid, 100, "trace-1").unwrap();
    runner
        .verify(mid, passing_verification(mid), "trace-1")
        .unwrap();
    runner.commit(mid, "trace-1").unwrap();
}

// ===========================================================================
// Section 1: CutoverType
// ===========================================================================

#[test]
fn cutover_type_display_all_variants() {
    assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
    assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
    assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
}

#[test]
fn cutover_type_serde_roundtrip() {
    for ct in [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ] {
        let json = serde_json::to_string(&ct).unwrap();
        let deser: CutoverType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, deser);
    }
}

#[test]
fn cutover_type_clone_copy_eq() {
    let a = CutoverType::HardCutover;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn cutover_type_ord() {
    assert!(CutoverType::HardCutover <= CutoverType::SoftMigration);
}

// ===========================================================================
// Section 2: ObjectClass
// ===========================================================================

#[test]
fn object_class_display_all() {
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
fn object_class_all_constant_has_eight() {
    assert_eq!(ObjectClass::ALL.len(), 8);
}

#[test]
fn object_class_serde_roundtrip_all() {
    for oc in ObjectClass::ALL {
        let json = serde_json::to_string(&oc).unwrap();
        let deser: ObjectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, deser);
    }
}

#[test]
fn object_class_ord() {
    assert!(ObjectClass::SerializationSchema < ObjectClass::KeyFormat);
}

// ===========================================================================
// Section 3: MigrationDeclaration
// ===========================================================================

#[test]
fn migration_declaration_construction() {
    let decl = make_declaration("m-1", CutoverType::HardCutover);
    assert_eq!(decl.migration_id, "m-1");
    assert_eq!(decl.from_version, "v1");
    assert_eq!(decl.to_version, "v2");
    assert_eq!(decl.affected_objects.len(), 2);
    assert_eq!(decl.cutover_type, CutoverType::HardCutover);
    assert!(!decl.description.is_empty());
    assert_eq!(decl.compatible_across.len(), 1);
    assert_eq!(decl.incompatible_across.len(), 1);
    assert!(decl.transition_end_tick.is_none());
}

#[test]
fn migration_declaration_soft_has_transition_end() {
    let decl = make_declaration("m-soft", CutoverType::SoftMigration);
    assert_eq!(decl.transition_end_tick, Some(1000));
}

#[test]
fn migration_declaration_serde_roundtrip() {
    let decl = make_declaration("m-1", CutoverType::HardCutover);
    let json = serde_json::to_string(&decl).unwrap();
    let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, deser);
}

#[test]
fn migration_declaration_serde_roundtrip_soft() {
    let decl = make_declaration("m-soft", CutoverType::SoftMigration);
    let json = serde_json::to_string(&decl).unwrap();
    let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, deser);
}

// ===========================================================================
// Section 4: MigrationStep
// ===========================================================================

#[test]
fn migration_step_display_all() {
    assert_eq!(MigrationStep::PreMigration.to_string(), "pre_migration");
    assert_eq!(MigrationStep::Checkpoint.to_string(), "checkpoint");
    assert_eq!(MigrationStep::Execute.to_string(), "execute");
    assert_eq!(MigrationStep::Verify.to_string(), "verify");
    assert_eq!(MigrationStep::Commit.to_string(), "commit");
    assert_eq!(MigrationStep::Rollback.to_string(), "rollback");
}

#[test]
fn migration_step_next_chain() {
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
    assert_eq!(
        MigrationStep::FORWARD_PIPELINE[0],
        MigrationStep::PreMigration
    );
    assert_eq!(MigrationStep::FORWARD_PIPELINE[4], MigrationStep::Commit);
}

#[test]
fn migration_step_forward_pipeline_chain_matches_next() {
    for i in 0..MigrationStep::FORWARD_PIPELINE.len() - 1 {
        let current = MigrationStep::FORWARD_PIPELINE[i];
        let next = MigrationStep::FORWARD_PIPELINE[i + 1];
        assert_eq!(
            current.next(),
            Some(next),
            "Pipeline step {i} .next() mismatch"
        );
    }
}

#[test]
fn migration_step_serde_roundtrip() {
    let steps = [
        MigrationStep::PreMigration,
        MigrationStep::Checkpoint,
        MigrationStep::Execute,
        MigrationStep::Verify,
        MigrationStep::Commit,
        MigrationStep::Rollback,
    ];
    for step in &steps {
        let json = serde_json::to_string(step).unwrap();
        let deser: MigrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(*step, deser);
    }
}

// ===========================================================================
// Section 5: MigrationState
// ===========================================================================

#[test]
fn migration_state_display_all() {
    assert_eq!(MigrationState::Declared.to_string(), "declared");
    assert_eq!(MigrationState::DryRunning.to_string(), "dry_running");
    assert_eq!(MigrationState::DryRunPassed.to_string(), "dry_run_passed");
    assert_eq!(MigrationState::DryRunFailed.to_string(), "dry_run_failed");
    assert_eq!(MigrationState::Executing.to_string(), "executing");
    assert_eq!(MigrationState::Verifying.to_string(), "verifying");
    assert_eq!(MigrationState::Verified.to_string(), "verified");
    assert_eq!(
        MigrationState::VerificationFailed.to_string(),
        "verification_failed"
    );
    assert_eq!(MigrationState::Committed.to_string(), "committed");
    assert_eq!(MigrationState::RollingBack.to_string(), "rolling_back");
    assert_eq!(MigrationState::RolledBack.to_string(), "rolled_back");
}

#[test]
fn migration_state_is_terminal() {
    let terminal = [
        MigrationState::Committed,
        MigrationState::RolledBack,
        MigrationState::DryRunFailed,
        MigrationState::VerificationFailed,
    ];
    for state in &terminal {
        assert!(state.is_terminal(), "{state:?} should be terminal");
    }

    let non_terminal = [
        MigrationState::Declared,
        MigrationState::DryRunning,
        MigrationState::DryRunPassed,
        MigrationState::Executing,
        MigrationState::Verifying,
        MigrationState::Verified,
        MigrationState::RollingBack,
    ];
    for state in &non_terminal {
        assert!(!state.is_terminal(), "{state:?} should NOT be terminal");
    }
}

#[test]
fn migration_state_serde_roundtrip_all() {
    let all = [
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
    for state in &all {
        let json = serde_json::to_string(state).unwrap();
        let deser: MigrationState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, deser);
    }
}

// ===========================================================================
// Section 6: MigrationContractError
// ===========================================================================

#[test]
fn migration_contract_error_display_all_variants() {
    let errors: Vec<MigrationContractError> = vec![
        MigrationContractError::MigrationNotFound {
            migration_id: "x".to_string(),
        },
        MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing,
        },
        MigrationContractError::DryRunFailed {
            migration_id: "x".to_string(),
            unconvertible_count: 5,
            detail: "d".to_string(),
        },
        MigrationContractError::VerificationFailed {
            migration_id: "x".to_string(),
            discrepancy_count: 3,
            detail: "d".to_string(),
        },
        MigrationContractError::OldFormatRejected {
            migration_id: "x".to_string(),
            object_class: ObjectClass::KeyFormat,
            detail: "d".to_string(),
        },
        MigrationContractError::DuplicateMigration {
            migration_id: "x".to_string(),
        },
        MigrationContractError::RollbackFailed {
            migration_id: "x".to_string(),
            detail: "d".to_string(),
        },
        MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "x".to_string(),
            discrepancy_count: 2,
        },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display should not be empty for {err:?}");
    }
}

#[test]
fn migration_contract_error_is_std_error() {
    let err = MigrationContractError::MigrationNotFound {
        migration_id: "test".to_string(),
    };
    let _dyn_err: &dyn std::error::Error = &err;
}

#[test]
fn migration_contract_error_display_contains_id() {
    let err = MigrationContractError::MigrationNotFound {
        migration_id: "m-42".to_string(),
    };
    assert!(err.to_string().contains("m-42"));
}

#[test]
fn migration_contract_error_display_contains_states() {
    let err = MigrationContractError::InvalidTransition {
        from: MigrationState::Declared,
        to: MigrationState::Executing,
    };
    let s = err.to_string();
    assert!(s.contains("declared"));
    assert!(s.contains("executing"));
}

#[test]
fn migration_contract_error_serde_roundtrip() {
    let errors = vec![
        MigrationContractError::MigrationNotFound {
            migration_id: "x".to_string(),
        },
        MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing,
        },
        MigrationContractError::DryRunFailed {
            migration_id: "x".to_string(),
            unconvertible_count: 10,
            detail: "d".to_string(),
        },
        MigrationContractError::OldFormatRejected {
            migration_id: "x".to_string(),
            object_class: ObjectClass::KeyFormat,
            detail: "d".to_string(),
        },
        MigrationContractError::DuplicateMigration {
            migration_id: "x".to_string(),
        },
        MigrationContractError::RollbackFailed {
            migration_id: "x".to_string(),
            detail: "d".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: MigrationContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, deser);
    }
}

// ===========================================================================
// Section 7: error_code function
// ===========================================================================

#[test]
fn error_codes_stable_all_variants() {
    assert_eq!(
        error_code(&MigrationContractError::MigrationNotFound {
            migration_id: "x".to_string()
        }),
        "MC_MIGRATION_NOT_FOUND"
    );
    assert_eq!(
        error_code(&MigrationContractError::InvalidTransition {
            from: MigrationState::Declared,
            to: MigrationState::Executing,
        }),
        "MC_INVALID_TRANSITION"
    );
    assert_eq!(
        error_code(&MigrationContractError::DryRunFailed {
            migration_id: "x".to_string(),
            unconvertible_count: 5,
            detail: "d".to_string(),
        }),
        "MC_DRY_RUN_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::VerificationFailed {
            migration_id: "x".to_string(),
            discrepancy_count: 3,
            detail: "d".to_string(),
        }),
        "MC_VERIFICATION_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::OldFormatRejected {
            migration_id: "x".to_string(),
            object_class: ObjectClass::KeyFormat,
            detail: "d".to_string(),
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
            detail: "d".to_string(),
        }),
        "MC_ROLLBACK_FAILED"
    );
    assert_eq!(
        error_code(&MigrationContractError::ParallelRunDiscrepancy {
            migration_id: "x".to_string(),
            discrepancy_count: 3,
        }),
        "MC_PARALLEL_DISCREPANCY"
    );
}

// ===========================================================================
// Section 8: MigrationEvent
// ===========================================================================

#[test]
fn migration_event_serde_roundtrip() {
    let event = MigrationEvent {
        trace_id: "t-1".to_string(),
        component: "migration_contract".to_string(),
        event: "migration_declared".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        migration_id: Some("m-1".to_string()),
        step: None,
        affected_count: Some(100),
        from_version: Some("v1".to_string()),
        to_version: Some("v2".to_string()),
        timestamp: DeterministicTimestamp(42),
    };
    let json = serde_json::to_string(&event).unwrap();
    let deser: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deser);
}

#[test]
fn migration_event_with_error_code() {
    let event = MigrationEvent {
        trace_id: "t-1".to_string(),
        component: "migration_contract".to_string(),
        event: "dry_run_complete".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("MC_DRY_RUN_FAILED".to_string()),
        migration_id: Some("m-1".to_string()),
        step: None,
        affected_count: Some(10),
        from_version: Some("v1".to_string()),
        to_version: Some("v2".to_string()),
        timestamp: DeterministicTimestamp(100),
    };
    let json = serde_json::to_string(&event).unwrap();
    let deser: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deser);
}

// ===========================================================================
// Section 9: DryRunResult
// ===========================================================================

#[test]
fn dry_run_result_passed_when_zero_unconvertible() {
    let result = passing_dry_run("m-1");
    assert!(result.passed());
    assert_eq!(result.unconvertible, 0);
    assert_eq!(result.total_objects, 100);
}

#[test]
fn dry_run_result_not_passed_when_unconvertible() {
    let result = failing_dry_run("m-1");
    assert!(!result.passed());
    assert_eq!(result.unconvertible, 10);
}

#[test]
fn dry_run_result_serde_roundtrip() {
    let result = passing_dry_run("m-1");
    let json = serde_json::to_string(&result).unwrap();
    let deser: DryRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
}

#[test]
fn dry_run_result_with_details_serde_roundtrip() {
    let result = failing_dry_run("m-1");
    let json = serde_json::to_string(&result).unwrap();
    let deser: DryRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
    assert_eq!(deser.details.len(), 1);
}

// ===========================================================================
// Section 10: VerificationResult
// ===========================================================================

#[test]
fn verification_result_passed_when_zero_discrepancies() {
    let result = passing_verification("m-1");
    assert!(result.passed());
    assert_eq!(result.discrepancies, 0);
}

#[test]
fn verification_result_not_passed_when_discrepancies() {
    let result = failing_verification("m-1");
    assert!(!result.passed());
    assert_eq!(result.discrepancies, 5);
}

#[test]
fn verification_result_serde_roundtrip() {
    let result = failing_verification("m-1");
    let json = serde_json::to_string(&result).unwrap();
    let deser: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
}

// ===========================================================================
// Section 11: AppliedMigrationRecord
// ===========================================================================

#[test]
fn applied_migration_record_serde_roundtrip() {
    let record = AppliedMigrationRecord {
        migration_id: "m-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::HardCutover,
        affected_objects: vec![ObjectClass::KeyFormat, ObjectClass::TokenFormat],
        applied_at: DeterministicTimestamp(42),
        checkpoint_seq: 10,
    };
    let json = serde_json::to_string(&record).unwrap();
    let deser: AppliedMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, deser);
}

#[test]
fn applied_migration_record_fields() {
    let record = AppliedMigrationRecord {
        migration_id: "m-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::SoftMigration,
        affected_objects: vec![ObjectClass::CheckpointFormat],
        applied_at: DeterministicTimestamp(100),
        checkpoint_seq: 5,
    };
    assert_eq!(record.migration_id, "m-1");
    assert_eq!(record.cutover_type, CutoverType::SoftMigration);
    assert_eq!(record.checkpoint_seq, 5);
}

// ===========================================================================
// Section 12: MigrationRunner — construction and defaults
// ===========================================================================

#[test]
fn runner_new_empty() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.migration_count(), 0);
    assert_eq!(runner.applied_count(), 0);
    assert!(runner.applied_migrations().is_empty());
    assert!(runner.events().is_empty());
}

#[test]
fn runner_default_same_as_new() {
    let runner = MigrationRunner::default();
    assert_eq!(runner.migration_count(), 0);
    assert_eq!(runner.applied_count(), 0);
}

// ===========================================================================
// Section 13: MigrationRunner — declare
// ===========================================================================

#[test]
fn declare_migration() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    assert_eq!(runner.migration_count(), 1);
    assert_eq!(runner.state("m-1"), Some(MigrationState::Declared));
}

#[test]
fn declare_duplicate_rejected() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::DuplicateMigration { .. }
    ));
}

#[test]
fn declare_multiple_migrations() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner
        .declare(make_declaration("m-2", CutoverType::SoftMigration), "t")
        .unwrap();
    runner
        .declare(make_declaration("m-3", CutoverType::ParallelRun), "t")
        .unwrap();
    assert_eq!(runner.migration_count(), 3);
}

#[test]
fn declaration_accessor() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let decl = runner.declaration("m-1").unwrap();
    assert_eq!(decl.migration_id, "m-1");
    assert_eq!(decl.cutover_type, CutoverType::HardCutover);
}

#[test]
fn declaration_missing_returns_none() {
    let runner = MigrationRunner::new();
    assert!(runner.declaration("missing").is_none());
}

// ===========================================================================
// Section 14: MigrationRunner — dry run
// ===========================================================================

#[test]
fn dry_run_pass_transitions_to_dry_run_passed() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunPassed));
}

#[test]
fn dry_run_fail_transitions_to_dry_run_failed() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .dry_run("m-1", failing_dry_run("m-1"), "t")
        .unwrap_err();
    assert!(matches!(err, MigrationContractError::DryRunFailed { .. }));
    assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunFailed));
}

#[test]
fn dry_run_requires_declared_state() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    let err = runner
        .dry_run("m-1", passing_dry_run("m-1"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn dry_run_missing_migration_fails() {
    let mut runner = MigrationRunner::new();
    let err = runner
        .dry_run("missing", passing_dry_run("missing"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::MigrationNotFound { .. }
    ));
}

// ===========================================================================
// Section 15: MigrationRunner — checkpoint
// ===========================================================================

#[test]
fn checkpoint_after_dry_run_transitions_to_executing() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::Executing));
}

#[test]
fn checkpoint_requires_dry_run_passed() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner.create_checkpoint("m-1", 42, "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn checkpoint_missing_migration_fails() {
    let mut runner = MigrationRunner::new();
    let err = runner.create_checkpoint("missing", 42, "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::MigrationNotFound { .. }
    ));
}

// ===========================================================================
// Section 16: MigrationRunner — execute
// ===========================================================================

#[test]
fn complete_execution_transitions_to_verifying() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.complete_execution("m-1", 100, "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::Verifying));
}

#[test]
fn complete_execution_requires_executing() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner.complete_execution("m-1", 100, "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

// ===========================================================================
// Section 17: MigrationRunner — verify
// ===========================================================================

#[test]
fn verification_pass_transitions_to_verified() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.complete_execution("m-1", 100, "t").unwrap();
    runner
        .verify("m-1", passing_verification("m-1"), "t")
        .unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::Verified));
}

#[test]
fn verification_fail_transitions_to_verification_failed() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.complete_execution("m-1", 100, "t").unwrap();
    let err = runner
        .verify("m-1", failing_verification("m-1"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::VerificationFailed { .. }
    ));
    assert_eq!(
        runner.state("m-1"),
        Some(MigrationState::VerificationFailed)
    );
}

#[test]
fn verification_requires_verifying_state() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .verify("m-1", passing_verification("m-1"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

// ===========================================================================
// Section 18: MigrationRunner — commit
// ===========================================================================

#[test]
fn commit_migration() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
    assert_eq!(runner.state("m-1"), Some(MigrationState::Committed));
    assert_eq!(runner.applied_count(), 1);
    assert_eq!(runner.applied_migrations()[0].migration_id, "m-1");
}

#[test]
fn commit_requires_verified() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner.commit("m-1", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn commit_missing_migration_fails() {
    let mut runner = MigrationRunner::new();
    let err = runner.commit("missing", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::MigrationNotFound { .. }
    ));
}

// ===========================================================================
// Section 19: MigrationRunner — rollback
// ===========================================================================

#[test]
fn rollback_from_executing() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.rollback("m-1", "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
}

#[test]
fn rollback_from_verifying() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.complete_execution("m-1", 100, "t").unwrap();
    runner.rollback("m-1", "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
}

#[test]
fn rollback_from_dry_run_passed() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.rollback("m-1", "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
}

#[test]
fn rollback_from_declared_fails() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner.rollback("m-1", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn rollback_from_committed_fails() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
    let err = runner.rollback("m-1", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn rollback_from_dry_run_failed_fails() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let _ = runner.dry_run("m-1", failing_dry_run("m-1"), "t");
    let err = runner.rollback("m-1", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::InvalidTransition { .. }
    ));
}

#[test]
fn rollback_missing_migration_fails() {
    let mut runner = MigrationRunner::new();
    let err = runner.rollback("missing", "t").unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::MigrationNotFound { .. }
    ));
}

// ===========================================================================
// Section 20: MigrationRunner — format enforcement (hard cutover)
// ===========================================================================

#[test]
fn hard_cutover_rejects_old_format() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::OldFormatRejected { .. }
    ));
}

#[test]
fn hard_cutover_accepts_new_format() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
        .unwrap();
}

#[test]
fn hard_cutover_only_rejects_affected_classes() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
    // TokenFormat is NOT in affected_objects
    runner
        .check_format_acceptance(ObjectClass::TokenFormat, "v1")
        .unwrap();
}

#[test]
fn soft_migration_does_not_reject_old_format_via_check() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
        .unwrap();
}

// ===========================================================================
// Section 21: MigrationRunner — soft migration window
// ===========================================================================

#[test]
fn soft_migration_window_open_before_end() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);
    runner.set_tick(500);
    assert_eq!(runner.check_soft_migration_window("m-1"), Some(true));
}

#[test]
fn soft_migration_window_closed_after_end() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);
    runner.set_tick(1000);
    assert_eq!(runner.check_soft_migration_window("m-1"), Some(false));
}

#[test]
fn soft_migration_window_none_for_hard_cutover() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
    // Hard cutover is not SoftMigration, should return None
    assert_eq!(runner.check_soft_migration_window("m-1"), None);
}

#[test]
fn soft_migration_window_missing_migration() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.check_soft_migration_window("missing"), None);
}

// ===========================================================================
// Section 22: MigrationRunner — events
// ===========================================================================

#[test]
fn events_emitted_for_full_pipeline() {
    let mut runner = MigrationRunner::new();
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

    let events = runner.drain_events();
    assert!(events.len() >= 5);

    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"migration_declared"));
    assert!(event_names.contains(&"dry_run_complete"));
    assert!(event_names.contains(&"checkpoint_created"));
    assert!(event_names.contains(&"execution_complete"));
    assert!(event_names.contains(&"verification_complete"));
    assert!(event_names.contains(&"migration_committed"));

    assert!(events.iter().all(|e| e.component == "migration_contract"));
}

#[test]
fn rollback_events_emitted() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.rollback("m-1", "t").unwrap();

    let events = runner.drain_events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"rollback_started"));
    assert!(event_names.contains(&"rollback_complete"));
}

#[test]
fn drain_clears_events() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(!runner.events().is_empty());
    let drained = runner.drain_events();
    assert!(!drained.is_empty());
    assert!(runner.events().is_empty());
}

// ===========================================================================
// Section 23: MigrationRunner — summary
// ===========================================================================

#[test]
fn summary_shows_all_migrations() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_pipeline(&mut runner, "m-2", CutoverType::SoftMigration);

    let summary = runner.summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary["m-1"], MigrationState::Declared);
    assert_eq!(summary["m-2"], MigrationState::Committed);
}

#[test]
fn summary_empty_runner() {
    let runner = MigrationRunner::new();
    assert!(runner.summary().is_empty());
}

// ===========================================================================
// Section 24: MigrationRunner — multiple migrations in order
// ===========================================================================

#[test]
fn multiple_migrations_applied_in_order() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);

    let mut d1 = make_declaration("m-1", CutoverType::HardCutover);
    d1.from_version = "v1".to_string();
    d1.to_version = "v2".to_string();
    runner.declare(d1, "t").unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 10, "t").unwrap();
    runner.complete_execution("m-1", 50, "t").unwrap();
    runner
        .verify("m-1", passing_verification("m-1"), "t")
        .unwrap();
    runner.commit("m-1", "t").unwrap();

    runner.set_tick(100);
    let mut d2 = make_declaration("m-2", CutoverType::SoftMigration);
    d2.from_version = "v2".to_string();
    d2.to_version = "v3".to_string();
    runner.declare(d2, "t").unwrap();
    runner.dry_run("m-2", passing_dry_run("m-2"), "t").unwrap();
    runner.create_checkpoint("m-2", 20, "t").unwrap();
    runner.complete_execution("m-2", 50, "t").unwrap();
    runner
        .verify("m-2", passing_verification("m-2"), "t")
        .unwrap();
    runner.commit("m-2", "t").unwrap();

    assert_eq!(runner.applied_count(), 2);
    assert_eq!(runner.applied_migrations()[0].from_version, "v1");
    assert_eq!(runner.applied_migrations()[0].to_version, "v2");
    assert_eq!(runner.applied_migrations()[1].from_version, "v2");
    assert_eq!(runner.applied_migrations()[1].to_version, "v3");
}

// ===========================================================================
// Section 25: MigrationRunner — state accessor for missing migration
// ===========================================================================

#[test]
fn state_returns_none_for_unknown() {
    let runner = MigrationRunner::new();
    assert_eq!(runner.state("nonexistent"), None);
}

// ===========================================================================
// Section 26: Deterministic replay
// ===========================================================================

#[test]
fn full_pipeline_deterministic() {
    let run = || {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
        let events = runner.drain_events();
        serde_json::to_string(&events).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Section 27: Applied migration record after commit
// ===========================================================================

#[test]
fn applied_record_has_correct_fields() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(42);
    run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

    let record = &runner.applied_migrations()[0];
    assert_eq!(record.migration_id, "m-1");
    assert_eq!(record.from_version, "v1");
    assert_eq!(record.to_version, "v2");
    assert_eq!(record.cutover_type, CutoverType::HardCutover);
    assert_eq!(record.checkpoint_seq, 42);
    assert_eq!(record.applied_at, DeterministicTimestamp(42));
}

// ===========================================================================
// Section 28: Chained hard cutover rejections
// ===========================================================================

#[test]
fn chained_hard_cutovers_reject_old_format() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);

    // First migration v1 -> v2
    let mut d1 = make_declaration("m-1", CutoverType::HardCutover);
    d1.from_version = "v1".to_string();
    d1.to_version = "v2".to_string();
    run_full_pipeline_custom(&mut runner, "m-1", d1);

    // Second migration v2 -> v3
    runner.set_tick(100);
    let mut d2 = make_declaration("m-2", CutoverType::HardCutover);
    d2.from_version = "v2".to_string();
    d2.to_version = "v3".to_string();
    run_full_pipeline_custom(&mut runner, "m-2", d2);

    // v1 rejected by first migration
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::OldFormatRejected { .. }
    ));

    // v2 rejected by second migration
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
        .unwrap_err();
    assert!(matches!(
        err,
        MigrationContractError::OldFormatRejected { .. }
    ));

    // v3 is current, should be accepted
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema, "v3")
        .unwrap();
}

fn run_full_pipeline_custom(runner: &mut MigrationRunner, mid: &str, decl: MigrationDeclaration) {
    runner.declare(decl, "trace-1").unwrap();
    runner
        .dry_run(mid, passing_dry_run(mid), "trace-1")
        .unwrap();
    runner.create_checkpoint(mid, 42, "trace-1").unwrap();
    runner.complete_execution(mid, 100, "trace-1").unwrap();
    runner
        .verify(mid, passing_verification(mid), "trace-1")
        .unwrap();
    runner.commit(mid, "trace-1").unwrap();
}

// ===========================================================================
// Section 29: Operations on missing migration all fail
// ===========================================================================

#[test]
fn operations_on_missing_migration_fail() {
    let mut runner = MigrationRunner::new();
    assert!(matches!(
        runner.dry_run("missing", passing_dry_run("missing"), "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
    assert!(matches!(
        runner.create_checkpoint("missing", 42, "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
    assert!(matches!(
        runner.complete_execution("missing", 100, "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
    assert!(matches!(
        runner.verify("missing", passing_verification("missing"), "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
    assert!(matches!(
        runner.commit("missing", "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
    assert!(matches!(
        runner.rollback("missing", "t"),
        Err(MigrationContractError::MigrationNotFound { .. })
    ));
}

// ===========================================================================
// Section 30: Events have correct timestamps
// ===========================================================================

#[test]
fn events_have_timestamps() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(42);
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    let events = runner.events();
    assert_eq!(events[0].timestamp, DeterministicTimestamp(42));
}

// ===========================================================================
// Section 31: Soft migration with transition window at tick boundary
// ===========================================================================

#[test]
fn soft_migration_window_boundary() {
    let mut runner = MigrationRunner::new();
    runner.set_tick(0);
    run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

    // transition_end_tick is 1000, window should close at tick 1000
    runner.set_tick(999);
    assert_eq!(runner.check_soft_migration_window("m-1"), Some(true));

    runner.set_tick(1000);
    assert_eq!(runner.check_soft_migration_window("m-1"), Some(false));
}

// ===========================================================================
// Section 32: Rollback from verified state
// ===========================================================================

#[test]
fn rollback_from_verified() {
    let mut runner = MigrationRunner::new();
    runner
        .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
    runner.create_checkpoint("m-1", 42, "t").unwrap();
    runner.complete_execution("m-1", 100, "t").unwrap();
    runner
        .verify("m-1", passing_verification("m-1"), "t")
        .unwrap();
    runner.rollback("m-1", "t").unwrap();
    assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
}
