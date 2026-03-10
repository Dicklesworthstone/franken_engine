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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::migration_compatibility::{
    AppliedMigrationEntry, CutoverAuditEvent, CutoverError, CutoverMigrationRunner, CutoverState,
    CutoverType, GoldenLedgerManifest, IncompatibleField, ManifestEntry,
    MigrationCompatibilityEvent, MigrationDeclaration, MigrationError, MigrationErrorCode,
    MigrationFunction, MigrationOutcome, MigrationPhase, MigrationRegistry, MigrationTestResult,
    ObjectClass, PhaseExecutionRecord, PhaseOutcome, TransitionWindow, cutover_error_code,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    MigrationDeclaration {
        migration_id: id.to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: affected,
        cutover_type: cutover,
        description: "test migration".to_string(),
        compatible_across_boundary: vec!["wire format".to_string()],
        incompatible_across_boundary: vec!["storage format".to_string()],
    }
}

fn run_full_migration(runner: &mut CutoverMigrationRunner, id: &str) -> AppliedMigrationEntry {
    runner.begin(id, 100, "trace-1").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "trace-1").unwrap();
    runner.set_tick(20);
    runner.execute(100, "trace-1").unwrap();
    runner.set_tick(30);
    runner.verify(0, "trace-1").unwrap();
    runner.set_tick(40);
    runner.commit("trace-1").unwrap()
}

// ===========================================================================
// MigrationErrorCode — exhaustive Display
// ===========================================================================

#[test]
fn migration_error_code_display_all_variants() {
    let cases = [
        (
            MigrationErrorCode::MajorVersionIncompatible,
            "major_version_incompatible",
        ),
        (
            MigrationErrorCode::RequiredFieldMissing,
            "required_field_missing",
        ),
        (MigrationErrorCode::FieldTypeChanged, "field_type_changed"),
        (
            MigrationErrorCode::MigrationFunctionFailed,
            "migration_function_failed",
        ),
        (
            MigrationErrorCode::NonDeterministicMigration,
            "non_deterministic_migration",
        ),
        (
            MigrationErrorCode::PartialReplayFailure,
            "partial_replay_failure",
        ),
        (MigrationErrorCode::NoMigrationPath, "no_migration_path"),
        (MigrationErrorCode::LossyMigration, "lossy_migration"),
    ];
    for (code, expected) in cases {
        assert_eq!(code.to_string(), expected, "Display for {code:?}");
    }
}

#[test]
fn migration_error_code_hash_deterministic() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(MigrationErrorCode::MajorVersionIncompatible);
    set.insert(MigrationErrorCode::MajorVersionIncompatible);
    assert_eq!(set.len(), 1);
    set.insert(MigrationErrorCode::LossyMigration);
    assert_eq!(set.len(), 2);
}

#[test]
fn migration_error_code_serde_all_variants() {
    for code in [
        MigrationErrorCode::MajorVersionIncompatible,
        MigrationErrorCode::RequiredFieldMissing,
        MigrationErrorCode::FieldTypeChanged,
        MigrationErrorCode::MigrationFunctionFailed,
        MigrationErrorCode::NonDeterministicMigration,
        MigrationErrorCode::PartialReplayFailure,
        MigrationErrorCode::NoMigrationPath,
        MigrationErrorCode::LossyMigration,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let restored: MigrationErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, restored, "roundtrip for {code:?}");
    }
}

// ===========================================================================
// MigrationError — Display and std::error::Error
// ===========================================================================

#[test]
fn migration_error_display_zero_incompatible_fields() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::NoMigrationPath,
        incompatible_fields: Vec::new(),
        message: "no path".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("0 incompatible fields"));
    assert!(s.contains("v1"));
    assert!(s.contains("v2"));
    assert!(s.contains("no_migration_path"));
}

#[test]
fn migration_error_display_many_incompatible_fields() {
    let fields: Vec<IncompatibleField> = (0..5)
        .map(|i| IncompatibleField {
            field_path: format!("field_{i}"),
            reason: format!("reason_{i}"),
        })
        .collect();
    let err = MigrationError {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v3".to_string(),
        error_code: MigrationErrorCode::FieldTypeChanged,
        incompatible_fields: fields,
        message: "multiple fields changed type".to_string(),
    };
    assert!(err.to_string().contains("5 incompatible fields"));
}

#[test]
fn migration_error_implements_std_error() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::MajorVersionIncompatible,
        incompatible_fields: Vec::new(),
        message: "test".to_string(),
    };
    let e: &dyn std::error::Error = &err;
    assert!(e.source().is_none());
    assert!(!e.to_string().is_empty());
}

#[test]
fn migration_error_serde_roundtrip() {
    let err = MigrationError {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v3".to_string(),
        error_code: MigrationErrorCode::LossyMigration,
        incompatible_fields: vec![IncompatibleField {
            field_path: "metadata.precision".to_string(),
            reason: "f64 truncated to f32".to_string(),
        }],
        message: "precision loss in migration".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: MigrationError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

// ===========================================================================
// IncompatibleField — serde
// ===========================================================================

#[test]
fn incompatible_field_serde_roundtrip() {
    let field = IncompatibleField {
        field_path: "metadata.x.y".to_string(),
        reason: "nested field removed".to_string(),
    };
    let json = serde_json::to_string(&field).expect("serialize");
    let restored: IncompatibleField = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(field, restored);
}

// ===========================================================================
// MigrationFunction — serde
// ===========================================================================

#[test]
fn migration_function_serde_roundtrip() {
    let func = MigrationFunction {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
        lossy: true,
        description: "lossy schema change".to_string(),
    };
    let json = serde_json::to_string(&func).expect("serialize");
    let restored: MigrationFunction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(func.from_version, restored.from_version);
    assert_eq!(func.to_version, restored.to_version);
    assert_eq!(func.lossy, restored.lossy);
    assert_eq!(func.description, restored.description);
}

// ===========================================================================
// MigrationRegistry — Default, edge cases
// ===========================================================================

#[test]
fn migration_registry_default_is_empty() {
    let registry = MigrationRegistry::default();
    assert!(registry.all().is_empty());
    assert!(registry.find("any", "other").is_none());
}

// ===========================================================================
// MigrationOutcome — Display all + serde all
// ===========================================================================

#[test]
fn migration_outcome_display_all() {
    assert_eq!(
        MigrationOutcome::BackwardCompatible.to_string(),
        "backward_compatible"
    );
    assert_eq!(
        MigrationOutcome::MigratedSuccessfully.to_string(),
        "migrated_successfully"
    );
    assert_eq!(
        MigrationOutcome::LossyMigration.to_string(),
        "lossy_migration"
    );
    assert_eq!(MigrationOutcome::Failed.to_string(), "failed");
}

#[test]
fn migration_outcome_serde_all_variants() {
    for outcome in [
        MigrationOutcome::BackwardCompatible,
        MigrationOutcome::MigratedSuccessfully,
        MigrationOutcome::LossyMigration,
        MigrationOutcome::Failed,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let restored: MigrationOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, restored, "roundtrip for {outcome}");
    }
}

// ===========================================================================
// MigrationTestResult — passed() edge cases + serde
// ===========================================================================

#[test]
fn test_result_failed_outcome_not_passed_even_with_no_errors() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::Failed,
        entries_processed: 0,
        entries_replayed_ok: 0,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(!result.passed(), "Failed outcome should not pass");
}

#[test]
fn test_result_backward_compatible_with_no_violations_passes() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v1".to_string(),
        outcome: MigrationOutcome::BackwardCompatible,
        entries_processed: 10,
        entries_replayed_ok: 10,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(result.passed());
}

#[test]
fn test_result_lossy_with_violations_fails() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::LossyMigration,
        entries_processed: 10,
        entries_replayed_ok: 8,
        errors: Vec::new(),
        replay_violations: 2,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(!result.passed());
}

#[test]
fn test_result_serde_roundtrip() {
    let result = MigrationTestResult {
        golden_ledger_name: "corpus-v1".to_string(),
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
        outcome: MigrationOutcome::MigratedSuccessfully,
        entries_processed: 5,
        entries_replayed_ok: 5,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: MigrationTestResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result.golden_ledger_name, restored.golden_ledger_name);
    assert_eq!(result.outcome, restored.outcome);
    assert_eq!(result.entries_processed, restored.entries_processed);
}

// ===========================================================================
// MigrationCompatibilityEvent — serde
// ===========================================================================

#[test]
fn migration_compatibility_event_serde_with_error_code() {
    let event = MigrationCompatibilityEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "migration_compatibility".to_string(),
        event: "no_migration_path".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("no_migration_path".to_string()),
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn migration_compatibility_event_serde_without_error_code() {
    let event = MigrationCompatibilityEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "migration_compatibility".to_string(),
        event: "backward_compat_check".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        from_version: "v1".to_string(),
        to_version: "v1".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// ===========================================================================
// GoldenLedgerManifest — edge cases
// ===========================================================================

#[test]
fn manifest_default_is_empty() {
    let manifest = GoldenLedgerManifest::default();
    assert!(manifest.is_empty());
    assert_eq!(manifest.len(), 0);
}

#[test]
fn manifest_entry_serde_roundtrip() {
    let entry = ManifestEntry {
        schema_version: "evidence-v1".to_string(),
        corpus_hash: ContentHash::compute(b"test data"),
        entry_count: 42,
        frozen_at_ms: 1_700_000_000_000,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: ManifestEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn manifest_serde_roundtrip_empty() {
    let manifest = GoldenLedgerManifest::new();
    let json = serde_json::to_string(&manifest).expect("serialize");
    let restored: GoldenLedgerManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, restored);
}

// ===========================================================================
// CutoverType — Display + serde + ordering
// ===========================================================================

#[test]
fn cutover_type_display_all() {
    assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
    assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
    assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
}

#[test]
fn cutover_type_serde_all_variants() {
    for ct in [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ] {
        let json = serde_json::to_string(&ct).expect("serialize");
        let restored: CutoverType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ct, restored);
    }
}

#[test]
fn cutover_type_ordering() {
    assert!(CutoverType::HardCutover < CutoverType::SoftMigration);
    assert!(CutoverType::SoftMigration < CutoverType::ParallelRun);
}

// ===========================================================================
// ObjectClass — Display all variants + ordering + serde
// ===========================================================================

#[test]
fn object_class_display_all_variants() {
    let cases = [
        (ObjectClass::SerializationSchema, "serialization_schema"),
        (ObjectClass::KeyFormat, "key_format"),
        (ObjectClass::TokenFormat, "token_format"),
        (ObjectClass::CheckpointFormat, "checkpoint_format"),
        (ObjectClass::RevocationFormat, "revocation_format"),
        (ObjectClass::PolicyFormat, "policy_format"),
    ];
    for (class, expected) in cases {
        assert_eq!(class.to_string(), expected, "Display for {class:?}");
    }
}

#[test]
fn object_class_serde_all_variants() {
    for oc in [
        ObjectClass::SerializationSchema,
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyFormat,
    ] {
        let json = serde_json::to_string(&oc).expect("serialize");
        let restored: ObjectClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(oc, restored);
    }
}

#[test]
fn object_class_ordering() {
    assert!(ObjectClass::SerializationSchema < ObjectClass::KeyFormat);
    assert!(ObjectClass::KeyFormat < ObjectClass::TokenFormat);
    assert!(ObjectClass::TokenFormat < ObjectClass::CheckpointFormat);
    assert!(ObjectClass::CheckpointFormat < ObjectClass::RevocationFormat);
    assert!(ObjectClass::RevocationFormat < ObjectClass::PolicyFormat);
}

// ===========================================================================
// MigrationPhase — Display all variants + serde + ordering
// ===========================================================================

#[test]
fn migration_phase_display_all_variants() {
    let cases = [
        (MigrationPhase::PreMigration, "pre_migration"),
        (MigrationPhase::Checkpoint, "checkpoint"),
        (MigrationPhase::Execute, "execute"),
        (MigrationPhase::Verify, "verify"),
        (MigrationPhase::Commit, "commit"),
        (MigrationPhase::Rollback, "rollback"),
    ];
    for (phase, expected) in cases {
        assert_eq!(phase.to_string(), expected, "Display for {phase:?}");
    }
}

#[test]
fn migration_phase_serde_all_variants() {
    for phase in [
        MigrationPhase::PreMigration,
        MigrationPhase::Checkpoint,
        MigrationPhase::Execute,
        MigrationPhase::Verify,
        MigrationPhase::Commit,
        MigrationPhase::Rollback,
    ] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let restored: MigrationPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(phase, restored);
    }
}

#[test]
fn migration_phase_ordering() {
    assert!(MigrationPhase::PreMigration < MigrationPhase::Checkpoint);
    assert!(MigrationPhase::Checkpoint < MigrationPhase::Execute);
    assert!(MigrationPhase::Execute < MigrationPhase::Verify);
    assert!(MigrationPhase::Verify < MigrationPhase::Commit);
    assert!(MigrationPhase::Commit < MigrationPhase::Rollback);
}

// ===========================================================================
// PhaseOutcome — Display + serde + ordering
// ===========================================================================

#[test]
fn phase_outcome_display_all() {
    assert_eq!(PhaseOutcome::Success.to_string(), "success");
    assert_eq!(PhaseOutcome::Failed.to_string(), "failed");
    assert_eq!(PhaseOutcome::Skipped.to_string(), "skipped");
}

#[test]
fn phase_outcome_serde_all_variants() {
    for outcome in [
        PhaseOutcome::Success,
        PhaseOutcome::Failed,
        PhaseOutcome::Skipped,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let restored: PhaseOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, restored);
    }
}

#[test]
fn phase_outcome_ordering() {
    assert!(PhaseOutcome::Success < PhaseOutcome::Failed);
    assert!(PhaseOutcome::Failed < PhaseOutcome::Skipped);
}

// ===========================================================================
// CutoverState — Display all + serde all + ordering
// ===========================================================================

#[test]
fn cutover_state_display_all_variants() {
    let cases = [
        (CutoverState::Declared, "declared"),
        (CutoverState::PreMigrated, "pre_migrated"),
        (CutoverState::Checkpointed, "checkpointed"),
        (CutoverState::Executed, "executed"),
        (CutoverState::Verified, "verified"),
        (CutoverState::Committed, "committed"),
        (CutoverState::RolledBack, "rolled_back"),
    ];
    for (state, expected) in cases {
        assert_eq!(state.to_string(), expected, "Display for {state:?}");
    }
}

#[test]
fn cutover_state_serde_all_variants() {
    for state in [
        CutoverState::Declared,
        CutoverState::PreMigrated,
        CutoverState::Checkpointed,
        CutoverState::Executed,
        CutoverState::Verified,
        CutoverState::Committed,
        CutoverState::RolledBack,
    ] {
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: CutoverState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }
}

#[test]
fn cutover_state_ordering() {
    assert!(CutoverState::Declared < CutoverState::PreMigrated);
    assert!(CutoverState::PreMigrated < CutoverState::Checkpointed);
    assert!(CutoverState::Checkpointed < CutoverState::Executed);
    assert!(CutoverState::Executed < CutoverState::Verified);
    assert!(CutoverState::Verified < CutoverState::Committed);
    assert!(CutoverState::Committed < CutoverState::RolledBack);
}

// ===========================================================================
// CutoverError — Display with specific content
// ===========================================================================

#[test]
fn cutover_error_display_invalid_declaration() {
    let err = CutoverError::InvalidDeclaration {
        detail: "migration_id is empty".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("invalid migration declaration"));
    assert!(s.contains("migration_id is empty"));
}

#[test]
fn cutover_error_display_dry_run_failed() {
    let err = CutoverError::DryRunFailed {
        unconvertible_count: 42,
    };
    assert!(err.to_string().contains("42 unconvertible objects"));
}

#[test]
fn cutover_error_display_verification_failed() {
    let err = CutoverError::VerificationFailed { violations: 7 };
    assert!(err.to_string().contains("7 violations"));
}

#[test]
fn cutover_error_display_parallel_discrepancy() {
    let err = CutoverError::ParallelRunDiscrepancy {
        discrepancy_count: 3,
    };
    assert!(err.to_string().contains("3 mismatches"));
}

#[test]
fn cutover_error_display_old_format_rejected() {
    let err = CutoverError::OldFormatRejected {
        object_class: ObjectClass::TokenFormat,
    };
    let s = err.to_string();
    assert!(s.contains("old-format object rejected"));
    assert!(s.contains("token_format"));
}

#[test]
fn cutover_error_display_transition_expired() {
    let err = CutoverError::TransitionWindowExpired {
        migration_id: "mig-soft-1".to_string(),
    };
    assert!(err.to_string().contains("mig-soft-1"));
}

#[test]
fn cutover_error_display_phase_failed() {
    let err = CutoverError::PhaseFailed {
        phase: MigrationPhase::Checkpoint,
        detail: "disk full".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("checkpoint"));
    assert!(s.contains("disk full"));
}

#[test]
fn cutover_error_display_already_committed() {
    let err = CutoverError::AlreadyCommitted {
        migration_id: "mig-1".to_string(),
    };
    assert!(err.to_string().contains("already committed"));
    assert!(err.to_string().contains("mig-1"));
}

#[test]
fn cutover_error_display_no_migration_in_progress() {
    let err = CutoverError::NoMigrationInProgress;
    assert_eq!(err.to_string(), "no migration in progress");
}

#[test]
fn cutover_error_display_migration_not_found() {
    let err = CutoverError::MigrationNotFound {
        migration_id: "nonexistent".to_string(),
    };
    assert!(err.to_string().contains("migration not found"));
    assert!(err.to_string().contains("nonexistent"));
}

// ===========================================================================
// CutoverError — std::error::Error
// ===========================================================================

#[test]
fn cutover_error_implements_std_error() {
    let err = CutoverError::NoMigrationInProgress;
    let e: &dyn std::error::Error = &err;
    assert!(e.source().is_none());
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// cutover_error_code — exhaustive coverage
// ===========================================================================

#[test]
fn cutover_error_code_all_variants() {
    let cases: Vec<(CutoverError, &str)> = vec![
        (
            CutoverError::InvalidDeclaration {
                detail: "x".to_string(),
            },
            "MC_INVALID_DECLARATION",
        ),
        (
            CutoverError::DryRunFailed {
                unconvertible_count: 1,
            },
            "MC_DRY_RUN_FAILED",
        ),
        (
            CutoverError::VerificationFailed { violations: 1 },
            "MC_VERIFICATION_FAILED",
        ),
        (
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 1,
            },
            "MC_PARALLEL_DISCREPANCY",
        ),
        (
            CutoverError::OldFormatRejected {
                object_class: ObjectClass::KeyFormat,
            },
            "MC_OLD_FORMAT_REJECTED",
        ),
        (
            CutoverError::TransitionWindowExpired {
                migration_id: "m".to_string(),
            },
            "MC_WINDOW_EXPIRED",
        ),
        (
            CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: "x".to_string(),
            },
            "MC_PHASE_FAILED",
        ),
        (
            CutoverError::AlreadyCommitted {
                migration_id: "m".to_string(),
            },
            "MC_ALREADY_COMMITTED",
        ),
        (CutoverError::NoMigrationInProgress, "MC_NO_MIGRATION"),
        (
            CutoverError::MigrationNotFound {
                migration_id: "m".to_string(),
            },
            "MC_NOT_FOUND",
        ),
    ];
    for (err, expected_code) in cases {
        assert_eq!(
            cutover_error_code(&err),
            expected_code,
            "error code for {err:?}"
        );
    }
}

// ===========================================================================
// CutoverError — serde roundtrip all variants
// ===========================================================================

#[test]
fn cutover_error_serde_all_variants() {
    let errors: Vec<CutoverError> = vec![
        CutoverError::InvalidDeclaration {
            detail: "test".to_string(),
        },
        CutoverError::DryRunFailed {
            unconvertible_count: 5,
        },
        CutoverError::VerificationFailed { violations: 3 },
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 2,
        },
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::PolicyFormat,
        },
        CutoverError::TransitionWindowExpired {
            migration_id: "mig-1".to_string(),
        },
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Rollback,
            detail: "detail".to_string(),
        },
        CutoverError::AlreadyCommitted {
            migration_id: "mig-1".to_string(),
        },
        CutoverError::NoMigrationInProgress,
        CutoverError::MigrationNotFound {
            migration_id: "mig-1".to_string(),
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: CutoverError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored, "roundtrip for {err:?}");
    }
}

// ===========================================================================
// TransitionWindow — edge cases + serde
// ===========================================================================

#[test]
fn transition_window_zero_length() {
    let w = TransitionWindow {
        migration_id: "m".to_string(),
        start_tick: 100,
        end_tick: 100,
        old_format_accepted: true,
    };
    assert!(!w.is_active(100));
    assert!(w.is_expired(100));
}

#[test]
fn transition_window_tick_zero() {
    let w = TransitionWindow {
        migration_id: "m".to_string(),
        start_tick: 0,
        end_tick: 10,
        old_format_accepted: true,
    };
    assert!(w.is_active(0));
    assert!(!w.is_expired(0));
    assert!(w.is_expired(10));
}

#[test]
fn transition_window_boundary_values() {
    let w = TransitionWindow {
        migration_id: "m".to_string(),
        start_tick: 100,
        end_tick: 200,
        old_format_accepted: true,
    };
    assert!(!w.is_active(99));
    assert!(w.is_active(100));
    assert!(w.is_active(199));
    assert!(!w.is_active(200));
    assert!(!w.is_expired(199));
    assert!(w.is_expired(200));
    assert!(w.is_expired(201));
}

#[test]
fn transition_window_serde_roundtrip() {
    let w = TransitionWindow {
        migration_id: "mig-soft-1".to_string(),
        start_tick: 100,
        end_tick: 1100,
        old_format_accepted: true,
    };
    let json = serde_json::to_string(&w).expect("serialize");
    let restored: TransitionWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(w, restored);
}

// ===========================================================================
// CutoverMigrationRunner — Default + empty state
// ===========================================================================

#[test]
fn cutover_runner_default_is_empty() {
    let runner = CutoverMigrationRunner::default();
    assert_eq!(runner.declaration_count(), 0);
    assert!(runner.applied_migrations().is_empty());
    assert!(runner.active_state().is_none());
    assert!(runner.active_migration_id().is_none());
    assert!(runner.transition_windows().is_empty());
    assert!(runner.audit_events().is_empty());
}

// ===========================================================================
// CutoverMigrationRunner — active_state across lifecycle
// ===========================================================================

#[test]
fn active_state_tracks_through_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(runner.active_state().is_none());

    runner.begin("mig-1", 100, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::PreMigrated));
    assert_eq!(runner.active_migration_id(), Some("mig-1"));

    runner.create_checkpoint(1, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Checkpointed));

    runner.execute(100, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Executed));

    runner.verify(0, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Verified));

    runner.commit("t").unwrap();
    assert!(runner.active_state().is_none());
    assert!(runner.active_migration_id().is_none());
}

// ===========================================================================
// CutoverMigrationRunner — sequential migrations
// ===========================================================================

#[test]
fn sequential_migrations_after_first_completes() {
    let mut runner = CutoverMigrationRunner::new();

    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "mig-1");

    let mut decl2 = test_declaration("mig-2", CutoverType::SoftMigration);
    decl2.from_version = "v2".to_string();
    decl2.to_version = "v3".to_string();
    runner.declare(decl2, "t").unwrap();
    runner.set_tick(50);
    run_full_migration(&mut runner, "mig-2");

    assert_eq!(runner.applied_migrations().len(), 2);
    assert_eq!(runner.applied_migrations()[0].migration_id, "mig-1");
    assert_eq!(runner.applied_migrations()[1].migration_id, "mig-2");
    assert_eq!(runner.declaration_count(), 2);
}

// ===========================================================================
// CutoverMigrationRunner — check_format_acceptance for ParallelRun
// ===========================================================================

#[test]
fn parallel_run_accepts_old_format_after_commit() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::ParallelRun), "t")
        .unwrap();
    run_full_migration(&mut runner, "mig-1");

    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();
}

// ===========================================================================
// CutoverMigrationRunner — fail_dry_run without active
// ===========================================================================

#[test]
fn fail_dry_run_without_active_migration() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.fail_dry_run(10, "t").unwrap_err();
    assert!(matches!(err, CutoverError::NoMigrationInProgress));
}

// ===========================================================================
// CutoverMigrationRunner — report_parallel_discrepancies without active
// ===========================================================================

#[test]
fn report_parallel_discrepancies_without_active_migration() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.report_parallel_discrepancies(1, "t").unwrap_err();
    assert!(matches!(err, CutoverError::NoMigrationInProgress));
}

// ===========================================================================
// CutoverMigrationRunner — multiple affected object classes
// ===========================================================================

#[test]
fn declaration_with_multiple_object_classes() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::KeyFormat);
    affected.insert(ObjectClass::TokenFormat);

    let decl = MigrationDeclaration {
        migration_id: "multi-class".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: affected,
        cutover_type: CutoverType::HardCutover,
        description: "affects multiple object classes".to_string(),
        compatible_across_boundary: Vec::new(),
        incompatible_across_boundary: Vec::new(),
    };

    let mut runner = CutoverMigrationRunner::new();
    runner.declare(decl, "t").unwrap();
    run_full_migration(&mut runner, "multi-class");

    assert!(
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema)
            .is_err()
    );
    assert!(
        runner
            .check_format_acceptance(ObjectClass::KeyFormat)
            .is_err()
    );
    assert!(
        runner
            .check_format_acceptance(ObjectClass::TokenFormat)
            .is_err()
    );
    runner
        .check_format_acceptance(ObjectClass::CheckpointFormat)
        .unwrap();
    runner
        .check_format_acceptance(ObjectClass::RevocationFormat)
        .unwrap();
    runner
        .check_format_acceptance(ObjectClass::PolicyFormat)
        .unwrap();
}

// ===========================================================================
// CutoverMigrationRunner — applied entry has phase records
// ===========================================================================

#[test]
fn applied_entry_has_all_phase_records() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    let entry = run_full_migration(&mut runner, "mig-1");

    let phases: Vec<MigrationPhase> = entry.phase_records.iter().map(|r| r.phase).collect();
    assert_eq!(
        phases,
        vec![
            MigrationPhase::PreMigration,
            MigrationPhase::Checkpoint,
            MigrationPhase::Execute,
            MigrationPhase::Verify,
            MigrationPhase::Commit,
        ]
    );
    for record in &entry.phase_records {
        assert_eq!(record.outcome, PhaseOutcome::Success);
        assert_eq!(record.migration_id, "mig-1");
    }
}

// ===========================================================================
// CutoverMigrationRunner — committed_at only when committed
// ===========================================================================

#[test]
fn rolled_back_entry_has_no_committed_at() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();
    runner.rollback("t").unwrap();

    let applied = &runner.applied_migrations()[0];
    assert_eq!(applied.state, CutoverState::RolledBack);
    assert!(applied.committed_at.is_none());
}

#[test]
fn committed_entry_has_committed_at() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    let entry = run_full_migration(&mut runner, "mig-1");
    assert_eq!(entry.state, CutoverState::Committed);
    assert!(entry.committed_at.is_some());
}

// ===========================================================================
// CutoverMigrationRunner — drain_audit_events
// ===========================================================================

#[test]
fn drain_clears_audit_events() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(!runner.audit_events().is_empty());
    let drained = runner.drain_audit_events();
    assert!(!drained.is_empty());
    assert!(runner.audit_events().is_empty());
}

// ===========================================================================
// CutoverMigrationRunner — audit events content
// ===========================================================================

#[test]
fn audit_events_emitted_on_full_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_declaration("mig-1", CutoverType::HardCutover),
            "trace-audit",
        )
        .unwrap();
    run_full_migration(&mut runner, "mig-1");

    let events = runner.audit_events();
    assert!(events.len() >= 5);
    assert!(events.iter().any(|e| e.event == "migration_declared"));
    assert!(events.iter().any(|e| e.event == "pre_migration_complete"));
    assert!(events.iter().any(|e| e.event == "checkpoint_created"));
    assert!(events.iter().any(|e| e.event == "migration_executed"));
    assert!(events.iter().any(|e| e.event == "migration_committed"));

    for event in events {
        assert_eq!(event.component, "migration_compatibility");
        assert_eq!(event.migration_id, "mig-1");
        // run_full_migration uses "trace-1"; the declare call uses "trace-audit".
        assert!(
            event.trace_id == "trace-audit" || event.trace_id == "trace-1",
            "unexpected trace_id: {}",
            event.trace_id
        );
    }
}

#[test]
fn audit_events_include_error_code_on_verification_failure() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();
    let _ = runner.verify(2, "t");

    let events = runner.drain_audit_events();
    let fail_event = events
        .iter()
        .find(|e| e.event == "verification_failed")
        .unwrap();
    assert_eq!(
        fail_event.error_code.as_deref(),
        Some("MC_VERIFICATION_FAILED")
    );
    assert_eq!(fail_event.affected_count, Some(2));
}

#[test]
fn audit_events_include_error_code_on_dry_run_failure() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    let _ = runner.fail_dry_run(15, "t");

    let events = runner.drain_audit_events();
    let fail_event = events.iter().find(|e| e.event == "dry_run_failed").unwrap();
    assert_eq!(fail_event.error_code.as_deref(), Some("MC_DRY_RUN_FAILED"));
    assert_eq!(fail_event.affected_count, Some(15));
}

// ===========================================================================
// CutoverMigrationRunner — declaration validation edge cases
// ===========================================================================

#[test]
fn declare_rejects_empty_migration_id() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("", CutoverType::HardCutover);
    decl.migration_id = String::new();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_empty_affected_objects() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("mig-1", CutoverType::HardCutover);
    decl.affected_objects.clear();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_same_from_to_version() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("mig-1", CutoverType::HardCutover);
    decl.to_version = decl.from_version.clone();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_duplicate_id() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
        .unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

// ===========================================================================
// CutoverMigrationRunner — phase ordering enforcement
// ===========================================================================

#[test]
fn all_operations_without_active_fail() {
    let mut runner = CutoverMigrationRunner::new();
    assert!(matches!(
        runner.create_checkpoint(1, "t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
    assert!(matches!(
        runner.execute(10, "t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
    assert!(matches!(
        runner.verify(0, "t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
    assert!(matches!(
        runner.commit("t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
    assert!(matches!(
        runner.rollback("t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
}

#[test]
fn begin_unknown_migration_fails() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.begin("nonexistent", 100, "t").unwrap_err();
    assert!(matches!(err, CutoverError::MigrationNotFound { .. }));
}

#[test]
fn only_one_active_migration_at_a_time() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    let mut decl2 = test_declaration("mig-2", CutoverType::SoftMigration);
    decl2.from_version = "v2".to_string();
    decl2.to_version = "v3".to_string();
    runner.declare(decl2, "t").unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    let err = runner.begin("mig-2", 50, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

// ===========================================================================
// CutoverMigrationRunner — soft migration transition window
// ===========================================================================

#[test]
fn soft_migration_creates_transition_window_on_commit() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::SoftMigration), "t")
        .unwrap();
    run_full_migration(&mut runner, "mig-1");

    assert_eq!(runner.transition_windows().len(), 1);
    let window = &runner.transition_windows()[0];
    assert_eq!(window.migration_id, "mig-1");
    assert!(window.old_format_accepted);
    // Window starts at commit tick (40) and ends at tick + 1000.
    assert_eq!(window.start_tick, 40);
    assert_eq!(window.end_tick, 1040);
}

#[test]
fn hard_cutover_does_not_create_transition_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "mig-1");
    assert!(runner.transition_windows().is_empty());
}

// ===========================================================================
// Serde roundtrips for structured types
// ===========================================================================

#[test]
fn cutover_audit_event_serde_roundtrip() {
    let event = CutoverAuditEvent {
        trace_id: "trace-test".to_string(),
        component: "migration_compatibility".to_string(),
        migration_id: "mig-1".to_string(),
        event: "verification_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("MC_VERIFICATION_FAILED".to_string()),
        phase: Some("verify".to_string()),
        affected_count: Some(42),
        timestamp: DeterministicTimestamp(9999),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: CutoverAuditEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn phase_execution_record_serde_roundtrip() {
    let record = PhaseExecutionRecord {
        migration_id: "mig-1".to_string(),
        phase: MigrationPhase::Verify,
        outcome: PhaseOutcome::Failed,
        affected_count: 7,
        detail: "7 conformance violations".to_string(),
        timestamp: DeterministicTimestamp(30),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let restored: PhaseExecutionRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, restored);
}

#[test]
fn applied_migration_entry_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::KeyFormat);
    let entry = AppliedMigrationEntry {
        migration_id: "mig-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::SoftMigration,
        state: CutoverState::Committed,
        affected_objects: affected,
        phase_records: vec![PhaseExecutionRecord {
            migration_id: "mig-1".to_string(),
            phase: MigrationPhase::PreMigration,
            outcome: PhaseOutcome::Success,
            affected_count: 100,
            detail: "dry run".to_string(),
            timestamp: DeterministicTimestamp(0),
        }],
        declared_at: DeterministicTimestamp(10),
        committed_at: Some(DeterministicTimestamp(40)),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: AppliedMigrationEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn migration_declaration_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::PolicyFormat);
    affected.insert(ObjectClass::RevocationFormat);
    let decl = MigrationDeclaration {
        migration_id: "mig-policy-v2".to_string(),
        from_version: "policy-v1".to_string(),
        to_version: "policy-v2".to_string(),
        affected_objects: affected,
        cutover_type: CutoverType::ParallelRun,
        description: "policy format change".to_string(),
        compatible_across_boundary: vec!["decision wire format".to_string()],
        incompatible_across_boundary: vec!["storage layout".to_string()],
    };
    let json = serde_json::to_string(&decl).expect("serialize");
    let restored: MigrationDeclaration = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decl, restored);
}

// ===========================================================================
// End-to-end: cutover runner deterministic audit trail
// ===========================================================================

#[test]
fn cutover_runner_deterministic_audit_trail() {
    let run = || {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "mig-1");
        serde_json::to_string(runner.audit_events()).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// End-to-end: soft migration full lifecycle with window expiry
// ===========================================================================

#[test]
fn end_to_end_soft_migration_window_expiry() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_declaration("mig-soft", CutoverType::SoftMigration),
            "trace-e2e",
        )
        .unwrap();

    runner.begin("mig-soft", 200, "trace-e2e").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "trace-e2e").unwrap();
    runner.set_tick(20);
    runner.execute(200, "trace-e2e").unwrap();
    runner.set_tick(30);
    runner.verify(0, "trace-e2e").unwrap();
    runner.set_tick(40);
    let entry = runner.commit("trace-e2e").unwrap();

    assert_eq!(entry.state, CutoverState::Committed);
    assert_eq!(entry.cutover_type, CutoverType::SoftMigration);

    let window = &runner.transition_windows()[0];
    assert_eq!(window.start_tick, 40);
    assert_eq!(window.end_tick, 1040);

    // During window: old format accepted.
    runner.set_tick(500);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();

    // After window: old format rejected.
    runner.set_tick(1040);
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::TransitionWindowExpired { .. }));

    // Verify audit trail.
    let events = runner.audit_events();
    assert!(events.len() >= 5);
    assert!(
        events
            .iter()
            .all(|e| e.component == "migration_compatibility")
    );
    assert!(events.iter().all(|e| e.migration_id == "mig-soft"));
    assert!(events.iter().all(|e| e.trace_id == "trace-e2e"));
}

// ===========================================================================
// End-to-end: verification failure auto-rollback
// ===========================================================================

#[test]
fn end_to_end_verification_failure_auto_rollback() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::HardCutover), "t")
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();

    let err = runner.verify(3, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::VerificationFailed { violations: 3 }
    ));

    assert!(runner.active_migration_id().is_none());
    let applied = runner.applied_migrations();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].state, CutoverState::RolledBack);
    assert!(applied[0].committed_at.is_none());

    // Old format still accepted after rollback.
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();
}

// ===========================================================================
// End-to-end: parallel run discrepancy abort
// ===========================================================================

#[test]
fn end_to_end_parallel_discrepancy_abort() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("mig-1", CutoverType::ParallelRun), "t")
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();

    let err = runner.report_parallel_discrepancies(5, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 5
        }
    ));
    assert!(runner.active_migration_id().is_none());

    let events = runner.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.event == "parallel_run_discrepancy" && e.outcome == "fail")
    );
}
