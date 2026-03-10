#![forbid(unsafe_code)]

//! Integration tests for the `migration_compatibility` module.
//!
//! Covers: MigrationError, MigrationErrorCode, IncompatibleField, GoldenLedger,
//! MigrationFunction, MigrationRegistry, MigrationCompatibilityEvent,
//! MigrationOutcome, MigrationTestResult, MigrationCompatibilityChecker,
//! GoldenLedgerManifest, ManifestEntry, plus the cutover migration subsystem
//! (CutoverType, ObjectClass, MigrationDeclaration, MigrationPhase,
//! PhaseOutcome, PhaseExecutionRecord, CutoverError, cutover_error_code,
//! CutoverState, AppliedMigrationEntry, CutoverAuditEvent, TransitionWindow,
//! CutoverMigrationRunner).

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::control_plane::mocks::{
    MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
};
use frankenengine_engine::evidence_emission::{
    ActionCategory, CanonicalEvidenceEmitter, CanonicalEvidenceEntry, EmitterConfig,
    EvidenceEmissionRequest,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::migration_compatibility::{
    AppliedMigrationEntry, CutoverAuditEvent, CutoverError, CutoverMigrationRunner, CutoverState,
    CutoverType, GoldenLedger, GoldenLedgerManifest, IncompatibleField, ManifestEntry,
    MigrationCompatibilityChecker, MigrationCompatibilityEvent, MigrationDeclaration,
    MigrationError, MigrationErrorCode, MigrationFunction, MigrationOutcome, MigrationPhase,
    MigrationRegistry, MigrationTestResult, ObjectClass, PhaseExecutionRecord, PhaseOutcome,
    TransitionWindow, cutover_error_code,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_cx() -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000))
}

fn make_emitter() -> CanonicalEvidenceEmitter {
    CanonicalEvidenceEmitter::new(EmitterConfig::default())
}

fn make_request(action: &str, ts: u64) -> EvidenceEmissionRequest {
    EvidenceEmissionRequest {
        category: ActionCategory::DecisionContract,
        action_name: action.to_string(),
        trace_id: trace_id_from_seed(1),
        decision_id: decision_id_from_seed(1),
        policy_id: policy_id_from_seed(1),
        ts_unix_ms: ts,
        posterior: vec![0.7, 0.3],
        expected_losses: {
            let mut m = BTreeMap::new();
            m.insert("allow".to_string(), 0.1);
            m.insert("deny".to_string(), 0.4);
            m
        },
        chosen_expected_loss: 0.1,
        calibration_score: 0.94,
        fallback_active: false,
        top_features: vec![("feature_a".to_string(), 0.85)],
        metadata: BTreeMap::new(),
    }
}

fn build_golden_ledger(name: &str, schema_version: &str, n: usize) -> GoldenLedger {
    let mut emitter = make_emitter();
    let mut cx = mock_cx();
    for i in 0..n {
        let ts = 1_700_000_000_000 + (i as u64) * 1000;
        let req = make_request(&format!("action_{i}"), ts);
        emitter.emit(&mut cx, &req).expect("emit");
    }
    let entries = emitter.entries().to_vec();
    GoldenLedger::freeze(name, schema_version, entries, 1_700_000_000_000)
}

fn identity_migration(
    entry: &CanonicalEvidenceEntry,
) -> Result<CanonicalEvidenceEntry, MigrationError> {
    Ok(entry.clone())
}

fn v1_to_v2_migration(
    entry: &CanonicalEvidenceEntry,
) -> Result<CanonicalEvidenceEntry, MigrationError> {
    let mut migrated = entry.clone();
    migrated.schema_version = "evidence-v2".to_string();
    migrated
        .metadata
        .insert("migrated_from".to_string(), "evidence-v1".to_string());
    Ok(migrated)
}

fn failing_migration(
    entry: &CanonicalEvidenceEntry,
) -> Result<CanonicalEvidenceEntry, MigrationError> {
    Err(MigrationError {
        from_version: entry.schema_version.clone(),
        to_version: "evidence-v2".to_string(),
        error_code: MigrationErrorCode::RequiredFieldMissing,
        incompatible_fields: vec![IncompatibleField {
            field_path: "metadata.required_field".to_string(),
            reason: "field required in v2 but absent in v1".to_string(),
        }],
        message: "cannot migrate: required field missing".to_string(),
    })
}

fn test_cutover_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
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

fn run_full_cutover(runner: &mut CutoverMigrationRunner, id: &str) -> AppliedMigrationEntry {
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
// Section 1: MigrationErrorCode
// ===========================================================================

#[test]
fn migration_error_code_display_all_variants() {
    let expected = [
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
    for (code, label) in &expected {
        assert_eq!(code.to_string(), *label, "Display mismatch for {code:?}");
    }
}

#[test]
fn migration_error_code_ord_stable() {
    assert!(
        MigrationErrorCode::MajorVersionIncompatible < MigrationErrorCode::RequiredFieldMissing
    );
    assert!(MigrationErrorCode::RequiredFieldMissing < MigrationErrorCode::FieldTypeChanged);
    assert!(MigrationErrorCode::NoMigrationPath < MigrationErrorCode::LossyMigration);
}

#[test]
fn migration_error_code_serde_roundtrip_all() {
    let all = [
        MigrationErrorCode::MajorVersionIncompatible,
        MigrationErrorCode::RequiredFieldMissing,
        MigrationErrorCode::FieldTypeChanged,
        MigrationErrorCode::MigrationFunctionFailed,
        MigrationErrorCode::NonDeterministicMigration,
        MigrationErrorCode::PartialReplayFailure,
        MigrationErrorCode::NoMigrationPath,
        MigrationErrorCode::LossyMigration,
    ];
    for code in &all {
        let json = serde_json::to_string(code).expect("serialize");
        let restored: MigrationErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*code, restored);
    }
}

#[test]
fn migration_error_code_clone_and_copy() {
    let code = MigrationErrorCode::FieldTypeChanged;
    let cloned = code;
    assert_eq!(code, cloned);
}

// ===========================================================================
// Section 2: MigrationError
// ===========================================================================

#[test]
fn migration_error_display_format() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::RequiredFieldMissing,
        incompatible_fields: vec![
            IncompatibleField {
                field_path: "metadata.x".to_string(),
                reason: "missing".to_string(),
            },
            IncompatibleField {
                field_path: "metadata.y".to_string(),
                reason: "type mismatch".to_string(),
            },
        ],
        message: "test".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("v1"), "should contain from_version");
    assert!(s.contains("v2"), "should contain to_version");
    assert!(
        s.contains("2 incompatible fields"),
        "should contain field count"
    );
}

#[test]
fn migration_error_is_std_error() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::MajorVersionIncompatible,
        incompatible_fields: Vec::new(),
        message: "major version mismatch".to_string(),
    };
    let _dyn_err: &dyn std::error::Error = &err;
}

#[test]
fn migration_error_serde_roundtrip_with_fields() {
    let err = MigrationError {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
        error_code: MigrationErrorCode::FieldTypeChanged,
        incompatible_fields: vec![
            IncompatibleField {
                field_path: "candidates[0].expected_loss".to_string(),
                reason: "type changed from i64 to f64".to_string(),
            },
            IncompatibleField {
                field_path: "metadata.score".to_string(),
                reason: "renamed to metadata.calibration_score".to_string(),
            },
        ],
        message: "two fields incompatible".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: MigrationError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

#[test]
fn migration_error_zero_incompatible_fields() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::NoMigrationPath,
        incompatible_fields: Vec::new(),
        message: "no path".to_string(),
    };
    assert!(err.to_string().contains("0 incompatible fields"));
}

// ===========================================================================
// Section 3: IncompatibleField
// ===========================================================================

#[test]
fn incompatible_field_serde_roundtrip() {
    let field = IncompatibleField {
        field_path: "metadata.x.y".to_string(),
        reason: "removed in v2".to_string(),
    };
    let json = serde_json::to_string(&field).expect("serialize");
    let restored: IncompatibleField = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(field, restored);
}

#[test]
fn incompatible_field_clone_eq() {
    let a = IncompatibleField {
        field_path: "a.b".to_string(),
        reason: "mismatch".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Section 4: GoldenLedger
// ===========================================================================

#[test]
fn golden_ledger_freeze_and_verify_integrity() {
    let ledger = build_golden_ledger("corpus-v1", "evidence-v1", 5);
    assert_eq!(ledger.name, "corpus-v1");
    assert_eq!(ledger.schema_version, "evidence-v1");
    assert_eq!(ledger.len(), 5);
    assert!(!ledger.is_empty());
    assert!(ledger.verify_integrity());
}

#[test]
fn golden_ledger_empty_is_valid() {
    let ledger = GoldenLedger::freeze("empty", "evidence-v1", Vec::new(), 0);
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert!(ledger.verify_integrity());
}

#[test]
fn golden_ledger_tamper_detected() {
    let mut ledger = build_golden_ledger("corpus-v1", "evidence-v1", 3);
    assert!(ledger.verify_integrity());
    ledger.entries[1].action_name = "tampered_action".to_string();
    assert!(!ledger.verify_integrity());
}

#[test]
fn golden_ledger_serde_roundtrip() {
    let ledger = build_golden_ledger("corpus-v1", "evidence-v1", 3);
    let json = serde_json::to_string(&ledger).expect("serialize");
    let restored: GoldenLedger = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ledger, restored);
    assert!(restored.verify_integrity());
}

#[test]
fn golden_ledger_frozen_at_ms_recorded() {
    let ledger = build_golden_ledger("test", "evidence-v1", 1);
    assert_eq!(ledger.frozen_at_ms, 1_700_000_000_000);
}

#[test]
fn golden_ledger_metadata_initially_empty() {
    let ledger = build_golden_ledger("test", "evidence-v1", 1);
    assert!(ledger.metadata.is_empty());
}

// ===========================================================================
// Section 5: MigrationFunction
// ===========================================================================

#[test]
fn migration_function_serde_roundtrip() {
    let func = MigrationFunction {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
        lossy: false,
        description: "add metadata field".to_string(),
    };
    let json = serde_json::to_string(&func).expect("serialize");
    let restored: MigrationFunction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(func.from_version, restored.from_version);
    assert_eq!(func.to_version, restored.to_version);
    assert_eq!(func.lossy, restored.lossy);
    assert_eq!(func.description, restored.description);
}

#[test]
fn migration_function_lossy_flag() {
    let func = MigrationFunction {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        lossy: true,
        description: "drops precision".to_string(),
    };
    assert!(func.lossy);
}

// ===========================================================================
// Section 6: MigrationRegistry
// ===========================================================================

#[test]
fn registry_new_is_empty() {
    let registry = MigrationRegistry::new();
    assert!(registry.all().is_empty());
}

#[test]
fn registry_default_is_empty() {
    let registry = MigrationRegistry::default();
    assert!(registry.all().is_empty());
}

#[test]
fn registry_register_and_find() {
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "v1->v2".to_string(),
        },
        identity_migration,
    );

    assert!(registry.find("evidence-v1", "evidence-v2").is_some());
    assert!(registry.find("evidence-v2", "evidence-v3").is_none());
    assert!(registry.find("evidence-v2", "evidence-v1").is_none());
}

#[test]
fn registry_all_returns_all_registered() {
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            lossy: false,
            description: "m1".to_string(),
        },
        identity_migration,
    );
    registry.register(
        MigrationFunction {
            from_version: "v2".to_string(),
            to_version: "v3".to_string(),
            lossy: true,
            description: "m2".to_string(),
        },
        identity_migration,
    );
    assert_eq!(registry.all().len(), 2);
}

// ===========================================================================
// Section 7: MigrationOutcome
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
fn migration_outcome_serde_roundtrip_all() {
    for outcome in [
        MigrationOutcome::BackwardCompatible,
        MigrationOutcome::MigratedSuccessfully,
        MigrationOutcome::LossyMigration,
        MigrationOutcome::Failed,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let restored: MigrationOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, restored);
    }
}

// ===========================================================================
// Section 8: MigrationTestResult
// ===========================================================================

#[test]
fn test_result_passed_no_errors_no_violations() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::MigratedSuccessfully,
        entries_processed: 5,
        entries_replayed_ok: 5,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(result.passed());
}

#[test]
fn test_result_failed_with_replay_violations() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::MigratedSuccessfully,
        entries_processed: 5,
        entries_replayed_ok: 3,
        errors: Vec::new(),
        replay_violations: 2,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(!result.passed());
}

#[test]
fn test_result_failed_with_errors() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::Failed,
        entries_processed: 5,
        entries_replayed_ok: 0,
        errors: vec![MigrationError {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            error_code: MigrationErrorCode::NoMigrationPath,
            incompatible_fields: Vec::new(),
            message: "no path".to_string(),
        }],
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: false,
    };
    assert!(!result.passed());
}

#[test]
fn test_result_failed_outcome_alone_means_not_passed() {
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
        determinism_verified: false,
    };
    assert!(!result.passed());
}

#[test]
fn test_result_lossy_migration_passes_when_no_violations() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::LossyMigration,
        entries_processed: 3,
        entries_replayed_ok: 3,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(result.passed());
}

#[test]
fn test_result_serde_roundtrip() {
    let result = MigrationTestResult {
        golden_ledger_name: "test".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::BackwardCompatible,
        entries_processed: 10,
        entries_replayed_ok: 10,
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
// Section 9: MigrationCompatibilityEvent
// ===========================================================================

#[test]
fn compatibility_event_serde_roundtrip() {
    let event = MigrationCompatibilityEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "migration_compatibility".to_string(),
        event: "backward_compat_check".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v2".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn compatibility_event_with_error_code() {
    let event = MigrationCompatibilityEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "migration_compatibility".to_string(),
        event: "no_migration_path".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("no_migration_path".to_string()),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
    };
    assert!(event.error_code.is_some());
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// ===========================================================================
// Section 10: MigrationCompatibilityChecker
// ===========================================================================

#[test]
fn checker_backward_compatible_same_version() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
    checker.add_golden_ledger(ledger);

    assert_eq!(checker.golden_ledger_count(), 1);
    assert_eq!(checker.target_version(), "evidence-v1");

    let results = checker.run_all();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::BackwardCompatible);
    assert_eq!(results[0].entries_processed, 5);
    assert_eq!(results[0].entries_replayed_ok, 5);
    assert!(results[0].determinism_verified);
}

#[test]
fn checker_successful_migration_v1_to_v2() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);

    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "add metadata field".to_string(),
        },
        v1_to_v2_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::MigratedSuccessfully);
    assert!(results[0].determinism_verified);
}

#[test]
fn checker_no_migration_path_returns_error() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let registry = MigrationRegistry::new();

    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::Failed);
    assert_eq!(results[0].errors.len(), 1);
    assert_eq!(
        results[0].errors[0].error_code,
        MigrationErrorCode::NoMigrationPath
    );
}

#[test]
fn checker_failing_migration_function_reports_errors() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);

    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "broken migration".to_string(),
        },
        failing_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert!(!results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::Failed);
    assert_eq!(results[0].errors.len(), 3); // one per entry
    assert_eq!(
        results[0].errors[0].error_code,
        MigrationErrorCode::RequiredFieldMissing
    );
}

#[test]
fn checker_lossy_migration_marked() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);

    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: true,
            description: "lossy schema change".to_string(),
        },
        v1_to_v2_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert!(results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::LossyMigration);
}

#[test]
fn checker_multiple_golden_ledgers() {
    let ledger_v1 = build_golden_ledger("v1-corpus", "evidence-v1", 3);
    let ledger_v2 = build_golden_ledger("v2-corpus", "evidence-v2", 4);

    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "v1 to v2".to_string(),
        },
        v1_to_v2_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger_v1);
    checker.add_golden_ledger(ledger_v2);

    assert_eq!(checker.golden_ledger_count(), 2);

    let results = checker.run_all();
    assert_eq!(results.len(), 2);
    assert!(results[0].passed()); // v1 migrated to v2
    assert!(results[1].passed()); // v2 backward compatible
}

#[test]
fn checker_emits_structured_events() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
    checker.add_golden_ledger(ledger);

    let _ = checker.run_all();
    let events = checker.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].component, "migration_compatibility");
    assert_eq!(events[0].event, "backward_compat_check");
    assert_eq!(events[0].outcome, "pass");
}

#[test]
fn checker_events_contain_version_info() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let _ = checker.run_all();
    let events = checker.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].from_version, "evidence-v1");
    assert_eq!(events[0].to_version, "evidence-v2");
}

#[test]
fn checker_empty_corpus_returns_no_results() {
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
    assert_eq!(checker.golden_ledger_count(), 0);
    let results = checker.run_all();
    assert!(results.is_empty());
}

#[test]
fn checker_registry_accessor() {
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            lossy: false,
            description: "test".to_string(),
        },
        identity_migration,
    );
    let checker = MigrationCompatibilityChecker::new("v2", registry);
    assert_eq!(checker.registry().all().len(), 1);
}

#[test]
fn checker_deterministic_across_runs() {
    let make_checker = || {
        let ledger = build_golden_ledger("test-v1", "evidence-v1", 5);
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "evidence-v1".to_string(),
                to_version: "evidence-v2".to_string(),
                lossy: false,
                description: "test".to_string(),
            },
            v1_to_v2_migration,
        );
        let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
        checker.add_golden_ledger(ledger);
        checker
    };

    let mut c1 = make_checker();
    let mut c2 = make_checker();

    let j1 = serde_json::to_string(&c1.run_all()).unwrap();
    let j2 = serde_json::to_string(&c2.run_all()).unwrap();
    assert_eq!(j1, j2);
}

// ===========================================================================
// Section 11: GoldenLedgerManifest
// ===========================================================================

#[test]
fn manifest_new_is_empty() {
    let manifest = GoldenLedgerManifest::new();
    assert!(manifest.is_empty());
    assert_eq!(manifest.len(), 0);
}

#[test]
fn manifest_default_is_empty() {
    let manifest = GoldenLedgerManifest::default();
    assert!(manifest.is_empty());
}

#[test]
fn manifest_add_and_verify() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    assert_eq!(manifest.len(), 1);
    assert!(!manifest.is_empty());
    assert!(manifest.verify(&ledger));
}

#[test]
fn manifest_tampered_ledger_fails_verify() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    let mut tampered = ledger;
    tampered.entries[0].action_name = "tampered".to_string();
    let payload = serde_json::to_vec(&tampered.entries).unwrap();
    tampered.corpus_hash = ContentHash::compute(&payload);
    assert!(!manifest.verify(&tampered));
}

#[test]
fn manifest_unknown_ledger_fails_verify() {
    let ledger = build_golden_ledger("unknown", "evidence-v1", 3);
    let manifest = GoldenLedgerManifest::new();
    assert!(!manifest.verify(&ledger));
}

#[test]
fn manifest_serde_roundtrip() {
    let ledger = build_golden_ledger("test-v1", "evidence-v1", 3);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    let json = serde_json::to_string(&manifest).expect("serialize");
    let restored: GoldenLedgerManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, restored);
}

#[test]
fn manifest_multiple_ledgers() {
    let l1 = build_golden_ledger("corpus-a", "evidence-v1", 2);
    let l2 = build_golden_ledger("corpus-b", "evidence-v2", 4);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&l1);
    manifest.add(&l2);

    assert_eq!(manifest.len(), 2);
    assert!(manifest.verify(&l1));
    assert!(manifest.verify(&l2));
}

#[test]
fn manifest_entry_fields() {
    let ledger = build_golden_ledger("test", "evidence-v1", 3);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    let entry: &ManifestEntry = manifest.entries.get("test").expect("entry exists");
    assert_eq!(entry.schema_version, "evidence-v1");
    assert_eq!(entry.entry_count, 3);
    assert_eq!(entry.frozen_at_ms, 1_700_000_000_000);
    assert_eq!(entry.corpus_hash, ledger.corpus_hash);
}

// ===========================================================================
// Section 12: CutoverType (migration_compatibility sub-module)
// ===========================================================================

#[test]
fn cutover_type_display_all() {
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

// ===========================================================================
// Section 13: ObjectClass (migration_compatibility sub-module)
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
    assert_eq!(ObjectClass::PolicyFormat.to_string(), "policy_format");
}

#[test]
fn object_class_serde_roundtrip() {
    for oc in [
        ObjectClass::SerializationSchema,
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyFormat,
    ] {
        let json = serde_json::to_string(&oc).unwrap();
        let deser: ObjectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, deser);
    }
}

// ===========================================================================
// Section 14: MigrationPhase
// ===========================================================================

#[test]
fn migration_phase_display_all() {
    assert_eq!(MigrationPhase::PreMigration.to_string(), "pre_migration");
    assert_eq!(MigrationPhase::Checkpoint.to_string(), "checkpoint");
    assert_eq!(MigrationPhase::Execute.to_string(), "execute");
    assert_eq!(MigrationPhase::Verify.to_string(), "verify");
    assert_eq!(MigrationPhase::Commit.to_string(), "commit");
    assert_eq!(MigrationPhase::Rollback.to_string(), "rollback");
}

#[test]
fn migration_phase_serde_roundtrip() {
    for phase in [
        MigrationPhase::PreMigration,
        MigrationPhase::Checkpoint,
        MigrationPhase::Execute,
        MigrationPhase::Verify,
        MigrationPhase::Commit,
        MigrationPhase::Rollback,
    ] {
        let json = serde_json::to_string(&phase).unwrap();
        let deser: MigrationPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, deser);
    }
}

// ===========================================================================
// Section 15: PhaseOutcome
// ===========================================================================

#[test]
fn phase_outcome_display_all() {
    assert_eq!(PhaseOutcome::Success.to_string(), "success");
    assert_eq!(PhaseOutcome::Failed.to_string(), "failed");
    assert_eq!(PhaseOutcome::Skipped.to_string(), "skipped");
}

#[test]
fn phase_outcome_serde_roundtrip() {
    for po in [
        PhaseOutcome::Success,
        PhaseOutcome::Failed,
        PhaseOutcome::Skipped,
    ] {
        let json = serde_json::to_string(&po).unwrap();
        let deser: PhaseOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(po, deser);
    }
}

// ===========================================================================
// Section 16: PhaseExecutionRecord
// ===========================================================================

#[test]
fn phase_execution_record_serde_roundtrip() {
    let record = PhaseExecutionRecord {
        migration_id: "mig-1".to_string(),
        phase: MigrationPhase::Execute,
        outcome: PhaseOutcome::Success,
        affected_count: 100,
        detail: "done".to_string(),
        timestamp: DeterministicTimestamp(20),
    };
    let json = serde_json::to_string(&record).unwrap();
    let deser: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, deser);
}

// ===========================================================================
// Section 17: CutoverError
// ===========================================================================

#[test]
fn cutover_error_display_all_variants() {
    let errors: Vec<CutoverError> = vec![
        CutoverError::InvalidDeclaration {
            detail: "bad".to_string(),
        },
        CutoverError::DryRunFailed {
            unconvertible_count: 5,
        },
        CutoverError::VerificationFailed { violations: 3 },
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 2,
        },
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::KeyFormat,
        },
        CutoverError::TransitionWindowExpired {
            migration_id: "m1".to_string(),
        },
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Execute,
            detail: "fail".to_string(),
        },
        CutoverError::AlreadyCommitted {
            migration_id: "m1".to_string(),
        },
        CutoverError::NoMigrationInProgress,
        CutoverError::MigrationNotFound {
            migration_id: "m1".to_string(),
        },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display should not be empty for {err:?}");
    }
}

#[test]
fn cutover_error_is_std_error() {
    let err = CutoverError::NoMigrationInProgress;
    let _dyn_err: &dyn std::error::Error = &err;
}

#[test]
fn cutover_error_codes_stable() {
    assert_eq!(
        cutover_error_code(&CutoverError::InvalidDeclaration {
            detail: "x".to_string()
        }),
        "MC_INVALID_DECLARATION"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::DryRunFailed {
            unconvertible_count: 1
        }),
        "MC_DRY_RUN_FAILED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::VerificationFailed { violations: 1 }),
        "MC_VERIFICATION_FAILED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 1
        }),
        "MC_PARALLEL_DISCREPANCY"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::OldFormatRejected {
            object_class: ObjectClass::KeyFormat
        }),
        "MC_OLD_FORMAT_REJECTED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::TransitionWindowExpired {
            migration_id: "x".to_string()
        }),
        "MC_WINDOW_EXPIRED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::PhaseFailed {
            phase: MigrationPhase::Execute,
            detail: "x".to_string()
        }),
        "MC_PHASE_FAILED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::AlreadyCommitted {
            migration_id: "x".to_string()
        }),
        "MC_ALREADY_COMMITTED"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::NoMigrationInProgress),
        "MC_NO_MIGRATION"
    );
    assert_eq!(
        cutover_error_code(&CutoverError::MigrationNotFound {
            migration_id: "x".to_string()
        }),
        "MC_NOT_FOUND"
    );
}

#[test]
fn cutover_error_serde_roundtrip() {
    let err = CutoverError::VerificationFailed { violations: 5 };
    let json = serde_json::to_string(&err).unwrap();
    let deser: CutoverError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, deser);
}

// ===========================================================================
// Section 18: CutoverState
// ===========================================================================

#[test]
fn cutover_state_display_all() {
    assert_eq!(CutoverState::Declared.to_string(), "declared");
    assert_eq!(CutoverState::PreMigrated.to_string(), "pre_migrated");
    assert_eq!(CutoverState::Checkpointed.to_string(), "checkpointed");
    assert_eq!(CutoverState::Executed.to_string(), "executed");
    assert_eq!(CutoverState::Verified.to_string(), "verified");
    assert_eq!(CutoverState::Committed.to_string(), "committed");
    assert_eq!(CutoverState::RolledBack.to_string(), "rolled_back");
}

#[test]
fn cutover_state_serde_roundtrip() {
    for state in [
        CutoverState::Declared,
        CutoverState::PreMigrated,
        CutoverState::Checkpointed,
        CutoverState::Executed,
        CutoverState::Verified,
        CutoverState::Committed,
        CutoverState::RolledBack,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let deser: CutoverState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deser);
    }
}

// ===========================================================================
// Section 19: TransitionWindow
// ===========================================================================

#[test]
fn transition_window_active_and_expired() {
    let w = TransitionWindow {
        migration_id: "m1".to_string(),
        start_tick: 100,
        end_tick: 200,
        old_format_accepted: true,
    };
    assert!(!w.is_active(50)); // before start
    assert!(w.is_active(100)); // at start
    assert!(w.is_active(150)); // during
    assert!(!w.is_active(200)); // at end (expired)
    assert!(!w.is_expired(99));
    assert!(!w.is_expired(199));
    assert!(w.is_expired(200));
    assert!(w.is_expired(300));
}

#[test]
fn transition_window_serde_roundtrip() {
    let w = TransitionWindow {
        migration_id: "m1".to_string(),
        start_tick: 10,
        end_tick: 20,
        old_format_accepted: true,
    };
    let json = serde_json::to_string(&w).unwrap();
    let deser: TransitionWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, deser);
}

// ===========================================================================
// Section 20: CutoverAuditEvent
// ===========================================================================

#[test]
fn cutover_audit_event_serde_roundtrip() {
    let event = CutoverAuditEvent {
        trace_id: "t-1".to_string(),
        component: "migration_compatibility".to_string(),
        migration_id: "mig-1".to_string(),
        event: "migration_committed".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        phase: Some("commit".to_string()),
        affected_count: Some(100),
        timestamp: DeterministicTimestamp(42),
    };
    let json = serde_json::to_string(&event).unwrap();
    let deser: CutoverAuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deser);
}

// ===========================================================================
// Section 21: AppliedMigrationEntry
// ===========================================================================

#[test]
fn applied_migration_entry_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    let entry = AppliedMigrationEntry {
        migration_id: "mig-1".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::HardCutover,
        state: CutoverState::Committed,
        affected_objects: affected,
        phase_records: Vec::new(),
        declared_at: DeterministicTimestamp(10),
        committed_at: Some(DeterministicTimestamp(40)),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let deser: AppliedMigrationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, deser);
}

// ===========================================================================
// Section 22: CutoverMigrationRunner — declaration validation
// ===========================================================================

#[test]
fn cutover_runner_new_accessors() {
    let runner = CutoverMigrationRunner::new();
    assert_eq!(runner.declaration_count(), 0);
    assert!(runner.applied_migrations().is_empty());
    assert!(runner.active_state().is_none());
    assert!(runner.active_migration_id().is_none());
    assert!(runner.transition_windows().is_empty());
    assert!(runner.audit_events().is_empty());
}

#[test]
fn cutover_runner_default() {
    let runner = CutoverMigrationRunner::default();
    assert_eq!(runner.declaration_count(), 0);
}

#[test]
fn declare_valid_migration() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    assert_eq!(runner.declaration_count(), 1);
}

#[test]
fn declare_rejects_empty_migration_id() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_cutover_declaration("", CutoverType::HardCutover);
    decl.migration_id = String::new();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_empty_affected_objects() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_cutover_declaration("mig-1", CutoverType::HardCutover);
    decl.affected_objects.clear();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_same_from_to_version() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_cutover_declaration("mig-1", CutoverType::HardCutover);
    decl.to_version = decl.from_version.clone();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn declare_rejects_duplicate_id() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    let err = runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::SoftMigration),
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

// ===========================================================================
// Section 23: CutoverMigrationRunner — full hard cutover lifecycle
// ===========================================================================

#[test]
fn hard_cutover_full_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();

    let entry = run_full_cutover(&mut runner, "mig-1");
    assert_eq!(entry.state, CutoverState::Committed);
    assert_eq!(entry.cutover_type, CutoverType::HardCutover);
    assert!(entry.committed_at.is_some());
    assert_eq!(entry.phase_records.len(), 5);
}

#[test]
fn hard_cutover_rejects_old_format() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::OldFormatRejected { .. }));
}

#[test]
fn hard_cutover_accepts_unaffected_object_class() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");
    runner
        .check_format_acceptance(ObjectClass::KeyFormat)
        .unwrap();
}

// ===========================================================================
// Section 24: CutoverMigrationRunner — soft migration lifecycle
// ===========================================================================

#[test]
fn soft_migration_opens_transition_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::SoftMigration),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    assert_eq!(runner.transition_windows().len(), 1);
    let window = &runner.transition_windows()[0];
    assert_eq!(window.migration_id, "mig-1");
    assert!(window.old_format_accepted);
}

#[test]
fn soft_migration_accepts_old_format_during_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::SoftMigration),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    runner.set_tick(41);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();
}

#[test]
fn soft_migration_rejects_old_format_after_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::SoftMigration),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    runner.set_tick(1041);
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::TransitionWindowExpired { .. }));
}

// ===========================================================================
// Section 25: CutoverMigrationRunner — parallel run
// ===========================================================================

#[test]
fn parallel_run_discrepancy_aborts() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::ParallelRun),
            "t",
        )
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "t").unwrap();
    runner.set_tick(20);
    runner.execute(100, "t").unwrap();
    runner.set_tick(25);

    let err = runner.report_parallel_discrepancies(5, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 5
        }
    ));
    assert!(runner.active_migration_id().is_none());
}

#[test]
fn parallel_run_zero_discrepancies_ok() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::ParallelRun),
            "t",
        )
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "t").unwrap();
    runner.set_tick(20);
    runner.execute(100, "t").unwrap();
    runner.report_parallel_discrepancies(0, "t").unwrap();
}

#[test]
fn parallel_discrepancy_rejected_for_non_parallel() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();

    let err = runner.report_parallel_discrepancies(0, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

// ===========================================================================
// Section 26: CutoverMigrationRunner — verification failure auto-rollback
// ===========================================================================

#[test]
fn verification_failure_auto_rolls_back() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
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
    assert_eq!(
        runner.applied_migrations()[0].state,
        CutoverState::RolledBack
    );
}

// ===========================================================================
// Section 27: CutoverMigrationRunner — dry run failure
// ===========================================================================

#[test]
fn dry_run_failure_rolls_back() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    let err = runner.fail_dry_run(10, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::DryRunFailed {
            unconvertible_count: 10
        }
    ));
    assert!(runner.active_migration_id().is_none());
}

// ===========================================================================
// Section 28: CutoverMigrationRunner — manual rollback
// ===========================================================================

#[test]
fn manual_rollback_before_commit() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();
    runner.rollback("t").unwrap();

    assert!(runner.active_migration_id().is_none());
    assert_eq!(
        runner.applied_migrations()[0].state,
        CutoverState::RolledBack
    );
}

#[test]
fn rollback_after_commit_fails() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    let err = runner.rollback("t").unwrap_err();
    assert!(matches!(err, CutoverError::NoMigrationInProgress));
}

// ===========================================================================
// Section 29: CutoverMigrationRunner — phase ordering enforcement
// ===========================================================================

#[test]
fn checkpoint_requires_pre_migrated() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();

    let err = runner.create_checkpoint(2, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn execute_requires_checkpointed() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();

    let err = runner.execute(100, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn verify_requires_executed() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();

    let err = runner.verify(0, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn commit_requires_verified() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    runner.begin("mig-1", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();

    let err = runner.commit("t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

// ===========================================================================
// Section 30: CutoverMigrationRunner — missing migration / concurrency
// ===========================================================================

#[test]
fn begin_unknown_migration_fails() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.begin("nonexistent", 100, "t").unwrap_err();
    assert!(matches!(err, CutoverError::MigrationNotFound { .. }));
}

#[test]
fn only_one_active_migration() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    let mut decl2 = test_cutover_declaration("mig-2", CutoverType::SoftMigration);
    decl2.from_version = "v2".to_string();
    decl2.to_version = "v3".to_string();
    runner.declare(decl2, "t").unwrap();

    runner.begin("mig-1", 100, "t").unwrap();
    let err = runner.begin("mig-2", 50, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn operations_without_active_migration_fail() {
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

// ===========================================================================
// Section 31: CutoverMigrationRunner — audit events
// ===========================================================================

#[test]
fn audit_events_emitted_on_full_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    let events = runner.audit_events();
    assert!(events.len() >= 5);
    assert!(events.iter().any(|e| e.event == "migration_declared"));
    assert!(events.iter().any(|e| e.event == "pre_migration_complete"));
    assert!(events.iter().any(|e| e.event == "checkpoint_created"));
    assert!(events.iter().any(|e| e.event == "migration_executed"));
    assert!(events.iter().any(|e| e.event == "migration_committed"));
}

#[test]
fn audit_events_include_error_code_on_failure() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
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
fn drain_clears_audit_events() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    assert!(!runner.audit_events().is_empty());
    let drained = runner.drain_audit_events();
    assert!(!drained.is_empty());
    assert!(runner.audit_events().is_empty());
}

// ===========================================================================
// Section 32: CutoverMigrationRunner — applied migrations log
// ===========================================================================

#[test]
fn applied_migrations_preserved() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    let applied = runner.applied_migrations();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].migration_id, "mig-1");
    assert_eq!(applied[0].from_version, "v1");
    assert_eq!(applied[0].to_version, "v2");
}

// ===========================================================================
// Section 33: Deterministic replay
// ===========================================================================

#[test]
fn cutover_lifecycle_deterministic() {
    let run = || {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(
                test_cutover_declaration("mig-1", CutoverType::HardCutover),
                "t",
            )
            .unwrap();
        run_full_cutover(&mut runner, "mig-1");
        serde_json::to_string(runner.audit_events()).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Section 34: MigrationDeclaration serde (cutover sub-module)
// ===========================================================================

#[test]
fn cutover_migration_declaration_serde_roundtrip() {
    let decl = test_cutover_declaration("mig-1", CutoverType::HardCutover);
    let json = serde_json::to_string(&decl).unwrap();
    let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, deser);
}

// ===========================================================================
// Section 35: Active migration state tracking
// ===========================================================================

#[test]
fn active_state_tracks_phases() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
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
}

// ===========================================================================
// Section 36: Multiple cutover migrations in sequence
// ===========================================================================

#[test]
fn sequential_cutover_migrations() {
    let mut runner = CutoverMigrationRunner::new();

    runner
        .declare(
            test_cutover_declaration("mig-1", CutoverType::HardCutover),
            "t",
        )
        .unwrap();
    run_full_cutover(&mut runner, "mig-1");

    let mut decl2 = test_cutover_declaration("mig-2", CutoverType::SoftMigration);
    decl2.from_version = "v2".to_string();
    decl2.to_version = "v3".to_string();
    runner.declare(decl2, "t").unwrap();
    runner.set_tick(100);
    run_full_cutover(&mut runner, "mig-2");

    assert_eq!(runner.applied_migrations().len(), 2);
    assert_eq!(runner.applied_migrations()[0].migration_id, "mig-1");
    assert_eq!(runner.applied_migrations()[1].migration_id, "mig-2");
}
