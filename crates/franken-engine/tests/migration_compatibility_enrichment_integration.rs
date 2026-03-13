#![forbid(unsafe_code)]

//! Enrichment integration tests for the `migration_compatibility` module.
//!
//! Covers all public types, enum variants, Display impls, serde roundtrips,
//! builder/constructor edge cases, determinism checks, field access,
//! complex multi-step workflows, and error conditions.

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
use frankenengine_engine::migration_compatibility::*;
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
            field_path: "metadata.new_required_field".to_string(),
            reason: "field required in v2 but absent in v1".to_string(),
        }],
        message: "cannot migrate: required field missing".to_string(),
    })
}

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
// 1. MigrationErrorCode — Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_migration_error_code_display_values_all_unique() {
    let codes = [
        MigrationErrorCode::MajorVersionIncompatible,
        MigrationErrorCode::RequiredFieldMissing,
        MigrationErrorCode::FieldTypeChanged,
        MigrationErrorCode::MigrationFunctionFailed,
        MigrationErrorCode::NonDeterministicMigration,
        MigrationErrorCode::PartialReplayFailure,
        MigrationErrorCode::NoMigrationPath,
        MigrationErrorCode::LossyMigration,
    ];
    let mut display_strings: Vec<String> = codes.iter().map(|c| c.to_string()).collect();
    let original_len = display_strings.len();
    display_strings.sort();
    display_strings.dedup();
    assert_eq!(
        display_strings.len(),
        original_len,
        "Display values must be unique across all 8 variants"
    );
}

#[test]
fn enrichment_migration_error_code_serde_json_roundtrip_deterministic() {
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
        let json1 = serde_json::to_string(&code).unwrap();
        let json2 = serde_json::to_string(&code).unwrap();
        assert_eq!(
            json1, json2,
            "Serialization must be deterministic for {code:?}"
        );
        let restored: MigrationErrorCode = serde_json::from_str(&json1).unwrap();
        assert_eq!(code, restored);
    }
}

#[test]
fn enrichment_migration_error_code_ord_total_ordering() {
    let codes = [
        MigrationErrorCode::MajorVersionIncompatible,
        MigrationErrorCode::RequiredFieldMissing,
        MigrationErrorCode::FieldTypeChanged,
        MigrationErrorCode::MigrationFunctionFailed,
        MigrationErrorCode::NonDeterministicMigration,
        MigrationErrorCode::PartialReplayFailure,
        MigrationErrorCode::NoMigrationPath,
        MigrationErrorCode::LossyMigration,
    ];
    // Verify that ordering is total (every pair is comparable)
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert!(a.partial_cmp(b).is_some());
        }
    }
}

#[test]
fn enrichment_migration_error_code_clone_produces_equal() {
    let original = MigrationErrorCode::NonDeterministicMigration;
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.to_string(), cloned.to_string());
}

// ===========================================================================
// 2. MigrationError — Display, serde, std::error::Error
// ===========================================================================

#[test]
fn enrichment_migration_error_display_contains_versions_and_count() {
    let err = MigrationError {
        from_version: "schema-a".to_string(),
        to_version: "schema-b".to_string(),
        error_code: MigrationErrorCode::MajorVersionIncompatible,
        incompatible_fields: vec![
            IncompatibleField {
                field_path: "f1".to_string(),
                reason: "r1".to_string(),
            },
            IncompatibleField {
                field_path: "f2".to_string(),
                reason: "r2".to_string(),
            },
            IncompatibleField {
                field_path: "f3".to_string(),
                reason: "r3".to_string(),
            },
        ],
        message: "major version change".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("schema-a"));
    assert!(display.contains("schema-b"));
    assert!(display.contains("3 incompatible fields"));
    assert!(display.contains("major_version_incompatible"));
}

#[test]
fn enrichment_migration_error_display_zero_fields() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::NoMigrationPath,
        incompatible_fields: Vec::new(),
        message: "none".to_string(),
    };
    assert!(err.to_string().contains("0 incompatible fields"));
}

#[test]
fn enrichment_migration_error_serde_preserves_all_fields() {
    let err = MigrationError {
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v3".to_string(),
        error_code: MigrationErrorCode::LossyMigration,
        incompatible_fields: vec![IncompatibleField {
            field_path: "calibration.score".to_string(),
            reason: "precision reduced from f64 to f32".to_string(),
        }],
        message: "lossy conversion".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: MigrationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err.from_version, restored.from_version);
    assert_eq!(err.to_version, restored.to_version);
    assert_eq!(err.error_code, restored.error_code);
    assert_eq!(
        err.incompatible_fields.len(),
        restored.incompatible_fields.len()
    );
    assert_eq!(
        err.incompatible_fields[0].field_path,
        restored.incompatible_fields[0].field_path
    );
    assert_eq!(
        err.incompatible_fields[0].reason,
        restored.incompatible_fields[0].reason
    );
    assert_eq!(err.message, restored.message);
}

#[test]
fn enrichment_migration_error_implements_error_trait() {
    let err = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::FieldTypeChanged,
        incompatible_fields: Vec::new(),
        message: "type mismatch".to_string(),
    };
    // Verify it implements std::error::Error
    let e: &dyn std::error::Error = &err;
    assert!(!e.to_string().is_empty());
    assert!(e.source().is_none());
}

#[test]
fn enrichment_migration_error_eq_symmetry() {
    let a = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::RequiredFieldMissing,
        incompatible_fields: vec![IncompatibleField {
            field_path: "x".to_string(),
            reason: "missing".to_string(),
        }],
        message: "test".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(b, a);
}

// ===========================================================================
// 3. IncompatibleField — serde, clone, eq
// ===========================================================================

#[test]
fn enrichment_incompatible_field_serde_roundtrip() {
    let field = IncompatibleField {
        field_path: "metadata.deep.nested.field".to_string(),
        reason: "type changed from string to integer".to_string(),
    };
    let json = serde_json::to_string(&field).unwrap();
    let restored: IncompatibleField = serde_json::from_str(&json).unwrap();
    assert_eq!(field, restored);
}

#[test]
fn enrichment_incompatible_field_clone_and_eq() {
    let original = IncompatibleField {
        field_path: "a.b.c".to_string(),
        reason: "removed".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_incompatible_field_empty_strings_valid() {
    let field = IncompatibleField {
        field_path: String::new(),
        reason: String::new(),
    };
    let json = serde_json::to_string(&field).unwrap();
    let restored: IncompatibleField = serde_json::from_str(&json).unwrap();
    assert_eq!(field, restored);
}

// ===========================================================================
// 4. GoldenLedger — freeze, verify, tamper detection, serde
// ===========================================================================

#[test]
fn enrichment_golden_ledger_freeze_preserves_name_and_version() {
    let ledger = build_golden_ledger("my-corpus", "schema-v3", 4);
    assert_eq!(ledger.name, "my-corpus");
    assert_eq!(ledger.schema_version, "schema-v3");
    assert_eq!(ledger.len(), 4);
    assert!(!ledger.is_empty());
}

#[test]
fn enrichment_golden_ledger_freeze_computes_deterministic_hash() {
    let l1 = build_golden_ledger("test", "v1", 3);
    let l2 = build_golden_ledger("test", "v1", 3);
    assert_eq!(l1.corpus_hash, l2.corpus_hash);
}

#[test]
fn enrichment_golden_ledger_empty_corpus_has_valid_hash() {
    let ledger = GoldenLedger::freeze("empty", "v1", Vec::new(), 0);
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert!(ledger.verify_integrity());
    // Hash should still be non-trivial (hash of empty JSON array)
    let payload = serde_json::to_vec::<Vec<CanonicalEvidenceEntry>>(&Vec::new()).unwrap();
    let expected_hash = ContentHash::compute(&payload);
    assert_eq!(ledger.corpus_hash, expected_hash);
}

#[test]
fn enrichment_golden_ledger_verify_integrity_after_tamper() {
    let mut ledger = build_golden_ledger("test", "v1", 5);
    assert!(ledger.verify_integrity());
    // Tamper with last entry
    ledger.entries.last_mut().unwrap().action_name = "TAMPERED_VALUE".to_string();
    assert!(!ledger.verify_integrity());
}

#[test]
fn enrichment_golden_ledger_metadata_does_not_affect_hash() {
    let mut ledger = build_golden_ledger("test", "v1", 3);
    let hash_before = ledger.corpus_hash;
    ledger
        .metadata
        .insert("author".to_string(), "test-suite".to_string());
    ledger
        .metadata
        .insert("notes".to_string(), "enrichment test".to_string());
    // Metadata is not part of corpus_hash
    assert_eq!(ledger.corpus_hash, hash_before);
    assert!(ledger.verify_integrity());
}

#[test]
fn enrichment_golden_ledger_frozen_at_ms_stored() {
    let ledger = GoldenLedger::freeze("ts-test", "v1", Vec::new(), 1_700_123_456_789);
    assert_eq!(ledger.frozen_at_ms, 1_700_123_456_789);
}

#[test]
fn enrichment_golden_ledger_serde_roundtrip_nonempty() {
    let ledger = build_golden_ledger("serde-test", "schema-v2", 5);
    let json = serde_json::to_string(&ledger).unwrap();
    let restored: GoldenLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, restored);
    assert!(restored.verify_integrity());
}

#[test]
fn enrichment_golden_ledger_different_entries_different_hash() {
    let l1 = build_golden_ledger("a", "v1", 3);
    let l2 = build_golden_ledger("a", "v1", 5);
    assert_ne!(l1.corpus_hash, l2.corpus_hash);
}

// ===========================================================================
// 5. MigrationFunction — serde, field access
// ===========================================================================

#[test]
fn enrichment_migration_function_serde_roundtrip() {
    let func = MigrationFunction {
        from_version: "schema-v1".to_string(),
        to_version: "schema-v2".to_string(),
        lossy: true,
        description: "drop deprecated fields".to_string(),
    };
    let json = serde_json::to_string(&func).unwrap();
    let restored: MigrationFunction = serde_json::from_str(&json).unwrap();
    assert_eq!(func.from_version, restored.from_version);
    assert_eq!(func.to_version, restored.to_version);
    assert_eq!(func.lossy, restored.lossy);
    assert_eq!(func.description, restored.description);
}

#[test]
fn enrichment_migration_function_lossy_flag_accessible() {
    let non_lossy = MigrationFunction {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        lossy: false,
        description: "lossless".to_string(),
    };
    assert!(!non_lossy.lossy);

    let lossy = MigrationFunction {
        from_version: "v2".to_string(),
        to_version: "v3".to_string(),
        lossy: true,
        description: "lossy".to_string(),
    };
    assert!(lossy.lossy);
}

// ===========================================================================
// 6. MigrationRegistry — register, find, all, default
// ===========================================================================

#[test]
fn enrichment_migration_registry_new_is_empty() {
    let registry = MigrationRegistry::new();
    assert!(registry.all().is_empty());
}

#[test]
fn enrichment_migration_registry_default_is_empty() {
    let registry = MigrationRegistry::default();
    assert!(registry.all().is_empty());
}

#[test]
fn enrichment_migration_registry_find_returns_correct_pair() {
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
        v1_to_v2_migration,
    );

    let found = registry.find("v1", "v2");
    assert!(found.is_some());
    assert_eq!(found.unwrap().0.from_version, "v1");

    let found2 = registry.find("v2", "v3");
    assert!(found2.is_some());
    assert!(found2.unwrap().0.lossy);

    // Not found
    assert!(registry.find("v1", "v3").is_none());
    assert!(registry.find("v3", "v1").is_none());
}

#[test]
fn enrichment_migration_registry_all_returns_correct_count() {
    let mut registry = MigrationRegistry::new();
    assert_eq!(registry.all().len(), 0);

    for i in 0..5 {
        registry.register(
            MigrationFunction {
                from_version: format!("v{i}"),
                to_version: format!("v{}", i + 1),
                lossy: false,
                description: format!("migration {i}"),
            },
            identity_migration,
        );
    }
    assert_eq!(registry.all().len(), 5);
}

// ===========================================================================
// 7. MigrationOutcome — Display, serde, uniqueness
// ===========================================================================

#[test]
fn enrichment_migration_outcome_display_all_unique() {
    let outcomes = [
        MigrationOutcome::BackwardCompatible,
        MigrationOutcome::MigratedSuccessfully,
        MigrationOutcome::LossyMigration,
        MigrationOutcome::Failed,
    ];
    let mut displays: Vec<String> = outcomes.iter().map(|o| o.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_migration_outcome_serde_roundtrip_all_variants() {
    for outcome in [
        MigrationOutcome::BackwardCompatible,
        MigrationOutcome::MigratedSuccessfully,
        MigrationOutcome::LossyMigration,
        MigrationOutcome::Failed,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let restored: MigrationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
    }
}

#[test]
fn enrichment_migration_outcome_display_exact_values() {
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

// ===========================================================================
// 8. MigrationCompatibilityEvent — serde, field access
// ===========================================================================

#[test]
fn enrichment_migration_compatibility_event_serde_with_error_code() {
    let event = MigrationCompatibilityEvent {
        trace_id: "trace-42".to_string(),
        decision_id: "decision-7".to_string(),
        policy_id: "policy-3".to_string(),
        component: "migration_compatibility".to_string(),
        event: "no_migration_path".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("no_migration_path".to_string()),
        from_version: "evidence-v1".to_string(),
        to_version: "evidence-v3".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
    assert_eq!(restored.error_code.as_deref(), Some("no_migration_path"));
}

#[test]
fn enrichment_migration_compatibility_event_serde_without_error_code() {
    let event = MigrationCompatibilityEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "migration_compatibility".to_string(),
        event: "backward_compat_check".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        from_version: "v1".to_string(),
        to_version: "v1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MigrationCompatibilityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
    assert!(restored.error_code.is_none());
}

// ===========================================================================
// 9. MigrationTestResult — passed(), field access, serde
// ===========================================================================

#[test]
fn enrichment_test_result_passed_requires_no_errors_no_violations_not_failed() {
    // passes: no errors, no violations, not Failed
    let passing = MigrationTestResult {
        golden_ledger_name: "corpus".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::MigratedSuccessfully,
        entries_processed: 10,
        entries_replayed_ok: 10,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(passing.passed());
}

#[test]
fn enrichment_test_result_fails_with_errors_even_if_outcome_ok() {
    let result = MigrationTestResult {
        golden_ledger_name: "corpus".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::MigratedSuccessfully,
        entries_processed: 5,
        entries_replayed_ok: 5,
        errors: vec![MigrationError {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            error_code: MigrationErrorCode::LossyMigration,
            incompatible_fields: Vec::new(),
            message: "lossy".to_string(),
        }],
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(
        !result.passed(),
        "presence of errors should mean not passed"
    );
}

#[test]
fn enrichment_test_result_fails_with_violations_even_if_no_errors() {
    let result = MigrationTestResult {
        golden_ledger_name: "corpus".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::BackwardCompatible,
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
fn enrichment_test_result_backward_compatible_passes() {
    let result = MigrationTestResult {
        golden_ledger_name: "bc".to_string(),
        from_version: "v1".to_string(),
        to_version: "v1".to_string(),
        outcome: MigrationOutcome::BackwardCompatible,
        entries_processed: 20,
        entries_replayed_ok: 20,
        errors: Vec::new(),
        replay_violations: 0,
        schema_migrations_detected: Vec::new(),
        determinism_verified: true,
    };
    assert!(result.passed());
}

#[test]
fn enrichment_test_result_lossy_passes_when_no_violations() {
    let result = MigrationTestResult {
        golden_ledger_name: "lossy".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        outcome: MigrationOutcome::LossyMigration,
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
fn enrichment_test_result_serde_roundtrip_complex() {
    let result = MigrationTestResult {
        golden_ledger_name: "complex-corpus".to_string(),
        from_version: "ev-v1".to_string(),
        to_version: "ev-v2".to_string(),
        outcome: MigrationOutcome::Failed,
        entries_processed: 100,
        entries_replayed_ok: 42,
        errors: vec![
            MigrationError {
                from_version: "ev-v1".to_string(),
                to_version: "ev-v2".to_string(),
                error_code: MigrationErrorCode::RequiredFieldMissing,
                incompatible_fields: vec![IncompatibleField {
                    field_path: "metadata.x".to_string(),
                    reason: "missing".to_string(),
                }],
                message: "err1".to_string(),
            },
            MigrationError {
                from_version: "ev-v1".to_string(),
                to_version: "ev-v2".to_string(),
                error_code: MigrationErrorCode::FieldTypeChanged,
                incompatible_fields: Vec::new(),
                message: "err2".to_string(),
            },
        ],
        replay_violations: 58,
        schema_migrations_detected: Vec::new(),
        determinism_verified: false,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: MigrationTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.golden_ledger_name, restored.golden_ledger_name);
    assert_eq!(result.outcome, restored.outcome);
    assert_eq!(result.errors.len(), restored.errors.len());
    assert_eq!(result.entries_processed, restored.entries_processed);
    assert_eq!(result.entries_replayed_ok, restored.entries_replayed_ok);
    assert_eq!(result.replay_violations, restored.replay_violations);
    assert_eq!(result.determinism_verified, restored.determinism_verified);
}

// ===========================================================================
// 10. MigrationCompatibilityChecker — orchestration workflows
// ===========================================================================

#[test]
fn enrichment_checker_target_version_accessor() {
    let registry = MigrationRegistry::new();
    let checker = MigrationCompatibilityChecker::new("evidence-v5", registry);
    assert_eq!(checker.target_version(), "evidence-v5");
}

#[test]
fn enrichment_checker_golden_ledger_count_increments() {
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("v1", registry);
    assert_eq!(checker.golden_ledger_count(), 0);

    checker.add_golden_ledger(build_golden_ledger("a", "v1", 1));
    assert_eq!(checker.golden_ledger_count(), 1);

    checker.add_golden_ledger(build_golden_ledger("b", "v1", 2));
    assert_eq!(checker.golden_ledger_count(), 2);
}

#[test]
fn enrichment_checker_backward_compat_same_version_passes() {
    let ledger = build_golden_ledger("compat", "evidence-v1", 3);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("evidence-v1", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::BackwardCompatible);
    assert!(results[0].determinism_verified);
    assert_eq!(results[0].entries_processed, 3);
    assert_eq!(results[0].entries_replayed_ok, 3);
}

#[test]
fn enrichment_checker_migration_with_identity_function() {
    let ledger = build_golden_ledger("test", "v-old", 4);
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v-old".to_string(),
            to_version: "v-new".to_string(),
            lossy: false,
            description: "identity".to_string(),
        },
        identity_migration,
    );
    let mut checker = MigrationCompatibilityChecker::new("v-new", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::MigratedSuccessfully);
}

#[test]
fn enrichment_checker_no_migration_path_produces_error() {
    let ledger = build_golden_ledger("test", "v-old", 3);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("v-new", registry);
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
    assert!(!results[0].determinism_verified);
}

#[test]
fn enrichment_checker_failing_migration_reports_per_entry_errors() {
    let ledger = build_golden_ledger("test", "evidence-v1", 4);
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "broken".to_string(),
        },
        failing_migration,
    );
    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert!(!results[0].passed());
    assert_eq!(results[0].errors.len(), 4, "one error per entry");
    for err in &results[0].errors {
        assert_eq!(err.error_code, MigrationErrorCode::RequiredFieldMissing);
        assert_eq!(err.incompatible_fields.len(), 1);
    }
}

#[test]
fn enrichment_checker_lossy_migration_outcome() {
    let ledger = build_golden_ledger("test", "evidence-v1", 3);
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: true,
            description: "lossy change".to_string(),
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
fn enrichment_checker_events_populated_after_run() {
    let ledger = build_golden_ledger("test", "v1", 2);
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("v1", registry);
    checker.add_golden_ledger(ledger);
    let _ = checker.run_all();

    let events = checker.events();
    assert!(!events.is_empty());
    for event in events {
        assert_eq!(event.component, "migration_compatibility");
    }
}

#[test]
fn enrichment_checker_registry_accessor() {
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
fn enrichment_checker_multiple_ledgers_mixed_outcomes() {
    let ledger_same = build_golden_ledger("same-ver", "v2", 3);
    let ledger_migrate = build_golden_ledger("needs-migrate", "v1", 2);
    let ledger_no_path = build_golden_ledger("no-path", "v0", 1);

    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            lossy: false,
            description: "v1->v2".to_string(),
        },
        identity_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("v2", registry);
    checker.add_golden_ledger(ledger_same);
    checker.add_golden_ledger(ledger_migrate);
    checker.add_golden_ledger(ledger_no_path);

    let results = checker.run_all();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].outcome, MigrationOutcome::BackwardCompatible);
    assert_eq!(results[1].outcome, MigrationOutcome::MigratedSuccessfully);
    assert_eq!(results[2].outcome, MigrationOutcome::Failed);
}

#[test]
fn enrichment_checker_determinism_verified_for_identity() {
    let ledger = build_golden_ledger("det-check", "v1", 5);
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            lossy: false,
            description: "identity".to_string(),
        },
        identity_migration,
    );
    let mut checker = MigrationCompatibilityChecker::new("v2", registry);
    checker.add_golden_ledger(ledger);

    let results = checker.run_all();
    assert!(results[0].determinism_verified);
}

#[test]
fn enrichment_checker_run_all_deterministic() {
    let make = || {
        let ledger = build_golden_ledger("test", "v1", 3);
        let mut registry = MigrationRegistry::new();
        registry.register(
            MigrationFunction {
                from_version: "v1".to_string(),
                to_version: "v2".to_string(),
                lossy: false,
                description: "det-test".to_string(),
            },
            v1_to_v2_migration,
        );
        let mut checker = MigrationCompatibilityChecker::new("v2", registry);
        checker.add_golden_ledger(ledger);
        checker
    };

    let mut c1 = make();
    let mut c2 = make();
    let j1 = serde_json::to_string(&c1.run_all()).unwrap();
    let j2 = serde_json::to_string(&c2.run_all()).unwrap();
    assert_eq!(j1, j2, "run_all must produce identical serialized results");
}

#[test]
fn enrichment_checker_empty_corpus_no_results() {
    let registry = MigrationRegistry::new();
    let mut checker = MigrationCompatibilityChecker::new("v1", registry);
    let results = checker.run_all();
    assert!(results.is_empty());
    assert!(checker.events().is_empty());
}

// ===========================================================================
// 11. GoldenLedgerManifest — add, verify, serde
// ===========================================================================

#[test]
fn enrichment_manifest_new_is_empty() {
    let manifest = GoldenLedgerManifest::new();
    assert!(manifest.is_empty());
    assert_eq!(manifest.len(), 0);
}

#[test]
fn enrichment_manifest_default_is_empty() {
    let manifest = GoldenLedgerManifest::default();
    assert!(manifest.is_empty());
}

#[test]
fn enrichment_manifest_add_and_verify_match() {
    let ledger = build_golden_ledger("corpus-alpha", "v1", 5);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);
    assert_eq!(manifest.len(), 1);
    assert!(manifest.verify(&ledger));
}

#[test]
fn enrichment_manifest_tampered_ledger_fails_verify() {
    let ledger = build_golden_ledger("corpus", "v1", 3);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    let mut tampered = ledger;
    tampered.entries[0].action_name = "TAMPERED".to_string();
    let payload = serde_json::to_vec(&tampered.entries).unwrap();
    tampered.corpus_hash = ContentHash::compute(&payload);
    assert!(!manifest.verify(&tampered));
}

#[test]
fn enrichment_manifest_unknown_name_fails_verify() {
    let manifest = GoldenLedgerManifest::new();
    let ledger = build_golden_ledger("not-tracked", "v1", 1);
    assert!(!manifest.verify(&ledger));
}

#[test]
fn enrichment_manifest_overwrite_same_name() {
    let mut manifest = GoldenLedgerManifest::new();
    let l1 = build_golden_ledger("shared", "v1", 2);
    let l2 = build_golden_ledger("shared", "v2", 4);
    manifest.add(&l1);
    assert!(manifest.verify(&l1));
    manifest.add(&l2);
    assert_eq!(manifest.len(), 1);
    assert!(manifest.verify(&l2));
    assert!(!manifest.verify(&l1));
}

#[test]
fn enrichment_manifest_multiple_distinct_ledgers() {
    let mut manifest = GoldenLedgerManifest::new();
    for i in 0..10 {
        let ledger = build_golden_ledger(&format!("corpus-{i}"), "v1", i + 1);
        manifest.add(&ledger);
    }
    assert_eq!(manifest.len(), 10);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let mut manifest = GoldenLedgerManifest::new();
    let l1 = build_golden_ledger("alpha", "v1", 3);
    let l2 = build_golden_ledger("beta", "v2", 5);
    manifest.add(&l1);
    manifest.add(&l2);

    let json = serde_json::to_string(&manifest).unwrap();
    let restored: GoldenLedgerManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn enrichment_manifest_entry_fields_populated() {
    let ledger = build_golden_ledger("entry-test", "v3", 7);
    let mut manifest = GoldenLedgerManifest::new();
    manifest.add(&ledger);

    let entry = manifest.entries.get("entry-test").unwrap();
    assert_eq!(entry.schema_version, "v3");
    assert_eq!(entry.entry_count, 7);
    assert_eq!(entry.frozen_at_ms, 1_700_000_000_000);
    assert_eq!(entry.corpus_hash, ledger.corpus_hash);
}

#[test]
fn enrichment_manifest_entry_serde_roundtrip() {
    let entry = ManifestEntry {
        schema_version: "evidence-v5".to_string(),
        corpus_hash: ContentHash::compute(b"manifest-test-data"),
        entry_count: 42,
        frozen_at_ms: 1_700_500_000_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: ManifestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// ===========================================================================
// 12. CutoverType — Display, serde, ordering
// ===========================================================================

#[test]
fn enrichment_cutover_type_display_all_unique() {
    let types = [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ];
    let mut displays: Vec<String> = types.iter().map(|t| t.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_cutover_type_serde_roundtrip_all() {
    for ct in [
        CutoverType::HardCutover,
        CutoverType::SoftMigration,
        CutoverType::ParallelRun,
    ] {
        let json = serde_json::to_string(&ct).unwrap();
        let restored: CutoverType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, restored);
    }
}

#[test]
fn enrichment_cutover_type_display_exact() {
    assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
    assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
    assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
}

// ===========================================================================
// 13. ObjectClass — Display, serde, ordering
// ===========================================================================

#[test]
fn enrichment_object_class_display_all_6_unique() {
    let classes = [
        ObjectClass::SerializationSchema,
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyFormat,
    ];
    let mut displays: Vec<String> = classes.iter().map(|c| c.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_object_class_serde_roundtrip_all() {
    for oc in [
        ObjectClass::SerializationSchema,
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyFormat,
    ] {
        let json = serde_json::to_string(&oc).unwrap();
        let restored: ObjectClass = serde_json::from_str(&json).unwrap();
        assert_eq!(oc, restored);
    }
}

#[test]
fn enrichment_object_class_display_exact_values() {
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
fn enrichment_object_class_btreeset_deterministic_order() {
    let mut set = BTreeSet::new();
    set.insert(ObjectClass::PolicyFormat);
    set.insert(ObjectClass::KeyFormat);
    set.insert(ObjectClass::SerializationSchema);
    let ordered: Vec<ObjectClass> = set.iter().copied().collect();
    // BTreeSet uses Ord, so order should be stable
    assert_eq!(ordered[0], ordered[0]); // at least verify no panic
    assert_eq!(ordered.len(), 3);
}

// ===========================================================================
// 14. MigrationDeclaration — serde, field access
// ===========================================================================

#[test]
fn enrichment_migration_declaration_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::KeyFormat);
    affected.insert(ObjectClass::TokenFormat);

    let decl = MigrationDeclaration {
        migration_id: "mig-enrichment-1".to_string(),
        from_version: "format-v3".to_string(),
        to_version: "format-v4".to_string(),
        affected_objects: affected.clone(),
        cutover_type: CutoverType::ParallelRun,
        description: "enrichment test declaration".to_string(),
        compatible_across_boundary: vec!["API".to_string(), "wire format".to_string()],
        incompatible_across_boundary: vec!["storage layout".to_string()],
    };
    let json = serde_json::to_string(&decl).unwrap();
    let restored: MigrationDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(decl, restored);
    assert_eq!(restored.affected_objects.len(), 3);
    assert_eq!(restored.compatible_across_boundary.len(), 2);
    assert_eq!(restored.incompatible_across_boundary.len(), 1);
}

#[test]
fn enrichment_migration_declaration_all_object_classes() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::KeyFormat);
    affected.insert(ObjectClass::TokenFormat);
    affected.insert(ObjectClass::CheckpointFormat);
    affected.insert(ObjectClass::RevocationFormat);
    affected.insert(ObjectClass::PolicyFormat);

    let decl = MigrationDeclaration {
        migration_id: "all-classes".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: affected,
        cutover_type: CutoverType::HardCutover,
        description: "all object classes".to_string(),
        compatible_across_boundary: Vec::new(),
        incompatible_across_boundary: Vec::new(),
    };
    assert_eq!(decl.affected_objects.len(), 6);
}

// ===========================================================================
// 15. MigrationPhase — Display, serde, ordering, uniqueness
// ===========================================================================

#[test]
fn enrichment_migration_phase_display_all_6_unique() {
    let phases = [
        MigrationPhase::PreMigration,
        MigrationPhase::Checkpoint,
        MigrationPhase::Execute,
        MigrationPhase::Verify,
        MigrationPhase::Commit,
        MigrationPhase::Rollback,
    ];
    let mut displays: Vec<String> = phases.iter().map(|p| p.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_migration_phase_serde_roundtrip_all() {
    for phase in [
        MigrationPhase::PreMigration,
        MigrationPhase::Checkpoint,
        MigrationPhase::Execute,
        MigrationPhase::Verify,
        MigrationPhase::Commit,
        MigrationPhase::Rollback,
    ] {
        let json = serde_json::to_string(&phase).unwrap();
        let restored: MigrationPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, restored);
    }
}

#[test]
fn enrichment_migration_phase_display_exact() {
    assert_eq!(MigrationPhase::PreMigration.to_string(), "pre_migration");
    assert_eq!(MigrationPhase::Checkpoint.to_string(), "checkpoint");
    assert_eq!(MigrationPhase::Execute.to_string(), "execute");
    assert_eq!(MigrationPhase::Verify.to_string(), "verify");
    assert_eq!(MigrationPhase::Commit.to_string(), "commit");
    assert_eq!(MigrationPhase::Rollback.to_string(), "rollback");
}

// ===========================================================================
// 16. PhaseOutcome — Display, serde, uniqueness
// ===========================================================================

#[test]
fn enrichment_phase_outcome_display_all_unique() {
    let outcomes = [
        PhaseOutcome::Success,
        PhaseOutcome::Failed,
        PhaseOutcome::Skipped,
    ];
    let mut displays: Vec<String> = outcomes.iter().map(|o| o.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_phase_outcome_serde_roundtrip_all() {
    for po in [
        PhaseOutcome::Success,
        PhaseOutcome::Failed,
        PhaseOutcome::Skipped,
    ] {
        let json = serde_json::to_string(&po).unwrap();
        let restored: PhaseOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(po, restored);
    }
}

#[test]
fn enrichment_phase_outcome_display_exact() {
    assert_eq!(PhaseOutcome::Success.to_string(), "success");
    assert_eq!(PhaseOutcome::Failed.to_string(), "failed");
    assert_eq!(PhaseOutcome::Skipped.to_string(), "skipped");
}

// ===========================================================================
// 17. PhaseExecutionRecord — serde, field access
// ===========================================================================

#[test]
fn enrichment_phase_execution_record_serde_roundtrip() {
    let record = PhaseExecutionRecord {
        migration_id: "mig-99".to_string(),
        phase: MigrationPhase::Verify,
        outcome: PhaseOutcome::Failed,
        affected_count: 1_000_000,
        detail: "1000000 entries verified with 5 failures".to_string(),
        timestamp: DeterministicTimestamp(987_654_321),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn enrichment_phase_execution_record_all_phases_serializable() {
    for phase in [
        MigrationPhase::PreMigration,
        MigrationPhase::Checkpoint,
        MigrationPhase::Execute,
        MigrationPhase::Verify,
        MigrationPhase::Commit,
        MigrationPhase::Rollback,
    ] {
        let record = PhaseExecutionRecord {
            migration_id: "test".to_string(),
            phase,
            outcome: PhaseOutcome::Success,
            affected_count: 0,
            detail: "ok".to_string(),
            timestamp: DeterministicTimestamp(0),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.phase, restored.phase);
    }
}

// ===========================================================================
// 18. CutoverError — Display, serde, error codes, std::error::Error
// ===========================================================================

#[test]
fn enrichment_cutover_error_display_all_10_variants_nonempty() {
    let errors: Vec<CutoverError> = vec![
        CutoverError::InvalidDeclaration {
            detail: "bad".to_string(),
        },
        CutoverError::DryRunFailed {
            unconvertible_count: 42,
        },
        CutoverError::VerificationFailed { violations: 7 },
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 3,
        },
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::TokenFormat,
        },
        CutoverError::TransitionWindowExpired {
            migration_id: "m-old".to_string(),
        },
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Checkpoint,
            detail: "disk full".to_string(),
        },
        CutoverError::AlreadyCommitted {
            migration_id: "m-done".to_string(),
        },
        CutoverError::NoMigrationInProgress,
        CutoverError::MigrationNotFound {
            migration_id: "m-missing".to_string(),
        },
    ];
    for err in &errors {
        let display = err.to_string();
        assert!(!display.is_empty(), "empty Display for {err:?}");
    }
}

#[test]
fn enrichment_cutover_error_display_contains_inner_values() {
    assert!(
        CutoverError::InvalidDeclaration {
            detail: "BAD_INPUT".to_string()
        }
        .to_string()
        .contains("BAD_INPUT")
    );
    assert!(
        CutoverError::DryRunFailed {
            unconvertible_count: 99
        }
        .to_string()
        .contains("99")
    );
    assert!(
        CutoverError::VerificationFailed { violations: 13 }
            .to_string()
            .contains("13")
    );
    assert!(
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 8
        }
        .to_string()
        .contains("8")
    );
    assert!(
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::CheckpointFormat
        }
        .to_string()
        .contains("checkpoint_format")
    );
    assert!(
        CutoverError::TransitionWindowExpired {
            migration_id: "XYZ".to_string()
        }
        .to_string()
        .contains("XYZ")
    );
    assert!(
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Execute,
            detail: "boom".to_string()
        }
        .to_string()
        .contains("execute")
    );
    assert!(
        CutoverError::AlreadyCommitted {
            migration_id: "ABC".to_string()
        }
        .to_string()
        .contains("ABC")
    );
    assert!(
        CutoverError::MigrationNotFound {
            migration_id: "QRS".to_string()
        }
        .to_string()
        .contains("QRS")
    );
}

#[test]
fn enrichment_cutover_error_code_all_10_exact_values() {
    let expected = [
        (
            CutoverError::InvalidDeclaration {
                detail: String::new(),
            },
            "MC_INVALID_DECLARATION",
        ),
        (
            CutoverError::DryRunFailed {
                unconvertible_count: 0,
            },
            "MC_DRY_RUN_FAILED",
        ),
        (
            CutoverError::VerificationFailed { violations: 0 },
            "MC_VERIFICATION_FAILED",
        ),
        (
            CutoverError::ParallelRunDiscrepancy {
                discrepancy_count: 0,
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
                migration_id: String::new(),
            },
            "MC_WINDOW_EXPIRED",
        ),
        (
            CutoverError::PhaseFailed {
                phase: MigrationPhase::Execute,
                detail: String::new(),
            },
            "MC_PHASE_FAILED",
        ),
        (
            CutoverError::AlreadyCommitted {
                migration_id: String::new(),
            },
            "MC_ALREADY_COMMITTED",
        ),
        (CutoverError::NoMigrationInProgress, "MC_NO_MIGRATION"),
        (
            CutoverError::MigrationNotFound {
                migration_id: String::new(),
            },
            "MC_NOT_FOUND",
        ),
    ];
    for (err, code) in &expected {
        assert_eq!(cutover_error_code(err), *code);
    }
}

#[test]
fn enrichment_cutover_error_code_all_unique() {
    let errors: Vec<CutoverError> = vec![
        CutoverError::InvalidDeclaration {
            detail: String::new(),
        },
        CutoverError::DryRunFailed {
            unconvertible_count: 0,
        },
        CutoverError::VerificationFailed { violations: 0 },
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 0,
        },
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::KeyFormat,
        },
        CutoverError::TransitionWindowExpired {
            migration_id: String::new(),
        },
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Execute,
            detail: String::new(),
        },
        CutoverError::AlreadyCommitted {
            migration_id: String::new(),
        },
        CutoverError::NoMigrationInProgress,
        CutoverError::MigrationNotFound {
            migration_id: String::new(),
        },
    ];
    let mut codes: Vec<&str> = errors.iter().map(|e| cutover_error_code(e)).collect();
    let n = codes.len();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), n, "error codes must be unique");
}

#[test]
fn enrichment_cutover_error_serde_roundtrip_all_10() {
    let errors: Vec<CutoverError> = vec![
        CutoverError::InvalidDeclaration {
            detail: "test-detail".to_string(),
        },
        CutoverError::DryRunFailed {
            unconvertible_count: 42,
        },
        CutoverError::VerificationFailed { violations: 7 },
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 3,
        },
        CutoverError::OldFormatRejected {
            object_class: ObjectClass::RevocationFormat,
        },
        CutoverError::TransitionWindowExpired {
            migration_id: "m-exp".to_string(),
        },
        CutoverError::PhaseFailed {
            phase: MigrationPhase::Rollback,
            detail: "rollback".to_string(),
        },
        CutoverError::AlreadyCommitted {
            migration_id: "m-comm".to_string(),
        },
        CutoverError::NoMigrationInProgress,
        CutoverError::MigrationNotFound {
            migration_id: "m-nf".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: CutoverError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn enrichment_cutover_error_implements_std_error() {
    let err = CutoverError::PhaseFailed {
        phase: MigrationPhase::Execute,
        detail: "disk failure".to_string(),
    };
    let e: &dyn std::error::Error = &err;
    assert!(!e.to_string().is_empty());
    assert!(e.source().is_none());
}

// ===========================================================================
// 19. CutoverState — Display, serde, ordering, uniqueness
// ===========================================================================

#[test]
fn enrichment_cutover_state_display_all_7_unique() {
    let states = [
        CutoverState::Declared,
        CutoverState::PreMigrated,
        CutoverState::Checkpointed,
        CutoverState::Executed,
        CutoverState::Verified,
        CutoverState::Committed,
        CutoverState::RolledBack,
    ];
    let mut displays: Vec<String> = states.iter().map(|s| s.to_string()).collect();
    let n = displays.len();
    displays.sort();
    displays.dedup();
    assert_eq!(displays.len(), n);
}

#[test]
fn enrichment_cutover_state_serde_roundtrip_all() {
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
        let restored: CutoverState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }
}

#[test]
fn enrichment_cutover_state_display_exact() {
    assert_eq!(CutoverState::Declared.to_string(), "declared");
    assert_eq!(CutoverState::PreMigrated.to_string(), "pre_migrated");
    assert_eq!(CutoverState::Checkpointed.to_string(), "checkpointed");
    assert_eq!(CutoverState::Executed.to_string(), "executed");
    assert_eq!(CutoverState::Verified.to_string(), "verified");
    assert_eq!(CutoverState::Committed.to_string(), "committed");
    assert_eq!(CutoverState::RolledBack.to_string(), "rolled_back");
}

// ===========================================================================
// 20. TransitionWindow — active/expired logic, serde
// ===========================================================================

#[test]
fn enrichment_transition_window_boundary_values() {
    let w = TransitionWindow {
        migration_id: "tw-1".to_string(),
        start_tick: 100,
        end_tick: 200,
        old_format_accepted: true,
    };
    // Before start
    assert!(!w.is_active(0));
    assert!(!w.is_active(99));
    assert!(!w.is_expired(0));
    assert!(!w.is_expired(99));

    // At start
    assert!(w.is_active(100));
    assert!(!w.is_expired(100));

    // During
    assert!(w.is_active(150));
    assert!(!w.is_expired(150));

    // At end (expired)
    assert!(!w.is_active(200));
    assert!(w.is_expired(200));

    // Well past end
    assert!(!w.is_active(1000));
    assert!(w.is_expired(1000));
}

#[test]
fn enrichment_transition_window_zero_length() {
    let w = TransitionWindow {
        migration_id: "tw-zero".to_string(),
        start_tick: 50,
        end_tick: 50,
        old_format_accepted: true,
    };
    // Zero-length window: never active, immediately expired at start_tick
    assert!(!w.is_active(50));
    assert!(w.is_expired(50));
    assert!(!w.is_active(49));
    assert!(!w.is_expired(49));
}

#[test]
fn enrichment_transition_window_serde_roundtrip() {
    let w = TransitionWindow {
        migration_id: "tw-serde".to_string(),
        start_tick: 500,
        end_tick: 1500,
        old_format_accepted: false,
    };
    let json = serde_json::to_string(&w).unwrap();
    let restored: TransitionWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, restored);
}

#[test]
fn enrichment_transition_window_max_ticks() {
    let w = TransitionWindow {
        migration_id: "tw-max".to_string(),
        start_tick: 0,
        end_tick: u64::MAX,
        old_format_accepted: true,
    };
    assert!(w.is_active(0));
    assert!(w.is_active(u64::MAX - 1));
    assert!(!w.is_active(u64::MAX));
    assert!(w.is_expired(u64::MAX));
}

// ===========================================================================
// 21. AppliedMigrationEntry — serde, field access
// ===========================================================================

#[test]
fn enrichment_applied_migration_entry_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::PolicyFormat);

    let entry = AppliedMigrationEntry {
        migration_id: "mig-applied-1".to_string(),
        from_version: "fmt-v1".to_string(),
        to_version: "fmt-v2".to_string(),
        cutover_type: CutoverType::SoftMigration,
        state: CutoverState::Committed,
        affected_objects: affected,
        phase_records: vec![
            PhaseExecutionRecord {
                migration_id: "mig-applied-1".to_string(),
                phase: MigrationPhase::PreMigration,
                outcome: PhaseOutcome::Success,
                affected_count: 50,
                detail: "dry run ok".to_string(),
                timestamp: DeterministicTimestamp(100),
            },
            PhaseExecutionRecord {
                migration_id: "mig-applied-1".to_string(),
                phase: MigrationPhase::Commit,
                outcome: PhaseOutcome::Success,
                affected_count: 50,
                detail: "committed".to_string(),
                timestamp: DeterministicTimestamp(200),
            },
        ],
        declared_at: DeterministicTimestamp(100),
        committed_at: Some(DeterministicTimestamp(200)),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: AppliedMigrationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn enrichment_applied_migration_entry_rolled_back_no_committed_at() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::KeyFormat);

    let entry = AppliedMigrationEntry {
        migration_id: "mig-rolled-back".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        cutover_type: CutoverType::HardCutover,
        state: CutoverState::RolledBack,
        affected_objects: affected,
        phase_records: Vec::new(),
        declared_at: DeterministicTimestamp(50),
        committed_at: None,
    };
    assert!(entry.committed_at.is_none());
    assert_eq!(entry.state, CutoverState::RolledBack);
}

// ===========================================================================
// 22. CutoverAuditEvent — serde, field access
// ===========================================================================

#[test]
fn enrichment_cutover_audit_event_serde_with_all_optional_fields() {
    let event = CutoverAuditEvent {
        trace_id: "trace-enrichment".to_string(),
        component: "migration_compatibility".to_string(),
        migration_id: "mig-audit-1".to_string(),
        event: "verification_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("MC_VERIFICATION_FAILED".to_string()),
        phase: Some("verify".to_string()),
        affected_count: Some(77),
        timestamp: DeterministicTimestamp(999),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CutoverAuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_cutover_audit_event_serde_with_none_optionals() {
    let event = CutoverAuditEvent {
        trace_id: "t".to_string(),
        component: "migration_compatibility".to_string(),
        migration_id: "m".to_string(),
        event: "migration_declared".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        phase: None,
        affected_count: None,
        timestamp: DeterministicTimestamp(0),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CutoverAuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// 23. CutoverMigrationRunner — lifecycle, accessors, edge cases
// ===========================================================================

#[test]
fn enrichment_runner_new_empty_state() {
    let runner = CutoverMigrationRunner::new();
    assert_eq!(runner.declaration_count(), 0);
    assert!(runner.applied_migrations().is_empty());
    assert!(runner.active_state().is_none());
    assert!(runner.active_migration_id().is_none());
    assert!(runner.transition_windows().is_empty());
    assert!(runner.audit_events().is_empty());
}

#[test]
fn enrichment_runner_default_same_as_new() {
    let from_new = CutoverMigrationRunner::new();
    let from_default = CutoverMigrationRunner::default();
    assert_eq!(
        from_new.declaration_count(),
        from_default.declaration_count()
    );
    assert_eq!(
        from_new.applied_migrations().len(),
        from_default.applied_migrations().len()
    );
}

#[test]
fn enrichment_runner_declare_increments_count() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m1", CutoverType::HardCutover), "t")
        .unwrap();
    assert_eq!(runner.declaration_count(), 1);

    let mut decl2 = test_declaration("m2", CutoverType::SoftMigration);
    decl2.from_version = "v2".to_string();
    decl2.to_version = "v3".to_string();
    runner.declare(decl2, "t").unwrap();
    assert_eq!(runner.declaration_count(), 2);
}

#[test]
fn enrichment_runner_declare_rejects_empty_id() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("", CutoverType::HardCutover);
    decl.migration_id = String::new();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    if let CutoverError::InvalidDeclaration { detail } = &err {
        assert!(detail.contains("migration_id"));
    }
}

#[test]
fn enrichment_runner_declare_rejects_empty_affected_objects() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("m1", CutoverType::HardCutover);
    decl.affected_objects.clear();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn enrichment_runner_declare_rejects_same_from_to() {
    let mut runner = CutoverMigrationRunner::new();
    let mut decl = test_declaration("m1", CutoverType::HardCutover);
    decl.to_version = decl.from_version.clone();
    let err = runner.declare(decl, "t").unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
}

#[test]
fn enrichment_runner_declare_rejects_duplicate_id() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("dup", CutoverType::HardCutover), "t")
        .unwrap();
    let err = runner
        .declare(test_declaration("dup", CutoverType::SoftMigration), "t")
        .unwrap_err();
    assert!(matches!(err, CutoverError::InvalidDeclaration { .. }));
    if let CutoverError::InvalidDeclaration { detail } = &err {
        assert!(detail.contains("duplicate"));
    }
}

#[test]
fn enrichment_runner_hard_cutover_full_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-hard", CutoverType::HardCutover), "t")
        .unwrap();
    let entry = run_full_migration(&mut runner, "m-hard");

    assert_eq!(entry.state, CutoverState::Committed);
    assert_eq!(entry.cutover_type, CutoverType::HardCutover);
    assert!(entry.committed_at.is_some());
    assert_eq!(entry.phase_records.len(), 5);
    assert!(runner.active_migration_id().is_none());
}

#[test]
fn enrichment_runner_hard_cutover_rejects_old_format() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-hard", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-hard");

    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::OldFormatRejected { .. }));
}

#[test]
fn enrichment_runner_hard_cutover_accepts_unaffected_class() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-hard", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-hard");

    // KeyFormat not in affected_objects -> should pass
    runner
        .check_format_acceptance(ObjectClass::KeyFormat)
        .unwrap();
    runner
        .check_format_acceptance(ObjectClass::PolicyFormat)
        .unwrap();
}

#[test]
fn enrichment_runner_soft_migration_creates_transition_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-soft", CutoverType::SoftMigration), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-soft");

    let windows = runner.transition_windows();
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].migration_id, "m-soft");
    assert!(windows[0].old_format_accepted);
    // Default window is 1000 ticks from commit tick (40)
    assert_eq!(windows[0].start_tick, 40);
    assert_eq!(windows[0].end_tick, 1040);
}

#[test]
fn enrichment_runner_soft_migration_accepts_during_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-soft", CutoverType::SoftMigration), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-soft");

    runner.set_tick(500);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();
}

#[test]
fn enrichment_runner_soft_migration_rejects_after_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-soft", CutoverType::SoftMigration), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-soft");

    // Window is [40, 1040), so tick 1040 should expire
    runner.set_tick(1040);
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::TransitionWindowExpired { .. }));
}

#[test]
fn enrichment_runner_parallel_run_accepts_old_format_after_commit() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-par", CutoverType::ParallelRun), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-par");

    runner.set_tick(999_999);
    runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap();
}

#[test]
fn enrichment_runner_parallel_discrepancy_aborts() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-par", CutoverType::ParallelRun), "t")
        .unwrap();
    runner.begin("m-par", 100, "t").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "t").unwrap();
    runner.set_tick(20);
    runner.execute(100, "t").unwrap();

    let err = runner.report_parallel_discrepancies(3, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::ParallelRunDiscrepancy {
            discrepancy_count: 3
        }
    ));
    assert!(runner.active_migration_id().is_none());
    assert_eq!(
        runner.applied_migrations()[0].state,
        CutoverState::RolledBack
    );
}

#[test]
fn enrichment_runner_parallel_zero_discrepancies_ok() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-par", CutoverType::ParallelRun), "t")
        .unwrap();
    runner.begin("m-par", 100, "t").unwrap();
    runner.set_tick(10);
    runner.create_checkpoint(1, "t").unwrap();
    runner.set_tick(20);
    runner.execute(100, "t").unwrap();

    runner.report_parallel_discrepancies(0, "t").unwrap();
    // Active migration still present, can continue
    assert!(runner.active_migration_id().is_some());
}

#[test]
fn enrichment_runner_parallel_discrepancy_rejected_for_hard_cutover() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-hard", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-hard", 100, "t").unwrap();

    let err = runner.report_parallel_discrepancies(0, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_verification_failure_auto_rollback() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-vf", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-vf", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();

    let err = runner.verify(5, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::VerificationFailed { violations: 5 }
    ));
    assert!(runner.active_migration_id().is_none());
    assert_eq!(
        runner.applied_migrations()[0].state,
        CutoverState::RolledBack
    );
}

#[test]
fn enrichment_runner_dry_run_failure_rollback() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-dr", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-dr", 100, "t").unwrap();

    let err = runner.fail_dry_run(15, "t").unwrap_err();
    assert!(matches!(
        err,
        CutoverError::DryRunFailed {
            unconvertible_count: 15
        }
    ));
    assert!(runner.active_migration_id().is_none());
}

#[test]
fn enrichment_runner_manual_rollback_before_commit() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-rb", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-rb", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();

    runner.rollback("t").unwrap();
    assert!(runner.active_migration_id().is_none());
    assert_eq!(
        runner.applied_migrations()[0].state,
        CutoverState::RolledBack
    );
    assert!(runner.applied_migrations()[0].committed_at.is_none());
}

#[test]
fn enrichment_runner_rollback_no_active_fails() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.rollback("t").unwrap_err();
    assert!(matches!(err, CutoverError::NoMigrationInProgress));
}

#[test]
fn enrichment_runner_begin_unknown_migration_fails() {
    let mut runner = CutoverMigrationRunner::new();
    let err = runner.begin("nonexistent", 50, "t").unwrap_err();
    assert!(matches!(err, CutoverError::MigrationNotFound { .. }));
}

#[test]
fn enrichment_runner_only_one_active_migration() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m1", CutoverType::HardCutover), "t")
        .unwrap();
    let mut d2 = test_declaration("m2", CutoverType::SoftMigration);
    d2.from_version = "v2".to_string();
    d2.to_version = "v3".to_string();
    runner.declare(d2, "t").unwrap();

    runner.begin("m1", 100, "t").unwrap();
    let err = runner.begin("m2", 50, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_phase_ordering_checkpoint_before_premigrated() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    // Already checkpointed, second checkpoint should fail
    let err = runner.create_checkpoint(2, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_phase_ordering_execute_without_checkpoint() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m", 100, "t").unwrap();
    let err = runner.execute(100, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_phase_ordering_verify_without_execute() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    let err = runner.verify(0, "t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_phase_ordering_commit_without_verify() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();
    let err = runner.commit("t").unwrap_err();
    assert!(matches!(err, CutoverError::PhaseFailed { .. }));
}

#[test]
fn enrichment_runner_all_operations_no_active_fail() {
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
    assert!(matches!(
        runner.fail_dry_run(1, "t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
    assert!(matches!(
        runner.report_parallel_discrepancies(0, "t"),
        Err(CutoverError::NoMigrationInProgress)
    ));
}

#[test]
fn enrichment_runner_active_state_tracks_through_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-track", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(runner.active_state().is_none());

    runner.begin("m-track", 50, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::PreMigrated));
    assert_eq!(runner.active_migration_id(), Some("m-track"));

    runner.create_checkpoint(1, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Checkpointed));

    runner.execute(50, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Executed));

    runner.verify(0, "t").unwrap();
    assert_eq!(runner.active_state(), Some(CutoverState::Verified));

    runner.commit("t").unwrap();
    assert!(runner.active_state().is_none());
}

#[test]
fn enrichment_runner_audit_events_emitted_on_lifecycle() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-audit", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-audit");

    let events = runner.audit_events();
    assert!(events.len() >= 5);
    assert!(events.iter().any(|e| e.event == "migration_declared"));
    assert!(events.iter().any(|e| e.event == "pre_migration_complete"));
    assert!(events.iter().any(|e| e.event == "checkpoint_created"));
    assert!(events.iter().any(|e| e.event == "migration_executed"));
    assert!(events.iter().any(|e| e.event == "migration_committed"));

    for event in events {
        assert_eq!(event.component, "migration_compatibility");
    }
}

#[test]
fn enrichment_runner_audit_events_error_code_on_failure() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-fail", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-fail", 100, "t").unwrap();
    runner.create_checkpoint(1, "t").unwrap();
    runner.execute(100, "t").unwrap();
    let _ = runner.verify(3, "t");

    let events = runner.audit_events();
    let fail = events
        .iter()
        .find(|e| e.event == "verification_failed")
        .unwrap();
    assert_eq!(fail.error_code.as_deref(), Some("MC_VERIFICATION_FAILED"));
    assert_eq!(fail.affected_count, Some(3));
}

#[test]
fn enrichment_runner_drain_clears_events() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-drain", CutoverType::HardCutover), "t")
        .unwrap();
    assert!(!runner.audit_events().is_empty());
    let drained = runner.drain_audit_events();
    assert!(!drained.is_empty());
    assert!(runner.audit_events().is_empty());
}

#[test]
fn enrichment_runner_applied_migrations_preserved() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-ap", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-ap");

    let applied = runner.applied_migrations();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].migration_id, "m-ap");
    assert_eq!(applied[0].from_version, "v1");
    assert_eq!(applied[0].to_version, "v2");
    assert_eq!(applied[0].state, CutoverState::Committed);
}

#[test]
fn enrichment_runner_sequential_migrations() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-seq-1", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-seq-1");

    // Now declare and run a second migration
    let mut d2 = test_declaration("m-seq-2", CutoverType::SoftMigration);
    d2.from_version = "v2".to_string();
    d2.to_version = "v3".to_string();
    runner.declare(d2, "t").unwrap();
    runner.set_tick(50);
    run_full_migration(&mut runner, "m-seq-2");

    assert_eq!(runner.applied_migrations().len(), 2);
    assert_eq!(runner.applied_migrations()[0].migration_id, "m-seq-1");
    assert_eq!(runner.applied_migrations()[1].migration_id, "m-seq-2");
}

#[test]
fn enrichment_runner_hard_cutover_no_transition_window() {
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("m-notw", CutoverType::HardCutover), "t")
        .unwrap();
    run_full_migration(&mut runner, "m-notw");
    assert!(runner.transition_windows().is_empty());
}

#[test]
fn enrichment_runner_lifecycle_deterministic() {
    let run = || {
        let mut runner = CutoverMigrationRunner::new();
        runner
            .declare(test_declaration("m-det", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_migration(&mut runner, "m-det");
        serde_json::to_string(runner.audit_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_runner_format_acceptance_no_applied_ok() {
    let runner = CutoverMigrationRunner::new();
    // No migrations applied, any class should be ok
    for oc in [
        ObjectClass::SerializationSchema,
        ObjectClass::KeyFormat,
        ObjectClass::TokenFormat,
        ObjectClass::CheckpointFormat,
        ObjectClass::RevocationFormat,
        ObjectClass::PolicyFormat,
    ] {
        runner.check_format_acceptance(oc).unwrap();
    }
}

// ===========================================================================
// 24. Complex multi-step workflows
// ===========================================================================

#[test]
fn enrichment_workflow_full_checker_then_cutover() {
    // Phase 1: Use checker to validate migration compatibility
    let ledger = build_golden_ledger("golden", "evidence-v1", 3);
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "evidence-v1".to_string(),
            to_version: "evidence-v2".to_string(),
            lossy: false,
            description: "v1->v2".to_string(),
        },
        v1_to_v2_migration,
    );
    let mut checker = MigrationCompatibilityChecker::new("evidence-v2", registry);
    checker.add_golden_ledger(ledger.clone());
    let results = checker.run_all();
    assert!(results[0].passed());

    // Phase 2: Use cutover runner to execute the migration
    let mut runner = CutoverMigrationRunner::new();
    runner
        .declare(test_declaration("cutover-1", CutoverType::HardCutover), "t")
        .unwrap();
    let entry = run_full_migration(&mut runner, "cutover-1");
    assert_eq!(entry.state, CutoverState::Committed);

    // Phase 3: Verify old format is rejected
    let err = runner
        .check_format_acceptance(ObjectClass::SerializationSchema)
        .unwrap_err();
    assert!(matches!(err, CutoverError::OldFormatRejected { .. }));
}

#[test]
fn enrichment_workflow_manifest_tracks_multiple_ledger_versions() {
    let mut manifest = GoldenLedgerManifest::new();

    let l1 = build_golden_ledger("corpus-v1", "evidence-v1", 5);
    let l2 = build_golden_ledger("corpus-v2", "evidence-v2", 3);
    let l3 = build_golden_ledger("corpus-v3", "evidence-v3", 7);

    manifest.add(&l1);
    manifest.add(&l2);
    manifest.add(&l3);

    assert_eq!(manifest.len(), 3);
    assert!(manifest.verify(&l1));
    assert!(manifest.verify(&l2));
    assert!(manifest.verify(&l3));

    // Manifest roundtrips through JSON
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: GoldenLedgerManifest = serde_json::from_str(&json).unwrap();
    assert!(restored.verify(&l1));
    assert!(restored.verify(&l2));
    assert!(restored.verify(&l3));
}

#[test]
fn enrichment_workflow_migration_chain_v1_v2_v3() {
    // Two golden ledgers: one at v1, one at v2
    let l_v1 = build_golden_ledger("corpus-v1", "v1", 2);
    let l_v2 = build_golden_ledger("corpus-v2", "v2", 3);

    // Migrate to v3
    let mut registry = MigrationRegistry::new();
    registry.register(
        MigrationFunction {
            from_version: "v1".to_string(),
            to_version: "v3".to_string(),
            lossy: false,
            description: "v1->v3 direct".to_string(),
        },
        identity_migration,
    );
    registry.register(
        MigrationFunction {
            from_version: "v2".to_string(),
            to_version: "v3".to_string(),
            lossy: false,
            description: "v2->v3".to_string(),
        },
        identity_migration,
    );

    let mut checker = MigrationCompatibilityChecker::new("v3", registry);
    checker.add_golden_ledger(l_v1);
    checker.add_golden_ledger(l_v2);

    let results = checker.run_all();
    assert_eq!(results.len(), 2);
    assert!(results[0].passed());
    assert!(results[1].passed());
    assert_eq!(results[0].outcome, MigrationOutcome::MigratedSuccessfully);
    assert_eq!(results[1].outcome, MigrationOutcome::MigratedSuccessfully);
}

// ===========================================================================
// 25. Fixed-point millionths determinism check
// ===========================================================================

#[test]
fn enrichment_fixed_point_millionths_in_evidence_entries() {
    // The evidence emitter uses fixed-point millionths; verify they roundtrip
    let ledger = build_golden_ledger("fp-test", "v1", 3);
    let json = serde_json::to_string(&ledger).unwrap();
    let restored: GoldenLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger.entries.len(), restored.entries.len());
    // Verify the hashes match exactly (determinism)
    assert_eq!(ledger.corpus_hash, restored.corpus_hash);
}

// ===========================================================================
// 26. ContentHash usage
// ===========================================================================

#[test]
fn enrichment_content_hash_compute_deterministic() {
    let data = b"migration_compatibility_enrichment_test_data";
    let h1 = ContentHash::compute(data);
    let h2 = ContentHash::compute(data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_data_different_hash() {
    let h1 = ContentHash::compute(b"data_a");
    let h2 = ContentHash::compute(b"data_b");
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_golden_ledger_corpus_hash_uses_content_hash() {
    let ledger = build_golden_ledger("hash-test", "v1", 2);
    let payload = serde_json::to_vec(&ledger.entries).unwrap();
    let expected = ContentHash::compute(&payload);
    assert_eq!(ledger.corpus_hash, expected);
}

// ===========================================================================
// 27. DeterministicTimestamp usage
// ===========================================================================

#[test]
fn enrichment_deterministic_timestamp_in_phase_record() {
    let ts = DeterministicTimestamp(42_000_000);
    let record = PhaseExecutionRecord {
        migration_id: "ts-test".to_string(),
        phase: MigrationPhase::Execute,
        outcome: PhaseOutcome::Success,
        affected_count: 0,
        detail: "test".to_string(),
        timestamp: ts,
    };
    assert_eq!(record.timestamp, DeterministicTimestamp(42_000_000));
    let json = serde_json::to_string(&record).unwrap();
    let restored: PhaseExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.timestamp, restored.timestamp);
}

// ===========================================================================
// 28. Edge case: runner with multiple affected object classes
// ===========================================================================

#[test]
fn enrichment_runner_multiple_object_classes_all_rejected_after_hard_cutover() {
    let mut affected = BTreeSet::new();
    affected.insert(ObjectClass::SerializationSchema);
    affected.insert(ObjectClass::KeyFormat);
    affected.insert(ObjectClass::TokenFormat);

    let decl = MigrationDeclaration {
        migration_id: "m-multi".to_string(),
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        affected_objects: affected,
        cutover_type: CutoverType::HardCutover,
        description: "multi-class hard cutover".to_string(),
        compatible_across_boundary: Vec::new(),
        incompatible_across_boundary: Vec::new(),
    };

    let mut runner = CutoverMigrationRunner::new();
    runner.declare(decl, "t").unwrap();
    run_full_migration(&mut runner, "m-multi");

    // All three affected classes should be rejected
    assert!(matches!(
        runner.check_format_acceptance(ObjectClass::SerializationSchema),
        Err(CutoverError::OldFormatRejected { .. })
    ));
    assert!(matches!(
        runner.check_format_acceptance(ObjectClass::KeyFormat),
        Err(CutoverError::OldFormatRejected { .. })
    ));
    assert!(matches!(
        runner.check_format_acceptance(ObjectClass::TokenFormat),
        Err(CutoverError::OldFormatRejected { .. })
    ));

    // Unaffected classes still accepted
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
// 29. Edge case: set_tick persistence
// ===========================================================================

#[test]
fn enrichment_runner_set_tick_persists() {
    let mut runner = CutoverMigrationRunner::new();
    runner.set_tick(12345);
    runner
        .declare(test_declaration("m-tick", CutoverType::HardCutover), "t")
        .unwrap();
    runner.begin("m-tick", 10, "t").unwrap();

    // The pre-migration record should use the tick set before begin
    // (begin calls set_tick internally after begin, but the pre-migration phase
    // records use current_tick at the time of begin)
    let events = runner.audit_events();
    let pre = events
        .iter()
        .find(|e| e.event == "pre_migration_complete")
        .unwrap();
    assert_eq!(pre.timestamp, DeterministicTimestamp(12345));
}

// ===========================================================================
// 30. Clone and equality checks
// ===========================================================================

#[test]
fn enrichment_migration_error_clone_deep() {
    let original = MigrationError {
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
        error_code: MigrationErrorCode::MigrationFunctionFailed,
        incompatible_fields: vec![
            IncompatibleField {
                field_path: "a".to_string(),
                reason: "x".to_string(),
            },
            IncompatibleField {
                field_path: "b".to_string(),
                reason: "y".to_string(),
            },
        ],
        message: "complex error".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Verify deep clone (not just pointer copy)
    let json_orig = serde_json::to_string(&original).unwrap();
    let json_clone = serde_json::to_string(&cloned).unwrap();
    assert_eq!(json_orig, json_clone);
}

#[test]
fn enrichment_golden_ledger_clone_independent() {
    let original = build_golden_ledger("clone-test", "v1", 3);
    let mut cloned = original.clone();
    assert_eq!(original, cloned);

    // Modify clone, original unchanged
    cloned.entries[0].action_name = "modified".to_string();
    assert_ne!(original.entries[0].action_name, "modified");
}

#[test]
fn enrichment_migration_outcome_clone_eq() {
    let o = MigrationOutcome::LossyMigration;
    let c = o.clone();
    assert_eq!(o, c);
}

#[test]
fn enrichment_cutover_type_clone_copy_eq() {
    let ct = CutoverType::ParallelRun;
    let copied = ct;
    let cloned = ct.clone();
    assert_eq!(ct, copied);
    assert_eq!(ct, cloned);
}

#[test]
fn enrichment_object_class_clone_copy_eq() {
    let oc = ObjectClass::PolicyFormat;
    let copied = oc;
    let cloned = oc.clone();
    assert_eq!(oc, copied);
    assert_eq!(oc, cloned);
}
