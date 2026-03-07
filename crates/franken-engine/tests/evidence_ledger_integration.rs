#![forbid(unsafe_code)]

//! Integration tests for the `evidence_ledger` module.
//!
//! Covers construction of all public types, Display impls, serde roundtrips,
//! builder ergonomics, InMemoryLedger operations (append, query, filtering,
//! duplicate rejection), deterministic hashing, error handling paths,
//! edge cases (empty inputs, boundary values), and metadata ordering.

use std::collections::BTreeMap;

use frankenengine_engine::evidence_ledger::{
    ArtifactRecord, CandidateAction, ChosenAction, Constraint, DecisionSemanticsAnnotations,
    DecisionType, EvidenceEmitter, EvidenceEntry, EvidenceEntryBuilder, EvidenceGraphEdgeKind,
    EvidenceLedgerStitchingBundle, InMemoryLedger, LedgerError, SchemaVersionExt, Witness,
    current_schema_version,
};
use frankenengine_engine::hindsight_boundary_capture::{
    BoundaryCaptureRecord, BoundaryCaptureSession, BoundaryContext,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn sample_chosen() -> ChosenAction {
    ChosenAction {
        action_name: "sandbox".to_string(),
        expected_loss_millionths: 100_000,
        rationale: "lowest expected loss within constraints".to_string(),
    }
}

fn sample_witness() -> Witness {
    Witness {
        witness_id: "obs-001".to_string(),
        witness_type: "posterior".to_string(),
        value: "0.85".to_string(),
    }
}

fn sample_constraint() -> Constraint {
    Constraint {
        constraint_id: "max-loss".to_string(),
        description: "maximum expected loss threshold".to_string(),
        active: true,
    }
}

fn sample_entry() -> EvidenceEntry {
    EvidenceEntryBuilder::new(
        "trace-001",
        "decision-001",
        "policy-v1",
        SecurityEpoch::from_raw(5),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(1_000_000)
    .candidate(CandidateAction::new("sandbox", 100_000))
    .candidate(CandidateAction::new("terminate", 500_000))
    .candidate(CandidateAction::filtered(
        "ignore",
        900_000,
        "exceeds loss budget",
    ))
    .constraint(sample_constraint())
    .chosen(sample_chosen())
    .witness(sample_witness())
    .meta("extension_id", "ext-abc")
    .build()
    .expect("build sample entry")
}

fn make_entry(
    trace: &str,
    decision: &str,
    epoch: u64,
    decision_type: DecisionType,
) -> EvidenceEntry {
    EvidenceEntryBuilder::new(
        trace,
        decision,
        "policy-v1",
        SecurityEpoch::from_raw(epoch),
        decision_type,
    )
    .chosen(ChosenAction {
        action_name: "default_action".to_string(),
        expected_loss_millionths: 0,
        rationale: "test entry".to_string(),
    })
    .build()
    .expect("build entry")
}

fn sample_boundary_records() -> Vec<BoundaryCaptureRecord> {
    let mut session = BoundaryCaptureSession::default_v1();
    let context = BoundaryContext::new(
        "trace-001",
        "decision-001",
        "policy-v1",
        "integration-orchestrator",
        128,
    );
    let scheduling = session
        .capture_scheduling_decision(&context, "hot-lane", "task-17", "digest-order", None)
        .expect("capture scheduling decision");
    let override_record = session
        .capture_controller_override(
            &context,
            "safety-router",
            "force-sandbox",
            "digest-override",
            None,
        )
        .expect("capture controller override");
    let policy = session
        .capture_external_policy_read(&context, "release_policy", "digest-policy", 11, None)
        .expect("capture policy read");
    vec![scheduling, override_record, policy]
}

// ===========================================================================
// 1. DecisionType — Display impl
// ===========================================================================

#[test]
fn decision_type_display_security_action() {
    assert_eq!(DecisionType::SecurityAction.to_string(), "security_action");
}

#[test]
fn decision_type_display_policy_update() {
    assert_eq!(DecisionType::PolicyUpdate.to_string(), "policy_update");
}

#[test]
fn decision_type_display_epoch_transition() {
    assert_eq!(
        DecisionType::EpochTransition.to_string(),
        "epoch_transition"
    );
}

#[test]
fn decision_type_display_revocation() {
    assert_eq!(DecisionType::Revocation.to_string(), "revocation");
}

#[test]
fn decision_type_display_extension_lifecycle() {
    assert_eq!(
        DecisionType::ExtensionLifecycle.to_string(),
        "extension_lifecycle"
    );
}

#[test]
fn decision_type_display_capability_decision() {
    assert_eq!(
        DecisionType::CapabilityDecision.to_string(),
        "capability_decision"
    );
}

#[test]
fn decision_type_display_contract_evaluation() {
    assert_eq!(
        DecisionType::ContractEvaluation.to_string(),
        "contract_evaluation"
    );
}

#[test]
fn decision_type_display_remote_authorization() {
    assert_eq!(
        DecisionType::RemoteAuthorization.to_string(),
        "remote_authorization"
    );
}

// ===========================================================================
// 2. DecisionType — serde roundtrip for all variants
// ===========================================================================

#[test]
fn decision_type_serde_roundtrip_all_variants() {
    let variants = [
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::EpochTransition,
        DecisionType::Revocation,
        DecisionType::ExtensionLifecycle,
        DecisionType::CapabilityDecision,
        DecisionType::ContractEvaluation,
        DecisionType::RemoteAuthorization,
    ];
    for dt in &variants {
        let json = serde_json::to_string(dt).expect("serialize DecisionType");
        let restored: DecisionType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*dt, restored);
    }
}

// ===========================================================================
// 3. CandidateAction — construction and serde
// ===========================================================================

#[test]
fn candidate_action_new_is_unfiltered() {
    let c = CandidateAction::new("allow", 50_000);
    assert_eq!(c.action_name, "allow");
    assert_eq!(c.expected_loss_millionths, 50_000);
    assert!(!c.filtered);
    assert!(c.filter_reason.is_none());
}

#[test]
fn candidate_action_filtered_constructor() {
    let c = CandidateAction::filtered("terminate", 999_000, "policy forbids");
    assert_eq!(c.action_name, "terminate");
    assert_eq!(c.expected_loss_millionths, 999_000);
    assert!(c.filtered);
    assert_eq!(c.filter_reason.as_deref(), Some("policy forbids"));
}

#[test]
fn candidate_action_serde_roundtrip_unfiltered() {
    let c = CandidateAction::new("sandbox", 200_000);
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: CandidateAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

#[test]
fn candidate_action_serde_roundtrip_filtered() {
    let c = CandidateAction::filtered("quarantine", 750_000, "exceeds threshold");
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: CandidateAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

#[test]
fn candidate_action_zero_loss() {
    let c = CandidateAction::new("noop", 0);
    assert_eq!(c.expected_loss_millionths, 0);
}

#[test]
fn candidate_action_negative_loss() {
    let c = CandidateAction::new("reward", -500_000);
    assert_eq!(c.expected_loss_millionths, -500_000);
}

// ===========================================================================
// 4. Constraint — construction and serde
// ===========================================================================

#[test]
fn constraint_construction() {
    let c = Constraint {
        constraint_id: "rate-limit".to_string(),
        description: "max 10 requests per second".to_string(),
        active: false,
    };
    assert_eq!(c.constraint_id, "rate-limit");
    assert!(!c.active);
}

#[test]
fn constraint_serde_roundtrip() {
    let c = sample_constraint();
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: Constraint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

// ===========================================================================
// 5. Witness — construction and serde
// ===========================================================================

#[test]
fn witness_construction() {
    let w = Witness {
        witness_id: "sensor-42".to_string(),
        witness_type: "temperature".to_string(),
        value: "72500000".to_string(),
    };
    assert_eq!(w.witness_id, "sensor-42");
    assert_eq!(w.witness_type, "temperature");
}

#[test]
fn witness_serde_roundtrip() {
    let w = sample_witness();
    let json = serde_json::to_string(&w).expect("serialize");
    let restored: Witness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(w, restored);
}

// ===========================================================================
// 6. ChosenAction — construction and serde
// ===========================================================================

#[test]
fn chosen_action_construction() {
    let ca = sample_chosen();
    assert_eq!(ca.action_name, "sandbox");
    assert_eq!(ca.expected_loss_millionths, 100_000);
    assert!(!ca.rationale.is_empty());
}

#[test]
fn chosen_action_serde_roundtrip() {
    let ca = sample_chosen();
    let json = serde_json::to_string(&ca).expect("serialize");
    let restored: ChosenAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ca, restored);
}

// ===========================================================================
// 7. SchemaVersion — current version and compatibility
// ===========================================================================

#[test]
fn current_schema_version_is_1_0_0() {
    let v = current_schema_version();
    assert_eq!(v.major_val(), 1);
    assert_eq!(v.minor_val(), 0);
    assert_eq!(v.to_string(), "1.0.0");
}

#[test]
fn schema_version_serde_roundtrip() {
    let v = current_schema_version();
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: frankenengine_engine::control_plane::SchemaVersion =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

#[test]
fn schema_version_same_major_same_minor_compatible() {
    let v1_0 = frankenengine_engine::control_plane::SchemaVersion::new(1, 0, 0);
    assert!(v1_0.is_compatible_with(&v1_0));
}

#[test]
fn schema_version_same_major_lower_minor_compatible() {
    let v1_0 = frankenengine_engine::control_plane::SchemaVersion::new(1, 0, 0);
    let v1_1 = frankenengine_engine::control_plane::SchemaVersion::new(1, 1, 0);
    // v1.0 entry is compatible with v1.1 reader
    assert!(v1_0.is_compatible_with(&v1_1));
}

#[test]
fn schema_version_same_major_higher_minor_incompatible() {
    let v1_0 = frankenengine_engine::control_plane::SchemaVersion::new(1, 0, 0);
    let v1_1 = frankenengine_engine::control_plane::SchemaVersion::new(1, 1, 0);
    // v1.1 entry NOT compatible with v1.0 reader
    assert!(!v1_1.is_compatible_with(&v1_0));
}

#[test]
fn schema_version_different_major_incompatible() {
    let v1_0 = frankenengine_engine::control_plane::SchemaVersion::new(1, 0, 0);
    let v2_0 = frankenengine_engine::control_plane::SchemaVersion::new(2, 0, 0);
    assert!(!v1_0.is_compatible_with(&v2_0));
    assert!(!v2_0.is_compatible_with(&v1_0));
}

// ===========================================================================
// 8. EvidenceEntryBuilder — building entries
// ===========================================================================

#[test]
fn builder_produces_valid_entry_with_all_fields() {
    let entry = sample_entry();
    assert_eq!(entry.schema_version, current_schema_version());
    assert!(entry.entry_id.starts_with("ev-"));
    assert_eq!(entry.trace_id, "trace-001");
    assert_eq!(entry.decision_id, "decision-001");
    assert_eq!(entry.policy_id, "policy-v1");
    assert_eq!(entry.epoch_id, SecurityEpoch::from_raw(5));
    assert_eq!(entry.timestamp_ns, 1_000_000);
    assert_eq!(entry.decision_type, DecisionType::SecurityAction);
    assert_eq!(entry.candidates.len(), 3);
    assert_eq!(entry.constraints.len(), 1);
    assert_eq!(entry.chosen_action.action_name, "sandbox");
    assert_eq!(entry.witnesses.len(), 1);
    assert!(!entry.evidence_hash.is_empty());
    assert_eq!(entry.metadata["extension_id"], "ext-abc");
}

#[test]
fn builder_minimal_entry() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::PolicyUpdate,
    )
    .chosen(ChosenAction {
        action_name: "rotate".to_string(),
        expected_loss_millionths: 0,
        rationale: "scheduled".to_string(),
    })
    .build()
    .expect("build minimal entry");

    assert!(entry.entry_id.starts_with("ev-"));
    assert_eq!(entry.trace_id, "t");
    assert_eq!(entry.candidates.len(), 0);
    assert_eq!(entry.constraints.len(), 0);
    assert_eq!(entry.witnesses.len(), 0);
    assert!(entry.metadata.is_empty());
    assert_eq!(entry.timestamp_ns, 0);
}

#[test]
fn builder_missing_chosen_action_returns_error() {
    let result = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::PolicyUpdate,
    )
    .build();
    assert_eq!(result.unwrap_err(), LedgerError::MissingChosenAction);
}

#[test]
fn builder_timestamp_ns_is_set() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::Revocation,
    )
    .timestamp_ns(999_999_999)
    .chosen(ChosenAction {
        action_name: "revoke".to_string(),
        expected_loss_millionths: 0,
        rationale: "test".to_string(),
    })
    .build()
    .expect("build");

    assert_eq!(entry.timestamp_ns, 999_999_999);
}

#[test]
fn builder_multiple_metadata_keys_preserved() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::CapabilityDecision,
    )
    .meta("key_a", "value_a")
    .meta("key_b", "value_b")
    .meta("key_c", "value_c")
    .chosen(ChosenAction {
        action_name: "grant".to_string(),
        expected_loss_millionths: 0,
        rationale: "test".to_string(),
    })
    .build()
    .expect("build");

    assert_eq!(entry.metadata.len(), 3);
    assert_eq!(entry.metadata["key_a"], "value_a");
    assert_eq!(entry.metadata["key_b"], "value_b");
    assert_eq!(entry.metadata["key_c"], "value_c");
}

#[test]
fn builder_metadata_btreemap_is_deterministic_order() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .meta("zebra", "1")
    .meta("alpha", "2")
    .meta("mango", "3")
    .chosen(sample_chosen())
    .build()
    .expect("build");

    let keys: Vec<&String> = entry.metadata.keys().collect();
    assert_eq!(keys, vec!["alpha", "mango", "zebra"]);
}

#[test]
fn builder_multiple_witnesses() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .witness(Witness {
        witness_id: "w1".to_string(),
        witness_type: "sensor".to_string(),
        value: "100".to_string(),
    })
    .witness(Witness {
        witness_id: "w2".to_string(),
        witness_type: "posterior".to_string(),
        value: "0.75".to_string(),
    })
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_eq!(entry.witnesses.len(), 2);
    assert_eq!(entry.witnesses[0].witness_id, "w1");
    assert_eq!(entry.witnesses[1].witness_id, "w2");
}

#[test]
fn builder_multiple_constraints() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .constraint(Constraint {
        constraint_id: "c1".to_string(),
        description: "first".to_string(),
        active: true,
    })
    .constraint(Constraint {
        constraint_id: "c2".to_string(),
        description: "second".to_string(),
        active: false,
    })
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_eq!(entry.constraints.len(), 2);
    assert!(entry.constraints[0].active);
    assert!(!entry.constraints[1].active);
}

// ===========================================================================
// 9. Deterministic hashing
// ===========================================================================

#[test]
fn entry_id_and_hash_are_deterministic_across_calls() {
    let e1 = sample_entry();
    let e2 = sample_entry();
    assert_eq!(e1.entry_id, e2.entry_id);
    assert_eq!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn different_entries_produce_different_hashes() {
    let e1 = make_entry("trace-a", "dec-a", 1, DecisionType::SecurityAction);
    let e2 = make_entry("trace-b", "dec-b", 2, DecisionType::PolicyUpdate);
    assert_ne!(e1.entry_id, e2.entry_id);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn entry_id_has_ev_prefix_and_16_char_hash_suffix() {
    let entry = sample_entry();
    assert!(entry.entry_id.starts_with("ev-"));
    // "ev-" (3 chars) + 16 hex chars = 19 chars total
    assert_eq!(entry.entry_id.len(), 19);
}

#[test]
fn evidence_hash_is_16_hex_digits() {
    let entry = sample_entry();
    assert_eq!(entry.evidence_hash.len(), 16);
    assert!(entry.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn changing_metadata_changes_hash() {
    let e1 = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .meta("key", "value_a")
    .chosen(sample_chosen())
    .build()
    .expect("build");

    let e2 = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .meta("key", "value_b")
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn changing_epoch_changes_hash() {
    let e1 = make_entry("t", "d", 1, DecisionType::SecurityAction);
    let e2 = make_entry("t", "d", 2, DecisionType::SecurityAction);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn changing_decision_type_changes_hash() {
    let e1 = make_entry("t", "d", 1, DecisionType::SecurityAction);
    let e2 = make_entry("t", "d", 1, DecisionType::PolicyUpdate);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

// ===========================================================================
// 10. EvidenceEntry — serde roundtrip
// ===========================================================================

#[test]
fn evidence_entry_serde_roundtrip() {
    let entry = sample_entry();
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn evidence_entry_deterministic_serialization() {
    let entry = sample_entry();
    let json1 = serde_json::to_string(&entry).expect("serialize 1");
    let json2 = serde_json::to_string(&entry).expect("serialize 2");
    assert_eq!(json1, json2);
}

#[test]
fn evidence_entry_pretty_json_roundtrip() {
    let entry = sample_entry();
    let json = serde_json::to_string_pretty(&entry).expect("serialize pretty");
    let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn evidence_entry_clone_equality() {
    let entry = sample_entry();
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ===========================================================================
// 11. LedgerError — display and serde
// ===========================================================================

#[test]
fn ledger_error_missing_chosen_action_display() {
    let err = LedgerError::MissingChosenAction;
    assert_eq!(err.to_string(), "chosen action is required");
}

#[test]
fn ledger_error_schema_validation_failed_display() {
    let err = LedgerError::SchemaValidationFailed {
        reason: "field X missing".to_string(),
    };
    assert_eq!(err.to_string(), "schema validation failed: field X missing");
}

#[test]
fn ledger_error_incompatible_schema_display() {
    let err = LedgerError::IncompatibleSchema {
        entry_version: frankenengine_engine::control_plane::SchemaVersion::new(2, 0, 0),
        reader_version: current_schema_version(),
    };
    assert_eq!(
        err.to_string(),
        "incompatible schema: entry 2.0.0, reader 1.0.0"
    );
}

#[test]
fn ledger_error_duplicate_entry_id_display() {
    let err = LedgerError::DuplicateEntryId {
        entry_id: "ev-abc123".to_string(),
    };
    assert_eq!(err.to_string(), "duplicate entry id: ev-abc123");
}

#[test]
fn ledger_error_serde_roundtrip_all_variants() {
    let errors = vec![
        LedgerError::MissingChosenAction,
        LedgerError::SchemaValidationFailed {
            reason: "test reason".to_string(),
        },
        LedgerError::IncompatibleSchema {
            entry_version: frankenengine_engine::control_plane::SchemaVersion::new(2, 1, 0),
            reader_version: current_schema_version(),
        },
        LedgerError::DuplicateEntryId {
            entry_id: "ev-test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: LedgerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn ledger_error_implements_std_error() {
    let err = LedgerError::MissingChosenAction;
    // Verify it implements std::error::Error by calling source()
    let _source: Option<&dyn std::error::Error> = std::error::Error::source(&err);
}

// ===========================================================================
// 12. InMemoryLedger — basic operations
// ===========================================================================

#[test]
fn in_memory_ledger_default_is_empty() {
    let ledger = InMemoryLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert!(ledger.entries().is_empty());
}

#[test]
fn in_memory_ledger_emit_increments_len() {
    let mut ledger = InMemoryLedger::new();
    ledger.emit(sample_entry()).expect("emit");
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.is_empty());
}

#[test]
fn in_memory_ledger_entries_preserves_insertion_order() {
    let mut ledger = InMemoryLedger::new();

    let e1 = make_entry("trace-1", "dec-1", 1, DecisionType::SecurityAction);
    let e2 = make_entry("trace-2", "dec-2", 2, DecisionType::PolicyUpdate);
    let e3 = make_entry("trace-3", "dec-3", 3, DecisionType::Revocation);

    ledger.emit(e1.clone()).expect("emit 1");
    ledger.emit(e2.clone()).expect("emit 2");
    ledger.emit(e3.clone()).expect("emit 3");

    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.entries()[0].trace_id, "trace-1");
    assert_eq!(ledger.entries()[1].trace_id, "trace-2");
    assert_eq!(ledger.entries()[2].trace_id, "trace-3");
}

#[test]
fn in_memory_ledger_rejects_duplicate_entry_id() {
    let mut ledger = InMemoryLedger::new();
    let entry = sample_entry();
    ledger.emit(entry.clone()).expect("first emit");

    let err = ledger.emit(entry.clone()).unwrap_err();
    if let LedgerError::DuplicateEntryId { entry_id } = &err {
        assert_eq!(*entry_id, entry.entry_id);
    } else {
        panic!("expected DuplicateEntryId, got: {err:?}");
    }
}

#[test]
fn in_memory_ledger_accepts_distinct_entries() {
    let mut ledger = InMemoryLedger::new();
    for i in 0..10 {
        let entry = make_entry(
            &format!("trace-{i}"),
            &format!("dec-{i}"),
            i,
            DecisionType::SecurityAction,
        );
        ledger.emit(entry).expect("emit");
    }
    assert_eq!(ledger.len(), 10);
}

// ===========================================================================
// 13. InMemoryLedger — query by decision type
// ===========================================================================

#[test]
fn by_decision_type_filters_correctly() {
    let mut ledger = InMemoryLedger::new();

    ledger
        .emit(make_entry("t1", "d1", 1, DecisionType::SecurityAction))
        .expect("emit");
    ledger
        .emit(make_entry("t2", "d2", 2, DecisionType::PolicyUpdate))
        .expect("emit");
    ledger
        .emit(make_entry("t3", "d3", 3, DecisionType::SecurityAction))
        .expect("emit");
    ledger
        .emit(make_entry("t4", "d4", 4, DecisionType::Revocation))
        .expect("emit");

    let security = ledger.by_decision_type(DecisionType::SecurityAction);
    assert_eq!(security.len(), 2);

    let policy = ledger.by_decision_type(DecisionType::PolicyUpdate);
    assert_eq!(policy.len(), 1);

    let revocation = ledger.by_decision_type(DecisionType::Revocation);
    assert_eq!(revocation.len(), 1);

    let lifecycle = ledger.by_decision_type(DecisionType::ExtensionLifecycle);
    assert!(lifecycle.is_empty());
}

#[test]
fn by_decision_type_on_empty_ledger_returns_empty() {
    let ledger = InMemoryLedger::new();
    assert!(
        ledger
            .by_decision_type(DecisionType::SecurityAction)
            .is_empty()
    );
}

// ===========================================================================
// 14. InMemoryLedger — query by epoch
// ===========================================================================

#[test]
fn by_epoch_filters_correctly() {
    let mut ledger = InMemoryLedger::new();

    ledger
        .emit(make_entry("t1", "d1", 5, DecisionType::SecurityAction))
        .expect("emit");
    ledger
        .emit(make_entry("t2", "d2", 5, DecisionType::PolicyUpdate))
        .expect("emit");
    ledger
        .emit(make_entry("t3", "d3", 10, DecisionType::Revocation))
        .expect("emit");

    let epoch5 = ledger.by_epoch(SecurityEpoch::from_raw(5));
    assert_eq!(epoch5.len(), 2);

    let epoch10 = ledger.by_epoch(SecurityEpoch::from_raw(10));
    assert_eq!(epoch10.len(), 1);

    let epoch0 = ledger.by_epoch(SecurityEpoch::GENESIS);
    assert!(epoch0.is_empty());
}

#[test]
fn by_epoch_on_empty_ledger_returns_empty() {
    let ledger = InMemoryLedger::new();
    assert!(ledger.by_epoch(SecurityEpoch::from_raw(99)).is_empty());
}

// ===========================================================================
// 15. Edge cases — empty strings, boundary epoch values
// ===========================================================================

#[test]
fn builder_accepts_empty_string_fields() {
    let entry = EvidenceEntryBuilder::new(
        "",
        "",
        "",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .chosen(ChosenAction {
        action_name: String::new(),
        expected_loss_millionths: 0,
        rationale: String::new(),
    })
    .build()
    .expect("build with empty strings");

    assert_eq!(entry.trace_id, "");
    assert_eq!(entry.decision_id, "");
    assert!(entry.entry_id.starts_with("ev-"));
}

#[test]
fn builder_with_genesis_epoch() {
    let entry = make_entry("t", "d", 0, DecisionType::SecurityAction);
    assert_eq!(entry.epoch_id, SecurityEpoch::GENESIS);
}

#[test]
fn builder_with_max_epoch() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::from_raw(u64::MAX),
        DecisionType::EpochTransition,
    )
    .chosen(ChosenAction {
        action_name: "transition".to_string(),
        expected_loss_millionths: 0,
        rationale: "max epoch".to_string(),
    })
    .build()
    .expect("build");

    assert_eq!(entry.epoch_id.as_u64(), u64::MAX);
}

#[test]
fn builder_with_max_timestamp_ns() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .timestamp_ns(u64::MAX)
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_eq!(entry.timestamp_ns, u64::MAX);
}

#[test]
fn builder_with_extreme_loss_values() {
    let c_max = CandidateAction::new("max", i64::MAX);
    let c_min = CandidateAction::new("min", i64::MIN);

    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .candidate(c_max)
    .candidate(c_min)
    .chosen(ChosenAction {
        action_name: "extreme".to_string(),
        expected_loss_millionths: i64::MAX,
        rationale: "test".to_string(),
    })
    .build()
    .expect("build");

    assert_eq!(entry.candidates[0].expected_loss_millionths, i64::MAX);
    assert_eq!(entry.candidates[1].expected_loss_millionths, i64::MIN);
}

// ===========================================================================
// 16. Large ledger stress
// ===========================================================================

#[test]
fn ledger_handles_100_entries() {
    let mut ledger = InMemoryLedger::new();
    for i in 0_u64..100 {
        let decision_type = match i % 4 {
            0 => DecisionType::SecurityAction,
            1 => DecisionType::PolicyUpdate,
            2 => DecisionType::Revocation,
            _ => DecisionType::EpochTransition,
        };
        let entry = make_entry(
            &format!("trace-{i}"),
            &format!("dec-{i}"),
            i / 10,
            decision_type,
        );
        ledger.emit(entry).expect("emit");
    }
    assert_eq!(ledger.len(), 100);

    // Verify filtering works on larger datasets
    let security = ledger.by_decision_type(DecisionType::SecurityAction);
    assert_eq!(security.len(), 25);

    let epoch_0 = ledger.by_epoch(SecurityEpoch::GENESIS);
    assert_eq!(epoch_0.len(), 10);
}

// ===========================================================================
// 17. All decision type variants produce unique entries
// ===========================================================================

#[test]
fn all_decision_type_variants_create_distinct_entries() {
    let variants = [
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::EpochTransition,
        DecisionType::Revocation,
        DecisionType::ExtensionLifecycle,
        DecisionType::CapabilityDecision,
        DecisionType::ContractEvaluation,
        DecisionType::RemoteAuthorization,
    ];

    let mut ledger = InMemoryLedger::new();
    for (i, dt) in variants.iter().enumerate() {
        let entry = make_entry(&format!("trace-{i}"), &format!("dec-{i}"), i as u64, *dt);
        ledger.emit(entry).expect("emit");
    }
    assert_eq!(ledger.len(), 8);

    // Each decision type query returns exactly 1
    for dt in &variants {
        let results = ledger.by_decision_type(*dt);
        assert_eq!(results.len(), 1, "expected 1 entry for {dt}");
    }
}

// ===========================================================================
// 18. Metadata edge cases
// ===========================================================================

#[test]
fn metadata_key_overwrite_keeps_last_value() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .meta("key", "first")
    .meta("key", "second")
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_eq!(entry.metadata.len(), 1);
    assert_eq!(entry.metadata["key"], "second");
}

#[test]
fn metadata_empty_key_and_value() {
    let entry = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    )
    .meta("", "")
    .chosen(sample_chosen())
    .build()
    .expect("build");

    assert_eq!(entry.metadata.len(), 1);
    assert_eq!(entry.metadata[""], "");
}

// ===========================================================================
// 19. DecisionType ordering
// ===========================================================================

#[test]
fn decision_type_ord_is_defined() {
    // DecisionType derives Ord; verify that ordering is consistent.
    let mut types = vec![
        DecisionType::RemoteAuthorization,
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::ContractEvaluation,
    ];
    types.sort();
    // Verify sort is deterministic by sorting again
    let mut types2 = types.clone();
    types2.sort();
    assert_eq!(types, types2);
}

// ===========================================================================
// 20. InMemoryLedger — Debug impl
// ===========================================================================

#[test]
fn in_memory_ledger_debug_impl() {
    let ledger = InMemoryLedger::new();
    let debug_str = format!("{ledger:?}");
    assert!(debug_str.contains("InMemoryLedger"));
}

// ===========================================================================
// 21. EvidenceEntryBuilder — Debug impl
// ===========================================================================

#[test]
fn evidence_entry_builder_debug_impl() {
    let builder = EvidenceEntryBuilder::new(
        "t",
        "d",
        "p",
        SecurityEpoch::GENESIS,
        DecisionType::SecurityAction,
    );
    let debug_str = format!("{builder:?}");
    assert!(debug_str.contains("EvidenceEntryBuilder"));
}

// ===========================================================================
// 22. Combined query: filter by epoch then type
// ===========================================================================

#[test]
fn combined_epoch_and_type_filtering() {
    let mut ledger = InMemoryLedger::new();

    // Epoch 1: SecurityAction + PolicyUpdate
    ledger
        .emit(make_entry("t1", "d1", 1, DecisionType::SecurityAction))
        .expect("emit");
    ledger
        .emit(make_entry("t2", "d2", 1, DecisionType::PolicyUpdate))
        .expect("emit");
    // Epoch 2: SecurityAction
    ledger
        .emit(make_entry("t3", "d3", 2, DecisionType::SecurityAction))
        .expect("emit");

    let epoch1 = ledger.by_epoch(SecurityEpoch::from_raw(1));
    assert_eq!(epoch1.len(), 2);

    // Manual intersection: epoch 1 + SecurityAction
    let epoch1_security: Vec<_> = epoch1
        .iter()
        .filter(|e| e.decision_type == DecisionType::SecurityAction)
        .collect();
    assert_eq!(epoch1_security.len(), 1);
    assert_eq!(epoch1_security[0].trace_id, "t1");
}

// ===========================================================================
// 23. LedgerError equality
// ===========================================================================

#[test]
fn ledger_error_equality() {
    let e1 = LedgerError::MissingChosenAction;
    let e2 = LedgerError::MissingChosenAction;
    assert_eq!(e1, e2);

    let e3 = LedgerError::DuplicateEntryId {
        entry_id: "a".to_string(),
    };
    let e4 = LedgerError::DuplicateEntryId {
        entry_id: "b".to_string(),
    };
    assert_ne!(e3, e4);
}

// ===========================================================================
// 24. Entry fields are accessible after building
// ===========================================================================

#[test]
fn entry_schema_version_matches_current() {
    let entry = sample_entry();
    assert_eq!(entry.schema_version.major, 1);
    assert_eq!(entry.schema_version.minor, 0);
}

// ===========================================================================
// 25. Serde roundtrip for entry with all optional fields populated
// ===========================================================================

#[test]
fn serde_roundtrip_fully_populated_entry() {
    let mut metadata = BTreeMap::new();
    metadata.insert("region".to_string(), "us-east-1".to_string());
    metadata.insert("severity".to_string(), "high".to_string());

    let entry = EvidenceEntryBuilder::new(
        "trace-full",
        "decision-full",
        "policy-full",
        SecurityEpoch::from_raw(42),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(12_345_678)
    .candidate(CandidateAction::new("allow", 10_000))
    .candidate(CandidateAction::filtered("deny", 800_000, "too risky"))
    .constraint(Constraint {
        constraint_id: "budget-limit".to_string(),
        description: "max budget per decision".to_string(),
        active: true,
    })
    .constraint(Constraint {
        constraint_id: "rate-limit".to_string(),
        description: "max decisions per second".to_string(),
        active: false,
    })
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 10_000,
        rationale: "within budget and rate limit".to_string(),
    })
    .witness(Witness {
        witness_id: "obs-1".to_string(),
        witness_type: "bayesian_posterior".to_string(),
        value: "950000".to_string(),
    })
    .witness(Witness {
        witness_id: "obs-2".to_string(),
        witness_type: "sensor_reading".to_string(),
        value: "37".to_string(),
    })
    .meta("region", "us-east-1")
    .meta("severity", "high")
    .build()
    .expect("build fully populated entry");

    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
    assert_eq!(restored.candidates.len(), 2);
    assert_eq!(restored.constraints.len(), 2);
    assert_eq!(restored.witnesses.len(), 2);
    assert_eq!(restored.metadata.len(), 2);
}

// ===========================================================================
// 26. Evidence-ledger stitching bundle integration
// ===========================================================================

#[test]
fn stitching_bundle_supports_controller_benchmark_support_and_release_queries() {
    let entry = sample_entry();
    let boundaries = sample_boundary_records();
    let artifacts = vec![
        ArtifactRecord::new(
            "benchmark-snapshot",
            "benchmark_manifest",
            "artifacts/benchmark-snapshot.json",
            "hash-benchmark",
        )
        .supporting_boundary(boundaries[0].correlation_key.clone()),
        ArtifactRecord::new(
            "release-gate",
            "release_gate_report",
            "artifacts/release-gate.json",
            "hash-release",
        )
        .supporting_boundary(boundaries[2].correlation_key.clone()),
        ArtifactRecord::new(
            "support-export",
            "support_bundle",
            "artifacts/support-export.json",
            "hash-support",
        ),
    ];
    let annotations = DecisionSemanticsAnnotations {
        confidence_tier: Some("high".to_string()),
        fallback_reason: Some("safe-mode-ready".to_string()),
        regret_summary: Some("expected_regret<=1000".to_string()),
        scope_limits: vec![
            "controller=safety-router".to_string(),
            "release=report-only".to_string(),
        ],
        assumptions: BTreeMap::from([
            ("benchmark_profile".to_string(), "p95".to_string()),
            ("support_visibility".to_string(), "operator".to_string()),
        ]),
        linked_boundary_correlation_keys: boundaries
            .iter()
            .map(|boundary| boundary.correlation_key.clone())
            .collect(),
    };

    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
            .expect("stitching bundle");

    assert_eq!(bundle.decision_semantics_log.len(), 1);
    assert_eq!(bundle.artifact_lineage_index.len(), 3);
    assert_eq!(bundle.evidence_ledger_graph.nodes.len(), 7);
    assert_eq!(
        bundle
            .evidence_ledger_graph
            .edges
            .iter()
            .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundaryInformsDecision)
            .count(),
        3
    );
    assert_eq!(
        bundle
            .evidence_ledger_graph
            .edges
            .iter()
            .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::DecisionProducesArtifact)
            .count(),
        3
    );
    assert_eq!(
        bundle
            .evidence_ledger_graph
            .edges
            .iter()
            .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundarySupportsArtifact)
            .count(),
        5
    );

    let semantics = &bundle.decision_semantics_log[0];
    assert_eq!(semantics.boundary_correlation_keys.len(), 3);
    assert_eq!(semantics.confidence_tier.as_deref(), Some("high"));
    assert_eq!(
        semantics.fallback_reason.as_deref(),
        Some("safe-mode-ready")
    );
    assert_eq!(semantics.assumptions["benchmark_profile"], "p95");

    let benchmark_lineage = bundle
        .artifact_lineage_index
        .iter()
        .find(|artifact| artifact.artifact_id == "benchmark-snapshot")
        .expect("benchmark lineage");
    assert_eq!(benchmark_lineage.boundary_correlation_keys.len(), 1);
    assert_eq!(
        benchmark_lineage.boundary_correlation_keys[0],
        boundaries[0].correlation_key
    );

    let support_lineage = bundle
        .artifact_lineage_index
        .iter()
        .find(|artifact| artifact.artifact_id == "support-export")
        .expect("support lineage");
    assert_eq!(support_lineage.boundary_correlation_keys.len(), 3);

    let query = bundle
        .evidence_query_surface_snapshot
        .by_decision("decision-001")
        .expect("query record");
    assert_eq!(query.boundary_correlation_keys.len(), 3);
    assert_eq!(
        query.artifact_ids,
        vec!["benchmark-snapshot", "release-gate", "support-export"]
    );
    assert_eq!(query.confidence_tier.as_deref(), Some("high"));
    assert_eq!(query.fallback_reason.as_deref(), Some("safe-mode-ready"));
}

#[test]
fn stitching_bundle_rejects_artifact_boundary_gap() {
    let entry = sample_entry();
    let boundaries = sample_boundary_records();
    let artifacts = vec![
        ArtifactRecord::new(
            "support-export",
            "support_bundle",
            "artifacts/support-export.json",
            "hash-support",
        )
        .supporting_boundary("bcorr_missing"),
    ];

    let err = EvidenceLedgerStitchingBundle::stitch(
        &entry,
        &boundaries,
        &artifacts,
        DecisionSemanticsAnnotations::default(),
    )
    .unwrap_err();

    assert_eq!(
        err,
        LedgerError::SchemaValidationFailed {
            reason: "support-export references missing boundary correlation key: bcorr_missing"
                .to_string(),
        }
    );
}
