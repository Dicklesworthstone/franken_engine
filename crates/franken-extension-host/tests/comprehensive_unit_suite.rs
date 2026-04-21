//! Comprehensive unit test suite for the franken-extension-host crate.
//!
//! bd-2yc1: Covers all major public APIs with emphasis on edge cases,
//! error variants, lattice operations, and decision contract chains.

use std::collections::BTreeSet;

use frankenengine_extension_host::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn valid_manifest() -> ExtensionManifest {
    ExtensionManifest {
        name: "test-extension".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "main.js".to_string(),
        capabilities: BTreeSet::from([Capability::FsRead]),
        publisher_signature: None,
        content_hash: [0u8; 32],
        trust_chain_ref: None,
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    }
}

fn signed_manifest() -> ExtensionManifest {
    ExtensionManifest {
        publisher_signature: Some(vec![1, 2, 3, 4]),
        trust_chain_ref: Some("chain-ref-1".to_string()),
        ..valid_manifest()
    }
}

fn lifecycle_ctx<'a>() -> LifecycleContext<'a> {
    LifecycleContext::new("trace-01", "decision-01", "policy-01")
}

/// Helper: create a lifecycle manager with a validated manifest already set
/// (required before any transition past Validate).
fn manager_with_manifest(
    ext_id: &str,
    budget: ResourceBudget,
    policy: BudgetExhaustionPolicy,
) -> ExtensionLifecycleManager {
    let mut mgr =
        ExtensionLifecycleManager::new(ext_id, budget, policy, CancellationConfig::default());
    mgr.set_validated_manifest(valid_manifest())
        .expect("manifest should validate");
    mgr
}

fn flow_ctx<'a>() -> FlowEnforcementContext<'a> {
    FlowEnforcementContext::new("trace-01", "decision-01", "policy-01")
}

fn manifest_ctx<'a>() -> ManifestValidationContext<'a> {
    ManifestValidationContext::new("trace-01", "decision-01", "policy-01", "ext-01")
}

// ---------------------------------------------------------------------------
// Manifest Validation — Error Variants
// ---------------------------------------------------------------------------

#[test]
fn manifest_empty_name_rejected() {
    let m = ExtensionManifest {
        name: String::new(),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(err, ManifestValidationError::EmptyName));
    assert!(!err.error_code().is_empty());
}

#[test]
fn manifest_empty_version_rejected() {
    let m = ExtensionManifest {
        version: String::new(),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(err, ManifestValidationError::EmptyVersion));
}

#[test]
fn manifest_empty_entrypoint_rejected() {
    let m = ExtensionManifest {
        entrypoint: String::new(),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(err, ManifestValidationError::EmptyEntrypoint));
}

#[test]
fn manifest_unsupported_engine_version() {
    let m = ExtensionManifest {
        min_engine_version: "999.0.0".to_string(),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::UnsupportedEngineVersion { .. }
    ));
}

#[test]
fn manifest_name_too_long() {
    let m = ExtensionManifest {
        name: "x".repeat(MAX_NAME_LEN + 1),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::FieldTooLong { field: "name", .. }
    ));
}

#[test]
fn manifest_version_too_long() {
    let m = ExtensionManifest {
        version: "v".repeat(MAX_VERSION_LEN + 1),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::FieldTooLong {
            field: "version",
            ..
        }
    ));
}

#[test]
fn manifest_entrypoint_too_long() {
    let m = ExtensionManifest {
        entrypoint: "e".repeat(MAX_ENTRYPOINT_LEN + 1),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::FieldTooLong {
            field: "entrypoint",
            ..
        }
    ));
}

#[test]
fn manifest_trust_chain_ref_too_long() {
    let m = ExtensionManifest {
        trust_chain_ref: Some("t".repeat(MAX_TRUST_CHAIN_REF_LEN + 1)),
        ..valid_manifest()
    };
    let err = validate_manifest(&m).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::FieldTooLong {
            field: "trust_chain_ref",
            ..
        }
    ));
}

#[test]
fn manifest_valid_passes() {
    let m = valid_manifest();
    assert!(validate_manifest(&m).is_ok());
}

// ---------------------------------------------------------------------------
// Capability Lattice Validation
// ---------------------------------------------------------------------------

#[test]
fn capability_lattice_fs_write_requires_fs_read() {
    let caps = BTreeSet::from([Capability::FsWrite]);
    let err = validate_capability_lattice(&caps).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::InvalidCapabilityLattice {
            declared: Capability::FsWrite,
            missing_implied: Capability::FsRead,
        }
    ));
}

#[test]
fn capability_lattice_fs_write_with_fs_read_ok() {
    let caps = BTreeSet::from([Capability::FsWrite, Capability::FsRead]);
    assert!(validate_capability_lattice(&caps).is_ok());
}

#[test]
fn capability_lattice_empty_ok() {
    let caps = BTreeSet::new();
    assert!(validate_capability_lattice(&caps).is_ok());
}

#[test]
fn capability_as_str_all_variants() {
    let variants = [
        Capability::FsRead,
        Capability::FsWrite,
        Capability::NetClient,
        Capability::HostCall,
        Capability::ProcessSpawn,
        Capability::Declassify,
    ];
    let mut labels = BTreeSet::new();
    for cap in &variants {
        let label = cap.as_str();
        assert!(!label.is_empty());
        labels.insert(label);
    }
    assert_eq!(labels.len(), 6, "all capability labels must be unique");
}

// ---------------------------------------------------------------------------
// Trust Level & Provenance
// ---------------------------------------------------------------------------

#[test]
fn manifest_development_trust_no_signature() {
    let m = valid_manifest();
    assert_eq!(m.inferred_trust_level(), ManifestTrustLevel::Development);
}

#[test]
fn manifest_signed_supply_chain_trust() {
    let m = signed_manifest();
    assert_eq!(
        m.inferred_trust_level(),
        ManifestTrustLevel::SignedSupplyChain
    );
}

#[test]
fn provenance_signed_requires_signature() {
    let m = ExtensionManifest {
        publisher_signature: None,
        ..valid_manifest()
    };
    let err = validate_provenance(&m, ManifestTrustLevel::SignedSupplyChain).unwrap_err();
    assert!(matches!(
        err,
        ManifestValidationError::MissingPublisherSignature
    ));
}

#[test]
fn provenance_signed_requires_trust_chain_ref() {
    let m = ExtensionManifest {
        publisher_signature: Some(vec![1, 2, 3]),
        trust_chain_ref: None,
        ..valid_manifest()
    };
    let err = validate_provenance(&m, ManifestTrustLevel::SignedSupplyChain).unwrap_err();
    assert!(matches!(err, ManifestValidationError::MissingTrustChainRef));
}

#[test]
fn provenance_development_allows_missing_signature() {
    let m = valid_manifest();
    assert!(validate_provenance(&m, ManifestTrustLevel::Development).is_ok());
}

// ---------------------------------------------------------------------------
// Canonical Serialization
// ---------------------------------------------------------------------------

#[test]
fn canonical_json_deterministic() {
    let m = valid_manifest();
    let json1 = canonical_manifest_json(&m).unwrap();
    let json2 = canonical_manifest_json(&m).unwrap();
    assert_eq!(json1, json2, "canonical JSON must be deterministic");
}

#[test]
fn canonical_bytes_deterministic() {
    let m = valid_manifest();
    let b1 = canonical_manifest_bytes(&m).unwrap();
    let b2 = canonical_manifest_bytes(&m).unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn content_hash_deterministic() {
    let m = valid_manifest();
    let h1 = compute_content_hash(&m).unwrap();
    let h2 = compute_content_hash(&m).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn with_computed_content_hash_fills_hash() {
    let m = valid_manifest();
    let filled = with_computed_content_hash(m).unwrap();
    assert_ne!(
        filled.content_hash, [0u8; 32],
        "hash should be non-zero after computation"
    );
}

// ---------------------------------------------------------------------------
// Manifest Validation with Context
// ---------------------------------------------------------------------------

#[test]
fn validate_manifest_with_context_valid() {
    let m = valid_manifest();
    let ctx = manifest_ctx();
    let report = validate_manifest_with_context(&m, &ctx);
    assert!(report.error.is_none());
    assert_eq!(report.event.outcome, "pass");
}

#[test]
fn validate_manifest_with_context_invalid_produces_event() {
    let m = ExtensionManifest {
        name: String::new(),
        ..valid_manifest()
    };
    let ctx = manifest_ctx();
    let report = validate_manifest_with_context(&m, &ctx);
    assert!(report.error.is_some());
    assert_eq!(report.event.outcome, "fail");
    assert!(report.event.error_code.is_some());
}

#[test]
fn validation_report_into_result() {
    let m = valid_manifest();
    let ctx = manifest_ctx();
    let report = validate_manifest_with_context(&m, &ctx);
    assert!(report.into_result().is_ok());
}

// ---------------------------------------------------------------------------
// Error Code & Message Coverage
// ---------------------------------------------------------------------------

#[test]
fn manifest_validation_error_codes_are_unique() {
    // Construct all error variants and verify unique codes
    let errors: Vec<ManifestValidationError> = vec![
        ManifestValidationError::EmptyName,
        ManifestValidationError::EmptyVersion,
        ManifestValidationError::EmptyEntrypoint,
        ManifestValidationError::UnsupportedEngineVersion {
            min_engine_version: "999".to_string(),
            supported_engine_version: "0.1.0",
        },
        ManifestValidationError::InvalidCapabilityLattice {
            declared: Capability::FsWrite,
            missing_implied: Capability::FsRead,
        },
        ManifestValidationError::MissingPublisherSignature,
        ManifestValidationError::MissingTrustChainRef,
        ManifestValidationError::InvalidContentHash,
        ManifestValidationError::FieldTooLong {
            field: "name",
            max: 128,
            actual: 200,
        },
    ];

    for err in &errors {
        let code = err.error_code();
        let msg = err.message();
        assert!(!code.is_empty(), "error code must not be empty");
        assert!(!msg.is_empty(), "error message must not be empty");
    }
}

#[test]
fn manifest_validation_error_structured_message() {
    let err = ManifestValidationError::EmptyName;
    let structured = err.structured_message("trace-01", "ext-01");
    assert!(structured.contains("trace-01"));
    assert!(structured.contains("ext-01"));
}

// ---------------------------------------------------------------------------
// Extension Lifecycle — State Machine
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_full_happy_path() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = manager_with_manifest("ext-01", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();

    assert_eq!(mgr.state(), ExtensionState::Unloaded);

    let transitions = [
        (LifecycleTransition::Validate, ExtensionState::Validating),
        (LifecycleTransition::Load, ExtensionState::Loading),
        (LifecycleTransition::Start, ExtensionState::Starting),
        (LifecycleTransition::Activate, ExtensionState::Running),
    ];

    let mut ts = 1_000_000u64;
    for (transition, expected_state) in &transitions {
        let event = mgr.apply_transition(*transition, ts, &ctx).unwrap();
        assert_eq!(mgr.state(), *expected_state);
        assert_eq!(event.outcome, "pass");
        ts += 1_000_000;
    }
}

#[test]
fn lifecycle_suspend_resume_cycle() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = manager_with_manifest("ext-suspend", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();
    let mut ts = 1_000_000u64;

    // Get to Running
    for t in [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
    ] {
        mgr.apply_transition(t, ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    // Suspend
    mgr.apply_transition(LifecycleTransition::Suspend, ts, &ctx)
        .unwrap();
    ts += 1_000_000;
    mgr.apply_transition(LifecycleTransition::Freeze, ts, &ctx)
        .unwrap();
    ts += 1_000_000;
    assert_eq!(mgr.state(), ExtensionState::Suspended);

    // Resume
    mgr.apply_transition(LifecycleTransition::Resume, ts, &ctx)
        .unwrap();
    ts += 1_000_000;
    mgr.apply_transition(LifecycleTransition::Reactivate, ts, &ctx)
        .unwrap();
    assert_eq!(mgr.state(), ExtensionState::Running);
}

#[test]
fn lifecycle_invalid_transition_rejected() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = ExtensionLifecycleManager::new(
        "ext-invalid",
        budget,
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    let ctx = lifecycle_ctx();

    // Can't Start from Unloaded
    let err = mgr
        .apply_transition(LifecycleTransition::Start, 1_000_000, &ctx)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    assert!(!err.error_code().is_empty());
}

#[test]
fn lifecycle_quarantine_from_running() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = manager_with_manifest("ext-quarantine", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();
    let mut ts = 1_000_000u64;

    for t in [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
    ] {
        mgr.apply_transition(t, ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    mgr.apply_transition(LifecycleTransition::Quarantine, ts, &ctx)
        .unwrap();
    assert_eq!(mgr.state(), ExtensionState::Quarantined);
}

#[test]
fn lifecycle_non_monotonic_timestamp_rejected() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = ExtensionLifecycleManager::new(
        "ext-ts",
        budget,
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    let ctx = lifecycle_ctx();

    mgr.apply_transition(LifecycleTransition::Validate, 2_000_000, &ctx)
        .unwrap();

    // Earlier timestamp should fail
    let err = mgr
        .apply_transition(LifecycleTransition::Load, 1_000_000, &ctx)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::NonMonotonicTimestamp { .. }));
}

#[test]
fn lifecycle_transition_log_recorded() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = manager_with_manifest("ext-log", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();

    mgr.apply_transition(LifecycleTransition::Validate, 1_000_000, &ctx)
        .unwrap();
    mgr.apply_transition(LifecycleTransition::Load, 2_000_000, &ctx)
        .unwrap();

    let log = mgr.transition_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].from_state, ExtensionState::Unloaded);
    assert_eq!(log[0].to_state, ExtensionState::Validating);
    assert_eq!(log[1].from_state, ExtensionState::Validating);
    assert_eq!(log[1].to_state, ExtensionState::Loading);
}

#[test]
fn lifecycle_telemetry_events_produced() {
    let budget = ResourceBudget::new(1_000_000, 1024 * 1024, 100);
    let mut mgr = ExtensionLifecycleManager::new(
        "ext-telemetry",
        budget,
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    let ctx = lifecycle_ctx();

    mgr.apply_transition(LifecycleTransition::Validate, 1_000_000, &ctx)
        .unwrap();
    let events = mgr.telemetry_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].extension_id, "ext-telemetry");
}

// ---------------------------------------------------------------------------
// Budget Consumption & Enforcement
// ---------------------------------------------------------------------------

#[test]
fn budget_cpu_consumption_tracked() {
    let budget = ResourceBudget::new(10_000, 1024, 10);
    let mut mgr = manager_with_manifest("ext-cpu", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();
    let mut ts = 1_000_000u64;

    for t in [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
    ] {
        mgr.apply_transition(t, ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    mgr.consume_cpu_time(5_000, ts, &ctx).unwrap();
    ts += 1_000_000;
    assert_eq!(mgr.resource_budget().cpu_time_ns_remaining, 5_000);

    // Exhaust remaining
    let err = mgr.consume_cpu_time(10_000, ts, &ctx).unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::BudgetExhausted {
            dimension: "cpu_time_ns_remaining",
            ..
        }
    ));
}

#[test]
fn budget_memory_consumption_tracked() {
    let budget = ResourceBudget::new(100_000, 1024, 10);
    let mut mgr = manager_with_manifest("ext-mem", budget, BudgetExhaustionPolicy::Terminate);
    let ctx = lifecycle_ctx();
    let mut ts = 1_000_000u64;

    for t in [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
    ] {
        mgr.apply_transition(t, ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    mgr.consume_memory_bytes(512, ts, &ctx).unwrap();
    ts += 1_000_000;

    let err = mgr.consume_memory_bytes(600, ts, &ctx).unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::BudgetExhausted {
            dimension: "memory_bytes_remaining",
            ..
        }
    ));
}

#[test]
fn budget_hostcall_consumption_tracked() {
    let budget = ResourceBudget::new(100_000, 1024 * 1024, 3);
    let mut mgr = manager_with_manifest("ext-hc", budget, BudgetExhaustionPolicy::Suspend);
    let ctx = lifecycle_ctx();
    let mut ts = 1_000_000u64;

    for t in [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
    ] {
        mgr.apply_transition(t, ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    // Budget is 3 hostcalls; the 3rd consume brings remaining to 0 and triggers exhaustion
    for _ in 0..2 {
        mgr.consume_hostcall(ts, &ctx).unwrap();
        ts += 1_000_000;
    }

    let err = mgr.consume_hostcall(ts, &ctx).unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::BudgetExhausted {
            dimension: "hostcall_count_remaining",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Lifecycle Target State
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_target_state_all_valid_transitions() {
    // Verify all valid transitions produce expected target states
    let cases = [
        (
            ExtensionState::Unloaded,
            LifecycleTransition::Validate,
            ExtensionState::Validating,
        ),
        (
            ExtensionState::Validating,
            LifecycleTransition::Load,
            ExtensionState::Loading,
        ),
        (
            ExtensionState::Loading,
            LifecycleTransition::Start,
            ExtensionState::Starting,
        ),
        (
            ExtensionState::Starting,
            LifecycleTransition::Activate,
            ExtensionState::Running,
        ),
    ];

    for (from, transition, expected) in &cases {
        let target = lifecycle_target_state(*from, *transition);
        assert_eq!(target, Some(*expected), "from {from:?} via {transition:?}");
    }
}

#[test]
fn lifecycle_target_state_invalid_returns_none() {
    // Unloaded -> Start should not be valid
    assert_eq!(
        lifecycle_target_state(ExtensionState::Unloaded, LifecycleTransition::Start),
        None
    );
}

// ---------------------------------------------------------------------------
// Allowed Transitions
// ---------------------------------------------------------------------------

#[test]
fn allowed_transitions_from_unloaded() {
    let transitions = allowed_lifecycle_transitions(ExtensionState::Unloaded);
    assert!(transitions.contains(&LifecycleTransition::Validate));
    assert!(!transitions.contains(&LifecycleTransition::Start));
}

#[test]
fn allowed_transitions_from_running() {
    let transitions = allowed_lifecycle_transitions(ExtensionState::Running);
    assert!(transitions.contains(&LifecycleTransition::Suspend));
    assert!(transitions.contains(&LifecycleTransition::Terminate));
    assert!(transitions.contains(&LifecycleTransition::Quarantine));
}

// ---------------------------------------------------------------------------
// IFC — Flow Labels
// ---------------------------------------------------------------------------

#[test]
fn flow_label_join_max_secrecy_min_integrity() {
    let a = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let b = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted);
    let joined = a.join(b);
    assert_eq!(joined.secrecy(), SecrecyLevel::Secret);
    assert_eq!(joined.integrity(), IntegrityLevel::Untrusted);
}

#[test]
fn flow_label_default_is_maximally_restrictive() {
    let default_label = FlowLabel::default();
    assert_eq!(default_label.secrecy(), SecrecyLevel::TopSecret);
    assert_eq!(default_label.integrity(), IntegrityLevel::Untrusted);
}

#[test]
fn flow_label_join_idempotent() {
    let a = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    let joined = a.join(a);
    assert_eq!(joined.secrecy(), a.secrecy());
    assert_eq!(joined.integrity(), a.integrity());
}

#[test]
fn secrecy_level_ordering() {
    assert!(SecrecyLevel::Public.rank() < SecrecyLevel::Internal.rank());
    assert!(SecrecyLevel::Internal.rank() < SecrecyLevel::Confidential.rank());
    assert!(SecrecyLevel::Confidential.rank() < SecrecyLevel::Secret.rank());
    assert!(SecrecyLevel::Secret.rank() < SecrecyLevel::TopSecret.rank());
}

#[test]
fn integrity_level_ordering() {
    assert!(IntegrityLevel::Untrusted.rank() < IntegrityLevel::Validated.rank());
    assert!(IntegrityLevel::Validated.rank() < IntegrityLevel::Verified.rank());
    assert!(IntegrityLevel::Verified.rank() < IntegrityLevel::Trusted.rank());
}

// ---------------------------------------------------------------------------
// IFC — Lattice Flow Checks
// ---------------------------------------------------------------------------

#[test]
fn can_flow_same_label() {
    let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    assert!(FlowLabelLattice::can_flow(&label, &label));
}

#[test]
fn can_flow_public_to_secret() {
    let from = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let to = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
    assert!(FlowLabelLattice::can_flow(&from, &to));
}

#[test]
fn cannot_flow_secret_to_public() {
    let from = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
    let to = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert!(!FlowLabelLattice::can_flow(&from, &to));
}

#[test]
fn cannot_flow_untrusted_to_trusted() {
    let from = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    let to = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert!(!FlowLabelLattice::can_flow(&from, &to));
}

#[test]
fn can_flow_trusted_to_untrusted() {
    let from = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let to = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    assert!(FlowLabelLattice::can_flow(&from, &to));
}

#[test]
fn sink_clearance_allows_within_bounds() {
    let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    let sink = SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
    assert!(FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

#[test]
fn sink_clearance_rejects_exceeding_secrecy() {
    let label = FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Trusted);
    let sink = SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Untrusted);
    assert!(!FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

#[test]
fn sink_clearance_rejects_insufficient_integrity() {
    let label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    let sink = SinkClearance::new(SecrecyLevel::TopSecret, IntegrityLevel::Verified);
    assert!(!FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

// ---------------------------------------------------------------------------
// IFC — Labeled<T>
// ---------------------------------------------------------------------------

#[test]
fn labeled_new_preserves_value_and_label() {
    let label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let labeled = Labeled::new(42, label);
    assert_eq!(*labeled.value(), 42);
    assert_eq!(labeled.label().secrecy(), SecrecyLevel::Public);
}

#[test]
fn labeled_system_generated_is_public_trusted() {
    let labeled = Labeled::system_generated("hello");
    assert_eq!(labeled.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(labeled.label().integrity(), IntegrityLevel::Trusted);
}

#[test]
fn labeled_from_uses_default_label() {
    let labeled: Labeled<i32> = 42.into();
    assert_eq!(labeled.label().secrecy(), SecrecyLevel::TopSecret);
    assert_eq!(labeled.label().integrity(), IntegrityLevel::Untrusted);
}

#[test]
fn labeled_map_preserves_label() {
    let label = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Verified);
    let labeled = Labeled::new(10, label);
    let mapped = labeled.map(|x| x * 2);
    assert_eq!(*mapped.value(), 20);
    assert_eq!(mapped.label().secrecy(), SecrecyLevel::Confidential);
}

#[test]
fn labeled_into_inner_extracts_value() {
    let labeled = Labeled::system_generated("data");
    let val = labeled.into_inner();
    assert_eq!(val, "data");
}

// ---------------------------------------------------------------------------
// Hostcall Dispatch
// ---------------------------------------------------------------------------

#[test]
fn hostcall_type_sink_variants() {
    assert!(HostcallType::FsWrite.is_sink());
    assert!(HostcallType::NetworkSend.is_sink());
    assert!(HostcallType::IpcSend.is_sink());
    assert!(!HostcallType::FsRead.is_sink());
    assert!(!HostcallType::NetworkRecv.is_sink());
    assert!(!HostcallType::MemAlloc.is_sink());
}

#[test]
fn hostcall_type_as_str_unique() {
    let types = [
        HostcallType::FsRead,
        HostcallType::FsWrite,
        HostcallType::NetworkSend,
        HostcallType::NetworkRecv,
        HostcallType::ProcessSpawn,
        HostcallType::EnvRead,
        HostcallType::MemAlloc,
        HostcallType::TimerCreate,
        HostcallType::CryptoOp,
        HostcallType::IpcSend,
        HostcallType::IpcRecv,
    ];
    let labels: BTreeSet<&str> = types.iter().map(|t| t.as_str()).collect();
    assert_eq!(labels.len(), types.len());
}

#[test]
fn hostcall_dispatch_capability_escalation_denied() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = BTreeSet::from([Capability::FsRead]);
    let fctx = flow_ctx();

    let argument = Labeled::system_generated("data".to_string());
    let outcome = dispatcher.dispatch(
        "ext-01",
        HostcallType::FsWrite,
        &caps,
        Capability::FsWrite,
        argument,
        &fctx,
    );

    assert!(matches!(
        outcome.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscalation { .. }
        }
    ));
}

#[test]
fn hostcall_dispatch_flow_violation_denied() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = BTreeSet::from([Capability::FsRead, Capability::FsWrite]);
    let fctx = flow_ctx();

    // TopSecret data to fs_write sink (requires Internal)
    let argument: Labeled<String> = "secret-data".to_string().into(); // TopSecret, Untrusted
    let outcome = dispatcher.dispatch(
        "ext-02",
        HostcallType::FsWrite,
        &caps,
        Capability::FsWrite,
        argument,
        &fctx,
    );

    assert!(matches!(
        outcome.result,
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { .. }
        }
    ));
    assert!(!dispatcher.violation_events().is_empty());
    assert!(!dispatcher.guardplane_evidence().is_empty());
}

#[test]
fn hostcall_dispatch_rejects_public_system_generated_spoof_on_sink() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = BTreeSet::from([Capability::FsRead, Capability::FsWrite]);
    let fctx = flow_ctx();

    // Public constructors cannot mint host-trusted authority for sink checks.
    let argument = Labeled::system_generated("ok-data".to_string());
    let outcome = dispatcher.dispatch(
        "ext-03",
        HostcallType::FsWrite,
        &caps,
        Capability::FsWrite,
        argument,
        &fctx,
    );

    assert!(matches!(
        outcome.result,
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { .. }
        }
    ));
    assert!(outcome.output.is_none());
}

// ---------------------------------------------------------------------------
// Declassification Gateway
// ---------------------------------------------------------------------------

#[test]
fn declassification_gateway_default_creates() {
    let gw = DeclassificationGateway::default();
    assert!(gw.receipt_log().receipts().is_empty());
    assert!(gw.events().is_empty());
}

#[test]
fn declassification_denied_missing_capability() {
    let mut gw = DeclassificationGateway::default();
    let caps = BTreeSet::from([Capability::FsRead]); // No Declassify capability
    let fctx = flow_ctx();

    let request = DeclassificationRequest {
        request_id: "req-01".to_string(),
        requester: "ext-01".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        purpose: DeclassificationPurpose::UserConsent,
        justification: "user approved".to_string(),
        timestamp_ns: 1_000_000,
    };

    let outcome = gw.evaluate_request(request, &caps, 500_000, &fctx);
    assert!(matches!(outcome, DeclassificationOutcome::Denied { .. }));
    assert!(!gw.receipt_log().receipts().is_empty());
}

#[test]
fn declassification_approved_with_correct_capability() {
    let mut gw = DeclassificationGateway::default();
    let caps = BTreeSet::from([Capability::Declassify]);
    let fctx = flow_ctx();

    let request = DeclassificationRequest {
        request_id: "req-02".to_string(),
        requester: "ext-02".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        purpose: DeclassificationPurpose::PublicApiResponse,
        justification: "api response".to_string(),
        timestamp_ns: 1_000_000,
    };

    let outcome = gw.evaluate_request(request, &caps, 500_000, &fctx);
    assert!(matches!(outcome, DeclassificationOutcome::Approved { .. }));
}

#[test]
fn declassification_receipt_signature_verifies() {
    let signing_key = DecisionSigningKey::default();
    let public_key = signing_key.public_key();
    let mut gw = DeclassificationGateway::with_default_contracts(signing_key);
    let caps = BTreeSet::from([Capability::Declassify]);
    let fctx = flow_ctx();

    let request = DeclassificationRequest {
        request_id: "req-sig".to_string(),
        requester: "ext-sig".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        purpose: DeclassificationPurpose::UserConsent,
        justification: "test".to_string(),
        timestamp_ns: 1_000_000,
    };

    let _outcome = gw.evaluate_request(request, &caps, 500_000, &fctx);
    let receipts = gw.receipt_log().receipts();
    assert!(!receipts.is_empty());
    assert!(receipts[0].verify(&public_key));
}

#[test]
fn declassification_denied_empty_justification() {
    let mut gw = DeclassificationGateway::default();
    let caps = BTreeSet::from([Capability::Declassify]);
    let fctx = flow_ctx();

    let request = DeclassificationRequest {
        request_id: "req-empty".to_string(),
        requester: "ext-empty".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        purpose: DeclassificationPurpose::UserConsent,
        justification: String::new(),
        timestamp_ns: 1_000_000,
    };

    let outcome = gw.evaluate_request(request, &caps, 500_000, &fctx);
    assert!(matches!(outcome, DeclassificationOutcome::Denied { .. }));
}

#[test]
fn declassification_no_op_same_label() {
    let mut gw = DeclassificationGateway::default();
    let caps = BTreeSet::from([Capability::Declassify]);
    let fctx = flow_ctx();

    let label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let request = DeclassificationRequest {
        request_id: "req-noop".to_string(),
        requester: "ext-noop".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: label,
        target_label: label,
        purpose: DeclassificationPurpose::UserConsent,
        justification: "test".to_string(),
        timestamp_ns: 1_000_000,
    };

    let outcome = gw.evaluate_request(request, &caps, 500_000, &fctx);
    // No declassification needed — should be denied as NoDeclassificationRequired
    assert!(matches!(outcome, DeclassificationOutcome::Denied { .. }));
}

// ---------------------------------------------------------------------------
// Decision Contracts
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_contract_within_limit() {
    let contract = RateLimitContract::new(10, 60_000_000_000);
    let request = DeclassificationRequest {
        request_id: "req-rate".to_string(),
        requester: "ext-rate".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Trusted),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
        purpose: DeclassificationPurpose::UserConsent,
        justification: "test".to_string(),
        timestamp_ns: 1_000_000,
    };

    let caps = BTreeSet::from([Capability::Declassify]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000_000);
    let verdict = contract.evaluate(&request, &ctx);
    // Should not be denied by rate limit alone (0 prior requests < 10 limit)
    assert!(!matches!(
        verdict,
        DecisionVerdict::Denied {
            reason: DeclassificationDenialReason::RateLimited { .. }
        }
    ));
}

// ---------------------------------------------------------------------------
// Delegate Cell
// ---------------------------------------------------------------------------

#[test]
fn delegate_cell_factory_creates_cell() {
    let factory = DelegateCellFactory::default();
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: "parent-ext".to_string(),
        max_lifetime_ns: 60_000_000_000,
    };
    let budget = ResourceBudget::new(10_000_000, 1024 * 1024, 100);
    let ctx = lifecycle_ctx();

    let cell = factory.create_delegate_cell(
        "delegate-01",
        manifest,
        budget,
        BudgetExhaustionPolicy::Terminate,
        1_000_000,
        &ctx,
    );
    assert!(cell.is_ok());

    let cell = cell.unwrap();
    assert_eq!(cell.delegate_id(), "delegate-01");
    assert_eq!(cell.state(), ExtensionState::Running);
}

#[test]
fn delegate_cell_invalid_budget_rejected() {
    let factory = DelegateCellFactory::default();
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::ConfigUpdate,
        delegator_id: "parent".to_string(),
        max_lifetime_ns: 60_000_000_000,
    };
    // Exceeds MAX_DELEGATE_CPU_BUDGET_NS
    let budget = ResourceBudget::new(MAX_DELEGATE_CPU_BUDGET_NS + 1, 1024, 10);
    let ctx = lifecycle_ctx();

    let result = factory.create_delegate_cell(
        "delegate-bad",
        manifest,
        budget,
        BudgetExhaustionPolicy::Suspend,
        1_000_000,
        &ctx,
    );
    assert!(result.is_err());
}

#[test]
fn delegate_cell_lifetime_check() {
    let factory = DelegateCellFactory::default();
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: "parent".to_string(),
        max_lifetime_ns: 1_000_000_000, // 1 second
    };
    let budget = ResourceBudget::new(10_000_000, 1024 * 1024, 100);
    let ctx = lifecycle_ctx();

    let mut cell = factory
        .create_delegate_cell(
            "delegate-expire",
            manifest,
            budget,
            BudgetExhaustionPolicy::Terminate,
            1_000_000,
            &ctx,
        )
        .unwrap();

    // Within lifetime
    assert!(cell.check_lifetime(500_000_000, &ctx).is_ok());

    // Past lifetime
    let err = cell.check_lifetime(2_000_000_000, &ctx).unwrap_err();
    assert!(matches!(err, DelegateCellError::LifetimeExpired { .. }));
}

#[test]
fn delegate_cell_lifecycle_transitions() {
    let factory = DelegateCellFactory::default();
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::ModuleReplacement,
        delegator_id: "parent".to_string(),
        max_lifetime_ns: 60_000_000_000,
    };
    let budget = ResourceBudget::new(10_000_000, 1024 * 1024, 100);
    let ctx = lifecycle_ctx();

    let mut cell = factory
        .create_delegate_cell(
            "delegate-lc",
            manifest,
            budget,
            BudgetExhaustionPolicy::Terminate,
            1_000_000,
            &ctx,
        )
        .unwrap();

    // Factory brings it all the way to Running
    assert_eq!(cell.state(), ExtensionState::Running);

    // Suspend -> Freeze -> Resume -> Reactivate
    cell.apply_transition(LifecycleTransition::Suspend, 2_000_000, &ctx)
        .unwrap();
    assert_eq!(cell.state(), ExtensionState::Suspending);
    cell.apply_transition(LifecycleTransition::Freeze, 3_000_000, &ctx)
        .unwrap();
    assert_eq!(cell.state(), ExtensionState::Suspended);
    cell.apply_transition(LifecycleTransition::Resume, 4_000_000, &ctx)
        .unwrap();
    assert_eq!(cell.state(), ExtensionState::Resuming);
    cell.apply_transition(LifecycleTransition::Reactivate, 5_000_000, &ctx)
        .unwrap();
    assert_eq!(cell.state(), ExtensionState::Running);
}

#[test]
fn delegate_cell_manifest_validation() {
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: "parent".to_string(),
        max_lifetime_ns: 60_000_000_000,
    };
    assert!(manifest.validate().is_ok());
}

#[test]
fn delegate_cell_invalid_manifest_empty_delegator() {
    let manifest = DelegateCellManifest {
        base_manifest: valid_manifest(),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: String::new(),
        max_lifetime_ns: 60_000_000_000,
    };
    assert!(manifest.validate().is_err());
}

// ---------------------------------------------------------------------------
// Delegation Scope
// ---------------------------------------------------------------------------

#[test]
fn delegation_scope_as_str() {
    let scopes = [
        DelegationScope::ModuleReplacement,
        DelegationScope::ConfigUpdate,
        DelegationScope::DiagnosticCollection,
        DelegationScope::TrustChainRotation,
        DelegationScope::Custom("test".to_string()),
    ];
    for scope in &scopes {
        assert!(!scope.as_str().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Extension State & Transition Labels
// ---------------------------------------------------------------------------

#[test]
fn extension_state_as_str_unique() {
    let states = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    let labels: BTreeSet<&str> = states.iter().map(|s| s.as_str()).collect();
    assert_eq!(labels.len(), states.len());
}

#[test]
fn lifecycle_transition_as_str_unique() {
    let transitions = [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
        LifecycleTransition::Suspend,
        LifecycleTransition::Freeze,
        LifecycleTransition::Resume,
        LifecycleTransition::Reactivate,
        LifecycleTransition::Terminate,
        LifecycleTransition::Finalize,
        LifecycleTransition::Quarantine,
    ];
    let labels: BTreeSet<&str> = transitions.iter().map(|t| t.as_str()).collect();
    assert_eq!(labels.len(), transitions.len());
}

// ---------------------------------------------------------------------------
// Budget Exhaustion Policy
// ---------------------------------------------------------------------------

#[test]
fn budget_exhaustion_policy_as_str() {
    assert_eq!(BudgetExhaustionPolicy::Suspend.as_str(), "suspend");
    assert_eq!(BudgetExhaustionPolicy::Terminate.as_str(), "terminate");
}

// ---------------------------------------------------------------------------
// Cancellation Config
// ---------------------------------------------------------------------------

#[test]
fn cancellation_config_default() {
    let config = CancellationConfig::default();
    assert_eq!(config.grace_period_ns, DEFAULT_TERMINATION_GRACE_PERIOD_NS);
}

#[test]
fn cancellation_config_clamped() {
    let config = CancellationConfig {
        grace_period_ns: MAX_TERMINATION_GRACE_PERIOD_NS + 1_000_000,
    };
    let clamped = config.clamped();
    assert_eq!(clamped.grace_period_ns, MAX_TERMINATION_GRACE_PERIOD_NS);
}

// ---------------------------------------------------------------------------
// Decision Signing Key
// ---------------------------------------------------------------------------

#[test]
fn decision_signing_key_sign_and_verify() {
    let key = DecisionSigningKey::default();
    let public = key.public_key();
    let payload = b"test payload";
    let sig = key.sign(payload);
    assert!(public.verify(payload, &sig));
}

#[test]
fn decision_signing_key_wrong_payload_fails() {
    let key = DecisionSigningKey::default();
    let public = key.public_key();
    let sig = key.sign(b"original");
    assert!(!public.verify(b"tampered", &sig));
}

// ---------------------------------------------------------------------------
// Decision Receipt Log
// ---------------------------------------------------------------------------

#[test]
fn decision_receipt_log_append_only() {
    let mut log = DecisionReceiptLog::default();
    assert!(log.receipts().is_empty());

    let receipt = CryptographicDecisionReceipt {
        receipt_id: "r-1".to_string(),
        request_id: "req-1".to_string(),
        verdict: DecisionVerdict::Approved { conditions: vec![] },
        contract_chain: vec!["c-1".to_string()],
        conditions: vec![],
        posterior_at_decision_micros: 500_000,
        timestamp_ns: 1_000_000,
        signature: [0u8; 32],
    };
    log.append(receipt);
    assert_eq!(log.receipts().len(), 1);
}

// ---------------------------------------------------------------------------
// Declassification Purpose
// ---------------------------------------------------------------------------

#[test]
fn declassification_purpose_as_str() {
    let purposes = [
        DeclassificationPurpose::UserConsent,
        DeclassificationPurpose::AggregationAnonymization,
        DeclassificationPurpose::PublicApiResponse,
        DeclassificationPurpose::DiagnosticExport,
        DeclassificationPurpose::OperatorOverride,
        DeclassificationPurpose::Custom("custom-purpose".to_string()),
    ];
    for p in &purposes {
        assert!(!p.as_str().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_sensible() {
    const { assert!(MAX_NAME_LEN > 0) };
    const { assert!(MAX_VERSION_LEN > 0) };
    const { assert!(MAX_ENTRYPOINT_LEN > 0) };
    const { assert!(MAX_TRUST_CHAIN_REF_LEN > 0) };
    const { assert!(DEFAULT_TERMINATION_GRACE_PERIOD_NS > 0) };
    const { assert!(MAX_TERMINATION_GRACE_PERIOD_NS >= DEFAULT_TERMINATION_GRACE_PERIOD_NS) };
    const { assert!(MAX_DELEGATE_LIFETIME_NS > 0) };
    const { assert!(MAX_DELEGATE_CPU_BUDGET_NS > 0) };
    const { assert!(MAX_DELEGATE_MEMORY_BUDGET_BYTES > 0) };
    const { assert!(MAX_DELEGATE_HOSTCALL_BUDGET > 0) };
}

// ---------------------------------------------------------------------------
// Hostcall Sink Policy
// ---------------------------------------------------------------------------

#[test]
fn hostcall_sink_policy_default_clearances() {
    let policy = HostcallSinkPolicy::default();
    assert!(policy.clearance_for(HostcallType::FsWrite).is_some());
    assert!(policy.clearance_for(HostcallType::NetworkSend).is_some());
    assert!(policy.clearance_for(HostcallType::IpcSend).is_some());
    // Non-sink hostcalls should return None
    assert!(policy.clearance_for(HostcallType::FsRead).is_none());
}

// ---------------------------------------------------------------------------
// DataRef
// ---------------------------------------------------------------------------

#[test]
fn data_ref_construction() {
    let dr = DataRef::new("namespace", "key");
    assert_eq!(dr.namespace, "namespace");
    assert_eq!(dr.key, "key");
}

// ---------------------------------------------------------------------------
// DeclassificationCondition
// ---------------------------------------------------------------------------

#[test]
fn declassification_condition_construction() {
    let cond = DeclassificationCondition::new("rate_limit", "10/min");
    assert_eq!(cond.key, "rate_limit");
    assert_eq!(cond.value, "10/min");
}

// ---------------------------------------------------------------------------
// DeclassificationEvaluationContext
// ---------------------------------------------------------------------------

#[test]
fn evaluation_context_has_capability() {
    let caps = BTreeSet::from([Capability::FsRead, Capability::Declassify]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000_000);
    assert!(ctx.has_capability(Capability::Declassify));
    assert!(!ctx.has_capability(Capability::NetClient));
}

#[test]
fn evaluation_context_request_count_within_window() {
    let caps = BTreeSet::from([Capability::Declassify]);
    let history = vec![900_000u64, 950_000, 980_000]; // 3 requests before current
    let ctx = DeclassificationEvaluationContext::new(&caps, Some(&history), 1_000_000);
    // All 3 requests within 1_000_000ns window
    let count = ctx.request_count_within_window(1_000_000);
    assert!(count >= 3);
}

// ---------------------------------------------------------------------------
// Engine Version Validation
// ---------------------------------------------------------------------------

#[test]
fn engine_version_current_passes() {
    assert!(validate_engine_version(CURRENT_ENGINE_VERSION).is_ok());
}

#[test]
fn engine_version_future_fails() {
    assert!(validate_engine_version("999.0.0").is_err());
}

// ---------------------------------------------------------------------------
// Lifecycle Error Coverage
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_error_codes_non_empty() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "ext".to_string(),
            current_state: ExtensionState::Unloaded,
            attempted_transition: LifecycleTransition::Start,
        },
        LifecycleError::NonMonotonicTimestamp {
            previous: 2,
            current: 1,
        },
    ];

    for err in &errors {
        assert!(!err.error_code().is_empty());
        assert!(!err.message().is_empty());
    }
}
