//! Edge-case integration tests for the error_code module.

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

use std::collections::{BTreeSet, HashSet};

use frankenengine_engine::error_code::{
    ALL_ERROR_CODES, ERROR_CODE_COMPATIBILITY_POLICY, ERROR_CODE_REGISTRY_VERSION, ErrorCodeEntry,
    ErrorCodeRegistry, ErrorSeverity, ErrorSubsystem, FrankenErrorCode, HasErrorCode,
    error_code_registry,
};

// ===========================================================================
// FrankenErrorCode serde / traits
// ===========================================================================

#[test]
fn franken_error_code_serde_all_codes() {
    for code in ALL_ERROR_CODES {
        let json = serde_json::to_string(code).unwrap();
        let back: FrankenErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, code, "serde roundtrip failed for {code:?}");
    }
}

#[test]
fn franken_error_code_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for code in ALL_ERROR_CODES {
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        code.hash(&mut h1);
        code.hash(&mut h2);
        assert_eq!(
            h1.finish(),
            h2.finish(),
            "hash not deterministic for {code:?}"
        );
    }
}

#[test]
fn franken_error_code_hash_unique_per_code() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let hashes: HashSet<u64> = ALL_ERROR_CODES
        .iter()
        .map(|c| {
            let mut h = DefaultHasher::new();
            c.hash(&mut h);
            h.finish()
        })
        .collect();
    // Hash collisions are possible but extremely unlikely for 42 values
    assert!(hashes.len() >= ALL_ERROR_CODES.len() - 1);
}

#[test]
fn franken_error_code_display_all_fe_format() {
    for code in ALL_ERROR_CODES {
        let display = format!("{code}");
        assert!(display.starts_with("FE-"), "{display} must start with FE-");
        assert_eq!(display.len(), 7, "{display} must be 7 chars");
        assert_eq!(display, code.stable_code());
    }
}

#[test]
fn franken_error_code_numeric_unique() {
    let numerics: BTreeSet<u16> = ALL_ERROR_CODES.iter().map(|c| c.numeric()).collect();
    assert_eq!(numerics.len(), ALL_ERROR_CODES.len());
}

#[test]
fn franken_error_code_stable_code_unique() {
    let codes: BTreeSet<String> = ALL_ERROR_CODES.iter().map(|c| c.stable_code()).collect();
    assert_eq!(codes.len(), ALL_ERROR_CODES.len());
}

#[test]
fn franken_error_code_from_numeric_all() {
    for code in ALL_ERROR_CODES {
        let recovered = FrankenErrorCode::from_numeric(code.numeric());
        assert_eq!(recovered, Some(*code));
    }
}

#[test]
fn franken_error_code_from_numeric_unassigned() {
    assert_eq!(FrankenErrorCode::from_numeric(0), None);
    assert_eq!(FrankenErrorCode::from_numeric(3), None);
    assert_eq!(FrankenErrorCode::from_numeric(999), None);
    assert_eq!(FrankenErrorCode::from_numeric(1500), None);
    assert_eq!(FrankenErrorCode::from_numeric(9999), None);
    assert_eq!(FrankenErrorCode::from_numeric(u16::MAX), None);
}

#[test]
fn franken_error_code_none_deprecated() {
    for code in ALL_ERROR_CODES {
        assert!(!code.deprecated());
    }
}

// ===========================================================================
// ErrorSeverity serde with snake_case
// ===========================================================================

#[test]
fn error_severity_serde_snake_case_format() {
    let json = serde_json::to_string(&ErrorSeverity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");

    let json = serde_json::to_string(&ErrorSeverity::Error).unwrap();
    assert_eq!(json, "\"error\"");

    let json = serde_json::to_string(&ErrorSeverity::Warning).unwrap();
    assert_eq!(json, "\"warning\"");

    let json = serde_json::to_string(&ErrorSeverity::Info).unwrap();
    assert_eq!(json, "\"info\"");
}

#[test]
fn error_severity_serde_roundtrip_all() {
    for s in [
        ErrorSeverity::Critical,
        ErrorSeverity::Error,
        ErrorSeverity::Warning,
        ErrorSeverity::Info,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ErrorSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// ErrorSubsystem serde with snake_case
// ===========================================================================

#[test]
fn error_subsystem_serde_snake_case_format() {
    let json = serde_json::to_string(&ErrorSubsystem::SerializationEncoding).unwrap();
    assert_eq!(json, "\"serialization_encoding\"");

    let json = serde_json::to_string(&ErrorSubsystem::IdentityAuthentication).unwrap();
    assert_eq!(json, "\"identity_authentication\"");

    let json = serde_json::to_string(&ErrorSubsystem::CapabilityAuthorization).unwrap();
    assert_eq!(json, "\"capability_authorization\"");

    let json = serde_json::to_string(&ErrorSubsystem::CheckpointPolicy).unwrap();
    assert_eq!(json, "\"checkpoint_policy\"");

    let json = serde_json::to_string(&ErrorSubsystem::Reserved).unwrap();
    assert_eq!(json, "\"reserved\"");
}

#[test]
fn error_subsystem_serde_roundtrip_all() {
    for sub in [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
        ErrorSubsystem::Reserved,
    ] {
        let json = serde_json::to_string(&sub).unwrap();
        let back: ErrorSubsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sub);
    }
}

// ===========================================================================
// ErrorSubsystem ranges
// ===========================================================================

#[test]
fn error_subsystem_ranges_contiguous_non_overlapping() {
    let subsystems = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
        ErrorSubsystem::Reserved,
    ];
    let mut prev_end = 0u16;
    for sub in subsystems {
        let (start, end) = sub.range();
        assert_eq!(start, prev_end + 1);
        assert!(end >= start);
        prev_end = end;
    }
    assert_eq!(prev_end, 9999);
}

#[test]
fn error_subsystem_includes_boundary_all() {
    let subsystems = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
        ErrorSubsystem::Reserved,
    ];
    for sub in subsystems {
        let (start, end) = sub.range();
        assert!(sub.includes(start));
        assert!(sub.includes(end));
        if start > 1 {
            assert!(!sub.includes(start - 1));
        }
        if end < u16::MAX {
            assert!(!sub.includes(end + 1));
        }
    }
}

#[test]
fn error_subsystem_every_code_belongs_to_its_subsystem() {
    for code in ALL_ERROR_CODES {
        let sub = code.subsystem();
        assert!(
            sub.includes(code.numeric()),
            "{code:?} numeric={} not in subsystem {sub:?}",
            code.numeric()
        );
    }
}

// ===========================================================================
// Severity classification
// ===========================================================================

#[test]
fn severity_critical_exactly_five_codes() {
    let critical: Vec<_> = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() == ErrorSeverity::Critical)
        .collect();
    assert_eq!(critical.len(), 5);
}

#[test]
fn severity_critical_specific_codes() {
    let expected_critical = [
        FrankenErrorCode::PolicyCheckpointValidationError,
        FrankenErrorCode::CheckpointFrontierEnforcementError,
        FrankenErrorCode::ForkDetectionError,
        FrankenErrorCode::RevocationChainIntegrityError,
        FrankenErrorCode::EpochMonotonicityViolation,
    ];
    for code in expected_critical {
        assert_eq!(code.severity(), ErrorSeverity::Critical);
    }
}

#[test]
fn severity_non_critical_are_error() {
    let non_critical: Vec<_> = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() != ErrorSeverity::Critical)
        .collect();
    for code in &non_critical {
        assert_eq!(code.severity(), ErrorSeverity::Error);
    }
}

// ===========================================================================
// Description / operator_action
// ===========================================================================

#[test]
fn description_non_empty_all() {
    for code in ALL_ERROR_CODES {
        assert!(!code.description().is_empty());
    }
}

#[test]
fn operator_action_non_empty_all() {
    for code in ALL_ERROR_CODES {
        assert!(!code.operator_action().is_empty());
    }
}

#[test]
fn description_unique_per_code() {
    let descriptions: BTreeSet<_> = ALL_ERROR_CODES.iter().map(|c| c.description()).collect();
    assert_eq!(descriptions.len(), ALL_ERROR_CODES.len());
}

#[test]
fn operator_action_unique_per_code() {
    let actions: BTreeSet<_> = ALL_ERROR_CODES
        .iter()
        .map(|c| c.operator_action())
        .collect();
    assert_eq!(actions.len(), ALL_ERROR_CODES.len());
}

// ===========================================================================
// ErrorCodeEntry
// ===========================================================================

#[test]
fn error_code_entry_serde_roundtrip() {
    let entry = FrankenErrorCode::CapabilityDeniedError.to_registry_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let back: ErrorCodeEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn error_code_entry_to_registry_preserves_all_fields() {
    for code in ALL_ERROR_CODES {
        let entry = code.to_registry_entry();
        assert_eq!(entry.code, code.stable_code());
        assert_eq!(entry.numeric, code.numeric());
        assert_eq!(entry.subsystem, code.subsystem());
        assert_eq!(entry.severity, code.severity());
        assert_eq!(entry.description, code.description());
        assert_eq!(entry.operator_action, code.operator_action());
        assert_eq!(entry.deprecated, code.deprecated());
    }
}

// ===========================================================================
// ErrorCodeRegistry
// ===========================================================================

#[test]
fn error_code_registry_serde_roundtrip() {
    let registry = error_code_registry();
    let json = serde_json::to_string(&registry).unwrap();
    let back: ErrorCodeRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, registry);
}

#[test]
fn error_code_registry_deterministic() {
    let r1 = serde_json::to_string(&error_code_registry()).unwrap();
    let r2 = serde_json::to_string(&error_code_registry()).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn error_code_registry_version_matches_constant() {
    let registry = error_code_registry();
    assert_eq!(registry.version, ERROR_CODE_REGISTRY_VERSION);
}

#[test]
fn error_code_registry_compatibility_policy_matches() {
    let registry = error_code_registry();
    assert_eq!(
        registry.compatibility_policy,
        ERROR_CODE_COMPATIBILITY_POLICY
    );
}

#[test]
fn error_code_registry_entries_count_matches_all_codes() {
    let registry = error_code_registry();
    assert_eq!(registry.entries.len(), ALL_ERROR_CODES.len());
}

#[test]
fn error_code_registry_entries_in_same_order_as_all_codes() {
    let registry = error_code_registry();
    for (i, entry) in registry.entries.iter().enumerate() {
        assert_eq!(
            entry.numeric,
            ALL_ERROR_CODES[i].numeric(),
            "entry {i} order mismatch"
        );
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn error_code_registry_version_is_one() {
    assert_eq!(ERROR_CODE_REGISTRY_VERSION, 1);
}

#[test]
fn error_code_compatibility_policy_append_only() {
    assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("append-only"));
    assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("permanent"));
    assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("never reused"));
}

// ===========================================================================
// ALL_ERROR_CODES array properties
// ===========================================================================

#[test]
fn all_error_codes_length() {
    // 42 assigned error codes as of this version
    assert_eq!(ALL_ERROR_CODES.len(), 42);
}

#[test]
fn all_error_codes_numeric_positive() {
    for code in ALL_ERROR_CODES {
        assert!(code.numeric() > 0);
    }
}

#[test]
fn all_error_codes_monotonic_within_subsystem() {
    // Within each subsystem, codes should be non-decreasing
    let mut by_subsystem: BTreeSet<(u16, u16)> = BTreeSet::new();
    for code in ALL_ERROR_CODES {
        let (start, _) = code.subsystem().range();
        by_subsystem.insert((start, code.numeric()));
    }
    let codes: Vec<_> = by_subsystem.into_iter().collect();
    for window in codes.windows(2) {
        assert!(window[0].1 < window[1].1);
    }
}

// ===========================================================================
// Specific stable_code values
// ===========================================================================

#[test]
fn stable_code_specific_values() {
    assert_eq!(
        FrankenErrorCode::NonCanonicalEncodingError.stable_code(),
        "FE-0001"
    );
    assert_eq!(
        FrankenErrorCode::DeterministicSerdeError.stable_code(),
        "FE-0002"
    );
    assert_eq!(
        FrankenErrorCode::EngineObjectIdError.stable_code(),
        "FE-1000"
    );
    assert_eq!(
        FrankenErrorCode::CapabilityDeniedError.stable_code(),
        "FE-2000"
    );
    assert_eq!(
        FrankenErrorCode::PolicyCheckpointValidationError.stable_code(),
        "FE-3000"
    );
    assert_eq!(
        FrankenErrorCode::RevocationChainIntegrityError.stable_code(),
        "FE-4000"
    );
    assert_eq!(
        FrankenErrorCode::LeaseLifecycleError.stable_code(),
        "FE-5000"
    );
    assert_eq!(
        FrankenErrorCode::AllocationDomainBudgetError.stable_code(),
        "FE-6000"
    );
    assert_eq!(
        FrankenErrorCode::EvidenceContractError.stable_code(),
        "FE-7000"
    );
    assert_eq!(
        FrankenErrorCode::EpochMonotonicityViolation.stable_code(),
        "FE-8000"
    );
}

// ===========================================================================
// HasErrorCode trait — integration-level mapping tests
// ===========================================================================

#[test]
fn has_error_code_eval_error_all_codes_map_to_eval_runtime() {
    use frankenengine_engine::{EvalError, EvalErrorCode};
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    for code in codes {
        let err = EvalError {
            code,
            message: "test".into(),
            correlation_ids: None,
            location: None,
            stack_frames: Vec::new(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::EvalRuntimeError);
    }
}

#[test]
fn has_error_code_token_error_empty_capabilities() {
    use frankenengine_engine::capability_token::TokenError;
    let err = TokenError::EmptyCapabilities;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::CapabilityTokenValidationError
    );
}

#[test]
fn has_error_code_id_error_empty_bytes() {
    use frankenengine_engine::engine_object_id::IdError;
    let err = IdError::EmptyCanonicalBytes;
    assert_eq!(err.error_code(), FrankenErrorCode::EngineObjectIdError);
}

#[test]
fn has_error_code_signature_error_invalid_key() {
    use frankenengine_engine::signature_preimage::SignatureError;
    let err = SignatureError::InvalidSigningKey;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::SignatureVerificationError
    );
}

#[test]
fn has_error_code_multi_sig_empty_array() {
    use frankenengine_engine::sorted_multisig::MultiSigError;
    let err = MultiSigError::EmptyArray;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::MultiSigVerificationError
    );
}

#[test]
fn has_error_code_key_derivation_empty_master() {
    use frankenengine_engine::key_derivation::KeyDerivationError;
    let err = KeyDerivationError::EmptyMasterKey;
    assert_eq!(err.error_code(), FrankenErrorCode::KeyDerivationFailure);
}

#[test]
fn has_error_code_cancel_mask_nesting_denied() {
    use frankenengine_engine::cancel_mask::MaskError;
    let err = MaskError::NestingDenied;
    assert_eq!(err.error_code(), FrankenErrorCode::CancelMaskPolicyError);
}

#[test]
fn has_error_code_checkpoint_empty_policy_heads() {
    use frankenengine_engine::policy_checkpoint::CheckpointError;
    let err = CheckpointError::EmptyPolicyHeads;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::PolicyCheckpointValidationError
    );
}

#[test]
fn has_error_code_barrier_no_transition() {
    use frankenengine_engine::epoch_barrier::BarrierError;
    let err = BarrierError::NoTransitionInProgress;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::EpochBarrierTransitionError
    );
}

#[test]
fn has_error_code_policy_controller_empty_action_set() {
    use frankenengine_engine::policy_controller::PolicyControllerError;
    let err = PolicyControllerError::EmptyActionSet;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::PolicyControllerDecisionError
    );
}

#[test]
fn has_error_code_reconcile_empty_object_set() {
    use frankenengine_engine::anti_entropy::ReconcileError;
    let err = ReconcileError::EmptyObjectSet;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::AntiEntropyReconciliationError
    );
}

#[test]
fn has_error_code_chain_integrity_empty_stream() {
    use frankenengine_engine::marker_stream::ChainIntegrityError;
    let err = ChainIntegrityError::EmptyStream;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::MarkerStreamIntegrityError
    );
}

#[test]
fn has_error_code_lease_zero_ttl() {
    use frankenengine_engine::lease_tracker::LeaseError;
    let err = LeaseError::ZeroTtl;
    assert_eq!(err.error_code(), FrankenErrorCode::LeaseLifecycleError);
}

#[test]
fn has_error_code_lease_empty_holder() {
    use frankenengine_engine::lease_tracker::LeaseError;
    let err = LeaseError::EmptyHolder;
    assert_eq!(err.error_code(), FrankenErrorCode::LeaseLifecycleError);
}

#[test]
fn has_error_code_obligation_not_found() {
    use frankenengine_engine::obligation_channel::ObligationError;
    let err = ObligationError::NotFound { obligation_id: 42 };
    assert_eq!(err.error_code(), FrankenErrorCode::ObligationChannelError);
}

#[test]
fn has_error_code_lane_empty_trace_id() {
    use frankenengine_engine::scheduler_lane::LaneError;
    let err = LaneError::EmptyTraceId;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::SchedulerLaneAdmissionError
    );
}

#[test]
fn has_error_code_saga_empty_steps() {
    use frankenengine_engine::saga_orchestrator::SagaError;
    let err = SagaError::EmptySteps;
    assert_eq!(err.error_code(), FrankenErrorCode::SagaExecutionError);
}

#[test]
fn has_error_code_saga_concurrency_limit_reached() {
    use frankenengine_engine::saga_orchestrator::SagaError;
    let err = SagaError::ConcurrencyLimitReached {
        active_count: 4,
        max_concurrent: 3,
    };
    assert_eq!(err.error_code(), FrankenErrorCode::SagaExecutionError);
}

#[test]
fn has_error_code_alloc_domain_budget_overflow() {
    use frankenengine_engine::alloc_domain::AllocDomainError;
    let err = AllocDomainError::BudgetOverflow;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::AllocationDomainBudgetError
    );
}

#[test]
fn has_error_code_gc_heap_not_found() {
    use frankenengine_engine::gc::GcError;
    let err = GcError::HeapNotFound {
        extension_id: "ext-1".into(),
    };
    assert_eq!(err.error_code(), FrankenErrorCode::GarbageCollectionError);
}

#[test]
fn has_error_code_proof_empty_stream() {
    use frankenengine_engine::mmr_proof::ProofError;
    let err = ProofError::EmptyStream;
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::MerkleProofVerificationError
    );
}

#[test]
fn has_error_code_detector_unknown_metric_stream() {
    use frankenengine_engine::regime_detector::DetectorError;
    let err = DetectorError::UnknownMetricStream {
        stream: "s-1".into(),
    };
    assert_eq!(err.error_code(), FrankenErrorCode::RegimeDetectionError);
}

#[test]
fn has_error_code_monotonicity_violation() {
    use frankenengine_engine::security_epoch::{MonotonicityViolation, SecurityEpoch};
    let err = MonotonicityViolation {
        current: SecurityEpoch::from_raw(5),
        attempted: SecurityEpoch::from_raw(3),
    };
    assert_eq!(
        err.error_code(),
        FrankenErrorCode::EpochMonotonicityViolation
    );
}

#[test]
fn has_error_code_fork_persistence_failed() {
    use frankenengine_engine::fork_detection::ForkError;
    let err = ForkError::PersistenceFailed {
        detail: "disk full".into(),
    };
    assert_eq!(err.error_code(), FrankenErrorCode::ForkDetectionError);
}

// ===========================================================================
// Integration: registry as machine-readable JSON
// ===========================================================================

#[test]
fn registry_json_pretty_is_valid() {
    let registry = error_code_registry();
    let json = serde_json::to_string_pretty(&registry).unwrap();
    let back: ErrorCodeRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries.len(), ALL_ERROR_CODES.len());
}

#[test]
fn registry_entries_subsystem_matches_numeric_range() {
    let registry = error_code_registry();
    for entry in &registry.entries {
        assert!(
            entry.subsystem.includes(entry.numeric),
            "entry {} numeric {} not in subsystem {:?}",
            entry.code,
            entry.numeric,
            entry.subsystem
        );
    }
}

#[test]
fn registry_json_contains_all_stable_codes() {
    let registry = error_code_registry();
    let json = serde_json::to_string(&registry).unwrap();
    for code in ALL_ERROR_CODES {
        let stable = code.stable_code();
        assert!(
            json.contains(&stable),
            "registry JSON missing code {stable}"
        );
    }
}
