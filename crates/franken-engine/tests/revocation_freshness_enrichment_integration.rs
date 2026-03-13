//! Enrichment integration tests for the `revocation_freshness` module.
//!
//! Covers: FreshnessState ordering/Copy/Hash, OperationType ordering/Copy/Hash,
//! DegradedDenial std::error::Error, OverrideError std::error::Error, Debug
//! uniqueness for all types, override preimage determinism, zone-dependent
//! override IDs, boundary edge cases, DegradedModeDecisionEvent serde with
//! populated override fields, recovering-state denials, config-driven behavior.

#![forbid(unsafe_code)]
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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_freshness::{
    DegradedDenial, DegradedModeDecisionEvent, DegradedModeOverride, FreshnessConfig,
    FreshnessDecision, FreshnessState, FreshnessStateChangeEvent, OperationType, OverrideError,
    RevocationFreshnessController,
};
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn operator_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
        0xBD, 0xBE, 0xBF, 0xC0,
    ])
}

fn make_config() -> FreshnessConfig {
    let mut authorized = BTreeSet::new();
    authorized.insert("ops-admin-01".to_string());

    let mut override_eligible = BTreeSet::new();
    override_eligible.insert(OperationType::ExtensionActivation);
    override_eligible.insert(OperationType::TokenAcceptance);

    FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 10,
        override_eligible,
        authorized_operators: authorized,
    }
}

fn make_controller() -> RevocationFreshnessController {
    RevocationFreshnessController::new(make_config(), "test-zone")
}

fn make_override(operation: OperationType, expiry_tick: u64) -> DegradedModeOverride {
    let sk = operator_key();
    DegradedModeOverride::create(
        operation,
        "ops-admin-01",
        "emergency deploy",
        DeterministicTimestamp(expiry_tick),
        "test-zone",
        &sk,
    )
}

// =========================================================================
// A. FreshnessState — ordering, Copy, Hash
// =========================================================================

#[test]
fn enrichment_freshness_state_ordering_all_pairs() {
    let states = [
        FreshnessState::Fresh,
        FreshnessState::Stale,
        FreshnessState::Degraded,
        FreshnessState::Recovering,
    ];
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert!(states[i] < states[j], "{:?} should be < {:?}", states[i], states[j]);
        }
    }
}

#[test]
fn enrichment_freshness_state_copy_preserves_value() {
    let a = FreshnessState::Degraded;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_freshness_state_hash_distinct_per_variant() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let states = [
        FreshnessState::Fresh,
        FreshnessState::Stale,
        FreshnessState::Degraded,
        FreshnessState::Recovering,
    ];
    let hashes: BTreeSet<u64> = states
        .iter()
        .map(|s| {
            let mut h = DefaultHasher::new();
            s.hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(hashes.len(), 4);
}

// =========================================================================
// B. OperationType — ordering, Copy, Hash
// =========================================================================

#[test]
fn enrichment_operation_type_ordering_all_pairs() {
    let ops = [
        OperationType::SafeOperation,
        OperationType::TokenAcceptance,
        OperationType::ExtensionActivation,
        OperationType::HighRiskOperation,
        OperationType::HealthCheck,
    ];
    for i in 0..ops.len() {
        for j in (i + 1)..ops.len() {
            assert!(ops[i] < ops[j], "{:?} should be < {:?}", ops[i], ops[j]);
        }
    }
}

#[test]
fn enrichment_operation_type_copy_preserves_value() {
    let a = OperationType::HighRiskOperation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_operation_type_hash_distinct_per_variant() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ops = [
        OperationType::SafeOperation,
        OperationType::TokenAcceptance,
        OperationType::ExtensionActivation,
        OperationType::HighRiskOperation,
        OperationType::HealthCheck,
    ];
    let hashes: BTreeSet<u64> = ops
        .iter()
        .map(|o| {
            let mut h = DefaultHasher::new();
            o.hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(hashes.len(), 5);
}

// =========================================================================
// C. DegradedDenial — std::error::Error
// =========================================================================

#[test]
fn enrichment_degraded_denial_error_trait() {
    let denial = DegradedDenial {
        operation_type: OperationType::TokenAcceptance,
        local_head_seq: 0,
        expected_head_seq: 10,
        staleness_gap: 10,
    };
    let err: &dyn std::error::Error = &denial;
    assert!(err.source().is_none());
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_degraded_denial_display_contains_all_fields() {
    let denial = DegradedDenial {
        operation_type: OperationType::ExtensionActivation,
        local_head_seq: 42,
        expected_head_seq: 99,
        staleness_gap: 57,
    };
    let s = denial.to_string();
    assert!(s.contains("extension_activation"));
    assert!(s.contains("42"));
    assert!(s.contains("99"));
    assert!(s.contains("57"));
}

// =========================================================================
// D. OverrideError — std::error::Error, all Display variants
// =========================================================================

#[test]
fn enrichment_override_error_all_variants_error_trait() {
    let errors: Vec<OverrideError> = vec![
        OverrideError::Expired {
            expiry: DeterministicTimestamp(100),
            current: DeterministicTimestamp(200),
        },
        OverrideError::OperationMismatch {
            requested: OperationType::TokenAcceptance,
            override_type: OperationType::ExtensionActivation,
        },
        OverrideError::SignatureInvalid {
            detail: "corrupt key".to_string(),
        },
        OverrideError::UnauthorizedOperator {
            operator_id: "rogue-op".to_string(),
        },
        OverrideError::NotDegraded {
            current_state: FreshnessState::Fresh,
        },
    ];
    for err in &errors {
        let dyn_err: &dyn std::error::Error = err;
        assert!(dyn_err.source().is_none());
        assert!(!dyn_err.to_string().is_empty());
    }
}

#[test]
fn enrichment_override_error_display_strings_distinct() {
    let errors: Vec<OverrideError> = vec![
        OverrideError::Expired {
            expiry: DeterministicTimestamp(100),
            current: DeterministicTimestamp(200),
        },
        OverrideError::OperationMismatch {
            requested: OperationType::TokenAcceptance,
            override_type: OperationType::ExtensionActivation,
        },
        OverrideError::SignatureInvalid {
            detail: "corrupt key".to_string(),
        },
        OverrideError::UnauthorizedOperator {
            operator_id: "rogue-op".to_string(),
        },
        OverrideError::NotDegraded {
            current_state: FreshnessState::Fresh,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// =========================================================================
// E. Debug formatting — all types produce distinct strings
// =========================================================================

#[test]
fn enrichment_debug_freshness_state_distinct() {
    let states = [
        FreshnessState::Fresh,
        FreshnessState::Stale,
        FreshnessState::Degraded,
        FreshnessState::Recovering,
    ];
    let debugs: BTreeSet<String> = states.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_debug_operation_type_distinct() {
    let ops = [
        OperationType::SafeOperation,
        OperationType::TokenAcceptance,
        OperationType::ExtensionActivation,
        OperationType::HighRiskOperation,
        OperationType::HealthCheck,
    ];
    let debugs: BTreeSet<String> = ops.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", FreshnessState::Fresh).is_empty());
    assert!(!format!("{:?}", OperationType::SafeOperation).is_empty());
    assert!(
        !format!(
            "{:?}",
            DegradedDenial {
                operation_type: OperationType::TokenAcceptance,
                local_head_seq: 0,
                expected_head_seq: 5,
                staleness_gap: 5,
            }
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            OverrideError::NotDegraded {
                current_state: FreshnessState::Fresh,
            }
        )
        .is_empty()
    );
    assert!(!format!("{:?}", FreshnessConfig::default()).is_empty());
    let ctrl = make_controller();
    assert!(!format!("{ctrl:?}").is_empty());
}

// =========================================================================
// F. Override — zone-dependent IDs
// =========================================================================

#[test]
fn enrichment_override_different_zones_produce_different_ids() {
    let sk = operator_key();
    let t1 = DegradedModeOverride::create(
        OperationType::ExtensionActivation,
        "ops-admin-01",
        "emergency",
        DeterministicTimestamp(2000),
        "zone-alpha",
        &sk,
    );
    let t2 = DegradedModeOverride::create(
        OperationType::ExtensionActivation,
        "ops-admin-01",
        "emergency",
        DeterministicTimestamp(2000),
        "zone-beta",
        &sk,
    );
    assert_ne!(t1.override_id, t2.override_id);
}

#[test]
fn enrichment_override_same_params_same_id() {
    let t1 = make_override(OperationType::ExtensionActivation, 5000);
    let t2 = make_override(OperationType::ExtensionActivation, 5000);
    assert_eq!(t1.override_id, t2.override_id);
    assert_eq!(t1.signature, t2.signature);
}

// =========================================================================
// G. Recovering state — denies revocation-dependent operations
// =========================================================================

#[test]
fn enrichment_recovering_denies_token_acceptance() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    let result = ctrl.evaluate(OperationType::TokenAcceptance, "t-rec-ta");
    assert!(result.is_err());
}

#[test]
fn enrichment_recovering_allows_safe_and_health() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    assert!(ctrl.evaluate(OperationType::SafeOperation, "t-rec-safe").is_ok());
    assert!(ctrl.evaluate(OperationType::HealthCheck, "t-rec-hc").is_ok());
}

// =========================================================================
// H. DegradedModeDecisionEvent — serde with override fields populated
// =========================================================================

#[test]
fn enrichment_decision_event_serde_with_override_fields() {
    let event = DegradedModeDecisionEvent {
        operation_type: OperationType::ExtensionActivation,
        outcome: "override_granted".to_string(),
        local_head_seq: 50,
        expected_head_seq: 60,
        override_id: Some(EngineObjectId([0xAA; 32])),
        operator_id: Some("ops-admin-01".to_string()),
        trace_id: "t-override".to_string(),
        timestamp: DeterministicTimestamp(1000),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: DegradedModeDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_decision_event_serde_without_override_fields() {
    let event = DegradedModeDecisionEvent {
        operation_type: OperationType::TokenAcceptance,
        outcome: "denied".to_string(),
        local_head_seq: 0,
        expected_head_seq: 10,
        override_id: None,
        operator_id: None,
        trace_id: "t-deny".to_string(),
        timestamp: DeterministicTimestamp(500),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: DegradedModeDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// I. FreshnessStateChangeEvent — serde roundtrip
// =========================================================================

#[test]
fn enrichment_state_change_event_serde_roundtrip() {
    let event = FreshnessStateChangeEvent {
        from_state: FreshnessState::Stale,
        to_state: FreshnessState::Degraded,
        local_head_seq: 5,
        expected_head_seq: 20,
        staleness_gap: 15,
        threshold: 5,
        trace_id: "t-transition".to_string(),
        timestamp: DeterministicTimestamp(777),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: FreshnessStateChangeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// J. Config-driven behavior — custom thresholds
// =========================================================================

#[test]
fn enrichment_custom_staleness_threshold_controls_degraded_transition() {
    let config = FreshnessConfig {
        staleness_threshold: 100,
        holdoff_ticks: 5,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "custom-zone");

    // Gap of 50 stays stale (threshold 100)
    ctrl.update_expected_head(50, "t-stale");
    assert_eq!(ctrl.state(), FreshnessState::Stale);

    // Gap of 101 degrades
    ctrl.update_expected_head(101, "t-degrade");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);
}

#[test]
fn enrichment_custom_holdoff_ticks_controls_recovery_duration() {
    let config = FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 3,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::new(),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "holdoff-zone");
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // holdoff_ticks = 3, so tick 103 should transition to Fresh
    ctrl.set_tick(103);
    ctrl.check_freshness("t-holdoff");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
}

// =========================================================================
// K. FreshnessDecision — serde all variants
// =========================================================================

#[test]
fn enrichment_freshness_decision_serde_proceed() {
    let d = FreshnessDecision::Proceed;
    let json = serde_json::to_string(&d).unwrap();
    let restored: FreshnessDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn enrichment_freshness_decision_serde_denied() {
    let d = FreshnessDecision::Denied(DegradedDenial {
        operation_type: OperationType::HighRiskOperation,
        local_head_seq: 10,
        expected_head_seq: 50,
        staleness_gap: 40,
    });
    let json = serde_json::to_string(&d).unwrap();
    let restored: FreshnessDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn enrichment_freshness_decision_serde_override_granted() {
    let d = FreshnessDecision::OverrideGranted {
        override_id: EngineObjectId([0xBB; 32]),
        operator_id: "admin".to_string(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: FreshnessDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

// =========================================================================
// L. Controller — config and zone accessors
// =========================================================================

#[test]
fn enrichment_controller_config_accessor() {
    let ctrl = make_controller();
    let config = ctrl.config();
    assert_eq!(config.staleness_threshold, 5);
    assert_eq!(config.holdoff_ticks, 10);
}

#[test]
fn enrichment_controller_zone_accessor() {
    let ctrl = RevocationFreshnessController::new(FreshnessConfig::default(), "my-zone");
    assert_eq!(ctrl.zone(), "my-zone");
}

// =========================================================================
// M. Boundary — holdoff expires exactly at boundary tick
// =========================================================================

#[test]
fn enrichment_holdoff_expires_at_exact_boundary() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // holdoff_ticks = 10, recovery started at tick 100
    // At tick 109 (one before), still recovering
    ctrl.set_tick(109);
    ctrl.check_freshness("t-before");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // At tick 110, should transition to Fresh
    ctrl.set_tick(110);
    ctrl.check_freshness("t-at");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
}

// =========================================================================
// N. Multiple override grants accumulate outcome counts
// =========================================================================

#[test]
fn enrichment_multiple_overrides_count_accumulation() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    ctrl.update_expected_head(10, "t-degrade");

    let vk = operator_key().verification_key();

    // Two overrides
    let t1 = make_override(OperationType::ExtensionActivation, 2000);
    ctrl.evaluate_with_override(OperationType::ExtensionActivation, &t1, &vk, "t-ov1")
        .unwrap();

    let t2 = make_override(OperationType::TokenAcceptance, 2000);
    ctrl.evaluate_with_override(OperationType::TokenAcceptance, &t2, &vk, "t-ov2")
        .unwrap();

    let counts = ctrl.outcome_counts();
    assert_eq!(counts.get("override_granted"), Some(&2));
}

// =========================================================================
// O. State transition events — count matches transitions
// =========================================================================

#[test]
fn enrichment_state_events_count_matches_transitions() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);

    // Fresh -> Stale (1 transition)
    ctrl.update_expected_head(3, "t-stale");
    // Stale -> Degraded (gap increases past threshold) — need to push past threshold
    ctrl.update_expected_head(10, "t-degrade");
    // 2 transitions so far: Fresh->Stale, Stale->Degraded

    let events = ctrl.drain_state_events();
    // Fresh->Stale then Stale->Degraded when gap went to 3,
    // then when gap went to 10 the second call triggers Stale->Degraded
    // Actually first call: gap 3, Fresh->Stale. Second call: gap 10, Stale->Degraded.
    // Wait, the first call pushes to Stale with gap=3 (below threshold 5).
    // Second call: expected=10, gap=10, reevaluate Stale with gap 10 > threshold 5 -> Degraded.
    assert!(events.len() >= 2);
    assert_eq!(events[0].from_state, FreshnessState::Fresh);
    assert_eq!(events[0].to_state, FreshnessState::Stale);
}

// =========================================================================
// P. FreshnessConfig — empty override_eligible means no overrides possible
// =========================================================================

#[test]
fn enrichment_empty_override_eligible_rejects_all_overrides() {
    let config = FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 10,
        override_eligible: BTreeSet::new(),
        authorized_operators: BTreeSet::from(["ops-admin-01".to_string()]),
    };
    let mut ctrl = RevocationFreshnessController::new(config, "test-zone");
    ctrl.set_tick(1000);
    ctrl.update_expected_head(10, "t-degrade");

    let token = make_override(OperationType::ExtensionActivation, 2000);
    let vk = operator_key().verification_key();

    let result =
        ctrl.evaluate_with_override(OperationType::ExtensionActivation, &token, &vk, "t-no-ov");
    assert!(result.is_err());
}

// =========================================================================
// Q. Clone independence — DegradedDenial, OverrideError, FreshnessConfig
// =========================================================================

#[test]
fn enrichment_degraded_denial_clone_independence() {
    let a = DegradedDenial {
        operation_type: OperationType::HighRiskOperation,
        local_head_seq: 100,
        expected_head_seq: 200,
        staleness_gap: 100,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_override_error_clone_independence() {
    let a = OverrideError::UnauthorizedOperator {
        operator_id: "test-op".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_freshness_config_clone_independence() {
    let a = make_config();
    let b = a.clone();
    assert_eq!(a, b);
}
