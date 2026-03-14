#![forbid(unsafe_code)]

//! Enrichment integration tests for native_addon_membrane module.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::native_addon_membrane::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ── AddonAbi ────────────────────────────────────────────────────────────

#[test]
fn enrichment_addon_abi_copy_semantics() {
    let a = AddonAbi::NodeApi;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_addon_abi_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in AddonAbi::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
    for v in AddonAbi::ALL {
        assert!(!set.insert(*v));
    }
}

#[test]
fn enrichment_addon_abi_debug_all_unique() {
    let debugs: BTreeSet<String> = AddonAbi::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_addon_abi_display_all_unique() {
    let displays: BTreeSet<String> = AddonAbi::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_addon_abi_as_str_matches_display() {
    for v in AddonAbi::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── HandleKind ──────────────────────────────────────────────────────────

#[test]
fn enrichment_handle_kind_copy_semantics() {
    let a = HandleKind::ValueHandle;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_handle_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in HandleKind::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_handle_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = HandleKind::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_handle_kind_display_all_unique() {
    let displays: BTreeSet<String> = HandleKind::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_handle_kind_as_str_matches_display() {
    for v in HandleKind::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── HandleState ─────────────────────────────────────────────────────────

#[test]
fn enrichment_handle_state_copy_semantics() {
    let a = HandleState::Active;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_handle_state_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in HandleState::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_handle_state_debug_all_unique() {
    let debugs: BTreeSet<String> = HandleState::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_handle_state_display_all_unique() {
    let displays: BTreeSet<String> = HandleState::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_handle_state_as_str_matches_display() {
    for v in HandleState::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_handle_state_only_active_is_live() {
    for v in HandleState::ALL {
        if *v == HandleState::Active {
            assert!(v.is_live());
        } else {
            assert!(!v.is_live());
        }
    }
}

// ── CrashContainmentMode ────────────────────────────────────────────────

#[test]
fn enrichment_crash_containment_copy_semantics() {
    let a = CrashContainmentMode::Isolate;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_crash_containment_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in CrashContainmentMode::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_crash_containment_debug_all_unique() {
    let debugs: BTreeSet<String> = CrashContainmentMode::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_crash_containment_display_all_unique() {
    let displays: BTreeSet<String> = CrashContainmentMode::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_crash_containment_as_str_matches_display() {
    for v in CrashContainmentMode::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── CapabilityKind ──────────────────────────────────────────────────────

#[test]
fn enrichment_capability_kind_copy_semantics() {
    let a = CapabilityKind::ReadFs;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_capability_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in CapabilityKind::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_capability_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = CapabilityKind::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 8);
}

#[test]
fn enrichment_capability_kind_display_all_unique() {
    let displays: BTreeSet<String> = CapabilityKind::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_capability_kind_as_str_matches_display() {
    for v in CapabilityKind::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── ViolationKind ───────────────────────────────────────────────────────

#[test]
fn enrichment_violation_kind_copy_semantics() {
    let a = ViolationKind::CrashDetected;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_violation_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in ViolationKind::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_violation_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = ViolationKind::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_violation_kind_display_all_unique() {
    let displays: BTreeSet<String> = ViolationKind::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_violation_kind_as_str_matches_display() {
    for v in ViolationKind::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── MembraneVerdict ─────────────────────────────────────────────────────

#[test]
fn enrichment_membrane_verdict_copy_semantics() {
    let a = MembraneVerdict::Healthy;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_membrane_verdict_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in MembraneVerdict::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_membrane_verdict_debug_all_unique() {
    let debugs: BTreeSet<String> = MembraneVerdict::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_membrane_verdict_display_all_unique() {
    let displays: BTreeSet<String> = MembraneVerdict::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_membrane_verdict_as_str_matches_display() {
    for v in MembraneVerdict::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_membrane_verdict_exactly_two_operational() {
    let count = MembraneVerdict::ALL
        .iter()
        .filter(|v| v.is_operational())
        .count();
    assert_eq!(count, 2);
}

// ── RouteDecision ───────────────────────────────────────────────────────

#[test]
fn enrichment_route_decision_clone_independence() {
    let a = RouteDecision::FastPath;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_route_decision_debug_all_unique() {
    let variants = [
        RouteDecision::FastPath,
        RouteDecision::SlowPath,
        RouteDecision::Fallback,
        RouteDecision::Deny {
            reason: "test".into(),
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_route_decision_display_deny_contains_reason() {
    let d = RouteDecision::Deny {
        reason: "blocked".into(),
    };
    assert!(d.to_string().contains("blocked"));
}

#[test]
fn enrichment_route_decision_is_allowed_for_non_deny() {
    assert!(RouteDecision::FastPath.is_allowed());
    assert!(RouteDecision::SlowPath.is_allowed());
    assert!(RouteDecision::Fallback.is_allowed());
    assert!(!RouteDecision::Deny { reason: "x".into() }.is_allowed());
}

#[test]
fn enrichment_route_decision_is_fast_path() {
    assert!(RouteDecision::FastPath.is_fast_path());
    assert!(!RouteDecision::SlowPath.is_fast_path());
    assert!(!RouteDecision::Fallback.is_fast_path());
}

// ── HandleRecord ────────────────────────────────────────────────────────

#[test]
fn enrichment_handle_record_clone_independence() {
    let a = HandleRecord::new(1, HandleKind::ValueHandle, "scope-a", epoch());
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_handle_record_json_field_names() {
    let r = HandleRecord::new(1, HandleKind::BufferHandle, "scope-a", epoch());
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "id",
        "kind",
        "state",
        "owner_scope",
        "creation_epoch",
        "content_hash",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_handle_record_debug_nonempty() {
    let r = HandleRecord::new(1, HandleKind::ValueHandle, "scope-a", epoch());
    let d = format!("{r:?}");
    assert!(!d.is_empty());
    assert!(d.contains("HandleRecord"));
}

#[test]
fn enrichment_handle_record_new_is_active() {
    let r = HandleRecord::new(1, HandleKind::ValueHandle, "scope-a", epoch());
    assert_eq!(r.state, HandleState::Active);
    assert!(r.state.is_live());
}

#[test]
fn enrichment_handle_record_content_hash_deterministic() {
    let a = HandleRecord::new(42, HandleKind::CallbackHandle, "scope-x", epoch());
    let b = HandleRecord::new(42, HandleKind::CallbackHandle, "scope-x", epoch());
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_handle_record_content_hash_differs_by_id() {
    let a = HandleRecord::new(1, HandleKind::ValueHandle, "scope-a", epoch());
    let b = HandleRecord::new(2, HandleKind::ValueHandle, "scope-a", epoch());
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_handle_record_seal_changes_hash() {
    let mut r = HandleRecord::new(1, HandleKind::ValueHandle, "scope-a", epoch());
    let original = r.content_hash;
    r.state = HandleState::Revoked;
    r.seal();
    assert_ne!(r.content_hash, original);
}

// ── MembranePolicy ──────────────────────────────────────────────────────

#[test]
fn enrichment_membrane_policy_clone_independence() {
    let a = MembranePolicy::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_membrane_policy_json_field_names() {
    let p = MembranePolicy::default();
    let v: serde_json::Value = serde_json::to_value(&p).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "max_active_handles",
        "max_handle_age_micros",
        "allow_external_handles",
        "allow_callback_escape",
        "crash_containment_mode",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 5);
}

#[test]
fn enrichment_membrane_policy_debug_nonempty() {
    let p = MembranePolicy::default();
    let d = format!("{p:?}");
    assert!(!d.is_empty());
    assert!(d.contains("MembranePolicy"));
}

#[test]
fn enrichment_membrane_policy_default_matches_constants() {
    let p = MembranePolicy::default();
    assert_eq!(p.max_active_handles, DEFAULT_MAX_ACTIVE_HANDLES);
    assert_eq!(p.max_handle_age_micros, DEFAULT_MAX_HANDLE_AGE_MICROS);
    assert_eq!(p.crash_containment_mode, DEFAULT_CRASH_CONTAINMENT);
    assert!(!p.allow_external_handles);
    assert!(!p.allow_callback_escape);
}

// ── RoutingConfig ───────────────────────────────────────────────────────

#[test]
fn enrichment_routing_config_clone_independence() {
    let a = RoutingConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_routing_config_json_field_names() {
    let c = RoutingConfig::default();
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "fast_path_max_latency_micros",
        "fast_path_allowed_abis",
        "fallback_threshold_failures",
        "deny_unregistered",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn enrichment_routing_config_default_matches_constants() {
    let c = RoutingConfig::default();
    assert_eq!(
        c.fast_path_max_latency_micros,
        DEFAULT_FAST_PATH_MAX_LATENCY_MICROS
    );
    assert_eq!(
        c.fallback_threshold_failures,
        DEFAULT_FALLBACK_THRESHOLD_FAILURES
    );
    assert!(c.deny_unregistered);
    assert!(c.fast_path_allowed_abis.contains(&AddonAbi::NodeApi));
    assert!(c.fast_path_allowed_abis.contains(&AddonAbi::WasiPreview1));
}

// ── AddonRegistration ───────────────────────────────────────────────────

#[test]
fn enrichment_addon_registration_clone_independence() {
    let hash = ContentHash::compute(b"addon-binary");
    let a = AddonRegistration::new(
        "test-addon",
        AddonAbi::NodeApi,
        hash,
        BTreeSet::from([CapabilityKind::ReadFs, CapabilityKind::Buffer]),
        epoch(),
    );
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_addon_registration_json_field_names() {
    let hash = ContentHash::compute(b"addon-binary");
    let r = AddonRegistration::new(
        "test",
        AddonAbi::WasiPreview1,
        hash,
        BTreeSet::new(),
        epoch(),
    );
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "addon_id",
        "abi",
        "content_hash",
        "capabilities",
        "registered_epoch",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 5);
}

// ── Violation ───────────────────────────────────────────────────────────

#[test]
fn enrichment_violation_clone_independence() {
    let a = Violation::new(ViolationKind::CrashDetected, "addon-1", "segfault", 1_000);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_violation_json_field_names() {
    let v = Violation::new(ViolationKind::HandleEscaped, "a", "detail", 500);
    let val: serde_json::Value = serde_json::to_value(&v).unwrap();
    let obj = val.as_object().unwrap();
    for key in &["kind", "addon_id", "detail", "timestamp_micros"] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 4);
}

// ── MembraneError ───────────────────────────────────────────────────────

#[test]
fn enrichment_membrane_error_display_all_unique() {
    let errors: Vec<MembraneError> = vec![
        MembraneError::HandleLimitExceeded { detail: "x".into() },
        MembraneError::HandleNotFound { handle_id: 1 },
        MembraneError::HandleAlreadyRevoked { handle_id: 2 },
        MembraneError::HandleAlreadyFinalized { handle_id: 3 },
        MembraneError::AddonNotRegistered {
            addon_id: "a".into(),
        },
        MembraneError::AddonAlreadyRegistered {
            addon_id: "b".into(),
        },
        MembraneError::ExternalHandlesNotAllowed,
        MembraneError::CallbackEscapeNotAllowed,
        MembraneError::MembraneShutDown,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn enrichment_membrane_error_is_std_error() {
    let err = MembraneError::MembraneShutDown;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_membrane_error_clone_independence() {
    let a = MembraneError::HandleNotFound { handle_id: 42 };
    let b = a.clone();
    assert_eq!(a, b);
}

// ── MembraneState ───────────────────────────────────────────────────────

#[test]
fn enrichment_membrane_state_new_is_empty() {
    let state = MembraneState::new();
    assert_eq!(state.registrations.len(), 0);
    assert_eq!(state.handle_table.len(), 0);
    assert_eq!(state.active_handles, 0);
    assert_eq!(state.crash_count, 0);
}

#[test]
fn enrichment_membrane_state_clone_independence() {
    let a = MembraneState::new();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_membrane_state_debug_nonempty() {
    let s = MembraneState::new();
    let d = format!("{s:?}");
    assert!(!d.is_empty());
    assert!(d.contains("MembraneState"));
}

#[test]
fn enrichment_membrane_state_register_addon() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"addon");
    state
        .register_addon(AddonRegistration::new(
            "test",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::from([CapabilityKind::ReadFs]),
            epoch(),
        ))
        .unwrap();
    assert_eq!(state.registrations.len(), 1);
}

#[test]
fn enrichment_membrane_state_register_duplicate_errors() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"addon");
    let reg = AddonRegistration::new("dup", AddonAbi::NodeApi, hash, BTreeSet::new(), epoch());
    state.register_addon(reg.clone()).unwrap();
    let err = state.register_addon(reg).unwrap_err();
    assert!(matches!(err, MembraneError::AddonAlreadyRegistered { .. }));
}

#[test]
fn enrichment_membrane_state_allocate_handle() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"addon-a");
    state
        .register_addon(AddonRegistration::new(
            "scope-a",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::new(),
            epoch(),
        ))
        .unwrap();
    let policy = MembranePolicy::default();
    let handle = state.allocate_handle("scope-a", HandleKind::ValueHandle, epoch(), &policy);
    assert!(handle.is_ok());
    assert_eq!(state.active_handles, 1);
    assert_eq!(state.handle_table.len(), 1);
}

#[test]
fn enrichment_membrane_state_revoke_handle() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"addon-b");
    state
        .register_addon(AddonRegistration::new(
            "scope-a",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::new(),
            epoch(),
        ))
        .unwrap();
    let policy = MembranePolicy::default();
    let id = state
        .allocate_handle("scope-a", HandleKind::ValueHandle, epoch(), &policy)
        .unwrap();
    state.revoke_handle(id).unwrap();
    assert_eq!(state.active_handles, 0);
    assert_eq!(state.revoked_handles, 1);
}

#[test]
fn enrichment_membrane_state_revoke_missing_handle_errors() {
    let mut state = MembraneState::new();
    let err = state.revoke_handle(999).unwrap_err();
    assert!(matches!(err, MembraneError::HandleNotFound { .. }));
}

// ── evaluate_membrane ───────────────────────────────────────────────────

#[test]
fn enrichment_evaluate_membrane_empty_state_healthy() {
    let state = MembraneState::new();
    let report = evaluate_membrane(&state, &MembranePolicy::default(), &epoch(), 1_000_000);
    assert_eq!(report.verdict, MembraneVerdict::Healthy);
    assert_eq!(report.active_handles, 0);
    assert_eq!(report.crash_count, 0);
}

#[test]
fn enrichment_evaluate_membrane_report_serde_roundtrip() {
    let state = MembraneState::new();
    let report = evaluate_membrane(&state, &MembranePolicy::default(), &epoch(), 1_000_000);
    let json = serde_json::to_string(&report).unwrap();
    let back: MembraneReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ── compute_state_hash ──────────────────────────────────────────────────

#[test]
fn enrichment_compute_state_hash_deterministic() {
    let state = MembraneState::new();
    let a = compute_state_hash(&state);
    let b = compute_state_hash(&state);
    assert_eq!(a, b);
}

#[test]
fn enrichment_compute_state_hash_changes_with_registration() {
    let s1 = MembraneState::new();
    let h1 = compute_state_hash(&s1);
    let mut s2 = MembraneState::new();
    let hash = ContentHash::compute(b"addon");
    s2.register_addon(AddonRegistration::new(
        "test",
        AddonAbi::NodeApi,
        hash,
        BTreeSet::new(),
        epoch(),
    ))
    .unwrap();
    let h2 = compute_state_hash(&s2);
    assert_ne!(h1, h2);
}

// ── addon_has_capability ────────────────────────────────────────────────

#[test]
fn enrichment_addon_has_capability_registered() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"addon");
    state
        .register_addon(AddonRegistration::new(
            "test",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::from([CapabilityKind::ReadFs, CapabilityKind::Crypto]),
            epoch(),
        ))
        .unwrap();
    assert!(addon_has_capability(&state, "test", CapabilityKind::ReadFs));
    assert!(addon_has_capability(&state, "test", CapabilityKind::Crypto));
    assert!(!addon_has_capability(
        &state,
        "test",
        CapabilityKind::Network
    ));
}

#[test]
fn enrichment_addon_has_capability_unregistered() {
    let state = MembraneState::new();
    assert!(!addon_has_capability(
        &state,
        "unknown",
        CapabilityKind::ReadFs
    ));
}

// ── count_registrations_by_abi ──────────────────────────────────────────

#[test]
fn enrichment_count_registrations_by_abi() {
    let mut state = MembraneState::new();
    let hash = ContentHash::compute(b"a");
    state
        .register_addon(AddonRegistration::new(
            "a1",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::new(),
            epoch(),
        ))
        .unwrap();
    state
        .register_addon(AddonRegistration::new(
            "a2",
            AddonAbi::NodeApi,
            hash,
            BTreeSet::new(),
            epoch(),
        ))
        .unwrap();
    state
        .register_addon(AddonRegistration::new(
            "a3",
            AddonAbi::WasiPreview1,
            hash,
            BTreeSet::new(),
            epoch(),
        ))
        .unwrap();
    assert_eq!(count_registrations_by_abi(&state, AddonAbi::NodeApi), 2);
    assert_eq!(
        count_registrations_by_abi(&state, AddonAbi::WasiPreview1),
        1
    );
    assert_eq!(count_registrations_by_abi(&state, AddonAbi::NativeEsm), 0);
}

// ── Five-run determinism ────────────────────────────────────────────────

#[test]
fn enrichment_five_run_determinism_state_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| compute_state_hash(&MembraneState::new()))
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_evaluate_membrane() {
    let reports: Vec<_> = (0..5)
        .map(|_| {
            evaluate_membrane(
                &MembraneState::new(),
                &MembranePolicy::default(),
                &epoch(),
                1_000_000,
            )
        })
        .collect();
    for r in &reports[1..] {
        assert_eq!(reports[0], *r);
    }
}

// ── Constants stability ─────────────────────────────────────────────────

#[test]
fn enrichment_constants_stable() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.native-addon-membrane.v1");
    assert_eq!(COMPONENT, "native_addon_membrane");
    assert_eq!(BEAD_ID, "bd-1lsy.5.9.2");
    assert_eq!(POLICY_ID, "RGC-407B");
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_MAX_ACTIVE_HANDLES, 4096);
    assert_eq!(DEFAULT_CRASH_CONTAINMENT, CrashContainmentMode::Isolate);
    assert_eq!(CRASH_SHUTDOWN_THRESHOLD, 10);
    assert_eq!(CRASH_BREACHED_THRESHOLD, 3);
}
