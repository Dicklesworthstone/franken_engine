//! Integration tests for the native-addon safety membrane and fast-path
//! routing — handle discipline, crash containment, capability validation,
//! routing decisions, evaluation verdicts, decision receipts, and serde
//! roundtrips (RGC-407B).

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
use frankenengine_engine::native_addon_membrane::{
    AddonAbi, AddonRegistration, BEAD_ID, COMPONENT, CRASH_BREACHED_THRESHOLD,
    CRASH_SHUTDOWN_THRESHOLD, CapabilityKind, CrashContainmentMode,
    DEFAULT_FALLBACK_THRESHOLD_FAILURES, DEFAULT_FAST_PATH_MAX_LATENCY_MICROS,
    DEFAULT_MAX_ACTIVE_HANDLES, DEFAULT_MAX_HANDLE_AGE_MICROS, DecisionReceipt, HandleKind,
    HandleState, MILLIONTHS, MembraneError, MembranePolicy, MembraneReport, MembraneState,
    MembraneVerdict, POLICY_ID, RouteDecision, RoutingConfig, SCHEMA_VERSION, Violation,
    ViolationKind, addon_has_capability, compute_receipt, compute_state_hash,
    count_registrations_by_abi, evaluate_membrane, revoke_all_handles_for_addon,
    validate_capabilities,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_policy() -> MembranePolicy {
    MembranePolicy::default()
}

fn default_routing() -> RoutingConfig {
    RoutingConfig::default()
}

fn make_registration(addon_id: &str, abi: AddonAbi, caps: &[CapabilityKind]) -> AddonRegistration {
    AddonRegistration::new(
        addon_id,
        abi,
        ContentHash::compute(addon_id.as_bytes()),
        caps.iter().copied().collect(),
        epoch(1),
    )
}

fn make_state_with_addon(addon_id: &str) -> MembraneState {
    let mut state = MembraneState::new();
    let reg = make_registration(addon_id, AddonAbi::NodeApi, &[CapabilityKind::Buffer]);
    state.register_addon(reg).unwrap();
    state
}

fn make_state_with_addons(ids: &[&str]) -> MembraneState {
    let mut state = MembraneState::new();
    for id in ids {
        let reg = make_registration(id, AddonAbi::NodeApi, &[CapabilityKind::Buffer]);
        state.register_addon(reg).unwrap();
    }
    state
}

// ===========================================================================
// Registration tests
// ===========================================================================

#[test]
fn register_single_addon() {
    let mut s = MembraneState::new();
    let reg = make_registration("addon-a", AddonAbi::NodeApi, &[]);
    assert!(s.register_addon(reg).is_ok());
    assert_eq!(s.registrations.len(), 1);
    assert!(s.find_registration("addon-a").is_some());
}

#[test]
fn register_multiple_addons() {
    let s = make_state_with_addons(&["a", "b", "c"]);
    assert_eq!(s.registrations.len(), 3);
}

#[test]
fn register_duplicate_addon_fails() {
    let mut s = make_state_with_addon("a");
    let reg = make_registration("a", AddonAbi::WasiPreview1, &[]);
    assert!(matches!(
        s.register_addon(reg),
        Err(MembraneError::AddonAlreadyRegistered { .. })
    ));
}

#[test]
fn register_addon_after_shutdown_fails() {
    let mut s = MembraneState::new();
    s.shutdown();
    let reg = make_registration("x", AddonAbi::NodeApi, &[]);
    assert!(matches!(
        s.register_addon(reg),
        Err(MembraneError::MembraneShutDown)
    ));
}

#[test]
fn find_registration_none() {
    let s = MembraneState::new();
    assert!(s.find_registration("missing").is_none());
}

#[test]
fn registration_preserves_capabilities() {
    let mut s = MembraneState::new();
    let reg = make_registration(
        "cap-addon",
        AddonAbi::NodeApi,
        &[CapabilityKind::ReadFs, CapabilityKind::Network],
    );
    s.register_addon(reg).unwrap();
    let r = s.find_registration("cap-addon").unwrap();
    assert!(r.capabilities.contains(&CapabilityKind::ReadFs));
    assert!(r.capabilities.contains(&CapabilityKind::Network));
    assert!(!r.capabilities.contains(&CapabilityKind::WriteFs));
}

#[test]
fn registration_preserves_abi() {
    let mut s = MembraneState::new();
    let reg = make_registration("wasi-addon", AddonAbi::WasiPreview1, &[]);
    s.register_addon(reg).unwrap();
    assert_eq!(
        s.find_registration("wasi-addon").unwrap().abi,
        AddonAbi::WasiPreview1
    );
}

// ===========================================================================
// Handle allocation tests
// ===========================================================================

#[test]
fn allocate_handle_basic() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    assert_eq!(id, 1);
    assert_eq!(s.active_handles, 1);
}

#[test]
fn allocate_multiple_handles() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    for i in 1..=5 {
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
            .unwrap();
        assert_eq!(id, i);
    }
    assert_eq!(s.active_handles, 5);
    assert_eq!(s.total_handle_count(), 5);
}

#[test]
fn allocate_handle_unregistered_fails() {
    let mut s = MembraneState::new();
    let p = default_policy();
    assert!(matches!(
        s.allocate_handle("nope", HandleKind::ValueHandle, epoch(1), &p),
        Err(MembraneError::AddonNotRegistered { .. })
    ));
}

#[test]
fn allocate_external_handle_denied_by_default() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    assert!(matches!(
        s.allocate_handle("a", HandleKind::ExternalHandle, epoch(1), &p),
        Err(MembraneError::ExternalHandlesNotAllowed)
    ));
}

#[test]
fn allocate_external_handle_when_allowed() {
    let mut s = make_state_with_addon("a");
    let mut p = default_policy();
    p.allow_external_handles = true;
    assert!(
        s.allocate_handle("a", HandleKind::ExternalHandle, epoch(1), &p)
            .is_ok()
    );
}

#[test]
fn allocate_handle_at_limit_fails() {
    let mut s = make_state_with_addon("a");
    let mut p = default_policy();
    p.max_active_handles = 1;
    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    assert!(matches!(
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p),
        Err(MembraneError::HandleLimitExceeded { .. })
    ));
}

#[test]
fn allocate_handle_after_shutdown_fails() {
    let mut s = make_state_with_addon("a");
    s.shutdown();
    let p = default_policy();
    assert!(matches!(
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p),
        Err(MembraneError::MembraneShutDown)
    ));
}

#[test]
fn allocate_different_kinds() {
    let mut s = make_state_with_addon("a");
    let mut p = default_policy();
    p.allow_external_handles = true;
    for kind in HandleKind::ALL {
        assert!(s.allocate_handle("a", *kind, epoch(1), &p).is_ok());
    }
    assert_eq!(s.active_handles, 5);
}

// ===========================================================================
// Handle revocation tests
// ===========================================================================

#[test]
fn revoke_active_handle() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    assert!(s.revoke_handle(id).is_ok());
    assert_eq!(s.active_handles, 0);
    assert_eq!(s.revoked_handles, 1);
}

#[test]
fn revoke_nonexistent_handle() {
    let mut s = MembraneState::new();
    assert!(matches!(
        s.revoke_handle(999),
        Err(MembraneError::HandleNotFound { .. })
    ));
}

#[test]
fn revoke_already_revoked() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.revoke_handle(id).unwrap();
    assert!(matches!(
        s.revoke_handle(id),
        Err(MembraneError::HandleAlreadyRevoked { .. })
    ));
}

#[test]
fn revoke_finalized_handle() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.finalize_handle(id).unwrap();
    assert!(matches!(
        s.revoke_handle(id),
        Err(MembraneError::HandleAlreadyFinalized { .. })
    ));
}

#[test]
fn revoke_escaped_handle_succeeds() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.mark_handle_escaped(id, 100).unwrap();
    assert!(s.revoke_handle(id).is_ok());
    assert_eq!(s.get_handle(id).unwrap().state, HandleState::Revoked);
}

#[test]
fn revoke_after_shutdown() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.shutdown();
    assert!(matches!(
        s.revoke_handle(id),
        Err(MembraneError::MembraneShutDown)
    ));
}

// ===========================================================================
// Handle finalization tests
// ===========================================================================

#[test]
fn finalize_active_handle() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    assert!(s.finalize_handle(id).is_ok());
    assert_eq!(s.get_handle(id).unwrap().state, HandleState::Finalized);
    assert_eq!(s.active_handles, 0);
}

#[test]
fn finalize_revoked_handle() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.revoke_handle(id).unwrap();
    assert!(s.finalize_handle(id).is_ok());
}

#[test]
fn finalize_escaped_handle() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.mark_handle_escaped(id, 100).unwrap();
    assert!(s.finalize_handle(id).is_ok());
}

#[test]
fn finalize_already_finalized() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.finalize_handle(id).unwrap();
    assert!(matches!(
        s.finalize_handle(id),
        Err(MembraneError::HandleAlreadyFinalized { .. })
    ));
}

#[test]
fn finalize_after_shutdown() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.shutdown();
    assert!(matches!(
        s.finalize_handle(id),
        Err(MembraneError::MembraneShutDown)
    ));
}

// ===========================================================================
// Handle escape tests
// ===========================================================================

#[test]
fn mark_handle_escaped_basic() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::CallbackHandle, epoch(1), &p)
        .unwrap();
    assert!(s.mark_handle_escaped(id, 5000).is_ok());
    assert_eq!(s.get_handle(id).unwrap().state, HandleState::Escaped);
    assert_eq!(s.active_handles, 0);
}

#[test]
fn escape_creates_violation() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.mark_handle_escaped(id, 1000).unwrap();
    assert_eq!(s.violations.len(), 1);
    assert_eq!(s.violations[0].kind, ViolationKind::HandleEscaped);
    assert_eq!(s.violations[0].addon_id, "a");
}

#[test]
fn escape_finalized_handle_fails() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.finalize_handle(id).unwrap();
    assert!(matches!(
        s.mark_handle_escaped(id, 100),
        Err(MembraneError::HandleAlreadyFinalized { .. })
    ));
}

#[test]
fn escape_nonexistent_handle_fails() {
    let mut s = MembraneState::new();
    assert!(matches!(
        s.mark_handle_escaped(999, 100),
        Err(MembraneError::HandleNotFound { .. })
    ));
}

#[test]
fn escape_after_shutdown() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.shutdown();
    assert!(matches!(
        s.mark_handle_escaped(id, 100),
        Err(MembraneError::MembraneShutDown)
    ));
}

// ===========================================================================
// Routing tests
// ===========================================================================

#[test]
fn route_fast_path_for_node_api() {
    let mut s = make_state_with_addon("a");
    let config = default_routing();
    assert_eq!(s.route_call("a", &config), RouteDecision::FastPath);
    assert_eq!(s.fast_path_calls, 1);
    assert_eq!(s.total_calls, 1);
}

#[test]
fn route_slow_path_for_custom_ffi() {
    let mut s = MembraneState::new();
    s.register_addon(make_registration("a", AddonAbi::CustomFfi, &[]))
        .unwrap();
    let config = default_routing();
    assert_eq!(s.route_call("a", &config), RouteDecision::SlowPath);
    assert_eq!(s.slow_path_calls, 1);
}

#[test]
fn route_deny_unregistered() {
    let mut s = MembraneState::new();
    let config = default_routing();
    let d = s.route_call("missing", &config);
    assert!(matches!(d, RouteDecision::Deny { .. }));
    assert_eq!(s.denied_calls, 1);
}

#[test]
fn route_slow_path_unregistered_when_not_denied() {
    let mut s = MembraneState::new();
    let mut config = default_routing();
    config.deny_unregistered = false;
    assert_eq!(s.route_call("missing", &config), RouteDecision::SlowPath);
}

#[test]
fn route_fallback_after_failures() {
    let mut s = make_state_with_addon("a");
    for _ in 0..DEFAULT_FALLBACK_THRESHOLD_FAILURES {
        s.record_crash("a", "crash", 100);
    }
    let config = default_routing();
    assert_eq!(s.route_call("a", &config), RouteDecision::Fallback);
}

#[test]
fn route_fast_path_below_failure_threshold() {
    let mut s = make_state_with_addon("a");
    for _ in 0..(DEFAULT_FALLBACK_THRESHOLD_FAILURES - 1) {
        s.record_crash("a", "crash", 100);
    }
    let config = default_routing();
    assert_eq!(s.route_call("a", &config), RouteDecision::FastPath);
}

#[test]
fn route_wasi_on_fast_path() {
    let mut s = MembraneState::new();
    s.register_addon(make_registration("w", AddonAbi::WasiPreview1, &[]))
        .unwrap();
    let config = default_routing();
    assert_eq!(s.route_call("w", &config), RouteDecision::FastPath);
}

#[test]
fn route_native_esm_slow_path() {
    let mut s = MembraneState::new();
    s.register_addon(make_registration("e", AddonAbi::NativeEsm, &[]))
        .unwrap();
    let config = default_routing();
    assert_eq!(s.route_call("e", &config), RouteDecision::SlowPath);
}

#[test]
fn route_call_increments_total() {
    let mut s = make_state_with_addon("a");
    let config = default_routing();
    for _ in 0..10 {
        s.route_call("a", &config);
    }
    assert_eq!(s.total_calls, 10);
}

#[test]
fn route_with_custom_allowed_abis() {
    let mut s = MembraneState::new();
    s.register_addon(make_registration("a", AddonAbi::CustomFfi, &[]))
        .unwrap();
    let mut config = default_routing();
    config.fast_path_allowed_abis.insert(AddonAbi::CustomFfi);
    assert_eq!(s.route_call("a", &config), RouteDecision::FastPath);
}

// ===========================================================================
// Crash recording tests
// ===========================================================================

#[test]
fn record_crash_basic() {
    let mut s = make_state_with_addon("a");
    s.record_crash("a", "segfault", 1000);
    assert_eq!(s.crash_count, 1);
    assert_eq!(s.addon_failure_count("a"), 1);
}

#[test]
fn record_multiple_crashes() {
    let mut s = make_state_with_addon("a");
    for i in 0..5 {
        s.record_crash("a", &format!("crash-{i}"), i * 100);
    }
    assert_eq!(s.crash_count, 5);
    assert_eq!(s.addon_failure_count("a"), 5);
    assert_eq!(s.violations.len(), 5);
}

#[test]
fn crash_creates_violation() {
    let mut s = make_state_with_addon("a");
    s.record_crash("a", "boom", 42);
    assert_eq!(s.violations[0].kind, ViolationKind::CrashDetected);
    assert_eq!(s.violations[0].addon_id, "a");
    assert_eq!(s.violations[0].timestamp_micros, 42);
}

#[test]
fn crash_isolation_between_addons() {
    let mut s = make_state_with_addons(&["a", "b"]);
    s.record_crash("a", "crash", 100);
    assert_eq!(s.addon_failure_count("a"), 1);
    assert_eq!(s.addon_failure_count("b"), 0);
}

#[test]
fn reset_failure_count_basic() {
    let mut s = make_state_with_addon("a");
    s.record_crash("a", "crash", 100);
    s.record_crash("a", "crash2", 200);
    s.reset_failure_count("a");
    assert_eq!(s.addon_failure_count("a"), 0);
    // total crash count is NOT reset
    assert_eq!(s.crash_count, 2);
}

#[test]
fn failure_count_unknown_addon() {
    let s = MembraneState::new();
    assert_eq!(s.addon_failure_count("nobody"), 0);
}

// ===========================================================================
// Evaluate membrane tests
// ===========================================================================

#[test]
fn evaluate_healthy_empty_state() {
    let s = MembraneState::new();
    let p = default_policy();
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Healthy);
    assert!(r.violations.is_empty());
}

#[test]
fn evaluate_degraded_with_violation() {
    let mut s = MembraneState::new();
    s.record_violation(Violation::new(
        ViolationKind::AbiMismatch,
        "x",
        "wrong abi",
        100,
    ));
    let p = default_policy();
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Degraded);
}

#[test]
fn evaluate_breached_on_escape() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.mark_handle_escaped(id, 100).unwrap();
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Breached);
    assert!(r.escaped_handles > 0);
}

#[test]
fn evaluate_breached_on_crashes() {
    let mut s = make_state_with_addon("a");
    for i in 0..CRASH_BREACHED_THRESHOLD {
        s.record_crash("a", &format!("c{i}"), i * 100);
    }
    let p = default_policy();
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Breached);
}

#[test]
fn evaluate_shutdown_on_many_crashes() {
    let mut s = make_state_with_addon("a");
    for i in 0..CRASH_SHUTDOWN_THRESHOLD {
        s.record_crash("a", &format!("c{i}"), i * 100);
    }
    let p = default_policy();
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Shutdown);
}

#[test]
fn evaluate_report_counts() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let config = default_routing();
    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.allocate_handle("a", HandleKind::BufferHandle, epoch(1), &p)
        .unwrap();
    s.route_call("a", &config);
    s.route_call("a", &config);
    s.route_call("a", &config);
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.active_handles, 2);
    assert_eq!(r.total_calls, 3);
    assert_eq!(r.fast_path_calls, 3);
    assert_eq!(r.registered_addon_count, 1);
}

#[test]
fn evaluate_receipt_has_correct_fields() {
    let s = MembraneState::new();
    let p = default_policy();
    let r = evaluate_membrane(&s, &p, &epoch(42), 9999);
    assert_eq!(r.receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(r.receipt.component, COMPONENT);
    assert_eq!(r.receipt.bead_id, BEAD_ID);
    assert_eq!(r.receipt.policy_id, POLICY_ID);
    assert_eq!(r.receipt.epoch, epoch(42));
    assert_eq!(r.receipt.timestamp_micros, 9999);
}

#[test]
fn evaluate_includes_accumulated_violations() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    let id = s
        .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.mark_handle_escaped(id, 100).unwrap();
    s.record_crash("a", "boom", 200);
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert!(r.violations.len() >= 2);
}

#[test]
fn evaluate_deterministic() {
    let s = make_state_with_addon("a");
    let p = default_policy();
    let r1 = evaluate_membrane(&s, &p, &epoch(1), 1000);
    let r2 = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r1, r2);
}

// ===========================================================================
// Decision receipt tests
// ===========================================================================

#[test]
fn receipt_deterministic() {
    let ih = ContentHash::compute(b"test");
    let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    let r2 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    assert_eq!(r1, r2);
}

#[test]
fn receipt_varies_with_epoch() {
    let ih = ContentHash::compute(b"test");
    let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    let r2 = compute_receipt(&epoch(2), &ih, MembraneVerdict::Healthy, 1000);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_varies_with_verdict() {
    let ih = ContentHash::compute(b"test");
    let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    let r2 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Breached, 1000);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_varies_with_timestamp() {
    let ih = ContentHash::compute(b"test");
    let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    let r2 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 2000);
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_seal_is_stable() {
    let ih = ContentHash::compute(b"test");
    let mut r = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    r.seal();
    let h1 = r.verdict_hash.clone();
    r.seal();
    assert_eq!(r.verdict_hash, h1);
}

// ===========================================================================
// Capability validation tests
// ===========================================================================

#[test]
fn addon_has_capability_granted() {
    let s = make_state_with_addon("a"); // has Buffer
    assert!(addon_has_capability(&s, "a", CapabilityKind::Buffer));
}

#[test]
fn addon_has_capability_not_granted() {
    let s = make_state_with_addon("a");
    assert!(!addon_has_capability(&s, "a", CapabilityKind::Network));
}

#[test]
fn addon_has_capability_unregistered() {
    let s = MembraneState::new();
    assert!(!addon_has_capability(&s, "x", CapabilityKind::Buffer));
}

#[test]
fn validate_capabilities_all_ok() {
    let s = make_state_with_addon("a");
    let req: BTreeSet<CapabilityKind> = [CapabilityKind::Buffer].into_iter().collect();
    assert!(validate_capabilities(&s, "a", &req).is_empty());
}

#[test]
fn validate_capabilities_some_denied() {
    let s = make_state_with_addon("a");
    let req: BTreeSet<CapabilityKind> = [CapabilityKind::Buffer, CapabilityKind::Process]
        .into_iter()
        .collect();
    let denied = validate_capabilities(&s, "a", &req);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0], CapabilityKind::Process);
}

#[test]
fn validate_capabilities_unregistered_all_denied() {
    let s = MembraneState::new();
    let req: BTreeSet<CapabilityKind> = [CapabilityKind::ReadFs].into_iter().collect();
    let denied = validate_capabilities(&s, "x", &req);
    assert_eq!(denied.len(), 1);
}

// ===========================================================================
// Bulk handle operations
// ===========================================================================

#[test]
fn revoke_all_handles_for_addon_basic() {
    let mut s = make_state_with_addons(&["a", "b"]);
    let p = default_policy();
    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.allocate_handle("a", HandleKind::BufferHandle, epoch(1), &p)
        .unwrap();
    s.allocate_handle("b", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    let revoked = revoke_all_handles_for_addon(&mut s, "a");
    assert_eq!(revoked.len(), 2);
    assert_eq!(s.active_handles, 1);
}

#[test]
fn revoke_all_handles_empty() {
    let mut s = make_state_with_addon("a");
    let revoked = revoke_all_handles_for_addon(&mut s, "a");
    assert!(revoked.is_empty());
}

#[test]
fn count_registrations_by_abi_basic() {
    let mut s = MembraneState::new();
    s.register_addon(make_registration("a", AddonAbi::NodeApi, &[]))
        .unwrap();
    s.register_addon(make_registration("b", AddonAbi::NodeApi, &[]))
        .unwrap();
    s.register_addon(make_registration("c", AddonAbi::CustomFfi, &[]))
        .unwrap();
    assert_eq!(count_registrations_by_abi(&s, AddonAbi::NodeApi), 2);
    assert_eq!(count_registrations_by_abi(&s, AddonAbi::CustomFfi), 1);
    assert_eq!(count_registrations_by_abi(&s, AddonAbi::WasiPreview1), 0);
}

// ===========================================================================
// State hash tests
// ===========================================================================

#[test]
fn state_hash_deterministic() {
    let s = MembraneState::new();
    assert_eq!(compute_state_hash(&s), compute_state_hash(&s));
}

#[test]
fn state_hash_changes_with_registration() {
    let mut s = MembraneState::new();
    let h1 = compute_state_hash(&s);
    s.register_addon(make_registration("a", AddonAbi::NodeApi, &[]))
        .unwrap();
    assert_ne!(h1, compute_state_hash(&s));
}

#[test]
fn state_hash_changes_with_handle() {
    let mut s = make_state_with_addon("a");
    let h1 = compute_state_hash(&s);
    let p = default_policy();
    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    assert_ne!(h1, compute_state_hash(&s));
}

#[test]
fn state_hash_changes_with_crash() {
    let mut s = make_state_with_addon("a");
    let h1 = compute_state_hash(&s);
    s.record_crash("a", "boom", 100);
    assert_ne!(h1, compute_state_hash(&s));
}

// ===========================================================================
// Serde roundtrip tests
// ===========================================================================

#[test]
fn addon_abi_serde() {
    for abi in AddonAbi::ALL {
        let j = serde_json::to_string(abi).unwrap();
        let b: AddonAbi = serde_json::from_str(&j).unwrap();
        assert_eq!(*abi, b);
    }
}

#[test]
fn handle_kind_serde() {
    for k in HandleKind::ALL {
        let j = serde_json::to_string(k).unwrap();
        let b: HandleKind = serde_json::from_str(&j).unwrap();
        assert_eq!(*k, b);
    }
}

#[test]
fn handle_state_serde() {
    for st in HandleState::ALL {
        let j = serde_json::to_string(st).unwrap();
        let b: HandleState = serde_json::from_str(&j).unwrap();
        assert_eq!(*st, b);
    }
}

#[test]
fn crash_containment_serde() {
    for m in CrashContainmentMode::ALL {
        let j = serde_json::to_string(m).unwrap();
        let b: CrashContainmentMode = serde_json::from_str(&j).unwrap();
        assert_eq!(*m, b);
    }
}

#[test]
fn capability_kind_serde() {
    for c in CapabilityKind::ALL {
        let j = serde_json::to_string(c).unwrap();
        let b: CapabilityKind = serde_json::from_str(&j).unwrap();
        assert_eq!(*c, b);
    }
}

#[test]
fn violation_kind_serde() {
    for v in ViolationKind::ALL {
        let j = serde_json::to_string(v).unwrap();
        let b: ViolationKind = serde_json::from_str(&j).unwrap();
        assert_eq!(*v, b);
    }
}

#[test]
fn membrane_verdict_serde() {
    for v in MembraneVerdict::ALL {
        let j = serde_json::to_string(v).unwrap();
        let b: MembraneVerdict = serde_json::from_str(&j).unwrap();
        assert_eq!(*v, b);
    }
}

#[test]
fn route_decision_serde() {
    let decisions = vec![
        RouteDecision::FastPath,
        RouteDecision::SlowPath,
        RouteDecision::Fallback,
        RouteDecision::Deny {
            reason: "test".into(),
        },
    ];
    for d in &decisions {
        let j = serde_json::to_string(d).unwrap();
        let b: RouteDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(*d, b);
    }
}

#[test]
fn membrane_state_serde() {
    let mut s = make_state_with_addon("a");
    let p = default_policy();
    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.record_crash("a", "boom", 100);
    let j = serde_json::to_string(&s).unwrap();
    let b: MembraneState = serde_json::from_str(&j).unwrap();
    assert_eq!(s, b);
}

#[test]
fn membrane_policy_serde() {
    let p = default_policy();
    let j = serde_json::to_string(&p).unwrap();
    let b: MembranePolicy = serde_json::from_str(&j).unwrap();
    assert_eq!(p, b);
}

#[test]
fn routing_config_serde() {
    let r = default_routing();
    let j = serde_json::to_string(&r).unwrap();
    let b: RoutingConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(r, b);
}

#[test]
fn membrane_report_serde() {
    let s = MembraneState::new();
    let p = default_policy();
    let report = evaluate_membrane(&s, &p, &epoch(1), 1000);
    let j = serde_json::to_string(&report).unwrap();
    let b: MembraneReport = serde_json::from_str(&j).unwrap();
    assert_eq!(report, b);
}

#[test]
fn decision_receipt_serde() {
    let ih = ContentHash::compute(b"test");
    let r = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
    let j = serde_json::to_string(&r).unwrap();
    let b: DecisionReceipt = serde_json::from_str(&j).unwrap();
    assert_eq!(r, b);
}

#[test]
fn violation_serde() {
    let v = Violation::new(ViolationKind::CrashDetected, "a", "boom", 42);
    let j = serde_json::to_string(&v).unwrap();
    let b: Violation = serde_json::from_str(&j).unwrap();
    assert_eq!(v, b);
}

#[test]
fn handle_record_serde() {
    use frankenengine_engine::native_addon_membrane::HandleRecord;
    let r = HandleRecord::new(1, HandleKind::ValueHandle, "owner", epoch(1));
    let j = serde_json::to_string(&r).unwrap();
    let b: HandleRecord = serde_json::from_str(&j).unwrap();
    assert_eq!(r, b);
}

#[test]
fn addon_registration_serde() {
    let reg = make_registration("x", AddonAbi::WasiPreview1, &[CapabilityKind::Crypto]);
    let j = serde_json::to_string(&reg).unwrap();
    let b: AddonRegistration = serde_json::from_str(&j).unwrap();
    assert_eq!(reg, b);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn addon_abi_display() {
    assert_eq!(format!("{}", AddonAbi::NodeApi), "node_api");
    assert_eq!(format!("{}", AddonAbi::WasiPreview1), "wasi_preview1");
    assert_eq!(format!("{}", AddonAbi::NativeEsm), "native_esm");
    assert_eq!(format!("{}", AddonAbi::CustomFfi), "custom_ffi");
}

#[test]
fn handle_kind_display() {
    assert_eq!(format!("{}", HandleKind::ValueHandle), "value_handle");
    assert_eq!(
        format!("{}", HandleKind::TypedArrayHandle),
        "typed_array_handle"
    );
}

#[test]
fn handle_state_display() {
    assert_eq!(format!("{}", HandleState::Active), "active");
    assert_eq!(format!("{}", HandleState::Escaped), "escaped");
}

#[test]
fn crash_containment_display() {
    assert_eq!(format!("{}", CrashContainmentMode::Terminate), "terminate");
    assert_eq!(
        format!("{}", CrashContainmentMode::LogAndContinue),
        "log_and_continue"
    );
}

#[test]
fn route_decision_display() {
    assert_eq!(format!("{}", RouteDecision::FastPath), "fast_path");
    assert_eq!(
        format!(
            "{}",
            RouteDecision::Deny {
                reason: "bad".into()
            }
        ),
        "deny: bad"
    );
}

#[test]
fn capability_kind_display() {
    assert_eq!(format!("{}", CapabilityKind::ReadFs), "read_fs");
    assert_eq!(format!("{}", CapabilityKind::Buffer), "buffer");
}

#[test]
fn violation_kind_display() {
    assert_eq!(
        format!("{}", ViolationKind::HandleLimitExceeded),
        "handle_limit_exceeded"
    );
    assert_eq!(
        format!("{}", ViolationKind::UnregisteredAddon),
        "unregistered_addon"
    );
}

#[test]
fn membrane_verdict_display() {
    assert_eq!(format!("{}", MembraneVerdict::Healthy), "healthy");
    assert_eq!(format!("{}", MembraneVerdict::Shutdown), "shutdown");
}

// ===========================================================================
// Constant validation tests
// ===========================================================================

#[test]
fn constants_correct() {
    assert_eq!(BEAD_ID, "bd-1lsy.5.9.2");
    assert_eq!(POLICY_ID, "RGC-407B");
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn default_constants() {
    assert_eq!(DEFAULT_MAX_ACTIVE_HANDLES, 4096);
    assert_eq!(DEFAULT_MAX_HANDLE_AGE_MICROS, 60_000_000);
    assert_eq!(DEFAULT_FAST_PATH_MAX_LATENCY_MICROS, 1_000);
    assert_eq!(DEFAULT_FALLBACK_THRESHOLD_FAILURES, 5);
    assert!(CRASH_BREACHED_THRESHOLD < CRASH_SHUTDOWN_THRESHOLD);
}

// ===========================================================================
// MembraneVerdict edge cases
// ===========================================================================

#[test]
fn verdict_operational_check() {
    assert!(MembraneVerdict::Healthy.is_operational());
    assert!(MembraneVerdict::Degraded.is_operational());
    assert!(!MembraneVerdict::Breached.is_operational());
    assert!(!MembraneVerdict::Shutdown.is_operational());
}

// ===========================================================================
// Complex scenarios
// ===========================================================================

#[test]
fn scenario_full_lifecycle() {
    let mut s = MembraneState::new();
    let p = default_policy();
    let config = default_routing();

    // Register
    s.register_addon(make_registration(
        "addon-a",
        AddonAbi::NodeApi,
        &[CapabilityKind::Buffer, CapabilityKind::Crypto],
    ))
    .unwrap();

    // Route calls
    let d = s.route_call("addon-a", &config);
    assert_eq!(d, RouteDecision::FastPath);

    // Allocate handles
    let h1 = s
        .allocate_handle("addon-a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    let h2 = s
        .allocate_handle("addon-a", HandleKind::BufferHandle, epoch(1), &p)
        .unwrap();
    assert_eq!(s.active_handles, 2);

    // Revoke one
    s.revoke_handle(h1).unwrap();
    assert_eq!(s.active_handles, 1);

    // Finalize the other
    s.finalize_handle(h2).unwrap();
    assert_eq!(s.active_handles, 0);

    // Evaluate
    let report = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(report.verdict, MembraneVerdict::Healthy);
}

#[test]
fn scenario_crash_escalation() {
    let mut s = make_state_with_addon("unstable");
    let p = default_policy();
    let config = default_routing();

    // First few crashes: still fast path
    for i in 0..(CRASH_BREACHED_THRESHOLD - 1) {
        s.record_crash("unstable", &format!("crash-{i}"), i * 100);
    }
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Degraded);

    // One more crash: breached
    s.record_crash("unstable", "one-more", 999);
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Breached);

    // Route should now fallback
    assert_eq!(s.route_call("unstable", &config), RouteDecision::Fallback);
}

#[test]
fn scenario_multi_addon_isolation() {
    let mut s = make_state_with_addons(&["stable", "crashing", "blocked"]);
    let _p = default_policy();
    let mut config = default_routing();
    config.deny_unregistered = true;

    // crashing addon fails a lot
    for _ in 0..DEFAULT_FALLBACK_THRESHOLD_FAILURES {
        s.record_crash("crashing", "crash", 100);
    }

    // stable still gets fast path
    assert_eq!(s.route_call("stable", &config), RouteDecision::FastPath);
    // crashing gets fallback
    assert_eq!(s.route_call("crashing", &config), RouteDecision::Fallback);
    // unregistered gets denied
    assert!(matches!(
        s.route_call("unknown", &config),
        RouteDecision::Deny { .. }
    ));
}

#[test]
fn scenario_handle_escape_and_containment() {
    let mut s = make_state_with_addon("leaky");
    let p = default_policy();

    let h1 = s
        .allocate_handle("leaky", HandleKind::CallbackHandle, epoch(1), &p)
        .unwrap();
    let h2 = s
        .allocate_handle("leaky", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();

    // h1 escapes
    s.mark_handle_escaped(h1, 500).unwrap();
    assert_eq!(s.active_handles, 1);

    // Containment: revoke the escaped handle
    s.revoke_handle(h1).unwrap();

    // h2 is still active
    assert_eq!(s.get_handle(h2).unwrap().state, HandleState::Active);

    // Evaluate should still be breached (escaped handle existed)
    let r = evaluate_membrane(&s, &p, &epoch(1), 1000);
    assert_eq!(r.verdict, MembraneVerdict::Breached);
}

#[test]
fn scenario_recovery_after_failures() {
    let mut s = make_state_with_addon("recovering");
    let config = default_routing();

    // Fail up to threshold
    for _ in 0..DEFAULT_FALLBACK_THRESHOLD_FAILURES {
        s.record_crash("recovering", "crash", 100);
    }
    assert_eq!(s.route_call("recovering", &config), RouteDecision::Fallback);

    // Reset and re-route
    s.reset_failure_count("recovering");
    assert_eq!(s.route_call("recovering", &config), RouteDecision::FastPath);
}

#[test]
fn scenario_policy_tuning() {
    let mut s = make_state_with_addon("a");
    let mut p = default_policy();
    p.max_active_handles = 3;
    p.allow_external_handles = true;

    s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p)
        .unwrap();
    s.allocate_handle("a", HandleKind::ExternalHandle, epoch(1), &p)
        .unwrap();
    s.allocate_handle("a", HandleKind::BufferHandle, epoch(1), &p)
        .unwrap();

    // At limit
    assert!(matches!(
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &p),
        Err(MembraneError::HandleLimitExceeded { .. })
    ));
}
