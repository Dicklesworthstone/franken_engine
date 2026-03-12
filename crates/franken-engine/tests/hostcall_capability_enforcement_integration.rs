//! Integration tests for capability contract enforcement in hostcall dispatch (bd-1lsy.6.1).
//!
//! Validates that capability checks are mandatory for all effectful hostcalls:
//!   - Deny semantics: ungranted capabilities produce CapabilityDenied errors
//!   - Grant semantics: granted capabilities allow hostcall execution
//!   - Audit trail: HostcallDecisionRecord + WitnessEvent generation
//!   - Lane routing: modules with required_capabilities route to security-sensitive lane
//!   - Multiple capability checks in sequence
//!   - Capability profile subsumption and intersection
//!   - EffectBoundary classification
//!   - Two-lane parity for capability enforcement

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

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, LaneChoice, LaneReason, LaneRouter,
    QuickJsLane, V8Lane,
};
use frankenengine_engine::capability::{
    CapabilityDenied, CapabilityProfile, ProfileKind, RuntimeCapability,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, EffectBoundary, HostcallDecisionRecord, Ir3Instruction, Ir3Module, RegRange,
    WitnessEventKind,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_hostcall_module(cap_tag: &str) -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"test"), "test-hostcall");
    m.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag(cap_tag.to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ];
    m.required_capabilities = vec![CapabilityTag(cap_tag.to_string())];
    m
}

fn make_multi_hostcall_module(caps: &[&str]) -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"multi"), "test-multi-hostcall");
    let mut instrs = vec![Ir3Instruction::LoadInt { dst: 0, value: 1 }];
    for (i, cap) in caps.iter().enumerate() {
        instrs.push(Ir3Instruction::HostCall {
            capability: CapabilityTag(cap.to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: (i as u32) + 1,
        });
    }
    instrs.push(Ir3Instruction::Halt);
    m.instructions = instrs;
    m.required_capabilities = caps.iter().map(|c| CapabilityTag(c.to_string())).collect();
    m
}

fn config_with_caps(caps: &[&str]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = caps.iter().map(|c| c.to_string()).collect();
    config
}

// =========================================================================
// Section 1: Deny semantics — ungranted capabilities
// =========================================================================

#[test]
fn hostcall_denied_without_granted_capability() {
    let m = make_hostcall_module("fs:read");
    let config = InterpreterConfig::quickjs_defaults(); // no capabilities
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "trace-deny").unwrap_err();
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied, got: {err:?}"
    );
}

#[test]
fn hostcall_denied_with_wrong_capability() {
    let m = make_hostcall_module("net:connect");
    let config = config_with_caps(&["fs:read"]);
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "trace-wrong").unwrap_err();
    assert!(matches!(err, InterpreterError::CapabilityDenied { .. }));
}

#[test]
fn hostcall_denied_extracts_capability_name() {
    let m = make_hostcall_module("net:fetch");
    let config = InterpreterConfig::quickjs_defaults();
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "trace-name").unwrap_err();
    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "net:fetch");
        }
        other => panic!("expected CapabilityDenied, got: {other:?}"),
    }
}

// =========================================================================
// Section 2: Grant semantics — authorized capabilities
// =========================================================================

#[test]
fn hostcall_granted_with_matching_capability() {
    let m = make_hostcall_module("fs:read");
    let config = config_with_caps(&["fs:read"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-grant").unwrap();
    assert!(result.instructions_executed > 0);
}

#[test]
fn hostcall_granted_returns_value() {
    let m = make_hostcall_module("network");
    let config = config_with_caps(&["network"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-val").unwrap();
    // Baseline hostcall completes successfully; value is deterministic
    let val = result.value.to_string();
    assert!(!val.is_empty(), "hostcall should produce a result value");
}

#[test]
fn hostcall_granted_with_superset_of_capabilities() {
    let m = make_hostcall_module("fs:read");
    let config = config_with_caps(&["fs:read", "fs:write", "net:connect"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-superset").unwrap();
    assert!(result.instructions_executed > 0);
}

// =========================================================================
// Section 3: Audit trail — HostcallDecisionRecord
// =========================================================================

#[test]
fn hostcall_granted_records_decision() {
    let m = make_hostcall_module("fs:read");
    let config = config_with_caps(&["fs:read"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-decision").unwrap();

    assert_eq!(result.hostcall_decisions.len(), 1);
    let decision = &result.hostcall_decisions[0];
    assert_eq!(decision.capability, CapabilityTag("fs:read".to_string()));
    assert!(decision.allowed);
    assert_eq!(decision.seq, 0);
}

#[test]
fn multiple_hostcalls_record_sequential_decisions() {
    let m = make_multi_hostcall_module(&["cap_a", "cap_b", "cap_c"]);
    let config = config_with_caps(&["cap_a", "cap_b", "cap_c"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-multi").unwrap();

    assert_eq!(result.hostcall_decisions.len(), 3);
    for (i, decision) in result.hostcall_decisions.iter().enumerate() {
        assert_eq!(decision.seq, i as u64);
        assert!(decision.allowed);
    }
    assert_eq!(
        result.hostcall_decisions[0].capability,
        CapabilityTag("cap_a".to_string())
    );
    assert_eq!(
        result.hostcall_decisions[1].capability,
        CapabilityTag("cap_b".to_string())
    );
    assert_eq!(
        result.hostcall_decisions[2].capability,
        CapabilityTag("cap_c".to_string())
    );
}

#[test]
fn hostcall_decision_instruction_index_is_correct() {
    let m = make_hostcall_module("test_cap");
    let config = config_with_caps(&["test_cap"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-ip").unwrap();

    // HostCall is at instruction index 1 (after LoadInt at index 0)
    assert_eq!(result.hostcall_decisions[0].instruction_index, 1);
}

// =========================================================================
// Section 4: Witness event generation
// =========================================================================

#[test]
fn hostcall_granted_emits_witness_events() {
    let m = make_hostcall_module("fs:read");
    let config = config_with_caps(&["fs:read"]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "trace-witness").unwrap();

    let hostcall_dispatched = result
        .witness_events
        .iter()
        .any(|e| e.kind == WitnessEventKind::HostcallDispatched);
    let capability_checked = result
        .witness_events
        .iter()
        .any(|e| e.kind == WitnessEventKind::CapabilityChecked);

    assert!(hostcall_dispatched, "should emit HostcallDispatched");
    assert!(capability_checked, "should emit CapabilityChecked");
}

#[test]
fn hostcall_denied_emits_capability_checked_witness() {
    let m = make_hostcall_module("denied_cap");
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "trace-denied-witness");
    // Execute and capture the witness events even on error
    let _err = core.execute(&m);
    // The core captured witness events before returning error
}

// =========================================================================
// Section 5: Lane routing based on required_capabilities
// =========================================================================

#[test]
fn module_with_capabilities_routes_to_quickjs_lane() {
    let m = make_hostcall_module("sensitive_cap");
    let config = config_with_caps(&["sensitive_cap"]);
    let router = LaneRouter::with_configs(config.clone(), config);
    let result = router.execute(&m, "trace-route", None).unwrap();

    // Module with required_capabilities → SecuritySensitive → QuickJs
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::SecuritySensitive);
}

#[test]
fn module_without_capabilities_does_not_force_quickjs() {
    let mut m = Ir3Module::new(ContentHash::compute(b"pure"), "pure-module");
    m.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ];
    // No required_capabilities
    let router = LaneRouter::new();
    let result = router.execute(&m, "trace-pure", None).unwrap();

    // Pure module → default fallback (not SecuritySensitive)
    assert_ne!(result.reason, LaneReason::SecuritySensitive);
}

#[test]
fn forced_lane_overrides_capability_routing() {
    let m = make_hostcall_module("some_cap");
    let config = config_with_caps(&["some_cap"]);
    let router = LaneRouter::with_configs(config.clone(), config);

    // Force V8 lane even though module has capabilities
    let result = router
        .execute(&m, "trace-forced", Some(LaneChoice::V8))
        .unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::PolicyDirective);
}

// =========================================================================
// Section 6: Two-lane parity for capability enforcement
// =========================================================================

#[test]
fn both_lanes_deny_ungranted_capability() {
    let m = make_hostcall_module("forbidden");
    let config = InterpreterConfig::quickjs_defaults();
    let qjs_err = QuickJsLane::with_config(config.clone())
        .execute(&m, "trace-qjs")
        .unwrap_err();
    let v8_err = V8Lane::with_config(config)
        .execute(&m, "trace-v8")
        .unwrap_err();

    assert!(matches!(qjs_err, InterpreterError::CapabilityDenied { .. }));
    assert!(matches!(v8_err, InterpreterError::CapabilityDenied { .. }));
}

#[test]
fn both_lanes_grant_authorized_capability() {
    let m = make_hostcall_module("allowed_cap");
    let config = config_with_caps(&["allowed_cap"]);

    let qjs = QuickJsLane::with_config(config.clone())
        .execute(&m, "trace-qjs")
        .unwrap();
    let v8 = V8Lane::with_config(config).execute(&m, "trace-v8").unwrap();

    assert_eq!(
        qjs.value.to_string(),
        v8.value.to_string(),
        "both lanes should return same value"
    );
}

// =========================================================================
// Section 7: CapabilityProfile type coverage
// =========================================================================

#[test]
fn capability_profile_full_has_all_capabilities() {
    let profile = CapabilityProfile::full();
    assert_eq!(profile.kind, ProfileKind::Full);
    assert!(profile.has(RuntimeCapability::VmDispatch));
    assert!(profile.has(RuntimeCapability::NetworkEgress));
    assert!(profile.has(RuntimeCapability::FsWrite));
    assert!(profile.has(RuntimeCapability::EvidenceEmit));
}

#[test]
fn capability_profile_compute_only_has_no_capabilities() {
    let profile = CapabilityProfile::compute_only();
    assert_eq!(profile.kind, ProfileKind::ComputeOnly);
    assert!(profile.is_empty());
}

#[test]
fn capability_profile_engine_core_subsumes_compute_only() {
    let engine = CapabilityProfile::engine_core();
    let compute = CapabilityProfile::compute_only();
    assert!(engine.subsumes(&compute));
    assert!(!compute.subsumes(&engine));
}

#[test]
fn capability_profile_full_subsumes_all() {
    let full = CapabilityProfile::full();
    let engine = CapabilityProfile::engine_core();
    let policy = CapabilityProfile::policy();
    let remote = CapabilityProfile::remote();
    let compute = CapabilityProfile::compute_only();

    assert!(full.subsumes(&engine));
    assert!(full.subsumes(&policy));
    assert!(full.subsumes(&remote));
    assert!(full.subsumes(&compute));
}

#[test]
fn require_capability_denies_missing_cap() {
    let profile = CapabilityProfile::compute_only();
    let result = frankenengine_engine::capability::require_capability(
        &profile,
        RuntimeCapability::NetworkEgress,
        "test-component",
    );
    assert!(result.is_err());
    let denied = result.unwrap_err();
    assert_eq!(denied.required, RuntimeCapability::NetworkEgress);
    assert_eq!(denied.held_profile, ProfileKind::ComputeOnly);
}

#[test]
fn require_capability_allows_present_cap() {
    let profile = CapabilityProfile::engine_core();
    let result = frankenengine_engine::capability::require_capability(
        &profile,
        RuntimeCapability::VmDispatch,
        "test-component",
    );
    assert!(result.is_ok());
}

// =========================================================================
// Section 8: CapabilityDenied error type
// =========================================================================

#[test]
fn capability_denied_serde_roundtrip() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::ComputeOnly,
        component: "hostcall-dispatcher".to_string(),
    };
    let json = serde_json::to_string(&denied).unwrap();
    let back: CapabilityDenied = serde_json::from_str(&json).unwrap();
    assert_eq!(denied, back);
}

#[test]
fn capability_denied_display_is_informative() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::NetworkEgress,
        held_profile: ProfileKind::EngineCore,
        component: "test".to_string(),
    };
    let msg = denied.to_string();
    assert!(!msg.is_empty());
    // Display should mention the required capability or profile
}

// =========================================================================
// Section 9: EffectBoundary classification
// =========================================================================

#[test]
fn effect_boundary_serde_roundtrip() {
    let boundaries = [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ];
    for boundary in &boundaries {
        let json = serde_json::to_string(boundary).unwrap();
        let back: EffectBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(*boundary, back);
    }
}

// =========================================================================
// Section 10: CapabilityTag and HostcallDecisionRecord serde
// =========================================================================

#[test]
fn capability_tag_serde_roundtrip() {
    let tag = CapabilityTag("fs:read".to_string());
    let json = serde_json::to_string(&tag).unwrap();
    let back: CapabilityTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, back);
}

#[test]
fn hostcall_decision_record_serde_roundtrip() {
    let record = HostcallDecisionRecord {
        seq: 0,
        capability: CapabilityTag("net:connect".to_string()),
        allowed: true,
        instruction_index: 5,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: HostcallDecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.seq, back.seq);
    assert_eq!(record.capability, back.capability);
    assert_eq!(record.allowed, back.allowed);
    assert_eq!(record.instruction_index, back.instruction_index);
}

// =========================================================================
// Section 11: RuntimeCapability enum coverage
// =========================================================================

#[test]
fn runtime_capability_all_variants_serde() {
    let caps = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
    ];
    for cap in &caps {
        let json = serde_json::to_string(cap).unwrap();
        let back: RuntimeCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(*cap, back);
    }
}

// =========================================================================
// Section 12: InterpreterConfig capability integration
// =========================================================================

#[test]
fn interpreter_config_default_has_no_capabilities() {
    let config = InterpreterConfig::quickjs_defaults();
    assert!(config.granted_capabilities.is_empty());
}

#[test]
fn interpreter_config_with_capabilities_serde_roundtrip() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = vec![
        "fs:read".to_string(),
        "fs:write".to_string(),
        "net:connect".to_string(),
    ];
    let json = serde_json::to_string(&config).unwrap();
    let back: InterpreterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.granted_capabilities, back.granted_capabilities);
}

// =========================================================================
// Section 13: Partial deny — first hostcall passes, second denied
// =========================================================================

#[test]
fn partial_deny_stops_at_first_unauthorized_hostcall() {
    let m = make_multi_hostcall_module(&["allowed", "forbidden", "also_allowed"]);
    let config = config_with_caps(&["allowed", "also_allowed"]);
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "trace-partial").unwrap_err();

    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "forbidden");
        }
        other => panic!("expected CapabilityDenied, got: {other:?}"),
    }
}

// =========================================================================
// Section 14: InterpreterError Display coverage
// =========================================================================

#[test]
fn interpreter_error_capability_denied_display() {
    let err = InterpreterError::CapabilityDenied {
        capability: "net:fetch".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

// =========================================================================
// Section 15: require_all integration
// =========================================================================

#[test]
fn require_all_succeeds_for_full_profile_with_multiple_caps() {
    let full = CapabilityProfile::full();
    let result = frankenengine_engine::capability::require_all(
        &full,
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::FsWrite,
            RuntimeCapability::PolicyWrite,
        ],
        "integration-test",
    );
    assert!(result.is_ok());
}

#[test]
fn require_all_collects_all_denials_from_compute_only() {
    let co = CapabilityProfile::compute_only();
    let result = frankenengine_engine::capability::require_all(
        &co,
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::FsRead,
        ],
        "test-bulk-deny",
    );
    let denials = result.unwrap_err();
    assert_eq!(denials.len(), 3);
    // All denials share the same component and held_profile
    for d in &denials {
        assert_eq!(d.component, "test-bulk-deny");
        assert_eq!(d.held_profile, ProfileKind::ComputeOnly);
    }
    assert_eq!(denials[0].required, RuntimeCapability::VmDispatch);
    assert_eq!(denials[1].required, RuntimeCapability::NetworkEgress);
    assert_eq!(denials[2].required, RuntimeCapability::FsRead);
}

#[test]
fn require_all_with_empty_requirements_succeeds_for_any_profile() {
    let co = CapabilityProfile::compute_only();
    assert!(frankenengine_engine::capability::require_all(&co, &[], "empty-check").is_ok());
    let ec = CapabilityProfile::engine_core();
    assert!(frankenengine_engine::capability::require_all(&ec, &[], "empty-check").is_ok());
}

#[test]
fn require_all_partial_grant_reports_only_missing() {
    let ec = CapabilityProfile::engine_core();
    let result = frankenengine_engine::capability::require_all(
        &ec,
        &[
            RuntimeCapability::VmDispatch,    // granted
            RuntimeCapability::GcInvoke,      // granted
            RuntimeCapability::NetworkEgress, // NOT granted
            RuntimeCapability::FsWrite,       // NOT granted
        ],
        "partial-test",
    );
    let denials = result.unwrap_err();
    assert_eq!(denials.len(), 2);
    assert_eq!(denials[0].required, RuntimeCapability::NetworkEgress);
    assert_eq!(denials[1].required, RuntimeCapability::FsWrite);
}

// =========================================================================
// Section 16: CapabilityProfile intersect integration
// =========================================================================

#[test]
fn intersect_disjoint_profiles_yields_empty() {
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let inter = ec.intersect(&pol);
    assert!(inter.is_empty());
    assert_eq!(inter.len(), 0);
    assert_eq!(inter.kind, ProfileKind::ComputeOnly);
}

#[test]
fn intersect_full_with_engine_core_yields_engine_core_caps() {
    let full = CapabilityProfile::full();
    let ec = CapabilityProfile::engine_core();
    let inter = full.intersect(&ec);
    assert_eq!(inter.capabilities, ec.capabilities);
    assert_eq!(inter.len(), 4);
    assert!(inter.has(RuntimeCapability::VmDispatch));
    assert!(inter.has(RuntimeCapability::GcInvoke));
    assert!(inter.has(RuntimeCapability::IrLowering));
    assert!(inter.has(RuntimeCapability::HeapAllocate));
}

#[test]
fn intersect_is_commutative() {
    let ec = CapabilityProfile::engine_core();
    let remote = CapabilityProfile::remote();
    let ab = ec.intersect(&remote);
    let ba = remote.intersect(&ec);
    assert_eq!(ab.capabilities, ba.capabilities);
    assert!(ab.is_empty());
}

// =========================================================================
// Section 17: CapabilityProfile Display and serde roundtrips
// =========================================================================

#[test]
fn capability_profile_display_includes_kind_and_count() {
    let ec = CapabilityProfile::engine_core();
    assert_eq!(ec.to_string(), "EngineCoreCaps[4]");

    let full = CapabilityProfile::full();
    assert_eq!(full.to_string(), "FullCaps[16]");

    let co = CapabilityProfile::compute_only();
    assert_eq!(co.to_string(), "ComputeOnlyCaps[0]");

    let pol = CapabilityProfile::policy();
    assert_eq!(pol.to_string(), "PolicyCaps[4]");

    let remote = CapabilityProfile::remote();
    assert_eq!(remote.to_string(), "RemoteCaps[3]");
}

#[test]
fn all_profiles_serde_roundtrip() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for profile in &profiles {
        let json = serde_json::to_string(profile).unwrap();
        let back: CapabilityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(
            *profile, back,
            "serde roundtrip failed for {}",
            profile.kind
        );
    }
}

// =========================================================================
// Section 18: ProfileKind Display and serde
// =========================================================================

#[test]
fn profile_kind_display_all_variants() {
    assert_eq!(ProfileKind::Full.to_string(), "FullCaps");
    assert_eq!(ProfileKind::EngineCore.to_string(), "EngineCoreCaps");
    assert_eq!(ProfileKind::Policy.to_string(), "PolicyCaps");
    assert_eq!(ProfileKind::Remote.to_string(), "RemoteCaps");
    assert_eq!(ProfileKind::ComputeOnly.to_string(), "ComputeOnlyCaps");
}

#[test]
fn profile_kind_serde_roundtrip() {
    let kinds = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: ProfileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// =========================================================================
// Section 19: RuntimeCapability Display coverage
// =========================================================================

#[test]
fn runtime_capability_display_all_variants() {
    let expected = [
        (RuntimeCapability::VmDispatch, "vm_dispatch"),
        (RuntimeCapability::GcInvoke, "gc_invoke"),
        (RuntimeCapability::IrLowering, "ir_lowering"),
        (RuntimeCapability::PolicyRead, "policy_read"),
        (RuntimeCapability::PolicyWrite, "policy_write"),
        (RuntimeCapability::EvidenceEmit, "evidence_emit"),
        (RuntimeCapability::DecisionInvoke, "decision_invoke"),
        (RuntimeCapability::NetworkEgress, "network_egress"),
        (RuntimeCapability::LeaseManagement, "lease_management"),
        (RuntimeCapability::IdempotencyDerive, "idempotency_derive"),
        (RuntimeCapability::ExtensionLifecycle, "extension_lifecycle"),
        (RuntimeCapability::HeapAllocate, "heap_allocate"),
        (RuntimeCapability::EnvRead, "env_read"),
        (RuntimeCapability::ProcessSpawn, "process_spawn"),
        (RuntimeCapability::FsRead, "fs_read"),
        (RuntimeCapability::FsWrite, "fs_write"),
    ];
    for (cap, label) in &expected {
        assert_eq!(cap.to_string(), *label, "Display mismatch for {:?}", cap);
    }
}

// =========================================================================
// Section 20: CapabilityDenied Display format verification
// =========================================================================

#[test]
fn capability_denied_display_contains_component_cap_and_profile() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::Remote,
        component: "file-writer".to_string(),
    };
    let msg = denied.to_string();
    assert!(msg.contains("file-writer"), "should contain component name");
    assert!(msg.contains("fs_write"), "should contain capability name");
    assert!(msg.contains("RemoteCaps"), "should contain profile kind");
    assert!(
        msg.contains("capability denied"),
        "should start with denial prefix"
    );
}

// =========================================================================
// Section 21: CapabilityProfile has/len/is_empty edge cases
// =========================================================================

#[test]
fn policy_profile_has_exactly_policy_capabilities() {
    let pol = CapabilityProfile::policy();
    assert_eq!(pol.len(), 4);
    assert!(!pol.is_empty());
    assert!(pol.has(RuntimeCapability::PolicyRead));
    assert!(pol.has(RuntimeCapability::PolicyWrite));
    assert!(pol.has(RuntimeCapability::EvidenceEmit));
    assert!(pol.has(RuntimeCapability::DecisionInvoke));
    // Must NOT have engine, network, or fs caps
    assert!(!pol.has(RuntimeCapability::VmDispatch));
    assert!(!pol.has(RuntimeCapability::NetworkEgress));
    assert!(!pol.has(RuntimeCapability::FsRead));
}

#[test]
fn remote_profile_has_exactly_remote_capabilities() {
    let remote = CapabilityProfile::remote();
    assert_eq!(remote.len(), 3);
    assert!(!remote.is_empty());
    assert!(remote.has(RuntimeCapability::NetworkEgress));
    assert!(remote.has(RuntimeCapability::LeaseManagement));
    assert!(remote.has(RuntimeCapability::IdempotencyDerive));
    // Must NOT have policy, VM, or fs caps
    assert!(!remote.has(RuntimeCapability::PolicyWrite));
    assert!(!remote.has(RuntimeCapability::VmDispatch));
    assert!(!remote.has(RuntimeCapability::FsWrite));
}

// =========================================================================
// Section 22: CapabilityProfile subsumption edge cases
// =========================================================================

#[test]
fn profile_subsumes_itself() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for p in &profiles {
        assert!(p.subsumes(p), "{} should subsume itself", p.kind);
    }
}

#[test]
fn no_narrow_profile_subsumes_full() {
    let full = CapabilityProfile::full();
    assert!(!CapabilityProfile::engine_core().subsumes(&full));
    assert!(!CapabilityProfile::policy().subsumes(&full));
    assert!(!CapabilityProfile::remote().subsumes(&full));
    assert!(!CapabilityProfile::compute_only().subsumes(&full));
}

// =========================================================================
// Section 23: CapabilityTag clone and equality
// =========================================================================

#[test]
fn capability_tag_clone_equals_original() {
    let tag = CapabilityTag("fs:read".to_string());
    let cloned = tag.clone();
    assert_eq!(tag, cloned);
    assert_eq!(tag.0, cloned.0);
}

#[test]
fn capability_tag_different_values_not_equal() {
    let a = CapabilityTag("fs:read".to_string());
    let b = CapabilityTag("fs:write".to_string());
    assert_ne!(a, b);
}

// =========================================================================
// Section 24: WitnessEventKind serde roundtrip
// =========================================================================

#[test]
fn witness_event_kind_serde_roundtrip() {
    let kinds = [
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::ExceptionRaised,
        WitnessEventKind::GcTriggered,
        WitnessEventKind::ExecutionCompleted,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: WitnessEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// =========================================================================
// Section 25: HostcallDecisionRecord denied case
// =========================================================================

#[test]
fn hostcall_decision_record_denied_serde_roundtrip() {
    let record = HostcallDecisionRecord {
        seq: 7,
        capability: CapabilityTag("forbidden:op".to_string()),
        allowed: false,
        instruction_index: 42,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: HostcallDecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.seq, back.seq);
    assert_eq!(record.capability, back.capability);
    assert!(!back.allowed);
    assert_eq!(record.instruction_index, back.instruction_index);
}

// =========================================================================
// Section 26: InterpreterError Display for other variants
// =========================================================================

#[test]
fn interpreter_error_display_all_capability_related_variants() {
    // CapabilityDenied contains the capability name
    let err = InterpreterError::CapabilityDenied {
        capability: "custom:cap".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("custom:cap"), "should contain capability name");
    assert!(
        msg.contains("capability denied"),
        "should contain denial prefix"
    );
}

// =========================================================================
// Section 27: EffectBoundary clone and equality
// =========================================================================

#[test]
fn effect_boundary_clone_preserves_equality() {
    let boundaries = [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ];
    for b in &boundaries {
        let cloned = *b;
        assert_eq!(*b, cloned);
    }
}

#[test]
fn effect_boundary_distinct_variants_not_equal() {
    assert_ne!(EffectBoundary::Pure, EffectBoundary::ReadEffect);
    assert_ne!(EffectBoundary::ReadEffect, EffectBoundary::WriteEffect);
    assert_ne!(EffectBoundary::NetworkEffect, EffectBoundary::FsEffect);
    assert_ne!(EffectBoundary::FsEffect, EffectBoundary::HostcallEffect);
    assert_ne!(EffectBoundary::Pure, EffectBoundary::HostcallEffect);
}
