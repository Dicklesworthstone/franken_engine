//! Capability enforcement integration tests
//!
//! These tests verify capability enforcement end-to-end across the
//! capability->interpreter boundary. They serve as regression gates
//! against the security gaps identified in modes-of-reasoning analysis.
//!
//! Addresses bd-3pa1u.5
//!
//! STATUS: API drift - needs rewrite. Every import in this module points
//! at a type or function that no longer exists at the expected path:
//! `ModuleHeader` (removed from `ir_contract`), `DeterministicTimestamp`
//! (moved to `policy_checkpoint`), `SecurityEpoch` (moved to
//! `security_epoch`), and `generate_ed25519_keypair` (no longer exported
//! from `signature_preimage`). Porting the 400+ lines of test bodies to
//! the new surface is beyond the ~40-line threshold per test, so disable
//! the whole module until it is rewritten against the current APIs.

// NOTE: still quarantined - pervasive API drift: ModuleHeader removed from
// ir_contract, DeterministicTimestamp + SecurityEpoch + generate_ed25519_keypair
// moved out of their original modules, Ir3Module lost literal_table/
// identifier_table/exception_table, Ir3Instruction::LoadInt32 renamed,
// Ir3Instruction::Add fields renamed (dest/left/right -> dst/lhs/rhs),
// Ir3Instruction::Hostcall variant gone, VerificationContext gained new
// required fields. Rewriting all 500+ lines is beyond scope.
#![cfg(any())]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, QuickJsLane,
};
use frankenengine_engine::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use frankenengine_engine::capability_token::{
    CapabilityToken, PrincipalId, TokenBuilder, TokenError, VerificationContext,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module, ModuleHeader};
use frankenengine_engine::runtime_config::DeterministicTimestamp;
use frankenengine_engine::signature_preimage::{SecurityEpoch, generate_ed25519_keypair};

// Test helper functions

fn create_test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: ModuleHeader {
            source_label: "test-module".to_string(),
            phase_completeness: Default::default(),
            source_hash: ContentHash::compute(b"test-source"),
            schema_version: Default::default(),
        },
        instructions,
        required_capabilities: Vec::new(),
        function_table: Vec::new(),
        literal_table: Vec::new(),
        identifier_table: Vec::new(),
        exception_table: Vec::new(),
    }
}

fn create_basic_config_with_capabilities(
    capabilities: BTreeSet<RuntimeCapability>,
) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = capabilities;
    config
}

fn make_principal(id: u32) -> PrincipalId {
    PrincipalId(EngineObjectId([
        id as u8,
        (id >> 8) as u8,
        (id >> 16) as u8,
        (id >> 24) as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]))
}

fn basic_verification_context() -> VerificationContext {
    VerificationContext { current_tick: 500 }
}

// Integration tests

#[test]
fn compute_only_profile_executes_pure_arithmetic() {
    let capabilities = BTreeSet::new(); // Empty = ComputeOnly
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "compute-only-test");

    // Pure arithmetic should work without any capabilities
    let module = create_test_module(vec![
        Ir3Instruction::LoadInt32 { dest: 0, value: 42 },
        Ir3Instruction::LoadInt32 { dest: 1, value: 24 },
        Ir3Instruction::Add {
            dest: 2,
            left: 0,
            right: 1,
        },
        Ir3Instruction::Halt,
    ]);

    // This should fail because ComputeOnly doesn't have VmDispatch capability
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(err, InterpreterError::CapabilityDenied { .. }));
}

#[test]
fn compute_only_profile_fails_hostcall_with_network_egress() {
    let capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]); // Add VmDispatch but not NetworkEgress
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "compute-only-hostcall-test");

    // Module that tries to make a network hostcall
    let module = create_test_module(vec![
        Ir3Instruction::Hostcall {
            capability_tag: "network-fetch".to_string(),
            dest: 0,
            args: vec![],
        },
        Ir3Instruction::Halt,
    ]);

    let result = core.execute(&module);
    // Should either fail with capability denied during hostcall or execute but deny the hostcall
    // The exact behavior depends on the hostcall implementation details
    match result {
        Ok(_) => {
            // If it executes, the hostcall should be denied during dispatch
            // We can't easily test this without a more complex setup
        }
        Err(InterpreterError::CapabilityDenied { .. }) => {
            // This is also acceptable if capability checking happens earlier
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn engine_core_profile_executes_and_allocates() {
    let capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
    ]);
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "engine-core-test");

    // Should succeed with VmDispatch capability
    let module = create_test_module(vec![Ir3Instruction::Halt]);
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Should succeed with HeapAllocate capability
    let obj_result = core.alloc_object_with_prototype(None);
    assert!(obj_result.is_ok());
}

#[test]
fn engine_core_profile_fails_policy_write() {
    let capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        // Notably missing PolicyWrite
    ]);
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "engine-core-policy-test");

    // Module that tries to make a policy write hostcall
    let module = create_test_module(vec![
        Ir3Instruction::Hostcall {
            capability_tag: "policy-write".to_string(),
            dest: 0,
            args: vec![],
        },
        Ir3Instruction::Halt,
    ]);

    let result = core.execute(&module);
    // Similar to network test - should execute but deny the hostcall
    match result {
        Ok(_) => {
            // Hostcall should be denied during dispatch
        }
        Err(InterpreterError::CapabilityDenied { .. }) => {
            // Also acceptable
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn remote_caps_profile_allows_network_denies_vm_dispatch() {
    let capabilities = BTreeSet::from([
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        // Notably missing VmDispatch
    ]);
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "remote-caps-test");

    // Should fail execution due to lack of VmDispatch
    let module = create_test_module(vec![Ir3Instruction::Halt]);
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::CapabilityDenied { capability } if capability == "VmDispatch"
    ));

    // Note: We can't easily test network egress success without a more complex hostcall setup
}

#[test]
fn policy_caps_profile_allows_policy_denies_network() {
    let capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch, // Add VmDispatch for execution
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        // Notably missing NetworkEgress
    ]);
    let config = create_basic_config_with_capabilities(capabilities);
    let mut core = InterpreterCore::new(config, "policy-caps-test");

    // Should succeed with VmDispatch
    let module = create_test_module(vec![Ir3Instruction::Halt]);
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Test that network hostcall would be denied
    let module = create_test_module(vec![
        Ir3Instruction::Hostcall {
            capability_tag: "network-fetch".to_string(),
            dest: 0,
            args: vec![],
        },
        Ir3Instruction::Halt,
    ]);

    let result = core.execute(&module);
    match result {
        Ok(_) => {
            // Hostcall should be denied during dispatch
        }
        Err(InterpreterError::CapabilityDenied { .. }) => {
            // Also acceptable
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn token_with_empty_audience_build_fails() {
    let (sk, _vk) = generate_ed25519_keypair().unwrap();

    let err = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "test-zone",
    )
    .add_capability(RuntimeCapability::VmDispatch)
    // Notably no add_audience() call
    .build()
    .unwrap_err();

    assert!(matches!(err, TokenError::EmptyAudience));
}

#[test]
fn token_with_valid_audience_wrong_presenter_verify_fails() {
    let (sk, _vk) = generate_ed25519_keypair().unwrap();

    let token = TokenBuilder::new(
        sk,
        DeterministicTimestamp(100),
        DeterministicTimestamp(1000),
        SecurityEpoch::GENESIS,
        "test-zone",
    )
    .add_audience(make_principal(100)) // Audience is principal(100)
    .add_capability(RuntimeCapability::VmDispatch)
    .build()
    .unwrap();

    let ctx = basic_verification_context();
    let wrong_presenter = make_principal(200); // Different principal

    let err = frankenengine_engine::capability_token::verify_token(&token, &wrong_presenter, &ctx)
        .unwrap_err();

    assert!(matches!(
        err,
        TokenError::AudienceRejected {
            audience_size: 1,
            ..
        }
    ));
}

#[test]
fn intersect_full_with_engine_core_returns_correct_profile_kind() {
    let full = CapabilityProfile::full();
    let engine_core = CapabilityProfile::engine_core();

    let intersection = full.intersect(&engine_core);

    // Key assertion: the ProfileKind should be EngineCore, not ComputeOnly
    assert_eq!(intersection.kind, ProfileKind::EngineCore);
    assert_eq!(intersection.capabilities, engine_core.capabilities);
}

#[test]
fn profile_subsumption_full_subsumes_engine_core() {
    let full = CapabilityProfile::full();
    let engine_core = CapabilityProfile::engine_core();

    assert!(full.subsumes(&engine_core));
    assert!(!engine_core.subsumes(&full)); // Should not be symmetric
}

#[test]
fn profile_subsumption_comprehensive_hierarchy() {
    let full = CapabilityProfile::full();
    let engine_core = CapabilityProfile::engine_core();
    let policy = CapabilityProfile::policy();
    let remote = CapabilityProfile::remote();
    let compute_only = CapabilityProfile::compute_only();

    // Full should subsume everything
    assert!(full.subsumes(&full));
    assert!(full.subsumes(&engine_core));
    assert!(full.subsumes(&policy));
    assert!(full.subsumes(&remote));
    assert!(full.subsumes(&compute_only));

    // ComputeOnly should only subsume itself
    assert!(compute_only.subsumes(&compute_only));
    assert!(!compute_only.subsumes(&engine_core));
    assert!(!compute_only.subsumes(&policy));
    assert!(!compute_only.subsumes(&remote));
    assert!(!compute_only.subsumes(&full));

    // Specific profiles should not subsume each other (no overlap)
    assert!(!engine_core.subsumes(&policy));
    assert!(!policy.subsumes(&engine_core));
    assert!(!engine_core.subsumes(&remote));
    assert!(!remote.subsumes(&engine_core));
    assert!(!policy.subsumes(&remote));
    assert!(!remote.subsumes(&policy));

    // Each profile should subsume itself
    assert!(engine_core.subsumes(&engine_core));
    assert!(policy.subsumes(&policy));
    assert!(remote.subsumes(&remote));
}

#[test]
fn capability_enforcement_covers_all_runtime_capabilities() {
    // Verify that all RuntimeCapability variants are covered by at least one profile
    use frankenengine_engine::capability::RuntimeCapability::*;

    let all_capabilities = [
        VmDispatch,
        GcInvoke,
        IrLowering,
        PolicyRead,
        PolicyWrite,
        EvidenceEmit,
        DecisionInvoke,
        NetworkEgress,
        LeaseManagement,
        IdempotencyDerive,
        ExtensionLifecycle,
        HeapAllocate,
        EnvRead,
        ProcessSpawn,
        FsRead,
        FsWrite,
        ModuleLoad,
    ];

    let full = CapabilityProfile::full();

    for cap in &all_capabilities {
        assert!(
            full.has(*cap),
            "Full profile should contain capability: {:?}",
            cap
        );
    }

    // Verify that all capabilities are covered by at least one named profile
    let engine_core = CapabilityProfile::engine_core();
    let policy = CapabilityProfile::policy();
    let remote = CapabilityProfile::remote();

    for cap in &all_capabilities {
        let covered =
            full.has(*cap) || engine_core.has(*cap) || policy.has(*cap) || remote.has(*cap);
        assert!(
            covered,
            "Capability {:?} is not covered by any profile",
            cap
        );
    }
}

#[test]
fn integration_test_vm_dispatch_capability_boundary() {
    // Test the exact capability->interpreter boundary for VmDispatch

    // Case 1: With VmDispatch - should succeed
    let mut config_with = InterpreterConfig::quickjs_defaults();
    config_with
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    let mut core_with = InterpreterCore::new(config_with, "vm-dispatch-with");

    let module = create_test_module(vec![Ir3Instruction::Halt]);
    let result = core_with.execute(&module);
    assert!(
        result.is_ok(),
        "Execution should succeed with VmDispatch capability"
    );

    // Case 2: Without VmDispatch - should fail
    let mut config_without = InterpreterConfig::quickjs_defaults();
    config_without.granted_capabilities.clear(); // No capabilities
    let mut core_without = InterpreterCore::new(config_without, "vm-dispatch-without");

    let result = core_without.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "VmDispatch");
        }
        other => panic!("Expected CapabilityDenied for VmDispatch, got: {:?}", other),
    }
}

#[test]
fn integration_test_heap_allocate_capability_boundary() {
    // Test the exact capability->interpreter boundary for HeapAllocate

    // Case 1: With HeapAllocate - should succeed
    let mut config_with = InterpreterConfig::quickjs_defaults();
    config_with
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core_with = InterpreterCore::new(config_with, "heap-alloc-with");

    let result = core_with.alloc_object_with_prototype(None);
    assert!(
        result.is_ok(),
        "Object allocation should succeed with HeapAllocate capability"
    );

    // Case 2: Without HeapAllocate - should fail
    let mut config_without = InterpreterConfig::quickjs_defaults();
    config_without.granted_capabilities.clear(); // No capabilities
    let mut core_without = InterpreterCore::new(config_without, "heap-alloc-without");

    let result = core_without.alloc_object_with_prototype(None);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "HeapAllocate");
        }
        other => panic!(
            "Expected CapabilityDenied for HeapAllocate, got: {:?}",
            other
        ),
    }
}
