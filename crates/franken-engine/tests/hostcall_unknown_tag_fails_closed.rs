//! Regression tests for unknown hostcall capability tags (bd-3ux9r).
//!
//! Verifies that unknown/unmapped capability tags fail closed rather than being
//! granted by default. This prevents security bypasses where malicious IR3 modules
//! could use future or unknown capability strings to bypass security controls.

#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use std::collections::BTreeSet;

/// Create an InterpreterCore with minimal capabilities for testing.
fn minimal_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::default();
    config.granted_capabilities.clear(); // No capabilities granted
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    InterpreterCore::new(config, "unknown-capability-test")
}

/// Create an InterpreterCore with a specific capability granted for positive testing.
fn interpreter_with_capability(cap: RuntimeCapability) -> InterpreterCore {
    let mut config = InterpreterConfig::default();
    config.granted_capabilities.clear();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config.granted_capabilities.insert(cap);
    InterpreterCore::new(config, "granted-capability-test")
}

/// Create an IR3 module that makes a hostcall with the given capability tag.
fn module_with_hostcall(capability_tag: &str) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: Some(ContentHash::compute(capability_tag.as_bytes())),
            source_label: "unknown-hostcall-test".to_string(),
        },
        instructions: vec![
            // Load a simple argument for the hostcall
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            // Attempt hostcall with unknown capability
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability_tag.to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        bindings: Vec::new(),
        debug_info: None,
    }
}

#[test]
fn test_unknown_capability_xyz_totally_unknown_capability_v0_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("xyz_totally_unknown_capability_v0");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "xyz_totally_unknown_capability_v0");
        }
        other => panic!(
            "Expected CapabilityDenied for unknown capability, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_malformed_empty_capability_tag_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "");
        }
        other => panic!(
            "Expected CapabilityDenied for empty capability tag, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_malformed_whitespace_capability_tag_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("   ");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "   ");
        }
        other => panic!(
            "Expected CapabilityDenied for whitespace capability tag, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_malformed_very_long_capability_tag_fails() {
    let very_long_tag = "a".repeat(1000);
    let mut core = minimal_interpreter();
    let module = module_with_hostcall(&very_long_tag);

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, very_long_tag);
        }
        other => panic!(
            "Expected CapabilityDenied for very long capability tag, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_attack_scenario_ifc_declassify_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("ifc.declassify");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "ifc.declassify");
        }
        other => panic!(
            "Expected CapabilityDenied for ifc.declassify attack, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_attack_scenario_hostcall_invoke_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("hostcall.invoke");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "hostcall.invoke");
        }
        other => panic!(
            "Expected CapabilityDenied for hostcall.invoke attack, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_attack_scenario_future_dangerous_fails() {
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("future.dangerous");

    let result = core.execute(&module);
    match result {
        Err(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "future.dangerous");
        }
        other => panic!(
            "Expected CapabilityDenied for future.dangerous attack, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_properly_granted_capability_still_passes() {
    // Verify that properly granted capabilities still work
    let mut core = interpreter_with_capability(RuntimeCapability::HeapAllocate);
    let module = module_with_hostcall("heap.allocate");

    let result = core.execute(&module);
    // This should succeed (not fail with CapabilityDenied)
    // Note: It might fail with other errors like UnsupportedOperation, which is fine
    // We just want to ensure it doesn't fail with CapabilityDenied
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        panic!(
            "Properly granted capability 'heap.allocate' was denied: {}",
            capability
        );
    }
    // Any other result (success or different error) is acceptable for this test
}

#[test]
fn test_internal_allowed_promise_capability_passes() {
    // Promise capabilities should be internally allowed even without explicit grants
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("promise:resolve");

    let result = core.execute(&module);
    // This should not fail with CapabilityDenied
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        panic!(
            "Internal promise capability 'promise:resolve' was denied: {}",
            capability
        );
    }
    // Any other result (success or different error) is acceptable for this test
}

#[test]
fn test_internal_allowed_ifc_check_flow_passes() {
    // ifc.check_flow should be internally allowed
    let mut core = minimal_interpreter();
    let module = module_with_hostcall("ifc.check_flow");

    let result = core.execute(&module);
    // This should not fail with CapabilityDenied
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        panic!(
            "Internal IFC capability 'ifc.check_flow' was denied: {}",
            capability
        );
    }
    // Any other result (success or different error) is acceptable for this test
}
