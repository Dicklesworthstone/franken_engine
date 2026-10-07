//! Regression tests for unknown hostcall capability tags (bd-3ux9r).
//!
//! Verifies that unknown/unmapped capability tags fail closed rather than being
//! granted by default. This prevents security bypasses where malicious IR3 modules
//! could use future or unknown capability strings to bypass security controls.

#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

/// Create an InterpreterCore with minimal capabilities for testing: VM
/// dispatch and heap allocation, which running any module needs (the realm
/// allocates its intrinsics before the first instruction). Without the
/// second, every test here stopped at `HeapAllocate` before reaching the
/// hostcall it checks, so the fail-closed property went untested.
fn minimal_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.clear();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    InterpreterCore::new(config, "unknown-capability-test")
}

/// Create an InterpreterCore with a specific capability granted for positive testing.
fn interpreter_with_capability(cap: RuntimeCapability) -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.clear();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(cap);
    InterpreterCore::new(config, "granted-capability-test")
}

/// Create an IR3 module that makes a hostcall with the given capability tag.
fn module_with_hostcall(capability_tag: &str) -> Ir3Module {
    let capability = CapabilityTag(capability_tag.to_string());
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
                capability: capability.clone(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: vec![capability],
        function_lengths: Default::default(),
        function_sources: Default::default(),
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
            // An overlong tag is recorded as a SHA-256 commitment to the whole
            // tag followed by a bounded display prefix (bd-hxukn, bd-lvoff).
            let marker = format!(
                "<TRUNCATED:sha256:{}>:",
                ContentHash::compute(very_long_tag.as_bytes()).to_hex()
            );
            let display = capability
                .strip_prefix(&marker)
                .unwrap_or_else(|| panic!("denial must commit to the full tag: {capability}"));
            assert!(
                !display.is_empty() && very_long_tag.starts_with(display),
                "denial display must be a prefix of the tag: {capability}"
            );
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
    // A registered tag passes the gate when its authority is granted and is
    // denied when it is not. (`heap.allocate` is no hostcall tag since the
    // typed-capability registry, so it was denied either way.)
    let mut core = interpreter_with_capability(RuntimeCapability::Console);
    let module = module_with_hostcall("console:log");
    let result = core.execute(&module);
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        panic!(
            "Properly granted capability 'console:log' was denied: {}",
            capability
        );
    }

    let mut ungranted = minimal_interpreter();
    match ungranted.execute(&module_with_hostcall("console:log")) {
        Err(InterpreterError::CapabilityDenied { .. }) => {}
        other => panic!("console:log without the Console grant must be denied, got: {other:?}"),
    }
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
