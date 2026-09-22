#![forbid(unsafe_code)]

//! Real Wasm binaries through the production linker, guest memory and meter.
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::{self, I32};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmNumericLimits, WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WASI_PREVIEW1_MODULE, WasiPreview1Config, WasiPreview1Error,
};
use std::collections::{BTreeMap, BTreeSet};

const INPUT_NAMES: [&str; 4] = [
    "args_sizes_get",
    "args_get",
    "environ_sizes_get",
    "environ_get",
];

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend(payload);
}

fn name(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend(leb(text.len()));
    bytes.extend(text.as_bytes());
}

fn module(names: &[&str], memory: bool, start: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(
        &mut bytes,
        1,
        &[2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0],
    );
    let mut imports = leb(names.len());
    for function in names {
        name(&mut imports, WASI_PREVIEW1_MODULE);
        name(&mut imports, function);
        imports.extend([0, 0]);
    }
    section(&mut bytes, 2, &imports);
    if start {
        section(&mut bytes, 3, &[1, 1]);
    }
    if memory {
        section(&mut bytes, 5, &[1, 1, 1, 1]);
    }
    let mut exports = leb(names.len() + usize::from(memory));
    for (index, function) in names.iter().enumerate() {
        name(&mut exports, function);
        exports.push(0);
        exports.extend(leb(index));
    }
    if memory {
        name(&mut exports, "memory");
        exports.extend([2, 0]);
    }
    section(&mut bytes, 7, &exports);
    if start {
        section(&mut bytes, 8, &leb(names.len()));
        // Startup queries sizes and writes the same argv used by later calls.
        let code = [
            0, 0x41, 0, 0x41, 4, 0x10, 0, 0x1a, 0x41, 8, 0x41, 32, 0x10, 1, 0x1a, 0x0b,
        ];
        let mut bodies = vec![1];
        bodies.extend(leb(code.len()));
        bodies.extend(code);
        section(&mut bytes, 10, &bodies);
    }
    bytes
}

fn grants() -> BTreeSet<RuntimeCapability> {
    BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::Builtin,
        RuntimeCapability::EnvRead,
    ])
}

fn config() -> WasiPreview1Config {
    WasiPreview1Config {
        arguments: vec!["app".into(), "".into(), "λ".into()],
        environment: BTreeMap::from([("Z".into(), "last".into()), ("A".into(), "x=y".into())]),
        ..WasiPreview1Config::default()
    }
}

fn vm(names: &[&str]) -> WasmNumericVm {
    WasmNumericVm::parse(&module(names, true, false), WasmNumericLimits::default()).unwrap()
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn explicit_utf8_arguments_include_empty_entries_and_exact_pointer_layout() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    assert_eq!(
        instance
            .call_export("args_sizes_get", &[I32(0), I32(4)])
            .unwrap()
            .results,
        [I32(0)]
    );
    let memory = instance.memory_export("memory").unwrap();
    assert_eq!((u32_at(memory, 0), u32_at(memory, 4)), (3, 8));
    let result = instance
        .call_export("args_get", &[I32(8), I32(32)])
        .unwrap();
    assert_eq!(result.results, [I32(0)]);
    assert_eq!(result.instructions_executed, 9); // fixed+ABI=2, pointer work=3, writes=4
    let memory = instance.memory_export("memory").unwrap();
    assert_eq!(&memory[32..40], "app\0\0λ\0".as_bytes());
    assert_eq!(
        [u32_at(memory, 8), u32_at(memory, 12), u32_at(memory, 16)],
        [32, 36, 37]
    );
    assert_eq!(&memory[20..32], &[0; 12]);
}

#[test]
fn environment_is_sorted_explicit_and_preserves_equals_in_values() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    instance
        .call_export("environ_sizes_get", &[I32(0), I32(4)])
        .unwrap();
    assert_eq!(u32_at(instance.memory_export("memory").unwrap(), 0), 2);
    assert_eq!(u32_at(instance.memory_export("memory").unwrap(), 4), 13);
    assert_eq!(
        instance
            .call_export("environ_get", &[I32(8), I32(32)])
            .unwrap()
            .results,
        [I32(0)]
    );
    let memory = instance.memory_export("memory").unwrap();
    assert_eq!(&memory[32..45], b"A=x=y\0Z=last\0");
    assert_eq!([u32_at(memory, 8), u32_at(memory, 12)], [32, 38]);
}

#[test]
fn empty_inputs_do_not_inherit_the_embedding_process() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(
            WasiPreview1Config::default()
                .into_imports(grants())
                .unwrap(),
        )
        .unwrap();
    for export in ["args_sizes_get", "environ_sizes_get"] {
        assert_eq!(
            instance
                .call_export(export, &[I32(0), I32(4)])
                .unwrap()
                .results,
            [I32(0)]
        );
        assert_eq!(&instance.memory_export("memory").unwrap()[..8], &[0; 8]);
    }
    for export in ["args_get", "environ_get"] {
        assert_eq!(
            instance
                .call_export(export, &[I32(65_536), I32(65_536)])
                .unwrap()
                .results,
            [I32(0)]
        );
        assert_eq!(
            instance
                .call_export(export, &[I32(65_537), I32(0)])
                .unwrap()
                .results,
            [I32(21)]
        );
    }
}

#[test]
fn bad_sizes_pointer_never_changes_the_other_output_or_latches_an_errno() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    for export in ["args_sizes_get", "environ_sizes_get"] {
        for values in [[0, 65_533], [65_533, 0], [0, -1], [i32::MIN, 4]] {
            let before = instance.memory_export("memory").unwrap().to_vec();
            assert_eq!(
                instance
                    .call_export(export, &values.map(I32))
                    .unwrap()
                    .results,
                [I32(21)]
            );
            assert_eq!(instance.memory_export("memory").unwrap(), before);
        }
        assert_eq!(
            instance
                .call_export(export, &[I32(0), I32(4)])
                .unwrap()
                .results,
            [I32(0)]
        );
    }
}

#[test]
fn get_checks_both_complete_extents_before_any_guest_write() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    for export in ["args_get", "environ_get"] {
        for values in [[0, 65_535], [65_535, 32], [-1, 32], [0, -1], [0, i32::MIN]] {
            assert_eq!(
                instance
                    .call_export(export, &values.map(I32))
                    .unwrap()
                    .results,
                [I32(21)]
            );
            assert!(
                instance
                    .memory_export("memory")
                    .unwrap()
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    assert_eq!(
        instance
            .call_export("args_get", &[I32(65_524), I32(65_516)])
            .unwrap()
            .results,
        [I32(0)]
    );
    assert_eq!(
        &instance.memory_export("memory").unwrap()[65_516..65_524],
        "app\0\0λ\0".as_bytes()
    );
}

#[test]
fn missing_memory_is_wasi_fault_not_a_fabricated_host_memory() {
    let vm = WasmNumericVm::parse(
        &module(&INPUT_NAMES, false, false),
        WasmNumericLimits::default(),
    )
    .unwrap();
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    for export in INPUT_NAMES {
        assert_eq!(
            instance
                .call_export(export, &[I32(0), I32(0)])
                .unwrap()
                .results,
            [I32(21)]
        );
    }
}

#[test]
fn vm_budget_refusal_is_not_an_errno_and_precedes_partial_string_writes() {
    for (export, budget, exact) in [("args_sizes_get", 3, 4), ("args_get", 8, 9)] {
        let bytes = module(&INPUT_NAMES, true, false);
        let limited = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: budget,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let mut instance = limited
            .instantiate_with_imports(config().into_imports(grants()).unwrap())
            .unwrap();
        assert!(matches!(
            instance.call_export(export, &[I32(0), I32(32)]),
            Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
        ));
        assert!(
            instance
                .memory_export("memory")
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        let limited = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: exact,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let mut instance = limited
            .instantiate_with_imports(config().into_imports(grants()).unwrap())
            .unwrap();
        assert_eq!(
            instance
                .call_export(export, &[I32(0), I32(32)])
                .unwrap()
                .instructions_executed,
            exact
        );
    }
}

#[test]
fn configuration_limits_include_terminators_environment_equals_and_both_tables() {
    let mut input = config();
    input.max_strings = 4;
    assert!(matches!(
        input.into_imports(grants()),
        Err(WasiPreview1Error::LimitExceeded {
            resource: "input strings",
            actual: 5,
            max: 4
        })
    ));
    let mut input = config();
    input.max_bytes = 20;
    assert!(matches!(
        input.into_imports(grants()),
        Err(WasiPreview1Error::LimitExceeded {
            resource: "input bytes",
            actual: 21,
            max: 20
        })
    ));
    let mut input = config();
    input.max_bytes = 21;
    input.max_strings = 5;
    assert!(input.into_imports(grants()).is_ok());
}

#[test]
fn invalid_c_strings_are_rejected_before_creating_a_registry() {
    let mut input = config();
    input.arguments.push("bad\0arg".into());
    assert!(matches!(
        input.into_imports(grants()),
        Err(WasiPreview1Error::InvalidString {
            field: "argument",
            ..
        })
    ));
    for (key, value) in [("", "x"), ("X=Y", "x"), ("X\0Y", "x"), ("X", "x\0y")] {
        let input = WasiPreview1Config {
            environment: BTreeMap::from([(key.into(), value.into())]),
            ..WasiPreview1Config::default()
        };
        assert!(matches!(
            input.into_imports(grants()),
            Err(WasiPreview1Error::InvalidString {
                field: "environment entry",
                ..
            })
        ));
    }
}

#[test]
fn unused_environment_services_do_not_require_environment_authority() {
    let vm = vm(&["args_sizes_get"]);
    let caps = BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin]);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(caps).unwrap())
        .unwrap();
    assert_eq!(
        instance
            .call_export("args_sizes_get", &[I32(0), I32(4)])
            .unwrap()
            .results,
        [I32(0)]
    );
}

#[test]
fn declared_environment_imports_require_explicit_authority_before_startup() {
    let vm = vm(&INPUT_NAMES);
    let caps = BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin]);
    assert!(matches!(
        vm.instantiate_with_imports(config().into_imports(caps).unwrap()),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: RuntimeCapability::EnvRead,
                ..
            }
        )))
    ));
}

#[test]
fn revocation_still_precedes_provider_writes() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    assert!(instance.revoke_host_capability(RuntimeCapability::EnvRead));
    assert!(matches!(
        instance.call_export("environ_get", &[I32(8), I32(32)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { .. }
        )))
    ));
    assert!(
        instance
            .memory_export("memory")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        instance
            .call_export("args_get", &[I32(8), I32(32)])
            .unwrap()
            .results,
        [I32(0)]
    );
}

#[test]
fn startup_and_later_calls_use_the_same_owned_configuration() {
    let vm = WasmNumericVm::parse(
        &module(&INPUT_NAMES, true, true),
        WasmNumericLimits::default(),
    )
    .unwrap();
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    assert!(instance.start_execution().is_some());
    assert_eq!(
        &instance.memory_export("memory").unwrap()[32..40],
        "app\0\0λ\0".as_bytes()
    );
    instance
        .call_export("args_get", &[I32(64), I32(96)])
        .unwrap();
    assert_eq!(
        &instance.memory_export("memory").unwrap()[96..104],
        "app\0\0λ\0".as_bytes()
    );
}

#[test]
fn two_instances_can_receive_different_inputs_without_sharing_mutable_guest_state() {
    let vm = vm(&INPUT_NAMES);
    let mut a = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    let mut b = vm
        .instantiate_with_imports(
            WasiPreview1Config::default()
                .into_imports(grants())
                .unwrap(),
        )
        .unwrap();
    a.call_export("args_get", &[I32(8), I32(32)]).unwrap();
    b.call_export("args_sizes_get", &[I32(0), I32(4)]).unwrap();
    assert!(
        b.memory_export("memory")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        &a.memory_export("memory").unwrap()[32..40],
        "app\0\0λ\0".as_bytes()
    );
}

#[test]
fn unimplemented_wasi_services_remain_unbound() {
    let vm = vm(&["random_get"]);
    assert!(
        matches!(vm.instantiate_with_imports(config().into_imports(grants()).unwrap()),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { name, .. }))) if name == "random_get")
    );
}

#[test]
fn the_existing_linker_enforces_scalar_arguments_before_any_provider_effect() {
    let vm = vm(&INPUT_NAMES);
    let mut instance = vm
        .instantiate_with_imports(config().into_imports(grants()).unwrap())
        .unwrap();
    assert!(matches!(
        instance.call_export("args_get", &[WasmBoundaryValue::I64(0), I32(32)]),
        Err(WasmNumericVmError::TypeMismatch { .. })
    ));
    assert!(
        instance
            .memory_export("memory")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
}
