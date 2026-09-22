#![forbid(unsafe_code)]

//! Real binary modules through the production validator, linker and executor.
use WasmBoundaryValue::I32;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmValueType,
};
use std::collections::BTreeSet;

fn leb(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (n & 127) as u8;
        n >>= 7;
        bytes.push(byte | if n == 0 { 0 } else { 128 });
        if n == 0 {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

struct Fixture {
    memory: bool,
    export_memory: bool,
    code: Vec<u8>,
    start: Option<Vec<u8>>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            memory: true,
            export_memory: true,
            code: vec![0x20, 0, 0x20, 1, 0x10, 0, 0x0b],
            start: None,
        }
    }
}

impl Fixture {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(
            &mut bytes,
            1,
            &[
                3, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0, 0x60, 1, 0x7f, 1, 0x7f,
            ],
        );
        section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
        section(
            &mut bytes,
            3,
            if self.start.is_some() {
                &[3, 0, 2, 1]
            } else {
                &[2, 0, 2]
            },
        );
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        if self.memory {
            section(&mut bytes, 5, &[1, 1, 1, 2]);
        }
        section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
        let mut exports = vec![
            4 + u8::from(self.memory && self.export_memory),
            1,
            b'f',
            0,
            1,
            1,
            b'h',
            0,
            0,
            1,
            b'r',
            0,
            2,
            1,
            b'g',
            3,
            0,
        ];
        if self.memory && self.export_memory {
            exports.extend([1, b'm', 2, 0]);
        }
        section(&mut bytes, 7, &exports);
        if self.start.is_some() {
            section(&mut bytes, 8, &[3]);
        }
        section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
        let reader = if self.memory {
            vec![0x20, 0, 0x2d, 0, 0, 0x0b]
        } else {
            vec![0x41, 0, 0x0b]
        };
        let mut bodies = leb(2 + usize::from(self.start.is_some()));
        for code in [&self.code, &reader].into_iter().chain(self.start.iter()) {
            bodies.extend(leb(code.len() + 1));
            bodies.push(0);
            bodies.extend(code);
        }
        section(&mut bytes, 10, &bodies);
        if self.memory {
            section(
                &mut bytes,
                11,
                &[1, 0, 0x41, 8, 0x0b, 6, 0, 255, 128, b'a', b'b', b'c'],
            );
        }
        bytes
    }

    fn vm(&self, limits: WasmNumericLimits) -> WasmNumericVm {
        WasmNumericVm::parse(&self.bytes(), limits).unwrap()
    }
}

fn bindings<F>(callback: F) -> WasmHostImports
where
    F: FnMut(
            &mut WasmHostCaller<'_, '_>,
            &[WasmBoundaryValue],
        ) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError>
        + Send
        + Sync
        + 'static,
{
    let mut imports = WasmHostImports::new(BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::Builtin,
    ]));
    imports
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![WasmValueType::I32; 2],
                results: vec![WasmValueType::I32],
            },
            BTreeSet::from([RuntimeCapability::Builtin]),
            1,
            callback,
        )
        .unwrap();
    imports
}

fn pointer(args: &[WasmBoundaryValue]) -> (u32, u32) {
    let [I32(address), I32(length)] = args else {
        panic!("validated signature");
    };
    (*address as u32, *length as u32)
}

fn round_trip(
    caller: &mut WasmHostCaller<'_, '_>,
    args: &[WasmBoundaryValue],
) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> {
    let (address, length) = pointer(args);
    let input = caller.read_memory(address, length)?.to_vec();
    caller.write_memory(32, &input)?;
    Ok(vec![I32(length as i32)])
}

#[test]
fn binary_buffers_round_trip_through_direct_indirect_and_exported_imports() {
    for indirect in [false, true] {
        let mut fixture = Fixture::default();
        if indirect {
            fixture.code = vec![0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x0b];
        }
        let vm = fixture.vm(WasmNumericLimits::default());
        let mut instance = vm.instantiate_with_imports(bindings(round_trip)).unwrap();
        for export in ["f", "h"] {
            assert_eq!(
                instance
                    .call_export(export, &[I32(8), I32(6)])
                    .unwrap()
                    .results,
                [I32(6)]
            );
            let memory = instance.memory_export("m").unwrap();
            assert_eq!(&memory[8..14], &[0, 255, 128, b'a', b'b', b'c']);
            assert_eq!(&memory[32..38], &memory[8..14]);
            assert_eq!((memory[31], memory[38]), (0, 0));
            assert_eq!(
                instance.call_export("r", &[I32(33)]).unwrap().results,
                [I32(255)]
            );
        }
    }
}

#[test]
fn unexported_memory_is_initialized_before_start_and_is_instance_local() {
    let fixture = Fixture {
        export_memory: false,
        start: Some(vec![0x41, 8, 0x41, 6, 0x10, 0, 0x1a, 0x0b]),
        ..Fixture::default()
    };
    let vm = fixture.vm(WasmNumericLimits::default());
    let build = || {
        let mut count = 0_u8;
        bindings(move |caller, _| {
            assert_eq!(caller.memory_size_bytes(), Some(65_536));
            assert_eq!(caller.read_memory(8, 6)?, &[0, 255, 128, b'a', b'b', b'c']);
            count += 1;
            caller.write_memory(32, &[count])?;
            Ok(vec![I32(i32::from(count))])
        })
    };
    let mut first = vm.instantiate_with_imports(build()).unwrap();
    let mut second = vm.instantiate_with_imports(build()).unwrap();
    assert!(first.memory_export("m").is_none());
    assert!(first.start_execution().is_some());
    assert_eq!(
        first.call_export("r", &[I32(32)]).unwrap().results,
        [I32(1)]
    );
    assert_eq!(
        first.call_export("f", &[I32(8), I32(6)]).unwrap().results,
        [I32(2)]
    );
    assert_eq!(
        first.call_export("r", &[I32(32)]).unwrap().results,
        [I32(2)]
    );
    assert_eq!(
        second.call_export("r", &[I32(32)]).unwrap().results,
        [I32(1)]
    );
}

#[test]
fn reads_check_complete_unsigned_extents_including_empty_ranges() {
    let vm = Fixture::default().vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, args| {
            let (address, length) = pointer(args);
            caller.read_memory(address, length)?;
            Ok(vec![I32(7)])
        }))
        .unwrap();
    for args in [[65_536, 0], [65_535, 1], [0, 65_536]] {
        assert_eq!(
            instance.call_export("h", &args.map(I32)).unwrap().results,
            [I32(7)]
        );
    }
    for args in [
        [65_537, 0],
        [65_536, 1],
        [65_535, 2],
        [-1, 0],
        [-1, 2],
        [8, -1],
    ] {
        let error = instance.call_export("h", &args.map(I32)).unwrap_err();
        assert!(
            matches!(error, WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds {
            address, width, memory_bytes: 65_536,
        }) if address == u64::from(args[0] as u32) && width == u64::from(args[1] as u32))
        );
    }
    // Refusal is latched only for its callback, not forever on the instance.
    assert!(instance.call_export("h", &[I32(8), I32(6)]).is_ok());
}

#[test]
fn failed_host_writes_are_atomic_and_do_not_wrap() {
    let vm = Fixture::default().vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, args| {
            let (address, _) = pointer(args);
            caller.write_memory(address, &[9, 8, 7, 6])?;
            Ok(vec![I32(0)])
        }))
        .unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    for address in [65_533, 65_536, -1, -2] {
        assert!(matches!(
            instance.call_export("h", &[I32(address), I32(0)]),
            Err(WasmNumericVmError::State(
                WasmStateError::MemoryOutOfBounds { .. }
            ))
        ));
        assert_eq!(instance.memory_export("m").unwrap(), before);
    }
    instance.call_export("h", &[I32(65_532), I32(0)]).unwrap();
    assert_eq!(
        &instance.memory_export("m").unwrap()[65_532..],
        &[9, 8, 7, 6]
    );
}

#[test]
fn ignored_bounds_fault_blocks_later_access_and_overrides_success() {
    let vm = Fixture::default().vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, _| {
            let error = caller.read_memory(u32::MAX, 2).unwrap_err();
            assert_eq!(caller.write_memory(8, b"changed").unwrap_err(), error);
            assert_eq!(caller.read_memory(8, 1).unwrap_err(), error);
            assert_eq!(caller.charge_work(0).unwrap_err(), error);
            Ok(vec![I32(42)])
        }))
        .unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    assert!(matches!(
        instance.call_export("h", &[I32(0), I32(0)]),
        Err(WasmNumericVmError::State(
            WasmStateError::MemoryOutOfBounds {
                address: 4_294_967_295,
                width: 2,
                ..
            }
        ))
    ));
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn host_buffer_work_is_precharged_with_exact_64_byte_rounding() {
    for length in [0_usize, 1, 63, 64, 65, 128, 129] {
        let expected = 2 + 2 * (length as u64).div_ceil(64); // fixed host + ABI + read + write
        let vm = Fixture::default().vm(WasmNumericLimits {
            max_instructions: expected,
            ..WasmNumericLimits::default()
        });
        let mut instance = vm.instantiate_with_imports(bindings(round_trip)).unwrap();
        assert_eq!(
            instance
                .call_export("h", &[I32(8), I32(length as i32)])
                .unwrap()
                .instructions_executed,
            expected
        );
    }
    for budget in [2, 3, 4, 5] {
        let vm = Fixture::default().vm(WasmNumericLimits {
            max_instructions: budget,
            ..WasmNumericLimits::default()
        });
        let mut instance = vm.instantiate_with_imports(bindings(round_trip)).unwrap();
        let before = instance.memory_export("m").unwrap().to_vec();
        assert_eq!(
            instance.call_export("h", &[I32(8), I32(65)]),
            Err(WasmNumericVmError::InstructionBudgetExceeded { max: budget })
        );
        assert_eq!(instance.memory_export("m").unwrap(), before);
    }
}

#[test]
fn swallowed_budget_refusal_prevents_memory_mutation() {
    let vm = Fixture::default().vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, _| {
            let error = caller.charge_work(u64::MAX).unwrap_err();
            assert_eq!(caller.write_memory(8, &[42]).unwrap_err(), error);
            assert_eq!(caller.read_memory(8, 1).unwrap_err(), error);
            Err(WasmHostError::trap("provider tried to replace the first failure").into())
        }))
        .unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    assert!(matches!(
        instance.call_export("h", &[I32(0), I32(0)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
    ));
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn completed_host_writes_survive_later_host_and_guest_traps() {
    for host_trap in [false, true] {
        let fixture = Fixture {
            code: vec![0x20, 0, 0x20, 1, 0x10, 0, 0x1a, 0x00, 0x0b],
            ..Fixture::default()
        };
        let vm = fixture.vm(WasmNumericLimits::default());
        let build = || {
            bindings(move |caller, _| {
                caller.write_memory(32, b"kept")?;
                if host_trap {
                    caller.read_memory(u32::MAX, 1)?;
                }
                Ok(vec![I32(0)])
            })
        };
        let mut first = vm.instantiate_with_imports(build()).unwrap();
        let second = vm.instantiate_with_imports(build()).unwrap();
        let error = first.call_export("f", &[I32(0), I32(0)]).unwrap_err();
        if host_trap {
            assert!(matches!(
                error,
                WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. })
            ));
        } else {
            assert!(matches!(error, WasmNumericVmError::Unreachable { .. }));
        }
        assert_eq!(&first.memory_export("m").unwrap()[32..36], b"kept");
        assert_eq!(&second.memory_export("m").unwrap()[32..36], &[0; 4]);
    }
}

#[test]
fn modules_without_memory_do_not_synthesize_even_an_empty_buffer() {
    let fixture = Fixture {
        memory: false,
        ..Fixture::default()
    };
    let vm = fixture.vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, _| {
            assert_eq!(caller.memory_size_bytes(), None);
            let error = caller.write_memory(0, &[]).unwrap_err();
            assert_eq!(caller.read_memory(0, 0).unwrap_err(), error);
            Ok(vec![I32(0)])
        }))
        .unwrap();
    assert!(matches!(
        instance.call_export("h", &[I32(0), I32(0)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::MissingMemory
        )))
    ));
}

#[test]
fn callbacks_observe_current_memory_after_guest_growth() {
    let fixture = Fixture {
        code: vec![0x41, 1, 0x40, 0, 0x1a, 0x20, 0, 0x20, 1, 0x10, 0, 0x0b],
        ..Fixture::default()
    };
    let vm = fixture.vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|caller, _| {
            assert_eq!(caller.memory_size_bytes(), Some(131_072));
            assert_eq!(caller.read_memory(65_536, 4)?, &[0; 4]);
            caller.write_memory(65_536, b"grow")?;
            Ok(vec![I32(1)])
        }))
        .unwrap();
    instance.call_export("f", &[I32(0), I32(0)]).unwrap();
    assert_eq!(
        &instance.memory_export("m").unwrap()[65_536..65_540],
        b"grow"
    );
}

#[test]
fn revoked_host_grant_denies_buffer_access_before_callback_entry() {
    let vm = Fixture::default().vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(bindings(|_, _| panic!("revoked callback entered")))
        .unwrap();
    assert!(instance.revoke_host_capability(RuntimeCapability::Builtin));
    let before = instance.memory_export("m").unwrap().to_vec();
    assert!(matches!(
        instance.call_export("h", &[I32(8), I32(6)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { .. }
        )))
    ));
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn buffer_work_shares_the_start_function_budget() {
    let fixture = Fixture {
        start: Some(vec![0x41, 8, 0x41, 6, 0x10, 0, 0x1a, 0x0b]),
        ..Fixture::default()
    };
    // Startup: two consts + call + fixed host/ABI + read/write + drop + end = 9.
    let vm = fixture.vm(WasmNumericLimits {
        max_instructions: 9,
        ..WasmNumericLimits::default()
    });
    let instance = vm.instantiate_with_imports(bindings(round_trip)).unwrap();
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 9);
    assert_eq!(
        &instance.memory_export("m").unwrap()[32..38],
        &[0, 255, 128, b'a', b'b', b'c']
    );
    let vm = fixture.vm(WasmNumericLimits {
        max_instructions: 6,
        ..WasmNumericLimits::default()
    });
    assert!(matches!(
        vm.instantiate_with_imports(bindings(round_trip)),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 6 })
    ));
}
