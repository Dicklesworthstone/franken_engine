#![forbid(unsafe_code)]

//! Real binary programs exercise the shared library executor, not a model.
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
use frankenengine_engine::capability::RuntimeCapability;
use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};

// COUNTDOWN: f(n) = n == 0 ? 0 : f(n - 1) + 1 (not a tail call).
// PREFIX_SUM: f(n) = n == 0 ? 0 : n + f(n - 1), retaining each n.
// The other fixtures isolate locals, multi-results, early returns, startup,
// host dispatch and completed writes on traps. Hex preserves the exact binary.
const COUNTDOWN: &str = "0061736d0100000001060160017f017f0302010007060102663000000a17011500200045047f410005200041016b100041016a0b0b";
const PREFIX_SUM: &str = "0061736d0100000001060160017f017f0302010007060102663000000a17011500200045047f4100052000200041016b10006a0b0b";
const LOCAL_RESET: &str = "0061736d010000000105016000017f0303020000070b02026630000002663100010a15020b01017f200041016a22000b0700100010006a0b";
const MULTIVALUE: &str = "0061736d01000000010c0160047d7e7c7f047d7e7c7f0303020000070b02026630000002663100010a19020a0020002001200220030b0c00200020012002200310000b";
const EARLY_RETURN: &str = "0061736d010000000105016000017f0303020000070b02026630000002663100010a15020b00410a027f412a0f0b6a0b0700410510006a0b";
const TRAPPING_CALLEE: &str = "0061736d010000000108026000006000017f0304030000010606017f0141000b071404026630000002663100010266320002016703000a1a030a00230041016a2400000b08001000412a24000b040023000b";
const INDIRECT_COUNTDOWN: &str = "0061736d0100000001060160017f017f03020100040401700001070a020266300000017401000907010041000b01000a1a011800200045047f410005200041016b410011000041016a0b0b";
const START_CHAIN: &str = "0061736d01000000010d0360017f017f6000006000017f0304030001020606017f0141000b071404026630000002663100010266320002016703000801010a26031500200045047f410005200041016b100041016a0b0b090041d00f100024000b040023000b";
const HOST_CHAIN: &str = "0061736d0100000001060160017f017f020b0103656e7603696e6300000303020000070b02026630000102663100020a120209004107200010006a0b0600200010010b";
const LARGE_LOCALS: &str = "0061736d010000000105016000017f0302010007060102663000000a08010601417f412a0b";
const LOCAL_ADMISSION: &str = "0061736d010000000105016000017f03030200000606017f0141000b070f0302663000000266310001016703000a14020a01037f41092400412a0b0700410710006a0b";

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn vm(hex: &str, limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&bytes(hex), limits).unwrap()
}

#[test]
fn deep_guest_recursion_runs_on_a_small_native_thread_stack() {
    std::thread::Builder::new().stack_size(128 * 1024).spawn(|| {
        let vm = vm(COUNTDOWN, WasmNumericLimits {
            max_call_depth: 20_001, max_instructions: 300_000,
            ..WasmNumericLimits::default()
        });
        let result = vm.call_export("f0", &[I32(20_000)]).unwrap();
        assert_eq!(result.results, [I32(20_000)]);
        assert_eq!(result.max_call_depth, 20_001);
        assert_eq!(result.instructions_executed, 220_006);
        assert_eq!(result.peak_stack_values, 2);
    }).unwrap().join().unwrap();
}

#[test]
fn exact_call_depth_limits_remain_guest_faults() {
    let vm = vm(COUNTDOWN, WasmNumericLimits {
        max_call_depth: 64, ..WasmNumericLimits::default()
    });
    assert_eq!(vm.call_export("f0", &[I32(63)]).unwrap().max_call_depth, 64);
    assert_eq!(vm.call_export("f0", &[I32(64)]),
        Err(WasmNumericVmError::CallDepthExceeded { max: 64 }));
    let zero = WasmNumericVm::parse(&bytes(COUNTDOWN), WasmNumericLimits {
        max_call_depth: 0, ..WasmNumericLimits::default()
    }).unwrap();
    assert_eq!(zero.call_export("f0", &[I32(0)]),
        Err(WasmNumericVmError::CallDepthExceeded { max: 0 }));
}

#[test]
fn suspended_operands_and_locals_share_one_live_value_ceiling() {
    let tight = vm(PREFIX_SUM, WasmNumericLimits {
        max_live_values: 21, ..WasmNumericLimits::default()
    });
    assert!(matches!(tight.call_export("f0", &[I32(10)]),
        Err(WasmNumericVmError::LiveValueLimitExceeded { actual: 22, max: 21 })));
    let exact = vm(PREFIX_SUM, WasmNumericLimits {
        max_live_values: 22, ..WasmNumericLimits::default()
    });
    let mut instance = exact.instantiate().unwrap();
    for _ in 0..3 {
        let result = instance.call_export("f0", &[I32(10)]).unwrap();
        assert_eq!(result.results, [I32(55)]);
        assert_eq!(result.max_call_depth, 11);
        assert_eq!(result.peak_stack_values, 3);
    }
    // A failed invocation must not retain another invocation's activations.
    assert_eq!(tight.call_export("f0", &[I32(0)]).unwrap().results, [I32(0)]);
}

#[test]
fn local_arrays_are_admitted_before_any_callee_effects() {
    let tight = vm(LOCAL_ADMISSION, WasmNumericLimits {
        max_live_values: 3, ..WasmNumericLimits::default()
    });
    let mut instance = tight.instantiate().unwrap();
    assert!(matches!(instance.call_export("f1", &[]),
        Err(WasmNumericVmError::LiveValueLimitExceeded { actual: 4, max: 3 })));
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
    let exact = vm(LOCAL_ADMISSION, WasmNumericLimits {
        max_live_values: 5, ..WasmNumericLimits::default()
    });
    let mut instance = exact.instantiate().unwrap();
    assert_eq!(instance.call_export("f1", &[]).unwrap().results, [I32(49)]);
    assert_eq!(instance.global_export("g"), Some(&I32(9)));
}

#[test]
fn repeated_calls_zero_locals_and_preserve_the_suspended_prefix() {
    let vm = vm(LOCAL_RESET, WasmNumericLimits::default());
    let result = vm.call_export("f1", &[]).unwrap();
    assert_eq!(result.results, [I32(2)]);
    assert_eq!(result.instructions_executed, 14);
    assert_eq!(result.max_call_depth, 2);
    assert_eq!(result, vm.call_export("f1", &[]).unwrap());
}

#[test]
fn multi_results_keep_abi_order_and_exact_float_payloads() {
    let vm = vm(MULTIVALUE, WasmNumericLimits::default());
    let values = [F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000), I32(-9)];
    let result = vm.call_export("f1", &values).unwrap();
    assert_eq!(result.results, values);
    assert_eq!(result.instructions_executed, 11);
    assert_eq!(result.max_call_depth, 2);
    assert_eq!(result.peak_stack_values, 4);
}

#[test]
fn returning_discards_only_the_callee_control_and_operand_state() {
    let result = vm(EARLY_RETURN, WasmNumericLimits::default()).call_export("f1", &[]).unwrap();
    assert_eq!(result.results, [I32(47)]);
    assert_eq!(result.instructions_executed, 8);
}

#[test]
fn trapped_call_chains_unwind_without_undoing_completed_guest_writes() {
    let vm = vm(TRAPPING_CALLEE, WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    for expected in [1, 2] {
        assert_eq!(instance.call_export("f1", &[]),
            Err(WasmNumericVmError::Unreachable { function_index: 0 }));
        // f1's write of 42 after the call must never execute.
        assert_eq!(instance.call_export("f2", &[]).unwrap().results, [I32(expected)]);
        assert_eq!(instance.global_export("g"), Some(&I32(expected)));
    }
    assert_eq!(vm.instantiate().unwrap().global_export("g"), Some(&I32(0)));
}

#[test]
fn indirect_recursion_uses_flat_frames_and_the_existing_signature_meter() {
    let vm = vm(INDIRECT_COUNTDOWN, WasmNumericLimits {
        max_call_depth: 10_001, max_instructions: 150_000,
        ..WasmNumericLimits::default()
    });
    let result = vm.call_export("f0", &[I32(10_000)]).unwrap();
    assert_eq!(result.results, [I32(10_000)]);
    assert_eq!(result.max_call_depth, 10_001);
    assert_eq!(result.instructions_executed, 130_006);
}

#[test]
fn startup_uses_the_same_activation_machine_and_runs_once() {
    let vm = vm(START_CHAIN, WasmNumericLimits {
        max_call_depth: 2_002, ..WasmNumericLimits::default()
    });
    let mut instance = vm.instantiate().unwrap();
    let start = instance.start_execution().unwrap().clone();
    assert_eq!(start.max_call_depth, 2_002);
    assert_eq!(instance.global_export("g"), Some(&I32(2_000)));
    for _ in 0..2 {
        let result = instance.call_export("f2", &[]).unwrap();
        assert_eq!(result.results, [I32(2_000)]);
        assert_eq!(result.max_call_depth, 1);
        assert_eq!(result.instructions_executed, 2);
        assert_eq!(instance.start_execution(), Some(&start));
    }
}

#[test]
fn imported_calls_resume_the_correct_frame_and_keep_revocation_checks() {
    let vm = vm(HOST_CHAIN, WasmNumericLimits::default());
    let grants = [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect();
    let mut imports = WasmHostImports::new(grants);
    imports.define("env", "inc", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
    }, [RuntimeCapability::Builtin].into_iter().collect(), 1, |_, arguments| {
        let [I32(value)] = arguments else { panic!("validated host ABI"); };
        Ok(vec![I32(value + 1)])
    }).unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let result = instance.call_export("f1", &[I32(34)]).unwrap();
    assert_eq!(result.results, [I32(42)]);
    assert_eq!(result.max_call_depth, 3);
    assert_eq!(result.instructions_executed, 10);
    instance.revoke_host_capability(RuntimeCapability::Builtin);
    assert!(matches!(instance.call_export("f1", &[I32(34)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied {
            capability: RuntimeCapability::Builtin, ..
        })))));
}

#[test]
fn large_local_setup_is_metered_and_refusals_do_not_poison_later_calls() {
    let vm = vm(LARGE_LOCALS, WasmNumericLimits {
        max_instructions: 3, max_live_values: 66, ..WasmNumericLimits::default()
    });
    let result = vm.call_export("f0", &[]).unwrap();
    assert_eq!(result.results, [I32(42)]);
    assert_eq!(result.instructions_executed, 3); // setup group + const + end
    let vm = WasmNumericVm::parse(&bytes(COUNTDOWN), WasmNumericLimits {
        max_instructions: 100, ..WasmNumericLimits::default()
    }).unwrap();
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.call_export("f0", &[I32(100)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 100 }));
    assert_eq!(instance.call_export("f0", &[I32(0)]).unwrap().instructions_executed, 6);
}

#[test]
fn omitted_live_value_setting_uses_a_bounded_default() {
    let limits: WasmNumericLimits = serde_json::from_str("{\"max_call_depth\":64}").unwrap();
    assert_eq!(limits.max_live_values, 1_048_576);
    assert_eq!(limits.max_call_depth, 64);
}

mod continuation_regressions {
    #![forbid(unsafe_code)]

    //! Binary programs exercise the public native VM, not a second evaluator.
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
    use frankenengine_engine::wasm_runtime_lane::numeric::{
        WasmHostImports, WasmNumericLimits, WasmNumericVm, WasmNumericVmError,
    };
    use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};

    fn leb(mut n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (n & 127) as u8;
            n >>= 7;
            bytes.push(byte | if n == 0 { 0 } else { 128 });
            if n == 0 { return bytes; }
        }
    }

    fn section(bytes: &mut Vec<u8>, id: u8, data: &[u8]) {
        bytes.push(id);
        bytes.extend(leb(data.len()));
        bytes.extend_from_slice(data);
    }

    struct Function {
        ty: u32,
        locals: Vec<u8>,
        code: Vec<u8>,
    }

    fn function(ty: u32, code: &[u8]) -> Function {
        Function { ty, locals: Vec::new(), code: code.to_vec() }
    }

    #[derive(Default)]
    struct Program {
        types: Vec<(Vec<u8>, Vec<u8>)>,
        functions: Vec<Function>,
        imports: Vec<u32>,
        table: Option<Vec<u32>>,
        start: Option<u32>,
    }

    impl Program {
        fn bytes(&self) -> Vec<u8> {
            let mut bytes = b"\0asm\x01\0\0\0".to_vec();
            let mut types = leb(self.types.len());
            for (params, results) in &self.types {
                types.push(0x60);
                types.extend(leb(params.len())); types.extend(params);
                types.extend(leb(results.len())); types.extend(results);
            }
            section(&mut bytes, 1, &types);
            if !self.imports.is_empty() {
                let mut imports = leb(self.imports.len());
                for ty in &self.imports {
                    imports.extend([1, b'h', 1, b'f', 0]);
                    imports.extend(leb(*ty as usize));
                }
                section(&mut bytes, 2, &imports);
            }
            let mut declarations = leb(self.functions.len());
            for function in &self.functions { declarations.extend(leb(function.ty as usize)); }
            section(&mut bytes, 3, &declarations);
            if let Some(entries) = &self.table {
                let mut tables = vec![1, 0x70, 0]; tables.extend(leb(entries.len()));
                section(&mut bytes, 4, &tables);
            }
            section(&mut bytes, 5, &[1, 0, 1]);
            section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
            let mut exports = leb(self.functions.len() + 2);
            for index in 0..self.functions.len() {
                let name = format!("f{index}");
                exports.extend(leb(name.len())); exports.extend(name.as_bytes());
                exports.push(0); exports.extend(leb(index + self.imports.len()));
            }
            exports.extend([1, b'm', 2, 0, 1, b'g', 3, 0]);
            section(&mut bytes, 7, &exports);
            if let Some(start) = self.start { section(&mut bytes, 8, &leb(start as usize)); }
            if let Some(entries) = &self.table {
                let mut elements = vec![1, 0, 0x41, 0, 0x0b];
                elements.extend(leb(entries.len()));
                for entry in entries { elements.extend(leb(*entry as usize)); }
                section(&mut bytes, 9, &elements);
            }
            let mut code = leb(self.functions.len());
            for function in &self.functions {
                let mut body = leb(function.locals.len());
                for ty in &function.locals { body.extend([1, *ty]); }
                body.extend(&function.code);
                code.extend(leb(body.len())); code.extend(body);
            }
            section(&mut bytes, 10, &code);
            bytes
        }

        fn vm(&self, limits: WasmNumericLimits) -> WasmNumericVm {
            WasmNumericVm::parse(&self.bytes(), limits).unwrap()
        }
    }

    fn triangle_code(call: &[u8]) -> Vec<u8> {
        let mut code = vec![0x20,0,0x45,0x04,0x7f,0x41,0,0x05,
            0x20,0,0x20,0,0x41,1,0x6b];
        code.extend_from_slice(call);
        code.extend([0x6a,0x0b,0x0b]);
        code
    }

    fn triangle(indirect: bool) -> Program {
        let call: &[u8] = if indirect { &[0x41,0,0x11,0,0] } else { &[0x10,0] };
        Program {
            types: vec![(vec![0x7f], vec![0x7f])],
            functions: vec![function(0, &triangle_code(call))],
            table: indirect.then(|| vec![0]),
            ..Program::default()
        }
    }

    #[test]
    fn deep_direct_recursion_does_not_consume_the_native_thread_stack() {
        std::thread::Builder::new().stack_size(128 * 1024).spawn(|| {
            let vm = triangle(false).vm(WasmNumericLimits {
                max_call_depth: 20_001, ..WasmNumericLimits::default()
            });
            let result = vm.call_export("f0", &[I32(20_000)]).unwrap();
            assert_eq!(result.results, [I32(200_010_000)]);
            assert_eq!(result.max_call_depth, 20_001);
            assert_eq!(result.instructions_executed, 220_006);
            assert_eq!(result.peak_stack_values, 3);
        }).unwrap().join().unwrap();
    }

    #[test]
    fn deep_indirect_recursion_uses_the_same_activation_stack_and_meter() {
        std::thread::Builder::new().stack_size(128 * 1024).spawn(|| {
            let vm = triangle(true).vm(WasmNumericLimits {
                max_call_depth: 12_001, ..WasmNumericLimits::default()
            });
            let result = vm.call_export("f0", &[I32(12_000)]).unwrap();
            assert_eq!(result.results, [I32(72_006_000)]);
            assert_eq!(result.max_call_depth, 12_001);
            assert_eq!(result.instructions_executed, 156_006);
            assert_eq!(result.peak_stack_values, 3);
        }).unwrap().join().unwrap();
    }

    #[test]
    fn mutual_recursion_restores_each_distinct_function_continuation() {
        let mut program = triangle(false);
        program.functions[0].code = triangle_code(&[0x10,1]);
        program.functions.push(function(0, &triangle_code(&[0x10,0])));
        let vm = program.vm(WasmNumericLimits::default());
        for n in [0, 1, 2, 63, 64] {
            let result = vm.call_export("f0", &[I32(n)]).unwrap();
            assert_eq!(result.results, [I32(n * (n + 1) / 2)]);
            assert_eq!(result.instructions_executed, 11 * n as u64 + 6);
            assert_eq!(result.max_call_depth, n as u32 + 1);
            assert_eq!(result, vm.call_export("f0", &[I32(n)]).unwrap());
        }
    }

    #[test]
    fn depth_refusal_precedes_callee_writes_and_retains_completed_parent_writes() {
        let mut program = triangle(false);
        let mut code = vec![0x23,0,0x41,1,0x6a,0x24,0,0x41,0,0x23,0,0x36,2,0];
        code.extend(&program.functions[0].code);
        program.functions[0].code = code;
        let vm = program.vm(WasmNumericLimits { max_call_depth: 4, ..WasmNumericLimits::default() });
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.call_export("f0", &[I32(5)]), Err(WasmNumericVmError::CallDepthExceeded { max: 4 }));
        assert_eq!(instance.global_export("g"), Some(&I32(4)));
        assert_eq!(&instance.memory_export("m").unwrap()[..4], &4_i32.to_le_bytes());
        assert_eq!(vm.instantiate().unwrap().global_export("g"), Some(&I32(0)));
        assert_eq!(instance.call_export("f0", &[I32(0)]).unwrap().results, [I32(0)]);
        assert_eq!(instance.global_export("g"), Some(&I32(5)));
    }

    #[test]
    fn budget_refusal_unwinds_suspended_frames_without_poisoning_the_next_call() {
        let vm = triangle(false).vm(WasmNumericLimits { max_instructions: 8, ..WasmNumericLimits::default() });
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.call_export("f0", &[I32(10)]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 8 }));
        let result = instance.call_export("f0", &[I32(0)]).unwrap();
        assert_eq!(result.results, [I32(0)]);
        assert_eq!(result.instructions_executed, 6);
        assert_eq!(result.max_call_depth, 1);
    }

    #[test]
    fn nested_loop_labels_and_mutated_locals_resume_after_each_call() {
        let program = Program {
            types: vec![(vec![0x7f], vec![0x7f])],
            functions: vec![
                Function { ty: 0, locals: vec![0x7f], code: vec![
                    0x41,0,0x21,1,0x02,0x40,0x03,0x40,0x20,0,0x45,0x0d,1,
                    0x20,1,0x20,0,0x10,1,0x6a,0x21,1,
                    0x20,0,0x41,1,0x6b,0x21,0,0x0c,0,0x0b,0x0b,0x20,1,0x0b,
                ] },
                function(0, &[0x20,0,0x41,2,0x6c,0x0b]),
            ], ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits::default());
        for n in [0, 1, 5, 50] {
            assert_eq!(vm.call_export("f0", &[I32(n)]).unwrap().results, [I32(n * (n + 1))]);
        }
    }

    #[test]
    fn multivalue_returns_preserve_scalar_bits_order_and_caller_prefix() {
        let values = vec![0x7d, 0x7e, 0x7c];
        let params = vec![0x7f, 0x7d, 0x7e, 0x7c];
        let program = Program {
            types: vec![(params.clone(), values.clone()), (vec![], values), (params.clone(), params)],
            functions: vec![
                function(0, &[0x20,0,0x45,0x04,1,0x20,1,0x20,2,0x20,3,0x05,
                    0x20,0,0x41,1,0x6b,0x20,1,0x20,2,0x20,3,0x10,0,0x0b,0x0b]),
                function(2, &[0x41,7,0x20,0,0x20,1,0x20,2,0x20,3,0x10,0,0x0b]),
            ], ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits::default());
        let result = vm.call_export("f1", &[I32(100), F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000)]).unwrap();
        assert_eq!(result.results, [I32(7), F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000)]);
        assert_eq!(result.max_call_depth, 102);
    }

    #[test]
    fn explicit_return_and_function_branches_transfer_only_result_values() {
        for exit in [vec![0x0f], vec![0x0c,0]] {
            let mut callee = vec![0x41,10,0x41,42];
            callee.extend(exit); callee.push(0x0b);
            let program = Program {
                types: vec![(vec![], vec![0x7f])],
                functions: vec![function(0, &[0x41,7,0x10,1,0x6a,0x0b]), function(0, &callee)],
                ..Program::default()
            };
            assert_eq!(program.vm(WasmNumericLimits::default()).call_export("f0", &[]).unwrap().results, [I32(49)]);
        }
    }

    #[test]
    fn a_guest_trap_does_not_resume_any_suspended_caller() {
        let program = Program {
            types: vec![(vec![], vec![])],
            functions: vec![
                function(0, &[0x10,1,0x41,9,0x24,0,0x0b]),
                function(0, &[0x41,7,0x24,0,0x00,0x0b]),
            ], ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.call_export("f0", &[]), Err(WasmNumericVmError::Unreachable { function_index: 1 }));
        assert_eq!(instance.global_export("g"), Some(&I32(7)));
    }

    fn host_program() -> Program {
        Program {
            types: vec![(vec![], vec![0x7f]), (vec![0x7f], vec![0x7f])],
            imports: vec![0],
            functions: vec![function(1, &[0x20,0,0x45,0x04,0x7f,0x10,0,0x05,
                0x20,0,0x41,1,0x6b,0x10,1,0x41,1,0x6a,0x0b,0x0b])],
            ..Program::default()
        }
    }

    #[test]
    fn host_leaf_results_resume_guest_frames_through_the_existing_authority_gate() {
        let vm = host_program().vm(WasmNumericLimits::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect());
        imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![WasmValueType::I32] },
            [RuntimeCapability::Builtin].into_iter().collect(), 3, move |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(vec![I32(35)])
            }).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        let result = instance.call_export("f0", &[I32(7)]).unwrap();
        assert_eq!(result.results, [I32(42)]);
        assert_eq!(result.max_call_depth, 9);
        assert_eq!(result.instructions_executed, 87);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(vm.call_export("f0", &[I32(7)]), Err(WasmNumericVmError::ImportedFunctionUnsupported { function_index: 0, .. })));
    }

    #[test]
    fn host_leaf_type_failure_never_runs_the_callers_continuation() {
        let mut program = host_program();
        program.functions[0].code = vec![0x10,0,0x41,9,0x24,0,0x0b];
        let vm = program.vm(WasmNumericLimits::default());
        let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect());
        imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![WasmValueType::I32] },
            [RuntimeCapability::Builtin].into_iter().collect(), 3, |_, _| Ok(vec![I64(35)])).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert!(instance.call_export("f0", &[I32(0)]).is_err());
        assert_eq!(instance.global_export("g"), Some(&I32(0)));
    }

    #[test]
    fn startup_uses_the_same_nonrecursive_executor_and_runs_only_once() {
        let mut program = triangle(false);
        program.types.push((vec![], vec![]));
        program.functions.push(function(1, &[0x41,50,0x10,0,0x24,0,0x0b]));
        program.start = Some(1);
        let vm = program.vm(WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.global_export("g"), Some(&I32(1275)));
        let start = instance.start_execution().unwrap().clone();
        assert_eq!(start.max_call_depth, 52);
        assert_eq!(start.instructions_executed, 560);
        instance.call_export("f0", &[I32(0)]).unwrap();
        assert_eq!(instance.start_execution(), Some(&start));
        assert_eq!(instance.global_export("g"), Some(&I32(1275)));
    }

    fn tail_sum_code(call: &[u8]) -> Vec<u8> {
        let mut code = vec![0x20,0,0x45,0x04,0x7f,0x20,1,0x05,
            0x20,0,0x41,1,0x6b,0x20,1,0x20,0,0x6a];
        code.extend_from_slice(call);
        // This instruction is valid dead code, but must never execute after a tail call.
        code.extend([0x00,0x0b,0x0b]);
        code
    }

    fn tail_sum(indirect: bool) -> Program {
        let call: &[u8] = if indirect { &[0x41,0,0x13,0,0] } else { &[0x12,0] };
        Program {
            types: vec![(vec![0x7f,0x7f], vec![0x7f])],
            functions: vec![function(0, &tail_sum_code(call))],
            table: indirect.then(|| vec![0]),
            ..Program::default()
        }
    }

    #[test]
    fn direct_and_indirect_tail_recursion_reuse_a_single_activation() {
        for indirect in [false, true] {
            std::thread::Builder::new().stack_size(128 * 1024).spawn(move || {
                let vm = tail_sum(indirect).vm(WasmNumericLimits {
                    max_call_depth: 1, ..WasmNumericLimits::default()
                });
                let result = vm.call_export("f0", &[I32(50_000), I32(0)]).unwrap();
                assert_eq!(result.results, [I32(1_250_025_000)]);
                assert_eq!(result.max_call_depth, 1);
                assert_eq!(result.instructions_executed, if indirect { 600_006 } else { 500_006 });
                assert_eq!(result.peak_stack_values, 3);
            }).unwrap().join().unwrap();
        }
    }

    #[test]
    fn mutual_tail_calls_switch_functions_without_growing_depth() {
        let mut program = tail_sum(false);
        program.functions[0].code = tail_sum_code(&[0x12,1]);
        program.functions.push(function(0, &tail_sum_code(&[0x12,0])));
        let vm = program.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() });
        let result = vm.call_export("f0", &[I32(10_001), I32(0)]).unwrap();
        assert_eq!(result.results, [I32(50_015_001)]);
        assert_eq!(result.max_call_depth, 1);
    }

    #[test]
    fn tail_calls_allow_different_parameter_arities_and_reset_callee_locals() {
        let program = Program {
            types: vec![(vec![], vec![0x7f]), (vec![0x7f], vec![0x7f])],
            functions: vec![
                Function { ty: 0, locals: vec![0x7f], code: vec![
                    0x41,9,0x21,0,0x41,7,0x41,42,0x12,1,0x00,0x0b,
                ] },
                Function { ty: 1, locals: vec![0x7f], code: vec![0x20,0,0x20,1,0x6a,0x0b] },
            ], ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() });
        assert_eq!(vm.call_export("f0", &[]).unwrap().results, [I32(42)]);
    }

    #[test]
    fn nested_tail_calls_discard_old_labels_and_operands_not_the_callers_prefix() {
        for tail in [vec![0x12,2], vec![0x41,0,0x13,1,0]] {
            let mut middle = vec![0x41,10,0x02,0x7f,0x41,42];
            middle.extend(tail); middle.extend([0x0b,0x00,0x0b]);
            let program = Program {
                types: vec![(vec![], vec![0x7f]), (vec![0x7f], vec![0x7f])],
                functions: vec![
                    function(0, &[0x41,7,0x10,1,0x6a,0x0b]),
                    function(0, &middle),
                    function(1, &[0x20,0,0x0b]),
                ], table: Some(vec![2]), ..Program::default()
            };
            let vm = program.vm(WasmNumericLimits { max_call_depth: 2, ..WasmNumericLimits::default() });
            let result = vm.call_export("f0", &[]).unwrap();
            assert_eq!(result.results, [I32(49)]);
            assert_eq!(result.max_call_depth, 2);
        }
    }

    #[test]
    fn tail_call_result_contracts_are_validated_even_in_unreachable_code() {
        for (params, results, code) in [
            (vec![], vec![0x7e], vec![0x00,0x12,1,0x0b]),
            (vec![], vec![], vec![0x00,0x12,1,0x0b]),
            (vec![], vec![0x7e], vec![0x00,0x13,1,0,0x0b]),
        ] {
            let callee = if results.is_empty() { vec![0x0b] } else { vec![0x42,0,0x0b] };
            let program = Program {
                types: vec![(vec![], vec![0x7f]), (params, results)],
                functions: vec![function(0, &code), function(1, &callee)],
                table: Some(vec![1]), ..Program::default()
            };
            assert!(WasmNumericVm::parse(&program.bytes(), WasmNumericLimits::default()).is_err());
        }
    }

    #[test]
    fn tail_immediates_and_concrete_operand_types_cannot_hide_in_dead_code() {
        for code in [
            vec![0x00,0x12,99,0x0b],
            vec![0x00,0x13,99,0,0x0b],
            vec![0x00,0x13,0,1,0x0b],
            vec![0x00,0x12,0x80,0x80,0x80,0x80,0x10,0x0b],
            vec![0x00,0x42,0,0x12,0,0x0b],
            vec![0x00,0x42,0,0x13,0,0,0x0b],
        ] {
            let mut program = triangle(false);
            program.table = Some(vec![0]);
            program.functions[0].code = code;
            assert!(WasmNumericVm::parse(&program.bytes(), WasmNumericLimits::default()).is_err());
        }
    }

    #[test]
    fn tail_indirect_type_and_bounds_traps_precede_target_effects() {
        let program = Program {
            types: vec![(vec![0x7f], vec![0x7f]), (vec![0x7f], vec![0x7e])],
            functions: vec![
                function(0, &[0x41,7,0x24,0,0x41,0,0x20,0,0x13,0,0,0x0b]),
                function(1, &[0x41,9,0x24,0,0x42,1,0x0b]),
            ], table: Some(vec![1]), ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        for index in [0, 1, -1] {
            assert!(instance.call_export("f0", &[I32(index)]).is_err());
            assert_eq!(instance.global_export("g"), Some(&I32(7)));
        }
    }

    #[test]
    fn tail_host_import_returns_directly_under_the_existing_host_contract() {
        let mut program = host_program();
        program.functions[0].code = vec![0x41,9,0x12,0,0x00,0x0b];
        let vm = program.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() });
        let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect());
        imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![WasmValueType::I32] },
            [RuntimeCapability::Builtin].into_iter().collect(), 3, |_, _| Ok(vec![I32(42)])).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        let result = instance.call_export("f0", &[I32(0)]).unwrap();
        assert_eq!(result.results, [I32(42)]);
        assert_eq!(result.max_call_depth, 1);
        assert_eq!(result.instructions_executed, 6);
        assert!(matches!(vm.call_export("f0", &[I32(0)]), Err(WasmNumericVmError::ImportedFunctionUnsupported { function_index: 0, .. })));
    }

    #[test]
    fn an_infinite_tail_cycle_exhausts_work_not_native_stack_or_call_depth() {
        let program = Program {
            types: vec![(vec![], vec![])],
            functions: vec![function(0, &[0x12,0,0x0b])],
            ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits {
            max_call_depth: 1, max_instructions: 10_000, ..WasmNumericLimits::default()
        });
        let mut instance = vm.instantiate().unwrap();
        for _ in 0..2 {
            assert_eq!(instance.call_export("f0", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 10_000 }));
        }
    }

    #[test]
    fn full_leb_tail_indices_execute_without_becoming_spurious_opcodes() {
        for instruction in [vec![0x12,0x80,0], vec![0x41,0,0x13,0x80,0,0x80,0]] {
            let mut program = tail_sum(false);
            program.table = Some(vec![0]);
            program.functions[0].code = tail_sum_code(&instruction);
            let result = program.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() })
                .call_export("f0", &[I32(100), I32(0)]).unwrap();
            assert_eq!(result.results, [I32(5050)]);
            assert_eq!(result.max_call_depth, 1);
        }
    }

    #[test]
    fn tail_loops_reuse_live_value_capacity_without_bypassing_the_limit() {
        for indirect in [false, true] {
            let program = tail_sum(indirect);
            let exact = program.vm(WasmNumericLimits {
                max_call_depth: 1, max_live_values: 5, ..WasmNumericLimits::default()
            });
            let mut instance = exact.instantiate().unwrap();
            for _ in 0..3 {
                let result = instance.call_export("f0", &[I32(5_000), I32(0)]).unwrap();
                assert_eq!(result.results, [I32(12_502_500)]);
                assert_eq!(result.max_call_depth, 1);
            }
            let tight = program.vm(WasmNumericLimits {
                max_call_depth: 1, max_live_values: 4, ..WasmNumericLimits::default()
            });
            assert!(matches!(tight.call_export("f0", &[I32(1), I32(0)]),
                Err(WasmNumericVmError::LiveValueLimitExceeded { actual: 5, max: 4 })));
            assert_eq!(tight.call_export("f0", &[I32(0), I32(7)]).unwrap().results, [I32(7)]);
        }
    }

    #[test]
    fn tail_replacement_keeps_older_suspended_prefixes_charged_exactly_once() {
        for indirect in [false, true] {
            let call: &[u8] = if indirect { &[0x41,0,0x13,1,0] } else { &[0x12,1] };
            let program = Program {
                types: vec![(vec![], vec![0x7f]), (vec![0x7f; 2], vec![0x7f])],
                functions: vec![
                    function(0, &[0x41,7,0x41,20,0x41,0,0x10,1,0x6a,0x0b]),
                    function(1, &tail_sum_code(call)),
                ], table: Some(vec![1]), ..Program::default()
            };
            let exact = program.vm(WasmNumericLimits {
                max_call_depth: 2, max_live_values: 6, ..WasmNumericLimits::default()
            });
            let mut instance = exact.instantiate().unwrap();
            for _ in 0..3 {
                let result = instance.call_export("f0", &[]).unwrap();
                assert_eq!(result.results, [I32(217)]);
                assert_eq!(result.max_call_depth, 2);
            }
            let tight = program.vm(WasmNumericLimits {
                max_call_depth: 2, max_live_values: 5, ..WasmNumericLimits::default()
            });
            assert!(matches!(tight.call_export("f0", &[]),
                Err(WasmNumericVmError::LiveValueLimitExceeded { actual: 6, max: 5 })));
        }
    }

    #[test]
    fn tail_callee_local_admission_precedes_effects_and_releases_old_locals() {
        let program = Program {
            types: vec![(vec![], vec![0x7f]), (vec![0x7f], vec![0x7f])],
            functions: vec![
                Function { ty: 0, locals: vec![0x7f; 2], code: vec![
                    0x41,7,0x24,0,0x41,7,0x41,42,0x12,1,0x0b,
                ] },
                Function { ty: 1, locals: vec![0x7f; 4], code: vec![
                    0x41,9,0x24,0,0x20,0,0x0b,
                ] },
            ], ..Program::default()
        };
        let tight = program.vm(WasmNumericLimits {
            max_call_depth: 1, max_live_values: 4, ..WasmNumericLimits::default()
        });
        let mut instance = tight.instantiate().unwrap();
        assert!(matches!(instance.call_export("f0", &[]),
            Err(WasmNumericVmError::LiveValueLimitExceeded { actual: 5, max: 4 })));
        assert_eq!(instance.global_export("g"), Some(&I32(7)));
        let exact = program.vm(WasmNumericLimits {
            max_call_depth: 1, max_live_values: 6, ..WasmNumericLimits::default()
        });
        let mut instance = exact.instantiate().unwrap();
        assert_eq!(instance.call_export("f0", &[]).unwrap().results, [I32(42)]);
        assert_eq!(instance.global_export("g"), Some(&I32(9)));
    }

    #[test]
    fn zero_result_host_tails_resume_older_callers_and_cannot_bypass_revocation() {
        use frankenengine_engine::wasm_runtime_lane::numeric::{WasmHostError, WasmStateError};
        for indirect in [false, true] {
            let tail: &[u8] = if indirect { &[0x41,0,0x13,1,0,0x0b] } else { &[0x12,0,0x0b] };
            let program = Program {
                types: vec![(vec![], vec![0x7f]), (vec![], vec![])],
                imports: vec![1],
                functions: vec![
                    function(0, &[0x41,42,0x10,2,0x0b]),
                    Function { ty: 1, locals: vec![0x7f; 3], code: tail.to_vec() },
                ], table: Some(vec![0]), ..Program::default()
            };
            let vm = program.vm(WasmNumericLimits {
                max_call_depth: 2, max_live_values: 5, ..WasmNumericLimits::default()
            });
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect());
            imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
                [RuntimeCapability::Builtin].into_iter().collect(), 1, move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![])
                }).unwrap();
            let mut instance = vm.instantiate_with_imports(imports).unwrap();
            for _ in 0..3 {
                let result = instance.call_export("f0", &[]).unwrap();
                assert_eq!(result.results, [I32(42)]);
                assert_eq!(result.max_call_depth, 2);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            instance.revoke_host_capability(RuntimeCapability::Builtin);
            assert!(matches!(instance.call_export("f0", &[]),
                Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied {
                    capability: RuntimeCapability::Builtin, ..
                })))));
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }
    }

    #[test]
    fn tail_host_refusal_never_resumes_the_older_guest_continuation() {
        let program = Program {
            types: vec![(vec![], vec![0x7f])], imports: vec![0],
            functions: vec![
                function(0, &[0x10,2,0x41,9,0x24,0,0x0b]),
                function(0, &[0x12,0,0x00,0x0b]),
            ], ..Program::default()
        };
        let vm = program.vm(WasmNumericLimits { max_call_depth: 2, ..WasmNumericLimits::default() });
        for bad_type in [false, true] {
            let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect());
            imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![WasmValueType::I32] },
                [RuntimeCapability::Builtin].into_iter().collect(), 1, move |caller, _| {
                    if bad_type { return Ok(vec![I64(42)]); }
                    let _ = caller.charge_work(u64::MAX);
                    Ok(vec![I32(42)])
                }).unwrap();
            let mut instance = vm.instantiate_with_imports(imports).unwrap();
            let result = instance.call_export("f0", &[]);
            if bad_type {
                assert!(matches!(result, Err(WasmNumericVmError::TypeMismatch { .. })));
            } else {
                assert!(matches!(result, Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
            }
            assert_eq!(instance.global_export("g"), Some(&I32(0)));
        }
    }

    #[test]
    fn startup_tail_calls_and_multivalue_tails_keep_the_existing_boundaries() {
        let startup = Program {
            types: vec![(vec![], vec![])],
            functions: vec![function(0, &[0x12,1,0x0b]), function(0, &[0x41,7,0x24,0,0x0b])],
            start: Some(0), ..Program::default()
        };
        let vm = startup.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() });
        let instance = vm.instantiate().unwrap();
        assert_eq!(instance.global_export("g"), Some(&I32(7)));
        let start = instance.start_execution().unwrap();
        assert_eq!(start.max_call_depth, 1);
        assert_eq!(start.instructions_executed, 4);
        for indirect in [false, true] {
            let mut code = vec![0x41,7,0x20,0,0x20,1,0x20,2];
            code.extend_from_slice(if indirect { &[0x41,0,0x13,0,0,0x0b] } else { &[0x12,1,0x0b] });
            let types = vec![0x7d, 0x7e, 0x7c];
            let program = Program {
                types: vec![(types.clone(), types)],
                functions: vec![function(0, &code), function(0, &[0x20,0,0x20,1,0x20,2,0x0b])],
                table: Some(vec![1]), ..Program::default()
            };
            let vm = program.vm(WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() });
            let values = [F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000)];
            let result = vm.call_export("f0", &values).unwrap();
            assert_eq!(result.results, values);
            assert_eq!(result.max_call_depth, 1);
        }
    }
}
