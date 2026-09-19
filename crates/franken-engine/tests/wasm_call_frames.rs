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
