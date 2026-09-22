#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue,
    numeric::{WasmNumericLimits, WasmNumericVm, WasmNumericVmError},
};
use serde_json::Value;

const ADD_I32_HEX: &str =
    "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b";
const CALL_ADD_I32_HEX: &str = "0061736d0100000001070160027f7f017f03030200000707010361646400010a11020700200020016a0b07002000200110000b";
const RECURSIVE_VOID_HEX: &str =
    "0061736d01000000010401600000030201000707010372656300000a0601040010000b";
const DIV_I32_HEX: &str =
    "0061736d0100000001070160027f7f017f030201000707010364697600000a09010700200020016d0b";
const IF_I32_HEX: &str =
    "0061736d0100000001070160027f7f017f030201000707010361646400000a0901070020002001040b";

fn run_vm(input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken_wasm_numeric"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wasm numeric runner");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write request");
    child.wait_with_output().expect("wasm numeric output")
}

fn successful_json(input: &str) -> Value {
    let output = run_vm(input);
    assert!(
        output.status.success(),
        "wasm runner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("runner JSON")
}

#[test]
fn parameterized_i32_add_executes_through_process_boundary() {
    let json = successful_json(&format!(
        r#"{{"module_hex":"{ADD_I32_HEX}","export":"add","arguments":[{{"I32":20}},{{"I32":22}}]}}"#
    ));
    assert_eq!(json["component"], "wasm_numeric_vm");
    assert_eq!(
        json["execution"]["results"],
        serde_json::json!([{"I32":42}])
    );
    assert_eq!(json["execution"]["max_call_depth"], 1);
    assert!(
        json["execution"]["instructions_executed"]
            .as_u64()
            .unwrap_or(0)
            >= 4
    );
}

#[test]
fn direct_local_function_call_executes_with_shared_meter() {
    let json = successful_json(&format!(
        r#"{{"module_hex":"{CALL_ADD_I32_HEX}","export":"add","arguments":[{{"I32":19}},{{"I32":23}}]}}"#
    ));
    assert_eq!(
        json["execution"]["results"],
        serde_json::json!([{"I32":42}])
    );
    assert_eq!(json["execution"]["max_call_depth"], 2);
    assert!(
        json["execution"]["instructions_executed"]
            .as_u64()
            .unwrap_or(0)
            >= 8
    );
}

#[test]
fn recursive_call_hits_deterministic_call_depth_limit() {
    let output = run_vm(&format!(
        r#"{{
            "module_hex":"{RECURSIVE_VOID_HEX}",
            "export":"rec",
            "limits":{{"max_call_depth":4}}
        }}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("call depth exceeds limit 4"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn integer_divide_by_zero_traps_at_process_boundary() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{DIV_I32_HEX}","export":"div","arguments":[{{"I32":7}},{{"I32":0}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("divide by zero"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn instruction_budget_exhaustion_fails_closed() {
    let output = run_vm(&format!(
        r#"{{
            "module_hex":"{ADD_I32_HEX}",
            "export":"add",
            "arguments":[{{"I32":1}},{{"I32":2}}],
            "limits":{{"max_instructions":2}}
        }}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("instruction budget"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn malformed_if_block_type_fails_before_execution() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{IF_I32_HEX}","export":"add","arguments":[{{"I32":1}},{{"I32":2}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // This fixture has an if followed by 0x0b where its block type belongs.
    // That decodes as missing type index 11, not an unsupported if opcode.
    assert!(
        stderr.contains("type index 11 is out of bounds"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn argument_type_mismatch_fails_closed() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{ADD_I32_HEX}","export":"add","arguments":[{{"I32":1}},{{"I64":2}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expects i32, got i64"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn malformed_hex_is_rejected_before_execution() {
    let output = run_vm(r#"{"module_hex":"xy","export":"add"}"#);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not valid hexadecimal"));
}

#[test]
fn oversized_hex_is_rejected_before_decode_allocation() {
    let output =
        run_vm(r#"{"module_hex":"000102","export":"add","limits":{"max_module_bytes":2}}"#);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("3 bytes; limit is 2"));
}

// f(delta) increments an instance global, stores it in linear memory and
// returns it. m and g are declared exports, not host-provided capabilities.
const STATEFUL_I32_HEX: &str = "0061736d0100000001060160017f017f0302010005030100010606017f0141000b070d0301660000016d0200016703000a14011200230020006a24004100230036020023000b";
const VALID_IF_I32_HEX: &str =
    "0061736d0100000001060160017f017f03020100070501016600000a0e010c002000047f412a0541090b0b";

#[test]
fn embedded_instances_retain_memory_and_globals_without_cross_instance_state() {
    let bytes = hex::decode(STATEFUL_I32_HEX).unwrap();
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let mut a = vm.instantiate().unwrap();
    let mut b = vm.instantiate().unwrap();
    for (delta, expected) in [(2_i32, 2_i32), (3, 5)] {
        let execution = a
            .call_export("f", &[WasmBoundaryValue::I32(delta)])
            .unwrap();
        assert_eq!(execution.results, [WasmBoundaryValue::I32(expected)]);
        assert_eq!(
            a.global_export("g"),
            Some(&WasmBoundaryValue::I32(expected))
        );
        assert_eq!(&a.memory_export("m").unwrap()[..4], &expected.to_le_bytes());
        assert_eq!(execution.instructions_executed, 9);
    }
    assert_eq!(b.global_export("g"), Some(&WasmBoundaryValue::I32(0)));
    assert!(b.memory_export("m").unwrap().iter().all(|byte| *byte == 0));
    assert_eq!(
        b.call_export("f", &[WasmBoundaryValue::I32(7)])
            .unwrap()
            .results,
        [WasmBoundaryValue::I32(7)]
    );
    assert_eq!(a.global_export("g"), Some(&WasmBoundaryValue::I32(5)));
    assert!(a.memory_export("undeclared").is_none());
    assert!(a.global_export("undeclared").is_none());
}

#[test]
fn embedding_type_and_budget_refusals_do_not_mutate_instance_state() {
    let bytes = hex::decode(STATEFUL_I32_HEX).unwrap();
    let vm = WasmNumericVm::parse(
        &bytes,
        WasmNumericLimits {
            max_instructions: 3,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(
        instance.call_export("f", &[WasmBoundaryValue::I64(7)]),
        Err(WasmNumericVmError::TypeMismatch { .. })
    ));
    // global.set is the fourth instruction: the budget stops before that
    // mutation, not after publishing a partially updated instance.
    assert_eq!(
        instance.call_export("f", &[WasmBoundaryValue::I32(7)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 3 })
    );
    assert_eq!(
        instance.global_export("g"),
        Some(&WasmBoundaryValue::I32(0))
    );
    assert!(
        instance
            .memory_export("m")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn cli_and_embedded_execution_use_the_same_vm_and_instruction_accounting() {
    let bytes = hex::decode(STATEFUL_I32_HEX).unwrap();
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let expected = vm.call_export("f", &[WasmBoundaryValue::I32(17)]).unwrap();
    let response = successful_json(&format!(
        r#"{{"module_hex":"{STATEFUL_I32_HEX}","export":"f","arguments":[{{"I32":17}}]}}"#
    ));
    assert_eq!(
        response["execution"],
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(
        response["execution"]["results"],
        serde_json::json!([{"I32":17}])
    );
    assert_eq!(response["available_exports"], serde_json::json!(["f"]));
}

#[test]
fn valid_conditional_executes_both_arms_through_cli_and_library() {
    let bytes = hex::decode(VALID_IF_I32_HEX).unwrap();
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    for (condition, expected) in [(0, 9), (1, 42), (-1, 42)] {
        let execution = vm
            .call_export("f", &[WasmBoundaryValue::I32(condition)])
            .unwrap();
        assert_eq!(execution.results, [WasmBoundaryValue::I32(expected)]);
        let response = successful_json(&format!(
            r#"{{"module_hex":"{VALID_IF_I32_HEX}","export":"f","arguments":[{{"I32":{condition}}}]}}"#
        ));
        assert_eq!(
            response["execution"],
            serde_json::to_value(&execution).unwrap()
        );
    }
}

#[test]
fn existing_abi_public_paths_still_describe_the_same_numeric_types() {
    use frankenengine_engine::wasm_runtime_lane::{WasmModuleAbi, WasmValueType};
    let bytes = hex::decode(ADD_I32_HEX).unwrap();
    let abi = WasmModuleAbi::from_source(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let export = abi.function_exports.get("add").unwrap();
    assert_eq!(
        export.signature.params,
        [WasmValueType::I32, WasmValueType::I32]
    );
    assert_eq!(export.signature.results, [WasmValueType::I32]);
    assert!(export.const_body.is_none());
    // Non-constant execution belongs to the shared numeric VM rather than
    // pretending the older constant-body ABI route has executed this body.
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    assert_eq!(
        vm.call_export(
            "add",
            &[WasmBoundaryValue::I32(2), WasmBoundaryValue::I32(3)]
        )
        .unwrap()
        .results,
        [WasmBoundaryValue::I32(5)]
    );
}
