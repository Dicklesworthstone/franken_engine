#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const ADD_I32_HEX: &str = "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b";
const DIV_I32_HEX: &str = "0061736d0100000001070160027f7f017f030201000707010364697600000a09010700200020016d0b";
const IF_I32_HEX: &str = "0061736d0100000001070160027f7f017f030201000707010361646400000a0901070020002001040b";

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
    assert_eq!(json["execution"]["results"], serde_json::json!([{"I32":42}]));
    assert_eq!(json["execution"]["max_call_depth"], 1);
    assert!(json["execution"]["instructions_executed"].as_u64().unwrap_or(0) >= 4);
}

#[test]
fn integer_divide_by_zero_traps_at_process_boundary() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{DIV_I32_HEX}","export":"div","arguments":[{{"I32":7}},{{"I32":0}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("divide by zero"), "unexpected stderr: {stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn instruction_budget_exhaustion_fails_closed() {
    let output = run_vm(&format!(
        r#"{{
            "module_hex":"{ADD_I32_HEX}",
            "export":"add",
            "arguments":[{{"I32":1}},{{"I32":2}}],
            "limits":{{
                "max_module_bytes":16777216,
                "max_functions":65536,
                "max_locals_per_call":65536,
                "max_stack_values":65536,
                "max_call_depth":256,
                "max_instructions":2
            }}
        }}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("instruction budget"), "unexpected stderr: {stderr}");
}

#[test]
fn unsupported_control_flow_fails_closed() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{IF_I32_HEX}","export":"add","arguments":[{{"I32":1}},{{"I32":2}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported opcode 0x04"), "unexpected stderr: {stderr}");
}

#[test]
fn argument_type_mismatch_fails_closed() {
    let output = run_vm(&format!(
        r#"{{"module_hex":"{ADD_I32_HEX}","export":"add","arguments":[{{"I32":1}},{{"I64":2}}]}}"#
    ));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expects i32, got i64"), "unexpected stderr: {stderr}");
}

#[test]
fn malformed_hex_is_rejected_before_execution() {
    let output = run_vm(r#"{"module_hex":"xyz","export":"add"}"#);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not valid hexadecimal"));
}
