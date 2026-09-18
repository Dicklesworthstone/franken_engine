#![forbid(unsafe_code)]

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, numeric as wasm_numeric_vm};
use wasm_numeric_vm::{WasmNumericExecution, WasmNumericLimits, WasmNumericVm};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    module_hex: String,
    export: String,
    #[serde(default)]
    arguments: Vec<WasmBoundaryValue>,
    #[serde(default)]
    limits: Option<WasmNumericLimits>,
}

#[derive(Debug, Serialize)]
struct Response {
    component: &'static str,
    schema_version: &'static str,
    export: String,
    available_exports: Vec<String>,
    execution: WasmNumericExecution,
}

fn decode_module_hex(
    module_hex: &str,
    limits: &WasmNumericLimits,
) -> Result<Vec<u8>, String> {
    let module_hex = module_hex.trim();
    if module_hex.len() % 2 != 0 {
        return Err("module_hex must contain an even number of hexadecimal digits".to_string());
    }
    let max_hex_digits = limits
        .max_module_bytes
        .checked_mul(2)
        .unwrap_or(usize::MAX);
    if module_hex.len() > max_hex_digits {
        return Err(format!(
            "module_hex represents {} bytes; limit is {}",
            module_hex.len() / 2,
            limits.max_module_bytes
        ));
    }
    hex::decode(module_hex).map_err(|error| format!("module_hex is not valid hexadecimal: {error}"))
}

fn run(request: Request) -> Result<Response, String> {
    let limits = request.limits.unwrap_or_default();
    let module_bytes = decode_module_hex(&request.module_hex, &limits)?;
    let vm = WasmNumericVm::parse(&module_bytes, limits).map_err(|error| error.to_string())?;
    let available_exports = vm.export_names().map(str::to_string).collect();
    let execution = vm
        .call_export(&request.export, &request.arguments)
        .map_err(|error| error.to_string())?;
    Ok(Response {
        component: wasm_numeric_vm::WASM_NUMERIC_VM_COMPONENT,
        schema_version: wasm_numeric_vm::WASM_NUMERIC_VM_SCHEMA_VERSION,
        export: request.export,
        available_exports,
        execution,
    })
}

fn main() {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read wasm numeric request from stdin: {error}");
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_str(&input) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("invalid wasm numeric request JSON: {error}");
            std::process::exit(2);
        }
    };
    let response = match run(request) {
        Ok(response) => response,
        Err(error) => {
            eprintln!("wasm numeric execution failed: {error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string_pretty(&response) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode wasm numeric response: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADD_I32_HEX: &str = "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b";

    #[test]
    fn request_executes_real_parameterized_wasm() {
        let response = run(Request {
            module_hex: ADD_I32_HEX.to_string(),
            export: "add".to_string(),
            arguments: vec![WasmBoundaryValue::I32(20), WasmBoundaryValue::I32(22)],
            limits: None,
        })
        .expect("execute add");
        assert_eq!(response.execution.results, vec![WasmBoundaryValue::I32(42)]);
        assert_eq!(response.available_exports, vec!["add".to_string()]);
    }

    #[test]
    fn invalid_hex_fails_closed() {
        let error = run(Request {
            module_hex: "xy".to_string(),
            export: "add".to_string(),
            arguments: Vec::new(),
            limits: None,
        })
        .expect_err("invalid hex must fail");
        assert!(error.contains("not valid hexadecimal"));
    }

    #[test]
    fn odd_hex_fails_before_decode() {
        let error = decode_module_hex("abc", &WasmNumericLimits::default()).unwrap_err();
        assert!(error.contains("even number"));
    }

    #[test]
    fn module_size_limit_fails_before_decode_allocation() {
        let limits = WasmNumericLimits {
            max_module_bytes: 2,
            ..WasmNumericLimits::default()
        };
        let error = decode_module_hex("000102", &limits).unwrap_err();
        assert!(error.contains("3 bytes; limit is 2"));
    }
}
