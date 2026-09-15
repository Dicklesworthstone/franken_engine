#![forbid(unsafe_code)]

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

pub use frankenengine_engine::wasm_runtime_lane;

#[path = "../wasm_numeric_vm.rs"]
mod wasm_numeric_vm;

use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue;
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

fn run(request: Request) -> Result<Response, String> {
    let module_bytes = hex::decode(request.module_hex.trim())
        .map_err(|error| format!("module_hex is not valid hexadecimal: {error}"))?;
    let vm = WasmNumericVm::parse(&module_bytes, request.limits.unwrap_or_default())
        .map_err(|error| error.to_string())?;
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
            module_hex: "xyz".to_string(),
            export: "add".to_string(),
            arguments: Vec::new(),
            limits: None,
        })
        .expect_err("invalid hex must fail");
        assert!(error.contains("not valid hexadecimal"));
    }
}
