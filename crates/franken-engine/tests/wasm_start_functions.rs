#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::I32;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmNumericLimits, WasmNumericVm, WasmNumericVmError, WasmStateError,
};

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

struct Fixture {
    types: Vec<(Vec<u8>, Vec<u8>)>,
    functions: Vec<(u32, Vec<u8>)>,
    starts: Vec<Vec<u8>>,
    imports: Vec<u8>,
    tables: Vec<u8>,
    elements: Vec<u8>,
    memory: Vec<u8>,
    data: Vec<u8>,
    exports: Vec<u8>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            types: vec![(vec![], vec![]), (vec![], vec![0x7f])],
            functions: vec![
                (0, vec![0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x0b]),
                (1, vec![0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x23, 0, 0x0b]),
            ],
            starts: vec![vec![0]],
            imports: vec![],
            tables: vec![],
            elements: vec![],
            memory: vec![],
            data: vec![],
            exports: vec![2, 1, b'f', 0, 1, 1, b'g', 3, 0],
        }
    }
}

impl Fixture {
    fn bytes(&self) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        let mut types = leb(self.types.len());
        for (params, results) in &self.types {
            types.push(0x60);
            types.extend(leb(params.len()));
            types.extend(params);
            types.extend(leb(results.len()));
            types.extend(results);
        }
        section(&mut module, 1, &types);
        if !self.imports.is_empty() {
            section(&mut module, 2, &self.imports);
        }
        let mut declarations = leb(self.functions.len());
        for (ty, _) in &self.functions {
            declarations.extend(leb(*ty as usize));
        }
        section(&mut module, 3, &declarations);
        if !self.tables.is_empty() {
            section(&mut module, 4, &self.tables);
        }
        if !self.memory.is_empty() {
            section(&mut module, 5, &self.memory);
        }
        section(&mut module, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
        section(&mut module, 7, &self.exports);
        for start in &self.starts {
            section(&mut module, 8, start);
        }
        if !self.elements.is_empty() {
            section(&mut module, 9, &self.elements);
        }
        let mut bodies = leb(self.functions.len());
        for (_, code) in &self.functions {
            bodies.extend(leb(code.len() + 1));
            bodies.push(0);
            bodies.extend(code);
        }
        section(&mut module, 10, &bodies);
        if !self.data.is_empty() {
            section(&mut module, 11, &self.data);
        }
        module
    }

    fn vm(&self) -> WasmNumericVm {
        WasmNumericVm::parse(&self.bytes(), WasmNumericLimits::default()).unwrap()
    }

    fn with_memory(&mut self) {
        self.memory = vec![1, 1, 1, 2];
        self.data = vec![1, 0, 0x41, 0, 0x0b, 4, 41, 0, 0, 0];
        self.exports[0] += 1;
        self.exports.extend([1, b'm', 2, 0]);
    }
}

#[test]
fn start_runs_once_per_instance_before_any_export() {
    let vm = Fixture::default().vm();
    let mut a = vm.instantiate().unwrap();
    let mut b = vm.instantiate().unwrap();
    assert_eq!(a.global_export("g"), Some(&I32(1)));
    assert_eq!(b.global_export("g"), Some(&I32(1)));
    let startup = a.start_execution().unwrap().clone();
    assert!(startup.results.is_empty());
    assert_eq!(startup.instructions_executed, 5);
    assert_eq!(startup.peak_stack_values, 2);
    assert_eq!(startup.max_call_depth, 1);
    assert_eq!(a.call_export("f", &[]).unwrap().results, [I32(2)]);
    assert_eq!(a.call_export("f", &[]).unwrap().results, [I32(3)]);
    assert_eq!(b.call_export("f", &[]).unwrap().results, [I32(2)]);
    assert_eq!(a.start_execution(), Some(&startup));
    assert_eq!(vm.instantiate().unwrap().start_execution(), Some(&startup));
    let first = vm.call_export("f", &[]).unwrap();
    assert_eq!(first.results, [I32(2)]);
    assert_eq!(first, vm.call_export("f", &[]).unwrap());
}

#[test]
fn start_reads_initialized_data_and_publishes_its_memory_writes() {
    let mut fixture = Fixture::default();
    fixture.with_memory();
    fixture.functions[0].1 = vec![
        0x41, 0, 0x28, 2, 0, 0x41, 1, 0x6a, 0x24, 0, 0x41, 4, 0x23, 0, 0x36, 2, 0, 0x0b,
    ];
    let vm = fixture.vm();
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.global_export("g"), Some(&I32(42)));
    assert_eq!(
        &instance.memory_export("m").unwrap()[..8],
        &[41, 0, 0, 0, 42, 0, 0, 0]
    );
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 9);
    assert_eq!(instance.call_export("f", &[]).unwrap().results, [I32(43)]);
}

#[test]
fn start_can_dispatch_through_initialized_element_segments() {
    let mut fixture = Fixture::default();
    fixture.tables = vec![1, 0x70, 0, 1];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 2];
    fixture.functions.push((0, vec![0x41, 42, 0x24, 0, 0x0b]));
    fixture.functions[0].1 = vec![0x41, 0, 0x11, 0, 0, 0x0b];
    let vm = fixture.vm();
    let instance = vm.instantiate().unwrap();
    assert_eq!(instance.global_export("g"), Some(&I32(42)));
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 6);
    assert_eq!(instance.start_execution().unwrap().max_call_depth, 2);
}

#[test]
fn absent_start_is_distinct_from_an_empty_start_and_never_invokes_function_zero() {
    let mut fixture = Fixture::default();
    fixture.functions[0].1 = vec![0x00, 0x0b];
    fixture.starts.clear();
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_instructions: 0,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let instance = vm.instantiate().unwrap();
    assert_eq!(instance.start_execution(), None);
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
    fixture.functions[0].1 = vec![0x0b];
    fixture.starts.push(vec![0]);
    let vm = fixture.vm();
    assert_eq!(
        vm.instantiate()
            .unwrap()
            .start_execution()
            .unwrap()
            .instructions_executed,
        1
    );
}

#[test]
fn a_non_exported_start_function_still_executes() {
    let mut fixture = Fixture::default();
    fixture.exports = vec![1, 1, b'g', 3, 0];
    let vm = fixture.vm();
    assert_eq!(vm.export_names().count(), 0);
    assert_eq!(vm.instantiate().unwrap().global_export("g"), Some(&I32(1)));
}

#[test]
fn start_indices_signatures_and_section_integrity_are_validated_before_execution() {
    for starts in [
        vec![vec![99]],
        vec![vec![1]],
        vec![vec![0, 0]],
        vec![vec![]],
        vec![vec![0x80]],
        vec![vec![0], vec![0]],
    ] {
        let mut fixture = Fixture::default();
        fixture.starts = starts;
        assert!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()).is_err());
    }
    let mut fixture = Fixture::default();
    fixture.types[0].0 = vec![0x7f];
    assert!(
        matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::InvalidModule { detail }) if detail.contains("[] -> []"))
    );
    fixture.types[0].0.clear();
    fixture.starts = vec![vec![0x80, 0]]; // padded u32 index zero is valid
    assert_eq!(
        fixture.vm().instantiate().unwrap().global_export("g"),
        Some(&I32(1))
    );
}

#[test]
fn a_trapping_start_never_returns_a_partial_instance_and_parse_does_not_execute_it() {
    let mut fixture = Fixture::default();
    fixture.functions[0].1 = vec![0x41, 42, 0x24, 0, 0x00, 0x0b];
    let vm = fixture.vm();
    for _ in 0..3 {
        assert!(matches!(
            vm.instantiate(),
            Err(WasmNumericVmError::Unreachable { function_index: 0 })
        ));
    }
    assert!(matches!(
        vm.call_export("f", &[]),
        Err(WasmNumericVmError::Unreachable { function_index: 0 })
    ));
    fixture.starts.clear();
    assert_eq!(
        fixture.vm().instantiate().unwrap().global_export("g"),
        Some(&I32(0))
    );
}

#[test]
fn segment_bounds_fail_before_start_code_is_entered() {
    let mut fixture = Fixture::default();
    fixture.with_memory();
    fixture.data = vec![1, 0, 0x41, 0x7f, 0x0b, 0]; // offset -1, even for zero bytes
    fixture.functions[0].1 = vec![0x00, 0x0b];
    assert!(matches!(
        fixture.vm().instantiate(),
        Err(WasmNumericVmError::State(
            WasmStateError::DataSegmentOutOfBounds { .. }
        ))
    ));
    fixture.data.clear();
    fixture.tables = vec![1, 0x70, 0, 0];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 0];
    assert!(matches!(
        fixture.vm().instantiate(),
        Err(WasmNumericVmError::State(
            WasmStateError::ElementSegmentOutOfBounds { .. }
        ))
    ));
}

#[test]
fn start_uses_exact_instruction_and_call_depth_limits_without_unmetered_loops() {
    let mut fixture = Fixture::default();
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_instructions: 4,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        vm.instantiate(),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 4 })
    ));
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_instructions: 5,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        vm.instantiate()
            .unwrap()
            .start_execution()
            .unwrap()
            .instructions_executed,
        5
    );
    fixture.functions[0].1 = vec![0x03, 0x40, 0x0c, 0, 0x0b, 0x0b];
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_instructions: 17,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        vm.instantiate(),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 17 })
    ));
    fixture.functions[0].1 = vec![0x10, 0, 0x0b];
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_call_depth: 4,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        vm.instantiate(),
        Err(WasmNumericVmError::CallDepthExceeded { max: 4 })
    ));
}

#[test]
fn start_memory_growth_uses_the_same_native_work_meter() {
    let mut fixture = Fixture::default();
    fixture.with_memory();
    fixture.functions[0].1 = vec![0x41, 1, 0x40, 0, 0x1a, 0x0b];
    let vm = fixture.vm();
    let instance = vm.instantiate().unwrap();
    assert_eq!(instance.memory_export("m").unwrap().len(), 131_072);
    assert_eq!(
        instance.start_execution().unwrap().instructions_executed,
        1028
    );
    let vm = WasmNumericVm::parse(
        &fixture.bytes(),
        WasmNumericLimits {
            max_instructions: 1027,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        vm.instantiate(),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 1027 })
    ));
}

#[test]
fn imported_start_function_does_not_acquire_ambient_host_authority() {
    let mut fixture = Fixture::default();
    fixture.imports = vec![1, 1, b'h', 1, b'f', 0, 0];
    fixture.functions.clear();
    fixture.exports = vec![1, 1, b'g', 3, 0];
    assert!(
        matches!(fixture.vm().instantiate(), Err(WasmNumericVmError::ImportedFunctionUnsupported { function_index: 0, module, name }) if module == "h" && name == "f")
    );
}

#[test]
fn cli_runs_initialization_and_reports_start_and_export_work_separately() {
    let fixture = Fixture::default();
    let vm = fixture.vm();
    let mut instance = vm.instantiate().unwrap();
    let startup = serde_json::to_value(instance.start_execution().unwrap()).unwrap();
    let invocation = serde_json::to_value(instance.call_export("f", &[]).unwrap()).unwrap();
    let request = serde_json::json!({"module_hex": hex::encode(fixture.bytes()), "export": "f", "limits": {"max_instructions": 6}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken_wasm_numeric"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["start_execution"], startup);
    assert_eq!(response["execution"], invocation);
    assert_eq!(
        response["execution"]["results"],
        serde_json::json!([{"I32": 2}])
    );
}
