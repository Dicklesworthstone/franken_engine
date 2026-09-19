#![forbid(unsafe_code)]

use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmNumericLimits, WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
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
    tables: Vec<u8>,
    elements: Vec<u8>,
    imports: Vec<u8>,
    globals: Vec<u8>,
    exports: Vec<u8>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            types: vec![(vec![0x7f, 0x7f], vec![0x7f]), (vec![0x7f; 3], vec![0x7f])],
            functions: vec![
                (0, vec![0x20, 0, 0x20, 1, 0x6a, 0x0b]),
                (0, vec![0x20, 0, 0x20, 1, 0x6b, 0x0b]),
                (1, vec![0x20, 0, 0x20, 1, 0x20, 2, 0x11, 0, 0, 0x0b]),
            ],
            tables: vec![1, 0x70, 1, 3, 3],
            elements: vec![1, 0, 0x41, 0, 0x0b, 2, 0, 1],
            imports: Vec::new(),
            globals: Vec::new(),
            exports: vec![2, 1, b'f', 0, 2, 1, b't', 1, 0],
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
        if !self.imports.is_empty() { section(&mut module, 2, &self.imports); }
        let mut declarations = leb(self.functions.len());
        for (ty, _) in &self.functions { declarations.extend(leb(*ty as usize)); }
        section(&mut module, 3, &declarations);
        if !self.tables.is_empty() { section(&mut module, 4, &self.tables); }
        if !self.globals.is_empty() { section(&mut module, 6, &self.globals); }
        section(&mut module, 7, &self.exports);
        if !self.elements.is_empty() { section(&mut module, 9, &self.elements); }
        let mut bodies = leb(self.functions.len());
        for (_, code) in &self.functions {
            bodies.extend(leb(code.len() + 1));
            bodies.push(0);
            bodies.extend(code);
        }
        section(&mut module, 10, &bodies);
        module
    }

    fn vm(&self) -> WasmNumericVm {
        WasmNumericVm::parse(&self.bytes(), WasmNumericLimits::default()).unwrap()
    }

    fn with_global(&mut self) {
        self.globals = vec![1, 0x7f, 1, 0x41, 0, 0x0b];
        self.exports[0] += 1;
        self.exports.extend([1, b'g', 3, 0]);
    }
}

#[test]
fn table_dispatch_selects_real_functions_and_replays_with_shared_meter() {
    let vm = Fixture::default().vm();
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.table_export("t"), Some([Some(0), Some(1), None].as_slice()));
    for (index, expected) in [(0, 42), (1, 16)] {
        let args = [I32(29), I32(13), I32(index)];
        let result = instance.call_export("f", &args).unwrap();
        assert_eq!(result.results, [I32(expected)]);
        assert_eq!(result.max_call_depth, 2);
        // Nine guest instructions plus one bounded signature-comparison unit.
        assert_eq!(result.instructions_executed, 10);
        assert_eq!(result, vm.call_export("f", &args).unwrap());
    }
    assert!(instance.table_export("missing").is_none());
    assert!(instance.table_export("f").is_none());
    assert!(instance.memory_export("t").is_none());
    assert!(matches!(instance.call_export("t", &[]), Err(WasmNumericVmError::ExportIsNotFunction { kind: 1, .. })));
}

#[test]
fn null_and_unsigned_out_of_range_indices_trap_without_fabricated_results() {
    let vm = Fixture::default().vm();
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2), I32(2)]), Err(WasmNumericVmError::State(WasmStateError::UninitializedTableElement { table_index: 0, element_index: 2 }))));
    for (index, unsigned) in [(3, 3), (-1, u32::MAX), (i32::MIN, 0x8000_0000)] {
        assert!(matches!(instance.call_export("f", &[I32(1), I32(2), I32(index)]), Err(WasmNumericVmError::State(WasmStateError::TableElementOutOfBounds { table_index: 0, element_index, table_size: 3 })) if element_index == unsigned));
    }
    assert_eq!(instance.call_export("f", &[I32(20), I32(22), I32(0)]).unwrap().results, [I32(42)]);
}

#[test]
fn duplicate_type_indices_match_structurally() {
    let mut fixture = Fixture::default();
    fixture.types.push(fixture.types[0].clone());
    fixture.functions[0].0 = 2;
    assert_eq!(fixture.vm().call_export("f", &[I32(20), I32(22), I32(0)]).unwrap().results, [I32(42)]);
}

#[test]
fn signature_mismatch_is_detected_before_any_callee_effects() {
    for params in [vec![], vec![0x7f, 0x7f]] {
        let mut fixture = Fixture::default();
        fixture.with_global();
        fixture.types.push((params, vec![0x7e]));
        fixture.functions[0] = (2, vec![0x41, 42, 0x24, 0, 0x42, 1, 0x0b]);
        let vm = fixture.vm();
        let mut instance = vm.instantiate().unwrap();
        assert!(matches!(instance.call_export("f", &[I32(20), I32(22), I32(0)]), Err(WasmNumericVmError::State(WasmStateError::IndirectCallTypeMismatch { function_index: 0, type_index: 0 }))));
        assert_eq!(instance.global_export("g"), Some(&I32(0)));
    }
}

#[test]
fn indirect_calls_preserve_multivalue_order_and_exact_scalar_bits() {
    let mut fixture = Fixture::default();
    let values = vec![0x7d, 0x7e, 0x7c, 0x7f];
    let mut params = values.clone();
    params.push(0x7f);
    fixture.types = vec![(values.clone(), values.clone()), (params, values)];
    fixture.functions = vec![
        (0, vec![0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x0b]),
        (1, vec![0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x20, 4, 0x11, 0, 0, 0x0b]),
    ];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 0];
    fixture.exports[4] = 1;
    let args = [F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000), I32(-9), I32(0)];
    let result = fixture.vm().call_export("f", &args).unwrap();
    assert_eq!(result.results, args[..4]);
    assert_eq!(result.max_call_depth, 2);
    assert_eq!(result.peak_stack_values, 5);
}

#[test]
fn explicit_nonzero_table_indices_and_element_encodings_execute() {
    for elements in [
        vec![1, 2, 1, 0x41, 0, 0x0b, 0, 2, 0, 1],
        vec![1, 6, 1, 0x41, 0, 0x0b, 0x70, 2, 0xd2, 0, 0x0b, 0xd2, 1, 0x0b],
    ] {
        let mut fixture = Fixture::default();
        fixture.tables = vec![2, 0x70, 0, 0, 0x70, 1, 2, 2];
        fixture.elements = elements;
        fixture.functions[2].1[8] = 1;
        fixture.exports[8] = 1;
        let vm = fixture.vm();
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.table_export("t"), Some([Some(0), Some(1)].as_slice()));
        assert_eq!(instance.call_export("f", &[I32(29), I32(13), I32(1)]).unwrap().results, [I32(16)]);
    }
}

#[test]
fn expression_elements_preserve_explicit_nulls() {
    let mut fixture = Fixture::default();
    fixture.elements = vec![1, 4, 0x41, 0, 0x0b, 3, 0xd2, 0, 0x0b, 0xd0, 0x70, 0x0b, 0xd2, 1, 0x0b];
    let vm = fixture.vm();
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.table_export("t"), Some([Some(0), None, Some(1)].as_slice()));
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2), I32(1)]), Err(WasmNumericVmError::State(WasmStateError::UninitializedTableElement { .. }))));
    assert_eq!(instance.call_export("f", &[I32(29), I32(13), I32(2)]).unwrap().results, [I32(16)]);
}

#[test]
fn later_element_segments_win_and_empty_end_boundary_is_valid() {
    let mut fixture = Fixture::default();
    fixture.elements = vec![3, 0, 0x41, 0, 0x0b, 2, 0, 1, 2, 0, 0x41, 1, 0x0b, 0, 1, 0, 0, 0x41, 3, 0x0b, 0];
    let vm = fixture.vm();
    let instance = vm.instantiate().unwrap();
    assert_eq!(instance.table_export("t"), Some([Some(0), Some(0), None].as_slice()));
}

#[test]
fn element_bounds_fail_at_instantiation_without_wrapping_or_partial_publication() {
    for (offset, entries) in [(3, vec![0]), (4, vec![]), (0x7f, vec![])] {
        let mut fixture = Fixture::default();
        fixture.elements = vec![2, 0, 0x41, 0, 0x0b, 1, 0, 0, 0x41, offset, 0x0b];
        fixture.elements.extend(leb(entries.len()));
        fixture.elements.extend(entries);
        let vm = fixture.vm();
        assert!(matches!(vm.instantiate(), Err(WasmNumericVmError::State(WasmStateError::ElementSegmentOutOfBounds { segment: 1, .. }))));
    }
}

#[test]
fn all_element_function_indices_are_validated_even_without_defined_functions() {
    let mut fixture = Fixture::default();
    fixture.functions.clear();
    fixture.exports = vec![1, 1, b't', 1, 0];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 0];
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::UnknownFunction { function_index: 0 })));
}

#[test]
fn invalid_indirect_immediates_and_operands_fail_whole_body_validation() {
    for code in [
        vec![0x00, 0x11, 99, 0, 0x0b],
        vec![0x00, 0x11, 0, 1, 0x0b],
        vec![0x00, 0x11, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0b],
        vec![0x41, 1, 0x42, 2, 0x41, 0, 0x11, 0, 0, 0x0b],
        vec![0x41, 1, 0x41, 2, 0x42, 0, 0x11, 0, 0, 0x0b],
        vec![0x41, 0, 0x11, 0, 0, 0x0b],
    ] {
        let mut fixture = Fixture::default();
        fixture.functions[2].1 = code;
        assert!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()).is_err());
    }
    let mut fixture = Fixture::default();
    fixture.tables.clear();
    fixture.elements.clear();
    fixture.exports = vec![1, 1, b'f', 0, 2];
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::State(WasmStateError::UnknownTable { table_index: 0 }))));
}

#[test]
fn imported_function_targets_cannot_bypass_the_host_authority_boundary() {
    let mut fixture = Fixture::default();
    fixture.imports = vec![1, 1, b'h', 1, b'f', 0, 0];
    fixture.functions = vec![fixture.functions[2].clone()];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 0];
    fixture.exports[4] = 1;
    let vm = fixture.vm();
    assert!(matches!(vm.call_export("f", &[I32(1), I32(2), I32(0)]), Err(WasmNumericVmError::ImportedFunctionUnsupported { function_index: 0, module, name }) if module == "h" && name == "f"));
}

#[test]
fn recursive_indirect_calls_obey_the_same_call_depth_and_instruction_caps() {
    let mut fixture = Fixture::default();
    fixture.types = vec![(vec![0x7f], vec![0x7f])];
    fixture.functions = vec![(0, vec![0x20, 0, 0x45, 0x04, 0x7f, 0x41, 0, 0x05, 0x20, 0, 0x20, 0, 0x41, 1, 0x6b, 0x41, 0, 0x11, 0, 0, 0x6a, 0x0b, 0x0b])];
    fixture.elements = vec![1, 0, 0x41, 0, 0x0b, 1, 0];
    fixture.exports[4] = 0;
    assert_eq!(fixture.vm().call_export("f", &[I32(5)]).unwrap().results, [I32(15)]);
    let vm = WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_call_depth: 4, ..WasmNumericLimits::default() }).unwrap();
    assert_eq!(vm.call_export("f", &[I32(5)]), Err(WasmNumericVmError::CallDepthExceeded { max: 4 }));
    let vm = WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_instructions: 5, ..WasmNumericLimits::default() }).unwrap();
    assert_eq!(vm.call_export("f", &[I32(5)]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 5 }));
}

#[test]
fn indirect_callee_effects_persist_per_instance_and_budget_refuses_before_entry() {
    let mut fixture = Fixture::default();
    fixture.with_global();
    fixture.functions[0].1 = vec![0x23, 0, 0x20, 0, 0x6a, 0x24, 0, 0x23, 0, 0x0b];
    let vm = fixture.vm();
    let mut a = vm.instantiate().unwrap();
    let b = vm.instantiate().unwrap();
    assert_eq!(a.call_export("f", &[I32(2), I32(0), I32(0)]).unwrap().results, [I32(2)]);
    assert_eq!(a.call_export("f", &[I32(3), I32(0), I32(0)]).unwrap().results, [I32(5)]);
    assert_eq!(b.global_export("g"), Some(&I32(0)));
    let vm = WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_instructions: 4, ..WasmNumericLimits::default() }).unwrap();
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.call_export("f", &[I32(7), I32(0), I32(0)]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 4 }));
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
}

#[test]
fn completed_indirect_callee_writes_survive_a_later_dispatch_trap() {
    let mut fixture = Fixture::default();
    fixture.with_global();
    fixture.functions[0].1 = vec![0x20, 0, 0x24, 0, 0x23, 0, 0x0b];
    fixture.functions[2].1 = vec![
        0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x1a,
        0x20, 0, 0x20, 1, 0x20, 2, 0x11, 0, 0, 0x0b,
    ];
    let vm = fixture.vm();
    let mut instance = vm.instantiate().unwrap();
    for index in [2, -1] {
        assert!(instance.call_export("f", &[I32(42), I32(0), I32(index)]).is_err());
        assert_eq!(instance.global_export("g"), Some(&I32(42)));
        assert_eq!(instance.table_export("t"), Some([Some(0), Some(1), None].as_slice()));
    }
    assert_eq!(vm.instantiate().unwrap().global_export("g"), Some(&I32(0)));
}

#[test]
fn malformed_or_unsupported_tables_and_elements_are_refused() {
    for table in [vec![1, 0x6f, 0, 1], vec![1, 0x70, 2, 1], vec![1, 0x70, 1, 2, 1], vec![1, 0x70, 0, 0x80]] {
        let mut fixture = Fixture::default();
        fixture.tables = table;
        assert!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()).is_err());
    }
    for elements in [
        vec![1, 1, 0, 1, 0], // passive elements are not yet executable
        vec![1, 0, 0x42, 0, 0x0b, 0], // wrong offset type
        vec![1, 2, 1, 0x41, 0, 0x0b, 0, 0], // missing table
        vec![1, 0, 0x41, 0, 0x0b, 2, 0], // truncated vector
        vec![1, 0, 0x41, 0, 0x0b, 1, 99], // missing function
        vec![1, 4, 0x41, 0, 0x0b, 1, 0xd0, 0x6f, 0x0b], // extern null
        vec![1, 4, 0x41, 0, 0x0b, 1, 0xd2, 0, 0xd2, 1, 0x0b], // trailing expression
    ] {
        let mut fixture = Fixture::default();
        fixture.elements = elements;
        assert!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()).is_err());
    }
}

#[test]
fn table_and_element_allocations_share_the_instance_record_ceiling() {
    let fixture = Fixture::default();
    // One table + three slots + one segment + two function references.
    assert!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_state_entries: 7, ..WasmNumericLimits::default() }).unwrap().instantiate().is_ok());
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_state_entries: 6, ..WasmNumericLimits::default() }), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 7, max: 6, .. }))));
    let mut fixture = fixture;
    fixture.with_global();
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_state_entries: 7, ..WasmNumericLimits::default() }), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 8, max: 7, .. }))));
    fixture.tables = vec![1, 0x70, 0, 0xff, 0xff, 0xff, 0xff, 0x0f];
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { .. }))));
}

#[test]
fn duplicate_export_names_and_invalid_table_exports_fail_validation() {
    for exports in [vec![2, 1, b'f', 0, 2, 1, b'f', 1, 0], vec![2, 1, b't', 1, 0, 1, b't', 1, 0]] {
        let mut fixture = Fixture::default();
        fixture.exports = exports;
        assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::DuplicateExport { .. })));
    }
    let mut fixture = Fixture::default();
    fixture.exports[8] = 1;
    assert!(matches!(WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits::default()), Err(WasmNumericVmError::State(WasmStateError::UnknownTable { table_index: 1 }))));
}
