//! Binary programs run through the production validator and instance executor.
use super::*;

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

fn fixture(operation: &[u8], params: &[u8], results: &[u8], elements: &[u8]) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![3, 0x60, 0, 1, 0x7f, 0x60];
    types.extend(leb(params.len()));
    types.extend_from_slice(params);
    types.extend(leb(results.len()));
    types.extend_from_slice(results);
    types.extend([0x60, 1, 0x7f, 1, 0x7f]);
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &[6, 0, 0, 0, 1, 2, 2]);
    section(&mut bytes, 4, &[2, 0x70, 1, 6, 6, 0x70, 1, 6, 6]);
    section(&mut bytes, 7, &[5, 1, b'f', 0, 3, 1, b'a', 0, 4, 1, b'b', 0, 5, 1, b't', 1, 0, 1, b'u', 1, 1]);
    section(&mut bytes, 9, elements);
    let mut body = vec![0];
    body.extend_from_slice(operation);
    let mut bodies = vec![6];
    for code in [
        &[0, 0x41, 10, 0x0b][..], &[0, 0x41, 20, 0x0b][..],
        &[0, 0x41, 30, 0x0b][..], body.as_slice(),
        &[0, 0x20, 0, 0x11, 0, 0, 0x0b][..],
        &[0, 0x20, 0, 0x11, 0, 1, 0x0b][..],
    ] {
        bodies.extend(leb(code.len()));
        bodies.extend_from_slice(code);
    }
    section(&mut bytes, 10, &bodies);
    bytes
}

// Table zero starts [f0, f1, f2, null, null, null]; table one is all null.
fn active_elements() -> Vec<u8> { vec![1, 0, 0x41, 0, 0x0b, 3, 0, 1, 2] }

fn copy_code(to: u8, from: u8) -> Vec<u8> {
    vec![0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 14, to, from, 0x0b]
}

fn vm(code: &[u8], limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(code, &[0x7f; 3], &[], &active_elements()), limits).unwrap()
}

fn args(values: [i32; 3]) -> [WasmBoundaryValue; 3] { values.map(WasmBoundaryValue::I32) }

#[test]
fn table_copy_handles_both_overlaps_without_a_temporary_snapshot() {
    let vm = vm(&copy_code(0, 0), WasmNumericLimits::default());
    for (values, expected) in [
        ([1, 0, 3], [Some(0), Some(0), Some(1), Some(2), None, None]),
        ([0, 1, 3], [Some(1), Some(2), None, None, None, None]),
        ([0, 0, 6], [Some(0), Some(1), Some(2), None, None, None]),
        ([6, 6, 0], [Some(0), Some(1), Some(2), None, None, None]),
    ] {
        let mut instance = vm.instantiate().unwrap();
        instance.call_export("f", &args(values)).unwrap();
        assert_eq!(instance.table_export("t").unwrap(), &expected);
    }
}

#[test]
fn cross_table_copy_changes_real_indirect_dispatch_and_preserves_nulls() {
    let vm = vm(&copy_code(1, 0), WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f", &args([1, 0, 4])).unwrap();
    assert_eq!(instance.table_export("u").unwrap(), &[None, Some(0), Some(1), Some(2), None, None]);
    for (slot, expected) in [(1, 10), (2, 20), (3, 30)] {
        assert_eq!(instance.call_export("b", &[WasmBoundaryValue::I32(slot)]).unwrap().results, [WasmBoundaryValue::I32(expected)]);
    }
    assert!(matches!(instance.call_export("b", &[WasmBoundaryValue::I32(4)]), Err(WasmNumericVmError::State(WasmStateError::UninitializedTableElement { .. }))));
    let vm = vm_for_reverse_copy();
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f", &args([0, 0, 3])).unwrap();
    assert_eq!(instance.table_export("t").unwrap(), &[None; 6]);
}

fn vm_for_reverse_copy() -> WasmNumericVm {
    vm(&copy_code(0, 1), WasmNumericLimits::default())
}

#[test]
fn table_copy_checks_entire_unsigned_ranges_before_any_mutation() {
    for (to, from) in [(0, 0), (1, 0), (0, 1)] {
        let vm = vm(&copy_code(to, from), WasmNumericLimits::default());
        for values in [[5, 0, 2], [0, 5, 2], [-1, 0, 1], [0, -1, 1], [0, 0, -1], [7, 0, 0], [0, 7, 0]] {
            let mut instance = vm.instantiate().unwrap();
            let before_t = instance.table_export("t").unwrap().to_vec();
            let before_u = instance.table_export("u").unwrap().to_vec();
            assert!(matches!(instance.call_export("f", &args(values)), Err(WasmNumericVmError::State(WasmStateError::TableElementOutOfBounds { .. }))));
            assert_eq!(instance.table_export("t").unwrap(), before_t);
            assert_eq!(instance.table_export("u").unwrap(), before_u);
        }
    }
}

#[test]
fn table_copy_precharges_reference_work_and_refuses_atomically() {
    let vm = vm(&copy_code(1, 0), WasmNumericLimits { max_instructions: 6, ..WasmNumericLimits::default() });
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.call_export("f", &args([0, 0, 3])), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 6 }));
    assert_eq!(instance.table_export("u").unwrap(), &[None; 6]);
    for length in 0..=6 {
        let budget = 5 + length as u64;
        let vm = self::vm(&copy_code(1, 0), WasmNumericLimits { max_instructions: budget, ..WasmNumericLimits::default() });
        assert_eq!(vm.call_export("f", &args([0, 0, length])).unwrap().instructions_executed, budget);
    }
}

#[test]
fn completed_table_copy_survives_later_trap_without_cross_instance_leaks() {
    let mut code = copy_code(1, 0);
    code.insert(code.len() - 1, 0x00);
    let vm = vm(&code, WasmNumericLimits::default());
    let mut first = vm.instantiate().unwrap();
    let second = vm.instantiate().unwrap();
    assert!(matches!(first.call_export("f", &args([0, 0, 3])), Err(WasmNumericVmError::Unreachable { .. })));
    assert_eq!(first.table_export("u").unwrap(), &[Some(0), Some(1), Some(2), None, None, None]);
    assert_eq!(second.table_export("u").unwrap(), &[None; 6]);
}

#[test]
fn table_size_uses_the_declared_table_and_the_normal_stack_meter() {
    for code in [vec![0xfc, 16, 0, 0x0b], vec![0xfc, 0x90, 0, 0x81, 0, 0x0b]] {
        let bytes = fixture(&code, &[], &[0x7f], &active_elements());
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
        let result = vm.call_export("f", &[]).unwrap();
        assert_eq!(result.results, [WasmBoundaryValue::I32(6)]);
        assert_eq!(result.instructions_executed, 2);
        assert_eq!(result.peak_stack_values, 1);
        assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits { max_stack_values: 0, ..WasmNumericLimits::default() }).is_err());
    }
}

#[test]
fn table_bulk_immediates_and_types_are_validated_even_in_dead_code() {
    for instruction in [vec![0xfc, 14, 2, 0], vec![0xfc, 14, 0, 2], vec![0xfc, 16, 2], vec![0xfc, 14, 0, 0x80], vec![0xfc, 16, 0x80, 0x80, 0x80, 0x80, 0x10]] {
        let mut code = vec![0x00];
        code.extend(instruction);
        code.push(0x0b);
        assert!(WasmNumericVm::parse(&fixture(&code, &[], &[], &active_elements()), WasmNumericLimits::default()).is_err());
    }
    for wrong in 0..3 {
        let mut code = vec![0x00];
        for operand in 0..3 { code.extend([if operand == wrong { 0x42 } else { 0x41 }, 0]); }
        code.extend([0xfc, 14, 0, 0, 0x0b]);
        assert!(matches!(WasmNumericVm::parse(&fixture(&code, &[], &[], &active_elements()), WasmNumericLimits::default()), Err(WasmNumericVmError::TypeMismatch { .. })));
    }
}

#[test]
fn padded_table_copy_encodings_replay_the_same_results_and_work() {
    let plain = vm(&copy_code(1, 0), WasmNumericLimits::default());
    let padded = vm(&[0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 0x8e, 0, 0x81, 0, 0x80, 0, 0x0b], WasmNumericLimits::default());
    let mut a = plain.instantiate().unwrap();
    let mut b = padded.instantiate().unwrap();
    assert_eq!(a.call_export("f", &args([1, 0, 3])).unwrap(), b.call_export("f", &args([1, 0, 3])).unwrap());
    assert_eq!(a.table_export("u"), b.table_export("u"));
}
