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

fn elements(mode: u8, functions: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1, mode];
    if mode & 1 == 0 {
        if mode & 2 != 0 { bytes.push(1); }
        bytes.extend([0x41, 0, 0x0b]);
    }
    if mode & 3 != 0 { bytes.push(if mode & 4 == 0 { 0 } else { 0x70 }); }
    bytes.extend(leb(functions.len()));
    for function in functions {
        if mode & 4 == 0 { bytes.push(*function); }
        else if *function == 255 { bytes.extend([0xd0, 0x70, 0x0b]); }
        else { bytes.extend([0xd2, *function, 0x0b]); }
    }
    bytes
}

fn init_code(element: u8, table: u8) -> Vec<u8> {
    vec![0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 12, element, table, 0x0b]
}

fn element_vm(code: &[u8], elements: &[u8], limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(code, &[0x7f; 3], &[], elements), limits).unwrap()
}

#[test]
fn passive_index_and_expression_elements_initialize_real_dispatch() {
    for (mode, functions, expected) in [
        (1, [0, 1, 2], [Some(0), Some(1), Some(2)]),
        (5, [0, 255, 2], [Some(0), None, Some(2)]),
    ] {
        let vm = element_vm(&init_code(0, 1), &elements(mode, &functions), WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.table_export("u").unwrap(), &[None; 6]);
        instance.call_export("f", &args([1, 0, 3])).unwrap();
        assert_eq!(&instance.table_export("u").unwrap()[1..4], &expected);
        assert_eq!(instance.call_export("b", &[WasmBoundaryValue::I32(1)]).unwrap().results, [WasmBoundaryValue::I32(10)]);
        assert_eq!(instance.call_export("b", &[WasmBoundaryValue::I32(3)]).unwrap().results, [WasmBoundaryValue::I32(30)]);
        if mode == 5 {
            assert!(matches!(instance.call_export("b", &[WasmBoundaryValue::I32(2)]), Err(WasmNumericVmError::State(WasmStateError::UninitializedTableElement { .. }))));
        }
    }
}

#[test]
fn initialization_does_not_consume_passive_elements_or_share_table_mutation() {
    let vm = element_vm(&init_code(0, 1), &elements(1, &[0, 1, 2]), WasmNumericLimits::default());
    let mut first = vm.instantiate().unwrap();
    let mut second = vm.instantiate().unwrap();
    let result = first.call_export("f", &args([0, 0, 3])).unwrap();
    first.call_export("f", &args([3, 0, 3])).unwrap();
    assert_eq!(first.table_export("u").unwrap(), &[Some(0), Some(1), Some(2), Some(0), Some(1), Some(2)]);
    assert_eq!(second.table_export("u").unwrap(), &[None; 6]);
    assert_eq!(second.call_export("f", &args([0, 0, 3])).unwrap(), result);
    assert_eq!(vm.call_export("f", &args([0, 0, 3])).unwrap(), result);
}

// destination == 0 selects elem.drop; any other destination selects table.init.
fn drop_or_init(trap_after_drop: bool) -> Vec<u8> {
    let mut code = vec![0x20, 0, 0x45, 0x04, 0x40, 0xfc, 13, 0];
    if trap_after_drop { code.push(0x00); }
    code.extend([0x05, 0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 12, 0, 1, 0x0b, 0x0b]);
    code
}

#[test]
fn element_drop_is_idempotent_instance_local_and_keeps_copied_references() {
    let vm = element_vm(&drop_or_init(false), &elements(1, &[0, 1, 2]), WasmNumericLimits::default());
    let mut first = vm.instantiate().unwrap();
    let mut second = vm.instantiate().unwrap();
    first.call_export("f", &args([1, 0, 3])).unwrap();
    first.call_export("f", &args([0, 0, 0])).unwrap();
    first.call_export("f", &args([0, 0, 0])).unwrap();
    assert!(matches!(first.call_export("f", &args([1, 0, 1])), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 1, max: 0, .. }))));
    assert_eq!(first.call_export("b", &[WasmBoundaryValue::I32(2)]).unwrap().results, [WasmBoundaryValue::I32(20)]);
    first.call_export("f", &args([6, 0, 0])).unwrap();
    assert!(first.call_export("f", &args([6, 1, 0])).is_err());
    second.call_export("f", &args([1, 0, 3])).unwrap();
    assert_eq!(first.table_export("u"), second.table_export("u"));
}

#[test]
fn all_active_and_declarative_encodings_are_dropped_before_guest_execution() {
    for mode in [0, 2, 3, 4, 6, 7] {
        let vm = element_vm(&init_code(0, 1), &elements(mode, &[0, 1, 2]), WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        let before = instance.table_export("u").unwrap().to_vec();
        assert!(matches!(instance.call_export("f", &args([0, 0, 1])), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 1, max: 0, .. }))));
        assert_eq!(instance.table_export("u").unwrap(), before);
        instance.call_export("f", &args([6, 0, 0])).unwrap();
        assert!(instance.call_export("f", &args([0, 1, 0])).is_err());
    }
}

#[test]
fn table_init_checks_source_and_destination_extents_before_writes() {
    let vm = element_vm(&init_code(0, 1), &elements(1, &[0, 1, 2]), WasmNumericLimits::default());
    for values in [[5, 0, 2], [0, 2, 2], [-1, 0, 1], [0, -1, 1], [0, 0, -1], [7, 0, 0], [0, 4, 0]] {
        let mut instance = vm.instantiate().unwrap();
        assert!(instance.call_export("f", &args(values)).is_err());
        assert_eq!(instance.table_export("u").unwrap(), &[None; 6]);
        instance.call_export("f", &args([0, 0, 3])).unwrap();
        assert_eq!(&instance.table_export("u").unwrap()[..3], &[Some(0), Some(1), Some(2)]);
    }
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f", &args([6, 3, 0])).unwrap();
    assert!(matches!(instance.call_export("f", &args([0, 2, 2])), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 4, max: 3, resource })) if resource == "element segment 0 source range"));
}

#[test]
fn table_initialization_and_drop_obey_pre_mutation_budget_refusal() {
    let source = elements(1, &[0, 1, 2]);
    let vm = element_vm(&init_code(0, 1), &source, WasmNumericLimits { max_instructions: 6, ..WasmNumericLimits::default() });
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(instance.call_export("f", &args([0, 0, 3])), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 6 }));
    assert_eq!(instance.table_export("u").unwrap(), &[None; 6]);
    instance.call_export("f", &args([0, 0, 1])).unwrap();
    assert_eq!(instance.table_export("u").unwrap()[0], Some(0));
    for length in 0..=3 {
        let budget = 5 + length as u64;
        let vm = element_vm(&init_code(0, 1), &source, WasmNumericLimits { max_instructions: budget, ..WasmNumericLimits::default() });
        assert_eq!(vm.call_export("f", &args([0, 0, length])).unwrap().instructions_executed, budget);
    }
    let bytes = fixture(&[0xfc, 13, 0, 0x0b], &[], &[], &source);
    for (budget, dropped) in [(0, false), (1, true), (2, true)] {
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_instructions: budget, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = vm.instantiate().unwrap();
        let result = instance.call_export("f", &[]);
        assert_eq!(result.is_ok(), budget == 2);
        assert_eq!(instance.state.tables.elements[0].is_none(), dropped);
    }
}

#[test]
fn completed_element_drop_survives_later_traps_but_not_across_instances() {
    let vm = element_vm(&drop_or_init(true), &elements(1, &[0]), WasmNumericLimits::default());
    let mut first = vm.instantiate().unwrap();
    let mut second = vm.instantiate().unwrap();
    assert!(matches!(first.call_export("f", &args([0, 0, 0])), Err(WasmNumericVmError::Unreachable { .. })));
    assert!(first.call_export("f", &args([1, 0, 1])).is_err());
    second.call_export("f", &args([1, 0, 1])).unwrap();
    assert_eq!(second.call_export("b", &[WasmBoundaryValue::I32(1)]).unwrap().results, [WasmBoundaryValue::I32(10)]);
}

fn with_start(bytes: &[u8], start: u8) -> Vec<u8> {
    let mut result = bytes[..8].to_vec();
    let mut reader = ByteReader::new(&bytes[8..]);
    while !reader.remaining().is_empty() {
        let id = reader.read_u8().unwrap();
        let length = reader.read_u32_leb().unwrap() as usize;
        let payload = reader.read_bytes(length).unwrap();
        if id == 9 { section(&mut result, 8, &[start]); }
        section(&mut result, id, payload);
    }
    result
}

#[test]
fn start_function_can_initialize_and_drop_passive_dispatch_tables() {
    let code = [0x41, 0, 0x41, 0, 0x41, 3, 0xfc, 12, 0, 1, 0xfc, 13, 0, 0x0b];
    let bytes = with_start(&fixture(&code, &[], &[], &elements(1, &[0, 1, 2])), 3);
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let mut instance = vm.instantiate().unwrap();
    let startup = instance.start_execution().unwrap().clone();
    assert_eq!(startup.instructions_executed, 9);
    for _ in 0..2 {
        assert_eq!(instance.call_export("b", &[WasmBoundaryValue::I32(1)]).unwrap().results, [WasmBoundaryValue::I32(20)]);
        assert_eq!(instance.start_execution(), Some(&startup));
    }
    assert!(instance.call_export("f", &[]).is_err()); // a second initialization sees a dropped segment
    assert_eq!(vm.instantiate().unwrap().start_execution(), Some(&startup));
    // Active segments are already dropped when start executes, so no partial
    // instance is returned from this otherwise valid module.
    let bytes = with_start(&fixture(&code, &[], &[], &elements(0, &[0, 1, 2])), 3);
    assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap().instantiate().is_err());
}

#[test]
fn passive_and_declarative_segments_need_no_table_for_element_drop() {
    for mode in [1, 3, 5, 7] {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, 7, &[1, 1, b'f', 0, 0]);
        section(&mut bytes, 9, &elements(mode, &[]));
        section(&mut bytes, 10, &[1, 5, 0, 0xfc, 13, 0, 0x0b]);
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
        assert!(vm.call_export("f", &[]).unwrap().results.is_empty());
    }
}

#[test]
fn table_init_binary_indices_and_padded_immediates_are_not_reversed() {
    // Element 0 is empty; element 1 holds f2. Destination table is 0.
    let sources = [2, 1, 0, 0, 1, 0, 1, 2];
    for code in [init_code(1, 0), vec![0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 0x8c, 0, 0x81, 0, 0x80, 0, 0x0b]] {
        let vm = element_vm(&code, &sources, WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        instance.call_export("f", &args([0, 0, 1])).unwrap();
        assert_eq!(instance.table_export("t").unwrap()[0], Some(2));
        assert_eq!(instance.call_export("a", &[WasmBoundaryValue::I32(0)]).unwrap().results, [WasmBoundaryValue::I32(30)]);
    }
    for instruction in [vec![0xfc, 12, 2, 0], vec![0xfc, 12, 0, 2], vec![0xfc, 13, 2], vec![0xfc, 13, 0x80, 0x80, 0x80, 0x80, 0x10]] {
        let mut code = vec![0x00]; code.extend(instruction); code.push(0x0b);
        assert!(WasmNumericVm::parse(&fixture(&code, &[], &[], &sources), WasmNumericLimits::default()).is_err());
    }
    for wrong in 0..3 {
        let mut code = vec![0x00];
        for operand in 0..3 { code.extend([if wrong == operand { 0x42 } else { 0x41 }, 0]); }
        code.extend([0xfc, 12, 0, 0, 0x0b]);
        assert!(matches!(WasmNumericVm::parse(&fixture(&code, &[], &[], &sources), WasmNumericLimits::default()), Err(WasmNumericVmError::TypeMismatch { .. })));
    }
}

#[test]
fn all_element_modes_validate_references_types_and_shared_resource_limits() {
    for mode in [1, 3, 5, 7] {
        let bytes = fixture(&[0x0b], &[], &[], &elements(mode, &[99]));
        assert!(matches!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()), Err(WasmNumericVmError::UnknownFunction { function_index: 99 })));
    }
    for bad in [vec![1, 8], vec![1, 1, 1, 0], vec![1, 5, 0x6f, 0], vec![1, 3, 0, 2, 0], vec![1, 7, 0x70, 1, 0xd2, 0, 0xd2, 1, 0x0b]] {
        assert!(WasmNumericVm::parse(&fixture(&[0x0b], &[], &[], &bad), WasmNumericLimits::default()).is_err());
    }
    let bytes = fixture(&init_code(0, 1), &[0x7f; 3], &[], &elements(1, &[0, 1, 2]));
    assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits { max_state_entries: 18, ..WasmNumericLimits::default() }).unwrap().instantiate().is_ok());
    assert!(matches!(WasmNumericVm::parse(&bytes, WasmNumericLimits { max_state_entries: 17, ..WasmNumericLimits::default() }), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { actual: 18, max: 17, .. }))));
}

#[test]
fn passive_initialization_does_not_bypass_indirect_signature_checks() {
    // The initialized target is f itself, with the wrong signature for b.
    let vm = element_vm(&init_code(0, 1), &elements(1, &[3]), WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f", &args([0, 0, 1])).unwrap();
    assert!(matches!(instance.call_export("b", &[WasmBoundaryValue::I32(0)]), Err(WasmNumericVmError::State(WasmStateError::IndirectCallTypeMismatch { function_index: 3, .. }))));
    assert_eq!(instance.table_export("u").unwrap()[0], Some(3));
}
