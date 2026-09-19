use super::*;

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len() as u32));
    module.extend_from_slice(payload);
}

fn module(params: &[u8], results: &[u8], code: &[u8], memory: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![1, 0x60];
    types.extend(leb(params.len() as u32));
    types.extend_from_slice(params);
    types.extend(leb(results.len() as u32));
    types.extend_from_slice(results);
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &[1, 0]);
    if memory {
        section(&mut bytes, 5, &[1, 1, 1, 2]);
    }
    let mut exports = vec![1 + u8::from(memory), 1, b'f', 0, 0];
    if memory {
        exports.extend([1, b'm', 2, 0]);
    }
    section(&mut bytes, 7, &exports);
    let mut bodies = vec![1];
    bodies.extend(leb(code.len() as u32 + 1));
    bodies.push(0);
    bodies.extend_from_slice(code);
    section(&mut bytes, 10, &bodies);
    bytes
}

fn conversion_module(subopcode: u32, padded: bool) -> Vec<u8> {
    let input = if subopcode & 2 == 0 { 0x7d } else { 0x7c };
    let output = if subopcode < 4 { 0x7f } else { 0x7e };
    let mut code = vec![0x20, 0, PREFIX];
    if padded {
        code.extend([subopcode as u8 | 128, 128, 128, 128, 0]);
    } else {
        code.extend(leb(subopcode));
    }
    code.push(0x0b);
    module(&[input], &[output], &code, false)
}

fn input(subopcode: u32, number: f64) -> WasmBoundaryValue {
    if subopcode & 2 == 0 {
        WasmBoundaryValue::F32Bits((number as f32).to_bits())
    } else {
        WasmBoundaryValue::F64Bits(number.to_bits())
    }
}

#[test]
fn all_eight_saturating_conversions_have_numeric_not_trapping_semantics() {
    // Values in these rows are exact in f32 and f64. Expectations are constants,
    // not the casts used by the implementation under test.
    let rows = [
        (0.0, 0_i32, 0_i32, 0_i64, 0_i64),
        (-0.0, 0, 0, 0, 0),
        (0.75, 0, 0, 0, 0),
        (-0.75, 0, 0, 0, 0),
        (42.75, 42, 42, 42, 42),
        (-42.75, -42, 0, -42, 0),
        (f64::NAN, 0, 0, 0, 0),
        (f64::INFINITY, i32::MAX, -1, i64::MAX, -1),
        (f64::NEG_INFINITY, i32::MIN, 0, i64::MIN, 0),
        (2_147_483_648.0, i32::MAX, i32::MIN, 2_147_483_648, 2_147_483_648),
        (-2_147_483_648.0, i32::MIN, 0, -2_147_483_648, 0),
        (4_294_967_296.0, i32::MAX, -1, 4_294_967_296, 4_294_967_296),
        (9_223_372_036_854_775_808.0, i32::MAX, -1, i64::MAX, i64::MIN),
        (-9_223_372_036_854_775_808.0, i32::MIN, 0, i64::MIN, 0),
        (18_446_744_073_709_551_616.0, i32::MAX, -1, i64::MAX, -1),
    ];
    for subopcode in 0..8 {
        for padded in [false, true] {
            let vm = WasmNumericVm::parse(
                &conversion_module(subopcode, padded),
                WasmNumericLimits::default(),
            ).unwrap();
            for &(number, i32_s, i32_u, i64_s, i64_u) in &rows {
                let expected = match subopcode {
                    0 | 2 => WasmBoundaryValue::I32(i32_s),
                    1 | 3 => WasmBoundaryValue::I32(i32_u),
                    4 | 6 => WasmBoundaryValue::I64(i64_s),
                    _ => WasmBoundaryValue::I64(i64_u),
                };
                let result = vm.call_export("f", &[input(subopcode, number)]).unwrap();
                assert_eq!(result.results, [expected], "subopcode {subopcode}, {number}, padded={padded}");
                assert_eq!(result.instructions_executed, 3);
                assert_eq!(result.peak_stack_values, 1);
            }
        }
    }
}

#[test]
fn adjacent_f64_integer_boundaries_do_not_saturate_early() {
    let rows = [
        (2, 2_147_483_647.75, WasmBoundaryValue::I32(i32::MAX)),
        (2, -2_147_483_648.75, WasmBoundaryValue::I32(i32::MIN)),
        (3, 4_294_967_295.75, WasmBoundaryValue::I32(-1)),
        (6, f64::from_bits(9_223_372_036_854_775_808.0_f64.to_bits() - 1), WasmBoundaryValue::I64(9_223_372_036_854_774_784)),
        (6, f64::from_bits((-9_223_372_036_854_775_808.0_f64).to_bits() - 1), WasmBoundaryValue::I64(-9_223_372_036_854_774_784)),
        (7, f64::from_bits(18_446_744_073_709_551_616.0_f64.to_bits() - 1), WasmBoundaryValue::I64(-2048)),
    ];
    for (subopcode, value, expected) in rows {
        let vm = WasmNumericVm::parse(
            &conversion_module(subopcode, false), WasmNumericLimits::default(),
        ).unwrap();
        assert_eq!(vm.call_export("f", &[input(subopcode, value)]).unwrap().results, [expected]);
    }
}

#[test]
fn nan_sign_and_payload_do_not_change_the_zero_result() {
    for subopcode in 0..8 {
        let vm = WasmNumericVm::parse(
            &conversion_module(subopcode, false), WasmNumericLimits::default(),
        ).unwrap();
        let values = if subopcode & 2 == 0 {
            vec![0x7f80_0001, 0x7fc0_0042, 0xff80_0001, 0xffc0_0042]
                .into_iter().map(WasmBoundaryValue::F32Bits).collect::<Vec<_>>()
        } else {
            vec![0x7ff0_0000_0000_0001, 0x7ff8_0000_0000_0042, 0xfff0_0000_0000_0001, 0xfff8_0000_0000_0042]
                .into_iter().map(WasmBoundaryValue::F64Bits).collect::<Vec<_>>()
        };
        let zero = if subopcode < 4 { WasmBoundaryValue::I32(0) } else { WasmBoundaryValue::I64(0) };
        for value in values {
            assert_eq!(vm.call_export("f", &[value]).unwrap().results, [zero.clone()]);
        }
    }
}

#[test]
fn prefixed_conversions_validate_input_and_result_types() {
    for subopcode in 0..8_u8 {
        let expected_input = if subopcode & 2 == 0 { 0x7d } else { 0x7c };
        let expected_output = if subopcode < 4 { 0x7f } else { 0x7e };
        for input_type in [0x7f, 0x7e, 0x7d, 0x7c] {
            for output_type in [0x7f, 0x7e, 0x7d, 0x7c] {
                let result = WasmNumericVm::parse(
                    &module(&[input_type], &[output_type], &[0x20, 0, PREFIX, subopcode, 0x0b], false),
                    WasmNumericLimits::default(),
                );
                assert_eq!(result.is_ok(), input_type == expected_input && output_type == expected_output);
            }
        }
    }
}

#[test]
fn malformed_prefixes_are_rejected_in_untaken_branches() {
    for suffix in [
        vec![0x80, 0x80, 0x80, 0x80, 0x10], // u32 overflow
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0], // overlong LEB
        vec![0xff, 0xff, 0xff, 0xff, 0x0f], // valid LEB, unknown opcode
    ] {
        let mut code = vec![0x41, 0, 0x04, 0x40, 0x00, PREFIX];
        code.extend(suffix);
        code.extend([0x0b, 0x0b]);
        assert!(WasmNumericVm::parse(&module(&[], &[], &code, false), WasmNumericLimits::default()).is_err());
    }
    for suffix in [vec![PREFIX], vec![PREFIX, 0x80]] {
        assert!(WasmNumericVm::parse(&module(&[], &[], &suffix, false), WasmNumericLimits::default()).is_err());
    }
}

#[test]
fn saturating_conversion_keeps_the_existing_instruction_budget() {
    for subopcode in 0..8 {
        let limits = WasmNumericLimits { max_instructions: 1, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&conversion_module(subopcode, false), limits).unwrap();
        assert!(matches!(vm.call_export("f", &[input(subopcode, f64::INFINITY)]),
            Err(WasmNumericVmError::InstructionBudgetExceeded { max: 1 })));
    }
}

fn bulk_module(instruction: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut code = prefix.to_vec();
    code.extend([0x20, 0, 0x20, 1, 0x20, 2]);
    code.extend_from_slice(instruction);
    code.push(0x0b);
    let mut bytes = module(&[0x7f; 3], &[], &code, true);
    let mut data = vec![1, 0, 0x41, 0, 0x0b, 16];
    data.extend_from_slice(b"0123456789abcdef");
    section(&mut bytes, 11, &data);
    bytes
}

fn bulk_vm(instruction: &[u8], limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&bulk_module(instruction, &[]), limits).unwrap()
}

fn arguments(values: [i32; 3]) -> [WasmBoundaryValue; 3] {
    values.map(WasmBoundaryValue::I32)
}

#[test]
fn memory_copy_is_memmove_in_both_overlap_directions() {
    let vm = bulk_vm(&[PREFIX, 10, 0, 0], WasmNumericLimits::default());
    for (args, expected) in [
        ([2, 0, 8], b"0101234567abcdef"),
        ([0, 2, 8], b"2345678989abcdef"),
        ([8, 0, 4], b"012345670123cdef"),
        ([0, 0, 16], b"0123456789abcdef"),
        ([65_536, 65_536, 0], b"0123456789abcdef"),
    ] {
        let mut instance = vm.instantiate().unwrap();
        instance.call_export("f", &arguments(args)).unwrap();
        assert_eq!(&instance.memory_export("m").unwrap()[..16], expected);
    }
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f", &arguments([65_532, 0, 4])).unwrap();
    assert_eq!(&instance.memory_export("m").unwrap()[65_532..], b"0123");
}

#[test]
fn memory_fill_uses_only_the_low_byte_and_preserves_neighbors() {
    let vm = bulk_vm(&[PREFIX, 11, 0], WasmNumericLimits::default());
    for (value, byte) in [(0x1ff, 255), (-1, 255), (0x100, 0), (0x142, 0x42)] {
        let mut instance = vm.instantiate().unwrap();
        instance.call_export("f", &arguments([3, value, 5])).unwrap();
        let memory = instance.memory_export("m").unwrap();
        assert_eq!(&memory[..3], b"012");
        assert_eq!(&memory[3..8], &[byte; 5]);
        assert_eq!(&memory[8..16], b"89abcdef");
    }
}

#[test]
fn bulk_memory_bounds_traps_do_not_partially_write() {
    for (instruction, cases) in [
        (&[PREFIX, 10, 0, 0][..], vec![
            [65_535, 0, 2], [0, 65_535, 2], [-1, 0, 1], [0, -1, 1], [0, 0, -1],
            [65_537, 0, 0], [0, 65_537, 0],
        ]),
        (&[PREFIX, 11, 0][..], vec![
            [65_535, 42, 2], [-1, 42, 1], [0, 42, -1], [65_537, 42, 0],
        ]),
    ] {
        let vm = bulk_vm(instruction, WasmNumericLimits::default());
        for args in cases {
            let mut instance = vm.instantiate().unwrap();
            let before = instance.memory_export("m").unwrap().to_vec();
            assert!(matches!(instance.call_export("f", &arguments(args)),
                Err(WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))));
            assert_eq!(instance.memory_export("m").unwrap(), before);
        }
    }
}

#[test]
fn zero_length_bulk_operations_allow_exactly_one_past_the_end() {
    for instruction in [&[PREFIX, 10, 0, 0][..], &[PREFIX, 11, 0][..]] {
        let vm = bulk_vm(instruction, WasmNumericLimits::default());
        let mut instance = vm.instantiate().unwrap();
        instance.call_export("f", &arguments([65_536, 65_536, 0])).unwrap();
        assert_eq!(&instance.memory_export("m").unwrap()[..16], b"0123456789abcdef");
    }
}

#[test]
fn bulk_work_is_precharged_and_budget_refusal_is_atomic() {
    for instruction in [&[PREFIX, 10, 0, 0][..], &[PREFIX, 11, 0][..]] {
        let vm = bulk_vm(instruction, WasmNumericLimits { max_instructions: 4, ..WasmNumericLimits::default() });
        let mut instance = vm.instantiate().unwrap();
        let before = instance.memory_export("m").unwrap().to_vec();
        assert!(matches!(instance.call_export("f", &arguments([2, 1, 1])),
            Err(WasmNumericVmError::InstructionBudgetExceeded { max: 4 })));
        assert_eq!(instance.memory_export("m").unwrap(), before);
        for (length, budget) in [(0, 5), (1, 6), (63, 6), (64, 6), (65, 7)] {
            let vm = bulk_vm(instruction, WasmNumericLimits { max_instructions: budget, ..WasmNumericLimits::default() });
            let result = vm.call_export("f", &arguments([128, 0, length])).unwrap();
            assert_eq!(result.instructions_executed, budget);
        }
    }
}

#[test]
fn bulk_failure_retains_earlier_stores_but_never_leaks_between_instances() {
    // Store byte 42 at zero, then perform an out-of-bounds copy.
    let prefix = [0x41, 0, 0x41, 42, 0x3a, 0, 0];
    let vm = WasmNumericVm::parse(
        &bulk_module(&[PREFIX, 10, 0, 0], &prefix), WasmNumericLimits::default(),
    ).unwrap();
    let mut first = vm.instantiate().unwrap();
    let second = vm.instantiate().unwrap();
    assert!(first.call_export("f", &arguments([65_536, 0, 1])).is_err());
    assert_eq!(first.memory_export("m").unwrap()[0], 42);
    assert_eq!(second.memory_export("m").unwrap()[0], b'0');
    assert_eq!(&first.memory_export("m").unwrap()[1..16], b"123456789abcdef");
}

#[test]
fn bulk_memory_immediates_and_all_operand_types_are_validated() {
    for instruction in [&[PREFIX, 10, 0, 0][..], &[PREFIX, 11, 0][..]] {
        let mut code = vec![0x20, 0, 0x20, 1, 0x20, 2];
        code.extend(instruction);
        code.push(0x0b);
        assert!(WasmNumericVm::parse(&module(&[0x7f; 3], &[], &code, false), WasmNumericLimits::default()).is_err());
        for position in 0..3 {
            for wrong in [0x7e, 0x7d, 0x7c] {
                let mut types = [0x7f; 3];
                types[position] = wrong;
                assert!(WasmNumericVm::parse(&module(&types, &[], &code, true), WasmNumericLimits::default()).is_err());
            }
        }
    }
    for instruction in [
        vec![PREFIX, 10, 1, 0], vec![PREFIX, 10, 0, 1], vec![PREFIX, 11, 1],
        vec![PREFIX, 11, 128, 128, 128, 128, 16],
    ] {
        // The unreachable stack is polymorphic, but immediates must still be checked.
        let mut code = vec![0x41, 0, 0x04, 0x40, 0];
        code.extend(instruction);
        code.extend([0x0b, 0x0b]);
        assert!(WasmNumericVm::parse(&module(&[], &[], &code, true), WasmNumericLimits::default()).is_err());
    }
}

#[test]
fn padded_zero_memory_indices_are_not_misparsed_as_instructions() {
    for instruction in [
        vec![PREFIX, 0x8a, 0, 128, 0, 128, 128, 128, 128, 0],
        vec![PREFIX, 11, 128, 128, 128, 128, 0],
    ] {
        let vm = bulk_vm(&instruction, WasmNumericLimits::default());
        assert!(vm.call_export("f", &arguments([8, 0, 4])).is_ok());
    }
}
