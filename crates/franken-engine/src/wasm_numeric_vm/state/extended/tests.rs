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
