//! Real binary modules exercise parsing, validation and persistent execution.
use super::*;

fn leb(mut value: usize) -> Vec<u8> {
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

fn signed(mut value: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 64 == 0) || (value == -1 && byte & 64 != 0);
        bytes.push(byte | if done { 0 } else { 128 });
        if done {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

fn data(segments: &[(Option<i32>, &[u8])]) -> Vec<u8> {
    let mut payload = leb(segments.len());
    for (offset, bytes) in segments {
        if let Some(offset) = offset {
            payload.extend([0, 0x41]);
            payload.extend(signed(*offset));
            payload.push(0x0b);
        } else {
            payload.push(1);
        }
        payload.extend(leb(bytes.len()));
        payload.extend_from_slice(bytes);
    }
    payload
}

// Every function has no results and is exported as f0, f1, ... . Its body
// includes end, but not the local declaration vector. Memory is exported as m.
fn module(
    functions: &[(&[u8], &[u8])],
    segments: Option<&[u8]>,
    count: Option<u32>,
    pages: Option<u32>,
    start: Option<u32>,
) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let mut types = leb(functions.len());
    let mut declarations = leb(functions.len());
    let mut exports = leb(functions.len() + usize::from(pages.is_some()));
    let mut bodies = leb(functions.len());
    for (index, (params, code)) in functions.iter().enumerate() {
        types.push(0x60);
        types.extend(leb(params.len()));
        types.extend_from_slice(params);
        types.push(0);
        declarations.extend(leb(index));
        let name = format!("f{index}");
        exports.extend(leb(name.len()));
        exports.extend_from_slice(name.as_bytes());
        exports.push(0);
        exports.extend(leb(index));
        bodies.extend(leb(code.len() + 1));
        bodies.push(0);
        bodies.extend_from_slice(code);
    }
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &declarations);
    if let Some(pages) = pages {
        let mut memory = vec![1, 0];
        memory.extend(leb(pages as usize));
        section(&mut bytes, 5, &memory);
        exports.extend([1, b'm', 2, 0]);
    }
    section(&mut bytes, 7, &exports);
    if let Some(start) = start {
        section(&mut bytes, 8, &leb(start as usize));
    }
    if let Some(count) = count {
        section(&mut bytes, 12, &leb(count as usize));
    }
    section(&mut bytes, 10, &bodies);
    if let Some(segments) = segments {
        section(&mut bytes, 11, segments);
    }
    bytes
}

fn init(index: u8) -> Vec<u8> {
    vec![0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 8, index, 0, 0x0b]
}

fn drop_data(index: u8) -> Vec<u8> {
    vec![0xfc, 9, index, 0x0b]
}
fn args(values: [i32; 3]) -> [WasmBoundaryValue; 3] {
    values.map(WasmBoundaryValue::I32)
}
fn parse(bytes: &[u8]) -> WasmNumericVm {
    WasmNumericVm::parse(bytes, WasmNumericLimits::default()).unwrap()
}

fn program(contents: &[u8]) -> Vec<u8> {
    module(
        &[(&[0x7f; 3], &init(0)), (&[], &drop_data(0))],
        Some(&data(&[(None, contents)])),
        Some(1),
        Some(1),
        None,
    )
}

fn reorder(bytes: &[u8], order: &[u8]) -> Vec<u8> {
    let mut sections = BTreeMap::new();
    let mut offset = 8;
    while offset < bytes.len() {
        let begin = offset;
        let id = bytes[offset];
        offset += 1;
        let (length, consumed) = read_u32_leb(&bytes[offset..]).unwrap();
        offset += consumed + length as usize;
        sections.insert(id, &bytes[begin..offset]);
    }
    let mut result = bytes[..8].to_vec();
    for id in order {
        result.extend_from_slice(sections[id]);
    }
    result
}

#[test]
fn passive_payloads_do_not_initialize_memory_and_need_no_memory_declaration() {
    let segments = data(&[(None, b"passive")]);
    for count in [None, Some(1)] {
        let vm = parse(&module(
            &[(&[], &[0x0b])],
            Some(&segments),
            count,
            None,
            None,
        ));
        assert!(vm.instantiate().unwrap().memory_export("m").is_none());
        let vm = parse(&module(
            &[(&[], &[0x0b])],
            Some(&segments),
            count,
            Some(0),
            None,
        ));
        assert!(
            vm.instantiate()
                .unwrap()
                .memory_export("m")
                .unwrap()
                .is_empty()
        );
    }
    let vm = parse(&program(b"passive"));
    assert!(
        vm.instantiate()
            .unwrap()
            .memory_export("m")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn memory_init_copies_subranges_without_consuming_the_segment() {
    let vm = parse(&program(b"abcdef"));
    let mut instance = vm.instantiate().unwrap();
    let first = instance.call_export("f0", &args([2, 1, 3])).unwrap();
    assert!(first.results.is_empty());
    assert_eq!(first.instructions_executed, 6); // 3 locals + init + work + end
    assert_eq!(first.peak_stack_values, 3);
    assert_eq!(&instance.memory_export("m").unwrap()[..7], b"\0\0bcd\0\0");
    instance.call_export("f0", &args([3, 0, 6])).unwrap();
    assert_eq!(&instance.memory_export("m").unwrap()[2..10], b"babcdef\0");
    assert_eq!(vm.call_export("f0", &args([2, 1, 3])).unwrap(), first);
}

#[test]
fn data_drop_is_idempotent_and_instance_local_with_shared_immutable_payloads() {
    let vm = parse(&program(b"abc"));
    let mut a = vm.instantiate().unwrap();
    let mut b = vm.instantiate().unwrap();
    assert!(Arc::ptr_eq(
        a.state.data[0].as_ref().unwrap(),
        b.state.data[0].as_ref().unwrap()
    ));
    a.call_export("f1", &[]).unwrap();
    a.call_export("f1", &[]).unwrap();
    assert!(a.state.data[0].is_none());
    for values in [[0, 0, 1], [0, 1, 0], [0, -1, 0]] {
        assert!(matches!(
            a.call_export("f0", &args(values)),
            Err(WasmNumericVmError::State(
                WasmStateError::DataSourceOutOfBounds { data_bytes: 0, .. }
            ))
        ));
    }
    a.call_export("f0", &args([65_536, 0, 0])).unwrap();
    b.call_export("f0", &args([0, 0, 3])).unwrap();
    assert_eq!(&b.memory_export("m").unwrap()[..3], b"abc");
    vm.instantiate()
        .unwrap()
        .call_export("f0", &args([0, 0, 3]))
        .unwrap();
}

#[test]
fn active_segments_keep_indices_but_are_dropped_before_export_calls() {
    let bytes = module(
        &[
            (&[0x7f; 3], &init(0)),
            (&[], &drop_data(0)),
            (&[0x7f; 3], &init(1)),
        ],
        Some(&data(&[(Some(0), b"active"), (None, b"passive")])),
        Some(2),
        Some(1),
        None,
    );
    let vm = parse(&bytes);
    let mut instance = vm.instantiate().unwrap();
    assert_eq!(&instance.memory_export("m").unwrap()[..6], b"active");
    assert!(matches!(
        instance.call_export("f0", &args([0, 0, 1])),
        Err(WasmNumericVmError::State(
            WasmStateError::DataSourceOutOfBounds {
                data_index: 0,
                data_bytes: 0,
                ..
            }
        ))
    ));
    instance.call_export("f1", &[]).unwrap();
    instance.call_export("f0", &args([6, 0, 0])).unwrap();
    instance.call_export("f2", &args([6, 0, 7])).unwrap();
    assert_eq!(
        &instance.memory_export("m").unwrap()[..13],
        b"activepassive"
    );
}

#[test]
fn entire_unsigned_source_and_destination_ranges_are_checked_before_mutation() {
    let vm = parse(&program(b"abcdef"));
    for values in [
        [65_535, 0, 2],
        [0, 5, 2],
        [-1, 0, 1],
        [0, -1, 1],
        [0, 0, -1],
        [65_537, 0, 0],
        [0, 7, 0],
    ] {
        let mut instance = vm.instantiate().unwrap();
        let before = instance.memory_export("m").unwrap().to_vec();
        assert!(matches!(
            instance.call_export("f0", &args(values)),
            Err(WasmNumericVmError::State(
                WasmStateError::MemoryOutOfBounds { .. }
                    | WasmStateError::DataSourceOutOfBounds { .. }
            ))
        ));
        assert_eq!(instance.memory_export("m").unwrap(), before);
        // A bounds trap must not consume the source segment either.
        instance.call_export("f0", &args([0, 0, 6])).unwrap();
        assert_eq!(&instance.memory_export("m").unwrap()[..6], b"abcdef");
    }
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f0", &args([65_536, 6, 0])).unwrap();
    instance.call_export("f0", &args([65_530, 0, 6])).unwrap();
    assert_eq!(&instance.memory_export("m").unwrap()[65_530..], b"abcdef");
}

#[test]
fn work_budget_refusal_is_atomic_but_later_refusal_preserves_completed_copy() {
    let bytes = program(&[0x5a; 65]);
    for (budget, length) in [(4, 1), (5, 65)] {
        let vm = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: budget,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let mut instance = vm.instantiate().unwrap();
        assert!(matches!(
            instance.call_export("f0", &args([0, 0, length])),
            Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
        ));
        assert!(
            instance
                .memory_export("m")
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(instance.state.data[0].is_some());
    }
    let vm = WasmNumericVm::parse(
        &bytes,
        WasmNumericLimits {
            max_instructions: 5,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(
        instance.call_export("f0", &args([0, 0, 1])),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
    ));
    assert_eq!(instance.memory_export("m").unwrap()[0], 0x5a);
    let vm = parse(&bytes);
    assert_eq!(
        vm.call_export("f0", &args([0, 0, 65]))
            .unwrap()
            .instructions_executed,
        7
    );
}

#[test]
fn data_drop_obeys_the_opcode_budget_and_survives_a_later_trap() {
    let bytes = program(b"abc");
    for (budget, dropped) in [(0, false), (1, true)] {
        let vm = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: budget,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let mut instance = vm.instantiate().unwrap();
        assert!(matches!(
            instance.call_export("f1", &[]),
            Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
        ));
        assert_eq!(instance.state.data[0].is_none(), dropped);
    }
    let bytes = module(
        &[(&[], &[0xfc, 9, 0, 0x00, 0x0b])],
        Some(&data(&[(None, b"abc")])),
        Some(1),
        None,
        None,
    );
    let vm = parse(&bytes);
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(
        instance.call_export("f0", &[]),
        Err(WasmNumericVmError::Unreachable { .. })
    ));
    assert!(instance.state.data[0].is_none());
}

#[test]
fn start_can_initialize_and_drop_passive_data_before_instance_publication() {
    let start = [0x41, 4, 0x41, 0, 0x41, 3, 0xfc, 8, 0, 0, 0xfc, 9, 0, 0x0b];
    let bytes = module(
        &[(&[0x7f; 3], &init(0)), (&[], &start)],
        Some(&data(&[(None, b"abc")])),
        Some(1),
        Some(1),
        Some(1),
    );
    let vm = parse(&bytes);
    for _ in 0..2 {
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(&instance.memory_export("m").unwrap()[4..7], b"abc");
        assert_eq!(instance.start_execution().unwrap().instructions_executed, 7);
        assert!(matches!(
            instance.call_export("f0", &args([0, 0, 1])),
            Err(WasmNumericVmError::State(
                WasmStateError::DataSourceOutOfBounds { data_bytes: 0, .. }
            ))
        ));
    }
    // The same start body cannot re-read an active segment: it is already gone.
    let bytes = module(
        &[(&[], &start)],
        Some(&data(&[(Some(0), b"abc")])),
        Some(1),
        Some(1),
        Some(0),
    );
    assert!(matches!(
        parse(&bytes).instantiate(),
        Err(WasmNumericVmError::State(
            WasmStateError::DataSourceOutOfBounds { data_bytes: 0, .. }
        ))
    ));
}

#[test]
fn direct_calls_share_passive_data_and_completed_copies_survive_traps() {
    let caller = [0x20, 0, 0x20, 1, 0x20, 2, 0x10, 0, 0x00, 0x0b];
    let bytes = module(
        &[(&[0x7f; 3], &init(0)), (&[0x7f; 3], &caller)],
        Some(&data(&[(None, b"abc")])),
        Some(1),
        Some(1),
        None,
    );
    let vm = parse(&bytes);
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(
        instance.call_export("f1", &args([0, 0, 3])),
        Err(WasmNumericVmError::Unreachable { .. })
    ));
    assert_eq!(&instance.memory_export("m").unwrap()[..3], b"abc");
    assert!(instance.state.data[0].is_some());
}

#[test]
fn data_drop_requires_no_memory_and_does_not_pop_an_operand() {
    let bytes = module(
        &[(&[], &[0x41, 7, 0xfc, 9, 0, 0x1a, 0x0b])],
        Some(&data(&[(None, b"abc")])),
        Some(1),
        None,
        None,
    );
    let vm = parse(&bytes);
    let mut instance = vm.instantiate().unwrap();
    assert!(instance.call_export("f0", &[]).unwrap().results.is_empty());
    assert!(instance.state.data[0].is_none());
}

#[test]
fn data_count_must_match_even_without_a_data_section() {
    for count in [0, 2] {
        let bytes = module(
            &[(&[], &[0x0b])],
            Some(&data(&[(None, b"abc")])),
            Some(count),
            None,
            None,
        );
        assert!(
            matches!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()), Err(WasmNumericVmError::InvalidModule { detail }) if detail.contains("data count section"))
        );
    }
    let bytes = module(&[(&[], &[0x0b])], None, Some(1), None, None);
    assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
    parse(&module(&[(&[], &[0x0b])], None, Some(0), None, None))
        .instantiate()
        .unwrap();
}

#[test]
fn data_count_ordering_preserves_duplicate_and_out_of_order_rejection() {
    let bytes = module(&[(&[], &[0x0b])], Some(&[0]), Some(0), None, None);
    parse(&bytes);
    for order in [
        vec![1, 3, 7, 10, 12, 11],
        vec![1, 3, 7, 12, 11, 10],
        vec![1, 3, 7, 12, 12, 10, 11],
        vec![1, 3, 7, 12, 10, 11, 11],
    ] {
        assert!(
            WasmNumericVm::parse(&reorder(&bytes, &order), WasmNumericLimits::default()).is_err(),
            "{order:?}"
        );
    }
    let mut custom = reorder(&bytes, &[1, 3, 7, 12]);
    section(&mut custom, 0, &[0]);
    custom.extend_from_slice(&reorder(&bytes, &[10, 11])[8..]);
    parse(&custom).instantiate().unwrap();
}

#[test]
fn data_indices_count_and_memory_are_validated_in_unreachable_code_too() {
    for code in [
        vec![0x00, 0xfc, 8, 0, 0, 0x0b],
        vec![0x00, 0xfc, 9, 0, 0x0b],
    ] {
        let bytes = module(
            &[(&[], &code)],
            Some(&data(&[(None, b"a")])),
            None,
            Some(1),
            None,
        );
        assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
        // Polymorphic unreachable operands are valid when the indices are real.
        parse(&module(
            &[(&[], &code)],
            Some(&data(&[(None, b"a")])),
            Some(1),
            Some(1),
            None,
        ));
    }
    for code in [
        vec![0x00, 0xfc, 8, 1, 0, 0x0b],
        vec![0x00, 0xfc, 9, 1, 0x0b],
    ] {
        let bytes = module(
            &[(&[], &code)],
            Some(&data(&[(None, b"a")])),
            Some(1),
            Some(1),
            None,
        );
        assert!(matches!(
            WasmNumericVm::parse(&bytes, WasmNumericLimits::default()),
            Err(WasmNumericVmError::State(
                WasmStateError::UnknownDataSegment { data_index: 1 }
            ))
        ));
    }
    let bytes = module(
        &[(&[], &[0x00, 0xfc, 8, 0, 0, 0x0b])],
        Some(&data(&[(None, b"a")])),
        Some(1),
        None,
        None,
    );
    assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
    let code = [0x00, 0x42, 0, 0x42, 0, 0x42, 0, 0xfc, 8, 0, 0, 0x0b];
    let bytes = module(
        &[(&[], &code)],
        Some(&data(&[(None, b"a")])),
        Some(1),
        Some(1),
        None,
    );
    assert!(matches!(
        WasmNumericVm::parse(&bytes, WasmNumericLimits::default()),
        Err(WasmNumericVmError::TypeMismatch {
            expected: WasmValueType::I32,
            actual: WasmValueType::I64,
            ..
        })
    ));
}

#[test]
fn padded_subopcodes_data_indices_and_memory_indices_are_decoded_completely() {
    let code = [
        0x20, 0, 0x20, 1, 0x20, 2, 0xfc, 0x88, 0, 0x80, 0, 0x80, 0, 0x0b,
    ];
    let drop = [0xfc, 0x89, 0, 0x80, 0, 0x0b];
    let bytes = module(
        &[(&[0x7f; 3], &code), (&[], &drop)],
        Some(&[1, 0x81, 0, 1, 42]),
        Some(1),
        Some(1),
        None,
    );
    let vm = parse(&bytes);
    let mut instance = vm.instantiate().unwrap();
    instance.call_export("f0", &args([0, 0, 1])).unwrap();
    assert_eq!(instance.memory_export("m").unwrap()[0], 42);
    instance.call_export("f1", &[]).unwrap();
    assert!(instance.state.data[0].is_none());
    for code in [
        vec![0x00, 0xfc, 8, 0, 1, 0x0b],
        vec![0x00, 0xfc, 9, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0b],
        vec![0x00, 0xfc, 8, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0b],
    ] {
        let bytes = module(
            &[(&[], &code)],
            Some(&data(&[(None, b"a")])),
            Some(1),
            Some(1),
            None,
        );
        assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
    }
}

#[test]
fn segment_counts_and_payload_boundaries_remain_bounded() {
    let bytes = module(
        &[(&[], &[0x0b])],
        Some(&data(&[(None, b"a")])),
        Some(1),
        None,
        None,
    );
    let limits = WasmNumericLimits {
        max_state_entries: 1,
        ..WasmNumericLimits::default()
    };
    WasmNumericVm::parse(&bytes, limits)
        .unwrap()
        .instantiate()
        .unwrap();
    for count in [1, u32::MAX] {
        let bytes = module(&[(&[], &[0x0b])], None, Some(count), None, None);
        assert!(matches!(
            WasmNumericVm::parse(
                &bytes,
                WasmNumericLimits {
                    max_state_entries: 0,
                    ..WasmNumericLimits::default()
                }
            ),
            Err(WasmNumericVmError::State(
                WasmStateError::LimitExceeded { .. }
            ))
        ));
    }
    for segments in [
        vec![1, 1, 4, b'a'],
        vec![1, 3, 0],
        vec![1, 2, 1, 0x41, 0, 0x0b, 0],
    ] {
        let bytes = module(&[(&[], &[0x0b])], Some(&segments), Some(1), Some(1), None);
        assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
    }
    // With an unusually permissive embedding, a short hostile vector still
    // cannot trigger an allocation based on its enormous advertised count.
    let bytes = module(
        &[(&[], &[0x0b])],
        Some(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
        None,
        None,
        None,
    );
    let limits = WasmNumericLimits {
        max_state_entries: usize::MAX,
        ..WasmNumericLimits::default()
    };
    assert!(
        matches!(WasmNumericVm::parse(&bytes, limits), Err(WasmNumericVmError::InvalidModule { detail }) if detail == "truncated data segment vector")
    );
    let vm = parse(&module(
        &[(&[0x7f; 3], &init(0))],
        Some(&data(&[(None, b"")])),
        Some(1),
        Some(0),
        None,
    ));
    vm.instantiate()
        .unwrap()
        .call_export("f0", &args([0, 0, 0]))
        .unwrap();
}
