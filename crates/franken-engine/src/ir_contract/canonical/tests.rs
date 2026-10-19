use super::*;
use crate::ast::FunctionSourceText;
use crate::deterministic_serde::{decode_value, encode_value};
use crate::ir_contract::{AccessorKind, CapabilityTag, IteratorCloseReason, SpecializationLinkage};

fn opcode_corpus(seed: u32) -> Vec<Ir3Instruction> {
    use Ir3Instruction::*;
    let a = seed;
    let b = seed.wrapping_add(0x1020_3040);
    let c = seed.wrapping_add(0xfedc_ba98);
    let args = RegRange { start: a, count: b };
    let mut instructions = vec![
        LoadInt {
            dst: a,
            value: i64::MIN,
        },
        LoadBigInt {
            dst: b,
            value: "-123456789012345678901234567890".into(),
        },
        LoadFloat {
            dst: c,
            bits: 0xfff0_0000_0000_0001,
        },
        LoadStr {
            dst: a,
            pool_index: b,
        },
        LoadBool {
            dst: a,
            value: true,
        },
        LoadNull { dst: a },
        LoadUndefined { dst: a },
        Construct {
            callee: a,
            args,
            dst: c,
        },
        ConstructWithNewTarget {
            callee: a,
            new_target: b,
            args,
            dst: c,
        },
        ConstructSuper { args, dst: c },
        RegisterDerivedConstructor {
            constructor: a,
            parent: b,
            default_constructor: false,
        },
        ForInInit { src: a, dst: b },
        ForInNext {
            iterator: a,
            value_dst: b,
            done_target: c,
        },
        ForOfInit { src: a, dst: b },
        ForOfNext {
            iterator: a,
            value_dst: b,
            done_target: c,
        },
        IteratorClose {
            iterator: a,
            reason: IteratorCloseReason::Break,
        },
        Jump { target: a },
        JumpIf { cond: a, target: b },
        JumpIfNullish { cond: a, target: b },
        Call {
            callee: a,
            args,
            dst: c,
        },
        CallMethod {
            receiver: a,
            callee: b,
            args,
            dst: c,
        },
        Return { value: a },
        HostCall {
            capability: CapabilityTag("builtin:\0é🚀".into()),
            args,
            dst: c,
        },
        GetProperty {
            obj: a,
            key: b,
            dst: c,
        },
        SetProperty {
            obj: a,
            key: b,
            val: c,
        },
        SetPropertySloppy {
            obj: a,
            key: b,
            val: c,
        },
        CreateDataProperty {
            obj: a,
            key: b,
            val: c,
        },
        DefineAccessor {
            obj: a,
            key: b,
            func: c,
            kind: AccessorKind::Get,
        },
        DefineMethod {
            obj: a,
            key: b,
            func: c,
        },
        DeleteProperty {
            obj: a,
            key: b,
            dst: c,
        },
        NewObject { dst: a },
        NewArray { dst: a },
        ArrayPush {
            array: a,
            element: b,
        },
        ArraySlice {
            array: a,
            start: b,
            dst: c,
        },
        SpreadIntoArray {
            array: a,
            iterable: b,
        },
        SpreadIntoObject {
            target: a,
            source: b,
        },
        TemplateLiteral {
            parts: args,
            dst: c,
        },
        Halt,
        LoadThis { dst: a },
        LoadNewTarget { dst: a },
        LoadSuper { dst: a },
        BeginTry {
            catch_target: a,
            finally_target: Some(b),
        },
        BeginTry {
            catch_target: a,
            finally_target: None,
        },
        EndTry,
        Throw { value: a },
        EnterCatch { dst: a },
        EnterFinally,
        EndFinally,
        DiscardAbruptCompletion,
        CreateClosure {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        CreateArrowClosure {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        PushCapture { name_pool_index: a },
        PushScope,
        PopScope,
        DeclareBinding {
            name_pool_index: a,
            kind: u8::MAX,
        },
        LoadScoped {
            dst: a,
            name_pool_index: b,
        },
        LoadName {
            dst: a,
            name_pool_index: b,
            allow_missing: true,
        },
        ResolveNameStatus {
            dst: a,
            name_pool_index: b,
        },
        DeleteName {
            dst: a,
            name_pool_index: b,
        },
        StoreScoped {
            src: a,
            name_pool_index: b,
        },
        PutName {
            src: a,
            name_pool_index: b,
            strict: false,
        },
        PutNameWithStatus {
            src: a,
            status: b,
            name_pool_index: c,
            strict: true,
        },
        InitBinding {
            name_pool_index: a,
            src: b,
        },
        CreatePerIterationBinding {
            name_pool_index: a,
            kind: 2,
            preserve_state: true,
        },
        ImportModule {
            specifier: a,
            dst: b,
        },
        ExportBinding {
            name_pool_index: a,
            src: b,
        },
        CreateGenerator {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        Yield {
            value: a,
            delegate: true,
            resume_dst: b,
        },
        CreateAsyncFunction {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        CreateAsyncArrowClosure {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        AwaitValue { promise_reg: a },
        AsyncReturn { value_reg: a },
        AsyncThrow { error_reg: a },
        CreateAsyncGenerator {
            dst: a,
            function_index: b,
            capture_count: c,
        },
        ModuleAwaitValue { promise_reg: a },
    ];
    macro_rules! binary {
        ($($variant:ident),+ $(,)?) => {
            instructions.extend([$($variant { dst: a, lhs: b, rhs: c }),+]);
        };
    }
    binary!(
        Add,
        Sub,
        Mul,
        Div,
        Mod,
        Exp,
        Lt,
        Lte,
        Gt,
        Gte,
        Eq,
        StrictEq,
        NotEq,
        StrictNotEq,
        BitAnd,
        BitOr,
        BitXor,
        Shl,
        Shr,
        Ushr,
        InstanceOf,
        InOp
    );
    macro_rules! unary {
        ($($variant:ident),+ $(,)?) => {
            instructions.extend([$($variant { dst: a, src: b }),+]);
        };
    }
    unary!(
        UnaryNeg, UnaryPlus, LogicalNot, BitNot, TypeOf, Void, Move, Inc, Dec
    );
    instructions
}

#[test]
fn every_opcode_preserves_reference_bytes_and_hash() {
    for seed in [0, 1, 0x0123_4567, u32::MAX] {
        for op in opcode_corpus(seed) {
            let mut writer = CanonicalWriter::new();
            instruction(&mut writer, &op);
            let actual = writer.finish();
            let reference_value = op.canonical_value();
            let expected = encode_value(&reference_value);
            assert_eq!(actual, expected, "{op:?}");
            assert_eq!(
                ContentHash::compute(&actual),
                ContentHash::compute(&expected)
            );
            assert_eq!(
                decode_value(&actual).expect("canonical instruction"),
                reference_value
            );
        }
    }
}

fn assert_module_matches_reference(module: &Ir3Module) {
    let reference_value = module.canonical_value();
    let expected = encode_value(&reference_value);
    assert_eq!(module.canonical_bytes(), expected);
    assert_eq!(module.content_hash(), ContentHash::compute(&expected));
    assert_eq!(
        decode_value(&expected).expect("canonical module"),
        reference_value
    );
}

#[test]
fn optional_metadata_combinations_preserve_module_layout() {
    for flags in 0..16 {
        let mut module = Ir3Module::new(ContentHash::compute(b"source"), "módulo\0.js");
        module.instructions = opcode_corpus(17);
        module.required_capabilities =
            vec![CapabilityTag("".into()), CapabilityTag("fs:read".into())];
        module.function_table = vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 3,
                frame_size: 9,
                name: None,
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: u32::MAX,
                arity: u32::MAX,
                frame_size: u32::MAX,
                name: Some("f\0🚀".into()),
                is_generator: true,
                rest_param_index: Some(0),
            },
        ];
        if flags & 1 != 0 {
            module.function_lengths.insert(u32::MAX, 0);
            module.function_lengths.insert(0, u32::MAX);
        }
        if flags & 2 != 0 {
            module.function_sources.insert(
                u32::MAX,
                FunctionSourceText::from("function f() { return 'é'; }"),
            );
            module
                .function_sources
                .insert(0, FunctionSourceText::from(""));
        }
        if flags & 4 != 0 {
            module.sloppy_functions.insert(u32::MAX, true);
            module.sloppy_functions.insert(0, false);
        }
        if flags & 8 != 0 {
            module.specialization = Some(SpecializationLinkage {
                proof_input_ids: vec!["proof-2".into(), "proof-1".into()],
                optimization_class: "test\0🚀".into(),
                validity_epoch: u64::MAX,
                rollback_token: ContentHash::compute(b"rollback"),
            });
        }
        assert_module_matches_reference(&module);
    }
    assert_module_matches_reference(&Ir3Module::new(ContentHash::compute(b""), ""));
}

#[test]
fn exact_string_units_and_float_payloads_are_preserved() {
    let mut module = Ir3Module::new(ContentHash::compute(b"strings"), "strings.js");
    module.constant_pool = vec![
        JsString::from(""),
        JsString::from("ascii\0"),
        JsString::from("é中🚀"),
        JsString::from_code_units(&[0xd800]),
        JsString::from_code_units(&[0xdc00]),
        JsString::from_code_units(&[0xd800, 0x61, 0xdc00, 0xd800, 0xdc00]),
    ];
    let rope = JsString::concat(
        &JsString::from("é".repeat(256)),
        &JsString::from("🚀".repeat(256)),
    );
    module.constant_pool.push(rope);
    module.instructions.extend(
        [
            0,
            1,
            u64::MAX,
            0x8000_0000_0000_0000,
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0x7ff0_0000_0000_0001,
            0x7ff8_0000_0000_0000,
        ]
        .map(|bits| Ir3Instruction::LoadFloat { dst: 7, bits }),
    );
    module
        .instructions
        .extend([i64::MIN, -1, 0, i64::MAX].map(|value| Ir3Instruction::LoadInt { dst: 9, value }));
    assert_module_matches_reference(&module);
}

/// A local serialization-kernel measurement, not a JS/V8 throughput claim.
/// Run with `cargo test --release -p frankenengine-engine --no-default-features
/// --lib ir3_streaming_benchmark -- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore = "release serialization benchmark; runs reference and candidate together"]
fn ir3_streaming_benchmark() {
    use std::hint::black_box;
    use std::time::Instant;

    for scale in [1, 100, 1_000] {
        let mut module = Ir3Module::new(ContentHash::compute(b"benchmark"), "mixed-ir3.js");
        for index in 0..scale {
            module.instructions.extend(opcode_corpus(index));
            module
                .constant_pool
                .push(JsString::from(format!("key_{index}:é🚀")));
            module.function_table.push(Ir3FunctionDesc {
                entry: index,
                arity: 2,
                frame_size: 16,
                name: Some(format!("f{index}")),
                is_generator: index % 2 == 0,
                rest_param_index: None,
            });
        }
        assert_module_matches_reference(&module);
        let reference =
            |module: &Ir3Module| ContentHash::compute(&encode_value(&module.canonical_value()));
        let candidate = |module: &Ir3Module| module.content_hash();
        for _ in 0..3 {
            assert_eq!(
                black_box(reference(black_box(&module))),
                black_box(candidate(black_box(&module)))
            );
        }
        let mut reference_ns = Vec::new();
        let mut candidate_ns = Vec::new();
        for sample in 0..30 {
            // Deterministic alternating order prevents always favoring the
            // candidate through warmed caches or changing host load.
            for is_candidate in [sample % 2 == 0, sample % 2 != 0] {
                let start = Instant::now();
                let digest = if is_candidate {
                    candidate(black_box(&module))
                } else {
                    reference(black_box(&module))
                };
                black_box(digest);
                let elapsed = start.elapsed().as_nanos();
                if is_candidate {
                    candidate_ns.push(elapsed);
                } else {
                    reference_ns.push(elapsed);
                }
            }
        }
        println!(
            "{}",
            serde_json::json!({
                "scope": "ir3_serialization_and_sha256_kernel",
                "instructions": module.instructions.len(),
                "encoded_bytes": module.canonical_bytes().len(),
                "reference_ns": reference_ns,
                "candidate_ns": candidate_ns,
            })
        );
    }
}
