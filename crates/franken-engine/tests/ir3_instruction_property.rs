#![forbid(unsafe_code)]

use frankenengine_engine::deterministic_serde;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, IteratorCloseReason, Reg, RegRange,
};
use proptest::prelude::*;

fn reg() -> impl Strategy<Value = Reg> {
    0u32..64
}

fn instr_index() -> impl Strategy<Value = u32> {
    0u32..512
}

fn reg_range() -> impl Strategy<Value = RegRange> {
    (reg(), 0u32..8).prop_map(|(start, count)| RegRange { start, count })
}

fn capability() -> impl Strategy<Value = CapabilityTag> {
    prop::string::string_regex("[a-z][a-z0-9_.:-]{0,31}")
        .expect("capability regex should compile")
        .prop_map(CapabilityTag)
}

fn close_reason() -> impl Strategy<Value = IteratorCloseReason> {
    prop_oneof![
        Just(IteratorCloseReason::Break),
        Just(IteratorCloseReason::Return),
        Just(IteratorCloseReason::Throw),
    ]
}

fn load_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (reg(), any::<i64>()).prop_map(|(dst, value)| Ir3Instruction::LoadInt { dst, value }),
        (reg(), any::<u64>()).prop_map(|(dst, bits)| Ir3Instruction::LoadFloat { dst, bits }),
        (reg(), 0u32..128)
            .prop_map(|(dst, pool_index)| Ir3Instruction::LoadStr { dst, pool_index }),
        (reg(), any::<bool>()).prop_map(|(dst, value)| Ir3Instruction::LoadBool { dst, value }),
        reg().prop_map(|dst| Ir3Instruction::LoadNull { dst }),
        reg().prop_map(|dst| Ir3Instruction::LoadUndefined { dst }),
        reg().prop_map(|dst| Ir3Instruction::NewObject { dst }),
        reg().prop_map(|dst| Ir3Instruction::NewArray { dst }),
        reg().prop_map(|dst| Ir3Instruction::LoadThis { dst }),
        reg().prop_map(|dst| Ir3Instruction::LoadSuper { dst }),
    ]
    .boxed()
}

fn binary_instruction() -> BoxedStrategy<Ir3Instruction> {
    (0u8..22, reg(), reg(), reg())
        .prop_map(|(op, dst, lhs, rhs)| match op {
            0 => Ir3Instruction::Add { dst, lhs, rhs },
            1 => Ir3Instruction::Sub { dst, lhs, rhs },
            2 => Ir3Instruction::Mul { dst, lhs, rhs },
            3 => Ir3Instruction::Div { dst, lhs, rhs },
            4 => Ir3Instruction::Mod { dst, lhs, rhs },
            5 => Ir3Instruction::Exp { dst, lhs, rhs },
            6 => Ir3Instruction::Lt { dst, lhs, rhs },
            7 => Ir3Instruction::Lte { dst, lhs, rhs },
            8 => Ir3Instruction::Gt { dst, lhs, rhs },
            9 => Ir3Instruction::Gte { dst, lhs, rhs },
            10 => Ir3Instruction::Eq { dst, lhs, rhs },
            11 => Ir3Instruction::StrictEq { dst, lhs, rhs },
            12 => Ir3Instruction::NotEq { dst, lhs, rhs },
            13 => Ir3Instruction::StrictNotEq { dst, lhs, rhs },
            14 => Ir3Instruction::BitAnd { dst, lhs, rhs },
            15 => Ir3Instruction::BitOr { dst, lhs, rhs },
            16 => Ir3Instruction::BitXor { dst, lhs, rhs },
            17 => Ir3Instruction::Shl { dst, lhs, rhs },
            18 => Ir3Instruction::Shr { dst, lhs, rhs },
            19 => Ir3Instruction::Ushr { dst, lhs, rhs },
            20 => Ir3Instruction::InstanceOf { dst, lhs, rhs },
            _ => Ir3Instruction::InOp { dst, lhs, rhs },
        })
        .boxed()
}

fn unary_instruction() -> BoxedStrategy<Ir3Instruction> {
    (0u8..7, reg(), reg())
        .prop_map(|(op, dst, src)| match op {
            0 => Ir3Instruction::UnaryNeg { dst, src },
            1 => Ir3Instruction::UnaryPlus { dst, src },
            2 => Ir3Instruction::LogicalNot { dst, src },
            3 => Ir3Instruction::BitNot { dst, src },
            4 => Ir3Instruction::TypeOf { dst, src },
            5 => Ir3Instruction::Void { dst, src },
            _ => Ir3Instruction::Move { dst, src },
        })
        .boxed()
}

fn iterator_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (reg(), reg()).prop_map(|(src, dst)| Ir3Instruction::ForInInit { src, dst }),
        (reg(), reg(), instr_index()).prop_map(|(iterator, value_dst, done_target)| {
            Ir3Instruction::ForInNext {
                iterator,
                value_dst,
                done_target,
            }
        }),
        (reg(), reg()).prop_map(|(src, dst)| Ir3Instruction::ForOfInit { src, dst }),
        (reg(), reg(), instr_index()).prop_map(|(iterator, value_dst, done_target)| {
            Ir3Instruction::ForOfNext {
                iterator,
                value_dst,
                done_target,
            }
        }),
        (reg(), close_reason())
            .prop_map(|(iterator, reason)| Ir3Instruction::IteratorClose { iterator, reason }),
    ]
    .boxed()
}

fn control_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        instr_index().prop_map(|target| Ir3Instruction::Jump { target }),
        (reg(), instr_index()).prop_map(|(cond, target)| Ir3Instruction::JumpIf { cond, target }),
        (reg(), instr_index())
            .prop_map(|(cond, target)| Ir3Instruction::JumpIfNullish { cond, target }),
        reg().prop_map(|value| Ir3Instruction::Return { value }),
        Just(Ir3Instruction::Halt),
    ]
    .boxed()
}

fn call_and_property_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (reg(), reg_range(), reg())
            .prop_map(|(callee, args, dst)| { Ir3Instruction::Construct { callee, args, dst } }),
        (reg(), reg_range(), reg()).prop_map(|(callee, args, dst)| Ir3Instruction::Call {
            callee,
            args,
            dst
        }),
        (reg(), reg(), reg_range(), reg()).prop_map(|(receiver, callee, args, dst)| {
            Ir3Instruction::CallMethod {
                receiver,
                callee,
                args,
                dst,
            }
        }),
        (capability(), reg_range(), reg()).prop_map(|(capability, args, dst)| {
            Ir3Instruction::HostCall {
                capability,
                args,
                dst,
            }
        }),
        (reg(), reg(), reg()).prop_map(|(obj, key, dst)| Ir3Instruction::GetProperty {
            obj,
            key,
            dst,
        }),
        (reg(), reg(), reg()).prop_map(|(obj, key, val)| Ir3Instruction::SetProperty {
            obj,
            key,
            val,
        }),
        (reg(), reg(), reg()).prop_map(|(obj, key, dst)| Ir3Instruction::DeleteProperty {
            obj,
            key,
            dst,
        }),
        (reg(), reg()).prop_map(|(array, element)| Ir3Instruction::ArrayPush { array, element }),
        (reg(), reg())
            .prop_map(|(array, iterable)| Ir3Instruction::SpreadIntoArray { array, iterable }),
        (reg(), reg())
            .prop_map(|(target, source)| Ir3Instruction::SpreadIntoObject { target, source }),
        (reg_range(), reg())
            .prop_map(|(parts, dst)| Ir3Instruction::TemplateLiteral { parts, dst }),
    ]
    .boxed()
}

fn exception_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (instr_index(), prop::option::of(instr_index())).prop_map(
            |(catch_target, finally_target)| Ir3Instruction::BeginTry {
                catch_target,
                finally_target,
            },
        ),
        Just(Ir3Instruction::EndTry),
        reg().prop_map(|value| Ir3Instruction::Throw { value }),
        reg().prop_map(|dst| Ir3Instruction::EnterCatch { dst }),
        Just(Ir3Instruction::EnterFinally),
        Just(Ir3Instruction::EndFinally),
    ]
    .boxed()
}

fn scope_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (reg(), 0u32..64, 0u32..16).prop_map(|(dst, function_index, capture_count)| {
            Ir3Instruction::CreateClosure {
                dst,
                function_index,
                capture_count,
            }
        },),
        (0u32..128).prop_map(|name_pool_index| Ir3Instruction::PushCapture { name_pool_index }),
        Just(Ir3Instruction::PushScope),
        Just(Ir3Instruction::PopScope),
        (0u32..128, 0u8..5).prop_map(|(name_pool_index, kind)| {
            Ir3Instruction::DeclareBinding {
                name_pool_index,
                kind,
            }
        }),
        (reg(), 0u32..128).prop_map(|(dst, name_pool_index)| Ir3Instruction::LoadScoped {
            dst,
            name_pool_index,
        }),
        (reg(), 0u32..128).prop_map(|(src, name_pool_index)| Ir3Instruction::StoreScoped {
            src,
            name_pool_index,
        }),
        (0u32..128, reg()).prop_map(|(name_pool_index, src)| Ir3Instruction::InitBinding {
            name_pool_index,
            src,
        }),
        (reg(), reg()).prop_map(|(specifier, dst)| Ir3Instruction::ImportModule { specifier, dst }),
        (0u32..128, reg()).prop_map(|(name_pool_index, src)| Ir3Instruction::ExportBinding {
            name_pool_index,
            src,
        }),
    ]
    .boxed()
}

fn generator_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        (reg(), 0u32..64, 0u32..16).prop_map(|(dst, function_index, capture_count)| {
            Ir3Instruction::CreateGenerator {
                dst,
                function_index,
                capture_count,
            }
        },),
        (reg(), any::<bool>(), reg()).prop_map(|(value, delegate, resume_dst)| {
            Ir3Instruction::Yield {
                value,
                delegate,
                resume_dst,
            }
        }),
        (reg(), 0u32..64, 0u32..16).prop_map(|(dst, function_index, capture_count)| {
            Ir3Instruction::CreateAsyncFunction {
                dst,
                function_index,
                capture_count,
            }
        },),
        reg().prop_map(|promise_reg| Ir3Instruction::AwaitValue { promise_reg }),
        reg().prop_map(|value_reg| Ir3Instruction::AsyncReturn { value_reg }),
        reg().prop_map(|error_reg| Ir3Instruction::AsyncThrow { error_reg }),
        (reg(), 0u32..64, 0u32..16).prop_map(|(dst, function_index, capture_count)| {
            Ir3Instruction::CreateAsyncGenerator {
                dst,
                function_index,
                capture_count,
            }
        },),
    ]
    .boxed()
}

fn ir3_instruction() -> BoxedStrategy<Ir3Instruction> {
    prop_oneof![
        load_instruction(),
        binary_instruction(),
        unary_instruction(),
        iterator_instruction(),
        control_instruction(),
        call_and_property_instruction(),
        exception_instruction(),
        scope_instruction(),
        generator_instruction(),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn ir3_instruction_json_roundtrip_preserves_canonical_encoding(instr in ir3_instruction()) {
        let json = serde_json::to_string(&instr).expect("IR3 instruction should encode to JSON");
        let restored: Ir3Instruction =
            serde_json::from_str(&json).expect("IR3 instruction should decode from JSON");

        prop_assert_eq!(&restored, &instr);
        prop_assert_eq!(
            deterministic_serde::encode_value(&restored.canonical_value()),
            deterministic_serde::encode_value(&instr.canonical_value())
        );
    }

    #[test]
    fn ir3_instruction_json_roundtrip_is_idempotent(instr in ir3_instruction()) {
        let first_json =
            serde_json::to_string(&instr).expect("IR3 instruction should encode to JSON");
        let restored: Ir3Instruction =
            serde_json::from_str(&first_json).expect("IR3 instruction should decode from JSON");
        let second_json =
            serde_json::to_string(&restored).expect("restored IR3 instruction should re-encode");

        prop_assert_eq!(second_json, first_json);
    }
}
