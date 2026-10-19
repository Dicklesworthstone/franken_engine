//! Borrowed canonical IR3 encoding. The owned `canonical_value` representation
//! remains the reference for byte-for-byte differential tests.
//!
//! Bundle profiles in bd-9vouw.382 attributed 20.5% of a run to canonical IR
//! hashing. Reusing pass hashes removed redundant hashes; this removes the
//! remaining whole-module tree of owned maps, strings and arrays per hash.

use super::{Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange};
use crate::deterministic_serde::CanonicalWriter;
use crate::hash_tiers::ContentHash;
use crate::js_string::JsString;

#[derive(Clone, Copy)]
enum Field<'a> {
    U64(u64),
    I64(i64),
    Bool(bool),
    Str(&'a str),
    Range(RegRange),
    Null,
}

impl From<u64> for Field<'_> {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl From<u32> for Field<'_> {
    fn from(value: u32) -> Self {
        Self::U64(u64::from(value))
    }
}

impl From<u8> for Field<'_> {
    fn from(value: u8) -> Self {
        Self::U64(u64::from(value))
    }
}

impl From<i64> for Field<'_> {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<bool> for Field<'_> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<RegRange> for Field<'_> {
    fn from(value: RegRange) -> Self {
        Self::Range(value)
    }
}

impl<'a> From<&'a str> for Field<'a> {
    fn from(value: &'a str) -> Self {
        Self::Str(value)
    }
}

impl From<Option<u32>> for Field<'_> {
    fn from(value: Option<u32>) -> Self {
        value.map_or(Self::Null, |value| Self::U64(u64::from(value)))
    }
}

fn fields<const N: usize>(writer: &mut CanonicalWriter, mut entries: [(&str, Field<'_>); N]) {
    // The largest instruction has six fields. Sorting its borrowed stack
    // array replaces N owned keys and a BTreeMap without changing key order.
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let count = writer.map_header(N);
    for (key, value) in entries.into_iter().take(count) {
        writer.key(key);
        match value {
            Field::U64(value) => writer.u64(value),
            Field::I64(value) => writer.i64(value),
            Field::Bool(value) => writer.boolean(value),
            Field::Str(value) => writer.string(value),
            Field::Null => writer.null(),
            Field::Range(value) => fields(
                writer,
                [
                    ("count", Field::from(value.count)),
                    ("start", Field::from(value.start)),
                ],
            ),
        }
    }
}

fn instruction(writer: &mut CanonicalWriter, instruction: &Ir3Instruction) {
    use Ir3Instruction::*;

    macro_rules! emit {
        ($op:literal $(, $key:ident = $value:expr)* $(,)?) => {
            fields(writer, [
                ("op", Field::Str($op)),
                $((stringify!($key), Field::from($value)),)*
            ])
        };
    }
    macro_rules! copied {
        ($op:literal $(, $key:ident)* $(,)?) => {
            emit!($op $(, $key = *$key)*)
        };
    }

    // Exhaustive: adding an opcode requires deciding its canonical encoding.
    // Raw float bits deliberately remain U64, including NaN payloads and -0.
    match instruction {
        LoadInt { dst, value } => copied!("load_int", dst, value),
        LoadBigInt { dst, value } => emit!("load_bigint", dst = *dst, value = value.as_str()),
        LoadFloat { dst, bits } => copied!("load_float", dst, bits),
        LoadStr { dst, pool_index } => copied!("load_str", dst, pool_index),
        LoadBool { dst, value } => copied!("load_bool", dst, value),
        LoadNull { dst } => copied!("load_null", dst),
        LoadUndefined { dst } => copied!("load_undefined", dst),
        Add { dst, lhs, rhs } => copied!("add", dst, lhs, rhs),
        Sub { dst, lhs, rhs } => copied!("sub", dst, lhs, rhs),
        Mul { dst, lhs, rhs } => copied!("mul", dst, lhs, rhs),
        Div { dst, lhs, rhs } => copied!("div", dst, lhs, rhs),
        Mod { dst, lhs, rhs } => copied!("mod", dst, lhs, rhs),
        Exp { dst, lhs, rhs } => copied!("exp", dst, lhs, rhs),
        UnaryNeg { dst, src } => copied!("unary_neg", dst, src),
        UnaryPlus { dst, src } => copied!("unary_plus", dst, src),
        LogicalNot { dst, src } => copied!("logical_not", dst, src),
        BitNot { dst, src } => copied!("bit_not", dst, src),
        TypeOf { dst, src } => copied!("typeof", dst, src),
        Void { dst, src } => copied!("void", dst, src),
        Lt { dst, lhs, rhs } => copied!("lt", dst, lhs, rhs),
        Lte { dst, lhs, rhs } => copied!("lte", dst, lhs, rhs),
        Gt { dst, lhs, rhs } => copied!("gt", dst, lhs, rhs),
        Gte { dst, lhs, rhs } => copied!("gte", dst, lhs, rhs),
        Eq { dst, lhs, rhs } => copied!("eq", dst, lhs, rhs),
        StrictEq { dst, lhs, rhs } => copied!("strict_eq", dst, lhs, rhs),
        NotEq { dst, lhs, rhs } => copied!("not_eq", dst, lhs, rhs),
        StrictNotEq { dst, lhs, rhs } => copied!("strict_not_eq", dst, lhs, rhs),
        BitAnd { dst, lhs, rhs } => copied!("bit_and", dst, lhs, rhs),
        BitOr { dst, lhs, rhs } => copied!("bit_or", dst, lhs, rhs),
        BitXor { dst, lhs, rhs } => copied!("bit_xor", dst, lhs, rhs),
        Shl { dst, lhs, rhs } => copied!("shl", dst, lhs, rhs),
        Shr { dst, lhs, rhs } => copied!("shr", dst, lhs, rhs),
        Ushr { dst, lhs, rhs } => copied!("ushr", dst, lhs, rhs),
        InstanceOf { dst, lhs, rhs } => copied!("instance_of", dst, lhs, rhs),
        InOp { dst, lhs, rhs } => copied!("in_op", dst, lhs, rhs),
        Construct { callee, args, dst } => copied!("construct", callee, args, dst),
        ConstructWithNewTarget {
            callee,
            new_target,
            args,
            dst,
        } => {
            copied!("construct_with_new_target", callee, new_target, args, dst)
        }
        ConstructSuper { args, dst } => copied!("construct_super", args, dst),
        RegisterDerivedConstructor {
            constructor,
            parent,
            default_constructor,
        } => {
            copied!(
                "register_derived_constructor",
                constructor,
                parent,
                default_constructor
            )
        }
        ForInInit { src, dst } => copied!("for_in_init", src, dst),
        ForInNext {
            iterator,
            value_dst,
            done_target,
        } => {
            copied!("for_in_next", iterator, value_dst, done_target)
        }
        ForOfInit { src, dst } => copied!("for_of_init", src, dst),
        ForOfNext {
            iterator,
            value_dst,
            done_target,
        } => {
            copied!("for_of_next", iterator, value_dst, done_target)
        }
        IteratorClose { iterator, reason } => {
            emit!(
                "iterator_close",
                iterator = *iterator,
                reason = reason.as_str()
            )
        }
        Move { dst, src } => copied!("move", dst, src),
        Jump { target } => copied!("jump", target),
        JumpIf { cond, target } => copied!("jump_if", cond, target),
        JumpIfNullish { cond, target } => copied!("jump_if_nullish", cond, target),
        Call { callee, args, dst } => copied!("call", callee, args, dst),
        CallMethod {
            receiver,
            callee,
            args,
            dst,
        } => {
            copied!("call_method", receiver, callee, args, dst)
        }
        Return { value } => copied!("return", value),
        HostCall {
            capability,
            args,
            dst,
        } => {
            emit!(
                "hostcall",
                capability = capability.0.as_str(),
                args = *args,
                dst = *dst
            )
        }
        GetProperty { obj, key, dst } => copied!("get_property", obj, key, dst),
        SetProperty { obj, key, val } => copied!("set_property", obj, key, val),
        SetPropertySloppy { obj, key, val } => copied!("set_property_sloppy", obj, key, val),
        CreateDataProperty { obj, key, val } => copied!("create_data_property", obj, key, val),
        DefineAccessor {
            obj,
            key,
            func,
            kind,
        } => {
            emit!(
                "define_accessor",
                obj = *obj,
                key = *key,
                func = *func,
                kind = kind.as_str()
            )
        }
        DefineMethod { obj, key, func } => copied!("define_method", obj, key, func),
        DeleteProperty { obj, key, dst } => copied!("delete_property", obj, key, dst),
        NewObject { dst } => copied!("new_object", dst),
        NewArray { dst } => copied!("new_array", dst),
        ArrayPush { array, element } => copied!("array_push", array, element),
        ArraySlice { array, start, dst } => copied!("array_slice", array, start, dst),
        SpreadIntoArray { array, iterable } => copied!("spread_into_array", array, iterable),
        SpreadIntoObject { target, source } => copied!("spread_into_object", target, source),
        TemplateLiteral { parts, dst } => copied!("template_literal", parts, dst),
        Halt => copied!("halt"),
        LoadThis { dst } => copied!("load_this", dst),
        LoadNewTarget { dst } => copied!("load_new_target", dst),
        LoadSuper { dst } => copied!("load_super", dst),
        BeginTry {
            catch_target,
            finally_target,
        } => copied!("begin_try", catch_target, finally_target),
        EndTry => copied!("end_try"),
        Throw { value } => copied!("throw", value),
        EnterCatch { dst } => copied!("enter_catch", dst),
        EnterFinally => copied!("enter_finally"),
        EndFinally => copied!("end_finally"),
        DiscardAbruptCompletion => copied!("discard_abrupt_completion"),
        CreateClosure {
            dst,
            function_index,
            capture_count,
        } => {
            copied!("create_closure", dst, function_index, capture_count)
        }
        CreateArrowClosure {
            dst,
            function_index,
            capture_count,
        } => {
            copied!("create_arrow_closure", dst, function_index, capture_count)
        }
        PushCapture { name_pool_index } => copied!("push_capture", name_pool_index),
        PushScope => copied!("push_scope"),
        PopScope => copied!("pop_scope"),
        DeclareBinding {
            name_pool_index,
            kind,
        } => copied!("declare_binding", name_pool_index, kind),
        LoadScoped {
            dst,
            name_pool_index,
        } => copied!("load_scoped", dst, name_pool_index),
        LoadName {
            dst,
            name_pool_index,
            allow_missing,
        } => {
            copied!("load_name", dst, name_pool_index, allow_missing)
        }
        ResolveNameStatus {
            dst,
            name_pool_index,
        } => copied!("resolve_name_status", dst, name_pool_index),
        DeleteName {
            dst,
            name_pool_index,
        } => copied!("delete_name", dst, name_pool_index),
        StoreScoped {
            src,
            name_pool_index,
        } => copied!("store_scoped", src, name_pool_index),
        PutName {
            src,
            name_pool_index,
            strict,
        } => copied!("put_name", src, name_pool_index, strict),
        PutNameWithStatus {
            src,
            status,
            name_pool_index,
            strict,
        } => {
            copied!("put_name_with_status", src, status, name_pool_index, strict)
        }
        InitBinding {
            name_pool_index,
            src,
        } => copied!("init_binding", name_pool_index, src),
        CreatePerIterationBinding {
            name_pool_index,
            kind,
            preserve_state,
        } => {
            copied!(
                "create_per_iteration_binding",
                name_pool_index,
                kind,
                preserve_state
            )
        }
        ImportModule { specifier, dst } => copied!("import_module", specifier, dst),
        ExportBinding {
            name_pool_index,
            src,
        } => copied!("export_binding", name_pool_index, src),
        CreateGenerator {
            dst,
            function_index,
            capture_count,
        } => {
            copied!("create_generator", dst, function_index, capture_count)
        }
        Yield {
            value,
            delegate,
            resume_dst,
        } => copied!("yield", value, delegate, resume_dst),
        CreateAsyncFunction {
            dst,
            function_index,
            capture_count,
        } => {
            copied!("create_async_function", dst, function_index, capture_count)
        }
        CreateAsyncArrowClosure {
            dst,
            function_index,
            capture_count,
        } => {
            copied!(
                "create_async_arrow_closure",
                dst,
                function_index,
                capture_count
            )
        }
        AwaitValue { promise_reg } => copied!("await_value", promise_reg),
        AsyncReturn { value_reg } => copied!("async_return", value_reg),
        AsyncThrow { error_reg } => copied!("async_throw", error_reg),
        CreateAsyncGenerator {
            dst,
            function_index,
            capture_count,
        } => {
            copied!("create_async_generator", dst, function_index, capture_count)
        }
        ModuleAwaitValue { promise_reg } => copied!("module_await_value", promise_reg),
        Inc { dst, src } => copied!("inc", dst, src),
        Dec { dst, src } => copied!("dec", dst, src),
    }
}

fn string(writer: &mut CanonicalWriter, value: &JsString) {
    if let Some(text) = value.as_str() {
        writer.string(text);
    } else {
        writer.map_header(1);
        writer.key("$wtf16");
        let count = writer.array_header(value.utf16_len());
        for unit in value.encode_utf16().take(count) {
            writer.u64(u64::from(unit));
        }
    }
}

fn function(writer: &mut CanonicalWriter, value: &Ir3FunctionDesc) {
    // rest_param_index is intentionally excluded by the existing contract.
    fields(
        writer,
        [
            ("arity", Field::from(value.arity)),
            ("entry", Field::from(value.entry)),
            ("frame_size", Field::from(value.frame_size)),
            ("is_generator", Field::from(value.is_generator)),
            (
                "name",
                value.name.as_deref().map_or(Field::Null, Field::Str),
            ),
        ],
    );
}

pub(super) fn module_bytes(module: &Ir3Module) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    let has_lengths = !module.function_lengths.is_empty();
    let has_sources = !module.function_sources.is_empty();
    let has_sloppy = !module.sloppy_functions.is_empty();
    writer.map_header(
        6 + usize::from(has_lengths) + usize::from(has_sources) + usize::from(has_sloppy),
    );

    // Keep the module's fixed field set lexicographic; optional fields occupy
    // the same positions as in the reference BTreeMap.
    writer.key("constant_pool");
    let count = writer.array_header(module.constant_pool.len());
    for value in module.constant_pool.iter().take(count) {
        string(&mut writer, value);
    }
    if has_lengths {
        writer.key("function_lengths");
        let count = writer.array_header(module.function_lengths.len());
        for (function, length) in module.function_lengths.iter().take(count) {
            writer.array_header(2);
            writer.u64(u64::from(*function));
            writer.u64(u64::from(*length));
        }
    }
    if has_sources {
        writer.key("function_sources");
        let count = writer.array_header(module.function_sources.len());
        for (function, text) in module.function_sources.iter().take(count) {
            writer.array_header(2);
            writer.u64(u64::from(*function));
            writer.bytes(ContentHash::compute(text.as_str().as_bytes()).as_bytes());
        }
    }
    writer.key("function_table");
    let count = writer.array_header(module.function_table.len());
    for value in module.function_table.iter().take(count) {
        function(&mut writer, value);
    }
    writer.key("header");
    writer.value(&module.header.canonical_value());
    writer.key("instructions");
    let count = writer.array_header(module.instructions.len());
    for value in module.instructions.iter().take(count) {
        instruction(&mut writer, value);
    }
    writer.key("required_capabilities");
    let count = writer.array_header(module.required_capabilities.len());
    for value in module.required_capabilities.iter().take(count) {
        writer.string(&value.0);
    }
    if has_sloppy {
        writer.key("sloppy_functions");
        let count = writer.array_header(module.sloppy_functions.len());
        for (function, simple_parameters) in module.sloppy_functions.iter().take(count) {
            writer.array_header(2);
            writer.u64(u64::from(*function));
            writer.boolean(*simple_parameters);
        }
    }
    writer.key("specialization");
    if let Some(value) = &module.specialization {
        writer.value(&value.canonical_value());
    } else {
        writer.null();
    }
    writer.finish()
}

#[cfg(test)]
mod tests;
