//! Dense, allocation-free profiling keys. No serialized IR tags change.

use crate::ir_contract::Ir3Instruction;

// Keep the names, dense indices and exhaustive match in one declaration.
// Adding an IR opcode must extend this list; a wildcard would silently merge
// or drop new instructions in profiles. The private index is never serialized.
macro_rules! profiling_opcodes {
    (structured: [$($structured:ident),* $(,)?], unit: [$($unit:ident),* $(,)?]) => {
        #[repr(usize)]
        enum Opcode {
            $($structured,)*
            $($unit,)*
        }

        pub(super) const NAMES: &[&str] = &[
            $(stringify!($structured),)*
            $(stringify!($unit),)*
        ];

        #[inline]
        pub(super) fn index(instruction: &Ir3Instruction) -> usize {
            match instruction {
                $(Ir3Instruction::$structured { .. } => Opcode::$structured as usize,)*
                $(Ir3Instruction::$unit => Opcode::$unit as usize,)*
            }
        }
    };
}

profiling_opcodes! {
    structured: [
        LoadInt,
        LoadFloat,
        LoadStr,
        LoadBool,
        LoadNull,
        LoadUndefined,
        Add,
        Sub,
        Mul,
        Div,
        Mod,
        Exp,
        UnaryNeg,
        UnaryPlus,
        LogicalNot,
        BitNot,
        TypeOf,
        Void,
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
        InOp,
        Construct,
        ConstructWithNewTarget,
        ConstructSuper,
        RegisterDerivedConstructor,
        ForInInit,
        ForInNext,
        ForOfInit,
        ForOfNext,
        IteratorClose,
        Move,
        Jump,
        JumpIf,
        JumpIfNullish,
        Call,
        CallMethod,
        Return,
        HostCall,
        GetProperty,
        SetProperty,
        DefineMethod,
        DeleteProperty,
        NewObject,
        NewArray,
        ArrayPush,
        ArraySlice,
        SpreadIntoArray,
        SpreadIntoObject,
        CopyDataProperties,
        TemplateLiteral,
        LoadThis,
        LoadNewTarget,
        LoadSuper,
        BeginTry,
        Throw,
        EnterCatch,
        CreateClosure,
        PushCapture,
        DeclareBinding,
        LoadScoped,
        StoreScoped,
        InitBinding,
        ImportModule,
        ExportBinding,
        CreateGenerator,
        Yield,
        CreateAsyncFunction,
        AwaitValue,
        AsyncReturn,
        AsyncThrow,
        CreateAsyncGenerator,
    ],
    unit: [
        Halt,
        EndTry,
        EnterFinally,
        EndFinally,
        DiscardAbruptCompletion,
        PushScope,
        PopScope,
        GeneratorBodyStart,
    ]
}
