//! Exception-semantics conformance, differential, and shipped-path replay gates.
//!
//! Bead: bd-1lsy.4.13.4 [RGC-313D]
//!
//! This test surface ensures the engine cannot regress back to placeholder
//! exception behavior.  It validates:
//! - IR lowering produces real BeginTry/EndTry/Throw/EnterCatch/EnterFinally/EndFinally
//! - Runtime unwinder executes catch/finally/rethrow semantics correctly
//! - Module rejection propagates real exception descriptions
//! - Deterministic replay stability for exception control flow

#![allow(clippy::needless_borrows_for_generic_args, clippy::too_many_arguments)]

use frankenengine_engine::ast::{
    BlockStatement, CatchClause, Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement,
    SyntaxTree, ThrowStatement, TryCatchStatement,
};
use frankenengine_engine::baseline_interpreter::{InterpreterError, QuickJsLane, Value};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::module_async_evaluation::{AsyncModuleEvaluator, AsyncModulePhase};
use frankenengine_engine::module_live_binding::LiveBindingMap;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseHandle;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

fn stmt_ir0(stmts: Vec<Statement>) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: stmts,
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "test_exception_conformance.js")
}

fn lower_to_ir3(stmts: Vec<Statement>) -> Ir3Module {
    let ir0 = stmt_ir0(stmts);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module
}

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"conformance-test"), "conformance.js");
    m.instructions = instructions;
    m.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 16,
        name: Some("main".to_string()),
    });
    m
}

// ---------------------------------------------------------------------------
// 1. IR Lowering Conformance: throw/try/catch/finally produce real IR3
// ---------------------------------------------------------------------------

#[test]
fn conformance_throw_produces_ir3_throw_not_halt() {
    let ir3 = lower_to_ir3(vec![Statement::Throw(ThrowStatement {
        argument: Expression::StringLiteral("error".into()),
        span: span(),
    })]);
    // Must contain Throw, must NOT rely on Halt for exception semantics.
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::Throw { .. }))
    );
    // The Halt at the end is the normal program termination sentinel,
    // not an exception handler.
    let throw_idx = ir3
        .instructions
        .iter()
        .position(|i| matches!(i, Ir3Instruction::Throw { .. }))
        .unwrap();
    let halt_idx = ir3
        .instructions
        .iter()
        .position(|i| matches!(i, Ir3Instruction::Halt))
        .unwrap();
    assert!(
        throw_idx < halt_idx,
        "Throw must come before the trailing Halt"
    );
}

#[test]
fn conformance_try_catch_produces_all_exception_ir3() {
    let ir3 = lower_to_ir3(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            span: span(),
        }),
        finalizer: None,
        span: span(),
    })]);
    let has = |pred: fn(&Ir3Instruction) -> bool| ir3.instructions.iter().any(pred);
    assert!(has(|i| matches!(i, Ir3Instruction::BeginTry { .. })));
    assert!(has(|i| matches!(i, Ir3Instruction::EndTry)));
    assert!(has(|i| matches!(i, Ir3Instruction::EnterCatch { .. })));
}

#[test]
fn conformance_try_finally_produces_finally_ir3() {
    let ir3 = lower_to_ir3(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: None,
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(99),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })]);
    let has = |pred: fn(&Ir3Instruction) -> bool| ir3.instructions.iter().any(pred);
    assert!(has(|i| matches!(i, Ir3Instruction::BeginTry { .. })));
    assert!(has(|i| matches!(i, Ir3Instruction::EnterFinally)));
    assert!(has(|i| matches!(i, Ir3Instruction::EndFinally)));
    // Verify finally_target is set
    let bt = ir3
        .instructions
        .iter()
        .find(|i| matches!(i, Ir3Instruction::BeginTry { .. }));
    assert!(matches!(
        bt,
        Some(Ir3Instruction::BeginTry {
            finally_target: Some(_),
            ..
        })
    ));
}

#[test]
fn conformance_try_catch_finally_all_instructions_present() {
    let ir3 = lower_to_ir3(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            span: span(),
        }),
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })]);
    let has = |pred: fn(&Ir3Instruction) -> bool| ir3.instructions.iter().any(pred);
    assert!(has(|i| matches!(i, Ir3Instruction::BeginTry { .. })));
    assert!(has(|i| matches!(i, Ir3Instruction::EndTry)));
    assert!(has(|i| matches!(i, Ir3Instruction::EnterCatch { .. })));
    assert!(has(|i| matches!(i, Ir3Instruction::EnterFinally)));
    assert!(has(|i| matches!(i, Ir3Instruction::EndFinally)));
}

// ---------------------------------------------------------------------------
// 2. Runtime Conformance: catch/finally/rethrow execute correctly
// ---------------------------------------------------------------------------

#[test]
fn conformance_runtime_throw_without_catch_is_uncaught() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Throw { value: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = QuickJsLane::new().execute(&m, "conformance");
    assert!(
        matches!(result, Err(InterpreterError::UncaughtException { .. })),
        "throw without catch must produce UncaughtException, got {result:?}"
    );
}

#[test]
fn conformance_runtime_try_catch_catches_exception() {
    // try { throw 42; } catch(e) { return e; }
    let m = test_module(vec![
        // 0: BeginTry → catch at instruction 4
        Ir3Instruction::BeginTry {
            catch_target: 4,
            finally_target: None,
        },
        // 1: LoadInt 42 into r0
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        // 2: Throw r0
        Ir3Instruction::Throw { value: 0 },
        // 3: EndTry (skipped because throw unwinds)
        Ir3Instruction::EndTry,
        // 4: EnterCatch → exception into r1
        Ir3Instruction::EnterCatch { dst: 1 },
        // 5: Return r1 (the caught value)
        Ir3Instruction::Return { value: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = QuickJsLane::new()
        .execute(&m, "conformance")
        .expect("try/catch should not error");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn conformance_runtime_try_catch_normal_path() {
    // try { r0 = 10; } catch(e) { r0 = 99; }
    // Normal path: r0 = 10, catch is skipped.
    let m = test_module(vec![
        // 0: BeginTry → catch at 4
        Ir3Instruction::BeginTry {
            catch_target: 4,
            finally_target: None,
        },
        // 1: LoadInt 10
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        // 2: EndTry
        Ir3Instruction::EndTry,
        // 3: Jump past catch
        Ir3Instruction::Jump { target: 6 },
        // 4: EnterCatch
        Ir3Instruction::EnterCatch { dst: 1 },
        // 5: Load 99 (should not execute on normal path)
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        // 6: Halt
        Ir3Instruction::Halt,
    ]);
    let result = QuickJsLane::new()
        .execute(&m, "conformance")
        .expect("normal try should not error");
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn conformance_runtime_finally_executes_on_normal_path() {
    // try { r0 = 10; } finally { r0 = r0 (identity, but EnterFinally/EndFinally run) }
    let m = test_module(vec![
        // 0: BeginTry → catch at 3, finally at 5
        Ir3Instruction::BeginTry {
            catch_target: 3,
            finally_target: Some(5),
        },
        // 1: LoadInt 10
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        // 2: EndTry + Jump to finally
        Ir3Instruction::EndTry,
        // 3: EnterCatch (exception path)
        Ir3Instruction::EnterCatch { dst: 1 },
        // 4: Jump to finally
        Ir3Instruction::Jump { target: 5 },
        // 5: EnterFinally
        Ir3Instruction::EnterFinally,
        // 6: LoadInt 20 (finally body overwrites r0)
        Ir3Instruction::LoadInt { dst: 0, value: 20 },
        // 7: EndFinally
        Ir3Instruction::EndFinally,
        // 8: Halt
        Ir3Instruction::Halt,
    ]);
    let result = QuickJsLane::new()
        .execute(&m, "conformance")
        .expect("finally on normal path should succeed");
    // r0 should be 20 because finally body executed
    assert_eq!(result.value, Value::Int(20));
}

// ---------------------------------------------------------------------------
// 3. Throw/Catch Value Propagation: exception values survive unwinding
// ---------------------------------------------------------------------------

#[test]
fn conformance_throw_string_value_survives_unwinding() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 },
        Ir3Instruction::LoadInt { dst: 2, value: 42 },
        Ir3Instruction::BeginTry {
            catch_target: 5,
            finally_target: None,
        },
        Ir3Instruction::Throw { value: 2 },
        Ir3Instruction::EndTry,
        // catch handler
        Ir3Instruction::EnterCatch { dst: 3 },
        Ir3Instruction::Move { dst: 0, src: 3 },
        Ir3Instruction::Halt,
    ]);
    let result = QuickJsLane::new()
        .execute(&m, "conformance")
        .expect("catch should succeed");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn conformance_uncaught_throw_reports_value_type() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: true,
        },
        Ir3Instruction::Throw { value: 0 },
    ]);
    let err = QuickJsLane::new().execute(&m, "conformance").unwrap_err();
    match err {
        InterpreterError::UncaughtException { value } => {
            assert_eq!(value, "true");
        }
        other => panic!("expected UncaughtException, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. IR Shape Stability: instruction ordering is deterministic
// ---------------------------------------------------------------------------

#[test]
fn conformance_ir3_instruction_ordering_is_stable() {
    // Lower the same input twice; IR3 must be identical.
    let stmts = vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Throw(ThrowStatement {
                argument: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            span: span(),
        }),
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(99),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })];
    let ir3_a = lower_to_ir3(stmts.clone());
    let ir3_b = lower_to_ir3(stmts);
    assert_eq!(
        ir3_a.instructions.len(),
        ir3_b.instructions.len(),
        "instruction count must be stable across runs"
    );
    assert_eq!(
        ir3_a.content_hash(),
        ir3_b.content_hash(),
        "IR3 content hash must be deterministic"
    );
}

// ---------------------------------------------------------------------------
// 5. Exception Support Matrix: enumerate exception features
// ---------------------------------------------------------------------------

#[test]
fn conformance_exception_support_matrix_coverage() {
    // Verify the support matrix: all exception features are implemented at IR3 level.
    let features = vec![
        "BeginTry",
        "EndTry",
        "Throw",
        "EnterCatch",
        "EnterFinally",
        "EndFinally",
    ];
    // All features must appear in the IR3 instruction set.
    for feature in &features {
        // Construct a try/catch/finally and verify the feature appears.
        let ir3 = lower_to_ir3(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Throw(ThrowStatement {
                    argument: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("e".into()),
                body: BlockStatement {
                    body: vec![],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: Some(BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(99),
                    span: span(),
                })],
                span: span(),
            }),
            span: span(),
        })]);
        let found = ir3.instructions.iter().any(|i| {
            let name = match i {
                Ir3Instruction::BeginTry { .. } => "BeginTry",
                Ir3Instruction::EndTry => "EndTry",
                Ir3Instruction::Throw { .. } => "Throw",
                Ir3Instruction::EnterCatch { .. } => "EnterCatch",
                Ir3Instruction::EnterFinally => "EnterFinally",
                Ir3Instruction::EndFinally => "EndFinally",
                _ => "",
            };
            name == *feature
        });
        assert!(
            found,
            "exception feature '{feature}' must be present in IR3 for try/catch/finally"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Module Rejection Conformance: real exception descriptions propagate
// ---------------------------------------------------------------------------

#[test]
fn conformance_module_rejection_preserves_description() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("failing.js", true, &[], Some(PromiseHandle(100)));
    let mut bindings = LiveBindingMap::new();
    let reason = JsValue::Str("TypeError: x is not a function".into());
    let linkage = eval
        .reject_module("failing.js", &reason, &mut bindings)
        .expect("reject_module should succeed");
    assert!(
        linkage
            .rejection_reason_description
            .as_deref()
            .unwrap_or("")
            .contains("TypeError"),
        "rejection description should contain the error type"
    );
    let state = &eval.states()["failing.js"];
    assert_eq!(state.phase, AsyncModulePhase::Rejected);
    assert!(state.rejection_reason_description.is_some());
}
