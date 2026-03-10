#![forbid(unsafe_code)]
//! Iterable workload verification harness with iterator-level trace artifacts.
//!
//! Exercises the full pipeline (parse → IR0 → IR1 → IR2 → IR3) for for..in,
//! for..of, and mixed iteration patterns.  Verifies determinism, structural
//! invariants, and that iteration opcodes survive the full lowering chain.
//!
//! Plan reference: bd-1lsy.4.8.3 [RGC-308C].

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::ast::{
    BindingPattern, Expression, ExpressionStatement, ForInStatement, ForOfStatement, ParseGoal,
    SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator,
};
use frankenengine_engine::engine_object_id::{self, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    EffectBoundary, Ir0Module, Ir1Module, Ir1Op, Ir3Instruction, IteratorCloseReason,
};
use frankenengine_engine::iterator_protocol::{
    CloseReason, ITERATOR_PROTOCOL_SCHEMA_VERSION, IterationCompletion, IterationKind,
    IterationOperation, IteratorResult, IteratorSymbolKind, IteratorValue,
};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

fn ctx() -> LoweringContext {
    LoweringContext::new("trace-verify", "decision-verify", "policy-verify")
}

fn for_in_stmt(
    binding: &str,
    kind: Option<VariableDeclarationKind>,
    object: &str,
    body: Statement,
) -> Statement {
    Statement::ForIn(ForInStatement {
        binding: BindingPattern::Identifier(binding.into()),
        binding_kind: kind,
        object: Expression::Identifier(object.into()),
        body: Box::new(body),
        span: span(),
    })
}

fn for_of_stmt(
    binding: &str,
    kind: Option<VariableDeclarationKind>,
    iterable: &str,
    body: Statement,
) -> Statement {
    Statement::ForOf(ForOfStatement {
        binding: BindingPattern::Identifier(binding.into()),
        binding_kind: kind,
        iterable: Expression::Identifier(iterable.into()),
        body: Box::new(body),
        span: span(),
    })
}

fn expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

fn ir0_from_stmts(stmts: Vec<Statement>, label: &str) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: stmts,
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, label)
}

// ── Trace artifact: records IR1 op sequence for verification ────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct IterationTraceArtifact {
    label: String,
    ir1_op_count: usize,
    for_in_init_count: usize,
    for_in_next_count: usize,
    for_of_init_count: usize,
    for_of_next_count: usize,
    iterator_close_count: usize,
    close_reasons: Vec<IteratorCloseReason>,
    label_count: usize,
    jump_count: usize,
    store_binding_count: usize,
    ir1_content_hash: ContentHash,
}

fn trace_ir1_ops(module: &Ir1Module, label: &str) -> IterationTraceArtifact {
    let mut artifact = IterationTraceArtifact {
        label: label.to_string(),
        ir1_op_count: module.ops.len(),
        for_in_init_count: 0,
        for_in_next_count: 0,
        for_of_init_count: 0,
        for_of_next_count: 0,
        iterator_close_count: 0,
        close_reasons: Vec::new(),
        label_count: 0,
        jump_count: 0,
        store_binding_count: 0,
        ir1_content_hash: module.content_hash(),
    };

    for op in &module.ops {
        match op {
            Ir1Op::ForInInit => artifact.for_in_init_count += 1,
            Ir1Op::ForInNext { .. } => artifact.for_in_next_count += 1,
            Ir1Op::ForOfInit => artifact.for_of_init_count += 1,
            Ir1Op::ForOfNext { .. } => artifact.for_of_next_count += 1,
            Ir1Op::IteratorClose { reason } => {
                artifact.iterator_close_count += 1;
                artifact.close_reasons.push(*reason);
            }
            Ir1Op::Label { .. } => artifact.label_count += 1,
            Ir1Op::Jump { .. } => artifact.jump_count += 1,
            Ir1Op::StoreBinding { .. } => artifact.store_binding_count += 1,
            _ => {}
        }
    }

    artifact
}

// ===========================================================================
// Section 1: Single for..in lowering verification
// ===========================================================================

#[test]
fn single_for_in_produces_expected_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "key",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("key".into())),
        )],
        "single_for_in.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("for-in lowering");
    let trace = trace_ir1_ops(&result.module, "single_for_in");

    assert_eq!(trace.for_in_init_count, 1, "exactly one ForInInit");
    assert_eq!(trace.for_in_next_count, 1, "exactly one ForInNext");
    assert_eq!(trace.for_of_init_count, 0, "no ForOfInit");
    assert_eq!(trace.iterator_close_count, 0, "no IteratorClose for for-in");
    assert!(trace.label_count >= 3, "loop/continue/end labels");
    assert!(trace.jump_count >= 1, "back-edge jump");
    assert!(trace.store_binding_count >= 1, "binding store for key");
}

#[test]
fn for_in_const_binding_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Const),
            "table",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "for_in_const.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("const for-in").module,
        "for_in_const",
    );
    assert_eq!(trace.for_in_init_count, 1);
    assert_eq!(trace.for_in_next_count, 1);
}

#[test]
fn for_in_var_binding_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Var),
            "data",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "for_in_var.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("var for-in").module,
        "for_in_var",
    );
    assert_eq!(trace.for_in_init_count, 1);
}

#[test]
fn for_in_no_binding_kind_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            None,
            "obj",
            expr_stmt(Expression::NumericLiteral(0)),
        )],
        "for_in_none.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("none for-in").module,
        "for_in_none",
    );
    assert_eq!(trace.for_in_init_count, 1);
}

// ===========================================================================
// Section 2: Single for..of lowering verification
// ===========================================================================

#[test]
fn single_for_of_produces_expected_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "val",
            Some(VariableDeclarationKind::Const),
            "arr",
            expr_stmt(Expression::Identifier("val".into())),
        )],
        "single_for_of.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("for-of lowering");
    let trace = trace_ir1_ops(&result.module, "single_for_of");

    assert_eq!(trace.for_of_init_count, 1, "exactly one ForOfInit");
    assert_eq!(trace.for_of_next_count, 1, "exactly one ForOfNext");
    assert_eq!(trace.for_in_init_count, 0, "no ForInInit");
    assert_eq!(
        trace.iterator_close_count, 1,
        "one IteratorClose for break path"
    );
    assert_eq!(trace.close_reasons, vec![IteratorCloseReason::Break]);
    assert!(trace.label_count >= 4, "loop/continue/close/end labels");
    assert!(trace.store_binding_count >= 1, "binding store for val");
}

#[test]
fn for_of_let_binding_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "item",
            Some(VariableDeclarationKind::Let),
            "items",
            expr_stmt(Expression::Identifier("item".into())),
        )],
        "for_of_let.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("let for-of").module,
        "for_of_let",
    );
    assert_eq!(trace.for_of_init_count, 1);
    assert_eq!(trace.iterator_close_count, 1);
}

#[test]
fn for_of_var_binding_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "x",
            Some(VariableDeclarationKind::Var),
            "list",
            expr_stmt(Expression::Identifier("x".into())),
        )],
        "for_of_var.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("var for-of").module,
        "for_of_var",
    );
    assert_eq!(trace.for_of_init_count, 1);
}

#[test]
fn for_of_no_binding_kind_trace() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            None,
            "iter",
            expr_stmt(Expression::NumericLiteral(42)),
        )],
        "for_of_none.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("none for-of").module,
        "for_of_none",
    );
    assert_eq!(trace.for_of_init_count, 1);
    assert_eq!(trace.iterator_close_count, 1);
}

// ===========================================================================
// Section 3: Mixed iteration patterns
// ===========================================================================

#[test]
fn mixed_for_in_for_of_trace() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "k",
                Some(VariableDeclarationKind::Let),
                "map",
                expr_stmt(Expression::Identifier("k".into())),
            ),
            for_of_stmt(
                "v",
                Some(VariableDeclarationKind::Const),
                "values",
                expr_stmt(Expression::Identifier("v".into())),
            ),
        ],
        "mixed_in_of.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("mixed lowering");
    let trace = trace_ir1_ops(&result.module, "mixed_in_of");

    assert_eq!(trace.for_in_init_count, 1);
    assert_eq!(trace.for_in_next_count, 1);
    assert_eq!(trace.for_of_init_count, 1);
    assert_eq!(trace.for_of_next_count, 1);
    assert_eq!(trace.iterator_close_count, 1);
}

#[test]
fn two_for_of_loops_produce_two_close_ops() {
    let ir0 = ir0_from_stmts(
        vec![
            for_of_stmt(
                "a",
                Some(VariableDeclarationKind::Let),
                "xs",
                expr_stmt(Expression::Identifier("a".into())),
            ),
            for_of_stmt(
                "b",
                Some(VariableDeclarationKind::Let),
                "ys",
                expr_stmt(Expression::Identifier("b".into())),
            ),
        ],
        "two_for_of.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("two for-of").module,
        "two_for_of",
    );
    assert_eq!(trace.for_of_init_count, 2);
    assert_eq!(trace.for_of_next_count, 2);
    assert_eq!(trace.iterator_close_count, 2);
    assert_eq!(
        trace.close_reasons,
        vec![IteratorCloseReason::Break, IteratorCloseReason::Break]
    );
}

#[test]
fn three_for_in_loops_produce_three_init_next_pairs() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "a",
                Some(VariableDeclarationKind::Let),
                "x",
                expr_stmt(Expression::NumericLiteral(1)),
            ),
            for_in_stmt(
                "b",
                Some(VariableDeclarationKind::Let),
                "y",
                expr_stmt(Expression::NumericLiteral(2)),
            ),
            for_in_stmt(
                "c",
                Some(VariableDeclarationKind::Let),
                "z",
                expr_stmt(Expression::NumericLiteral(3)),
            ),
        ],
        "three_for_in.js",
    );
    let trace = trace_ir1_ops(
        &lower_ir0_to_ir1(&ir0).expect("three for-in").module,
        "three_for_in",
    );
    assert_eq!(trace.for_in_init_count, 3);
    assert_eq!(trace.for_in_next_count, 3);
    assert_eq!(trace.for_of_init_count, 0);
}

// ===========================================================================
// Section 4: Full pipeline verification (IR0 → IR1 → IR2 → IR3)
// ===========================================================================

#[test]
fn for_in_full_pipeline_produces_valid_ir3() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "key",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("key".into())),
        )],
        "for_in_pipeline.js",
    );
    let context = ctx();
    let output = lower_ir0_to_ir3(&ir0, &context).expect("for-in pipeline");
    assert!(!output.ir3.instructions.is_empty());
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
    assert!(!output.ir3.function_table.is_empty());
}

#[test]
fn for_of_full_pipeline_produces_valid_ir3() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "val",
            Some(VariableDeclarationKind::Const),
            "arr",
            expr_stmt(Expression::Identifier("val".into())),
        )],
        "for_of_pipeline.js",
    );
    let context = ctx();
    let output = lower_ir0_to_ir3(&ir0, &context).expect("for-of pipeline");
    assert!(!output.ir3.instructions.is_empty());
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn mixed_iteration_full_pipeline() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "k",
                Some(VariableDeclarationKind::Let),
                "obj",
                expr_stmt(Expression::Identifier("k".into())),
            ),
            for_of_stmt(
                "v",
                Some(VariableDeclarationKind::Let),
                "arr",
                expr_stmt(Expression::Identifier("v".into())),
            ),
        ],
        "mixed_pipeline.js",
    );
    let context = ctx();
    let output = lower_ir0_to_ir3(&ir0, &context).expect("mixed pipeline");
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

// ===========================================================================
// Section 5: Determinism verification
// ===========================================================================

#[test]
fn for_in_ir1_is_deterministic() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "det_for_in.js",
    );
    let a = lower_ir0_to_ir1(&ir0).expect("a");
    let b = lower_ir0_to_ir1(&ir0).expect("b");
    assert_eq!(a.module.content_hash(), b.module.content_hash());
    assert_eq!(a.module.ops.len(), b.module.ops.len());
}

#[test]
fn for_of_ir1_is_deterministic() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Const),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "det_for_of.js",
    );
    let a = lower_ir0_to_ir1(&ir0).expect("a");
    let b = lower_ir0_to_ir1(&ir0).expect("b");
    assert_eq!(a.module.content_hash(), b.module.content_hash());
}

#[test]
fn for_in_full_pipeline_deterministic() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "data",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "det_pipeline_for_in.js",
    );
    let ctx = ctx();
    let a = lower_ir0_to_ir3(&ir0, &ctx).expect("a");
    let b = lower_ir0_to_ir3(&ir0, &ctx).expect("b");
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn for_of_full_pipeline_deterministic() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Let),
            "items",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "det_pipeline_for_of.js",
    );
    let ctx = ctx();
    let a = lower_ir0_to_ir3(&ir0, &ctx).expect("a");
    let b = lower_ir0_to_ir3(&ir0, &ctx).expect("b");
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn mixed_iteration_pipeline_deterministic() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "k",
                Some(VariableDeclarationKind::Let),
                "map",
                expr_stmt(Expression::Identifier("k".into())),
            ),
            for_of_stmt(
                "v",
                Some(VariableDeclarationKind::Const),
                "values",
                expr_stmt(Expression::Identifier("v".into())),
            ),
        ],
        "det_mixed.js",
    );
    let ctx = ctx();
    let a = lower_ir0_to_ir3(&ir0, &ctx).expect("a");
    let b = lower_ir0_to_ir3(&ir0, &ctx).expect("b");
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

// ===========================================================================
// Section 6: IR2 effect classification verification
// ===========================================================================

#[test]
fn for_in_ir2_iteration_ops_have_read_effect() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "effect_for_in.js",
    );
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir1");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("ir2");

    let iteration_ops: Vec<_> = ir2
        .module
        .ops
        .iter()
        .filter(|op| matches!(op.inner, Ir1Op::ForInInit | Ir1Op::ForInNext { .. }))
        .collect();
    assert!(!iteration_ops.is_empty());
    for op in &iteration_ops {
        assert_eq!(op.effect, EffectBoundary::ReadEffect);
    }
}

#[test]
fn for_of_ir2_iteration_ops_have_read_effect() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Let),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "effect_for_of.js",
    );
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir1");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("ir2");

    let iteration_ops: Vec<_> = ir2
        .module
        .ops
        .iter()
        .filter(|op| {
            matches!(
                op.inner,
                Ir1Op::ForOfInit | Ir1Op::ForOfNext { .. } | Ir1Op::IteratorClose { .. }
            )
        })
        .collect();
    assert!(!iteration_ops.is_empty());
    for op in &iteration_ops {
        assert_eq!(op.effect, EffectBoundary::ReadEffect);
    }
}

// ===========================================================================
// Section 7: Serde round-trip for iteration IR1
// ===========================================================================

#[test]
fn for_in_ir1_serde_roundtrip() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "serde_for_in.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("ir1");
    let json = serde_json::to_string(&result.module).expect("ser");
    let restored: Ir1Module = serde_json::from_str(&json).expect("de");
    assert_eq!(result.module.ops.len(), restored.ops.len());
    assert_eq!(result.module.content_hash(), restored.content_hash());
}

#[test]
fn for_of_ir1_serde_roundtrip() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Const),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "serde_for_of.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("ir1");
    let json = serde_json::to_string(&result.module).expect("ser");
    let restored: Ir1Module = serde_json::from_str(&json).expect("de");
    assert_eq!(result.module.ops.len(), restored.ops.len());
    assert_eq!(result.module.content_hash(), restored.content_hash());
}

#[test]
fn iterator_close_reason_as_str_values() {
    assert_eq!(IteratorCloseReason::Break.as_str(), "break");
    assert_eq!(IteratorCloseReason::Return.as_str(), "return");
    assert_eq!(IteratorCloseReason::Throw.as_str(), "throw");
}

#[test]
fn iterator_close_reason_serde_roundtrip() {
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ] {
        let json = serde_json::to_string(&reason).expect("ser");
        let restored: IteratorCloseReason = serde_json::from_str(&json).expect("de");
        assert_eq!(reason, restored);
    }
}

// ===========================================================================
// Section 8: Iterator protocol substrate integration
// ===========================================================================

#[test]
fn iterator_protocol_schema_version_is_stable() {
    assert_eq!(
        ITERATOR_PROTOCOL_SCHEMA_VERSION,
        "franken-engine.iterator-protocol.v1"
    );
}

#[test]
fn iterator_value_all_variants_serde() {
    let values = vec![
        IteratorValue::Undefined,
        IteratorValue::Null,
        IteratorValue::Boolean(true),
        IteratorValue::Integer(42),
        IteratorValue::String("hello".into()),
        IteratorValue::FixedPoint(1_000_000),
        IteratorValue::Array(vec![IteratorValue::Integer(1), IteratorValue::Integer(2)]),
    ];
    for val in &values {
        let json = serde_json::to_string(val).expect("ser");
        let restored: IteratorValue = serde_json::from_str(&json).expect("de");
        assert_eq!(*val, restored);
    }
}

#[test]
fn iterator_result_done_true_serde() {
    let result = IteratorResult {
        value: IteratorValue::Undefined,
        done: true,
    };
    let json = serde_json::to_string(&result).expect("ser");
    let restored: IteratorResult = serde_json::from_str(&json).expect("de");
    assert_eq!(result, restored);
    assert!(restored.done);
}

#[test]
fn iterator_result_done_false_serde() {
    let result = IteratorResult {
        value: IteratorValue::String("x".into()),
        done: false,
    };
    let json = serde_json::to_string(&result).expect("ser");
    let restored: IteratorResult = serde_json::from_str(&json).expect("de");
    assert_eq!(result, restored);
    assert!(!restored.done);
}

#[test]
fn iteration_kind_all_variants() {
    let kinds = [
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).expect("ser");
        let restored: IterationKind = serde_json::from_str(&json).expect("de");
        assert_eq!(*kind, restored);
    }
}

#[test]
fn iteration_operation_all_variants_serde() {
    let schema = SchemaId::from_definition(b"test-schema");
    let dummy_id =
        engine_object_id::derive_id(ObjectDomain::PolicyObject, "test", &schema, &[1, 2, 3])
            .unwrap();
    let ops = vec![
        IterationOperation::GetIterator {
            symbol: IteratorSymbolKind::Iterator,
            iterable_ref: dummy_id.clone(),
        },
        IterationOperation::IteratorNext {
            result: IteratorResult {
                value: IteratorValue::Integer(1),
                done: false,
            },
        },
        IterationOperation::IteratorComplete { done: true },
        IterationOperation::IteratorValue {
            value: IteratorValue::String("x".into()),
        },
        IterationOperation::IteratorClose {
            reason: CloseReason::Break,
            return_called: false,
        },
        IterationOperation::EnumerateProperties {
            object_ref: dummy_id,
            keys: vec!["a".into(), "b".into()],
        },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).expect("ser");
        let restored: IterationOperation = serde_json::from_str(&json).expect("de");
        assert_eq!(*op, restored);
    }
}

#[test]
fn close_reason_all_variants() {
    let reasons = [
        CloseReason::Break,
        CloseReason::Return,
        CloseReason::Throw,
        CloseReason::DestructuringExhausted,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).expect("ser");
        let restored: CloseReason = serde_json::from_str(&json).expect("de");
        assert_eq!(*reason, restored);
    }
}

#[test]
fn iteration_completion_all_variants() {
    let completions = vec![
        IterationCompletion::Normal,
        IterationCompletion::NotIterable,
        IterationCompletion::InvalidResult,
        IterationCompletion::CloseThrew,
    ];
    for completion in &completions {
        let json = serde_json::to_string(completion).expect("ser");
        let restored: IterationCompletion = serde_json::from_str(&json).expect("de");
        assert_eq!(*completion, restored);
    }
}

// ===========================================================================
// Section 9: Structural invariants across lowering
// ===========================================================================

#[test]
fn for_in_init_always_precedes_next_in_ir1() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "a",
                Some(VariableDeclarationKind::Let),
                "x",
                expr_stmt(Expression::NumericLiteral(1)),
            ),
            for_in_stmt(
                "b",
                Some(VariableDeclarationKind::Let),
                "y",
                expr_stmt(Expression::NumericLiteral(2)),
            ),
        ],
        "ordering_for_in.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let ops = &result.module.ops;
    let init_positions: Vec<_> = ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| matches!(op, Ir1Op::ForInInit).then_some(i))
        .collect();
    let next_positions: Vec<_> = ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| matches!(op, Ir1Op::ForInNext { .. }).then_some(i))
        .collect();
    assert_eq!(init_positions.len(), next_positions.len());
    for (init, next) in init_positions.iter().zip(next_positions.iter()) {
        assert!(
            init < next,
            "ForInInit at {init} must precede ForInNext at {next}"
        );
    }
}

#[test]
fn for_of_init_next_close_ordering() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Let),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "ordering_for_of.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let ops = &result.module.ops;
    let init_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForOfInit))
        .expect("ForOfInit");
    let next_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForOfNext { .. }))
        .expect("ForOfNext");
    let close_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::IteratorClose { .. }))
        .expect("IteratorClose");
    assert!(init_pos < next_pos);
    assert!(next_pos < close_pos);
}

#[test]
fn for_in_next_done_label_targets_end_label() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "done_label_for_in.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let ops = &result.module.ops;
    // Find the ForInNext and its done_label.
    let done_label = ops.iter().find_map(|op| {
        if let Ir1Op::ForInNext { done_label } = op {
            Some(*done_label)
        } else {
            None
        }
    });
    assert!(done_label.is_some(), "ForInNext has a done_label");
    let label_id = done_label.unwrap();
    // Verify a Label with that id exists after the ForInNext.
    let next_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForInNext { .. }))
        .unwrap();
    let has_matching_label = ops[next_pos..]
        .iter()
        .any(|op| matches!(op, Ir1Op::Label { id } if *id == label_id));
    assert!(has_matching_label, "done_label must have matching Label");
}

#[test]
fn for_of_next_done_label_targets_end_label() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Let),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "done_label_for_of.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let ops = &result.module.ops;
    let done_label = ops.iter().find_map(|op| {
        if let Ir1Op::ForOfNext { done_label } = op {
            Some(*done_label)
        } else {
            None
        }
    });
    assert!(done_label.is_some());
    let label_id = done_label.unwrap();
    let next_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForOfNext { .. }))
        .unwrap();
    let has_matching_label = ops[next_pos..]
        .iter()
        .any(|op| matches!(op, Ir1Op::Label { id } if *id == label_id));
    assert!(has_matching_label);
}

// ===========================================================================
// Section 10: Content hash stability
// ===========================================================================

#[test]
fn for_in_content_hash_stable_across_runs() {
    let ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "hash_for_in.js",
    );
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            lower_ir0_to_ir1(&ir0)
                .expect("lowering")
                .module
                .content_hash()
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn for_of_content_hash_stable_across_runs() {
    let ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "v",
            Some(VariableDeclarationKind::Const),
            "arr",
            expr_stmt(Expression::Identifier("v".into())),
        )],
        "hash_for_of.js",
    );
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            lower_ir0_to_ir1(&ir0)
                .expect("lowering")
                .module
                .content_hash()
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn for_in_and_for_of_have_distinct_hashes() {
    let in_ir0 = ir0_from_stmts(
        vec![for_in_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "distinct_in.js",
    );
    let of_ir0 = ir0_from_stmts(
        vec![for_of_stmt(
            "k",
            Some(VariableDeclarationKind::Let),
            "obj",
            expr_stmt(Expression::Identifier("k".into())),
        )],
        "distinct_of.js",
    );
    let in_hash = lower_ir0_to_ir1(&in_ir0)
        .expect("for-in")
        .module
        .content_hash();
    let of_hash = lower_ir0_to_ir1(&of_ir0)
        .expect("for-of")
        .module
        .content_hash();
    assert_ne!(in_hash, of_hash);
}

// ===========================================================================
// Section 11: Iteration alongside regular control flow
// ===========================================================================

#[test]
fn for_in_with_preceding_var_decl() {
    let ir0 = ir0_from_stmts(
        vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("obj".into()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(),
                }],
                span: span(),
            }),
            for_in_stmt(
                "k",
                Some(VariableDeclarationKind::Let),
                "obj",
                expr_stmt(Expression::Identifier("k".into())),
            ),
        ],
        "var_then_for_in.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let trace = trace_ir1_ops(&result.module, "var_then_for_in");
    assert_eq!(trace.for_in_init_count, 1);
}

#[test]
fn for_of_between_two_expressions() {
    let ir0 = ir0_from_stmts(
        vec![
            expr_stmt(Expression::NumericLiteral(1)),
            for_of_stmt(
                "v",
                Some(VariableDeclarationKind::Let),
                "arr",
                expr_stmt(Expression::Identifier("v".into())),
            ),
            expr_stmt(Expression::NumericLiteral(2)),
        ],
        "expr_forof_expr.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let trace = trace_ir1_ops(&result.module, "expr_forof_expr");
    assert_eq!(trace.for_of_init_count, 1);
    assert_eq!(trace.for_of_next_count, 1);
    assert_eq!(trace.iterator_close_count, 1);
}

// ===========================================================================
// Section 12: Trace artifact serde round-trip
// ===========================================================================

#[test]
fn trace_artifact_captures_all_counts() {
    let ir0 = ir0_from_stmts(
        vec![
            for_in_stmt(
                "k",
                Some(VariableDeclarationKind::Let),
                "obj",
                expr_stmt(Expression::Identifier("k".into())),
            ),
            for_of_stmt(
                "v",
                Some(VariableDeclarationKind::Let),
                "arr",
                expr_stmt(Expression::Identifier("v".into())),
            ),
        ],
        "trace_all.js",
    );
    let result = lower_ir0_to_ir1(&ir0).expect("lowering");
    let trace = trace_ir1_ops(&result.module, "trace_all");

    assert_eq!(trace.for_in_init_count, 1);
    assert_eq!(trace.for_in_next_count, 1);
    assert_eq!(trace.for_of_init_count, 1);
    assert_eq!(trace.for_of_next_count, 1);
    assert_eq!(trace.iterator_close_count, 1);
    // Total iteration ops: 1+1+1+1+1 = 5
    let total_iter_ops = trace.for_in_init_count
        + trace.for_in_next_count
        + trace.for_of_init_count
        + trace.for_of_next_count
        + trace.iterator_close_count;
    assert_eq!(total_iter_ops, 5);
    assert!(
        trace.ir1_op_count > total_iter_ops,
        "must have non-iteration ops too"
    );
}
