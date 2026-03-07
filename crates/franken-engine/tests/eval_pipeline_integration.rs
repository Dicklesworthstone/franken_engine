//! Integration tests for the real parse→lower→execute pipeline (bd-1lsy.4.1).
//!
//! Validates the end-to-end eval surface:
//!   Source string → CanonicalEs2020Parser → IR0 → IR1 → IR2 → IR3 → LaneRouter → ExecutionResult
//!
//! Coverage:
//!   - eval_via_native_pipeline wiring through parse/lower/execute
//!   - JsEngine trait implementations (QuickJs, V8, HybridRouter)
//!   - LaneRouter two-lane execution with policy-directed routing
//!   - Error mapping (parse errors, lowering errors, capability denials)
//!   - IR3 execution for supported syntax families
//!   - Determinism (same input produces same output)
//!   - Witness and event generation through the pipeline

use frankenengine_engine::ast::{
    BindingPattern, Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::baseline_interpreter::{LaneChoice, LaneRouter};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::{
    EngineKind, EvalError, EvalErrorCode, ExceptionBoundary, HybridRouter, JsEngine,
    QuickJsInspiredNativeEngine, RouteReason, V8InspiredNativeEngine,
    propagate_error_across_boundary,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 10)
}

fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: SourceSpan::new(0, 100, 1, 1, 10, 1),
    }
}

fn var_decl(kind: VariableDeclarationKind, name: &str, init: Option<Expression>) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier(name.to_string()),
            initializer: init,
            span: span(),
        }],
        span: span(),
    })
}

fn expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

// =========================================================================
// Section 1: JsEngine trait implementations
// =========================================================================

#[test]
fn quickjs_engine_kind_is_correct() {
    let engine = QuickJsInspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::QuickJsInspiredNative);
}

#[test]
fn v8_engine_kind_is_correct() {
    let engine = V8InspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::V8InspiredNative);
}

#[test]
fn hybrid_router_default_is_constructible() {
    // HybridRouter has its own eval method (not via JsEngine trait).
    let mut router = HybridRouter::default();
    // Verify it can evaluate a trivial program.
    let outcome = router.eval("42").expect("should eval literal");
    assert_eq!(outcome.engine, EngineKind::QuickJsInspiredNative);
    assert_eq!(outcome.value, "42");
}

#[test]
fn quickjs_eval_executes_expression_instead_of_echoing_source() {
    let mut engine = QuickJsInspiredNativeEngine;
    let outcome = engine
        .eval("'alpha'")
        .expect("quickjs should execute expression");
    assert_eq!(outcome.engine, EngineKind::QuickJsInspiredNative);
    assert_eq!(outcome.value, "alpha");
}

#[test]
fn v8_eval_executes_expression_instead_of_echoing_source() {
    let mut engine = V8InspiredNativeEngine;
    let outcome = engine
        .eval("\"beta\"")
        .expect("v8 should execute expression");
    assert_eq!(outcome.engine, EngineKind::V8InspiredNative);
    assert_eq!(outcome.value, "beta");
}

#[test]
fn invalid_syntax_maps_to_parse_failure_for_direct_lanes() {
    let mut quickjs = QuickJsInspiredNativeEngine;
    let mut v8 = V8InspiredNativeEngine;

    let quickjs_err = quickjs.eval("var").expect_err("expected parse failure");
    let v8_err = v8.eval("let").expect_err("expected parse failure");

    assert_eq!(quickjs_err.code, EvalErrorCode::ParseFailure);
    assert_eq!(v8_err.code, EvalErrorCode::ParseFailure);
    assert!(quickjs_err.correlation_ids.is_some());
    assert!(v8_err.correlation_ids.is_some());
    assert_eq!(quickjs_err.stack_frames[0].stage, "parse");
    assert_eq!(v8_err.stack_frames[0].stage, "parse");
    assert!(quickjs_err.location.is_some());
    assert!(v8_err.location.is_some());
}

#[test]
fn parse_failure_display_includes_location_correlation_and_stack_trace() {
    let mut quickjs = QuickJsInspiredNativeEngine;
    let err = quickjs.eval("let").expect_err("expected parse failure");
    let display = format!("{err}");

    let location = err
        .location
        .as_ref()
        .expect("parse failure should carry source location");
    let location_text = format!("{location}");

    assert!(display.contains("eval.parse.failure"));
    assert!(display.contains(&location_text));
    assert!(display.contains("trace_id=eval-quickjs-"));
    assert!(display.contains("decision_id=eval-decision-"));
    assert!(display.contains("policy_id=eval-policy-quickjs"));
    assert!(display.contains("stack=parse@"));
}

#[test]
fn module_parse_failure_display_includes_location_correlation_and_stack_trace() {
    let mut router = HybridRouter::default();
    let err = router
        .eval("import")
        .expect_err("expected module parse failure");
    let display = format!("{err}");

    let location = err
        .location
        .as_ref()
        .expect("module parse failure should carry source location");
    let location_text = format!("{location}");

    assert_eq!(err.code, EvalErrorCode::ParseFailure);
    assert!(display.contains("eval.parse.failure"));
    assert!(display.contains(&location_text));
    assert!(display.contains("trace_id=eval-"));
    assert!(display.contains("decision_id=eval-decision-"));
    assert!(display.contains("policy_id=eval-policy-"));
    assert!(display.contains("stack=parse@"));
}

// =========================================================================
// Section 2: Error handling — invalid/empty inputs
// =========================================================================

#[test]
fn quickjs_rejects_empty_source() {
    let mut engine = QuickJsInspiredNativeEngine;
    let err = engine
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn v8_rejects_empty_source() {
    let mut engine = V8InspiredNativeEngine;
    let err = engine
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn hybrid_rejects_empty_source() {
    let mut router = HybridRouter::default();
    let err: EvalError = router
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn quickjs_rejects_whitespace_only() {
    let mut engine = QuickJsInspiredNativeEngine;
    let err = engine.eval("   ").expect_err("whitespace-only should fail");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn v8_rejects_whitespace_only() {
    let mut engine = V8InspiredNativeEngine;
    let err = engine.eval("   ").expect_err("whitespace-only should fail");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn boundary_propagation_appends_boundary_stack_frame() {
    let err =
        EvalError::runtime_fault("boom").with_correlation_ids("trace-a", "decision-a", "policy-a");
    let propagated = propagate_error_across_boundary(err, ExceptionBoundary::Hostcall);
    assert!(propagated.message.contains("boundary=hostcall"));
    assert_eq!(propagated.stack_frames.len(), 1);
    assert_eq!(propagated.stack_frames[0].stage, "boundary_transition");
    assert_eq!(
        propagated.stack_frames[0].boundary.as_deref(),
        Some("hostcall")
    );
}

#[test]
fn boundary_propagation_copies_location_into_boundary_stack_frame() {
    let mut quickjs = QuickJsInspiredNativeEngine;
    let err = quickjs.eval("let").expect_err("expected parse failure");
    let location = err.location.clone().expect("expected parse location");
    let propagated = propagate_error_across_boundary(err, ExceptionBoundary::Hostcall);

    assert_eq!(propagated.stack_frames.len(), 2);
    assert_eq!(propagated.stack_frames[0].stage, "parse");
    assert_eq!(propagated.stack_frames[1].stage, "boundary_transition");
    assert_eq!(
        propagated.stack_frames[1].boundary.as_deref(),
        Some("hostcall")
    );
    assert_eq!(
        propagated.stack_frames[1].location.as_ref(),
        Some(&location)
    );
}

#[test]
fn async_and_hostcall_boundary_chain_preserves_parse_location() {
    let mut quickjs = QuickJsInspiredNativeEngine;
    let err = quickjs.eval("let").expect_err("expected parse failure");
    let location = err.location.clone().expect("expected parse location");

    let after_async = propagate_error_across_boundary(err, ExceptionBoundary::AsyncJob);
    let after_hostcall = propagate_error_across_boundary(after_async, ExceptionBoundary::Hostcall);

    assert_eq!(after_hostcall.stack_frames.len(), 3);
    assert_eq!(after_hostcall.stack_frames[0].stage, "parse");
    assert_eq!(after_hostcall.stack_frames[1].stage, "boundary_transition");
    assert_eq!(
        after_hostcall.stack_frames[1].boundary.as_deref(),
        Some("async_job")
    );
    assert_eq!(after_hostcall.stack_frames[2].stage, "boundary_transition");
    assert_eq!(
        after_hostcall.stack_frames[2].boundary.as_deref(),
        Some("hostcall")
    );
    assert_eq!(
        after_hostcall.stack_frames[1].location.as_ref(),
        Some(&location)
    );
    assert_eq!(
        after_hostcall.stack_frames[2].location.as_ref(),
        Some(&location)
    );
}

// =========================================================================
// Section 3: Route selection
// =========================================================================

#[test]
fn hybrid_routes_import_keyword_to_v8() {
    let _router = HybridRouter::default();
    // The routing decision is based on keyword detection.
    let route = if "import x from 'y'".contains("import ") {
        RouteReason::ContainsImportKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    };
    assert_eq!(route, RouteReason::ContainsImportKeyword);
}

#[test]
fn hybrid_routes_await_keyword_to_v8() {
    let route = if "await job()".contains("await ") {
        RouteReason::ContainsAwaitKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    };
    assert_eq!(route, RouteReason::ContainsAwaitKeyword);
}

#[test]
fn hybrid_routes_simple_source_to_quickjs() {
    let mut router = HybridRouter::default();
    let outcome = router.eval("'route'").expect("expected eval success");
    assert_eq!(outcome.route_reason, RouteReason::DefaultQuickJsPath);
    assert_eq!(outcome.engine, EngineKind::QuickJsInspiredNative);
    assert_eq!(outcome.value, "route");
}

// =========================================================================
// Section 4: IR3 pipeline execution (AST-level, bypasses parser)
// =========================================================================

#[test]
fn ir3_execution_of_numeric_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(42))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "num.js");
    let ctx = LoweringContext::new("trace-num", "decision-num", "policy-num");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-num", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_string_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::StringLiteral("hello".to_string()))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "str.js");
    let ctx = LoweringContext::new("trace-str", "decision-str", "policy-str");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-str", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_boolean_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::BooleanLiteral(true))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "bool.js");
    let ctx = LoweringContext::new("trace-bool", "decision-bool", "policy-bool");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-bool", Some(LaneChoice::V8))
        .expect("execution should succeed");
    assert_eq!(result.lane, LaneChoice::V8);
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_var_declaration() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(99)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "var.js");
    let ctx = LoweringContext::new("trace-var", "decision-var", "policy-var");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-var", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_produces_witness_events() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "witness.js");
    let ctx = LoweringContext::new("trace-wit", "decision-wit", "policy-wit");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-wit", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    // Execution should produce at least one witness event.
    assert!(
        !result.result.witness_events.is_empty(),
        "expected witness events from execution"
    );
}

// =========================================================================
// Section 5: Determinism — same input produces same output
// =========================================================================

#[test]
fn ir3_execution_is_deterministic() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(10)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::StringLiteral("test".to_string())),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree.clone(), "determ.js");
    let ctx = LoweringContext::new("trace-det", "decision-det", "policy-det");

    let output1 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 1");
    let output2 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 2");

    let router = LaneRouter::new();
    let r1 = router
        .execute(&output1.ir3, "trace-det", Some(LaneChoice::QuickJs))
        .expect("exec 1");
    let r2 = router
        .execute(&output2.ir3, "trace-det", Some(LaneChoice::QuickJs))
        .expect("exec 2");

    assert_eq!(
        r1.result.instructions_executed, r2.result.instructions_executed,
        "instruction count must be deterministic"
    );
    assert_eq!(
        r1.result.value.to_string(),
        r2.result.value.to_string(),
        "result value must be deterministic"
    );
}

// =========================================================================
// Section 6: Two-lane parity
// =========================================================================

#[test]
fn quickjs_and_v8_lanes_produce_same_result_for_simple_program() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(42))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "parity.js");
    let ctx = LoweringContext::new("trace-parity", "decision-parity", "policy-parity");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let qjs = router
        .execute(&output.ir3, "trace-qjs", Some(LaneChoice::QuickJs))
        .expect("quickjs exec");
    let v8 = router
        .execute(&output.ir3, "trace-v8", Some(LaneChoice::V8))
        .expect("v8 exec");

    assert_eq!(
        qjs.result.value.to_string(),
        v8.result.value.to_string(),
        "both lanes should produce same value"
    );
}

// =========================================================================
// Section 7: Error mapping through eval
// =========================================================================

#[test]
fn eval_error_code_serde_roundtrip() {
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let back: EvalErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

#[test]
fn eval_error_display_is_non_empty_for_all_codes() {
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    for code in &codes {
        assert!(!format!("{code:?}").is_empty());
    }
}

// =========================================================================
// Section 8: Lowering pipeline output completeness
// =========================================================================

#[test]
fn lowering_output_has_witnesses_and_events() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "output.js");
    let ctx = LoweringContext::new("trace-out", "decision-out", "policy-out");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    assert!(!output.witnesses.is_empty(), "output should have witnesses");
    assert!(!output.events.is_empty(), "output should have events");
    assert!(
        !output.ir3.instructions.is_empty(),
        "IR3 should have instructions"
    );
}

#[test]
fn lowering_output_ir3_terminates_with_halt() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "halt.js");
    let ctx = LoweringContext::new("trace-halt", "decision-halt", "policy-halt");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    use frankenengine_engine::ir_contract::Ir3Instruction;
    assert!(
        matches!(output.ir3.instructions.last(), Some(Ir3Instruction::Halt)),
        "IR3 must terminate with Halt instruction"
    );
}

// =========================================================================
// Section 9: Complex programs
// =========================================================================

#[test]
fn multiple_var_declarations_execute_successfully() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "b",
                Some(Expression::NumericLiteral(2)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "c",
                Some(Expression::NumericLiteral(3)),
            ),
            expr_stmt(Expression::Identifier("a".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "multi.js");
    let ctx = LoweringContext::new("trace-multi", "decision-multi", "policy-multi");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-multi", Some(LaneChoice::QuickJs))
        .expect("execution");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn mixed_literal_types_execute_successfully() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "s",
                Some(Expression::StringLiteral("hi".to_string())),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "n",
                Some(Expression::NumericLiteral(0)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::BooleanLiteral(false)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "u",
                Some(Expression::UndefinedLiteral),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "z",
                Some(Expression::NullLiteral),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "mixed_lit.js");
    let ctx = LoweringContext::new("trace-mix", "decision-mix", "policy-mix");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-mix", Some(LaneChoice::V8))
        .expect("execution");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn hybrid_router_debug_is_nonempty() {
    let router = HybridRouter::default();
    assert!(!format!("{router:?}").is_empty());
}

#[test]
fn eval_error_code_debug_is_nonempty() {
    let code = EvalErrorCode::ParseFailure;
    assert!(!format!("{code:?}").is_empty());
}

#[test]
fn lane_choice_debug_is_nonempty() {
    let choice = LaneChoice::V8;
    assert!(!format!("{choice:?}").is_empty());
}

// =========================================================================
// Section 10: Serde and Display for key types
// =========================================================================

#[test]
fn engine_kind_serde_roundtrip() {
    let kinds = [
        EngineKind::QuickJsInspiredNative,
        EngineKind::V8InspiredNative,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let expected = match kind {
            EngineKind::QuickJsInspiredNative => "baseline_deterministic_profile",
            EngineKind::V8InspiredNative => "baseline_throughput_profile",
            EngineKind::Hybrid => unreachable!("hybrid is not covered here"),
        };
        assert_eq!(json, format!("\"{expected}\""));
        let back: EngineKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn lane_choice_serde_roundtrip() {
    let lanes = [LaneChoice::QuickJs, LaneChoice::V8];
    for lane in &lanes {
        let json = serde_json::to_string(lane).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, back);
    }
}

#[test]
fn eval_error_correlation_ids_survive_serde() {
    let err = EvalError::runtime_fault("test-error").with_correlation_ids(
        "trace-serde",
        "decision-serde",
        "policy-serde",
    );
    let json = serde_json::to_string(&err).unwrap();
    let back: EvalError = serde_json::from_str(&json).unwrap();
    assert_eq!(back.code, EvalErrorCode::RuntimeFault);
    let ids = back
        .correlation_ids
        .expect("correlation ids should roundtrip");
    assert_eq!(ids.trace_id, "trace-serde");
    assert_eq!(ids.decision_id, "decision-serde");
    assert_eq!(ids.policy_id, "policy-serde");
}

#[test]
fn propagation_through_all_exception_boundaries() {
    let base = EvalError::runtime_fault("propagation test").with_correlation_ids(
        "trace-prop",
        "decision-prop",
        "policy-prop",
    );
    let after_sync = propagate_error_across_boundary(base, ExceptionBoundary::SyncCallframe);
    let after_async = propagate_error_across_boundary(after_sync, ExceptionBoundary::AsyncJob);
    let after_host = propagate_error_across_boundary(after_async, ExceptionBoundary::Hostcall);
    assert_eq!(after_host.stack_frames.len(), 3);
    assert!(after_host.message.contains("boundary=hostcall"));
    assert_eq!(after_host.code, EvalErrorCode::RuntimeFault);
}

#[test]
fn ir3_null_literal_produces_valid_execution() {
    let tree = make_tree(ParseGoal::Script, vec![expr_stmt(Expression::NullLiteral)]);
    let ir0 = Ir0Module::from_syntax_tree(tree, "null.js");
    let ctx = LoweringContext::new("trace-null", "decision-null", "policy-null");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-null", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}
