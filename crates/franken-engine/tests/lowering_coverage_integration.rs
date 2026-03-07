//! Lowering Coverage Integration Tests — bd-1lsy.2.3
//!
//! Verifies that EVERY parser-supported syntax family lowers through the
//! full IR0 → IR1 → IR2 → IR3 pipeline with:
//! - deterministic output (run twice, get identical hashes)
//! - witness generation (all passes produce witnesses)
//! - hash chain integrity (each level's source_hash references the previous level)
//! - correct scope/binding resolution
//! - canonical hash stability

#![forbid(unsafe_code)]

use frankenengine_engine::ast::{
    ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, BlockStatement, BreakStatement,
    CatchClause, ContinueStatement, DoWhileStatement, ExportDeclaration, ExportKind, Expression,
    ExpressionStatement, ForStatement, FunctionDeclaration, FunctionParam, IfStatement,
    ImportDeclaration, ObjectProperty, ParseGoal, ReturnStatement, SourceSpan, Statement,
    SwitchCase, SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement, UnaryOperator,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator, WhileStatement,
};
use frankenengine_engine::ir_contract::{
    BindingKind, Ir0Module, Ir1Op, Ir1PropertyKey, Ir3Instruction, IrLevel, ScopeKind,
};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, LoweringPipelineOutput, lower_ir0_to_ir1,
    lower_ir0_to_ir3, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::static_semantics::analyze;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 10)
}

fn ctx() -> LoweringContext {
    LoweringContext::new("trace-cov", "decision-cov", "policy-cov")
}

fn make_ir0(goal: ParseGoal, body: Vec<Statement>) -> Ir0Module {
    Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal,
            body,
            span: span(),
        },
        "<lowering-coverage>",
    )
}

fn make_var_decl(kind: VariableDeclarationKind, name: &str, init: Option<Expression>) -> Statement {
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

fn make_import(source: &str, binding: Option<&str>) -> Statement {
    Statement::Import(ImportDeclaration {
        source: source.to_string(),
        binding: binding.map(|s| s.to_string()),
        span: span(),
    })
}

fn make_default_export(expr: Expression) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expr),
        span: span(),
    })
}

fn make_named_export(clause: &str) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(clause.to_string()),
        span: span(),
    })
}

fn make_expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

fn run_full(ir0: &Ir0Module) -> LoweringPipelineOutput {
    lower_ir0_to_ir3(ir0, &ctx()).expect("full pipeline should succeed")
}

// ===========================================================================
// Section 1: Full-Pipeline Determinism — Every Syntax Family
// ===========================================================================

#[test]
fn determinism_var_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
    assert_eq!(a.witnesses.len(), b.witnesses.len());
    for (wa, wb) in a.witnesses.iter().zip(b.witnesses.iter()) {
        assert_eq!(wa.output_hash, wb.output_hash);
    }
}

#[test]
fn determinism_let_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "y",
            Some(Expression::StringLiteral("hello".to_string())),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_const_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Const,
            "PI",
            Some(Expression::NumericLiteral(314159)),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_import_with_binding() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("react", Some("React"))]);
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_import_no_binding() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("side-effect", None)]);
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_default_export() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_default_export(Expression::NumericLiteral(1))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_named_export() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_var_decl(
                VariableDeclarationKind::Const,
                "foo",
                Some(Expression::NumericLiteral(1)),
            ),
            make_named_export("{ foo }"),
        ],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_all_literal_types() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_expr_stmt(Expression::NumericLiteral(0)),
            make_expr_stmt(Expression::StringLiteral("text".to_string())),
            make_expr_stmt(Expression::BooleanLiteral(true)),
            make_expr_stmt(Expression::BooleanLiteral(false)),
            make_expr_stmt(Expression::NullLiteral),
            make_expr_stmt(Expression::UndefinedLiteral),
        ],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_identifier_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Identifier(
            "console".to_string(),
        ))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_await_expression() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_expr_stmt(Expression::Await(Box::new(
            Expression::Identifier("promise".to_string()),
        )))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_raw_expression_no_call() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Raw(
            "some_raw_thing".to_string(),
        ))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_raw_expression_with_call() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Raw("fn()".to_string()))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

// ===========================================================================
// Section 2: Hash Chain Integrity
// ===========================================================================

#[test]
fn hash_chain_ir1_links_to_ir0() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "a",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir0_hash = ir0.content_hash();
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1_result.module.header.source_hash, Some(ir0_hash));
    assert_eq!(ir1_result.module.header.level, IrLevel::Ir1);
}

#[test]
fn hash_chain_ir2_links_to_ir1() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "b",
            Some(Expression::NumericLiteral(2)),
        )],
    );
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    let ir1_hash = ir1_result.module.content_hash();
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module).unwrap();
    assert_eq!(ir2_result.module.header.source_hash, Some(ir1_hash));
    assert_eq!(ir2_result.module.header.level, IrLevel::Ir2);
}

#[test]
fn hash_chain_ir3_links_to_ir2() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "c",
            Some(Expression::NumericLiteral(3)),
        )],
    );
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module).unwrap();
    let ir2_hash = ir2_result.module.content_hash();
    let ir3_result = lower_ir2_to_ir3(&ir2_result.module).unwrap();
    assert_eq!(ir3_result.module.header.source_hash, Some(ir2_hash));
    assert_eq!(ir3_result.module.header.level, IrLevel::Ir3);
}

#[test]
fn full_pipeline_three_witnesses() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "d",
            Some(Expression::NumericLiteral(4)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.witnesses[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.witnesses[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.witnesses[2].pass_id, "ir2_to_ir3");
}

#[test]
fn full_pipeline_isomorphism_ledger_entries() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "e",
            Some(Expression::NumericLiteral(5)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert_eq!(output.isomorphism_ledger[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.isomorphism_ledger[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.isomorphism_ledger[2].pass_id, "ir2_to_ir3");
}

#[test]
fn witness_invariant_checks_all_pass() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("pkg", Some("P")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "val",
                Some(Expression::NumericLiteral(100)),
            ),
            make_default_export(Expression::NumericLiteral(100)),
        ],
    );
    let output = run_full(&ir0);
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(
                check.passed,
                "invariant {} failed: {}",
                check.name, check.detail
            );
        }
    }
}

// ===========================================================================
// Section 3: Scope and Binding Resolution
// ===========================================================================

#[test]
fn script_goal_creates_global_scope() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes.len(), 1);
    assert_eq!(ir1.module.scopes[0].kind, ScopeKind::Global);
}

#[test]
fn module_goal_creates_module_scope() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("mod", Some("m"))]);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes.len(), 1);
    assert_eq!(ir1.module.scopes[0].kind, ScopeKind::Module);
}

#[test]
fn var_declaration_creates_var_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "x");
    assert_eq!(binding.kind, BindingKind::Var);
}

#[test]
fn let_declaration_creates_let_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "y",
            Some(Expression::NumericLiteral(2)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "y");
    assert_eq!(binding.kind, BindingKind::Let);
}

#[test]
fn const_declaration_creates_const_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Const,
            "Z",
            Some(Expression::NumericLiteral(3)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "Z");
    assert_eq!(binding.kind, BindingKind::Const);
}

#[test]
fn import_creates_import_binding() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("react", Some("React"))]);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "React");
    assert_eq!(binding.kind, BindingKind::Import);
}

#[test]
fn multiple_var_declarations_reuse_same_binding_id() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    // var + var should reuse — only one binding
    assert_eq!(ir1.module.scopes[0].bindings.len(), 1);
}

#[test]
fn multi_declarator_creates_multiple_bindings() {
    let ir0 = Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![
                    VariableDeclarator {
                        pattern: BindingPattern::Identifier("a".to_string()),
                        initializer: Some(Expression::NumericLiteral(1)),
                        span: span(),
                    },
                    VariableDeclarator {
                        pattern: BindingPattern::Identifier("b".to_string()),
                        initializer: Some(Expression::NumericLiteral(2)),
                        span: span(),
                    },
                    VariableDeclarator {
                        pattern: BindingPattern::Identifier("c".to_string()),
                        initializer: Some(Expression::NumericLiteral(3)),
                        span: span(),
                    },
                ],
                span: span(),
            })],
            span: span(),
        },
        "<multi-decl>",
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes[0].bindings.len(), 3);
    assert_eq!(ir1.module.scopes[0].bindings[0].name, "a");
    assert_eq!(ir1.module.scopes[0].bindings[1].name, "b");
    assert_eq!(ir1.module.scopes[0].bindings[2].name, "c");
}

// ===========================================================================
// Section 4: IR3 Instruction Verification
// ===========================================================================

#[test]
fn ir3_ends_with_halt() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(42))],
    );
    let output = run_full(&ir0);
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn ir3_has_main_function_descriptor() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.ir3.function_table.len(), 1);
    assert_eq!(output.ir3.function_table[0].name.as_deref(), Some("main"));
    assert_eq!(output.ir3.function_table[0].entry, 0);
}

#[test]
fn ir3_numeric_literal_produces_load_int() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(99))],
    );
    let output = run_full(&ir0);
    let has_load_int = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadInt { value: 99, .. }));
    assert!(has_load_int, "expected LoadInt(99)");
}

#[test]
fn ir3_string_literal_uses_constant_pool() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::StringLiteral(
            "hello world".to_string(),
        ))],
    );
    let output = run_full(&ir0);
    assert!(
        output
            .ir3
            .constant_pool
            .contains(&"hello world".to_string())
    );
    let has_load_str = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadStr { .. }));
    assert!(has_load_str, "expected LoadStr instruction");
}

#[test]
fn ir3_boolean_literal_produces_load_bool() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_expr_stmt(Expression::BooleanLiteral(true)),
            make_expr_stmt(Expression::BooleanLiteral(false)),
        ],
    );
    let output = run_full(&ir0);
    let has_true = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadBool { value: true, .. }));
    let has_false = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadBool { value: false, .. }));
    assert!(has_true, "expected LoadBool(true)");
    assert!(has_false, "expected LoadBool(false)");
}

#[test]
fn ir3_null_literal_produces_load_null() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NullLiteral)],
    );
    let output = run_full(&ir0);
    let has_load_null = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadNull { .. }));
    assert!(has_load_null, "expected LoadNull");
}

#[test]
fn ir3_undefined_literal_produces_load_undefined() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::UndefinedLiteral)],
    );
    let output = run_full(&ir0);
    let has_load_undef = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadUndefined { .. }));
    assert!(has_load_undef, "expected LoadUndefined");
}

#[test]
fn ir3_import_uses_constant_pool_for_specifier() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("lodash", Some("_"))]);
    let output = run_full(&ir0);
    assert!(output.ir3.constant_pool.contains(&"lodash".to_string()));
}

// ===========================================================================
// Section 5: IFC / Flow Proof Artifact
// ===========================================================================

#[test]
fn flow_proof_artifact_has_schema_version() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("pkg", Some("p"))]);
    let output = run_full(&ir0);
    assert!(!output.ir2_flow_proof_artifact.schema_version.is_empty());
}

#[test]
fn flow_proof_artifact_has_artifact_id() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("pkg", Some("p"))]);
    let output = run_full(&ir0);
    assert!(
        output
            .ir2_flow_proof_artifact
            .artifact_id
            .starts_with("sha256:"),
        "artifact_id should be a sha256 hash"
    );
}

#[test]
fn flow_proof_artifact_deterministic() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("pkg", Some("p"))]);
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(
        a.ir2_flow_proof_artifact.artifact_id,
        b.ir2_flow_proof_artifact.artifact_id
    );
}

#[test]
fn flow_proof_no_denied_flows_for_clean_module() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("clean", Some("c")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "val",
                Some(Expression::NumericLiteral(42)),
            ),
        ],
    );
    let output = run_full(&ir0);
    assert!(
        output.ir2_flow_proof_artifact.denied_flows.is_empty(),
        "clean module should have no denied flows"
    );
}

// ===========================================================================
// Section 6: Error Paths
// ===========================================================================

#[test]
fn empty_body_rejects_lowering() {
    let ir0 = make_ir0(ParseGoal::Script, vec![]);
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::EmptyIr0Body));
}

#[test]
fn const_without_initializer_rejects() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(VariableDeclarationKind::Const, "bad", None)],
    );
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn duplicate_let_binding_rejects() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn full_pipeline_empty_body_reports_error() {
    let ir0 = make_ir0(ParseGoal::Script, vec![]);
    let err = lower_ir0_to_ir3(&ir0, &ctx()).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::EmptyIr0Body));
}

// ===========================================================================
// Section 7: Events / Structured Logging
// ===========================================================================

#[test]
fn full_pipeline_emits_success_events() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "z",
            Some(Expression::NumericLiteral(7)),
        )],
    );
    let output = run_full(&ir0);
    assert!(!output.events.is_empty());
    // All events should be successes for a clean module
    for event in &output.events {
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn events_include_all_pass_names() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("pkg", Some("p"))]);
    let output = run_full(&ir0);
    let event_names: Vec<&str> = output.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"ir0_to_ir1_lowered"));
    assert!(event_names.contains(&"ir1_to_ir2_lowered"));
    assert!(event_names.contains(&"ir2_to_ir3_lowered"));
}

#[test]
fn events_carry_context_fields() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let output = run_full(&ir0);
    for event in &output.events {
        assert_eq!(event.trace_id, "trace-cov");
        assert_eq!(event.decision_id, "decision-cov");
        assert_eq!(event.policy_id, "policy-cov");
    }
}

// ===========================================================================
// Section 8: Static Semantics Integration
// ===========================================================================

#[test]
fn static_semantics_passes_for_valid_var_program() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
        span: span(),
    };
    let result = analyze(&tree);
    assert!(result.passed());
    // Also verify lowering succeeds
    let ir0 = Ir0Module::from_syntax_tree(tree, "<integrated>");
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn static_semantics_detects_duplicate_let_then_lowering_also_rejects() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        span: span(),
    };
    // Static semantics catches it
    let analysis = analyze(&tree);
    assert!(!analysis.passed());
    // Lowering also catches it
    let ir0 = Ir0Module::from_syntax_tree(tree, "<dup>");
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn static_semantics_const_without_init_matches_lowering_rejection() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![make_var_decl(VariableDeclarationKind::Const, "bad", None)],
        span: span(),
    };
    let analysis = analyze(&tree);
    assert!(!analysis.passed());
    let ir0 = Ir0Module::from_syntax_tree(tree, "<const-no-init>");
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn static_semantics_module_with_imports_and_exports_integrates() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            make_import("react", Some("React")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "App",
                Some(Expression::StringLiteral("component".to_string())),
            ),
            make_default_export(Expression::NumericLiteral(1)),
        ],
        span: span(),
    };
    let analysis = analyze(&tree);
    assert!(analysis.passed());
    let ir0 = Ir0Module::from_syntax_tree(tree, "<module-integrated>");
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert!(output.ir2_flow_proof_artifact.denied_flows.is_empty());
}

// ===========================================================================
// Section 9: Canonical Hash Stability
// ===========================================================================

#[test]
fn canonical_hash_differs_for_different_inputs() {
    let ir0_a = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0_b = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(2))],
    );
    let out_a = run_full(&ir0_a);
    let out_b = run_full(&ir0_b);
    assert_ne!(out_a.ir3.content_hash(), out_b.ir3.content_hash());
}

#[test]
fn canonical_hash_differs_for_script_vs_module() {
    let body = vec![make_expr_stmt(Expression::NumericLiteral(1))];
    let ir0_script = make_ir0(ParseGoal::Script, body.clone());
    let ir0_module = make_ir0(ParseGoal::Module, body);
    let out_script = run_full(&ir0_script);
    let out_module = run_full(&ir0_module);
    assert_ne!(out_script.ir3.content_hash(), out_module.ir3.content_hash());
}

#[test]
fn canonical_hash_differs_for_var_vs_let() {
    let ir0_var = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir0_let = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let out_var = run_full(&ir0_var);
    let out_let = run_full(&ir0_let);
    // Different binding kinds should produce different IR, hence different hashes
    assert_ne!(out_var.ir1.content_hash(), out_let.ir1.content_hash());
}

// ===========================================================================
// Section 10: Complex / Composite Programs
// ===========================================================================

#[test]
fn complex_module_with_all_syntax_families() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("react", Some("React")),
            make_import("side-fx", None),
            make_var_decl(
                VariableDeclarationKind::Const,
                "VERSION",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "state",
                Some(Expression::BooleanLiteral(false)),
            ),
            make_expr_stmt(Expression::StringLiteral("init".to_string())),
            make_expr_stmt(Expression::NullLiteral),
            make_expr_stmt(Expression::UndefinedLiteral),
            make_default_export(Expression::NumericLiteral(42)),
            make_named_export("{ VERSION }"),
        ],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert!(!output.events.is_empty());
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(check.passed);
        }
    }
    // Determinism
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn mixed_var_and_expression_statements() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            make_expr_stmt(Expression::NumericLiteral(99)),
            make_var_decl(
                VariableDeclarationKind::Var,
                "b",
                Some(Expression::StringLiteral("test".to_string())),
            ),
            make_expr_stmt(Expression::Raw("fn()".to_string())),
        ],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn serde_roundtrip_for_pipeline_output() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("pkg", Some("P")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(42)),
            ),
        ],
    );
    let output = run_full(&ir0);
    // Test IR1 serde
    let ir1_json = serde_json::to_string(&output.ir1).unwrap();
    let ir1_back: frankenengine_engine::ir_contract::Ir1Module =
        serde_json::from_str(&ir1_json).unwrap();
    assert_eq!(output.ir1, ir1_back);
    // Test IR2 serde
    let ir2_json = serde_json::to_string(&output.ir2).unwrap();
    let ir2_back: frankenengine_engine::ir_contract::Ir2Module =
        serde_json::from_str(&ir2_json).unwrap();
    assert_eq!(output.ir2, ir2_back);
    // Test witness serde
    let witness_json = serde_json::to_string(&output.witnesses).unwrap();
    let witness_back: Vec<frankenengine_engine::lowering_pipeline::PassWitness> =
        serde_json::from_str(&witness_json).unwrap();
    assert_eq!(output.witnesses, witness_back);
}

#[test]
fn serde_roundtrip_for_flow_proof_artifact() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("pkg", Some("P"))]);
    let output = run_full(&ir0);
    let json = serde_json::to_string(&output.ir2_flow_proof_artifact).unwrap();
    let back: frankenengine_engine::lowering_pipeline::Ir2FlowProofArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output.ir2_flow_proof_artifact, back);
}

// ===========================================================================
// Section 11: Control Flow Statement Lowering
// ===========================================================================

fn make_block(stmts: Vec<Statement>) -> Statement {
    Statement::Block(BlockStatement {
        body: stmts,
        span: span(),
    })
}

fn make_if(cond: Expression, then: Statement, alt: Option<Statement>) -> Statement {
    Statement::If(IfStatement {
        condition: cond,
        consequent: Box::new(then),
        alternate: alt.map(Box::new),
        span: span(),
    })
}

fn make_while(cond: Expression, body: Statement) -> Statement {
    Statement::While(WhileStatement {
        condition: cond,
        body: Box::new(body),
        span: span(),
    })
}

fn make_do_while(body: Statement, cond: Expression) -> Statement {
    Statement::DoWhile(DoWhileStatement {
        body: Box::new(body),
        condition: cond,
        span: span(),
    })
}

fn make_for(
    init: Option<Statement>,
    cond: Option<Expression>,
    update: Option<Expression>,
    body: Statement,
) -> Statement {
    Statement::For(ForStatement {
        init: init.map(Box::new),
        condition: cond,
        update,
        body: Box::new(body),
        span: span(),
    })
}

fn make_return(arg: Option<Expression>) -> Statement {
    Statement::Return(ReturnStatement {
        argument: arg,
        span: span(),
    })
}

fn make_throw(arg: Expression) -> Statement {
    Statement::Throw(ThrowStatement {
        argument: arg,
        span: span(),
    })
}

fn make_try_catch(
    body: Vec<Statement>,
    catch_param: Option<&str>,
    catch_body: Vec<Statement>,
    finally_body: Option<Vec<Statement>>,
) -> Statement {
    Statement::TryCatch(TryCatchStatement {
        block: BlockStatement { body, span: span() },
        handler: Some(CatchClause {
            parameter: catch_param.map(|s| s.to_string()),
            body: BlockStatement {
                body: catch_body,
                span: span(),
            },
            span: span(),
        }),
        finalizer: finally_body.map(|stmts| BlockStatement {
            body: stmts,
            span: span(),
        }),
        span: span(),
    })
}

fn make_switch(disc: Expression, cases: Vec<SwitchCase>) -> Statement {
    Statement::Switch(SwitchStatement {
        discriminant: disc,
        cases,
        span: span(),
    })
}

fn make_func_decl(name: &str, params: &[&str], body: Vec<Statement>) -> Statement {
    Statement::FunctionDeclaration(FunctionDeclaration {
        name: Some(name.to_string()),
        params: params
            .iter()
            .map(|p| FunctionParam {
                pattern: BindingPattern::Identifier(p.to_string()),
                span: span(),
            })
            .collect(),
        body: BlockStatement { body, span: span() },
        is_async: false,
        is_generator: false,
        span: span(),
    })
}

#[test]
fn lowering_block_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_block(vec![make_expr_stmt(
            Expression::NumericLiteral(1),
        )])],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_if_statement_consequent_only() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_if(
            Expression::BooleanLiteral(true),
            make_expr_stmt(Expression::NumericLiteral(42)),
            None,
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_if_statement_with_alternate() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_if(
            Expression::BooleanLiteral(false),
            make_expr_stmt(Expression::NumericLiteral(1)),
            Some(make_expr_stmt(Expression::NumericLiteral(2))),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_if_produces_jump_instructions() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_if(
            Expression::BooleanLiteral(true),
            make_expr_stmt(Expression::NumericLiteral(1)),
            Some(make_expr_stmt(Expression::NumericLiteral(2))),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_jump_if_falsy = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }));
    assert!(has_jump_if_falsy, "if statement should produce JumpIfFalsy");
    let has_jump = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Jump { .. }));
    assert!(has_jump, "if-else should produce unconditional Jump");
}

#[test]
fn lowering_while_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_while(
            Expression::BooleanLiteral(false),
            make_expr_stmt(Expression::NumericLiteral(99)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_while_produces_loop_structure() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_while(
            Expression::BooleanLiteral(false),
            make_expr_stmt(Expression::NumericLiteral(1)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let label_count = ir1
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Label { .. }))
        .count();
    assert!(label_count >= 2, "while loop needs start and end labels");
    let has_jump = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Jump { .. }));
    assert!(has_jump, "while loop needs back-edge jump");
}

#[test]
fn lowering_do_while_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_do_while(
            make_expr_stmt(Expression::NumericLiteral(1)),
            Expression::BooleanLiteral(false),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_for_statement_full() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_for(
            Some(make_var_decl(
                VariableDeclarationKind::Let,
                "i",
                Some(Expression::NumericLiteral(0)),
            )),
            Some(Expression::BooleanLiteral(true)),
            Some(Expression::NumericLiteral(1)),
            make_expr_stmt(Expression::NumericLiteral(99)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_for_statement_no_init() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_for(
            None,
            Some(Expression::BooleanLiteral(false)),
            None,
            make_expr_stmt(Expression::NumericLiteral(0)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_for_statement_infinite_skeleton() {
    // for(;;) body — all optional parts omitted
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_for(
            None,
            None,
            None,
            make_expr_stmt(Expression::NumericLiteral(0)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_return_with_argument() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_return(Some(Expression::NumericLiteral(42)))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_return = ir1.module.ops.iter().any(|op| matches!(op, Ir1Op::Return));
    assert!(has_return, "return statement should produce Ir1Op::Return");
}

#[test]
fn lowering_return_without_argument() {
    let ir0 = make_ir0(ParseGoal::Script, vec![make_return(None)]);
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_throw_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_throw(Expression::StringLiteral("err".to_string()))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_throw = ir1.module.ops.iter().any(|op| matches!(op, Ir1Op::Throw));
    assert!(has_throw, "throw statement should produce Ir1Op::Throw");
}

#[test]
fn lowering_try_catch_basic() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_try_catch(
            vec![make_expr_stmt(Expression::NumericLiteral(1))],
            Some("e"),
            vec![make_expr_stmt(Expression::NumericLiteral(2))],
            None,
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_try_catch_with_finally() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_try_catch(
            vec![make_expr_stmt(Expression::NumericLiteral(1))],
            Some("err"),
            vec![make_expr_stmt(Expression::NumericLiteral(2))],
            Some(vec![make_expr_stmt(Expression::NumericLiteral(3))]),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_try_catch_produces_begin_end_try() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_try_catch(
            vec![make_expr_stmt(Expression::NumericLiteral(1))],
            Some("e"),
            vec![make_expr_stmt(Expression::NumericLiteral(2))],
            None,
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_begin_try = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::BeginTry { .. }));
    let has_end_try = ir1.module.ops.iter().any(|op| matches!(op, Ir1Op::EndTry));
    assert!(has_begin_try, "try-catch should produce BeginTry");
    assert!(has_end_try, "try-catch should produce EndTry");
}

#[test]
fn lowering_switch_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_switch(
            Expression::NumericLiteral(1),
            vec![
                SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![make_expr_stmt(Expression::StringLiteral("one".to_string()))],
                    span: span(),
                },
                SwitchCase {
                    test: Some(Expression::NumericLiteral(2)),
                    consequent: vec![make_expr_stmt(Expression::StringLiteral("two".to_string()))],
                    span: span(),
                },
                SwitchCase {
                    test: None, // default
                    consequent: vec![make_expr_stmt(Expression::StringLiteral(
                        "default".to_string(),
                    ))],
                    span: span(),
                },
            ],
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_break_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_while(
            Expression::BooleanLiteral(true),
            Statement::Break(BreakStatement {
                label: None,
                span: span(),
            }),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_continue_statement() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_for(
            None,
            Some(Expression::BooleanLiteral(true)),
            Some(Expression::NumericLiteral(1)),
            Statement::Continue(ContinueStatement {
                label: None,
                span: span(),
            }),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_function_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_func_decl(
            "greet",
            &["name"],
            vec![make_return(Some(Expression::StringLiteral(
                "hello".to_string(),
            )))],
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_decl_func = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::DeclareFunction { name, .. } if name == "greet"));
    assert!(
        has_decl_func,
        "function declaration should produce DeclareFunction"
    );
}

#[test]
fn lowering_function_declaration_creates_let_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_func_decl(
            "add",
            &["a", "b"],
            vec![make_expr_stmt(Expression::NumericLiteral(0))],
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let func_binding = ir1.module.scopes[0]
        .bindings
        .iter()
        .find(|b| b.name == "add");
    assert!(func_binding.is_some(), "function name should be bound");
    assert_eq!(func_binding.unwrap().kind, BindingKind::Var);
}

// ===========================================================================
// Section 12: Expression Lowering — New Syntax Types
// ===========================================================================

#[test]
fn lowering_binary_add_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_binop = ir1.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::BinaryOp {
                operator: BinaryOperator::Add
            }
        )
    });
    assert!(has_binop, "binary add should produce BinaryOp");
}

#[test]
fn lowering_binary_operators_all_arithmetic() {
    for (op, label) in [
        (BinaryOperator::Add, "add"),
        (BinaryOperator::Subtract, "sub"),
        (BinaryOperator::Multiply, "mul"),
        (BinaryOperator::Divide, "div"),
        (BinaryOperator::Remainder, "rem"),
    ] {
        let ir0 = make_ir0(
            ParseGoal::Script,
            vec![make_expr_stmt(Expression::Binary {
                operator: op.clone(),
                left: Box::new(Expression::NumericLiteral(10)),
                right: Box::new(Expression::NumericLiteral(3)),
            })],
        );
        let output = run_full(&ir0);
        assert_eq!(output.witnesses.len(), 3, "failed for {label}");
    }
}

#[test]
fn lowering_binary_comparison_operators() {
    for (op, label) in [
        (BinaryOperator::Equal, "eq"),
        (BinaryOperator::NotEqual, "neq"),
        (BinaryOperator::StrictEqual, "seq"),
        (BinaryOperator::StrictNotEqual, "sneq"),
        (BinaryOperator::LessThan, "lt"),
        (BinaryOperator::GreaterThan, "gt"),
    ] {
        let ir0 = make_ir0(
            ParseGoal::Script,
            vec![make_expr_stmt(Expression::Binary {
                operator: op.clone(),
                left: Box::new(Expression::NumericLiteral(1)),
                right: Box::new(Expression::NumericLiteral(2)),
            })],
        );
        let output = run_full(&ir0);
        assert_eq!(output.witnesses.len(), 3, "failed for {label}");
    }
}

#[test]
fn lowering_binary_logical_operators() {
    for (op, label) in [
        (BinaryOperator::LogicalAnd, "and"),
        (BinaryOperator::LogicalOr, "or"),
        (BinaryOperator::NullishCoalescing, "nullish"),
    ] {
        let ir0 = make_ir0(
            ParseGoal::Script,
            vec![make_expr_stmt(Expression::Binary {
                operator: op.clone(),
                left: Box::new(Expression::BooleanLiteral(true)),
                right: Box::new(Expression::BooleanLiteral(false)),
            })],
        );
        let output = run_full(&ir0);
        assert_eq!(output.witnesses.len(), 3, "failed for {label}");
    }
}

#[test]
fn lowering_unary_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Unary {
            operator: UnaryOperator::Negate,
            argument: Box::new(Expression::NumericLiteral(5)),
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_unary = ir1.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::UnaryOp {
                operator: UnaryOperator::Negate
            }
        )
    });
    assert!(has_unary, "unary negate should produce UnaryOp");
}

#[test]
fn lowering_unary_operators_all_variants() {
    for (op, label) in [
        (UnaryOperator::Negate, "negate"),
        (UnaryOperator::BitwiseNot, "bitwise_not"),
        (UnaryOperator::LogicalNot, "logical_not"),
        (UnaryOperator::Typeof, "typeof"),
        (UnaryOperator::Void, "void"),
    ] {
        let ir0 = make_ir0(
            ParseGoal::Script,
            vec![make_expr_stmt(Expression::Unary {
                operator: op.clone(),
                argument: Box::new(Expression::NumericLiteral(1)),
            })],
        );
        let output = run_full(&ir0);
        assert_eq!(output.witnesses.len(), 3, "failed for {label}");
    }
}

#[test]
fn lowering_conditional_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(Expression::NumericLiteral(1)),
            alternate: Box::new(Expression::NumericLiteral(0)),
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_conditional_produces_branch_ops() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(Expression::NumericLiteral(1)),
            alternate: Box::new(Expression::NumericLiteral(0)),
        })],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_branch_ops = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }));
    assert!(
        has_branch_ops,
        "conditional expression should lower through explicit branch control flow"
    );
    assert!(
        !ir1.module.ops.iter().any(|op| matches!(op, Ir1Op::Pop)),
        "conditional expression should not eagerly evaluate both branches"
    );
}

#[test]
fn lowering_call_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Call {
            callee: Box::new(Expression::Identifier("console".to_string())),
            arguments: vec![Expression::StringLiteral("hello".to_string())],
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_call = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Call { arg_count: 1 }));
    assert!(
        has_call,
        "call expression should produce Call with arg_count=1"
    );
}

#[test]
fn lowering_call_expression_no_args() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Call {
            callee: Box::new(Expression::Identifier("fn".to_string())),
            arguments: vec![],
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_call_expression_multiple_args() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Call {
            callee: Box::new(Expression::Identifier("add".to_string())),
            arguments: vec![
                Expression::NumericLiteral(1),
                Expression::NumericLiteral(2),
                Expression::NumericLiteral(3),
            ],
        })],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_call = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Call { arg_count: 3 }));
    assert!(has_call, "3-arg call should have arg_count=3");
}

#[test]
fn lowering_member_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_get_prop = ir1.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(key)
            } if key == "prop"
        )
    });
    assert!(has_get_prop, "member expression should produce GetProperty");
}

#[test]
fn lowering_computed_member_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("propKey".to_string())),
            computed: true,
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_dynamic_get_prop = ir1.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Dynamic
            }
        )
    });
    assert!(
        has_dynamic_get_prop,
        "computed member expression should preserve a dynamic property key"
    );
}

#[test]
fn lowering_computed_member_assignment() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".to_string())),
                property: Box::new(Expression::Identifier("propKey".to_string())),
                computed: true,
            }),
            right: Box::new(Expression::NumericLiteral(7)),
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_dynamic_set_prop = ir1.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Dynamic
            }
        )
    });
    assert!(
        has_dynamic_set_prop,
        "computed member assignment should preserve a dynamic property key"
    );
    assert!(
        !ir1.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)),
        "computed member assignment should no longer degrade to a Nop placeholder"
    );
}

#[test]
fn lowering_this_expression() {
    let ir0 = make_ir0(ParseGoal::Script, vec![make_expr_stmt(Expression::This)]);
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_load_this = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::LoadThis));
    assert!(has_load_this, "this expression should produce LoadThis");
}

#[test]
fn lowering_array_literal() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ArrayLiteral(vec![
            Some(Expression::NumericLiteral(1)),
            Some(Expression::NumericLiteral(2)),
            Some(Expression::NumericLiteral(3)),
        ]))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_new_array = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::NewArray { count: 3 }));
    assert!(
        has_new_array,
        "array literal should produce NewArray(count=3)"
    );
}

#[test]
fn lowering_array_literal_with_holes() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ArrayLiteral(vec![
            Some(Expression::NumericLiteral(1)),
            None,
            Some(Expression::NumericLiteral(3)),
        ]))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_object_literal() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ObjectLiteral(vec![
            ObjectProperty {
                key: Expression::Identifier("x".to_string()),
                value: Expression::NumericLiteral(1),
                computed: false,
                shorthand: false,
            },
            ObjectProperty {
                key: Expression::Identifier("y".to_string()),
                value: Expression::NumericLiteral(2),
                computed: false,
                shorthand: false,
            },
        ]))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let has_new_object = ir1
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::NewObject { count: 2 }));
    assert!(
        has_new_object,
        "object literal should produce NewObject(count=2)"
    );
}

#[test]
fn lowering_object_literal_computed_key() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ObjectLiteral(vec![
            ObjectProperty {
                key: Expression::StringLiteral("dynamic-key".to_string()),
                value: Expression::NumericLiteral(42),
                computed: true,
                shorthand: false,
            },
        ]))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn lowering_arrow_function_expression_body() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ArrowFunction {
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("x".to_string()),
                span: span(),
            }],
            body: ArrowBody::Expression(Box::new(Expression::Binary {
                operator: BinaryOperator::Add,
                left: Box::new(Expression::Identifier("x".to_string())),
                right: Box::new(Expression::NumericLiteral(1)),
            })),
            is_async: false,
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn lowering_arrow_function_block_body() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::ArrowFunction {
            params: vec![
                FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: span(),
                },
                FunctionParam {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    span: span(),
                },
            ],
            body: ArrowBody::Block(BlockStatement {
                body: vec![make_return(Some(Expression::Binary {
                    operator: BinaryOperator::Add,
                    left: Box::new(Expression::Identifier("a".to_string())),
                    right: Box::new(Expression::Identifier("b".to_string())),
                }))],
                span: span(),
            }),
            is_async: false,
        })],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

// ===========================================================================
// Section 13: Determinism for Composite Control Flow
// ===========================================================================

#[test]
fn determinism_nested_if_in_while() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_while(
            Expression::BooleanLiteral(true),
            make_if(
                Expression::BooleanLiteral(false),
                make_expr_stmt(Expression::NumericLiteral(1)),
                Some(make_expr_stmt(Expression::NumericLiteral(2))),
            ),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_for_with_complex_body() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_for(
            Some(make_var_decl(
                VariableDeclarationKind::Let,
                "i",
                Some(Expression::NumericLiteral(0)),
            )),
            Some(Expression::Binary {
                operator: BinaryOperator::LessThan,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(10)),
            }),
            Some(Expression::NumericLiteral(1)),
            make_block(vec![make_expr_stmt(Expression::Call {
                callee: Box::new(Expression::Identifier("log".to_string())),
                arguments: vec![Expression::Identifier("i".to_string())],
            })]),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_try_catch_in_function() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_func_decl(
            "safe",
            &[],
            vec![make_try_catch(
                vec![make_throw(Expression::StringLiteral("oops".to_string()))],
                Some("e"),
                vec![make_expr_stmt(Expression::NumericLiteral(0))],
                Some(vec![make_expr_stmt(Expression::NumericLiteral(99))]),
            )],
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_complex_expression_tree() {
    // (a + b) * (c - d) > 0 ? "pos" : "neg"
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Conditional {
            test: Box::new(Expression::Binary {
                operator: BinaryOperator::GreaterThan,
                left: Box::new(Expression::Binary {
                    operator: BinaryOperator::Multiply,
                    left: Box::new(Expression::Binary {
                        operator: BinaryOperator::Add,
                        left: Box::new(Expression::Identifier("a".to_string())),
                        right: Box::new(Expression::Identifier("b".to_string())),
                    }),
                    right: Box::new(Expression::Binary {
                        operator: BinaryOperator::Subtract,
                        left: Box::new(Expression::Identifier("c".to_string())),
                        right: Box::new(Expression::Identifier("d".to_string())),
                    }),
                }),
                right: Box::new(Expression::NumericLiteral(0)),
            }),
            consequent: Box::new(Expression::StringLiteral("pos".to_string())),
            alternate: Box::new(Expression::StringLiteral("neg".to_string())),
        })],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_switch_with_mixed_cases() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(3)),
            ),
            make_switch(
                Expression::Identifier("x".to_string()),
                vec![
                    SwitchCase {
                        test: Some(Expression::NumericLiteral(1)),
                        consequent: vec![
                            make_expr_stmt(Expression::StringLiteral("one".to_string())),
                            Statement::Break(BreakStatement {
                                label: None,
                                span: span(),
                            }),
                        ],
                        span: span(),
                    },
                    SwitchCase {
                        test: Some(Expression::NumericLiteral(2)),
                        consequent: vec![make_expr_stmt(Expression::StringLiteral(
                            "two".to_string(),
                        ))],
                        span: span(),
                    },
                    SwitchCase {
                        test: None,
                        consequent: vec![make_expr_stmt(Expression::StringLiteral(
                            "other".to_string(),
                        ))],
                        span: span(),
                    },
                ],
            ),
        ],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

// ===========================================================================
// Section 14: Hash Discrimination — Different Syntax Families Produce Different Hashes
// ===========================================================================

#[test]
fn hash_differs_if_vs_while() {
    let cond = Expression::BooleanLiteral(true);
    let body = make_expr_stmt(Expression::NumericLiteral(1));
    let ir0_if = make_ir0(
        ParseGoal::Script,
        vec![make_if(cond.clone(), body.clone(), None)],
    );
    let ir0_while = make_ir0(ParseGoal::Script, vec![make_while(cond, body)]);
    let out_if = run_full(&ir0_if);
    let out_while = run_full(&ir0_while);
    assert_ne!(out_if.ir3.content_hash(), out_while.ir3.content_hash());
}

#[test]
fn hash_differs_while_vs_do_while() {
    let cond = Expression::BooleanLiteral(false);
    let body = make_expr_stmt(Expression::NumericLiteral(42));
    let ir0_while = make_ir0(
        ParseGoal::Script,
        vec![make_while(cond.clone(), body.clone())],
    );
    let ir0_do = make_ir0(ParseGoal::Script, vec![make_do_while(body, cond)]);
    let out_while = run_full(&ir0_while);
    let out_do = run_full(&ir0_do);
    assert_ne!(out_while.ir3.content_hash(), out_do.ir3.content_hash());
}

#[test]
fn hash_differs_add_vs_subtract() {
    let left = Box::new(Expression::NumericLiteral(10));
    let right = Box::new(Expression::NumericLiteral(5));
    let ir0_add = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Add,
            left: left.clone(),
            right: right.clone(),
        })],
    );
    let ir0_sub = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Subtract,
            left,
            right,
        })],
    );
    let out_add = run_full(&ir0_add);
    let out_sub = run_full(&ir0_sub);
    assert_ne!(out_add.ir3.content_hash(), out_sub.ir3.content_hash());
}

#[test]
fn hash_differs_return_vs_throw() {
    let val = Expression::StringLiteral("value".to_string());
    let ir0_ret = make_ir0(ParseGoal::Script, vec![make_return(Some(val.clone()))]);
    let ir0_throw = make_ir0(ParseGoal::Script, vec![make_throw(val)]);
    let out_ret = run_full(&ir0_ret);
    let out_throw = run_full(&ir0_throw);
    assert_ne!(out_ret.ir3.content_hash(), out_throw.ir3.content_hash());
}

// ===========================================================================
// Section 15: IR3 Instruction Patterns for New Ops
// ===========================================================================

#[test]
fn ir3_binary_add_produces_add_instruction() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(3)),
            right: Box::new(Expression::NumericLiteral(4)),
        })],
    );
    let output = run_full(&ir0);
    let has_add = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Add { .. }));
    assert!(has_add, "binary Add should lower to IR3 Add instruction");
}

#[test]
fn ir3_binary_subtract_produces_sub_instruction() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Subtract,
            left: Box::new(Expression::NumericLiteral(10)),
            right: Box::new(Expression::NumericLiteral(3)),
        })],
    );
    let output = run_full(&ir0);
    let has_sub = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Sub { .. }));
    assert!(
        has_sub,
        "binary Subtract should lower to IR3 Sub instruction"
    );
}

#[test]
fn ir3_binary_multiply_produces_mul_instruction() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Binary {
            operator: BinaryOperator::Multiply,
            left: Box::new(Expression::NumericLiteral(6)),
            right: Box::new(Expression::NumericLiteral(7)),
        })],
    );
    let output = run_full(&ir0);
    let has_mul = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Mul { .. }));
    assert!(
        has_mul,
        "binary Multiply should lower to IR3 Mul instruction"
    );
}

#[test]
fn ir3_if_else_produces_jump_if() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_if(
            Expression::BooleanLiteral(true),
            make_expr_stmt(Expression::NumericLiteral(1)),
            Some(make_expr_stmt(Expression::NumericLiteral(2))),
        )],
    );
    let output = run_full(&ir0);
    let has_jump_if = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::JumpIf { .. }));
    assert!(has_jump_if, "if-else should lower to IR3 JumpIf");
}

#[test]
fn ir3_while_loop_produces_jump() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_while(
            Expression::BooleanLiteral(false),
            make_expr_stmt(Expression::NumericLiteral(1)),
        )],
    );
    let output = run_full(&ir0);
    let has_jump = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Jump { .. }));
    assert!(has_jump, "while loop should lower to IR3 Jump");
}

#[test]
fn ir3_member_expression_produces_get_property() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("field".to_string())),
            computed: false,
        })],
    );
    let output = run_full(&ir0);
    let has_get_prop = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::GetProperty { .. }));
    assert!(
        has_get_prop,
        "member expression should lower to IR3 GetProperty"
    );
}

// ===========================================================================
// Section 16: Witness Invariants for New Syntax
// ===========================================================================

#[test]
fn witness_invariants_pass_for_control_flow() {
    let programs: Vec<(&str, Vec<Statement>)> = vec![
        (
            "if",
            vec![make_if(
                Expression::BooleanLiteral(true),
                make_expr_stmt(Expression::NumericLiteral(1)),
                None,
            )],
        ),
        (
            "while",
            vec![make_while(
                Expression::BooleanLiteral(false),
                make_expr_stmt(Expression::NumericLiteral(1)),
            )],
        ),
        (
            "do-while",
            vec![make_do_while(
                make_expr_stmt(Expression::NumericLiteral(1)),
                Expression::BooleanLiteral(false),
            )],
        ),
        (
            "return",
            vec![make_return(Some(Expression::NumericLiteral(0)))],
        ),
        (
            "throw",
            vec![make_throw(Expression::StringLiteral("err".to_string()))],
        ),
        (
            "try-catch",
            vec![make_try_catch(
                vec![make_expr_stmt(Expression::NumericLiteral(1))],
                Some("e"),
                vec![make_expr_stmt(Expression::NumericLiteral(2))],
                None,
            )],
        ),
    ];
    for (label, body) in programs {
        let ir0 = make_ir0(ParseGoal::Script, body);
        let output = run_full(&ir0);
        for witness in &output.witnesses {
            for check in &witness.invariant_checks {
                assert!(
                    check.passed,
                    "{label}: invariant {} failed: {}",
                    check.name, check.detail
                );
            }
        }
    }
}

#[test]
fn witness_invariants_pass_for_expressions() {
    let exprs: Vec<(&str, Expression)> = vec![
        (
            "binary_add",
            Expression::Binary {
                operator: BinaryOperator::Add,
                left: Box::new(Expression::NumericLiteral(1)),
                right: Box::new(Expression::NumericLiteral(2)),
            },
        ),
        (
            "unary_negate",
            Expression::Unary {
                operator: UnaryOperator::Negate,
                argument: Box::new(Expression::NumericLiteral(5)),
            },
        ),
        (
            "conditional",
            Expression::Conditional {
                test: Box::new(Expression::BooleanLiteral(true)),
                consequent: Box::new(Expression::NumericLiteral(1)),
                alternate: Box::new(Expression::NumericLiteral(0)),
            },
        ),
        (
            "call",
            Expression::Call {
                callee: Box::new(Expression::Identifier("f".to_string())),
                arguments: vec![Expression::NumericLiteral(1)],
            },
        ),
        (
            "member",
            Expression::Member {
                object: Box::new(Expression::Identifier("o".to_string())),
                property: Box::new(Expression::Identifier("p".to_string())),
                computed: false,
            },
        ),
        ("this", Expression::This),
        (
            "array",
            Expression::ArrayLiteral(vec![Some(Expression::NumericLiteral(1))]),
        ),
        (
            "object",
            Expression::ObjectLiteral(vec![ObjectProperty {
                key: Expression::Identifier("k".to_string()),
                value: Expression::NumericLiteral(1),
                computed: false,
                shorthand: false,
            }]),
        ),
    ];
    for (label, expr) in exprs {
        let ir0 = make_ir0(ParseGoal::Script, vec![make_expr_stmt(expr)]);
        let output = run_full(&ir0);
        for witness in &output.witnesses {
            for check in &witness.invariant_checks {
                assert!(
                    check.passed,
                    "{label}: invariant {} failed: {}",
                    check.name, check.detail
                );
            }
        }
    }
}
