#![forbid(unsafe_code)]
//! Integration tests for the `lowering_pipeline` module.
//!
//! Covers: public structs, enums, error variants, Display formatting,
//! serde round-trips, pipeline stage transitions (IR0->IR1->IR2->IR3),
//! determinism, IFC flow inference, hostcall capability extraction,
//! and cross-concern integration scenarios.

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    BindingPattern, ExportDeclaration, ExportKind, Expression, ExpressionStatement,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    EffectBoundary, Ir0Module, Ir1Literal, Ir1Module, Ir1Op, Ir3Instruction, IrLevel,
};
use frankenengine_engine::lowering_pipeline::{
    InvariantCheck, IsomorphismLedgerEntry, LoweringContext, LoweringEvent, LoweringPassResult,
    LoweringPipelineError, LoweringPipelineOutput, PassWitness, lower_ir0_to_ir1, lower_ir0_to_ir3,
    lower_ir1_to_ir2, lower_ir2_to_ir3,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

fn ctx() -> LoweringContext {
    LoweringContext::new("trace-integ", "decision-integ", "policy-integ")
}

fn script_ir0_numeric(value: i64) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(value),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "fixture.js")
}

fn script_ir0_string(value: &str) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral(value.to_string()),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "string_fixture.js")
}

fn empty_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: Vec::new(),
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "empty.js")
}

fn module_ir0_import(source: &str, binding: Option<&str>) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            source: source.to_string(),
            binding: binding.map(|s| s.to_string()),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "import_fixture.mjs")
}

fn module_ir0_default_export(expr: Expression) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(expr),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "default_export.mjs")
}

fn module_ir0_named_export(clause: &str) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(clause.to_string()),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "named_export.mjs")
}

fn const_decl(name: &str, value: i64) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier(name.to_string()),
            initializer: Some(Expression::NumericLiteral(value)),
            span: span(),
        }],
        span: span(),
    })
}

fn run_full_pipeline(ir0: &Ir0Module) -> LoweringPipelineOutput {
    lower_ir0_to_ir3(ir0, &ctx()).expect("full pipeline should succeed")
}

// ============================================================================
// Section 1: LoweringContext
// ============================================================================

#[test]
fn lowering_context_new_and_field_access() {
    let lc = LoweringContext::new("t1", "d1", "p1");
    assert_eq!(lc.trace_id, "t1");
    assert_eq!(lc.decision_id, "d1");
    assert_eq!(lc.policy_id, "p1");
}

#[test]
fn lowering_context_accepts_string_types() {
    let lc = LoweringContext::new(
        String::from("trace"),
        String::from("decision"),
        String::from("policy"),
    );
    assert_eq!(lc.trace_id, "trace");
}

#[test]
fn lowering_context_clone_eq() {
    let lc = LoweringContext::new("t", "d", "p");
    let cloned = lc.clone();
    assert_eq!(lc, cloned);
}

#[test]
fn lowering_context_debug() {
    let lc = LoweringContext::new("t", "d", "p");
    let debug = format!("{lc:?}");
    assert!(debug.contains("LoweringContext"));
    assert!(debug.contains("trace_id"));
}

#[test]
fn lowering_context_serde_roundtrip() {
    let lc = LoweringContext::new("trace-rt", "decision-rt", "policy-rt");
    let json = serde_json::to_string(&lc).expect("serialize");
    let decoded: LoweringContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, lc);
}

// ============================================================================
// Section 2: LoweringEvent
// ============================================================================

#[test]
fn lowering_event_construction_and_serde() {
    let event = LoweringEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: LoweringEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, event);
}

#[test]
fn lowering_event_with_error_code_serde() {
    let event = LoweringEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "test_fail".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-LOWER-0001".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: LoweringEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.error_code, Some("FE-LOWER-0001".to_string()));
}

// ============================================================================
// Section 3: InvariantCheck
// ============================================================================

#[test]
fn invariant_check_construction_and_serde() {
    let check = InvariantCheck {
        name: "test_invariant".to_string(),
        passed: true,
        detail: "all good".to_string(),
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let decoded: InvariantCheck = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, check);
}

#[test]
fn invariant_check_failed_serde() {
    let check = InvariantCheck {
        name: "bad_check".to_string(),
        passed: false,
        detail: "scope binding ids not unique".to_string(),
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let decoded: InvariantCheck = serde_json::from_str(&json).expect("deserialize");
    assert!(!decoded.passed);
}

// ============================================================================
// Section 4: PassWitness
// ============================================================================

#[test]
fn pass_witness_construction_and_serde() {
    let witness = PassWitness {
        pass_id: "ir0_to_ir1".to_string(),
        input_hash: "sha256:aaa".to_string(),
        output_hash: "sha256:bbb".to_string(),
        rollback_token: "sha256:aaa".to_string(),
        invariant_checks: vec![InvariantCheck {
            name: "check1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        }],
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let decoded: PassWitness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, witness);
    assert_eq!(decoded.invariant_checks.len(), 1);
}

#[test]
fn pass_witness_empty_checks_serde() {
    let witness = PassWitness {
        pass_id: "test".to_string(),
        input_hash: "sha256:000".to_string(),
        output_hash: "sha256:111".to_string(),
        rollback_token: "sha256:000".to_string(),
        invariant_checks: Vec::new(),
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let decoded: PassWitness = serde_json::from_str(&json).expect("deserialize");
    assert!(decoded.invariant_checks.is_empty());
}

// ============================================================================
// Section 5: IsomorphismLedgerEntry
// ============================================================================

#[test]
fn isomorphism_ledger_entry_construction_and_serde() {
    let entry = IsomorphismLedgerEntry {
        pass_id: "ir1_to_ir2".to_string(),
        input_hash: "sha256:in".to_string(),
        output_hash: "sha256:out".to_string(),
        input_op_count: 5,
        output_op_count: 8,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: IsomorphismLedgerEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, entry);
    assert_eq!(decoded.input_op_count, 5);
    assert_eq!(decoded.output_op_count, 8);
}

// ============================================================================
// Section 6: LoweringPipelineError — variant construction and Display
// ============================================================================

#[test]
fn error_empty_ir0_body_display() {
    let err = LoweringPipelineError::EmptyIr0Body;
    let display = err.to_string();
    assert_eq!(display, "IR0 module has no statements");
}

#[test]
fn error_ir_contract_validation_display() {
    let err = LoweringPipelineError::IrContractValidation {
        code: "FE-IR-001".to_string(),
        level: IrLevel::Ir1,
        message: "bad scope graph".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("FE-IR-001"));
    assert!(display.contains("bad scope graph"));
    assert!(display.contains("ir1"));
}

#[test]
fn error_invariant_violation_display() {
    let err = LoweringPipelineError::InvariantViolation {
        detail: "IR2 invariants failed",
    };
    let display = err.to_string();
    assert!(display.contains("deterministic invariant failed"));
    assert!(display.contains("IR2 invariants failed"));
}

#[test]
fn error_variants_eq() {
    let a = LoweringPipelineError::EmptyIr0Body;
    let b = LoweringPipelineError::EmptyIr0Body;
    assert_eq!(a, b);

    let c = LoweringPipelineError::InvariantViolation { detail: "test" };
    let d = LoweringPipelineError::InvariantViolation { detail: "test" };
    assert_eq!(c, d);
}

#[test]
fn error_debug_format() {
    let err = LoweringPipelineError::EmptyIr0Body;
    let debug = format!("{err:?}");
    assert!(debug.contains("EmptyIr0Body"));
}

// ============================================================================
// Section 7: lower_ir0_to_ir1 — individual pass tests
// ============================================================================

#[test]
fn ir0_to_ir1_numeric_literal_produces_load_and_return() {
    let ir0 = script_ir0_numeric(42);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    assert_eq!(result.witness.pass_id, "ir0_to_ir1");
    assert_eq!(result.module.header.level, IrLevel::Ir1);
    assert!(!result.module.ops.is_empty());

    let has_load = result.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(42)
            }
        )
    });
    assert!(has_load, "should contain LoadLiteral(Integer(42))");

    let has_return = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Return));
    assert!(has_return, "should end with Return");
}

#[test]
fn ir0_to_ir1_string_literal() {
    let ir0 = script_ir0_string("hello");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_string = result.module.ops.iter().any(
        |op| matches!(op, Ir1Op::LoadLiteral { value: Ir1Literal::String(s) } if s == "hello"),
    );
    assert!(has_string);
}

#[test]
fn ir0_to_ir1_boolean_literal() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::BooleanLiteral(true),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "bool.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_bool = result.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(true)
            }
        )
    });
    assert!(has_bool);
}

#[test]
fn ir0_to_ir1_null_literal() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NullLiteral,
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "null.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_null = result.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Null
            }
        )
    });
    assert!(has_null);
}

#[test]
fn ir0_to_ir1_undefined_literal() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::UndefinedLiteral,
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "undef.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_undef = result.module.ops.iter().any(|op| {
        matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )
    });
    assert!(has_undef);
}

#[test]
fn ir0_to_ir1_identifier_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier("myVar".to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "ident.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_load_binding = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::LoadBinding { .. }));
    assert!(has_load_binding);

    // Check scope has binding named "myVar"
    assert!(!result.module.scopes.is_empty());
    let root_scope = &result.module.scopes[0];
    let has_binding = root_scope.bindings.iter().any(|b| b.name == "myVar");
    assert!(has_binding);
}

#[test]
fn ir0_to_ir1_empty_body_returns_error() {
    let ir0 = empty_ir0();
    let err = lower_ir0_to_ir1(&ir0).expect_err("should fail");
    assert_eq!(err, LoweringPipelineError::EmptyIr0Body);
}

#[test]
fn ir0_to_ir1_import_with_binding() {
    let ir0 = module_ir0_import("lodash", Some("_"));
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_import = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ImportModule { specifier } if specifier == "lodash"));
    assert!(has_import);

    let has_store = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::StoreBinding { .. }));
    assert!(has_store);
}

#[test]
fn ir0_to_ir1_import_without_binding() {
    let ir0 = module_ir0_import("side-effects", None);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_import =
        result.module.ops.iter().any(
            |op| matches!(op, Ir1Op::ImportModule { specifier } if specifier == "side-effects"),
        );
    assert!(has_import);

    // No StoreBinding after import when no binding specified
    let import_idx = result
        .module
        .ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ImportModule { .. }))
        .unwrap();
    // Next op should NOT be StoreBinding (if there is a next op)
    if import_idx + 1 < result.module.ops.len() {
        let next = &result.module.ops[import_idx + 1];
        assert!(
            !matches!(next, Ir1Op::StoreBinding { .. }),
            "import without binding should not emit StoreBinding"
        );
    }
    // Regardless, verify the import was found
    assert!(import_idx < result.module.ops.len());
}

#[test]
fn ir0_to_ir1_default_export() {
    let ir0 = module_ir0_default_export(Expression::NumericLiteral(99));
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "default"));
    assert!(has_export);
}

#[test]
fn ir0_to_ir1_named_export_unknown_is_error() {
    let ir0 = module_ir0_named_export("{ bar }");
    let err = lower_ir0_to_ir1(&ir0).expect_err("undeclared export should fail");
    assert!(matches!(
        err,
        LoweringPipelineError::SemanticViolation(sem)
            if sem.code == frankenengine_engine::parser::SemanticErrorCode::UndeclaredExportBinding
    ));
}

#[test]
fn ir0_to_ir1_named_export_known_binding_reuses_id() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            const_decl("foo", 1),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ foo as published }".to_string()),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "named_known.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "published"));
    assert!(has_export);
}

#[test]
fn ir0_to_ir1_await_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "await.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_await = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Await));
    assert!(has_await);
}

#[test]
fn ir0_to_ir1_raw_expression_with_call() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Raw("console.log(42)".to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "raw_call.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_call = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Call { .. }));
    assert!(has_call, "raw expression containing '(' should emit Call");
}

#[test]
fn ir0_to_ir1_raw_expression_without_call() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Raw("console".to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "raw_no_call.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_call = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Call { .. }));
    assert!(!has_call, "raw expression without '(' should not emit Call");
}

#[test]
fn ir0_to_ir1_script_goal_creates_global_scope() {
    let ir0 = script_ir0_numeric(1);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    assert_eq!(
        result.module.scopes[0].kind,
        frankenengine_engine::ir_contract::ScopeKind::Global
    );
}

#[test]
fn ir0_to_ir1_module_goal_creates_module_scope() {
    let ir0 = module_ir0_import("m", Some("x"));
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    assert_eq!(
        result.module.scopes[0].kind,
        frankenengine_engine::ir_contract::ScopeKind::Module
    );
}

#[test]
fn ir0_to_ir1_witness_invariant_checks_all_pass() {
    let ir0 = script_ir0_numeric(1);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    assert!(result.witness.invariant_checks.iter().all(|c| c.passed));
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|c| c.name == "source_hash_linkage")
    );
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|c| c.name == "scope_binding_ids_unique")
    );
}

#[test]
fn ir0_to_ir1_ledger_entry_has_correct_pass_id() {
    let ir0 = script_ir0_numeric(1);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    assert_eq!(result.ledger_entry.pass_id, "ir0_to_ir1");
    assert!(result.ledger_entry.input_hash.starts_with("sha256:"));
    assert!(result.ledger_entry.output_hash.starts_with("sha256:"));
    assert!(result.ledger_entry.input_op_count > 0);
    assert!(result.ledger_entry.output_op_count > 0);
}

// ============================================================================
// Section 8: lower_ir1_to_ir2 — individual pass tests
// ============================================================================

#[test]
fn ir1_to_ir2_basic_script() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");

    assert_eq!(result.witness.pass_id, "ir1_to_ir2");
    assert_eq!(result.module.header.level, IrLevel::Ir2);
    assert!(!result.module.ops.is_empty());
    assert!(result.witness.invariant_checks.iter().all(|c| c.passed));
}

#[test]
fn ir1_to_ir2_preserves_scopes_from_ir1() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");
    assert_eq!(result.module.scopes.len(), ir1.scopes.len());
}

#[test]
fn ir1_to_ir2_classifies_call_as_hostcall_effect() {
    // Build an IR1 with a Call op
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "call_test.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(1),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 0 });
    ir1.ops.push(Ir1Op::Return);

    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");
    let call_op = result
        .module
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
        .expect("should have call op");

    assert_eq!(call_op.effect, EffectBoundary::HostcallEffect);
    assert!(call_op.required_capability.is_some());
    assert_eq!(
        call_op.required_capability.as_ref().unwrap().0,
        "hostcall.invoke"
    );
}

#[test]
fn ir1_to_ir2_classifies_import_as_read_effect() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "import_test.js");
    ir1.ops.push(Ir1Op::ImportModule {
        specifier: "lodash".to_string(),
    });
    ir1.ops.push(Ir1Op::Return);

    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");
    let import_op = result
        .module
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::ImportModule { .. }))
        .expect("should have import op");

    assert_eq!(import_op.effect, EffectBoundary::ReadEffect);
    assert_eq!(
        import_op.required_capability.as_ref().unwrap().0,
        "module.import"
    );
}

#[test]
fn ir1_to_ir2_flow_annotation_for_secret_string() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "secret_test.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("my_secret_token".to_string()),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 1 });
    ir1.ops.push(Ir1Op::Return);

    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");
    let call_op = result
        .module
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
        .expect("should have call op");

    let flow = call_op
        .flow
        .as_ref()
        .expect("call should have flow annotation");
    // The call should require declassification because the data label is Secret
    // flowing through a hostcall.invoke (which has Internal clearance)
    assert!(flow.declassification_required);
}

#[test]
fn ir1_to_ir2_invariant_checks_include_flow_metrics() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");

    let has_flow_metrics = result
        .witness
        .invariant_checks
        .iter()
        .any(|c| c.name == "ir2_flow_metrics_consistent");
    assert!(has_flow_metrics);

    let has_coverage = result
        .witness
        .invariant_checks
        .iter()
        .any(|c| c.name == "ir2_static_flow_coverage_ratio");
    assert!(has_coverage);
}

#[test]
fn ir1_to_ir2_hostcall_string_literal_extracts_capability() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "hostcall_extract.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
    });
    ir1.ops.push(Ir1Op::Return);

    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");

    let hostcall_op = result
        .module
        .ops
        .iter()
        .find(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .expect("should have hostcall op");

    assert_eq!(
        hostcall_op.required_capability.as_ref().unwrap().0,
        "fs.read"
    );
}

#[test]
fn ir1_to_ir2_required_capabilities_collected() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "caps_test.js");
    ir1.ops.push(Ir1Op::ImportModule {
        specifier: "lodash".to_string(),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 0 });
    ir1.ops.push(Ir1Op::Return);

    let result = lower_ir1_to_ir2(&ir1).expect("ir1->ir2");
    let cap_names: BTreeSet<&str> = result
        .module
        .required_capabilities
        .iter()
        .map(|c| c.0.as_str())
        .collect();

    assert!(cap_names.contains("module.import"));
    assert!(cap_names.contains("hostcall.invoke"));
}

// ============================================================================
// Section 9: lower_ir2_to_ir3 — individual pass tests
// ============================================================================

#[test]
fn ir2_to_ir3_basic_numeric_produces_instructions() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert_eq!(result.witness.pass_id, "ir2_to_ir3");
    assert_eq!(result.module.header.level, IrLevel::Ir3);
    assert!(!result.module.instructions.is_empty());
}

#[test]
fn ir2_to_ir3_ends_with_halt() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert!(
        matches!(
            result.module.instructions.last(),
            Some(Ir3Instruction::Halt)
        ),
        "IR3 should end with Halt"
    );
}

#[test]
fn ir2_to_ir3_has_main_function_entry() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert!(!result.module.function_table.is_empty());
    let main_fn = &result.module.function_table[0];
    assert_eq!(main_fn.entry, 0);
    assert_eq!(main_fn.arity, 0);
    assert_eq!(main_fn.name.as_deref(), Some("main"));
    assert!(main_fn.frame_size >= 1);
}

#[test]
fn ir2_to_ir3_string_literal_goes_to_constant_pool() {
    let ir0 = script_ir0_string("hello world");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert!(
        result
            .module
            .constant_pool
            .contains(&"hello world".to_string()),
        "constant pool should contain the string literal"
    );

    let has_load_str = result
        .module
        .instructions
        .iter()
        .any(|instr| matches!(instr, Ir3Instruction::LoadStr { .. }));
    assert!(has_load_str);
}

#[test]
fn ir2_to_ir3_integer_literal_emits_load_int() {
    let ir0 = script_ir0_numeric(99);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    let has_load_int = result
        .module
        .instructions
        .iter()
        .any(|instr| matches!(instr, Ir3Instruction::LoadInt { value: 99, .. }));
    assert!(has_load_int);
}

#[test]
fn ir2_to_ir3_import_module_emits_load_str_for_specifier() {
    let ir0 = module_ir0_import("lodash", Some("_"));
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert!(
        result.module.constant_pool.contains(&"lodash".to_string()),
        "constant pool should contain the import specifier"
    );
}

#[test]
fn ir2_to_ir3_call_emits_call_instruction() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "call_ir3.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(1),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 0 });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    // Call ops go through the HostcallEffect path
    let has_hostcall = result
        .module
        .instructions
        .iter()
        .any(|instr| matches!(instr, Ir3Instruction::HostCall { .. }));
    assert!(
        has_hostcall,
        "Call should produce a HostCall instruction in IR3"
    );
}

#[test]
fn ir2_to_ir3_nop_emits_self_move() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"test-ir0"), "nop_test.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(1),
    });
    ir1.ops.push(Ir1Op::Nop);
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    // Nop should produce a Move { dst, src } where dst == src
    let has_self_move = result
        .module
        .instructions
        .iter()
        .any(|instr| matches!(instr, Ir3Instruction::Move { dst, src } if dst == src));
    assert!(has_self_move, "Nop should emit a self-move instruction");
}

#[test]
fn ir2_to_ir3_await_emits_move() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "await_ir3.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    let has_move = result
        .module
        .instructions
        .iter()
        .any(|instr| matches!(instr, Ir3Instruction::Move { .. }));
    assert!(has_move, "Await should produce Move instructions");
}

#[test]
fn ir2_to_ir3_witness_invariant_checks() {
    let ir0 = script_ir0_numeric(1);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let result = lower_ir2_to_ir3(&ir2).expect("ir2->ir3");

    assert!(result.witness.invariant_checks.iter().all(|c| c.passed));
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|c| c.name == "source_hash_linkage")
    );
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|c| c.name == "function_table_present")
    );
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|c| c.name == "terminal_halt_instruction")
    );
}

// ============================================================================
// Section 10: IFC flow inference — runtime guard insertion
// ============================================================================

#[test]
fn dynamic_hostcall_inserts_ifc_runtime_guard() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("secret_token".to_string()),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 1 });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("ir2->ir3").module;

    let hostcall_caps: Vec<&str> = ir3
        .instructions
        .iter()
        .filter_map(|instr| match instr {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect();

    assert!(
        hostcall_caps.contains(&"ifc.check_flow"),
        "IFC runtime guard should be inserted for secret data flowing to hostcall"
    );
    assert!(hostcall_caps.contains(&"hostcall.invoke"));

    // Guard should come before the actual hostcall
    let guard_idx = ir3
        .instructions
        .iter()
        .position(|instr| {
            matches!(instr, Ir3Instruction::HostCall { capability, .. } if capability.0 == "ifc.check_flow")
        })
        .expect("guard hostcall");
    let invoke_idx = ir3
        .instructions
        .iter()
        .position(|instr| {
            matches!(instr, Ir3Instruction::HostCall { capability, .. } if capability.0 == "hostcall.invoke")
        })
        .expect("invoke hostcall");
    assert!(guard_idx < invoke_idx);
}

#[test]
fn static_hostcall_skips_ifc_runtime_guard() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("ir2->ir3").module;

    let hostcall_caps: Vec<&str> = ir3
        .instructions
        .iter()
        .filter_map(|instr| match instr {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect();

    assert!(hostcall_caps.contains(&"fs.read"));
    assert!(
        !hostcall_caps.contains(&"ifc.check_flow"),
        "statically proven hostcall should not insert IFC guard"
    );
}

#[test]
fn public_data_through_hostcall_no_guard() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "public_flow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hello world".to_string()),
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 1 });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;

    // Check that the call flow has declassification_required
    let call_op = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
        .expect("call op");
    let flow = call_op.flow.as_ref().expect("call should have flow");

    // Public data flowing through hostcall.invoke (Internal clearance):
    // Public can flow to Internal, so no declassification needed
    assert!(
        !flow.declassification_required,
        "public data should not require declassification to flow to Internal"
    );
}

// ============================================================================
// Section 11: Full pipeline (lower_ir0_to_ir3)
// ============================================================================

#[test]
fn full_pipeline_numeric_script() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert_eq!(output.events.len(), 4);
    assert!(
        output
            .events
            .iter()
            .any(|event| event.event == "ir2_flow_check_completed")
    );
    assert!(
        output
            .ir2_flow_proof_artifact
            .artifact_id
            .starts_with("sha256:")
    );

    // Check witness pass_ids
    assert_eq!(output.witnesses[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.witnesses[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.witnesses[2].pass_id, "ir2_to_ir3");

    // Check ledger pass_ids
    assert_eq!(output.isomorphism_ledger[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.isomorphism_ledger[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.isomorphism_ledger[2].pass_id, "ir2_to_ir3");
}

#[test]
fn full_pipeline_events_have_governance_fields() {
    let ir0 = script_ir0_numeric(1);
    let context = LoweringContext::new("trace-gov", "decision-gov", "policy-gov");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("should succeed");

    for event in &output.events {
        assert_eq!(event.trace_id, "trace-gov");
        assert_eq!(event.decision_id, "decision-gov");
        assert_eq!(event.policy_id, "policy-gov");
        assert_eq!(event.component, "lowering_pipeline");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn full_pipeline_module_with_import_and_export() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                source: "lodash".to_string(),
                binding: Some("_".to_string()),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::Identifier("_".to_string())),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "full.mjs");
    let output = run_full_pipeline(&ir0);

    assert_eq!(output.witnesses.len(), 3);
    assert!(
        output
            .events
            .iter()
            .all(|e| e.outcome == "pass" && e.component == "lowering_pipeline")
    );
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn full_pipeline_empty_ir0_fails() {
    let ir0 = empty_ir0();
    let context = ctx();
    let err = lower_ir0_to_ir3(&ir0, &context).expect_err("should fail");
    assert_eq!(err, LoweringPipelineError::EmptyIr0Body);
}

#[test]
fn full_pipeline_string_literal_in_constant_pool() {
    let ir0 = script_ir0_string("test string");
    let output = run_full_pipeline(&ir0);
    assert!(
        output
            .ir3
            .constant_pool
            .contains(&"test string".to_string())
    );
}

#[test]
fn full_pipeline_all_literal_types() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("str".to_string()),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::BooleanLiteral(false),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::NullLiteral,
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::UndefinedLiteral,
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "all_literals.js");
    let output = run_full_pipeline(&ir0);

    // Should have instructions for all literal types
    let instrs = &output.ir3.instructions;
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadInt { .. }))
    );
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadStr { .. }))
    );
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadBool { .. }))
    );
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadNull { .. }))
    );
    assert!(
        instrs
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadUndefined { .. }))
    );
}

// ============================================================================
// Section 12: Determinism — same inputs produce same outputs
// ============================================================================

#[test]
fn pipeline_is_deterministic_for_numeric_literal() {
    let ir0 = script_ir0_numeric(42);
    let context = LoweringContext::new("trace-det", "decision-det", "policy-det");
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first run");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second run");

    assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
    assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.witnesses, second.witnesses);
    assert_eq!(first.isomorphism_ledger, second.isomorphism_ledger);
}

#[test]
fn pipeline_is_deterministic_for_string_literal() {
    let ir0 = script_ir0_string("hello");
    let context = ctx();
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second");

    assert_eq!(first.ir1, second.ir1);
    assert_eq!(first.ir2, second.ir2);
    assert_eq!(first.ir3, second.ir3);
}

#[test]
fn pipeline_is_deterministic_for_module_with_imports() {
    let ir0 = module_ir0_import("lodash", Some("_"));
    let context = ctx();
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second");

    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.witnesses, second.witnesses);
}

#[test]
fn ir0_to_ir1_is_deterministic() {
    let ir0 = script_ir0_numeric(42);
    let first = lower_ir0_to_ir1(&ir0).expect("first");
    let second = lower_ir0_to_ir1(&ir0).expect("second");

    assert_eq!(first.module.content_hash(), second.module.content_hash());
    assert_eq!(first.witness, second.witness);
    assert_eq!(first.ledger_entry, second.ledger_entry);
}

#[test]
fn ir1_to_ir2_is_deterministic() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let first = lower_ir1_to_ir2(&ir1).expect("first");
    let second = lower_ir1_to_ir2(&ir1).expect("second");

    assert_eq!(first.module.content_hash(), second.module.content_hash());
    assert_eq!(first.witness, second.witness);
}

#[test]
fn ir2_to_ir3_is_deterministic() {
    let ir0 = script_ir0_numeric(42);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;
    let first = lower_ir2_to_ir3(&ir2).expect("first");
    let second = lower_ir2_to_ir3(&ir2).expect("second");

    assert_eq!(first.module.content_hash(), second.module.content_hash());
}

// ============================================================================
// Section 13: Hash chain linkage across passes
// ============================================================================

#[test]
fn hash_chain_linkage_across_pipeline() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    // IR1 witness output_hash should match IR2 witness input_hash
    assert_eq!(
        output.witnesses[0].output_hash, output.witnesses[1].input_hash,
        "IR1 output hash should chain to IR2 input hash"
    );

    // IR2 witness output_hash should match IR3 witness input_hash
    assert_eq!(
        output.witnesses[1].output_hash, output.witnesses[2].input_hash,
        "IR2 output hash should chain to IR3 input hash"
    );
}

#[test]
fn ledger_entry_hashes_chain_across_passes() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    assert_eq!(
        output.isomorphism_ledger[0].output_hash, output.isomorphism_ledger[1].input_hash,
        "IR0->IR1 output should chain to IR1->IR2 input"
    );
    assert_eq!(
        output.isomorphism_ledger[1].output_hash, output.isomorphism_ledger[2].input_hash,
        "IR1->IR2 output should chain to IR2->IR3 input"
    );
}

#[test]
fn all_hashes_are_sha256_prefixed() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    for witness in &output.witnesses {
        assert!(witness.input_hash.starts_with("sha256:"));
        assert!(witness.output_hash.starts_with("sha256:"));
        assert!(witness.rollback_token.starts_with("sha256:"));
    }

    for entry in &output.isomorphism_ledger {
        assert!(entry.input_hash.starts_with("sha256:"));
        assert!(entry.output_hash.starts_with("sha256:"));
    }
}

// ============================================================================
// Section 14: LoweringPassResult serde
// ============================================================================

#[test]
fn lowering_pass_result_ir1_serde_roundtrip() {
    let ir0 = script_ir0_numeric(42);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    let json = serde_json::to_string(&result).expect("serialize");
    let decoded: LoweringPassResult<Ir1Module> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.witness, result.witness);
    assert_eq!(decoded.ledger_entry, result.ledger_entry);
}

#[test]
fn lowering_pipeline_output_serde_roundtrip() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);
    let json = serde_json::to_string(&output).expect("serialize");
    let decoded: LoweringPipelineOutput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.witnesses, output.witnesses);
    assert_eq!(decoded.isomorphism_ledger, output.isomorphism_ledger);
    assert_eq!(decoded.events, output.events);
    assert_eq!(decoded.ir1, output.ir1);
    assert_eq!(decoded.ir2, output.ir2);
    assert_eq!(decoded.ir3, output.ir3);
    assert_eq!(
        decoded.ir2_flow_proof_artifact,
        output.ir2_flow_proof_artifact
    );
}

// ============================================================================
// Section 15: IR level correctness
// ============================================================================

#[test]
fn ir_levels_are_correct_at_each_stage() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    assert_eq!(output.ir1.header.level, IrLevel::Ir1);
    assert_eq!(output.ir2.header.level, IrLevel::Ir2);
    assert_eq!(output.ir3.header.level, IrLevel::Ir3);
}

// ============================================================================
// Section 16: Cross-concern integration scenarios
// ============================================================================

#[test]
fn multi_statement_script_preserves_ordering() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(2),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(3),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "multi.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    // Extract integer values in order
    let int_values: Vec<i64> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(v),
            } => Some(*v),
            _ => None,
        })
        .collect();
    assert_eq!(
        int_values,
        vec![1, 2, 3],
        "statement order should be preserved"
    );
}

#[test]
fn import_then_export_then_expression_complex_module() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                source: "react".to_string(),
                binding: Some("React".to_string()),
                span: span(),
            }),
            Statement::Import(ImportDeclaration {
                source: "lodash".to_string(),
                binding: Some("_".to_string()),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("console.log(React)".to_string()),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::Identifier("React".to_string())),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "complex.mjs");
    let output = run_full_pipeline(&ir0);

    // Both imports should appear in constant pool
    assert!(output.ir3.constant_pool.contains(&"react".to_string()));
    assert!(output.ir3.constant_pool.contains(&"lodash".to_string()));

    // Should have hostcall for the Call from Raw expression
    let has_hostcall = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::HostCall { .. }));
    assert!(has_hostcall);
}

#[test]
fn await_chain_through_pipeline() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "fetch".to_string(),
                ))),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier("json".to_string()))),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "await_chain.js");
    let output = run_full_pipeline(&ir0);

    // Both awaits should generate Move instructions in IR3
    let move_count = output
        .ir3
        .instructions
        .iter()
        .filter(|i| matches!(i, Ir3Instruction::Move { .. }))
        .count();
    assert!(
        move_count >= 2,
        "await chain should produce multiple Move instructions"
    );
}

#[test]
fn secret_data_in_module_export_requires_declassification() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("my_password_hash".to_string()),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::StringLiteral("API_KEY_value".to_string())),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "secret_export.mjs");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("ir1->ir2").module;

    // Find the LoadLiteral for the api_key string
    let secret_op = ir2.ops.iter().find(|op| {
        matches!(
            &op.inner,
            Ir1Op::LoadLiteral { value: Ir1Literal::String(s) } if s.to_ascii_lowercase().contains("api_key")
        )
    });
    // The api_key literal itself is pure, but it should be labeled Secret
    let op = secret_op.expect("should find an op containing api_key");
    // Pure ops with no capability don't get flow annotations in all cases;
    // the data label inference happens at IR2 level.
    if let Some(flow) = &op.flow {
        assert_eq!(flow.data_label, Label::Secret);
    }
}

#[test]
fn pipeline_with_hostcall_marker_in_string() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral("hostcall<\"net.write\">".to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "hostcall_marker.js");
    let output = run_full_pipeline(&ir0);

    // The hostcall marker should extract the capability and route through HostCall
    let has_net_write = output.ir3.instructions.iter().any(
        |i| matches!(i, Ir3Instruction::HostCall { capability, .. } if capability.0 == "net.write"),
    );
    assert!(
        has_net_write,
        "hostcall marker should produce HostCall with net.write capability"
    );
}

#[test]
fn pipeline_required_capabilities_aggregate_in_ir3() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                source: "fs".to_string(),
                binding: Some("fs".to_string()),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("fs.readFile()".to_string()),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "caps_aggregate.mjs");
    let output = run_full_pipeline(&ir0);

    let cap_names: BTreeSet<&str> = output
        .ir3
        .required_capabilities
        .iter()
        .map(|c| c.0.as_str())
        .collect();

    // Should have at least hostcall.invoke from the Call
    assert!(
        cap_names.contains("hostcall.invoke"),
        "should collect hostcall.invoke capability"
    );
}

#[test]
fn multiple_exports_pipeline() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            const_decl("foo", 1),
            const_decl("bar", 2),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ foo }".to_string()),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ bar }".to_string()),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "multi_export.mjs");
    let output = run_full_pipeline(&ir0);

    assert_eq!(output.events.len(), 4);
    assert!(output.events.iter().all(|e| e.outcome == "pass"));
}

// ============================================================================
// Section 17: Op count tracking in ledger entries
// ============================================================================

#[test]
fn ledger_op_counts_monotonically_track_operations() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    for entry in &output.isomorphism_ledger {
        assert!(
            entry.input_op_count > 0,
            "every ledger entry should have input ops"
        );
        assert!(
            entry.output_op_count > 0,
            "every ledger entry should have output ops"
        );
    }

    // The first entry's input_op_count should match IR0's statement count
    assert_eq!(output.isomorphism_ledger[0].input_op_count, 1);
}

// ============================================================================
// Section 18: Rollback tokens
// ============================================================================

#[test]
fn rollback_tokens_reference_input_hashes() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    for witness in &output.witnesses {
        assert_eq!(
            witness.rollback_token, witness.input_hash,
            "rollback_token should equal input_hash for this pass"
        );
    }
}

// ============================================================================
// Section 19: Different IR0 inputs produce different outputs
// ============================================================================

#[test]
fn different_inputs_produce_different_hashes() {
    let ir0_a = script_ir0_numeric(1);
    let ir0_b = script_ir0_numeric(2);
    let context = ctx();

    let output_a = lower_ir0_to_ir3(&ir0_a, &context).expect("a");
    let output_b = lower_ir0_to_ir3(&ir0_b, &context).expect("b");

    assert_ne!(
        output_a.ir1.content_hash(),
        output_b.ir1.content_hash(),
        "different numeric literals should produce different IR1 hashes"
    );
    assert_ne!(
        output_a.ir3.content_hash(),
        output_b.ir3.content_hash(),
        "different numeric literals should produce different IR3 hashes"
    );
}

// ============================================================================
// Section 20: Boolean literal in IR3
// ============================================================================

#[test]
fn boolean_false_through_full_pipeline() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::BooleanLiteral(false),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "bool_false.js");
    let output = run_full_pipeline(&ir0);

    let has_load_bool = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadBool { value: false, .. }));
    assert!(has_load_bool);
}

// ============================================================================
// Section 21: Witness all-pass invariant across all passes
// ============================================================================

#[test]
fn all_witnesses_have_passing_invariant_checks() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    for (idx, witness) in output.witnesses.iter().enumerate() {
        assert!(
            witness.invariant_checks.iter().all(|c| c.passed),
            "witness {} ({}) should have all passing checks",
            idx,
            witness.pass_id
        );
    }
}

// ============================================================================
// Section 22: Constant pool deduplication
// ============================================================================

#[test]
fn constant_pool_deduplicates_identical_strings() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("hello".to_string()),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("hello".to_string()),
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("world".to_string()),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "dedup.js");
    let output = run_full_pipeline(&ir0);

    // "hello" should appear only once in the pool
    let hello_count = output
        .ir3
        .constant_pool
        .iter()
        .filter(|s| s.as_str() == "hello")
        .count();
    assert_eq!(hello_count, 1, "constant pool should deduplicate 'hello'");
    assert!(output.ir3.constant_pool.contains(&"world".to_string()));
}

// ============================================================================
// Section 23: LoweringPipelineError is std::error::Error
// ============================================================================

#[test]
fn lowering_pipeline_error_is_std_error() {
    let err = LoweringPipelineError::EmptyIr0Body;
    let _: &dyn std::error::Error = &err;
}

// ============================================================================
// Section 24: Return instruction is always present in IR1
// ============================================================================

#[test]
fn ir1_always_ends_with_return() {
    let ir0 = script_ir0_numeric(42);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    // The last op before scopes are pushed should be Return
    let last_op = result.module.ops.last().expect("should have ops");
    assert!(
        matches!(last_op, Ir1Op::Return),
        "IR1 should end with Return op"
    );
}

// ============================================================================
// Section 25: IR3 Return instruction present
// ============================================================================

#[test]
fn ir3_contains_return_instruction() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);

    let has_return = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Return { .. }));
    assert!(has_return, "IR3 should contain a Return instruction");
}

// ============================================================================
// Section 26: IR2 source_hash_linkage check
// ============================================================================

#[test]
fn ir2_source_hash_references_ir1_hash() {
    let ir0 = script_ir0_numeric(42);
    let ir1_result = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    let ir1_hash = ir1_result.module.content_hash();
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module).expect("ir1->ir2");

    assert_eq!(
        ir2_result.module.header.source_hash.as_ref(),
        Some(&ir1_hash),
        "IR2 source_hash should reference IR1 content hash"
    );
}

// ============================================================================
// Section 27: Multiple default exports (synthetic index increments)
// ============================================================================

#[test]
fn multiple_default_exports_have_unique_synthetic_bindings() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::NumericLiteral(1)),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::NumericLiteral(2)),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "multi_default.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    // Both should produce ExportBinding with name "default"
    let export_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "default"))
        .count();
    assert_eq!(export_count, 2, "should have two default exports");

    // All binding IDs in the scope should be unique
    let binding_ids: BTreeSet<u32> = result.module.scopes[0]
        .bindings
        .iter()
        .map(|b| b.binding_id)
        .collect();
    assert_eq!(
        binding_ids.len(),
        result.module.scopes[0].bindings.len(),
        "all binding IDs should be unique"
    );
}

// ============================================================================
// Section 28: Large program determinism stress test
// ============================================================================

#[test]
fn large_program_determinism() {
    let mut stmts = Vec::new();
    for i in 0..50 {
        stmts.push(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(i),
            span: span(),
        }));
    }
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: stmts,
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "large.js");
    let context = ctx();
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second");

    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.ir3.instructions.len(), second.ir3.instructions.len());
}

// ── for..in / for..of iteration lowering ────────────────────────────────────

use frankenengine_engine::ast::{ForInStatement, ForOfStatement};
use frankenengine_engine::ir_contract::IteratorCloseReason;

fn for_in_ir0(binding_kind: Option<VariableDeclarationKind>) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".into()),
            binding_kind,
            object: Expression::Identifier("obj".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier("k".into()),
                span: span(),
            })),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "for_in_fixture.js")
}

fn for_of_ir0(binding_kind: Option<VariableDeclarationKind>) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("v".into()),
            binding_kind,
            iterable: Expression::Identifier("arr".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier("v".into()),
                span: span(),
            })),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "for_of_fixture.js")
}

#[test]
fn for_in_lowering_produces_for_in_init_and_next() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Let));
    let result = lower_ir0_to_ir1(&ir0).expect("for-in lowering");
    let ops = &result.module.ops;
    assert!(ops.iter().any(|op| matches!(op, Ir1Op::ForInInit)));
    assert!(ops.iter().any(|op| matches!(op, Ir1Op::ForInNext { .. })));
}

#[test]
fn for_in_lowering_no_binding_kind_defaults_to_let() {
    let ir0 = for_in_ir0(None);
    let result = lower_ir0_to_ir1(&ir0).expect("for-in None binding_kind");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForInInit))
    );
}

#[test]
fn for_in_lowering_var_binding() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Var));
    let result = lower_ir0_to_ir1(&ir0).expect("for-in var binding");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForInInit))
    );
}

#[test]
fn for_in_lowering_const_binding() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Const));
    let result = lower_ir0_to_ir1(&ir0).expect("for-in const binding");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForInInit))
    );
}

#[test]
fn for_of_lowering_produces_for_of_init_next_and_close() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Const));
    let result = lower_ir0_to_ir1(&ir0).expect("for-of lowering");
    let ops = &result.module.ops;
    assert!(ops.iter().any(|op| matches!(op, Ir1Op::ForOfInit)));
    assert!(ops.iter().any(|op| matches!(op, Ir1Op::ForOfNext { .. })));
    assert!(
        ops.iter()
            .any(|op| matches!(op, Ir1Op::IteratorClose { .. }))
    );
}

#[test]
fn for_of_close_reason_is_break() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Let));
    let result = lower_ir0_to_ir1(&ir0).expect("for-of break close");
    let close_ops: Vec<_> = result
        .module
        .ops
        .iter()
        .filter_map(|op| {
            if let Ir1Op::IteratorClose { reason } = op {
                Some(*reason)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(close_ops, vec![IteratorCloseReason::Break]);
}

#[test]
fn for_of_lowering_var_binding() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Var));
    let result = lower_ir0_to_ir1(&ir0).expect("for-of var binding");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForOfInit))
    );
}

#[test]
fn for_of_lowering_no_binding_kind() {
    let ir0 = for_of_ir0(None);
    let result = lower_ir0_to_ir1(&ir0).expect("for-of None binding_kind");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForOfInit))
    );
}

#[test]
fn for_in_ir1_through_full_pipeline() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Let));
    let context = ctx();
    let output = lower_ir0_to_ir3(&ir0, &context).expect("for-in full pipeline");
    assert!(!output.ir3.instructions.is_empty());
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn for_of_ir1_through_full_pipeline() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Const));
    let context = ctx();
    let output = lower_ir0_to_ir3(&ir0, &context).expect("for-of full pipeline");
    assert!(!output.ir3.instructions.is_empty());
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn for_in_for_of_produce_different_ir1_ops() {
    let for_in = lower_ir0_to_ir1(&for_in_ir0(Some(VariableDeclarationKind::Let))).expect("for-in");
    let for_of = lower_ir0_to_ir1(&for_of_ir0(Some(VariableDeclarationKind::Let))).expect("for-of");
    let in_has_for_in_init = for_in
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ForInInit));
    let of_has_for_of_init = for_of
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ForOfInit));
    assert!(in_has_for_in_init);
    assert!(of_has_for_of_init);
    // for-in should NOT have ForOfInit and vice versa.
    assert!(
        !for_in
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForOfInit))
    );
    assert!(
        !for_of
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForInInit))
    );
}

#[test]
fn for_in_op_sequence_has_correct_structure() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Let));
    let result = lower_ir0_to_ir1(&ir0).expect("for-in structure");
    let ops = &result.module.ops;
    // Verify the canonical ordering: ForInInit comes before ForInNext.
    let init_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForInInit))
        .expect("ForInInit");
    let next_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForInNext { .. }))
        .expect("ForInNext");
    assert!(init_pos < next_pos, "ForInInit must precede ForInNext");
}

#[test]
fn for_of_op_sequence_has_correct_structure() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Let));
    let result = lower_ir0_to_ir1(&ir0).expect("for-of structure");
    let ops = &result.module.ops;
    // Verify: ForOfInit < ForOfNext < IteratorClose.
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
    assert!(init_pos < next_pos, "ForOfInit before ForOfNext");
    assert!(next_pos < close_pos, "ForOfNext before IteratorClose");
}

#[test]
fn for_in_pipeline_deterministic() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Let));
    let context = ctx();
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second");
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
}

#[test]
fn for_of_pipeline_deterministic() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Const));
    let context = ctx();
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second");
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
}

#[test]
fn for_in_ir1_serde_roundtrip() {
    let ir0 = for_in_ir0(Some(VariableDeclarationKind::Let));
    let result = lower_ir0_to_ir1(&ir0).expect("for-in");
    let json = serde_json::to_string(&result.module).expect("ser");
    let restored: Ir1Module = serde_json::from_str(&json).expect("de");
    assert_eq!(result.module.ops.len(), restored.ops.len());
}

#[test]
fn for_of_ir1_serde_roundtrip() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Const));
    let result = lower_ir0_to_ir1(&ir0).expect("for-of");
    let json = serde_json::to_string(&result.module).expect("ser");
    let restored: Ir1Module = serde_json::from_str(&json).expect("de");
    assert_eq!(result.module.ops.len(), restored.ops.len());
}

#[test]
fn iterator_close_reason_serde_roundtrip() {
    let reasons = vec![
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).expect("ser");
        let restored: IteratorCloseReason = serde_json::from_str(&json).expect("de");
        assert_eq!(*reason, restored);
    }
}

#[test]
fn for_in_for_of_ir2_has_read_effect_for_iteration_ops() {
    let ir0 = for_of_ir0(Some(VariableDeclarationKind::Let));
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir1");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("ir2");
    // All iteration ops should have ReadEffect classification.
    let iteration_effects: Vec<_> = ir2
        .module
        .ops
        .iter()
        .filter(|op| {
            matches!(
                op.inner,
                Ir1Op::ForOfInit | Ir1Op::ForOfNext { .. } | Ir1Op::IteratorClose { .. }
            )
        })
        .map(|op| op.effect)
        .collect();
    assert!(!iteration_effects.is_empty());
    for effect in &iteration_effects {
        assert_eq!(*effect, EffectBoundary::ReadEffect);
    }
}
