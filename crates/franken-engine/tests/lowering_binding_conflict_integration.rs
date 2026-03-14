//! Integration tests for lowering-pipeline binding conflict detection (bd-1lsy.2.2).
//!
//! These tests verify the defense-in-depth layer added to `lowering_pipeline.rs`:
//!   - `alloc_binding()` now returns `Result` and checks for ES2020 binding conflicts
//!   - `check_binding_conflict()` classifies redeclaration legality
//!   - SemanticViolation variant on LoweringPipelineError
//!   - Identifier references bypass conflict detection (regression guards)
//!
//! Complement to the unit tests in `static_semantics.rs` and the existing
//! `static_semantics_integration.rs`.

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
    BindingPattern, ExportDeclaration, ExportKind, Expression, ExpressionStatement,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir1, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{
    SemanticDiagnosticCategory, SemanticError, SemanticErrorCode, SemanticValidationResult,
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

fn multi_decl(kind: VariableDeclarationKind, names: &[(&str, Option<Expression>)]) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations: names
            .iter()
            .map(|(name, init)| VariableDeclarator {
                pattern: BindingPattern::Identifier(name.to_string()),
                initializer: init.clone(),
                span: span(),
            })
            .collect(),
        span: span(),
    })
}

fn import_stmt(binding: Option<&str>, source: &str) -> Statement {
    Statement::Import(ImportDeclaration {
        binding: binding.map(ToString::to_string),
        source: source.to_string(),
        span: span(),
    })
}

fn export_default(expr: Expression) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expr),
        span: span(),
    })
}

fn export_named(name: &str) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(format!("{{ {name} }}")),
        span: span(),
    })
}

fn expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

fn lower(goal: ParseGoal, body: Vec<Statement>, label: &str) -> Result<(), LoweringPipelineError> {
    let tree = make_tree(goal, body);
    let ir0 = Ir0Module::from_syntax_tree(tree, label);
    lower_ir0_to_ir1(&ir0).map(|_| ())
}

// =========================================================================
// 1. Const-without-initializer
// =========================================================================

#[test]
fn const_without_init_single_declarator() {
    let result = lower(
        ParseGoal::Script,
        vec![var_decl(VariableDeclarationKind::Const, "c", None)],
        "const_no_init.js",
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    if let LoweringPipelineError::SemanticViolation(sem) = &err {
        assert_eq!(sem.code, SemanticErrorCode::ConstWithoutInitializer);
        assert_eq!(sem.binding_name.as_deref(), Some("c"));
    } else {
        panic!("expected SemanticViolation, got: {err}");
    }
}

#[test]
fn const_without_init_in_multi_declarator() {
    let result = lower(
        ParseGoal::Script,
        vec![multi_decl(
            VariableDeclarationKind::Const,
            &[
                ("a", Some(Expression::NumericLiteral(1))),
                ("b", None), // missing
            ],
        )],
        "const_multi_no_init.js",
    );
    assert!(result.is_err());
}

#[test]
fn const_with_init_succeeds() {
    let result = lower(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "c",
            Some(Expression::NumericLiteral(42)),
        )],
        "const_with_init.js",
    );
    assert!(result.is_ok());
}

// =========================================================================
// 2. Duplicate let/const (same scope)
// =========================================================================

#[test]
fn duplicate_let_same_scope() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "dup_let.js",
    );
    assert!(result.is_err());
    if let Err(LoweringPipelineError::SemanticViolation(sem)) = &result {
        assert_eq!(sem.code, SemanticErrorCode::DuplicateLetConstDeclaration);
    }
}

#[test]
fn duplicate_const_same_scope() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Const,
                "k",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "k",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "dup_const.js",
    );
    assert!(result.is_err());
}

#[test]
fn let_then_const_same_name() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "let_then_const.js",
    );
    assert!(result.is_err());
}

#[test]
fn const_then_let_same_name() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "const_then_let.js",
    );
    assert!(result.is_err());
}

// =========================================================================
// 3. Var redeclaration (legal)
// =========================================================================

#[test]
fn var_redeclaration_is_legal() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "var_reuse.js",
    );
    assert!(result.is_ok());
}

#[test]
fn var_triple_redeclaration_is_legal() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "v",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "v",
                Some(Expression::NumericLiteral(2)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "v",
                Some(Expression::NumericLiteral(3)),
            ),
        ],
        "var_triple.js",
    );
    assert!(result.is_ok());
}

// =========================================================================
// 4. Let/const + var collision (either direction)
// =========================================================================

#[test]
fn let_then_var_collision() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "let_var.js",
    );
    assert!(result.is_err());
    if let Err(LoweringPipelineError::SemanticViolation(sem)) = &result {
        assert_eq!(sem.code, SemanticErrorCode::LexicalConflictsWithVar);
    }
}

#[test]
fn var_then_let_collision() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "var_let.js",
    );
    assert!(result.is_err());
    if let Err(LoweringPipelineError::SemanticViolation(sem)) = &result {
        assert_eq!(sem.code, SemanticErrorCode::VarConflictsWithLexical);
    }
}

#[test]
fn const_then_var_collision() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "const_var.js",
    );
    assert!(result.is_err());
}

#[test]
fn var_then_const_collision() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "var_const.js",
    );
    assert!(result.is_err());
}

// =========================================================================
// 5. Import binding collisions
// =========================================================================

#[test]
fn duplicate_import_binding() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "alpha"),
            import_stmt(Some("x"), "beta"),
        ],
        "dup_import.mjs",
    );
    assert!(result.is_err());
    if let Err(LoweringPipelineError::SemanticViolation(sem)) = &result {
        assert_eq!(sem.code, SemanticErrorCode::DuplicateImportBinding);
    }
}

#[test]
fn import_then_let_same_name() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "mod"),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
        ],
        "import_let.mjs",
    );
    assert!(result.is_err());
}

#[test]
fn import_then_var_same_name() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "mod"),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
        ],
        "import_var.mjs",
    );
    assert!(result.is_err());
}

// =========================================================================
// 6. Identifier references bypass conflict detection (regression guards)
// =========================================================================

#[test]
fn identifier_ref_does_not_conflict_with_import() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("_"), "lodash"),
            export_default(Expression::Identifier("_".to_string())),
        ],
        "import_ref.mjs",
    );
    assert!(
        result.is_ok(),
        "referencing imported binding must not conflict: {result:?}"
    );
}

#[test]
fn identifier_ref_does_not_conflict_with_let() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            expr_stmt(Expression::Identifier("x".to_string())),
        ],
        "let_ref.js",
    );
    assert!(
        result.is_ok(),
        "referencing let binding must not conflict: {result:?}"
    );
}

#[test]
fn identifier_ref_does_not_conflict_with_var() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            expr_stmt(Expression::Identifier("x".to_string())),
        ],
        "var_ref.js",
    );
    assert!(
        result.is_ok(),
        "referencing var binding must not conflict: {result:?}"
    );
}

#[test]
fn forward_reference_before_var_declaration() {
    let result = lower(
        ParseGoal::Script,
        vec![
            expr_stmt(Expression::Identifier("x".to_string())),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
        ],
        "forward_ref.js",
    );
    assert!(
        result.is_ok(),
        "forward reference before var should succeed: {result:?}"
    );
}

#[test]
fn multiple_references_to_same_binding() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            expr_stmt(Expression::Identifier("x".to_string())),
            expr_stmt(Expression::Identifier("x".to_string())),
            expr_stmt(Expression::Identifier("x".to_string())),
        ],
        "multi_ref.js",
    );
    assert!(
        result.is_ok(),
        "multiple references to same binding should succeed"
    );
}

// =========================================================================
// 7. Multi-declarator edge cases
// =========================================================================

#[test]
fn multi_var_declarators_succeed() {
    let result = lower(
        ParseGoal::Script,
        vec![multi_decl(
            VariableDeclarationKind::Var,
            &[
                ("a", Some(Expression::NumericLiteral(1))),
                ("b", Some(Expression::NumericLiteral(2))),
                ("c", Some(Expression::NumericLiteral(3))),
            ],
        )],
        "multi_var.js",
    );
    assert!(result.is_ok());
}

#[test]
fn multi_let_declarators_distinct_names_succeed() {
    let result = lower(
        ParseGoal::Script,
        vec![multi_decl(
            VariableDeclarationKind::Let,
            &[
                ("a", Some(Expression::NumericLiteral(1))),
                ("b", Some(Expression::NumericLiteral(2))),
            ],
        )],
        "multi_let.js",
    );
    assert!(result.is_ok());
}

#[test]
fn multi_const_all_initialized_succeeds() {
    let result = lower(
        ParseGoal::Script,
        vec![multi_decl(
            VariableDeclarationKind::Const,
            &[
                ("x", Some(Expression::NumericLiteral(1))),
                ("y", Some(Expression::StringLiteral("two".to_string()))),
            ],
        )],
        "multi_const.js",
    );
    assert!(result.is_ok());
}

// =========================================================================
// 8. Full pipeline (IR0 → IR3) integration with semantic checks
// =========================================================================

#[test]
fn full_pipeline_module_succeeds() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("_"), "lodash"),
            export_default(Expression::Identifier("_".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "pipeline.mjs");
    let ctx = LoweringContext::new("trace-bc", "decision-bc", "policy-bc");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline should succeed");
    assert!(output.witnesses.len() >= 2);
    assert!(output.events.iter().all(|e| e.outcome == "pass"));
}

#[test]
fn full_pipeline_rejects_semantic_error() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "dup_let_pipeline.js");
    let ctx = LoweringContext::new("trace-err", "decision-err", "policy-err");
    let result = lower_ir0_to_ir3(&ir0, &ctx);
    assert!(result.is_err(), "duplicate let should fail before IR3");
}

#[test]
fn full_pipeline_script_with_all_literal_types() {
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
                Some(Expression::NumericLiteral(42)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::BooleanLiteral(true)),
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
    let ir0 = Ir0Module::from_syntax_tree(tree, "all_literals.js");
    let ctx = LoweringContext::new("trace-al", "decision-al", "policy-al");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("all-literal pipeline should succeed");
    assert!(output.ir3.constant_pool.contains(&"hi".to_string()));
}

// =========================================================================
// 9. SemanticErrorCode taxonomy coverage
// =========================================================================

#[test]
fn semantic_error_code_serde_roundtrip_all_variants() {
    // Exhaustive: all 22 variants via SemanticErrorCode::ALL.
    for code in &SemanticErrorCode::ALL {
        let json = serde_json::to_string(code).unwrap();
        let back: SemanticErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back, "roundtrip failed for {code:?}");
    }
}

#[test]
fn semantic_error_codes_have_distinct_display_values() {
    let displays: Vec<String> = SemanticErrorCode::ALL
        .iter()
        .map(|c| format!("{c}"))
        .collect();
    let mut sorted = displays.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        displays.len(),
        sorted.len(),
        "all display values must be distinct"
    );
}

#[test]
fn semantic_error_display_includes_diagnostic_prefix() {
    let code = SemanticErrorCode::DuplicateLetConstDeclaration;
    let display = format!("{code}");
    assert!(
        display.starts_with("FE-SEM-"),
        "expected FE-SEM- prefix, got: {display}"
    );
}

#[test]
fn semantic_error_struct_fields() {
    let err = SemanticError::new(
        SemanticErrorCode::ConstWithoutInitializer,
        Some("x".to_string()),
        Some(span()),
    );
    assert_eq!(err.code, SemanticErrorCode::ConstWithoutInitializer);
    assert_eq!(err.binding_name.as_deref(), Some("x"));
    assert!(err.span.is_some());
    // Display should be non-empty.
    assert!(!format!("{err}").is_empty());
}

#[test]
fn semantic_diagnostic_category_all_variants_distinct() {
    let categories = [
        SemanticDiagnosticCategory::Binding,
        SemanticDiagnosticCategory::Module,
        SemanticDiagnosticCategory::StrictMode,
        SemanticDiagnosticCategory::Label,
        SemanticDiagnosticCategory::ControlFlow,
        SemanticDiagnosticCategory::ContextRestriction,
    ];
    for (i, a) in categories.iter().enumerate() {
        for (j, b) in categories.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn semantic_validation_result_serde_roundtrip() {
    let result = SemanticValidationResult::new();
    let json = serde_json::to_string(&result).unwrap();
    let back: SemanticValidationResult = serde_json::from_str(&json).unwrap();
    assert!(back.errors.is_empty());
    assert!(!back.taxonomy_version.is_empty());
}

// =========================================================================
// 10. LoweringPipelineError::SemanticViolation
// =========================================================================

#[test]
fn semantic_violation_error_display() {
    let err = LoweringPipelineError::SemanticViolation(SemanticError::new(
        SemanticErrorCode::DuplicateLetConstDeclaration,
        Some("x".to_string()),
        None,
    ));
    let display = format!("{err}");
    assert!(!display.is_empty());
}

#[test]
fn semantic_violation_is_std_error() {
    let err = LoweringPipelineError::SemanticViolation(SemanticError::new(
        SemanticErrorCode::ConstWithoutInitializer,
        None,
        None,
    ));
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// 11. Named export edge cases
// =========================================================================

#[test]
fn named_export_of_declared_binding() {
    let result = lower(
        ParseGoal::Module,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(42)),
            ),
            export_named("x"),
        ],
        "named_export.mjs",
    );
    assert!(result.is_ok());
}

#[test]
fn named_export_of_undeclared_is_error() {
    let result = lower(
        ParseGoal::Module,
        vec![export_named("unknown")],
        "synth_export.mjs",
    );
    assert!(matches!(
        result,
        Err(LoweringPipelineError::SemanticViolation(sem))
            if sem.code == SemanticErrorCode::UndeclaredExportBinding
    ));
}

#[test]
fn default_export_with_string_literal() {
    let result = lower(
        ParseGoal::Module,
        vec![export_default(Expression::StringLiteral(
            "exported".to_string(),
        ))],
        "default_str_export.mjs",
    );
    assert!(result.is_ok());
}

// =========================================================================
// 12. Var hoisting with cross-references
// =========================================================================

#[test]
fn var_hoisting_forward_reference_in_initializer() {
    // `var y = x; var x = 1;` — x is referenced before declaration, legal with var.
    let tree = make_tree(
        ParseGoal::Script,
        vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("y".to_string()),
                    initializer: Some(Expression::Identifier("x".to_string())),
                    span: span(),
                },
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("x".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(),
                },
            ],
            span: span(),
        })],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "var_hoist.js");
    let result = lower_ir0_to_ir1(&ir0);
    assert!(
        result.is_ok(),
        "var hoisting forward ref should succeed: {result:?}"
    );
}

#[test]
fn mixed_imports_and_exports_with_references() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "alpha"),
            import_stmt(Some("b"), "beta"),
            expr_stmt(Expression::Identifier("a".to_string())),
            export_default(Expression::Identifier("b".to_string())),
        ],
        "mixed.mjs",
    );
    assert!(
        result.is_ok(),
        "mixed import/export/ref should succeed: {result:?}"
    );
}

// =========================================================================
// 13. SemanticValidationResult – Default impl and mutable API
// =========================================================================

#[test]
fn test_semantic_validation_result_default_equals_new() {
    let via_default = SemanticValidationResult::default();
    let via_new = SemanticValidationResult::new();
    assert_eq!(via_default, via_new);
}

#[test]
fn test_semantic_validation_result_is_valid_empty() {
    let result = SemanticValidationResult::new();
    assert!(result.is_valid());
    assert_eq!(result.error_count(), 0);
}

#[test]
fn test_semantic_validation_result_add_error_increments_count() {
    let mut result = SemanticValidationResult::new();
    assert!(result.is_valid());
    result.add_error(SemanticError::new(
        SemanticErrorCode::DuplicateLetConstDeclaration,
        Some("x".to_string()),
        None,
    ));
    assert!(!result.is_valid());
    assert_eq!(result.error_count(), 1);
    result.add_error(SemanticError::new(
        SemanticErrorCode::ConstWithoutInitializer,
        Some("y".to_string()),
        None,
    ));
    assert_eq!(result.error_count(), 2);
}

#[test]
fn test_semantic_validation_result_clone_and_eq() {
    let mut r = SemanticValidationResult::new();
    r.add_error(SemanticError::new(
        SemanticErrorCode::VarConflictsWithLexical,
        Some("z".to_string()),
        None,
    ));
    let r2 = r.clone();
    assert_eq!(r, r2);
}

// =========================================================================
// 14. SemanticError Clone/Debug/PartialEq/serde
// =========================================================================

#[test]
fn test_semantic_error_clone_eq() {
    let e = SemanticError::new(
        SemanticErrorCode::LexicalConflictsWithVar,
        Some("a".to_string()),
        Some(span()),
    );
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn test_semantic_error_debug_non_empty() {
    let e = SemanticError::new(SemanticErrorCode::DuplicateImportBinding, None, None);
    let debug = format!("{e:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("DuplicateImportBinding"));
}

#[test]
fn test_semantic_error_serde_roundtrip_with_span() {
    let e = SemanticError::new(
        SemanticErrorCode::UndeclaredExportBinding,
        Some("foo".to_string()),
        Some(span()),
    );
    let json = serde_json::to_string(&e).expect("serialize SemanticError");
    let back: SemanticError = serde_json::from_str(&json).expect("deserialize SemanticError");
    assert_eq!(e, back);
}

#[test]
fn test_semantic_error_serde_roundtrip_no_span_no_name() {
    let e = SemanticError::new(SemanticErrorCode::IllegalBreak, None, None);
    let json = serde_json::to_string(&e).unwrap();
    let back: SemanticError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// =========================================================================
// 15. SemanticErrorCode – as_str and stable_diagnostic_code coverage
// =========================================================================

#[test]
fn test_semantic_error_code_as_str_distinct() {
    let mut strs: Vec<&str> = SemanticErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    let orig_len = strs.len();
    strs.sort_unstable();
    strs.dedup();
    assert_eq!(strs.len(), orig_len, "all as_str values must be distinct");
}

#[test]
fn test_semantic_error_code_stable_diagnostic_code_all_prefixed() {
    for code in &SemanticErrorCode::ALL {
        let diag = code.stable_diagnostic_code();
        assert!(
            diag.starts_with("FE-SEM-"),
            "stable_diagnostic_code must start with FE-SEM-, got: {diag}"
        );
    }
}

#[test]
fn test_semantic_error_code_diagnostic_category_coverage() {
    // Every variant must return a valid category (no panic).
    for code in &SemanticErrorCode::ALL {
        let _ = code.diagnostic_category();
    }
}

// =========================================================================
// 16. SemanticDiagnosticCategory serde roundtrip
// =========================================================================

#[test]
fn test_semantic_diagnostic_category_serde_roundtrip() {
    let categories = [
        SemanticDiagnosticCategory::Binding,
        SemanticDiagnosticCategory::Module,
        SemanticDiagnosticCategory::StrictMode,
        SemanticDiagnosticCategory::Label,
        SemanticDiagnosticCategory::ControlFlow,
        SemanticDiagnosticCategory::ContextRestriction,
    ];
    for cat in &categories {
        let json = serde_json::to_string(cat).expect("serialize category");
        let back: SemanticDiagnosticCategory =
            serde_json::from_str(&json).expect("deserialize category");
        assert_eq!(*cat, back, "roundtrip failed for {cat:?}");
    }
}

// =========================================================================
// 17. LoweringContext serde roundtrip and Clone/Debug
// =========================================================================

#[test]
fn test_lowering_context_serde_roundtrip() {
    let ctx = LoweringContext::new("trace-1", "decision-1", "policy-1");
    let json = serde_json::to_string(&ctx).expect("serialize LoweringContext");
    let back: LoweringContext = serde_json::from_str(&json).expect("deserialize LoweringContext");
    assert_eq!(ctx, back);
}

#[test]
fn test_lowering_context_clone_debug() {
    let ctx = LoweringContext::new("t", "d", "p");
    let ctx2 = ctx.clone();
    assert_eq!(ctx, ctx2);
    let debug = format!("{ctx:?}");
    assert!(debug.contains("LoweringContext"));
}

// =========================================================================
// 18. EmptyIr0Body error path
// =========================================================================

#[test]
fn test_empty_body_is_err() {
    let tree = make_tree(ParseGoal::Script, vec![]);
    let ir0 = Ir0Module::from_syntax_tree(tree, "empty.js");
    let result = lower_ir0_to_ir1(&ir0);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        LoweringPipelineError::EmptyIr0Body
    ));
}

#[test]
fn test_empty_body_ir3_pipeline_also_fails() {
    let tree = make_tree(ParseGoal::Script, vec![]);
    let ir0 = Ir0Module::from_syntax_tree(tree, "empty3.js");
    let ctx = LoweringContext::new("t", "d", "p");
    let result = lower_ir0_to_ir3(&ir0, &ctx);
    assert!(result.is_err());
}

// =========================================================================
// 19. Binding name in error captures the correct name
// =========================================================================

#[test]
fn test_duplicate_let_error_captures_binding_name() {
    let result = lower(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "myVar",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "myVar",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        "dup_named.js",
    );
    let err = result.unwrap_err();
    if let LoweringPipelineError::SemanticViolation(sem) = err {
        assert_eq!(sem.binding_name.as_deref(), Some("myVar"));
    } else {
        panic!("expected SemanticViolation");
    }
}

#[test]
fn test_const_no_init_error_captures_binding_name() {
    let result = lower(
        ParseGoal::Script,
        vec![var_decl(VariableDeclarationKind::Const, "K", None)],
        "const_name.js",
    );
    let err = result.unwrap_err();
    if let LoweringPipelineError::SemanticViolation(sem) = err {
        assert_eq!(sem.binding_name.as_deref(), Some("K"));
    } else {
        panic!("expected SemanticViolation");
    }
}

// =========================================================================
// 20. SemanticValidationResult taxonomy_version is stable
// =========================================================================

#[test]
fn test_semantic_validation_result_taxonomy_version_stable() {
    let r = SemanticValidationResult::new();
    assert_eq!(
        r.taxonomy_version,
        "franken-engine.static-semantics.taxonomy.v1"
    );
}

// =========================================================================
// 21. Lowering error: import conflict captures correct error code
// =========================================================================

#[test]
fn test_import_then_const_same_name_is_import_error() {
    let result = lower(
        ParseGoal::Module,
        vec![
            import_stmt(Some("mod"), "source"),
            var_decl(
                VariableDeclarationKind::Const,
                "mod",
                Some(Expression::NumericLiteral(99)),
            ),
        ],
        "import_const.mjs",
    );
    assert!(result.is_err());
    if let Err(LoweringPipelineError::SemanticViolation(sem)) = result {
        assert_eq!(sem.code, SemanticErrorCode::DuplicateImportBinding);
    } else {
        panic!("expected DuplicateImportBinding");
    }
}

// =========================================================================
// 22. Multi-binding within same let declaration must not self-conflict
// =========================================================================

#[test]
fn test_multi_let_declarators_distinct_names_no_conflict() {
    // `let a = 1, b = 2, c = 3;` — all distinct, must succeed.
    let result = lower(
        ParseGoal::Script,
        vec![multi_decl(
            VariableDeclarationKind::Let,
            &[
                ("alpha", Some(Expression::NumericLiteral(1))),
                ("beta", Some(Expression::NumericLiteral(2))),
                ("gamma", Some(Expression::NumericLiteral(3))),
            ],
        )],
        "multi_let_distinct.js",
    );
    assert!(
        result.is_ok(),
        "distinct multi-let must succeed: {result:?}"
    );
}

// =========================================================================
// 23. LoweringPipelineOutput witnesses and events shape
// =========================================================================

#[test]
fn test_full_pipeline_output_witnesses_all_have_pass_id() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("React"), "react"),
            export_default(Expression::Identifier("React".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "witnesses.mjs");
    let ctx = LoweringContext::new("trace-w", "dec-w", "pol-w");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline must succeed");
    for w in &output.witnesses {
        assert!(
            !w.pass_id.is_empty(),
            "every PassWitness must have a non-empty pass_id"
        );
    }
}

#[test]
fn test_full_pipeline_events_contain_trace_id() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "PI",
            Some(Expression::NumericLiteral(3)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "events.js");
    let ctx = LoweringContext::new("my-trace-id", "my-decision", "my-policy");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline must succeed");
    for ev in &output.events {
        assert_eq!(ev.trace_id, "my-trace-id");
        assert_eq!(ev.decision_id, "my-decision");
        assert_eq!(ev.policy_id, "my-policy");
    }
}
