//! Integration tests for lexical environment semantics (bd-1lsy.4.2).
//!
//! Tests cross-module interaction between:
//!   - `closure_model::ScopeChain` (runtime lexical environments)
//!   - `lowering_pipeline` (IR0 → IR3 with scope/binding resolution)
//!   - `baseline_interpreter` (IR3 execution with register machine)
//!   - `ir_contract` (scope/binding IR types)
//!
//! Coverage:
//!   - TDZ enforcement through the eval pipeline (let/const semantics)
//!   - Var hoisting vs let/const block scoping
//!   - Scope chain lifecycle with nested environments
//!   - Closure capture resolution
//!   - IFC label propagation through lexical environments
//!   - Binding kind resolution across pipeline stages
//!   - ScopeChain determinism and serde roundtrips
//!   - InterpreterCore interaction with scope-resolved bindings
//!   - Error propagation: TDZ, const assignment, duplicate bindings

#![forbid(unsafe_code)]
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
    BindingPattern, Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::baseline_interpreter::{LaneChoice, LaneRouter};
use frankenengine_engine::closure_model::{
    BindingSlot, Closure, ClosureCapture, ClosureHandle, ClosureStore, EnvValue, EnvironmentHandle,
    EnvironmentKind, EnvironmentRecord, ScopeChain, ScopeError,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    BindingId, BindingKind, Ir0Module, Ir3Instruction, ScopeId, ScopeKind,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

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

fn sid(depth: u32, index: u32) -> ScopeId {
    ScopeId { depth, index }
}

fn lowering_ctx(label: &str) -> LoweringContext {
    LoweringContext::new(
        format!("trace-{label}"),
        format!("decision-{label}"),
        format!("policy-{label}"),
    )
}

// =========================================================================
// Section 1: TDZ enforcement — let/const through the lowering pipeline
// =========================================================================

#[test]
fn let_declaration_creates_binding_in_ir1() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "let-decl.js");
    let ctx = lowering_ctx("let-decl");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    // IR1 should have at least one binding with kind Let
    assert!(
        output
            .ir1
            .scopes
            .iter()
            .flat_map(|s| s.bindings.iter())
            .any(|b| b.kind == BindingKind::Let),
        "IR1 must contain a Let binding"
    );
}

#[test]
fn const_declaration_creates_const_binding_in_ir1() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "PI",
            Some(Expression::NumericLiteral(3_141_593)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "const-decl.js");
    let ctx = lowering_ctx("const-decl");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    assert!(
        output
            .ir1
            .scopes
            .iter()
            .flat_map(|s| s.bindings.iter())
            .any(|b| b.kind == BindingKind::Const),
        "IR1 must contain a Const binding"
    );
}

#[test]
fn var_declaration_creates_var_binding_in_ir1() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Var,
            "count",
            Some(Expression::NumericLiteral(0)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "var-decl.js");
    let ctx = lowering_ctx("var-decl");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    assert!(
        output
            .ir1
            .scopes
            .iter()
            .flat_map(|s| s.bindings.iter())
            .any(|b| b.kind == BindingKind::Var),
        "IR1 must contain a Var binding"
    );
}

#[test]
fn let_and_var_coexist_in_ir1() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "let-var.js");
    let ctx = lowering_ctx("let-var");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let has_var = output
        .ir1
        .scopes
        .iter()
        .flat_map(|s| s.bindings.iter())
        .any(|b| b.kind == BindingKind::Var);
    let has_let = output
        .ir1
        .scopes
        .iter()
        .flat_map(|s| s.bindings.iter())
        .any(|b| b.kind == BindingKind::Let);
    assert!(has_var && has_let, "must have both Var and Let bindings");
}

#[test]
fn binding_names_preserved_through_lowering() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "alpha",
                Some(Expression::StringLiteral("hello".to_string())),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "beta",
                Some(Expression::BooleanLiteral(true)),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "names.js");
    let ctx = lowering_ctx("names");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let names: Vec<&str> = output
        .ir1
        .scopes
        .iter()
        .flat_map(|s| s.bindings.iter())
        .map(|b| b.name.as_str())
        .collect();
    assert!(names.contains(&"alpha"), "binding 'alpha' must be present");
    assert!(names.contains(&"beta"), "binding 'beta' must be present");
}

// =========================================================================
// Section 2: ScopeChain + BindingKind interaction
// =========================================================================

#[test]
fn scope_chain_var_hoists_to_function_scope() {
    let mut chain = ScopeChain::new();
    // Push a function scope
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    // Push a block scope inside the function
    chain.push_scope(sid(2, 0), ScopeKind::Block);

    // Declare var in block scope — should hoist to function scope
    chain.declare_var("x".to_string(), 1).unwrap();

    // Pop block scope
    chain.pop_scope().unwrap();

    // Variable should still be accessible in function scope
    let result = chain.get_value("x");
    assert!(
        result.is_ok(),
        "var should be visible after block scope pop"
    );
}

#[test]
fn scope_chain_let_does_not_hoist_out_of_block() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.push_scope(sid(2, 0), ScopeKind::Block);

    chain.declare_let("y".to_string(), 2).unwrap();
    chain
        .initialize_binding("y", EnvValue::Number(7_000_000), Label::Public)
        .unwrap();

    // Let is visible inside block after initialization
    let result_in_block = chain.get_value("y");
    assert!(
        result_in_block.is_ok(),
        "let should be visible in block scope"
    );

    chain.pop_scope().unwrap();

    // Let should not be visible after block scope pop
    let result_after_pop = chain.get_value("y");
    assert!(
        result_after_pop.is_err(),
        "let should NOT be visible after block scope pop"
    );
}

#[test]
fn scope_chain_const_binding_tdz_before_init() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    chain.declare_const("PI".to_string(), 3).unwrap();

    // Before initialization, get_value should return TDZ error
    let result = chain.get_value("PI");
    assert!(
        matches!(result, Err(ScopeError::TemporalDeadZone { .. })),
        "const before init should be TDZ: {result:?}"
    );

    // Initialize the binding
    chain
        .initialize_binding("PI", EnvValue::Number(3_141_593), Label::Public)
        .unwrap();

    // After initialization, should be accessible
    let val = chain.get_value("PI").unwrap();
    assert_eq!(*val, EnvValue::Number(3_141_593));
}

#[test]
fn scope_chain_const_rejects_assignment_after_init() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    chain.declare_const("CONST_VAL".to_string(), 4).unwrap();
    chain
        .initialize_binding("CONST_VAL", EnvValue::Number(42_000_000), Label::Public)
        .unwrap();

    // Assignment to const should fail
    let result = chain.set_value("CONST_VAL", EnvValue::Number(99_000_000), Label::Public);
    assert!(
        matches!(result, Err(ScopeError::ConstAssignment { .. })),
        "const assignment should fail: {result:?}"
    );
}

#[test]
fn scope_chain_let_tdz_before_init() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    chain.declare_let("x".to_string(), 5).unwrap();

    // Before initialization, get_value should return TDZ error
    let result = chain.get_value("x");
    assert!(
        matches!(result, Err(ScopeError::TemporalDeadZone { .. })),
        "let before init should be TDZ"
    );
}

#[test]
fn scope_chain_let_allows_assignment_after_init() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    chain.declare_let("x".to_string(), 6).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(10_000_000), Label::Public)
        .unwrap();

    // Assignment to let should succeed
    chain
        .set_value("x", EnvValue::Number(20_000_000), Label::Public)
        .unwrap();
    let val = chain.get_value("x").unwrap();
    assert_eq!(*val, EnvValue::Number(20_000_000));
}

// =========================================================================
// Section 3: Closure capture and free variable resolution
// =========================================================================

#[test]
fn compute_captures_resolves_outer_bindings() {
    let mut chain = ScopeChain::new();
    // Outer function scope with variable "outer_x"
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("outer_x".to_string(), 10).unwrap();
    chain
        .initialize_binding("outer_x", EnvValue::Number(42_000_000), Label::Public)
        .unwrap();

    // Inner function scope that references "outer_x"
    chain.push_scope(sid(2, 0), ScopeKind::Function);

    let captures = chain
        .compute_captures(&["outer_x".to_string()])
        .expect("capture should succeed");
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].name, "outer_x");
    assert_eq!(captures[0].binding_id, 10);
}

#[test]
fn compute_captures_multiple_free_vars() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    chain.declare_let("a".to_string(), 20).unwrap();
    chain
        .initialize_binding("a", EnvValue::Number(1_000_000), Label::Public)
        .unwrap();
    chain.declare_var("b".to_string(), 21).unwrap();
    chain.declare_const("c".to_string(), 22).unwrap();
    chain
        .initialize_binding("c", EnvValue::Str("hello".to_string()), Label::Public)
        .unwrap();

    chain.push_scope(sid(2, 0), ScopeKind::Function);

    let captures = chain
        .compute_captures(&["a".to_string(), "b".to_string(), "c".to_string()])
        .expect("captures should succeed");
    assert_eq!(captures.len(), 3);

    let names: Vec<&str> = captures.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    assert!(names.contains(&"c"));
}

#[test]
fn compute_captures_fails_for_undeclared_variable() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    let result = chain.compute_captures(&["nonexistent".to_string()]);
    assert!(result.is_err(), "capture of undeclared var should fail");
}

#[test]
fn closure_creation_preserves_captures() {
    let capture = ClosureCapture {
        name: "x".to_string(),
        binding_id: 42,
        source_scope: sid(1, 0),
        label: Label::Public,
    };
    let closure = Closure {
        handle: ClosureHandle(0),
        name: "myFunc".to_string(),
        arity: 1,
        strict: true,
        captures: vec![capture.clone()],
        max_capture_label: Label::Public,
        creation_env: EnvironmentHandle(0),
    };

    assert_eq!(closure.captures.len(), 1);
    assert_eq!(closure.captures[0].name, "x");
    assert_eq!(closure.captures[0].binding_id, 42);
    assert!(closure.strict);
    assert_eq!(closure.arity, 1);
}

// =========================================================================
// Section 4: ClosureStore management
// =========================================================================

#[test]
fn closure_store_create_and_retrieve() {
    let mut store = ClosureStore::new();
    let handle = store.create_closure("f".to_string(), 0, false, vec![], EnvironmentHandle(0));
    let retrieved = store.get(handle).expect("should retrieve closure");
    assert_eq!(retrieved.name, "f");
}

#[test]
fn closure_store_multiple_closures() {
    let mut store = ClosureStore::new();
    let h1 = store.create_closure("f1".to_string(), 0, false, vec![], EnvironmentHandle(0));
    let h2 = store.create_closure("f2".to_string(), 2, true, vec![], EnvironmentHandle(1));

    assert_ne!(h1, h2);
    assert_eq!(store.get(h1).unwrap().name, "f1");
    assert_eq!(store.get(h2).unwrap().name, "f2");
    assert_eq!(store.get(h2).unwrap().arity, 2);
}

// =========================================================================
// Section 5: IFC label propagation through environments
// =========================================================================

#[test]
fn binding_slot_default_label_is_public() {
    let slot = BindingSlot::new_lexical("x".to_string(), 1, BindingKind::Let);
    assert_eq!(slot.label, Label::Public);
}

#[test]
fn capture_carries_source_label() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("secret".to_string(), 30).unwrap();
    chain
        .initialize_binding(
            "secret",
            EnvValue::Str("classified".to_string()),
            Label::Public,
        )
        .unwrap();

    chain.push_scope(sid(2, 0), ScopeKind::Function);
    let captures = chain.compute_captures(&["secret".to_string()]).unwrap();

    // Default label is Public; IFC checks would upgrade this in production
    assert_eq!(captures[0].label, Label::Public);
}

// =========================================================================
// Section 6: Nested scope chain lifecycle
// =========================================================================

#[test]
fn nested_scopes_three_deep() {
    let mut chain = ScopeChain::new();
    // Global already has depth 1
    assert_eq!(chain.depth(), 1);

    chain.push_scope(sid(1, 0), ScopeKind::Function);
    assert_eq!(chain.depth(), 2);
    chain.declare_var("a".to_string(), 40).unwrap();

    chain.push_scope(sid(2, 0), ScopeKind::Block);
    assert_eq!(chain.depth(), 3);
    chain.declare_let("b".to_string(), 41).unwrap();
    chain
        .initialize_binding("b", EnvValue::Number(2_000_000), Label::Public)
        .unwrap();

    chain.push_scope(sid(3, 0), ScopeKind::Block);
    assert_eq!(chain.depth(), 4);
    chain.declare_let("c".to_string(), 42).unwrap();
    chain
        .initialize_binding("c", EnvValue::Number(3_000_000), Label::Public)
        .unwrap();

    // All three are visible from innermost scope
    assert!(chain.get_value("a").is_ok());
    assert_eq!(*chain.get_value("b").unwrap(), EnvValue::Number(2_000_000));
    assert_eq!(*chain.get_value("c").unwrap(), EnvValue::Number(3_000_000));

    // Pop innermost
    chain.pop_scope().unwrap();
    assert_eq!(chain.depth(), 3);
    assert!(chain.get_value("a").is_ok());
    assert!(chain.get_value("b").is_ok());
    assert!(chain.get_value("c").is_err(), "c should be gone");

    // Pop block
    chain.pop_scope().unwrap();
    assert_eq!(chain.depth(), 2);
    assert!(chain.get_value("a").is_ok(), "var should survive block pop");
    assert!(chain.get_value("b").is_err(), "let b should be gone");
}

#[test]
fn scope_chain_cannot_pop_global() {
    let mut chain = ScopeChain::new();
    // Global scope should not be poppable
    let result = chain.pop_scope();
    assert!(result.is_err(), "should not pop global scope");
}

#[test]
fn scope_chain_push_pop_roundtrip() {
    let mut chain = ScopeChain::new();
    let initial_depth = chain.depth();

    for i in 0..10u32 {
        chain.push_scope(sid(i + 1, 0), ScopeKind::Block);
    }
    assert_eq!(chain.depth(), initial_depth + 10);

    for _ in 0..10 {
        chain.pop_scope().unwrap();
    }
    assert_eq!(chain.depth(), initial_depth);
}

// =========================================================================
// Section 7: Binding kind resolution in lowered output
// =========================================================================

#[test]
fn all_three_binding_kinds_in_single_program() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "v",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "l",
                Some(Expression::NumericLiteral(2)),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::NumericLiteral(3)),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "all-kinds.js");
    let ctx = lowering_ctx("all-kinds");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let kinds: Vec<BindingKind> = output
        .ir1
        .scopes
        .iter()
        .flat_map(|s| s.bindings.iter())
        .map(|b| b.kind)
        .collect();
    assert!(kinds.contains(&BindingKind::Var), "must have Var");
    assert!(kinds.contains(&BindingKind::Let), "must have Let");
    assert!(kinds.contains(&BindingKind::Const), "must have Const");
}

#[test]
fn binding_ids_are_unique() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "c",
                Some(Expression::NumericLiteral(3)),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "unique-ids.js");
    let ctx = lowering_ctx("unique-ids");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let ids: Vec<BindingId> = output
        .ir1
        .scopes
        .iter()
        .flat_map(|s| s.bindings.iter())
        .map(|b| b.binding_id)
        .collect();
    let unique_count = {
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        sorted.len()
    };
    assert_eq!(ids.len(), unique_count, "all binding IDs must be unique");
}

// =========================================================================
// Section 8: IR3 execution preserves let/const/var initialization semantics
// =========================================================================

#[test]
fn ir3_execution_of_let_declaration_succeeds() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "let-exec.js");
    let ctx = lowering_ctx("let-exec");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-let-exec", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_const_declaration_succeeds() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "MAX",
            Some(Expression::NumericLiteral(100)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "const-exec.js");
    let ctx = lowering_ctx("const-exec");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-const-exec", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_mixed_declarations() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "v",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "l",
                Some(Expression::StringLiteral("hello".to_string())),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::BooleanLiteral(false)),
            ),
            expr_stmt(Expression::Identifier("v".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "mixed-exec.js");
    let ctx = lowering_ctx("mixed-exec");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-mixed", Some(LaneChoice::V8))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

// =========================================================================
// Section 9: Environment record construction and query
// =========================================================================

#[test]
fn environment_record_new_has_correct_defaults() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(env.bindings.is_empty());
    assert_eq!(env.scope_kind, ScopeKind::Global);
    assert_eq!(env.env_kind, EnvironmentKind::Global);
    assert_eq!(env.max_label, Label::Public);
}

#[test]
fn environment_record_add_and_get_binding() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(1),
        sid(1, 0),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    let slot = BindingSlot::new_hoisted("x".to_string(), 1, BindingKind::Var);
    env.add_binding(slot);

    let retrieved = env.get_binding("x");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "x");
    assert!(
        retrieved.unwrap().initialized,
        "hoisted should be initialized"
    );
}

#[test]
fn environment_record_function_is_var_scope() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(2),
        sid(1, 0),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    assert!(env.is_var_scope(), "function scope should be var scope");
}

#[test]
fn environment_record_block_is_not_var_scope() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(3),
        sid(2, 0),
        ScopeKind::Block,
        EnvironmentKind::Declarative,
    );
    assert!(!env.is_var_scope(), "block scope should not be var scope");
}

// =========================================================================
// Section 10: ScopeChain determinism
// =========================================================================

#[test]
fn scope_chain_operations_are_deterministic() {
    // Build the same chain twice and compare results
    let build = || {
        let mut chain = ScopeChain::new();
        chain.push_scope(sid(1, 0), ScopeKind::Function);
        chain.declare_let("x".to_string(), 1).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(42_000_000), Label::Public)
            .unwrap();
        chain.declare_var("y".to_string(), 2).unwrap();
        chain.push_scope(sid(2, 0), ScopeKind::Block);
        chain.declare_const("z".to_string(), 3).unwrap();
        chain
            .initialize_binding("z", EnvValue::Str("hello".to_string()), Label::Public)
            .unwrap();
        chain
    };

    let chain1 = build();
    let chain2 = build();

    // Same values at the same points
    assert_eq!(
        chain1.get_value("x").unwrap(),
        chain2.get_value("x").unwrap()
    );
    assert_eq!(
        chain1.get_value("z").unwrap(),
        chain2.get_value("z").unwrap()
    );
    assert_eq!(chain1.depth(), chain2.depth());
}

#[test]
fn lowering_pipeline_determinism_for_binding_resolution() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "b",
                Some(Expression::StringLiteral("test".to_string())),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "determ.js");
    let ctx = lowering_ctx("determ");

    let out1 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 1");
    let out2 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 2");

    // Binding resolution should be deterministic
    let bindings1: Vec<_> = out1.ir1.scopes.iter().flat_map(|s| &s.bindings).collect();
    let bindings2: Vec<_> = out2.ir1.scopes.iter().flat_map(|s| &s.bindings).collect();
    assert_eq!(bindings1.len(), bindings2.len());
    for (b1, b2) in bindings1.iter().zip(bindings2.iter()) {
        assert_eq!(b1.name, b2.name);
        assert_eq!(b1.kind, b2.kind);
        assert_eq!(b1.binding_id, b2.binding_id);
    }
}

// =========================================================================
// Section 11: Serde roundtrips for closure model types
// =========================================================================

#[test]
fn env_value_serde_roundtrip() {
    let values = vec![
        EnvValue::Undefined,
        EnvValue::Null,
        EnvValue::Bool(true),
        EnvValue::Number(42_000_000),
        EnvValue::Str("hello".to_string()),
        EnvValue::ObjectRef(99),
        EnvValue::ClosureRef(ClosureHandle(7)),
        EnvValue::Tdz,
    ];
    for val in &values {
        let json = serde_json::to_string(val).unwrap();
        let back: EnvValue = serde_json::from_str(&json).unwrap();
        assert_eq!(*val, back, "roundtrip failed for {val}");
    }
}

#[test]
fn binding_slot_serde_roundtrip() {
    let slot = BindingSlot::new_lexical("x".to_string(), 1, BindingKind::Let);
    let json = serde_json::to_string(&slot).unwrap();
    let back: BindingSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, back);
}

#[test]
fn closure_capture_serde_roundtrip() {
    let cap = ClosureCapture {
        name: "captured".to_string(),
        binding_id: 42,
        source_scope: sid(1, 0),
        label: Label::Public,
    };
    let json = serde_json::to_string(&cap).unwrap();
    let back: ClosureCapture = serde_json::from_str(&json).unwrap();
    assert_eq!(cap, back);
}

#[test]
fn closure_serde_roundtrip() {
    let closure = Closure {
        handle: ClosureHandle(5),
        name: "myFunc".to_string(),
        arity: 2,
        strict: true,
        captures: vec![ClosureCapture {
            name: "outer".to_string(),
            binding_id: 10,
            source_scope: sid(1, 0),
            label: Label::Public,
        }],
        max_capture_label: Label::Public,
        creation_env: EnvironmentHandle(3),
    };
    let json = serde_json::to_string(&closure).unwrap();
    let back: Closure = serde_json::from_str(&json).unwrap();
    assert_eq!(closure, back);
}

// =========================================================================
// Section 12: Display impls
// =========================================================================

#[test]
fn env_value_display_is_meaningful() {
    assert_eq!(EnvValue::Undefined.to_string(), "undefined");
    assert_eq!(EnvValue::Null.to_string(), "null");
    assert_eq!(EnvValue::Bool(true).to_string(), "true");
    assert_eq!(EnvValue::Number(42).to_string(), "42");
    assert_eq!(EnvValue::Str("hi".to_string()).to_string(), "\"hi\"");
    assert_eq!(EnvValue::Tdz.to_string(), "<TDZ>");
}

#[test]
fn scope_error_display_is_non_empty() {
    let errors = vec![
        ScopeError::TemporalDeadZone {
            name: "x".to_string(),
        },
        ScopeError::ConstAssignment {
            name: "PI".to_string(),
        },
        ScopeError::UndeclaredVariable {
            name: "z".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "display should be non-empty for {err:?}");
    }
}

// =========================================================================
// Section 13: Scope kind and environment kind coverage
// =========================================================================

#[test]
fn all_scope_kinds_can_be_pushed() {
    let mut chain = ScopeChain::new();
    let kinds = [
        ScopeKind::Function,
        ScopeKind::Block,
        ScopeKind::Catch,
        ScopeKind::Module,
    ];
    for (i, &kind) in kinds.iter().enumerate() {
        chain.push_scope(sid(i as u32 + 1, 0), kind);
    }
    assert_eq!(chain.depth(), 1 + kinds.len());
}

#[test]
fn environment_kind_serde_roundtrip() {
    let kinds = [
        EnvironmentKind::Declarative,
        EnvironmentKind::Object,
        EnvironmentKind::Global,
        EnvironmentKind::Module,
        EnvironmentKind::Function,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: EnvironmentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// =========================================================================
// Section 14: IR3 Halt instruction at end of lowered output
// =========================================================================

#[test]
fn lowered_let_program_terminates_with_halt() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "z",
            Some(Expression::BooleanLiteral(true)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "halt-let.js");
    let ctx = lowering_ctx("halt-let");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    assert!(
        matches!(output.ir3.instructions.last(), Some(Ir3Instruction::Halt)),
        "IR3 must terminate with Halt"
    );
}

// =========================================================================
// Section 15: Two-lane parity for let/const programs
// =========================================================================

#[test]
fn quickjs_v8_parity_for_let_declarations() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(42)),
            ),
            expr_stmt(Expression::Identifier("x".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "parity-let.js");
    let ctx = lowering_ctx("parity-let");
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
        "both lanes should produce same value for let program"
    );
}
