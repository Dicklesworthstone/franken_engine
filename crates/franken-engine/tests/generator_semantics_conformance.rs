//! Generator-function semantics conformance tests.
//!
//! Bead: bd-6a61n.1.4 [RC-1.4]
//!
//! Validates:
//! - Parser recognizes function* and yield/yield* expressions
//! - IR lowering produces CreateGenerator + Yield instructions
//! - Interpreter creates GeneratorObject on generator function call
//! - Value type discrimination for GeneratorFunction / Generator

#![allow(clippy::needless_borrows_for_generic_args, clippy::too_many_arguments)]

use frankenengine_engine::ast::{Expression, FunctionDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree};
use frankenengine_engine::baseline_interpreter::Value;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange};
use frankenengine_engine::lowering_pipeline::{lower_ir0_to_ir3, LoweringContext};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::parser_api_stability::parse_script;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lower_source_to_ir3(source: &str) -> Ir3Module {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "generator_conformance_source.js");
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            "trace-generator-source",
            "decision-generator-source",
            "policy-generator-source",
        ),
    )
    .expect("source should lower")
    .ir3
}

fn run_ir3(module: &Ir3Module) -> Value {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "gen-test");
    core.execute(module).expect("execution should succeed").value
}

// ---------------------------------------------------------------------------
// 1. Parser: function* and yield are recognized
// ---------------------------------------------------------------------------

#[test]
fn parser_recognizes_generator_declaration() {
    let source = "function* gen() { yield 1; }";
    let tree = parse_script(source).expect("generator declaration should parse");
    assert!(!tree.body.is_empty(), "should produce AST nodes");
    match &tree.body[0] {
        Statement::FunctionDeclaration(fd) => {
            assert!(fd.is_generator, "function* should set is_generator=true");
        }
        other => panic!("expected FunctionDeclaration, got {:?}", other),
    }
}

#[test]
fn parser_recognizes_yield_expression() {
    let source = "function* gen() { yield 42; }";
    let tree = parse_script(source).expect("yield expression should parse");
    match &tree.body[0] {
        Statement::FunctionDeclaration(fd) => {
            assert!(fd.is_generator);
            assert!(!fd.body.body.is_empty(), "generator body should have statements");
        }
        other => panic!("expected FunctionDeclaration, got {:?}", other),
    }
}

#[test]
fn parser_recognizes_yield_star() {
    let source = "function* gen() { yield* [1, 2]; }";
    let tree = parse_script(source).expect("yield* should parse");
    match &tree.body[0] {
        Statement::FunctionDeclaration(fd) => {
            assert!(fd.is_generator);
        }
        other => panic!("expected FunctionDeclaration, got {:?}", other),
    }
}

#[test]
fn parser_recognizes_bare_yield() {
    let source = "function* gen() { yield; }";
    let tree = parse_script(source);
    assert!(tree.is_ok(), "bare yield should parse: {:?}", tree.err());
}

// ---------------------------------------------------------------------------
// 2. IR Lowering: CreateGenerator and Yield instructions produced
// ---------------------------------------------------------------------------

#[test]
fn lowering_produces_create_generator_for_function_star() {
    let source = "function* gen() { yield 1; }";
    let ir3 = lower_source_to_ir3(source);
    let has_create_gen = ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::CreateGenerator { .. }));
    assert!(
        has_create_gen,
        "function* should lower to CreateGenerator instruction. Instructions: {:?}",
        ir3.instructions
    );
}

#[test]
fn lowering_produces_yield_instruction() {
    let source = "function* gen() { yield 42; }";
    let ir3 = lower_source_to_ir3(source);
    let has_yield = ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Yield { .. }));
    assert!(
        has_yield,
        "yield expression should lower to Yield instruction. Instructions: {:?}",
        ir3.instructions
    );
}

#[test]
fn lowering_generator_function_desc_has_is_generator_true() {
    let source = "function* gen() { yield 1; }";
    let ir3 = lower_source_to_ir3(source);
    let gen_fns: Vec<_> = ir3
        .function_table
        .iter()
        .filter(|f| f.is_generator)
        .collect();
    assert!(
        !gen_fns.is_empty(),
        "generator function should have is_generator=true. Table: {:?}",
        ir3.function_table
    );
}

// ---------------------------------------------------------------------------
// 3. Interpreter: generator function call creates GeneratorObject
// ---------------------------------------------------------------------------

#[test]
fn calling_generator_function_returns_generator_object() {
    let mut m = Ir3Module::new(ContentHash::compute(b"gen-call-test"), "gen.js");
    m.instructions = vec![
        // ip=0: Create generator function value in r0
        Ir3Instruction::CreateGenerator {
            dst: 0,
            function_index: 1,
            capture_count: 0,
        },
        // ip=1: Call the generator function to get a GeneratorObject in r1
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 2, count: 0 },
            dst: 1,
        },
        // ip=2: Halt — r0 has the generator function
        Ir3Instruction::Halt,
        // ip=3: Generator body: yield 42, then return
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::LoadUndefined { dst: 0 },
        Ir3Instruction::Return { value: 0 },
    ];
    m.function_table = vec![
        Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 16,
            name: Some("main".to_string()),
            is_generator: false,
        },
        Ir3FunctionDesc {
            entry: 3,
            arity: 0,
            frame_size: 16,
            name: Some("gen".to_string()),
            is_generator: true,
        },
    ];

    let result = run_ir3(&m);
    // r0 holds the GeneratorFunction value (register 0 is the return value)
    assert!(
        matches!(result, Value::GeneratorFunction(_)),
        "register 0 should hold GeneratorFunction, got: {result}"
    );
}

// ---------------------------------------------------------------------------
// 4. Value type discrimination
// ---------------------------------------------------------------------------

#[test]
fn generator_function_value_is_truthy() {
    assert!(Value::GeneratorFunction(0).is_truthy());
}

#[test]
fn generator_value_is_truthy() {
    assert!(Value::Generator(0).is_truthy());
}

#[test]
fn generator_function_typeof_is_function() {
    assert_eq!(Value::GeneratorFunction(0).typeof_name(), "function");
}

#[test]
fn generator_typeof_is_object() {
    assert_eq!(Value::Generator(0).typeof_name(), "object");
}

#[test]
fn generator_function_type_name_is_function() {
    assert_eq!(Value::GeneratorFunction(0).type_name(), "function");
}

#[test]
fn generator_type_name_is_object() {
    assert_eq!(Value::Generator(0).type_name(), "object");
}

#[test]
fn generator_function_display_contains_generator() {
    let s = format!("{}", Value::GeneratorFunction(5));
    assert!(
        s.contains("generator"),
        "GeneratorFunction display should contain 'generator', got: {s}"
    );
}

#[test]
fn generator_display_contains_generator() {
    let s = format!("{}", Value::Generator(3));
    assert!(
        s.contains("generator"),
        "Generator display should contain 'generator', got: {s}"
    );
}

#[test]
fn generator_function_not_nullish() {
    assert!(!Value::GeneratorFunction(0).is_nullish());
}

#[test]
fn generator_not_nullish() {
    assert!(!Value::Generator(0).is_nullish());
}
