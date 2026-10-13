//! bd-9vouw.493: `return x` of a function's parameter or local returns the
//! binding's register instead of copying it first (Return reads its value
//! when it runs, before any finally). The first test checks returns where
//! the value matters: parameters, let and const locals, a return inside
//! try/finally whose finally reassigns the local, generators, returns from a
//! loop, a closure-captured local, `arguments`. Node v22.2.0 prints the line,
//! as did the n65 frankenctl before this change. The second checks that
//! `return a` is a bare Return of the parameter's register.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn returned_bindings_keep_their_values() {
    let source = r#"const out = [];
function k3(a) { return a; }
function k4(a) { let r = a + 1; return r; }
function k6(a) { const r = a * 2; return r; }
function fin(a) { let x = a; try { return x; } finally { x = 99; } }
function fin2(a) { let x = a; try { x += 1; return x; } finally { x = -1; out.push('f' + x); } }
function* gen(a) { let y = a; yield y; return y; }
function swap(a, b) { let t = a; a = b; b = t; return a; }
function loopret(n) { for (let i = 0; i < n; i++) { if (i === 3) return i; } return -1; }
function closure(a) { let z = a; const g = () => z; z = a + 5; return g(); }
function args1() { return arguments.length; }
out.push(k3(1), k4(1), k6(3), fin(7), fin2(7), [...gen(4)].join(), gen(4).next().value, swap(1, 2), loopret(10), loopret(2), closure(1), args1(1, 2));
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, [r#"f-1 1 2 6 7 8 4 4 2 3 -1 6 2"#]);
}

#[test]
fn returning_a_parameter_runs_no_copy() {
    let tree = CanonicalEs2020Parser
        .parse("function k(a) { return a; }", ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "return_in_place_bd_9vouw_493.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let instructions = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions;
    let body: Vec<_> = instructions
        .iter()
        .skip_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .skip(1)
        .collect();
    assert!(
        matches!(body.first(), Some(Ir3Instruction::Return { value: 0 })),
        "{body:?}"
    );
}
