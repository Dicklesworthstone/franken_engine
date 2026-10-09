//! bd-9vouw.330: in a function body, a local read that the next op consumes
//! (an operator or a static property read, or an operator after one more
//! load) reads the binding's register instead of a copy. The first test
//! checks values where a copy matters: a read followed by a write of the same
//! binding in one expression (`x + (x = 5)`, `y + y++`, `(z = 10) + z`),
//! swaps, a local reassigned after a property read, conversions that run
//! code, strings and mixed operators. Node v22.2.0 gives the line; Bun 1.4.2
//! and the land41 gate binary agree. The second checks the instructions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn in_place_local_reads_keep_values() {
    let source = r#"
var out = [];
function hazards() { var x = 1; var a = x + (x = 5); var y = 2; var b = y + y++; var z = 3; var c = (z = 10) + z; return [a, b, c, x, y, z].join(); }
function reads(o, limit) { var n = 0; for (let i = 0; i < limit; i++) { if (o.a === 1) n++; } return n; }
function swaps() { var p = 1, q = 2; var t = p; p = q; q = t; return [p - q, p < q, p * q + p].join(); }
function members(o) { var k = o; var first = k.a; k = { a: 9 }; return [first, k.a, o.a].join(); }
function converted() { var log = []; var v = { valueOf: function () { log.push('v'); return 4; } }; var w = 3; var r = v * w + (w < v ? 1 : 0); return [r, log.join('')].join(); }
function strings(s) { var t = s + '!'; return [t, s.length, t > s].join(); }
function chain(a, b, c) { return a * b - c / a + (b % c) + (a === b) + (a < b && b < c); }
out.push(hazards(), reads({ a: 1 }, 5), swaps(), members({ a: 7 }), converted(), strings('hi'), chain(2, 3, 4));
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
    assert_eq!(
        lines,
        ["6,4,20,5,3,10 5 1,false,4 7,9,7 13,vv hi!,2,true 8"]
    );
}

/// The instructions of the function bodies: those after the script's own
/// code, which ends at its `Halt` (it stores the function with a `Move` of
/// its own registers).
fn ir3_of(source: &str) -> Vec<Ir3Instruction> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "local_reads_in_place_bd_9vouw_330.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions
        .into_iter()
        .skip_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .skip(1)
        .collect()
}

#[test]
fn operators_and_property_reads_use_parameter_registers() {
    // `o` and `limit` are the function's registers 0 and 1.
    let instructions = ir3_of(
        "function run(o, limit) { var n = 0; for (let i = 0; i < limit; i++) { if (o.a === 1) n++; } return n; }",
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Lt { rhs: 1, .. })),
        "`i < limit` reads limit's register: {instructions:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::GetProperty { obj: 0, .. })),
        "`o.a` reads o's register: {instructions:?}"
    );
    assert!(
        !instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Move { src: 0 | 1, .. })),
        "no copy of o or limit: {instructions:?}"
    );

    // A read followed by a write of the same binding keeps its copy.
    let hazard = ir3_of("function f(x) { return x + (x = 5); }");
    assert!(
        hazard
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Move { src: 0, .. })),
        "`x + (x = 5)` copies x before the assignment: {hazard:?}"
    );
}
