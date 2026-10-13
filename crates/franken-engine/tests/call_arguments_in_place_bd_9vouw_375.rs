//! bd-9vouw.375: a Call or CallMethod whose arguments already sit in
//! contiguous temporaries at the top of the frame reads them in place
//! instead of copying each into a fresh window. The first test checks calls
//! where that matters: computed, literal, repeated and nested arguments,
//! argument evaluation order, a callee that reassigns its parameters (the
//! caller's bindings keep their values), rest and default parameters,
//! `arguments`, method calls with getter arguments, call/apply, built-ins,
//! a generator call and calls in a loop, in a function and at top level.
//! Node v22.2.0 and Bun 1.4.3 print the line, as did the n65 frankenctl
//! before this change. The second checks the instructions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, RegRange};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn calls_with_in_place_arguments_keep_values() {
    let source = r#"const out = [];
const log = [];
function f(a, b, c) { return [a, b, c].join(','); }
function mut(a, b) { a = 'x'; b = 'y'; return a + b; }
function rest(a, ...more) { return a + ':' + more.join(''); }
function dflt(a, b = a * 2) { return a + b; }
function args() { return arguments.length + ':' + Array.prototype.join.call(arguments, '-'); }
const t = (v) => (log.push(v), v);
const o = { m(x, y) { return this.k + x + y; }, k: 10, get g() { log.push('get'); return 5; } };
function run(n) {
  let s = 1, w = 'w';
  out.push(f(s + 1, s * 3, 'lit'), f(s, s, s), f(f(s, 2, 3), f(4, 5, 6), w));
  out.push(f(t(1), t(2), t(3)), log.join(''));
  out.push(mut(s, w), s, w);
  out.push(rest(s, 2, 3, 4), dflt(n), dflt(n, 1), args(s, n, w), args());
  out.push(o.m(s + 1, 2), o.m(o.g, o.k), log.join(''));
  out.push(f.call(null, s, 2, 3), f.apply(null, [s, n, 9]), Math.max(s, n, 3), String(n + 1));
  const g = function* (a, b) { yield a; yield b; };
  out.push([...g(s, n)].join('|'));
  let acc = 0; for (let i = 0; i < 5; i++) acc += Math.min(i, 3) + parseInt(String(i));
  out.push(acc);
}
run(7);
let top = 2; out.push(f(top + 1, top, 'top'), Math.abs(-top));
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
        [
            r#"2,3,lit 1,1,1 1,2,3,4,5,6,w 1,2,3 123 xy 1 w 1:234 21 8 3:1-7-w 0: 14 25 123get 1,2,3 1,7,9 7 8 1|7 19 3,2,top 2"#
        ]
    );
}

#[test]
fn computed_arguments_are_passed_where_they_were_computed() {
    let tree = CanonicalEs2020Parser
        .parse(
            "function f(a, b) { return a; } function g(x) { return f(x + 1, x * 2); }",
            ParseGoal::Script,
        )
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "call_arguments_in_place_bd_9vouw_375.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let instructions = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions;
    // g's body: the call's window is the two operator results (Add, then
    // Mul), with no Move between the Add and the Call.
    let call = instructions
        .iter()
        .rposition(|instruction| matches!(instruction, Ir3Instruction::Call { .. }))
        .expect("g calls f");
    let Ir3Instruction::Call {
        args: RegRange { start, count },
        ..
    } = &instructions[call]
    else {
        unreachable!()
    };
    assert_eq!(*count, 2);
    assert!(
        matches!(&instructions[call - 1], Ir3Instruction::Mul { dst, .. } if *dst == start + 1),
        "the second argument is the Mul's result, passed in place: {instructions:?}"
    );
    let add = instructions[..call]
        .iter()
        .rposition(
            |instruction| matches!(instruction, Ir3Instruction::Add { dst, .. } if dst == start),
        )
        .unwrap_or_else(|| panic!("the first argument is an Add's result: {instructions:?}"));
    assert!(
        !instructions[add..call]
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Move { .. })),
        "no argument copies: {instructions:?}"
    );
}
