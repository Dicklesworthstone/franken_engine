//! bd-9vouw.496: a loop's literals and static property keys are loaded once
//! into pinned registers before the loop (before its entry jump to the
//! bottom test, or before the body of a do-while) instead of on every
//! iteration. The first test runs loops whose constants matter: every
//! literal kind, distinct literals that compare loosely equal (`1`, `1.0`,
//! `'1'`), static keys read and written, nested loops (hoisted before the
//! outer one), labelled continue/break, try/catch/finally, a generator, call
//! arguments, object and array literals, template parts, stores of
//! literals, a loop whose body never runs, top-level loops. Node v22.2.0 and
//! Bun 1.4.3 print the line, as did the n66 frankenctl before this change.
//! The second checks the IR of `t += o.k * 2` in a loop.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn hoisted_loop_constants_keep_their_values() {
    let source = r##"const out = [];
function kinds(n) { let s = ''; for (let i = 0; i < n; i++) { s += 1 + ':' + 1.5 + ':' + '1' + ':' + true + ':' + null + ':' + undefined + '|'; } return s; }
function keys(n) { const o = { a: 1, b: 2 }; let t = 0; for (let i = 0; i < n; i++) { t += o.a * 10 + o.b; o.a = o.a + 1; o['b'] = 2; } return t + ',' + o.a + ',' + o.b; }
function nested(n) { let t = 0; for (let i = 0; i < n; i++) { for (let j = 0; j < 3; j++) { t += j * 2 + 1; } t += 100; } return t; }
function whileDo(n) { let i = 0, s = 0; while (i < n) { s += i % 3; i++; } let k = 0; do { s += 7; k++; } while (k < 2); return s; }
function flow(n) { let s = 0; outer: for (let i = 0; i < n; i++) { for (let j = 0; j < 5; j++) { if (j === 2) continue outer; if (i === 3) break outer; s += 10; } } return s; }
function tries(n) { let s = 0; for (let i = 0; i < n; i++) { try { if (i % 2) throw new Error('e' + 1); s += 1; } catch (e) { s += e.message.length * 10; } finally { s += 100; } } return s; }
function* gen(n) { for (let i = 0; i < n; i++) { yield i * 2 + 1; } }
function callsAndLits(n) { const r = []; for (let i = 0; i < n; i++) { r.push(Math.max(i, 2)); const o = { k: 5, v: [1, 'x'] }; r.push(o.k + o.v[0], `${i}-${'t'}`); } return r.join(); }
function stores(n) { let a = 0, b = ''; for (let i = 0; i < n; i++) { a = 9; b = 'q'; a = a + 1; } return a + b; }
function zero() { let s = 'start'; for (let i = 0; i < 0; i++) { s += 'never' + 42; } return s; }
function sameNumbers(n) { let s = 0; for (let i = 0; i < n; i++) { s += 1; s += 1.0; s += 0.5; s += '1' === 1 ? 100 : 0; } return s; }
out.push(kinds(2), keys(3), nested(3), whileDo(5), flow(5), tries(4), [...gen(3)].join(), callsAndLits(3), stores(3), zero(), sameNumbers(2));
let tt = 0; for (let i = 0; i < 4; i++) { tt += i * 3 + 7; } const to = { m: 2 }; let tm = 0; for (let i = 0; i < 3; i++) { tm += to.m * 5; }
out.push(tt, tm);
console.log(out.join(' '));
"##;
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
            r##"1:1.5:1:true:null:undefined|1:1.5:1:true:null:undefined| 66,4,2 327 18 60 442 1,3,5 2,6,0-t,2,6,1-t,2,6,2-t 10q start 5 46 30"##
        ]
    );
}

#[test]
fn a_loop_runs_no_constant_load() {
    let tree = CanonicalEs2020Parser
        .parse(
            "function f(o, n) { let t = 0; for (let i = 0; i < n; i++) { t += o.k * 2; } return t; }",
            ParseGoal::Script,
        )
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "loop_constant_hoisting_bd_9vouw_496.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let body: Vec<_> = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions
        .into_iter()
        .skip_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .skip(1)
        .collect();
    let entry = body
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Jump { .. }))
        .expect("the loop's entry jump");
    let back_edge = body
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::JumpIf { .. }))
        .expect("the loop's back edge");
    let is_constant_load = |instruction: &Ir3Instruction| {
        matches!(
            instruction,
            Ir3Instruction::LoadInt { .. }
                | Ir3Instruction::LoadStr { .. }
                | Ir3Instruction::LoadFloat { .. }
        )
    };
    assert!(
        !body[entry..=back_edge].iter().any(is_constant_load),
        "no constant load inside the loop: {body:?}"
    );
    assert!(
        body[..entry]
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadInt { value: 2, .. }))
            && body[..entry]
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::LoadStr { .. })),
        "the `2` and the key `k` are loaded before the loop: {body:?}"
    );
}
