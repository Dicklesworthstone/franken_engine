//! bd-9vouw.491: an array literal no longer ends with a store of its length
//! (LoadStr "length", LoadInt n, SetProperty through the generic [[Set]]):
//! CreateDataProperty of index n - 1 already makes the length n, and a hole
//! (defined, then deleted) keeps it. The first test checks literal shapes
//! where the length matters: holes (leading, inner, trailing, only holes),
//! spreads, nesting, a 100-element literal, an Array.prototype '0' accessor
//! the literal must not call (and a hole that reads it), pushes after a
//! trailing hole, literals in a function, and a frozen Array.prototype.
//! Node v22.2.0 prints the line (Bun 1.4.3 differs only in reading the hole
//! through the inherited getter), as did the release frankenctl of
//! rc-next59. The second checks the instructions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn array_literal_lengths_hold_without_a_length_store() {
    let source = r#"const out = [];
const show = (a) => a.length + ':' + JSON.stringify(a) + ':' + Object.keys(a).join('');
out.push(show([]), show([1]), show([1, 2, 3]), show([1, , 3]), show([1, ,]), show([, ,]), show([,]), show([, 1]));
out.push(show([...[1, 2], 3]), show([...'ab']), show([1, ...[], 2]), JSON.stringify([[1], [2, [3]]]));
const big = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99];
out.push(big.length, big[99]);
let calls = 0;
Object.defineProperty(Array.prototype, '0', { set(v) { calls++; }, get() { return 'proto'; }, configurable: true });
const withSetter = [7, 8];
out.push(withSetter[0], withSetter.hasOwnProperty('0'), calls, [, 5][0]);
delete Array.prototype[0];
const t = [1, ,]; t.push(9); out.push(show(t));
function inFn(i) { const p = [i, i * 2]; return p.length + p[1]; }
let s = 0; for (let i = 0; i < 5; i++) s += inFn(i);
out.push(s);
Object.freeze(Array.prototype);
out.push(show([3, 4]));
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
            r#"0:[]: 1:[1]:0 3:[1,2,3]:012 3:[1,null,3]:02 2:[1,null]:0 2:[null,null]: 1:[null]: 2:[null,1]:1 3:[1,2,3]:012 2:["a","b"]:01 2:[1,2]:01 [[1],[2,[3]]] 100 99 7 true 0 proto 3:[1,null,9]:02 30 2:[3,4]:01"#
        ]
    );
}

#[test]
fn an_array_literal_runs_no_set_property() {
    let tree = CanonicalEs2020Parser
        .parse(
            "function f(i) { const p = [i, i]; return p; }",
            ParseGoal::Script,
        )
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "array_literal_length_store_bd_9vouw_491.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let instructions = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions;
    let body: Vec<_> = instructions
        .iter()
        .skip_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .collect();
    assert_eq!(
        body.iter()
            .filter(|instruction| matches!(instruction, Ir3Instruction::CreateDataProperty { .. }))
            .count(),
        2,
        "{body:?}"
    );
    assert!(
        !body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::SetProperty { .. })),
        "no length store: {body:?}"
    );
}
