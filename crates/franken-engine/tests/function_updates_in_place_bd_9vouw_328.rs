//! bd-9vouw.328: in a function body, a postfix update whose value is
//! discarded (`n++;`) lowers as the prefix one, a register local's compound
//! or prefix update runs in place, and an `if` without else does not jump
//! to the next instruction. The first test checks that the values are
//! unchanged (Node v22.2.0 gives the line; Bun 1.4.2 agrees): counters,
//! compound operators on numbers, strings and BigInts, postfix values that
//! are used, an object converted once by `o++`, captured counters, nested
//! ifs, and a variable read on both sides of its own update. The second
//! checks the instructions themselves.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn updates_and_branches_keep_their_values() {
    let source = r#"
var out = [];
function counts(o, limit) { var n = 0, m = 10; for (let i = 0; i < limit; i++) { if (o.a === 1) n++; if (i % 2) m--; } return [n, m]; }
out.push(counts({ a: 1 }, 7).join());
function compound() { var x = 2, s = 'a', b = 5n, e = 3; x *= 3; x -= 1; x **= 2; s += 'b'; b++; b += 2n; e <<= 2; e |= 1; return [x, s, String(b), e].join(); }
out.push(compound());
function postfixUsed() { var n = 4; var a = n++; var b = n--; return [a, b, n].join(); }
out.push(postfixUsed());
function coerced() { var calls = 0; var o = { valueOf: function () { calls++; return 41; } }; o++; var s = '5'; s++; return [o, calls, s, typeof s].join(); }
out.push(coerced());
function captured() { var c = 0; function bump() { c++; c += 2; } bump(); bump(); return c; }
out.push(captured());
function ifs(v) { var r = ''; if (v > 1) r += 'a'; if (v > 2) { r += 'b'; } else r += 'c'; if (v > 3) if (v > 4) r += 'd'; return r; }
out.push(ifs(1), ifs(3), ifs(5));
function selfRef() { var y = 2; y = y++ + y; var z = 3; z = z-- * z; return [y, z].join(); }
out.push(selfRef());
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
    assert_eq!(lines, ["7,7 25,ab,8,13 4,5,4 42,1,6,number 6 c ab abd 5,6"]);
}

fn ir3_of(source: &str) -> Vec<Ir3Instruction> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "function_updates_in_place_bd_9vouw_328.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions
}

#[test]
fn counting_loop_updates_in_place_without_jumps_to_the_next_instruction() {
    let instructions = ir3_of(
        "function run(o, limit) { var n = 0; for (let i = 0; i < limit; i++) { if (o.a === 1) n++; } return n; }",
    );
    assert!(
        !instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::UnaryNeg { .. })),
        "a discarded `n++` keeps no old value: {instructions:?}"
    );
    let in_place = instructions
        .iter()
        .filter(|instruction| matches!(instruction, Ir3Instruction::Inc { dst, src } if dst == src))
        .count();
    assert_eq!(
        in_place, 2,
        "`n++` and `i++` step their registers: {instructions:?}"
    );
    for (index, instruction) in instructions.iter().enumerate() {
        if let Ir3Instruction::Jump { target } = instruction {
            assert_ne!(
                *target as usize,
                index + 1,
                "jump to the next instruction at {index}: {instructions:?}"
            );
        }
    }

    // A postfix value that is used still keeps ToNumeric of the old value.
    let used = ir3_of("function f(n) { var a = n++; return a; }");
    assert!(
        used.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::UnaryNeg { .. })),
        "a used `n++` converts its old value: {used:?}"
    );
}
