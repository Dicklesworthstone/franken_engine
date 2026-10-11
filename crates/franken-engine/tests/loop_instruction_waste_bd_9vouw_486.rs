//! bd-9vouw.486: loop bodies run no dead or copy instructions for the `1`
//! of `++`/`--` (IR1 pushes it, no lowering of the update reads it), the
//! right operand of a compound assignment that is a register binding
//! (`s += i` reads `i`'s register, as bd-9vouw.330 does for operators, now
//! also at top level), or the top-level completion of a loop test or a for
//! update. The first test checks values where those matter: updates of
//! register, captured and top-level bindings as statements and as values,
//! BigInt, string and valueOf operands, compound operators of every kind,
//! a binding used on both sides (`x += x`, `u += u * 2`, `h = h + h * 2`,
//! `v = v * v`), and
//! the read-then-write hazards (`x -= (x = 5)`, `y += y++`, `z *= ++z`).
//! Node v22.2.0 and Bun 1.4.2 print the line, as did the release frankenctl
//! of rc-next59 (fctl_abp_53ef3d835) before this change. The second checks
//! the completion value of a loop (Node's vm.runInNewContext: undefined and
//! 30; that frankenctl reported 2 and 3, the last update's value). The last
//! two check the instructions.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn updates_and_compound_operands_keep_values() {
    let source = r#"var out = [];
function sums(n) { let s = 0; for (let i = 0; i < n; i++) s += i; return s; }
function ops(n) { let a = 100, b = 1, c = 7; for (let i = 1; i <= n; i++) { a -= i; b *= i; c ^= i; c <<= 1; c >>= 1; c >>>= 0; c |= i; c &= 255; c %= 97; } let d = 2; d **= 3; d /= 4; return [a, b, c, d].join(); }
function self(n) { let x = 3; x += x; x *= x; let y = n; y -= y; return [x, y].join(); }
function updates() { let i = 0, j = 10, k = 5n, s = 'a', log = []; const o = { valueOf() { log.push('v'); return 4; } }; let p = o; i++; ++i; j--; --j; k++; s++; p++; const a = i++, b = ++i, c = j--, d = --j; return [i, j, a, b, c, d, k, s, p, log.join('')].join(); }
function captured() { let n = 0; const read = () => n; for (let i = 0; i < 3; i++) { n++; n += i; } return [n, read()].join(); }
function argsInPlace(f) { let i = 1; return [f(i++, i++), f(++i, ++i), i].join(); }
function hazard() { let x = 2; x -= (x = 5); let y = 3; y += y++; let z = 4; z *= ++z; return [x, y, z].join(); }
out.push(sums(10), ops(6), self(9), updates(), captured(), argsInPlace((a, b) => a * 10 + b), hazard());
let s = 0; for (let i = 0; i < 10; i++) s += i;
let t = 1; for (let i = 1; i < 6; i++) { t *= i; t -= 1; }
let u = 3; u += u * 2; let h = 3; h = h + h * 2; let v = 4; v = v * v; let w = 5; w += w;
let m = 0, q = 0; for (let i = 0, j = 10; i < j; i++, j--) { m += i; q += j; }
var g = 0; function bump() { return g; } for (var r = 0; r < 4; r++) g += r;
let e = 0; let cnt = 0; while (e < 5) { e++; } do { cnt += 2; } while (cnt < 7);
let big = 1n; for (let i = 0; i < 3; i++) big *= 3n; let str = 'x'; for (let i = 0; i < 2; i++) str += i;
let hits = 0; const peek = () => hits; for (let i = 0; i < 3; i++) hits++; hits--; ++hits; const old = hits++;
out.push(s, t, u, h, v, w, m, q, g, bump(), r, e, cnt, big, str, hits, peek(), old);
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
            "45 79,720,7,2 36,0 4,6,2,4,8,6,6,NaN,5,v 6,6 12,45,5 -3,6,20 45 -86 9 9 16 10 10 40 6 6 4 5 8 27 x01 4 4 3"
        ]
    );
}

#[test]
fn a_loop_completes_with_its_body_value() {
    for (source, value, completion_type) in [
        (
            "let x = 1; for (let i = 0; i < 2; i++) {}",
            "undefined",
            "undefined",
        ),
        (
            "let n = 0; for (let i = 0; i < 3; i++) { n += 10; }",
            "30",
            "number",
        ),
    ] {
        let outcome = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("evaluation of {source} failed: {error}"));
        assert_eq!(
            (outcome.value.as_str(), outcome.completion_type.as_deref()),
            (value, Some(completion_type)),
            "completion value of {source}"
        );
    }
}

fn lowered(source: &str) -> Vec<Ir3Instruction> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "loop_instruction_waste_bd_9vouw_486.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions
}

/// The function bodies: the instructions after the script's own `Halt`.
fn function_bodies(source: &str) -> Vec<Ir3Instruction> {
    lowered(source)
        .into_iter()
        .skip_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .skip(1)
        .collect()
}

/// The script's own code: the instructions before its `Halt`.
fn script_code(source: &str) -> Vec<Ir3Instruction> {
    lowered(source)
        .into_iter()
        .take_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .collect()
}

#[test]
fn a_function_counting_loop_runs_five_instructions_per_iteration() {
    // n is register 0, s register 1, i register 2.
    let body = function_bodies(
        "function g(n) { let s = 0; for (let i = 0; i < n; i++) s += i; return s; }",
    );
    assert!(
        body.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::Add {
                dst: 1,
                lhs: 1,
                rhs: 2
            }
        )),
        "`s += i` reads i's register: {body:?}"
    );
    assert!(
        body.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Inc { dst: 2, src: 2 })),
        "`i++` steps i in place: {body:?}"
    );
    assert!(
        !body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadInt { value: 1, .. })),
        "no load of the update's 1: {body:?}"
    );
    assert!(
        !body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Move { src: 2, .. })),
        "no copy of i: {body:?}"
    );
    // The loop: Lt, JumpIf, the exit Jump, Add, Inc and the back Jump.
    let start = body
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Lt { .. }))
        .expect("loop test");
    let end = body
        .iter()
        .rposition(|instruction| matches!(instruction, Ir3Instruction::Jump { .. }))
        .expect("back jump");
    assert_eq!(
        end - start + 1,
        6,
        "loop instructions: {:?}",
        &body[start..=end]
    );
}

#[test]
fn a_top_level_loop_records_only_its_body_as_the_completion() {
    // s is register 1, i register 2; register 0 is the completion value.
    let code = script_code("let s = 0; for (let i = 0; i < 5; i++) s += i;");
    let completion_moves = code
        .iter()
        .filter(|instruction| matches!(instruction, Ir3Instruction::Move { dst: 0, .. }))
        .count();
    assert_eq!(
        completion_moves, 1,
        "only the body's `s += i` is a completion value: {code:?}"
    );
    assert!(
        code.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Lt { lhs: 2, .. })),
        "`i < 5` reads i's register: {code:?}"
    );
    assert!(
        code.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::Add {
                dst: 1,
                lhs: 1,
                rhs: 2
            }
        )),
        "`s += i` reads i's register: {code:?}"
    );
    assert!(
        !code
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadInt { value: 1, .. })),
        "no load of the update's 1: {code:?}"
    );

    // A binding read again while an in-place compound read holds its
    // register stays a copy: in `s = s + s * 2` the sum is written to s's
    // register, so reading s in place for the product would write 6 there
    // before the sum reads it (12, not 9; the value test checks `h`).
    let twice = script_code("let s = 3; s = s + s * 2;");
    assert!(
        twice
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Move { src: 1, .. })),
        "the second read of s is a copy: {twice:?}"
    );
}
