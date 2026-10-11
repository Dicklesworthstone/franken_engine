//! bd-9vouw.486: loops and ifs run no dead, copy or redundant jump
//! instructions: no load of the `1` of `++`/`--` (IR1 pushes it, no lowering
//! of the update reads it), no copy of a register binding that is the right
//! operand of a compound assignment (`s += i` reads `i`'s register, as
//! bd-9vouw.330 does for operators, now also at top level), no top-level
//! completion Move for a loop test or a for update, loops that test at the
//! bottom so an iteration ends in one conditional jump back to the body, and
//! `if (!x)` / `if (a === b)` branching on the exact negation in one jump.
//! The first test checks values where those matter: updates of register,
//! captured and top-level bindings as statements and as values, BigInt,
//! string and valueOf operands, compound operators of every kind, a binding
//! used on both sides (`x += x`, `u += u * 2`, `h = h + h * 2`, `v = v * v`),
//! and the read-then-write hazards (`x -= (x = 5)`, `y += y++`, `z *= ++z`).
//! Node v22.2.0 and Bun 1.4.2 print the line, as did the release frankenctl
//! of rc-next59 (fctl_abp_53ef3d835) before this change. Others check loop
//! control flow, negated if tests and the completion value of a loop (Node's
//! vm.runInNewContext: undefined and 30; that frankenctl reported 2 and 3,
//! the last update's value). The last three check the instructions.

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

/// Loops whose test now runs at the bottom: break, continue (labeled too),
/// zero-iteration loops, how often each test runs, closures over the
/// per-iteration binding made in the head, test, update and body, loops in a
/// switch case and in a generator. Node v22.2.0, Bun 1.4.2 and the release
/// frankenctl of rc-next59 print the line.
#[test]
fn loop_control_flow_keeps_values() {
    let source = r#"var out = [];
function tests() { let calls = 0; const t = (v) => { calls++; return v; }; let a = 0; while (t(a < 3)) a++; let b = 0; do { b++; } while (t(b < 2)); for (let i = 0; t(i < 2); i++) {} let z = 0; while (t(false)) z++; for (let i = 0; t(false); i++) z++; return [a, b, z, calls].join(); }
function control() { let log = []; for (let i = 0; i < 6; i++) { if (i === 1) continue; if (i === 4) break; log.push(i); } let j = 0; while (true) { j++; if (j < 3) continue; if (j > 4) break; log.push('w' + j); } let k = 0; do { k++; if (k === 2) continue; log.push('d' + k); } while (k < 3); outer: for (let x = 0; x < 3; x++) { for (let y = 0; y < 3; y++) { if (y === 1) continue outer; if (x === 2) break outer; log.push(x + '' + y); } } for (;;) { log.push('f'); break; } return log.join(); }
function closures() { const fs = []; for (let i = 0, g = () => i; i < 3; i++, fs.push(() => i)) fs.push(() => i * 10); const fromTest = []; for (let i = 0; fromTest.push(() => i) && i < 2; i++) {} return [fs.map(f => f()).join('|'), fromTest.map(f => f()).join('|')].join(' '); }
function nested(n) { let total = 0; switch (n) { case 1: for (let i = 0; i < 3; i++) { let j = 0; while (j < i) { total += j; j++; } } break; default: total = -1; } return total; }
function gen() { function* g() { let i = 0; while (i < 3) { yield i; i++; } do { yield 'd'; } while (false); } return [...g()].join(); }
out.push(tests(), control(), closures(), nested(1), nested(2), gen());
let c = 0; for (let i = 10; i > 0; i -= 3) c++; let w = 0, n = 5; while (n--) w += n; let dw = 0; do dw += 2; while (dw < 5);
out.push(c, w, n, dw);
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
        ["3,2,0,11 0,2,3,w3,w4,d1,d3,00,10,f 0|1|10|2|20|3 0|1|2 1 -1 0,1,2,d 4 10 -1 6"]
    );
}

/// `if (!x)` and the (in)equality tests branch on their exact negation:
/// every falsy and truthy kind of value, `==` coercion that runs valueOf
/// (once per test), NaN and -0, operand order, else branches, ifs in a loop
/// body and at top level. Node v22.2.0, Bun 1.4.2 and the release frankenctl
/// of rc-next59 print the line.
#[test]
fn negated_if_conditions_keep_values() {
    let source = r#"var out = [];
function nots() { const vals = [0, -0, '', null, undefined, NaN, false, 0n, 1, 'a', [], {}, -1, 1n, Symbol('s')]; const r = []; for (const v of vals) { if (!v) r.push('f'); else r.push('t'); } let x = 3; if (!!x) r.push('dd'); if (!(x > 2)) r.push('no'); else r.push('gt'); return r.join(''); }
function eqs() { const log = []; const o = { valueOf() { log.push('v'); return 1; } }; const r = []; if (null == undefined) r.push(1); if (null === undefined) r.push(2); else r.push(3); if ('1' == 1) r.push(4); if ('1' != 1) r.push(5); else r.push(6); if (o == 1) r.push(7); if (o != 1) r.push(8); if (NaN == NaN) r.push(9); if (NaN != NaN) r.push(10); if (NaN !== NaN) r.push(11); if (0 === -0) r.push(12); if (!(0 !== -0)) r.push(13); return [r.join(','), log.join('')].join(' '); }
function order() { const log = []; const a = () => (log.push('a'), 1), b = () => (log.push('b'), 2); if (a() === b()) log.push('eq'); else log.push('ne'); if (a() !== b()) log.push('NE'); if (!a()) log.push('x'); return log.join(''); }
function inLoop(n) { let hits = 0, misses = 0; for (let i = 0; i < n; i++) { if (i % 4 === 0) hits++; else misses++; if (!(i & 1)) hits += 10; } return [hits, misses].join(); }
out.push(nots(), eqs(), order(), inLoop(20));
let k = 0, m = 'x'; if (k === 0) m += 'z'; if (!k) m += 'n'; if (k != 0) m += 'bad'; else m += 'e';
out.push(m);
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
        ["fffffffftttttttddgt 1,3,4,6,7,10,11,12,13 vv abneabNEa 105,15 xzne"]
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
fn a_function_counting_loop_runs_four_instructions_per_iteration() {
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
    // One iteration: Add, Inc, Lt and the JumpIf back to the body.
    assert_eq!(
        iteration(&lowered(
            "function g(n) { let s = 0; for (let i = 0; i < n; i++) s += i; return s; }"
        )),
        4
    );
}

/// The instructions of a program's one loop iteration: from the back edge's
/// target through the back edge, a conditional jump to an earlier
/// instruction (the test runs at the bottom).
fn iteration(instructions: &[Ir3Instruction]) -> usize {
    let (back_edge, target) = instructions
        .iter()
        .enumerate()
        .find_map(|(index, instruction)| match instruction {
            Ir3Instruction::JumpIf { target, .. } if (*target as usize) < index => {
                Some((index, *target as usize))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no conditional back edge: {instructions:?}"));
    assert!(
        !instructions[target..back_edge]
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Jump { .. })),
        "an iteration runs no unconditional jump: {:?}",
        &instructions[target..=back_edge]
    );
    back_edge - target + 1
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
    // One iteration: Add, its completion Move, Inc, the literal 5, Lt and
    // the JumpIf back to the body.
    assert_eq!(iteration(&code), 6);

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

#[test]
fn equality_and_not_tests_branch_in_one_jump() {
    // a is register 0, b register 1, n register 2.
    let eq = function_bodies("function f(a, b) { let n = 0; if (a === b) n++; return n; }");
    let test = eq
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::StrictNotEq { .. }))
        .unwrap_or_else(|| panic!("`a === b` branches on `a !== b`: {eq:?}"));
    assert!(
        matches!(eq.get(test + 1), Some(Ir3Instruction::JumpIf { .. }))
            && matches!(
                eq.get(test + 2),
                Some(Ir3Instruction::Inc { dst: 2, src: 2 })
            ),
        "the negated test jumps over `n++` in one JumpIf: {eq:?}"
    );
    assert!(
        !eq.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::StrictEq { .. })),
        "{eq:?}"
    );

    let not = function_bodies("function g(a) { let n = 0; if (!a) n++; return n; }");
    assert!(
        !not.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LogicalNot { .. })),
        "`!a` branches on a itself: {not:?}"
    );
    assert!(
        !not.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Jump { .. })),
        "{not:?}"
    );

    // A relational test keeps JumpIfFalsy's JumpIf over a Jump: `a < b` and
    // `a >= b` are both false when either is NaN.
    let lt = function_bodies("function h(a, b) { let n = 0; if (a < b) n++; return n; }");
    assert!(
        lt.iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Lt { .. }))
            && lt
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::Jump { .. })),
        "{lt:?}"
    );
}
