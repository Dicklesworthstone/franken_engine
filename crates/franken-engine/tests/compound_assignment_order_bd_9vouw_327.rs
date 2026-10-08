//! bd-9vouw.327: `x op= rhs` reads x before evaluating rhs (ES2020
//! 12.15.4 step 2.b). An identifier target was read after rhs, so a right
//! side that wrote x (`x += (x = 5)`, `x += x++`, a call that updates a
//! captured or global x) changed the result, and a TDZ read threw only
//! after rhs's side effects. The program covers locals, captured and global
//! bindings, the member form (already right), an accumulator updated by its
//! own visitor, the TDZ order, and simple right sides. Node v22.2.0 gives
//! this line; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn compound_assignment_reads_its_target_first() {
    let source = r#"
var out = [];
function a() { var x = 1; x += (x = 5); return x; }
function b() { var x = 1; function f() { x = 10; return 1; } x += f(); return x; }
var g = 1; function c() { g += (g = 5); return g; }
function d() { var o = { p: 1 }; o.p += (o.p = 5); return o.p; }
function e() { var x = 2; x += x++; return x; }
function f() { var s = 'a'; function g() { s = 'z'; return 'b'; } s += g(); return s; }
function h() { var total = 0; function visit(n) { total += n; return n; } total += visit(3) + visit(4); return total; }
function k() { var called = false; function f() { called = true; return 1; } try { x += f(); } catch (err) { return err.constructor.name + ',' + called; } let x = 1; }
function n() { var i = 0, s = 'x', y = 3; i += 1; i -= 2; s += 'y'; y *= i; return [i, s, y].join(); }
out.push(a(), b(), c(), d(), e(), f(), h(), k(), n());
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
    assert_eq!(lines, ["6 2 6 6 4 ab 7 ReferenceError,false -1,xy,-3"]);
}

/// The same order at the top level, where the script emitter lowers the
/// read: a right side that writes the target (`x += (x = 5)`, `z += z++`)
/// or a call that updates a captured target keeps the value read first,
/// while a target nothing in the right side can write (calls of other
/// functions, member reads, operators, a `let`) is read in place by the
/// operator. A conditional right side is not scanned and reads a copy. The
/// line is Node v22.2.0's; the land43 base (main 79f757c32) gave
/// `10 11 5 ...`.
#[test]
fn top_level_compound_assignment_reads_its_target_first() {
    let source = r#"
var out = [];
var x = 1; x += (x = 5); out.push(x);
var y = 1; function fy() { y = 10; return 1; } y += fy(); out.push(y);
var z = 2; z += z++; out.push(z);
var s = 0; for (var i = 0; i < 5; i++) { s += Math.max(i, 1); } out.push(s);
var t = 'a'; t += String(1) + 'b'; out.push(t);
var o = { p: 4 }; var u = 3; u *= o.p - 1; out.push(u);
var w = 'k'; w += [1, 2].join('') + o['p']; out.push(w);
let q = 1; q += Math.abs(-2) * 2; out.push(q);
var n = 7; var keep = n; n -= Math.min(n, 3); out.push(n, keep);
var c = 0; var arr = [1, 2]; c += arr.length ? arr[0] : 0; out.push(c);
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
    assert_eq!(lines, ["6 2 4 11 a1b 9 k124 5 4 7 1",]);
}

/// The script's own instructions (up to its `Halt`).
fn top_level_ir3(source: &str) -> Vec<frankenengine_engine::ir_contract::Ir3Instruction> {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
    use frankenengine_engine::lowering_pipeline::{
        lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
    };
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "compound_assignment_order_bd_9vouw_327.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3")
        .module
        .instructions
        .into_iter()
        .take_while(|instruction| !matches!(instruction, Ir3Instruction::Halt))
        .collect()
}

/// `s += Math.max(i, 1)` in a top-level loop: the Add reads and writes s's
/// register, with no copy of s before the call and no Move of the result
/// after it (bd-9vouw.327's read-first order had added three Moves per
/// iteration here). `x += (x = 5)` still adds to a copy of x.
#[test]
fn top_level_compound_operator_reads_an_unwritten_target_in_place() {
    use frankenengine_engine::ir_contract::Ir3Instruction;

    let looped =
        top_level_ir3("var s = 0; for (var i = 0; i < 9000; i++) { s += Math.max(i, 1); }");
    let adds: Vec<_> = looped
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::Add { dst, lhs, rhs } => Some((*dst, *lhs, *rhs)),
            _ => None,
        })
        .collect();
    assert_eq!(adds.len(), 1, "{looped:?}");
    let (dst, lhs, call_result) = adds[0];
    assert_eq!(dst, lhs, "the Add writes s's register in place: {looped:?}");
    let add_index = looped
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Add { .. }))
        .expect("the Add");
    assert!(
        matches!(
            looped[add_index - 1],
            Ir3Instruction::CallMethod { dst, .. } if dst == call_result
        ),
        "the Add follows the call and reads its result register: {looped:?}"
    );
    let body_start = looped[..add_index]
        .iter()
        .rposition(|instruction| matches!(instruction, Ir3Instruction::JumpIf { .. }))
        .expect("the loop condition's jump");
    assert!(
        !looped[body_start..add_index]
            .iter()
            .any(|instruction| matches!(
                instruction,
                Ir3Instruction::Move { src, .. } if *src == lhs
            )),
        "no copy of s before the call: {looped:?}"
    );

    // The Add's result is stored to x by the Move after it; its left operand
    // is the copy of x taken before `x = 5`, not x's register.
    let hazard = top_level_ir3("var x = 1; x += (x = 5);");
    let add_index = hazard
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Add { .. }))
        .expect("the Add");
    let Ir3Instruction::Add { dst: sum, lhs, .. } = hazard[add_index] else {
        unreachable!()
    };
    assert!(
        matches!(
            hazard.get(add_index + 1),
            Some(Ir3Instruction::Move { dst: x_register, src }) if *src == sum && *x_register != lhs
        ),
        "`x += (x = 5)` adds to a copy of x and stores the sum to x: {hazard:?}"
    );
}
