//! bd-9vouw.494: a plain store into a register-resident local (`x = e`,
//! `let x = e`) lets the instruction that computed `e` write the binding's
//! register instead of a temporary that a Move then copied. The first test
//! runs stores whose value matters: producers that throw (getter, callee,
//! valueOf, unresolvable name) and must leave the binding unchanged,
//! conditional / logical / nullish / optional-chain right-hand sides (their
//! arms join at a label, so the copy stays), chained stores, `x = x++`,
//! right-hand sides that read or write the stored binding, short-lived
//! locals, a generator, a finally, a template whose parts run toString,
//! parameters with `arguments`, and top-level stores. Node v22.2.0 and Bun
//! 1.4.3 print the line, as did the n65 frankenctl before this change. The
//! other two check the IR: an arithmetic or call result is not copied into
//! its binding, and a conditional right-hand side keeps its copy.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

/// The instructions after the top level's Halt: the bodies of the declared
/// functions, in declaration order.
fn function_bodies(source: &str) -> Vec<Ir3Instruction> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "store_in_place_bd_9vouw_494.js");
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

/// The destination of an arithmetic or call instruction.
fn computed_destination(instruction: &Ir3Instruction) -> Option<u32> {
    match instruction {
        Ir3Instruction::Add { dst, .. }
        | Ir3Instruction::Sub { dst, .. }
        | Ir3Instruction::Mul { dst, .. }
        | Ir3Instruction::Call { dst, .. } => Some(*dst),
        _ => None,
    }
}

#[test]
fn stored_values_match_node() {
    let source = r#"const out = [];
function arith(n) { let s = 0; let t = 0; for (let i = 0; i < n; i++) { s += i; t = s + i; s = t * 2 - s; } return s + ',' + t; }
function chain(c) { let a, b; a = b = c + 1; return a + b; }
function postinc() { let x = 5; x = x++; let y = 5; y = ++y; return x + ',' + y; }
function selfref(a) { let s = a; s = s * 2 + s; s = s - (s = 1); return s; }
function cond(f) { let x = 1; x = f ? x + 10 : x + 20; let y = 0; y = f || 7; let z = null; z = z ?? 3; const o = { p: { q: 4 } }; let w = 0; w = o?.p?.q; let v = 9; v = (void 0)?.p; return [x, y, z, w, v].join(); }
function throwing() {
  let x = 1;
  const bad = { get p() { throw new Error('g'); } };
  try { x = bad.p; } catch (e) { out.push('get:' + x); }
  function boom() { throw 7; }
  try { x = boom(); } catch (e) { out.push('call:' + x); }
  const vo = { valueOf() { throw 8; } };
  try { x = vo + 1; } catch (e) { out.push('valueOf:' + x); }
  try { x = undefinedName + 1; } catch (e) { out.push('ref:' + x); }
  try { let y = 2; y = bad.p; } catch (e) { out.push('decl'); }
  return x;
}
function calls(n) { function f(v) { return v + 1; } let s = 0; for (let i = 0; i < n; i++) s = f(s); return s; }
function linked() { let o = { v: 1, next: { v: 2, next: { v: 3, next: null } } }; let sum = 0; while (o) { sum += o.v; o = o.next; } return sum; }
function method() { let a = [3, 1, 2]; a = a.slice().sort(); let s = 'x'; s = s.toUpperCase(); const t = `${a}-${s}`; return t; }
function* gen(n) { let x = 0; x = yield x + 1; x = x * n; yield x; }
function fin(a) { let x = a; try { x = x + 1; return x; } finally { x = x * 100; out.push('fin' + x); } }
function shortLived(n) { let r = 0; for (let i = 0; i < n; i++) { let tmp = i * 3; tmp = tmp + 1; r += tmp; } return r; }
function swap(a, b) { let t = a; a = b; b = t; return a + ':' + b; }
function templ() { let n = 0; const o = { toString() { n++; return 'o'; } }; let s = ''; s = `${o}${o}`; return s + n; }
function unary(v) { let k; k = typeof v; let m; m = -v; let b; b = !v; let c; c = ~v; return k + m + b + c; }
function closure(a) { let z = a; const g = () => z; z = a + 5; return g(); }
function cmp(a, b) { let r; r = a < b; let e; e = a === b; let i; i = 'x' in { x: 1 }; return [r, e, i].join(); }
function argsStore(a, b) { a = b + 1; b = a * 2; return a + '/' + b + '/' + arguments.length; }
function seqStore(a) { let x = 0; x = (a++, a + 1); return x + ',' + a; }
const gi = gen(3); const g1 = gi.next().value; const g2 = gi.next(5).value;
out.push(arith(5), chain(1), postinc(), selfref(2), cond(true), cond(false), throwing(), calls(10), linked(), method(), g1, g2, fin(1), shortLived(4), swap(1, 2), templ(), unary(3), closure(1), cmp(1, 2), argsStore(1, 2), seqStore(1));
let top = 1; let topT = 0; for (let i = 0; i < 4; i++) { topT = top + i; top = topT * 2; }
let topC = 5; topC = topC > 3 ? topC - 1 : topC + 1;
let topS = 'a'; topS = topS + topS; let topO = { n: { n: null } }; topO = topO.n;
out.push(top, topT, topC, topS, topO.n);
console.log(out.join(' '));
"#;
    assert_eq!(
        console_lines(source),
        [
            r#"get:1 call:1 valueOf:1 ref:1 decl fin200 30,26 4 5,6 5 11,true,3,4, 21,7,3,4, 1 10 6 1,2,3-X 1 15 2 22 2:1 oo2 number-3false-4 6 true,false,true 3/6/2 3,2 38 19 4 aa "#
        ]
    );
}

#[test]
fn arithmetic_and_call_results_are_not_copied_into_their_binding() {
    let body = function_bodies(
        "function g(s, i) { let t = 0; for (let k = 0; k < 3; k++) { t = s + i; s = t * 2 - s; } return t + s; }
function c(n) { function f(v) { return v + 1; } let s = 0; for (let i = 0; i < n; i++) s = f(s); return s; }",
    );
    for pair in body.windows(2) {
        if let (Some(written), Ir3Instruction::Move { src, .. }) =
            (computed_destination(&pair[0]), &pair[1])
        {
            assert_ne!(
                written, *src,
                "result copied by a Move: {pair:?} in {body:?}"
            );
        }
    }
}

#[test]
fn a_conditional_right_hand_side_keeps_its_copy() {
    let body = function_bodies(
        "function h(c) { let x = 0; for (let k = 0; k < 3; k++) { x = c ? k + 1 : k + 2; } return x; }",
    );
    let Some(Ir3Instruction::Return { value }) = body
        .iter()
        .find(|instruction| matches!(instruction, Ir3Instruction::Return { .. }))
    else {
        panic!("no Return in {body:?}");
    };
    assert!(
        body.iter().any(
            |instruction| matches!(instruction, Ir3Instruction::Move { dst, .. } if dst == value)
        ),
        "the joined value is copied into x: {body:?}"
    );
}

#[test]
fn store_results_and_compound_reads_match_node() {
    let source = r#"const out = [];
function make() { return { p: 7, q: { r: 8 } }; }
function storeThenRead() { let o; const v = (o = make()).p; let x; const w = 3 + (x = 4); let k; const obj = { a: 'A' }; const z = obj[(k = 'a')]; return [v, o.q.r, w, x, z, k].join(); }
function retStore(a) { let x = 0; if (a) return x = a * 2; return x; }
function retStoreFinally(a) { let x = 1; try { return x = a + 1; } finally { x = -5; out.push('rf' + x); } }
function meth(o, n) { let s = 0; for (let i = 0; i < n; i++) { s += o.m(i, 1); } return s; }
function selfArg(n) { function f(v) { return v * 2; } let s = 1; for (let i = 0; i < n; i++) { s += f(s); } return s; }
function captured() { let s = 1; const h = () => { s = 100; return 1; }; s += h(); return s; }
function writesInRhs() { let s = 1; s += (s = 10) + 1; let t = 2; t *= t++ + 1; return s + ',' + t; }
function compoundMethod(a) { let acc = ''; for (const x of a) { acc += x.toUpperCase(); } return acc; }
function minus(o) { let s = 100; s -= o.v(); s *= o.v(); s /= o.v(); return s; }
function throwsInRhs() { let s = 5; const o = { m() { throw new Error('x'); } }; try { s += o.m(); } catch (e) { out.push('kept' + s); } return s; }
out.push(storeThenRead(), retStore(3), retStore(0), retStoreFinally(4), meth({ m(a, b) { return a + b; } }, 4), selfArg(4), captured(), writesInRhs(), compoundMethod(['a', 'b', 'c']), minus({ v() { return 2; } }), throwsInRhs());
let ts = 0; const to = { m(a) { return a * 3; } }; for (let i = 0; i < 3; i++) { ts += to.m(i); } let tk; const tv = ({ a: 9 })[(tk = 'a')];
out.push(ts, tv, tk);
console.log(out.join(' '));
"#;
    assert_eq!(
        console_lines(source),
        [r#"rf-5 kept5 7,8,7,4,A,a 6 0 5 10 81 2 12,6 ABC 98 5 9 9 a"#]
    );
}

#[test]
fn a_method_call_compound_writes_its_binding_in_place() {
    let body = function_bodies(
        "function m(o, n) { let s = 0; for (let i = 0; i < n; i++) { s += o.m(i, 1); } return s; }",
    );
    let adds: Vec<_> = body
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::Add { dst, lhs, .. } => Some((*dst, *lhs)),
            _ => None,
        })
        .collect();
    assert_eq!(adds.len(), 1, "{body:?}");
    let (dst, s_register) = adds[0];
    assert_eq!(dst, s_register, "the Add writes s's register: {body:?}");
    assert!(
        !body.iter().any(
            |instruction| matches!(instruction, Ir3Instruction::Move { src, .. } if *src == s_register)
        ),
        "s is read in place, not copied: {body:?}"
    );
    // The method lookup reads the receiver's register as stored, with no
    // copy between the store and the GetProperty.
    let get = body
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::GetProperty { .. }))
        .expect("the method lookup");
    let Ir3Instruction::GetProperty { obj, .. } = body[get] else {
        unreachable!()
    };
    let receiver_store = body[..get]
        .iter()
        .rev()
        .find_map(|instruction| match instruction {
            Ir3Instruction::Move { dst, src } => Some((*dst, *src)),
            _ => None,
        })
        .expect("the receiver store");
    assert_eq!(
        receiver_store,
        (obj, 0),
        "receiver store then lookup: {body:?}"
    );
    // The call reads the receiver local itself, not a reloaded copy.
    assert!(
        body.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::CallMethod { receiver, .. } if *receiver == obj
        )),
        "the call's receiver is the receiver local: {body:?}"
    );
}

/// Callees and method-call receivers read in place: a callee or receiver the
/// arguments reassign keeps the value read before them, nested and chained
/// method calls, a computed method key, a short-lived local as callee, yields
/// in an argument list, optional calls, a throwing argument. Node v22.2.0
/// prints the line, as did the n65 frankenctl before this change (Bun 1.4.3
/// agrees except where it runs the file as strict code, `g()` throwing, and
/// prints function sources with double quotes).
#[test]
fn callees_and_receivers_match_node() {
    let source = r#"const out = [];
function reassignCallee() { let f = (x) => 'f' + x; const g = (x) => 'g' + x; return f(f = g) + ',' + f(1); }
function reassignReceiver() { let o = { n: 'A', m(x) { return this.n + (typeof x === 'object' ? x.n : x); } }; const other = { n: 'B', m() { return 'other'; } }; return o.m(o = other) + ',' + o.m(); }
function nested() { const o = { v: 2, m(x) { return this.v * x; } }; const p = { v: 5, m(x) { return this.v + x; } }; return [o.m(o.m(3)), o.m(p.m(1)), p.m(o.m(p.m(0)))].join(); }
function chained() { const a = { b: { c(x) { return x + 1; }, d: { e(y) { return this === a.b.d ? y * 10 : -1; } } } }; return a.b.c(1) + a.b.d.e(2); }
function computedKey() { const o = { mx(v) { return v + 'x'; }, my(v) { return v + 'y'; } }; let k = 'm'; return o[k + 'x'](1) + o[(k = 'my')](2) + k; }
function shortLivedCallee(n) { let r = 0; for (let i = 0; i < n; i++) { const h = (v) => v * i; r += h(2); } return r; }
function* genArgs() { const o = { m(a, b) { return a + ':' + b; } }; const r = o.m(yield 1, yield 2); yield r; }
function optionalCalls() { const o = { m(x) { return x * 2; } }; const n = null; return [o?.m(4), n?.m(5), o.m?.(6)].join(); }
function pushLen() { const arr = []; for (let i = 0; i < 4; i++) arr.push(arr.length * 10); return arr.join('-'); }
function throwingArgs() { let f = (x) => 'called' + x; const bad = { get v() { throw new Error('arg'); } }; try { f(bad.v); } catch (e) { out.push('argthrow:' + f(0)); } return 'ok'; }
function thisInCallee() { const o = { k: 7, get() { return this.k; } }; const g = o.get; let r; try { r = g(); } catch (e) { r = 'TypeError'; } return o.get() + ',' + r; }
function argsAliasReceiver() { const o = { list: [1], add(x) { this.list.push(x.list.length); return this; } }; return o.add(o).add(o).list.join(); }
const gi = genArgs(); gi.next(); gi.next('A'); const gr = gi.next('B').value;
out.push(reassignCallee(), reassignReceiver(), nested(), chained(), computedKey(), shortLivedCallee(4), gr, optionalCalls(), pushLen(), throwingArgs(), thisInCallee(), argsAliasReceiver());
let tf = (x) => x + 1; let tr = tf(tf = (x) => x * 100); const to = { v: 3, m(x) { return this.v + x; } }; let tsum = 0; for (let i = 0; i < 3; i++) { tsum += to.m(to.m(i)); }
out.push(tr, tf(2), tsum);
console.log(out.join(' '));
"#;
    assert_eq!(
        console_lines(source),
        [
            r#"argthrow:called0 f(x) => 'g' + x,g1 AB,other 12,12,15 22 1x2ymy 12 A:B 8,,12 0-10-20-30 ok 7,undefined 1,1,2 (x) => x * 1001 200 21"#
        ]
    );
}
