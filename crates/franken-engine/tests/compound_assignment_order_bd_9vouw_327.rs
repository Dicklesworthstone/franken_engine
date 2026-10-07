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
