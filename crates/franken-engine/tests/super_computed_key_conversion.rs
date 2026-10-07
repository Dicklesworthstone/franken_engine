#![forbid(unsafe_code)]

//! A computed super member assignment converts its key with ToPropertyKey at
//! each read and write (as GetValue / PutValue do), not once up front: a
//! simple assignment converts after its right-hand side (a throwing key
//! toString loses to a throwing right-hand side, Test262
//! assignment/target-super-computed-reference), a compound one converts twice
//! and a short-circuiting `||=` once; the key expression itself still runs
//! before the right-hand side.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn super_computed_key_converts_at_each_access() {
    let source = r#"var n = 0; var k = { toString: function () { n++; return "x"; } };
class B { } B.prototype.x = 1;
class C extends B { m() { super[k] = 5; var a = n; super[k] += 1; var b = n; super[k] ||= 9; return [a, b, n, this.x]; } }
console.log(new C().m().join());
function attempt(f) { try { f(); return 'none'; } catch (e) { return e.name; } }
var throwingKey = { toString: function () { throw new RangeError('key'); } };
class D extends B { m() { super[throwingKey] = (function () { throw new TypeError('rhs'); })(); } }
class E extends B { m() { super[(function () { throw new SyntaxError('expr'); })()] = (function () { throw new TypeError('rhs'); })(); } }
console.log(attempt(function () { new D().m(); }), attempt(function () { new E().m(); }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["1,3,4,2", "TypeError SyntaxError",]);
}
