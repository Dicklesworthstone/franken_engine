//! bd-9vouw.317: an arrow function has no new.target of its own; it reads
//! the enclosing non-arrow function's (ES2020 12.3.8.1 GetNewTarget). It
//! read undefined, the new.target of the arrow's own call frame. The
//! program reads new.target through arrows, nested arrows, a derived class
//! constructor, Reflect.construct, a callback, an async arrow and an arrow
//! returned out of its constructor and called later. It also checks the
//! places where the value must stay undefined: a plain call, a function
//! expression between the constructor and the arrow, a class field
//! initializer and a generator. Node v22.2.0 gives this line; Bun 1.4.2
//! agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn arrow_functions_read_the_enclosing_new_target() {
    let source = r#"
var out = [];
function n(v) { return v === undefined ? 'undefined' : typeof v === 'function' ? v.name : String(v); }
function F() { var a = () => new.target; out.push(a() === F); }
new F();
function F2() { out.push((() => () => new.target)()() === F2); }
new F2();
class C { constructor() { var a = () => new.target; out.push(a() === D); } }
class D extends C {}
new D();
function H() { return () => new.target; }
out.push(new H()() === H);
function G() { var a = () => new.target; return a(); }
out.push(n(G()));
function R() { out.push((() => new.target)() === Array); }
Reflect.construct(R, [], Array);
function U() { out.push([1].map(() => new.target === U)[0]); }
new U();
function I() { out.push(n((function () { return (() => new.target)(); })())); }
new I();
function O() { class K { f = () => new.target; } out.push(n(new K().f())); }
new O();
function* Gen() { yield (() => new.target)(); }
out.push(n(Gen().next().value));
function W() { var a = () => new.target; return a; }
var w = new W();
out.push(w() === W, w.call({}) === W);
function A2() { return () => [new.target === A2, arguments.length].join(); }
out.push(new A2(1, 2)());
function M() { this.p = (async () => new.target)(); }
new M().p.then(function (v) {
  out.push(v === M);
  console.log(out.join(' '));
});
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
            "true true true true undefined true true undefined undefined undefined true true true,2 true"
        ]
    );
}
