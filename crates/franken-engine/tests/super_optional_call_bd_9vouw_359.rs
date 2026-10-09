//! bd-9vouw.359 follow-up: `super.m?.(...)` calls the [[HomeObject]]
//! prototype's method with this activation's `this`, as `super.m(...)`
//! does (Test262 optional-chaining/super-property-optional-call). The
//! optional chain lowering leaves a `super` prefix to the plain OptionalCall
//! lowering, which evaluated `super.m` as a value and called it without a
//! receiver, so the method read `this.tag` from undefined. Covers fixed and
//! spread arguments, a missing method (undefined), a computed key, an
//! arrow inside the method, and an object literal method. The line is Node
//! v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn super_optional_calls_keep_this() {
    let source = r#"
var out = [];
class Base {
  method(a, b) { return [this.tag, a, b, arguments.length].join(':'); }
  get prop() { return 'P' + this.tag; }
}
class Foo extends Base {
  constructor() { super(); this.tag = 'foo'; }
  plain() { return super.method?.(1, 2); }
  spread() { return super.method?.(...[3, 4, 5]); }
  missing() { return super.nope?.(1); }
  computed() { var k = 'method'; return super[k]?.(6); }
  arrow() { return (() => super.method?.(7))(); }
}
var foo = new Foo();
out.push(foo.plain(), foo.spread(), String(foo.missing()), foo.computed(), foo.arrow());
var obj = { __proto__: { greet(n) { return 'hi ' + n + ' ' + this.name; } }, name: 'o', run() { return super.greet?.('x'); } };
out.push(obj.run());
console.log(out.join(' | '));
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
        ["foo:1:2:2 | foo:3:4:3 | undefined | foo:6::1 | foo:7::1 | hi x o"]
    );
}
