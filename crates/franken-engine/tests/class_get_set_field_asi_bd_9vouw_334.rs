//! bd-9vouw.334: a class element `get` or `set` followed by a line break and
//! `*` is a field named get or set and, by ASI, a generator method: an
//! accessor cannot be a generator. The parser read `set <LF> *c() {}` as a
//! setter (and refused the program) and `get <LF> *a() {}` as a getter
//! named `*a`. The program also keeps the forms that do continue across a
//! line break: `static <LF> *g() {}` (one static generator), `get <LF> x()`
//! and `set <LF> y(v)` (accessors). Node v22.2.0 gives this line; Bun 1.4.2
//! agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn get_and_set_before_a_generator_are_fields() {
    let source = r#"
var out = [];
class A {
  get
  *a() { yield 1; }
}
var x = new A();
out.push(Object.prototype.hasOwnProperty.call(x, 'get'), typeof A.prototype.a, A.prototype.a.constructor.name);
class B {
  static get
  *b() {}
  set
  *c() {}
}
out.push(Object.prototype.hasOwnProperty.call(B, 'get'), typeof B.prototype.b, Object.prototype.hasOwnProperty.call(new B(), 'set'), typeof B.prototype.c);
class C {
  static
  *g() { yield 2; }
  get
  x() { return 3; }
  set
  y(v) { this._y = v; }
}
var c = new C();
c.y = 4;
out.push(C.g().next().value, c.x, c._y, Object.getOwnPropertyDescriptor(C.prototype, 'x').get !== undefined);
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
        ["true function GeneratorFunction true function true function 2 3 4 true"]
    );
}
