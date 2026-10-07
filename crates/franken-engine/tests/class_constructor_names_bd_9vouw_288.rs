#![forbid(unsafe_code)]

//! bd-9vouw.288: a class method named `constructor` was always taken for
//! the class constructor, so `static constructor() {}` (and its accessor,
//! generator and async forms) was lost, while `get constructor() {}` was
//! accepted (10 Node-passing Test262 grammar-static-ctor-*-valid tests).

use frankenengine_engine::HybridRouter;

/// Static `constructor` methods, accessors and generators are own members
/// of the class beside its real constructor; a quoted `'constructor'`
/// method is the constructor; a non-static getter, setter, generator or
/// async method named `constructor` and a static member named `prototype`
/// are SyntaxErrors, a computed `["constructor"]` getter is not. Expected
/// lines are Node v22.2.0's output, captured programmatically (Bun 1.4.2
/// agrees).
#[test]
fn class_constructor_names_match_node_bd_9vouw_288() {
    let source = r#"class C {
  static constructor() { return 'static'; }
  constructor() { this.made = true; }
}
class D {
  static get constructor() { return 'getter'; }
  static set constructor(_) {}
  constructor() {}
}
class E {
  static *constructor() { yield 1; }
}
class Q {
  'constructor'() { this.quoted = 1; }
}
console.log(C.hasOwnProperty('constructor'), C.prototype.hasOwnProperty('constructor'), C.prototype.constructor === C, C.constructor === C.prototype.constructor, C.constructor(), new C().made, Object.getOwnPropertyNames(C).join());
console.log(D.hasOwnProperty('constructor'), D.constructor, typeof Object.getOwnPropertyDescriptor(D, 'constructor').set, D.prototype.constructor === D);
console.log(E.hasOwnProperty('constructor'), E.constructor().next().value, E.prototype.constructor === E, new Q().quoted, Q.prototype.constructor === Q);
function syntax(source) { try { new Function(source); return 'ok'; } catch (e) { return e.constructor.name; } }
console.log(syntax('class A { get constructor() {} }'), syntax('class A { set constructor(v) {} }'), syntax('class A { *constructor() {} }'), syntax('class A { async constructor() {} }'), syntax('class A { static prototype() {} }'), syntax('class A { static get prototype() {} }'), syntax('class A { prototype() {} }'), syntax('class A { static constructor() {} constructor() {} }'), syntax('class A { ["constructor"]() {} get ["constructor"]() {} }'));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "true true true false static true length,name,prototype,constructor",
            "true getter function true",
            "true 1 true 1 true",
            "SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError ok ok ok",
        ]
    );
}
