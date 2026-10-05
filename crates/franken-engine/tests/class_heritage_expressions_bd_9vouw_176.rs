#![forbid(unsafe_code)]

//! bd-9vouw.176: a class whose heritage holds braces, and a numeric literal
//! that starts with its decimal point and has a separator, parse.
//!
//! A class expression's body was taken to start at its first `{`, so
//! `class extends class {} {}` and `class extends (() => {}) {}` were not
//! whole class expressions and became an unsupported-syntax value (a
//! SyntaxError when evaluated). A function-expression heritage
//! (`class D extends function () {} {}`) failed to parse even as a
//! declaration. `.0_1e2` was rejected because a separator was only accepted
//! after a leading digit. The expected lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

const PROGRAM: &str = r#"const A = class extends class { m() { return 'm'; } } { n() { return this.m() + 'n'; } };
const B = class extends (function () { this.base = 1; }) { constructor() { super(); this.own = 2; } };
const C = class Named extends function () {} {};
class D extends function () { this.d = 4; } { get d2() { return this.d * 2; } }
const mixin = (Base) => class extends Base { mixed() { return 'mixed'; } };
const E = class extends mixin(class { base() { return 'base'; } }) {};
const F = class extends (async () => {}, Object) {};
console.log(new A().n(), A.name, JSON.stringify(new B()), C.name, new D().d2, new E().mixed(), new E().base(), F.name);
console.log(typeof class extends (Object) {}, (class {}).name === '', [class extends Array {}].length);
const G = class extends async function () {}.constructor {};
console.log(typeof G);
console.log(.0_1e2, .1_01e2, .00_01e2, .5_5, 1_0.2_5);
"#;

#[test]
fn heritage_braces_and_leading_dot_separators_parse_and_run() {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(PROGRAM).expect("the program runs");
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "mn A {\"base\":1,\"own\":2} Named 8 mixed base F",
            "function true 1",
            "function",
            "1 10.1 0.01 0.55 10.25",
        ]
    );
}

/// Class elements whose private name uses a non-alphanumeric ID_Start letter
/// (`#\u2118`, U+2118) or `\u{..}` escapes, and computed keys holding a
/// function body: the class body is split and the names read as Node reads
/// them (Test262 class elements `*-grammar-privatename-*`, `cpn-*`).
#[test]
fn private_names_with_unicode_letters_and_escapes() {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(PRIVATE_NAMES).expect("the program runs");
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        ["o,p,zwnj,s,getter arrow key computed getter method",]
    );
}

const PRIVATE_NAMES: &str = r#"var C = class {
  #\u{6F} = 'o';
  #\u2118 = 'p';
  #ZW_\u200C_NJ = 'zwnj';
  static #\u{73} = 's';
  get #\u{67}() { return 'getter'; }
  [(() => 'computed')()]() { return 'arrow key'; }
  get [function () { return 'gk'; }()]() { return 'computed getter'; }
  read() { return [this.#o, this.#\u2118, this.#ZW_\u200C_NJ, C.#s, this.#g].join(','); }
  \u2118() { return 'method'; }
};
const c = new C();
console.log(c.read(), c.computed(), c.gk, c['\u2118']());
"#;
