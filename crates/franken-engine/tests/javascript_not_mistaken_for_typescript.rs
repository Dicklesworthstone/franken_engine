#![forbid(unsafe_code)]
//! Plain JavaScript was classified as TypeScript when a string or regex
//! literal held `!:` (marked's `"!:"`, path-to-regexp's
//! `/[{}()\[\]+?!:*\\]/g`) or a line assigned a variable named `type`
//! (yargs-parser's `type = DefaultValuesForTypeKey.STRING;`). TS
//! normalization then treated class constructor parameters as TypeScript
//! parameter properties and the bundle failed with "invalid assignment
//! target". The sniffing now reads code only (literal text blanked) and a
//! `type` line must declare an alias (`type Name = ...`). Expected values
//! are Node v22.2.0's completion values for the same programs.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn definite_assignment_text_in_literals_keeps_javascript() {
    check(
        "var s = \"!:\"; var C = class { constructor(e) { this.o = e; } }; new C(5).o + s.length",
        "7",
    );
    check(
        "var re = /[!:]/g; class D { constructor(x) { this.x = x; } } \
         \"a!b:c\".replace(re, \"\") + new D(1).x",
        "abc1",
    );
}

#[test]
fn assignment_to_a_variable_named_type_keeps_javascript() {
    check(
        "var type; function f(k) { if (k)\n  type = k;\n return type; } \
         class E { constructor(t) { this.t = t; } } f(\"s\") + new E(2).t",
        "s2",
    );
}
