//! bd-9a8cz.4 regression: JSON.parse must parse objects and arrays (not just
//! scalars). Previously builtin:JsonParse handled only null/bool/string/number
//! and returned undefined for {}/[], so `JSON.parse("[1,2,3]").length` faulted.
//!
//! NOTE: JS string literals use SINGLE quotes here so the embedded JSON's double
//! quotes need no `\"` escaping — escaped quotes inside a double-quoted JS string
//! literal are mishandled by the engine's lexer (a separate pre-existing bug,
//! see jh_escaped_quote_probe below), which would corrupt the JSON input before
//! JSON.parse ever runs.

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> String {
    let mut r = HybridRouter::default();
    match r.eval(src) {
        Ok(o) => o.value,
        Err(e) => panic!("expected Ok for {src:?}, got Err: {e:?}"),
    }
}

#[test]
fn parse_array_length() {
    assert_eq!(eval_ok("JSON.parse('[1,2,3]').length;"), "3");
}

#[test]
fn parse_array_element() {
    assert_eq!(eval_ok("JSON.parse('[10,20,30]')[1];"), "20");
}

#[test]
fn parse_object_property() {
    assert_eq!(eval_ok("JSON.parse('{\"a\":1,\"b\":2}').a;"), "1");
    assert_eq!(
        eval_ok("let o=JSON.parse('{\"a\":1,\"b\":2}'); o.a + o.b;"),
        "3"
    );
}

#[test]
fn parse_object_string_value() {
    assert_eq!(eval_ok("JSON.parse('{\"s\":\"hello\"}').s;"), "hello");
}

#[test]
fn parse_nested() {
    assert_eq!(
        eval_ok("JSON.parse('{\"xs\":[1,2,{\"y\":7}]}').xs[2].y;"),
        "7"
    );
}

#[test]
fn parse_scalars_still_work() {
    assert_eq!(eval_ok("JSON.parse('42');"), "42");
    assert_eq!(eval_ok("JSON.parse('true');"), "true");
    assert_eq!(eval_ok("JSON.parse('null');"), "null");
    assert_eq!(eval_ok("JSON.parse('3.5');"), "3.5");
    assert_eq!(eval_ok("JSON.parse('\"hi\"');"), "hi");
}

#[test]
fn parse_empty_containers() {
    assert_eq!(eval_ok("JSON.parse('[]').length;"), "0");
    assert_eq!(eval_ok("typeof JSON.parse('{}');"), "object");
}

#[test]
fn parse_roundtrip() {
    assert_eq!(
        eval_ok("let o={a:1,b:2}; JSON.parse(JSON.stringify(o)).b;"),
        "2"
    );
}

#[test]
fn parse_whitespace_tolerant() {
    assert_eq!(eval_ok("JSON.parse('  [ 1 , 2 ]  ').length;"), "2");
}

#[test]
fn parse_invalid_yields_undefined() {
    // Preserved pre-existing simplified error policy (spec throws SyntaxError).
    assert_eq!(eval_ok("typeof JSON.parse('{bad');"), "undefined");
    assert_eq!(eval_ok("typeof JSON.parse('[1,2');"), "undefined");
}

/// Diagnostic (non-asserting): confirms the separate escaped-quote bug — a
/// double-quoted JS string literal containing `\"` is mislexed. Printed for the
/// defect bead; does not gate the JSON.parse fix.
#[test]
fn jh_escaped_quote_probe() {
    let mut r = HybridRouter::default();
    for (label, src) in [
        ("dquote-escaped-quote", "let x = \"a\\\"b\"; x.length;"), // want 3
        ("squote-with-dquote", "let x = 'a\"b'; x.length;"),       // want 3
        ("dquote-newline-escape", "let x = \"a\\nb\"; x.length;"), // want 3
    ] {
        match r.eval(src) {
            Ok(o) => eprintln!("[{label}] OK value={} <<{src}>>", o.value),
            Err(e) => eprintln!("[{label}] ERR {e} <<{src}>>"),
        }
    }
}
