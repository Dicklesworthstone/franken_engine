//! Regression coverage for bd-n9oxa: existing Array iterator and String
//! prototype builtins were present but unreachable through eval member access,
//! and `Object.fromEntries` was missing from the unbound static-global path.

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => outcome.value.to_string(),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn array_iterator_methods_are_reachable_from_member_access() {
    assert_eq!(eval("[7,8].keys().next().value;"), "0");
    assert_eq!(eval("[7,8].values().next().value;"), "7");
    assert_eq!(
        eval("let pair = [7,8].entries().next().value; pair[0] + pair[1];"),
        "7"
    );
}

#[test]
fn object_from_entries_static_global_is_reachable() {
    assert_eq!(eval("Object.fromEntries([[\"a\",1],[\"b\",2]]).b;"), "2");
    assert_eq!(
        eval("let o = {a:1,b:2}; let x = Object.fromEntries(Object.entries(o)); x.a + x.b;"),
        "3"
    );
}

#[test]
fn string_normalize_and_locale_compare_are_reachable() {
    assert_eq!(eval("\"Cafe\\u0301\".normalize();"), "Caf\u{00e9}");
    assert_eq!(eval("\"a\".localeCompare(\"b\") < 0;"), "true");
    assert_eq!(eval("\"b\".localeCompare(\"a\") > 0;"), "true");
}

#[test]
fn object_from_entries_static_global_is_shadowable() {
    assert_eq!(
        eval("let Object = { fromEntries: () => 9 }; Object.fromEntries([]);"),
        "9"
    );
}
