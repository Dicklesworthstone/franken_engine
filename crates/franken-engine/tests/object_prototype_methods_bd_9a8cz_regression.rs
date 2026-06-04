//! Regression coverage for bd-9a8cz.5: Object.prototype instance methods must
//! resolve through member access on ordinary heap objects. Before this fallback,
//! `o.hasOwnProperty("x")` and siblings resolved to `undefined` even though the
//! corresponding builtin hostcall arms already existed.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    engine
        .eval(src)
        .unwrap_or_else(|err| panic!("eval failed for {src:?}: {err}"))
        .value
}

#[test]
fn has_own_property_checks_own_data_properties() {
    assert_eq!(
        eval_value("let o = {a: 1, b: 2}; o.hasOwnProperty(\"a\");"),
        "true"
    );
    assert_eq!(
        eval_value("let o = {a: 1}; o.hasOwnProperty(\"missing\");"),
        "false"
    );
}

#[test]
fn property_is_enumerable_matches_own_heap_properties() {
    assert_eq!(
        eval_value("let o = {a: 1}; o.propertyIsEnumerable(\"a\");"),
        "true"
    );
    assert_eq!(
        eval_value("let o = {a: 1}; o.propertyIsEnumerable(\"missing\");"),
        "false"
    );
}

#[test]
fn value_of_returns_the_receiver_object() {
    assert_eq!(
        eval_value("let o = {answer: 42}; o.valueOf().answer;"),
        "42"
    );
}

#[test]
fn to_string_returns_object_tag() {
    assert_eq!(
        eval_value("let o = {a: 1}; o.toString();"),
        "[object Object]"
    );
}

#[test]
fn own_properties_shadow_object_prototype_methods() {
    assert_eq!(
        eval_value("let o = {a: 1}; o.hasOwnProperty = 7; o.hasOwnProperty;"),
        "7"
    );
    assert_eq!(
        eval_value("let o = {a: 1}; o.toString = \"custom\"; o.toString;"),
        "custom"
    );
}

#[test]
fn array_exotics_still_inherit_object_prototype_methods() {
    assert_eq!(eval_value("let a = [10]; a.hasOwnProperty(\"0\");"), "true");
    assert_eq!(eval_value("let a = [10]; a.toString();"), "[object Array]");
}
