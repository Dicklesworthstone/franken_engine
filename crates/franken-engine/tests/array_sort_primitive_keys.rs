//! Primitive default-sort specialization through the public source evaluator.
//! The same cases run against V8 with scripts/check_sort_primitive_keys.cjs.

use frankenengine_engine::HybridRouter;

#[test]
fn default_sort_keeps_primitive_keys_and_observable_fallback_semantics() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/array_sort_primitive_keys.json"
    ))
    .expect("valid primitive-sort cases");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("case name");
        let source = case["source"].as_str().expect("JavaScript source");
        let expected = case["expected"].as_str().expect("reference result");
        let outcome = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("{name}: native execution failed: {error:?}"));
        assert_eq!(outcome.value, expected, "{name}");
    }
}
