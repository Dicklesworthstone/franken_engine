//! Unified, live FlattenIntoArray through the public source evaluator.
//! The reference runner consumes the same fixtures; a reference pass is not
//! evidence that this public native evaluator passes them.

use frankenengine_engine::HybridRouter;

#[test]
fn flat_and_flat_map_preserve_observable_traversal_semantics() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/array_flatten_live.json"
    ))
    .expect("valid flatten cases");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("case name");
        let source = case["source"].as_str().expect("JavaScript source");
        let expected = case["expected"].as_str().expect("fixed reference result");
        let outcome = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("{name}: native execution failed: {error:?}"));
        assert_eq!(outcome.value, expected, "{name}");
    }
}
