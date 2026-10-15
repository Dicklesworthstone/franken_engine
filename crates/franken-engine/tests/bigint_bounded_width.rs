//! Exercises the production BigInt narrowing entry points and binary stores.
use frankenengine_engine::HybridRouter;

#[test]
fn large_bigints_narrow_without_changing_coercions_or_binary_store_results() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/bigint_bounded_width.json"
    ))
    .expect("valid BigInt narrowing cases");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("case name");
        let source = case["source"].as_str().expect("JavaScript source");
        let expected = case["expected"].as_str().expect("expected result");
        let actual = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(actual.value, expected, "{name}");
    }
}
