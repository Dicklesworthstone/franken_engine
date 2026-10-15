//! The generic Array sorter must keep observable capture/writeback behavior.
use frankenengine_engine::HybridRouter;

#[test]
fn adaptive_default_sort_preserves_generic_array_observations() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/array_sort_adaptive.json"
    ))
    .expect("valid adaptive sort fixtures");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("case name");
        let source = case["source"].as_str().expect("source");
        let expected = case["expected"].as_str().expect("reference result");
        let actual = HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(actual.value, expected, "{name}");
    }
}
