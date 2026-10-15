//! Exact mixed numeric ordering through the production source evaluator.
use frankenengine_engine::HybridRouter;

#[test]
fn bigint_number_order_keeps_precision_and_observable_coercions() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/bigint_number_order.json"
    ))
    .expect("valid mixed numeric cases");
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
