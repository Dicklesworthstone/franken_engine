//! Public source evaluator coverage for lazy generic Array iterator creation.
use frankenengine_engine::HybridRouter;

#[test]
fn generic_array_iterators_preserve_live_reads_and_abrupt_order() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/array_iterator_live.json"
    )).expect("iterator fixtures");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("name");
        let source = case["source"].as_str().expect("source");
        // expected is normative. A separately recorded Node discrepancy
        // must never weaken the native assertion or bless an extra Get.
        let expected = case["expected"].as_str().expect("expected");
        let outcome = HybridRouter::default().eval(source)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(outcome.value, expected, "{name}");
    }
}
