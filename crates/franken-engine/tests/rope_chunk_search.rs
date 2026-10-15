//! End-to-end expectations shared with the Node reference fixtures.
use frankenengine_engine::HybridRouter;

#[test]
fn rope_search_keeps_utf16_positions_crossings_and_fallbacks() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/rope_chunk_search.json"
    )).expect("valid rope-search fixture");
    for case in cases.as_array().expect("case array") {
        let name = case["name"].as_str().expect("name");
        let source = case["source"].as_str().expect("source");
        let expected = case["expected"].as_str().expect("expected");
        let result = HybridRouter::default().eval(source)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(result.value, expected, "{name}");
    }
}
