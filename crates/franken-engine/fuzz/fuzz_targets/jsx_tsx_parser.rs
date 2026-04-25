#![no_main]

use frankenengine_engine::jsx_tsx_parser::{
    JsxParseError, JsxParseResult, JsxParserConfig, JsxRuntimeMode, parse_jsx,
};
use libfuzzer_sys::fuzz_target;

/// Assert structural invariants that hold for every Ok/Err the parser returns.
fn check_result_invariants(result: &Result<JsxParseResult, JsxParseError>) {
    match result {
        Ok(parse_result) => {
            // Successful parse must round-trip through JSON without panicking.
            let serialized = serde_json::to_string(parse_result)
                .expect("JsxParseResult should always serialize");
            let _deserialized: serde_json::Value = serde_json::from_str(&serialized)
                .expect("Serialized JsxParseResult should deserialize");
        }
        Err(err) => {
            // Error must round-trip through JSON without panicking.
            let _serialized =
                serde_json::to_string(err).expect("JsxParseError should always serialize");

            // Display must never panic and must produce a non-empty message.
            let display = format!("{err}");
            assert!(
                !display.is_empty(),
                "JsxParseError Display should produce a non-empty message"
            );

            // Structural invariant: FailClosed must carry at least one diagnostic.
            if let JsxParseError::FailClosed { diagnostics } = err {
                assert!(
                    !diagnostics.is_empty(),
                    "FailClosed errors must carry at least one diagnostic"
                );
            }
        }
    }
}

/// Re-run the parser with the same input/config and assert byte-for-byte determinism.
fn check_determinism(
    source: &str,
    config: &JsxParserConfig,
    first: &Result<JsxParseResult, JsxParseError>,
) {
    let second = parse_jsx(source, config);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "Parser should be deterministic across re-parses for the same input/config"
    );
    match (first, &second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.node, b.node, "Deterministic parse: node mismatch");
            assert_eq!(
                a.diagnostics, b.diagnostics,
                "Deterministic parse: diagnostics mismatch"
            );
            assert_eq!(
                a.feature_families_used, b.feature_families_used,
                "Deterministic parse: feature_families_used mismatch"
            );
        }
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "Deterministic parse: error mismatch");
        }
        _ => unreachable!("is_ok() guarded above"),
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing.
    if data.is_empty() || data.len() > 4096 {
        return;
    }

    let source = String::from_utf8_lossy(data);

    // Configs we exercise on every input (cheap; covers the public surface).
    let config_default = JsxParserConfig::default();
    let config_tsx = JsxParserConfig {
        tsx_mode: true,
        ..JsxParserConfig::default()
    };
    let config_classic = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        ..JsxParserConfig::default()
    };
    let config_namespaced = JsxParserConfig {
        allow_namespaced_names: true,
        ..JsxParserConfig::default()
    };

    let configs: [(&str, &JsxParserConfig); 4] = [
        ("default", &config_default),
        ("tsx", &config_tsx),
        ("classic", &config_classic),
        ("namespaced", &config_namespaced),
    ];

    // Invariant: parsing never panics; serde and Display contracts hold; FailClosed carries
    // diagnostics; and the same input + same config produces byte-identical output across reparses.
    for (_label, config) in &configs {
        let result = parse_jsx(&source, config);
        check_result_invariants(&result);
        check_determinism(&source, config, &result);
    }

    // Depth-limit branch: very small max_depth must still uphold all invariants
    // (and is the cheapest way to drive the DepthExceeded error path during fuzzing).
    if source.len() < 100 {
        let config_shallow = JsxParserConfig {
            max_depth: 2,
            ..JsxParserConfig::default()
        };
        let result_shallow = parse_jsx(&source, &config_shallow);
        check_result_invariants(&result_shallow);
        check_determinism(&source, &config_shallow, &result_shallow);
    }
});
