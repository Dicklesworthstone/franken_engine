#![no_main]

use frankenengine_engine::jsx_tsx_parser::{parse_jsx, JsxParserConfig, JsxRuntimeMode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing
    if data.is_empty() || data.len() > 4096 {
        return;
    }

    let source = String::from_utf8_lossy(data);

    // Test with default config (automatic runtime, non-TSX)
    let config_default = JsxParserConfig::default();
    let result_default = parse_jsx(&source, &config_default);

    // Test with TSX mode enabled
    let config_tsx = JsxParserConfig {
        tsx_mode: true,
        ..JsxParserConfig::default()
    };
    let result_tsx = parse_jsx(&source, &config_tsx);

    // Test with classic runtime mode
    let config_classic = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        ..JsxParserConfig::default()
    };
    let result_classic = parse_jsx(&source, &config_classic);

    // Test with namespaced names allowed
    let config_namespaced = JsxParserConfig {
        allow_namespaced_names: true,
        ..JsxParserConfig::default()
    };
    let result_namespaced = parse_jsx(&source, &config_namespaced);

    // Invariant: Parser should never panic regardless of input
    // Results can be Ok or Err, both are valid outcomes

    // If parsing succeeds, verify round-trip serialization of results
    if let Ok(parse_result) = &result_default {
        let serialized = serde_json::to_string(parse_result)
            .expect("JsxParseResult should always serialize");
        let _deserialized: serde_json::Value = serde_json::from_str(&serialized)
            .expect("Serialized JsxParseResult should deserialize");
    }

    // Invariant: Same input should produce same result (deterministic parsing)
    let result_default_2 = parse_jsx(&source, &config_default);
    assert_eq!(result_default.is_ok(), result_default_2.is_ok(),
               "Parser should be deterministic for same input and config");

    // If both succeeded, the results should be identical
    if let (Ok(r1), Ok(r2)) = (&result_default, &result_default_2) {
        assert_eq!(r1.node, r2.node, "Parse results should be identical for same input");
        assert_eq!(r1.diagnostics, r2.diagnostics, "Diagnostics should be identical for same input");
    }

    // Invariant: Error cases should provide structured diagnostics, not panics
    if let Err(err) = &result_default {
        // Error should serialize without panicking
        let _ = serde_json::to_string(err)
            .expect("JsxParseError should always serialize");
    }

    // Metamorphic relation: If TSX mode accepts input, default mode handling should be consistent
    // (TSX is a superset, so TSX success doesn't guarantee default success, but error patterns should be related)

    // Check that parser handles edge cases gracefully
    if source.len() < 100 {  // Only for small inputs to avoid performance impact
        // Test with reduced max depth
        let config_shallow = JsxParserConfig {
            max_depth: 2,
            ..JsxParserConfig::default()
        };
        let result_shallow = parse_jsx(&source, &config_shallow);

        // Should not panic even with very limited depth
        if let Err(err) = &result_shallow {
            let _ = serde_json::to_string(err)
                .expect("Shallow parse error should serialize");
        }
    }
});