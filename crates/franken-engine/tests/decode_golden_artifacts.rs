#![forbid(unsafe_code)]

//! Golden Artifact Testing for Decode Operations
//!
//! Locks down deterministic output of decode/encode operations to catch
//! unintentional changes in serialization format or behavior.
//!
//! Pattern: Exact Golden (Pattern 1) with scrubbing for non-deterministic values.

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaRegistry, decode_value, encode_value, serialize_with_schema,
};

// bd-ub6x8.21 (sub: bd-drdxa): migrated from the shared GoldenDiag helper
// (which read/wrote tests/golden/<name>.golden via UPDATE_GOLDENS=1) to
// `insta::assert_snapshot!`. Fixtures now live under
// tests/snapshots/decode_golden_artifacts__<name>.snap, reviewed via
// `cargo insta review` (or regenerated via `INSTA_UPDATE=always cargo test
// --test decode_golden_artifacts`).

// Render a `CanonicalValue` via its `Serialize` impl (a stable contract), not
// Rust's `Debug` (which is not a stability contract). bd-ub6x8.9.1.
fn render_value(value: &CanonicalValue) -> String {
    serde_json::to_string(value).expect("CanonicalValue is always JSON-serializable")
}

// Render a byte slice as `[0xHH, 0xHH, ...]` — lower-case, two-hex-digit per
// byte, stable across compiler / Debug-impl changes. bd-ub6x8.9.1.
fn render_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 6);
    out.push('[');
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{byte:02x}"));
    }
    out.push(']');
    out
}

/// Generate deterministic synthetic value from seed
fn synthetic_value(seed: u8) -> CanonicalValue {
    match seed % 5 {
        0 => CanonicalValue::U64(u64::from(seed)),
        1 => CanonicalValue::Bytes((0..8).map(|i| seed.wrapping_add(i)).collect()),
        2 => CanonicalValue::String(
            (0..8)
                .map(|i| char::from(b'a' + ((seed.wrapping_add(i)) % 26)))
                .collect(),
        ),
        3 => CanonicalValue::Array(
            (0..4)
                .map(|i| CanonicalValue::U64(u64::from(seed.wrapping_add(i))))
                .collect(),
        ),
        _ => {
            let mut map = BTreeMap::new();
            for i in 0..3 {
                map.insert(
                    format!("k{:02x}", i),
                    CanonicalValue::U64(u64::from(seed.wrapping_add(i))),
                );
            }
            CanonicalValue::Map(map)
        }
    }
}

#[test]
fn test_decode_encode_roundtrip_golden() {
    let mut output = String::new();

    // Test with a fixed set of seeds for deterministic output
    for seed in [0, 1, 42, 127, 255] {
        let original = synthetic_value(seed);
        output.push_str(&format!("=== Seed {} ===\n", seed));

        // Show original value (serde_json: stable, not Debug).
        output.push_str(&format!("Original: {}\n", render_value(&original)));

        // Encode -> Decode roundtrip
        let encoded = encode_value(&original);
        output.push_str(&format!("Encoded bytes: {} bytes\n", encoded.len()));

        match decode_value(&encoded) {
            Ok(decoded) => {
                output.push_str(&format!("Decoded: {}\n", render_value(&decoded)));
                output.push_str(&format!("Roundtrip OK: {}\n", original == decoded));
            }
            Err(e) => {
                output.push_str(&format!("Decode Error: {e}\n"));
            }
        }

        // Schema-based serialization test
        let mut registry = SchemaRegistry::new();
        let schema = registry.register(
            &format!("test.seed_{}", seed),
            1,
            format!("test.seed_{}.v1", seed).as_bytes(),
        );

        let schema_encoded = serialize_with_schema(&schema, &original);
        output.push_str(&format!("Schema encoded: {} bytes\n", schema_encoded.len()));

        match registry.deserialize_checked(&schema_encoded) {
            Ok((_schema_def, schema_decoded)) => {
                output.push_str(&format!(
                    "Schema decoded: {}\n",
                    render_value(&schema_decoded)
                ));
                output.push_str(&format!(
                    "Schema roundtrip OK: {}\n",
                    original == schema_decoded
                ));
            }
            Err(e) => {
                output.push_str(&format!("Schema decode error: {e}\n"));
            }
        }

        output.push('\n');
    }

    insta::assert_snapshot!("decode_encode_roundtrip", output);
}

#[test]
fn test_malformed_input_behavior_golden() {
    let mut output = String::new();

    // Test behavior on known malformed inputs
    let malformed_inputs = [
        vec![],                             // Empty
        vec![0xFF],                         // Single invalid byte
        vec![0x04, 0xFF, 0xFF, 0xFF, 0xFF], // Malformed length prefix (from original test)
        vec![0x01, 0x02, 0x03],             // Too short
        vec![0x00; 100],                    // All zeros
    ];

    for (i, input) in malformed_inputs.iter().enumerate() {
        output.push_str(&format!("=== Malformed input {} ===\n", i));
        output.push_str(&format!("Input: {}\n", render_bytes(input)));

        match decode_value(input) {
            Ok(decoded) => {
                output.push_str(&format!("Decoded: {}\n", render_value(&decoded)));
            }
            Err(e) => {
                output.push_str(&format!("Error: {e}\n"));
            }
        }
        output.push('\n');
    }

    insta::assert_snapshot!("malformed_input_behavior", output);
}

#[test]
fn test_schema_hash_determinism_golden() {
    let mut output = String::new();

    // Test that schema hashing is deterministic
    let test_schemas = [
        ("simple", "simple.v1"),
        ("complex", "complex.metadata.v2"),
        ("unicode", "tëst.schéma.v1"),
        ("numbers", "schema123.v456"),
        ("empty", ""),
    ];

    for (name, schema_bytes) in test_schemas {
        output.push_str(&format!("=== Schema: {} ===\n", name));
        output.push_str(&format!(
            "Schema bytes: {}\n",
            render_bytes(schema_bytes.as_bytes())
        ));

        let mut registry = SchemaRegistry::new();
        let schema = registry.register(name, 1, schema_bytes.as_bytes());
        // `SchemaHash` Display impl is lower-case hex — a stable contract,
        // distinct from `Debug`'s `SchemaHash([byte; 32])` rendering.
        output.push_str(&format!("Schema hash: {schema}\n"));
        output.push('\n');
    }

    insta::assert_snapshot!("schema_hash_determinism", output);
}
