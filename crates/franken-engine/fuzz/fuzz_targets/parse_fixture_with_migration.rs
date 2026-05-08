#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_engine::e2e_harness::parse_fixture_with_migration;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 12;
const MAX_ARRAY_LEN: usize = 32;
const MAX_OBJECT_LEN: usize = 32;
const MAX_STRING_LEN: usize = 1024;

#[derive(Clone, Debug)]
struct ArbitraryFixtureJson {
    fixture_version: u64,
    fixture_id: String,
    seed: Option<u64>,
    virtual_time_start_micros: Option<u64>,
    policy_id: Option<String>,
    steps: Vec<Value>,
    expected_events: Vec<Value>,
    determinism_check: bool,
    extra_fields: BTreeMap<String, Value>,
}

impl<'a> Arbitrary<'a> for ArbitraryFixtureJson {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            fixture_version: u.arbitrary()?,
            fixture_id: bounded_string(u, MAX_STRING_LEN)?,
            seed: u.arbitrary()?,
            virtual_time_start_micros: u.arbitrary()?,
            policy_id: Option::<String>::arbitrary(u)?.map(|_| bounded_string(u, MAX_STRING_LEN)).transpose()?,
            steps: bounded_json_array(u, MAX_ARRAY_LEN, 0)?,
            expected_events: bounded_json_array(u, MAX_ARRAY_LEN, 0)?,
            determinism_check: u.arbitrary()?,
            extra_fields: bounded_json_object(u, MAX_OBJECT_LEN, 0)?,
        })
    }
}

impl ArbitraryFixtureJson {
    fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();

        obj.insert("fixture_version".to_string(), Value::Number(self.fixture_version.into()));
        obj.insert("fixture_id".to_string(), Value::String(self.fixture_id.clone()));

        if let Some(seed) = self.seed {
            obj.insert("seed".to_string(), Value::Number(seed.into()));
        }

        if let Some(virtual_time) = self.virtual_time_start_micros {
            obj.insert("virtual_time_start_micros".to_string(), Value::Number(virtual_time.into()));
        }

        if let Some(policy_id) = &self.policy_id {
            obj.insert("policy_id".to_string(), Value::String(policy_id.clone()));
        }

        obj.insert("steps".to_string(), Value::Array(self.steps.clone()));
        obj.insert("expected_events".to_string(), Value::Array(self.expected_events.clone()));
        obj.insert("determinism_check".to_string(), Value::Bool(self.determinism_check));

        // Add extra fields to test unknown field handling
        for (key, value) in &self.extra_fields {
            obj.insert(key.clone(), value.clone());
        }

        Value::Object(obj)
    }
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> arbitrary::Result<String> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len() / 4))?;
    let bytes = u.bytes(len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn bounded_json_value(u: &mut Unstructured<'_>, max_len: usize, depth: usize) -> arbitrary::Result<Value> {
    if depth >= MAX_JSON_DEPTH {
        return Ok(Value::Null);
    }

    let tag = u.int_in_range(0_u8..=6)?;
    Ok(match tag {
        0 => Value::Null,
        1 => Value::Bool(u.arbitrary()?),
        2 => Value::Number((u.arbitrary::<u64>()?).into()),
        3 => Value::Number((u.arbitrary::<i64>()?).into()),
        4 => Value::String(bounded_string(u, max_len)?),
        5 => Value::Array(bounded_json_array(u, max_len.min(MAX_ARRAY_LEN), depth + 1)?),
        _ => Value::Object(bounded_json_object(u, max_len.min(MAX_OBJECT_LEN), depth + 1)?.into_iter().collect()),
    })
}

fn bounded_json_array(u: &mut Unstructured<'_>, max_len: usize, depth: usize) -> arbitrary::Result<Vec<Value>> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len() / 8))?;
    let mut arr = Vec::with_capacity(len);
    for _ in 0..len {
        arr.push(bounded_json_value(u, max_len / 4, depth)?);
    }
    Ok(arr)
}

fn bounded_json_object(u: &mut Unstructured<'_>, max_len: usize, depth: usize) -> arbitrary::Result<BTreeMap<String, Value>> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len() / 16))?;
    let mut obj = BTreeMap::new();
    for _ in 0..len {
        let key = bounded_string(u, 64)?;
        let value = bounded_json_value(u, max_len / 4, depth)?;
        obj.insert(key, value);
    }
    Ok(obj)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Test 1: Direct raw bytes to test JSON parsing robustness
    let _ = parse_fixture_with_migration(data);

    // Test 2: Exercise specific version migration paths with structured input
    if let Some((structured_data, raw_suffix)) = data.split_at_checked(data.len() / 2) {
        let mut u = Unstructured::new(structured_data);

        if let Ok(fixture_json) = ArbitraryFixtureJson::arbitrary(&mut u) {
            // Test current version path
            let json_bytes = serde_json::to_vec(&fixture_json.to_json()).unwrap_or_default();
            let _ = parse_fixture_with_migration(&json_bytes);

            // Test legacy version (0) path by forcing fixture_version = 0
            let mut legacy_fixture = fixture_json.clone();
            legacy_fixture.fixture_version = 0;
            let legacy_json_bytes = serde_json::to_vec(&legacy_fixture.to_json()).unwrap_or_default();
            let _ = parse_fixture_with_migration(&legacy_json_bytes);

            // Test unsupported version path
            let mut unsupported_fixture = fixture_json.clone();
            unsupported_fixture.fixture_version = 999999;
            let unsupported_json_bytes = serde_json::to_vec(&unsupported_fixture.to_json()).unwrap_or_default();
            let _ = parse_fixture_with_migration(&unsupported_json_bytes);
        }

        // Test 3: Edge cases for fixture_version field
        test_version_edge_cases(&mut u, raw_suffix);
    }

    // Test 4: Malformed JSON patterns that could cause issues
    test_malformed_json_patterns(data);
});

fn test_version_edge_cases(u: &mut Unstructured<'_>, suffix: &[u8]) {
    let patterns = [
        r#"{"fixture_version":null}"#,
        r#"{"fixture_version":"not_a_number"}"#,
        r#"{"fixture_version":[]}"#,
        r#"{"fixture_version":{}}"#,
        r#"{"fixture_version":-1}"#,
        r#"{"fixture_version":18446744073709551615}"#, // u64::MAX
    ];

    for pattern in &patterns {
        let _ = parse_fixture_with_migration(pattern.as_bytes());

        // Combine with suffix for more variation
        if !suffix.is_empty() {
            let mut combined = pattern.as_bytes().to_vec();
            combined.extend_from_slice(&suffix[..suffix.len().min(32)]);
            let _ = parse_fixture_with_migration(&combined);
        }
    }

    // Test specific version numbers that could be problematic
    if let Ok(version_num) = u.arbitrary::<u32>() {
        let version_test = format!(r#"{{"fixture_version":{}}}"#, version_num);
        let _ = parse_fixture_with_migration(version_test.as_bytes());
    }
}

fn test_malformed_json_patterns(data: &[u8]) {
    // Test deeply nested structures that could cause stack overflow
    let deep_array = "[".repeat(1000) + &"]".repeat(1000);
    let _ = parse_fixture_with_migration(deep_array.as_bytes());

    let deep_object = "{\"a\":".repeat(500) + "null" + &"}".repeat(500);
    let _ = parse_fixture_with_migration(deep_object.as_bytes());

    // Test large strings that could cause OOM
    if data.len() > 4 {
        let large_string = format!(r#"{{"fixture_version":1,"large_field":"{}"}}"#,
            String::from_utf8_lossy(&data[..data.len().min(8192)]));
        let _ = parse_fixture_with_migration(large_string.as_bytes());
    }

    // Test incomplete JSON
    let incomplete_patterns = [
        b"{",
        b"[",
        b"\"",
        b"{\"fixture_version\":",
        b"{\"fixture_version\":1,",
        b"{\"fixture_version\":1,\"incomplete\"",
    ];

    for pattern in &incomplete_patterns {
        let _ = parse_fixture_with_migration(pattern);

        // Combine with input data
        if !data.is_empty() {
            let mut combined = pattern.to_vec();
            combined.extend_from_slice(&data[..data.len().min(256)]);
            let _ = parse_fixture_with_migration(&combined);
        }
    }
}