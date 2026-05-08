#![no_main]

use frankenengine_engine::capability::CapabilityProfile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs to focus on logic vs memory exhaustion
    if data.is_empty() || data.len() > 32768 {
        return;
    }

    // Test JSON deserialization with arbitrary byte input
    let result = serde_json::from_slice::<CapabilityProfile>(data);

    match result {
        Ok(profile) => {
            // SECURITY INVARIANT: Every successfully deserialized profile must
            // exactly match one of the five canonical profiles.
            // This prevents capability smuggling where kind and capabilities mismatch.
            let canonical_profiles = [
                CapabilityProfile::full(),
                CapabilityProfile::engine_core(),
                CapabilityProfile::policy(),
                CapabilityProfile::remote(),
                CapabilityProfile::compute_only(),
            ];

            let matches_canonical = canonical_profiles.iter().any(|canonical| {
                &profile == canonical
            });

            if !matches_canonical {
                panic!(
                    "SECURITY VIOLATION: Deserialized profile does not match any canonical profile: {:?}",
                    profile
                );
            }

            // Additional validation: ensure the profile can be serialized back to JSON
            let _serialized = serde_json::to_string(&profile)
                .expect("Canonical profiles should always serialize");

            // Test round-trip consistency
            let re_parsed: CapabilityProfile = serde_json::from_str(&_serialized)
                .expect("Serialized canonical profile should re-parse");

            assert_eq!(profile, re_parsed, "Round-trip serialization should be consistent");
        }
        Err(_) => {
            // Expected errors are fine (malformed JSON, validation failures, etc.)
            // The harness should never panic on malformed input - only on capability smuggling
        }
    }

    // Test some specific edge cases if input is small enough to be interpreted as structured data
    if data.len() < 1024 {
        // Test various JSON patterns that might cause issues:

        // 1. Try interpreting as UTF-8 string for manual JSON construction
        if let Ok(s) = std::str::from_utf8(data) {
            let _result = serde_json::from_str::<CapabilityProfile>(s);
            // Result can be Ok or Err, just testing for panics
        }

        // 2. Test with common JSON patterns that might bypass validation
        let test_patterns = [
            r#"{"kind":"Full","capabilities":[]}"#, // Wrong caps for Full
            r#"{"kind":"ComputeOnly","capabilities":["VmDispatch"]}"#, // Wrong caps for ComputeOnly
            r#"{"kind":"Policy","capabilities":["NetworkEgress"]}"#, // Wrong caps for Policy
            r#"{"kind":"Unknown","capabilities":[]}"#, // Unknown kind
            r#"{"capabilities":[]}"#, // Missing kind
            r#"{"kind":"Full"}"#, // Missing capabilities
            r#"{}"#, // Empty object
        ];

        for pattern in &test_patterns {
            let _result = serde_json::from_str::<CapabilityProfile>(pattern);
            // These should all fail validation, but shouldn't panic
        }
    }
});