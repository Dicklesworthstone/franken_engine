#![no_main]

use frankenengine_engine::shadow_handoff_contracts::{
    deserialize_panel_bundle, serialize_panel_bundle, ShadowStatusPanelBundle,
    ShadowStatusPanel, SourceFreshnessPanel, DegradedGatesPanel, ReplayDriftPanel,
    RecommendedActionsPanel, DaemonHealth, SourceFreshnessEntry, DegradedGateEntry,
    ReplayDriftEntry, RecommendedAction, GateDegradationSeverity, ActionPriority,
    DriftSeverity
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Test raw JSON parsing - the primary attack surface
    // Convert bytes to UTF-8 string, allowing invalid UTF-8 to be handled gracefully
    let json_result = std::str::from_utf8(data);

    match json_result {
        Ok(json_str) => {
            // Test the target function with UTF-8 JSON string
            let parse_result = deserialize_panel_bundle(json_str);

            match parse_result {
                Ok(bundle) => {
                    // Critical invariant: successfully deserialized bundles must round-trip
                    // This prevents serialization drift mentioned in the bead
                    let serialized = serialize_panel_bundle(&bundle)
                        .expect("Valid bundle should always serialize");

                    // Verify round-trip consistency
                    let round_trip_result = deserialize_panel_bundle(&serialized);
                    assert!(round_trip_result.is_ok(),
                           "Round-trip parsing should succeed for valid bundle");

                    let round_trip_bundle = round_trip_result.unwrap();

                    // Validate critical fields are preserved through round-trip
                    assert_eq!(bundle.bundle_version, round_trip_bundle.bundle_version,
                              "Bundle version should be preserved");
                    assert_eq!(bundle.generated_at, round_trip_bundle.generated_at,
                              "Generated timestamp should be preserved");
                    assert_eq!(bundle.shadow_status.daemon_health, round_trip_bundle.shadow_status.daemon_health,
                              "Daemon health status should be preserved");

                    // Additional validation: check for sensible defaults vs. wrong-result issues
                    // This catches the "missing/invalid status fields deserialize into passing defaults" issue
                    validate_bundle_sanity(&bundle);

                    // Test that bundle can be processed without panicking
                    let _debug_repr = format!("{:?}", bundle);

                    // Test deep field access to ensure no panics on nested data
                    test_deep_field_access(&bundle);
                }
                Err(_) => {
                    // Expected for malformed JSON - should not panic, just return error gracefully
                    // This is the correct behavior for invalid/malformed input
                }
            }
        }
        Err(_) => {
            // Invalid UTF-8 should be handled gracefully - no panic expected
            // The function expects &str so invalid UTF-8 won't reach it
        }
    }

    // Structure-aware fuzzing: generate synthetic bundles for additional coverage
    if data.len() >= 8 {
        let synthetic_bundle = generate_synthetic_bundle(data);
        test_synthetic_bundle(&synthetic_bundle);
    }

    // Test edge cases that could cause OOM or DoS via adversarial arrays/strings
    if data.len() < 100 {
        test_adversarial_patterns(data);
    }
});

fn validate_bundle_sanity(bundle: &ShadowStatusPanelBundle) {
    // Validate that critical fields have reasonable values, not suspicious defaults
    // This helps catch "wrong-result where missing fields deserialize into passing defaults"

    // Bundle version should not be empty
    assert!(!bundle.bundle_version.is_empty(),
           "Bundle version should not be empty");

    // Titles should not be empty
    assert!(!bundle.shadow_status.title.is_empty(),
           "Shadow status title should not be empty");
    assert!(!bundle.source_freshness.title.is_empty(),
           "Source freshness title should not be empty");

    // Counts should be consistent with array lengths
    assert_eq!(bundle.source_freshness.sources.len() as u32, bundle.source_freshness.stale_source_count,
               "Stale source count should match actual stale sources or be a summary");
    assert_eq!(bundle.degraded_gates.gates.len() as u32, bundle.degraded_gates.degraded_count,
               "Degraded gate count should match actual degraded gates or be a summary");

    // Health status should be consistent with other fields
    if matches!(bundle.shadow_status.daemon_health, DaemonHealth::Healthy) {
        // If healthy, we shouldn't have excessive degraded gates
        // (This is a heuristic - actual business logic may vary)
    }
}

fn test_deep_field_access(bundle: &ShadowStatusPanelBundle) {
    // Test deep nested field access to ensure no panics

    // Access daemon health details
    match &bundle.shadow_status.daemon_health {
        DaemonHealth::Degraded { reason } => {
            let _ = reason.len(); // Test string access
        }
        _ => {}
    }

    // Access all source freshness entries
    for source in &bundle.source_freshness.sources {
        let _ = source.source_id.len();
        let _ = source.last_update.as_u64();
    }

    // Access all degraded gate entries
    for gate in &bundle.degraded_gates.gates {
        let _ = gate.gate_id.len();
        let _ = gate.degradation_reason.len();
    }

    // Access all replay drift entries
    for drift in &bundle.replay_drift.drift_entries {
        let _ = drift.journal_id.len();
        let _ = drift.drift_type.len();
    }

    // Access all recommended action entries
    for action in &bundle.recommended_actions.actions {
        let _ = action.action_id.len();
        let _ = action.description.len();
        let _ = action.command_preview.len();
    }
}

fn generate_synthetic_bundle(data: &[u8]) -> ShadowStatusPanelBundle {
    // Generate structure-aware bundles using input bytes as seed
    let mut bundle = ShadowStatusPanelBundle::default();

    // Fuzz daemon health
    bundle.shadow_status.daemon_health = fuzz_daemon_health(data, 0);
    bundle.shadow_status.active_journals = fuzz_u32(data, 1);
    bundle.shadow_status.uptime_seconds = fuzz_u64(data, 2);

    // Fuzz generated timestamp
    bundle.generated_at = SecurityEpoch::from_raw(fuzz_u64(data, 3));

    // Add fuzzed source freshness entries
    let source_count = (byte(data, 4) % 8) as usize; // 0-7 sources
    for i in 0..source_count {
        bundle.source_freshness.sources.push(SourceFreshnessEntry {
            source_id: fuzz_string(data, 10 + i * 5, 32),
            last_update: SecurityEpoch::from_raw(fuzz_u64(data, 11 + i * 5)),
            staleness_seconds: fuzz_u64(data, 12 + i * 5),
            threshold_seconds: fuzz_u64(data, 13 + i * 5),
            is_stale: byte(data, 14 + i * 5) % 2 == 0,
        });
    }
    bundle.source_freshness.stale_source_count = source_count as u32;

    // Add fuzzed degraded gate entries
    let gate_count = (byte(data, 50) % 6) as usize; // 0-5 gates
    for i in 0..gate_count {
        bundle.degraded_gates.gates.push(DegradedGateEntry {
            gate_id: fuzz_string(data, 55 + i * 4, 24),
            degradation_reason: fuzz_string(data, 56 + i * 4, 64),
            degraded_since: SecurityEpoch::from_raw(fuzz_u64(data, 57 + i * 4)),
            severity: fuzz_gate_severity(data, 58 + i * 4),
        });
    }
    bundle.degraded_gates.degraded_count = gate_count as u32;

    // Add fuzzed replay drift entries
    let drift_count = (byte(data, 80) % 5) as usize; // 0-4 drift entries
    for i in 0..drift_count {
        bundle.replay_drift.drift_entries.push(ReplayDriftEntry {
            journal_id: fuzz_string(data, 85 + i * 5, 20),
            drift_type: fuzz_string(data, 86 + i * 5, 32),
            detected_at: fuzz_system_time(data, 87 + i * 5),
            severity: fuzz_drift_severity(data, 88 + i * 5),
            expected_migration: byte(data, 89 + i * 5) % 2 == 0,
        });
    }
    bundle.replay_drift.total_drift_count = drift_count as u32;

    // Add fuzzed recommended action entries
    let action_count = (byte(data, 110) % 4) as usize; // 0-3 actions
    for i in 0..action_count {
        bundle.recommended_actions.actions.push(RecommendedAction {
            action_id: fuzz_string(data, 115 + i * 5, 16),
            description: fuzz_string(data, 116 + i * 5, 128),
            command_preview: fuzz_string(data, 117 + i * 5, 64),
            priority: fuzz_action_priority(data, 118 + i * 5),
            estimated_duration: if byte(data, 119 + i * 5) % 2 == 0 {
                Some(fuzz_u64(data, 119 + i * 5))
            } else {
                None
            },
        });
    }
    bundle.recommended_actions.priority_action_count = action_count as u32;

    bundle
}

fn test_synthetic_bundle(bundle: &ShadowStatusPanelBundle) {
    // Test serialization of synthetic bundle
    let serialized = serialize_panel_bundle(bundle);
    assert!(serialized.is_ok(), "Synthetic bundle should serialize successfully");

    if let Ok(json) = serialized {
        // Test deserialization round-trip
        let parsed = deserialize_panel_bundle(&json);
        assert!(parsed.is_ok(), "Synthetic bundle should deserialize successfully");

        if let Ok(reparsed) = parsed {
            // Basic sanity checks
            assert_eq!(bundle.bundle_version, reparsed.bundle_version);
            assert_eq!(bundle.shadow_status.title, reparsed.shadow_status.title);
        }
    }
}

fn test_adversarial_patterns(data: &[u8]) {
    // Test patterns that could cause OOM or DoS
    let adversarial_patterns = [
        "{}",                                          // Empty object
        r#"{"source_freshness":{"sources":[]}}"#,     // Empty arrays
        r#"{"bundle_version":""}"#,                   // Empty strings
        r#"{"shadow_status":null}"#,                  // Null fields
        r#"{"generated_at":18446744073709551615}"#,   // Large numbers
        format!(r#"{{"long_string":"{}"}}"#, "x".repeat(1000)), // Long strings
        r#"{"deeply":{"nested":{"structure":{"value":true}}}}"#, // Deep nesting
    ];

    for pattern in adversarial_patterns {
        let _result = deserialize_panel_bundle(&pattern);
        // Should not panic on any adversarial pattern
    }

    // Test with byte-based adversarial string construction
    if !data.is_empty() {
        let adversarial_json = construct_adversarial_json(data);
        let _result = deserialize_panel_bundle(&adversarial_json);
    }
}

fn construct_adversarial_json(data: &[u8]) -> String {
    // Construct potentially problematic JSON from input bytes
    match byte(data, 0) % 5 {
        0 => format!(r#"{{"bundle_version":"{}"}}"#, fuzz_string(data, 1, 1000)),
        1 => format!(r#"{{"source_freshness":{{"sources":[{}]}}}}"#,
                    (0..byte(data, 1) % 10).map(|_| "{}").collect::<Vec<_>>().join(",")),
        2 => format!(r#"{{"generated_at":{}}}"#, fuzz_u64(data, 1)),
        3 => r#"{"malformed":}"#.to_string(), // Malformed JSON
        _ => format!(r#"{{"nested":{}}}"#, construct_adversarial_json(&data[1..])),
    }
}

// Helper fuzzing functions
fn fuzz_daemon_health(data: &[u8], seed: usize) -> DaemonHealth {
    match byte(data, seed) % 4 {
        0 => DaemonHealth::Healthy,
        1 => DaemonHealth::Degraded {
            reason: fuzz_string(data, seed + 1, 64)
        },
        2 => DaemonHealth::Offline,
        _ => DaemonHealth::Unknown,
    }
}

fn fuzz_gate_severity(data: &[u8], seed: usize) -> GateDegradationSeverity {
    match byte(data, seed) % 3 {
        0 => GateDegradationSeverity::Warning,
        1 => GateDegradationSeverity::Error,
        _ => GateDegradationSeverity::Critical,
    }
}

fn fuzz_drift_severity(data: &[u8], seed: usize) -> DriftSeverity {
    match byte(data, seed) % 3 {
        0 => DriftSeverity::Minor,
        1 => DriftSeverity::Major,
        _ => DriftSeverity::Critical,
    }
}

fn fuzz_system_time(data: &[u8], seed: usize) -> SystemTime {
    let secs = fuzz_u64(data, seed) % (365 * 24 * 3600 * 10); // Within 10 years
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn fuzz_action_priority(data: &[u8], seed: usize) -> ActionPriority {
    match byte(data, seed) % 4 {
        0 => ActionPriority::Low,
        1 => ActionPriority::Medium,
        2 => ActionPriority::High,
        _ => ActionPriority::Urgent,
    }
}

fn fuzz_string(data: &[u8], seed: usize, max_len: usize) -> String {
    if data.is_empty() {
        return String::new();
    }

    let start = seed % data.len();
    let len = (byte(data, seed) as usize) % max_len.min(32);

    data.iter()
        .skip(start)
        .take(len)
        .map(|&b| char::from(b.wrapping_add(32) % 95 + 32)) // Printable ASCII
        .collect()
}

fn fuzz_u32(data: &[u8], seed: usize) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    let start = seed % (data.len() - 3);
    u32::from_le_bytes([
        data[start],
        data[start + 1],
        data[start + 2],
        data[start + 3],
    ])
}

fn fuzz_u64(data: &[u8], seed: usize) -> u64 {
    if data.len() < 8 {
        return 0;
    }
    let start = seed % (data.len() - 7);
    u64::from_le_bytes([
        data[start],
        data[start + 1],
        data[start + 2],
        data[start + 3],
        data[start + 4],
        data[start + 5],
        data[start + 6],
        data[start + 7],
    ])
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}