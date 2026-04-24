#![no_main]

use frankenengine_engine::parallel_parser::{parse, ParseInput, ParallelConfig};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs for fuzzing efficiency
    if data.is_empty() || data.len() > 8192 {
        return;
    }

    let source = String::from_utf8_lossy(data);
    let config = ParallelConfig::default();

    // Create ParseInput with default values
    let input = ParseInput {
        source: &source,
        trace_id: "fuzz_trace",
        run_id: "fuzz_run",
        epoch: SecurityEpoch::GENESIS,
        config: &config,
    };

    // Test with default config
    let result1 = parse(&input);

    // Test with different config variants to explore code paths
    let config_single_worker = ParallelConfig {
        max_workers: 1,
        ..config
    };
    let input_single = ParseInput {
        config: &config_single_worker,
        ..input
    };
    let result_single = parse(&input_single);

    // Test with forced parallel mode (lower threshold)
    let config_force_parallel = ParallelConfig {
        min_parallel_bytes: 1,  // Force parallel on any non-empty input
        max_workers: 4,
        ..config
    };
    let input_parallel = ParseInput {
        config: &config_force_parallel,
        ..input
    };
    let result_parallel = parse(&input_parallel);

    // Test with parity checking always enabled
    let config_parity = ParallelConfig {
        always_check_parity: true,
        min_parallel_bytes: 1,
        ..config
    };
    let input_parity = ParseInput {
        config: &config_parity,
        ..input
    };
    let result_parity = parse(&input_parity);

    // Invariant: Parser should never panic regardless of input
    // Results can be Ok or Err, both are valid outcomes

    // Invariant: Same input should produce same result (deterministic parsing)
    let result2 = parse(&input);
    assert_eq!(result1.is_ok(), result2.is_ok(),
               "Parallel parser should be deterministic for same input");

    // If both succeeded, compare critical properties
    if let (Ok(r1), Ok(r2)) = (&result1, &result2) {
        assert_eq!(r1.tokens.len(), r2.tokens.len(),
                   "Token count should be deterministic");
        assert_eq!(r1.mode_used, r2.mode_used,
                   "Parse mode should be deterministic");
    }

    // Invariant: Single-worker mode should always work if any mode works
    // (Single-worker is the most conservative mode)

    // If parsing succeeds, verify serialization doesn't panic
    if let Ok(parse_result) = &result1 {
        let serialized = serde_json::to_string(parse_result)
            .expect("ParseOutput should serialize");
        let _deserialized: serde_json::Value = serde_json::from_str(&serialized)
            .expect("Serialized ParseOutput should deserialize");
    }

    // Test edge case configs (but only for small inputs to avoid timeout)
    if source.len() < 100 {
        let config_tiny_budget = ParallelConfig {
            chunk_budget_us: 1,  // Minimal budget
            max_workers: 2,
            ..config
        };
        let input_tiny = ParseInput {
            config: &config_tiny_budget,
            ..input
        };
        let _result_tiny = parse(&input_tiny);  // Should not panic
    }
});