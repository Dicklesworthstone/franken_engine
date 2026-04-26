#![no_main]

use frankenengine_engine::parallel_parser::{
    ParallelConfig, ParseError, ParseInput, ParseOutput, parse,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

fn check_result_invariants(result: &Result<ParseOutput, ParseError>) {
    match result {
        Ok(parse_result) => {
            let serialized =
                serde_json::to_string(parse_result).expect("ParseOutput should serialize");
            let deserialized: ParseOutput =
                serde_json::from_str(&serialized).expect("Serialized ParseOutput should deserialize");
            assert_eq!(
                deserialized, *parse_result,
                "ParseOutput serde round-trip should preserve all fields"
            );
        }
        Err(err) => {
            let serialized = serde_json::to_string(err).expect("ParseError should serialize");
            let deserialized: ParseError =
                serde_json::from_str(&serialized).expect("Serialized ParseError should deserialize");
            assert_eq!(
                deserialized, *err,
                "ParseError serde round-trip should preserve all fields"
            );
        }
    }
}

fn check_determinism(label: &str, input: &ParseInput<'_>) -> Result<ParseOutput, ParseError> {
    let first = parse(input);
    let second = parse(input);
    assert_eq!(
        first, second,
        "Parallel parser should be deterministic for same input/config ({label})"
    );
    check_result_invariants(&first);
    first
}

fn make_input<'a>(source: &'a str, config: &'a ParallelConfig) -> ParseInput<'a> {
    ParseInput {
        source,
        trace_id: "fuzz_trace",
        run_id: "fuzz_run",
        epoch: SecurityEpoch::GENESIS,
        config,
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs for fuzzing efficiency
    if data.is_empty() || data.len() > 8192 {
        return;
    }

    let source = String::from_utf8_lossy(data);
    let config = ParallelConfig::default();

    let input = make_input(&source, &config);

    // Test with default config
    let _result_default = check_determinism("default", &input);

    // Test with different config variants to explore code paths
    let config_single_worker = ParallelConfig {
        max_workers: 1,
        ..config.clone()
    };
    let input_single = make_input(&source, &config_single_worker);
    let _result_single = check_determinism("single-worker", &input_single);

    // Test with forced parallel mode (lower threshold)
    let config_force_parallel = ParallelConfig {
        min_parallel_bytes: 1, // Force parallel on any non-empty input
        max_workers: 4,
        ..config.clone()
    };
    let input_parallel = make_input(&source, &config_force_parallel);
    let _result_parallel = check_determinism("force-parallel", &input_parallel);

    // Test with parity checking always enabled
    let config_parity = ParallelConfig {
        always_check_parity: true,
        min_parallel_bytes: 1,
        ..config.clone()
    };
    let input_parity = make_input(&source, &config_parity);
    let _result_parity = check_determinism("parity-always-on", &input_parity);

    // Test edge case configs (but only for small inputs to avoid timeout)
    if source.len() < 100 {
        let config_tiny_budget = ParallelConfig {
            chunk_budget_us: 1, // Minimal budget
            max_workers: 2,
            ..config.clone()
        };
        let input_tiny = make_input(&source, &config_tiny_budget);
        let _result_tiny = check_determinism("tiny-budget", &input_tiny);
    }
});
