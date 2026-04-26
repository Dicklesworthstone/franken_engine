#![no_main]

use frankenengine_engine::parallel_parser::{
    ParallelConfig, ParseError, ParseInput, ParseOutput, ParserMode, parse,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

fn check_output_invariants(source_len: u64, output: &ParseOutput) {
    assert_eq!(
        output.bytes_scanned, source_len,
        "bytes_scanned should match the full source length"
    );
    assert_eq!(
        output.token_count,
        output.tokens.len() as u64,
        "token_count should match the token vector length"
    );

    for (index, token) in output.tokens.iter().enumerate() {
        assert!(
            token.start <= token.end,
            "token start must not exceed end: {:?}",
            token
        );
        assert!(
            token.end <= source_len,
            "token end {} exceeds source length {}",
            token.end,
            source_len
        );
        if let Some(previous) = index.checked_sub(1).and_then(|idx| output.tokens.get(idx)) {
            assert!(
                previous.start <= token.start,
                "tokens must remain source-ordered: previous={:?} current={:?}",
                previous,
                token
            );
            assert!(
                previous.end <= token.start,
                "tokens must not overlap after merge/repair: previous={:?} current={:?}",
                previous,
                token
            );
        }
    }

    match output.mode {
        ParserMode::Parallel => {
            assert!(
                output.chunk_plan.is_some(),
                "parallel outputs must retain a chunk plan"
            );
            assert!(
                output.merge_witness.is_some(),
                "parallel outputs must retain a merge witness"
            );
            assert!(
                output.schedule_transcript.is_some(),
                "parallel outputs must retain a schedule transcript"
            );
        }
        ParserMode::Serial if output.fallback_cause.is_none() => {
            assert!(
                output.chunk_plan.is_none(),
                "serial non-fallback outputs must not retain a chunk plan"
            );
            assert!(
                output.merge_witness.is_none(),
                "serial non-fallback outputs must not retain a merge witness"
            );
            assert!(
                output.schedule_transcript.is_none(),
                "serial non-fallback outputs must not retain a schedule transcript"
            );
        }
        ParserMode::Serial => {}
    }

    if let Some(merge_witness) = &output.merge_witness {
        assert_eq!(
            merge_witness.total_tokens, output.token_count,
            "merge witness total_tokens should match the final token count"
        );
    }
    if output.fallback_cause.is_some() {
        assert!(
            output.failover_decision.is_some(),
            "fallback outputs must retain a failover decision"
        );
    }
}

fn check_result_invariants(source_len: u64, result: &Result<ParseOutput, ParseError>) {
    match result {
        Ok(parse_result) => {
            let serialized =
                serde_json::to_string(parse_result).expect("ParseOutput should serialize");
            let deserialized: ParseOutput = serde_json::from_str(&serialized)
                .expect("Serialized ParseOutput should deserialize");
            assert_eq!(
                deserialized, *parse_result,
                "ParseOutput serde round-trip should preserve all fields"
            );
            check_output_invariants(source_len, parse_result);
        }
        Err(err) => {
            let serialized = serde_json::to_string(err).expect("ParseError should serialize");
            let deserialized: ParseError = serde_json::from_str(&serialized)
                .expect("Serialized ParseError should deserialize");
            assert_eq!(
                deserialized, *err,
                "ParseError serde round-trip should preserve all fields"
            );
        }
    }
}

fn assert_semantic_equivalence(
    left_label: &str,
    left: &Result<ParseOutput, ParseError>,
    right_label: &str,
    right: &Result<ParseOutput, ParseError>,
) {
    assert_eq!(
        left.is_ok(),
        right.is_ok(),
        "parallel parser should keep success/error surface stable across configs ({left_label} vs {right_label})"
    );

    match (left, right) {
        (Ok(left_output), Ok(right_output)) => {
            assert_eq!(
                left_output.tokens, right_output.tokens,
                "token stream drifted across configs ({left_label} vs {right_label})"
            );
            assert_eq!(
                left_output.token_count, right_output.token_count,
                "token count drifted across configs ({left_label} vs {right_label})"
            );
            assert_eq!(
                left_output.bytes_scanned, right_output.bytes_scanned,
                "bytes_scanned drifted across configs ({left_label} vs {right_label})"
            );
            assert_eq!(
                left_output.output_hash, right_output.output_hash,
                "output hash drifted across configs ({left_label} vs {right_label})"
            );
        }
        (Err(left_error), Err(right_error)) => {
            assert_eq!(
                std::mem::discriminant(left_error),
                std::mem::discriminant(right_error),
                "error class drifted across configs ({left_label} vs {right_label})"
            );
            assert_eq!(
                left_error.to_string(),
                right_error.to_string(),
                "error text drifted across configs ({left_label} vs {right_label})"
            );
        }
        _ => unreachable!("is_ok() equality guarded above"),
    }
}

fn check_determinism(label: &str, input: &ParseInput<'_>) -> Result<ParseOutput, ParseError> {
    let first = parse(input);
    let second = parse(input);
    assert_eq!(
        first, second,
        "Parallel parser should be deterministic for same input/config ({label})"
    );
    check_result_invariants(input.source.len() as u64, &first);
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
    let result_default = check_determinism("default", &input);

    // Test with different config variants to explore code paths
    let config_single_worker = ParallelConfig {
        max_workers: 1,
        ..config.clone()
    };
    let input_single = make_input(&source, &config_single_worker);
    let result_single = check_determinism("single-worker", &input_single);
    assert_semantic_equivalence("default", &result_default, "single-worker", &result_single);

    // Test with forced parallel mode (lower threshold)
    let config_force_parallel = ParallelConfig {
        min_parallel_bytes: 1, // Force parallel on any non-empty input
        max_workers: 4,
        ..config.clone()
    };
    let input_parallel = make_input(&source, &config_force_parallel);
    let result_parallel = check_determinism("force-parallel", &input_parallel);
    assert_semantic_equivalence(
        "default",
        &result_default,
        "force-parallel",
        &result_parallel,
    );

    // Test with parity checking always enabled
    let config_parity = ParallelConfig {
        always_check_parity: true,
        min_parallel_bytes: 1,
        ..config.clone()
    };
    let input_parity = make_input(&source, &config_parity);
    let result_parity = check_determinism("parity-always-on", &input_parity);
    assert_semantic_equivalence(
        "default",
        &result_default,
        "parity-always-on",
        &result_parity,
    );

    // Test edge case configs (but only for small inputs to avoid timeout)
    if source.len() < 100 {
        let config_tiny_budget = ParallelConfig {
            chunk_budget_us: 1, // Minimal budget
            max_workers: 2,
            ..config.clone()
        };
        let input_tiny = make_input(&source, &config_tiny_budget);
        let result_tiny = check_determinism("tiny-budget", &input_tiny);
        assert_semantic_equivalence("default", &result_default, "tiny-budget", &result_tiny);
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_config_equivalence_preserves_parallel_parser_tokens() {
        let source = r#"
import { value } from "./dep.js";
const message = `hi ${value ?? "fallback"}`;
foo?.bar?.(message);
value && message;
"#;
        let parallel_config = ParallelConfig {
            min_parallel_bytes: 1,
            max_workers: 4,
            ..ParallelConfig::default()
        };
        let single_worker_config = ParallelConfig {
            max_workers: 1,
            ..parallel_config.clone()
        };

        let parallel_result = check_determinism("parallel", &make_input(source, &parallel_config));
        let single_result =
            check_determinism("single-worker", &make_input(source, &single_worker_config));

        assert_semantic_equivalence(
            "parallel",
            &parallel_result,
            "single-worker",
            &single_result,
        );
    }

    #[test]
    fn output_invariants_hold_for_serial_and_parallel_routes() {
        let serial_config = ParallelConfig::default();
        let serial_source = "x";
        let serial_result = check_determinism("serial", &make_input(serial_source, &serial_config));
        let serial_output =
            serial_result.expect("serial route should parse a single identifier cleanly");
        assert_eq!(serial_output.mode, ParserMode::Serial);
        check_output_invariants(serial_source.len() as u64, &serial_output);

        let parallel_config = ParallelConfig {
            min_parallel_bytes: 1,
            max_workers: 4,
            ..ParallelConfig::default()
        };
        let parallel_source = "let snowman = \"\u{2603}\";\nfoo?.bar?.(snowman);\n/* boundary */\nexport { snowman };\n";
        let parallel_result =
            check_determinism("parallel", &make_input(parallel_source, &parallel_config));
        let parallel_output =
            parallel_result.expect("parallel route should preserve valid token spans");
        assert_eq!(parallel_output.mode, ParserMode::Parallel);
        check_output_invariants(parallel_source.len() as u64, &parallel_output);
    }
}
