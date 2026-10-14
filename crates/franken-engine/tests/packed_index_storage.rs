//! Real parse/lower/execute coverage for the shared packed property carrier.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &[&str]) {
    let actual: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();