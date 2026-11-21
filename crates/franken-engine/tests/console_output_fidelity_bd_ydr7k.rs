//! bd-ydr7k: console output fidelity and dropped-entry accounting.
//!
//! Verifies that:
//! 1. A 10,000-line `console.log("line" + i)` loop delivers every line in
//!    order (`line0`..`line9999`) with `dropped_console_entries == 0` and
//!    never silently drops the head via a ring buffer.
//! 2. Setting `max_console_entries = Some(0)` on `ExecutionOrchestrator`
//!    suppresses capture while recording the exact `dropped_console_entries`
//!    count (`10_000`) on `OrchestratorResult`.
//! 3. Exceeding a positive `max_console_entries` cap fails closed with
//!    `InterpreterError::ConsoleBudgetExceeded` rather than silently
//!    overwriting earlier entries.

use std::collections::BTreeMap;

use frankenengine_engine::baseline_interpreter::InterpreterError;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

fn package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: Some(format!("{id}.js")),
        module_root: None,
        capabilities: Vec::new(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn orchestrator_with_budget(instruction_budget: u64) -> ExecutionOrchestrator {
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = instruction_budget;
    runtime.execution.throughput_budget = instruction_budget;
    ExecutionOrchestrator::new_lab_with_runtime_config(OrchestratorConfig::default(), runtime)
}

#[test]
fn ten_thousand_console_lines_are_delivered_intact_without_head_truncation() {
    let mut orchestrator = orchestrator_with_budget(50_000_000);
    let pkg = package(
        "console-10k-intact",
        "for (let i = 0; i < 10000; i++) { console.log('line' + i); }",
    );
    let result = orchestrator
        .execute(&pkg)
        .expect("10,000 console lines fit within default console budget");
    assert_eq!(result.console_output.len(), 10_000);
    assert_eq!(result.dropped_console_entries, 0);
    assert_eq!(result.console_output[0].message, "line0");
    assert_eq!(result.console_output[9_999].message, "line9999");
    for (idx, entry) in result.console_output.iter().enumerate() {
        assert_eq!(entry.message, format!("line{idx}"));
    }
}

#[test]
fn zero_console_cap_counts_exact_dropped_entries_on_orchestrator_result() {
    let mut orchestrator = orchestrator_with_budget(50_000_000).with_max_console_entries(Some(0));
    let pkg = package(
        "console-10k-zero-cap",
        "for (let i = 0; i < 10000; i++) { console.log('line' + i); }",
    );
    let result = orchestrator
        .execute(&pkg)
        .expect("zero console cap drops entries without aborting execution");
    assert!(result.console_output.is_empty());
    assert_eq!(result.dropped_console_entries, 10_000);
}

#[test]
fn positive_console_cap_fails_closed_instead_of_silently_dropping_oldest_lines() {
    let mut orchestrator = orchestrator_with_budget(5_000_000).with_max_console_entries(Some(5));
    let pkg = package(
        "console-cap-exceeded",
        "for (let i = 0; i < 10; i++) { console.log('line' + i); }",
    );
    let err = orchestrator
        .execute(&pkg)
        .expect_err("exceeding positive max_console_entries must fail closed");
    let primary = match &err {
        OrchestratorError::PostCellFailure(failure) => {
            assert!(
                failure.committed_evidence_chain.is_some(),
                "console budget refusal must preserve committed evidence chain"
            );
            failure.primary_error.as_ref()
        }
        other => other,
    };
    assert!(
        matches!(
            primary,
            OrchestratorError::Interpreter(InterpreterError::ConsoleBudgetExceeded {
                entries: 6,
                max_entries: 5,
                ..
            })
        ),
        "expected ConsoleBudgetExceeded(entries=6, max_entries=5), got {err:?}"
    );
}
