#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

//! Process-tree containment regressions for the external differential-oracle
//! lanes (`bd-xv0ln`). These exercise the public receipt path with a hermetic
//! `/bin/sh` runtime, so the assertions cover process-group teardown, bounded
//! capture, diagnostics, and receipt classification together.

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use frankenengine_engine::differential_oracle::{
    DifferentialBackend, DifferentialBackendReceipt, DifferentialBackendStatus,
    DifferentialOracleInput, DifferentialOracleReport, run_differential_oracle,
};

const MAX_CAPTURED_STREAM_BYTES: usize = 4 * 1024 * 1024;

fn shell_input(case_id: &str, script: &str, timeout: Duration) -> DifferentialOracleInput {
    let timeout_ms = u64::try_from(timeout.as_millis()).expect("test timeout fits u64");
    let mut input = DifferentialOracleInput::new(case_id, script)
        .with_timeout_ms(timeout_ms)
        .with_selected_backends([DifferentialBackend::NodeLts]);
    input.node.program = "/bin/sh".to_string();
    input.node.version_args = vec![
        "-c".to_string(),
        "printf 'franken-oracle-test-shell-v1\\n'".to_string(),
    ];
    input.node.eval_args = vec!["-c".to_string()];
    input
}

fn node_receipt(report: &DifferentialOracleReport) -> &DifferentialBackendReceipt {
    report
        .backends
        .iter()
        .find(|receipt| receipt.backend == DifferentialBackend::NodeLts)
        .expect("node receipt")
}

fn process_id_from_output(output: &str, key: &str) -> u32 {
    output
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing `{key}` in captured output: {output:?}"))
        .parse()
        .unwrap_or_else(|error| panic!("invalid pid after `{key}`: {error}"))
}

fn assert_process_id_gone(process_id: u32) {
    let proc_entry = std::path::PathBuf::from(format!("/proc/{process_id}"));
    for _ in 0..200 {
        if !proc_entry.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let state = fs::read_to_string(proc_entry.join("stat")).unwrap_or_default();
    panic!("process {process_id} survived oracle teardown: {state}");
}

#[test]
fn timeout_kills_runtime_descendants_without_pipe_join_delay_bd_xv0ln() {
    const SCRIPT: &str = r#"
sleep 5 &
descendant=$!
printf 'parent=%s\ndescendant=%s\npartial-output\n' "$$" "$descendant"
while :; do :; done
"#;
    let input = shell_input(
        "bd-xv0ln-descendant-timeout",
        SCRIPT,
        Duration::from_millis(250),
    );

    let started = Instant::now();
    let report = run_differential_oracle(&input);
    let elapsed = started.elapsed();
    let receipt = node_receipt(&report);

    assert_eq!(receipt.status, DifferentialBackendStatus::Timeout);
    assert!(
        elapsed < Duration::from_secs(2),
        "inherited pipes extended a 250ms deadline to {elapsed:?}"
    );
    assert!(
        receipt.stdout.ends_with("partial-output\n"),
        "partial output was not preserved: {:?}",
        receipt.stdout
    );
    assert!(receipt.stdout.len() <= MAX_CAPTURED_STREAM_BYTES);
    assert!(
        receipt
            .diagnostics
            .iter()
            .any(|detail| detail.contains("250ms timeout and was killed"))
    );

    let parent = process_id_from_output(&receipt.stdout, "parent=");
    let descendant = process_id_from_output(&receipt.stdout, "descendant=");
    assert_process_id_gone(parent);
    assert_process_id_gone(descendant);
}

#[test]
fn oversized_output_is_prefix_bounded_and_degraded_bd_xv0ln() {
    const SCRIPT: &str = r#"
printf 'retained-prefix\n'
head -c 5242880 /dev/zero
"#;
    let input = shell_input("bd-xv0ln-output-bound", SCRIPT, Duration::from_secs(5));

    let report = run_differential_oracle(&input);
    let receipt = node_receipt(&report);

    assert_eq!(receipt.status, DifferentialBackendStatus::Degraded);
    assert!(receipt.stdout.starts_with("retained-prefix\n"));
    assert_eq!(receipt.stdout.len(), MAX_CAPTURED_STREAM_BYTES);
    assert!(
        receipt
            .diagnostics
            .iter()
            .any(|detail| detail.contains("stdout exceeded the 4194304-byte capture limit"))
    );
}
