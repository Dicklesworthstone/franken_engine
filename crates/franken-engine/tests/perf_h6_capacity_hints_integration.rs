#![forbid(unsafe_code)]

//! PERF-H6.5 integration test (bd-o4cbn.4.5).
//!
//! The H6 capacity-hint sweep (H6.2 / bd-o4cbn.4.2) only pre-sizes backing
//! allocations on hot-path `Vec`/`String` constructors — it is pure metadata
//! and MUST NOT change any observable output. This test runs the real
//! `frankenctl run` binary on a fixed input and asserts the emitted JSON is
//! byte-identical to a golden captured from the same code, so any future
//! capacity-hint tweak that accidentally alters output (reordering, dropping,
//! truncation) fails closed here.
//!
//! Determinism notes:
//!   * The command is invoked with `--input input.js` from the fixture
//!     directory (relative path) so no machine-specific absolute path leaks
//!     into the output.
//!   * `frankenctl run` derives its trace/decision ids deterministically from
//!     the input, so repeated runs are byte-stable (asserted below).
//!
//! Acceptance (bd-o4cbn.4.5): test passes, golden committed, runtime <= 5 s.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("perf_h6")
}

fn run_frankenctl() -> String {
    let dir = fixtures_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(&dir)
        .args([
            "run",
            "--input",
            "input.js",
            "--extension-id",
            "perf-h6-fixture",
            "--goal",
            "script",
        ])
        .output()
        .expect("frankenctl run must spawn");

    assert!(
        output.status.success(),
        "frankenctl run failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("frankenctl stdout must be valid UTF-8")
}

#[test]
fn frankenctl_run_output_matches_golden_after_capacity_hint_sweep() {
    let start = Instant::now();

    let golden = include_str!("fixtures/perf_h6/run_output.golden.json");
    let actual = run_frankenctl();

    // Byte-identical comparison: capacity hints must not perturb any output.
    assert_eq!(
        actual.trim_end(),
        golden.trim_end(),
        "frankenctl run output diverged from the pre-H6 golden — capacity \
         hints must be pure metadata and must not change observable output"
    );

    // Determinism guard: a second run must reproduce the first byte-for-byte.
    let second = run_frankenctl();
    assert_eq!(
        actual, second,
        "frankenctl run output must be deterministic across runs"
    );

    assert!(
        start.elapsed().as_secs() < 5,
        "H6.5 acceptance: runtime must be <= 5 s (was {:?})",
        start.elapsed()
    );
}
