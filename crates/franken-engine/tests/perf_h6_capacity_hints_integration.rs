#![forbid(unsafe_code)]

//! PERF-H6.5 integration test (bd-o4cbn.4.5).
//!
//! The H6 capacity-hint sweep (H6.2 / bd-o4cbn.4.2) only pre-sizes backing
//! allocations on hot-path `Vec`/`String` constructors — it is pure metadata
//! and MUST NOT change any observable output. This test runs the real
//! `frankenctl run` binary on a fixed input and asserts the emitted JSON is
//! identical after normalizing the intentionally fresh runtime evidence
//! identity, so any future capacity-hint tweak that accidentally alters output
//! (reordering, dropping, truncation) fails closed here.
//!
//! Determinism notes:
//!   * The command is invoked with `--input input.js` from the fixture
//!     directory (relative path) so no machine-specific absolute path leaks
//!     into the output.
//!   * `frankenctl run` derives its trace/decision ids deterministically from
//!     the input. Runtime evidence authorities are fresh per process, so the
//!     test validates and normalizes only those public identity coordinates.
//!
//! Acceptance (bd-o4cbn.4.5): test passes, golden committed, runtime <= 5 s.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use serde_json::Value;

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

/// Parse the run report, assert the current output contract, and normalize
/// every field derived from the per-invocation runtime signing authority.
///
/// The report schema is `franken-engine.frankenctl.run.v2`; it deliberately
/// omits a top-level `evidence_verification_identity` (bd-8yhg4 — verifiers
/// resolve the receipt signer through their own registry) and instead embeds
/// the signed evidence chain. The signing key is freshly generated per
/// invocation, so the chain artifact and the ids/hashes derived from it are
/// the only legitimately unstable output; everything else (including the
/// sealed IR4 witness, bd-drb55) must be identical across runs for fixed
/// inputs. Chain integrity itself is enforced by `verify_genesis` inside the
/// CLI and by the bd-8yhg4 exact-chain test, not by this snapshot.
fn parse_run_report_current_contract(actual: &str) -> Value {
    let mut parsed: Value = serde_json::from_str(actual).expect("run output must be JSON");
    assert_eq!(
        parsed["schema_version"].as_str(),
        Some("franken-engine.frankenctl.run.v2"),
        "run report schema drifted; update this test alongside the CLI"
    );
    assert!(
        parsed.get("evidence_verification_identity").is_none(),
        "run report must not carry a self-authenticating trust root"
    );
    parsed["source_ingestion"]["original_source_hash"]
        .as_str()
        .expect("run output must carry the source hash")
        .strip_prefix("sha256:")
        .expect("source hash must use the sha256 prefix");
    let obj = parsed
        .as_object_mut()
        .expect("run output must be a JSON object");
    for (field, placeholder) in [
        ("evidence_chain_artifact", "[FRESH_AUTHORITY_CHAIN]"),
        ("evidence_chain_instance_id", "[FRESH_AUTHORITY_ID]"),
        ("evidence_ledger_id", "[FRESH_AUTHORITY_ID]"),
        ("evidence_chain_head", "[FRESH_AUTHORITY_HASH]"),
    ] {
        assert!(
            obj.contains_key(field),
            "run report must carry `{field}`; the schema drifted"
        );
        obj.insert(field.to_string(), Value::String(placeholder.to_string()));
    }
    parsed
}

#[test]
fn frankenctl_run_output_matches_golden_after_capacity_hint_sweep() {
    let start = Instant::now();

    let actual = run_frankenctl();
    let normalized = parse_run_report_current_contract(&actual);

    insta::assert_snapshot!(
        "frankenctl_run_output_after_capacity_hint_sweep",
        serde_json::to_string_pretty(&normalized).expect("normalized output must serialize")
    );

    // Determinism guard: a second run must reproduce all stable semantics.
    let second = run_frankenctl();
    assert_eq!(
        normalized,
        parse_run_report_current_contract(&second),
        "frankenctl run output must be stable apart from fresh runtime authority"
    );

    assert!(
        start.elapsed().as_secs() < 5,
        "H6.5 acceptance: runtime must be <= 5 s (was {:?})",
        start.elapsed()
    );
}
