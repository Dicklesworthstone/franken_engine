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

fn normalize_fresh_runtime_evidence_identity(actual: &str) -> Value {
    let mut parsed: Value = serde_json::from_str(actual).expect("run output must be JSON");
    let source_hash = parsed["source_ingestion"]["original_source_hash"]
        .as_str()
        .expect("run output must carry the source hash")
        .strip_prefix("sha256:")
        .expect("source hash must use the sha256 prefix")
        .to_string();
    let identity = parsed["evidence_verification_identity"]
        .as_object_mut()
        .expect("run output must carry an evidence verification identity");
    let producer_id = identity["producer_id"]
        .as_str()
        .expect("runtime producer id must be a string");
    assert!(
        producer_id.starts_with(&format!("frankenctl.run:{source_hash}:")),
        "runtime producer id must bind the source hash"
    );
    let verification_key = identity["verification_key"]
        .as_object()
        .and_then(|value| value.get("inner"))
        .and_then(Value::as_array)
        .expect("runtime verification key must use the canonical wire form");
    assert_eq!(verification_key.len(), 32);
    assert!(
        verification_key
            .iter()
            .any(|byte| byte.as_u64().is_some_and(|byte| byte != 0)),
        "runtime verification key must not be all zero"
    );
    let provenance = identity["key_provenance"]
        .as_object_mut()
        .expect("runtime identity must carry key provenance");
    assert_eq!(provenance["authority_class"], "runtime");
    assert_eq!(provenance["activation_epoch"], 0);
    assert_eq!(provenance["rotation_sequence"], 1);
    assert!(!provenance.contains_key("previous_key_id"));
    let key_id = provenance["key_id"]
        .as_str()
        .expect("runtime key id must be a string");
    assert!(
        key_id
            .strip_prefix("ed25519:")
            .is_some_and(|digest| digest.len() == 64),
        "runtime key id must be a domain-separated SHA-256 identifier"
    );
    provenance.insert(
        "key_id".to_string(),
        Value::String("[RUNTIME_KEY_ID]".to_string()),
    );

    identity.insert(
        "producer_id".to_string(),
        Value::String("[RUNTIME_PRODUCER_ID]".to_string()),
    );
    identity.insert(
        "verification_key".to_string(),
        Value::String("[RUNTIME_VERIFICATION_KEY]".to_string()),
    );
    parsed
}

#[test]
fn frankenctl_run_output_matches_golden_after_capacity_hint_sweep() {
    let start = Instant::now();

    let actual = run_frankenctl();
    let normalized = normalize_fresh_runtime_evidence_identity(&actual);

    insta::assert_snapshot!(
        "frankenctl_run_output_after_capacity_hint_sweep",
        serde_json::to_string_pretty(&normalized).expect("normalized output must serialize")
    );

    // Determinism guard: a second run must reproduce all stable semantics.
    let second = run_frankenctl();
    assert_eq!(
        normalized,
        normalize_fresh_runtime_evidence_identity(&second),
        "frankenctl run output must be stable apart from fresh runtime authority"
    );

    assert!(
        start.elapsed().as_secs() < 5,
        "H6.5 acceptance: runtime must be <= 5 s (was {:?})",
        start.elapsed()
    );
}
