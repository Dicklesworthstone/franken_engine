#![forbid(unsafe_code)]

//! PERF-H2.8 integration tests (bd-o4cbn.6.8).
//!
//! The H2 lazy-seed change defers materializing interpreter execution state
//! until a seed surface is written. That optimization must be observationally
//! invisible to CLI users and evidence consumers. These tests exercise the
//! real `frankenctl` binary, deterministic replay trace validation, and a
//! ledger-chain invariant that mirrors the acceptance notes on the bead.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEmitter, EvidenceEntryBuilder,
    InMemoryLedger, LabFixtureEvidenceEntryBuilderExt as _, LabFixtureInMemoryLedgerExt as _,
    Witness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serde_json::Value;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("perf_h2")
}

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "franken_engine_perf_h2_{}_{}_{}.{}",
        std::process::id(),
        name,
        seq,
        extension
    ))
}

fn run_frankenctl(input: &Path, extension_id: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("test input path must be valid UTF-8"),
            "--extension-id",
            extension_id,
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

fn run_frankenctl_fixture() -> String {
    let dir = fixtures_dir();
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(&dir)
        .args([
            "run",
            "--input",
            "input.js",
            "--extension-id",
            "perf-h2-lazy-seed-fixture",
            "--goal",
            "script",
        ])
        .output()
        .map(|output| {
            assert!(
                output.status.success(),
                "frankenctl run failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            String::from_utf8(output.stdout).expect("frankenctl stdout must be valid UTF-8")
        })
        .expect("frankenctl run must spawn")
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
fn frankenctl_run_evidence_stable_besides_runtime_authority_under_lazy_seed() {
    let start = Instant::now();
    let actual = run_frankenctl_fixture();
    let normalized = parse_run_report_current_contract(&actual);

    insta::assert_snapshot!(
        "frankenctl_run_evidence_under_lazy_seed",
        serde_json::to_string_pretty(&normalized).expect("normalized output must serialize")
    );

    let second = run_frankenctl_fixture();
    assert_eq!(
        normalized,
        parse_run_report_current_contract(&second),
        "frankenctl run output must be stable apart from fresh runtime authority"
    );

    assert_eq!(normalized["evidence_entries"], 1);
    assert_eq!(normalized["execution_value"], "60");
    assert!(
        start.elapsed().as_secs() < 60,
        "H2.8 acceptance: runtime must be <= 60 s (was {:?})",
        start.elapsed()
    );
}

#[test]
fn frankenctl_replay_strict_passes_under_lazy_seed_fixture() {
    let mut trace = NondeterminismTrace::new("perf-h2-lazy-seed-session");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "perf-h2-router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 0, 0, 7],
        200,
        "perf-h2-clock",
    );
    trace.finalise(300);

    let trace_path = temp_path("strict_trace", "json");
    std::fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace).expect("trace must serialize"),
    )
    .expect("trace fixture must be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().expect("trace path must be valid UTF-8"),
            "--mode",
            "strict",
        ])
        .output()
        .expect("frankenctl replay run must spawn");

    assert!(
        output.status.success(),
        "frankenctl replay run failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("replay output must be JSON");
    assert_eq!(report["mode"], "strict");
    assert_eq!(report["session_id"], "perf-h2-lazy-seed-session");
    assert_eq!(report["event_count"], 2);
    assert_eq!(report["replayed_events"], 2);
    assert_eq!(report["divergence_count"], 0);
    assert_eq!(report["complete"], true);
}

#[test]
fn evidence_ledger_chained_prev_hash_intact_under_lazy_seed() {
    let epoch = SecurityEpoch::from_raw(6);
    let mut ledger = InMemoryLedger::for_epoch(epoch);
    ledger.authorize_policy("perf-h2-policy");

    let mut previous_hash = "genesis".to_string();
    for index in 0..100 {
        let entry = EvidenceEntryBuilder::new(
            format!("perf-h2-trace-{index}"),
            format!("perf-h2-decision-{index}"),
            "perf-h2-policy",
            epoch,
            DecisionType::ContractEvaluation,
        )
        .timestamp_ns(index)
        .candidate(CandidateAction::new("allow", 1_000))
        .constraint(Constraint {
            constraint_id: "lazy-seed-byte-identical".to_string(),
            description: "lazy seed must not alter evidence chain output".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 1_000,
            rationale: "deterministic H2 fixture accepted".to_string(),
        })
        .witness(Witness {
            witness_id: format!("perf-h2-witness-{index}"),
            witness_type: "byte_identical_run".to_string(),
            value: "pass".to_string(),
        })
        .meta("bead", "bd-o4cbn.6.8")
        .meta("prev_hash", previous_hash.clone())
        .build()
        .expect("evidence entry must build");

        assert_eq!(
            entry.metadata.get("prev_hash"),
            Some(&previous_hash),
            "entry {index} must bind the previous hash before emission"
        );
        previous_hash = entry.evidence_hash.clone();
        ledger.emit(entry).expect("ledger must accept linked entry");
    }

    assert_eq!(ledger.len(), 100);
    let entries = ledger.entries();
    assert_eq!(entries[0].metadata["prev_hash"], "genesis");
    for pair in entries.windows(2) {
        assert_eq!(
            pair[1].metadata["prev_hash"], pair[0].evidence_hash,
            "ledger prev_hash metadata must match the prior evidence hash"
        );
    }
}

#[test]
fn capture_reset_idempotence_under_proptest_inputs() {
    let mut runner = TestRunner::new(Config {
        cases: 100,
        ..Config::default()
    });

    runner
        .run(&(0i64..1_000, 0i64..1_000, 0i64..1_000), |(a, b, c)| {
            let source_path = temp_path("proptest_input", "js");
            let source = format!(
                "const a = {a};\nconst b = {b};\nconst c = {c};\nlet total = 0;\ntotal = total + a;\ntotal = total + b;\ntotal = total + c;\ntotal;\n"
            );
            std::fs::write(&source_path, source).expect("proptest source must be writable");

            let first = run_frankenctl(&source_path, "perf-h2-proptest");
            let second = run_frankenctl(&source_path, "perf-h2-proptest");
            let first = parse_run_report_current_contract(&first);
            let second = parse_run_report_current_contract(&second);
            prop_assert_eq!(&first, &second);

            let expected = (a + b + c).to_string();
            prop_assert_eq!(first["execution_value"].as_str(), Some(expected.as_str()));
            prop_assert_eq!(first["evidence_entries"].as_u64(), Some(1));
            Ok(())
        })
        .expect("100 generated frankenctl runs must have stable execution semantics");
}
