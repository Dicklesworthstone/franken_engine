#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use chrono::{DateTime, Duration, Utc};
use frankenengine_engine::execution_truth_ledger::{
    ERROR_CLAIM_DRIFT, ERROR_FINDING, ERROR_FORBIDDEN_TEXT, ERROR_GIT_TRACKING,
    ERROR_HASH_MISMATCH, ERROR_IO, ERROR_JSON, ERROR_MARKDOWN_DRIFT, ERROR_MISSING_PROOF,
    ERROR_OWNER, ERROR_STALE, ERROR_SURFACE, ERROR_TRACKER_DRIFT, ExecutionTruthLedger,
    ValidationContext, ValidationEvent, ValidationOutput, validate_ledger_file, write_events_jsonl,
};
use tempfile::{NamedTempFile, tempdir};

fn repo_root() -> PathBuf {
    for mut path in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        PathBuf::from(file!()),
    ] {
        if path.is_file() {
            path.pop();
        }
        loop {
            if path.join("docs/execution_truth_ledger_v1.json").is_file() {
                return path;
            }
            if !path.pop() {
                break;
            }
        }
    }
    panic!("could not find repository root from manifest or test source path");
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join("docs/execution_truth_ledger_v1.json")
}

fn fixed_context(root: &Path) -> ValidationContext {
    let cutoff = DateTime::parse_from_rfc3339(&load_ledger(root).source_cutoff_utc)
        .expect("canonical source cutoff parses")
        .with_timezone(&Utc);
    let as_of = cutoff + Duration::hours(1);
    ValidationContext::deterministic_for_tests(as_of)
}

fn load_ledger(root: &Path) -> ExecutionTruthLedger {
    let bytes = fs::read(ledger_path(root)).expect("canonical ledger is readable");
    serde_json::from_slice(&bytes).expect("canonical ledger parses")
}

fn validate_temporary(root: &Path, ledger: &ExecutionTruthLedger) -> ValidationOutput {
    let file = NamedTempFile::new().expect("temporary ledger");
    fs::write(
        file.path(),
        serde_json::to_vec_pretty(ledger).expect("serialize ledger"),
    )
    .expect("write temporary ledger");
    validate_ledger_file(root, file.path(), &fixed_context(root))
}

fn assert_has_code(output: &ValidationOutput, expected: &str) {
    assert!(
        output
            .report
            .findings
            .iter()
            .any(|finding| finding.error_code == expected),
        "expected {expected}; actual findings: {:?}",
        output.report.findings
    );
}

#[test]
fn canonical_ledger_validates_against_live_repository() {
    let root = repo_root();
    let output = validate_ledger_file(&root, &ledger_path(&root), &fixed_context(&root));
    assert!(
        output.passed(),
        "canonical truth ledger must pass: {:?}",
        output.report.findings
    );
    assert_eq!(output.report.subject_count, 19);
    assert!(output.report.proof_count >= 25);
    assert!(output.report.checks_run > output.report.proof_count);
    assert!(output.events.iter().all(|event| {
        event.schema_version == "franken-engine.execution-truth-ledger.validation-event.v1"
            && event.attempt == 1
            && event.reason.len() <= 771
    }));
}

#[test]
fn deterministic_revalidation_has_identical_decisions_and_report() {
    let root = repo_root();
    let first = validate_ledger_file(&root, &ledger_path(&root), &fixed_context(&root));
    let second = validate_ledger_file(&root, &ledger_path(&root), &fixed_context(&root));
    assert_eq!(first.report, second.report);

    let normalize = |mut events: Vec<ValidationEvent>| {
        for event in &mut events {
            event.duration_us = 0;
        }
        events
    };
    assert_eq!(normalize(first.events), normalize(second.events));
}

#[test]
fn missing_mandatory_subject_fails_closed() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    ledger
        .subjects
        .retain(|subject| subject.subject_id != "bead:bd-1lsy.7.3");
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_SURFACE);
}

#[test]
fn artifact_hash_tamper_is_rejected() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let proof = ledger
        .subjects
        .iter_mut()
        .flat_map(|subject| &mut subject.proofs)
        .find(|proof| proof.proof_id == "fe-claim-010.denominator")
        .expect("denominator proof exists");
    proof.file_sha256 = Some("0".repeat(64));
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_HASH_MISMATCH);
}

#[test]
fn forbidden_backend_dependency_is_rejected() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let proof = ledger
        .subjects
        .iter_mut()
        .flat_map(|subject| &mut subject.proofs)
        .find(|proof| proof.proof_id == "bd-1lsy-7-3.manifest-no-cranelift")
        .expect("manifest proof exists");
    proof.forbidden_text.push("[dependencies]".to_string());
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_FORBIDDEN_TEXT);
}

#[test]
fn ignored_perf_artifact_cannot_be_relabelled_tracked() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let proof = ledger
        .subjects
        .iter_mut()
        .flat_map(|subject| &mut subject.proofs)
        .find(|proof| proof.proof_id == "bd-o4cbn.pass1-baseline")
        .expect("pass1 proof exists");
    proof.expected_git_tracked = Some(true);
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_GIT_TRACKING);
}

#[test]
fn absent_local_optional_proof_is_explicit_and_does_not_fabricate_revalidation() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let proof = ledger
        .subjects
        .iter_mut()
        .flat_map(|subject| &mut subject.proofs)
        .find(|proof| proof.proof_id == "bd-o4cbn.pass1-baseline")
        .expect("local optional proof exists");
    proof.path = "artifacts/execution_truth_ledger/absent-local-optional.json".to_string();
    let output = validate_temporary(&root, &ledger);
    assert!(
        output.events.iter().any(|event| {
            event.phase == "proof.optional_absence"
                && event.proof_id.as_deref() == Some("bd-o4cbn.pass1-baseline")
                && event.decision == "pass"
                && event.reason.contains("retained hash was not revalidated")
        }),
        "optional absence must be visible in structured events"
    );
    assert!(!output.report.findings.iter().any(|finding| {
        finding.proof_id.as_deref() == Some("bd-o4cbn.pass1-baseline")
            && finding.error_code == ERROR_MISSING_PROOF
    }));
}

#[test]
fn tracker_status_drift_is_rejected() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let subject = ledger
        .subjects
        .iter_mut()
        .find(|subject| subject.subject_id == "bead:bd-o4cbn")
        .expect("perf subject exists");
    subject.current_state = "closed".to_string();
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_TRACKER_DRIFT);
}

#[test]
fn claim_promotion_without_matrix_change_is_rejected() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    let subject = ledger
        .subjects
        .iter_mut()
        .find(|subject| subject.subject_id == "claim:FE-CLAIM-010")
        .expect("performance claim exists");
    subject.current_state = "observed".to_string();
    subject.claim_posture = frankenengine_engine::execution_truth_ledger::ClaimPosture::Observed;
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_CLAIM_DRIFT);
}

#[test]
fn stale_snapshot_is_rejected_with_stable_code() {
    let root = repo_root();
    let ledger = load_ledger(&root);
    let stale_context = ValidationContext::deterministic_for_tests(
        DateTime::parse_from_rfc3339("2027-07-24T08:00:00Z")
            .expect("fixed time parses")
            .with_timezone(&Utc),
    );
    let file = NamedTempFile::new().expect("temporary ledger");
    fs::write(
        file.path(),
        serde_json::to_vec_pretty(&ledger).expect("serialize ledger"),
    )
    .expect("write ledger");
    let output = validate_ledger_file(&root, file.path(), &stale_context);
    assert_has_code(&output, ERROR_STALE);
}

#[test]
fn generated_markdown_drift_is_rejected() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    ledger.rendered_markdown_path = "README.md".to_string();
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_MARKDOWN_DRIFT);
}

#[test]
fn malformed_and_missing_ledgers_emit_structured_failures() {
    let root = repo_root();
    let malformed = NamedTempFile::new().expect("temporary ledger");
    fs::write(malformed.path(), b"{not-json").expect("write malformed input");
    let malformed_output = validate_ledger_file(&root, malformed.path(), &fixed_context(&root));
    assert_has_code(&malformed_output, ERROR_JSON);

    let missing = root.join("artifacts/execution_truth_ledger/definitely-missing.json");
    let missing_output = validate_ledger_file(&root, &missing, &fixed_context(&root));
    assert_has_code(&missing_output, ERROR_IO);
}

#[test]
fn unknown_schema_fields_fail_closed_instead_of_being_ignored() {
    let root = repo_root();
    let mut ledger: serde_json::Value =
        serde_json::from_slice(&fs::read(ledger_path(&root)).expect("read ledger"))
            .expect("parse ledger value");
    ledger.as_object_mut().expect("ledger is an object").insert(
        "silently_ignored_claim".to_string(),
        serde_json::json!("must fail"),
    );
    let file = NamedTempFile::new().expect("temporary ledger");
    fs::write(
        file.path(),
        serde_json::to_vec_pretty(&ledger).expect("serialize ledger"),
    )
    .expect("write ledger");
    let output = validate_ledger_file(&root, file.path(), &fixed_context(&root));
    assert_has_code(&output, ERROR_JSON);
}

#[test]
fn freshness_rejects_one_second_beyond_the_exact_boundary() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    ledger.source_cutoff_utc = "2026-07-23T08:00:00Z".to_string();
    ledger.max_age_days = 1;
    let context = ValidationContext::deterministic_for_tests(
        DateTime::parse_from_rfc3339("2026-07-24T08:00:01Z")
            .expect("fixed time parses")
            .with_timezone(&Utc),
    );
    let file = NamedTempFile::new().expect("temporary ledger");
    fs::write(
        file.path(),
        serde_json::to_vec_pretty(&ledger).expect("serialize ledger"),
    )
    .expect("write ledger");
    let output = validate_ledger_file(&root, file.path(), &context);
    assert_has_code(&output, ERROR_STALE);
}

#[test]
fn invented_revalidation_owner_is_rejected_against_live_tracker() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    ledger.subjects[0].revalidation.owner_id = "bd-definitely-not-a-real-owner".to_string();
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_OWNER);
}

#[test]
fn finding_scores_outside_the_governed_range_fail_closed() {
    let root = repo_root();
    let mut ledger = load_ledger(&root);
    ledger.findings[0].opportunity_score = 0;
    let output = validate_temporary(&root, &ledger);
    assert_has_code(&output, ERROR_FINDING);
}

#[test]
fn event_publication_is_atomic_and_refuses_overwrite() {
    let root = repo_root();
    let output = validate_ledger_file(&root, &ledger_path(&root), &fixed_context(&root));
    let directory = tempdir().expect("temporary event directory");
    let path = directory.path().join("events.jsonl");
    write_events_jsonl(&path, &output.events).expect("first event publication succeeds");
    let original = fs::read(&path).expect("published events readable");
    let error =
        write_events_jsonl(&path, &output.events).expect_err("second publication must fail closed");
    assert!(error.contains("refusing to overwrite"));
    assert_eq!(
        fs::read(&path).expect("prior event artifact remains readable"),
        original
    );
    assert!(
        fs::read_dir(directory.path())
            .expect("event directory readable")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".partial-"))
    );
}

#[test]
fn concurrent_event_publishers_cannot_replace_the_winner() {
    let root = repo_root();
    let output = validate_ledger_file(&root, &ledger_path(&root), &fixed_context(&root));
    let directory = tempdir().expect("temporary event directory");
    let path = directory.path().join("events.jsonl");
    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));

    let results = thread::scope(|scope| {
        let handles: Vec<_> = (0..worker_count)
            .map(|worker| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                let mut events = output.events.clone();
                for event in &mut events {
                    event.run_id = format!("concurrent-publisher-{worker}");
                }
                scope.spawn(move || {
                    barrier.wait();
                    (
                        worker,
                        write_events_jsonl(&path, &events),
                        events[0].run_id.clone(),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("publisher thread completes"))
            .collect::<Vec<_>>()
    });

    let winners: Vec<_> = results
        .iter()
        .filter(|(_, result, _)| result.is_ok())
        .collect();
    assert_eq!(winners.len(), 1, "exactly one publisher wins: {results:?}");

    let published = fs::read_to_string(&path).expect("winning artifact is readable");
    let published_ids: std::collections::BTreeSet<_> = published
        .lines()
        .map(|line| {
            serde_json::from_str::<ValidationEvent>(line)
                .expect("published event is valid JSON")
                .run_id
        })
        .collect();
    assert_eq!(
        published_ids,
        std::collections::BTreeSet::from([winners[0].2.clone()]),
        "the first successful artifact remains intact"
    );
    assert!(
        results
            .iter()
            .filter(|(_, result, _)| result.is_err())
            .all(|(_, result, _)| {
                let reason = result.as_ref().expect_err("loser has an error");
                reason.contains("refusing to overwrite")
                    || reason.contains("without replacement")
                    || reason.contains("recoverable event prefix")
            })
    );
}
