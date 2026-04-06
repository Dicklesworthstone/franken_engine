#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(path: &str) -> String {
    let absolute = repo_root().join(path);
    fs::read_to_string(&absolute)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", absolute.display()))
}

#[test]
fn gate_script_replaces_placeholder_backfills_with_receipt_writer() {
    let script = read_repo_file("scripts/run_parser_oracle_gate.sh");

    assert!(script.contains("parser_oracle_missing_artifact_receipt.json"));
    assert!(script.contains("write_missing_artifact_receipt"));
    assert!(script.contains("emit_missing_artifact_receipt"));
    assert!(script.contains("select_missing_artifact_reason_id"));
    assert!(!script.contains("echo \"{}\" >\"$baseline_path\""));
    assert!(
        !script.contains("echo \"{\\\"status\\\":\\\"not_run\\\"}\" >\"$relation_report_path\"")
    );
    assert!(!script.contains(": >\"$relation_events_path\""));
    assert!(!script.contains(": >\"$evidence_path\""));
    assert!(!script.contains(": >\"$drift_digest_path\""));
    assert!(script.contains("\"missing_artifact_receipt\": \"${missing_artifact_receipt_path}\""));
}

#[test]
fn gate_doc_mentions_receipt_contract_and_artifact_behavior() {
    let doc = read_repo_file("docs/PARSER_ORACLE_GATE.md");

    assert!(doc.contains("## Missing-Artifact Contract"));
    assert!(doc.contains("parser_oracle_missing_artifact_receipt.json"));
    assert!(doc.contains("docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md"));
    assert!(doc.contains("The gate no longer backfills them with `{}`"));
}

#[test]
fn contract_validation_lane_tracks_receipt_writer_not_legacy_placeholders() {
    let script = read_repo_file("scripts/run_parser_oracle_missing_artifact_contract.sh");

    assert!(script.contains("write_missing_artifact_receipt"));
    assert!(script.contains("parser_oracle_missing_artifact_receipt.json"));
    assert!(!script.contains("gate script no longer exposes write_placeholders() context"));
}

#[test]
fn writer_validation_script_covers_required_scenarios_and_rch_commands() {
    let script = read_repo_file("scripts/run_parser_oracle_missing_artifact_writer.sh");

    for scenario in [
        "not_run_by_design_check",
        "skipped_by_gate_condition_override",
        "failed_before_artifact_creation",
        "missing_unexpected_absence",
        "all_artifacts_present",
    ] {
        assert!(
            script.contains(scenario),
            "writer validation script missing scenario {scenario}"
        );
    }

    for required in [
        "parser_oracle_missing_artifact_writer_report.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "cargo check -p frankenengine-engine --test parser_oracle_missing_artifact_writer",
        "cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_writer",
        "cargo clippy -p frankenengine-engine --test parser_oracle_missing_artifact_writer -- -D warnings",
    ] {
        assert!(
            script.contains(required),
            "writer validation script missing requirement {required}"
        );
    }
}

#[test]
fn writer_replay_wrapper_requires_complete_bundle() {
    let script = read_repo_file("scripts/e2e/parser_oracle_missing_artifact_writer_replay.sh");

    for required in [
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "parser_oracle_missing_artifact_writer_report.json",
        "step_logs/step_000.log",
    ] {
        assert!(
            script.contains(required),
            "writer replay wrapper missing completeness requirement: {required}"
        );
    }
}
