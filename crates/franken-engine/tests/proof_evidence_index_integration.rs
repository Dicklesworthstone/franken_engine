#![forbid(unsafe_code)]

use frankenengine_engine::proof_artifact::PROOF_MANIFEST_SCHEMA_VERSION;
use frankenengine_engine::proof_evidence_index::{
    FOCUSED_PROOF_RUNNER_REPORT_SCHEMA_VERSION, GateReportImport,
    PROOF_EVIDENCE_QUERY_SCHEMA_VERSION, SWARM_VALIDATION_PLAN_SCHEMA_VERSION,
    import_gate_report_json, import_proof_manifest_json, import_validation_plan_json,
    proof_evidence_query_report_json, query_artifacts_older_than_freshness_policy,
    query_proof_by_bead, query_proof_by_source_revision, query_recent_failed_gates,
};
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};
use serde_json::{Value, json};

const SOURCE_REVISION: &str = "abc1234";
const SHA_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA_B: &str = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35";

fn ctx() -> EventContext {
    EventContext::new(
        "trace-proof-index",
        "decision-proof-index",
        "policy-proof-index",
    )
    .expect("valid context")
}

fn manifest_with(status: &str, source_revision: &str, artifacts: Vec<Value>) -> String {
    json!({
        "schema_version": PROOF_MANIFEST_SCHEMA_VERSION,
        "bundle_id": "focused-proof-runner-20260505T120000Z",
        "gate_name": "focused-proof-runner",
        "status": status,
        "generated_utc": "2026-05-05T12:00:00Z",
        "source_revision": source_revision,
        "rerun_command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_p03vs cargo test -p frankenengine-engine --test proof_evidence_index_integration",
        "bead_ids": ["bd-p03vs"],
        "generated_artifacts": artifacts
    })
    .to_string()
}

fn generated_artifacts() -> Vec<Value> {
    vec![
        json!({
            "path": "artifacts/focused_proof_runner/run/commands.txt",
            "sha256": SHA_A,
            "role": "command_transcript"
        }),
        json!({
            "path": "artifacts/focused_proof_runner/run/report.json",
            "sha256": SHA_B,
            "schema_version": "franken-engine.focused-proof-runner-report.v1",
            "role": "source_machine_report"
        }),
        json!({
            "path": "artifacts/focused_proof_runner/run/redaction_policy.json",
            "sha256": null,
            "role": "redaction_policy"
        }),
    ]
}

fn validation_plan() -> String {
    json!({
        "schema_version": SWARM_VALIDATION_PLAN_SCHEMA_VERSION,
        "bead_id": "bd-p03vs",
        "source_revision": SOURCE_REVISION,
        "decision": "admit_narrow",
        "reason_codes": ["package_lib_fallback"],
        "changed_paths": ["crates/franken-engine/src/proof_evidence_index.rs"],
        "commands": [
            {
                "command_id": "cargo-check-frankenengine-engine-lib",
                "display": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_p03vs_lib cargo check -p frankenengine-engine --lib",
                "command_kind": "rch_cargo_check_lib",
                "package": "frankenengine-engine",
                "target": "lib",
                "rationale": "package lib fallback"
            }
        ],
        "expected_artifacts": [
            {"path": "artifacts/swarm_validation/plan.json", "role": "validation_plan"},
            {"path": "artifacts/swarm_validation/commands.txt", "role": "command_transcript"}
        ],
        "artifact_paths": {
            "run_dir": "artifacts/swarm_validation",
            "plan_json": "artifacts/swarm_validation/plan.json",
            "commands_txt": "artifacts/swarm_validation/commands.txt",
            "report_md": "artifacts/swarm_validation/report.md"
        }
    })
    .to_string()
}

fn gate_report(status: &str) -> String {
    json!({
        "schema_version": FOCUSED_PROOF_RUNNER_REPORT_SCHEMA_VERSION,
        "status": status,
        "focused_suite": "proof-evidence-index",
        "diagnostics_id": "diag-proof-index-1"
    })
    .to_string()
}

#[test]
fn imports_valid_manifest_and_replays_duplicate_imports() {
    let context = ctx();
    let mut adapter = InMemoryStorageAdapter::new();
    let manifest = manifest_with("pass", SOURCE_REVISION, generated_artifacts());

    let first = import_proof_manifest_json(
        &mut adapter,
        &manifest,
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect("valid manifest imports");
    let second = import_proof_manifest_json(
        &mut adapter,
        &manifest,
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect("duplicate manifest import replays stable ids");

    assert_eq!(first.len(), 2);
    assert_eq!(
        first.iter().map(|row| row.evidence_id).collect::<Vec<_>>(),
        second.iter().map(|row| row.evidence_id).collect::<Vec<_>>()
    );

    let rows = query_proof_by_bead(&mut adapter, "bd-p03vs", &context).expect("query by bead");
    assert_eq!(
        rows.len(),
        2,
        "duplicate import must not create duplicate rows"
    );
    assert_eq!(
        rows[0].artifact_path,
        "artifacts/focused_proof_runner/run/commands.txt"
    );
    assert_eq!(rows[0].receipt_kind, "command_receipt");
    assert_eq!(rows[1].receipt_kind, "proof_artifact");
}

#[test]
fn malformed_json_and_unsupported_schema_fail_closed() {
    let context = ctx();
    let mut adapter = InMemoryStorageAdapter::new();

    let err = import_proof_manifest_json(
        &mut adapter,
        "{not json",
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect_err("malformed JSON must fail closed");
    assert!(err.to_string().contains("not valid JSON"));

    let mut unsupported: Value = serde_json::from_str(&manifest_with(
        "pass",
        SOURCE_REVISION,
        generated_artifacts(),
    ))
    .expect("fixture parses");
    unsupported["schema_version"] = json!("franken-engine.proof-artifact-manifest.v0");
    let err = import_proof_manifest_json(
        &mut adapter,
        &unsupported.to_string(),
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect_err("unsupported schema must fail closed");
    assert!(err.to_string().contains("unsupported schema_version"));
}

#[test]
fn stale_source_revision_and_missing_artifacts_fail_closed() {
    let context = ctx();
    let mut adapter = InMemoryStorageAdapter::new();

    let err = import_proof_manifest_json(
        &mut adapter,
        &manifest_with("pass", "stale999", generated_artifacts()),
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect_err("stale source revision must fail closed");
    assert!(err.to_string().contains("stale source_revision"));

    let err = import_proof_manifest_json(
        &mut adapter,
        &manifest_with(
            "pass",
            SOURCE_REVISION,
            vec![json!({
                "path": "artifacts/focused_proof_runner/run/report.json",
                "role": "source_machine_report"
            })],
        ),
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect_err("artifact without sha256 must fail closed");
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn validation_plan_imports_generated_fixture_without_mocks() {
    let context = ctx();
    let mut adapter = InMemoryStorageAdapter::new();

    let imported = import_validation_plan_json(
        &mut adapter,
        &validation_plan(),
        SOURCE_REVISION,
        1_777_000_000_000,
        86_400_000,
        &context,
    )
    .expect("generated validation plan fixture imports");

    assert_eq!(imported.len(), 2);
    assert!(
        imported
            .iter()
            .any(|row| row.receipt_kind == "validation_command")
    );
    assert!(
        imported
            .iter()
            .any(|row| row.receipt_kind == "validation_plan")
    );

    let rows = query_proof_by_source_revision(&mut adapter, SOURCE_REVISION, &context)
        .expect("query by source revision");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].bead_id, "bd-p03vs");
}

#[test]
fn query_output_is_stable_json_and_ordered_deterministically() {
    let context = ctx();
    let mut adapter_a = InMemoryStorageAdapter::new();
    let mut adapter_b = InMemoryStorageAdapter::new();
    let mut reversed = generated_artifacts();
    reversed.reverse();

    import_proof_manifest_json(
        &mut adapter_a,
        &manifest_with("pass", SOURCE_REVISION, generated_artifacts()),
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect("first import succeeds");
    import_proof_manifest_json(
        &mut adapter_b,
        &manifest_with("pass", SOURCE_REVISION, reversed),
        SOURCE_REVISION,
        86_400_000,
        &context,
    )
    .expect("reordered import succeeds");

    let rows_a = query_proof_by_bead(&mut adapter_a, "bd-p03vs", &context).expect("rows a");
    let rows_b = query_proof_by_bead(&mut adapter_b, "bd-p03vs", &context).expect("rows b");
    let json_a = proof_evidence_query_report_json("proof_by_bead", rows_a).expect("report a");
    let json_b = proof_evidence_query_report_json("proof_by_bead", rows_b).expect("report b");

    assert_eq!(json_a, json_b);
    assert!(json_a.contains(PROOF_EVIDENCE_QUERY_SCHEMA_VERSION));
    assert!(json_a.contains("\"rows\""));
}

#[test]
fn queries_failed_gates_and_stale_artifacts() {
    let context = ctx();
    let mut adapter = InMemoryStorageAdapter::new();

    import_proof_manifest_json(
        &mut adapter,
        &manifest_with("fail", SOURCE_REVISION, generated_artifacts()),
        SOURCE_REVISION,
        1,
        &context,
    )
    .expect("failed manifest imports");
    import_gate_report_json(
        &mut adapter,
        &gate_report("fail"),
        GateReportImport {
            bead_id: "bd-p03vs",
            source_revision: SOURCE_REVISION,
            artifact_path: "artifacts/focused_proof_runner/run/gate_report.json",
            expected_source_revision: SOURCE_REVISION,
            generated_timestamp_ms: 1_777_000_000_000,
            freshness_policy_ms: 1,
        },
        &context,
    )
    .expect("failed gate report imports");

    let failed = query_recent_failed_gates(&mut adapter, 10, &context).expect("failed query");
    assert_eq!(failed.len(), 3);
    assert!(failed.iter().all(|row| row.gate_status == "fail"));

    let stale =
        query_artifacts_older_than_freshness_policy(&mut adapter, 1_778_000_000_000, &context)
            .expect("stale query");
    assert_eq!(stale.len(), 3);
    assert!(
        stale
            .windows(2)
            .all(|window| window[0].freshness_deadline_ms <= window[1].freshness_deadline_ms)
    );
}
