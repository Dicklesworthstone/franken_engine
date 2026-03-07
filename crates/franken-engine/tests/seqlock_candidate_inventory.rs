#[path = "../src/seqlock_candidate_inventory.rs"]
mod seqlock_candidate_inventory;

use std::fs;
use std::path::PathBuf;

use seqlock_candidate_inventory::{
    ArtifactContext, CONTRACT_SCHEMA_VERSION, CandidateDisposition, build_contract_fixture,
    emit_default_inventory_bundle,
};

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    path.push(format!(
        "franken-engine-seqlock-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn bundle_writes_required_artifacts_and_contract_files() {
    let artifact_dir = temp_dir("bundle");
    let mut context = ArtifactContext::new(&artifact_dir);
    context.run_id = "run-rgc-621b-test".to_string();
    context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
    context.source_commit = "deadbeef".to_string();
    context.toolchain = "nightly".to_string();
    context.command_invocation = format!(
        "cargo run -p frankenengine-engine --bin franken_seqlock_candidate_inventory -- --artifact-dir {}",
        artifact_dir.display()
    );

    let bundle = emit_default_inventory_bundle(&context).expect("bundle should write");

    for artifact in [
        "commands.txt",
        "env.json",
        "events.jsonl",
        "incumbent_fallback_matrix.json",
        "manifest.json",
        "repro.lock",
        "retry_budget_policy.json",
        "retry_safety_matrix.json",
        "run_manifest.json",
        "seqlock_candidate_inventory.json",
        "seqlock_reader_writer_contract.json",
        "snapshot_baseline_comparator.json",
        "summary.md",
        "trace_ids.json",
    ] {
        assert!(
            artifact_dir.join(artifact).exists(),
            "expected artifact `{artifact}` to exist",
        );
    }

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest should parse");
    let manifest_artifacts = manifest["artifacts"].as_array().expect("artifacts array");
    assert!(
        manifest_artifacts
            .iter()
            .any(|entry| entry["path"] == "env.json"),
        "manifest should reference env.json",
    );
    assert!(
        manifest_artifacts
            .iter()
            .any(|entry| entry["path"] == "repro.lock"),
        "manifest should reference repro.lock",
    );

    let trace_ids: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("trace_ids.json")).expect("read trace ids"),
    )
    .expect("trace ids parse");
    assert_eq!(trace_ids["trace_ids"][0], "trace.rgc.621b");

    let run_manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("run manifest should parse");
    assert_eq!(
        run_manifest["reader_writer_contract_hash"].as_str(),
        Some(bundle.reader_writer_contract.contract_hash.as_str())
    );
    assert_eq!(
        run_manifest["retry_budget_policy_hash"].as_str(),
        Some(bundle.retry_budget_policy.policy_hash.as_str())
    );
    assert_eq!(
        run_manifest["incumbent_fallback_matrix_hash"].as_str(),
        Some(bundle.incumbent_fallback_matrix.matrix_hash.as_str())
    );

    assert_eq!(bundle.inventory.counts.accept, 3);
    assert_eq!(bundle.reader_writer_contract.rows.len(), 9);
    assert_eq!(bundle.retry_budget_policy.rows.len(), 9);
    assert_eq!(bundle.incumbent_fallback_matrix.rows.len(), 9);
    assert!(
        !artifact_dir
            .join(".seqlock_candidate_inventory.lock")
            .exists(),
        "bundle write lock should be cleaned up after publication",
    );

    let _ = fs::remove_dir_all(&artifact_dir);
}

#[test]
fn docs_contract_fixture_matches_inventory_dispositions() {
    let expected = build_contract_fixture();
    let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/rgc_seqlock_candidate_inventory_v1.json");
    let actual: seqlock_candidate_inventory::ContractFixture =
        serde_json::from_slice(&fs::read(&docs_path).expect("read docs fixture"))
            .expect("fixture should parse");

    assert_eq!(actual.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(actual, expected);
    assert!(
        actual
            .candidate_expectations
            .iter()
            .any(|entry| entry.candidate_id == "module-cache-snapshot"
                && entry.disposition == CandidateDisposition::Accept),
        "fixture should keep the module cache candidate accepted",
    );
}
