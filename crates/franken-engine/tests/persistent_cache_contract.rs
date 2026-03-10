#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

pub use frankenengine_engine::hash_tiers;
pub use frankenengine_engine::module_cache;

#[path = "../src/persistent_cache_contract.rs"]
mod persistent_cache_contract;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use persistent_cache_contract::{
    ArtifactContext, DocsContractFixture, build_docs_contract_fixture, emit_default_contract_bundle,
};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "franken-engine-persistent-cache-contract-{label}-{}-{nanos}",
        process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn load_docs_fixture() -> DocsContractFixture {
    serde_json::from_slice(
        &fs::read(Path::new(
            "../../docs/rgc_persistent_cache_contract_v1.json",
        ))
        .expect("read persistent cache docs fixture"),
    )
    .expect("deserialize persistent cache docs fixture")
}

fn load_doc_markdown() -> String {
    fs::read_to_string(Path::new("../../docs/RGC_PERSISTENT_CACHE_CONTRACT_V1.md"))
        .expect("read persistent cache markdown doc")
}

fn load_runner_script() -> String {
    fs::read_to_string(Path::new(
        "../../scripts/run_persistent_cache_contract_suite.sh",
    ))
    .expect("read persistent cache runner")
}

fn emit_bundle(label: &str) -> (PathBuf, persistent_cache_contract::BundleWriteReport) {
    let artifact_dir = temp_dir(label);
    let mut context = ArtifactContext::new(&artifact_dir);
    context.source_commit = "test-commit".to_string();
    let report = emit_default_contract_bundle(&context).expect("emit bundle");
    (artifact_dir, report)
}

// ── Existing tests ──────────────────────────────────────────────────

#[test]
fn docs_fixture_matches_machine_readable_contract() {
    assert_eq!(build_docs_contract_fixture(), load_docs_fixture());
}

#[test]
fn emitted_bundle_writes_required_contract_artifacts() {
    let artifact_dir = temp_dir("bundle");
    let mut context = ArtifactContext::new(&artifact_dir);
    context.source_commit = "test-commit".to_string();
    let report = emit_default_contract_bundle(&context).expect("emit bundle");

    for artifact in &build_docs_contract_fixture().required_artifacts {
        assert!(
            artifact_dir.join(artifact).exists(),
            "missing required artifact `{artifact}`"
        );
    }

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&report.run_manifest_path).expect("read run manifest"))
            .expect("deserialize run manifest");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-engine.rgc-persistent-cache-run-manifest.v1")
    );
    assert_eq!(manifest["receipt_count"].as_u64(), Some(2));
    assert_eq!(manifest["scenario_count"].as_u64(), Some(5));
    assert!(
        !artifact_dir
            .join(".persistent_cache_contract.lock")
            .exists(),
        "bundle write lock should be released after publication",
    );
}

#[test]
fn markdown_doc_references_bin_and_suite() {
    let doc = load_doc_markdown();
    assert!(doc.contains("franken_persistent_cache_contract"));
    assert!(doc.contains("./scripts/run_persistent_cache_contract_suite.sh ci"));
    assert!(doc.contains("persistent_cache_contract.json"));
}

#[test]
fn runner_script_is_rch_backed_and_verifies_bundle() {
    let script = load_runner_script();
    assert!(script.contains("rch exec -- env"));
    assert!(script.contains("persistent_cache_contract.json"));
    assert!(script.contains("run_manifest.json"));
    assert!(script.contains("trace_ids.json"));
}

// ── New tests ───────────────────────────────────────────────────────

#[test]
fn docs_fixture_serde_round_trip() {
    let fixture = build_docs_contract_fixture();
    let json = serde_json::to_vec_pretty(&fixture).expect("serialize");
    let deserialized: DocsContractFixture = serde_json::from_slice(&json).expect("deserialize");
    assert_eq!(fixture, deserialized);
}

#[test]
fn docs_fixture_schema_version_is_correct() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-persistent-cache-docs.v1"
    );
}

#[test]
fn docs_fixture_bead_id_matches_constant() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture.bead_id, "bd-1lsy.7.10.1");
}

#[test]
fn docs_fixture_required_artifacts_non_empty() {
    let fixture = build_docs_contract_fixture();
    assert!(
        !fixture.required_artifacts.is_empty(),
        "required_artifacts must not be empty"
    );
}

#[test]
fn docs_fixture_required_artifacts_are_unique() {
    let fixture = build_docs_contract_fixture();
    let unique: BTreeSet<_> = fixture.required_artifacts.iter().collect();
    assert_eq!(
        unique.len(),
        fixture.required_artifacts.len(),
        "required_artifacts must contain no duplicates"
    );
}

#[test]
fn docs_fixture_key_fields_non_empty() {
    let fixture = build_docs_contract_fixture();
    assert!(
        !fixture.key_fields.is_empty(),
        "key_fields must not be empty"
    );
}

#[test]
fn docs_fixture_key_fields_include_module_id_and_source_hash() {
    let fixture = build_docs_contract_fixture();
    assert!(fixture.key_fields.contains(&"module_id".to_string()));
    assert!(fixture.key_fields.contains(&"source_hash".to_string()));
}

#[test]
fn docs_fixture_consumers_include_product_benchmark_replay() {
    let fixture = build_docs_contract_fixture();
    assert!(fixture.consumers.contains(&"product".to_string()));
    assert!(fixture.consumers.contains(&"benchmark".to_string()));
    assert!(fixture.consumers.contains(&"replay".to_string()));
}

#[test]
fn docs_fixture_scenario_ids_include_all_five_defaults() {
    let fixture = build_docs_contract_fixture();
    let expected = vec![
        "cache_hit",
        "cache_miss",
        "source_invalidation",
        "receipt_corruption",
        "rollback_plan",
    ];
    for id in &expected {
        assert!(
            fixture.scenario_ids.contains(&id.to_string()),
            "missing scenario_id: {id}"
        );
    }
    assert_eq!(fixture.scenario_ids.len(), expected.len());
}

#[test]
fn docs_fixture_equality_is_reflexive() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture, fixture.clone());
}

#[test]
fn artifact_context_default_trace_fields() {
    let ctx = ArtifactContext::new("/tmp/test-ctx");
    assert_eq!(ctx.trace_id, "trace.rgc.610a");
    assert_eq!(ctx.decision_id, "decision.rgc.610a");
    assert_eq!(ctx.policy_id, "policy.rgc.610a");
}

#[test]
fn artifact_context_default_source_commit_is_unknown() {
    let ctx = ArtifactContext::new("/tmp/test-ctx");
    assert_eq!(ctx.source_commit, "unknown");
}

#[test]
fn artifact_context_run_id_contains_component() {
    let ctx = ArtifactContext::new("/tmp/test-ctx");
    assert!(
        ctx.run_id.starts_with("run-persistent_cache_contract-"),
        "run_id should start with run-persistent_cache_contract-"
    );
}

#[test]
fn artifact_context_artifact_dir_is_preserved() {
    let ctx = ArtifactContext::new("/some/custom/path");
    assert_eq!(ctx.artifact_dir, PathBuf::from("/some/custom/path"));
}

#[test]
fn artifact_context_serde_round_trip() {
    let ctx = ArtifactContext::new("/tmp/test-serde");
    let json = serde_json::to_vec_pretty(&ctx).expect("serialize");
    let deserialized: ArtifactContext = serde_json::from_slice(&json).expect("deserialize");
    assert_eq!(ctx, deserialized);
}

#[test]
fn artifact_context_with_custom_source_commit() {
    let mut ctx = ArtifactContext::new("/tmp/test-custom");
    ctx.source_commit = "abc123def456".to_string();
    assert_eq!(ctx.source_commit, "abc123def456");
}

#[test]
fn emit_bundle_deterministic_hashes_across_calls() {
    let dir_a = temp_dir("determ-a");
    let dir_b = temp_dir("determ-b");
    let mut ctx_a = ArtifactContext::new(&dir_a);
    ctx_a.source_commit = "determ-test".to_string();
    ctx_a.generated_at_utc = "2026-01-01T00:00:00Z".to_string();
    ctx_a.run_id = "run-deterministic".to_string();
    let mut ctx_b = ctx_a.clone();
    ctx_b.artifact_dir = dir_b.clone();

    let report_a = emit_default_contract_bundle(&ctx_a).expect("emit a");
    let report_b = emit_default_contract_bundle(&ctx_b).expect("emit b");

    assert_eq!(
        report_a.contract.contract_hash, report_b.contract.contract_hash,
        "contract hash must be deterministic across identical contexts"
    );
}

#[test]
fn bundle_contract_json_schema_version() {
    let (artifact_dir, _report) = emit_bundle("contract-sv");
    let contract: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("persistent_cache_contract.json")).expect("read"),
    )
    .expect("parse");
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("franken-engine.rgc-persistent-cache-contract.v1")
    );
}

#[test]
fn bundle_contract_json_has_two_receipts() {
    let (_artifact_dir, report) = emit_bundle("receipts-count");
    assert_eq!(report.contract.receipts.len(), 2);
}

#[test]
fn bundle_contract_json_has_five_scenarios() {
    let (_artifact_dir, report) = emit_bundle("scenarios-count");
    assert_eq!(report.contract.scenarios.len(), 5);
}

#[test]
fn bundle_contract_all_scenarios_pass() {
    let (_artifact_dir, report) = emit_bundle("scenarios-pass");
    for scenario in &report.contract.scenarios {
        assert_eq!(
            scenario.outcome, "pass",
            "scenario `{}` did not pass",
            scenario.scenario_id
        );
    }
}

#[test]
fn bundle_trace_ids_json_structure() {
    let (artifact_dir, _report) = emit_bundle("trace-ids");
    let trace_ids: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("trace_ids.json")).expect("read"))
            .expect("parse");
    assert_eq!(
        trace_ids["schema_version"].as_str(),
        Some("franken-engine.rgc-persistent-cache-trace-ids.v1")
    );
    assert!(trace_ids["trace_ids"].is_array());
    let arr = trace_ids["trace_ids"].as_array().unwrap();
    assert!(!arr.is_empty(), "trace_ids array must not be empty");
}

#[test]
fn bundle_events_jsonl_has_lines() {
    let (artifact_dir, _report) = emit_bundle("events-jsonl");
    let events_content =
        fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    let lines: Vec<&str> = events_content.lines().collect();
    assert!(
        lines.len() >= 2,
        "events.jsonl should have at least 2 lines (one per receipt + scenarios)"
    );
    for line in &lines {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each events.jsonl line must be valid JSON");
        assert!(parsed["component"].is_string());
        assert!(parsed["event"].is_string());
    }
}

#[test]
fn bundle_events_jsonl_contains_receipt_and_scenario_events() {
    let (artifact_dir, _report) = emit_bundle("events-types");
    let events_content =
        fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    let mut has_receipt_event = false;
    let mut has_scenario_event = false;
    for line in events_content.lines() {
        let parsed: serde_json::Value = serde_json::from_str(line).expect("parse");
        match parsed["event"].as_str() {
            Some("cache_receipt_emitted") => has_receipt_event = true,
            Some("contract_scenario") => has_scenario_event = true,
            _ => {}
        }
    }
    assert!(
        has_receipt_event,
        "events.jsonl must contain cache_receipt_emitted"
    );
    assert!(
        has_scenario_event,
        "events.jsonl must contain contract_scenario"
    );
}

#[test]
fn bundle_env_json_structure() {
    let (artifact_dir, _report) = emit_bundle("env-json");
    let env_val: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("env.json")).expect("read"))
            .expect("parse");
    assert_eq!(
        env_val["schema_version"].as_str(),
        Some("franken-engine.env.v1")
    );
    assert!(env_val["project"]["name"].is_string());
    assert!(env_val["host"]["os"].is_string());
    assert!(env_val["toolchain"]["rustup_toolchain"].is_string());
    assert!(env_val["runtime"]["component"].is_string());
}

#[test]
fn bundle_env_json_source_commit_propagated() {
    let (artifact_dir, _report) = emit_bundle("env-commit");
    let env_val: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("env.json")).expect("read"))
            .expect("parse");
    assert_eq!(env_val["project"]["commit"].as_str(), Some("test-commit"));
}

#[test]
fn bundle_repro_lock_determinism_flags() {
    let (artifact_dir, _report) = emit_bundle("repro-lock");
    let repro: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("repro.lock")).expect("read"))
            .expect("parse");
    assert_eq!(
        repro["schema_version"].as_str(),
        Some("franken-engine.repro-lock.v1")
    );
    assert_eq!(repro["determinism"]["allow_network"].as_bool(), Some(false));
    assert_eq!(
        repro["determinism"]["allow_wall_clock"].as_bool(),
        Some(false)
    );
    assert_eq!(
        repro["determinism"]["allow_randomness"].as_bool(),
        Some(false)
    );
}

#[test]
fn bundle_repro_lock_contains_expected_outputs() {
    let (artifact_dir, _report) = emit_bundle("repro-outputs");
    let repro: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("repro.lock")).expect("read"))
            .expect("parse");
    let outputs = repro["expected_outputs"]
        .as_array()
        .expect("expected_outputs array");
    assert!(
        !outputs.is_empty(),
        "expected_outputs in repro.lock must not be empty"
    );
    for output in outputs {
        assert!(output["path"].is_string());
        let sha = output["sha256"].as_str().expect("sha256 field");
        assert!(
            sha.starts_with("sha256:"),
            "expected sha256 prefix in expected_outputs"
        );
    }
}

#[test]
fn bundle_commands_txt_contains_invocation() {
    let (artifact_dir, _report) = emit_bundle("commands-txt");
    let commands =
        fs::read_to_string(artifact_dir.join("commands.txt")).expect("read commands.txt");
    assert!(
        commands.contains("franken_persistent_cache_contract"),
        "commands.txt should reference the binary"
    );
}

#[test]
fn bundle_summary_md_contains_contract_header() {
    let (artifact_dir, _report) = emit_bundle("summary-md");
    let summary = fs::read_to_string(artifact_dir.join("summary.md")).expect("read summary.md");
    assert!(summary.contains("# Persistent Cache Contract Summary"));
    assert!(summary.contains("## Consumer Routes"));
    assert!(summary.contains("## Scenario Outcomes"));
}

#[test]
fn bundle_summary_md_lists_all_consumers() {
    let (artifact_dir, _report) = emit_bundle("summary-consumers");
    let summary = fs::read_to_string(artifact_dir.join("summary.md")).expect("read summary.md");
    assert!(summary.contains("`product`"));
    assert!(summary.contains("`benchmark`"));
    assert!(summary.contains("`replay`"));
}

#[test]
fn bundle_manifest_json_schema() {
    let (artifact_dir, _report) = emit_bundle("manifest-json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("manifest.json")).expect("read"))
            .expect("parse");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-engine.manifest.v1")
    );
    assert!(manifest["claim"]["claim_id"].is_string());
    assert!(manifest["provenance"]["trace_id"].is_string());
    assert!(manifest["artifacts"].is_array());
}

#[test]
fn bundle_written_files_map_covers_all_required_artifacts() {
    let (_artifact_dir, report) = emit_bundle("written-map");
    let fixture = build_docs_contract_fixture();
    for artifact in &fixture.required_artifacts {
        assert!(
            report.written_files.contains_key(artifact),
            "written_files should contain `{artifact}`"
        );
    }
}

#[test]
fn bundle_written_files_hashes_start_with_sha256() {
    let (_artifact_dir, report) = emit_bundle("written-hashes");
    for (name, hash) in &report.written_files {
        assert!(
            hash.starts_with("sha256:"),
            "hash for `{name}` should start with sha256:"
        );
    }
}

#[test]
fn bundle_run_manifest_artifacts_list_matches_required() {
    let (artifact_dir, _report) = emit_bundle("run-mf-arts");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("run_manifest.json")).expect("read"))
            .expect("parse");
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifacts array in run_manifest");
    let fixture = build_docs_contract_fixture();
    let artifact_names: BTreeSet<String> = artifacts
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    for required in &fixture.required_artifacts {
        assert!(
            artifact_names.contains(required),
            "run_manifest.json artifacts should include `{required}`"
        );
    }
}

#[test]
fn bundle_run_manifest_consumer_routes_list() {
    let (artifact_dir, _report) = emit_bundle("run-mf-consumers");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("run_manifest.json")).expect("read"))
            .expect("parse");
    let consumers = manifest["consumer_routes"]
        .as_array()
        .expect("consumer_routes in run_manifest");
    let consumer_strs: Vec<&str> = consumers.iter().filter_map(|v| v.as_str()).collect();
    assert!(consumer_strs.contains(&"product"));
    assert!(consumer_strs.contains(&"benchmark"));
    assert!(consumer_strs.contains(&"replay"));
}

#[test]
fn multiple_bundle_emissions_dont_interfere() {
    let (dir_a, report_a) = emit_bundle("multi-a");
    let (dir_b, report_b) = emit_bundle("multi-b");

    assert_ne!(dir_a, dir_b);

    let fixture = build_docs_contract_fixture();
    for artifact in &fixture.required_artifacts {
        assert!(
            dir_a.join(artifact).exists(),
            "bundle A missing `{artifact}`"
        );
        assert!(
            dir_b.join(artifact).exists(),
            "bundle B missing `{artifact}`"
        );
    }

    assert_eq!(
        report_a.contract.bead_id, report_b.contract.bead_id,
        "bead_id should be stable across emissions"
    );
}

#[test]
fn bundle_contract_invalidation_rules_non_empty() {
    let (_artifact_dir, report) = emit_bundle("inv-rules");
    assert!(
        !report.contract.invalidation_rules.is_empty(),
        "invalidation_rules must not be empty"
    );
    for rule in &report.contract.invalidation_rules {
        assert!(!rule.rule_id.is_empty());
        assert!(!rule.trigger.is_empty());
        assert!(!rule.fail_closed_behavior.is_empty());
    }
}

#[test]
fn bundle_contract_consumer_routes_non_empty() {
    let (_artifact_dir, report) = emit_bundle("consumer-routes");
    assert_eq!(report.contract.consumer_routes.len(), 3);
    for route in &report.contract.consumer_routes {
        assert!(!route.consumer.is_empty());
        assert!(!route.required_fields.is_empty());
        assert!(!route.usage.is_empty());
    }
}

#[test]
fn bundle_contract_key_material_examples_present() {
    let (_artifact_dir, report) = emit_bundle("key-material");
    assert!(
        report.contract.key_material_examples.len() >= 2,
        "should have at least two key material examples (v1 and v2)"
    );
    for material in &report.contract.key_material_examples {
        assert!(!material.module_id.is_empty());
        assert!(!material.source_hash.is_empty());
        assert!(!material.config_fingerprint.is_empty());
    }
}

#[test]
fn bundle_contract_rollback_plan_is_fail_closed() {
    let (_artifact_dir, report) = emit_bundle("rollback-fc");
    let plan = &report.contract.rollback_plan;
    assert!(plan.fail_closed, "rollback plan must be fail_closed");
    assert!(
        !plan.criteria.is_empty(),
        "rollback criteria must not be empty"
    );
    assert!(
        !plan.rollback_receipt_id.is_empty(),
        "rollback_receipt_id must not be empty"
    );
}

#[test]
fn bundle_contract_receipts_have_all_required_fields() {
    let (_artifact_dir, report) = emit_bundle("receipt-fields");
    for receipt in &report.contract.receipts {
        assert!(!receipt.receipt_id.is_empty());
        assert!(!receipt.cache_key_id.is_empty());
        assert!(!receipt.module_id.is_empty());
        assert!(!receipt.source_hash.is_empty());
        assert!(!receipt.artifact_hash.is_empty());
        assert!(!receipt.snapshot_state_hash.is_empty());
        assert!(!receipt.resolved_specifier.is_empty());
        assert!(!receipt.trace_id.is_empty());
        assert!(!receipt.decision_id.is_empty());
        assert!(!receipt.policy_id.is_empty());
        assert_eq!(receipt.consumers.len(), 3);
    }
}

#[test]
fn markdown_doc_references_key_fields() {
    let doc = load_doc_markdown();
    let key_fields = [
        "module_id",
        "source_hash",
        "policy_version",
        "trust_revision",
        "config_fingerprint",
        "dependency_graph_hash",
        "transform_profile",
        "runtime_mode",
        "engine_version_marker",
    ];
    for field in &key_fields {
        assert!(
            doc.contains(&format!("`{field}`")),
            "markdown doc should reference key field `{field}`"
        );
    }
}

#[test]
fn markdown_doc_has_required_sections() {
    let doc = load_doc_markdown();
    assert!(doc.contains("## Purpose"));
    assert!(doc.contains("## Contract Artifacts"));
    assert!(doc.contains("## Key Fields"));
    assert!(doc.contains("## Consumer Routes"));
    assert!(doc.contains("## Verification"));
}

#[test]
fn runner_script_has_all_modes() {
    let script = load_runner_script();
    assert!(script.contains("check)"));
    assert!(script.contains("test)"));
    assert!(script.contains("clippy)"));
    assert!(script.contains("run)"));
    assert!(script.contains("ci)"));
}

#[test]
fn runner_script_verifies_bundle_in_run_and_ci_modes() {
    let script = load_runner_script();
    assert!(
        script.contains("verify_bundle"),
        "runner script should call verify_bundle"
    );
}

#[test]
fn runner_script_checks_all_required_artifacts() {
    let script = load_runner_script();
    let fixture = build_docs_contract_fixture();
    for artifact in &fixture.required_artifacts {
        assert!(
            script.contains(artifact),
            "runner script should check for artifact `{artifact}`"
        );
    }
}
