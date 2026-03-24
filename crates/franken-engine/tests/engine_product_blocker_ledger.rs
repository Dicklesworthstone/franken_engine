#![forbid(unsafe_code)]
#![allow(
    clippy::assertions_on_constants,
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::useless_vec
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::engine_product_blocker_ledger::{
    BEAD_ID as LEDGER_BEAD_ID, BlockerLedger, COMPONENT as LEDGER_COMPONENT, GateReport,
};
use serde::Deserialize;

#[allow(dead_code)]
#[path = "../src/bin/franken_engine_product_blocker_ledger.rs"]
mod blocker_ledger_bin;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-engine-product-blocker-ledger.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/engine_product_blocker_ledger_v1.json");

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    generated_by: String,
    generated_at_utc: String,
    source_inputs: Vec<String>,
    input_resolution: InputResolution,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    failure_conditions: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct InputResolution {
    support_surface_contract_path: String,
    bead_snapshot_command: String,
    stale_after_hours: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OwnerRoutingReport {
    orphaned_unresolved_count: usize,
    routes: Vec<OwnerRoutingEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OwnerRoutingEntry {
    blocker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CohortRollupArtifact {
    cohort_rollups: Vec<CohortRollupArtifactRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CohortRollupArtifactRow {
    cohort_name: String,
    blocker_ids: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Contract {
    serde_json::from_str(CONTRACT_JSON).expect("blocker ledger contract must parse")
}

fn load_runner_script() -> String {
    let path = repo_root().join("scripts/run_rgc_engine_product_blocker_ledger.sh");
    read_to_string(&path)
}

fn load_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh");
    read_to_string(&path)
}

fn fresh_temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "franken_engine_product_blocker_ledger_{label}_{}_{}",
        std::process::id(),
        unique
    ));
    fs::create_dir_all(&path)
        .unwrap_or_else(|err| panic!("failed to create temp dir {}: {err}", path.display()));
    path
}

#[test]
fn rgc_408b_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Engine-Product Blocker Ledger V1",
        "## Purpose",
        "## Inputs",
        "## Bundle Artifacts",
        "## Gate Runner",
        "## Failure Semantics",
        "## Operator Verification",
        "## Replay Workflow",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_408b_contract_is_versioned_and_declares_required_outputs() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.5.10.2");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-engine-product-blocker-ledger-v1"
    );
    assert_eq!(contract.generated_by, "bd-1lsy.5.10.2");
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert_eq!(
        contract.input_resolution.support_surface_contract_path,
        "docs/support_surface_contract.json"
    );
    assert_eq!(
        contract.input_resolution.bead_snapshot_command,
        "br list --all --json"
    );
    assert_eq!(contract.input_resolution.stale_after_hours, 720);

    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "engine_product_blocker_ledger.json",
        "cohort_readiness_rollup.json",
        "owner_routing_report.json",
        "gate_report.json",
        "support_surface_contract.json",
        "beads_snapshot.json",
        "step_logs/step_*.log",
    ] {
        assert!(
            contract
                .required_artifacts
                .iter()
                .any(|value| value == artifact),
            "missing required artifact {artifact}"
        );
    }

    for condition in [
        "missing_support_surface_contract",
        "invalid_support_surface_contract",
        "contradictory_support_contract_readiness_metadata",
        "missing_tracking_bead_in_snapshot",
        "unresolved_blocker_without_owner_or_bead",
        "stale_support_surface_contract",
        "missing_required_bundle_artifacts",
    ] {
        assert!(
            contract
                .failure_conditions
                .iter()
                .any(|value| value == condition),
            "missing failure condition {condition}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_engine_product_blocker_ledger.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "ci");
}

#[test]
fn rgc_408b_runner_script_uses_rch_and_live_bead_snapshot() {
    let script = load_runner_script();

    for needle in [
        "br list --all --json",
        "cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger",
        "--emit-local-bundle-json",
        "cargo check -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger",
        "cargo test -p frankenengine-engine --test engine_product_blocker_ledger",
        "cargo clippy -p frankenengine-engine --bin franken_engine_product_blocker_ledger --test engine_product_blocker_ledger -- -D warnings",
        "target_rch_rgc_engine_product_blocker_ledger_",
        "support-surface contract does not expose delegated franken-node handoff readiness metadata",
        "engine_product_blocker_ledger.json",
        "cohort_readiness_rollup.json",
        "owner_routing_report.json",
        "gate_report.json",
    ] {
        assert!(
            script.contains(needle),
            "runner missing required text: {needle}"
        );
    }
}

#[test]
fn rgc_408b_replay_wrapper_requires_complete_bundle() {
    let script = load_replay_script();

    assert!(
        script.contains("latest_complete_run_dir()"),
        "replay wrapper should locate the latest complete artifact directory"
    );
    assert!(
        script.contains("RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_REPLAY_RUN_DIR"),
        "replay wrapper should support exact-run-dir targeting for preserved bundles"
    );
    assert!(
        script.contains("run_dir_is_complete()"),
        "replay wrapper should centralize complete-bundle checks"
    );
    assert!(
        script.contains("warn_about_failed_gate_replay_source()"),
        "replay wrapper should centralize failed-gate replay warnings"
    );
    assert!(
        script.contains("pre_run_latest_artifact_dir_path"),
        "replay wrapper should remember the pre-run latest artifact directory so failed reruns can distinguish previous bundles from current output"
    );
    assert!(
        script.contains("if [[ -z \"${explicit_run_dir}\" && \"${mode}\" != \"show\" ]]; then"),
        "replay wrapper should skip rerunning the gate when an exact run directory is provided or show mode is requested"
    );
    assert!(
        script.contains("explicit run directory is incomplete"),
        "replay wrapper should fail closed on incomplete exact-run-dir targets"
    );
    assert!(
        script.contains("newest directory ${latest_artifact_dir_path} is incomplete"),
        "replay wrapper should warn when it skips an incomplete newest directory"
    );
    assert!(
        script.contains("replay output reflects latest complete run directory"),
        "replay wrapper should warn when it falls back to an older latest-complete bundle after a failed rerun"
    );
    assert!(
        script.contains("replay output reflects previous latest complete run directory"),
        "replay wrapper should distinguish failed reruns that never produced a new bundle from the current-run case"
    );
    assert!(
        script.contains("replay output reflects current run directory"),
        "replay wrapper should distinguish failed reruns that still produced the current complete bundle"
    );
    for needle in [
        "run_manifest.json",
        "trace_ids.json",
        "engine_product_blocker_ledger.json",
        "cohort_readiness_rollup.json",
        "owner_routing_report.json",
        "gate_report.json",
        "latest owner routing report",
    ] {
        assert!(script.contains(needle), "replay wrapper missing {needle}");
    }
}

#[test]
fn rgc_408b_doc_describes_replay_modes_and_exact_run_dir() {
    let path = repo_root().join("docs/RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_V1.md");
    let doc = read_to_string(&path);

    for needle in [
        "./scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh show",
        "./scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh ci",
        "RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_REPLAY_RUN_DIR=artifacts/rgc_engine_product_blocker_ledger/<timestamp>",
        "fails closed on incomplete explicit run directories",
        "previous latest complete bundle",
    ] {
        assert!(doc.contains(needle), "replay workflow doc missing {needle}");
    }
}

#[test]
fn rgc_408b_emit_bundle_enriches_owners_from_bead_snapshot() {
    let root = fresh_temp_dir("emit_ok");
    let artifact_dir = root.join("bundle");
    let beads_path = root.join("beads.json");
    let support_contract_path = root.join("support_surface_contract.json");

    fs::write(
        &beads_path,
        serde_json::to_string_pretty(&serde_json::json!([
            {
                "id": "bd-1lsy.5.2",
                "status": "in_progress",
                "assignee": "GentleDog",
                "title": "[RGC-402] Implement CJS loader and ESM<->CJS interop behavior"
            },
            {
                "id": "bd-1lsy.5.7.2",
                "status": "open",
                "assignee": "PearlTower",
                "title": "[RGC-405B] Verify SSR and client-entry React module graphs with deterministic receipts"
            },
            {
                "id": "bd-1lsy.5.9.2",
                "status": "open",
                "assignee": "BronzeGlen",
                "title": "[RGC-407B] Implement the native-addon safety membrane and fast-path routing"
            },
            {
                "id": "bd-1lsy.4.12.2",
                "status": "closed",
                "assignee": "PearlTower",
                "title": "[RGC-312B] Implement deterministic RegExp compilation, automata caches, and tail-risk guards"
            }
        ]))
        .expect("bead snapshot JSON should encode"),
    )
    .expect("bead snapshot should write");

    fs::write(
        &support_contract_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "readiness_answer_contract": {
                "engine_ready_when_support_status_in": ["shipped"],
                "engine_blocked_when_support_status_in": ["deferred", "unsupported", "candidate"],
                "product_ready_state": "delegated_to_franken_node_handoff",
                "product_ready_owner_repo": "franken_node",
                "product_ready_handoff_bead_id": "bd-1lsy.5.10.2",
                "operator_rule_summary": "Engine-ready rows are shipped; product-ready remains delegated downstream."
            }
        }))
        .expect("support contract JSON should encode"),
    )
    .expect("support contract should write");

    let config = blocker_ledger_bin::EmitConfig {
        artifact_dir: artifact_dir.clone(),
        beads_json: beads_path,
        support_contract_json: support_contract_path,
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        generated_at_utc: "2026-03-21T21:45:00Z".to_string(),
    };

    let report = blocker_ledger_bin::emit_bundle(&config).expect("bundle emission should succeed");
    assert!(Path::new(&report.ledger_path).exists());
    assert!(Path::new(&report.cohort_rollup_path).exists());
    assert!(Path::new(&report.owner_routing_report_path).exists());
    assert!(Path::new(&report.gate_report_path).exists());

    let ledger: BlockerLedger = serde_json::from_str(&read_to_string(
        &artifact_dir.join("engine_product_blocker_ledger.json"),
    ))
    .expect("ledger JSON should parse");
    assert_eq!(
        ledger.version,
        "franken-engine.engine-product-blocker-ledger.v1"
    );
    assert!(!ledger.cohort_rollups.is_empty());

    let cjs_blocker = ledger
        .blockers
        .iter()
        .find(|blocker| blocker.id == "blk_cjs_interop")
        .expect("cjs blocker must exist");
    assert_eq!(cjs_blocker.owner.as_deref(), Some("GentleDog"));
    assert_eq!(cjs_blocker.remediation.as_str(), "in_progress");

    let regex_blocker = ledger
        .blockers
        .iter()
        .find(|blocker| blocker.id == "blk_regex_unicode")
        .expect("regex blocker must exist");
    assert_eq!(regex_blocker.owner.as_deref(), Some("PearlTower"));
    assert_eq!(regex_blocker.remediation.as_str(), "verified");

    let gate_report: GateReport =
        serde_json::from_str(&read_to_string(&artifact_dir.join("gate_report.json")))
            .expect("gate report should parse");
    assert_eq!(gate_report.component, LEDGER_COMPONENT);
    assert_eq!(gate_report.bead_id, LEDGER_BEAD_ID);
    assert_eq!(gate_report.total_blockers, ledger.blockers.len());

    let owner_routing: OwnerRoutingReport = serde_json::from_str(&read_to_string(
        &artifact_dir.join("owner_routing_report.json"),
    ))
    .expect("owner routing report should parse");
    assert_eq!(owner_routing.orphaned_unresolved_count, 0);
    let route_ids = owner_routing
        .routes
        .iter()
        .map(|route| route.blocker_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        route_ids,
        vec![
            "blk_cjs_interop",
            "blk_cli_help",
            "blk_native_addon",
            "blk_obs_mode",
            "blk_react_ssr",
            "blk_regex_unicode",
        ]
    );

    let cohort_rollup_artifact: CohortRollupArtifact = serde_json::from_str(&read_to_string(
        &artifact_dir.join("cohort_readiness_rollup.json"),
    ))
    .expect("cohort rollup artifact should parse");
    let cohort_names = cohort_rollup_artifact
        .cohort_rollups
        .iter()
        .map(|rollup| rollup.cohort_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        cohort_names,
        vec!["cli_surface", "react_ecosystem", "tier_1_critical"]
    );
    let tier_one = cohort_rollup_artifact
        .cohort_rollups
        .iter()
        .find(|rollup| rollup.cohort_name == "tier_1_critical")
        .expect("tier_1_critical cohort must exist");
    assert_eq!(
        tier_one.blocker_ids,
        vec!["blk_cjs_interop", "blk_native_addon"]
    );
}

#[test]
fn rgc_408b_emit_bundle_fails_closed_when_tracking_beads_are_missing() {
    let root = fresh_temp_dir("emit_fail_missing_bead");
    let artifact_dir = root.join("bundle");
    let beads_path = root.join("beads.json");
    let support_contract_path = root.join("support_surface_contract.json");

    fs::write(
        &beads_path,
        serde_json::to_string_pretty(&serde_json::json!([
            {
                "id": "bd-1lsy.5.2",
                "status": "in_progress",
                "assignee": "GentleDog",
                "title": "[RGC-402] Implement CJS loader and ESM<->CJS interop behavior"
            }
        ]))
        .expect("bead snapshot JSON should encode"),
    )
    .expect("bead snapshot should write");

    fs::write(
        &support_contract_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "readiness_answer_contract": {
                "engine_ready_when_support_status_in": ["shipped"],
                "engine_blocked_when_support_status_in": ["deferred", "unsupported", "candidate"],
                "product_ready_state": "delegated_to_franken_node_handoff",
                "product_ready_owner_repo": "franken_node",
                "product_ready_handoff_bead_id": "bd-1lsy.5.10.2",
                "operator_rule_summary": "Engine-ready rows are shipped; product-ready remains delegated downstream."
            }
        }))
        .expect("support contract JSON should encode"),
    )
    .expect("support contract should write");

    let config = blocker_ledger_bin::EmitConfig {
        artifact_dir,
        beads_json: beads_path,
        support_contract_json: support_contract_path,
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        generated_at_utc: "2026-03-21T21:45:00Z".to_string(),
    };

    let error = blocker_ledger_bin::emit_bundle(&config).expect_err("bundle must fail closed");
    assert!(
        error.contains("tracking beads missing from snapshot"),
        "unexpected error: {error}"
    );
}

#[test]
fn rgc_408b_emit_bundle_fails_closed_on_bad_support_contract() {
    let root = fresh_temp_dir("emit_fail_support_contract");
    let artifact_dir = root.join("bundle");
    let beads_path = root.join("beads.json");
    let support_contract_path = root.join("support_surface_contract.json");

    fs::write(
        &beads_path,
        serde_json::to_string_pretty(&serde_json::json!([
            {
                "id": "bd-1lsy.5.2",
                "status": "in_progress",
                "assignee": "GentleDog",
                "title": "[RGC-402] Implement CJS loader and ESM<->CJS interop behavior"
            },
            {
                "id": "bd-1lsy.5.7.2",
                "status": "open",
                "assignee": "PearlTower",
                "title": "[RGC-405B] Verify SSR and client-entry React module graphs with deterministic receipts"
            },
            {
                "id": "bd-1lsy.5.9.2",
                "status": "open",
                "assignee": "BronzeGlen",
                "title": "[RGC-407B] Implement the native-addon safety membrane and fast-path routing"
            },
            {
                "id": "bd-1lsy.4.12.2",
                "status": "closed",
                "assignee": "PearlTower",
                "title": "[RGC-312B] Implement deterministic RegExp compilation, automata caches, and tail-risk guards"
            }
        ]))
        .expect("bead snapshot JSON should encode"),
    )
    .expect("bead snapshot should write");

    fs::write(
        &support_contract_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "readiness_answer_contract": {
                "engine_ready_when_support_status_in": ["shipped"],
                "engine_blocked_when_support_status_in": [],
                "product_ready_state": "product_ready_here",
                "product_ready_owner_repo": "franken_engine",
                "product_ready_handoff_bead_id": "",
                "operator_rule_summary": "bad contract"
            }
        }))
        .expect("support contract JSON should encode"),
    )
    .expect("support contract should write");

    let config = blocker_ledger_bin::EmitConfig {
        artifact_dir,
        beads_json: beads_path,
        support_contract_json: support_contract_path,
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        generated_at_utc: "2026-03-21T21:45:00Z".to_string(),
    };

    let error = blocker_ledger_bin::emit_bundle(&config).expect_err("bundle must fail closed");
    assert!(
        error.contains("product_ready_state must be delegated_to_franken_node_handoff"),
        "unexpected error: {error}"
    );
}
