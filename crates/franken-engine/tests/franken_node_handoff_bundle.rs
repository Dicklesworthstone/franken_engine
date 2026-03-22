#![forbid(unsafe_code)]
#![allow(
    clippy::assertions_on_constants,
    clippy::clone_on_copy,
    clippy::field_reassign_with_default,
    clippy::identity_op,
    clippy::len_zero,
    clippy::manual_abs_diff,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::unnecessary_get_then_check,
    clippy::useless_vec
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::engine_product_blocker_ledger::{
    BlockerLedgerGate, BlockerSeverity, COMPONENT as LEDGER_COMPONENT, RemediationStatus,
    SCHEMA_VERSION as LEDGER_SCHEMA_VERSION, build_seed_ledger,
};
use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-franken-node-handoff-bundle.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/franken_node_handoff_bundle_v1.json");
const SUPPORT_CONTRACT_JSON: &str = include_str!("../../../docs/support_surface_contract.json");

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HandoffBundleContract {
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
    sibling_smoke_checks: Vec<SiblingSmokeCheck>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct InputResolution {
    support_surface_contract_path: String,
    support_surface_contract_artifact_glob: String,
    blocker_ledger_env_var: String,
    blocker_ledger_artifact_glob: String,
    repo_split_contract_doc: String,
    sibling_repo_path: String,
    stale_after_hours: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SiblingSmokeCheck {
    check_id: String,
    description: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SupportSurfaceContract {
    readiness_answer_contract: ReadinessAnswerContract,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReadinessAnswerContract {
    product_ready_state: String,
    product_ready_owner_repo: String,
    product_ready_handoff_bead_id: String,
    operator_rule_summary: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> HandoffBundleContract {
    serde_json::from_str(CONTRACT_JSON).expect("handoff bundle contract must parse")
}

fn parse_support_contract() -> SupportSurfaceContract {
    serde_json::from_str(SUPPORT_CONTRACT_JSON).expect("support surface contract must parse")
}

fn load_runner_script() -> String {
    let path = repo_root().join("scripts/run_rgc_franken_node_handoff_bundle.sh");
    read_to_string(&path)
}

fn load_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh");
    read_to_string(&path)
}

#[test]
fn rgc_408c_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_FRANKEN_NODE_HANDOFF_BUNDLE_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC FrankenNode Handoff Bundle V1",
        "## Purpose",
        "## Inputs",
        "## Bundle Artifacts",
        "## Sibling Smoke Checks",
        "## Failure Semantics",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_408c_contract_is_versioned_and_references_required_inputs_and_outputs() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.5.10.3");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-franken-node-handoff-bundle-v1"
    );
    assert_eq!(contract.generated_by, "bd-1lsy.5.10.3");
    assert!(contract.generated_at_utc.ends_with('Z'));

    for input in [
        "docs/RGC_FRANKEN_NODE_HANDOFF_BUNDLE_V1.md",
        "docs/support_surface_contract.json",
        "docs/REPO_SPLIT_CONTRACT.md",
    ] {
        assert!(
            contract.source_inputs.iter().any(|value| value == input),
            "missing source input {input}"
        );
    }

    assert_eq!(
        contract.input_resolution.support_surface_contract_path,
        "docs/support_surface_contract.json"
    );
    assert_eq!(
        contract.input_resolution.blocker_ledger_env_var,
        "RGC_HANDOFF_BLOCKER_LEDGER_PATH"
    );
    assert_eq!(
        contract.input_resolution.repo_split_contract_doc,
        "docs/REPO_SPLIT_CONTRACT.md"
    );
    assert_eq!(
        contract.input_resolution.sibling_repo_path,
        "/dp/franken_node"
    );
    assert_eq!(contract.input_resolution.stale_after_hours, 720);

    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "franken_node_handoff_manifest.json",
        "sibling_smoke_verification.json",
        "support_surface_summary.md",
        "franken_node_handoff_bundle_contract.json",
        "support_surface_contract.json",
        "engine_product_blocker_ledger.json",
        "repo_split_contract.md",
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

    let mut seen = BTreeSet::new();
    for artifact in &contract.required_artifacts {
        assert!(
            seen.insert(artifact),
            "duplicate entry in required_artifacts: {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_franken_node_handoff_bundle.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "ci");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-franken-node-handoff-bundle.run-manifest.v1"
    );
}

#[test]
fn rgc_408c_smoke_check_ids_are_unique_and_cover_required_contract_checks() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();

    for check in &contract.sibling_smoke_checks {
        assert!(
            seen.insert(check.check_id.as_str()),
            "duplicate smoke check id: {}",
            check.check_id
        );
        assert!(
            !check.description.trim().is_empty(),
            "smoke check description must be non-empty for {}",
            check.check_id
        );
    }

    for check_id in [
        "sibling_repo_exists",
        "one_way_dependency_contract",
        "support_contract_delegates_product_ready",
        "unresolved_blockers_not_orphaned",
        "cohort_rollups_present",
    ] {
        assert!(seen.contains(check_id), "missing smoke check {check_id}");
    }
}

#[test]
fn rgc_408c_support_contract_still_delegates_product_ready_to_franken_node_handoff() {
    let readiness = &parse_support_contract().readiness_answer_contract;

    assert_eq!(
        readiness.product_ready_state,
        "delegated_to_franken_node_handoff"
    );
    assert_eq!(readiness.product_ready_owner_repo, "franken_node");
    assert!(
        !readiness.product_ready_handoff_bead_id.trim().is_empty(),
        "support-surface contract must retain a downstream handoff bead id"
    );
    assert!(
        readiness.operator_rule_summary.contains("franken_node"),
        "operator summary should mention downstream franken_node handoff"
    );
}

#[test]
fn rgc_408c_seed_blocker_ledger_is_usable_handoff_input() {
    let ledger = build_seed_ledger();
    assert_eq!(ledger.version, LEDGER_SCHEMA_VERSION);
    assert!(!ledger.blockers.is_empty(), "seed ledger must not be empty");
    assert!(
        !ledger.cohort_rollups.is_empty(),
        "seed ledger must expose cohort rollups"
    );

    let orphaned_unresolved: Vec<_> = ledger
        .blockers
        .iter()
        .filter(|entry| {
            matches!(
                entry.severity,
                BlockerSeverity::Blocking | BlockerSeverity::Degraded
            ) && !matches!(
                entry.remediation,
                RemediationStatus::Verified | RemediationStatus::WontFix
            ) && entry.tracking_bead.as_deref().unwrap_or("").is_empty()
                && entry.owner.as_deref().unwrap_or("").is_empty()
        })
        .collect();
    assert!(
        orphaned_unresolved.is_empty(),
        "seed ledger should not contain orphaned unresolved blocking/degraded entries"
    );

    let report = BlockerLedgerGate::with_defaults().evaluate(&ledger);
    assert_eq!(report.schema_version, LEDGER_SCHEMA_VERSION);
    assert_eq!(report.component, LEDGER_COMPONENT);
    assert_eq!(report.total_blockers, ledger.blockers.len());
    assert!(
        report.cohort_count > 0,
        "gate report must retain cohort counts"
    );
}

#[test]
fn rgc_408c_runner_script_requires_rch_repo_local_targets_and_handoff_outputs() {
    let script = load_runner_script();

    for snippet in [
        "rch is required for RGC franken_node handoff bundle heavy commands",
        "RGC_HANDOFF_BLOCKER_LEDGER_PATH",
        "RGC_HANDOFF_SIBLING_REPO_PATH",
        "docs/REPO_SPLIT_CONTRACT.md",
        "json_file_is_valid()",
        "franken_node_handoff_manifest.json",
        "sibling_smoke_verification.json",
        "support_surface_summary.md",
        "validate source inputs",
        "==> validation failed",
        "cargo check -p frankenengine-engine --test franken_node_handoff_bundle",
        "cargo test -p frankenengine-engine --test franken_node_handoff_bundle",
        "cargo clippy -p frankenengine-engine --test franken_node_handoff_bundle -- -D warnings",
        "target_rch_rgc_franken_node_handoff_bundle_",
        "engine-product blocker ledger contains orphaned unresolved blocking/degraded entries",
        "missing engine-product blocker ledger input",
        "support contract JSON is invalid",
        "blocker ledger JSON is invalid",
        "blocker ledger unavailable",
        "engine_product_blocker_ledger: (if ($blocker_ledger_path | length) > 0 then $blocker_ledger_path else null end)",
    ] {
        assert!(
            script.contains(snippet),
            "runner script missing required snippet: {snippet}"
        );
    }

    assert!(
        !script.contains("/tmp/rch_target_franken_engine"),
        "runner script must not default target dir under /tmp"
    );
}

#[test]
fn rgc_408c_runner_script_enforces_split_contract_and_support_delegation_checks() {
    let script = load_runner_script();

    for snippet in [
        "| . as $row",
        "index($row.support_status)",
        "product_ready_owner_repo == \"franken_node\"",
        "product_ready_state == \"delegated_to_franken_node_handoff\"",
        "grep -Fq -- '- `franken_node` -> `frankenengine-engine`'",
        "grep -Fq -- '- `franken_engine` -> `franken_node`'",
        "sibling_repo_exists",
        "one_way_dependency_contract",
        "support_contract_delegates_product_ready",
    ] {
        assert!(
            script.contains(snippet),
            "runner script missing split-contract/delegation check snippet: {snippet}"
        );
    }
}

#[test]
fn rgc_408c_replay_script_requires_complete_bundle_and_prints_key_artifacts() {
    let script = load_replay_script();

    for snippet in [
        "franken_node_handoff_manifest.json",
        "sibling_smoke_verification.json",
        "support_surface_summary.md",
        "franken_node_handoff_bundle_contract.json",
        "repo_split_contract.md",
        "latest blocker ledger unavailable",
        "latest first step log unavailable",
        "latest handoff manifest",
        "latest smoke verification",
        "latest summary",
        "latest first step log",
    ] {
        assert!(
            script.contains(snippet),
            "replay script missing required snippet: {snippet}"
        );
    }
}

#[test]
fn rgc_408c_operator_verification_commands_reference_env_runner_replay_and_rch_test() {
    let contract = parse_contract();

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains(
                "RGC_HANDOFF_BLOCKER_LEDGER_PATH=/abs/path/engine_product_blocker_ledger.json"
            )),
        "operator verification must require an explicit blocker-ledger path example"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_rgc_franken_node_handoff_bundle.sh ci")),
        "operator verification must reference the handoff runner"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh ci")),
        "operator verification must reference the handoff replay wrapper"
    );
    assert!(
        contract.operator_verification.iter().any(|cmd| cmd
            .contains("cargo test -p frankenengine-engine --test franken_node_handoff_bundle")),
        "operator verification must include the focused rch-backed cargo test"
    );
}
