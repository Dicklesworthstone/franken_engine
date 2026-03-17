#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-react-parity-gate.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_react_parity_gate_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReactParityGateContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: ContractTrack,
    downstream_consumers: Vec<String>,
    child_beads: Vec<ChildBead>,
    required_structured_log_fields: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChildBead {
    bead_id: String,
    policy_id: String,
    component: String,
    report_artifact: String,
    integration_test: String,
    owner_route_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ReactParityGateContract {
    serde_json::from_str(CONTRACT_JSON).expect("react parity gate contract must parse")
}

fn read_gate_script() -> String {
    let path = repo_root().join("scripts/run_rgc_react_parity_gate.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/rgc_react_parity_gate_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn rgc_807_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_REACT_PARITY_GATE_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# RGC React Parity Gate V1",
        "## Purpose",
        "## Scope",
        "## Child Reports",
        "## Gate Runner",
        "## Structured Logging And Artifacts",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_807_contract_is_versioned_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.9.7");
    assert_eq!(contract.generated_by, "bd-1lsy.9.7");
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert_eq!(contract.track.id, "RGC-807");
    assert_eq!(contract.track.name, "React Parity Gate");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-react-parity-gate.run-manifest.v1"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "fail_closed_on_rch_local_fallback"
    );
}

#[test]
fn rgc_807_child_beads_cover_compile_execution_and_catalog() {
    let contract = parse_contract();
    assert_eq!(
        contract.child_beads.len(),
        3,
        "expected three child bead rows"
    );

    let bead_ids: BTreeSet<_> = contract
        .child_beads
        .iter()
        .map(|row| row.bead_id.as_str())
        .collect();
    for bead_id in ["bd-1lsy.9.7.1", "bd-1lsy.9.7.2", "bd-1lsy.9.7.3"] {
        assert!(bead_ids.contains(bead_id), "missing child bead {bead_id}");
    }

    let report_artifacts: BTreeSet<_> = contract
        .child_beads
        .iter()
        .map(|row| row.report_artifact.as_str())
        .collect();
    for artifact in [
        "react_compile_parity_report.json",
        "react_ssr_client_parity_report.json",
        "react_mismatch_catalog.json",
    ] {
        assert!(
            report_artifacts.contains(artifact),
            "missing child report artifact {artifact}"
        );
    }
}

#[test]
fn rgc_807_required_log_fields_and_artifacts_are_present() {
    let contract = parse_contract();

    let fields: BTreeSet<_> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "runtime_lane",
        "seed",
        "outcome",
        "error_code",
    ] {
        assert!(fields.contains(field), "missing log field {field}");
    }

    let artifacts: BTreeSet<_> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "react_parity_gate_index.json",
        "react_compile_parity_report.json",
        "react_ssr_client_parity_report.json",
        "react_mismatch_catalog.json",
        "rgc_react_parity_gate_v1.json",
        "step_logs/step_000.log",
    ] {
        assert!(artifacts.contains(artifact), "missing artifact {artifact}");
    }
}

#[test]
fn rgc_807_downstream_consumers_include_docs_benchmarks_and_advisories() {
    let contract = parse_contract();
    let consumers: BTreeSet<_> = contract
        .downstream_consumers
        .iter()
        .map(String::as_str)
        .collect();

    for consumer in [
        "docs",
        "benchmarks",
        "advisories",
        "support_surface_contract",
    ] {
        assert!(
            consumers.contains(consumer),
            "missing downstream consumer {consumer}"
        );
    }
}

#[test]
fn rgc_807_gate_runner_paths_exist() {
    let contract = parse_contract();

    let gate_path = repo_root().join(&contract.gate_runner.script);
    let replay_path = repo_root().join(&contract.gate_runner.replay_wrapper);
    assert!(
        gate_path.exists(),
        "missing gate script {}",
        gate_path.display()
    );
    assert!(
        replay_path.exists(),
        "missing replay script {}",
        replay_path.display()
    );
}

#[test]
fn rgc_807_operator_verification_commands_are_present_and_repo_local() {
    let contract = parse_contract();

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/rgc_react_parity_gate_v1.json")),
        "operator verification must include contract json validation"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_rgc_react_parity_gate.sh ci")),
        "operator verification must include the gate script"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/e2e/rgc_react_parity_gate_replay.sh ci")),
        "operator verification must include the replay wrapper"
    );
    assert!(
        contract.operator_verification.iter().any(|cmd| {
            cmd.contains(
            "CARGO_TARGET_DIR=/data/projects/franken_engine/target_rch_rgc_react_parity_gate_verify"
        )
        }),
        "operator verification must include a repo-local rch target dir"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .all(|cmd| !cmd.contains("/tmp/rch_target")),
        "operator verification must not rely on /tmp rch target dirs"
    );
}

#[test]
fn rgc_807_gate_script_uses_repo_local_rch_target_and_rejects_local_fallback() {
    let script = read_gate_script();

    assert!(
        script.contains("target_rch_rgc_react_parity_gate_"),
        "gate script should use a dedicated repo-local remote target dir"
    );
    assert!(
        !script.contains("/tmp/rch_target_rgc_react_parity_gate_"),
        "gate script must not default to /tmp for the remote cargo target dir"
    );
    assert!(
        script.contains("rch reported local fallback; refusing local execution for heavy command"),
        "gate script must fail closed if rch falls back to local execution"
    );
}

#[test]
fn rgc_807_gate_script_reads_contract_operator_verification_and_emits_index() {
    let script = read_gate_script();

    assert!(
        script.contains("contract_operator_verification_json"),
        "gate script should collect published operator verification commands"
    );
    assert!(
        script.contains("jq '.operator_verification' \"$contract_json\""),
        "gate script should read operator verification commands from the contract JSON"
    );
    assert!(
        script.contains("\\\"react_parity_gate_index\\\":"),
        "gate manifest should include the parent parity gate index artifact"
    );
    assert!(
        script.contains("react_compile_parity_report.json"),
        "gate script should emit the compile parity child artifact"
    );
    assert!(
        script.contains("react_ssr_client_parity_report.json"),
        "gate script should emit the ssr child artifact"
    );
    assert!(
        script.contains("react_mismatch_catalog.json"),
        "gate script should emit the mismatch catalog child artifact"
    );
}

#[test]
fn rgc_807_gate_script_runs_focused_react_targets_only() {
    let script = read_gate_script();

    for test_name in [
        "react_compile_verification_integration",
        "react_ssr_verification_integration",
        "react_mismatch_catalog_integration",
        "rgc_react_parity_gate",
    ] {
        assert!(
            script.contains(test_name),
            "gate script must reference focused test target {test_name}"
        );
    }
}

#[test]
fn rgc_807_replay_wrapper_uses_latest_complete_bundle_and_prints_artifacts() {
    let script = read_replay_script();

    assert!(
        script.contains("latest_complete_run_dir()"),
        "replay wrapper should locate the latest complete artifact directory"
    );
    assert!(
        script.contains("newest directory ${latest_artifact_dir_path} is incomplete"),
        "replay wrapper should warn when it skips an incomplete newest directory"
    );
    assert!(
        script.contains("latest manifest: ${latest_run_dir}/run_manifest.json"),
        "replay wrapper should print the latest run manifest"
    );
    assert!(
        script.contains("latest trace ids: ${latest_run_dir}/trace_ids.json"),
        "replay wrapper should print the trace identifiers"
    );
    assert!(
        script.contains("latest index: ${latest_run_dir}/react_parity_gate_index.json"),
        "replay wrapper should print the parent index artifact"
    );
    assert!(
        script
            .contains("latest compile report: ${latest_run_dir}/react_compile_parity_report.json"),
        "replay wrapper should print the compile parity artifact"
    );
    assert!(
        script.contains("latest ssr report: ${latest_run_dir}/react_ssr_client_parity_report.json"),
        "replay wrapper should print the ssr parity artifact"
    );
    assert!(
        script.contains("latest mismatch catalog: ${latest_run_dir}/react_mismatch_catalog.json"),
        "replay wrapper should print the mismatch catalog artifact"
    );
    assert!(
        script.contains("latest contract: ${latest_run_dir}/rgc_react_parity_gate_v1.json"),
        "replay wrapper should print the copied contract"
    );
    assert!(
        script.contains("latest first step log: ${latest_run_dir}/step_logs/step_000.log"),
        "replay wrapper should print the first step log for operator triage"
    );
}

#[test]
fn rgc_807_contract_roundtrip_is_deterministic() {
    let contract = parse_contract();
    let json_a = serde_json::to_string_pretty(&contract).expect("serialize a");
    let recovered: ReactParityGateContract = serde_json::from_str(&json_a).expect("deserialize a");
    let json_b = serde_json::to_string_pretty(&recovered).expect("serialize b");
    assert_eq!(json_a, json_b, "serde roundtrip must be deterministic");
}
