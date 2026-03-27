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
use std::path::{Path, PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::minimized_repro_extraction::{
    BEAD_ID as REPRO_BEAD_ID, COMPONENT as REPRO_COMPONENT, ExtractionConfig, ExtractionEngine,
    FailureCategory, MinimizationStrategy, MinimizedRepro, POLICY_ID as REPRO_POLICY_ID,
    ReproInput, TriageFinding, TriageOwner, TriageSeverity,
};
use frankenengine_engine::react_doctor_preflight::{
    COMPONENT as DOCTOR_COMPONENT, DOCTOR_PREFLIGHT_BEAD_ID, DOCTOR_PREFLIGHT_POLICY_ID,
    DOCTOR_PREFLIGHT_SCHEMA_VERSION, DoctorConfig, build_support_bundle, run_doctor, run_preflight,
};
use frankenengine_engine::react_mismatch_catalog::{
    COMPONENT as MISMATCH_COMPONENT, ComparisonTarget, MISMATCH_CATALOG_BEAD_ID,
    MISMATCH_CATALOG_POLICY_ID, MismatchDomain, MismatchEntry, MismatchSeverity, RemediationStatus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Deserialize;
use serde_json::{Value, json};

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-react-doctor-preflight.v1";
const SUPPORT_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.react-doctor-support-contract.v1";
const SUPPORT_REPRO_INDEX_SCHEMA_VERSION: &str = "franken-engine.react-support-repro-index.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_react_doctor_preflight_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc912bContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    policy_id: String,
    track: ContractTrack,
    module_contract: ModuleContract,
    dependency_routes: Vec<DependencyRoute>,
    verdict_classes: Vec<VerdictClass>,
    required_structured_log_fields: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ModuleContract {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    component: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DependencyRoute {
    bead_id: String,
    policy_id: String,
    component: String,
    contract_role: String,
    required_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct VerdictClass {
    verdict: String,
    blocks_compile_or_build: bool,
    emitted_surface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Rgc912bContract {
    serde_json::from_str(CONTRACT_JSON).expect("RGC-912B contract must parse")
}

fn read_runner_script() -> String {
    read_to_string(&repo_root().join("scripts/run_rgc_react_doctor_preflight.sh"))
}

fn read_replay_script() -> String {
    read_to_string(&repo_root().join("scripts/e2e/rgc_react_doctor_preflight_replay.sh"))
}

fn epoch(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn mismatch_entry(
    entry_id: &str,
    domain: MismatchDomain,
    severity: MismatchSeverity,
    target: ComparisonTarget,
    remediation: RemediationStatus,
) -> MismatchEntry {
    MismatchEntry {
        entry_id: entry_id.to_string(),
        domain,
        severity,
        target,
        summary: format!("Mismatch for {entry_id}"),
        expected_behavior: "expected behavior".to_string(),
        actual_behavior: "actual behavior".to_string(),
        reproduction: format!("fixtures/{entry_id}.json"),
        remediation,
        advisory: format!("advisory for {entry_id}"),
        react_version_range: ">=18.0.0".to_string(),
        evidence_hash: ContentHash::compute(entry_id.as_bytes()),
        detected_epoch: epoch(3),
        verified_epoch: epoch(6),
        tags: ["react", "doctor", "preflight"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

fn sample_mismatch_entries() -> Vec<MismatchEntry> {
    vec![
        mismatch_entry(
            "jsx-transform-warning",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
            ComparisonTarget::NodeJs,
            RemediationStatus::Workaround,
        ),
        mismatch_entry(
            "ssr-config-error",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::InProgress,
        ),
        mismatch_entry(
            "module-graph-critical",
            MismatchDomain::ModuleGraph,
            MismatchSeverity::Critical,
            ComparisonTarget::Bun,
            RemediationStatus::None,
        ),
    ]
}

fn triage_severity_str(severity: TriageSeverity) -> &'static str {
    match severity {
        TriageSeverity::Info => "info",
        TriageSeverity::Warning => "warning",
        TriageSeverity::Error => "error",
        TriageSeverity::Critical => "critical",
    }
}

fn build_support_repro_index_artifact() -> Value {
    let mismatch_entries = sample_mismatch_entries();

    let repro_input = ReproInput::new(
        "react-hydration-repro".to_string(),
        FailureCategory::HydrationMismatch,
        120,
        7,
        5,
    );
    let repro = MinimizedRepro::new(
        repro_input.input_id.clone(),
        MinimizationStrategy::DeltaDebugging,
        18,
        120,
        true,
        2_500_000,
    );
    let finding = TriageFinding {
        category: FailureCategory::HydrationMismatch,
        owner: ExtractionEngine::default_owner(FailureCategory::HydrationMismatch),
        severity: TriageSeverity::Error,
        summary: "Hydration mismatch still reproduces after minimization".to_string(),
        repro_hash: Some(repro.repro_hash),
        recommended_action:
            "Route to the React integration lane and preserve the minimized fixture".to_string(),
    };

    let mut engine = ExtractionEngine::new(ExtractionConfig::default());
    engine.add_input(repro_input.clone());
    engine.add_repro(repro.clone());
    engine.add_finding(finding.clone());
    let report = engine.evaluate(epoch(7));

    json!({
        "schema_version": SUPPORT_REPRO_INDEX_SCHEMA_VERSION,
        "bead_id": DOCTOR_PREFLIGHT_BEAD_ID,
        "policy_id": DOCTOR_PREFLIGHT_POLICY_ID,
        "component": DOCTOR_COMPONENT,
        "upstream_catalog_bead_id": MISMATCH_CATALOG_BEAD_ID,
        "upstream_repro_bead_id": REPRO_BEAD_ID,
        "verdict": report.verdict.to_string(),
        "entries": [
            {
                "mismatch_entry_id": mismatch_entries[1].entry_id.clone(),
                "domain": mismatch_entries[1].domain.to_string(),
                "severity": mismatch_entries[1].severity.to_string(),
                "target": mismatch_entries[1].target.to_string(),
                "owner_route": finding.owner.to_string(),
                "owner_route_bead": REPRO_BEAD_ID,
                "triage_severity": triage_severity_str(finding.severity),
                "repro_input_id": repro_input.input_id,
                "repro_hash": repro.repro_hash,
                "repro_command": "frankenctl react doctor --input fixtures/react_hydration_mismatch.json --json",
                "recommended_action": finding.recommended_action,
                "source_reproduction": mismatch_entries[1].reproduction.clone()
            }
        ]
    })
}

fn build_support_contract_artifact() -> Value {
    let entries = sample_mismatch_entries();
    let config = DoctorConfig {
        current_epoch: epoch(7),
        ..DoctorConfig::default()
    };
    let report = run_doctor(&config, &entries).expect("doctor report should build");
    let preflight = run_preflight(&config, &entries).expect("preflight report should build");
    let bundle = build_support_bundle(&report).expect("support bundle should build");
    let repro_index = build_support_repro_index_artifact();

    let support_bundle_categories = bundle
        .entries
        .iter()
        .map(|entry| entry.category.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    json!({
        "schema_version": SUPPORT_CONTRACT_SCHEMA_VERSION,
        "bead_id": DOCTOR_PREFLIGHT_BEAD_ID,
        "policy_id": DOCTOR_PREFLIGHT_POLICY_ID,
        "component": DOCTOR_COMPONENT,
        "entries_analyzed": preflight.entries_analyzed,
        "passed": preflight.passed,
        "blocker_count": preflight.blocker_count(),
        "advisory_count": preflight.advisory_count(),
        "guidance_count": bundle.guidance.len(),
        "report_hash": report.report_hash,
        "result_hash": preflight.result_hash,
        "bundle_hash": bundle.bundle_hash,
        "blocking_check_ids": preflight
            .blockers
            .iter()
            .map(|check| check.check_id.clone())
            .collect::<Vec<_>>(),
        "guidance_ids": bundle
            .guidance
            .iter()
            .map(|entry| entry.guidance_id.clone())
            .collect::<Vec<_>>(),
        "support_bundle_categories": support_bundle_categories,
        "dependency_routes": [
            {
                "bead_id": MISMATCH_CATALOG_BEAD_ID,
                "policy_id": MISMATCH_CATALOG_POLICY_ID,
                "component": MISMATCH_COMPONENT
            },
            {
                "bead_id": REPRO_BEAD_ID,
                "policy_id": REPRO_POLICY_ID,
                "component": REPRO_COMPONENT
            }
        ],
        "repro_index_schema_version": repro_index["schema_version"].clone()
    })
}

#[test]
fn rgc_912b_doc_contains_required_sections_and_artifacts() {
    let path = repo_root().join("docs/RGC_REACT_DOCTOR_PREFLIGHT_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC React Doctor Preflight V1",
        "## Purpose",
        "## Scope",
        "## Upstream Evidence Inputs",
        "## Verdict And Guidance Contract",
        "## Required Artifacts",
        "## Gate Runner",
        "## Structured Logging Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    for required in [
        "react_doctor_support_contract.json",
        "react_support_repro_index.json",
        "trace_ids.json",
        "bd-1lsy.9.7.3",
        "bd-1lsy.5.7.3",
        "without rerunning the lane",
        "RGC_REACT_DOCTOR_PREFLIGHT_REPLAY_RUN_DIR",
        "current failed invocation",
        "older complete directory",
    ] {
        assert!(
            doc.contains(required),
            "missing required artifact or dependency reference in {}: {required}",
            path.display()
        );
    }

    assert!(
        doc.contains("$PWD/target_rch_rgc_react_doctor_preflight_verify"),
        "operator verification doc should use repo-local rch target dir"
    );
    assert!(
        !doc.contains("/tmp/"),
        "operator verification doc must not point to /tmp-backed target dirs"
    );
}

#[test]
fn rgc_912b_contract_is_versioned_and_dependency_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, DOCTOR_PREFLIGHT_BEAD_ID);
    assert_eq!(contract.generated_by, DOCTOR_PREFLIGHT_BEAD_ID);
    assert_eq!(contract.policy_id, "policy-rgc-react-doctor-preflight-v1");
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert_eq!(contract.track.id, "RGC-912B");
    assert_eq!(contract.track.name, "React Doctor Preflight");

    assert_eq!(
        contract.module_contract.schema_version,
        DOCTOR_PREFLIGHT_SCHEMA_VERSION
    );
    assert_eq!(contract.module_contract.bead_id, DOCTOR_PREFLIGHT_BEAD_ID);
    assert_eq!(
        contract.module_contract.policy_id,
        DOCTOR_PREFLIGHT_POLICY_ID
    );
    assert_eq!(contract.module_contract.component, DOCTOR_COMPONENT);

    let dependency_ids = contract
        .dependency_routes
        .iter()
        .map(|route| route.bead_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dependency_ids,
        BTreeSet::from([MISMATCH_CATALOG_BEAD_ID, REPRO_BEAD_ID])
    );

    let mismatch_route = contract
        .dependency_routes
        .iter()
        .find(|route| route.bead_id == MISMATCH_CATALOG_BEAD_ID)
        .expect("missing mismatch catalog dependency route");
    assert_eq!(mismatch_route.policy_id, MISMATCH_CATALOG_POLICY_ID);
    assert_eq!(mismatch_route.component, MISMATCH_COMPONENT);
    assert_eq!(mismatch_route.contract_role, "mismatch_catalog");
    for field in [
        "entry_id",
        "domain",
        "severity",
        "target",
        "reproduction",
        "advisory",
        "react_version_range",
    ] {
        assert!(
            mismatch_route
                .required_fields
                .iter()
                .any(|item| item == field),
            "missing mismatch route field {field}"
        );
    }

    let repro_route = contract
        .dependency_routes
        .iter()
        .find(|route| route.bead_id == REPRO_BEAD_ID)
        .expect("missing repro extraction dependency route");
    assert_eq!(repro_route.policy_id, REPRO_POLICY_ID);
    assert_eq!(repro_route.component, REPRO_COMPONENT);
    assert_eq!(repro_route.contract_role, "repro_index");
    for field in [
        "input_id",
        "category",
        "owner",
        "severity",
        "repro_hash",
        "recommended_action",
    ] {
        assert!(
            repro_route.required_fields.iter().any(|item| item == field),
            "missing repro route field {field}"
        );
    }

    let verdicts = contract
        .verdict_classes
        .iter()
        .map(|row| {
            (
                row.verdict.as_str(),
                row.blocks_compile_or_build,
                row.emitted_surface.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        verdicts,
        BTreeSet::from([
            ("fail", true, "blocking_preflight"),
            ("pass", false, "advisory_guidance"),
        ])
    );

    let log_fields = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_log_fields = BTreeSet::from([
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
    ]);
    assert_eq!(log_fields, expected_log_fields);

    let required_artifacts = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_artifacts = BTreeSet::from([
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "react_doctor_support_contract.json",
        "react_support_repro_index.json",
        "rgc_react_doctor_preflight_v1.json",
        "step_logs/step_000.log",
    ]);
    assert_eq!(required_artifacts, expected_artifacts);

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_react_doctor_preflight.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_react_doctor_preflight_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-react-doctor-preflight.run-manifest.v1"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command.contains("./scripts/run_rgc_react_doctor_preflight.sh ci")),
        "operator verification must include the canonical gate runner"
    );
    assert!(
        contract.operator_verification.iter().any(|command| {
            command.contains(
                "RGC_REACT_DOCTOR_PREFLIGHT_REPLAY_RUN_DIR=artifacts/rgc_react_doctor_preflight/<timestamp>"
            )
        }),
        "operator verification must document exact-run-dir replay"
    );
}

#[test]
fn rgc_912b_live_support_contract_is_dependency_bound_and_deterministic() {
    let first = build_support_contract_artifact();
    let second = build_support_contract_artifact();
    assert_eq!(
        first, second,
        "support contract artifact must be deterministic"
    );

    assert_eq!(
        first["schema_version"],
        Value::String(SUPPORT_CONTRACT_SCHEMA_VERSION.to_string())
    );
    assert_eq!(
        first["bead_id"],
        Value::String(DOCTOR_PREFLIGHT_BEAD_ID.to_string())
    );
    assert_eq!(
        first["policy_id"],
        Value::String(DOCTOR_PREFLIGHT_POLICY_ID.to_string())
    );
    assert_eq!(
        first["component"],
        Value::String(DOCTOR_COMPONENT.to_string())
    );
    assert_eq!(first["passed"], Value::Bool(false));
    assert_eq!(first["entries_analyzed"], json!(3));
    assert_eq!(first["blocker_count"], json!(2));
    assert_eq!(first["advisory_count"], json!(1));
    assert_eq!(
        first["repro_index_schema_version"],
        json!(SUPPORT_REPRO_INDEX_SCHEMA_VERSION)
    );

    let dependency_ids = first["dependency_routes"]
        .as_array()
        .expect("dependency_routes must be an array")
        .iter()
        .map(|entry| {
            entry["bead_id"]
                .as_str()
                .expect("dependency route bead_id must be a string")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dependency_ids,
        BTreeSet::from([MISMATCH_CATALOG_BEAD_ID, REPRO_BEAD_ID])
    );

    let categories = first["support_bundle_categories"]
        .as_array()
        .expect("support bundle categories must be an array")
        .iter()
        .map(|value| value.as_str().expect("category must be a string"))
        .collect::<BTreeSet<_>>();
    for expected in [
        "category_breakdown",
        "doctor_checks",
        "guidance",
        "severity_breakdown",
    ] {
        assert!(
            categories.contains(expected),
            "missing support-bundle category {expected}"
        );
    }
}

#[test]
fn rgc_912b_support_repro_index_routes_to_upstream_triage_lane() {
    let index = build_support_repro_index_artifact();

    assert_eq!(
        index["schema_version"],
        Value::String(SUPPORT_REPRO_INDEX_SCHEMA_VERSION.to_string())
    );
    assert_eq!(
        index["bead_id"],
        Value::String(DOCTOR_PREFLIGHT_BEAD_ID.to_string())
    );
    assert_eq!(
        index["policy_id"],
        Value::String(DOCTOR_PREFLIGHT_POLICY_ID.to_string())
    );
    assert_eq!(
        index["component"],
        Value::String(DOCTOR_COMPONENT.to_string())
    );
    assert_eq!(
        index["upstream_catalog_bead_id"],
        Value::String(MISMATCH_CATALOG_BEAD_ID.to_string())
    );
    assert_eq!(
        index["upstream_repro_bead_id"],
        Value::String(REPRO_BEAD_ID.to_string())
    );
    assert_eq!(index["verdict"], json!("complete"));

    let entries = index["entries"]
        .as_array()
        .expect("repro index entries must be an array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(
        entry["owner_route"],
        Value::String(TriageOwner::ReactIntegration.to_string())
    );
    assert_eq!(
        entry["owner_route_bead"],
        Value::String(REPRO_BEAD_ID.to_string())
    );
    assert_eq!(entry["triage_severity"], json!("error"));
    assert!(
        entry["repro_command"]
            .as_str()
            .expect("repro command must be a string")
            .contains("frankenctl react doctor"),
        "repro index command should route back through the React doctor surface"
    );
}

#[test]
fn rgc_912b_runner_is_rch_backed_and_fail_closed() {
    let script = read_runner_script();

    for required in [
        "command -v rch",
        "rch exec",
        "cargo check -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration",
        "cargo test -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration",
        "cargo clippy -p frankenengine-engine --test rgc_react_doctor_preflight --test react_doctor_preflight_integration --test react_doctor_preflight_enrichment_integration -- -D warnings",
        "react_doctor_support_contract.json",
        "react_support_repro_index.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "step_logs/step_000.log",
    ] {
        assert!(
            script.contains(required),
            "runner script missing required text: {required}"
        );
    }

    for fallback_guard in [
        "Remote toolchain failure, falling back to local",
        "local fallback",
        "running locally",
        "RCH-E326",
    ] {
        assert!(
            script.contains(fallback_guard),
            "runner script missing local-fallback guard: {fallback_guard}"
        );
    }
}

#[test]
fn rgc_912b_replay_wrapper_requires_complete_artifact_bundle() {
    let script = read_replay_script();

    for required in [
        "run_dir_is_complete()",
        "warn_about_failed_gate_replay_source()",
        "if [[ -z \"${explicit_run_dir}\" ]]; then",
        "RGC_REACT_DOCTOR_PREFLIGHT_REPLAY_RUN_DIR",
        "explicit run directory is incomplete",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "replay output reflects latest complete run directory",
        "replay output reflects current run directory",
        "scripts/run_rgc_react_doctor_preflight.sh",
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "react_doctor_support_contract.json",
        "react_support_repro_index.json",
        "rgc_react_doctor_preflight_v1.json",
        "step_logs/step_000.log",
    ] {
        assert!(
            script.contains(required),
            "replay script missing required text: {required}"
        );
    }
}
