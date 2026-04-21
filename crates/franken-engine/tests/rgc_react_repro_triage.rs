#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::minimized_repro_extraction::{
    ExtractionConfig, ExtractionEngine, FailureCategory, MinimizationStrategy,
    MinimizedRepro as ExtractionRepro, ReproInput, TriageFinding, TriageSeverity,
    BEAD_ID as EXTRACTION_BEAD_ID, COMPONENT as EXTRACTION_COMPONENT,
    POLICY_ID as EXTRACTION_POLICY_ID, SCHEMA_VERSION as EXTRACTION_SCHEMA_VERSION,
};
use frankenengine_engine::react_repro_triage::{
    assign_severity, build_triage_event, classify_failure, default_owner_route, generate_advisory,
    FailureClass, FailureSeverity, FailureSymptoms, MinimizedRepro, OwnerRoute, ReproCatalog,
    TriageEntry, BEAD_ID, COMPONENT, POLICY_ID, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Deserialize;
use serde_json::{json, Value};

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_react_repro_triage_v1.json");
const CATALOG_ARTIFACT_SCHEMA_VERSION: &str = "franken-engine.react-repro-catalog-artifact.v1";
const GENERATED_AT_UTC: &str = "2026-04-21T00:00:00Z";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc405cContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    policy_id: String,
    track: ContractTrack,
    library_surfaces: Vec<LibrarySurface>,
    failure_class_routes: Vec<FailureClassRoute>,
    severity_taxonomy: Vec<SeveritySpec>,
    required_structured_log_fields: Vec<String>,
    required_artifacts: Vec<String>,
    required_test_targets: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LibrarySurface {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    component: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FailureClassRoute {
    failure_class: String,
    owner_bead_id: String,
    owner_team: String,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SeveritySpec {
    severity: String,
    weight: u32,
    meaning: String,
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

fn read_runner_script() -> String {
    read_to_string(&repo_root().join("scripts/run_rgc_react_repro_triage.sh"))
}

fn read_replay_script() -> String {
    read_to_string(&repo_root().join("scripts/e2e/rgc_react_repro_triage_replay.sh"))
}

fn read_doc() -> String {
    read_to_string(&repo_root().join("docs/RGC_REACT_REPRO_TRIAGE_V1.md"))
}

fn parse_contract() -> Rgc405cContract {
    serde_json::from_str(CONTRACT_JSON).expect("RGC-405C contract must parse")
}

fn epoch(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn make_react_repro(source: &str) -> MinimizedRepro {
    MinimizedRepro::build(
        source,
        "expected React behavior",
        "actual FrankenEngine behavior",
        BTreeSet::from(["18.2.0".to_string()]),
        "./scripts/e2e/rgc_react_repro_triage_replay.sh ci",
    )
}

fn build_entry(
    symptoms: FailureSymptoms,
    blocks_core_workflow: bool,
    has_workaround: bool,
    is_edge_case: bool,
    source: &str,
) -> TriageEntry {
    let class = classify_failure(&symptoms);
    let severity = assign_severity(class, blocks_core_workflow, has_workaround, is_edge_case);
    let owner = default_owner_route(class);
    let advisory = generate_advisory(class, severity);
    TriageEntry::build(class, severity, owner, make_react_repro(source), &advisory)
}

fn build_sample_catalog() -> ReproCatalog {
    let transform = build_entry(
        FailureSymptoms {
            has_transform_diff: true,
            ..FailureSymptoms::default()
        },
        true,
        false,
        false,
        "export function App() { return <button>broken transform</button>; }",
    );
    let hydration = build_entry(
        FailureSymptoms {
            has_hydration_diff: true,
            ..FailureSymptoms::default()
        },
        false,
        false,
        false,
        "export function App() { return <main>{Date.now()}</main>; }",
    );
    let package = build_entry(
        FailureSymptoms {
            has_version_mismatch: true,
            ..FailureSymptoms::default()
        },
        false,
        false,
        false,
        "export function App() { return <section>mismatched package</section>; }",
    );
    ReproCatalog::build(vec![package, hydration, transform], epoch(7))
}

fn extraction_finding(
    category: FailureCategory,
    repro: &ExtractionRepro,
    severity: TriageSeverity,
    summary: &str,
    recommended_action: &str,
) -> TriageFinding {
    TriageFinding {
        category,
        owner: ExtractionEngine::default_owner(category),
        severity,
        summary: summary.to_string(),
        repro_hash: Some(repro.repro_hash),
        recommended_action: recommended_action.to_string(),
    }
}

fn build_sample_extraction_report(
) -> frankenengine_engine::minimized_repro_extraction::ExtractionReport {
    let config = ExtractionConfig::default();
    let mut engine = ExtractionEngine::new(config);

    let jsx_input = ReproInput::new(
        "jsx-transform-input".to_string(),
        FailureCategory::JsxTransform,
        120,
        6,
        5,
    );
    let hydration_input = ReproInput::new(
        "hydration-input".to_string(),
        FailureCategory::HydrationMismatch,
        100,
        5,
        4,
    );
    let build_tool_input = ReproInput::new(
        "build-tool-input".to_string(),
        FailureCategory::BuildToolIntegration,
        80,
        4,
        7,
    );

    let jsx_repro = ExtractionRepro::new(
        jsx_input.input_id.clone(),
        MinimizationStrategy::DeltaDebugging,
        18,
        120,
        true,
        1_000_000,
    );
    let hydration_repro = ExtractionRepro::new(
        hydration_input.input_id.clone(),
        MinimizationStrategy::HierarchicalReduction,
        20,
        100,
        true,
        1_500_000,
    );
    let build_tool_repro = ExtractionRepro::new(
        build_tool_input.input_id.clone(),
        MinimizationStrategy::DependencyStripping,
        20,
        80,
        true,
        2_000_000,
    );

    engine.add_input(jsx_input);
    engine.add_input(hydration_input);
    engine.add_input(build_tool_input);
    engine.add_repro(jsx_repro.clone());
    engine.add_repro(hydration_repro.clone());
    engine.add_repro(build_tool_repro.clone());
    engine.add_finding(extraction_finding(
        FailureCategory::JsxTransform,
        &jsx_repro,
        TriageSeverity::Critical,
        "JSX transform drift survives minimization",
        "Route to the JSX transform lane and preserve the reduced fixture",
    ));
    engine.add_finding(extraction_finding(
        FailureCategory::HydrationMismatch,
        &hydration_repro,
        TriageSeverity::Error,
        "Hydration mismatch survives minimization",
        "Route to the SSR hydration lane and keep the replay command",
    ));
    engine.add_finding(extraction_finding(
        FailureCategory::BuildToolIntegration,
        &build_tool_repro,
        TriageSeverity::Warning,
        "Build tool integration failure survives minimization",
        "Route to build tooling and keep the minimized dependency set",
    ));

    engine.evaluate(epoch(7))
}

fn build_catalog_artifact() -> Value {
    let catalog = build_sample_catalog();
    let extraction = build_sample_extraction_report();
    let entries: Vec<Value> = catalog
        .entries
        .iter()
        .map(|entry| {
            json!({
                "entry_id": entry.entry_id,
                "failure_class": entry.failure_class.as_str(),
                "severity": entry.severity.as_str(),
                "owner_bead": entry.owner.bead_id,
                "owner_team": entry.owner.team,
                "advisory": entry.advisory,
                "repro_id": entry.repro.repro_id,
                "replay_command": entry.repro.replay_command,
                "react_versions": entry.repro.react_versions.iter().cloned().collect::<Vec<_>>(),
            })
        })
        .collect();

    let owners: Vec<String> = extraction
        .findings
        .iter()
        .map(|finding| finding.owner.to_string())
        .collect();

    json!({
        "schema_version": CATALOG_ARTIFACT_SCHEMA_VERSION,
        "bead_id": BEAD_ID,
        "policy_id": POLICY_ID,
        "component": COMPONENT,
        "generated_at_utc": GENERATED_AT_UTC,
        "catalog_schema_version": SCHEMA_VERSION,
        "extraction_schema_version": EXTRACTION_SCHEMA_VERSION,
        "epoch": catalog.epoch.as_u64(),
        "entries": entries,
        "summary": {
            "total_entries": catalog.summary.total_entries,
            "by_class": catalog.summary.by_class,
            "by_severity": catalog.summary.by_severity,
            "unresolved_count": catalog.summary.unresolved_count,
            "engine_bug_count": catalog.summary.engine_bug_count,
            "distinct_owners": catalog.summary.distinct_owners,
            "severity_weighted_score": catalog.summary.severity_weighted_score,
        },
        "extraction_summary": {
            "verdict": extraction.verdict.as_str(),
            "avg_reduction_ratio_millionths": extraction.avg_reduction_ratio_millionths,
            "findings_count": extraction.findings.len(),
            "owners": owners,
        }
    })
}

fn maybe_emit_catalog_artifact_from_env() {
    let Ok(output_path) = std::env::var("RGC_REACT_REPRO_TRIAGE_EMIT_ARTIFACT_PATH") else {
        return;
    };
    let output_path = PathBuf::from(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", parent.display()));
    }
    let encoded = serde_json::to_string_pretty(&build_catalog_artifact())
        .expect("catalog artifact should encode");
    fs::write(&output_path, encoded)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", output_path.display()));
}

#[test]
fn rgc_405c_emit_catalog_artifact_for_runner() {
    maybe_emit_catalog_artifact_from_env();
}

#[test]
fn rgc_405c_contract_json_parses_and_matches_live_constants() {
    let contract = parse_contract();
    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-react-repro-triage.v1"
    );
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, BEAD_ID);
    assert_eq!(contract.generated_by, BEAD_ID);
    assert_eq!(contract.generated_at_utc, GENERATED_AT_UTC);
    assert_eq!(contract.track.id, "RGC-405C");
    assert_eq!(contract.track.name, "React Repro Triage");
    assert_eq!(contract.policy_id, "policy-rgc-react-repro-triage-v1");
    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_react_repro_triage.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_react_repro_triage_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-react-repro-triage.run-manifest.v1"
    );

    let surfaces: BTreeMap<_, _> = contract
        .library_surfaces
        .iter()
        .map(|surface| {
            (
                surface.component.as_str(),
                (
                    surface.schema_version.as_str(),
                    surface.bead_id.as_str(),
                    surface.policy_id.as_str(),
                ),
            )
        })
        .collect();
    assert_eq!(
        surfaces.get(EXTRACTION_COMPONENT),
        Some(&(
            EXTRACTION_SCHEMA_VERSION,
            EXTRACTION_BEAD_ID,
            EXTRACTION_POLICY_ID,
        ))
    );
    assert_eq!(
        surfaces.get(COMPONENT),
        Some(&(SCHEMA_VERSION, BEAD_ID, POLICY_ID))
    );
}

#[test]
fn rgc_405c_contract_routes_cover_all_failure_classes() {
    let contract = parse_contract();
    assert_eq!(
        contract.failure_class_routes.len(),
        FailureClass::all().len()
    );

    let routes: BTreeMap<_, _> = contract
        .failure_class_routes
        .iter()
        .map(|route| (route.failure_class.as_str(), route))
        .collect();

    for class in FailureClass::all() {
        let route = routes
            .get(class.as_str())
            .unwrap_or_else(|| panic!("missing route for {}", class.as_str()));
        let owner: OwnerRoute = default_owner_route(*class);
        assert_eq!(route.owner_bead_id, owner.bead_id);
        assert_eq!(route.owner_team, owner.team);
        assert_eq!(route.rationale, owner.rationale);
    }
}

#[test]
fn rgc_405c_contract_severity_taxonomy_matches_live_weights() {
    let contract = parse_contract();
    let severities = [
        (FailureSeverity::Critical, 5),
        (FailureSeverity::High, 4),
        (FailureSeverity::Medium, 3),
        (FailureSeverity::Low, 2),
        (FailureSeverity::Info, 1),
    ];

    let taxonomy: BTreeMap<_, _> = contract
        .severity_taxonomy
        .iter()
        .map(|severity| (severity.severity.as_str(), severity))
        .collect();

    for (severity, weight) in severities {
        let spec = taxonomy
            .get(severity.as_str())
            .unwrap_or_else(|| panic!("missing taxonomy for {}", severity.as_str()));
        assert_eq!(spec.weight, weight);
        assert_eq!(spec.weight, severity.weight());
        assert!(!spec.meaning.is_empty());
    }
}

#[test]
fn rgc_405c_catalog_artifact_matches_live_repro_triage_and_extraction_summary() {
    let artifact = build_catalog_artifact();

    assert_eq!(artifact["schema_version"], CATALOG_ARTIFACT_SCHEMA_VERSION);
    assert_eq!(artifact["bead_id"], BEAD_ID);
    assert_eq!(artifact["policy_id"], POLICY_ID);
    assert_eq!(artifact["component"], COMPONENT);
    assert_eq!(artifact["generated_at_utc"], GENERATED_AT_UTC);
    assert_eq!(artifact["catalog_schema_version"], SCHEMA_VERSION);
    assert_eq!(
        artifact["extraction_schema_version"],
        EXTRACTION_SCHEMA_VERSION
    );
    assert_eq!(artifact["epoch"], 7);

    assert_eq!(artifact["summary"]["total_entries"], 3);
    assert_eq!(artifact["summary"]["by_class"]["transform_bug"], 1);
    assert_eq!(artifact["summary"]["by_class"]["hydration_mismatch"], 1);
    assert_eq!(artifact["summary"]["by_class"]["package_misuse"], 1);
    assert_eq!(artifact["summary"]["by_severity"]["critical"], 1);
    assert_eq!(artifact["summary"]["by_severity"]["high"], 1);
    assert_eq!(artifact["summary"]["by_severity"]["low"], 1);
    assert_eq!(artifact["summary"]["unresolved_count"], 3);
    assert_eq!(artifact["summary"]["engine_bug_count"], 2);
    assert_eq!(artifact["summary"]["distinct_owners"], 3);
    assert_eq!(artifact["summary"]["severity_weighted_score"], 11);

    let entries = artifact["entries"]
        .as_array()
        .expect("entries should be an array");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["failure_class"], "transform_bug");
    assert_eq!(entries[0]["severity"], "critical");
    assert_eq!(entries[0]["owner_bead"], "bd-1lsy.3.6.1");
    assert_eq!(entries[0]["owner_team"], "jsx-transform");
    assert_eq!(
        entries[0]["replay_command"],
        "./scripts/e2e/rgc_react_repro_triage_replay.sh ci"
    );
    assert_eq!(entries[1]["failure_class"], "hydration_mismatch");
    assert_eq!(entries[1]["severity"], "high");
    assert_eq!(entries[1]["owner_bead"], "bd-1lsy.5.7.2");
    assert_eq!(entries[2]["failure_class"], "package_misuse");
    assert_eq!(entries[2]["severity"], "low");
    assert_eq!(entries[2]["owner_bead"], "bd-1lsy.5.7.3");

    assert_eq!(artifact["extraction_summary"]["verdict"], "complete");
    assert_eq!(
        artifact["extraction_summary"]["avg_reduction_ratio_millionths"],
        800000
    );
    assert_eq!(artifact["extraction_summary"]["findings_count"], 3);
    assert_eq!(
        artifact["extraction_summary"]["owners"],
        json!(["parser_compiler", "react_integration", "build_tooling"])
    );
}

#[test]
fn rgc_405c_triage_event_matches_required_structured_logging_fields() {
    let contract = parse_contract();
    let catalog = build_sample_catalog();
    let event = build_triage_event(
        "trace-rgc-405c",
        "decision-rgc-405c",
        "rgc-405c",
        &catalog.entries[0],
    );
    let event_value = serde_json::to_value(event).expect("triage event should serialize");

    for field in &contract.required_structured_log_fields {
        assert!(
            event_value.get(field).is_some(),
            "triage event should include required field {field}"
        );
    }
    assert_eq!(event_value["schema_version"], SCHEMA_VERSION);
    assert_eq!(event_value["policy_id"], POLICY_ID);
    assert_eq!(event_value["component"], COMPONENT);
    assert_eq!(event_value["event"], "failure_triaged");
    assert_eq!(event_value["outcome"], "unresolved");
}

#[test]
fn rgc_405c_runner_script_pins_repo_local_target_dir_and_targets() {
    let contract = parse_contract();
    let runner = read_runner_script();

    assert!(runner.contains("/data/projects/franken_engine/target_rch_rgc_react_repro_triage_"));
    assert!(runner.contains("react_repro_catalog.json"));
    assert!(runner.contains("rgc_react_repro_triage_v1.json"));
    assert!(runner.contains("rch-local-fallback-detected"));
    assert!(runner.contains("policy-rgc-react-repro-triage-v1"));
    assert!(runner.contains("RGC_REACT_REPRO_TRIAGE_EMIT_ARTIFACT_PATH"));
    assert!(runner.contains("rgc_405c_emit_catalog_artifact_for_runner"));
    assert!(contract
        .operator_verification
        .iter()
        .any(|command| command.contains("scripts/run_rgc_react_repro_triage.sh")));
    assert!(contract
        .operator_verification
        .iter()
        .any(|command| command.contains("scripts/e2e/rgc_react_repro_triage_replay.sh")));

    for target in &contract.required_test_targets {
        assert!(
            runner.contains(&format!("--test {target}")),
            "runner should verify {target}"
        );
    }
}

#[test]
fn rgc_405c_replay_wrapper_requires_complete_bundle_and_explicit_run_dir() {
    let replay = read_replay_script();

    assert!(replay.contains("RGC_REACT_REPRO_TRIAGE_REPLAY_RUN_DIR"));
    assert!(replay.contains("react_repro_catalog.json"));
    assert!(replay.contains("rgc_react_repro_triage_v1.json"));
    assert!(replay.contains("step_logs/step_000.log"));
    assert!(replay.contains("latest complete run directory"));
    assert!(replay.contains("explicit run directory is incomplete"));
}

#[test]
fn rgc_405c_markdown_doc_mentions_required_artifacts_and_replay_mode() {
    let contract = parse_contract();
    let doc = read_doc();

    assert!(doc.contains("RGC React Repro Triage V1"));
    assert!(doc.contains("rch"));
    assert!(doc.contains("RGC_REACT_REPRO_TRIAGE_REPLAY_RUN_DIR"));

    for artifact in &contract.required_artifacts {
        assert!(
            doc.contains(artifact),
            "markdown doc should mention required artifact {artifact}"
        );
    }

    for target in &contract.required_test_targets {
        assert!(
            doc.contains(target),
            "markdown doc should mention required target {target}"
        );
    }

    assert!(doc.contains("latest complete artifact bundle"));
    assert!(doc.contains("fails closed"));
}
