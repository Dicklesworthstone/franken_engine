#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_engine::intl_surface_contract::{
    CONTRACT_ID, CONTRACT_SCHEMA_VERSION, ERROR_AUTHORITY_HASH, ERROR_CANONICAL_JSON,
    ERROR_DISCOVERY, ERROR_DOC_CROSSWALK, ERROR_MARKDOWN_DRIFT, ERROR_OUTPUT_EXISTS,
    EVENT_SCHEMA_VERSION, IntlSurfaceContract, MutationReport, ValidationReport, canonical_json,
    generate_contract, parse_contract, render_markdown, run_mutation_suite, seal_directory,
    validate_contract_file, write_create_new,
};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    for mut candidate in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        PathBuf::from(file!()),
    ] {
        if candidate.is_file() {
            candidate.pop();
        }
        loop {
            if candidate
                .join("crates/franken-engine/src/intl_surface_contract.rs")
                .is_file()
            {
                return candidate;
            }
            if !candidate.pop() {
                break;
            }
        }
    }
    panic!("could not find franken_engine repository root");
}

fn node_root() -> PathBuf {
    repo_root().join("../franken_node")
}

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_franken_intl_surface_contract"))
}

fn canonical_contract() -> IntlSurfaceContract {
    generate_contract(&repo_root(), &node_root()).expect("live contract generates")
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(cli())
        .args(args)
        .output()
        .expect("contract CLI starts")
}

fn parse_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).expect("read JSON")).expect("parse JSON")
}

fn assert_failure_code(report: &ValidationReport, code: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.reason_code == code),
        "expected {code}; findings={:?}",
        report.findings
    );
}

#[test]
fn live_generation_has_exact_identity_and_complete_surface() {
    let contract = canonical_contract();
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_id, CONTRACT_ID);
    assert_eq!(contract.surfaces.len(), 9);
    assert_eq!(contract.probes.len(), 10);
    assert!(contract.authorities.len() >= 12);
    assert_eq!(contract.discovery_rules.len(), 1);
    assert_eq!(
        contract.discovery_rules[0].rule_id,
        "franken-node.no-independent-intl-shim"
    );
}

#[test]
fn committed_contract_is_byte_identical_to_live_generation() {
    let root = repo_root();
    let generated = canonical_json(&canonical_contract()).expect("serialize generated contract");
    let committed = fs::read(root.join("docs/intl_surface_contract_v1.json"))
        .expect("committed contract exists");
    assert_eq!(generated, committed);
}

#[test]
fn committed_markdown_is_byte_identical_to_renderer() {
    let root = repo_root();
    let generated = render_markdown(&canonical_contract());
    let committed = fs::read_to_string(root.join("docs/INTL_SURFACE_CONTRACT_V1.md"))
        .expect("committed Markdown exists");
    assert_eq!(generated, committed);
}

#[test]
fn committed_contract_validates_against_both_live_repositories() {
    let root = repo_root();
    let report = validate_contract_file(
        &root,
        &node_root(),
        &root.join("docs/intl_surface_contract_v1.json"),
    );
    assert!(report.passed(), "{:?}", report.findings);
    assert!(report.checks_run > 150);
    assert_eq!(report.exposed_count, 2);
    assert_eq!(report.absent_count, 2);
    assert_eq!(report.internal_unrouted_count, 5);
}

#[test]
fn cli_help_documents_create_new_and_score_separation_commands() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    for fragment in [
        "generate",
        "validate",
        "mutations",
        "probe",
        "render",
        "seal",
        "create-new",
    ] {
        assert!(stdout.contains(fragment), "missing {fragment}");
    }
}

#[test]
fn cli_generate_is_deterministic_and_create_new() {
    let temp = tempdir().expect("temp directory");
    let first_json = temp.path().join("first.json");
    let first_md = temp.path().join("first.md");
    let second_json = temp.path().join("second.json");
    let second_md = temp.path().join("second.md");
    let root = repo_root();
    let node = node_root();

    for (json, markdown) in [(&first_json, &first_md), (&second_json, &second_md)] {
        let output = run_cli(&[
            "generate",
            "--repo-root",
            root.to_str().unwrap(),
            "--franken-node-root",
            node.to_str().unwrap(),
            "--output",
            json.to_str().unwrap(),
            "--markdown",
            markdown.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        fs::read(&first_json).unwrap(),
        fs::read(&second_json).unwrap()
    );
    assert_eq!(fs::read(&first_md).unwrap(), fs::read(&second_md).unwrap());

    let overwrite = run_cli(&[
        "generate",
        "--repo-root",
        root.to_str().unwrap(),
        "--franken-node-root",
        node.to_str().unwrap(),
        "--output",
        first_json.to_str().unwrap(),
        "--markdown",
        first_md.to_str().unwrap(),
    ]);
    assert_eq!(overwrite.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&overwrite.stderr).contains(ERROR_OUTPUT_EXISTS),
        "{}",
        String::from_utf8_lossy(&overwrite.stderr)
    );
}

#[test]
fn cli_validate_emits_report_and_one_terminal_event() {
    let temp = tempdir().expect("temp directory");
    let report_path = temp.path().join("report.json");
    let events_path = temp.path().join("events.jsonl");
    let root = repo_root();
    let node = node_root();
    let input = root.join("docs/intl_surface_contract_v1.json");
    let output = run_cli(&[
        "validate",
        "--repo-root",
        root.to_str().unwrap(),
        "--franken-node-root",
        node.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
        "--report",
        report_path.to_str().unwrap(),
        "--events",
        events_path.to_str().unwrap(),
        "--run-id",
        "integration-run",
        "--trace-id",
        "integration-trace",
        "--test-id",
        "integration-test",
        "--seed",
        "42",
        "--attempt",
        "1",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: ValidationReport = parse_json_file(&report_path);
    assert!(report.passed());
    let event_text = fs::read_to_string(events_path).unwrap();
    let lines: Vec<&str> = event_text.lines().collect();
    assert_eq!(lines.len(), 2);
    let events: Vec<serde_json::Value> = lines
        .into_iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["terminal"] == true)
            .count(),
        1
    );
    assert!(events.iter().all(|event| {
        event["schema_version"] == EVENT_SCHEMA_VERSION
            && event["run_id"] == "integration-run"
            && event["trace_id"] == "integration-trace"
            && event["seed"] == 42
    }));
}

#[test]
fn cli_mutations_kill_every_seed_with_stable_codes() {
    let temp = tempdir().expect("temp directory");
    let report_path = temp.path().join("mutations.json");
    let events_path = temp.path().join("mutations.jsonl");
    let input = repo_root().join("docs/intl_surface_contract_v1.json");
    let output = run_cli(&[
        "mutations",
        "--input",
        input.to_str().unwrap(),
        "--report",
        report_path.to_str().unwrap(),
        "--events",
        events_path.to_str().unwrap(),
        "--run-id",
        "mutation-run",
        "--trace-id",
        "mutation-trace",
        "--test-id",
        "mutation-test",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: MutationReport = parse_json_file(&report_path);
    assert_eq!(report.decision, "pass");
    assert!(report.results.len() >= 16);
    assert!(
        report
            .results
            .iter()
            .all(|result| result.decision == "killed")
    );
    assert_eq!(
        fs::read_to_string(events_path).unwrap().lines().count(),
        report.results.len()
    );
}

#[test]
fn malformed_json_fails_without_creating_a_green_report() {
    let temp = tempdir().expect("temp directory");
    let input = temp.path().join("bad.json");
    fs::write(&input, b"{bad").unwrap();
    let report = temp.path().join("report.json");
    let events = temp.path().join("events.jsonl");
    let output = run_cli(&[
        "validate",
        "--repo-root",
        repo_root().to_str().unwrap(),
        "--franken-node-root",
        node_root().to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--events",
        events.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    let report: ValidationReport = parse_json_file(&report);
    assert!(!report.passed());
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == frankenengine_engine::intl_surface_contract::ERROR_JSON
    }));
}

#[test]
fn noncanonical_json_is_rejected_even_when_semantics_parse() {
    let root = repo_root();
    let temp = tempdir().expect("temp directory");
    let path = temp.path().join("compact.json");
    fs::write(
        &path,
        serde_json::to_vec(&canonical_contract()).expect("compact JSON"),
    )
    .unwrap();
    let report = validate_contract_file(&root, &node_root(), &path);
    assert_failure_code(&report, ERROR_CANONICAL_JSON);
}

#[test]
fn bounded_authority_hash_drift_fails() {
    let mut contract = canonical_contract();
    contract.authorities[0].sha256 = "0".repeat(64);
    let temp = tempdir().expect("temp directory");
    let path = temp.path().join("drift.json");
    fs::write(&path, canonical_json(&contract).unwrap()).unwrap();
    let report = validate_contract_file(&repo_root(), &node_root(), &path);
    assert_failure_code(&report, ERROR_AUTHORITY_HASH);
}

#[test]
fn missing_sibling_repository_fails_discovery_and_authority() {
    let temp = tempdir().expect("temp directory");
    let report = validate_contract_file(
        &repo_root(),
        temp.path(),
        &repo_root().join("docs/intl_surface_contract_v1.json"),
    );
    assert!(!report.passed());
    assert!(report.findings.iter().any(|finding| matches!(
        finding.reason_code.as_str(),
        ERROR_DISCOVERY | "FE-INTL-1012"
    )));
}

#[test]
fn documentation_overclaim_and_missing_render_are_distinct_failures() {
    let root = repo_root();
    let temp = tempdir().expect("temp directory");
    let mut contract = canonical_contract();
    contract.documentation_crosswalk[0]
        .required_text
        .push("definitely-not-present".to_string());
    contract
        .scoring_boundary
        .preservation_rule
        .push_str(" test-only Markdown drift");
    let path = temp.path().join("doc-drift.json");
    fs::write(&path, canonical_json(&contract).unwrap()).unwrap();
    let report = validate_contract_file(&root, &node_root(), &path);
    assert_failure_code(&report, ERROR_DOC_CROSSWALK);
    assert_failure_code(&report, ERROR_MARKDOWN_DRIFT);
}

#[test]
fn renderer_cli_refuses_to_overwrite() {
    let temp = tempdir().expect("temp directory");
    let output_path = temp.path().join("rendered.md");
    let input = repo_root().join("docs/intl_surface_contract_v1.json");
    let first = run_cli(&[
        "render",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert!(first.status.success());
    let second = run_cli(&[
        "render",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&second.stderr).contains(ERROR_OUTPUT_EXISTS));
}

#[test]
fn bundle_seal_hashes_every_preexisting_file_and_is_terminal() {
    let temp = tempdir().expect("temp directory");
    write_create_new(&temp.path().join("a"), b"a").unwrap();
    fs::create_dir(temp.path().join("nested")).unwrap();
    write_create_new(&temp.path().join("nested/b"), b"b").unwrap();
    let contract = canonical_contract();
    let manifest = seal_directory(temp.path(), &contract, "exact rerun", "pass").unwrap();
    assert_eq!(manifest.files.len(), 2);
    assert_eq!(manifest.files[0].path, "a");
    assert_eq!(manifest.files[1].path, "nested/b");
    assert_eq!(manifest.reproduction_command, "exact rerun");
    assert!(temp.path().join("run_manifest.json").is_file());
}

#[test]
fn seeded_mutation_suite_is_deterministic() {
    let contract = canonical_contract();
    assert_eq!(run_mutation_suite(&contract), run_mutation_suite(&contract));
}

#[test]
fn parser_rejects_recursive_unknown_fields() {
    let contract = canonical_contract();
    let mut value = serde_json::to_value(contract).unwrap();
    value["surfaces"][0]["descriptor"]["surprise"] = serde_json::json!(true);
    let error = parse_contract(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert!(error.contains("unknown field"));
}

#[test]
fn unsupported_cli_option_is_usage_error_and_writes_nothing() {
    let output = run_cli(&["generate", "--mystery", "value"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option"));
}

#[test]
fn duplicate_cli_option_is_usage_error() {
    let output = run_cli(&["render", "--input", "a", "--input", "b", "--output", "c"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate option"));
}
