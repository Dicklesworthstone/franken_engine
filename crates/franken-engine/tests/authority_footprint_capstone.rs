//! Capstone coverage for the E5 authority/intake analyzer (`bd-fqlfw.5.5`).
//!
//! This suite drives the shipped `frankenctl` binary across the file-level
//! checker and package-level intake paths. It ties together the unit-level
//! analyzer contracts, package aggregation, content-addressed bundles, and
//! bounded wording discipline without introducing a second authority model.
#![forbid(unsafe_code)]

use std::fs;
use std::process::{Command, Output};

use tempfile::tempdir;

fn run_frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

fn stdout_string(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_string(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn parse_stdout_json(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout_string(output)).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout={}\nstderr={}",
            stdout_string(output),
            stderr_string(output)
        )
    })
}

fn assert_content_hash(value: &serde_json::Value, field: &str) {
    let hash = value[field].as_str().expect("hash field is a string");
    assert_eq!(hash.len(), 64, "{field} should be a SHA-256 hex digest");
    assert!(
        hash.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{field} should be hex: {hash}"
    );
}

#[test]
fn check_corpus_reports_span_capability_bundle_and_bounded_wording() {
    let dir = tempdir().expect("tempdir");
    let source = dir.path().join("ambient.js");
    fs::write(
        &source,
        "const greeting = \"hello\";\nconst secret = process.env.SECRET_KEY;\n",
    )
    .expect("write source");
    let bundle = dir.path().join("check-bundle");

    let output = run_frankenctl(&[
        "check",
        source.to_str().unwrap(),
        "--format",
        "json",
        "--out",
        bundle.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "ambient authority finding should exit 1\nstdout={}\nstderr={}",
        stdout_string(&output),
        stderr_string(&output)
    );
    let report = parse_stdout_json(&output);

    assert_eq!(
        report["schema_version"],
        "franken-engine.authority-footprint.v1"
    );
    assert_eq!(
        report["analysis_completeness"],
        "bounded_at_first_violation"
    );
    assert_eq!(report["analyzable"], true);
    assert!(
        report["disclaimer"]
            .as_str()
            .unwrap()
            .contains("inferred authority footprint for SUPPORTED syntax"),
        "disclaimer must keep the bounded supported-syntax wording"
    );
    assert!(
        report["disclaimer"]
            .as_str()
            .unwrap()
            .contains("not a proof of noninterference"),
        "disclaimer must explicitly deny a noninterference proof claim"
    );
    assert_content_hash(&report, "report_sha256");

    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding["error_code"], "FE-CAP-0001");
    assert_eq!(finding["accessor"], "process.env");
    assert_eq!(finding["implied_capability"], "EnvRead");
    assert_eq!(finding["confidence"], "definite");
    assert_eq!(finding["location"]["start_line"], 2);

    let caps = report["required_capabilities"]
        .as_array()
        .expect("required_capabilities array");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0]["capability"], "EnvRead");
    assert_eq!(caps[0]["capability_tag"], "env_read");

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("run_manifest.json")).unwrap())
            .expect("run_manifest.json parses");
    assert_eq!(manifest["report_sha256"], report["report_sha256"]);
    let events = fs::read_to_string(bundle.join("events.jsonl")).expect("events.jsonl exists");
    let event_lines: Vec<&str> = events.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(event_lines.len(), 1);
    let event: serde_json::Value = serde_json::from_str(event_lines[0]).expect("event json");
    assert_eq!(event["error_code"], "FE-CAP-0001");
}

#[test]
fn check_surfaces_supported_declassification_obligation_as_ifc_finding() {
    let dir = tempdir().expect("tempdir");
    let source = dir.path().join("declass.js");
    fs::write(
        &source,
        "const token = \"secret_token\";\nhostcall<\"declassify.audit\">(token);\n",
    )
    .expect("write source");

    let output = run_frankenctl(&["check", source.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "required declassification should be a finding\nstdout={}\nstderr={}",
        stdout_string(&output),
        stderr_string(&output)
    );
    let report = parse_stdout_json(&output);
    assert_eq!(report["analyzable"], true);
    assert_eq!(report["analysis_completeness"], "complete");

    let findings = report["findings"].as_array().expect("findings array");
    let declass = findings
        .iter()
        .find(|finding| finding["error_code"] == "FE-CAP-0003")
        .expect("declassification finding is surfaced");
    assert!(
        declass["message"]
            .as_str()
            .unwrap()
            .contains("signed declassification receipt"),
        "finding should name the required receipt: {declass}"
    );

    let caps = report["required_capabilities"]
        .as_array()
        .expect("required_capabilities array");
    assert!(
        caps.iter()
            .any(|cap| cap["capability_tag"] == "declassify.audit"),
        "raw declassification capability tag should remain in the footprint: {caps:?}"
    );
}

#[test]
fn onboard_static_package_aggregates_reports_and_bundle_events() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path().join("pkg");
    fs::create_dir_all(&root).expect("package root");
    fs::write(
        root.join("index.js"),
        "import { cfg } from \"./config.js\";\nimport { send } from \"./sink\";\nimport pad from \"left-pad\";\nexport const out = send(cfg, pad);\n",
    )
    .expect("write index");
    fs::write(
        root.join("config.js"),
        "export const cfg = process.env.SECRET_KEY;\n",
    )
    .expect("write config");
    fs::write(
        root.join("sink.js"),
        "export const send = hostcall<\"declassify.audit\">(\"secret_token\");\n",
    )
    .expect("write sink");
    let bundle = dir.path().join("onboard-bundle");

    let output = run_frankenctl(&[
        "onboard",
        root.to_str().unwrap(),
        "--format",
        "json",
        "--out",
        bundle.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "bounded package intake should exit 1\nstdout={}\nstderr={}",
        stdout_string(&output),
        stderr_string(&output)
    );
    let report = parse_stdout_json(&output);
    assert_eq!(report["schema_version"], "franken-engine.package-intake.v1");
    assert_eq!(report["analyzable"], true);
    assert_eq!(report["completeness"], "bounded");
    assert_content_hash(&report, "report_sha256");

    assert_eq!(report["manifest_proposal"]["module_count"], 3);
    assert!(
        report["manifest_proposal"]["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module == "config.js")
    );
    assert!(
        report["external_dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dep| dep["specifier"] == "left-pad"),
        "external dependencies are reported, not silently analyzed"
    );
    assert_eq!(
        report["module_resolution_report"]["divergent_edge_count"], 1,
        "extensionless ./sink edge should diverge by compatibility mode"
    );

    let denied = report["denied_ambient_authority"]
        .as_array()
        .expect("denied array");
    assert!(denied.iter().any(|entry| {
        entry["module"] == "config.js"
            && entry["accessor"] == "process.env"
            && entry["implied_capability"] == "EnvRead"
            && entry["location"].is_object()
    }));

    let declass = report["ifc_flow_inventory"]["required_declassifications"]
        .as_array()
        .expect("declass array");
    assert!(
        declass.iter().any(|entry| entry["module"] == "sink.js"
            && entry["message"]
                .as_str()
                .unwrap()
                .contains("signed declassification receipt")),
        "sink.js declassification obligation should be aggregated"
    );

    let caps = report["capability_profile_proposal"]["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert!(caps.iter().any(|entry| {
        entry["capability_tag"] == "env_read"
            && entry["sites"]
                .as_array()
                .unwrap()
                .iter()
                .any(|site| site["module"] == "config.js")
    }));
    assert!(
        caps.iter()
            .any(|entry| entry["capability_tag"] == "declassify.audit"),
        "raw declassify capability tag should be retained"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("run_manifest.json")).unwrap())
            .expect("run_manifest.json parses");
    assert_eq!(manifest["report_sha256"], report["report_sha256"]);
    let events = fs::read_to_string(bundle.join("events.jsonl")).expect("events.jsonl exists");
    assert!(
        events.contains("\"event\":\"onboard.denied_ambient_authority\""),
        "bundle events should include denied ambient authority"
    );
    assert!(
        events.contains("\"event\":\"onboard.required_declassification\""),
        "bundle events should include declassification obligations"
    );
    assert!(
        events.contains("\"event\":\"onboard.resolution_divergence\""),
        "bundle events should include mode divergence"
    );
}
