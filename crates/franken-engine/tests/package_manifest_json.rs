#![forbid(unsafe_code)]
//! Execute complete CommonJS and ESM fixture graphs through production
//! frankenctl. The same package.json bytes and expected modules are checked
//! against live Node by scripts/test_package_manifest_json.cjs.

use std::fs;
use std::process::Command;

fn execute_graph(goal: &str, mode: &str, suffix: &str) {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/package_manifest_json.json"))
            .expect("manifest fixtures");
    let root = tempfile::tempdir().expect("isolated module root");
    let mut source = String::new();
    let mut expected = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().expect("case id");
        let directory = root.path().join(id).join("node_modules/pkg");
        fs::create_dir_all(&directory).expect("package directory");
        fs::write(
            directory.join("package.json"),
            case["manifest"].as_str().expect("exact JSON bytes"),
        )
        .expect("package manifest");
        for name in ["first.cjs", "last.cjs", "require.cjs", "import.cjs", "index.js"] {
            fs::write(
                directory.join(name),
                format!("module.exports = {};\n", serde_json::to_string(name).unwrap()),
            )
            .expect("candidate module");
        }
        let request = serde_json::to_string(case["specifier"].as_str().unwrap()).unwrap();
        let probe = if mode == "require" {
            format!("module.exports = require({request});\n")
        } else {
            format!("import value from {request}; export default value;\n")
        };
        fs::write(directory.join(format!("probe.{suffix}")), probe).expect("module importer");
        let relative = serde_json::to_string(&format!("./{id}/node_modules/pkg/probe.{suffix}"))
            .unwrap();
        let label = serde_json::to_string(id).unwrap();
        if mode == "require" {
            source.push_str(&format!("console.log({label}, require({relative}));\n"));
        } else {
            source.push_str(&format!(
                "import value{index} from {relative}; console.log({label}, value{index});\n"
            ));
        }
        expected.push(format!("{id} {}", case[mode].as_str().unwrap()));
    }
    let entry = root.path().join(format!("entry.{suffix}"));
    fs::write(&entry, source).expect("entrypoint");
    let report = root.path().join("run.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"])
        .arg(&entry)
        .args(["--extension-id", "manifest-json-regression", "--goal", goal, "--out"])
        .arg(&report)
        .output()
        .expect("execute production CLI");
    assert!(
        output.status.success(),
        "{goal}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(report).expect("execution report")).expect("report JSON");
    let actual: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect();
    assert_eq!(actual, expected, "{goal} must execute the selected files, not only resolve paths");
}

#[test]
fn commonjs_graph_uses_json_mapping_and_bom_semantics() {
    execute_graph("commonjs", "require", "cjs");
}

#[test]
fn esm_graph_uses_json_mapping_and_bom_semantics() {
    execute_graph("module", "import", "mjs");
}

fn assert_fatal_target(id: &str, diagnostic: &str) {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/package_target_validation.json"))
            .expect("target fixtures");
    let case = cases.iter().find(|case| case["id"] == id).expect("target case");
    for (goal, suffix) in [("commonjs", "cjs"), ("module", "mjs")] {
        let root = tempfile::tempdir().expect("isolated module root");
        let directory = root.path().join("node_modules/pkg");
        fs::create_dir_all(&directory).expect("package directory");
        let capture = case["capture"].as_str();
        let key = if capture.is_some() { "./*" } else { "." };
        let manifest = format!(
            "{{\"name\":\"pkg\",\"exports\":{{{}:{}}}}}",
            serde_json::to_string(key).unwrap(),
            case["target"].as_str().expect("raw target JSON")
        );
        fs::write(directory.join("package.json"), manifest).expect("exact manifest");
        for name in ["first.cjs", "last.cjs"] {
            fs::write(
                directory.join(name),
                "console.log('fallback-body-ran'); module.exports = 1;\n",
            )
            .expect("fallback exists but must not run");
        }
        let request = capture.map_or_else(|| "pkg".to_string(), |s| format!("pkg/{s}"));
        let quoted = serde_json::to_string(&request).unwrap();
        let source = if goal == "commonjs" {
            format!("require({quoted});\n")
        } else {
            format!("import {quoted};\n")
        };
        let entry = root.path().join(format!("entry.{suffix}"));
        fs::write(&entry, source).expect("entry source");
        let report_path = root.path().join("run.json");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args(["run", "--input"])
            .arg(&entry)
            .args(["--extension-id", "fatal-target", "--goal", goal, "--out"])
            .arg(&report_path)
            .output()
            .expect("execute production CLI");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{id} {goal}: invalid target executed");
        assert!(stderr.contains(diagnostic), "{id} {goal}: {stderr}");
        // Some error paths publish a partial execution report. It must not
        // contain effects from an alternative that should never be selected.
        if report_path.is_file() {
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(&report_path).unwrap()).expect("report JSON");
            if let Some(console) = report["console_output"].as_array() {
                assert!(
                    console.iter().all(|entry| entry["message"] != "fallback-body-ran"),
                    "{id} {goal}: invalid target executed a fallback body"
                );
            }
        }
    }
}

#[test]
fn invalid_conditional_configuration_does_not_run_a_valid_array_fallback() {
    assert_fatal_target("numeric_deep_array", "ERR_INVALID_PACKAGE_CONFIG");
}

#[test]
fn invalid_wildcard_capture_does_not_run_a_constant_array_fallback() {
    assert_fatal_target("bad_capture_array", "ERR_INVALID_MODULE_SPECIFIER");
}
