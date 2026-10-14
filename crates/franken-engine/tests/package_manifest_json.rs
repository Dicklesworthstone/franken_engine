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
