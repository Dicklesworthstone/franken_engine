//! bd-9vouw.419: `frankenctl run` without --goal runs a `.js` entry whose
//! nearest package.json says `"type": "module"` as an ES module, as Node
//! does. It ran such an entry as a script, which stopped at its first
//! `import` ("import declarations are only valid in module goal").
//!
//! The expected line is Node v22.2.0's for the same package.

use std::process::Command;

#[test]
fn a_js_entry_of_a_module_package_runs_as_an_es_module() {
    let root = tempfile::tempdir().expect("temp dir");
    let package = root.path().join("esm-app");
    std::fs::create_dir_all(&package).expect("create package");
    std::fs::write(
        package.join("package.json"),
        "{\"name\": \"esm-app\", \"type\": \"module\"}\n",
    )
    .expect("write package.json");
    std::fs::write(
        package.join("index.js"),
        "import { greet } from './lib.js';\nconsole.log(greet('esm'), typeof require);\n",
    )
    .expect("write index.js");
    std::fs::write(
        package.join("lib.js"),
        "export function greet(name) { return 'hello ' + name; }\n",
    )
    .expect("write lib.js");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            package.join("index.js").to_str().expect("utf8 path"),
            "--extension-id",
            "package-type",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(lines, ["hello esm undefined"]);
}
