//! bd-9vouw.433: TypeScript's type-only specifier elision (`export { type
//! A, b }`) read the first brace of every export statement as a specifier
//! list. An exported object literal lost its `type` member silently
//! (`export const config = { type: 'json', n: 1 }` ran with
//! `config.type === undefined`). An exported interface with a `type` member
//! lost its body and failed to parse ("named export clause must start with
//! `{`"). Expected output is Bun 1.4.2's.

use std::process::Command;

#[test]
fn exported_declarations_keep_their_type_members() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("actions.ts");
    std::fs::write(
        &entry,
        "export interface Action { type: string; payload: number }\nexport const config = { type: 'json', n: 1 };\nexport const make = (payload: number): Action => ({ type: 'add', payload });\nconsole.log(config.type, config.n, make(2).type, make(2).payload);\n",
    )
    .expect("write actions.ts");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "typescript-type-members",
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
    assert_eq!(lines, ["json 1 add 2"]);
}
