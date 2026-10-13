//! bd-9vouw.436: TypeScript normalization's text passes scan for strings
//! and comments but did not know regular expression literals, so a quote
//! inside one (`/[<>:"|?*]/u`, `/it's/`) opened a string that hid the rest
//! of the file from every rewrite: later `type` aliases and interfaces were
//! not erased and the file failed to parse ("unseparated expression
//! sequence"). Found by the real-world TypeScript sweep (734 files).
//! Expected output is Bun 1.4.2's.

use std::process::Command;

#[test]
fn quotes_inside_regular_expressions_do_not_hide_later_declarations() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("regex.ts");
    std::fs::write(
        &entry,
        "const FORBIDDEN = /[<>:\"|?*]/u;\nconst APOS = /it's/;\nconst half: number = 10 / 2;\ntype Entry = { isDirectory: boolean };\ninterface Shape { b: number }\nconst entry: Entry = { isDirectory: FORBIDDEN.test('\"') };\nconsole.log(entry.isDirectory, APOS.test(\"it's\"), half);\n",
    )
    .expect("write regex.ts");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "typescript-regex-literal-quotes",
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
    assert_eq!(lines, ["true true 5"]);
}
