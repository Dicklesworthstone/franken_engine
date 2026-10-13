//! bd-9vouw.434: an exported function declaration whose parameter list
//! starts on the next line (`export function c` newline `(a) {`), and an
//! exported class whose body brace does (`export class K` newline `{`),
//! failed to parse ("function declaration requires a parameter list",
//! "class declaration requires a braced body"). The line splitter ended an
//! export statement at every line break, while the same declarations
//! without `export` continued. TypeScript's multi-line type parameters
//! (`export function c<` newline `T,` newline `>(positions: T[])`, prettier's
//! layout) leave exactly that once erased: 4 of 734 real-world .ts files on
//! this machine failed so. Expected output is Node v22.2.0's for the module
//! and Bun 1.4.2's for the TypeScript file.

use std::path::Path;
use std::process::Command;

fn run(root: &Path, name: &str, source: &str) -> Vec<String> {
    let entry = root.join(name);
    std::fs::write(&entry, source).expect("write entry");
    let report = root.join(format!("{name}.report.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "export-declaration-line-breaks",
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
    report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn exported_declaration_headers_continue_onto_the_next_line() {
    let root = tempfile::tempdir().expect("temp dir");
    assert_eq!(
        run(
            root.path(),
            "m.mjs",
            "export function c\n(positions) { return positions.length }\nexport async function d\n(x) { return x }\nexport default function e\n(y) { return y * 2 }\nexport class K\n{ m() { return 1 } }\nexport function* g\n() { yield 5 }\nconsole.log(c([1, 2]), new K().m(), e(3), [...g()][0]);\nd(4).then((v) => console.log(v));\n",
        ),
        ["2 1 6 5", "4"]
    );
}

#[test]
fn exported_functions_with_multi_line_type_parameters_run() {
    let root = tempfile::tempdir().expect("temp dir");
    assert_eq!(
        run(
            root.path(),
            "t.ts",
            "export function c<\n\tT extends {\n\t\tusdValue?: number | null;\n\t},\n>(positions: readonly T[]): number {\n\treturn positions.length;\n}\nconsole.log(c([{ usdValue: 1 }]));\n",
        ),
        ["1"]
    );
}
