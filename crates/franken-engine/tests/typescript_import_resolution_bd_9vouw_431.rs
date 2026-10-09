//! bd-9vouw.431: a TypeScript project names its modules without their
//! extension (`./lib` for `lib.ts`, `./dir` for `dir/index.ts`) or by the
//! JavaScript file each compiles to (`./util.js` for `util.ts`,
//! `./esm.mjs` for `esm.mts`, TypeScript's NodeNext spelling). The module
//! resolver probed `.mjs` and `.js` only, so each import failed "module
//! not found". Expected output is Bun 1.4.2's.

use std::path::Path;
use std::process::Command;

fn run_module(root: &Path, entry: &str) -> Vec<String> {
    let report = root.join(format!("{entry}.report.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            root.join(entry).to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "typescript-import-resolution",
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
fn typescript_specifiers_resolve_as_bun_resolves_them() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir(root.path().join("dir")).expect("create dir");
    for (name, source) in [
        ("lib.ts", "export const a: string = 'lib';\n"),
        ("util.ts", "export const b: string = 'util';\n"),
        ("dir/index.ts", "export const c: string = 'dir';\n"),
        ("app.config.ts", "export const d: string = 'config';\n"),
        ("esm.mts", "export const e: string = 'm';\n"),
        (
            "main.ts",
            "import { a } from './lib';\nimport { b } from './util.js';\nimport { c } from './dir';\nimport { d } from './app.config';\nimport { e } from './esm.mjs';\nconsole.log(a, b, c, d, e);\n",
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_eq!(
        run_module(root.path(), "main.ts"),
        ["lib util dir config m"]
    );
}
