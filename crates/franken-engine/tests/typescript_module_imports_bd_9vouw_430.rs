//! bd-9vouw.430: a TypeScript file a module imports is normalized as the
//! entry file is. The module loader parsed an imported `.ts` / `.mts` file
//! as JavaScript, so its first type annotation (`a: number`) or
//! `export interface` failed the import as unsupported syntax, and no
//! multi-file TypeScript program ran. A file of declarations only, an empty
//! file and one holding only comments are modules with no code and no
//! exports. They failed as empty sources. Expected output is Bun 1.4.2's
//! (Node v22.2.0 does not run TypeScript).

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
            "typescript-module-imports",
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
fn imported_typescript_and_empty_modules_load() {
    let root = tempfile::tempdir().expect("temp dir");
    for (name, source) in [
        (
            "lib.ts",
            "export function add(a: number, b: number): number { return a + b; }\nexport const label: string = 'sum';\nexport class Box<T> { constructor(public value: T) {} }\n",
        ),
        (
            "types.ts",
            "export interface User { id: number; name: string }\nexport type Id = number;\n",
        ),
        ("helper.mts", "export const n: number = 2;\n"),
        ("empty.mjs", ""),
        (
            "comments.mjs",
            "// nothing but a comment\n/* and another */\n",
        ),
        (
            "main.ts",
            "import { add, label, Box } from './lib.ts';\nimport { User } from './types.ts';\nimport type { Id } from './types.ts';\nimport { n } from './helper.mts';\nimport './empty.mjs';\nimport './comments.mjs';\nconst u: User = { id: 1 as Id, name: 'a' };\nconsole.log(label, add(1, n), u.name, u.id, new Box<string>('b').value);\n",
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_eq!(run_module(root.path(), "main.ts"), ["sum 3 a 1 b"]);
}
