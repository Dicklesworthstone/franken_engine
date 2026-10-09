//! bd-1lsy.4.10.1: ES module imports are live bindings (ES2020 15.2.1.16.4:
//! an import binding is an indirect binding to the exporting module's
//! binding). A write the exporting module makes after it has evaluated, here
//! from its own exported functions, is seen through a named import, the
//! namespace object, a closure over the import, a named re-export
//! (`export { x as y } from`), an imported binding exported again and
//! `export * from` (a barrel, also through a diamond); assigning an import
//! is a TypeError. The engine copied each export once
//! when the import ran (bd-9vouw.222 published final values at the end of
//! the exporting module's body), so every line below printed the initial
//! values and the assignment succeeded.
//!
//! Expected lines are Node v22.2.0's for the same files.

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
            "esm-live-bindings",
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
fn imports_follow_the_exporting_modules_later_writes() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("counter.mjs"),
        r#"export let count = 0;
export function inc() { count++; }
export let config = { mode: 'a' };
export function setConfig(next) { config = next; }
"#,
    )
    .expect("write counter.mjs");
    std::fs::write(
        root.path().join("relay.mjs"),
        r#"export { count as relayed, inc as bump } from './counter.mjs';
import { count } from './counter.mjs';
export { count as held };
"#,
    )
    .expect("write relay.mjs");
    std::fs::write(
        root.path().join("main.mjs"),
        r#"import { count, inc, config, setConfig } from './counter.mjs';
import * as ns from './counter.mjs';
import { relayed, bump, held } from './relay.mjs';
const read = () => count;
console.log(count, ns.count, relayed, held, read());
inc();
console.log(count, ns.count, relayed, held, read());
bump();
for (let i = 0; i < 1000; i++) inc();
console.log(count, ns.count, relayed, held, read());
setConfig({ mode: 'b' });
console.log(config.mode, ns.config.mode, JSON.stringify(ns));
try { count = 5; console.log('assigned'); } catch (error) { console.log(error instanceof TypeError, count); }
"#,
    )
    .expect("write main.mjs");
    let lines = run_module(root.path(), "main.mjs");
    assert_eq!(
        lines,
        [
            "0 0 0 0 0",
            "1 1 1 1 1",
            "1002 1002 1002 1002 1002",
            "b b {\"config\":{\"mode\":\"b\"},\"count\":1002}",
            "true 1002",
        ]
    );
}

#[test]
fn star_reexports_follow_the_source_modules_later_writes() {
    let root = tempfile::tempdir().expect("temp dir");
    for (name, source) in [
        (
            "state.mjs",
            "export let level = 'low';\nexport function raise() { level = 'high'; }\n",
        ),
        (
            "index.mjs",
            "export * from './state.mjs';\nexport * from './inner.mjs';\n",
        ),
        (
            "inner.mjs",
            "export * from './state.mjs';\nexport const extra = 1;\n",
        ),
        (
            "main.mjs",
            "import { level, raise, extra } from './index.mjs';\nimport * as barrel from './index.mjs';\nimport * as inner from './inner.mjs';\nconsole.log(level, barrel.level, inner.level, extra);\nraise();\nconsole.log(level, barrel.level, inner.level, Object.keys(barrel).join());\n",
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_eq!(
        run_module(root.path(), "main.mjs"),
        ["low low low 1", "high high high extra,level,raise"]
    );
}
