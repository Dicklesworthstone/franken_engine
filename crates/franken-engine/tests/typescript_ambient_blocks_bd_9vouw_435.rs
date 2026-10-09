//! bd-9vouw.435: TypeScript's ambient blocks (`declare global { ... }`,
//! `declare module "m" { ... }`, `declare namespace N.M { ... }`) declare
//! types only, and were left in place ("unsupported expression syntax:
//! declare global"). A parameter named like a parameter-property modifier
//! (`override: unknown`) was taken for the modifier, so its annotation
//! stayed ("unsupported binding pattern"). Both from the real-world
//! TypeScript sweep (734 files; 2 and 1 failed so). Expected output is Bun
//! 1.4.2's.

use std::process::Command;

#[test]
fn ambient_blocks_and_modifier_named_parameters_run() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("ambient.ts");
    std::fs::write(
        &entry,
        "declare global {\n  interface PromiseConstructor {\n    withResolvers<T>(): {\n      promise: Promise<T>;\n      resolve: (_value: T | PromiseLike<T>) => void;\n    };\n  }\n}\ndeclare module \"pkg\" {\n  export const v: number;\n}\ndeclare namespace NS.Inner {\n  const v: number;\n}\nexport function pick(evidence: number, override: unknown): string {\n  return typeof override + evidence;\n}\nconsole.log(pick(1, 'x'));\n",
    )
    .expect("write ambient.ts");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "typescript-ambient-blocks",
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
    assert_eq!(lines, ["string1"]);
}
