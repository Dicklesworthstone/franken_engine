//! bd-9vouw.432: two ways a class field's initializer was misread, so the
//! next field's `private` was never erased and the parser refused the class
//! ("malformed class field"):
//! - without semicolons, a field whose line starts with a modifier
//!   (`private busy: boolean = false` after `private queue: number[] = []`)
//!   was read as part of the initializer above it;
//! - a call's type arguments in an initializer (`new Map<K, V>()`) ended it
//!   at their comma.
//! 8 of 734 real-world .ts files on this machine failed with "malformed
//! class field": 2 the first way, 6 the second. Expected output is Bun
//! 1.4.2's.

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
            "typescript-class-fields",
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
fn semicolonless_fields_with_modifiers_run() {
    let root = tempfile::tempdir().expect("temp dir");
    assert_eq!(
        run(
            root.path(),
            "fields.ts",
            "class C {\n  private queue: number[] = []\n  private busy: boolean = false\n  private readonly size = 2\n  static count = 0\n  protected get total() { return this.size + C.count }\n  run() { return [this.busy, this.queue.length, this.total] }\n}\nconsole.log(JSON.stringify(new C().run()))\n",
        ),
        ["[false,0,2]"]
    );
}

#[test]
fn a_generic_call_in_a_field_initializer_does_not_end_it() {
    let root = tempfile::tempdir().expect("temp dir");
    assert_eq!(
        run(
            root.path(),
            "cache.ts",
            "class Cache<K, V> {\n  private cache = new Map<K, V>();\n  private maxSize: number;\n  constructor(maxSize: number = 100) { this.maxSize = maxSize; }\n  set(key: K, value: V): number { this.cache.set(key, value); return this.cache.size + this.maxSize; }\n}\nconsole.log(new Cache<string, number>(5).set('a', 1));\n",
        ),
        ["6"]
    );
}
