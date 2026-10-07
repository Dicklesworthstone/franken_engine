#![forbid(unsafe_code)]

//! bd-9vouw.262: `frankenctl run` widens the deterministic lane's register
//! window to the entry module's widest verified frame, as source eval does.
//! The orchestrator built the QuickJS lane with 256 registers and never
//! widened it, so a module whose functions the lowering had sized wider
//! failed with "register 256 out of bounds (max 256)": @babel/standalone did
//! at load. The extra register carriers are charged to the memory budget
//! (reserve_eval_register_capacity).
//!
//! PROGRAM's function holds 96 locals and a 64-entry object literal whose
//! last value is another 64-entry literal; its compiled frame is wider than
//! 256 registers (checked below, so the run is not vacuous). Node v22.2.0
//! prints "4560 64 64 63".
//!
//! No-claim: modules loaded later (require, import, new Function) keep the
//! configured window.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{name}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

fn utf8(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

/// The program described in the module documentation.
fn program() -> String {
    let declarations: String = (0..96).map(|i| format!("  var v{i} = {i};\n")).collect();
    let inner: Vec<String> = (0..64).map(|j| format!("i{j}: v{}", j % 96)).collect();
    let mut outer: Vec<String> = (0..63).map(|i| format!("    k{i}: v{i}")).collect();
    outer.push(format!("    k63: {{ {} }}", inner.join(", ")));
    let uses: Vec<String> = (0..96).map(|i| format!("v{i}")).collect();
    format!(
        "function wide() {{\n{declarations}  var o = {{\n{}\n  }};\n  return [{}, \
         Object.keys(o).length, Object.keys(o.k63).length, o.k63.i63];\n}}\n\
         console.log(wide().join(' '));\n",
        outer.join(",\n"),
        uses.join(" + ")
    )
}

#[test]
fn a_module_with_a_frame_wider_than_256_registers_runs_bd_9vouw_262() {
    let root = temp_dir("fe_run_wide_frame");
    let source = root.join("wide.js");
    fs::write(&source, program()).expect("write program");

    let artifact = root.join("wide.ir.json");
    let compiled = frankenctl(&[
        "compile",
        "--input",
        utf8(&source),
        "--out",
        utf8(&artifact),
    ]);
    assert!(
        compiled.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&artifact).expect("read artifact")).expect("json");
    let widest = artifact["lowering"]["ir3"]["function_table"]
        .as_array()
        .expect("function table")
        .iter()
        .filter_map(|function| function["frame_size"].as_u64())
        .max()
        .expect("a function");
    assert!(
        widest > 256,
        "the program must need a wide frame, got {widest}"
    );

    let report = root.join("wide.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "wide-frame",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(lines, ["4560 64 64 63"]);
}
