//! bd-9vouw.466: in strict code an assignment to a global-object binding
//! is SetMutableBinding on the global object (ES2020 8.1.1.2.5): a binding
//! the right-hand side deleted is a ReferenceError, and a [[Set]] that fails
//! (a non-writable property, a getter without a setter) is a TypeError. The
//! engine dropped both writes silently, and recreated the deleted property.
//! Sloppy code still ignores the failed write. Expected lines are Node
//! v22.2.0's for the program run as a classic script.

use std::process::Command;

const PROGRAM: &str = r#"var global = this;
function attempt(label, f) {
  try {
    f();
    console.log(label + ": ok");
  } catch (e) {
    console.log(label + ": " + e.constructor.name);
  }
}
Object.defineProperty(globalThis, "ro", { value: 1, configurable: true });
attempt("strict non-writable", function () { "use strict"; ro = 2; });
console.log("ro after strict", ro);
attempt("sloppy non-writable", function () { ro = 3; });
console.log("ro after sloppy", ro);
attempt("strict compound", function () { "use strict"; ro += 1; });
attempt("strict update", function () { "use strict"; ro++; });
console.log("ro after compound", ro);
Object.defineProperty(this, "tw", { value: 1, configurable: true });
attempt("strict this-defined", function () { "use strict"; tw = 2; });
globalThis.gz = 1;
attempt("strict deleted", function () { "use strict"; gz = (delete globalThis.gz, 2); });
console.log("gz exists", "gz" in globalThis);
globalThis.gs = 1;
attempt("sloppy deleted", function () { gs = (delete globalThis.gs, 2); });
console.log("gs", gs);
Object.defineProperty(globalThis, "getterOnly", { get: function () { return 7; }, configurable: true });
attempt("strict getter-only", function () { "use strict"; getterOnly = 1; });
var seen = [];
Object.defineProperty(globalThis, "withSetter", {
  get: function () { return 0; },
  set: function (v) { seen.push(v); },
  configurable: true
});
attempt("strict setter", function () { "use strict"; withSetter = 5; });
console.log("setter saw", seen.join(","));
globalThis.plain = 1;
attempt("strict writable", function () { "use strict"; plain = 9; });
console.log("plain", plain);
var declared = 1;
attempt("strict var", function () { "use strict"; declared = 4; });
console.log("declared", declared);
attempt("strict undeclared", function () { "use strict"; nowhere = 1; });
attempt("strict NaN", function () { "use strict"; NaN = 1; });
var count = 0;
Object.defineProperty(this, "x", { configurable: true, value: 1 });
attempt("test262 shape", function () {
  "use strict";
  count++;
  x = (delete global.x, 2);
  count++;
});
console.log("count", count, "x" in this);
"#;

const EXPECTED: &[&str] = &[
    "strict non-writable: TypeError",
    "ro after strict 1",
    "sloppy non-writable: ok",
    "ro after sloppy 1",
    "strict compound: TypeError",
    "strict update: TypeError",
    "ro after compound 1",
    "strict this-defined: TypeError",
    "strict deleted: ReferenceError",
    "gz exists false",
    "sloppy deleted: ok",
    "gs 2",
    "strict getter-only: TypeError",
    "strict setter: ok",
    "setter saw 5",
    "strict writable: ok",
    "plain 9",
    "strict var: ok",
    "declared 4",
    "strict undeclared: ReferenceError",
    "strict NaN: TypeError",
    "test262 shape: ReferenceError",
    "count 1 false",
];

#[test]
fn strict_global_assignments_throw_as_node_does() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("strict_global_put.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "strict-global-put-value",
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
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(printed, EXPECTED);
}
