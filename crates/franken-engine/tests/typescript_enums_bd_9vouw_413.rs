//! bd-9vouw.413: TypeScript enums written across lines (the usual
//! formatting), `const enum`, `declare enum` (erased), merged declarations,
//! members whose initializers name earlier members or follow a computed
//! value, and the reverse mapping of numeric members (`Color[5] ===
//! "Green"`) behave as TypeScript compiles them; the enum object is a
//! plain mutable object. The engine lowered only an enum written on one
//! line, to a frozen object without the reverse mapping, and left the
//! others to fail when run. The line is Bun 1.4.2's for the same file (Node
//! v22.2.0 does not run TypeScript).

use std::process::Command;

#[test]
fn typescript_enums_lower_to_typescripts_enum_objects() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("enums.ts");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"enum Color {
  Red,
  Green = 5,
  Blue, // trailing comment
}
enum Status {
  Active = "active",
  /* block */ Inactive = "inactive",
}
const enum Bits { A = 1 << 0, B = 1 << 1, AB = A | B }
enum E { X, Y }
enum E { Z = 9 }
enum Weird { "a-b" = 1, delete = 2, Weird = 3, c }
declare enum Ambient { Q }
enum Empty { }
enum Expr {
  Len = "abc".length,
  Next,
}
console.log(JSON.stringify([Color.Red, Color.Green, Color.Blue, Color[5], Color[6], Status.Active, Status.Inactive, Bits.AB, E.Y, E[1], E.Z, E[9], Weird["a-b"], Weird.delete, Weird.Weird, Weird.c, Weird[4], typeof Ambient, Object.keys(Empty).length, Expr.Len, Expr.Next, Expr[4], Object.isFrozen(Color)]));
"#,
    )
    .expect("write enums.ts");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "ts-enums",
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
    assert_eq!(
        lines,
        [
            "[0,5,6,\"Green\",\"Blue\",\"active\",\"inactive\",3,1,\"Y\",9,\"Z\",1,2,3,4,\"c\",\"undefined\",0,3,4,\"Next\",false]"
        ]
    );
}
