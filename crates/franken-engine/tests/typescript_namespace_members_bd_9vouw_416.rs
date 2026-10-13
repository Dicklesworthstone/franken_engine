//! bd-9vouw.416: a TypeScript namespace's exported members are in scope in
//! its own body: a function or a later initializer names them unqualified
//! (`return PI * r * r`, `TAU = PI * 2`), also across merged declarations
//! of the namespace. The engine assigned them to the namespace object only
//! ("PI is not defined"). The line is Bun 1.4.2's for the same file (Node
//! v22.2.0 does not run TypeScript).

use std::process::Command;

#[test]
fn namespace_members_are_in_scope_in_the_namespace_body() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("geometry.ts");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"namespace Geometry {
  export const PI = 3;
  export const TAU = PI * 2;
  export function area(r: number): number {
    return PI * r * r;
  }
}
namespace Geometry {
  export function circumference(r: number): number {
    return TAU * r;
  }
}
console.log(Geometry.PI, Geometry.TAU, Geometry.area(2), Geometry.circumference(1));
"#,
    )
    .expect("write geometry.ts");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "ts-namespace",
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
    assert_eq!(lines, ["3 6 12 6"]);
}
