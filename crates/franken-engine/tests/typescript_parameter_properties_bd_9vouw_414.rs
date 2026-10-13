//! bd-9vouw.414: TypeScript parameter properties (`constructor(private
//! readonly x: T)`) in a one-line class, a multi-line parameter list with a
//! default value, with two modifiers or `override`, optional, with a
//! multi-line constructor body, and in a derived class (assigned after
//! `super(...)`). The engine lowered only a `constructor(` that started a
//! line with its whole parameter list on that line, closed a multi-line
//! body early and assigned before `super()`. An object literal's own
//! `constructor` method is untouched. The lines are Bun 1.4.2's for the
//! same file (Node v22.2.0 does not run TypeScript).

use std::process::Command;

#[test]
fn parameter_properties_lower_as_typescript_emits_them() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("params.ts");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"class B { constructor(public base: number) {} }
class D extends B {
  constructor(private extra: number) {
    super(1);
    console.log("derived", this.extra);
  }
  sum() { return this.base + this.extra; }
}
class S {
  constructor(
    private readonly a: number,
    public b: string = "x",
  ) {}
  get() { return this.a + this.b; }
}
class C extends B {
  constructor(public override base: number) {
    super(base * 10);
  }
}
class O { constructor(private a?: number, protected b = 2) {} s() { return String(this.a) + this.b; } }
const o = { constructor(x: number) { return x; } };
console.log([new D(2).sum(), new S(1).get(), new C(5).base, new O().s(), Object.keys(new S(7)).join(), o.constructor(4)].join(" | "));
"#,
    )
    .expect("write params.ts");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "ts-params",
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
    assert_eq!(lines, ["derived 2", "3 | 1x | 5 | undefined2 | a,b | 4"]);
}
