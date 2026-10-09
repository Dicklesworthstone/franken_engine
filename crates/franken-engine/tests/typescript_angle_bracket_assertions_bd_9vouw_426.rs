//! bd-9vouw.426: TypeScript's prefix type assertion `<T>value` (the form
//! older TypeScript code uses, `value as T`'s twin) runs in a `.ts` file:
//! nested, parenthesized, with generic and object types, after `return`,
//! `?` and `[`, and beside generic arrow functions, which keep their type
//! parameters. The engine left the `<T>` in place and the file failed to
//! parse ("expression begins with a binary operator"). The line is Bun
//! 1.4.2's for the same file (Node v22.2.0 does not run TypeScript).

use std::process::Command;

#[test]
fn prefix_type_assertions_run_in_a_ts_file() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("casts.ts");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"interface Box { v: number }
const raw: unknown = { v: 2 };
const a = <Box>raw;
const b = (<any>raw).v + 1;
const c = <number><unknown>"7" as unknown as number;
const d = <Array<string>>["x", "y"];
const e = <{ v: number }>raw;
function f(input: unknown): string { return <string>input; }
const g = <T>(x: T): T => x;
const h = <T,>(x: T) => [x];
const i = 1 < 2 ? <number>3 : 4;
const j = [<number>1, <number>2].map(<(n: number) => number>((n) => n * 2));
console.log(a.v, b, typeof c, d.join(), e.v, f("s"), g(5), h(6)[0], i, j.join());
"#,
    )
    .expect("write casts.ts");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "ts-casts",
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
    assert_eq!(lines, ["2 3 string x,y 2 s 5 6 3 2,4"]);
}
