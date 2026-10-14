//! The actual CLI must emit each completion marker; a clean exit with an
//! undrained promise is not success. Source fixtures are also runnable unchanged
//! by franken_node. Node reference execution is not evidence these tests pass.

use std::process::Command;

fn run(source: &str, name: &str, goal: &str, expected: &str) {
    let root = tempfile::tempdir().expect("temporary fixture directory");
    let input = root.path().join(name);
    let report = root.path().join("report.json");
    std::fs::write(&input, source).expect("write readable operator fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("UTF-8 input path"),
            "--goal",
            goal,
            "--extension-id",
            "readable-operators",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("UTF-8 report path"),
        ])
        .output()
        .expect("execute the production frankenctl binary");
    assert!(
        output.status.success(),
        "{name}: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read execution report"))
            .expect("valid JSON report");
    let actual = report["console_output"]
        .as_array()
        .expect("console output array")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect::<Vec<_>>();
    assert_eq!(actual, [expected], "{name}: completion must be observed");
}

#[test]
fn commonjs_operators_share_alias_identity_and_complete_async_work() {
    run(
        include_str!("../../../fixtures/stream_operators/commonjs.cjs"),
        "commonjs.cjs",
        "script",
        concat!(
            "READABLE_OPERATORS_OK ",
            r#"{"values":[4,5,6,7,8,9],"total":39,"found":7,"every":true,"some":false,"seen":6,"window":[6,7,8]}"#,
        ),
    );
}

#[test]
fn esm_operators_share_alias_identity_and_complete_async_work() {
    run(
        include_str!("../../../fixtures/stream_operators/esm.mjs"),
        "esm.mjs",
        "module",
        "READABLE_OPERATORS_ESM_OK [6]",
    );
}
