//! Production CLI coverage for retry and global capture reset semantics.

use std::process::Command;

#[test]
fn native_search_retries_preserve_observable_captures() {
    let root = tempfile::tempdir().expect("temporary directory");
    let entry = root.path().join("search.js");
    let report = root.path().join("report.json");
    std::fs::write(&entry, include_str!("fixtures/regexp_search/search.js")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run", "--input", entry.to_str().unwrap(),
            "--extension-id", "regexp-search-retries",
            "--instruction-budget", "2000000000",
            "--out", report.to_str().unwrap(),
        ])
        .output()
        .expect("run frankenctl");
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let actual = report["console_output"].as_array().unwrap().iter()
        .map(|entry| entry["message"].as_str().unwrap()).collect::<Vec<_>>();
    let expected = [
        r#"16384 needle 1025  "#,
        r#"0 ["ab","a"]"#,
        r#"3 ["aba","a"]"#,
        r#"0 ["baaabaac","ba",null,"abaac"]"#,
        r#"2 ["ababc",null,"b"]"#,
        r#"6 ["c","a","a",null,"c"]"#,
        r#"2 ["b",null,null]"#,
        r#"1 ["b",null]"#,
        r#"1 ["b",null,null]"#,
        r#"1 ["aa","a"]"#,
        r#"4 ["","1","053"]"#,
        r#"[[0,["ab","a"]],[2,["c",null]],[3,["ab","a"]],[5,["c",null]]] 0"#,
        r#"null 0"#,
        r#"3 ["n",""] 4"#,
    ];
    assert_eq!(actual, expected);
}
