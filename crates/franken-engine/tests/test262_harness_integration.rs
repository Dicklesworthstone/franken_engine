#[path = "support/test262_harness.rs"]
mod test262_harness;

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::tempdir;

use test262_harness::{Test262Harness, Test262HarnessConfig};

fn write_file(path: &Path, content: &str) {
    let parent = path.parent().expect("test fixture file must have parent");
    fs::create_dir_all(parent).expect("create fixture parent directories");
    fs::write(path, content).expect("write fixture file");
}

fn create_synthetic_test262_tarball(archive_path: &Path) {
    let suite_parent = archive_path
        .parent()
        .expect("archive path should have parent")
        .join("fixture-root");
    let suite_root = suite_parent.join("test262-sample");

    write_file(
        &suite_root.join("harness/helper.js"),
        "function helperAdd(a, b) { return a + b; }\n",
    );
    write_file(
        &suite_root.join("test/language/expressions/addition/helper-add.js"),
        r#"/*---
description: synthetic helper-backed addition test
includes:
  - helper.js
flags: [onlyStrict]
---*/
helperAdd(1, 2);
"#,
    );
    write_file(
        &suite_root.join("test/language/module-code/skip-me.js"),
        r#"/*---
description: module case skipped by default harness config
flags: [module]
---*/
export const value = 1;
"#,
    );

    let output = Command::new("tar")
        .arg("-czf")
        .arg(archive_path)
        .arg("-C")
        .arg(&suite_parent)
        .arg("test262-sample")
        .output()
        .expect("create synthetic test262 archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn harness_discovers_cases_from_test262_tarball_and_filters_module_flags() {
    let temp = tempdir().expect("create tempdir");
    let archive_path = temp.path().join("test262-sample.tar.gz");
    let extraction_root = temp.path().join("extracted");
    create_synthetic_test262_tarball(&archive_path);

    let harness = Test262Harness::new(Test262HarnessConfig::new(archive_path, extraction_root));
    let cases = harness.discover_cases().expect("discover test262 cases");

    assert_eq!(cases.len(), 1, "module test should be filtered out");
    let case = &cases[0];
    assert_eq!(case.test_id, "language/expressions/addition/helper-add.js");
    assert_eq!(case.metadata.includes, vec!["helper.js"]);
    assert_eq!(case.metadata.flags, vec!["onlyStrict"]);
    assert!(case.source.contains("function helperAdd(a, b)"));
    assert!(case.source.contains("\"use strict\";"));
    assert!(case.source.contains("helperAdd(1, 2);"));
}
