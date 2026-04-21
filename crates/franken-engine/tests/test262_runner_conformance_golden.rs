#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use frankenengine_engine::test262_conformance_runner::{
    TestCategory, TestRecord, TestResult, TestStatistics,
};
use serde::Serialize;

const EXPECTED: &str = include_str!("golden_vectors/test262_runner_accounting_v1.json");

#[derive(Debug, Serialize)]
struct CategoryCase {
    path: &'static str,
    category: &'static str,
}

#[derive(Debug, Serialize)]
struct Test262AccountingSnapshot {
    coverage_gap: &'static str,
    category_cases: Vec<CategoryCase>,
    overall: TestStatistics,
}

fn category_case(path: &'static str) -> CategoryCase {
    let category = TestCategory::from_path(Path::new(path));
    CategoryCase {
        path,
        category: category.as_str(),
    }
}

#[test]
fn test262_runner_accounting_matches_golden() {
    let records = vec![
        TestRecord::new(
            PathBuf::from("language/expressions/addition.js"),
            TestResult::Pass,
            10,
            None,
            false,
        ),
        TestRecord::new(
            PathBuf::from("built-ins/Array/prototype/push.js"),
            TestResult::Fail,
            20,
            Some("assertion mismatch".to_string()),
            false,
        ),
        TestRecord::new(
            PathBuf::from("intl402/DateTimeFormat/basic.js"),
            TestResult::Skip,
            30,
            Some("intl disabled in this lane".to_string()),
            false,
        ),
        TestRecord::new(
            PathBuf::from("harness/assert.js"),
            TestResult::Error,
            40,
            Some("fixture read failed".to_string()),
            false,
        ),
    ];

    let snapshot = Test262AccountingSnapshot {
        coverage_gap: "test262_conformance_runner accounting and category mapping",
        category_cases: vec![
            category_case("language/expressions/addition.js"),
            category_case("built-ins/Array/prototype/push.js"),
            category_case("intl402/DateTimeFormat/basic.js"),
            category_case("annexes/legacy-escape.js"),
            category_case("harness/assert.js"),
        ],
        overall: TestStatistics::from_records(&records),
    };

    let actual = format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap());
    assert_eq!(actual, EXPECTED);
}
