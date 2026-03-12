//! Integration tests for mock_seam_guardrail module.
//!
//! Bead: bd-3nr.1.2.2 [10.13X.B2]

use frankenengine_engine::mock_seam_guardrail::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// Pattern Registry
// ---------------------------------------------------------------------------

#[test]
fn default_registry_covers_all_categories() {
    let reg = build_default_registry();
    let categories: std::collections::BTreeSet<String> = reg.patterns.keys().cloned().collect();
    // Should have at least 4 distinct categories.
    assert!(
        categories.len() >= 4,
        "expected >=4 categories, got {}",
        categories.len()
    );
}

#[test]
fn default_registry_contains_mock_cx() {
    let reg = build_default_registry();
    let all_needles: Vec<&str> = reg
        .patterns
        .values()
        .flat_map(|v| v.iter())
        .map(|p| p.needle.as_str())
        .collect();
    assert!(all_needles.contains(&"MockCx"));
    assert!(all_needles.contains(&"MockBudget"));
}

#[test]
fn register_and_detect_custom_pattern() {
    let mut reg = build_default_registry();
    register_pattern(
        &mut reg,
        "TestStubContext".to_string(),
        PatternCategory::MockContextType,
        "custom stub".to_string(),
    )
    .unwrap();

    let waiver = empty_waiver_policy();
    let content = "let ctx = TestStubContext::new();\n";
    let result = scan_file_content("src/test.rs", content, &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::ProductionViolation);
    assert!(
        result
            .matches
            .iter()
            .any(|m| m.pattern_needle == "TestStubContext")
    );
}

#[test]
fn pattern_limit_enforcement() {
    let mut reg = PatternRegistry {
        patterns: std::collections::BTreeMap::new(),
        total_count: 0,
        registry_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"empty"),
    };
    // Fill up one category to the limit.
    for i in 0..256 {
        register_pattern(
            &mut reg,
            format!("pat_{i}"),
            PatternCategory::MockContextType,
            "test".to_string(),
        )
        .unwrap();
    }
    let err = register_pattern(
        &mut reg,
        "one_more".to_string(),
        PatternCategory::MockContextType,
        "overflow".to_string(),
    );
    assert!(matches!(
        err,
        Err(GuardrailError::PatternLimitExceeded { .. })
    ));
}

// ---------------------------------------------------------------------------
// Scope Classification
// ---------------------------------------------------------------------------

#[test]
fn scope_test_dir_always_test() {
    for path in &[
        "tests/unit.rs",
        "tests/integration/foo.rs",
        "crate/tests/bar.rs",
    ] {
        let scope = classify_scope(path, "MockCx::new()", false);
        assert_eq!(scope, ScopeClassification::TestOnly, "path={path}");
    }
}

#[test]
fn scope_cfg_test_block() {
    let scope = classify_scope("src/engine.rs", "use MockCx;", true);
    assert_eq!(scope, ScopeClassification::TestOnly);
}

#[test]
fn scope_production_non_test_non_comment() {
    let scope = classify_scope("src/engine.rs", "let cx = MockCx::new();", false);
    assert_eq!(scope, ScopeClassification::Production);
}

#[test]
fn scope_comment_lines_classified_test_only() {
    for line in &["// MockCx usage", "/// MockCx doc", "//! module doc MockCx"] {
        let scope = classify_scope("src/engine.rs", line, false);
        assert_eq!(scope, ScopeClassification::TestOnly, "line={line}");
    }
}

// ---------------------------------------------------------------------------
// File Scanning
// ---------------------------------------------------------------------------

#[test]
fn scan_detects_all_default_patterns() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let content = "\
use crate::control_plane::mocks;
let cx = MockCx::new();
let fb = FakeBudget::new(100);
let tid = trace_id_from_seed(42);
let sl = StubLifecycle::default();
let ep = FAKE_EPOCH;
";
    let result = scan_file_content("src/all.rs", content, &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::ProductionViolation);
    // Should detect multiple categories.
    let categories: std::collections::BTreeSet<PatternCategory> =
        result.matches.iter().map(|m| m.category).collect();
    assert!(categories.contains(&PatternCategory::MockModuleImport));
    assert!(categories.contains(&PatternCategory::MockContextType));
    assert!(categories.contains(&PatternCategory::SeedDerivedTrace));
    assert!(categories.contains(&PatternCategory::FakeBudget));
    assert!(categories.contains(&PatternCategory::StubLifecycle));
    assert!(categories.contains(&PatternCategory::HardcodedSentinel));
}

#[test]
fn scan_empty_file_clean() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let result = scan_file_content("src/empty.rs", "", &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::Clean);
    assert!(result.matches.is_empty());
}

#[test]
fn scan_line_numbers_correct() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let content = "line1\nline2\nMockCx::new()\nline4\n";
    let result = scan_file_content("src/lines.rs", content, &reg, &waiver, epoch(1));
    assert!(!result.matches.is_empty());
    assert_eq!(result.matches[0].line_number, 3);
}

#[test]
fn scan_truncates_long_lines() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let long = format!("MockCx::new(); {}", "a".repeat(500));
    let result = scan_file_content("src/long.rs", &long, &reg, &waiver, epoch(1));
    for m in &result.matches {
        assert!(m.line_excerpt.len() <= 200);
    }
}

// ---------------------------------------------------------------------------
// Waiver Policy
// ---------------------------------------------------------------------------

#[test]
fn waiver_exempts_specific_file_and_pattern() {
    let reg = build_default_registry();
    let mut waiver = empty_waiver_policy();
    add_waiver(
        &mut waiver,
        "w-legacy-mock".to_string(),
        "src/legacy_orchestrator.rs".to_string(),
        Some("MockCx".to_string()),
        "Legacy code under migration".to_string(),
        epoch(1),
        None,
    )
    .unwrap();

    let content = "let cx = MockCx::new();\nlet b = MockBudget::new(10);\n";
    let result = scan_file_content(
        "src/legacy_orchestrator.rs",
        content,
        &reg,
        &waiver,
        epoch(1),
    );
    // MockCx should be waived, but MockBudget should still flag.
    assert_eq!(result.verdict, FileVerdict::ProductionViolation);
    assert!(!result.matches.iter().any(|m| m.pattern_needle == "MockCx"));
    assert!(
        result
            .matches
            .iter()
            .any(|m| m.pattern_needle == "MockBudget")
    );
}

#[test]
fn waiver_wildcard_exempts_all_patterns() {
    let reg = build_default_registry();
    let mut waiver = empty_waiver_policy();
    add_waiver(
        &mut waiver,
        "w-full".to_string(),
        "src/legacy.rs".to_string(),
        None, // wildcard
        "Full exemption".to_string(),
        epoch(1),
        None,
    )
    .unwrap();

    let content = "MockCx::new();\nMockBudget::new(10);\ntrace_id_from_seed(1);\n";
    let result = scan_file_content("src/legacy.rs", content, &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::Clean);
}

#[test]
fn waiver_expiry_honored() {
    let reg = build_default_registry();
    let mut waiver = empty_waiver_policy();
    add_waiver(
        &mut waiver,
        "w-temp".to_string(),
        "src/temp.rs".to_string(),
        None,
        "Temporary".to_string(),
        epoch(1),
        Some(epoch(5)),
    )
    .unwrap();

    let content = "MockCx::new();\n";

    // Before expiry: waived.
    let r1 = scan_file_content("src/temp.rs", content, &reg, &waiver, epoch(3));
    assert_eq!(r1.verdict, FileVerdict::Clean);

    // After expiry: violation.
    let r2 = scan_file_content("src/temp.rs", content, &reg, &waiver, epoch(6));
    assert_eq!(r2.verdict, FileVerdict::ProductionViolation);
}

// ---------------------------------------------------------------------------
// Guard Report / Full Sweep
// ---------------------------------------------------------------------------

#[test]
fn full_sweep_pass_all_clean() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![
        ("src/a.rs", "fn a() { 1 + 1; }"),
        ("src/b.rs", "pub struct B;"),
        ("src/c.rs", "const X: u32 = 42;"),
    ];
    let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    assert_eq!(report.decision, GateDecision::Pass);
    assert_eq!(report.files_scanned, 3);
    assert_eq!(report.clean_files, 3);
    assert_eq!(report.files_with_violations, 0);
    assert_eq!(report.total_production_violations, 0);
}

#[test]
fn full_sweep_fail_single_violation() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![
        ("src/clean.rs", "fn clean() {}"),
        ("src/bad.rs", "let cx = MockCx::new();"),
    ];
    let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    assert_eq!(report.decision, GateDecision::Fail);
    assert_eq!(report.files_with_violations, 1);
}

#[test]
fn full_sweep_test_only_passes() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![
        ("tests/unit.rs", "use MockCx; use MockBudget;"),
        ("src/clean.rs", "fn foo() {}"),
    ];
    let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    assert_eq!(report.decision, GateDecision::Pass);
    assert_eq!(report.files_with_test_only, 1);
}

#[test]
fn full_sweep_violation_categories_populated() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![("src/a.rs", "MockCx::new();\ntrace_id_from_seed(1);")];
    let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    assert!(report.violation_categories.contains("mock_context_type"));
    assert!(report.violation_categories.contains("seed_derived_trace"));
}

#[test]
fn full_sweep_report_hash_deterministic() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![("src/a.rs", "MockCx::new();"), ("src/b.rs", "fn b() {}")];
    let r1 = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    let r2 = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    assert_eq!(r1.report_hash, r2.report_hash);
    assert_eq!(r1.decision, r2.decision);
}

#[test]
fn full_sweep_serde_round_trip() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files: Vec<(&str, &str)> = vec![("src/bad.rs", "MockCx::new();")];
    let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: GuardReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.decision, back.decision);
    assert_eq!(report.files_scanned, back.files_scanned);
    assert_eq!(
        report.total_production_violations,
        back.total_production_violations
    );
    assert_eq!(report.report_hash, back.report_hash);
}

// ---------------------------------------------------------------------------
// End-to-end: realistic scenario
// ---------------------------------------------------------------------------

#[test]
fn e2e_production_codebase_with_waivers() {
    let mut reg = build_default_registry();
    register_pattern(
        &mut reg,
        "PLACEHOLDER_TRACE".to_string(),
        PatternCategory::HardcodedSentinel,
        "placeholder trace constant".to_string(),
    )
    .unwrap();

    let mut waiver = empty_waiver_policy();
    add_waiver(
        &mut waiver,
        "w-migration".to_string(),
        "src/execution_orchestrator.rs".to_string(),
        Some("MockCx".to_string()),
        "Under active migration bd-3nr.1.2.1".to_string(),
        epoch(1),
        Some(epoch(100)),
    )
    .unwrap();

    let files: Vec<(&str, &str)> = vec![
        // Clean production code.
        (
            "src/bytecode_vm.rs",
            "fn execute(op: &Op) -> Result<(), Error> { Ok(()) }",
        ),
        // Orchestrator with waived MockCx usage.
        (
            "src/execution_orchestrator.rs",
            "let cx = MockCx::new(); // under migration",
        ),
        // Test file with extensive mock usage (OK).
        (
            "tests/orchestrator_test.rs",
            "use MockCx;\nuse MockBudget;\nuse trace_id_from_seed;",
        ),
        // New code with unauthorized mock usage (violation!).
        ("src/new_feature.rs", "let budget = MockBudget::new(999);"),
    ];

    let report = run_guard_sweep(&files, &reg, &waiver, epoch(5)).unwrap();

    // Should FAIL due to new_feature.rs.
    assert_eq!(report.decision, GateDecision::Fail);
    assert_eq!(report.files_scanned, 4);
    assert_eq!(report.files_with_violations, 1); // new_feature.rs
    assert_eq!(report.files_with_test_only, 1); // tests/
    // The orchestrator MockCx is waived, so doesn't count.
    // But MockBudget in orchestrator is NOT waived.
    // Actually, the orchestrator only has MockCx which is waived.
}

#[test]
fn e2e_all_clean_after_migration() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();

    // Simulating a fully migrated codebase: no mock usage in production.
    let files: Vec<(&str, &str)> = vec![
        ("src/bytecode_vm.rs", "fn execute() {}"),
        (
            "src/execution_orchestrator.rs",
            "fn run(cx: &RealCx) { cx.close(); }",
        ),
        (
            "src/lowering_pipeline.rs",
            "fn lower(ast: &Ast) -> Ir { todo!() }",
        ),
        ("tests/unit.rs", "use MockCx; // test-only OK"),
    ];

    let report = run_guard_sweep(&files, &reg, &waiver, epoch(10)).unwrap();
    assert_eq!(report.decision, GateDecision::Pass);
    assert_eq!(report.total_production_violations, 0);
}

// ---------------------------------------------------------------------------
// Error conditions
// ---------------------------------------------------------------------------

#[test]
fn error_display_coverage() {
    let errors = vec![
        GuardrailError::EmptyPattern,
        GuardrailError::PatternLimitExceeded {
            category: PatternCategory::MockModuleImport,
            limit: 256,
        },
        GuardrailError::DuplicatePattern {
            needle: "x".to_string(),
        },
        GuardrailError::FileLimitExceeded { limit: 8192 },
        GuardrailError::EmptyWaiverId,
        GuardrailError::DuplicateWaiver {
            waiver_id: "w".to_string(),
        },
        GuardrailError::WaiverExpired {
            waiver_id: "w".to_string(),
            expired_at: 5,
            current: 10,
        },
    ];
    for e in &errors {
        let s = format!("{e}");
        assert!(!s.is_empty(), "empty display for {e:?}");
    }
}

#[test]
fn error_serde_round_trip() {
    let e = GuardrailError::PatternLimitExceeded {
        category: PatternCategory::FakeBudget,
        limit: 256,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GuardrailError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}
