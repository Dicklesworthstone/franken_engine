#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::mock_seam_guardrail::{
    COMPONENT, FileVerdict, GateDecision, GuardReport, GuardrailError, PatternCategory,
    PatternMatch, SCHEMA_VERSION, ScopeClassification, Waiver, add_waiver, build_default_registry,
    build_guard_report, classify_scope, empty_waiver_policy, is_waived, register_pattern,
    scan_file_content,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// =========================================================================
// A. BTreeSet ordering and dedup for enums
// =========================================================================

#[test]
fn enrichment_pattern_category_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    for cat in PatternCategory::all() {
        set.insert(*cat);
    }
    set.insert(PatternCategory::MockModuleImport); // duplicate
    set.insert(PatternCategory::HardcodedSentinel); // duplicate
    assert_eq!(set.len(), 6);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_scope_classification_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ScopeClassification::TestOnly);
    set.insert(ScopeClassification::Production);
    set.insert(ScopeClassification::Unknown);
    set.insert(ScopeClassification::TestOnly); // duplicate
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_file_verdict_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(FileVerdict::Clean);
    set.insert(FileVerdict::TestOnlyUsage);
    set.insert(FileVerdict::ProductionViolation);
    set.insert(FileVerdict::Clean); // duplicate
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_gate_decision_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(GateDecision::Pass);
    set.insert(GateDecision::Fail);
    set.insert(GateDecision::AbortedExcessViolations);
    set.insert(GateDecision::Pass); // duplicate
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_pattern_category_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for cat in PatternCategory::all() {
        let mut h1 = DefaultHasher::new();
        cat.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        cat.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_scope_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for scope in &[
        ScopeClassification::TestOnly,
        ScopeClassification::Production,
        ScopeClassification::Unknown,
    ] {
        let mut h1 = DefaultHasher::new();
        scope.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        scope.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// =========================================================================
// C. Display values distinct
// =========================================================================

#[test]
fn enrichment_pattern_category_display_distinct() {
    let displays: BTreeSet<String> = PatternCategory::all()
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_scope_display_distinct() {
    let displays: BTreeSet<String> = [
        ScopeClassification::TestOnly,
        ScopeClassification::Production,
        ScopeClassification::Unknown,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_file_verdict_display_distinct() {
    let displays: BTreeSet<String> = [
        FileVerdict::Clean,
        FileVerdict::TestOnlyUsage,
        FileVerdict::ProductionViolation,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_gate_decision_display_distinct() {
    let displays: BTreeSet<String> = [
        GateDecision::Pass,
        GateDecision::Fail,
        GateDecision::AbortedExcessViolations,
    ]
    .iter()
    .map(|d| d.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_error_display_distinct() {
    let errors = [
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
            waiver_id: "w2".to_string(),
            expired_at: 10,
            current: 20,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

// =========================================================================
// D. Debug nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_enums() {
    for cat in PatternCategory::all() {
        assert!(!format!("{cat:?}").is_empty());
    }
    for scope in &[
        ScopeClassification::TestOnly,
        ScopeClassification::Production,
        ScopeClassification::Unknown,
    ] {
        assert!(!format!("{scope:?}").is_empty());
    }
    for verdict in &[
        FileVerdict::Clean,
        FileVerdict::TestOnlyUsage,
        FileVerdict::ProductionViolation,
    ] {
        assert!(!format!("{verdict:?}").is_empty());
    }
    for decision in &[
        GateDecision::Pass,
        GateDecision::Fail,
        GateDecision::AbortedExcessViolations,
    ] {
        assert!(!format!("{decision:?}").is_empty());
    }
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let reg = build_default_registry();
    assert!(!format!("{reg:?}").is_empty());

    let waiver_policy = empty_waiver_policy();
    assert!(!format!("{waiver_policy:?}").is_empty());

    let pm = PatternMatch {
        line_number: 1,
        pattern_needle: "MockCx".to_string(),
        category: PatternCategory::MockContextType,
        scope: ScopeClassification::Production,
        line_excerpt: "let cx = MockCx::new();".to_string(),
    };
    assert!(!format!("{pm:?}").is_empty());

    let waiver = Waiver {
        waiver_id: "w1".to_string(),
        file_pattern: "src/legacy.rs".to_string(),
        pattern_needle: Some("MockCx".to_string()),
        justification: "legacy code".to_string(),
        granted_epoch: epoch(1),
        expiry_epoch: Some(epoch(100)),
    };
    assert!(!format!("{waiver:?}").is_empty());

    for err in &[
        GuardrailError::EmptyPattern,
        GuardrailError::EmptyWaiverId,
        GuardrailError::DuplicatePattern {
            needle: "x".to_string(),
        },
    ] {
        assert!(!format!("{err:?}").is_empty());
    }
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_registry() {
    let original = build_default_registry();
    let mut cloned = original.clone();
    register_pattern(
        &mut cloned,
        "CUSTOM_MOCK".to_string(),
        PatternCategory::HardcodedSentinel,
        "Custom test pattern".to_string(),
    )
    .unwrap();
    assert!(cloned.total_count > original.total_count);
    assert_ne!(cloned.registry_hash, original.registry_hash);
}

#[test]
fn enrichment_clone_independence_waiver_policy() {
    let mut original = empty_waiver_policy();
    add_waiver(
        &mut original,
        "w1".to_string(),
        "src/a.rs".to_string(),
        None,
        "reason".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    let cloned = original.clone();
    add_waiver(
        &mut original,
        "w2".to_string(),
        "src/b.rs".to_string(),
        None,
        "reason2".to_string(),
        epoch(2),
        None,
    )
    .unwrap();
    assert_eq!(cloned.waivers.len(), 1);
    assert_eq!(original.waivers.len(), 2);
}

// =========================================================================
// F. Serde roundtrips
// =========================================================================

#[test]
fn enrichment_pattern_match_serde_roundtrip() {
    let pm = PatternMatch {
        line_number: 42,
        pattern_needle: "FakeBudget".to_string(),
        category: PatternCategory::FakeBudget,
        scope: ScopeClassification::Production,
        line_excerpt: "let b = FakeBudget::unlimited();".to_string(),
    };
    let json = serde_json::to_string(&pm).unwrap();
    let back: PatternMatch = serde_json::from_str(&json).unwrap();
    assert_eq!(pm, back);
}

#[test]
fn enrichment_waiver_serde_roundtrip() {
    let w = Waiver {
        waiver_id: "waiver-001".to_string(),
        file_pattern: "src/legacy/*.rs".to_string(),
        pattern_needle: Some("StubLifecycle".to_string()),
        justification: "grandfathered legacy".to_string(),
        granted_epoch: epoch(5),
        expiry_epoch: Some(epoch(100)),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: Waiver = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_waiver_no_expiry_serde_roundtrip() {
    let w = Waiver {
        waiver_id: "permanent".to_string(),
        file_pattern: "src/compat.rs".to_string(),
        pattern_needle: None,
        justification: "permanent waiver".to_string(),
        granted_epoch: epoch(1),
        expiry_epoch: None,
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: Waiver = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
    assert!(back.expiry_epoch.is_none());
    assert!(back.pattern_needle.is_none());
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = [
        GuardrailError::EmptyPattern,
        GuardrailError::PatternLimitExceeded {
            category: PatternCategory::SeedDerivedTrace,
            limit: 256,
        },
        GuardrailError::DuplicatePattern {
            needle: "test".to_string(),
        },
        GuardrailError::FileLimitExceeded { limit: 8192 },
        GuardrailError::EmptyWaiverId,
        GuardrailError::DuplicateWaiver {
            waiver_id: "dup-w".to_string(),
        },
        GuardrailError::WaiverExpired {
            waiver_id: "exp-w".to_string(),
            expired_at: 50,
            current: 100,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: GuardrailError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_guard_report_serde_roundtrip() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let result = scan_file_content(
        "src/main.rs",
        "fn main() { MockCx::new(); }",
        &reg,
        &waiver,
        epoch(1),
    );
    let report = build_guard_report(vec![result], &reg, &waiver, epoch(1));
    let json = serde_json::to_string(&report).unwrap();
    let back: GuardReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decision, report.decision);
    assert_eq!(back.files_scanned, report.files_scanned);
    assert_eq!(
        back.total_production_violations,
        report.total_production_violations
    );
}

// =========================================================================
// G. Scope classification edge cases
// =========================================================================

#[test]
fn enrichment_classify_scope_tests_directory_prefix() {
    // starts_with("tests/")
    assert_eq!(
        classify_scope("tests/integration.rs", "MockCx::new()", false),
        ScopeClassification::TestOnly
    );
}

#[test]
fn enrichment_classify_scope_nested_tests_directory() {
    assert_eq!(
        classify_scope("crates/engine/tests/foo.rs", "MockCx::new()", false),
        ScopeClassification::TestOnly
    );
}

#[test]
fn enrichment_classify_scope_doc_comment() {
    assert_eq!(
        classify_scope("src/lib.rs", "/// Example: MockCx::new()", false),
        ScopeClassification::TestOnly
    );
}

#[test]
fn enrichment_classify_scope_module_doc_comment() {
    assert_eq!(
        classify_scope("src/lib.rs", "//! This uses MockCx for illustration", false),
        ScopeClassification::TestOnly
    );
}

#[test]
fn enrichment_classify_scope_regular_comment() {
    assert_eq!(
        classify_scope("src/lib.rs", "// TODO: remove MockCx usage", false),
        ScopeClassification::TestOnly
    );
}

#[test]
fn enrichment_classify_scope_production_code() {
    assert_eq!(
        classify_scope("src/engine.rs", "let cx = MockCx::new();", false),
        ScopeClassification::Production
    );
}

#[test]
fn enrichment_classify_scope_in_test_block() {
    assert_eq!(
        classify_scope("src/engine.rs", "let cx = MockCx::new();", true),
        ScopeClassification::TestOnly
    );
}

// =========================================================================
// H. Waiver edge cases
// =========================================================================

#[test]
fn enrichment_waiver_exact_expiry_epoch_still_valid() {
    // Waiver expiry at epoch 10. Current epoch 10 → still valid (> not >=).
    let mut policy = empty_waiver_policy();
    add_waiver(
        &mut policy,
        "w-exp".to_string(),
        "src/a.rs".to_string(),
        Some("MockCx".to_string()),
        "temp".to_string(),
        epoch(1),
        Some(epoch(10)),
    )
    .unwrap();
    assert!(is_waived(&policy, "src/a.rs", "MockCx", epoch(10)));
    // Epoch 11 → expired
    assert!(!is_waived(&policy, "src/a.rs", "MockCx", epoch(11)));
}

#[test]
fn enrichment_waiver_suffix_matching() {
    let mut policy = empty_waiver_policy();
    add_waiver(
        &mut policy,
        "w-suffix".to_string(),
        "legacy.rs".to_string(),
        None,
        "legacy".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    // Suffix match: "src/compat/legacy.rs" ends with "legacy.rs"
    assert!(is_waived(
        &policy,
        "src/compat/legacy.rs",
        "MockCx",
        epoch(1)
    ));
    // No match: different suffix
    assert!(!is_waived(&policy, "src/legacy_v2.rs", "MockCx", epoch(1)));
}

#[test]
fn enrichment_waiver_no_pattern_matches_any_needle() {
    let mut policy = empty_waiver_policy();
    add_waiver(
        &mut policy,
        "w-all".to_string(),
        "src/exempt.rs".to_string(),
        None,
        "full exemption".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    assert!(is_waived(&policy, "src/exempt.rs", "MockCx", epoch(1)));
    assert!(is_waived(&policy, "src/exempt.rs", "FakeBudget", epoch(1)));
    assert!(is_waived(&policy, "src/exempt.rs", "ANYTHING", epoch(1)));
}

// =========================================================================
// I. Registry modification edge cases
// =========================================================================

#[test]
fn enrichment_register_pattern_updates_hash() {
    let mut reg = build_default_registry();
    let hash_before = reg.registry_hash;
    register_pattern(
        &mut reg,
        "NewPattern".to_string(),
        PatternCategory::MockContextType,
        "test".to_string(),
    )
    .unwrap();
    assert_ne!(reg.registry_hash, hash_before);
}

#[test]
fn enrichment_register_pattern_increments_count() {
    let mut reg = build_default_registry();
    let count_before = reg.total_count;
    register_pattern(
        &mut reg,
        "UniqueNew".to_string(),
        PatternCategory::FakeBudget,
        "test".to_string(),
    )
    .unwrap();
    assert_eq!(reg.total_count, count_before + 1);
}

#[test]
fn enrichment_default_registry_all_categories_present() {
    let reg = build_default_registry();
    for cat in PatternCategory::all() {
        let key = cat.label().to_string();
        assert!(
            reg.patterns.contains_key(&key),
            "category {key} not in default registry"
        );
        assert!(
            !reg.patterns[&key].is_empty(),
            "category {key} has no patterns"
        );
    }
}

// =========================================================================
// J. Scan edge cases
// =========================================================================

#[test]
fn enrichment_scan_no_matches_gives_clean_verdict() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let result = scan_file_content("src/clean.rs", "fn clean() {}\n", &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::Clean);
    assert_eq!(result.production_violation_count, 0);
    assert_eq!(result.test_only_count, 0);
    assert!(result.matches.is_empty());
}

#[test]
fn enrichment_scan_multiple_patterns_same_line() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    // Line contains both MockCx and FakeBudget
    let content = "let cx = MockCx::new(); let b = FakeBudget::unlimited();";
    let result = scan_file_content("src/bad.rs", content, &reg, &waiver, epoch(1));
    assert!(result.matches.len() >= 2);
    assert_eq!(result.verdict, FileVerdict::ProductionViolation);
}

#[test]
fn enrichment_scan_waived_match_excluded_from_counts() {
    let reg = build_default_registry();
    let mut waiver = empty_waiver_policy();
    add_waiver(
        &mut waiver,
        "w1".to_string(),
        "src/waived.rs".to_string(),
        Some("MockCx".to_string()),
        "waived".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    let content = "let cx = MockCx::new();";
    let result = scan_file_content("src/waived.rs", content, &reg, &waiver, epoch(1));
    // MockCx is waived, so no production violation for that
    assert_eq!(result.production_violation_count, 0);
}

#[test]
fn enrichment_scan_test_file_matches_are_test_only() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let content = "use control_plane::mocks;\nMockCx::new();\n";
    let result = scan_file_content("tests/my_test.rs", content, &reg, &waiver, epoch(1));
    assert_eq!(result.verdict, FileVerdict::TestOnlyUsage);
    assert_eq!(result.production_violation_count, 0);
    assert!(result.test_only_count > 0);
}

// =========================================================================
// K. Guard report edge cases
// =========================================================================

#[test]
fn enrichment_report_clean_files_excluded_from_results() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let clean = scan_file_content("src/clean.rs", "fn foo() {}", &reg, &waiver, epoch(1));
    let dirty = scan_file_content("src/dirty.rs", "MockCx::new();", &reg, &waiver, epoch(1));
    let report = build_guard_report(vec![clean, dirty], &reg, &waiver, epoch(1));
    // Only non-clean files in file_results
    assert_eq!(report.file_results.len(), 1);
    assert_eq!(report.files_scanned, 2);
    assert_eq!(report.clean_files, 1);
}

#[test]
fn enrichment_report_all_clean_is_pass() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let r1 = scan_file_content("src/a.rs", "fn a() {}", &reg, &waiver, epoch(1));
    let r2 = scan_file_content("src/b.rs", "fn b() {}", &reg, &waiver, epoch(1));
    let report = build_guard_report(vec![r1, r2], &reg, &waiver, epoch(1));
    assert_eq!(report.decision, GateDecision::Pass);
    assert_eq!(report.clean_files, 2);
    assert!(report.file_results.is_empty());
}

#[test]
fn enrichment_report_schema_and_component_populated() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let report = build_guard_report(vec![], &reg, &waiver, epoch(1));
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn enrichment_report_violation_categories_populated() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let r1 = scan_file_content("src/a.rs", "MockCx::new();", &reg, &waiver, epoch(1));
    let r2 = scan_file_content("src/b.rs", "FakeBudget::new();", &reg, &waiver, epoch(1));
    let report = build_guard_report(vec![r1, r2], &reg, &waiver, epoch(1));
    assert!(report.violation_categories.contains("mock_context_type"));
    assert!(report.violation_categories.contains("fake_budget"));
}

#[test]
fn enrichment_report_hash_deterministic() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let files = vec![
        ("src/a.rs", "MockCx::new();"),
        ("src/b.rs", "fn clean() {}"),
    ];
    let results1: Vec<_> = files
        .iter()
        .map(|(p, c)| scan_file_content(p, c, &reg, &waiver, epoch(1)))
        .collect();
    let results2: Vec<_> = files
        .iter()
        .map(|(p, c)| scan_file_content(p, c, &reg, &waiver, epoch(1)))
        .collect();
    let report1 = build_guard_report(results1, &reg, &waiver, epoch(1));
    let report2 = build_guard_report(results2, &reg, &waiver, epoch(1));
    assert_eq!(report1.report_hash, report2.report_hash);
}

// =========================================================================
// L. Constants cross-check
// =========================================================================

#[test]
fn enrichment_constants_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains('.'));
}

#[test]
fn enrichment_pattern_category_all_count() {
    assert_eq!(PatternCategory::all().len(), 6);
}

#[test]
fn enrichment_pattern_category_label_matches_display() {
    for cat in PatternCategory::all() {
        assert_eq!(cat.label(), cat.to_string());
    }
}

// =========================================================================
// M. Copy semantics for enums
// =========================================================================

#[test]
fn enrichment_copy_semantics_pattern_category() {
    let a = PatternCategory::FakeBudget;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_scope() {
    let a = ScopeClassification::Unknown;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_file_verdict() {
    let a = FileVerdict::TestOnlyUsage;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_gate_decision() {
    let a = GateDecision::AbortedExcessViolations;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// N. File scan result deterministic hash
// =========================================================================

#[test]
fn enrichment_scan_file_hash_deterministic() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let r1 = scan_file_content("src/x.rs", "fn x() {}", &reg, &waiver, epoch(1));
    let r2 = scan_file_content("src/x.rs", "fn x() {}", &reg, &waiver, epoch(1));
    assert_eq!(r1.file_hash, r2.file_hash);
}

#[test]
fn enrichment_scan_file_hash_sensitive_to_content() {
    let reg = build_default_registry();
    let waiver = empty_waiver_policy();
    let r1 = scan_file_content("src/x.rs", "fn a() {}", &reg, &waiver, epoch(1));
    let r2 = scan_file_content("src/x.rs", "fn b() {}", &reg, &waiver, epoch(1));
    assert_ne!(r1.file_hash, r2.file_hash);
}

// =========================================================================
// O. Add waiver validates uniqueness
// =========================================================================

#[test]
fn enrichment_add_waiver_updates_hash() {
    let mut policy = empty_waiver_policy();
    let hash_before = policy.policy_hash;
    add_waiver(
        &mut policy,
        "w-new".to_string(),
        "src/f.rs".to_string(),
        None,
        "test".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    assert_ne!(policy.policy_hash, hash_before);
}

#[test]
fn enrichment_add_waiver_empty_id_rejected() {
    let mut policy = empty_waiver_policy();
    let err = add_waiver(
        &mut policy,
        String::new(),
        "src/f.rs".to_string(),
        None,
        "test".to_string(),
        epoch(1),
        None,
    )
    .unwrap_err();
    assert_eq!(err, GuardrailError::EmptyWaiverId);
}

#[test]
fn enrichment_add_waiver_duplicate_rejected() {
    let mut policy = empty_waiver_policy();
    add_waiver(
        &mut policy,
        "w-dup".to_string(),
        "src/a.rs".to_string(),
        None,
        "first".to_string(),
        epoch(1),
        None,
    )
    .unwrap();
    let err = add_waiver(
        &mut policy,
        "w-dup".to_string(),
        "src/b.rs".to_string(),
        None,
        "second".to_string(),
        epoch(2),
        None,
    )
    .unwrap_err();
    assert!(matches!(err, GuardrailError::DuplicateWaiver { .. }));
}
