//! Integration tests for the npm compatibility matrix module (bd-1lsy.5.4).
//!
//! Tests cover: cohort management, incompatibility lifecycle, verdict
//! computation, seed cohort builders, deterministic hashing, serde
//! contracts, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::npm_compatibility_matrix::{
    BEAD_ID, COMPONENT, CohortTier, IncompatibilityRecord, IncompatibilityRootCause,
    IncompatibilitySeverity, MAX_INCOMPATIBILITIES_PER_PACKAGE, MatrixVerdict, ModuleSystemReq,
    NpmCompatibilityError, NpmCompatibilityMatrix, PackageCategory, PackageRecord,
    PackageTestOutcome, PackageTestResult, RemediationState, SCHEMA_VERSION,
    seed_tier1_critical_packages, seed_tier2_popular_packages,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_package(name: &str, tier: CohortTier) -> PackageRecord {
    PackageRecord {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        tier,
        category: PackageCategory::UtilityLibrary,
        module_system: ModuleSystemReq::DualEsmCjs,
        weekly_downloads: 1_000_000,
        dependency_fanout: 5,
        node_api_deps: BTreeSet::new(),
        types_only: false,
    }
}

fn make_test_result(
    name: &str,
    outcome: PackageTestOutcome,
    total: u32,
    passed: u32,
) -> PackageTestResult {
    PackageTestResult {
        package_name: name.to_string(),
        version: "1.0.0".to_string(),
        outcome,
        total_tests: total,
        passed_tests: passed,
        failed_tests: total.saturating_sub(passed),
        skipped_tests: 0,
        output_hash: None,
        test_epoch: 1,
    }
}

fn make_incompat(id: &str, pkg: &str, sev: IncompatibilitySeverity) -> IncompatibilityRecord {
    IncompatibilityRecord {
        incompatibility_id: id.to_string(),
        package_name: pkg.to_string(),
        root_cause: IncompatibilityRootCause::MissingNodeApi,
        severity: sev,
        summary: format!("test issue in {pkg}"),
        minimized_repro: "const x = require('missing');".to_string(),
        expected_behavior: "module loads".to_string(),
        actual_behavior: "throws Error".to_string(),
        remediation_state: RemediationState::Discovered,
        owner: String::new(),
        related_beads: BTreeSet::new(),
        discovered_epoch: 1,
        last_updated_epoch: 1,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_stable() {
    assert_eq!(COMPONENT, "npm_compatibility_matrix");
    assert_eq!(SCHEMA_VERSION, "franken-engine.npm-compatibility-matrix.v1");
    assert_eq!(BEAD_ID, "bd-1lsy.5.4");
}

// ---------------------------------------------------------------------------
// Matrix construction
// ---------------------------------------------------------------------------

#[test]
fn empty_matrix_properties() {
    let m = NpmCompatibilityMatrix::new();
    assert_eq!(m.total_packages(), 0);
    assert_eq!(m.total_incompatibilities(), 0);
    assert_eq!(m.schema_version, SCHEMA_VERSION);
    assert_eq!(m.bead_id, BEAD_ID);
    assert_eq!(m.verdict(), MatrixVerdict::InsufficientData);
    assert!(m.open_incompatibilities().is_empty());
    assert!(m.root_cause_distribution().is_empty());
    assert!(m.top_blockers(10).is_empty());
}

#[test]
fn default_equals_new() {
    assert_eq!(
        NpmCompatibilityMatrix::default(),
        NpmCompatibilityMatrix::new()
    );
}

// ---------------------------------------------------------------------------
// Package management
// ---------------------------------------------------------------------------

#[test]
fn add_packages_across_tiers() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(make_package("b", CohortTier::Tier2Popular))
        .unwrap();
    m.add_package(make_package("c", CohortTier::Tier3LongTail))
        .unwrap();
    assert_eq!(m.total_packages(), 3);
    assert_eq!(m.packages_in_tier(CohortTier::Tier1Critical).len(), 1);
    assert_eq!(m.packages_in_tier(CohortTier::Tier2Popular).len(), 1);
    assert_eq!(m.packages_in_tier(CohortTier::Tier3LongTail).len(), 1);
}

#[test]
fn packages_stored_sorted_by_name() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("zlib", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(make_package("axios", CohortTier::Tier1Critical))
        .unwrap();
    m.add_package(make_package("lodash", CohortTier::Tier1Critical))
        .unwrap();
    let names: Vec<&str> = m.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["axios", "lodash", "zlib"]);
}

#[test]
fn duplicate_package_name_rejected() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("express", CohortTier::Tier1Critical))
        .unwrap();
    let err = m
        .add_package(make_package("express", CohortTier::Tier2Popular))
        .unwrap_err();
    assert!(
        matches!(*err, NpmCompatibilityError::DuplicatePackage { ref name } if name == "express")
    );
}

#[test]
fn package_name_whitespace_normalized() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut pkg = make_package("  express  ", CohortTier::Tier1Critical);
    pkg.node_api_deps.insert("  http  ".to_string());
    m.add_package(pkg).unwrap();
    assert_eq!(m.packages[0].name, "express");
    assert!(m.packages[0].node_api_deps.contains("http"));
}

#[test]
fn types_only_package_flag() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut pkg = make_package("@types/node", CohortTier::Tier1Critical);
    pkg.types_only = true;
    m.add_package(pkg).unwrap();
    assert!(m.packages[0].types_only);
}

// ---------------------------------------------------------------------------
// Test results
// ---------------------------------------------------------------------------

#[test]
fn record_test_result_for_known_package() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("lodash", CohortTier::Tier1Critical))
        .unwrap();
    m.record_test_result(make_test_result(
        "lodash",
        PackageTestOutcome::Compatible,
        100,
        100,
    ))
    .unwrap();
    let r = m.get_test_result("lodash").unwrap();
    assert_eq!(r.outcome, PackageTestOutcome::Compatible);
    assert_eq!(r.pass_rate_millionths(), 1_000_000);
}

#[test]
fn test_result_for_unknown_package_rejected() {
    let mut m = NpmCompatibilityMatrix::new();
    let err = m
        .record_test_result(make_test_result(
            "ghost",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::PackageNotFound { .. }
    ));
}

#[test]
fn test_result_replaces_previous() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("lodash", CohortTier::Tier1Critical))
        .unwrap();
    m.record_test_result(make_test_result(
        "lodash",
        PackageTestOutcome::Incompatible,
        10,
        0,
    ))
    .unwrap();
    m.record_test_result(make_test_result(
        "lodash",
        PackageTestOutcome::Compatible,
        10,
        10,
    ))
    .unwrap();
    assert_eq!(m.test_results.len(), 1);
    assert_eq!(
        m.get_test_result("lodash").unwrap().outcome,
        PackageTestOutcome::Compatible
    );
}

#[test]
fn pass_rate_partial() {
    let r = make_test_result("x", PackageTestOutcome::PartiallyCompatible, 100, 75);
    assert_eq!(r.pass_rate_millionths(), 750_000);
}

#[test]
fn pass_rate_zero_when_no_tests() {
    let r = make_test_result("x", PackageTestOutcome::Skipped, 0, 0);
    assert_eq!(r.pass_rate_millionths(), 0);
}

// ---------------------------------------------------------------------------
// Incompatibility management
// ---------------------------------------------------------------------------

#[test]
fn add_incompatibility_and_query() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("express", CohortTier::Tier1Critical))
        .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "express",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    assert_eq!(m.total_incompatibilities(), 1);
    assert_eq!(m.incompatibilities_for_package("express").len(), 1);
    assert_eq!(m.incompatibilities_for_package("lodash").len(), 0);
    assert_eq!(m.open_incompatibilities().len(), 1);
}

#[test]
fn duplicate_incompatibility_id_rejected() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    let err = m
        .add_incompatibility(make_incompat(
            "INC-001",
            "b",
            IncompatibilitySeverity::Major,
        ))
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::DuplicateIncompatibility { .. }
    ));
}

#[test]
fn incompatibility_overflow_guard() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..MAX_INCOMPATIBILITIES_PER_PACKAGE {
        m.add_incompatibility(make_incompat(
            &format!("INC-{i:04}"),
            "pkg",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
    }
    let err = m
        .add_incompatibility(make_incompat(
            "INC-OVERFLOW",
            "pkg",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::IncompatibilityOverflow { .. }
    ));
}

#[test]
fn incompatibilities_by_root_cause() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut inc1 = make_incompat("INC-001", "a", IncompatibilitySeverity::Blocker);
    inc1.root_cause = IncompatibilityRootCause::NativeAddon;
    m.add_incompatibility(inc1).unwrap();

    let mut inc2 = make_incompat("INC-002", "b", IncompatibilitySeverity::Major);
    inc2.root_cause = IncompatibilityRootCause::NativeAddon;
    m.add_incompatibility(inc2).unwrap();

    let mut inc3 = make_incompat("INC-003", "c", IncompatibilitySeverity::Minor);
    inc3.root_cause = IncompatibilityRootCause::V8SpecificApi;
    m.add_incompatibility(inc3).unwrap();

    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::NativeAddon)
            .len(),
        2
    );
    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::V8SpecificApi)
            .len(),
        1
    );
    assert_eq!(
        m.incompatibilities_by_root_cause(IncompatibilityRootCause::CjsRequireDivergence)
            .len(),
        0
    );
}

// ---------------------------------------------------------------------------
// Remediation state machine
// ---------------------------------------------------------------------------

#[test]
fn full_remediation_lifecycle() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();

    // Discovered -> Triaged -> InProgress -> FixLanded -> Verified
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::InProgress, 3)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::Verified, 5)
        .unwrap();

    assert!(m.open_incompatibilities().is_empty());
    let inc = &m.incompatibilities[0];
    assert_eq!(inc.remediation_state, RemediationState::Verified);
    assert_eq!(inc.last_updated_epoch, 5);
}

#[test]
fn wont_fix_from_triaged() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::WontFix, 3)
        .unwrap();
    assert!(m.open_incompatibilities().is_empty());
}

#[test]
fn wont_fix_from_in_progress() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::InProgress, 3)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::WontFix, 4)
        .unwrap();
    assert!(m.open_incompatibilities().is_empty());
}

#[test]
fn regression_fix_landed_back_to_in_progress() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Major,
    ))
    .unwrap();
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::InProgress, 3)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::InProgress, 5)
        .unwrap();
    assert_eq!(m.open_incompatibilities().len(), 1);
}

#[test]
fn invalid_transition_discovered_to_verified() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    let err = m
        .transition_remediation("INC-001", RemediationState::Verified, 2)
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::InvalidStateTransition { .. }
    ));
}

#[test]
fn invalid_transition_discovered_to_in_progress() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    let err = m
        .transition_remediation("INC-001", RemediationState::InProgress, 2)
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::InvalidStateTransition { .. }
    ));
}

#[test]
fn transition_nonexistent_incompatibility() {
    let mut m = NpmCompatibilityMatrix::new();
    let err = m
        .transition_remediation("INC-999", RemediationState::Triaged, 1)
        .unwrap_err();
    assert!(matches!(
        *err,
        NpmCompatibilityError::IncompatibilityNotFound { .. }
    ));
}

// ---------------------------------------------------------------------------
// Cohort summaries
// ---------------------------------------------------------------------------

#[test]
fn cohort_summary_all_compatible() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..5 {
        m.add_package(make_package(&format!("pkg-{i}"), CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(make_test_result(
            &format!("pkg-{i}"),
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
    }
    let s = m.cohort_summary(CohortTier::Tier1Critical);
    assert_eq!(s.compatible_count, 5);
    assert_eq!(s.compatibility_rate_millionths, 1_000_000);
    assert!(s.unblocked);
}

#[test]
fn cohort_summary_below_threshold() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..10 {
        m.add_package(make_package(&format!("pkg-{i}"), CohortTier::Tier1Critical))
            .unwrap();
    }
    // Only 5/10 compatible = 50% < 95% threshold
    for i in 0..5 {
        m.record_test_result(make_test_result(
            &format!("pkg-{i}"),
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
    }
    for i in 5..10 {
        m.record_test_result(make_test_result(
            &format!("pkg-{i}"),
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();
    }
    let s = m.cohort_summary(CohortTier::Tier1Critical);
    assert!(!s.unblocked);
    assert_eq!(s.compatibility_rate_millionths, 500_000);
}

#[test]
fn cohort_summary_skipped_excluded_from_denominator() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("a", CohortTier::Tier2Popular))
        .unwrap();
    m.add_package(make_package("b", CohortTier::Tier2Popular))
        .unwrap();
    m.record_test_result(make_test_result(
        "a",
        PackageTestOutcome::Compatible,
        10,
        10,
    ))
    .unwrap();
    m.record_test_result(make_test_result("b", PackageTestOutcome::Skipped, 0, 0))
        .unwrap();
    let s = m.cohort_summary(CohortTier::Tier2Popular);
    assert_eq!(s.compatibility_rate_millionths, 1_000_000); // 1/1 testable
}

#[test]
fn cohort_summary_empty_tier() {
    let m = NpmCompatibilityMatrix::new();
    let s = m.cohort_summary(CohortTier::Tier3LongTail);
    assert_eq!(s.total_packages, 0);
    assert_eq!(s.compatibility_rate_millionths, 0);
}

#[test]
fn cohort_summary_tracks_blockers() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-002",
        "a",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    let s = m.cohort_summary(CohortTier::Tier1Critical);
    assert_eq!(s.open_incompatibilities, 2);
    assert_eq!(s.blocker_count, 1);
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_insufficient_when_mostly_untested() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..10 {
        m.add_package(make_package(&format!("pkg-{i}"), CohortTier::Tier1Critical))
            .unwrap();
    }
    // Only 4 tested
    for i in 0..4 {
        m.record_test_result(make_test_result(
            &format!("pkg-{i}"),
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
    }
    assert_eq!(m.verdict(), MatrixVerdict::InsufficientData);
}

#[test]
fn verdict_partially_unblocked() {
    let mut m = NpmCompatibilityMatrix::new();
    // Tier 1: 100% compatible
    m.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    m.record_test_result(make_test_result(
        "a",
        PackageTestOutcome::Compatible,
        10,
        10,
    ))
    .unwrap();
    // Tier 2: 0% compatible
    m.add_package(make_package("b", CohortTier::Tier2Popular))
        .unwrap();
    m.record_test_result(make_test_result(
        "b",
        PackageTestOutcome::Incompatible,
        10,
        0,
    ))
    .unwrap();
    assert_eq!(m.verdict(), MatrixVerdict::PartiallyUnblocked);
}

#[test]
fn verdict_all_unblocked_multi_tier() {
    let mut m = NpmCompatibilityMatrix::new();
    for (name, tier) in [
        ("a", CohortTier::Tier1Critical),
        ("b", CohortTier::Tier2Popular),
        ("c", CohortTier::Tier3LongTail),
    ] {
        m.add_package(make_package(name, tier)).unwrap();
        m.record_test_result(make_test_result(
            name,
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
    }
    assert_eq!(m.verdict(), MatrixVerdict::AllCohortsUnblocked);
}

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

#[test]
fn root_cause_distribution_with_resolved() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "a",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-002",
        "b",
        IncompatibilitySeverity::Minor,
    ))
    .unwrap();
    // Resolve INC-001
    m.transition_remediation("INC-001", RemediationState::Triaged, 2)
        .unwrap();
    m.transition_remediation("INC-001", RemediationState::WontFix, 3)
        .unwrap();
    let dist = m.root_cause_distribution();
    // Only INC-002 still open
    assert_eq!(dist.len(), 1);
    assert_eq!(dist[&IncompatibilityRootCause::MissingNodeApi], 1);
}

#[test]
fn top_blockers_sorted_by_weighted_score() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_incompatibility(make_incompat(
        "INC-001",
        "heavy",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-002",
        "heavy",
        IncompatibilitySeverity::Major,
    ))
    .unwrap();
    m.add_incompatibility(make_incompat(
        "INC-003",
        "light",
        IncompatibilitySeverity::Cosmetic,
    ))
    .unwrap();
    let top = m.top_blockers(10);
    assert_eq!(top[0].0, "heavy");
    assert!(top[0].1 > top[1].1);
}

#[test]
fn top_blockers_respects_limit() {
    let mut m = NpmCompatibilityMatrix::new();
    for i in 0..20 {
        m.add_incompatibility(make_incompat(
            &format!("INC-{i:03}"),
            &format!("pkg-{i}"),
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
    }
    assert_eq!(m.top_blockers(5).len(), 5);
}

#[test]
fn packages_by_downloads_ordering() {
    let mut m = NpmCompatibilityMatrix::new();
    m.add_package(PackageRecord {
        weekly_downloads: 100,
        ..make_package("low", CohortTier::Tier3LongTail)
    })
    .unwrap();
    m.add_package(PackageRecord {
        weekly_downloads: 50_000_000,
        ..make_package("high", CohortTier::Tier1Critical)
    })
    .unwrap();
    m.add_package(PackageRecord {
        weekly_downloads: 5_000_000,
        ..make_package("mid", CohortTier::Tier2Popular)
    })
    .unwrap();
    let sorted = m.packages_by_downloads();
    assert_eq!(sorted[0].name, "high");
    assert_eq!(sorted[1].name, "mid");
    assert_eq!(sorted[2].name, "low");
}

#[test]
fn packages_requiring_api_surface() {
    let mut m = NpmCompatibilityMatrix::new();
    let mut pkg1 = make_package("express", CohortTier::Tier1Critical);
    pkg1.node_api_deps.insert("http".to_string());
    pkg1.node_api_deps.insert("fs".to_string());
    m.add_package(pkg1).unwrap();

    let pkg2 = make_package("chalk", CohortTier::Tier1Critical);
    // chalk has no Node API deps
    m.add_package(pkg2).unwrap();

    assert_eq!(m.packages_requiring_api("http").len(), 1);
    assert_eq!(m.packages_requiring_api("fs").len(), 1);
    assert_eq!(m.packages_requiring_api("crypto").len(), 0);
}

// ---------------------------------------------------------------------------
// Seed cohort builders
// ---------------------------------------------------------------------------

#[test]
fn seed_tier1_valid_and_nonempty() {
    let pkgs = seed_tier1_critical_packages();
    assert!(pkgs.len() >= 5, "tier 1 should have at least 5 packages");
    for pkg in &pkgs {
        assert_eq!(pkg.tier, CohortTier::Tier1Critical);
        assert!(!pkg.name.is_empty());
        assert!(!pkg.version.is_empty());
        assert!(pkg.weekly_downloads > 0);
    }
}

#[test]
fn seed_tier2_valid_and_nonempty() {
    let pkgs = seed_tier2_popular_packages();
    assert!(pkgs.len() >= 5, "tier 2 should have at least 5 packages");
    for pkg in &pkgs {
        assert_eq!(pkg.tier, CohortTier::Tier2Popular);
        assert!(!pkg.name.is_empty());
        assert!(!pkg.version.is_empty());
    }
}

#[test]
fn seed_cohorts_no_name_collision() {
    let t1 = seed_tier1_critical_packages();
    let t2 = seed_tier2_popular_packages();
    let mut names = BTreeSet::new();
    for pkg in t1.iter().chain(t2.iter()) {
        assert!(
            names.insert(&pkg.name),
            "duplicate package name: {}",
            pkg.name
        );
    }
}

#[test]
fn seed_packages_can_be_added_to_matrix() {
    let mut m = NpmCompatibilityMatrix::new();
    for pkg in seed_tier1_critical_packages() {
        m.add_package(pkg).unwrap();
    }
    for pkg in seed_tier2_popular_packages() {
        m.add_package(pkg).unwrap();
    }
    assert_eq!(m.total_packages(), 20);
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

#[test]
fn hash_deterministic_across_insertion_order() {
    let mut m1 = NpmCompatibilityMatrix::new();
    m1.add_package(make_package("z", CohortTier::Tier1Critical))
        .unwrap();
    m1.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    m1.add_incompatibility(make_incompat("INC-B", "z", IncompatibilitySeverity::Minor))
        .unwrap();
    m1.add_incompatibility(make_incompat(
        "INC-A",
        "a",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();

    let mut m2 = NpmCompatibilityMatrix::new();
    m2.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    m2.add_package(make_package("z", CohortTier::Tier1Critical))
        .unwrap();
    m2.add_incompatibility(make_incompat(
        "INC-A",
        "a",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m2.add_incompatibility(make_incompat("INC-B", "z", IncompatibilitySeverity::Minor))
        .unwrap();

    let h1 = m1.normalize_and_hash();
    let h2 = m2.normalize_and_hash();
    assert_eq!(h1, h2, "hash should be insertion-order independent");
}

#[test]
fn hash_changes_with_data() {
    let mut m1 = NpmCompatibilityMatrix::new();
    m1.add_package(make_package("a", CohortTier::Tier1Critical))
        .unwrap();
    let h1 = m1.normalize_and_hash();

    let mut m2 = NpmCompatibilityMatrix::new();
    m2.add_package(make_package("b", CohortTier::Tier1Critical))
        .unwrap();
    let h2 = m2.normalize_and_hash();

    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_full_matrix() {
    let mut m = NpmCompatibilityMatrix::new();
    for pkg in seed_tier1_critical_packages() {
        m.add_package(pkg).unwrap();
    }
    m.add_incompatibility(make_incompat(
        "INC-001",
        "express",
        IncompatibilitySeverity::Blocker,
    ))
    .unwrap();
    m.record_test_result(make_test_result(
        "lodash",
        PackageTestOutcome::Compatible,
        500,
        500,
    ))
    .unwrap();

    let json = serde_json::to_string_pretty(&m).unwrap();
    let deserialized: NpmCompatibilityMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, deserialized);
}

#[test]
fn serde_round_trip_all_root_causes() {
    let causes = [
        IncompatibilityRootCause::MissingNodeApi,
        IncompatibilityRootCause::CjsRequireDivergence,
        IncompatibilityRootCause::EsmResolutionDivergence,
        IncompatibilityRootCause::ExportsMapDivergence,
        IncompatibilityRootCause::NativeAddon,
        IncompatibilityRootCause::V8SpecificApi,
        IncompatibilityRootCause::ProcessGlobalsDivergence,
        IncompatibilityRootCause::ChildProcessDivergence,
        IncompatibilityRootCause::StreamBufferDivergence,
        IncompatibilityRootCause::TypeScriptCompilation,
        IncompatibilityRootCause::RuntimeIdentityCheck,
        IncompatibilityRootCause::Other,
    ];
    for cause in causes {
        let json = serde_json::to_string(&cause).unwrap();
        let back: IncompatibilityRootCause = serde_json::from_str(&json).unwrap();
        assert_eq!(cause, back);
    }
}

#[test]
fn serde_round_trip_all_module_systems() {
    let systems = [
        ModuleSystemReq::EsmOnly,
        ModuleSystemReq::CjsOnly,
        ModuleSystemReq::DualEsmCjs,
        ModuleSystemReq::Unknown,
    ];
    for sys in systems {
        let json = serde_json::to_string(&sys).unwrap();
        let back: ModuleSystemReq = serde_json::from_str(&json).unwrap();
        assert_eq!(sys, back);
    }
}

#[test]
fn serde_round_trip_remediation_states() {
    let states = [
        RemediationState::Discovered,
        RemediationState::Triaged,
        RemediationState::InProgress,
        RemediationState::FixLanded,
        RemediationState::Verified,
        RemediationState::WontFix,
    ];
    for state in states {
        let json = serde_json::to_string(&state).unwrap();
        let back: RemediationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ---------------------------------------------------------------------------
// Display / as_str coverage
// ---------------------------------------------------------------------------

#[test]
fn all_as_str_methods_nonempty() {
    assert!(!CohortTier::Tier1Critical.as_str().is_empty());
    assert!(!CohortTier::Tier2Popular.as_str().is_empty());
    assert!(!CohortTier::Tier3LongTail.as_str().is_empty());
    assert!(!PackageCategory::BuildTool.as_str().is_empty());
    assert!(!PackageCategory::Other.as_str().is_empty());
    assert!(!ModuleSystemReq::EsmOnly.as_str().is_empty());
    assert!(!ModuleSystemReq::Unknown.as_str().is_empty());
    assert!(!IncompatibilityRootCause::MissingNodeApi.as_str().is_empty());
    assert!(!IncompatibilityRootCause::Other.as_str().is_empty());
    assert!(!IncompatibilitySeverity::Blocker.as_str().is_empty());
    assert!(!IncompatibilitySeverity::Cosmetic.as_str().is_empty());
    assert!(!RemediationState::Discovered.as_str().is_empty());
    assert!(!RemediationState::WontFix.as_str().is_empty());
    assert!(!PackageTestOutcome::Compatible.as_str().is_empty());
    assert!(!PackageTestOutcome::Untested.as_str().is_empty());
    assert!(!MatrixVerdict::AllCohortsUnblocked.as_str().is_empty());
    assert!(!MatrixVerdict::InsufficientData.as_str().is_empty());
}

#[test]
fn display_matches_as_str_for_all_types() {
    assert_eq!(
        format!("{}", CohortTier::Tier1Critical),
        CohortTier::Tier1Critical.as_str()
    );
    assert_eq!(
        format!("{}", PackageCategory::Framework),
        PackageCategory::Framework.as_str()
    );
    assert_eq!(
        format!("{}", IncompatibilitySeverity::Major),
        IncompatibilitySeverity::Major.as_str()
    );
    assert_eq!(
        format!("{}", IncompatibilityRootCause::NativeAddon),
        IncompatibilityRootCause::NativeAddon.as_str()
    );
    assert_eq!(
        format!("{}", RemediationState::FixLanded),
        RemediationState::FixLanded.as_str()
    );
    assert_eq!(
        format!("{}", PackageTestOutcome::PartiallyCompatible),
        PackageTestOutcome::PartiallyCompatible.as_str()
    );
    assert_eq!(
        format!("{}", MatrixVerdict::PartiallyUnblocked),
        MatrixVerdict::PartiallyUnblocked.as_str()
    );
}

// ---------------------------------------------------------------------------
// Threshold and weight constants
// ---------------------------------------------------------------------------

#[test]
fn tier_thresholds_ordered() {
    assert!(
        CohortTier::Tier1Critical.unblock_threshold_millionths()
            > CohortTier::Tier2Popular.unblock_threshold_millionths()
    );
    assert!(
        CohortTier::Tier2Popular.unblock_threshold_millionths()
            > CohortTier::Tier3LongTail.unblock_threshold_millionths()
    );
}

#[test]
fn severity_weights_strictly_ordered() {
    let b = IncompatibilitySeverity::Blocker.weight_millionths();
    let m = IncompatibilitySeverity::Major.weight_millionths();
    let n = IncompatibilitySeverity::Minor.weight_millionths();
    let c = IncompatibilitySeverity::Cosmetic.weight_millionths();
    assert!(b > m && m > n && n > c && c > 0);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_messages_nonempty() {
    let errors = vec![
        NpmCompatibilityError::DuplicatePackage { name: "x".into() },
        NpmCompatibilityError::DuplicateIncompatibility { id: "INC-1".into() },
        NpmCompatibilityError::PackageNotFound { name: "y".into() },
        NpmCompatibilityError::IncompatibilityNotFound { id: "INC-2".into() },
        NpmCompatibilityError::CohortOverflow {
            tier: CohortTier::Tier1Critical,
            count: 501,
        },
        NpmCompatibilityError::IncompatibilityOverflow {
            package: "z".into(),
            count: 101,
        },
        NpmCompatibilityError::InvalidStateTransition {
            id: "INC-3".into(),
            from: RemediationState::Discovered,
            to: RemediationState::Verified,
        },
        NpmCompatibilityError::SnapshotHashMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        },
    ];
    for err in &errors {
        let msg = format!("{err}");
        assert!(
            !msg.is_empty(),
            "error display should not be empty: {err:?}"
        );
    }
}
