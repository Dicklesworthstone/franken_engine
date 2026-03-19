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

//! Enrichment integration tests for the `react_doctor_preflight` module.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_doctor_preflight::*;
use frankenengine_engine::react_mismatch_catalog::{
    ComparisonTarget, MismatchDomain, MismatchEntry, MismatchSeverity, RemediationStatus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_entry(id: &str, domain: MismatchDomain, severity: MismatchSeverity) -> MismatchEntry {
    MismatchEntry {
        entry_id: id.to_string(),
        domain,
        severity,
        target: ComparisonTarget::NodeJs,
        summary: format!("Mismatch {id}"),
        expected_behavior: "expected".to_string(),
        actual_behavior: "actual".to_string(),
        reproduction: "test fixture".to_string(),
        remediation: RemediationStatus::None,
        advisory: "advisory text".to_string(),
        react_version_range: ">=18.0.0".to_string(),
        evidence_hash: ContentHash::compute(id.as_bytes()),
        detected_epoch: epoch(1),
        verified_epoch: epoch(2),
        tags: ["react", "test"].iter().map(|s| s.to_string()).collect(),
    }
}

fn make_entry_full(
    id: &str,
    domain: MismatchDomain,
    severity: MismatchSeverity,
    target: ComparisonTarget,
    remediation: RemediationStatus,
) -> MismatchEntry {
    let mut e = make_entry(id, domain, severity);
    e.target = target;
    e.remediation = remediation;
    e
}

fn default_config() -> DoctorConfig {
    DoctorConfig::default()
}

// ===========================================================================
// CheckCategory Display uniqueness
// ===========================================================================

#[test]
fn enrichment_check_category_display_all_unique() {
    let displays: BTreeSet<String> = ALL_CATEGORIES.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

// ===========================================================================
// CheckSeverity Display uniqueness
// ===========================================================================

#[test]
fn enrichment_check_severity_display_all_unique() {
    let severities = [
        CheckSeverity::Pass,
        CheckSeverity::Advisory,
        CheckSeverity::Warning,
        CheckSeverity::Error,
        CheckSeverity::Critical,
    ];
    let displays: BTreeSet<String> = severities.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// CheckSeverity weights monotonic
// ===========================================================================

#[test]
fn enrichment_check_severity_weights_monotonic() {
    let severities = [
        CheckSeverity::Pass,
        CheckSeverity::Advisory,
        CheckSeverity::Warning,
        CheckSeverity::Error,
        CheckSeverity::Critical,
    ];
    for w in severities.windows(2) {
        assert!(
            w[0].weight() <= w[1].weight(),
            "{:?} weight {} > {:?} weight {}",
            w[0],
            w[0].weight(),
            w[1],
            w[1].weight()
        );
    }
}

// ===========================================================================
// CheckSeverity is_blocking
// ===========================================================================

#[test]
fn enrichment_check_severity_is_blocking() {
    assert!(!CheckSeverity::Pass.is_blocking());
    assert!(!CheckSeverity::Advisory.is_blocking());
    assert!(!CheckSeverity::Warning.is_blocking());
    assert!(CheckSeverity::Error.is_blocking());
    assert!(CheckSeverity::Critical.is_blocking());
}

// ===========================================================================
// ALL_CATEGORIES count
// ===========================================================================

#[test]
fn enrichment_all_categories_count() {
    assert_eq!(ALL_CATEGORIES.len(), 8);
}

// ===========================================================================
// CheckCategory priority_weight positive
// ===========================================================================

#[test]
fn enrichment_check_category_priority_weight_positive() {
    for cat in ALL_CATEGORIES {
        assert!(cat.priority_weight() > 0, "{cat:?} has zero weight");
    }
}

// ===========================================================================
// DoctorConfig: default includes all categories
// ===========================================================================

#[test]
fn enrichment_config_default_includes_all() {
    let cfg = DoctorConfig::default();
    for cat in ALL_CATEGORIES {
        assert!(cfg.is_category_enabled(*cat), "default should include {cat:?}");
    }
}

// ===========================================================================
// DoctorConfig: exclude overrides include
// ===========================================================================

#[test]
fn enrichment_config_exclude_overrides_include() {
    let mut cfg = DoctorConfig::default();
    cfg.include_categories.insert(CheckCategory::PackageHealth);
    cfg.exclude_categories.insert(CheckCategory::PackageHealth);
    assert!(!cfg.is_category_enabled(CheckCategory::PackageHealth));
}

// ===========================================================================
// DoctorConfig: is_entry_relevant
// ===========================================================================

#[test]
fn enrichment_config_entry_relevant_severity_and_resolved() {
    let cfg = DoctorConfig {
        min_mismatch_severity: MismatchSeverity::Warning,
        ..DoctorConfig::default()
    };
    let info = make_entry("i", MismatchDomain::Diagnostics, MismatchSeverity::Info);
    let warn = make_entry("w", MismatchDomain::Diagnostics, MismatchSeverity::Warning);
    assert!(!cfg.is_entry_relevant(&info));
    assert!(cfg.is_entry_relevant(&warn));

    let resolved = make_entry_full(
        "r",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    );
    assert!(!cfg.is_entry_relevant(&resolved));

    let cfg2 = DoctorConfig {
        include_resolved: true,
        ..DoctorConfig::default()
    };
    assert!(cfg2.is_entry_relevant(&resolved));
}

// ===========================================================================
// DoctorReport: new is empty
// ===========================================================================

#[test]
fn enrichment_report_new_is_empty() {
    let report = DoctorReport::new(epoch(1));
    assert!(report.is_empty());
    assert_eq!(report.len(), 0);
    assert_eq!(report.blocking_count(), 0);
    assert_eq!(report.aggregate_score(), 0);
}

// ===========================================================================
// DoctorReport: schema constants
// ===========================================================================

#[test]
fn enrichment_report_schema_constants() {
    let report = DoctorReport::new(epoch(1));
    assert_eq!(report.schema_version, DOCTOR_PREFLIGHT_SCHEMA_VERSION);
    assert_eq!(report.bead_id, DOCTOR_PREFLIGHT_BEAD_ID);
    assert_eq!(report.policy_id, DOCTOR_PREFLIGHT_POLICY_ID);
}

// ===========================================================================
// run_doctor: empty entries returns empty report
// ===========================================================================

#[test]
fn enrichment_run_doctor_empty() {
    let report = run_doctor(&default_config(), &[]).unwrap();
    assert!(report.is_empty());
}

// ===========================================================================
// run_doctor: info entry non-blocking, critical blocking
// ===========================================================================

#[test]
fn enrichment_run_doctor_info_nonblocking_critical_blocking() {
    let info_entries = vec![make_entry("i1", MismatchDomain::HookSemantics, MismatchSeverity::Info)];
    let report_info = run_doctor(&default_config(), &info_entries).unwrap();
    assert!(!report_info.is_empty());
    assert_eq!(report_info.blocking_count(), 0);

    let crit_entries = vec![make_entry(
        "c1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Critical,
    )];
    let report_crit = run_doctor(&default_config(), &crit_entries).unwrap();
    assert!(report_crit.blocking_count() > 0);
}

// ===========================================================================
// run_doctor: respects max_checks
// ===========================================================================

#[test]
fn enrichment_run_doctor_max_checks_limit() {
    let mut cfg = default_config();
    cfg.max_checks = 2;
    let entries: Vec<_> = (0..10)
        .map(|i| make_entry(&format!("e-{i}"), MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .collect();
    let report = run_doctor(&cfg, &entries).unwrap();
    assert!(report.len() <= 2);
}

// ===========================================================================
// run_doctor: invalid config (max_checks = 0)
// ===========================================================================

#[test]
fn enrichment_run_doctor_invalid_config() {
    let mut cfg = default_config();
    cfg.max_checks = 0;
    let result = run_doctor(&cfg, &[]);
    assert!(result.is_err());
}

// ===========================================================================
// run_doctor: filters resolved by default
// ===========================================================================

#[test]
fn enrichment_run_doctor_filters_resolved() {
    let entries = vec![make_entry_full(
        "r1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(report.is_empty());
}

// ===========================================================================
// run_doctor: staleness detection
// ===========================================================================

#[test]
fn enrichment_run_doctor_staleness_detection() {
    let mut cfg = default_config();
    cfg.current_epoch = epoch(50);
    let mut e = make_entry("stale-1", MismatchDomain::Diagnostics, MismatchSeverity::Warning);
    e.verified_epoch = epoch(5); // 45 epochs behind
    let report = run_doctor(&cfg, &[e]).unwrap();
    let stale: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.check_id.contains("stale"))
        .collect();
    assert!(!stale.is_empty());
}

// ===========================================================================
// run_preflight: passes on empty
// ===========================================================================

#[test]
fn enrichment_preflight_passes_on_empty() {
    let result = run_preflight(&default_config(), &[]).unwrap();
    assert!(result.passed);
    assert_eq!(result.blocker_count(), 0);
}

// ===========================================================================
// run_preflight: warnings pass, errors fail, total_findings counted
// ===========================================================================

#[test]
fn enrichment_preflight_warnings_pass_errors_fail() {
    let warn_entries = vec![make_entry(
        "w1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let warn_result = run_preflight(&default_config(), &warn_entries).unwrap();
    assert!(warn_result.passed);
    assert!(warn_result.advisory_count() > 0);

    let err_entries = vec![make_entry(
        "e1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Error,
    )];
    let err_result = run_preflight(&default_config(), &err_entries).unwrap();
    assert!(!err_result.passed);
    assert!(err_result.blocker_count() > 0);
    assert!(err_result.total_findings() > 0);
}

// ===========================================================================
// build_support_bundle: from empty report
// ===========================================================================

#[test]
fn enrichment_support_bundle_from_empty() {
    let report = DoctorReport::new(epoch(1));
    let bundle = build_support_bundle(&report).unwrap();
    assert!(bundle.is_empty());
    assert_eq!(bundle.schema_version, DOCTOR_PREFLIGHT_SCHEMA_VERSION);
}

// ===========================================================================
// build_support_bundle: has entries for checks
// ===========================================================================

#[test]
fn enrichment_support_bundle_has_entries() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Error),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    assert!(!bundle.is_empty());
    let doctor_checks = bundle.entries_by_category("doctor_checks");
    assert!(!doctor_checks.is_empty());
}

// ===========================================================================
// generate_guidance: empty report
// ===========================================================================

#[test]
fn enrichment_guidance_empty_report() {
    let report = DoctorReport::new(epoch(1));
    let guidance = generate_guidance(&report).unwrap();
    assert!(guidance.is_empty());
}

// ===========================================================================
// generate_guidance: sorted by priority
// ===========================================================================

#[test]
fn enrichment_guidance_sorted_by_priority() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Critical),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    if guidance.len() >= 2 {
        assert!(guidance[0].priority <= guidance[1].priority);
    }
}

// ===========================================================================
// generate_guidance: has steps
// ===========================================================================

#[test]
fn enrichment_guidance_has_steps() {
    let entries = vec![make_entry(
        "e1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    assert!(!guidance.is_empty());
    assert!(!guidance[0].steps.is_empty());
}

// ===========================================================================
// is_react_ready
// ===========================================================================

#[test]
fn enrichment_is_react_ready() {
    assert!(is_react_ready(&DoctorReport::new(epoch(1))));

    let entries = vec![make_entry(
        "e1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Critical,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(!is_react_ready(&report));
}

// ===========================================================================
// summarize
// ===========================================================================

#[test]
fn enrichment_summarize_empty_report() {
    let report = DoctorReport::new(epoch(1));
    let summary = summarize(&report);
    assert_eq!(summary.total_checks, 0);
    assert!(summary.is_ready);
    assert_eq!(summary.aggregate_score, 0);
}

#[test]
fn enrichment_summarize_counts_match() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Error),
        make_entry("e3", MismatchDomain::Diagnostics, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let summary = summarize(&report);
    assert_eq!(
        summary.total_checks,
        summary.pass_count
            + summary.advisory_count
            + summary.warning_count
            + summary.error_count
            + summary.critical_count
    );
}

// ===========================================================================
// readiness_score
// ===========================================================================

#[test]
fn enrichment_readiness_score() {
    let report = DoctorReport::new(epoch(1));
    assert_eq!(readiness_score(&report), 1_000_000);

    let light = vec![make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Info)];
    let heavy = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Critical),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Critical),
    ];
    let r_light = run_doctor(&default_config(), &light).unwrap();
    let r_heavy = run_doctor(&default_config(), &heavy).unwrap();
    assert!(readiness_score(&r_light) > readiness_score(&r_heavy));
}

// ===========================================================================
// referenced_mismatch_ids
// ===========================================================================

#[test]
fn enrichment_referenced_mismatch_ids_collects_all() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::Diagnostics, MismatchSeverity::Error),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let ids = referenced_mismatch_ids(&report);
    assert!(ids.contains("e1"));
    assert!(ids.contains("e2"));
}

// ===========================================================================
// filter_by_categories
// ===========================================================================

#[test]
fn enrichment_filter_by_categories_restricts() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Error),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let cats: BTreeSet<_> = [CheckCategory::HookOrdering].into_iter().collect();
    let filtered = filter_by_categories(&report, &cats);
    for c in &filtered {
        assert_eq!(c.category, CheckCategory::HookOrdering);
    }
}

// ===========================================================================
// domain_triage
// ===========================================================================

#[test]
fn enrichment_domain_triage_counts_open_only() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry_full(
            "e2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ),
    ];
    let triage = domain_triage(&entries);
    assert_eq!(triage.get("compile_output"), Some(&1));
}

#[test]
fn enrichment_domain_triage_empty() {
    let triage = domain_triage(&[]);
    assert!(triage.is_empty());
}

// ===========================================================================
// DoctorError Display uniqueness
// ===========================================================================

#[test]
fn enrichment_doctor_error_display_all_unique() {
    let errors = vec![
        DoctorError::CheckCapacityExceeded { current: 100, max: 50 },
        DoctorError::GuidanceTooLong {
            guidance_id: "gd-0001".to_string(),
            len: 9999,
        },
        DoctorError::BundleTooLarge { current: 6000, max: 5000 },
        DoctorError::EmptyInput,
        DoctorError::InvalidConfig {
            reason: "bad".to_string(),
        },
        DoctorError::StaleData {
            entry_id: "e-1".to_string(),
            epoch_gap: 42,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

// ===========================================================================
// DoctorError serde roundtrip
// ===========================================================================

#[test]
fn enrichment_doctor_error_serde_roundtrip() {
    let errors = vec![
        DoctorError::CheckCapacityExceeded { current: 100, max: 50 },
        DoctorError::GuidanceTooLong {
            guidance_id: "gd-0001".to_string(),
            len: 9999,
        },
        DoctorError::BundleTooLarge { current: 6000, max: 5000 },
        DoctorError::EmptyInput,
        DoctorError::InvalidConfig {
            reason: "bad config".to_string(),
        },
        DoctorError::StaleData {
            entry_id: "e-1".to_string(),
            epoch_gap: 42,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: DoctorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// Serde roundtrips: DoctorReport, PreflightResult, SupportBundle
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_doctor_report() {
    let entries = vec![make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning)];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: DoctorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.len(), back.len());
    assert_eq!(report.report_hash, back.report_hash);
}

#[test]
fn enrichment_serde_roundtrip_preflight_result() {
    let entries = vec![make_entry("e1", MismatchDomain::HookSemantics, MismatchSeverity::Error)];
    let result = run_preflight(&default_config(), &entries).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: PreflightResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.passed, back.passed);
    assert_eq!(result.blocker_count(), back.blocker_count());
}

#[test]
fn enrichment_serde_roundtrip_doctor_config() {
    let cfg = DoctorConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DoctorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// Determinism: same inputs produce same report hash
// ===========================================================================

#[test]
fn enrichment_deterministic_report_hash() {
    let entries = vec![
        make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Warning),
        make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Error),
    ];
    let r1 = run_doctor(&default_config(), &entries).unwrap();
    let r2 = run_doctor(&default_config(), &entries).unwrap();
    assert_eq!(r1.report_hash, r2.report_hash);
}

// ===========================================================================
// Schema constants
// ===========================================================================

#[test]
fn enrichment_schema_constants() {
    assert!(!DOCTOR_PREFLIGHT_SCHEMA_VERSION.is_empty());
    assert!(!DOCTOR_PREFLIGHT_BEAD_ID.is_empty());
    assert!(DOCTOR_PREFLIGHT_BEAD_ID.starts_with("bd-"));
    assert!(!DOCTOR_PREFLIGHT_POLICY_ID.is_empty());
    assert!(DOCTOR_PREFLIGHT_POLICY_ID.starts_with("RGC-"));
    assert!(!COMPONENT.is_empty());
}
