//! Integration tests for the react_doctor_preflight module.
//!
//! Tests doctor checks, preflight validation, support bundles, guidance
//! generation, readiness scoring, serde roundtrips, and cross-concern
//! interactions with the react_mismatch_catalog module.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_doctor_preflight::{
    ALL_CATEGORIES, COMPONENT, CheckCategory, CheckSeverity, DOCTOR_PREFLIGHT_BEAD_ID,
    DOCTOR_PREFLIGHT_POLICY_ID, DOCTOR_PREFLIGHT_SCHEMA_VERSION, DoctorConfig, DoctorError,
    DoctorReport, DoctorSummary, GuidanceEntry, PreflightResult, SupportBundle,
    build_support_bundle, domain_triage, filter_by_categories, generate_guidance, is_react_ready,
    readiness_score, referenced_mismatch_ids, run_doctor, run_preflight, summarize,
};
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

fn entry(id: &str, domain: MismatchDomain, severity: MismatchSeverity) -> MismatchEntry {
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
        tags: ["react", "integration"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn entry_full(
    id: &str,
    domain: MismatchDomain,
    severity: MismatchSeverity,
    target: ComparisonTarget,
    remediation: RemediationStatus,
) -> MismatchEntry {
    let mut e = entry(id, domain, severity);
    e.target = target;
    e.remediation = remediation;
    e
}

fn entry_with_version(
    id: &str,
    domain: MismatchDomain,
    severity: MismatchSeverity,
    version_range: &str,
) -> MismatchEntry {
    let mut e = entry(id, domain, severity);
    e.react_version_range = version_range.to_string();
    e
}

fn entry_stale(
    id: &str,
    domain: MismatchDomain,
    severity: MismatchSeverity,
    verified: u64,
) -> MismatchEntry {
    let mut e = entry(id, domain, severity);
    e.verified_epoch = epoch(verified);
    e
}

fn default_config() -> DoctorConfig {
    DoctorConfig::default()
}

fn config_at_epoch(ep: u64) -> DoctorConfig {
    let mut cfg = default_config();
    cfg.current_epoch = epoch(ep);
    cfg
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_versioned() {
    assert!(DOCTOR_PREFLIGHT_SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn bead_id_starts_with_bd() {
    assert!(DOCTOR_PREFLIGHT_BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_starts_with_rgc() {
    assert!(DOCTOR_PREFLIGHT_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn component_name_matches_module() {
    assert_eq!(COMPONENT, "react_doctor_preflight");
}

// ---------------------------------------------------------------------------
// CheckCategory integration
// ---------------------------------------------------------------------------

#[test]
fn all_categories_have_distinct_str() {
    let strs: BTreeSet<&str> = ALL_CATEGORIES.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), ALL_CATEGORIES.len());
}

#[test]
fn all_categories_have_positive_priority() {
    for cat in ALL_CATEGORIES {
        assert!(cat.priority_weight() > 0);
        assert!(cat.priority_weight() <= 1_000_000);
    }
}

#[test]
fn check_category_serde_roundtrip_all() {
    for cat in ALL_CATEGORIES {
        let json = serde_json::to_string(cat).unwrap();
        let back: CheckCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn check_category_btreeset_deterministic_ordering() {
    let set: BTreeSet<CheckCategory> = ALL_CATEGORIES.iter().copied().collect();
    let v1: Vec<_> = set.iter().collect();
    let v2: Vec<_> = set.iter().collect();
    assert_eq!(v1, v2);
}

// ---------------------------------------------------------------------------
// CheckSeverity integration
// ---------------------------------------------------------------------------

#[test]
fn severity_weight_pass_is_zero() {
    assert_eq!(CheckSeverity::Pass.weight(), 0);
}

#[test]
fn severity_weight_critical_is_million() {
    assert_eq!(CheckSeverity::Critical.weight(), 1_000_000);
}

#[test]
fn severity_blocking_threshold() {
    let non_blocking = [
        CheckSeverity::Pass,
        CheckSeverity::Advisory,
        CheckSeverity::Warning,
    ];
    let blocking = [CheckSeverity::Error, CheckSeverity::Critical];
    for s in non_blocking {
        assert!(!s.is_blocking(), "{s:?} should not block");
    }
    for s in blocking {
        assert!(s.is_blocking(), "{s:?} should block");
    }
}

#[test]
fn severity_serde_roundtrip_all() {
    for sev in [
        CheckSeverity::Pass,
        CheckSeverity::Advisory,
        CheckSeverity::Warning,
        CheckSeverity::Error,
        CheckSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: CheckSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// ---------------------------------------------------------------------------
// run_doctor — basic
// ---------------------------------------------------------------------------

#[test]
fn doctor_empty_entries_produces_empty_report() {
    let report = run_doctor(&default_config(), &[]).unwrap();
    assert!(report.is_empty());
    assert_eq!(report.blocking_count(), 0);
}

#[test]
fn doctor_single_info_entry_non_blocking() {
    let entries = vec![entry(
        "i-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Info,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(!report.is_empty());
    assert_eq!(report.blocking_count(), 0);
}

#[test]
fn doctor_single_critical_entry_blocking() {
    let entries = vec![entry(
        "c-1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Critical,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(report.blocking_count() > 0);
}

#[test]
fn doctor_error_entry_blocking() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(report.blocking_count() > 0);
}

#[test]
fn doctor_warning_entry_non_blocking() {
    let entries = vec![entry(
        "w-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert_eq!(report.blocking_count(), 0);
}

// ---------------------------------------------------------------------------
// run_doctor — filtering
// ---------------------------------------------------------------------------

#[test]
fn doctor_filters_resolved_entries_by_default() {
    let entries = vec![entry_full(
        "r-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(report.is_empty());
}

#[test]
fn doctor_includes_resolved_when_configured() {
    let mut cfg = default_config();
    cfg.include_resolved = true;
    let entries = vec![entry_full(
        "r-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    )];
    let report = run_doctor(&cfg, &entries).unwrap();
    assert!(!report.is_empty());
}

#[test]
fn doctor_filters_by_min_severity() {
    let mut cfg = default_config();
    cfg.min_mismatch_severity = MismatchSeverity::Error;
    let entries = vec![
        entry("i-1", MismatchDomain::Diagnostics, MismatchSeverity::Info),
        entry(
            "w-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ),
        entry("e-1", MismatchDomain::Diagnostics, MismatchSeverity::Error),
    ];
    let report = run_doctor(&cfg, &entries).unwrap();
    // Only the Error entry should produce checks
    for check in &report.checks {
        assert!(
            check.severity == CheckSeverity::Error || check.severity == CheckSeverity::Warning,
            "unexpected severity: {:?}",
            check.severity
        );
    }
}

#[test]
fn doctor_filters_by_target_focus() {
    let mut cfg = default_config();
    cfg.focus_targets.insert(ComparisonTarget::Bun);
    let entries = vec![
        entry(
            "n-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry_full(
            "b-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
            ComparisonTarget::Bun,
            RemediationStatus::None,
        ),
    ];
    let report = run_doctor(&cfg, &entries).unwrap();
    // NodeJs entry should be filtered out
    let ids = referenced_mismatch_ids(&report);
    assert!(ids.contains("b-1"));
    assert!(!ids.contains("n-1"));
}

#[test]
fn doctor_excludes_category() {
    let mut cfg = default_config();
    cfg.exclude_categories.insert(CheckCategory::JsxTransform);
    let entries = vec![entry(
        "co-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&cfg, &entries).unwrap();
    let jsx = report.checks_by_category(CheckCategory::JsxTransform);
    assert!(jsx.is_empty());
}

#[test]
fn doctor_include_category_restricts() {
    let mut cfg = default_config();
    cfg.include_categories.insert(CheckCategory::SsrConfig);
    let entries = vec![
        entry(
            "co-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "ssr-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Warning,
        ),
    ];
    let report = run_doctor(&cfg, &entries).unwrap();
    for check in &report.checks {
        assert_eq!(check.category, CheckCategory::SsrConfig);
    }
}

// ---------------------------------------------------------------------------
// run_doctor — max_checks cap
// ---------------------------------------------------------------------------

#[test]
fn doctor_respects_max_checks_limit() {
    let mut cfg = default_config();
    cfg.max_checks = 3;
    let entries: Vec<_> = (0..20)
        .map(|i| {
            entry(
                &format!("e-{i}"),
                MismatchDomain::Diagnostics,
                MismatchSeverity::Warning,
            )
        })
        .collect();
    let report = run_doctor(&cfg, &entries).unwrap();
    assert!(report.len() <= 3);
}

#[test]
fn doctor_zero_max_checks_is_error() {
    let mut cfg = default_config();
    cfg.max_checks = 0;
    assert!(matches!(
        run_doctor(&cfg, &[]),
        Err(DoctorError::InvalidConfig { .. })
    ));
}

// ---------------------------------------------------------------------------
// run_doctor — staleness
// ---------------------------------------------------------------------------

#[test]
fn doctor_detects_stale_entries() {
    let cfg = config_at_epoch(100);
    let entries = vec![entry_stale(
        "s-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        5,
    )];
    let report = run_doctor(&cfg, &entries).unwrap();
    let stale: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.check_id.contains("stale"))
        .collect();
    assert!(!stale.is_empty());
}

#[test]
fn doctor_no_stale_for_fresh_entries() {
    let cfg = config_at_epoch(5);
    let entries = vec![entry(
        "f-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&cfg, &entries).unwrap();
    let stale: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.check_id.contains("stale"))
        .collect();
    assert!(stale.is_empty());
}

// ---------------------------------------------------------------------------
// run_doctor — version compatibility checks
// ---------------------------------------------------------------------------

#[test]
fn doctor_generates_version_compat_checks() {
    let entries = vec![
        entry_with_version(
            "vc-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
            ">=17.0.0",
        ),
        entry_with_version(
            "vc-2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Error,
            ">=17.0.0",
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let vc: Vec<_> = report.checks_by_category(CheckCategory::VersionCompat);
    assert!(!vc.is_empty());
}

// ---------------------------------------------------------------------------
// run_doctor — package health checks
// ---------------------------------------------------------------------------

#[test]
fn doctor_generates_package_health_checks() {
    let entries = vec![
        entry("d-1", MismatchDomain::Diagnostics, MismatchSeverity::Error),
        entry(
            "d-2",
            MismatchDomain::ErrorBoundary,
            MismatchSeverity::Warning,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let ph: Vec<_> = report.checks_by_category(CheckCategory::PackageHealth);
    assert!(!ph.is_empty());
}

// ---------------------------------------------------------------------------
// run_doctor — multiple domains
// ---------------------------------------------------------------------------

#[test]
fn doctor_handles_all_domains() {
    let domains = [
        MismatchDomain::CompileOutput,
        MismatchDomain::Diagnostics,
        MismatchDomain::SourceMap,
        MismatchDomain::ServerSideRender,
        MismatchDomain::ClientEntry,
        MismatchDomain::ArtifactShape,
        MismatchDomain::ModuleGraph,
        MismatchDomain::HookSemantics,
        MismatchDomain::SuspenseBoundary,
        MismatchDomain::ErrorBoundary,
    ];
    let entries: Vec<_> = domains
        .iter()
        .enumerate()
        .map(|(i, &d)| entry(&format!("d-{i}"), d, MismatchSeverity::Warning))
        .collect();
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(report.len() >= 10);
}

// ---------------------------------------------------------------------------
// run_preflight
// ---------------------------------------------------------------------------

#[test]
fn preflight_passes_on_empty_input() {
    let result = run_preflight(&default_config(), &[]).unwrap();
    assert!(result.passed);
    assert_eq!(result.blocker_count(), 0);
    assert_eq!(result.advisory_count(), 0);
}

#[test]
fn preflight_passes_on_warnings() {
    let entries = vec![entry(
        "w-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let result = run_preflight(&default_config(), &entries).unwrap();
    assert!(result.passed);
    assert!(result.advisory_count() > 0);
}

#[test]
fn preflight_fails_on_error() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Error,
    )];
    let result = run_preflight(&default_config(), &entries).unwrap();
    assert!(!result.passed);
    assert!(result.blocker_count() > 0);
}

#[test]
fn preflight_fails_on_critical() {
    let entries = vec![entry(
        "c-1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Critical,
    )];
    let result = run_preflight(&default_config(), &entries).unwrap();
    assert!(!result.passed);
}

#[test]
fn preflight_entries_analyzed_matches_input() {
    let entries = vec![
        entry("e-1", MismatchDomain::CompileOutput, MismatchSeverity::Info),
        entry(
            "e-2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-3",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let result = run_preflight(&default_config(), &entries).unwrap();
    assert_eq!(result.entries_analyzed, 3);
}

#[test]
fn preflight_total_findings_is_sum() {
    let entries = vec![
        entry(
            "w-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let result = run_preflight(&default_config(), &entries).unwrap();
    assert_eq!(
        result.total_findings(),
        result.blocker_count() + result.advisory_count()
    );
}

#[test]
fn preflight_result_has_hash() {
    let result = run_preflight(&default_config(), &[]).unwrap();
    // Hash should be non-trivial
    assert_ne!(result.result_hash, ContentHash::compute(b""));
}

// ---------------------------------------------------------------------------
// build_support_bundle
// ---------------------------------------------------------------------------

#[test]
fn support_bundle_empty_report() {
    let report = DoctorReport::new(epoch(1));
    let bundle = build_support_bundle(&report).unwrap();
    assert!(bundle.is_empty());
    assert_eq!(bundle.schema_version, DOCTOR_PREFLIGHT_SCHEMA_VERSION);
}

#[test]
fn support_bundle_includes_doctor_checks() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    let dc = bundle.entries_by_category("doctor_checks");
    assert!(!dc.is_empty());
}

#[test]
fn support_bundle_includes_severity_breakdown() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    let sev = bundle.entries_by_category("severity_breakdown");
    assert!(!sev.is_empty());
}

#[test]
fn support_bundle_includes_category_breakdown() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    let cat = bundle.entries_by_category("category_breakdown");
    assert!(!cat.is_empty());
}

#[test]
fn support_bundle_includes_guidance() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    let g = bundle.entries_by_category("guidance");
    assert!(!g.is_empty());
}

#[test]
fn support_bundle_hash_deterministic() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    )];
    let r1 = run_doctor(&default_config(), &entries).unwrap();
    let r2 = run_doctor(&default_config(), &entries).unwrap();
    let b1 = build_support_bundle(&r1).unwrap();
    let b2 = build_support_bundle(&r2).unwrap();
    assert_eq!(b1.bundle_hash, b2.bundle_hash);
}

// ---------------------------------------------------------------------------
// generate_guidance
// ---------------------------------------------------------------------------

#[test]
fn guidance_empty_report_empty_result() {
    let report = DoctorReport::new(epoch(1));
    let guidance = generate_guidance(&report).unwrap();
    assert!(guidance.is_empty());
}

#[test]
fn guidance_consolidates_same_category() {
    let entries = vec![
        entry(
            "co-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "co-2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    let jsx: Vec<_> = guidance
        .iter()
        .filter(|g| g.category == CheckCategory::JsxTransform)
        .collect();
    // Should be exactly one consolidated entry
    assert_eq!(jsx.len(), 1);
}

#[test]
fn guidance_sorted_by_priority_ascending() {
    let entries = vec![
        entry(
            "w-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "c-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Critical,
        ),
        entry("i-1", MismatchDomain::ModuleGraph, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    for window in guidance.windows(2) {
        assert!(
            window[0].priority <= window[1].priority,
            "guidance not sorted: {} > {}",
            window[0].priority,
            window[1].priority
        );
    }
}

#[test]
fn guidance_critical_has_priority_1() {
    let entries = vec![entry(
        "c-1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Critical,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    assert!(!guidance.is_empty());
    let crit: Vec<_> = guidance
        .iter()
        .filter(|g| g.severity == CheckSeverity::Critical)
        .collect();
    if !crit.is_empty() {
        assert_eq!(crit[0].priority, 1);
    }
}

#[test]
fn guidance_has_nonempty_steps() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::ServerSideRender,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    for g in &guidance {
        assert!(
            !g.steps.is_empty(),
            "guidance {} has no steps",
            g.guidance_id
        );
    }
}

#[test]
fn guidance_content_hash_stable() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let r1 = run_doctor(&default_config(), &entries).unwrap();
    let r2 = run_doctor(&default_config(), &entries).unwrap();
    let g1 = generate_guidance(&r1).unwrap();
    let g2 = generate_guidance(&r2).unwrap();
    assert_eq!(g1.len(), g2.len());
    for (a, b) in g1.iter().zip(g2.iter()) {
        assert_eq!(a.content_hash(), b.content_hash());
    }
}

// ---------------------------------------------------------------------------
// is_react_ready
// ---------------------------------------------------------------------------

#[test]
fn is_ready_empty_report() {
    let report = DoctorReport::new(epoch(1));
    assert!(is_react_ready(&report));
}

#[test]
fn is_ready_with_warnings_only() {
    let entries = vec![entry(
        "w-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(is_react_ready(&report));
}

#[test]
fn not_ready_with_errors() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(!is_react_ready(&report));
}

#[test]
fn not_ready_with_critical() {
    let entries = vec![entry(
        "c-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Critical,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(!is_react_ready(&report));
}

// ---------------------------------------------------------------------------
// summarize
// ---------------------------------------------------------------------------

#[test]
fn summarize_empty_report_all_zeros() {
    let report = DoctorReport::new(epoch(1));
    let s = summarize(&report);
    assert_eq!(s.total_checks, 0);
    assert_eq!(s.pass_count, 0);
    assert_eq!(s.advisory_count, 0);
    assert_eq!(s.warning_count, 0);
    assert_eq!(s.error_count, 0);
    assert_eq!(s.critical_count, 0);
    assert!(s.is_ready);
    assert_eq!(s.aggregate_score, 0);
}

#[test]
fn summarize_counts_sum_to_total() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
        entry("e-3", MismatchDomain::Diagnostics, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let s = summarize(&report);
    assert_eq!(
        s.total_checks,
        s.pass_count + s.advisory_count + s.warning_count + s.error_count + s.critical_count
    );
}

#[test]
fn summarize_is_ready_matches_is_react_ready() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::ModuleGraph,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let s = summarize(&report);
    assert_eq!(s.is_ready, is_react_ready(&report));
}

#[test]
fn summarize_by_category_populated() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let s = summarize(&report);
    assert!(!s.by_category.is_empty());
}

// ---------------------------------------------------------------------------
// readiness_score
// ---------------------------------------------------------------------------

#[test]
fn readiness_score_max_for_empty() {
    let report = DoctorReport::new(epoch(1));
    assert_eq!(readiness_score(&report), 1_000_000);
}

#[test]
fn readiness_score_decreases_with_severity() {
    let light = vec![entry(
        "i-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
    )];
    let heavy = vec![
        entry(
            "c-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Critical,
        ),
        entry(
            "c-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Critical,
        ),
    ];
    let r_light = run_doctor(&default_config(), &light).unwrap();
    let r_heavy = run_doctor(&default_config(), &heavy).unwrap();
    assert!(readiness_score(&r_light) > readiness_score(&r_heavy));
}

#[test]
fn readiness_score_nonzero_with_issues() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let score = readiness_score(&report);
    assert!(score > 0);
    assert!(score < 1_000_000);
}

// ---------------------------------------------------------------------------
// referenced_mismatch_ids
// ---------------------------------------------------------------------------

#[test]
fn referenced_ids_empty_report() {
    let report = DoctorReport::new(epoch(1));
    assert!(referenced_mismatch_ids(&report).is_empty());
}

#[test]
fn referenced_ids_collects_all_entries() {
    let entries = vec![
        entry(
            "m-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry("m-2", MismatchDomain::Diagnostics, MismatchSeverity::Error),
        entry("m-3", MismatchDomain::HookSemantics, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let ids = referenced_mismatch_ids(&report);
    assert!(ids.contains("m-1"));
    assert!(ids.contains("m-2"));
    assert!(ids.contains("m-3"));
}

// ---------------------------------------------------------------------------
// filter_by_categories
// ---------------------------------------------------------------------------

#[test]
fn filter_by_categories_restricts_output() {
    let entries = vec![
        entry(
            "co-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "hs-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
        entry("mg-1", MismatchDomain::ModuleGraph, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let cats: BTreeSet<_> = [CheckCategory::HookOrdering].into_iter().collect();
    let filtered = filter_by_categories(&report, &cats);
    for c in &filtered {
        assert_eq!(c.category, CheckCategory::HookOrdering);
    }
}

#[test]
fn filter_by_categories_empty_set_returns_nothing() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let cats: BTreeSet<CheckCategory> = BTreeSet::new();
    let filtered = filter_by_categories(&report, &cats);
    assert!(filtered.is_empty());
}

// ---------------------------------------------------------------------------
// domain_triage
// ---------------------------------------------------------------------------

#[test]
fn domain_triage_empty_input() {
    assert!(domain_triage(&[]).is_empty());
}

#[test]
fn domain_triage_counts_open_entries() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ),
        entry_full(
            "e-3",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ),
    ];
    let triage = domain_triage(&entries);
    assert_eq!(triage.get("compile_output"), Some(&2));
}

#[test]
fn domain_triage_multiple_domains() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let triage = domain_triage(&entries);
    assert_eq!(triage.len(), 2);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_doctor_report() {
    let entries = vec![
        entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
        entry(
            "e-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: DoctorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.len(), back.len());
    assert_eq!(report.report_hash, back.report_hash);
}

#[test]
fn serde_roundtrip_preflight_result() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::HookSemantics,
        MismatchSeverity::Error,
    )];
    let result = run_preflight(&default_config(), &entries).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: PreflightResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.passed, back.passed);
    assert_eq!(result.blocker_count(), back.blocker_count());
}

#[test]
fn serde_roundtrip_support_bundle() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let bundle = build_support_bundle(&report).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: SupportBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.len(), back.len());
    assert_eq!(bundle.bundle_hash, back.bundle_hash);
}

#[test]
fn serde_roundtrip_guidance_entry() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let guidance = generate_guidance(&report).unwrap();
    for g in &guidance {
        let json = serde_json::to_string(g).unwrap();
        let back: GuidanceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(g.guidance_id, back.guidance_id);
        assert_eq!(g.priority, back.priority);
    }
}

#[test]
fn serde_roundtrip_doctor_config() {
    let mut cfg = default_config();
    cfg.include_categories.insert(CheckCategory::SsrConfig);
    cfg.focus_targets.insert(ComparisonTarget::Bun);
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DoctorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn serde_roundtrip_doctor_error() {
    let errors = vec![
        DoctorError::EmptyInput,
        DoctorError::CheckCapacityExceeded {
            current: 100,
            max: 50,
        },
        DoctorError::GuidanceTooLong {
            guidance_id: "gd-1".to_string(),
            len: 9999,
        },
        DoctorError::BundleTooLarge {
            current: 6000,
            max: 5000,
        },
        DoctorError::InvalidConfig {
            reason: "bad".to_string(),
        },
        DoctorError::StaleData {
            entry_id: "s-1".to_string(),
            epoch_gap: 42,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: DoctorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn serde_roundtrip_doctor_summary() {
    let entries = vec![entry(
        "e-1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    )];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let summary = summarize(&report);
    let json = serde_json::to_string(&summary).unwrap();
    let back: DoctorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.total_checks, back.total_checks);
    assert_eq!(summary.is_ready, back.is_ready);
}

// ---------------------------------------------------------------------------
// Cross-concern: mismatch catalog -> doctor -> preflight -> bundle pipeline
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_clean_entries() {
    let entries = vec![
        entry("p-1", MismatchDomain::CompileOutput, MismatchSeverity::Info),
        entry("p-2", MismatchDomain::Diagnostics, MismatchSeverity::Info),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(is_react_ready(&report));

    let preflight = run_preflight(&default_config(), &entries).unwrap();
    assert!(preflight.passed);

    let bundle = build_support_bundle(&report).unwrap();
    assert!(!bundle.is_empty());

    let summary = summarize(&report);
    assert!(summary.is_ready);
}

#[test]
fn full_pipeline_with_blockers() {
    let entries = vec![
        entry(
            "p-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Critical,
        ),
        entry(
            "p-2",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        ),
        entry(
            "p-3",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    assert!(!is_react_ready(&report));

    let preflight = run_preflight(&default_config(), &entries).unwrap();
    assert!(!preflight.passed);
    assert!(preflight.blocker_count() >= 2);

    let guidance = generate_guidance(&report).unwrap();
    assert!(!guidance.is_empty());
    // First guidance should be highest priority (critical)
    assert_eq!(guidance[0].priority, 1);

    let bundle = build_support_bundle(&report).unwrap();
    assert!(!bundle.guidance.is_empty());

    let summary = summarize(&report);
    assert!(!summary.is_ready);
    assert!(summary.critical_count > 0);
    assert!(summary.error_count > 0);
}

#[test]
fn full_pipeline_with_mixed_targets() {
    let entries = vec![
        entry_full(
            "n-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ),
        entry_full(
            "b-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::Bun,
            RemediationStatus::None,
        ),
        entry_full(
            "d-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Warning,
            ComparisonTarget::Deno,
            RemediationStatus::None,
        ),
    ];
    let report = run_doctor(&default_config(), &entries).unwrap();
    let ids = referenced_mismatch_ids(&report);
    assert!(ids.contains("n-1"));
    assert!(ids.contains("b-1"));
    assert!(ids.contains("d-1"));
}
