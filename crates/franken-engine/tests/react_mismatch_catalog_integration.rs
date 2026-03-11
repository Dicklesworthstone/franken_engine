//! Integration tests for the react_mismatch_catalog module.
//!
//! Tests catalog construction, gate evaluation, advisory generation,
//! serde roundtrips, and cross-concern interactions.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_mismatch_catalog::{
    ALL_DOMAINS, COMPONENT, CatalogConfig, CatalogError, CatalogReport, ComparisonTarget,
    DomainSummary, GateVerdict, MISMATCH_CATALOG_BEAD_ID, MISMATCH_CATALOG_POLICY_ID,
    MISMATCH_CATALOG_SCHEMA_VERSION, MismatchAdvisory, MismatchCatalog, MismatchDomain,
    MismatchEntry, MismatchSeverity, RemediationStatus, TargetSummary, all_tags, domain_coverage,
    filter_entry_ids, generate_advisories, resolution_ratio,
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

fn full_domain_catalog() -> MismatchCatalog {
    let mut cat = MismatchCatalog::new(epoch(1));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i.is_multiple_of(2) {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        cat.add_entry(entry_full(
            &format!("full-{i}"),
            domain,
            MismatchSeverity::Info,
            target,
            RemediationStatus::Resolved,
        ))
        .unwrap();
    }
    cat
}

// ---------------------------------------------------------------------------
// Schema and constant tests
// ---------------------------------------------------------------------------

#[test]
fn schema_version_not_empty() {
    assert!(!MISMATCH_CATALOG_SCHEMA_VERSION.is_empty());
}

#[test]
fn bead_id_matches() {
    assert_eq!(MISMATCH_CATALOG_BEAD_ID, "bd-1lsy.9.7.3");
}

#[test]
fn policy_id_matches() {
    assert_eq!(MISMATCH_CATALOG_POLICY_ID, "RGC-807C");
}

#[test]
fn component_name_matches() {
    assert_eq!(COMPONENT, "react_mismatch_catalog");
}

#[test]
fn all_domains_has_ten_variants() {
    assert_eq!(ALL_DOMAINS.len(), 10);
}

// ---------------------------------------------------------------------------
// Domain tests
// ---------------------------------------------------------------------------

#[test]
fn domain_as_str_roundtrip() {
    for &d in ALL_DOMAINS {
        let s = d.as_str();
        assert!(!s.is_empty());
        assert_eq!(format!("{d}"), s);
    }
}

#[test]
fn domain_ordering_is_deterministic() {
    let mut sorted = ALL_DOMAINS.to_vec();
    sorted.sort();
    // Ordering should follow enum discriminant order.
    assert_eq!(sorted[0], MismatchDomain::CompileOutput);
}

// ---------------------------------------------------------------------------
// Severity tests
// ---------------------------------------------------------------------------

#[test]
fn severity_weights_increase() {
    assert!(MismatchSeverity::Info.weight() < MismatchSeverity::Warning.weight());
    assert!(MismatchSeverity::Warning.weight() < MismatchSeverity::Error.weight());
    assert!(MismatchSeverity::Error.weight() < MismatchSeverity::Critical.weight());
}

#[test]
fn severity_critical_is_one_million() {
    assert_eq!(MismatchSeverity::Critical.weight(), 1_000_000);
}

// ---------------------------------------------------------------------------
// RemediationStatus tests
// ---------------------------------------------------------------------------

#[test]
fn remediation_open_vs_closed() {
    let open = [
        RemediationStatus::None,
        RemediationStatus::Workaround,
        RemediationStatus::InProgress,
        RemediationStatus::Shipped,
    ];
    let closed = [RemediationStatus::Resolved, RemediationStatus::Accepted];
    for s in open {
        assert!(s.is_open(), "{} should be open", s);
    }
    for s in closed {
        assert!(!s.is_open(), "{} should be closed", s);
    }
}

// ---------------------------------------------------------------------------
// ComparisonTarget tests
// ---------------------------------------------------------------------------

#[test]
fn target_as_str_not_empty() {
    for t in [
        ComparisonTarget::NodeJs,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::V8Reference,
    ] {
        assert!(!t.as_str().is_empty());
        assert_eq!(format!("{t}"), t.as_str());
    }
}

// ---------------------------------------------------------------------------
// Entry tests
// ---------------------------------------------------------------------------

#[test]
fn entry_content_hash_is_deterministic() {
    let e1 = entry("x1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let e2 = entry("x1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn entry_content_hash_varies_by_id() {
    let e1 = entry("a", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let e2 = entry("b", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn entry_content_hash_varies_by_domain() {
    let e1 = entry("x", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let e2 = entry("x", MismatchDomain::Diagnostics, MismatchSeverity::Error);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn entry_is_open_reflects_remediation() {
    let e = entry("x", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert!(e.is_open());

    let e2 = entry_full(
        "y",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    );
    assert!(!e2.is_open());
}

// ---------------------------------------------------------------------------
// Catalog creation and CRUD
// ---------------------------------------------------------------------------

#[test]
fn empty_catalog_properties() {
    let cat = MismatchCatalog::new(epoch(5));
    assert!(cat.is_empty());
    assert_eq!(cat.len(), 0);
    assert_eq!(cat.open_count(), 0);
    assert_eq!(cat.epoch, epoch(5));
    assert_eq!(cat.schema_version, MISMATCH_CATALOG_SCHEMA_VERSION);
}

#[test]
fn add_and_retrieve_entry() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    assert_eq!(cat.len(), 1);
    let got = cat.get_entry("e1").unwrap();
    assert_eq!(got.entry_id, "e1");
}

#[test]
fn duplicate_entry_rejected() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let err = cat
        .add_entry(entry(
            "e1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Info,
        ))
        .unwrap_err();
    assert!(matches!(err, CatalogError::DuplicateEntry { .. }));
}

#[test]
fn advisory_too_long_rejected() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.advisory = "x".repeat(5000);
    let err = cat.add_entry(e).unwrap_err();
    assert!(matches!(err, CatalogError::AdvisoryTooLong { .. }));
}

#[test]
fn invalid_epoch_rejected() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.detected_epoch = epoch(10);
    e.verified_epoch = epoch(5);
    let err = cat.add_entry(e).unwrap_err();
    assert!(matches!(err, CatalogError::InvalidEpoch { .. }));
}

#[test]
fn remove_entry_succeeds() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let removed = cat.remove_entry("e1").unwrap();
    assert_eq!(removed.entry_id, "e1");
    assert!(cat.is_empty());
}

#[test]
fn remove_nonexistent_entry_fails() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let err = cat.remove_entry("nope").unwrap_err();
    assert!(matches!(err, CatalogError::EntryNotFound { .. }));
}

#[test]
fn update_remediation_changes_status() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    assert_eq!(cat.open_count(), 1);
    cat.update_remediation("e1", RemediationStatus::Resolved)
        .unwrap();
    assert_eq!(cat.open_count(), 0);
}

#[test]
fn update_remediation_nonexistent_fails() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let err = cat
        .update_remediation("nope", RemediationStatus::Resolved)
        .unwrap_err();
    assert!(matches!(err, CatalogError::EntryNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Aggregation queries
// ---------------------------------------------------------------------------

#[test]
fn count_by_severity_correct() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e3",
        MismatchDomain::SourceMap,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(cat.count_by_severity(MismatchSeverity::Error), 2);
    assert_eq!(cat.count_by_severity(MismatchSeverity::Warning), 1);
    assert_eq!(cat.count_by_severity(MismatchSeverity::Critical), 0);
}

#[test]
fn aggregate_open_score_sums_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(cat.aggregate_open_score(), 1_000_000);
}

#[test]
fn aggregate_score_excludes_resolved() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(cat.aggregate_open_score(), 300_000);
}

#[test]
fn covered_domains_tracks_entries() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::SourceMap,
        MismatchSeverity::Info,
    ))
    .unwrap();
    let covered = cat.covered_domains();
    assert_eq!(covered.len(), 2);
    assert!(covered.contains(&MismatchDomain::CompileOutput));
    assert!(covered.contains(&MismatchDomain::SourceMap));
}

#[test]
fn covered_targets_tracks_entries() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(entry_full(
        "e2",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
        ComparisonTarget::Bun,
        RemediationStatus::None,
    ))
    .unwrap();
    assert_eq!(cat.covered_targets().len(), 2);
}

// ---------------------------------------------------------------------------
// Filter queries
// ---------------------------------------------------------------------------

#[test]
fn entries_by_domain_filters_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e3",
        MismatchDomain::SourceMap,
        MismatchSeverity::Info,
    ))
    .unwrap();
    assert_eq!(
        cat.entries_by_domain(MismatchDomain::CompileOutput).len(),
        2
    );
    assert_eq!(cat.entries_by_domain(MismatchDomain::SourceMap).len(), 1);
    assert_eq!(
        cat.entries_by_domain(MismatchDomain::HookSemantics).len(),
        0
    );
}

#[test]
fn entries_by_target_filters_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(entry_full(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::Bun,
        RemediationStatus::None,
    ))
    .unwrap();
    assert_eq!(cat.entries_by_target(ComparisonTarget::NodeJs).len(), 1);
    assert_eq!(cat.entries_by_target(ComparisonTarget::Bun).len(), 1);
    assert_eq!(cat.entries_by_target(ComparisonTarget::Deno).len(), 0);
}

#[test]
fn entries_by_severity_filters_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e3",
        MismatchDomain::SourceMap,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(cat.entries_by_severity(MismatchSeverity::Error).len(), 2);
    assert_eq!(cat.entries_by_severity(MismatchSeverity::Warning).len(), 1);
}

#[test]
fn entries_by_tag_filters_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.tags.insert("ssr".to_string());
    cat.add_entry(e).unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(cat.entries_by_tag("ssr").len(), 1);
    assert_eq!(cat.entries_by_tag("react").len(), 2);
    assert_eq!(cat.entries_by_tag("nonexistent").len(), 0);
}

// ---------------------------------------------------------------------------
// Domain summary
// ---------------------------------------------------------------------------

#[test]
fn domain_summary_covers_all_domains() {
    let cat = MismatchCatalog::new(epoch(1));
    let summaries = cat.domain_summary();
    assert_eq!(summaries.len(), ALL_DOMAINS.len());
}

#[test]
fn domain_summary_counts_correct() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry_full(
        "e2",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    let summaries = cat.domain_summary();
    let co = summaries
        .iter()
        .find(|s| s.domain == MismatchDomain::CompileOutput)
        .unwrap();
    assert_eq!(co.total_entries, 2);
    assert_eq!(co.open_entries, 1);
    assert_eq!(co.resolved_entries, 1);
    assert_eq!(co.aggregate_score, 700_000);
}

// ---------------------------------------------------------------------------
// Target summary
// ---------------------------------------------------------------------------

#[test]
fn target_summary_empty_catalog() {
    let cat = MismatchCatalog::new(epoch(1));
    assert!(cat.target_summary().is_empty());
}

#[test]
fn target_summary_counts_correct() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(entry_full(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    let summaries = cat.target_summary();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].total_entries, 2);
    assert_eq!(summaries[0].aggregate_score, 1_000_000);
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_pass_with_all_domains_resolved() {
    let cat = full_domain_catalog();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(verdict.is_pass(), "verdict: {verdict}");
}

#[test]
fn gate_incomplete_missing_domains() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
    ))
    .unwrap();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(matches!(verdict, GateVerdict::Incomplete { .. }));
}

#[test]
fn gate_fail_open_critical() {
    let mut cat = full_domain_catalog();
    cat.add_entry(entry_full(
        "crit1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Critical,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(matches!(verdict, GateVerdict::Fail { .. }));
}

#[test]
fn gate_fail_too_many_errors() {
    let mut cat = full_domain_catalog();
    for i in 0..10 {
        cat.add_entry(entry_full(
            &format!("err-{i}"),
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
    }
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(matches!(verdict, GateVerdict::Fail { .. }));
}

#[test]
fn gate_fail_aggregate_score() {
    let mut cat = full_domain_catalog();
    for i in 0..10 {
        cat.add_entry(entry_full(
            &format!("heavy-{i}"),
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
    }
    let mut config = CatalogConfig::default();
    config.max_open_errors = 100;
    let verdict = cat.evaluate(&config);
    assert!(matches!(verdict, GateVerdict::Fail { .. }));
}

#[test]
fn gate_fail_stale_entries() {
    let mut cat = MismatchCatalog::new(epoch(10));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i.is_multiple_of(2) {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        let mut e = entry_full(
            &format!("stale-{i}"),
            domain,
            MismatchSeverity::Info,
            target,
            RemediationStatus::None,
        );
        e.verified_epoch = epoch(3);
        e.detected_epoch = epoch(1);
        cat.add_entry(e).unwrap();
    }
    let mut config = CatalogConfig::default();
    config.min_verification_epoch = epoch(5);
    let verdict = cat.evaluate(&config);
    if let GateVerdict::Fail { reasons } = &verdict {
        assert!(reasons.iter().any(|r| r.contains("stale")));
    } else {
        panic!("expected fail, got {verdict}");
    }
}

#[test]
fn gate_verdict_display_pass() {
    assert_eq!(format!("{}", GateVerdict::Pass), "PASS");
}

#[test]
fn gate_verdict_display_fail() {
    let v = GateVerdict::Fail {
        reasons: vec!["reason1".to_string()],
    };
    let s = format!("{v}");
    assert!(s.starts_with("FAIL:"));
    assert!(s.contains("reason1"));
}

#[test]
fn gate_verdict_display_incomplete() {
    let v = GateVerdict::Incomplete {
        missing_domains: vec![MismatchDomain::SourceMap],
        missing_targets: vec![ComparisonTarget::Deno],
    };
    let s = format!("{v}");
    assert!(s.contains("INCOMPLETE"));
    assert!(s.contains("source_map"));
    assert!(s.contains("deno"));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[test]
fn report_reflects_catalog_state() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    let report = cat.report();
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.open_entries, 2);
    assert_eq!(report.error_count, 1);
    assert_eq!(report.warning_count, 1);
    assert_eq!(report.aggregate_open_score, 1_000_000);
    assert_eq!(report.domains_covered, 2);
    assert_eq!(report.targets_covered, 1);
}

#[test]
fn report_hash_matches_catalog() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let report = cat.report();
    assert_eq!(report.catalog_hash, cat.catalog_hash);
}

// ---------------------------------------------------------------------------
// Advisory generation
// ---------------------------------------------------------------------------

#[test]
fn advisories_grouped_by_domain() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e3",
        MismatchDomain::SourceMap,
        MismatchSeverity::Info,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    assert_eq!(advisories.len(), 2);
}

#[test]
fn advisory_max_severity_correct() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    let co = advisories
        .iter()
        .find(|a| a.domains.contains(&MismatchDomain::CompileOutput))
        .unwrap();
    assert_eq!(co.max_severity, MismatchSeverity::Error);
}

#[test]
fn advisories_skip_resolved_domains() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    assert!(advisories.is_empty());
}

#[test]
fn advisory_has_adv_id_format() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    assert!(advisories[0].advisory_id.starts_with("ADV-"));
}

#[test]
fn advisory_entry_ids_match() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    assert!(advisories[0].entry_ids.contains(&"e1".to_string()));
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

#[test]
fn domain_coverage_partial() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Info,
    ))
    .unwrap();
    assert_eq!(domain_coverage(&cat), 100_000);
}

#[test]
fn domain_coverage_full() {
    let cat = full_domain_catalog();
    assert_eq!(domain_coverage(&cat), 1_000_000);
}

#[test]
fn domain_coverage_empty() {
    let cat = MismatchCatalog::new(epoch(1));
    assert_eq!(domain_coverage(&cat), 0);
}

#[test]
fn resolution_ratio_empty() {
    let cat = MismatchCatalog::new(epoch(1));
    assert_eq!(resolution_ratio(&cat), 1_000_000);
}

#[test]
fn resolution_ratio_half() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry_full(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    assert_eq!(resolution_ratio(&cat), 500_000);
}

#[test]
fn resolution_ratio_all_resolved() {
    let cat = full_domain_catalog();
    assert_eq!(resolution_ratio(&cat), 1_000_000);
}

#[test]
fn all_tags_collects_from_entries() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e1 = entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e1.tags.insert("ssr".to_string());
    cat.add_entry(e1).unwrap();
    let tags = all_tags(&cat);
    assert!(tags.contains("react"));
    assert!(tags.contains("integration"));
    assert!(tags.contains("ssr"));
}

#[test]
fn filter_entry_ids_works() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    cat.add_entry(entry(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
    ))
    .unwrap();
    let errors = filter_entry_ids(&cat, |e| e.severity == MismatchSeverity::Error);
    assert_eq!(errors, vec!["e1"]);
}

// ---------------------------------------------------------------------------
// Catalog hash integrity
// ---------------------------------------------------------------------------

#[test]
fn catalog_hash_changes_on_add() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let h0 = cat.catalog_hash.clone();
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    assert_ne!(cat.catalog_hash, h0);
}

#[test]
fn catalog_hash_changes_on_remove() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let h1 = cat.catalog_hash.clone();
    cat.remove_entry("e1").unwrap();
    assert_ne!(cat.catalog_hash, h1);
}

#[test]
fn catalog_hash_changes_on_remediation_update() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let h1 = cat.catalog_hash.clone();
    cat.update_remediation("e1", RemediationStatus::Resolved)
        .unwrap();
    assert_ne!(cat.catalog_hash, h1);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_entry() {
    let e = entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let json = serde_json::to_string(&e).unwrap();
    let parsed: MismatchEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, parsed);
}

#[test]
fn serde_roundtrip_catalog() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let json = serde_json::to_string(&cat).unwrap();
    let parsed: MismatchCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, parsed);
}

#[test]
fn serde_roundtrip_config() {
    let config = CatalogConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let parsed: CatalogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn serde_roundtrip_verdict() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail {
            reasons: vec!["test".to_string()],
        },
        GateVerdict::Incomplete {
            missing_domains: vec![MismatchDomain::SourceMap],
            missing_targets: vec![ComparisonTarget::Deno],
        },
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }
}

#[test]
fn serde_roundtrip_report() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let report = cat.report();
    let json = serde_json::to_string(&report).unwrap();
    let parsed: CatalogReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);
}

#[test]
fn serde_roundtrip_advisory() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let advisories = generate_advisories(&cat);
    let json = serde_json::to_string(&advisories[0]).unwrap();
    let parsed: MismatchAdvisory = serde_json::from_str(&json).unwrap();
    assert_eq!(advisories[0], parsed);
}

#[test]
fn serde_roundtrip_domain_summary() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let summaries = cat.domain_summary();
    let json = serde_json::to_string(&summaries).unwrap();
    let parsed: Vec<DomainSummary> = serde_json::from_str(&json).unwrap();
    assert_eq!(summaries, parsed);
}

#[test]
fn serde_roundtrip_target_summary() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(entry(
        "e1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
    ))
    .unwrap();
    let summaries = cat.target_summary();
    let json = serde_json::to_string(&summaries).unwrap();
    let parsed: Vec<TargetSummary> = serde_json::from_str(&json).unwrap();
    assert_eq!(summaries, parsed);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn catalog_error_display_capacity() {
    let e = CatalogError::CapacityExceeded {
        current: 10000,
        max: 10000,
    };
    let s = format!("{e}");
    assert!(s.contains("capacity exceeded"));
}

#[test]
fn catalog_error_display_duplicate() {
    let e = CatalogError::DuplicateEntry {
        entry_id: "dup".to_string(),
    };
    assert!(format!("{e}").contains("duplicate"));
}

#[test]
fn catalog_error_display_advisory_too_long() {
    let e = CatalogError::AdvisoryTooLong {
        entry_id: "x".to_string(),
        len: 5000,
    };
    assert!(format!("{e}").contains("too long"));
}

#[test]
fn catalog_error_display_not_found() {
    let e = CatalogError::EntryNotFound {
        entry_id: "missing".to_string(),
    };
    assert!(format!("{e}").contains("not found"));
}

#[test]
fn catalog_error_display_invalid_epoch() {
    let e = CatalogError::InvalidEpoch {
        entry_id: "x".to_string(),
        reason: "bad".to_string(),
    };
    assert!(format!("{e}").contains("invalid epoch"));
}

// ---------------------------------------------------------------------------
// Cross-concern integration
// ---------------------------------------------------------------------------

#[test]
fn full_workflow_add_evaluate_remediate_pass() {
    let mut cat = MismatchCatalog::new(epoch(5));

    // Add entries for all domains.
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i.is_multiple_of(2) {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        cat.add_entry(entry_full(
            &format!("wf-{i}"),
            domain,
            MismatchSeverity::Error,
            target,
            RemediationStatus::None,
        ))
        .unwrap();
    }

    // Gate should fail initially.
    let config = CatalogConfig::default();
    let v1 = cat.evaluate(&config);
    assert!(!v1.is_pass());

    // Resolve all entries.
    for i in 0..ALL_DOMAINS.len() {
        cat.update_remediation(&format!("wf-{i}"), RemediationStatus::Resolved)
            .unwrap();
    }

    // Gate should pass now.
    let v2 = cat.evaluate(&config);
    assert!(v2.is_pass(), "verdict: {v2}");

    // Report should reflect resolution.
    let report = cat.report();
    assert_eq!(report.open_entries, 0);
    assert_eq!(report.aggregate_open_score, 0);
}

#[test]
fn mixed_targets_coverage() {
    let mut cat = MismatchCatalog::new(epoch(1));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        // Alternate between NodeJs, Bun, Deno, V8Reference.
        let targets = [
            ComparisonTarget::NodeJs,
            ComparisonTarget::Bun,
            ComparisonTarget::Deno,
            ComparisonTarget::V8Reference,
        ];
        cat.add_entry(entry_full(
            &format!("mix-{i}"),
            domain,
            MismatchSeverity::Info,
            targets[i % 4],
            RemediationStatus::Resolved,
        ))
        .unwrap();
    }
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    // Should pass because all domains covered and required targets present.
    assert!(verdict.is_pass(), "verdict: {verdict}");
}
