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

//! Second enrichment integration tests for the `react_mismatch_catalog` module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_mismatch_catalog::*;
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
        reproduction: "test case".to_string(),
        remediation: RemediationStatus::None,
        advisory: "advisory".to_string(),
        react_version_range: ">=18.0.0".to_string(),
        evidence_hash: ContentHash::compute(id.as_bytes()),
        detected_epoch: epoch(1),
        verified_epoch: epoch(2),
        tags: ["react", "batch2"].iter().map(|s| s.to_string()).collect(),
    }
}

fn make_entry_with_target(
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

fn build_full_catalog() -> MismatchCatalog {
    let mut cat = MismatchCatalog::new(epoch(10));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i % 2 == 0 {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        cat.add_entry(make_entry_with_target(
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
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_entries_accessor_returns_slice() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("e2", MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .unwrap();
    let entries = cat.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].entry_id, "e1");
    assert_eq!(entries[1].entry_id, "e2");
}

#[test]
fn enrichment_catalog_get_entry_by_id() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("lookup", MismatchDomain::SourceMap, MismatchSeverity::Info))
        .unwrap();
    assert!(cat.get_entry("lookup").is_some());
    assert!(cat.get_entry("nonexistent").is_none());
}

#[test]
fn enrichment_catalog_entries_by_tag_multi_tag() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = make_entry("tagged", MismatchDomain::CompileOutput, MismatchSeverity::Warning);
    e.tags.insert("hydration".to_string());
    cat.add_entry(e).unwrap();

    assert_eq!(cat.entries_by_tag("react").len(), 1);
    assert_eq!(cat.entries_by_tag("hydration").len(), 1);
    assert_eq!(cat.entries_by_tag("nonexistent").len(), 0);
}

#[test]
fn enrichment_catalog_domain_summary_for_empty() {
    let cat = MismatchCatalog::new(epoch(1));
    let summaries = cat.domain_summary();
    assert_eq!(summaries.len(), ALL_DOMAINS.len());
    for s in &summaries {
        assert_eq!(s.total_entries, 0);
        assert_eq!(s.open_entries, 0);
        assert_eq!(s.resolved_entries, 0);
        assert_eq!(s.aggregate_score, 0);
    }
}

#[test]
fn enrichment_catalog_target_summary_multiple_targets() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_with_target(
        "t1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "t2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::Bun,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "t3",
        MismatchDomain::SourceMap,
        MismatchSeverity::Info,
        ComparisonTarget::Deno,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    let summaries = cat.target_summary();
    assert_eq!(summaries.len(), 3);
}

#[test]
fn enrichment_catalog_open_count_excludes_resolved_and_accepted() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_with_target(
        "open1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "resolved1",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "accepted1",
        MismatchDomain::SourceMap,
        MismatchSeverity::Warning,
        ComparisonTarget::NodeJs,
        RemediationStatus::Accepted,
    ))
    .unwrap();
    assert_eq!(cat.open_count(), 1);
    assert_eq!(cat.len(), 3);
}

#[test]
fn enrichment_catalog_open_count_by_severity_filters_correctly() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_with_target(
        "c1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Critical,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "c2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Critical,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    assert_eq!(cat.count_by_severity(MismatchSeverity::Critical), 2);
    assert_eq!(cat.open_count_by_severity(MismatchSeverity::Critical), 1);
}

#[test]
fn enrichment_gate_verdict_pass_with_relaxed_config() {
    let cat = build_full_catalog();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(verdict.is_pass());
}

#[test]
fn enrichment_gate_verdict_fail_too_many_errors() {
    let mut cat = build_full_catalog();
    // Add many open error entries
    for i in 0..10 {
        cat.add_entry(make_entry_with_target(
            &format!("err-{i}"),
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
    }
    let config = CatalogConfig {
        max_open_errors: 5,
        ..CatalogConfig::default()
    };
    let verdict = cat.evaluate(&config);
    assert!(!verdict.is_pass());
    if let GateVerdict::Fail { reasons } = &verdict {
        assert!(reasons.iter().any(|r| r.contains("error")));
    }
}

#[test]
fn enrichment_gate_verdict_incomplete_missing_target() {
    let mut cat = MismatchCatalog::new(epoch(1));
    // Cover all domains but only NodeJs target
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        cat.add_entry(make_entry_with_target(
            &format!("d-{i}"),
            domain,
            MismatchSeverity::Info,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
    }
    let config = CatalogConfig::default(); // requires NodeJs and Bun
    let verdict = cat.evaluate(&config);
    if let GateVerdict::Incomplete { missing_targets, .. } = &verdict {
        assert!(missing_targets.contains(&ComparisonTarget::Bun));
    } else {
        panic!("expected Incomplete verdict");
    }
}

#[test]
fn enrichment_gate_stale_entries_detected() {
    let mut cat = build_full_catalog();
    // Add an open entry with old verification epoch
    let mut e = make_entry("stale-1", MismatchDomain::CompileOutput, MismatchSeverity::Info);
    e.detected_epoch = epoch(1);
    e.verified_epoch = epoch(2);
    cat.add_entry(e).unwrap();
    let config = CatalogConfig {
        min_verification_epoch: epoch(5),
        ..CatalogConfig::default()
    };
    let verdict = cat.evaluate(&config);
    if let GateVerdict::Fail { reasons } = &verdict {
        assert!(reasons.iter().any(|r| r.contains("stale")));
    } else {
        panic!("expected Fail verdict for stale entries");
    }
}

#[test]
fn enrichment_advisories_grouped_by_domain() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("a1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("a2", MismatchDomain::CompileOutput, MismatchSeverity::Warning))
        .unwrap();
    cat.add_entry(make_entry("a3", MismatchDomain::HookSemantics, MismatchSeverity::Info))
        .unwrap();
    let advisories = generate_advisories(&cat);
    assert_eq!(advisories.len(), 2);
    let co_adv = advisories
        .iter()
        .find(|a| a.domains.contains(&MismatchDomain::CompileOutput))
        .unwrap();
    assert_eq!(co_adv.entry_count, 2);
    assert_eq!(co_adv.max_severity, MismatchSeverity::Error);
}

#[test]
fn enrichment_advisories_max_severity_correctly_computed() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("s1", MismatchDomain::SourceMap, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("s2", MismatchDomain::SourceMap, MismatchSeverity::Critical))
        .unwrap();
    let advisories = generate_advisories(&cat);
    let adv = advisories
        .iter()
        .find(|a| a.domains.contains(&MismatchDomain::SourceMap))
        .unwrap();
    assert_eq!(adv.max_severity, MismatchSeverity::Critical);
}

#[test]
fn enrichment_advisories_serde_roundtrip() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("adv-1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let advisories = generate_advisories(&cat);
    let json = serde_json::to_string(&advisories[0]).unwrap();
    let back: MismatchAdvisory = serde_json::from_str(&json).unwrap();
    assert_eq!(advisories[0], back);
}

#[test]
fn enrichment_domain_coverage_partial() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("dc1", MismatchDomain::CompileOutput, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("dc2", MismatchDomain::Diagnostics, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("dc3", MismatchDomain::SourceMap, MismatchSeverity::Info))
        .unwrap();
    // 3 out of 10 domains = 300_000 millionths
    assert_eq!(domain_coverage(&cat), 300_000);
}

#[test]
fn enrichment_resolution_ratio_all_resolved() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_with_target(
        "r1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "r2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::NodeJs,
        RemediationStatus::Accepted,
    ))
    .unwrap();
    assert_eq!(resolution_ratio(&cat), 1_000_000);
}

#[test]
fn enrichment_all_tags_multiple_entries() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e1 = make_entry("t1", MismatchDomain::CompileOutput, MismatchSeverity::Info);
    e1.tags.insert("ssr".to_string());
    cat.add_entry(e1).unwrap();
    let mut e2 = make_entry("t2", MismatchDomain::Diagnostics, MismatchSeverity::Info);
    e2.tags.insert("hydration".to_string());
    cat.add_entry(e2).unwrap();
    let tags = all_tags(&cat);
    assert!(tags.contains("react"));
    assert!(tags.contains("batch2"));
    assert!(tags.contains("ssr"));
    assert!(tags.contains("hydration"));
}

#[test]
fn enrichment_filter_entry_ids_by_target() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_with_target(
        "f1",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    ))
    .unwrap();
    cat.add_entry(make_entry_with_target(
        "f2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Warning,
        ComparisonTarget::Bun,
        RemediationStatus::None,
    ))
    .unwrap();
    let nodejs_ids = filter_entry_ids(&cat, |e| e.target == ComparisonTarget::NodeJs);
    assert_eq!(nodejs_ids, vec!["f1"]);
    let bun_ids = filter_entry_ids(&cat, |e| e.target == ComparisonTarget::Bun);
    assert_eq!(bun_ids, vec!["f2"]);
}

#[test]
fn enrichment_report_reflects_all_severity_counts() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("rp1", MismatchDomain::CompileOutput, MismatchSeverity::Critical))
        .unwrap();
    cat.add_entry(make_entry("rp2", MismatchDomain::Diagnostics, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("rp3", MismatchDomain::SourceMap, MismatchSeverity::Warning))
        .unwrap();
    cat.add_entry(make_entry("rp4", MismatchDomain::HookSemantics, MismatchSeverity::Info))
        .unwrap();
    let report = cat.report();
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.error_count, 1);
    assert_eq!(report.warning_count, 1);
    assert_eq!(report.info_count, 1);
    assert_eq!(report.total_entries, 4);
    assert_eq!(report.open_entries, 4);
}

#[test]
fn enrichment_catalog_hash_stability() {
    let mut cat1 = MismatchCatalog::new(epoch(1));
    let mut cat2 = MismatchCatalog::new(epoch(1));
    let e = make_entry("hash-test", MismatchDomain::CompileOutput, MismatchSeverity::Info);
    cat1.add_entry(e.clone()).unwrap();
    cat2.add_entry(e).unwrap();
    assert_eq!(cat1.catalog_hash, cat2.catalog_hash);
}

#[test]
fn enrichment_update_remediation_changes_open_count() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("rem1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("rem2", MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .unwrap();
    assert_eq!(cat.open_count(), 2);
    cat.update_remediation("rem1", RemediationStatus::Resolved).unwrap();
    assert_eq!(cat.open_count(), 1);
    cat.update_remediation("rem2", RemediationStatus::Accepted).unwrap();
    assert_eq!(cat.open_count(), 0);
}

#[test]
fn enrichment_entry_content_hash_varies_by_domain() {
    let e1 = make_entry("same-id", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let mut e2 = make_entry("same-id", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e2.domain = MismatchDomain::Diagnostics;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_entry_content_hash_varies_by_target() {
    let e1 = make_entry_with_target(
        "tgt-test",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::None,
    );
    let e2 = make_entry_with_target(
        "tgt-test",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::Bun,
        RemediationStatus::None,
    );
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_catalog_report_serde_roundtrip() {
    let cat = build_full_catalog();
    let report = cat.report();
    let json = serde_json::to_string(&report).unwrap();
    let back: CatalogReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_gate_verdict_incomplete_display() {
    let v = GateVerdict::Incomplete {
        missing_domains: vec![MismatchDomain::SourceMap, MismatchDomain::HookSemantics],
        missing_targets: vec![ComparisonTarget::Deno],
    };
    let s = format!("{v}");
    assert!(s.contains("INCOMPLETE"));
    assert!(s.contains("source_map"));
    assert!(s.contains("hook_semantics"));
    assert!(s.contains("deno"));
}

#[test]
fn enrichment_remediation_status_serde_shipped() {
    let status = RemediationStatus::Shipped;
    assert!(status.is_open());
    let json = serde_json::to_string(&status).unwrap();
    let back: RemediationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, back);
}

#[test]
fn enrichment_remediation_status_in_progress_is_open() {
    assert!(RemediationStatus::InProgress.is_open());
    assert_eq!(RemediationStatus::InProgress.as_str(), "in_progress");
}

#[test]
fn enrichment_catalog_error_serde_all_variants() {
    let errors: Vec<CatalogError> = vec![
        CatalogError::CapacityExceeded { current: 100, max: 50 },
        CatalogError::DuplicateEntry { entry_id: "dup".to_string() },
        CatalogError::AdvisoryTooLong { entry_id: "adv".to_string(), len: 9999 },
        CatalogError::EntryNotFound { entry_id: "miss".to_string() },
        CatalogError::InvalidEpoch {
            entry_id: "ep".to_string(),
            reason: "bad epoch".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CatalogError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_catalog_error_display_all_non_empty() {
    let errors: Vec<CatalogError> = vec![
        CatalogError::CapacityExceeded { current: 100, max: 50 },
        CatalogError::DuplicateEntry { entry_id: "dup".to_string() },
        CatalogError::AdvisoryTooLong { entry_id: "adv".to_string(), len: 9999 },
        CatalogError::EntryNotFound { entry_id: "miss".to_string() },
        CatalogError::InvalidEpoch {
            entry_id: "ep".to_string(),
            reason: "bad epoch".to_string(),
        },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn enrichment_gate_verdict_fail_display_contains_reasons() {
    let v = GateVerdict::Fail {
        reasons: vec!["too many critical".to_string(), "stale entries".to_string()],
    };
    let s = format!("{v}");
    assert!(s.starts_with("FAIL:"));
    assert!(s.contains("too many critical"));
    assert!(s.contains("stale entries"));
}

#[test]
fn enrichment_gate_verdict_is_pass_only_for_pass() {
    assert!(GateVerdict::Pass.is_pass());
    assert!(!GateVerdict::Fail { reasons: vec![] }.is_pass());
    assert!(
        !GateVerdict::Incomplete {
            missing_domains: vec![],
            missing_targets: vec![]
        }
        .is_pass()
    );
}

#[test]
fn enrichment_domain_summary_by_severity_populated() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("ds1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("ds2", MismatchDomain::CompileOutput, MismatchSeverity::Warning))
        .unwrap();
    let summaries = cat.domain_summary();
    let co = summaries
        .iter()
        .find(|s| s.domain == MismatchDomain::CompileOutput)
        .unwrap();
    assert_eq!(co.total_entries, 2);
    assert!(co.by_severity.contains_key("error"));
    assert!(co.by_severity.contains_key("warning"));
}
