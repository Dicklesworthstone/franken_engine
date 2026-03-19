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

//! Enrichment integration tests for the `react_mismatch_catalog` module.

use std::collections::BTreeSet;

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
        reproduction: "test fixture".to_string(),
        remediation: RemediationStatus::None,
        advisory: "advisory text".to_string(),
        react_version_range: ">=18.0.0".to_string(),
        evidence_hash: ContentHash::compute(id.as_bytes()),
        detected_epoch: epoch(1),
        verified_epoch: epoch(2),
        tags: ["react", "enrichment"].iter().map(|s| s.to_string()).collect(),
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

fn full_domain_catalog() -> MismatchCatalog {
    let mut cat = MismatchCatalog::new(epoch(1));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i % 2 == 0 {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        cat.add_entry(make_entry_full(
            &format!("enr-{i}"),
            domain,
            MismatchSeverity::Info,
            target,
            RemediationStatus::Resolved,
        ))
        .unwrap();
    }
    cat
}

// ===========================================================================
// Constants verification
// ===========================================================================

#[test]
fn enrichment_schema_version_format() {
    assert!(MISMATCH_CATALOG_SCHEMA_VERSION.contains(".v1"));
    assert!(MISMATCH_CATALOG_SCHEMA_VERSION.contains("react-mismatch-catalog"));
}

#[test]
fn enrichment_bead_id_starts_with_bd() {
    assert!(MISMATCH_CATALOG_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_starts_with_rgc() {
    assert!(MISMATCH_CATALOG_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_component_matches_module() {
    assert_eq!(COMPONENT, "react_mismatch_catalog");
}

// ===========================================================================
// MismatchDomain exhaustive checks
// ===========================================================================

#[test]
fn enrichment_all_domains_count() {
    assert_eq!(ALL_DOMAINS.len(), 10);
}

#[test]
fn enrichment_all_domains_unique_as_str() {
    let strs: BTreeSet<&str> = ALL_DOMAINS.iter().map(|d| d.as_str()).collect();
    assert_eq!(strs.len(), ALL_DOMAINS.len());
}

#[test]
fn enrichment_domain_display_matches_as_str() {
    for &d in ALL_DOMAINS {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrichment_domain_serde_roundtrip_all() {
    for &d in ALL_DOMAINS {
        let json = serde_json::to_string(&d).unwrap();
        let back: MismatchDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ===========================================================================
// MismatchSeverity enrichment
// ===========================================================================

#[test]
fn enrichment_severity_weights_strictly_increasing() {
    let severities = [
        MismatchSeverity::Info,
        MismatchSeverity::Warning,
        MismatchSeverity::Error,
        MismatchSeverity::Critical,
    ];
    for w in severities.windows(2) {
        assert!(w[0].weight() < w[1].weight());
    }
}

#[test]
fn enrichment_severity_display_matches_as_str() {
    let all = [
        MismatchSeverity::Info,
        MismatchSeverity::Warning,
        MismatchSeverity::Error,
        MismatchSeverity::Critical,
    ];
    for s in all {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrichment_severity_info_weight_is_100k() {
    assert_eq!(MismatchSeverity::Info.weight(), 100_000);
}

#[test]
fn enrichment_severity_critical_is_million() {
    assert_eq!(MismatchSeverity::Critical.weight(), 1_000_000);
}

// ===========================================================================
// RemediationStatus enrichment
// ===========================================================================

#[test]
fn enrichment_remediation_all_display_unique() {
    let all = [
        RemediationStatus::None,
        RemediationStatus::Workaround,
        RemediationStatus::InProgress,
        RemediationStatus::Shipped,
        RemediationStatus::Resolved,
        RemediationStatus::Accepted,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_remediation_display_matches_as_str() {
    let all = [
        RemediationStatus::None,
        RemediationStatus::Workaround,
        RemediationStatus::InProgress,
        RemediationStatus::Shipped,
        RemediationStatus::Resolved,
        RemediationStatus::Accepted,
    ];
    for s in all {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn enrichment_remediation_serde_roundtrip_all() {
    let all = [
        RemediationStatus::None,
        RemediationStatus::Workaround,
        RemediationStatus::InProgress,
        RemediationStatus::Shipped,
        RemediationStatus::Resolved,
        RemediationStatus::Accepted,
    ];
    for s in all {
        let json = serde_json::to_string(&s).unwrap();
        let back: RemediationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// ComparisonTarget enrichment
// ===========================================================================

#[test]
fn enrichment_target_serde_roundtrip_all() {
    for t in [
        ComparisonTarget::NodeJs,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::V8Reference,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: ComparisonTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn enrichment_target_display_matches_as_str() {
    for t in [
        ComparisonTarget::NodeJs,
        ComparisonTarget::Bun,
        ComparisonTarget::Deno,
        ComparisonTarget::V8Reference,
    ] {
        assert_eq!(t.to_string(), t.as_str());
    }
}

// ===========================================================================
// MismatchEntry enrichment
// ===========================================================================

#[test]
fn enrichment_entry_content_hash_deterministic() {
    let e1 = make_entry("det-1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    let e2 = make_entry("det-1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_entry_content_hash_varies_by_severity() {
    let e1 = make_entry("x", MismatchDomain::CompileOutput, MismatchSeverity::Warning);
    let e2 = make_entry("x", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_entry_weighted_score_matches_severity() {
    let e = make_entry("x", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    assert_eq!(e.weighted_score(), MismatchSeverity::Error.weight());
}

#[test]
fn enrichment_entry_is_open_for_workaround() {
    let e = make_entry_full(
        "x",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Workaround,
    );
    assert!(e.is_open());
}

#[test]
fn enrichment_entry_is_closed_for_accepted() {
    let e = make_entry_full(
        "x",
        MismatchDomain::CompileOutput,
        MismatchSeverity::Error,
        ComparisonTarget::NodeJs,
        RemediationStatus::Accepted,
    );
    assert!(!e.is_open());
}

// ===========================================================================
// MismatchCatalog CRUD enrichment
// ===========================================================================

#[test]
fn enrichment_catalog_new_is_empty() {
    let cat = MismatchCatalog::new(epoch(1));
    assert!(cat.is_empty());
    assert_eq!(cat.len(), 0);
    assert_eq!(cat.open_count(), 0);
}

#[test]
fn enrichment_catalog_add_multiple_entries() {
    let mut cat = MismatchCatalog::new(epoch(1));
    for i in 0..5 {
        cat.add_entry(make_entry(
            &format!("e-{i}"),
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ))
        .unwrap();
    }
    assert_eq!(cat.len(), 5);
    assert_eq!(cat.open_count(), 5);
}

#[test]
fn enrichment_catalog_duplicate_rejected() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("dup", MismatchDomain::CompileOutput, MismatchSeverity::Info))
        .unwrap();
    let err = cat
        .add_entry(make_entry("dup", MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .unwrap_err();
    assert!(matches!(err, CatalogError::DuplicateEntry { .. }));
}

#[test]
fn enrichment_catalog_remove_and_verify() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("rm-1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let removed = cat.remove_entry("rm-1").unwrap();
    assert_eq!(removed.entry_id, "rm-1");
    assert!(cat.is_empty());
}

#[test]
fn enrichment_catalog_remove_nonexistent() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let err = cat.remove_entry("ghost").unwrap_err();
    assert!(matches!(err, CatalogError::EntryNotFound { .. }));
}

#[test]
fn enrichment_catalog_update_remediation() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    assert_eq!(cat.open_count(), 1);
    cat.update_remediation("e1", RemediationStatus::Resolved).unwrap();
    assert_eq!(cat.open_count(), 0);
}

#[test]
fn enrichment_catalog_advisory_too_long() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = make_entry("long", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.advisory = "x".repeat(5000);
    let err = cat.add_entry(e).unwrap_err();
    assert!(matches!(err, CatalogError::AdvisoryTooLong { .. }));
}

#[test]
fn enrichment_catalog_invalid_epoch() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = make_entry("inv", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.detected_epoch = epoch(10);
    e.verified_epoch = epoch(5);
    let err = cat.add_entry(e).unwrap_err();
    assert!(matches!(err, CatalogError::InvalidEpoch { .. }));
}

// ===========================================================================
// Aggregation queries enrichment
// ===========================================================================

#[test]
fn enrichment_aggregate_open_score_mixed() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry_full(
        "e2",
        MismatchDomain::Diagnostics,
        MismatchSeverity::Critical,
        ComparisonTarget::NodeJs,
        RemediationStatus::Resolved,
    ))
    .unwrap();
    // Only open entry counts: Error weight = 700_000
    assert_eq!(cat.aggregate_open_score(), 700_000);
}

#[test]
fn enrichment_count_by_severity() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("e2", MismatchDomain::Diagnostics, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("e3", MismatchDomain::SourceMap, MismatchSeverity::Error))
        .unwrap();
    assert_eq!(cat.count_by_severity(MismatchSeverity::Info), 2);
    assert_eq!(cat.count_by_severity(MismatchSeverity::Error), 1);
    assert_eq!(cat.count_by_severity(MismatchSeverity::Critical), 0);
}

#[test]
fn enrichment_covered_domains() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Info))
        .unwrap();
    cat.add_entry(make_entry("e2", MismatchDomain::HookSemantics, MismatchSeverity::Warning))
        .unwrap();
    let domains = cat.covered_domains();
    assert_eq!(domains.len(), 2);
    assert!(domains.contains(&MismatchDomain::CompileOutput));
    assert!(domains.contains(&MismatchDomain::HookSemantics));
}

// ===========================================================================
// Gate evaluation enrichment
// ===========================================================================

#[test]
fn enrichment_gate_pass_full_catalog_resolved() {
    let cat = full_domain_catalog();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(verdict.is_pass());
}

#[test]
fn enrichment_gate_incomplete_single_domain() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Info))
        .unwrap();
    let config = CatalogConfig::default();
    let verdict = cat.evaluate(&config);
    assert!(matches!(verdict, GateVerdict::Incomplete { .. }));
}

#[test]
fn enrichment_gate_fail_on_critical() {
    let mut cat = full_domain_catalog();
    cat.add_entry(make_entry_full(
        "crit",
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
fn enrichment_gate_verdict_display_pass() {
    assert_eq!(format!("{}", GateVerdict::Pass), "PASS");
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail {
            reasons: vec!["reason".to_string()],
        },
        GateVerdict::Incomplete {
            missing_domains: vec![MismatchDomain::SourceMap],
            missing_targets: vec![ComparisonTarget::Deno],
        },
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// Advisory generation enrichment
// ===========================================================================

#[test]
fn enrichment_advisories_empty_catalog() {
    let cat = MismatchCatalog::new(epoch(1));
    let advisories = generate_advisories(&cat);
    assert!(advisories.is_empty());
}

#[test]
fn enrichment_advisories_skip_all_resolved() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry_full(
        "r1",
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
fn enrichment_advisories_id_format() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let advisories = generate_advisories(&cat);
    assert!(advisories[0].advisory_id.starts_with("ADV-"));
}

// ===========================================================================
// Helper functions enrichment
// ===========================================================================

#[test]
fn enrichment_domain_coverage_empty() {
    let cat = MismatchCatalog::new(epoch(1));
    assert_eq!(domain_coverage(&cat), 0);
}

#[test]
fn enrichment_domain_coverage_full() {
    let cat = full_domain_catalog();
    assert_eq!(domain_coverage(&cat), 1_000_000);
}

#[test]
fn enrichment_resolution_ratio_none_resolved() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    assert_eq!(resolution_ratio(&cat), 0);
}

#[test]
fn enrichment_resolution_ratio_empty_catalog() {
    let cat = MismatchCatalog::new(epoch(1));
    assert_eq!(resolution_ratio(&cat), 1_000_000);
}

#[test]
fn enrichment_all_tags_collects() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let mut e = make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
    e.tags.insert("custom".to_string());
    cat.add_entry(e).unwrap();
    let tags = all_tags(&cat);
    assert!(tags.contains("react"));
    assert!(tags.contains("enrichment"));
    assert!(tags.contains("custom"));
}

#[test]
fn enrichment_filter_entry_ids_by_domain() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("e2", MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .unwrap();
    let compile = filter_entry_ids(&cat, |e| e.domain == MismatchDomain::CompileOutput);
    assert_eq!(compile, vec!["e1"]);
}

// ===========================================================================
// Catalog hash enrichment
// ===========================================================================

#[test]
fn enrichment_catalog_hash_changes_on_add() {
    let mut cat = MismatchCatalog::new(epoch(1));
    let h0 = cat.catalog_hash;
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    assert_ne!(cat.catalog_hash, h0);
}

#[test]
fn enrichment_catalog_hash_changes_on_remove() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let h1 = cat.catalog_hash;
    cat.remove_entry("e1").unwrap();
    assert_ne!(cat.catalog_hash, h1);
}

#[test]
fn enrichment_catalog_hash_changes_on_remediation() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let h1 = cat.catalog_hash;
    cat.update_remediation("e1", RemediationStatus::Resolved).unwrap();
    assert_ne!(cat.catalog_hash, h1);
}

// ===========================================================================
// Serde roundtrips enrichment
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_catalog() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let json = serde_json::to_string(&cat).unwrap();
    let back: MismatchCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, back);
}

#[test]
fn enrichment_serde_roundtrip_config() {
    let config = CatalogConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: CatalogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_serde_roundtrip_report() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    let report = cat.report();
    let json = serde_json::to_string(&report).unwrap();
    let back: CatalogReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_serde_roundtrip_error() {
    let errors = vec![
        CatalogError::CapacityExceeded { current: 10000, max: 10000 },
        CatalogError::DuplicateEntry { entry_id: "dup".to_string() },
        CatalogError::AdvisoryTooLong { entry_id: "x".to_string(), len: 5000 },
        CatalogError::EntryNotFound { entry_id: "missing".to_string() },
        CatalogError::InvalidEpoch { entry_id: "x".to_string(), reason: "bad".to_string() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CatalogError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// CatalogError Display enrichment
// ===========================================================================

#[test]
fn enrichment_error_display_all_unique() {
    let errors: Vec<String> = vec![
        CatalogError::CapacityExceeded { current: 1, max: 1 }.to_string(),
        CatalogError::DuplicateEntry { entry_id: "x".to_string() }.to_string(),
        CatalogError::AdvisoryTooLong { entry_id: "x".to_string(), len: 1 }.to_string(),
        CatalogError::EntryNotFound { entry_id: "x".to_string() }.to_string(),
        CatalogError::InvalidEpoch { entry_id: "x".to_string(), reason: "y".to_string() }.to_string(),
    ];
    let unique: BTreeSet<String> = errors.into_iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// Report enrichment
// ===========================================================================

#[test]
fn enrichment_report_reflects_catalog() {
    let mut cat = MismatchCatalog::new(epoch(1));
    cat.add_entry(make_entry("e1", MismatchDomain::CompileOutput, MismatchSeverity::Error))
        .unwrap();
    cat.add_entry(make_entry("e2", MismatchDomain::Diagnostics, MismatchSeverity::Warning))
        .unwrap();
    let report = cat.report();
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.open_entries, 2);
    assert_eq!(report.error_count, 1);
    assert_eq!(report.warning_count, 1);
    assert_eq!(report.catalog_hash, cat.catalog_hash);
}

// ===========================================================================
// Cross-concern pipeline enrichment
// ===========================================================================

#[test]
fn enrichment_full_pipeline_add_remediate_pass() {
    let mut cat = MismatchCatalog::new(epoch(5));
    for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
        let target = if i % 2 == 0 {
            ComparisonTarget::NodeJs
        } else {
            ComparisonTarget::Bun
        };
        cat.add_entry(make_entry_full(
            &format!("pipe-{i}"),
            domain,
            MismatchSeverity::Error,
            target,
            RemediationStatus::None,
        ))
        .unwrap();
    }
    let config = CatalogConfig::default();
    assert!(!cat.evaluate(&config).is_pass());

    for i in 0..ALL_DOMAINS.len() {
        cat.update_remediation(&format!("pipe-{i}"), RemediationStatus::Resolved)
            .unwrap();
    }
    assert!(cat.evaluate(&config).is_pass());
    assert_eq!(cat.report().open_entries, 0);
}
