//! Integration tests for `semantic_flattening_inventory` module.

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_flattening_inventory::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_boundary() -> BoundaryPoint {
    BoundaryPoint {
        source_module: "policy_controller".to_string(),
        target_module: "execution_orchestrator".to_string(),
        api_surface: "apply_policy".to_string(),
        line_hint: Some(42),
    }
}

fn sample_boundary_no_line() -> BoundaryPoint {
    BoundaryPoint {
        source_module: "module_a".to_string(),
        target_module: "module_b".to_string(),
        api_surface: "transfer".to_string(),
        line_hint: None,
    }
}

fn sample_occurrence(id: &str) -> FlatteningOccurrence {
    FlatteningOccurrence::new(
        id.to_string(),
        SemanticDomain::Budget,
        sample_boundary(),
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
        "Budget collapsed from multi-tier to single flat value".to_string(),
        "Preserve tier breakdown across boundary".to_string(),
        "bd-fix-001".to_string(),
    )
}

fn make_occurrence(
    id: &str,
    domain: SemanticDomain,
    kind: TranslationKind,
    classification: FlatteningClassification,
    severity: FlatteningSeverity,
) -> FlatteningOccurrence {
    FlatteningOccurrence::new(
        id.to_string(),
        domain,
        sample_boundary(),
        kind,
        classification,
        severity,
        format!("desc for {id}"),
        format!("remediation for {id}"),
        format!("bd-{id}"),
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constant_schema_version() {
    assert_eq!(
        FLATTENING_SCHEMA_VERSION,
        "franken-engine.semantic-flattening-inventory.v1"
    );
}

#[test]
fn constant_bead_id() {
    assert_eq!(FLATTENING_BEAD_ID, "bd-3nr.1.1.3");
}

// ---------------------------------------------------------------------------
// SemanticDomain
// ---------------------------------------------------------------------------

#[test]
fn semantic_domain_display_all_variants() {
    assert_eq!(format!("{}", SemanticDomain::Budget), "Budget");
    assert_eq!(format!("{}", SemanticDomain::Outcome), "Outcome");
    assert_eq!(format!("{}", SemanticDomain::Capability), "Capability");
    assert_eq!(format!("{}", SemanticDomain::Severity), "Severity");
    assert_eq!(format!("{}", SemanticDomain::Diagnostics), "Diagnostics");
    assert_eq!(format!("{}", SemanticDomain::PolicyId), "PolicyId");
    assert_eq!(format!("{}", SemanticDomain::TraceId), "TraceId");
    assert_eq!(format!("{}", SemanticDomain::DecisionId), "DecisionId");
    assert_eq!(format!("{}", SemanticDomain::EvidenceLink), "EvidenceLink");
    assert_eq!(
        format!("{}", SemanticDomain::SchemaVersion),
        "SchemaVersion"
    );
}

#[test]
fn semantic_domain_serde_roundtrip_all() {
    let all = [
        SemanticDomain::Budget,
        SemanticDomain::Outcome,
        SemanticDomain::Capability,
        SemanticDomain::Severity,
        SemanticDomain::Diagnostics,
        SemanticDomain::PolicyId,
        SemanticDomain::TraceId,
        SemanticDomain::DecisionId,
        SemanticDomain::EvidenceLink,
        SemanticDomain::SchemaVersion,
    ];
    for d in all {
        let json = serde_json::to_string(&d).unwrap();
        let back: SemanticDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back, "roundtrip failed for {d}");
    }
}

#[test]
fn semantic_domain_ordering() {
    assert!(SemanticDomain::Budget < SemanticDomain::Outcome);
    assert!(SemanticDomain::Outcome < SemanticDomain::Capability);
}

// ---------------------------------------------------------------------------
// TranslationKind
// ---------------------------------------------------------------------------

#[test]
fn translation_kind_display_all() {
    assert_eq!(format!("{}", TranslationKind::Preserved), "Preserved");
    assert_eq!(format!("{}", TranslationKind::Narrowed), "Narrowed");
    assert_eq!(format!("{}", TranslationKind::Widened), "Widened");
    assert_eq!(format!("{}", TranslationKind::Collapsed), "Collapsed");
    assert_eq!(format!("{}", TranslationKind::Translated), "Translated");
    assert_eq!(format!("{}", TranslationKind::Dropped), "Dropped");
}

#[test]
fn translation_kind_serde_roundtrip_all() {
    let all = [
        TranslationKind::Preserved,
        TranslationKind::Narrowed,
        TranslationKind::Widened,
        TranslationKind::Collapsed,
        TranslationKind::Translated,
        TranslationKind::Dropped,
    ];
    for k in all {
        let json = serde_json::to_string(&k).unwrap();
        let back: TranslationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back, "roundtrip failed for {k}");
    }
}

#[test]
fn translation_kind_ordering() {
    assert!(TranslationKind::Preserved < TranslationKind::Narrowed);
    assert!(TranslationKind::Narrowed < TranslationKind::Widened);
    assert!(TranslationKind::Widened < TranslationKind::Collapsed);
    assert!(TranslationKind::Collapsed < TranslationKind::Translated);
    assert!(TranslationKind::Translated < TranslationKind::Dropped);
}

// ---------------------------------------------------------------------------
// FlatteningClassification
// ---------------------------------------------------------------------------

#[test]
fn flattening_classification_display_all() {
    assert_eq!(
        format!("{}", FlatteningClassification::Intentional),
        "Intentional"
    );
    assert_eq!(format!("{}", FlatteningClassification::MustFix), "MustFix");
    assert_eq!(
        format!("{}", FlatteningClassification::AcceptableEdge),
        "AcceptableEdge"
    );
    assert_eq!(
        format!("{}", FlatteningClassification::FalsePositive),
        "FalsePositive"
    );
}

#[test]
fn flattening_classification_serde_roundtrip() {
    for cls in [
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
    ] {
        let json = serde_json::to_string(&cls).unwrap();
        let back: FlatteningClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(cls, back);
    }
}

#[test]
fn flattening_classification_ordering() {
    assert!(FlatteningClassification::Intentional < FlatteningClassification::MustFix);
    assert!(FlatteningClassification::MustFix < FlatteningClassification::AcceptableEdge);
    assert!(FlatteningClassification::AcceptableEdge < FlatteningClassification::FalsePositive);
}

// ---------------------------------------------------------------------------
// FlatteningSeverity
// ---------------------------------------------------------------------------

#[test]
fn flattening_severity_display_all() {
    assert_eq!(format!("{}", FlatteningSeverity::Critical), "Critical");
    assert_eq!(format!("{}", FlatteningSeverity::High), "High");
    assert_eq!(format!("{}", FlatteningSeverity::Medium), "Medium");
    assert_eq!(format!("{}", FlatteningSeverity::Low), "Low");
    assert_eq!(format!("{}", FlatteningSeverity::Info), "Info");
}

#[test]
fn flattening_severity_serde_roundtrip() {
    for sev in [
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
        FlatteningSeverity::Medium,
        FlatteningSeverity::Low,
        FlatteningSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: FlatteningSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn flattening_severity_ordering() {
    assert!(FlatteningSeverity::Critical < FlatteningSeverity::High);
    assert!(FlatteningSeverity::High < FlatteningSeverity::Medium);
    assert!(FlatteningSeverity::Medium < FlatteningSeverity::Low);
    assert!(FlatteningSeverity::Low < FlatteningSeverity::Info);
}

// ---------------------------------------------------------------------------
// BoundaryPoint
// ---------------------------------------------------------------------------

#[test]
fn boundary_point_display_with_line_hint() {
    let bp = sample_boundary();
    let s = format!("{bp}");
    assert!(s.contains("policy_controller"));
    assert!(s.contains("execution_orchestrator"));
    assert!(s.contains("apply_policy"));
    assert!(s.contains("line 42"));
}

#[test]
fn boundary_point_display_without_line_hint() {
    let bp = sample_boundary_no_line();
    let s = format!("{bp}");
    assert!(s.contains("module_a -> module_b via transfer"));
    assert!(!s.contains("line"));
}

#[test]
fn boundary_point_serde_roundtrip() {
    let bp = sample_boundary();
    let json = serde_json::to_string(&bp).unwrap();
    let back: BoundaryPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, back);
}

#[test]
fn boundary_point_serde_roundtrip_no_line() {
    let bp = sample_boundary_no_line();
    let json = serde_json::to_string(&bp).unwrap();
    let back: BoundaryPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, back);
    // Verify null in JSON for line_hint
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val["line_hint"].is_null());
}

#[test]
fn boundary_point_ordering() {
    let bp1 = BoundaryPoint {
        source_module: "a".to_string(),
        target_module: "b".to_string(),
        api_surface: "call".to_string(),
        line_hint: None,
    };
    let bp2 = BoundaryPoint {
        source_module: "b".to_string(),
        target_module: "c".to_string(),
        api_surface: "call".to_string(),
        line_hint: None,
    };
    assert!(bp1 < bp2);
}

// ---------------------------------------------------------------------------
// FlatteningOccurrence
// ---------------------------------------------------------------------------

#[test]
fn occurrence_construction_fields() {
    let occ = sample_occurrence("FLAT-001");
    assert_eq!(occ.id, "FLAT-001");
    assert_eq!(occ.domain, SemanticDomain::Budget);
    assert_eq!(occ.translation_kind, TranslationKind::Collapsed);
    assert_eq!(occ.classification, FlatteningClassification::MustFix);
    assert_eq!(occ.severity, FlatteningSeverity::High);
    assert!(!occ.description.is_empty());
    assert!(!occ.remediation.is_empty());
}

#[test]
fn occurrence_hash_determinism() {
    let occ1 = sample_occurrence("DET-1");
    let occ2 = sample_occurrence("DET-1");
    assert_eq!(occ1.content_hash, occ2.content_hash);
}

#[test]
fn occurrence_hash_differs_for_different_ids() {
    let occ1 = sample_occurrence("A");
    let occ2 = sample_occurrence("B");
    assert_ne!(occ1.content_hash, occ2.content_hash);
}

#[test]
fn occurrence_hash_differs_for_different_domains() {
    let occ1 = make_occurrence(
        "X",
        SemanticDomain::Budget,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
    );
    let occ2 = make_occurrence(
        "X",
        SemanticDomain::Outcome,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
    );
    assert_ne!(occ1.content_hash, occ2.content_hash);
}

#[test]
fn occurrence_hash_differs_for_different_translation_kind() {
    let occ1 = make_occurrence(
        "X",
        SemanticDomain::Budget,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
    );
    let occ2 = make_occurrence(
        "X",
        SemanticDomain::Budget,
        TranslationKind::Dropped,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
    );
    assert_ne!(occ1.content_hash, occ2.content_hash);
}

#[test]
fn occurrence_display_contains_id() {
    let occ = sample_occurrence("FLAT-DISP");
    let s = format!("{occ}");
    assert!(s.contains("FLAT-DISP"));
    assert!(s.contains("High"));
    assert!(s.contains("MustFix"));
    assert!(s.contains("Collapsed"));
}

#[test]
fn occurrence_serde_roundtrip() {
    let occ = sample_occurrence("SERDE-1");
    let json = serde_json::to_string(&occ).unwrap();
    let back: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, back);
}

#[test]
fn occurrence_all_translation_kinds() {
    let kinds = [
        TranslationKind::Preserved,
        TranslationKind::Narrowed,
        TranslationKind::Widened,
        TranslationKind::Collapsed,
        TranslationKind::Translated,
        TranslationKind::Dropped,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let occ = FlatteningOccurrence::new(
            format!("TK-{i}"),
            SemanticDomain::Capability,
            sample_boundary(),
            *kind,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
            "test".to_string(),
            "none".to_string(),
            String::new(),
        );
        assert_eq!(occ.translation_kind, *kind);
    }
}

// ---------------------------------------------------------------------------
// FlatteningInventory — construction
// ---------------------------------------------------------------------------

#[test]
fn inventory_new_empty() {
    let inv = FlatteningInventory::new(SecurityEpoch::from_raw(5));
    assert_eq!(inv.occurrences.len(), 0);
    assert_eq!(inv.schema_version, FLATTENING_SCHEMA_VERSION);
    assert_eq!(inv.assessed_epoch, SecurityEpoch::from_raw(5));
}

#[test]
fn inventory_add_occurrences() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(sample_occurrence("A"));
    inv.add(sample_occurrence("B"));
    inv.add(sample_occurrence("C"));
    assert_eq!(inv.occurrences.len(), 3);
}

// ---------------------------------------------------------------------------
// FlatteningInventory — queries
// ---------------------------------------------------------------------------

#[test]
fn inventory_must_fix_items() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(sample_occurrence("MF-1")); // MustFix
    inv.add(make_occurrence(
        "INT-1",
        SemanticDomain::Capability,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
        FlatteningSeverity::Info,
    ));
    inv.add(sample_occurrence("MF-2")); // MustFix
    let mf = inv.must_fix_items();
    assert_eq!(mf.len(), 2);
    assert_eq!(mf[0].id, "MF-1");
    assert_eq!(mf[1].id, "MF-2");
}

#[test]
fn inventory_must_fix_empty() {
    let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    assert!(inv.must_fix_items().is_empty());
}

#[test]
fn inventory_by_domain() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(sample_occurrence("BD-1")); // Budget
    inv.add(make_occurrence(
        "CAP-1",
        SemanticDomain::Capability,
        TranslationKind::Narrowed,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Medium,
    ));
    inv.add(sample_occurrence("BD-2")); // Budget
    let budget = inv.by_domain(SemanticDomain::Budget);
    assert_eq!(budget.len(), 2);
    let cap = inv.by_domain(SemanticDomain::Capability);
    assert_eq!(cap.len(), 1);
    let diag = inv.by_domain(SemanticDomain::Diagnostics);
    assert!(diag.is_empty());
}

#[test]
fn inventory_by_severity() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(sample_occurrence("S-1")); // High
    inv.add(make_occurrence(
        "S-2",
        SemanticDomain::Outcome,
        TranslationKind::Dropped,
        FlatteningClassification::MustFix,
        FlatteningSeverity::Critical,
    ));
    let high = inv.by_severity(FlatteningSeverity::High);
    assert_eq!(high.len(), 1);
    let crit = inv.by_severity(FlatteningSeverity::Critical);
    assert_eq!(crit.len(), 1);
    let low = inv.by_severity(FlatteningSeverity::Low);
    assert!(low.is_empty());
}

// ---------------------------------------------------------------------------
// FlatteningInventory — summary
// ---------------------------------------------------------------------------

#[test]
fn inventory_summary_empty() {
    let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let s = inv.summary();
    assert_eq!(s.total, 0);
    assert_eq!(s.must_fix, 0);
    assert_eq!(s.intentional, 0);
    assert_eq!(s.acceptable, 0);
    assert_eq!(s.false_positive, 0);
    assert!(s.by_domain.is_empty());
    assert!(s.by_severity.is_empty());
}

#[test]
fn inventory_summary_populated() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(3));
    // MustFix, Budget, High
    inv.add(sample_occurrence("SUM-1"));
    // Intentional, Capability, Info
    inv.add(make_occurrence(
        "SUM-2",
        SemanticDomain::Capability,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
        FlatteningSeverity::Info,
    ));
    // AcceptableEdge, Capability, Medium
    inv.add(make_occurrence(
        "SUM-3",
        SemanticDomain::Capability,
        TranslationKind::Narrowed,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Medium,
    ));
    // FalsePositive, TraceId, Low
    inv.add(make_occurrence(
        "SUM-4",
        SemanticDomain::TraceId,
        TranslationKind::Translated,
        FlatteningClassification::FalsePositive,
        FlatteningSeverity::Low,
    ));

    let s = inv.summary();
    assert_eq!(s.total, 4);
    assert_eq!(s.must_fix, 1);
    assert_eq!(s.intentional, 1);
    assert_eq!(s.acceptable, 1);
    assert_eq!(s.false_positive, 1);
    assert_eq!(s.by_domain.get("Budget"), Some(&1));
    assert_eq!(s.by_domain.get("Capability"), Some(&2));
    assert_eq!(s.by_domain.get("TraceId"), Some(&1));
    assert_eq!(s.by_severity.get("High"), Some(&1));
    assert_eq!(s.by_severity.get("Info"), Some(&1));
    assert_eq!(s.by_severity.get("Medium"), Some(&1));
    assert_eq!(s.by_severity.get("Low"), Some(&1));
}

#[test]
fn inventory_summary_all_must_fix() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    for i in 0..5 {
        inv.add(sample_occurrence(&format!("MF-{i}")));
    }
    let s = inv.summary();
    assert_eq!(s.total, 5);
    assert_eq!(s.must_fix, 5);
    assert_eq!(s.intentional, 0);
}

// ---------------------------------------------------------------------------
// FlatteningInventory — content hash
// ---------------------------------------------------------------------------

#[test]
fn inventory_content_hash_determinism() {
    let mut inv1 = FlatteningInventory::new(SecurityEpoch::from_raw(7));
    inv1.add(sample_occurrence("DET-1"));
    inv1.add(sample_occurrence("DET-2"));

    let mut inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(7));
    inv2.add(sample_occurrence("DET-1"));
    inv2.add(sample_occurrence("DET-2"));

    assert_eq!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn inventory_content_hash_differs_for_different_epochs() {
    let mut inv1 = FlatteningInventory::new(SecurityEpoch::from_raw(1));
    inv1.add(sample_occurrence("EP-1"));

    let mut inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(2));
    inv2.add(sample_occurrence("EP-1"));

    assert_ne!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn inventory_content_hash_differs_for_different_items() {
    let mut inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv1.add(sample_occurrence("X"));

    let mut inv2 = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv2.add(sample_occurrence("Y"));

    assert_ne!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn inventory_empty_content_hash_not_default() {
    let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let hash = inv.content_hash();
    use frankenengine_engine::hash_tiers::ContentHash;
    assert_ne!(hash, ContentHash::default());
}

// ---------------------------------------------------------------------------
// FlatteningInventory — Display
// ---------------------------------------------------------------------------

#[test]
fn inventory_display_format() {
    let inv = FlatteningInventory::new(SecurityEpoch::from_raw(10));
    let s = format!("{inv}");
    assert!(s.contains("FlatteningInventory"));
    assert!(s.contains("count=0"));
}

#[test]
fn inventory_display_nonzero_count() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(1));
    inv.add(sample_occurrence("D-1"));
    inv.add(sample_occurrence("D-2"));
    let s = format!("{inv}");
    assert!(s.contains("count=2"));
}

// ---------------------------------------------------------------------------
// FlatteningInventory — serde
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(99));
    inv.add(sample_occurrence("RND-1"));
    inv.add(make_occurrence(
        "RND-2",
        SemanticDomain::Diagnostics,
        TranslationKind::Dropped,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Medium,
    ));
    let json = serde_json::to_string(&inv).unwrap();
    let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn inventory_serde_empty_roundtrip() {
    let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let json = serde_json::to_string(&inv).unwrap();
    let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// FlatteningSummary
// ---------------------------------------------------------------------------

#[test]
fn summary_display() {
    let s = FlatteningSummary {
        total: 10,
        must_fix: 2,
        intentional: 5,
        acceptable: 2,
        false_positive: 1,
        by_domain: std::collections::BTreeMap::new(),
        by_severity: std::collections::BTreeMap::new(),
    };
    let txt = format!("{s}");
    assert!(txt.contains("total=10"));
    assert!(txt.contains("must_fix=2"));
    assert!(txt.contains("intentional=5"));
}

#[test]
fn summary_serde_roundtrip() {
    let s = FlatteningSummary {
        total: 3,
        must_fix: 1,
        intentional: 1,
        acceptable: 1,
        false_positive: 0,
        by_domain: std::collections::BTreeMap::from([
            ("Budget".to_string(), 2),
            ("Capability".to_string(), 1),
        ]),
        by_severity: std::collections::BTreeMap::from([
            ("High".to_string(), 1),
            ("Low".to_string(), 2),
        ]),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: FlatteningSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn occurrence_with_empty_strings() {
    let occ = FlatteningOccurrence::new(
        String::new(),
        SemanticDomain::Budget,
        BoundaryPoint {
            source_module: String::new(),
            target_module: String::new(),
            api_surface: String::new(),
            line_hint: None,
        },
        TranslationKind::Preserved,
        FlatteningClassification::FalsePositive,
        FlatteningSeverity::Info,
        String::new(),
        String::new(),
        String::new(),
    );
    // Should not panic; hash should still be valid
    let json = serde_json::to_string(&occ).unwrap();
    let back: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, back);
}

#[test]
fn large_inventory_summary_correct() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(1));
    let domains = [
        SemanticDomain::Budget,
        SemanticDomain::Outcome,
        SemanticDomain::Capability,
        SemanticDomain::Severity,
        SemanticDomain::Diagnostics,
    ];
    for i in 0..50 {
        let domain = domains[i % domains.len()];
        let classification = if i % 4 == 0 {
            FlatteningClassification::MustFix
        } else if i % 4 == 1 {
            FlatteningClassification::Intentional
        } else if i % 4 == 2 {
            FlatteningClassification::AcceptableEdge
        } else {
            FlatteningClassification::FalsePositive
        };
        inv.add(make_occurrence(
            &format!("LARGE-{i}"),
            domain,
            TranslationKind::Collapsed,
            classification,
            FlatteningSeverity::Medium,
        ));
    }
    let s = inv.summary();
    assert_eq!(s.total, 50);
    // 50/4 = 12 remainder 2 -> must_fix: indices 0,4,8,...,48 = 13
    assert_eq!(s.must_fix, 13);
    // 50 items across 5 domains evenly = 10 each
    assert_eq!(s.by_domain.get("Budget"), Some(&10));
    assert_eq!(s.by_domain.get("Outcome"), Some(&10));
}

#[test]
fn compute_content_hash_static_method() {
    let bp = sample_boundary();
    let hash1 = FlatteningOccurrence::compute_content_hash(
        "X",
        SemanticDomain::Budget,
        &bp,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
    );
    let hash2 = FlatteningOccurrence::compute_content_hash(
        "X",
        SemanticDomain::Budget,
        &bp,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
    );
    assert_eq!(hash1, hash2);

    // Different classification -> different hash
    let hash3 = FlatteningOccurrence::compute_content_hash(
        "X",
        SemanticDomain::Budget,
        &bp,
        TranslationKind::Collapsed,
        FlatteningClassification::Intentional,
    );
    assert_ne!(hash1, hash3);
}

#[test]
fn inventory_by_domain_all_domains() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let all_domains = [
        SemanticDomain::Budget,
        SemanticDomain::Outcome,
        SemanticDomain::Capability,
        SemanticDomain::Severity,
        SemanticDomain::Diagnostics,
        SemanticDomain::PolicyId,
        SemanticDomain::TraceId,
        SemanticDomain::DecisionId,
        SemanticDomain::EvidenceLink,
        SemanticDomain::SchemaVersion,
    ];
    for (i, domain) in all_domains.iter().enumerate() {
        inv.add(make_occurrence(
            &format!("DOM-{i}"),
            *domain,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
        ));
    }
    for domain in all_domains {
        let items = inv.by_domain(domain);
        assert_eq!(items.len(), 1, "expected 1 item for domain {domain}");
    }
}
