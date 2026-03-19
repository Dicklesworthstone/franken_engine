//! Enrichment integration tests for `semantic_flattening_inventory` module.
//!
//! Covers: enum serde roundtrips, Display uniqueness, struct construction,
//! lifecycle, arithmetic, edge cases, content hash determinism, and
//! inventory filtering/summary invariants.

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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
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

fn make_boundary(src: &str, tgt: &str, api: &str, line: Option<u32>) -> BoundaryPoint {
    BoundaryPoint {
        source_module: src.to_string(),
        target_module: tgt.to_string(),
        api_surface: api.to_string(),
        line_hint: line,
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

fn make_occurrence_full(
    id: &str,
    domain: SemanticDomain,
    boundary: BoundaryPoint,
    kind: TranslationKind,
    classification: FlatteningClassification,
    severity: FlatteningSeverity,
) -> FlatteningOccurrence {
    FlatteningOccurrence::new(
        id.to_string(),
        domain,
        boundary,
        kind,
        classification,
        severity,
        format!("desc for {id}"),
        format!("remediation for {id}"),
        format!("bd-{id}"),
    )
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — cross-format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_semantic_domain_json_pretty_roundtrip() {
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
        let pretty = serde_json::to_string_pretty(&d).unwrap();
        let back: SemanticDomain = serde_json::from_str(&pretty).unwrap();
        assert_eq!(d, back, "pretty roundtrip failed for {d}");
    }
}

#[test]
fn enrichment_serde_translation_kind_json_value_roundtrip() {
    let all = [
        TranslationKind::Preserved,
        TranslationKind::Narrowed,
        TranslationKind::Widened,
        TranslationKind::Collapsed,
        TranslationKind::Translated,
        TranslationKind::Dropped,
    ];
    for k in all {
        let val: serde_json::Value = serde_json::to_value(&k).unwrap();
        let back: TranslationKind = serde_json::from_value(val.clone()).unwrap();
        assert_eq!(k, back, "Value roundtrip failed for {k}");
    }
}

#[test]
fn enrichment_serde_classification_from_string_literal() {
    let cases = [
        ("\"Intentional\"", FlatteningClassification::Intentional),
        ("\"MustFix\"", FlatteningClassification::MustFix),
        (
            "\"AcceptableEdge\"",
            FlatteningClassification::AcceptableEdge,
        ),
        ("\"FalsePositive\"", FlatteningClassification::FalsePositive),
    ];
    for (json_str, expected) in cases {
        let parsed: FlatteningClassification = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed, expected);
    }
}

#[test]
fn enrichment_serde_severity_from_string_literal() {
    let cases = [
        ("\"Critical\"", FlatteningSeverity::Critical),
        ("\"High\"", FlatteningSeverity::High),
        ("\"Medium\"", FlatteningSeverity::Medium),
        ("\"Low\"", FlatteningSeverity::Low),
        ("\"Info\"", FlatteningSeverity::Info),
    ];
    for (json_str, expected) in cases {
        let parsed: FlatteningSeverity = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed, expected);
    }
}

// ---------------------------------------------------------------------------
// Display uniqueness — no two variants share the same Display string
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_semantic_domain_all_unique() {
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
    let mut seen = BTreeSet::new();
    for d in all {
        let s = format!("{d}");
        assert!(seen.insert(s.clone()), "duplicate Display for {d}: {s}");
    }
    assert_eq!(seen.len(), 10);
}

#[test]
fn enrichment_display_translation_kind_all_unique() {
    let all = [
        TranslationKind::Preserved,
        TranslationKind::Narrowed,
        TranslationKind::Widened,
        TranslationKind::Collapsed,
        TranslationKind::Translated,
        TranslationKind::Dropped,
    ];
    let mut seen = BTreeSet::new();
    for k in all {
        let s = format!("{k}");
        assert!(seen.insert(s.clone()), "duplicate Display for {k}: {s}");
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_display_classification_all_unique() {
    let all = [
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
    ];
    let mut seen = BTreeSet::new();
    for c in all {
        let s = format!("{c}");
        assert!(seen.insert(s.clone()), "duplicate Display: {s}");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn enrichment_display_severity_all_unique() {
    let all = [
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
        FlatteningSeverity::Medium,
        FlatteningSeverity::Low,
        FlatteningSeverity::Info,
    ];
    let mut seen = BTreeSet::new();
    for s in all {
        let txt = format!("{s}");
        assert!(seen.insert(txt.clone()), "duplicate Display: {txt}");
    }
    assert_eq!(seen.len(), 5);
}

// ---------------------------------------------------------------------------
// BoundaryPoint construction and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_struct_boundary_point_display_with_large_line_hint() {
    let bp = make_boundary("engine", "runtime", "execute", Some(u32::MAX));
    let s = format!("{bp}");
    assert!(s.contains("engine -> runtime via execute"));
    assert!(s.contains(&format!("line {}", u32::MAX)));
}

#[test]
fn enrichment_struct_boundary_point_clone_eq() {
    let bp = make_boundary("src", "dst", "fn_call", Some(100));
    let cloned = bp.clone();
    assert_eq!(bp, cloned);
    assert_eq!(format!("{bp}"), format!("{cloned}"));
}

#[test]
fn enrichment_struct_boundary_point_ord_by_target_when_source_equal() {
    let bp1 = make_boundary("same", "aaa", "x", None);
    let bp2 = make_boundary("same", "bbb", "x", None);
    assert!(
        bp1 < bp2,
        "should order by target_module when source_module is equal"
    );
}

#[test]
fn enrichment_struct_boundary_point_ord_by_api_surface_when_modules_equal() {
    let bp1 = make_boundary("same", "same", "alpha", None);
    let bp2 = make_boundary("same", "same", "beta", None);
    assert!(
        bp1 < bp2,
        "should order by api_surface when modules are equal"
    );
}

#[test]
fn enrichment_struct_boundary_point_in_btreeset_deduplication() {
    let mut set = BTreeSet::new();
    set.insert(make_boundary("a", "b", "c", Some(1)));
    set.insert(make_boundary("a", "b", "c", Some(1)));
    assert_eq!(set.len(), 1, "identical boundary points should deduplicate");
    set.insert(make_boundary("a", "b", "c", Some(2)));
    assert_eq!(set.len(), 2, "different line_hint means different boundary");
}

// ---------------------------------------------------------------------------
// FlatteningOccurrence construction and content hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_occurrence_new_sets_all_fields() {
    let bp = make_boundary("mod_src", "mod_tgt", "api_fn", Some(77));
    let occ = FlatteningOccurrence::new(
        "OCC-FULL".to_string(),
        SemanticDomain::EvidenceLink,
        bp.clone(),
        TranslationKind::Translated,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Medium,
        "Evidence link format changed".to_string(),
        "Normalize format".to_string(),
        "bd-ev-001".to_string(),
    );
    assert_eq!(occ.id, "OCC-FULL");
    assert_eq!(occ.domain, SemanticDomain::EvidenceLink);
    assert_eq!(occ.boundary, bp);
    assert_eq!(occ.translation_kind, TranslationKind::Translated);
    assert_eq!(occ.classification, FlatteningClassification::AcceptableEdge);
    assert_eq!(occ.severity, FlatteningSeverity::Medium);
    assert_eq!(occ.description, "Evidence link format changed");
    assert_eq!(occ.remediation, "Normalize format");
    assert_eq!(occ.remediation_bead, "bd-ev-001");
    assert_ne!(occ.content_hash, ContentHash::default());
}

#[test]
fn enrichment_hash_occurrence_content_hash_matches_static_computation() {
    let bp = make_boundary("s", "t", "a", Some(10));
    let occ = FlatteningOccurrence::new(
        "MATCH-HASH".to_string(),
        SemanticDomain::PolicyId,
        bp.clone(),
        TranslationKind::Narrowed,
        FlatteningClassification::Intentional,
        FlatteningSeverity::Low,
        "desc".to_string(),
        "rem".to_string(),
        "bd-x".to_string(),
    );
    let expected = FlatteningOccurrence::compute_content_hash(
        "MATCH-HASH",
        SemanticDomain::PolicyId,
        &bp,
        TranslationKind::Narrowed,
        FlatteningClassification::Intentional,
    );
    assert_eq!(occ.content_hash, expected);
}

#[test]
fn enrichment_hash_different_boundaries_produce_different_hashes() {
    let bp1 = make_boundary("alpha", "beta", "call", None);
    let bp2 = make_boundary("gamma", "delta", "call", None);
    let h1 = FlatteningOccurrence::compute_content_hash(
        "id",
        SemanticDomain::Budget,
        &bp1,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
    );
    let h2 = FlatteningOccurrence::compute_content_hash(
        "id",
        SemanticDomain::Budget,
        &bp2,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
    );
    assert_ne!(h1, h2, "different boundaries must produce different hashes");
}

#[test]
fn enrichment_hash_line_hint_none_vs_some_zero() {
    let bp_none = make_boundary("s", "t", "a", None);
    let bp_zero = make_boundary("s", "t", "a", Some(0));
    let h1 = FlatteningOccurrence::compute_content_hash(
        "id",
        SemanticDomain::Budget,
        &bp_none,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
    );
    let h2 = FlatteningOccurrence::compute_content_hash(
        "id",
        SemanticDomain::Budget,
        &bp_zero,
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
    );
    assert_ne!(h1, h2, "None vs Some(0) should produce different hashes");
}

#[test]
fn enrichment_hash_occurrence_determinism_across_constructions() {
    let make = || {
        FlatteningOccurrence::new(
            "DETER".to_string(),
            SemanticDomain::DecisionId,
            make_boundary("x", "y", "z", Some(5)),
            TranslationKind::Widened,
            FlatteningClassification::MustFix,
            FlatteningSeverity::Critical,
            "decision widened".to_string(),
            "narrow it".to_string(),
            "bd-dec-001".to_string(),
        )
    };
    let a = make();
    let b = make();
    let c = make();
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(b.content_hash, c.content_hash);
}

// ---------------------------------------------------------------------------
// FlatteningOccurrence Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_occurrence_format_all_parts() {
    let occ = FlatteningOccurrence::new(
        "DISP-FULL".to_string(),
        SemanticDomain::SchemaVersion,
        make_boundary("schema_mgr", "validator", "validate_schema", Some(200)),
        TranslationKind::Dropped,
        FlatteningClassification::MustFix,
        FlatteningSeverity::Critical,
        "Schema version dropped at validation boundary".to_string(),
        "Pass schema version through".to_string(),
        "bd-sv-001".to_string(),
    );
    let s = format!("{occ}");
    assert!(s.contains("[DISP-FULL]"));
    assert!(s.contains("Critical"));
    assert!(s.contains("MustFix"));
    assert!(s.contains("Dropped"));
    assert!(s.contains("schema_mgr"));
    assert!(s.contains("validator"));
    assert!(s.contains("line 200"));
    assert!(s.contains("Schema version dropped"));
}

#[test]
fn enrichment_serde_occurrence_pretty_json_roundtrip() {
    let occ = make_occurrence_full(
        "PRETTY-1",
        SemanticDomain::TraceId,
        make_boundary("tracer", "logger", "log_trace", None),
        TranslationKind::Translated,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Low,
    );
    let pretty = serde_json::to_string_pretty(&occ).unwrap();
    let back: FlatteningOccurrence = serde_json::from_str(&pretty).unwrap();
    assert_eq!(occ, back);
}

#[test]
fn enrichment_serde_occurrence_json_contains_all_fields() {
    let occ = sample_occurrence("FIELD-CHECK");
    let val: serde_json::Value = serde_json::to_value(&occ).unwrap();
    assert!(val.get("id").is_some());
    assert!(val.get("domain").is_some());
    assert!(val.get("boundary").is_some());
    assert!(val.get("translation_kind").is_some());
    assert!(val.get("classification").is_some());
    assert!(val.get("severity").is_some());
    assert!(val.get("description").is_some());
    assert!(val.get("remediation").is_some());
    assert!(val.get("remediation_bead").is_some());
    assert!(val.get("content_hash").is_some());
}

// ---------------------------------------------------------------------------
// FlatteningInventory lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_inventory_add_preserves_insertion_order() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(1));
    for i in 0..10 {
        inv.add(sample_occurrence(&format!("ORD-{i}")));
    }
    for (i, occ) in inv.occurrences.iter().enumerate() {
        assert_eq!(
            occ.id,
            format!("ORD-{i}"),
            "insertion order not preserved at index {i}"
        );
    }
}

#[test]
fn enrichment_lifecycle_inventory_schema_version_is_constant() {
    let inv = FlatteningInventory::new(SecurityEpoch::from_raw(999));
    assert_eq!(inv.schema_version, FLATTENING_SCHEMA_VERSION);
}

#[test]
fn enrichment_lifecycle_inventory_epoch_preserved() {
    for raw in [0, 1, 42, 1000, u64::MAX] {
        let inv = FlatteningInventory::new(SecurityEpoch::from_raw(raw));
        assert_eq!(inv.assessed_epoch, SecurityEpoch::from_raw(raw));
    }
}

// ---------------------------------------------------------------------------
// FlatteningInventory filtering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_filter_must_fix_multiple_classifications() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let classifications = [
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
        FlatteningClassification::MustFix,
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
    ];
    for (i, cls) in classifications.iter().enumerate() {
        inv.add(make_occurrence_full(
            &format!("CLS-{i}"),
            SemanticDomain::Budget,
            sample_boundary(),
            TranslationKind::Collapsed,
            *cls,
            FlatteningSeverity::High,
        ));
    }
    let must_fix = inv.must_fix_items();
    assert_eq!(must_fix.len(), 3);
    assert_eq!(must_fix[0].id, "CLS-1");
    assert_eq!(must_fix[1].id, "CLS-4");
    assert_eq!(must_fix[2].id, "CLS-6");
}

#[test]
fn enrichment_filter_by_domain_multiple_per_domain() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    for i in 0..15 {
        let domain = if i < 5 {
            SemanticDomain::Outcome
        } else if i < 12 {
            SemanticDomain::Capability
        } else {
            SemanticDomain::Diagnostics
        };
        inv.add(make_occurrence_full(
            &format!("MPD-{i}"),
            domain,
            sample_boundary(),
            TranslationKind::Narrowed,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
        ));
    }
    assert_eq!(inv.by_domain(SemanticDomain::Outcome).len(), 5);
    assert_eq!(inv.by_domain(SemanticDomain::Capability).len(), 7);
    assert_eq!(inv.by_domain(SemanticDomain::Diagnostics).len(), 3);
    assert_eq!(inv.by_domain(SemanticDomain::Budget).len(), 0);
}

#[test]
fn enrichment_filter_by_severity_all_five_levels() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(10));
    let severities = [
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
        FlatteningSeverity::Medium,
        FlatteningSeverity::Low,
        FlatteningSeverity::Info,
    ];
    for (i, sev) in severities.iter().enumerate() {
        for j in 0..=i {
            inv.add(make_occurrence_full(
                &format!("SEV-{i}-{j}"),
                SemanticDomain::Budget,
                sample_boundary(),
                TranslationKind::Preserved,
                FlatteningClassification::Intentional,
                *sev,
            ));
        }
    }
    // Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5
    assert_eq!(inv.by_severity(FlatteningSeverity::Critical).len(), 1);
    assert_eq!(inv.by_severity(FlatteningSeverity::High).len(), 2);
    assert_eq!(inv.by_severity(FlatteningSeverity::Medium).len(), 3);
    assert_eq!(inv.by_severity(FlatteningSeverity::Low).len(), 4);
    assert_eq!(inv.by_severity(FlatteningSeverity::Info).len(), 5);
}

// ---------------------------------------------------------------------------
// FlatteningInventory summary invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arithmetic_summary_classification_counts_sum_to_total() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(2));
    let classifications = [
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
        FlatteningClassification::MustFix,
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
        FlatteningClassification::FalsePositive,
        FlatteningClassification::Intentional,
    ];
    for (i, cls) in classifications.iter().enumerate() {
        inv.add(make_occurrence_full(
            &format!("SUM-{i}"),
            SemanticDomain::Budget,
            sample_boundary(),
            TranslationKind::Collapsed,
            *cls,
            FlatteningSeverity::Medium,
        ));
    }
    let s = inv.summary();
    assert_eq!(
        s.must_fix + s.intentional + s.acceptable + s.false_positive,
        s.total,
        "classification counts must sum to total"
    );
}

#[test]
fn enrichment_arithmetic_summary_by_domain_values_sum_to_total() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let domains = [
        SemanticDomain::Budget,
        SemanticDomain::Outcome,
        SemanticDomain::Capability,
        SemanticDomain::Budget,
        SemanticDomain::Outcome,
        SemanticDomain::Budget,
    ];
    for (i, d) in domains.iter().enumerate() {
        inv.add(make_occurrence_full(
            &format!("BD-{i}"),
            *d,
            sample_boundary(),
            TranslationKind::Narrowed,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
        ));
    }
    let s = inv.summary();
    let domain_sum: usize = s.by_domain.values().sum();
    assert_eq!(domain_sum, s.total, "by_domain values must sum to total");
}

#[test]
fn enrichment_arithmetic_summary_by_severity_values_sum_to_total() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let severities = [
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
        FlatteningSeverity::Medium,
        FlatteningSeverity::Low,
        FlatteningSeverity::Info,
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
    ];
    for (i, sev) in severities.iter().enumerate() {
        inv.add(make_occurrence_full(
            &format!("BSEV-{i}"),
            SemanticDomain::Budget,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            *sev,
        ));
    }
    let s = inv.summary();
    let severity_sum: usize = s.by_severity.values().sum();
    assert_eq!(
        severity_sum, s.total,
        "by_severity values must sum to total"
    );
}

#[test]
fn enrichment_arithmetic_summary_by_domain_uses_display_keys() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(make_occurrence_full(
        "KEY-1",
        SemanticDomain::EvidenceLink,
        sample_boundary(),
        TranslationKind::Dropped,
        FlatteningClassification::MustFix,
        FlatteningSeverity::Critical,
    ));
    inv.add(make_occurrence_full(
        "KEY-2",
        SemanticDomain::SchemaVersion,
        sample_boundary(),
        TranslationKind::Translated,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Low,
    ));
    let s = inv.summary();
    assert!(s.by_domain.contains_key("EvidenceLink"));
    assert!(s.by_domain.contains_key("SchemaVersion"));
}

#[test]
fn enrichment_arithmetic_summary_by_severity_uses_display_keys() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv.add(make_occurrence_full(
        "SKEY-1",
        SemanticDomain::Budget,
        sample_boundary(),
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
        FlatteningSeverity::Critical,
    ));
    inv.add(make_occurrence_full(
        "SKEY-2",
        SemanticDomain::Budget,
        sample_boundary(),
        TranslationKind::Preserved,
        FlatteningClassification::Intentional,
        FlatteningSeverity::Info,
    ));
    let s = inv.summary();
    assert!(s.by_severity.contains_key("Critical"));
    assert!(s.by_severity.contains_key("Info"));
}

// ---------------------------------------------------------------------------
// FlatteningInventory content hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_inventory_empty_at_different_epochs_differ() {
    let inv1 = FlatteningInventory::new(SecurityEpoch::from_raw(100));
    let inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(200));
    assert_ne!(
        inv1.content_hash(),
        inv2.content_hash(),
        "empty inventories at different epochs must hash differently"
    );
}

#[test]
fn enrichment_hash_inventory_order_sensitive() {
    let mut inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv1.add(sample_occurrence("FIRST"));
    inv1.add(sample_occurrence("SECOND"));

    let mut inv2 = FlatteningInventory::new(SecurityEpoch::GENESIS);
    inv2.add(sample_occurrence("SECOND"));
    inv2.add(sample_occurrence("FIRST"));

    assert_ne!(
        inv1.content_hash(),
        inv2.content_hash(),
        "order of occurrences must affect inventory hash"
    );
}

#[test]
fn enrichment_hash_inventory_grows_with_addition() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(5));
    let h0 = inv.content_hash();
    inv.add(sample_occurrence("G-1"));
    let h1 = inv.content_hash();
    inv.add(sample_occurrence("G-2"));
    let h2 = inv.content_hash();
    // All three hashes should be distinct
    let mut hashes = BTreeSet::new();
    hashes.insert(format!("{h0:?}"));
    hashes.insert(format!("{h1:?}"));
    hashes.insert(format!("{h2:?}"));
    assert_eq!(hashes.len(), 3, "each addition should change the hash");
}

#[test]
fn enrichment_hash_inventory_determinism_with_mixed_occurrences() {
    let build = || {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(42));
        inv.add(make_occurrence_full(
            "MIX-1",
            SemanticDomain::PolicyId,
            make_boundary("pol", "enf", "apply", Some(10)),
            TranslationKind::Translated,
            FlatteningClassification::AcceptableEdge,
            FlatteningSeverity::Medium,
        ));
        inv.add(make_occurrence_full(
            "MIX-2",
            SemanticDomain::Diagnostics,
            make_boundary("diag", "ui", "render", None),
            TranslationKind::Dropped,
            FlatteningClassification::MustFix,
            FlatteningSeverity::High,
        ));
        inv
    };
    assert_eq!(build().content_hash(), build().content_hash());
}

// ---------------------------------------------------------------------------
// FlatteningInventory serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_inventory_full_roundtrip_with_diverse_items() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(77));
    inv.add(make_occurrence_full(
        "DIV-1",
        SemanticDomain::Budget,
        make_boundary("budget_mgr", "executor", "run", Some(1)),
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
        FlatteningSeverity::Critical,
    ));
    inv.add(make_occurrence_full(
        "DIV-2",
        SemanticDomain::Capability,
        make_boundary("cap_store", "policy_engine", "check_cap", None),
        TranslationKind::Widened,
        FlatteningClassification::MustFix,
        FlatteningSeverity::High,
    ));
    inv.add(make_occurrence_full(
        "DIV-3",
        SemanticDomain::SchemaVersion,
        make_boundary("schema_v2", "schema_v1", "downgrade", Some(500)),
        TranslationKind::Narrowed,
        FlatteningClassification::AcceptableEdge,
        FlatteningSeverity::Medium,
    ));
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
    assert_eq!(inv.content_hash(), back.content_hash());
    assert_eq!(inv.summary(), back.summary());
}

#[test]
fn enrichment_serde_summary_with_populated_maps() {
    let mut by_domain = BTreeMap::new();
    by_domain.insert("Budget".to_string(), 10);
    by_domain.insert("Outcome".to_string(), 5);
    by_domain.insert("Capability".to_string(), 3);
    let mut by_severity = BTreeMap::new();
    by_severity.insert("Critical".to_string(), 2);
    by_severity.insert("High".to_string(), 8);
    by_severity.insert("Medium".to_string(), 5);
    by_severity.insert("Low".to_string(), 3);
    let summary = FlatteningSummary {
        total: 18,
        must_fix: 4,
        intentional: 7,
        acceptable: 5,
        false_positive: 2,
        by_domain,
        by_severity,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: FlatteningSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// FlatteningInventory Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_inventory_contains_epoch_and_schema() {
    let inv = FlatteningInventory::new(SecurityEpoch::from_raw(55));
    let s = format!("{inv}");
    assert!(s.contains("FlatteningInventory"));
    assert!(s.contains("schema="));
    assert!(s.contains("epoch="));
    assert!(s.contains("count=0"));
}

#[test]
fn enrichment_display_summary_contains_all_classification_counts() {
    let summary = FlatteningSummary {
        total: 20,
        must_fix: 5,
        intentional: 8,
        acceptable: 4,
        false_positive: 3,
        by_domain: BTreeMap::new(),
        by_severity: BTreeMap::new(),
    };
    let s = format!("{summary}");
    assert!(s.contains("total=20"));
    assert!(s.contains("must_fix=5"));
    assert!(s.contains("intentional=8"));
    assert!(s.contains("acceptable=4"));
    assert!(s.contains("false_positive=3"));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_occurrence_with_unicode_strings() {
    let occ = FlatteningOccurrence::new(
        "UNI-\u{00e9}\u{00e8}\u{00ea}".to_string(),
        SemanticDomain::Diagnostics,
        make_boundary(
            "m\u{00f6}dule_\u{00e4}",
            "m\u{00fc}dule_\u{00f6}",
            "f\u{00fc}nktion",
            None,
        ),
        TranslationKind::Translated,
        FlatteningClassification::FalsePositive,
        FlatteningSeverity::Info,
        "Unicode description: \u{2603} snowman".to_string(),
        "No action needed".to_string(),
        String::new(),
    );
    let json = serde_json::to_string(&occ).unwrap();
    let back: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, back);
}

#[test]
fn enrichment_edge_occurrence_with_very_long_id() {
    let long_id: String = "X".repeat(10_000);
    let occ = sample_occurrence(&long_id);
    assert_eq!(occ.id.len(), 10_000);
    assert_ne!(occ.content_hash, ContentHash::default());
    // Serde roundtrip with large id
    let json = serde_json::to_string(&occ).unwrap();
    let back: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, back);
}

#[test]
fn enrichment_edge_inventory_genesis_epoch_hash_stable() {
    let inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
    let inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(0));
    assert_eq!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn enrichment_edge_summary_btreemap_keys_sorted() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
    // Add in reverse-alphabetical domain order
    let domains = [
        SemanticDomain::TraceId,
        SemanticDomain::SchemaVersion,
        SemanticDomain::Budget,
        SemanticDomain::Capability,
    ];
    for (i, d) in domains.iter().enumerate() {
        inv.add(make_occurrence_full(
            &format!("SORT-{i}"),
            *d,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
        ));
    }
    let s = inv.summary();
    let keys: Vec<&String> = s.by_domain.keys().collect();
    assert_eq!(
        keys,
        vec!["Budget", "Capability", "SchemaVersion", "TraceId"]
    );
}

#[test]
fn enrichment_edge_inventory_clone_equals_original() {
    let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(88));
    inv.add(sample_occurrence("CLN-1"));
    inv.add(sample_occurrence("CLN-2"));
    let cloned = inv.clone();
    assert_eq!(inv, cloned);
    assert_eq!(inv.content_hash(), cloned.content_hash());
    assert_eq!(inv.summary(), cloned.summary());
}

#[test]
fn enrichment_edge_constants_non_empty() {
    assert!(!FLATTENING_SCHEMA_VERSION.is_empty());
    assert!(!FLATTENING_BEAD_ID.is_empty());
    assert!(FLATTENING_SCHEMA_VERSION.contains("semantic-flattening"));
    assert!(FLATTENING_BEAD_ID.starts_with("bd-"));
}
