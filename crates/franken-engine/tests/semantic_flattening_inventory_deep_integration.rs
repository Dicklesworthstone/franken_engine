//! Deep integration tests for semantic_flattening_inventory module.
//!
//! Covers: inventory lifecycle, occurrence content-hash determinism,
//! classification/severity filtering, summary aggregation, serde roundtrips,
//! Display impls, and content-hash integrity verification.

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_flattening_inventory::{
    BoundaryPoint, FlatteningClassification, FlatteningInventory, FlatteningOccurrence,
    FlatteningSeverity, FlatteningSummary, SemanticDomain, TranslationKind,
    FLATTENING_BEAD_ID, FLATTENING_SCHEMA_VERSION,
};

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample_boundary(source: &str, target: &str, api: &str) -> BoundaryPoint {
    BoundaryPoint {
        source_module: source.to_string(),
        target_module: target.to_string(),
        api_surface: api.to_string(),
        line_hint: None,
    }
}

fn sample_boundary_with_line(source: &str, target: &str, api: &str, line: u32) -> BoundaryPoint {
    BoundaryPoint {
        source_module: source.to_string(),
        target_module: target.to_string(),
        api_surface: api.to_string(),
        line_hint: Some(line),
    }
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
        sample_boundary("module_a", "module_b", "transfer_fn"),
        kind,
        classification,
        severity,
        format!("Description for {id}"),
        format!("Remediation for {id}"),
        format!("bd-fix-{id}"),
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!FLATTENING_SCHEMA_VERSION.is_empty());
    assert!(!FLATTENING_BEAD_ID.is_empty());
    assert!(FLATTENING_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// SemanticDomain
// ---------------------------------------------------------------------------

#[test]
fn deep_semantic_domain_display_all() {
    let domains = [
        (SemanticDomain::Budget, "Budget"),
        (SemanticDomain::Outcome, "Outcome"),
        (SemanticDomain::Capability, "Capability"),
        (SemanticDomain::Severity, "Severity"),
        (SemanticDomain::Diagnostics, "Diagnostics"),
        (SemanticDomain::PolicyId, "PolicyId"),
        (SemanticDomain::TraceId, "TraceId"),
        (SemanticDomain::DecisionId, "DecisionId"),
        (SemanticDomain::EvidenceLink, "EvidenceLink"),
        (SemanticDomain::SchemaVersion, "SchemaVersion"),
    ];
    for (domain, expected) in domains {
        assert_eq!(format!("{domain}"), expected);
    }
}

#[test]
fn deep_semantic_domain_serde_roundtrip() {
    let domains = [
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
    for domain in domains {
        let json = serde_json::to_string(&domain).unwrap();
        let decoded: SemanticDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(domain, decoded);
    }
}

// ---------------------------------------------------------------------------
// TranslationKind
// ---------------------------------------------------------------------------

#[test]
fn deep_translation_kind_display_all() {
    let kinds = [
        (TranslationKind::Preserved, "Preserved"),
        (TranslationKind::Narrowed, "Narrowed"),
        (TranslationKind::Widened, "Widened"),
        (TranslationKind::Collapsed, "Collapsed"),
        (TranslationKind::Translated, "Translated"),
        (TranslationKind::Dropped, "Dropped"),
    ];
    for (kind, expected) in kinds {
        assert_eq!(format!("{kind}"), expected);
    }
}

#[test]
fn deep_translation_kind_serde_roundtrip() {
    let kinds = [
        TranslationKind::Preserved,
        TranslationKind::Narrowed,
        TranslationKind::Widened,
        TranslationKind::Collapsed,
        TranslationKind::Translated,
        TranslationKind::Dropped,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: TranslationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// FlatteningClassification
// ---------------------------------------------------------------------------

#[test]
fn deep_classification_serde_roundtrip() {
    let classes = [
        FlatteningClassification::Intentional,
        FlatteningClassification::MustFix,
        FlatteningClassification::AcceptableEdge,
        FlatteningClassification::FalsePositive,
    ];
    for class in classes {
        let json = serde_json::to_string(&class).unwrap();
        let decoded: FlatteningClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(class, decoded);
    }
}

// ---------------------------------------------------------------------------
// FlatteningSeverity
// ---------------------------------------------------------------------------

#[test]
fn deep_severity_serde_roundtrip() {
    let severities = [
        FlatteningSeverity::Critical,
        FlatteningSeverity::High,
        FlatteningSeverity::Medium,
        FlatteningSeverity::Low,
        FlatteningSeverity::Info,
    ];
    for sev in severities {
        let json = serde_json::to_string(&sev).unwrap();
        let decoded: FlatteningSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, decoded);
    }
}

// ---------------------------------------------------------------------------
// BoundaryPoint
// ---------------------------------------------------------------------------

#[test]
fn deep_boundary_display_without_line() {
    let bp = sample_boundary("source_mod", "target_mod", "api_fn");
    let display = format!("{bp}");
    assert!(display.contains("source_mod"));
    assert!(display.contains("target_mod"));
    assert!(display.contains("api_fn"));
    assert!(!display.contains("line"));
}

#[test]
fn deep_boundary_display_with_line() {
    let bp = sample_boundary_with_line("source", "target", "api", 42);
    let display = format!("{bp}");
    assert!(display.contains("line 42"));
}

#[test]
fn deep_boundary_serde_roundtrip() {
    let bp = sample_boundary_with_line("source", "target", "api", 100);
    let json = serde_json::to_string(&bp).unwrap();
    let decoded: BoundaryPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, decoded);
}

#[test]
fn deep_boundary_serde_roundtrip_no_line() {
    let bp = sample_boundary("source", "target", "api");
    let json = serde_json::to_string(&bp).unwrap();
    let decoded: BoundaryPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, decoded);
    assert_eq!(decoded.line_hint, None);
}

// ---------------------------------------------------------------------------
// FlatteningOccurrence
// ---------------------------------------------------------------------------

#[test]
fn deep_occurrence_content_hash_deterministic() {
    let o1 = make_occurrence("test-1", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    let o2 = make_occurrence("test-1", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    assert_eq!(o1.content_hash, o2.content_hash);
}

#[test]
fn deep_occurrence_content_hash_changes_on_id() {
    let o1 = make_occurrence("id-a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    let o2 = make_occurrence("id-b", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn deep_occurrence_content_hash_changes_on_domain() {
    let o1 = make_occurrence("test", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    let o2 = make_occurrence("test", SemanticDomain::Capability, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn deep_occurrence_content_hash_changes_on_translation() {
    let o1 = make_occurrence("test", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    let o2 = make_occurrence("test", SemanticDomain::Budget, TranslationKind::Dropped, FlatteningClassification::MustFix, FlatteningSeverity::High);
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn deep_occurrence_content_hash_changes_on_classification() {
    let o1 = make_occurrence("test", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High);
    let o2 = make_occurrence("test", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::Intentional, FlatteningSeverity::High);
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn deep_occurrence_display() {
    let occ = make_occurrence("occ-1", SemanticDomain::Outcome, TranslationKind::Narrowed, FlatteningClassification::AcceptableEdge, FlatteningSeverity::Medium);
    let display = format!("{occ}");
    assert!(display.contains("[occ-1]"));
    assert!(display.contains("Medium"));
    assert!(display.contains("AcceptableEdge"));
    assert!(display.contains("Narrowed"));
}

#[test]
fn deep_occurrence_serde_roundtrip() {
    let occ = make_occurrence("serde-test", SemanticDomain::PolicyId, TranslationKind::Translated, FlatteningClassification::Intentional, FlatteningSeverity::Info);
    let json = serde_json::to_string(&occ).unwrap();
    let decoded: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, decoded);
}

// ---------------------------------------------------------------------------
// FlatteningInventory
// ---------------------------------------------------------------------------

#[test]
fn deep_inventory_new_empty() {
    let inv = FlatteningInventory::new(epoch(1));
    assert_eq!(inv.occurrences.len(), 0);
    assert_eq!(inv.schema_version, FLATTENING_SCHEMA_VERSION);
    assert_eq!(inv.assessed_epoch, epoch(1));
}

#[test]
fn deep_inventory_add_and_query() {
    let mut inv = FlatteningInventory::new(epoch(1));
    inv.add(make_occurrence("a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));
    inv.add(make_occurrence("b", SemanticDomain::Capability, TranslationKind::Widened, FlatteningClassification::MustFix, FlatteningSeverity::Critical));
    inv.add(make_occurrence("c", SemanticDomain::Budget, TranslationKind::Preserved, FlatteningClassification::Intentional, FlatteningSeverity::Info));

    assert_eq!(inv.occurrences.len(), 3);
    assert_eq!(inv.must_fix_items().len(), 2);
    assert_eq!(inv.by_domain(SemanticDomain::Budget).len(), 2);
    assert_eq!(inv.by_domain(SemanticDomain::Capability).len(), 1);
    assert_eq!(inv.by_severity(FlatteningSeverity::Critical).len(), 1);
    assert_eq!(inv.by_severity(FlatteningSeverity::Info).len(), 1);
}

#[test]
fn deep_inventory_summary_counts() {
    let mut inv = FlatteningInventory::new(epoch(2));
    inv.add(make_occurrence("1", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));
    inv.add(make_occurrence("2", SemanticDomain::Outcome, TranslationKind::Narrowed, FlatteningClassification::Intentional, FlatteningSeverity::Low));
    inv.add(make_occurrence("3", SemanticDomain::Capability, TranslationKind::Widened, FlatteningClassification::AcceptableEdge, FlatteningSeverity::Medium));
    inv.add(make_occurrence("4", SemanticDomain::Severity, TranslationKind::Dropped, FlatteningClassification::FalsePositive, FlatteningSeverity::Info));

    let summary = inv.summary();
    assert_eq!(summary.total, 4);
    assert_eq!(summary.must_fix, 1);
    assert_eq!(summary.intentional, 1);
    assert_eq!(summary.acceptable, 1);
    assert_eq!(summary.false_positive, 1);
    assert_eq!(*summary.by_domain.get("Budget").unwrap_or(&0), 1);
    assert_eq!(*summary.by_domain.get("Outcome").unwrap_or(&0), 1);
    assert_eq!(*summary.by_severity.get("High").unwrap_or(&0), 1);
    assert_eq!(*summary.by_severity.get("Info").unwrap_or(&0), 1);
}

#[test]
fn deep_inventory_summary_empty() {
    let inv = FlatteningInventory::new(epoch(3));
    let summary = inv.summary();
    assert_eq!(summary.total, 0);
    assert_eq!(summary.must_fix, 0);
    assert!(summary.by_domain.is_empty());
}

#[test]
fn deep_inventory_content_hash_deterministic() {
    let build = || {
        let mut inv = FlatteningInventory::new(epoch(1));
        inv.add(make_occurrence("a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));
        inv.add(make_occurrence("b", SemanticDomain::Outcome, TranslationKind::Narrowed, FlatteningClassification::Intentional, FlatteningSeverity::Low));
        inv.content_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn deep_inventory_content_hash_changes_on_different_occurrences() {
    let mut inv1 = FlatteningInventory::new(epoch(1));
    inv1.add(make_occurrence("a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));

    let mut inv2 = FlatteningInventory::new(epoch(1));
    inv2.add(make_occurrence("b", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));

    assert_ne!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn deep_inventory_content_hash_changes_on_epoch() {
    let mut inv1 = FlatteningInventory::new(epoch(1));
    inv1.add(make_occurrence("a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));

    let mut inv2 = FlatteningInventory::new(epoch(2));
    inv2.add(make_occurrence("a", SemanticDomain::Budget, TranslationKind::Collapsed, FlatteningClassification::MustFix, FlatteningSeverity::High));

    assert_ne!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn deep_inventory_display() {
    let inv = FlatteningInventory::new(epoch(5));
    let display = format!("{inv}");
    assert!(display.contains("FlatteningInventory"));
    assert!(display.contains("count=0"));
}

#[test]
fn deep_inventory_serde_roundtrip() {
    let mut inv = FlatteningInventory::new(epoch(7));
    inv.add(make_occurrence("s1", SemanticDomain::TraceId, TranslationKind::Preserved, FlatteningClassification::Intentional, FlatteningSeverity::Info));
    inv.add(make_occurrence("s2", SemanticDomain::DecisionId, TranslationKind::Translated, FlatteningClassification::AcceptableEdge, FlatteningSeverity::Low));

    let json = serde_json::to_string(&inv).unwrap();
    let decoded: FlatteningInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, decoded);
}

// ---------------------------------------------------------------------------
// FlatteningSummary
// ---------------------------------------------------------------------------

#[test]
fn deep_summary_display() {
    let summary = FlatteningSummary {
        total: 10,
        must_fix: 2,
        intentional: 5,
        acceptable: 2,
        false_positive: 1,
        by_domain: std::collections::BTreeMap::new(),
        by_severity: std::collections::BTreeMap::new(),
    };
    let display = format!("{summary}");
    assert!(display.contains("total=10"));
    assert!(display.contains("must_fix=2"));
}

#[test]
fn deep_summary_serde_roundtrip() {
    let mut by_domain = std::collections::BTreeMap::new();
    by_domain.insert("Budget".to_string(), 3usize);
    by_domain.insert("Outcome".to_string(), 2);

    let summary = FlatteningSummary {
        total: 5,
        must_fix: 1,
        intentional: 2,
        acceptable: 1,
        false_positive: 1,
        by_domain,
        by_severity: std::collections::BTreeMap::new(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let decoded: FlatteningSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, decoded);
}

// ---------------------------------------------------------------------------
// Occurrence with line_hint affects content hash
// ---------------------------------------------------------------------------

#[test]
fn deep_occurrence_line_hint_affects_hash() {
    let boundary_no_line = sample_boundary("a", "b", "fn");
    let boundary_with_line = sample_boundary_with_line("a", "b", "fn", 42);

    let hash1 = FlatteningOccurrence::compute_content_hash(
        "test",
        SemanticDomain::Budget,
        &boundary_no_line,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
    );
    let hash2 = FlatteningOccurrence::compute_content_hash(
        "test",
        SemanticDomain::Budget,
        &boundary_with_line,
        TranslationKind::Collapsed,
        FlatteningClassification::MustFix,
    );
    assert_ne!(hash1, hash2);
}
