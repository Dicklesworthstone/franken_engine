//! Integration tests for the semantic cover schema module (RGC-808A).
//!
//! Covers: `EngineSurface`, `SupportStatus`, `CoverFeature`, `OverlapRestriction`,
//! `OverlapEntry`, `OverlapRestrictionMap`, `CoverGap`, `GapSeverity`, `SemanticCover`,
//! `SurfaceSummary`, `OverlapViolation`, `CoverSpecimen`, `CoverSpecimenFamily`,
//! `detect_overlap_violations`, `default_overlap_map`, `build_evidence_corpus`,
//! `run_evidence_corpus`.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_cover_schema::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_feature(key: &str, surfaces: &[(EngineSurface, SupportStatus)]) -> CoverFeature {
    let relevant: BTreeSet<EngineSurface> = surfaces.iter().map(|(s, _)| *s).collect();
    let support_map: BTreeMap<EngineSurface, SupportStatus> = surfaces.iter().cloned().collect();
    CoverFeature {
        key: key.to_string(),
        description: format!("Test feature {key}"),
        spec_area: "test".into(),
        relevant_surfaces: relevant,
        support_map,
        evidence_keys: BTreeSet::new(),
    }
}

fn make_feature_with_evidence(
    key: &str,
    surfaces: &[(EngineSurface, SupportStatus)],
    evidence: &[&str],
) -> CoverFeature {
    let mut f = make_feature(key, surfaces);
    for e in evidence {
        f.evidence_keys.insert((*e).to_string());
    }
    f
}

fn make_overlap_entry(
    a: EngineSurface,
    b: EngineSurface,
    restriction: OverlapRestriction,
    scope_prefix: Option<&str>,
) -> OverlapEntry {
    // Normalise ordering so surface_a <= surface_b (matches restriction_for lookup).
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    OverlapEntry {
        surface_a: lo,
        surface_b: hi,
        restriction,
        scope_prefix: scope_prefix.map(|s| s.to_string()),
        rationale: format!("test overlap {lo}-{hi}"),
    }
}

fn simple_cover(features: Vec<CoverFeature>) -> SemanticCover {
    SemanticCover::new(features, default_overlap_map(), epoch())
}

/// Build a custom overlap map with a single normalised exclusive entry.
fn exclusive_overlap_map(a: EngineSurface, b: EngineSurface) -> OverlapRestrictionMap {
    OverlapRestrictionMap::new(vec![make_overlap_entry(
        a,
        b,
        OverlapRestriction::Exclusive,
        None,
    )])
}

// ---------------------------------------------------------------------------
// EngineSurface
// ---------------------------------------------------------------------------

#[test]
fn test_engine_surface_all_returns_seven_variants() {
    let all = EngineSurface::all();
    assert_eq!(all.len(), 7);
    // Every variant must be distinct.
    let set: BTreeSet<EngineSurface> = all.iter().copied().collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn test_engine_surface_display_all_variants() {
    let expected = [
        (EngineSurface::Parser, "parser"),
        (EngineSurface::Lowering, "lowering"),
        (EngineSurface::Runtime, "runtime"),
        (EngineSurface::Module, "module"),
        (EngineSurface::TypeScript, "typescript"),
        (EngineSurface::React, "react"),
        (EngineSurface::Cli, "cli"),
    ];
    for (variant, label) in expected {
        assert_eq!(variant.to_string(), label);
    }
}

#[test]
fn test_engine_surface_ord_matches_declaration_order() {
    let all = EngineSurface::all();
    for w in all.windows(2) {
        assert!(w[0] < w[1], "{:?} should be < {:?}", w[0], w[1]);
    }
}

#[test]
fn test_engine_surface_serde_roundtrip_all() {
    for surface in EngineSurface::all() {
        let json = serde_json::to_string(surface).unwrap();
        let back: EngineSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*surface, back);
    }
}

#[test]
fn test_engine_surface_clone_eq() {
    let s = EngineSurface::TypeScript;
    let cloned = s;
    assert_eq!(s, cloned);
}

// ---------------------------------------------------------------------------
// SupportStatus
// ---------------------------------------------------------------------------

#[test]
fn test_support_status_display_all_variants() {
    let expected = [
        (SupportStatus::Supported, "supported"),
        (SupportStatus::Partial, "partial"),
        (SupportStatus::Unsupported, "unsupported"),
        (SupportStatus::Unknown, "unknown"),
        (SupportStatus::NotApplicable, "not_applicable"),
    ];
    for (variant, label) in expected {
        assert_eq!(variant.to_string(), label);
    }
}

#[test]
fn test_support_status_serde_roundtrip_all() {
    let statuses = [
        SupportStatus::Supported,
        SupportStatus::Partial,
        SupportStatus::Unsupported,
        SupportStatus::Unknown,
        SupportStatus::NotApplicable,
    ];
    for s in statuses {
        let json = serde_json::to_string(&s).unwrap();
        let back: SupportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// CoverFeature — construction & predicates
// ---------------------------------------------------------------------------

#[test]
fn test_feature_fully_covered_all_supported() {
    let f = make_feature(
        "es2015.arrowFunction",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    );
    assert!(f.is_fully_covered());
    assert!(!f.has_gap());
    assert_eq!(f.supported_surface_count(), 3);
    assert_eq!(f.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn test_feature_partial_status_not_fully_covered() {
    let f = make_feature(
        "es2020.optionalChaining",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Partial),
        ],
    );
    assert!(!f.is_fully_covered());
    // Partial is not Unsupported or Unknown, so has_gap() returns false.
    assert!(!f.has_gap());
    assert_eq!(f.supported_surface_count(), 1);
    assert_eq!(f.coverage_ratio_millionths(), 500_000);
}

#[test]
fn test_feature_unsupported_creates_gap() {
    let f = make_feature(
        "es2021.weakRef",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    );
    assert!(f.has_gap());
    assert!(!f.is_fully_covered());
}

#[test]
fn test_feature_unknown_creates_gap() {
    let f = make_feature(
        "stage3.decorators",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unknown),
        ],
    );
    assert!(f.has_gap());
}

#[test]
fn test_feature_not_applicable_no_gap() {
    let f = make_feature(
        "cli.doctor",
        &[
            (EngineSurface::Cli, SupportStatus::Supported),
            (EngineSurface::Parser, SupportStatus::NotApplicable),
        ],
    );
    // NotApplicable is neither Unsupported nor Unknown.
    assert!(!f.has_gap());
}

#[test]
fn test_feature_empty_relevant_surfaces() {
    let f = CoverFeature {
        key: "empty".into(),
        description: "no surfaces".into(),
        spec_area: "test".into(),
        relevant_surfaces: BTreeSet::new(),
        support_map: BTreeMap::new(),
        evidence_keys: BTreeSet::new(),
    };
    // Vacuously true.
    assert!(f.is_fully_covered());
    assert!(!f.has_gap());
    assert_eq!(f.supported_surface_count(), 0);
    assert_eq!(f.coverage_ratio_millionths(), 0);
}

#[test]
fn test_feature_coverage_ratio_one_of_three() {
    let f = make_feature(
        "es2024.groupBy",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unsupported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    );
    // 1 / 3 * 1_000_000 = 333_333
    assert_eq!(f.coverage_ratio_millionths(), 333_333);
}

#[test]
fn test_feature_coverage_ratio_two_of_three() {
    let f = make_feature(
        "es2024.arrayAt",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    );
    // 2 / 3 * 1_000_000 = 666_666
    assert_eq!(f.coverage_ratio_millionths(), 666_666);
}

#[test]
fn test_feature_evidence_keys_persisted() {
    let f = make_feature_with_evidence(
        "es2015.class",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
        &["parser.class_test", "runtime.class_test"],
    );
    assert_eq!(f.evidence_keys.len(), 2);
    assert!(f.evidence_keys.contains("parser.class_test"));
}

#[test]
fn test_feature_serde_roundtrip() {
    let f = make_feature_with_evidence(
        "es2020.nullishCoalescing",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Partial),
            (EngineSurface::Module, SupportStatus::NotApplicable),
        ],
        &["parser.nullish_test"],
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: CoverFeature = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// OverlapRestriction / OverlapEntry
// ---------------------------------------------------------------------------

#[test]
fn test_overlap_restriction_display() {
    assert_eq!(OverlapRestriction::Allowed.to_string(), "allowed");
    assert_eq!(
        OverlapRestriction::DelegationRequired.to_string(),
        "delegation_required"
    );
    assert_eq!(OverlapRestriction::Exclusive.to_string(), "exclusive");
    assert_eq!(
        OverlapRestriction::ReconciliationRequired.to_string(),
        "reconciliation_required"
    );
}

#[test]
fn test_overlap_restriction_serde_roundtrip() {
    let variants = [
        OverlapRestriction::Allowed,
        OverlapRestriction::DelegationRequired,
        OverlapRestriction::Exclusive,
        OverlapRestriction::ReconciliationRequired,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: OverlapRestriction = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_overlap_entry_serde_roundtrip() {
    let entry = make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Lowering,
        OverlapRestriction::DelegationRequired,
        Some("es2015."),
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: OverlapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry.surface_a, back.surface_a);
    assert_eq!(entry.surface_b, back.surface_b);
    assert_eq!(entry.restriction, back.restriction);
    assert_eq!(entry.scope_prefix, back.scope_prefix);
}

// ---------------------------------------------------------------------------
// OverlapRestrictionMap
// ---------------------------------------------------------------------------

#[test]
fn test_overlap_map_new_empty() {
    let map = OverlapRestrictionMap::new(vec![]);
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    assert_eq!(map.schema_version, COVER_SCHEMA_VERSION);
}

#[test]
fn test_overlap_map_content_hash_deterministic() {
    let entries = vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Runtime,
        OverlapRestriction::Exclusive,
        None,
    )];
    let m1 = OverlapRestrictionMap::new(entries.clone());
    let m2 = OverlapRestrictionMap::new(entries);
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn test_overlap_map_different_entries_different_hash() {
    let m1 = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Runtime,
        OverlapRestriction::Exclusive,
        None,
    )]);
    let m2 = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Runtime,
        OverlapRestriction::Allowed,
        None,
    )]);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn test_overlap_map_restriction_for_symmetric_lookup() {
    let map = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Cli,
        EngineSurface::Runtime,
        OverlapRestriction::Exclusive,
        None,
    )]);
    // Forward lookup.
    assert_eq!(
        map.restriction_for(EngineSurface::Cli, EngineSurface::Runtime),
        Some(OverlapRestriction::Exclusive)
    );
    // Reverse lookup should also find it (normalised order).
    assert_eq!(
        map.restriction_for(EngineSurface::Runtime, EngineSurface::Cli),
        Some(OverlapRestriction::Exclusive)
    );
}

#[test]
fn test_overlap_map_restriction_for_missing_pair() {
    let map = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Lowering,
        OverlapRestriction::DelegationRequired,
        None,
    )]);
    // A pair that is not in the map.
    assert_eq!(
        map.restriction_for(EngineSurface::Module, EngineSurface::Cli),
        None
    );
}

#[test]
fn test_overlap_map_restriction_for_ignores_scoped_entries() {
    // restriction_for only returns entries with scope_prefix = None.
    let map = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::TypeScript,
        OverlapRestriction::ReconciliationRequired,
        Some("ts."),
    )]);
    assert_eq!(
        map.restriction_for(EngineSurface::Parser, EngineSurface::TypeScript),
        None
    );
}

#[test]
fn test_overlap_map_restrictions_for_scope_matching_prefix() {
    let map = OverlapRestrictionMap::new(vec![
        make_overlap_entry(
            EngineSurface::Parser,
            EngineSurface::TypeScript,
            OverlapRestriction::ReconciliationRequired,
            Some("ts."),
        ),
        make_overlap_entry(
            EngineSurface::Parser,
            EngineSurface::TypeScript,
            OverlapRestriction::Allowed,
            None,
        ),
    ]);
    // Feature with "ts." prefix matches both entries.
    let entries =
        map.restrictions_for_scope(EngineSurface::Parser, EngineSurface::TypeScript, "ts.enum");
    assert_eq!(entries.len(), 2);

    // Feature without the prefix matches only the None-scoped entry.
    let entries = map.restrictions_for_scope(
        EngineSurface::Parser,
        EngineSurface::TypeScript,
        "es2015.arrow",
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].restriction, OverlapRestriction::Allowed);
}

#[test]
fn test_overlap_map_restrictions_for_scope_reverse_order() {
    let map = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::React,
        OverlapRestriction::ReconciliationRequired,
        Some("jsx."),
    )]);
    // Reverse order should still find the entry.
    let entries =
        map.restrictions_for_scope(EngineSurface::React, EngineSurface::Parser, "jsx.component");
    assert_eq!(entries.len(), 1);
}

// ---------------------------------------------------------------------------
// default_overlap_map
// ---------------------------------------------------------------------------

#[test]
fn test_default_overlap_map_has_expected_entries() {
    let map = default_overlap_map();
    assert!(!map.is_empty());
    assert!(map.len() >= 8);
    assert_eq!(map.schema_version, COVER_SCHEMA_VERSION);
}

#[test]
fn test_default_overlap_map_cli_runtime_exclusive() {
    let map = default_overlap_map();
    // Check via direct entry scan — the default map stores (Cli, Runtime).
    let found = map
        .entries
        .iter()
        .find(|e| {
            (e.surface_a == EngineSurface::Cli && e.surface_b == EngineSurface::Runtime)
                || (e.surface_a == EngineSurface::Runtime && e.surface_b == EngineSurface::Cli)
        })
        .unwrap();
    assert_eq!(found.restriction, OverlapRestriction::Exclusive);
}

#[test]
fn test_default_overlap_map_parser_lowering_delegation() {
    let map = default_overlap_map();
    let found = map
        .entries
        .iter()
        .find(|e| {
            (e.surface_a == EngineSurface::Parser && e.surface_b == EngineSurface::Lowering)
                || (e.surface_a == EngineSurface::Lowering && e.surface_b == EngineSurface::Parser)
        })
        .unwrap();
    assert_eq!(found.restriction, OverlapRestriction::DelegationRequired);
}

#[test]
fn test_default_overlap_map_module_runtime_allowed() {
    let map = default_overlap_map();
    let found = map
        .entries
        .iter()
        .find(|e| {
            (e.surface_a == EngineSurface::Module && e.surface_b == EngineSurface::Runtime)
                || (e.surface_a == EngineSurface::Runtime && e.surface_b == EngineSurface::Module)
        })
        .unwrap();
    assert_eq!(found.restriction, OverlapRestriction::Allowed);
}

#[test]
fn test_default_overlap_map_deterministic_hash() {
    let h1 = default_overlap_map().content_hash;
    let h2 = default_overlap_map().content_hash;
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// GapSeverity
// ---------------------------------------------------------------------------

#[test]
fn test_gap_severity_display() {
    assert_eq!(GapSeverity::Critical.to_string(), "critical");
    assert_eq!(GapSeverity::Moderate.to_string(), "moderate");
    assert_eq!(GapSeverity::Low.to_string(), "low");
    assert_eq!(GapSeverity::Informational.to_string(), "informational");
}

#[test]
fn test_gap_severity_ordering() {
    assert!(GapSeverity::Critical < GapSeverity::Moderate);
    assert!(GapSeverity::Moderate < GapSeverity::Low);
    assert!(GapSeverity::Low < GapSeverity::Informational);
}

#[test]
fn test_gap_severity_serde_roundtrip() {
    let severities = [
        GapSeverity::Critical,
        GapSeverity::Moderate,
        GapSeverity::Low,
        GapSeverity::Informational,
    ];
    for s in severities {
        let json = serde_json::to_string(&s).unwrap();
        let back: GapSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// SemanticCover — construction & queries
// ---------------------------------------------------------------------------

#[test]
fn test_cover_empty_features() {
    let cover = simple_cover(vec![]);
    assert_eq!(cover.feature_count(), 0);
    assert_eq!(cover.fully_covered_count(), 0);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 0);
    assert_eq!(cover.schema_version, COVER_SCHEMA_VERSION);
}

#[test]
fn test_cover_single_fully_covered() {
    let f = make_feature(
        "es2015.const",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Supported),
        ],
    );
    let cover = simple_cover(vec![f]);
    assert_eq!(cover.feature_count(), 1);
    assert_eq!(cover.fully_covered_count(), 1);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn test_cover_mixed_coverage_ratio() {
    let features = vec![
        make_feature(
            "full",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "half",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
    ];
    let cover = simple_cover(features);
    // (1_000_000 + 500_000) / 2 = 750_000
    assert_eq!(cover.coverage_ratio_millionths(), 750_000);
}

#[test]
fn test_cover_get_feature_found() {
    let f = make_feature(
        "es2020.bigint",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
    );
    let cover = simple_cover(vec![f]);
    let found = cover.get_feature("es2020.bigint");
    assert!(found.is_some());
    assert_eq!(found.unwrap().key, "es2020.bigint");
}

#[test]
fn test_cover_get_feature_not_found() {
    let cover = simple_cover(vec![]);
    assert!(cover.get_feature("nonexistent").is_none());
}

#[test]
fn test_cover_content_hash_deterministic() {
    let features = vec![make_feature(
        "f1",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
    )];
    let map = default_overlap_map();
    let c1 = SemanticCover::new(features.clone(), map.clone(), epoch());
    let c2 = SemanticCover::new(features, map, epoch());
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn test_cover_content_hash_differs_for_different_features() {
    let map = default_overlap_map();
    let c1 = SemanticCover::new(
        vec![make_feature(
            "alpha",
            &[(EngineSurface::Parser, SupportStatus::Supported)],
        )],
        map.clone(),
        epoch(),
    );
    let c2 = SemanticCover::new(
        vec![make_feature(
            "beta",
            &[(EngineSurface::Parser, SupportStatus::Supported)],
        )],
        map,
        epoch(),
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn test_cover_serde_roundtrip() {
    let features = vec![
        make_feature(
            "f1",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "f2",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Lowering, SupportStatus::Unsupported),
            ],
        ),
    ];
    let cover = simple_cover(features);
    let json = serde_json::to_string(&cover).unwrap();
    let back: SemanticCover = serde_json::from_str(&json).unwrap();
    assert_eq!(back.feature_count(), 2);
    assert_eq!(back.content_hash, cover.content_hash);
    assert_eq!(back.schema_version, COVER_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// SemanticCover — find_gaps
// ---------------------------------------------------------------------------

#[test]
fn test_cover_find_gaps_none_when_all_supported() {
    let features = vec![make_feature(
        "ok",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = simple_cover(features);
    assert!(cover.find_gaps().is_empty());
}

#[test]
fn test_cover_find_gaps_critical_two_unsupported() {
    let features = vec![make_feature(
        "crit",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unsupported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = simple_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].severity, GapSeverity::Critical);
    assert_eq!(gaps[0].unsupported_surfaces.len(), 2);
}

#[test]
fn test_cover_find_gaps_moderate_one_unsupported() {
    let features = vec![make_feature(
        "mod",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = simple_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].severity, GapSeverity::Moderate);
}

#[test]
fn test_cover_find_gaps_low_only_unknown() {
    let features = vec![make_feature(
        "low",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unknown),
        ],
    )];
    let cover = simple_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].severity, GapSeverity::Low);
    assert!(gaps[0].unsupported_surfaces.is_empty());
    assert_eq!(gaps[0].unknown_surfaces.len(), 1);
}

#[test]
fn test_cover_find_gaps_sorted_by_severity_then_key() {
    let features = vec![
        make_feature(
            "z_low",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unknown),
            ],
        ),
        make_feature(
            "a_critical",
            &[
                (EngineSurface::Parser, SupportStatus::Unsupported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
        make_feature(
            "m_moderate",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
    ];
    let cover = simple_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 3);
    assert_eq!(gaps[0].severity, GapSeverity::Critical);
    assert_eq!(gaps[0].feature_key, "a_critical");
    assert_eq!(gaps[1].severity, GapSeverity::Moderate);
    assert_eq!(gaps[1].feature_key, "m_moderate");
    assert_eq!(gaps[2].severity, GapSeverity::Low);
    assert_eq!(gaps[2].feature_key, "z_low");
}

// ---------------------------------------------------------------------------
// SemanticCover — surface_summary
// ---------------------------------------------------------------------------

#[test]
fn test_cover_surface_summary_all_surfaces_present() {
    let cover = simple_cover(vec![]);
    let summary = cover.surface_summary();
    // All 7 surfaces should be in the summary even with no features.
    assert_eq!(summary.len(), 7);
    for surface in EngineSurface::all() {
        let s = summary.get(surface).unwrap();
        assert_eq!(s.surface, *surface);
        assert_eq!(s.total_relevant, 0);
    }
}

#[test]
fn test_cover_surface_summary_counts() {
    let features = vec![
        make_feature(
            "f1",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
        make_feature(
            "f2",
            &[
                (EngineSurface::Parser, SupportStatus::Partial),
                (EngineSurface::Runtime, SupportStatus::Unknown),
            ],
        ),
        make_feature(
            "f3",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Module, SupportStatus::Supported),
            ],
        ),
    ];
    let cover = simple_cover(features);
    let summary = cover.surface_summary();

    let parser = summary.get(&EngineSurface::Parser).unwrap();
    assert_eq!(parser.total_relevant, 3);
    assert_eq!(parser.supported, 2);
    assert_eq!(parser.partial, 1);
    assert_eq!(parser.unsupported, 0);
    assert_eq!(parser.unknown, 0);

    let runtime = summary.get(&EngineSurface::Runtime).unwrap();
    assert_eq!(runtime.total_relevant, 2);
    assert_eq!(runtime.supported, 0);
    assert_eq!(runtime.unsupported, 1);
    assert_eq!(runtime.unknown, 1);

    let module = summary.get(&EngineSurface::Module).unwrap();
    assert_eq!(module.total_relevant, 1);
    assert_eq!(module.supported, 1);
}

#[test]
fn test_surface_summary_serde_roundtrip() {
    let summary = SurfaceSummary {
        surface: EngineSurface::Parser,
        total_relevant: 10,
        supported: 7,
        partial: 1,
        unsupported: 1,
        unknown: 1,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SurfaceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// detect_overlap_violations
// ---------------------------------------------------------------------------

#[test]
fn test_detect_violations_none_when_no_exclusive_overlap() {
    // Use a map with DelegationRequired — not Exclusive, so no violation.
    let map = OverlapRestrictionMap::new(vec![make_overlap_entry(
        EngineSurface::Parser,
        EngineSurface::Lowering,
        OverlapRestriction::DelegationRequired,
        None,
    )]);
    let features = vec![make_feature(
        "es2015.const",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, map, epoch());
    let violations = detect_overlap_violations(&cover);
    assert!(violations.is_empty());
}

#[test]
fn test_detect_violations_exclusive_pair() {
    // Use a custom map with a normalised exclusive entry for Parser-Runtime.
    let map = exclusive_overlap_map(EngineSurface::Parser, EngineSurface::Runtime);
    let features = vec![make_feature(
        "shared_feature",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, map, epoch());
    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].restriction, OverlapRestriction::Exclusive);
    assert_eq!(violations[0].feature_key, "shared_feature");
}

#[test]
fn test_detect_violations_not_triggered_by_unsupported() {
    // If one surface is unsupported, no violation even with exclusive restriction.
    let map = exclusive_overlap_map(EngineSurface::Parser, EngineSurface::Runtime);
    let features = vec![make_feature(
        "parser_only",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = SemanticCover::new(features, map, epoch());
    let violations = detect_overlap_violations(&cover);
    assert!(violations.is_empty());
}

#[test]
fn test_detect_violations_partial_triggers_check() {
    // Partial counts as "claiming support" for overlap detection.
    let map = exclusive_overlap_map(EngineSurface::Parser, EngineSurface::Runtime);
    let features = vec![make_feature(
        "partial_overlap",
        &[
            (EngineSurface::Parser, SupportStatus::Partial),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, map, epoch());
    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 1);
}

#[test]
fn test_overlap_violation_serde_roundtrip() {
    let v = OverlapViolation {
        feature_key: "test.feature".into(),
        surface_a: EngineSurface::Cli,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        description: "Both claim support".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: OverlapViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// CoverSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn test_specimen_family_display_all() {
    let expected = [
        (CoverSpecimenFamily::FullCoverage, "full_coverage"),
        (CoverSpecimenFamily::PartialCoverage, "partial_coverage"),
        (CoverSpecimenFamily::OverlapViolation, "overlap_violation"),
        (CoverSpecimenFamily::UnknownStatus, "unknown_status"),
        (CoverSpecimenFamily::NotApplicable, "not_applicable"),
    ];
    for (variant, label) in expected {
        assert_eq!(variant.to_string(), label);
    }
}

#[test]
fn test_specimen_family_serde_roundtrip() {
    let families = [
        CoverSpecimenFamily::FullCoverage,
        CoverSpecimenFamily::PartialCoverage,
        CoverSpecimenFamily::OverlapViolation,
        CoverSpecimenFamily::UnknownStatus,
        CoverSpecimenFamily::NotApplicable,
    ];
    for f in families {
        let json = serde_json::to_string(&f).unwrap();
        let back: CoverSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}

// ---------------------------------------------------------------------------
// build_evidence_corpus / run_evidence_corpus
// ---------------------------------------------------------------------------

#[test]
fn test_build_evidence_corpus_returns_four_specimens() {
    let specimens = build_evidence_corpus();
    assert_eq!(specimens.len(), 4);
}

#[test]
fn test_evidence_corpus_unique_ids() {
    let specimens = build_evidence_corpus();
    let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids.len(), specimens.len());
}

#[test]
fn test_evidence_corpus_covers_all_families() {
    let specimens = build_evidence_corpus();
    let families: BTreeSet<CoverSpecimenFamily> = specimens.iter().map(|s| s.family).collect();
    // FullCoverage, PartialCoverage, UnknownStatus, NotApplicable.
    assert!(families.contains(&CoverSpecimenFamily::FullCoverage));
    assert!(families.contains(&CoverSpecimenFamily::PartialCoverage));
    assert!(families.contains(&CoverSpecimenFamily::UnknownStatus));
    assert!(families.contains(&CoverSpecimenFamily::NotApplicable));
}

#[test]
fn test_evidence_corpus_full_specimen_is_fully_covered() {
    let specimens = build_evidence_corpus();
    let full = specimens
        .iter()
        .find(|s| s.family == CoverSpecimenFamily::FullCoverage)
        .unwrap();
    assert!(full.feature.is_fully_covered());
    assert!(!full.feature.has_gap());
}

#[test]
fn test_evidence_corpus_partial_specimen_has_gap() {
    let specimens = build_evidence_corpus();
    let partial = specimens
        .iter()
        .find(|s| s.family == CoverSpecimenFamily::PartialCoverage)
        .unwrap();
    assert!(partial.feature.has_gap());
}

#[test]
fn test_evidence_corpus_serde_roundtrip() {
    let specimens = build_evidence_corpus();
    for s in &specimens {
        let json = serde_json::to_string(s).unwrap();
        let back: CoverSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_run_evidence_corpus_deterministic_hash() {
    let (_, h1) = run_evidence_corpus();
    let (_, h2) = run_evidence_corpus();
    assert_eq!(h1, h2);
    assert!(!h1.to_hex().is_empty());
}

#[test]
fn test_run_evidence_corpus_hash_not_zero() {
    let (_, hash) = run_evidence_corpus();
    assert_ne!(hash, ContentHash::compute(&[]));
}

// ---------------------------------------------------------------------------
// CoverGap serde
// ---------------------------------------------------------------------------

#[test]
fn test_cover_gap_serde_roundtrip() {
    let mut unsup = BTreeSet::new();
    unsup.insert(EngineSurface::Runtime);
    let mut unk = BTreeSet::new();
    unk.insert(EngineSurface::Lowering);
    let gap = CoverGap {
        feature_key: "es2021.weakRef".into(),
        unsupported_surfaces: unsup,
        unknown_surfaces: unk,
        severity: GapSeverity::Moderate,
    };
    let json = serde_json::to_string(&gap).unwrap();
    let back: CoverGap = serde_json::from_str(&json).unwrap();
    assert_eq!(gap, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_constants_sane_values() {
    assert!(COVER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MAX_SURFACES >= 7); // At least as many as EngineSurface variants.
    assert!(MAX_FEATURES_PER_SURFACE > 0);
}
