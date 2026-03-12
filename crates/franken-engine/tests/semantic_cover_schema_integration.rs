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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_cover_schema::{
    COVER_SCHEMA_VERSION, CoverFeature, CoverGap, CoverSpecimen, CoverSpecimenFamily,
    EngineSurface, GapSeverity, MAX_FEATURES_PER_SURFACE, MAX_SURFACES, OverlapEntry,
    OverlapRestriction, OverlapRestrictionMap, OverlapViolation, SemanticCover, SupportStatus,
    SurfaceSummary, build_evidence_corpus, default_overlap_map, detect_overlap_violations,
    run_evidence_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn make_feature(key: &str, surfaces: &[(EngineSurface, SupportStatus)]) -> CoverFeature {
    let relevant: BTreeSet<EngineSurface> = surfaces.iter().map(|(s, _)| *s).collect();
    let support_map: BTreeMap<EngineSurface, SupportStatus> = surfaces.iter().cloned().collect();
    CoverFeature {
        key: key.to_string(),
        description: format!("Integration test feature {key}"),
        spec_area: "integration_test".into(),
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
    f.evidence_keys = evidence.iter().map(|e| e.to_string()).collect();
    f
}

fn make_cover(features: Vec<CoverFeature>) -> SemanticCover {
    SemanticCover::new(features, default_overlap_map(), test_epoch())
}

// ===========================================================================
// 1. EngineSurface tests
// ===========================================================================

#[test]
fn engine_surface_all_returns_seven_variants() {
    let all = EngineSurface::all();
    assert_eq!(all.len(), 7);
    assert!(all.contains(&EngineSurface::Parser));
    assert!(all.contains(&EngineSurface::Lowering));
    assert!(all.contains(&EngineSurface::Runtime));
    assert!(all.contains(&EngineSurface::Module));
    assert!(all.contains(&EngineSurface::TypeScript));
    assert!(all.contains(&EngineSurface::React));
    assert!(all.contains(&EngineSurface::Cli));
}

#[test]
fn engine_surface_display_all_variants() {
    assert_eq!(EngineSurface::Parser.to_string(), "parser");
    assert_eq!(EngineSurface::Lowering.to_string(), "lowering");
    assert_eq!(EngineSurface::Runtime.to_string(), "runtime");
    assert_eq!(EngineSurface::Module.to_string(), "module");
    assert_eq!(EngineSurface::TypeScript.to_string(), "typescript");
    assert_eq!(EngineSurface::React.to_string(), "react");
    assert_eq!(EngineSurface::Cli.to_string(), "cli");
}

#[test]
fn engine_surface_ordering_is_declaration_order() {
    let all = EngineSurface::all();
    for i in 1..all.len() {
        assert!(
            all[i - 1] < all[i],
            "expected {:?} < {:?}",
            all[i - 1],
            all[i]
        );
    }
}

#[test]
fn engine_surface_all_unique() {
    let all = EngineSurface::all();
    let as_set: BTreeSet<EngineSurface> = all.iter().copied().collect();
    assert_eq!(as_set.len(), all.len());
}

#[test]
fn engine_surface_serde_roundtrip_all() {
    for surface in EngineSurface::all() {
        let json = serde_json::to_string(surface).unwrap();
        let back: EngineSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*surface, back);
    }
}

#[test]
fn engine_surface_clone_eq() {
    let s = EngineSurface::React;
    let s2 = s;
    assert_eq!(s, s2);
}

// ===========================================================================
// 2. SupportStatus tests
// ===========================================================================

#[test]
fn support_status_display_all_variants() {
    assert_eq!(SupportStatus::Supported.to_string(), "supported");
    assert_eq!(SupportStatus::Partial.to_string(), "partial");
    assert_eq!(SupportStatus::Unsupported.to_string(), "unsupported");
    assert_eq!(SupportStatus::Unknown.to_string(), "unknown");
    assert_eq!(SupportStatus::NotApplicable.to_string(), "not_applicable");
}

#[test]
fn support_status_serde_roundtrip_all() {
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

#[test]
fn support_status_ordering() {
    assert!(SupportStatus::Supported < SupportStatus::Partial);
    assert!(SupportStatus::Partial < SupportStatus::Unsupported);
    assert!(SupportStatus::Unsupported < SupportStatus::Unknown);
    assert!(SupportStatus::Unknown < SupportStatus::NotApplicable);
}

// ===========================================================================
// 3. CoverFeature tests
// ===========================================================================

#[test]
fn feature_fully_covered_all_supported() {
    let f = make_feature(
        "es2015.let",
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
fn feature_not_fully_covered_with_partial() {
    let f = make_feature(
        "es2015.destructuring",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Partial),
        ],
    );
    assert!(!f.is_fully_covered());
    // Partial is not Unsupported/Unknown, so has_gap is false
    assert!(!f.has_gap());
    assert_eq!(f.supported_surface_count(), 1);
    assert_eq!(f.coverage_ratio_millionths(), 500_000);
}

#[test]
fn feature_has_gap_with_unsupported() {
    let f = make_feature(
        "es2022.topLevelAwait",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unsupported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    );
    assert!(f.has_gap());
    assert_eq!(f.supported_surface_count(), 2);
}

#[test]
fn feature_has_gap_with_unknown() {
    let f = make_feature(
        "stage3.decorators",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unknown),
        ],
    );
    assert!(f.has_gap());
    assert_eq!(f.supported_surface_count(), 1);
}

#[test]
fn feature_coverage_ratio_zero_for_empty_relevant() {
    let f = CoverFeature {
        key: "empty".into(),
        description: "no surfaces at all".into(),
        spec_area: "test".into(),
        relevant_surfaces: BTreeSet::new(),
        support_map: BTreeMap::new(),
        evidence_keys: BTreeSet::new(),
    };
    assert_eq!(f.coverage_ratio_millionths(), 0);
    // Vacuously fully covered
    assert!(f.is_fully_covered());
    assert!(!f.has_gap());
}

#[test]
fn feature_coverage_ratio_one_of_three() {
    let f = make_feature(
        "test.ratio",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unsupported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    );
    // 1/3 * 1_000_000 = 333_333
    assert_eq!(f.coverage_ratio_millionths(), 333_333);
}

#[test]
fn feature_with_evidence_keys_preserved() {
    let f = make_feature_with_evidence(
        "test.evidence",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
        &["ev1", "ev2", "ev3"],
    );
    assert_eq!(f.evidence_keys.len(), 3);
    assert!(f.evidence_keys.contains("ev1"));
    assert!(f.evidence_keys.contains("ev3"));
}

#[test]
fn feature_serde_roundtrip_with_evidence() {
    let f = make_feature_with_evidence(
        "serde.evidence",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Module, SupportStatus::Partial),
            (EngineSurface::React, SupportStatus::Unsupported),
        ],
        &["parser.test1", "module.test2"],
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: CoverFeature = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ===========================================================================
// 4. OverlapRestriction tests
// ===========================================================================

#[test]
fn overlap_restriction_display_all_variants() {
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
fn overlap_restriction_serde_roundtrip() {
    let restrictions = [
        OverlapRestriction::Allowed,
        OverlapRestriction::DelegationRequired,
        OverlapRestriction::Exclusive,
        OverlapRestriction::ReconciliationRequired,
    ];
    for r in restrictions {
        let json = serde_json::to_string(&r).unwrap();
        let back: OverlapRestriction = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ===========================================================================
// 5. OverlapRestrictionMap tests
// ===========================================================================

#[test]
fn overlap_map_new_computes_hash() {
    let entries = vec![OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        scope_prefix: None,
        rationale: "test".into(),
    }];
    let map = OverlapRestrictionMap::new(entries);
    assert_eq!(map.len(), 1);
    assert!(!map.is_empty());
    assert!(!map.content_hash.to_hex().is_empty());
}

#[test]
fn overlap_map_empty() {
    let map = OverlapRestrictionMap::new(vec![]);
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn overlap_map_restriction_for_normalizes_order() {
    let entries = vec![OverlapEntry {
        surface_a: EngineSurface::Lowering,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::DelegationRequired,
        scope_prefix: None,
        rationale: "test".into(),
    }];
    let map = OverlapRestrictionMap::new(entries);
    // Forward order
    assert_eq!(
        map.restriction_for(EngineSurface::Lowering, EngineSurface::Runtime),
        Some(OverlapRestriction::DelegationRequired)
    );
    // Reverse order should also work
    assert_eq!(
        map.restriction_for(EngineSurface::Runtime, EngineSurface::Lowering),
        Some(OverlapRestriction::DelegationRequired)
    );
}

#[test]
fn overlap_map_restriction_for_missing_pair_returns_none() {
    let map = OverlapRestrictionMap::new(vec![]);
    assert_eq!(
        map.restriction_for(EngineSurface::Parser, EngineSurface::Cli),
        None
    );
}

#[test]
fn overlap_map_restrictions_for_scope_with_prefix() {
    let entries = vec![
        OverlapEntry {
            surface_a: EngineSurface::Parser,
            surface_b: EngineSurface::TypeScript,
            restriction: OverlapRestriction::ReconciliationRequired,
            scope_prefix: Some("ts.".into()),
            rationale: "test".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Parser,
            surface_b: EngineSurface::TypeScript,
            restriction: OverlapRestriction::Allowed,
            scope_prefix: Some("js.".into()),
            rationale: "test".into(),
        },
    ];
    let map = OverlapRestrictionMap::new(entries);

    // "ts.enum" matches "ts." scope
    let hits =
        map.restrictions_for_scope(EngineSurface::Parser, EngineSurface::TypeScript, "ts.enum");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].restriction,
        OverlapRestriction::ReconciliationRequired
    );

    // "js.module" matches "js." scope
    let hits = map.restrictions_for_scope(
        EngineSurface::Parser,
        EngineSurface::TypeScript,
        "js.module",
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].restriction, OverlapRestriction::Allowed);

    // "react.component" matches neither scope
    let hits = map.restrictions_for_scope(
        EngineSurface::Parser,
        EngineSurface::TypeScript,
        "react.component",
    );
    assert_eq!(hits.len(), 0);
}

#[test]
fn overlap_map_content_hash_deterministic() {
    let entries = vec![OverlapEntry {
        surface_a: EngineSurface::Module,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Allowed,
        scope_prefix: None,
        rationale: "determinism test".into(),
    }];
    let m1 = OverlapRestrictionMap::new(entries.clone());
    let m2 = OverlapRestrictionMap::new(entries);
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn overlap_map_different_entries_different_hash() {
    let m1 = OverlapRestrictionMap::new(vec![OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        scope_prefix: None,
        rationale: "a".into(),
    }]);
    let m2 = OverlapRestrictionMap::new(vec![OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Allowed,
        scope_prefix: None,
        rationale: "b".into(),
    }]);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn overlap_map_serde_roundtrip() {
    let map = default_overlap_map();
    let json = serde_json::to_string(&map).unwrap();
    let back: OverlapRestrictionMap = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), map.len());
    assert_eq!(back.content_hash, map.content_hash);
}

// ===========================================================================
// 6. Default overlap map
// ===========================================================================

#[test]
fn default_overlap_map_has_expected_entries() {
    let map = default_overlap_map();
    assert!(map.len() >= 7);
    assert!(!map.is_empty());
}

#[test]
fn default_overlap_map_cli_runtime_exclusive() {
    let map = default_overlap_map();
    assert_eq!(
        map.restriction_for(EngineSurface::Cli, EngineSurface::Runtime),
        Some(OverlapRestriction::Exclusive)
    );
}

#[test]
fn default_overlap_map_parser_lowering_delegation() {
    let map = default_overlap_map();
    assert_eq!(
        map.restriction_for(EngineSurface::Parser, EngineSurface::Lowering),
        Some(OverlapRestriction::DelegationRequired)
    );
}

#[test]
fn default_overlap_map_module_runtime_allowed() {
    let map = default_overlap_map();
    assert_eq!(
        map.restriction_for(EngineSurface::Module, EngineSurface::Runtime),
        Some(OverlapRestriction::Allowed)
    );
}

#[test]
fn default_overlap_map_parser_react_jsx_reconciliation() {
    let map = default_overlap_map();
    let entries =
        map.restrictions_for_scope(EngineSurface::Parser, EngineSurface::React, "jsx.element");
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].restriction,
        OverlapRestriction::ReconciliationRequired
    );
}

// ===========================================================================
// 7. GapSeverity tests
// ===========================================================================

#[test]
fn gap_severity_display_all() {
    assert_eq!(GapSeverity::Critical.to_string(), "critical");
    assert_eq!(GapSeverity::Moderate.to_string(), "moderate");
    assert_eq!(GapSeverity::Low.to_string(), "low");
    assert_eq!(GapSeverity::Informational.to_string(), "informational");
}

#[test]
fn gap_severity_ordering_critical_first() {
    assert!(GapSeverity::Critical < GapSeverity::Moderate);
    assert!(GapSeverity::Moderate < GapSeverity::Low);
    assert!(GapSeverity::Low < GapSeverity::Informational);
}

// ===========================================================================
// 8. SemanticCover tests
// ===========================================================================

#[test]
fn semantic_cover_feature_count() {
    let features = vec![
        make_feature("f1", &[(EngineSurface::Parser, SupportStatus::Supported)]),
        make_feature("f2", &[(EngineSurface::Runtime, SupportStatus::Supported)]),
        make_feature(
            "f3",
            &[(EngineSurface::Lowering, SupportStatus::Unsupported)],
        ),
    ];
    let cover = make_cover(features);
    assert_eq!(cover.feature_count(), 3);
}

#[test]
fn semantic_cover_fully_covered_count() {
    let features = vec![
        make_feature(
            "full",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "partial",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
    ];
    let cover = make_cover(features);
    assert_eq!(cover.fully_covered_count(), 1);
}

#[test]
fn semantic_cover_gap_count() {
    let features = vec![
        make_feature(
            "ok",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "gap1",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
        make_feature(
            "gap2",
            &[
                (EngineSurface::Parser, SupportStatus::Unknown),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
    ];
    let cover = make_cover(features);
    assert_eq!(cover.gap_count(), 2);
}

#[test]
fn semantic_cover_coverage_ratio_all_supported() {
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
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
    ];
    let cover = make_cover(features);
    assert_eq!(cover.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn semantic_cover_coverage_ratio_mixed() {
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
    let cover = make_cover(features);
    // (1_000_000 + 500_000) / 2 = 750_000
    assert_eq!(cover.coverage_ratio_millionths(), 750_000);
}

#[test]
fn semantic_cover_coverage_ratio_empty() {
    let cover = make_cover(vec![]);
    assert_eq!(cover.coverage_ratio_millionths(), 0);
}

#[test]
fn semantic_cover_find_gaps_sorted_by_severity() {
    let features = vec![
        make_feature(
            "critical_gap",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
                (EngineSurface::Lowering, SupportStatus::Unsupported),
            ],
        ),
        make_feature(
            "moderate_gap",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
        ),
        make_feature(
            "low_gap",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unknown),
            ],
        ),
    ];
    let cover = make_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 3);
    assert_eq!(gaps[0].severity, GapSeverity::Critical);
    assert_eq!(gaps[0].feature_key, "critical_gap");
    assert_eq!(gaps[1].severity, GapSeverity::Moderate);
    assert_eq!(gaps[1].feature_key, "moderate_gap");
    assert_eq!(gaps[2].severity, GapSeverity::Low);
    assert_eq!(gaps[2].feature_key, "low_gap");
}

#[test]
fn semantic_cover_find_gaps_unsupported_surfaces_populated() {
    let features = vec![make_feature(
        "gap_detail",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
            (EngineSurface::Module, SupportStatus::Unknown),
        ],
    )];
    let cover = make_cover(features);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 1);
    assert!(
        gaps[0]
            .unsupported_surfaces
            .contains(&EngineSurface::Runtime)
    );
    assert!(gaps[0].unknown_surfaces.contains(&EngineSurface::Module));
}

#[test]
fn semantic_cover_find_gaps_none_when_all_covered() {
    let features = vec![
        make_feature("a", &[(EngineSurface::Parser, SupportStatus::Supported)]),
        make_feature("b", &[(EngineSurface::Runtime, SupportStatus::Supported)]),
    ];
    let cover = make_cover(features);
    assert!(cover.find_gaps().is_empty());
}

#[test]
fn semantic_cover_surface_summary_all_surfaces() {
    let features = vec![make_feature(
        "f1",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Partial),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
            (EngineSurface::Module, SupportStatus::Unknown),
        ],
    )];
    let cover = make_cover(features);
    let summary = cover.surface_summary();

    // All 7 surfaces present
    assert_eq!(summary.len(), 7);

    let parser_sum = summary.get(&EngineSurface::Parser).unwrap();
    assert_eq!(parser_sum.total_relevant, 1);
    assert_eq!(parser_sum.supported, 1);

    let lowering_sum = summary.get(&EngineSurface::Lowering).unwrap();
    assert_eq!(lowering_sum.partial, 1);

    let runtime_sum = summary.get(&EngineSurface::Runtime).unwrap();
    assert_eq!(runtime_sum.unsupported, 1);

    let module_sum = summary.get(&EngineSurface::Module).unwrap();
    assert_eq!(module_sum.unknown, 1);

    // Surfaces not relevant have 0
    let cli_sum = summary.get(&EngineSurface::Cli).unwrap();
    assert_eq!(cli_sum.total_relevant, 0);
}

#[test]
fn semantic_cover_get_feature_found() {
    let features = vec![
        make_feature(
            "target",
            &[(EngineSurface::Parser, SupportStatus::Supported)],
        ),
        make_feature(
            "other",
            &[(EngineSurface::Runtime, SupportStatus::Supported)],
        ),
    ];
    let cover = make_cover(features);
    let found = cover.get_feature("target");
    assert!(found.is_some());
    assert_eq!(found.unwrap().key, "target");
}

#[test]
fn semantic_cover_get_feature_not_found() {
    let cover = make_cover(vec![]);
    assert!(cover.get_feature("nonexistent").is_none());
}

#[test]
fn semantic_cover_content_hash_deterministic() {
    let features = vec![
        make_feature("a", &[(EngineSurface::Parser, SupportStatus::Supported)]),
        make_feature("b", &[(EngineSurface::Runtime, SupportStatus::Unsupported)]),
    ];
    let c1 = make_cover(features.clone());
    let c2 = make_cover(features);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn semantic_cover_different_features_different_hash() {
    let c1 = make_cover(vec![make_feature(
        "alpha",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
    )]);
    let c2 = make_cover(vec![make_feature(
        "beta",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
    )]);
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn semantic_cover_schema_version_populated() {
    let cover = make_cover(vec![]);
    assert_eq!(cover.schema_version, COVER_SCHEMA_VERSION);
}

#[test]
fn semantic_cover_epoch_preserved() {
    let epoch = SecurityEpoch::from_raw(999);
    let cover = SemanticCover::new(vec![], default_overlap_map(), epoch);
    assert_eq!(cover.epoch.as_u64(), 999);
}

// ===========================================================================
// 9. Overlap violation detection
// ===========================================================================

#[test]
fn detect_violations_exclusive_pair_both_supported() {
    // CLI + Runtime are exclusive in the default map
    let features = vec![make_feature(
        "shared_feature",
        &[
            (EngineSurface::Cli, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = make_cover(features);
    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].feature_key, "shared_feature");
    assert_eq!(violations[0].restriction, OverlapRestriction::Exclusive);
}

#[test]
fn detect_violations_none_when_no_overlap() {
    let features = vec![
        make_feature(
            "cli_only",
            &[(EngineSurface::Cli, SupportStatus::Supported)],
        ),
        make_feature(
            "runtime_only",
            &[(EngineSurface::Runtime, SupportStatus::Supported)],
        ),
    ];
    let cover = make_cover(features);
    assert!(detect_overlap_violations(&cover).is_empty());
}

#[test]
fn detect_violations_not_triggered_by_unsupported() {
    // One is unsupported, so no actual overlap
    let features = vec![make_feature(
        "test",
        &[
            (EngineSurface::Cli, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = make_cover(features);
    assert!(detect_overlap_violations(&cover).is_empty());
}

#[test]
fn detect_violations_partial_counts_as_overlap() {
    // Partial also counts for overlap detection
    let features = vec![make_feature(
        "partial_overlap",
        &[
            (EngineSurface::Cli, SupportStatus::Partial),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = make_cover(features);
    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 1);
}

#[test]
fn detect_violations_allowed_pair_no_violation() {
    // Module + Runtime is Allowed in the default map
    let features = vec![make_feature(
        "both_ok",
        &[
            (EngineSurface::Module, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = make_cover(features);
    assert!(detect_overlap_violations(&cover).is_empty());
}

#[test]
fn detect_violations_multiple_features_multiple_violations() {
    let features = vec![
        make_feature(
            "v1",
            &[
                (EngineSurface::Cli, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "v2",
            &[
                (EngineSurface::Cli, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
    ];
    let cover = make_cover(features);
    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 2);
}

// ===========================================================================
// 10. Serde roundtrips for complex types
// ===========================================================================

#[test]
fn serde_roundtrip_cover_gap() {
    let gap = CoverGap {
        feature_key: "test.gap".into(),
        unsupported_surfaces: {
            let mut s = BTreeSet::new();
            s.insert(EngineSurface::Runtime);
            s
        },
        unknown_surfaces: {
            let mut s = BTreeSet::new();
            s.insert(EngineSurface::Module);
            s
        },
        severity: GapSeverity::Moderate,
    };
    let json = serde_json::to_string(&gap).unwrap();
    let back: CoverGap = serde_json::from_str(&json).unwrap();
    assert_eq!(gap, back);
}

#[test]
fn serde_roundtrip_overlap_violation() {
    let violation = OverlapViolation {
        feature_key: "test.violation".into(),
        surface_a: EngineSurface::Cli,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        description: "both claim support".into(),
    };
    let json = serde_json::to_string(&violation).unwrap();
    let back: OverlapViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(violation, back);
}

#[test]
fn serde_roundtrip_surface_summary() {
    let summary = SurfaceSummary {
        surface: EngineSurface::Parser,
        total_relevant: 10,
        supported: 7,
        partial: 2,
        unsupported: 1,
        unknown: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SurfaceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn serde_roundtrip_overlap_entry() {
    let entry = OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::React,
        restriction: OverlapRestriction::ReconciliationRequired,
        scope_prefix: Some("jsx.".into()),
        rationale: "test rationale".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: OverlapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn serde_roundtrip_semantic_cover() {
    let features = vec![
        make_feature(
            "serde.f1",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Lowering, SupportStatus::Partial),
            ],
        ),
        make_feature(
            "serde.f2",
            &[(EngineSurface::Runtime, SupportStatus::Unsupported)],
        ),
    ];
    let cover = make_cover(features);
    let json = serde_json::to_string(&cover).unwrap();
    let back: SemanticCover = serde_json::from_str(&json).unwrap();
    assert_eq!(back.feature_count(), 2);
    assert_eq!(back.content_hash, cover.content_hash);
    assert_eq!(back.schema_version, COVER_SCHEMA_VERSION);
}

// ===========================================================================
// 11. Evidence corpus tests
// ===========================================================================

#[test]
fn evidence_corpus_builds_with_expected_count() {
    let specimens = build_evidence_corpus();
    assert_eq!(specimens.len(), 4);
}

#[test]
fn evidence_corpus_specimen_ids_unique() {
    let specimens = build_evidence_corpus();
    let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids.len(), specimens.len());
}

#[test]
fn evidence_corpus_specimen_families_diverse() {
    let specimens = build_evidence_corpus();
    let families: BTreeSet<String> = specimens.iter().map(|s| s.family.to_string()).collect();
    assert!(families.len() >= 3);
}

#[test]
fn evidence_corpus_run_deterministic_hash() {
    let (_, h1) = run_evidence_corpus();
    let (_, h2) = run_evidence_corpus();
    assert_eq!(h1, h2);
}

#[test]
fn evidence_corpus_serde_roundtrip() {
    let specimens = build_evidence_corpus();
    for s in &specimens {
        let json = serde_json::to_string(s).unwrap();
        let back: CoverSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn specimen_family_display_all() {
    assert_eq!(
        CoverSpecimenFamily::FullCoverage.to_string(),
        "full_coverage"
    );
    assert_eq!(
        CoverSpecimenFamily::PartialCoverage.to_string(),
        "partial_coverage"
    );
    assert_eq!(
        CoverSpecimenFamily::OverlapViolation.to_string(),
        "overlap_violation"
    );
    assert_eq!(
        CoverSpecimenFamily::UnknownStatus.to_string(),
        "unknown_status"
    );
    assert_eq!(
        CoverSpecimenFamily::NotApplicable.to_string(),
        "not_applicable"
    );
}

// ===========================================================================
// 12. Constants tests
// ===========================================================================

#[test]
fn constants_schema_version_format() {
    assert!(COVER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(COVER_SCHEMA_VERSION.contains("semantic-cover-schema"));
}

#[test]
fn constants_max_surfaces() {
    assert!(MAX_SURFACES >= EngineSurface::all().len());
}

#[test]
fn constants_max_features_per_surface() {
    assert!(MAX_FEATURES_PER_SURFACE > 0);
    assert!(MAX_FEATURES_PER_SURFACE <= 1024);
}

// ===========================================================================
// 13. Boundary cases
// ===========================================================================

#[test]
fn boundary_empty_cover() {
    let cover = make_cover(vec![]);
    assert_eq!(cover.feature_count(), 0);
    assert_eq!(cover.fully_covered_count(), 0);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 0);
    assert!(cover.find_gaps().is_empty());
    let summary = cover.surface_summary();
    for surface in EngineSurface::all() {
        let s = summary.get(surface).unwrap();
        assert_eq!(s.total_relevant, 0);
    }
}

#[test]
fn boundary_single_surface_single_feature() {
    let features = vec![make_feature(
        "solo",
        &[(EngineSurface::Cli, SupportStatus::Supported)],
    )];
    let cover = make_cover(features);
    assert_eq!(cover.feature_count(), 1);
    assert_eq!(cover.fully_covered_count(), 1);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn boundary_feature_all_surfaces_supported() {
    let surfaces: Vec<(EngineSurface, SupportStatus)> = EngineSurface::all()
        .iter()
        .map(|s| (*s, SupportStatus::Supported))
        .collect();
    let f = make_feature("all_surfaces", &surfaces);
    assert!(f.is_fully_covered());
    assert_eq!(f.supported_surface_count(), 7);
    assert_eq!(f.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn boundary_feature_all_surfaces_unsupported() {
    let surfaces: Vec<(EngineSurface, SupportStatus)> = EngineSurface::all()
        .iter()
        .map(|s| (*s, SupportStatus::Unsupported))
        .collect();
    let f = make_feature("all_unsupported", &surfaces);
    assert!(!f.is_fully_covered());
    assert!(f.has_gap());
    assert_eq!(f.supported_surface_count(), 0);
    assert_eq!(f.coverage_ratio_millionths(), 0);
}

#[test]
fn boundary_many_features() {
    let features: Vec<CoverFeature> = (0..100)
        .map(|i| {
            make_feature(
                &format!("feature_{i:03}"),
                &[(EngineSurface::Parser, SupportStatus::Supported)],
            )
        })
        .collect();
    let cover = make_cover(features);
    assert_eq!(cover.feature_count(), 100);
    assert_eq!(cover.fully_covered_count(), 100);
    assert_eq!(cover.gap_count(), 0);
}

// ===========================================================================
// 14. End-to-end pipeline
// ===========================================================================

#[test]
fn end_to_end_declare_build_check_analyze() {
    // Step 1: Declare features across multiple surfaces
    let features = vec![
        make_feature_with_evidence(
            "es2015.arrowFunction",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Lowering, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
            &[
                "parser.arrow_test",
                "lowering.arrow_ir",
                "runtime.arrow_exec",
            ],
        ),
        make_feature_with_evidence(
            "es2022.topLevelAwait",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Lowering, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ],
            &["parser.tla_test", "lowering.tla_ir"],
        ),
        make_feature_with_evidence(
            "ts.enum",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::TypeScript, SupportStatus::Supported),
            ],
            &["parser.enum_test", "ts.enum_norm"],
        ),
        make_feature(
            "cli.doctor",
            &[(EngineSurface::Cli, SupportStatus::Supported)],
        ),
        make_feature(
            "es2024.arrayGroupBy",
            &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unknown),
            ],
        ),
    ];

    // Step 2: Build the cover
    let epoch = SecurityEpoch::from_raw(42);
    let overlap_map = default_overlap_map();
    let cover = SemanticCover::new(features, overlap_map, epoch);

    // Step 3: Basic stats
    assert_eq!(cover.feature_count(), 5);
    assert_eq!(cover.fully_covered_count(), 3); // arrow, ts.enum, cli.doctor
    assert_eq!(cover.gap_count(), 2); // topLevelAwait (unsupported), arrayGroupBy (unknown)

    // Step 4: Check overlaps
    let violations = detect_overlap_violations(&cover);
    // No exclusive violations since no CLI+Runtime both-supported
    assert!(violations.is_empty());

    // Step 5: Find gaps
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 2);
    // Moderate (1 unsupported) comes before Low (only unknown)
    assert_eq!(gaps[0].severity, GapSeverity::Moderate);
    assert_eq!(gaps[0].feature_key, "es2022.topLevelAwait");
    assert_eq!(gaps[1].severity, GapSeverity::Low);
    assert_eq!(gaps[1].feature_key, "es2024.arrayGroupBy");

    // Step 6: Surface summary
    let summary = cover.surface_summary();
    let parser = summary.get(&EngineSurface::Parser).unwrap();
    assert_eq!(parser.total_relevant, 4); // arrow, tla, ts.enum, arrayGroupBy
    assert_eq!(parser.supported, 4);

    let runtime = summary.get(&EngineSurface::Runtime).unwrap();
    assert_eq!(runtime.total_relevant, 3); // arrow, tla, arrayGroupBy
    assert_eq!(runtime.supported, 1); // only arrow
    assert_eq!(runtime.unsupported, 1); // tla
    assert_eq!(runtime.unknown, 1); // arrayGroupBy

    // Step 7: Feature lookup
    let tla = cover.get_feature("es2022.topLevelAwait").unwrap();
    assert!(tla.has_gap());
    assert_eq!(tla.evidence_keys.len(), 2);

    // Step 8: Determinism
    let cover2 = SemanticCover::new(
        vec![
            make_feature_with_evidence(
                "es2015.arrowFunction",
                &[
                    (EngineSurface::Parser, SupportStatus::Supported),
                    (EngineSurface::Lowering, SupportStatus::Supported),
                    (EngineSurface::Runtime, SupportStatus::Supported),
                ],
                &[
                    "parser.arrow_test",
                    "lowering.arrow_ir",
                    "runtime.arrow_exec",
                ],
            ),
            make_feature_with_evidence(
                "es2022.topLevelAwait",
                &[
                    (EngineSurface::Parser, SupportStatus::Supported),
                    (EngineSurface::Lowering, SupportStatus::Supported),
                    (EngineSurface::Runtime, SupportStatus::Unsupported),
                ],
                &["parser.tla_test", "lowering.tla_ir"],
            ),
            make_feature_with_evidence(
                "ts.enum",
                &[
                    (EngineSurface::Parser, SupportStatus::Supported),
                    (EngineSurface::TypeScript, SupportStatus::Supported),
                ],
                &["parser.enum_test", "ts.enum_norm"],
            ),
            make_feature(
                "cli.doctor",
                &[(EngineSurface::Cli, SupportStatus::Supported)],
            ),
            make_feature(
                "es2024.arrayGroupBy",
                &[
                    (EngineSurface::Parser, SupportStatus::Supported),
                    (EngineSurface::Runtime, SupportStatus::Unknown),
                ],
            ),
        ],
        default_overlap_map(),
        SecurityEpoch::from_raw(42),
    );
    assert_eq!(cover.content_hash, cover2.content_hash);
}

#[test]
fn end_to_end_violation_pipeline() {
    // Build a scenario where a violation must be detected
    let features = vec![
        make_feature(
            "shared.exec",
            &[
                (EngineSurface::Cli, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
        make_feature(
            "safe.feature",
            &[
                (EngineSurface::Module, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ],
        ),
    ];
    let cover = make_cover(features);

    let violations = detect_overlap_violations(&cover);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].feature_key, "shared.exec");

    // Gaps
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.fully_covered_count(), 2);
}
