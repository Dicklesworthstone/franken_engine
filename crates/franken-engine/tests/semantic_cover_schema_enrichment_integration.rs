//! Enrichment integration tests for the `semantic_cover_schema` module.
//!
//! Deep coverage of EngineSurface, SupportStatus, CoverFeature, OverlapRestriction,
//! OverlapRestrictionMap, SemanticCover, CoverGap, GapSeverity, CoverSpecimen,
//! evidence corpus, violation detection, and serde round-trips.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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
    SecurityEpoch::from_raw(200)
}

fn make_feature(key: &str, surfaces: &[(EngineSurface, SupportStatus)]) -> CoverFeature {
    let relevant: BTreeSet<EngineSurface> = surfaces.iter().map(|(s, _)| *s).collect();
    let support_map: BTreeMap<EngineSurface, SupportStatus> = surfaces.iter().cloned().collect();
    CoverFeature {
        key: key.to_string(),
        description: format!("Enrichment test feature {key}"),
        spec_area: "enrichment_test".into(),
        relevant_surfaces: relevant,
        support_map,
        evidence_keys: BTreeSet::new(),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_schema_version_format() {
    assert!(COVER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(COVER_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrich_max_surfaces_positive() {
    assert!(MAX_SURFACES > 0);
    assert_eq!(MAX_SURFACES, 16);
}

#[test]
fn enrich_max_features_per_surface_positive() {
    assert!(MAX_FEATURES_PER_SURFACE > 0);
    assert_eq!(MAX_FEATURES_PER_SURFACE, 512);
}

// ---------------------------------------------------------------------------
// EngineSurface — Display, serde, all()
// ---------------------------------------------------------------------------

#[test]
fn enrich_surface_all_returns_seven() {
    assert_eq!(EngineSurface::all().len(), 7);
}

#[test]
fn enrich_surface_display_all_unique() {
    let displays: BTreeSet<String> = EngineSurface::all().iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrich_surface_serde_all_variants() {
    for surface in EngineSurface::all() {
        let json = serde_json::to_string(surface).unwrap();
        let back: EngineSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*surface, back);
    }
}

#[test]
fn enrich_surface_ordering_parser_before_cli() {
    assert!(EngineSurface::Parser < EngineSurface::Cli);
}

#[test]
fn enrich_surface_display_known_values() {
    assert_eq!(EngineSurface::Parser.to_string(), "parser");
    assert_eq!(EngineSurface::Lowering.to_string(), "lowering");
    assert_eq!(EngineSurface::Runtime.to_string(), "runtime");
    assert_eq!(EngineSurface::Module.to_string(), "module");
    assert_eq!(EngineSurface::TypeScript.to_string(), "typescript");
    assert_eq!(EngineSurface::React.to_string(), "react");
    assert_eq!(EngineSurface::Cli.to_string(), "cli");
}

// ---------------------------------------------------------------------------
// SupportStatus — Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_support_status_display_all() {
    let statuses = [
        (SupportStatus::Supported, "supported"),
        (SupportStatus::Partial, "partial"),
        (SupportStatus::Unsupported, "unsupported"),
        (SupportStatus::Unknown, "unknown"),
        (SupportStatus::NotApplicable, "not_applicable"),
    ];
    for (status, expected) in &statuses {
        assert_eq!(status.to_string(), *expected);
    }
}

#[test]
fn enrich_support_status_serde_all() {
    let statuses = [
        SupportStatus::Supported,
        SupportStatus::Partial,
        SupportStatus::Unsupported,
        SupportStatus::Unknown,
        SupportStatus::NotApplicable,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: SupportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// CoverFeature — coverage logic
// ---------------------------------------------------------------------------

#[test]
fn enrich_feature_all_supported_is_fully_covered() {
    let f = make_feature(
        "full",
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
fn enrich_feature_partial_not_fully_covered() {
    let f = make_feature(
        "partial",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Partial),
        ],
    );
    assert!(!f.is_fully_covered());
    assert_eq!(f.supported_surface_count(), 1);
    assert_eq!(f.coverage_ratio_millionths(), 500_000);
}

#[test]
fn enrich_feature_unsupported_has_gap() {
    let f = make_feature(
        "gap",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    );
    assert!(f.has_gap());
}

#[test]
fn enrich_feature_unknown_has_gap() {
    let f = make_feature(
        "unk",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unknown),
        ],
    );
    assert!(f.has_gap());
}

#[test]
fn enrich_feature_empty_relevant_is_vacuously_covered() {
    let f = CoverFeature {
        key: "empty".into(),
        description: "no surfaces".into(),
        spec_area: "test".into(),
        relevant_surfaces: BTreeSet::new(),
        support_map: BTreeMap::new(),
        evidence_keys: BTreeSet::new(),
    };
    assert!(f.is_fully_covered());
    assert_eq!(f.coverage_ratio_millionths(), 0);
}

#[test]
fn enrich_feature_serde_roundtrip() {
    let f = make_feature(
        "serde_test",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Module, SupportStatus::Partial),
        ],
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: CoverFeature = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn enrich_feature_single_surface_supported() {
    let f = make_feature("single", &[(EngineSurface::Cli, SupportStatus::Supported)]);
    assert!(f.is_fully_covered());
    assert_eq!(f.supported_surface_count(), 1);
    assert_eq!(f.coverage_ratio_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// OverlapRestriction — Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_overlap_restriction_display_all() {
    let expected = [
        (OverlapRestriction::Allowed, "allowed"),
        (
            OverlapRestriction::DelegationRequired,
            "delegation_required",
        ),
        (OverlapRestriction::Exclusive, "exclusive"),
        (
            OverlapRestriction::ReconciliationRequired,
            "reconciliation_required",
        ),
    ];
    for (r, text) in &expected {
        assert_eq!(r.to_string(), *text);
    }
}

#[test]
fn enrich_overlap_restriction_serde_all() {
    let variants = [
        OverlapRestriction::Allowed,
        OverlapRestriction::DelegationRequired,
        OverlapRestriction::Exclusive,
        OverlapRestriction::ReconciliationRequired,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: OverlapRestriction = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// OverlapRestrictionMap — default_overlap_map and lookups
// ---------------------------------------------------------------------------

#[test]
fn enrich_default_overlap_map_has_entries() {
    let map = default_overlap_map();
    assert!(!map.is_empty());
    assert!(map.len() >= 5);
}

#[test]
fn enrich_default_overlap_map_schema_version() {
    let map = default_overlap_map();
    assert_eq!(map.schema_version, COVER_SCHEMA_VERSION);
}

#[test]
fn enrich_overlap_map_restriction_for_parser_lowering() {
    let map = default_overlap_map();
    let r = map.restriction_for(EngineSurface::Parser, EngineSurface::Lowering);
    assert_eq!(r, Some(OverlapRestriction::DelegationRequired));
}

#[test]
fn enrich_overlap_map_restriction_symmetric_lookup() {
    let map = default_overlap_map();
    let forward = map.restriction_for(EngineSurface::Parser, EngineSurface::Lowering);
    let reverse = map.restriction_for(EngineSurface::Lowering, EngineSurface::Parser);
    assert_eq!(forward, reverse);
}

#[test]
fn enrich_overlap_map_cli_runtime_in_entries() {
    let map = default_overlap_map();
    // The entry has Cli/Runtime pair — verify it exists in entries
    let has_cli_runtime = map.entries.iter().any(|e| {
        (e.surface_a == EngineSurface::Cli && e.surface_b == EngineSurface::Runtime)
            || (e.surface_a == EngineSurface::Runtime && e.surface_b == EngineSurface::Cli)
    });
    assert!(has_cli_runtime);
}

#[test]
fn enrich_overlap_map_module_runtime_in_entries() {
    let map = default_overlap_map();
    // The entry has Module/Runtime pair — verify it exists in entries
    let has_mod_runtime = map.entries.iter().any(|e| {
        (e.surface_a == EngineSurface::Module && e.surface_b == EngineSurface::Runtime)
            || (e.surface_a == EngineSurface::Runtime && e.surface_b == EngineSurface::Module)
    });
    assert!(has_mod_runtime);
}

#[test]
fn enrich_overlap_map_scoped_ts_lookup() {
    let map = default_overlap_map();
    let entries =
        map.restrictions_for_scope(EngineSurface::Parser, EngineSurface::TypeScript, "ts.enum");
    assert!(!entries.is_empty());
}

#[test]
fn enrich_overlap_map_custom_entries() {
    let entries = vec![OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        scope_prefix: None,
        rationale: "test".into(),
    }];
    let map = OverlapRestrictionMap::new(entries);
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.restriction_for(EngineSurface::Parser, EngineSurface::Runtime),
        Some(OverlapRestriction::Exclusive)
    );
}

// ---------------------------------------------------------------------------
// GapSeverity — Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_gap_severity_display_all() {
    let expected = [
        (GapSeverity::Critical, "critical"),
        (GapSeverity::Moderate, "moderate"),
        (GapSeverity::Low, "low"),
        (GapSeverity::Informational, "informational"),
    ];
    for (sev, text) in &expected {
        assert_eq!(sev.to_string(), *text);
    }
}

#[test]
fn enrich_gap_severity_serde_all() {
    let variants = [
        GapSeverity::Critical,
        GapSeverity::Moderate,
        GapSeverity::Low,
        GapSeverity::Informational,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: GapSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CoverSpecimenFamily — Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_specimen_family_display_all() {
    let families = [
        (CoverSpecimenFamily::FullCoverage, "full_coverage"),
        (CoverSpecimenFamily::PartialCoverage, "partial_coverage"),
        (CoverSpecimenFamily::OverlapViolation, "overlap_violation"),
        (CoverSpecimenFamily::UnknownStatus, "unknown_status"),
        (CoverSpecimenFamily::NotApplicable, "not_applicable"),
    ];
    for (family, text) in &families {
        assert_eq!(family.to_string(), *text);
    }
}

#[test]
fn enrich_specimen_family_serde_all() {
    let families = [
        CoverSpecimenFamily::FullCoverage,
        CoverSpecimenFamily::PartialCoverage,
        CoverSpecimenFamily::OverlapViolation,
        CoverSpecimenFamily::UnknownStatus,
        CoverSpecimenFamily::NotApplicable,
    ];
    for f in &families {
        let json = serde_json::to_string(f).unwrap();
        let back: CoverSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ---------------------------------------------------------------------------
// SemanticCover — construction and queries
// ---------------------------------------------------------------------------

#[test]
fn enrich_semantic_cover_empty_features() {
    let cover = SemanticCover::new(vec![], default_overlap_map(), test_epoch());
    assert_eq!(cover.feature_count(), 0);
    assert_eq!(cover.fully_covered_count(), 0);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 0);
    assert!(cover.find_gaps().is_empty());
}

#[test]
fn enrich_semantic_cover_all_supported() {
    let features = vec![make_feature(
        "all_good",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    assert_eq!(cover.feature_count(), 1);
    assert_eq!(cover.fully_covered_count(), 1);
    assert_eq!(cover.gap_count(), 0);
    assert_eq!(cover.coverage_ratio_millionths(), 1_000_000);
}

#[test]
fn enrich_semantic_cover_with_gap() {
    let features = vec![make_feature(
        "has_gap",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    assert_eq!(cover.gap_count(), 1);
    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].feature_key, "has_gap");
    assert!(
        gaps[0]
            .unsupported_surfaces
            .contains(&EngineSurface::Runtime)
    );
}

#[test]
fn enrich_semantic_cover_gap_severity_two_unsupported_is_critical() {
    let features = vec![make_feature(
        "crit",
        &[
            (EngineSurface::Parser, SupportStatus::Unsupported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
            (EngineSurface::Lowering, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let gaps = cover.find_gaps();
    assert_eq!(gaps[0].severity, GapSeverity::Critical);
}

#[test]
fn enrich_semantic_cover_gap_severity_one_unsupported_is_moderate() {
    let features = vec![make_feature(
        "mod",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let gaps = cover.find_gaps();
    assert_eq!(gaps[0].severity, GapSeverity::Moderate);
}

#[test]
fn enrich_semantic_cover_gap_severity_unknown_only_is_low() {
    let features = vec![make_feature(
        "low",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unknown),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let gaps = cover.find_gaps();
    assert_eq!(gaps[0].severity, GapSeverity::Low);
}

#[test]
fn enrich_semantic_cover_get_feature_found() {
    let features = vec![make_feature(
        "needle",
        &[(EngineSurface::Parser, SupportStatus::Supported)],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let f = cover.get_feature("needle");
    assert!(f.is_some());
    assert_eq!(f.unwrap().key, "needle");
}

#[test]
fn enrich_semantic_cover_get_feature_not_found() {
    let cover = SemanticCover::new(vec![], default_overlap_map(), test_epoch());
    assert!(cover.get_feature("missing").is_none());
}

#[test]
fn enrich_semantic_cover_surface_summary_all_surfaces() {
    let features = vec![make_feature(
        "test",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Partial),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let summary = cover.surface_summary();
    assert_eq!(summary.len(), 7); // all 7 surfaces
    assert_eq!(summary[&EngineSurface::Parser].supported, 1);
    assert_eq!(summary[&EngineSurface::Lowering].partial, 1);
    assert_eq!(summary[&EngineSurface::Runtime].unsupported, 1);
}

// ---------------------------------------------------------------------------
// detect_overlap_violations
// ---------------------------------------------------------------------------

#[test]
fn enrich_no_violations_with_allowed_overlap() {
    let features = vec![make_feature(
        "shared",
        &[
            (EngineSurface::Module, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, default_overlap_map(), test_epoch());
    let violations = detect_overlap_violations(&cover);
    assert!(violations.is_empty());
}

#[test]
fn enrich_exclusive_overlap_triggers_violation_with_custom_map() {
    // Build a custom map with properly-ordered exclusive entry (lo < hi)
    let entries = vec![OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Lowering,
        restriction: OverlapRestriction::Exclusive,
        scope_prefix: None,
        rationale: "test exclusive".into(),
    }];
    let map = OverlapRestrictionMap::new(entries);
    let features = vec![make_feature(
        "exclusive_feature",
        &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Supported),
        ],
    )];
    let cover = SemanticCover::new(features, map, test_epoch());
    let violations = detect_overlap_violations(&cover);
    assert!(!violations.is_empty());
    assert_eq!(violations[0].restriction, OverlapRestriction::Exclusive);
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_corpus_has_specimens() {
    let specimens = build_evidence_corpus();
    assert!(!specimens.is_empty());
    assert!(specimens.len() >= 4);
}

#[test]
fn enrich_evidence_corpus_ids_unique() {
    let specimens = build_evidence_corpus();
    let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids.len(), specimens.len());
}

#[test]
fn enrich_run_evidence_corpus_returns_hash() {
    let (specimens, hash) = run_evidence_corpus();
    assert!(!specimens.is_empty());
    assert!(!hash.as_bytes().is_empty());
}

#[test]
fn enrich_run_evidence_corpus_deterministic() {
    let (_, h1) = run_evidence_corpus();
    let (_, h2) = run_evidence_corpus();
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Serde round-trips for compound types
// ---------------------------------------------------------------------------

#[test]
fn enrich_cover_gap_serde() {
    let gap = CoverGap {
        feature_key: "test.gap".into(),
        unsupported_surfaces: {
            let mut s = BTreeSet::new();
            s.insert(EngineSurface::Runtime);
            s
        },
        unknown_surfaces: BTreeSet::new(),
        severity: GapSeverity::Moderate,
    };
    let json = serde_json::to_string(&gap).unwrap();
    let back: CoverGap = serde_json::from_str(&json).unwrap();
    assert_eq!(gap, back);
}

#[test]
fn enrich_overlap_violation_serde() {
    let v = OverlapViolation {
        feature_key: "exclusive_test".into(),
        surface_a: EngineSurface::Cli,
        surface_b: EngineSurface::Runtime,
        restriction: OverlapRestriction::Exclusive,
        description: "Both claim support".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: OverlapViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrich_surface_summary_serde() {
    let summary = SurfaceSummary {
        surface: EngineSurface::Parser,
        total_relevant: 10,
        supported: 8,
        partial: 1,
        unsupported: 1,
        unknown: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SurfaceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrich_cover_specimen_serde() {
    let specimen = CoverSpecimen {
        id: "test-specimen".into(),
        family: CoverSpecimenFamily::FullCoverage,
        description: "A test specimen".into(),
        feature: make_feature(
            "spec_test",
            &[(EngineSurface::Parser, SupportStatus::Supported)],
        ),
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: CoverSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

#[test]
fn enrich_overlap_entry_serde() {
    let entry = OverlapEntry {
        surface_a: EngineSurface::Parser,
        surface_b: EngineSurface::Lowering,
        restriction: OverlapRestriction::DelegationRequired,
        scope_prefix: Some("es2024.".into()),
        rationale: "test rationale".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: OverlapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}
