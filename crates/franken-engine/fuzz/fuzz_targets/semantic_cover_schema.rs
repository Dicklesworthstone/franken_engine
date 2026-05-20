#![no_main]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_cover_schema::{
    COVER_SCHEMA_VERSION, CoverFeature, CoverSpecimen, EngineSurface, GapSeverity, OverlapEntry,
    OverlapRestriction, OverlapRestrictionMap, SemanticCover, default_overlap_map,
    detect_overlap_violations,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_CASE_FEATURES: usize = 64;
const MAX_CASE_OVERLAPS: usize = 64;
const MAX_FIELD_BYTES: usize = 512;
const MAX_EVIDENCE_KEYS: usize = 64;
const SCOPE_PROBES: [&str; 6] = [
    "",
    "es2015.arrowFunction",
    "ts.module.importType",
    "jsx.element",
    "react.component",
    "cli.doctor",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(feature) = serde_json::from_slice::<CoverFeature>(data)
        && feature_is_bounded(&feature)
    {
        exercise_feature(&feature);
        exercise_cover(&SemanticCover::new(
            vec![feature],
            default_overlap_map(),
            epoch_for_input(data),
        ));
    }

    if let Ok(features) = serde_json::from_slice::<Vec<CoverFeature>>(data)
        && let Some(features) = bounded_features(features)
    {
        exercise_cover(&SemanticCover::new(
            features,
            default_overlap_map(),
            epoch_for_input(data),
        ));
    }

    if let Ok(entries) = serde_json::from_slice::<Vec<OverlapEntry>>(data)
        && let Some(entries) = bounded_entries(entries)
    {
        let map = OverlapRestrictionMap::new(entries);
        exercise_overlap_map(&map);
        exercise_cover(&SemanticCover::new(Vec::new(), map, epoch_for_input(data)));
    }

    if let Ok(map) = serde_json::from_slice::<OverlapRestrictionMap>(data)
        && map_is_bounded(&map)
    {
        exercise_overlap_map(&map);
    }

    if let Ok(cover) = serde_json::from_slice::<SemanticCover>(data)
        && cover_is_bounded(&cover)
    {
        exercise_cover(&cover);
    }

    if let Ok(specimen) = serde_json::from_slice::<CoverSpecimen>(data)
        && feature_is_bounded(&specimen.feature)
    {
        exercise_feature(&specimen.feature);
        let encoded = serde_json::to_vec(&specimen).expect("cover specimen serializes");
        let decoded: CoverSpecimen =
            serde_json::from_slice(&encoded).expect("cover specimen re-parses");
        assert_eq!(decoded, specimen);
    }
});

fn epoch_for_input(data: &[u8]) -> SecurityEpoch {
    let mut raw = data.len() as u64;
    for byte in data.iter().take(8) {
        raw = raw.rotate_left(5) ^ u64::from(*byte);
    }
    SecurityEpoch::from_raw(raw)
}

fn exercise_feature(feature: &CoverFeature) {
    assert!(feature.supported_surface_count() <= feature.relevant_surfaces.len());

    let ratio = feature.coverage_ratio_millionths();
    assert!((0..=1_000_000).contains(&ratio));
    if feature.relevant_surfaces.is_empty() {
        assert_eq!(ratio, 0);
    } else if feature.is_fully_covered() {
        assert_eq!(ratio, 1_000_000);
    }
    if feature.has_gap() {
        assert!(!feature.is_fully_covered());
    }

    let encoded = serde_json::to_vec(feature).expect("cover feature serializes");
    let decoded: CoverFeature = serde_json::from_slice(&encoded).expect("cover feature re-parses");
    assert_eq!(&decoded, feature);
}

fn exercise_overlap_map(map: &OverlapRestrictionMap) {
    assert_eq!(map.len(), map.entries.len());
    assert_eq!(map.is_empty(), map.entries.is_empty());

    for surface_a in EngineSurface::all() {
        for surface_b in EngineSurface::all() {
            assert_eq!(
                map.restriction_for(*surface_a, *surface_b),
                map.restriction_for(*surface_b, *surface_a)
            );
            for probe in SCOPE_PROBES {
                assert_eq!(
                    map.restrictions_for_scope(*surface_a, *surface_b, probe)
                        .len(),
                    map.restrictions_for_scope(*surface_b, *surface_a, probe)
                        .len()
                );
            }
        }
    }

    let canonical = OverlapRestrictionMap::new(map.entries.clone());
    let canonical_again = OverlapRestrictionMap::new(map.entries.clone());
    assert_eq!(canonical.schema_version, COVER_SCHEMA_VERSION);
    assert_eq!(canonical.content_hash, canonical_again.content_hash);

    let encoded = serde_json::to_vec(&canonical).expect("overlap map serializes");
    let decoded: OverlapRestrictionMap =
        serde_json::from_slice(&encoded).expect("overlap map re-parses");
    assert_eq!(decoded.schema_version, canonical.schema_version);
    assert_eq!(decoded.entries, canonical.entries);
    assert_eq!(decoded.content_hash, canonical.content_hash);
}

fn exercise_cover(cover: &SemanticCover) {
    assert_eq!(cover.feature_count(), cover.features.len());
    assert!(cover.fully_covered_count() <= cover.feature_count());
    assert!(cover.gap_count() <= cover.feature_count());

    let coverage = cover.coverage_ratio_millionths();
    assert!((0..=1_000_000).contains(&coverage));
    if cover.features.is_empty() {
        assert_eq!(coverage, 0);
    }

    for feature in &cover.features {
        exercise_feature(feature);
        assert!(cover.get_feature(&feature.key).is_some());
    }

    let gaps = cover.find_gaps();
    assert_eq!(gaps.len(), cover.gap_count());
    for gap in &gaps {
        assert!(cover.get_feature(&gap.feature_key).is_some());
        assert!(gap.unsupported_surfaces.is_disjoint(&gap.unknown_surfaces));
        let expected_severity = if gap.unsupported_surfaces.len() >= 2 {
            GapSeverity::Critical
        } else if !gap.unsupported_surfaces.is_empty() {
            GapSeverity::Moderate
        } else if !gap.unknown_surfaces.is_empty() {
            GapSeverity::Low
        } else {
            GapSeverity::Informational
        };
        assert_eq!(gap.severity, expected_severity);
    }

    let summaries = cover.surface_summary();
    assert_eq!(summaries.len(), EngineSurface::all().len());
    for (surface, summary) in summaries {
        assert_eq!(surface, summary.surface);
        assert!(summary.total_relevant <= cover.feature_count());
        assert!(summary.supported <= summary.total_relevant);
        assert!(summary.partial <= summary.total_relevant);
        assert!(summary.unsupported <= summary.total_relevant);
        assert!(summary.unknown <= summary.total_relevant);
        assert!(
            summary
                .supported
                .saturating_add(summary.partial)
                .saturating_add(summary.unsupported)
                .saturating_add(summary.unknown)
                <= summary.total_relevant
        );
    }

    for violation in detect_overlap_violations(cover) {
        assert_eq!(violation.restriction, OverlapRestriction::Exclusive);
        assert_ne!(violation.surface_a, violation.surface_b);
        assert!(cover.get_feature(&violation.feature_key).is_some());
        assert!(!violation.description.is_empty());
    }

    let canonical_overlap = OverlapRestrictionMap::new(cover.overlap_map.entries.clone());
    let canonical = SemanticCover::new(cover.features.clone(), canonical_overlap, cover.epoch);
    let canonical_again = SemanticCover::new(
        cover.features.clone(),
        OverlapRestrictionMap::new(cover.overlap_map.entries.clone()),
        cover.epoch,
    );
    assert_eq!(canonical.schema_version, COVER_SCHEMA_VERSION);
    assert_eq!(canonical.feature_count(), cover.feature_count());
    assert_eq!(canonical.content_hash, canonical_again.content_hash);

    let encoded = serde_json::to_vec(&canonical).expect("semantic cover serializes");
    let decoded: SemanticCover =
        serde_json::from_slice(&encoded).expect("semantic cover re-parses");
    assert_eq!(decoded.schema_version, canonical.schema_version);
    assert_eq!(decoded.features.len(), canonical.features.len());
    assert_eq!(decoded.overlap_map.entries, canonical.overlap_map.entries);
    assert_eq!(decoded.content_hash, canonical.content_hash);
}

fn cover_is_bounded(cover: &SemanticCover) -> bool {
    cover.features.len() <= MAX_CASE_FEATURES
        && cover.features.iter().all(feature_is_bounded)
        && map_is_bounded(&cover.overlap_map)
}

fn map_is_bounded(map: &OverlapRestrictionMap) -> bool {
    map.entries.len() <= MAX_CASE_OVERLAPS && map.entries.iter().all(entry_is_bounded)
}

fn bounded_features(features: Vec<CoverFeature>) -> Option<Vec<CoverFeature>> {
    (features.len() <= MAX_CASE_FEATURES && features.iter().all(feature_is_bounded))
        .then_some(features)
}

fn bounded_entries(entries: Vec<OverlapEntry>) -> Option<Vec<OverlapEntry>> {
    (entries.len() <= MAX_CASE_OVERLAPS && entries.iter().all(entry_is_bounded)).then_some(entries)
}

fn feature_is_bounded(feature: &CoverFeature) -> bool {
    field_is_bounded(&feature.key)
        && field_is_bounded(&feature.description)
        && field_is_bounded(&feature.spec_area)
        && feature.evidence_keys.len() <= MAX_EVIDENCE_KEYS
        && feature
            .evidence_keys
            .iter()
            .all(|key| field_is_bounded(key))
}

fn entry_is_bounded(entry: &OverlapEntry) -> bool {
    entry
        .scope_prefix
        .as_ref()
        .is_none_or(|scope| field_is_bounded(scope))
        && field_is_bounded(&entry.rationale)
}

fn field_is_bounded(value: &str) -> bool {
    value.len() <= MAX_FIELD_BYTES
}
