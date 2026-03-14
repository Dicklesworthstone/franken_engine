#![forbid(unsafe_code)]

//! Enrichment integration tests for the frontier_complex_cartography module.

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

use std::collections::BTreeSet;

use frankenengine_engine::frontier_complex_cartography::{
    BEAD_ID, COMPONENT, CartographyError, FrontierComplex, HoleLedger, HoleSignificance,
    LedgerSummary, MILLIONTHS, POLICY_ID, PersistenceDiagram, PersistencePair, SCHEMA_VERSION,
    Simplex, SimplexDimension, bottleneck_distance_approx, build_complex, classify_hole,
    compute_persistence, euler_characteristic, filter_significant_holes,
    franken_engine_frontier_manifest, ledger_summary, stability_score, total_persistence,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vertex(id: &str, filt: u64) -> Simplex {
    Simplex {
        simplex_id: id.to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec![id.to_string()],
        filtration_value_millionths: filt,
    }
}

fn edge(id: &str, v1: &str, v2: &str, filt: u64) -> Simplex {
    Simplex {
        simplex_id: id.to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec![v1.to_string(), v2.to_string()],
        filtration_value_millionths: filt,
    }
}

fn simple_complex() -> FrontierComplex {
    build_complex(vec![
        vertex("v0", 0),
        vertex("v1", 100_000),
        edge("e01", "v0", "v1", 200_000),
    ])
    .unwrap()
}

// ---------------------------------------------------------------------------
// SimplexDimension — Copy / BTreeSet / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_simplex_dimension_copy_semantics() {
    let a = SimplexDimension::Vertex;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_simplex_dimension_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(SimplexDimension::Vertex);
    set.insert(SimplexDimension::Edge);
    set.insert(SimplexDimension::Triangle);
    set.insert(SimplexDimension::Tetrahedron);
    set.insert(SimplexDimension::HigherDim(4));
    set.insert(SimplexDimension::Vertex);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_simplex_dimension_clone_independence() {
    let a = SimplexDimension::Triangle;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_simplex_dimension_debug_nonempty() {
    assert!(!format!("{:?}", SimplexDimension::Vertex).is_empty());
    assert!(!format!("{:?}", SimplexDimension::HigherDim(5)).is_empty());
}

#[test]
fn enrichment_simplex_dimension_as_u32_roundtrip() {
    for dim in 0..=5u32 {
        let sd = SimplexDimension::from_u32(dim);
        assert_eq!(sd.as_u32(), dim);
    }
}

#[test]
fn enrichment_simplex_dimension_expected_vertex_count() {
    assert_eq!(SimplexDimension::Vertex.expected_vertex_count(), 1);
    assert_eq!(SimplexDimension::Edge.expected_vertex_count(), 2);
    assert_eq!(SimplexDimension::Triangle.expected_vertex_count(), 3);
    assert_eq!(SimplexDimension::Tetrahedron.expected_vertex_count(), 4);
    assert_eq!(SimplexDimension::HigherDim(4).expected_vertex_count(), 5);
}

#[test]
fn enrichment_simplex_dimension_display_nonempty() {
    let dims = [
        SimplexDimension::Vertex,
        SimplexDimension::Edge,
        SimplexDimension::Triangle,
        SimplexDimension::Tetrahedron,
        SimplexDimension::HigherDim(4),
    ];
    let displays: BTreeSet<String> = dims.iter().map(|d| format!("{}", d)).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_simplex_dimension_serde_roundtrip() {
    let dims = [
        SimplexDimension::Vertex,
        SimplexDimension::Edge,
        SimplexDimension::Triangle,
        SimplexDimension::Tetrahedron,
        SimplexDimension::HigherDim(7),
    ];
    for d in &dims {
        let json = serde_json::to_string(d).unwrap();
        let rt: SimplexDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, rt);
    }
}

// ---------------------------------------------------------------------------
// HoleSignificance — Copy / BTreeSet / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hole_significance_copy_semantics() {
    let a = HoleSignificance::Persistent;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_hole_significance_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(HoleSignificance::Persistent);
    set.insert(HoleSignificance::Transient);
    set.insert(HoleSignificance::SamplingNoise);
    set.insert(HoleSignificance::Structural);
    set.insert(HoleSignificance::Persistent);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_hole_significance_clone_independence() {
    let a = HoleSignificance::Structural;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_hole_significance_is_actionable() {
    assert!(HoleSignificance::Persistent.is_actionable());
    assert!(HoleSignificance::Structural.is_actionable());
    assert!(!HoleSignificance::Transient.is_actionable());
    assert!(!HoleSignificance::SamplingNoise.is_actionable());
}

#[test]
fn enrichment_hole_significance_display_all_unique() {
    let sigs = [
        HoleSignificance::Persistent,
        HoleSignificance::Transient,
        HoleSignificance::SamplingNoise,
        HoleSignificance::Structural,
    ];
    let displays: BTreeSet<String> = sigs.iter().map(|s| format!("{}", s)).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_hole_significance_serde_roundtrip_all() {
    let sigs = [
        HoleSignificance::Persistent,
        HoleSignificance::Transient,
        HoleSignificance::SamplingNoise,
        HoleSignificance::Structural,
    ];
    for s in &sigs {
        let json = serde_json::to_string(s).unwrap();
        let rt: HoleSignificance = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, rt);
    }
}

// ---------------------------------------------------------------------------
// CartographyError — Clone / Debug / Display / Error / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cartography_error_clone_independence() {
    let a = CartographyError::EmptyComplex;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_cartography_error_debug_all_unique() {
    let errors = [
        CartographyError::EmptyComplex,
        CartographyError::InvalidSimplex,
        CartographyError::FiltrationViolation,
        CartographyError::DiagramInconsistent,
        CartographyError::InternalError("test".to_string()),
    ];
    let dbgs: BTreeSet<String> = errors.iter().map(|e| format!("{:?}", e)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_cartography_error_display_all_unique() {
    let errors = [
        CartographyError::EmptyComplex,
        CartographyError::InvalidSimplex,
        CartographyError::FiltrationViolation,
        CartographyError::DiagramInconsistent,
        CartographyError::InternalError("msg".to_string()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{}", e)).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_cartography_error_is_std_error() {
    let e = CartographyError::EmptyComplex;
    let _err_ref: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_cartography_error_serde_roundtrip_all() {
    let errors = [
        CartographyError::EmptyComplex,
        CartographyError::InvalidSimplex,
        CartographyError::FiltrationViolation,
        CartographyError::DiagramInconsistent,
        CartographyError::InternalError("test".to_string()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: CartographyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ---------------------------------------------------------------------------
// Simplex — Clone / Debug / JSON / validate / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_simplex_clone_independence() {
    let s = vertex("v0", 0);
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_simplex_debug_nonempty() {
    assert!(!format!("{:?}", vertex("v0", 0)).is_empty());
}

#[test]
fn enrichment_simplex_json_field_names() {
    let s = vertex("v0", 0);
    let json = serde_json::to_string(&s).unwrap();
    for field in &[
        "simplex_id",
        "dimension",
        "vertices",
        "filtration_value_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_simplex_validate_correct() {
    assert!(vertex("v0", 0).validate().is_ok());
    assert!(edge("e01", "v0", "v1", 100).validate().is_ok());
}

#[test]
fn enrichment_simplex_validate_wrong_vertex_count() {
    let mut s = vertex("v0", 0);
    s.vertices.push("extra".to_string());
    assert!(s.validate().is_err());
}

#[test]
fn enrichment_simplex_content_hash_deterministic() {
    let s1 = vertex("v0", 100);
    let s2 = vertex("v0", 100);
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn enrichment_simplex_content_hash_differs() {
    let s1 = vertex("v0", 100);
    let s2 = vertex("v1", 100);
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn enrichment_simplex_serde_roundtrip() {
    let s = edge("e01", "v0", "v1", 200_000);
    let json = serde_json::to_string(&s).unwrap();
    let rt: Simplex = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

// ---------------------------------------------------------------------------
// FrontierComplex — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_complex_clone_independence() {
    let c = simple_complex();
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_frontier_complex_debug_nonempty() {
    assert!(!format!("{:?}", simple_complex()).is_empty());
}

#[test]
fn enrichment_frontier_complex_count_at_dimension() {
    let c = simple_complex();
    assert_eq!(c.count_at_dimension(0), 2);
    assert_eq!(c.count_at_dimension(1), 1);
    assert_eq!(c.count_at_dimension(2), 0);
}

#[test]
fn enrichment_frontier_complex_filtration_range() {
    let c = simple_complex();
    let range = c.filtration_range();
    assert!(range.is_some());
    let (min, max) = range.unwrap();
    assert_eq!(min, 0);
    assert_eq!(max, 200_000);
}

#[test]
fn enrichment_frontier_complex_serde_roundtrip() {
    let c = simple_complex();
    let json = serde_json::to_string(&c).unwrap();
    let rt: FrontierComplex = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ---------------------------------------------------------------------------
// build_complex — validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_complex_empty_fails() {
    let result = build_complex(vec![]);
    assert!(result.is_err());
}

#[test]
fn enrichment_build_complex_single_vertex() {
    let c = build_complex(vec![vertex("v0", 0)]).unwrap();
    assert_eq!(c.max_dimension, 0);
    assert_eq!(c.vertex_count, 1);
}

// ---------------------------------------------------------------------------
// PersistencePair — Clone / Debug / JSON / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_persistence_pair_clone_independence() {
    let p = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: 100_000,
        dimension: 0,
        generator_simplex: "v0".to_string(),
        killer_simplex: Some("e01".to_string()),
        persistence_millionths: 100_000,
    };
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn enrichment_persistence_pair_debug_nonempty() {
    let p = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: u64::MAX,
        dimension: 1,
        generator_simplex: "g1".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX,
    };
    assert!(!format!("{:?}", p).is_empty());
}

#[test]
fn enrichment_persistence_pair_is_essential() {
    let essential = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: u64::MAX,
        dimension: 0,
        generator_simplex: "v0".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX,
    };
    assert!(essential.is_essential());

    let finite = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: 100_000,
        dimension: 0,
        generator_simplex: "v0".to_string(),
        killer_simplex: Some("e01".to_string()),
        persistence_millionths: 100_000,
    };
    assert!(!finite.is_essential());
}

#[test]
fn enrichment_persistence_pair_serde_roundtrip() {
    let p = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "g1".to_string(),
        killer_simplex: Some("k1".to_string()),
        persistence_millionths: 500_000,
    };
    let json = serde_json::to_string(&p).unwrap();
    let rt: PersistencePair = serde_json::from_str(&json).unwrap();
    assert_eq!(p, rt);
}

// ---------------------------------------------------------------------------
// PersistenceDiagram — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_persistence_diagram_clone_independence() {
    let c = simple_complex();
    let d = compute_persistence(&c).unwrap();
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn enrichment_persistence_diagram_debug_nonempty() {
    let c = simple_complex();
    let d = compute_persistence(&c).unwrap();
    assert!(!format!("{:?}", d).is_empty());
}

#[test]
fn enrichment_persistence_diagram_serde_roundtrip() {
    let c = simple_complex();
    let d = compute_persistence(&c).unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let rt: PersistenceDiagram = serde_json::from_str(&json).unwrap();
    assert_eq!(d, rt);
}

// ---------------------------------------------------------------------------
// classify_hole — thresholds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_hole_structural() {
    let pair = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: u64::MAX,
        dimension: 0,
        generator_simplex: "v0".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX,
    };
    assert_eq!(
        classify_hole(&pair, 500_000, 100),
        HoleSignificance::Structural
    );
}

#[test]
fn enrichment_classify_hole_noise_low_samples() {
    let pair = PersistencePair {
        birth_filtration_millionths: 0,
        death_filtration_millionths: 900_000,
        dimension: 0,
        generator_simplex: "v0".to_string(),
        killer_simplex: Some("e01".to_string()),
        persistence_millionths: 900_000,
    };
    // With sample_count < 10, should be SamplingNoise
    assert_eq!(
        classify_hole(&pair, 500_000, 5),
        HoleSignificance::SamplingNoise
    );
}

// ---------------------------------------------------------------------------
// HoleLedger — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hole_ledger_clone_independence() {
    let m = franken_engine_frontier_manifest();
    let m2 = m.clone();
    assert_eq!(m, m2);
}

#[test]
fn enrichment_hole_ledger_debug_nonempty() {
    assert!(!format!("{:?}", franken_engine_frontier_manifest()).is_empty());
}

#[test]
fn enrichment_hole_ledger_total_holes() {
    let m = franken_engine_frontier_manifest();
    assert_eq!(m.total_holes(), m.holes.len());
}

#[test]
fn enrichment_hole_ledger_serde_roundtrip() {
    let m = franken_engine_frontier_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let rt: HoleLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}

// ---------------------------------------------------------------------------
// LedgerSummary — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ledger_summary_clone_independence() {
    let m = franken_engine_frontier_manifest();
    let s = ledger_summary(&m);
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_ledger_summary_debug_nonempty() {
    let m = franken_engine_frontier_manifest();
    assert!(!format!("{:?}", ledger_summary(&m)).is_empty());
}

#[test]
fn enrichment_ledger_summary_json_field_names() {
    let m = franken_engine_frontier_manifest();
    let s = ledger_summary(&m);
    let json = serde_json::to_string(&s).unwrap();
    for field in &[
        "ledger_id",
        "epoch",
        "total_holes",
        "persistent_holes",
        "transient_holes",
        "noise_holes",
        "structural_holes",
        "stability_score_millionths",
        "threshold_millionths",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_ledger_summary_serde_roundtrip() {
    let m = franken_engine_frontier_manifest();
    let s = ledger_summary(&m);
    let json = serde_json::to_string(&s).unwrap();
    let rt: LedgerSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

// ---------------------------------------------------------------------------
// Free functions — euler_characteristic / bottleneck / stability / filter
// ---------------------------------------------------------------------------

#[test]
fn enrichment_euler_characteristic_two_vertices_one_edge() {
    let c = simple_complex();
    // chi = 2 vertices - 1 edge = 1
    assert_eq!(euler_characteristic(&c), 1);
}

#[test]
fn enrichment_euler_characteristic_two_vertices_no_edge() {
    let c = build_complex(vec![vertex("v0", 0), vertex("v1", 100_000)]).unwrap();
    // chi = 2 - 0 = 2
    assert_eq!(euler_characteristic(&c), 2);
}

#[test]
fn enrichment_bottleneck_distance_same_diagram() {
    let c = simple_complex();
    let d = compute_persistence(&c).unwrap();
    let dist = bottleneck_distance_approx(&d, &d);
    assert_eq!(dist, Some(0));
}

#[test]
fn enrichment_stability_score_manifest() {
    let m = franken_engine_frontier_manifest();
    let score = stability_score(&m);
    assert!(score <= MILLIONTHS);
}

#[test]
fn enrichment_filter_significant_holes_manifest() {
    let m = franken_engine_frontier_manifest();
    let sig = filter_significant_holes(&m);
    for h in &sig {
        assert!(h.significance.is_actionable());
    }
}

#[test]
fn enrichment_total_persistence_equals_diagram() {
    let c = simple_complex();
    let d = compute_persistence(&c).unwrap();
    assert_eq!(total_persistence(&d), d.total_persistence_millionths);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.frontier-complex-cartography.v1"
    );
    assert_eq!(BEAD_ID, "bd-1lsy.9.9.1");
    assert_eq!(COMPONENT, "frontier_complex_cartography");
    assert_eq!(POLICY_ID, "RGC-809A");
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_complex() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&simple_complex()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "complex should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_manifest() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&franken_engine_frontier_manifest()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "manifest should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_manifest_has_all_significance_classes() {
    let m = franken_engine_frontier_manifest();
    let classes: BTreeSet<HoleSignificance> = m.holes.iter().map(|h| h.significance).collect();
    assert!(classes.contains(&HoleSignificance::Persistent));
    assert!(classes.contains(&HoleSignificance::Structural));
}

#[test]
fn enrichment_cross_cutting_ledger_counts_consistent() {
    let m = franken_engine_frontier_manifest();
    let summary = ledger_summary(&m);
    assert_eq!(
        summary.persistent_holes
            + summary.transient_holes
            + summary.noise_holes
            + summary.structural_holes,
        summary.total_holes
    );
}

#[test]
fn enrichment_cross_cutting_stability_score_in_summary() {
    let m = franken_engine_frontier_manifest();
    let summary = ledger_summary(&m);
    assert_eq!(summary.stability_score_millionths, stability_score(&m));
}

#[test]
fn enrichment_cross_cutting_hole_ids_unique() {
    let m = franken_engine_frontier_manifest();
    let ids: BTreeSet<&str> = m.holes.iter().map(|h| h.hole_id.as_str()).collect();
    assert_eq!(ids.len(), m.holes.len());
}
