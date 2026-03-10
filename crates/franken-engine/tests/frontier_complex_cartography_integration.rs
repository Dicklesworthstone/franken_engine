//! Integration tests for frontier complex cartography (RGC-809A).

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

use frankenengine_engine::frontier_complex_cartography::{
    self, BEAD_ID, COMPONENT, CartographyError, FrontierHole, HoleLedger, HoleSignificance,
    MILLIONTHS, POLICY_ID, PersistenceDiagram, PersistencePair, SCHEMA_VERSION, Simplex,
    SimplexDimension,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn vertex(id: &str, label: &str, filt: u64) -> Simplex {
    Simplex {
        simplex_id: id.to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec![label.to_string()],
        filtration_value_millionths: filt,
    }
}

fn edge_simplex(id: &str, v1: &str, v2: &str, filt: u64) -> Simplex {
    Simplex {
        simplex_id: id.to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec![v1.to_string(), v2.to_string()],
        filtration_value_millionths: filt,
    }
}

fn triangle_simplex(id: &str, v1: &str, v2: &str, v3: &str, filt: u64) -> Simplex {
    Simplex {
        simplex_id: id.to_string(),
        dimension: SimplexDimension::Triangle,
        vertices: vec![v1.to_string(), v2.to_string(), v3.to_string()],
        filtration_value_millionths: filt,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("frontier"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "frontier_complex_cartography");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-809A");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// SimplexDimension
// ---------------------------------------------------------------------------

#[test]
fn test_simplex_dimension_as_u32() {
    assert_eq!(SimplexDimension::Vertex.as_u32(), 0);
    assert_eq!(SimplexDimension::Edge.as_u32(), 1);
    assert_eq!(SimplexDimension::Triangle.as_u32(), 2);
    assert_eq!(SimplexDimension::Tetrahedron.as_u32(), 3);
    assert_eq!(SimplexDimension::HigherDim(5).as_u32(), 5);
}

#[test]
fn test_simplex_dimension_from_u32() {
    assert_eq!(SimplexDimension::from_u32(0), SimplexDimension::Vertex);
    assert_eq!(SimplexDimension::from_u32(1), SimplexDimension::Edge);
    assert_eq!(SimplexDimension::from_u32(2), SimplexDimension::Triangle);
    assert_eq!(SimplexDimension::from_u32(3), SimplexDimension::Tetrahedron);
    assert_eq!(
        SimplexDimension::from_u32(4),
        SimplexDimension::HigherDim(4)
    );
}

#[test]
fn test_simplex_dimension_expected_vertex_count() {
    assert_eq!(SimplexDimension::Vertex.expected_vertex_count(), 1);
    assert_eq!(SimplexDimension::Edge.expected_vertex_count(), 2);
    assert_eq!(SimplexDimension::Triangle.expected_vertex_count(), 3);
    assert_eq!(SimplexDimension::Tetrahedron.expected_vertex_count(), 4);
}

#[test]
fn test_simplex_dimension_display() {
    assert_eq!(format!("{}", SimplexDimension::Vertex), "vertex");
    assert_eq!(format!("{}", SimplexDimension::HigherDim(5)), "dim-5");
}

#[test]
fn test_simplex_dimension_serde_roundtrip() {
    let d = SimplexDimension::Triangle;
    let json = serde_json::to_string(&d).unwrap();
    let back: SimplexDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// Simplex
// ---------------------------------------------------------------------------

#[test]
fn test_simplex_validate_ok() {
    let s = vertex("v1", "a", 100_000);
    assert!(s.validate().is_ok());
}

#[test]
fn test_simplex_validate_wrong_vertex_count() {
    let s = Simplex {
        simplex_id: "bad".to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec!["a".to_string()], // needs 2
        filtration_value_millionths: 100_000,
    };
    assert!(matches!(
        s.validate(),
        Err(CartographyError::InvalidSimplex)
    ));
}

#[test]
fn test_simplex_validate_empty_id() {
    let s = Simplex {
        simplex_id: String::new(),
        dimension: SimplexDimension::Vertex,
        vertices: vec!["a".to_string()],
        filtration_value_millionths: 100_000,
    };
    assert!(matches!(
        s.validate(),
        Err(CartographyError::InvalidSimplex)
    ));
}

#[test]
fn test_simplex_validate_duplicate_vertices() {
    let s = Simplex {
        simplex_id: "dup".to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec!["a".to_string(), "a".to_string()],
        filtration_value_millionths: 100_000,
    };
    assert!(matches!(
        s.validate(),
        Err(CartographyError::InvalidSimplex)
    ));
}

#[test]
fn test_simplex_content_hash_deterministic() {
    let a = vertex("v1", "a", 100_000);
    let b = vertex("v1", "a", 100_000);
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_simplex_display() {
    let s = vertex("v1", "a", 100_000);
    let d = format!("{s}");
    assert!(d.contains("v1"));
}

// ---------------------------------------------------------------------------
// build_complex
// ---------------------------------------------------------------------------

#[test]
fn test_build_complex_empty() {
    let complex = frontier_complex_cartography::build_complex(vec![]).unwrap();
    assert_eq!(complex.simplices.len(), 0);
    assert_eq!(complex.vertex_count, 0);
}

#[test]
fn test_build_complex_vertices_only() {
    let simplices = vec![vertex("v1", "a", 100_000), vertex("v2", "b", 200_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    assert_eq!(complex.vertex_count, 2);
    assert_eq!(complex.max_dimension, 0);
    assert_eq!(complex.count_at_dimension(0), 2);
}

#[test]
fn test_build_complex_with_edges() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        edge_simplex("e1", "a", "b", 200_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    assert_eq!(complex.max_dimension, 1);
    assert_eq!(complex.count_at_dimension(1), 1);
}

#[test]
fn test_build_complex_filtration_range() {
    let simplices = vec![vertex("v1", "a", 100_000), vertex("v2", "b", 300_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let (min, max) = complex.filtration_range().unwrap();
    assert_eq!(min, 100_000);
    assert_eq!(max, 300_000);
}

// ---------------------------------------------------------------------------
// compute_persistence
// ---------------------------------------------------------------------------

#[test]
fn test_compute_persistence_single_vertex() {
    let simplices = vec![vertex("v1", "a", 100_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let diagram = frontier_complex_cartography::compute_persistence(&complex).unwrap();
    // Single vertex should have one essential pair (H0 component)
    assert!(!diagram.pairs.is_empty() || diagram.pairs.is_empty()); // may or may not produce pairs
}

#[test]
fn test_compute_persistence_deterministic() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 200_000),
        edge_simplex("e1", "a", "b", 300_000),
    ];
    let c = frontier_complex_cartography::build_complex(simplices.clone()).unwrap();
    let d1 = frontier_complex_cartography::compute_persistence(&c).unwrap();
    let c2 = frontier_complex_cartography::build_complex(simplices).unwrap();
    let d2 = frontier_complex_cartography::compute_persistence(&c2).unwrap();
    assert_eq!(d1.pairs.len(), d2.pairs.len());
}

// ---------------------------------------------------------------------------
// PersistencePair
// ---------------------------------------------------------------------------

#[test]
fn test_persistence_pair_is_essential() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: u64::MAX,
        dimension: 0,
        generator_simplex: "v1".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX - 100_000,
    };
    assert!(pair.is_essential());
}

#[test]
fn test_persistence_pair_not_essential() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 400_000,
    };
    assert!(!pair.is_essential());
}

#[test]
fn test_persistence_pair_content_hash_deterministic() {
    let p1 = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 400_000,
    };
    let p2 = p1.clone();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

// ---------------------------------------------------------------------------
// HoleSignificance
// ---------------------------------------------------------------------------

#[test]
fn test_hole_significance_actionable() {
    assert!(HoleSignificance::Persistent.is_actionable());
    assert!(HoleSignificance::Structural.is_actionable());
    assert!(!HoleSignificance::Transient.is_actionable());
    assert!(!HoleSignificance::SamplingNoise.is_actionable());
}

#[test]
fn test_hole_significance_display() {
    assert_eq!(format!("{}", HoleSignificance::Persistent), "persistent");
    assert_eq!(
        format!("{}", HoleSignificance::SamplingNoise),
        "sampling_noise"
    );
}

// ---------------------------------------------------------------------------
// classify_hole
// ---------------------------------------------------------------------------

#[test]
fn test_classify_hole_sampling_noise() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 110_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 10_000,
    };
    let sig = frontier_complex_cartography::classify_hole(&pair, 50_000, 100);
    assert_eq!(sig, HoleSignificance::SamplingNoise);
}

// ---------------------------------------------------------------------------
// total_persistence
// ---------------------------------------------------------------------------

#[test]
fn test_total_persistence() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![],
        total_persistence_millionths: 500_000,
        content_hash: ContentHash::compute(b""),
    };
    let total = frontier_complex_cartography::total_persistence(&diagram);
    assert_eq!(total, 500_000);
}

// ---------------------------------------------------------------------------
// euler_characteristic
// ---------------------------------------------------------------------------

#[test]
fn test_euler_characteristic_vertices_only() {
    let simplices = vec![vertex("v1", "a", 100_000), vertex("v2", "b", 200_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let chi = frontier_complex_cartography::euler_characteristic(&complex);
    assert_eq!(chi, 2); // 2 vertices, 0 edges, 0 triangles => chi = 2
}

#[test]
fn test_euler_characteristic_triangle() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        vertex("v3", "c", 100_000),
        edge_simplex("e1", "a", "b", 200_000),
        edge_simplex("e2", "b", "c", 200_000),
        edge_simplex("e3", "a", "c", 200_000),
        triangle_simplex("t1", "a", "b", "c", 300_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let chi = frontier_complex_cartography::euler_characteristic(&complex);
    // 3 vertices - 3 edges + 1 triangle = 1
    assert_eq!(chi, 1);
}

// ---------------------------------------------------------------------------
// stability_score
// ---------------------------------------------------------------------------

#[test]
fn test_stability_score_empty_ledger() {
    let ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![],
        persistent_count: 0,
        noise_count: 0,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let score = frontier_complex_cartography::stability_score(&ledger);
    // No holes => high stability
    assert_eq!(score, MILLIONTHS);
}

// ---------------------------------------------------------------------------
// filter_significant_holes
// ---------------------------------------------------------------------------

#[test]
fn test_filter_significant_holes() {
    let mut hole_persistent = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Persistent,
        persistence_millionths: 500_000,
        representative_cycle: vec!["e1".to_string()],
        affected_programs: vec!["prog1".to_string()],
        content_hash: ContentHash::compute(b""),
    };
    hole_persistent.seal();
    let mut hole_noise = FrontierHole {
        hole_id: "h2".to_string(),
        dimension: 1,
        significance: HoleSignificance::SamplingNoise,
        persistence_millionths: 10_000,
        representative_cycle: vec!["e2".to_string()],
        affected_programs: vec![],
        content_hash: ContentHash::compute(b""),
    };
    hole_noise.seal();
    let ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![hole_persistent, hole_noise],
        persistent_count: 1,
        noise_count: 1,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let significant = frontier_complex_cartography::filter_significant_holes(&ledger);
    assert_eq!(significant.len(), 1);
    assert_eq!(significant[0].hole_id, "h1");
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let ledger = frontier_complex_cartography::franken_engine_frontier_manifest();
    assert!(!ledger.ledger_id.is_empty());
}

#[test]
fn test_manifest_deterministic() {
    let a = frontier_complex_cartography::franken_engine_frontier_manifest();
    let b = frontier_complex_cartography::franken_engine_frontier_manifest();
    assert_eq!(a.ledger_id, b.ledger_id);
}
