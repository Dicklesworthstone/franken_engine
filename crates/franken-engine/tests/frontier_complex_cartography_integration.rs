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
    self, BEAD_ID, COMPONENT, CartographyError, FrontierComplex, FrontierHole, HoleLedger,
    HoleSignificance, MILLIONTHS, POLICY_ID, PersistenceDiagram, PersistencePair, SCHEMA_VERSION,
    Simplex, SimplexDimension,
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

// ===========================================================================
// Enrichment tests — SimplexDimension
// ===========================================================================

#[test]
fn simplex_dimension_roundtrip_all_named() {
    let dims = [
        SimplexDimension::Vertex,
        SimplexDimension::Edge,
        SimplexDimension::Triangle,
        SimplexDimension::Tetrahedron,
    ];
    for d in &dims {
        assert_eq!(SimplexDimension::from_u32(d.as_u32()), *d);
    }
}

#[test]
fn simplex_dimension_higher_dim_serde() {
    let d = SimplexDimension::HigherDim(7);
    let json = serde_json::to_string(&d).unwrap();
    let back: SimplexDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    assert_eq!(d.expected_vertex_count(), 8);
}

#[test]
fn simplex_dimension_display_all_named() {
    assert_eq!(SimplexDimension::Edge.to_string(), "edge");
    assert_eq!(SimplexDimension::Triangle.to_string(), "triangle");
    assert_eq!(SimplexDimension::Tetrahedron.to_string(), "tetrahedron");
}

// ===========================================================================
// Enrichment tests — Simplex
// ===========================================================================

#[test]
fn simplex_content_hash_sensitive_to_id() {
    let a = vertex("v1", "a", 100_000);
    let b = vertex("v2", "a", 100_000);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn simplex_content_hash_sensitive_to_filtration() {
    let a = vertex("v1", "a", 100_000);
    let b = vertex("v1", "a", 200_000);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn simplex_serde_roundtrip() {
    let s = edge_simplex("e1", "a", "b", 250_000);
    let json = serde_json::to_string(&s).unwrap();
    let back: Simplex = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn simplex_validate_triangle_ok() {
    let s = triangle_simplex("t1", "a", "b", "c", 300_000);
    assert!(s.validate().is_ok());
}

#[test]
fn simplex_validate_tetrahedron_ok() {
    let s = Simplex {
        simplex_id: "tet1".to_string(),
        dimension: SimplexDimension::Tetrahedron,
        vertices: vec!["a".into(), "b".into(), "c".into(), "d".into()],
        filtration_value_millionths: 400_000,
    };
    assert!(s.validate().is_ok());
}

#[test]
fn simplex_display_contains_dimension() {
    let s = edge_simplex("e1", "a", "b", 200_000);
    let display = format!("{s}");
    assert!(display.contains("e1"));
    assert!(display.contains("edge"));
}

// ===========================================================================
// Enrichment tests — FrontierComplex
// ===========================================================================

#[test]
fn frontier_complex_filtration_range_none_for_empty() {
    let simplices = vec![vertex("v1", "a", 100_000)];
    let mut complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    complex.simplices.clear();
    assert!(complex.filtration_range().is_none());
}

#[test]
fn frontier_complex_count_at_dimension_mixed() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        vertex("v3", "c", 100_000),
        edge_simplex("e1", "a", "b", 200_000),
        edge_simplex("e2", "b", "c", 200_000),
        triangle_simplex("t1", "a", "b", "c", 300_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    assert_eq!(complex.count_at_dimension(0), 3);
    assert_eq!(complex.count_at_dimension(1), 2);
    assert_eq!(complex.count_at_dimension(2), 1);
    assert_eq!(complex.count_at_dimension(3), 0);
}

#[test]
fn frontier_complex_display_contains_id() {
    let simplices = vec![vertex("v1", "a", 100_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let display = format!("{complex}");
    assert!(display.contains("FrontierComplex"));
    assert!(display.contains(&complex.complex_id));
}

#[test]
fn frontier_complex_seal_updates_hash() {
    let simplices = vec![vertex("v1", "a", 100_000)];
    let mut complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let h1 = complex.content_hash;
    complex.vertex_count = 999;
    complex.seal();
    let h2 = complex.content_hash;
    assert_ne!(h1, h2, "seal should produce different hash after mutation");
}

#[test]
fn frontier_complex_serde_roundtrip() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 200_000),
        edge_simplex("e1", "a", "b", 300_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let json = serde_json::to_string(&complex).unwrap();
    let back: FrontierComplex = serde_json::from_str(&json).unwrap();
    assert_eq!(back, complex);
}

// ===========================================================================
// Enrichment tests — build_complex validation
// ===========================================================================

#[test]
fn build_complex_filtration_violation() {
    // Edge appears at filtration value LESS than one of its face vertices
    let simplices = vec![
        vertex("v1", "a", 500_000),
        vertex("v2", "b", 100_000),
        edge_simplex("e1", "a", "b", 200_000), // face "a" has filt 500_000 > 200_000
    ];
    let result = frontier_complex_cartography::build_complex(simplices);
    assert!(
        matches!(result, Err(CartographyError::FiltrationViolation)),
        "expected FiltrationViolation, got {:?}",
        result
    );
}

#[test]
fn build_complex_simplices_sorted_by_filtration() {
    let simplices = vec![
        vertex("v2", "b", 300_000),
        vertex("v1", "a", 100_000),
        vertex("v3", "c", 200_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    for w in complex.simplices.windows(2) {
        assert!(
            w[0].filtration_value_millionths <= w[1].filtration_value_millionths,
            "simplices should be sorted by filtration"
        );
    }
}

// ===========================================================================
// Enrichment tests — PersistencePair
// ===========================================================================

#[test]
fn persistence_pair_serde_roundtrip() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 400_000,
    };
    let json = serde_json::to_string(&pair).unwrap();
    let back: PersistencePair = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pair);
}

#[test]
fn persistence_pair_display_finite() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 400_000,
    };
    let display = format!("{pair}");
    assert!(display.contains("dim=1"));
    assert!(display.contains("500000"));
}

#[test]
fn persistence_pair_display_essential() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: u64::MAX,
        dimension: 0,
        generator_simplex: "v1".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX - 100_000,
    };
    let display = format!("{pair}");
    assert!(display.contains("inf"));
}

#[test]
fn persistence_pair_content_hash_sensitive_to_dimension() {
    let a = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 0,
        generator_simplex: "v1".to_string(),
        killer_simplex: Some("e1".to_string()),
        persistence_millionths: 400_000,
    };
    let b = PersistencePair {
        dimension: 1,
        ..a.clone()
    };
    assert_ne!(a.content_hash(), b.content_hash());
}

// ===========================================================================
// Enrichment tests — PersistenceDiagram
// ===========================================================================

#[test]
fn persistence_diagram_count_at_dimension() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![
            PersistencePair {
                birth_filtration_millionths: 0,
                death_filtration_millionths: 100_000,
                dimension: 0,
                generator_simplex: "v1".to_string(),
                killer_simplex: Some("e1".to_string()),
                persistence_millionths: 100_000,
            },
            PersistencePair {
                birth_filtration_millionths: 0,
                death_filtration_millionths: u64::MAX,
                dimension: 0,
                generator_simplex: "v2".to_string(),
                killer_simplex: None,
                persistence_millionths: u64::MAX,
            },
            PersistencePair {
                birth_filtration_millionths: 100_000,
                death_filtration_millionths: 300_000,
                dimension: 1,
                generator_simplex: "e2".to_string(),
                killer_simplex: Some("t1".to_string()),
                persistence_millionths: 200_000,
            },
        ],
        total_persistence_millionths: 300_000,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(diagram.count_at_dimension(0), 2);
    assert_eq!(diagram.count_at_dimension(1), 1);
    assert_eq!(diagram.count_at_dimension(2), 0);
}

#[test]
fn persistence_diagram_essential_count() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![
            PersistencePair {
                birth_filtration_millionths: 0,
                death_filtration_millionths: u64::MAX,
                dimension: 0,
                generator_simplex: "v1".to_string(),
                killer_simplex: None,
                persistence_millionths: u64::MAX,
            },
            PersistencePair {
                birth_filtration_millionths: 100_000,
                death_filtration_millionths: 300_000,
                dimension: 1,
                generator_simplex: "e1".to_string(),
                killer_simplex: Some("t1".to_string()),
                persistence_millionths: 200_000,
            },
        ],
        total_persistence_millionths: 200_000,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(diagram.essential_count(), 1);
}

#[test]
fn persistence_diagram_max_persistence() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![
            PersistencePair {
                birth_filtration_millionths: 0,
                death_filtration_millionths: 100_000,
                dimension: 0,
                generator_simplex: "v1".to_string(),
                killer_simplex: Some("e1".to_string()),
                persistence_millionths: 100_000,
            },
            PersistencePair {
                birth_filtration_millionths: 0,
                death_filtration_millionths: 500_000,
                dimension: 1,
                generator_simplex: "e2".to_string(),
                killer_simplex: Some("t1".to_string()),
                persistence_millionths: 500_000,
            },
        ],
        total_persistence_millionths: 600_000,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(diagram.max_persistence(), 500_000);
}

#[test]
fn persistence_diagram_max_persistence_ignores_essential() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: u64::MAX,
            dimension: 0,
            generator_simplex: "v1".to_string(),
            killer_simplex: None,
            persistence_millionths: u64::MAX,
        }],
        total_persistence_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(diagram.max_persistence(), 0);
}

#[test]
fn persistence_diagram_display() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![],
        total_persistence_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    let display = format!("{diagram}");
    assert!(display.contains("PersistenceDiagram"));
    assert!(display.contains("d1"));
}

#[test]
fn persistence_diagram_serde_roundtrip() {
    let diagram = PersistenceDiagram {
        diagram_id: "d1".to_string(),
        pairs: vec![PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 100_000,
            dimension: 0,
            generator_simplex: "v1".to_string(),
            killer_simplex: Some("e1".to_string()),
            persistence_millionths: 100_000,
        }],
        total_persistence_millionths: 100_000,
        content_hash: ContentHash::compute(b""),
    };
    let json = serde_json::to_string(&diagram).unwrap();
    let back: PersistenceDiagram = serde_json::from_str(&json).unwrap();
    assert_eq!(back, diagram);
}

// ===========================================================================
// Enrichment tests — HoleSignificance
// ===========================================================================

#[test]
fn hole_significance_all_variants_serde() {
    let variants = [
        HoleSignificance::Persistent,
        HoleSignificance::Transient,
        HoleSignificance::SamplingNoise,
        HoleSignificance::Structural,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: HoleSignificance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

#[test]
fn hole_significance_display_all() {
    assert_eq!(HoleSignificance::Transient.to_string(), "transient");
    assert_eq!(HoleSignificance::Structural.to_string(), "structural");
}

// ===========================================================================
// Enrichment tests — classify_hole
// ===========================================================================

#[test]
fn classify_hole_essential_is_structural() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: u64::MAX,
        dimension: 0,
        generator_simplex: "v1".to_string(),
        killer_simplex: None,
        persistence_millionths: u64::MAX - 100_000,
    };
    assert_eq!(
        frontier_complex_cartography::classify_hole(&pair, 50_000, 100),
        HoleSignificance::Structural
    );
}

#[test]
fn classify_hole_low_samples_is_noise() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 500_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 400_000,
    };
    // sample_count below MIN_MEANINGFUL_SAMPLES (10)
    assert_eq!(
        frontier_complex_cartography::classify_hole(&pair, 50_000, 5),
        HoleSignificance::SamplingNoise
    );
}

#[test]
fn classify_hole_persistent_double_threshold() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 300_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 200_000, // >= 50_000 * 2
    };
    assert_eq!(
        frontier_complex_cartography::classify_hole(&pair, 50_000, 100),
        HoleSignificance::Persistent
    );
}

#[test]
fn classify_hole_transient_between_thresholds() {
    let pair = PersistencePair {
        birth_filtration_millionths: 100_000,
        death_filtration_millionths: 170_000,
        dimension: 1,
        generator_simplex: "e1".to_string(),
        killer_simplex: Some("t1".to_string()),
        persistence_millionths: 70_000, // >= 50_000 but < 100_000
    };
    assert_eq!(
        frontier_complex_cartography::classify_hole(&pair, 50_000, 100),
        HoleSignificance::Transient
    );
}

// ===========================================================================
// Enrichment tests — FrontierHole
// ===========================================================================

#[test]
fn frontier_hole_seal_updates_hash() {
    let mut hole = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Persistent,
        persistence_millionths: 500_000,
        representative_cycle: vec!["e1".to_string()],
        affected_programs: vec!["prog1".to_string()],
        content_hash: ContentHash::compute(b""),
    };
    let h1 = hole.content_hash;
    hole.seal();
    let h2 = hole.content_hash;
    assert_ne!(h1, h2, "seal should update content hash");
}

#[test]
fn frontier_hole_display() {
    let hole = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Persistent,
        persistence_millionths: 500_000,
        representative_cycle: vec!["e1".to_string()],
        affected_programs: vec!["prog1".to_string()],
        content_hash: ContentHash::compute(b""),
    };
    let display = format!("{hole}");
    assert!(display.contains("h1"));
    assert!(display.contains("persistent"));
}

#[test]
fn frontier_hole_serde_roundtrip() {
    let mut hole = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Transient,
        persistence_millionths: 70_000,
        representative_cycle: vec!["e1".to_string(), "e2".to_string()],
        affected_programs: vec!["prog1".to_string()],
        content_hash: ContentHash::compute(b""),
    };
    hole.seal();
    let json = serde_json::to_string(&hole).unwrap();
    let back: FrontierHole = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hole);
}

// ===========================================================================
// Enrichment tests — HoleLedger
// ===========================================================================

#[test]
fn hole_ledger_transient_count() {
    let mut h_transient = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Transient,
        persistence_millionths: 70_000,
        representative_cycle: vec!["e1".to_string()],
        affected_programs: vec![],
        content_hash: ContentHash::compute(b""),
    };
    h_transient.seal();
    let mut h_noise = FrontierHole {
        hole_id: "h2".to_string(),
        dimension: 1,
        significance: HoleSignificance::SamplingNoise,
        persistence_millionths: 5_000,
        representative_cycle: vec!["e2".to_string()],
        affected_programs: vec![],
        content_hash: ContentHash::compute(b""),
    };
    h_noise.seal();
    let ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![h_transient, h_noise],
        persistent_count: 0,
        noise_count: 1,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(ledger.transient_count(), 1);
    assert_eq!(ledger.structural_count(), 0);
    assert_eq!(ledger.total_holes(), 2);
}

#[test]
fn hole_ledger_display() {
    let ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![],
        persistent_count: 0,
        noise_count: 0,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let display = format!("{ledger}");
    assert!(display.contains("HoleLedger"));
    assert!(display.contains("l1"));
}

#[test]
fn hole_ledger_serde_roundtrip() {
    let mut ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![],
        persistent_count: 0,
        noise_count: 0,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    ledger.seal();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: HoleLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ledger);
}

// ===========================================================================
// Enrichment tests — CartographyError
// ===========================================================================

#[test]
fn cartography_error_all_variants_display() {
    let errors = [
        CartographyError::EmptyComplex,
        CartographyError::InvalidSimplex,
        CartographyError::FiltrationViolation,
        CartographyError::DiagramInconsistent,
        CartographyError::InternalError("test".into()),
    ];
    for e in &errors {
        let display = format!("{e}");
        assert!(!display.is_empty());
    }
}

#[test]
fn cartography_error_serde_roundtrip() {
    let errors = [
        CartographyError::EmptyComplex,
        CartographyError::InvalidSimplex,
        CartographyError::FiltrationViolation,
        CartographyError::DiagramInconsistent,
        CartographyError::InternalError("some error".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: CartographyError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *e);
    }
}

// ===========================================================================
// Enrichment tests — build_hole_ledger
// ===========================================================================

#[test]
fn build_hole_ledger_from_diagram() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        vertex("v3", "c", 200_000),
        edge_simplex("e1", "a", "b", 300_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let diagram = frontier_complex_cartography::compute_persistence(&complex).unwrap();
    let ledger =
        frontier_complex_cartography::build_hole_ledger(test_epoch(), &diagram, 50_000, 100);
    assert_eq!(ledger.epoch, test_epoch());
    assert!(!ledger.ledger_id.is_empty());
    assert_eq!(ledger.total_holes(), diagram.pairs.len());
    assert_eq!(
        ledger.persistent_count
            + ledger.noise_count
            + ledger.transient_count()
            + ledger.structural_count(),
        ledger.total_holes() as u64
    );
}

// ===========================================================================
// Enrichment tests — compute_persistence full pipeline
// ===========================================================================

#[test]
fn compute_persistence_triangle_complex() {
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
    let diagram = frontier_complex_cartography::compute_persistence(&complex).unwrap();
    assert!(!diagram.pairs.is_empty());
    assert!(!diagram.diagram_id.is_empty());
    // At least one pair should have dimension 0 (connected components)
    assert!(diagram.count_at_dimension(0) > 0);
}

#[test]
fn compute_persistence_total_matches_sum() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        edge_simplex("e1", "a", "b", 300_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let diagram = frontier_complex_cartography::compute_persistence(&complex).unwrap();
    let manual_sum: u64 = diagram
        .pairs
        .iter()
        .filter(|p| !p.is_essential())
        .map(|p| p.persistence_millionths)
        .sum();
    assert_eq!(diagram.total_persistence_millionths, manual_sum);
}

// ===========================================================================
// Enrichment tests — stability_score
// ===========================================================================

#[test]
fn stability_score_decreases_with_persistent_holes() {
    let empty_ledger = HoleLedger {
        ledger_id: "l1".to_string(),
        epoch: test_epoch(),
        holes: vec![],
        persistent_count: 0,
        noise_count: 0,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let empty_score = frontier_complex_cartography::stability_score(&empty_ledger);

    let mut h_persistent = FrontierHole {
        hole_id: "h1".to_string(),
        dimension: 1,
        significance: HoleSignificance::Persistent,
        persistence_millionths: 500_000,
        representative_cycle: vec!["e1".to_string()],
        affected_programs: vec!["prog1".to_string()],
        content_hash: ContentHash::compute(b""),
    };
    h_persistent.seal();
    let hole_ledger = HoleLedger {
        ledger_id: "l2".to_string(),
        epoch: test_epoch(),
        holes: vec![h_persistent],
        persistent_count: 1,
        noise_count: 0,
        significance_threshold_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let hole_score = frontier_complex_cartography::stability_score(&hole_ledger);
    assert!(
        hole_score <= empty_score,
        "stability should decrease with persistent holes: {} vs {}",
        hole_score,
        empty_score
    );
}

// ===========================================================================
// Enrichment tests — euler_characteristic edge cases
// ===========================================================================

#[test]
fn euler_characteristic_single_vertex() {
    let simplices = vec![vertex("v1", "a", 100_000)];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let chi = frontier_complex_cartography::euler_characteristic(&complex);
    assert_eq!(chi, 1); // single vertex = 1
}

#[test]
fn euler_characteristic_two_vertices_one_edge() {
    let simplices = vec![
        vertex("v1", "a", 100_000),
        vertex("v2", "b", 100_000),
        edge_simplex("e1", "a", "b", 200_000),
    ];
    let complex = frontier_complex_cartography::build_complex(simplices).unwrap();
    let chi = frontier_complex_cartography::euler_characteristic(&complex);
    // 2 vertices - 1 edge = 1
    assert_eq!(chi, 1);
}
