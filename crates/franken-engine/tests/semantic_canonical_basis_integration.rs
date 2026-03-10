//! Integration tests for `semantic_canonical_basis` module.
//!
//! Validates public API, serde contracts, determinism, coverage reporting,
//! orbit reduction, identification queries, and refusal semantics.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_canonical_basis::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn all_transforms() -> BTreeSet<EquivalenceTransformation> {
    EquivalenceTransformation::ALL.iter().copied().collect()
}

fn safe_only() -> BTreeSet<EquivalenceTransformation> {
    EquivalenceTransformation::ALL
        .iter()
        .copied()
        .filter(|t| t.is_universally_safe())
        .collect()
}

fn step(idx: usize, t: EquivalenceTransformation) -> OrbitStep {
    OrbitStep {
        step_index: idx,
        transformation: t,
        result_fingerprint: format!("step_{}", idx),
        cost_millionths: 50_000,
    }
}

fn orbit(fam: ArtifactFamily, inp: &str, canon: &str, steps: Vec<OrbitStep>) -> OrbitReduction {
    OrbitReduction::new(fam, inp.to_string(), canon.to_string(), steps, true)
}

fn representative(fam: ArtifactFamily, fp: &str) -> CanonicalRepresentative {
    CanonicalRepresentative::new(fam, fp.to_string(), 1, all_transforms(), epoch())
}

fn class(fam: ArtifactFamily, fp: &str, orbits: Vec<OrbitReduction>) -> EquivalenceClass {
    EquivalenceClass::new(representative(fam, fp), orbits, Vec::new())
}

fn basis(classes: Vec<EquivalenceClass>) -> SemanticCanonicalBasis {
    SemanticCanonicalBasis::new(epoch(), classes, all_transforms())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn bead_id_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "semantic_canonical_basis");
}

#[test]
fn max_orbit_depth_positive() {
    assert!(MAX_ORBIT_DEPTH > 0);
    assert!(MAX_ORBIT_DEPTH <= 256);
}

#[test]
fn max_classes_per_basis_positive() {
    assert!(MAX_CLASSES_PER_BASIS > 0);
}

#[test]
fn min_similarity_threshold_in_range() {
    assert!(MIN_SIMILARITY_THRESHOLD > 0);
    assert!(MIN_SIMILARITY_THRESHOLD <= 1_000_000);
}

// ---------------------------------------------------------------------------
// ArtifactFamily
// ---------------------------------------------------------------------------

#[test]
fn artifact_family_all_length() {
    assert_eq!(ArtifactFamily::ALL.len(), 10);
}

#[test]
fn artifact_family_names_unique() {
    let names: BTreeSet<&str> = ArtifactFamily::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(names.len(), ArtifactFamily::ALL.len());
}

#[test]
fn artifact_family_display_matches_as_str() {
    for f in ArtifactFamily::ALL {
        assert_eq!(f.to_string(), f.as_str());
    }
}

#[test]
fn artifact_family_serde_all_variants() {
    for f in ArtifactFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: ArtifactFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn artifact_family_ord_consistent() {
    let mut sorted: Vec<_> = ArtifactFamily::ALL.to_vec();
    sorted.sort();
    // Just check that sorting is consistent (doesn't panic)
    assert_eq!(sorted.len(), ArtifactFamily::ALL.len());
}

// ---------------------------------------------------------------------------
// EquivalenceTransformation
// ---------------------------------------------------------------------------

#[test]
fn transformation_all_length() {
    assert_eq!(EquivalenceTransformation::ALL.len(), 10);
}

#[test]
fn transformation_names_unique() {
    let names: BTreeSet<&str> = EquivalenceTransformation::ALL
        .iter()
        .map(|t| t.as_str())
        .collect();
    assert_eq!(names.len(), EquivalenceTransformation::ALL.len());
}

#[test]
fn transformation_display_matches_as_str() {
    for t in EquivalenceTransformation::ALL {
        assert_eq!(t.to_string(), t.as_str());
    }
}

#[test]
fn transformation_serde_all_variants() {
    for t in EquivalenceTransformation::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: EquivalenceTransformation = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn universally_safe_subset_is_proper() {
    let safe: Vec<_> = EquivalenceTransformation::ALL
        .iter()
        .filter(|t| t.is_universally_safe())
        .collect();
    assert!(!safe.is_empty());
    assert!(safe.len() < EquivalenceTransformation::ALL.len());
}

#[test]
fn alpha_renaming_is_universally_safe() {
    assert!(EquivalenceTransformation::AlphaRenaming.is_universally_safe());
}

#[test]
fn dead_code_elimination_is_not_universally_safe() {
    assert!(!EquivalenceTransformation::DeadCodeElimination.is_universally_safe());
}

// ---------------------------------------------------------------------------
// RefusalReason
// ---------------------------------------------------------------------------

#[test]
fn refusal_reason_all_tags_unique() {
    let reasons = vec![
        RefusalReason::FamilyMismatch {
            left: ArtifactFamily::Ir1Fragment,
            right: ArtifactFamily::CacheEntry,
        },
        RefusalReason::EpochMismatch {
            left_epoch: 1,
            right_epoch: 2,
        },
        RefusalReason::ObservableEffectDifference {
            description: "x".into(),
        },
        RefusalReason::OrbitDepthExceeded { depth_reached: 99 },
        RefusalReason::TransformationNotAllowed {
            transformation: EquivalenceTransformation::ConstantFolding,
        },
        RefusalReason::SimilarityBelowThreshold {
            score_millionths: 100_000,
            threshold_millionths: 950_000,
        },
        RefusalReason::OpaqueRegionPresent {
            region_label: "r".into(),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn refusal_reason_serde_roundtrip() {
    let reason = RefusalReason::ObservableEffectDifference {
        description: "side effect on global state".into(),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: RefusalReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}

#[test]
fn refusal_reason_display_family_mismatch() {
    let r = RefusalReason::FamilyMismatch {
        left: ArtifactFamily::RewritePack,
        right: ArtifactFamily::ShapeChain,
    };
    let s = r.to_string();
    assert!(s.contains("family mismatch"));
    assert!(s.contains("rewrite_pack"));
    assert!(s.contains("shape_chain"));
}

#[test]
fn refusal_reason_display_epoch_mismatch() {
    let r = RefusalReason::EpochMismatch {
        left_epoch: 10,
        right_epoch: 20,
    };
    assert!(r.to_string().contains("10"));
    assert!(r.to_string().contains("20"));
}

#[test]
fn refusal_reason_display_orbit_depth() {
    let r = RefusalReason::OrbitDepthExceeded { depth_reached: 100 };
    let s = r.to_string();
    assert!(s.contains("100"));
    assert!(s.contains(&MAX_ORBIT_DEPTH.to_string()));
}

// ---------------------------------------------------------------------------
// IdentificationRefusal
// ---------------------------------------------------------------------------

#[test]
fn refusal_deterministic_hash() {
    let r1 = IdentificationRefusal::new(
        "aa".into(),
        "bb".into(),
        Some(ArtifactFamily::Ir3Fragment),
        vec![RefusalReason::EpochMismatch {
            left_epoch: 5,
            right_epoch: 6,
        }],
        epoch(),
    );
    let r2 = IdentificationRefusal::new(
        "aa".into(),
        "bb".into(),
        Some(ArtifactFamily::Ir3Fragment),
        vec![RefusalReason::EpochMismatch {
            left_epoch: 5,
            right_epoch: 6,
        }],
        epoch(),
    );
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn refusal_different_inputs_different_hash() {
    let r1 = IdentificationRefusal::new("a".into(), "b".into(), None, vec![], epoch());
    let r2 = IdentificationRefusal::new("c".into(), "d".into(), None, vec![], epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn refusal_reason_count() {
    let r = IdentificationRefusal::new(
        "x".into(),
        "y".into(),
        None,
        vec![
            RefusalReason::FamilyMismatch {
                left: ArtifactFamily::Ir1Fragment,
                right: ArtifactFamily::CacheEntry,
            },
            RefusalReason::OrbitDepthExceeded { depth_reached: 70 },
        ],
        epoch(),
    );
    assert_eq!(r.reason_count(), 2);
    assert!(r.has_reason_tag("family_mismatch"));
    assert!(r.has_reason_tag("orbit_depth_exceeded"));
    assert!(!r.has_reason_tag("epoch_mismatch"));
}

#[test]
fn refusal_serde_roundtrip() {
    let r = IdentificationRefusal::new(
        "left_fp".into(),
        "right_fp".into(),
        Some(ArtifactFamily::BytecodeArtifact),
        vec![RefusalReason::OpaqueRegionPresent {
            region_label: "native_binding".into(),
        }],
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: IdentificationRefusal = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// OrbitStep
// ---------------------------------------------------------------------------

#[test]
fn orbit_step_serde_roundtrip() {
    let s = step(3, EquivalenceTransformation::CommutativeReorder);
    let json = serde_json::to_string(&s).unwrap();
    let back: OrbitStep = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn orbit_step_cost_non_negative() {
    let s = step(0, EquivalenceTransformation::AlphaRenaming);
    assert!(s.cost_millionths > 0);
}

// ---------------------------------------------------------------------------
// OrbitReduction
// ---------------------------------------------------------------------------

#[test]
fn orbit_trivial_identity() {
    let o = orbit(ArtifactFamily::Ir1Fragment, "same", "same", Vec::new());
    assert!(o.is_trivial());
    assert_eq!(o.depth(), 0);
    assert!(!o.exceeded_depth_limit());
    assert!(o.converged);
    assert_eq!(o.total_cost_millionths, 0);
}

#[test]
fn orbit_nontrivial_reduction() {
    let steps = vec![
        step(0, EquivalenceTransformation::AlphaRenaming),
        step(1, EquivalenceTransformation::DeadCodeElimination),
        step(2, EquivalenceTransformation::ConstantFolding),
    ];
    let o = orbit(ArtifactFamily::Ir3Fragment, "in", "out", steps);
    assert!(!o.is_trivial());
    assert_eq!(o.depth(), 3);
    assert_eq!(o.total_cost_millionths, 150_000);
    let used = o.transformations_used();
    assert_eq!(used.len(), 3);
}

#[test]
fn orbit_depth_limit_boundary() {
    let at_limit: Vec<_> = (0..MAX_ORBIT_DEPTH)
        .map(|i| step(i, EquivalenceTransformation::AlphaRenaming))
        .collect();
    let o = orbit(ArtifactFamily::CacheEntry, "a", "b", at_limit);
    assert!(!o.exceeded_depth_limit());

    let over_limit: Vec<_> = (0..MAX_ORBIT_DEPTH + 1)
        .map(|i| step(i, EquivalenceTransformation::AlphaRenaming))
        .collect();
    let o2 = orbit(ArtifactFamily::CacheEntry, "a", "b", over_limit);
    assert!(o2.exceeded_depth_limit());
}

#[test]
fn orbit_content_hash_deterministic() {
    let s = vec![step(0, EquivalenceTransformation::ScopeFlattening)];
    let o1 = orbit(ArtifactFamily::ModuleSnapshot, "in", "out", s.clone());
    let o2 = orbit(ArtifactFamily::ModuleSnapshot, "in", "out", s);
    assert_eq!(o1.content_hash, o2.content_hash);
}

#[test]
fn orbit_different_families_different_hash() {
    let o1 = orbit(ArtifactFamily::Ir1Fragment, "in", "out", Vec::new());
    let o2 = orbit(ArtifactFamily::Ir3Fragment, "in", "out", Vec::new());
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn orbit_serde_roundtrip() {
    let o = orbit(
        ArtifactFamily::RewritePack,
        "orig",
        "canon",
        vec![step(0, EquivalenceTransformation::LabelNormalization)],
    );
    let json = serde_json::to_string(&o).unwrap();
    let back: OrbitReduction = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

// ---------------------------------------------------------------------------
// CanonicalRepresentative
// ---------------------------------------------------------------------------

#[test]
fn representative_singleton_detection() {
    let r = representative(ArtifactFamily::Ir1Fragment, "solo");
    assert!(r.is_singleton());
}

#[test]
fn representative_multi_member() {
    let r = CanonicalRepresentative::new(
        ArtifactFamily::CacheEntry,
        "multi".into(),
        5,
        all_transforms(),
        epoch(),
    );
    assert!(!r.is_singleton());
}

#[test]
fn representative_allows_all_transforms() {
    let r = representative(ArtifactFamily::Ir3Fragment, "fp");
    for t in EquivalenceTransformation::ALL {
        assert!(r.allows_transformation(*t));
    }
}

#[test]
fn representative_restricted_transforms() {
    let r = CanonicalRepresentative::new(
        ArtifactFamily::EvidenceRecord,
        "restricted".into(),
        3,
        safe_only(),
        epoch(),
    );
    assert!(r.allows_transformation(EquivalenceTransformation::AlphaRenaming));
    assert!(!r.allows_transformation(EquivalenceTransformation::DeadCodeElimination));
}

#[test]
fn representative_allowed_fraction() {
    let r = representative(ArtifactFamily::Ir1Fragment, "full");
    assert_eq!(r.allowed_fraction_millionths(), 1_000_000);

    let r2 = CanonicalRepresentative::new(
        ArtifactFamily::Ir1Fragment,
        "safe".into(),
        1,
        safe_only(),
        epoch(),
    );
    let frac = r2.allowed_fraction_millionths();
    assert!(frac > 0);
    assert!(frac < 1_000_000);
}

#[test]
fn representative_content_hash_deterministic() {
    let r1 = representative(ArtifactFamily::ShapeChain, "fp");
    let r2 = representative(ArtifactFamily::ShapeChain, "fp");
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn representative_serde_roundtrip() {
    let r = representative(ArtifactFamily::TypeFeedbackProfile, "tfp");
    let json = serde_json::to_string(&r).unwrap();
    let back: CanonicalRepresentative = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// EquivalenceClass
// ---------------------------------------------------------------------------

#[test]
fn class_empty_members() {
    let c = class(ArtifactFamily::Ir1Fragment, "c", Vec::new());
    assert_eq!(c.member_count(), 0);
    assert_eq!(c.refusal_count(), 0);
    assert!(c.all_converged());
    assert_eq!(c.max_orbit_depth(), 0);
    assert_eq!(c.average_depth_millionths(), 0);
}

#[test]
fn class_with_orbits() {
    let orbits = vec![
        orbit(
            ArtifactFamily::Ir1Fragment,
            "a",
            "c",
            vec![step(0, EquivalenceTransformation::AlphaRenaming)],
        ),
        orbit(
            ArtifactFamily::Ir1Fragment,
            "b",
            "c",
            vec![
                step(0, EquivalenceTransformation::AlphaRenaming),
                step(1, EquivalenceTransformation::ConstantFolding),
            ],
        ),
    ];
    let c = class(ArtifactFamily::Ir1Fragment, "c", orbits);
    assert_eq!(c.member_count(), 2);
    assert_eq!(c.max_orbit_depth(), 2);
    assert_eq!(c.average_depth_millionths(), 1_500_000);
}

#[test]
fn class_all_transformations_used() {
    let orbits = vec![
        orbit(
            ArtifactFamily::CacheEntry,
            "x",
            "z",
            vec![step(0, EquivalenceTransformation::CommutativeReorder)],
        ),
        orbit(
            ArtifactFamily::CacheEntry,
            "y",
            "z",
            vec![step(0, EquivalenceTransformation::MetadataNormalization)],
        ),
    ];
    let c = class(ArtifactFamily::CacheEntry, "z", orbits);
    let used = c.all_transformations_used();
    assert_eq!(used.len(), 2);
    assert!(used.contains(&EquivalenceTransformation::CommutativeReorder));
    assert!(used.contains(&EquivalenceTransformation::MetadataNormalization));
}

#[test]
fn class_with_refusals() {
    let refusal = IdentificationRefusal::new(
        "bad_a".into(),
        "bad_b".into(),
        Some(ArtifactFamily::Ir1Fragment),
        vec![RefusalReason::EpochMismatch {
            left_epoch: 1,
            right_epoch: 2,
        }],
        epoch(),
    );
    let c = EquivalenceClass::new(
        representative(ArtifactFamily::Ir1Fragment, "c"),
        Vec::new(),
        vec![refusal],
    );
    assert_eq!(c.refusal_count(), 1);
}

// ---------------------------------------------------------------------------
// SemanticCanonicalBasis
// ---------------------------------------------------------------------------

#[test]
fn basis_empty() {
    let b = basis(Vec::new());
    assert_eq!(b.class_count(), 0);
    assert!(b.within_class_limit());
    assert_eq!(b.total_member_count(), 0);
    assert_eq!(b.total_refusal_count(), 0);
    assert!(b.all_orbits_converged());
    assert_eq!(b.max_orbit_depth(), 0);
    assert_eq!(b.schema_version, SCHEMA_VERSION);
}

#[test]
fn basis_content_hash_deterministic() {
    let c1 = class(ArtifactFamily::Ir1Fragment, "fp1", Vec::new());
    let c2 = class(ArtifactFamily::Ir1Fragment, "fp1", Vec::new());
    let b1 = basis(vec![c1]);
    let b2 = basis(vec![c2]);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn basis_different_classes_different_hash() {
    let b1 = basis(vec![class(ArtifactFamily::Ir1Fragment, "a", Vec::new())]);
    let b2 = basis(vec![class(ArtifactFamily::Ir3Fragment, "b", Vec::new())]);
    assert_ne!(b1.content_hash, b2.content_hash);
}

#[test]
fn basis_classes_for_family_filtering() {
    let classes = vec![
        class(ArtifactFamily::Ir1Fragment, "ir1_a", Vec::new()),
        class(ArtifactFamily::CacheEntry, "ce_a", Vec::new()),
        class(ArtifactFamily::Ir1Fragment, "ir1_b", Vec::new()),
        class(ArtifactFamily::RewritePack, "rp_a", Vec::new()),
    ];
    let b = basis(classes);
    assert_eq!(b.classes_for_family(ArtifactFamily::Ir1Fragment).len(), 2);
    assert_eq!(b.classes_for_family(ArtifactFamily::CacheEntry).len(), 1);
    assert_eq!(b.classes_for_family(ArtifactFamily::RewritePack).len(), 1);
    assert!(b.classes_for_family(ArtifactFamily::ShapeChain).is_empty());
}

#[test]
fn basis_coverage_partial() {
    let classes = vec![
        class(ArtifactFamily::Ir1Fragment, "a", Vec::new()),
        class(ArtifactFamily::CacheEntry, "b", Vec::new()),
    ];
    let b = basis(classes);
    let report = b.coverage_report();
    assert_eq!(report.covered_families.len(), 2);
    assert_eq!(
        report.uncovered_families.len(),
        ArtifactFamily::ALL.len() - 2
    );
    assert!(!report.is_complete());
    assert!(report.coverage_millionths > 0);
    assert!(report.coverage_millionths < 1_000_000);
}

#[test]
fn basis_coverage_complete() {
    let classes: Vec<_> = ArtifactFamily::ALL
        .iter()
        .map(|f| class(*f, &format!("rep_{}", f.as_str()), Vec::new()))
        .collect();
    let b = basis(classes);
    let report = b.coverage_report();
    assert!(report.is_complete());
    assert_eq!(report.coverage_millionths, 1_000_000);
    assert!(report.uncovered_families.is_empty());
}

#[test]
fn basis_total_members_and_refusals() {
    let orbits_a = vec![
        orbit(ArtifactFamily::Ir1Fragment, "m1", "c", Vec::new()),
        orbit(ArtifactFamily::Ir1Fragment, "m2", "c", Vec::new()),
    ];
    let orbits_b = vec![orbit(ArtifactFamily::CacheEntry, "n1", "d", Vec::new())];
    let classes = vec![
        class(ArtifactFamily::Ir1Fragment, "c", orbits_a),
        class(ArtifactFamily::CacheEntry, "d", orbits_b),
    ];
    let b = basis(classes);
    assert_eq!(b.total_member_count(), 3);
    assert_eq!(b.total_refusal_count(), 0);
}

#[test]
fn basis_serde_roundtrip() {
    let orbits = vec![orbit(
        ArtifactFamily::BytecodeArtifact,
        "x",
        "bc",
        vec![step(0, EquivalenceTransformation::MetadataNormalization)],
    )];
    let b = basis(vec![class(ArtifactFamily::BytecodeArtifact, "bc", orbits)]);
    let json = serde_json::to_string(&b).unwrap();
    let back: SemanticCanonicalBasis = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn basis_within_class_limit() {
    let b = basis(Vec::new());
    assert!(b.within_class_limit());
}

// ---------------------------------------------------------------------------
// query_identification
// ---------------------------------------------------------------------------

#[test]
fn query_same_class_succeeds() {
    let orbits = vec![
        orbit(ArtifactFamily::Ir1Fragment, "a", "canon", Vec::new()),
        orbit(ArtifactFamily::Ir1Fragment, "b", "canon", Vec::new()),
    ];
    let b = basis(vec![class(ArtifactFamily::Ir1Fragment, "canon", orbits)]);
    let result = query_identification(&b, ArtifactFamily::Ir1Fragment, "a", "b");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "canon");
}

#[test]
fn query_different_class_fails() {
    let orbits = vec![orbit(ArtifactFamily::Ir1Fragment, "a", "canon", Vec::new())];
    let b = basis(vec![class(ArtifactFamily::Ir1Fragment, "canon", orbits)]);
    let result = query_identification(&b, ArtifactFamily::Ir1Fragment, "a", "unknown");
    assert!(result.is_err());
    let refusal = result.unwrap_err();
    assert!(refusal.has_reason_tag("similarity_below_threshold"));
}

#[test]
fn query_empty_basis_refuses() {
    let b = basis(Vec::new());
    let result = query_identification(&b, ArtifactFamily::CacheEntry, "x", "y");
    assert!(result.is_err());
}

#[test]
fn query_wrong_family_misses() {
    let orbits = vec![
        orbit(ArtifactFamily::Ir1Fragment, "a", "canon", Vec::new()),
        orbit(ArtifactFamily::Ir1Fragment, "b", "canon", Vec::new()),
    ];
    let b = basis(vec![class(ArtifactFamily::Ir1Fragment, "canon", orbits)]);
    // Query with wrong family
    let result = query_identification(&b, ArtifactFamily::CacheEntry, "a", "b");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// refuse_cross_family
// ---------------------------------------------------------------------------

#[test]
fn cross_family_refusal_has_correct_tag() {
    let r = refuse_cross_family(
        ArtifactFamily::Ir1Fragment,
        ArtifactFamily::CacheEntry,
        "fp1",
        "fp2",
        epoch(),
    );
    assert!(r.has_reason_tag("family_mismatch"));
    assert_eq!(r.family, None);
    assert_eq!(r.reason_count(), 1);
}

#[test]
fn cross_family_refusal_deterministic() {
    let r1 = refuse_cross_family(
        ArtifactFamily::RewritePack,
        ArtifactFamily::ShapeChain,
        "a",
        "b",
        epoch(),
    );
    let r2 = refuse_cross_family(
        ArtifactFamily::RewritePack,
        ArtifactFamily::ShapeChain,
        "a",
        "b",
        epoch(),
    );
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// validate_orbit
// ---------------------------------------------------------------------------

#[test]
fn validate_orbit_all_allowed_passes() {
    let o = orbit(
        ArtifactFamily::Ir1Fragment,
        "in",
        "out",
        vec![step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let issues = validate_orbit(&o, &all_transforms());
    assert!(issues.is_empty());
}

#[test]
fn validate_orbit_disallowed_transform() {
    let o = orbit(
        ArtifactFamily::Ir1Fragment,
        "in",
        "out",
        vec![step(0, EquivalenceTransformation::DeadCodeElimination)],
    );
    let issues = validate_orbit(&o, &safe_only());
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        RefusalReason::TransformationNotAllowed { .. }
    ));
}

#[test]
fn validate_orbit_depth_exceeded() {
    let steps: Vec<_> = (0..MAX_ORBIT_DEPTH + 1)
        .map(|i| step(i, EquivalenceTransformation::AlphaRenaming))
        .collect();
    let o = orbit(ArtifactFamily::Ir1Fragment, "a", "b", steps);
    let issues = validate_orbit(&o, &all_transforms());
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RefusalReason::OrbitDepthExceeded { .. }))
    );
}

#[test]
fn validate_orbit_multiple_issues() {
    let steps: Vec<_> = (0..MAX_ORBIT_DEPTH + 1)
        .map(|i| step(i, EquivalenceTransformation::DeadCodeElimination))
        .collect();
    let o = orbit(ArtifactFamily::Ir1Fragment, "a", "b", steps);
    let issues = validate_orbit(&o, &safe_only());
    // Should have both depth-exceeded and disallowed-transformation issues
    assert!(issues.len() >= 2);
}

#[test]
fn validate_orbit_trivial_passes() {
    let o = orbit(ArtifactFamily::Ir1Fragment, "x", "x", Vec::new());
    let issues = validate_orbit(&o, &safe_only());
    assert!(issues.is_empty());
}
