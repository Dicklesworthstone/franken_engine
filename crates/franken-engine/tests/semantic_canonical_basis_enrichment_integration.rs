#![forbid(unsafe_code)]

//! Enrichment integration tests for the semantic_canonical_basis module.

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
use frankenengine_engine::semantic_canonical_basis::{
    ArtifactFamily, BEAD_ID, COMPONENT, CanonicalRepresentative, EquivalenceClass,
    EquivalenceTransformation, IdentificationRefusal, MAX_CLASSES_PER_BASIS, MAX_ORBIT_DEPTH,
    MIN_SIMILARITY_THRESHOLD, OrbitReduction, OrbitStep, RefusalReason, SCHEMA_VERSION,
    SemanticCanonicalBasis, query_identification, refuse_cross_family, validate_orbit,
};

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

fn make_step(idx: usize, t: EquivalenceTransformation) -> OrbitStep {
    OrbitStep {
        step_index: idx,
        transformation: t,
        result_fingerprint: format!("fp-step-{}", idx),
        cost_millionths: 10_000,
    }
}

fn make_orbit(
    family: ArtifactFamily,
    inp: &str,
    canon: &str,
    steps: Vec<OrbitStep>,
) -> OrbitReduction {
    OrbitReduction::new(family, inp.to_string(), canon.to_string(), steps, true)
}

fn make_representative(family: ArtifactFamily, fp: &str) -> CanonicalRepresentative {
    CanonicalRepresentative::new(family, fp.to_string(), 2, all_transforms(), epoch())
}

fn make_class(family: ArtifactFamily, fp: &str) -> EquivalenceClass {
    let rep = make_representative(family, fp);
    let orb = make_orbit(
        family,
        "inp-a",
        fp,
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    EquivalenceClass::new(rep, vec![orb], vec![])
}

fn make_basis(classes: Vec<EquivalenceClass>) -> SemanticCanonicalBasis {
    SemanticCanonicalBasis::new(epoch(), classes, all_transforms())
}

fn make_refusal() -> IdentificationRefusal {
    IdentificationRefusal::new(
        "fp-left".to_string(),
        "fp-right".to_string(),
        Some(ArtifactFamily::Ir1Fragment),
        vec![
            RefusalReason::FamilyMismatch {
                left: ArtifactFamily::Ir1Fragment,
                right: ArtifactFamily::CacheEntry,
            },
            RefusalReason::EpochMismatch {
                left_epoch: 1,
                right_epoch: 2,
            },
        ],
        epoch(),
    )
}

fn all_refusal_reasons() -> Vec<RefusalReason> {
    vec![
        RefusalReason::FamilyMismatch {
            left: ArtifactFamily::Ir1Fragment,
            right: ArtifactFamily::CacheEntry,
        },
        RefusalReason::EpochMismatch {
            left_epoch: 1,
            right_epoch: 2,
        },
        RefusalReason::ObservableEffectDifference {
            description: "effect diff".to_string(),
        },
        RefusalReason::OrbitDepthExceeded { depth_reached: 100 },
        RefusalReason::TransformationNotAllowed {
            transformation: EquivalenceTransformation::ConstantFolding,
        },
        RefusalReason::SimilarityBelowThreshold {
            score_millionths: 800_000,
            threshold_millionths: 950_000,
        },
        RefusalReason::OpaqueRegionPresent {
            region_label: "opaque-1".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// ArtifactFamily — Copy / BTreeSet / Clone / Debug / as_str / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_family_copy_semantics() {
    let a = ArtifactFamily::Ir1Fragment;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_family_btreeset_dedup_10() {
    let mut set = BTreeSet::new();
    for f in ArtifactFamily::ALL {
        set.insert(*f);
    }
    set.insert(ArtifactFamily::Ir1Fragment);
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_artifact_family_clone_independence() {
    let a = ArtifactFamily::CacheEntry;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_family_debug_all_unique() {
    let dbgs: BTreeSet<String> = ArtifactFamily::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 10);
}

#[test]
fn enrichment_artifact_family_as_str_all_unique() {
    let strs: BTreeSet<&str> = ArtifactFamily::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 10);
}

#[test]
fn enrichment_artifact_family_display_matches_as_str() {
    for f in ArtifactFamily::ALL {
        assert_eq!(format!("{}", f), f.as_str());
    }
}

#[test]
fn enrichment_artifact_family_serde_roundtrip_all() {
    for f in ArtifactFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let rt: ArtifactFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, rt);
    }
}

// ---------------------------------------------------------------------------
// EquivalenceTransformation — Copy / BTreeSet / Clone / Debug / as_str / safe
// ---------------------------------------------------------------------------

#[test]
fn enrichment_equivalence_transformation_copy_semantics() {
    let a = EquivalenceTransformation::AlphaRenaming;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_equivalence_transformation_btreeset_dedup_10() {
    let mut set = BTreeSet::new();
    for t in EquivalenceTransformation::ALL {
        set.insert(*t);
    }
    set.insert(EquivalenceTransformation::AlphaRenaming);
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_equivalence_transformation_clone_independence() {
    let a = EquivalenceTransformation::ConstantFolding;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_equivalence_transformation_debug_all_unique() {
    let dbgs: BTreeSet<String> = EquivalenceTransformation::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 10);
}

#[test]
fn enrichment_equivalence_transformation_as_str_all_unique() {
    let strs: BTreeSet<&str> = EquivalenceTransformation::ALL
        .iter()
        .map(|v| v.as_str())
        .collect();
    assert_eq!(strs.len(), 10);
}

#[test]
fn enrichment_equivalence_transformation_display_matches_as_str() {
    for t in EquivalenceTransformation::ALL {
        assert_eq!(format!("{}", t), t.as_str());
    }
}

#[test]
fn enrichment_equivalence_transformation_is_universally_safe_count_3() {
    let safe_count = EquivalenceTransformation::ALL
        .iter()
        .filter(|t| t.is_universally_safe())
        .count();
    assert_eq!(safe_count, 3);
}

#[test]
fn enrichment_equivalence_transformation_safe_subset_correct() {
    let safe = safe_only();
    assert!(safe.contains(&EquivalenceTransformation::AlphaRenaming));
    assert!(safe.contains(&EquivalenceTransformation::LabelNormalization));
    assert!(safe.contains(&EquivalenceTransformation::MetadataNormalization));
    assert!(!safe.contains(&EquivalenceTransformation::DeadCodeElimination));
    assert!(!safe.contains(&EquivalenceTransformation::ConstantFolding));
}

#[test]
fn enrichment_equivalence_transformation_serde_roundtrip_all() {
    for t in EquivalenceTransformation::ALL {
        let json = serde_json::to_string(t).unwrap();
        let rt: EquivalenceTransformation = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, rt);
    }
}

// ---------------------------------------------------------------------------
// RefusalReason — Clone / Debug / tag / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_refusal_reason_clone_independence() {
    let a = RefusalReason::FamilyMismatch {
        left: ArtifactFamily::Ir1Fragment,
        right: ArtifactFamily::CacheEntry,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_refusal_reason_debug_nonempty() {
    let r = RefusalReason::OrbitDepthExceeded { depth_reached: 100 };
    assert!(!format!("{:?}", r).is_empty());
}

#[test]
fn enrichment_refusal_reason_tag_all_unique_7() {
    let reasons = all_refusal_reasons();
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn enrichment_refusal_reason_display_all_nonempty() {
    for r in &all_refusal_reasons() {
        assert!(!format!("{}", r).is_empty(), "empty display for: {:?}", r);
    }
}

#[test]
fn enrichment_refusal_reason_serde_roundtrip_all() {
    for r in &all_refusal_reasons() {
        let json = serde_json::to_string(r).unwrap();
        let rt: RefusalReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, rt);
    }
}

// ---------------------------------------------------------------------------
// IdentificationRefusal — Clone / Debug / JSON / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_identification_refusal_clone_independence() {
    let a = make_refusal();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_identification_refusal_debug_nonempty() {
    assert!(!format!("{:?}", make_refusal()).is_empty());
}

#[test]
fn enrichment_identification_refusal_json_field_names() {
    let r = make_refusal();
    let json = serde_json::to_string(&r).unwrap();
    for field in &[
        "left_fingerprint",
        "right_fingerprint",
        "family",
        "reasons",
        "epoch",
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
fn enrichment_identification_refusal_reason_count() {
    let r = make_refusal();
    assert_eq!(r.reason_count(), 2);
}

#[test]
fn enrichment_identification_refusal_has_reason_tag() {
    let r = make_refusal();
    assert!(r.has_reason_tag("family_mismatch"));
    assert!(r.has_reason_tag("epoch_mismatch"));
    assert!(!r.has_reason_tag("orbit_depth_exceeded"));
}

#[test]
fn enrichment_identification_refusal_serde_roundtrip() {
    let r = make_refusal();
    let json = serde_json::to_string(&r).unwrap();
    let rt: IdentificationRefusal = serde_json::from_str(&json).unwrap();
    assert_eq!(r, rt);
}

// ---------------------------------------------------------------------------
// OrbitStep — Clone / Debug / JSON / serde / Ord
// ---------------------------------------------------------------------------

#[test]
fn enrichment_orbit_step_clone_independence() {
    let a = make_step(0, EquivalenceTransformation::AlphaRenaming);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_orbit_step_debug_nonempty() {
    assert!(
        !format!(
            "{:?}",
            make_step(0, EquivalenceTransformation::AlphaRenaming)
        )
        .is_empty()
    );
}

#[test]
fn enrichment_orbit_step_json_field_names() {
    let s = make_step(0, EquivalenceTransformation::AlphaRenaming);
    let json = serde_json::to_string(&s).unwrap();
    for field in &[
        "step_index",
        "transformation",
        "result_fingerprint",
        "cost_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_orbit_step_serde_roundtrip() {
    let s = make_step(0, EquivalenceTransformation::AlphaRenaming);
    let json = serde_json::to_string(&s).unwrap();
    let rt: OrbitStep = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

#[test]
fn enrichment_orbit_step_ord_by_index() {
    let s0 = make_step(0, EquivalenceTransformation::AlphaRenaming);
    let s1 = make_step(1, EquivalenceTransformation::AlphaRenaming);
    assert!(s0 < s1);
}

// ---------------------------------------------------------------------------
// OrbitReduction — Clone / Debug / JSON / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_orbit_reduction_clone_independence() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let o2 = o.clone();
    assert_eq!(o, o2);
}

#[test]
fn enrichment_orbit_reduction_debug_nonempty() {
    let o = make_orbit(ArtifactFamily::Ir1Fragment, "inp", "canon", vec![]);
    assert!(!format!("{:?}", o).is_empty());
}

#[test]
fn enrichment_orbit_reduction_json_field_names() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let json = serde_json::to_string(&o).unwrap();
    for field in &[
        "family",
        "input_fingerprint",
        "canonical_fingerprint",
        "steps",
        "total_cost_millionths",
        "converged",
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
fn enrichment_orbit_reduction_total_cost_computed() {
    let steps = vec![
        make_step(0, EquivalenceTransformation::AlphaRenaming),
        make_step(1, EquivalenceTransformation::ConstantFolding),
    ];
    let o = make_orbit(ArtifactFamily::Ir1Fragment, "inp", "canon", steps);
    assert_eq!(o.total_cost_millionths, 20_000);
}

#[test]
fn enrichment_orbit_reduction_depth() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![
            make_step(0, EquivalenceTransformation::AlphaRenaming),
            make_step(1, EquivalenceTransformation::ConstantFolding),
            make_step(2, EquivalenceTransformation::DeadCodeElimination),
        ],
    );
    assert_eq!(o.depth(), 3);
}

#[test]
fn enrichment_orbit_reduction_exceeded_depth_limit_false() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    assert!(!o.exceeded_depth_limit());
}

#[test]
fn enrichment_orbit_reduction_is_trivial_same_fingerprint_no_steps() {
    let o = make_orbit(ArtifactFamily::Ir1Fragment, "same", "same", vec![]);
    assert!(o.is_trivial());
}

#[test]
fn enrichment_orbit_reduction_not_trivial_different_fingerprints() {
    let o = make_orbit(ArtifactFamily::Ir1Fragment, "a", "b", vec![]);
    assert!(!o.is_trivial());
}

#[test]
fn enrichment_orbit_reduction_not_trivial_with_steps() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "same",
        "same",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    assert!(!o.is_trivial());
}

#[test]
fn enrichment_orbit_reduction_transformations_used() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![
            make_step(0, EquivalenceTransformation::AlphaRenaming),
            make_step(1, EquivalenceTransformation::ConstantFolding),
            make_step(2, EquivalenceTransformation::AlphaRenaming),
        ],
    );
    let used = o.transformations_used();
    assert_eq!(used.len(), 2);
    assert!(used.contains(&EquivalenceTransformation::AlphaRenaming));
    assert!(used.contains(&EquivalenceTransformation::ConstantFolding));
}

#[test]
fn enrichment_orbit_reduction_serde_roundtrip() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let json = serde_json::to_string(&o).unwrap();
    let rt: OrbitReduction = serde_json::from_str(&json).unwrap();
    assert_eq!(o, rt);
}

// ---------------------------------------------------------------------------
// CanonicalRepresentative — Clone / Debug / JSON / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_representative_clone_independence() {
    let r = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn enrichment_canonical_representative_debug_nonempty() {
    assert!(
        !format!(
            "{:?}",
            make_representative(ArtifactFamily::Ir1Fragment, "canon-1")
        )
        .is_empty()
    );
}

#[test]
fn enrichment_canonical_representative_json_field_names() {
    let r = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let json = serde_json::to_string(&r).unwrap();
    for field in &[
        "family",
        "canonical_fingerprint",
        "member_count",
        "allowed_transformations",
        "epoch",
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
fn enrichment_canonical_representative_is_singleton() {
    let r = CanonicalRepresentative::new(
        ArtifactFamily::Ir1Fragment,
        "fp".to_string(),
        1,
        all_transforms(),
        epoch(),
    );
    assert!(r.is_singleton());
    let r2 = make_representative(ArtifactFamily::Ir1Fragment, "fp");
    assert!(!r2.is_singleton());
}

#[test]
fn enrichment_canonical_representative_allows_transformation() {
    let r = make_representative(ArtifactFamily::Ir1Fragment, "fp");
    assert!(r.allows_transformation(EquivalenceTransformation::AlphaRenaming));
    let limited = CanonicalRepresentative::new(
        ArtifactFamily::Ir1Fragment,
        "fp".to_string(),
        1,
        BTreeSet::from([EquivalenceTransformation::AlphaRenaming]),
        epoch(),
    );
    assert!(limited.allows_transformation(EquivalenceTransformation::AlphaRenaming));
    assert!(!limited.allows_transformation(EquivalenceTransformation::ConstantFolding));
}

#[test]
fn enrichment_canonical_representative_allowed_fraction_full() {
    let r = make_representative(ArtifactFamily::Ir1Fragment, "fp");
    assert_eq!(r.allowed_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_canonical_representative_serde_roundtrip() {
    let r = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let json = serde_json::to_string(&r).unwrap();
    let rt: CanonicalRepresentative = serde_json::from_str(&json).unwrap();
    assert_eq!(r, rt);
}

// ---------------------------------------------------------------------------
// EquivalenceClass — Clone / Debug / methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_equivalence_class_clone_independence() {
    let c = make_class(ArtifactFamily::Ir1Fragment, "canon-1");
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_equivalence_class_debug_nonempty() {
    assert!(!format!("{:?}", make_class(ArtifactFamily::Ir1Fragment, "canon-1")).is_empty());
}

#[test]
fn enrichment_equivalence_class_member_count() {
    let c = make_class(ArtifactFamily::Ir1Fragment, "canon-1");
    assert_eq!(c.member_count(), 1);
}

#[test]
fn enrichment_equivalence_class_refusal_count_zero() {
    let c = make_class(ArtifactFamily::Ir1Fragment, "canon-1");
    assert_eq!(c.refusal_count(), 0);
}

#[test]
fn enrichment_equivalence_class_refusal_count_nonzero() {
    let rep = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let orb = make_orbit(ArtifactFamily::Ir1Fragment, "inp-a", "canon-1", vec![]);
    let refusal = make_refusal();
    let c = EquivalenceClass::new(rep, vec![orb], vec![refusal]);
    assert_eq!(c.refusal_count(), 1);
}

#[test]
fn enrichment_equivalence_class_all_converged_true() {
    let c = make_class(ArtifactFamily::Ir1Fragment, "canon-1");
    assert!(c.all_converged());
}

#[test]
fn enrichment_equivalence_class_max_orbit_depth() {
    let rep = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let orb1 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp-a",
        "canon-1",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let orb2 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp-b",
        "canon-1",
        vec![
            make_step(0, EquivalenceTransformation::AlphaRenaming),
            make_step(1, EquivalenceTransformation::ConstantFolding),
            make_step(2, EquivalenceTransformation::DeadCodeElimination),
        ],
    );
    let c = EquivalenceClass::new(rep, vec![orb1, orb2], vec![]);
    assert_eq!(c.max_orbit_depth(), 3);
}

#[test]
fn enrichment_equivalence_class_all_transformations_used() {
    let c = make_class(ArtifactFamily::Ir1Fragment, "canon-1");
    let used = c.all_transformations_used();
    assert!(used.contains(&EquivalenceTransformation::AlphaRenaming));
}

#[test]
fn enrichment_equivalence_class_average_depth_millionths() {
    let rep = make_representative(ArtifactFamily::Ir1Fragment, "canon-1");
    let orb1 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp-a",
        "canon-1",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let orb2 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp-b",
        "canon-1",
        vec![
            make_step(0, EquivalenceTransformation::AlphaRenaming),
            make_step(1, EquivalenceTransformation::ConstantFolding),
            make_step(2, EquivalenceTransformation::DeadCodeElimination),
        ],
    );
    let c = EquivalenceClass::new(rep, vec![orb1, orb2], vec![]);
    assert_eq!(c.average_depth_millionths(), 2_000_000);
}

// ---------------------------------------------------------------------------
// BasisCoverageReport — Clone / Debug / JSON / is_complete
// ---------------------------------------------------------------------------

#[test]
fn enrichment_basis_coverage_report_clone_independence() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let report = b.coverage_report();
    let report2 = report.clone();
    assert_eq!(report, report2);
}

#[test]
fn enrichment_basis_coverage_report_debug_nonempty() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert!(!format!("{:?}", b.coverage_report()).is_empty());
}

#[test]
fn enrichment_basis_coverage_report_json_field_names() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let report = b.coverage_report();
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "covered_families",
        "uncovered_families",
        "total_classes",
        "total_members",
        "total_refusals",
        "coverage_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_basis_coverage_report_not_complete_single_family() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let report = b.coverage_report();
    assert!(!report.is_complete());
}

// ---------------------------------------------------------------------------
// SemanticCanonicalBasis — Clone / Debug / JSON / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_semantic_canonical_basis_clone_independence() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let b2 = b.clone();
    assert_eq!(b, b2);
}

#[test]
fn enrichment_semantic_canonical_basis_debug_nonempty() {
    assert!(!format!("{:?}", make_basis(vec![])).is_empty());
}

#[test]
fn enrichment_semantic_canonical_basis_json_field_names() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let json = serde_json::to_string(&b).unwrap();
    for field in &[
        "schema_version",
        "epoch",
        "classes",
        "global_allowed_transformations",
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
fn enrichment_semantic_canonical_basis_class_count() {
    let b = make_basis(vec![
        make_class(ArtifactFamily::Ir1Fragment, "c1"),
        make_class(ArtifactFamily::CacheEntry, "c2"),
    ]);
    assert_eq!(b.class_count(), 2);
}

#[test]
fn enrichment_semantic_canonical_basis_within_class_limit() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert!(b.within_class_limit());
}

#[test]
fn enrichment_semantic_canonical_basis_total_member_count() {
    let b = make_basis(vec![
        make_class(ArtifactFamily::Ir1Fragment, "c1"),
        make_class(ArtifactFamily::CacheEntry, "c2"),
    ]);
    assert_eq!(b.total_member_count(), 2);
}

#[test]
fn enrichment_semantic_canonical_basis_total_refusal_count() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert_eq!(b.total_refusal_count(), 0);
}

#[test]
fn enrichment_semantic_canonical_basis_classes_for_family() {
    let b = make_basis(vec![
        make_class(ArtifactFamily::Ir1Fragment, "c1"),
        make_class(ArtifactFamily::CacheEntry, "c2"),
        make_class(ArtifactFamily::Ir1Fragment, "c3"),
    ]);
    let ir1_classes = b.classes_for_family(ArtifactFamily::Ir1Fragment);
    assert_eq!(ir1_classes.len(), 2);
    let cache_classes = b.classes_for_family(ArtifactFamily::CacheEntry);
    assert_eq!(cache_classes.len(), 1);
}

#[test]
fn enrichment_semantic_canonical_basis_all_orbits_converged() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert!(b.all_orbits_converged());
}

#[test]
fn enrichment_semantic_canonical_basis_max_orbit_depth() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert_eq!(b.max_orbit_depth(), 1);
}

#[test]
fn enrichment_semantic_canonical_basis_serde_roundtrip() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let json = serde_json::to_string(&b).unwrap();
    let rt: SemanticCanonicalBasis = serde_json::from_str(&json).unwrap();
    assert_eq!(b, rt);
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_query_identification_success() {
    let orb1 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "fp-a",
        "canon-shared",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let orb2 = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "fp-b",
        "canon-shared",
        vec![make_step(0, EquivalenceTransformation::ConstantFolding)],
    );
    let rep = CanonicalRepresentative::new(
        ArtifactFamily::Ir1Fragment,
        "canon-shared".to_string(),
        2,
        all_transforms(),
        epoch(),
    );
    let cls = EquivalenceClass::new(rep, vec![orb1, orb2], vec![]);
    let b = make_basis(vec![cls]);
    let result = query_identification(&b, ArtifactFamily::Ir1Fragment, "fp-a", "fp-b");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "canon-shared");
}

#[test]
fn enrichment_query_identification_failure() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let result = query_identification(&b, ArtifactFamily::Ir1Fragment, "unknown-a", "unknown-b");
    assert!(result.is_err());
}

#[test]
fn enrichment_refuse_cross_family_creates_refusal() {
    let refusal = refuse_cross_family(
        ArtifactFamily::Ir1Fragment,
        ArtifactFamily::CacheEntry,
        "fp-left",
        "fp-right",
        epoch(),
    );
    assert_eq!(refusal.reason_count(), 1);
    assert!(refusal.has_reason_tag("family_mismatch"));
    assert!(refusal.family.is_none());
}

#[test]
fn enrichment_validate_orbit_clean() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
    );
    let issues = validate_orbit(&o, &all_transforms());
    assert!(issues.is_empty());
}

#[test]
fn enrichment_validate_orbit_transformation_not_allowed() {
    let o = make_orbit(
        ArtifactFamily::Ir1Fragment,
        "inp",
        "canon",
        vec![make_step(0, EquivalenceTransformation::ConstantFolding)],
    );
    let issues = validate_orbit(&o, &safe_only());
    assert!(!issues.is_empty());
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.semantic-canonical-basis.v1");
    assert_eq!(BEAD_ID, "bd-1lsy.7.18.1");
    assert_eq!(COMPONENT, "semantic_canonical_basis");
    assert_eq!(MAX_ORBIT_DEPTH, 64);
    assert_eq!(MAX_CLASSES_PER_BASIS, 8_192);
    assert_eq!(MIN_SIMILARITY_THRESHOLD, 950_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_orbit() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let o = make_orbit(
                ArtifactFamily::Ir1Fragment,
                "inp",
                "canon",
                vec![make_step(0, EquivalenceTransformation::AlphaRenaming)],
            );
            serde_json::to_string(&o).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "orbit should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_basis() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
            serde_json::to_string(&b).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "basis should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_basis_schema_version() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    assert_eq!(b.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_cross_cutting_coverage_families_sum_to_10() {
    let b = make_basis(vec![
        make_class(ArtifactFamily::Ir1Fragment, "c1"),
        make_class(ArtifactFamily::CacheEntry, "c2"),
    ]);
    let report = b.coverage_report();
    assert_eq!(
        report.covered_families.len() + report.uncovered_families.len(),
        10
    );
}

#[test]
fn enrichment_cross_cutting_total_members_equals_sum() {
    let b = make_basis(vec![
        make_class(ArtifactFamily::Ir1Fragment, "c1"),
        make_class(ArtifactFamily::CacheEntry, "c2"),
    ]);
    let total: usize = b.classes.iter().map(|c| c.member_count()).sum();
    assert_eq!(b.total_member_count(), total);
}

#[test]
fn enrichment_cross_cutting_total_refusals_equals_sum() {
    let b = make_basis(vec![make_class(ArtifactFamily::Ir1Fragment, "c1")]);
    let total: usize = b.classes.iter().map(|c| c.refusal_count()).sum();
    assert_eq!(b.total_refusal_count(), total);
}
