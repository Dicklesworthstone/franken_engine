//! Deep integration tests for AARA resource certificates, effect summaries,
//! symbolic potentials, and certificate bundles (RGC-625A).
//!
//! Covers composition semantics, boundary conditions, hash determinism,
//! multi-dimensional certificates, large-scale stress, and serde round-trips
//! beyond what the existing unit and integration tests exercise.

#![forbid(unsafe_code)]
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

use frankenengine_engine::aara_resource_certificate::{
    AbstentionPoint, AbstentionReason, AssumptionKind, BEAD_ID, BUNDLE_SCHEMA_VERSION,
    CERTIFICATE_SCHEMA_VERSION, COMPONENT, CertificateAssumption, CertificateBundle,
    CertificateInput, CertificateVerdict, EFFECT_SUMMARY_SCHEMA_VERSION, EffectEntry, EffectKind,
    EffectSummary, MAX_ABSTENTION_POINTS_PER_REGION, MAX_ASSUMPTIONS_PER_CERTIFICATE,
    MIN_CERTIFICATE_CONFIDENCE, POTENTIAL_SCHEMA_VERSION, ResourceBound, ResourceCertificate,
    ResourceDimension, SymbolicPotential,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn mk_entry(kind: EffectKind, point: &str, count_m: i64, exact: bool) -> EffectEntry {
    EffectEntry {
        kind,
        program_point: point.into(),
        worst_case_count_millionths: count_m,
        is_exact: exact,
    }
}

fn mk_abstention(point: &str, reason: AbstentionReason, detail: &str) -> AbstentionPoint {
    AbstentionPoint {
        program_point: point.into(),
        reason,
        detail: detail.into(),
    }
}

fn mk_assumption(key: &str, kind: AssumptionKind, critical: bool) -> CertificateAssumption {
    CertificateAssumption {
        key: key.into(),
        kind,
        description: format!("assumption: {key}"),
        is_critical: critical,
    }
}

fn mk_bound(dim: ResourceDimension, upper_m: i64, confidence_m: i64, tight: bool) -> ResourceBound {
    ResourceBound {
        dimension: dim,
        upper_bound_millionths: upper_m,
        is_tight: tight,
        confidence_millionths: confidence_m,
    }
}

fn mk_potential(
    region: &str,
    dim: ResourceDimension,
    initial: i64,
    pts: &[(&str, i64)],
) -> SymbolicPotential {
    let mut map = BTreeMap::new();
    for &(k, v) in pts {
        map.insert(k.to_string(), v);
    }
    SymbolicPotential::new(region, dim, initial, map)
}

fn mk_cert(
    id: &str,
    region: &str,
    ep: SecurityEpoch,
    bounds: Vec<ResourceBound>,
    summary: EffectSummary,
    assumptions: Vec<CertificateAssumption>,
    abstentions: Vec<AbstentionPoint>,
    potentials: Vec<SymbolicPotential>,
) -> ResourceCertificate {
    ResourceCertificate::new(CertificateInput {
        certificate_id: id.into(),
        region_id: region.into(),
        epoch: ep,
        bounds,
        effect_summary: summary,
        assumptions,
        abstention_points: abstentions,
        potentials,
    })
}

// =========================================================================
// 1. EffectSummary.compose() -- composition semantics
// =========================================================================

#[test]
fn compose_merges_entries_from_both_summaries() {
    let s1 = EffectSummary::build(
        "a",
        vec![mk_entry(EffectKind::Allocation, "a:1", 2 * MILLION, true)],
        vec![],
    );
    let s2 = EffectSummary::build(
        "b",
        vec![mk_entry(EffectKind::Hostcall, "b:1", 3 * MILLION, true)],
        vec![],
    );
    let composed = s1.compose(&s2);
    assert_eq!(composed.entries.len(), 2);
    assert_eq!(composed.total_effect_count(), 5 * MILLION);
    assert_eq!(composed.region_id, "a+b");
}

#[test]
fn compose_sums_same_kind_totals() {
    let s1 = EffectSummary::build(
        "x",
        vec![mk_entry(EffectKind::Allocation, "x:1", 4 * MILLION, true)],
        vec![],
    );
    let s2 = EffectSummary::build(
        "y",
        vec![mk_entry(EffectKind::Allocation, "y:1", 6 * MILLION, false)],
        vec![],
    );
    let composed = s1.compose(&s2);
    let alloc_total = *composed.kind_totals.get(&EffectKind::Allocation).unwrap();
    assert_eq!(alloc_total, 10 * MILLION);
}

#[test]
fn compose_hash_changes_from_either_input() {
    let s1 = EffectSummary::build(
        "region1",
        vec![mk_entry(EffectKind::GlobalRead, "r1:1", MILLION, true)],
        vec![],
    );
    let s2 = EffectSummary::build(
        "region2",
        vec![mk_entry(EffectKind::GlobalWrite, "r2:1", MILLION, true)],
        vec![],
    );
    let s3 = EffectSummary::build(
        "region3",
        vec![mk_entry(EffectKind::GlobalWrite, "r3:1", 2 * MILLION, true)],
        vec![],
    );
    let c12 = s1.compose(&s2);
    let c13 = s1.compose(&s3);
    assert_ne!(c12.content_hash, c13.content_hash);
}

#[test]
fn compose_with_abstentions_merges_both() {
    let abs1 = mk_abstention("a:10", AbstentionReason::UnboundedLoop, "loop");
    let abs2 = mk_abstention("b:20", AbstentionReason::DynamicCodeGen, "eval");
    let s1 = EffectSummary::build("a", vec![], vec![abs1]);
    let s2 = EffectSummary::build("b", vec![], vec![abs2]);
    let composed = s1.compose(&s2);
    assert_eq!(composed.abstention_points.len(), 2);
    assert!(!composed.is_complete);
}

#[test]
fn compose_truncates_abstentions_at_max() {
    let abstentions_a: Vec<AbstentionPoint> = (0..100)
        .map(|i| mk_abstention(&format!("a:{i}"), AbstentionReason::UnboundedLoop, "loop"))
        .collect();
    let abstentions_b: Vec<AbstentionPoint> = (0..100)
        .map(|i| {
            mk_abstention(
                &format!("b:{i}"),
                AbstentionReason::BudgetExhausted,
                "budget",
            )
        })
        .collect();
    let s1 = EffectSummary::build("a", vec![], abstentions_a);
    let s2 = EffectSummary::build("b", vec![], abstentions_b);
    let composed = s1.compose(&s2);
    assert_eq!(
        composed.abstention_points.len(),
        MAX_ABSTENTION_POINTS_PER_REGION
    );
}

#[test]
fn compose_pure_with_pure_is_pure() {
    let s1 = EffectSummary::build("pure1", vec![], vec![]);
    let s2 = EffectSummary::build("pure2", vec![], vec![]);
    let composed = s1.compose(&s2);
    assert!(composed.is_pure());
    assert_eq!(composed.total_effect_count(), 0);
}

#[test]
fn compose_pure_with_impure_is_impure() {
    let s_pure = EffectSummary::build("pure", vec![], vec![]);
    let s_impure = EffectSummary::build(
        "impure",
        vec![mk_entry(EffectKind::ClosureCapture, "cc:1", MILLION, true)],
        vec![],
    );
    let composed = s_pure.compose(&s_impure);
    assert!(!composed.is_pure());
}

#[test]
fn compose_propagates_dynamic_code_gen() {
    let s1 = EffectSummary::build("safe", vec![], vec![]);
    let s2 = EffectSummary::build(
        "dangerous",
        vec![mk_entry(
            EffectKind::DynamicCodeGen,
            "eval:1",
            MILLION,
            true,
        )],
        vec![],
    );
    let composed = s1.compose(&s2);
    assert!(composed.has_dynamic_code_gen());
}

// =========================================================================
// 2. SymbolicPotential edge cases
// =========================================================================

#[test]
fn potential_all_positive_non_negative_fraction_is_million() {
    let pot = mk_potential(
        "fn:pos",
        ResourceDimension::Time,
        10 * MILLION,
        &[("a", 5 * MILLION), ("b", 3 * MILLION), ("c", MILLION)],
    );
    assert_eq!(pot.non_negative_fraction_millionths(), MILLION);
}

#[test]
fn potential_all_negative_non_negative_fraction_is_zero() {
    let pot = mk_potential(
        "fn:neg",
        ResourceDimension::HeapMemory,
        10 * MILLION,
        &[("a", -1), ("b", -MILLION), ("c", -2 * MILLION)],
    );
    assert_eq!(pot.non_negative_fraction_millionths(), 0);
}

#[test]
fn potential_empty_non_negative_fraction_is_million() {
    let pot = mk_potential("fn:empty", ResourceDimension::StackDepth, MILLION, &[]);
    assert_eq!(pot.non_negative_fraction_millionths(), MILLION);
}

#[test]
fn potential_mixed_non_negative_fraction() {
    let pot = mk_potential(
        "fn:mix",
        ResourceDimension::Time,
        MILLION,
        &[("a", 100), ("b", -1), ("c", 0), ("d", -100)],
    );
    // a >= 0: yes, b >= 0: no, c >= 0: yes (zero counts), d >= 0: no
    // 2 out of 4 = 500_000
    assert_eq!(pot.non_negative_fraction_millionths(), 500_000);
}

#[test]
fn potential_zero_value_counts_as_non_negative() {
    let pot = mk_potential("fn:zero", ResourceDimension::Time, 0, &[("only", 0)]);
    assert!(pot.is_valid);
    assert_eq!(pot.non_negative_fraction_millionths(), MILLION);
    assert_eq!(pot.min_potential_millionths, 0);
}

#[test]
fn potential_terminal_returns_last_btree_key() {
    let pot = mk_potential(
        "fn:order",
        ResourceDimension::GcPressure,
        10 * MILLION,
        &[("aaa", 5 * MILLION), ("mmm", 3 * MILLION), ("zzz", MILLION)],
    );
    // BTreeMap orders lexicographically; "zzz" is last
    assert_eq!(pot.terminal_potential(), MILLION);
}

#[test]
fn potential_min_tracks_true_minimum() {
    let pot = mk_potential(
        "fn:min",
        ResourceDimension::Time,
        100 * MILLION,
        &[
            ("p1", 99 * MILLION),
            ("p2", 50 * MILLION),
            ("p3", 1),
            ("p4", 50 * MILLION),
        ],
    );
    assert_eq!(pot.min_potential_millionths, 1);
    assert!(pot.is_valid);
}

#[test]
fn potential_single_negative_point_invalidates() {
    let pot = mk_potential(
        "fn:single_neg",
        ResourceDimension::HostcallCount,
        MILLION,
        &[
            ("ok1", MILLION),
            ("ok2", 500_000),
            ("bad", -1),
            ("ok3", MILLION),
        ],
    );
    assert!(!pot.is_valid);
    assert_eq!(pot.min_potential_millionths, -1);
}

// =========================================================================
// 3. ResourceBound boundary conditions
// =========================================================================

#[test]
fn bound_at_exact_min_confidence_meets_threshold() {
    let bound = mk_bound(
        ResourceDimension::Time,
        10 * MILLION,
        MIN_CERTIFICATE_CONFIDENCE,
        false,
    );
    assert!(bound.meets_confidence_threshold());
}

#[test]
fn bound_one_below_min_confidence_fails_threshold() {
    let bound = mk_bound(
        ResourceDimension::Time,
        10 * MILLION,
        MIN_CERTIFICATE_CONFIDENCE - 1,
        false,
    );
    assert!(!bound.meets_confidence_threshold());
}

#[test]
fn bound_full_confidence_meets_threshold() {
    let bound = mk_bound(ResourceDimension::Time, MILLION, MILLION, true);
    assert!(bound.meets_confidence_threshold());
}

#[test]
fn bound_zero_confidence_fails_threshold() {
    let bound = mk_bound(ResourceDimension::IoOperationCount, MILLION, 0, false);
    assert!(!bound.meets_confidence_threshold());
}

#[test]
fn bound_compose_tightness_requires_both_tight() {
    let b1 = mk_bound(ResourceDimension::HeapMemory, 5 * MILLION, MILLION, true);
    let b2 = mk_bound(ResourceDimension::HeapMemory, 3 * MILLION, MILLION, false);
    let composed = b1.compose(&b2).unwrap();
    assert!(!composed.is_tight);

    let b3 = mk_bound(ResourceDimension::HeapMemory, 2 * MILLION, MILLION, true);
    let composed2 = b1.compose(&b3).unwrap();
    assert!(composed2.is_tight);
}

#[test]
fn bound_compose_saturates_on_overflow() {
    let b1 = mk_bound(ResourceDimension::Time, i64::MAX, MILLION, true);
    let b2 = mk_bound(ResourceDimension::Time, MILLION, MILLION, true);
    let composed = b1.compose(&b2).unwrap();
    assert_eq!(composed.upper_bound_millionths, i64::MAX);
}

#[test]
fn bound_compose_takes_min_confidence() {
    let b1 = mk_bound(ResourceDimension::StackDepth, MILLION, 950_000, true);
    let b2 = mk_bound(ResourceDimension::StackDepth, MILLION, 800_000, true);
    let composed = b1.compose(&b2).unwrap();
    assert_eq!(composed.confidence_millionths, 800_000);
}

#[test]
fn bound_negative_upper_bound_is_representable() {
    // Negative bounds are valid structurally; they produce Violated verdict
    let bound = mk_bound(ResourceDimension::Time, -MILLION, MILLION, false);
    assert_eq!(bound.upper_bound_millionths, -MILLION);
}

// =========================================================================
// 4. ResourceCertificate.new() -- all verdict paths
// =========================================================================

#[test]
fn cert_certified_all_bounds_high_confidence_no_abstentions() {
    let cert = mk_cert(
        "c1",
        "fn:good",
        epoch(1),
        vec![
            mk_bound(ResourceDimension::Time, 10 * MILLION, MILLION, true),
            mk_bound(ResourceDimension::HeapMemory, 20 * MILLION, 950_000, false),
        ],
        EffectSummary::build("fn:good", vec![], vec![]),
        vec![],
        vec![],
        vec![
            mk_potential(
                "fn:good",
                ResourceDimension::Time,
                MILLION,
                &[("exit", 100_000)],
            ),
            mk_potential(
                "fn:good",
                ResourceDimension::HeapMemory,
                2 * MILLION,
                &[("exit", MILLION)],
            ),
        ],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Certified);
    assert_eq!(cert.certified_dimension_count(), 2);
    assert!(cert.all_potentials_valid());
}

#[test]
fn cert_violated_from_negative_bound() {
    let cert = mk_cert(
        "c-neg",
        "fn:neg_bound",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, -1, MILLION, false)],
        EffectSummary::build("fn:neg_bound", vec![], vec![]),
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
}

#[test]
fn cert_violated_from_invalid_potential() {
    let bad_pot = mk_potential("fn:bad", ResourceDimension::Time, MILLION, &[("boom", -1)]);
    assert!(!bad_pot.is_valid);

    let cert = mk_cert(
        "c-bad-pot",
        "fn:bad",
        epoch(1),
        vec![mk_bound(
            ResourceDimension::Time,
            10 * MILLION,
            MILLION,
            true,
        )],
        EffectSummary::build("fn:bad", vec![], vec![]),
        vec![],
        vec![],
        vec![bad_pot],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
}

#[test]
fn cert_abstained_from_input_abstention_points() {
    let cert = mk_cert(
        "c-abs1",
        "fn:abs",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:abs", vec![], vec![]),
        vec![],
        vec![mk_abstention(
            "fn:abs:10",
            AbstentionReason::UnboundedRecursion,
            "recursive",
        )],
        vec![mk_potential(
            "fn:abs",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 500_000)],
        )],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
}

#[test]
fn cert_abstained_from_effect_summary_abstentions() {
    let abs = mk_abstention("fn:eval:5", AbstentionReason::DynamicCodeGen, "eval found");
    let summary = EffectSummary::build("fn:eval", vec![], vec![abs.clone()]);
    let cert = mk_cert(
        "c-abs2",
        "fn:eval",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        summary,
        vec![],
        vec![], // No explicit abstentions, but summary has one
        vec![mk_potential(
            "fn:eval",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 500_000)],
        )],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
    assert!(cert.abstention_points.contains(&abs));
}

#[test]
fn cert_provisional_empty_bounds() {
    let cert = mk_cert(
        "c-no-bounds",
        "fn:nobounds",
        epoch(1),
        vec![],
        EffectSummary::build("fn:nobounds", vec![], vec![]),
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Provisional);
}

#[test]
fn cert_provisional_low_confidence() {
    let cert = mk_cert(
        "c-low",
        "fn:lowconf",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, 500_000, false)],
        EffectSummary::build("fn:lowconf", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:lowconf",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 100)],
        )],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Provisional);
}

#[test]
fn cert_provisional_mixed_confidence_at_least_one_below() {
    let cert = mk_cert(
        "c-mixed",
        "fn:mixed",
        epoch(1),
        vec![
            mk_bound(ResourceDimension::Time, MILLION, MILLION, true),
            mk_bound(ResourceDimension::HeapMemory, MILLION, 500_000, false),
        ],
        EffectSummary::build("fn:mixed", vec![], vec![]),
        vec![],
        vec![],
        vec![
            mk_potential(
                "fn:mixed",
                ResourceDimension::Time,
                MILLION,
                &[("exit", 100)],
            ),
            mk_potential(
                "fn:mixed",
                ResourceDimension::HeapMemory,
                MILLION,
                &[("exit", 100)],
            ),
        ],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Provisional);
    assert_eq!(cert.certified_dimension_count(), 1);
}

// =========================================================================
// 5. CertificateBundle aggregate functions
// =========================================================================

#[test]
fn bundle_empty_certification_rate_is_zero() {
    let bundle = CertificateBundle::build("empty", epoch(1), vec![]);
    assert_eq!(bundle.certification_rate_millionths(), 0);
    assert_eq!(bundle.total_count(), 0);
}

#[test]
fn bundle_single_certified_rate_is_million() {
    let cert = mk_cert(
        "c1",
        "fn:ok",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:ok", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:ok",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 1)],
        )],
    );
    let bundle = CertificateBundle::build("one", epoch(1), vec![cert]);
    assert_eq!(bundle.certification_rate_millionths(), MILLION);
    assert!(bundle.passes(MILLION));
}

#[test]
fn bundle_half_certified_rate() {
    let good = mk_cert(
        "c-g",
        "fn:good",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:good", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:good",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 1)],
        )],
    );
    let bad = mk_cert(
        "c-b",
        "fn:bad",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, 500_000, false)],
        EffectSummary::build("fn:bad", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:bad",
            ResourceDimension::Time,
            MILLION,
            &[("exit", 1)],
        )],
    );
    let bundle = CertificateBundle::build("half", epoch(1), vec![good, bad]);
    assert_eq!(bundle.certification_rate_millionths(), 500_000);
    assert!(!bundle.passes(900_000));
    assert!(bundle.passes(500_000));
}

#[test]
fn bundle_passes_requires_zero_violations() {
    let violated = mk_cert(
        "c-v",
        "fn:viol",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, -1, MILLION, false)],
        EffectSummary::build("fn:viol", vec![], vec![]),
        vec![],
        vec![],
        vec![],
    );
    let bundle = CertificateBundle::build("viol", epoch(1), vec![violated]);
    assert!(!bundle.passes(0));
}

#[test]
fn bundle_counts_all_verdict_types() {
    let certified = mk_cert(
        "c1",
        "fn:cert",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:cert", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:cert",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    let provisional = mk_cert(
        "c2",
        "fn:prov",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, 500_000, false)],
        EffectSummary::build("fn:prov", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:prov",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    let abstained = mk_cert(
        "c3",
        "fn:abs",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:abs", vec![], vec![]),
        vec![],
        vec![mk_abstention(
            "fn:abs:1",
            AbstentionReason::WithStatement,
            "with",
        )],
        vec![],
    );
    let violated = mk_cert(
        "c4",
        "fn:viol",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:viol", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:viol",
            ResourceDimension::Time,
            MILLION,
            &[("e", -1)],
        )],
    );
    let bundle = CertificateBundle::build(
        "all",
        epoch(1),
        vec![certified, provisional, abstained, violated],
    );
    assert_eq!(bundle.total_count(), 4);
    assert_eq!(bundle.certified_count, 1);
    assert_eq!(bundle.abstained_count, 1);
    assert_eq!(bundle.violated_count, 1);
}

// =========================================================================
// 6. Multi-dimensional certificates
// =========================================================================

#[test]
fn cert_covers_all_seven_dimensions() {
    let dims = ResourceDimension::ALL;
    let bounds: Vec<ResourceBound> = dims
        .iter()
        .map(|&d| mk_bound(d, 10 * MILLION, MILLION, true))
        .collect();
    let potentials: Vec<SymbolicPotential> = dims
        .iter()
        .map(|&d| mk_potential("fn:all_dims", d, MILLION, &[("exit", 500_000)]))
        .collect();
    let cert = mk_cert(
        "c-7d",
        "fn:all_dims",
        epoch(1),
        bounds,
        EffectSummary::build("fn:all_dims", vec![], vec![]),
        vec![],
        vec![],
        potentials,
    );
    assert_eq!(cert.verdict, CertificateVerdict::Certified);
    assert_eq!(cert.certified_dimension_count(), 7);
    let covered = cert.covered_dimensions();
    for d in dims {
        assert!(covered.contains(d));
    }
}

#[test]
fn cert_bound_for_returns_correct_dimension() {
    let cert = mk_cert(
        "c-bf",
        "fn:bf",
        epoch(1),
        vec![
            mk_bound(ResourceDimension::Time, 5 * MILLION, MILLION, true),
            mk_bound(ResourceDimension::HeapMemory, 20 * MILLION, 950_000, false),
            mk_bound(
                ResourceDimension::HostcallCount,
                100 * MILLION,
                MILLION,
                true,
            ),
        ],
        EffectSummary::build("fn:bf", vec![], vec![]),
        vec![],
        vec![],
        vec![],
    );
    let time_bound = cert.bound_for(ResourceDimension::Time).unwrap();
    assert_eq!(time_bound.upper_bound_millionths, 5 * MILLION);
    let heap_bound = cert.bound_for(ResourceDimension::HeapMemory).unwrap();
    assert_eq!(heap_bound.upper_bound_millionths, 20 * MILLION);
    assert!(cert.bound_for(ResourceDimension::GcPressure).is_none());
}

// =========================================================================
// 7. Assumption surface
// =========================================================================

#[test]
fn cert_no_assumptions_no_critical() {
    let cert = mk_cert(
        "c-no-a",
        "fn:na",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:na", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:na",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    assert!(!cert.has_critical_assumptions());
}

#[test]
fn cert_only_non_critical_assumptions_not_critical() {
    let cert = mk_cert(
        "c-nc",
        "fn:nc",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:nc", vec![], vec![]),
        vec![
            mk_assumption("a1", AssumptionKind::NoEval, false),
            mk_assumption("a2", AssumptionKind::StaticDispatch, false),
        ],
        vec![],
        vec![mk_potential(
            "fn:nc",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    assert!(!cert.has_critical_assumptions());
}

#[test]
fn cert_one_critical_among_many_non_critical_is_critical() {
    let cert = mk_cert(
        "c-1c",
        "fn:1c",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:1c", vec![], vec![]),
        vec![
            mk_assumption("a1", AssumptionKind::NoEval, false),
            mk_assumption("a2", AssumptionKind::BoundedIteration, true),
            mk_assumption("a3", AssumptionKind::StablePrototypes, false),
        ],
        vec![],
        vec![mk_potential(
            "fn:1c",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    assert!(cert.has_critical_assumptions());
}

// =========================================================================
// 8. Hash determinism
// =========================================================================

#[test]
fn effect_summary_hash_deterministic_across_builds() {
    let build = || {
        EffectSummary::build(
            "det_region",
            vec![
                mk_entry(EffectKind::Allocation, "p1", 2 * MILLION, true),
                mk_entry(EffectKind::Hostcall, "p2", 3 * MILLION, false),
            ],
            vec![mk_abstention("p3", AbstentionReason::UnboundedLoop, "loop")],
        )
    };
    let s1 = build();
    let s2 = build();
    let s3 = build();
    assert_eq!(s1.content_hash, s2.content_hash);
    assert_eq!(s2.content_hash, s3.content_hash);
}

#[test]
fn potential_hash_deterministic_across_builds() {
    let build = || {
        mk_potential(
            "fn:det_pot",
            ResourceDimension::HeapMemory,
            5 * MILLION,
            &[
                ("entry", 5 * MILLION),
                ("mid", 2 * MILLION),
                ("exit", 500_000),
            ],
        )
    };
    let p1 = build();
    let p2 = build();
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn certificate_hash_deterministic_across_builds() {
    let build = || {
        mk_cert(
            "c-det",
            "fn:det",
            epoch(42),
            vec![mk_bound(
                ResourceDimension::Time,
                10 * MILLION,
                950_000,
                false,
            )],
            EffectSummary::build(
                "fn:det",
                vec![mk_entry(EffectKind::GlobalRead, "r:1", MILLION, true)],
                vec![],
            ),
            vec![mk_assumption("a1", AssumptionKind::NoEval, true)],
            vec![],
            vec![mk_potential(
                "fn:det",
                ResourceDimension::Time,
                2 * MILLION,
                &[("exit", MILLION)],
            )],
        )
    };
    let c1 = build();
    let c2 = build();
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn bundle_hash_deterministic_across_builds() {
    let build_cert = || {
        mk_cert(
            "c-b",
            "fn:b",
            epoch(1),
            vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
            EffectSummary::build("fn:b", vec![], vec![]),
            vec![],
            vec![],
            vec![mk_potential(
                "fn:b",
                ResourceDimension::Time,
                MILLION,
                &[("e", 1)],
            )],
        )
    };
    let b1 = CertificateBundle::build("bundle-det", epoch(1), vec![build_cert()]);
    let b2 = CertificateBundle::build("bundle-det", epoch(1), vec![build_cert()]);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn different_region_ids_produce_different_hashes() {
    let s1 = EffectSummary::build("region_alpha", vec![], vec![]);
    let s2 = EffectSummary::build("region_beta", vec![], vec![]);
    assert_ne!(s1.content_hash, s2.content_hash);
}

// =========================================================================
// 9. EffectSummary.is_pure() and has_dynamic_code_gen() edge cases
// =========================================================================

#[test]
fn is_pure_false_with_entries_and_no_abstentions() {
    let s = EffectSummary::build(
        "fn:notpure",
        vec![mk_entry(EffectKind::ExceptionThrow, "p1", MILLION, true)],
        vec![],
    );
    assert!(!s.is_pure());
    assert!(s.is_complete);
}

#[test]
fn is_pure_false_with_no_entries_but_abstentions() {
    let s = EffectSummary::build(
        "fn:notpure2",
        vec![],
        vec![mk_abstention("p1", AbstentionReason::ProxyTrap, "proxy")],
    );
    assert!(!s.is_pure());
    assert!(!s.is_complete);
}

#[test]
fn has_dynamic_code_gen_false_for_all_other_kinds() {
    let kinds = [
        EffectKind::Allocation,
        EffectKind::PropertyMutation,
        EffectKind::GlobalRead,
        EffectKind::GlobalWrite,
        EffectKind::Hostcall,
        EffectKind::ModuleImport,
        EffectKind::ExceptionThrow,
        EffectKind::PrototypeTraversal,
        EffectKind::ClosureCapture,
    ];
    for kind in kinds {
        let s = EffectSummary::build(
            "fn:no_dcg",
            vec![mk_entry(kind, "p1", MILLION, true)],
            vec![],
        );
        assert!(
            !s.has_dynamic_code_gen(),
            "unexpected dynamic_code_gen for {:?}",
            kind
        );
    }
}

#[test]
fn has_dynamic_code_gen_true_even_with_zero_count() {
    // kind_totals entry exists even if the count happens to be zero
    // (build sums entries, so a zero-count entry still inserts into the map)
    let s = EffectSummary::build(
        "fn:zero_dcg",
        vec![mk_entry(EffectKind::DynamicCodeGen, "p1", 0, true)],
        vec![],
    );
    assert!(s.has_dynamic_code_gen());
}

#[test]
fn forces_abstention_only_for_dynamic_code_gen() {
    let all_kinds = [
        EffectKind::Allocation,
        EffectKind::PropertyMutation,
        EffectKind::GlobalRead,
        EffectKind::GlobalWrite,
        EffectKind::Hostcall,
        EffectKind::ModuleImport,
        EffectKind::ExceptionThrow,
        EffectKind::PrototypeTraversal,
        EffectKind::ClosureCapture,
        EffectKind::DynamicCodeGen,
    ];
    for kind in all_kinds {
        if kind == EffectKind::DynamicCodeGen {
            assert!(kind.forces_abstention());
        } else {
            assert!(!kind.forces_abstention());
        }
    }
}

// =========================================================================
// 10. Serde round-trips for complex types
// =========================================================================

#[test]
fn serde_roundtrip_effect_summary_with_all_kinds() {
    let entries: Vec<EffectEntry> = [
        EffectKind::Allocation,
        EffectKind::PropertyMutation,
        EffectKind::GlobalRead,
        EffectKind::GlobalWrite,
        EffectKind::Hostcall,
        EffectKind::ModuleImport,
        EffectKind::ExceptionThrow,
        EffectKind::PrototypeTraversal,
        EffectKind::ClosureCapture,
        EffectKind::DynamicCodeGen,
    ]
    .iter()
    .enumerate()
    .map(|(i, &k)| mk_entry(k, &format!("p:{i}"), (i as i64 + 1) * MILLION, i % 2 == 0))
    .collect();
    let abs = vec![
        mk_abstention("abs:1", AbstentionReason::DynamicCodeGen, "eval"),
        mk_abstention("abs:2", AbstentionReason::UnboundedLoop, "while(1)"),
    ];
    let s = EffectSummary::build("fn:all_kinds", entries, abs);
    let json = serde_json::to_string(&s).unwrap();
    let back: EffectSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn serde_roundtrip_symbolic_potential_many_points() {
    let pts: Vec<(&str, i64)> = vec![
        ("a", 100 * MILLION),
        ("b", 50 * MILLION),
        ("c", 0),
        ("d", -MILLION),
        ("e", 200 * MILLION),
    ];
    let pot = mk_potential(
        "fn:many_pts",
        ResourceDimension::GcPressure,
        200 * MILLION,
        &pts,
    );
    let json = serde_json::to_string(&pot).unwrap();
    let back: SymbolicPotential = serde_json::from_str(&json).unwrap();
    assert_eq!(pot, back);
}

#[test]
fn serde_roundtrip_certificate_with_all_fields() {
    let cert = mk_cert(
        "c-serde-full",
        "fn:serde_full",
        epoch(99),
        vec![
            mk_bound(ResourceDimension::Time, 10 * MILLION, 980_000, true),
            mk_bound(ResourceDimension::HeapMemory, 50 * MILLION, 950_000, false),
        ],
        EffectSummary::build(
            "fn:serde_full",
            vec![
                mk_entry(EffectKind::Allocation, "p1", 3 * MILLION, true),
                mk_entry(EffectKind::Hostcall, "p2", 2 * MILLION, false),
            ],
            vec![mk_abstention(
                "p3",
                AbstentionReason::PrototypeMutation,
                "mutated",
            )],
        ),
        vec![
            mk_assumption("a1", AssumptionKind::NoEval, true),
            mk_assumption("a2", AssumptionKind::BoundedIteration, false),
        ],
        vec![mk_abstention(
            "p4",
            AbstentionReason::UnknownHostcall,
            "unknown hc",
        )],
        vec![mk_potential(
            "fn:serde_full",
            ResourceDimension::Time,
            5 * MILLION,
            &[("exit", MILLION)],
        )],
    );
    let json = serde_json::to_string(&cert).unwrap();
    let back: ResourceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn serde_roundtrip_certificate_bundle_with_mixed() {
    let certified = mk_cert(
        "sc1",
        "fn:sc1",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:sc1", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:sc1",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    let abstained = mk_cert(
        "sc2",
        "fn:sc2",
        epoch(1),
        vec![],
        EffectSummary::build("fn:sc2", vec![], vec![]),
        vec![],
        vec![mk_abstention(
            "fn:sc2:1",
            AbstentionReason::WithStatement,
            "with",
        )],
        vec![],
    );
    let bundle = CertificateBundle::build("serde-bundle", epoch(1), vec![certified, abstained]);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: CertificateBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn serde_roundtrip_all_assumption_kinds() {
    let kinds = [
        AssumptionKind::BoundedIteration,
        AssumptionKind::NoEval,
        AssumptionKind::StaticDispatch,
        AssumptionKind::StablePrototypes,
        AssumptionKind::HostcallBoundsDeclared,
        AssumptionKind::NoWithStatement,
        AssumptionKind::NoProxyTraps,
        AssumptionKind::BoundedStackDepth,
        AssumptionKind::BoundedInputSize,
    ];
    for kind in kinds {
        let a = mk_assumption("k", kind, true);
        let json = serde_json::to_string(&a).unwrap();
        let back: CertificateAssumption = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

#[test]
fn serde_roundtrip_all_abstention_reasons() {
    let reasons = [
        AbstentionReason::DynamicDispatch,
        AbstentionReason::DynamicCodeGen,
        AbstentionReason::UnboundedLoop,
        AbstentionReason::UnboundedRecursion,
        AbstentionReason::UnknownHostcall,
        AbstentionReason::PrototypeMutation,
        AbstentionReason::WithStatement,
        AbstentionReason::ProxyTrap,
        AbstentionReason::BudgetExhausted,
    ];
    for reason in reasons {
        let abs = mk_abstention("pt", reason, "detail");
        let json = serde_json::to_string(&abs).unwrap();
        let back: AbstentionPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(abs, back);
    }
}

// =========================================================================
// 11. Large-scale stress
// =========================================================================

#[test]
fn stress_many_effect_entries() {
    let entries: Vec<EffectEntry> = (0..500)
        .map(|i| {
            mk_entry(
                EffectKind::Allocation,
                &format!("p:{i}"),
                MILLION,
                i % 3 == 0,
            )
        })
        .collect();
    let s = EffectSummary::build("fn:stress_entries", entries, vec![]);
    assert_eq!(s.entries.len(), 500);
    assert_eq!(s.total_effect_count(), 500 * MILLION);
    assert!(s.is_complete);
}

#[test]
fn stress_many_abstention_points() {
    let abs: Vec<AbstentionPoint> = (0..200)
        .map(|i| {
            mk_abstention(
                &format!("abs:{i}"),
                AbstentionReason::BudgetExhausted,
                "budget",
            )
        })
        .collect();
    let s = EffectSummary::build("fn:stress_abs", vec![], abs);
    assert!(!s.is_complete);
    // build does not truncate; only compose does
    assert_eq!(s.abstention_points.len(), 200);
}

#[test]
fn stress_many_potential_points() {
    let mut map = BTreeMap::new();
    for i in 0..1000 {
        map.insert(format!("pt:{i:04}"), (1000 - i) * 1000);
    }
    let pot = SymbolicPotential::new("fn:stress_pot", ResourceDimension::Time, MILLION, map);
    assert_eq!(pot.point_count(), 1000);
    assert!(pot.is_valid);
    assert_eq!(pot.min_potential_millionths, 1000); // last point: (1000 - 999) * 1000
}

#[test]
fn stress_many_assumptions() {
    let assumptions: Vec<CertificateAssumption> = (0..MAX_ASSUMPTIONS_PER_CERTIFICATE)
        .map(|i| {
            mk_assumption(
                &format!("a:{i}"),
                AssumptionKind::BoundedIteration,
                i % 2 == 0,
            )
        })
        .collect();
    let cert = mk_cert(
        "c-stress-a",
        "fn:stress_a",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:stress_a", vec![], vec![]),
        assumptions.clone(),
        vec![],
        vec![mk_potential(
            "fn:stress_a",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    assert_eq!(cert.assumptions.len(), MAX_ASSUMPTIONS_PER_CERTIFICATE);
    assert!(cert.has_critical_assumptions());
}

#[test]
fn stress_large_bundle() {
    let certs: Vec<ResourceCertificate> = (0..50)
        .map(|i| {
            mk_cert(
                &format!("c-{i}"),
                &format!("fn:b{i}"),
                epoch(1),
                vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
                EffectSummary::build(&format!("fn:b{i}"), vec![], vec![]),
                vec![],
                vec![],
                vec![mk_potential(
                    &format!("fn:b{i}"),
                    ResourceDimension::Time,
                    MILLION,
                    &[("e", 1)],
                )],
            )
        })
        .collect();
    let bundle = CertificateBundle::build("stress-bundle", epoch(1), certs);
    assert_eq!(bundle.total_count(), 50);
    assert_eq!(bundle.certified_count, 50);
    assert_eq!(bundle.certification_rate_millionths(), MILLION);
    assert!(bundle.passes(MILLION));
}

// =========================================================================
// 12. Certificate deduplication of effect summary abstentions
// =========================================================================

#[test]
fn cert_deduplicates_summary_abstentions_with_input_abstentions() {
    let abs = mk_abstention("fn:x:10", AbstentionReason::DynamicCodeGen, "eval");
    let summary = EffectSummary::build("fn:x", vec![], vec![abs.clone()]);
    // Pass the same abstention as both summary and input
    let cert = mk_cert(
        "c-dedup",
        "fn:x",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        summary,
        vec![],
        vec![abs.clone()],
        vec![],
    );
    // Should not duplicate
    assert_eq!(
        cert.abstention_points.iter().filter(|a| **a == abs).count(),
        1
    );
}

#[test]
fn cert_merges_distinct_summary_and_input_abstentions() {
    let abs1 = mk_abstention("fn:y:5", AbstentionReason::UnboundedLoop, "loop");
    let abs2 = mk_abstention("fn:y:10", AbstentionReason::DynamicCodeGen, "eval");
    let summary = EffectSummary::build("fn:y", vec![], vec![abs1.clone()]);
    let cert = mk_cert(
        "c-merge",
        "fn:y",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        summary,
        vec![],
        vec![abs2.clone()],
        vec![],
    );
    assert_eq!(cert.abstention_points.len(), 2);
    assert!(cert.abstention_points.contains(&abs1));
    assert!(cert.abstention_points.contains(&abs2));
}

// =========================================================================
// 13. Constants validation
// =========================================================================

#[test]
fn component_name_matches() {
    assert_eq!(COMPONENT, "aara_resource_certificate");
}

#[test]
fn bead_id_has_expected_prefix() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn max_abstention_points_is_128() {
    assert_eq!(MAX_ABSTENTION_POINTS_PER_REGION, 128);
}

#[test]
fn max_assumptions_is_64() {
    assert_eq!(MAX_ASSUMPTIONS_PER_CERTIFICATE, 64);
}

#[test]
fn min_confidence_is_90_percent() {
    assert_eq!(MIN_CERTIFICATE_CONFIDENCE, 900_000);
}

// =========================================================================
// 14. Display coverage
// =========================================================================

#[test]
fn resource_dimension_display_all_seven() {
    let expected = [
        (ResourceDimension::Time, "time"),
        (ResourceDimension::HeapMemory, "heap_memory"),
        (ResourceDimension::StackDepth, "stack_depth"),
        (ResourceDimension::HostcallCount, "hostcall_count"),
        (ResourceDimension::GcPressure, "gc_pressure"),
        (ResourceDimension::ModuleLoadCount, "module_load_count"),
        (ResourceDimension::IoOperationCount, "io_operation_count"),
    ];
    for (dim, text) in expected {
        assert_eq!(format!("{dim}"), text);
    }
}

#[test]
fn effect_kind_display_all_ten() {
    let expected = [
        (EffectKind::Allocation, "allocation"),
        (EffectKind::PropertyMutation, "property_mutation"),
        (EffectKind::GlobalRead, "global_read"),
        (EffectKind::GlobalWrite, "global_write"),
        (EffectKind::Hostcall, "hostcall"),
        (EffectKind::ModuleImport, "module_import"),
        (EffectKind::ExceptionThrow, "exception_throw"),
        (EffectKind::PrototypeTraversal, "prototype_traversal"),
        (EffectKind::ClosureCapture, "closure_capture"),
        (EffectKind::DynamicCodeGen, "dynamic_code_gen"),
    ];
    for (kind, text) in expected {
        assert_eq!(format!("{kind}"), text);
    }
}

#[test]
fn abstention_reason_display_all_nine() {
    let expected = [
        (AbstentionReason::DynamicDispatch, "dynamic_dispatch"),
        (AbstentionReason::DynamicCodeGen, "dynamic_code_gen"),
        (AbstentionReason::UnboundedLoop, "unbounded_loop"),
        (AbstentionReason::UnboundedRecursion, "unbounded_recursion"),
        (AbstentionReason::UnknownHostcall, "unknown_hostcall"),
        (AbstentionReason::PrototypeMutation, "prototype_mutation"),
        (AbstentionReason::WithStatement, "with_statement"),
        (AbstentionReason::ProxyTrap, "proxy_trap"),
        (AbstentionReason::BudgetExhausted, "budget_exhausted"),
    ];
    for (reason, text) in expected {
        assert_eq!(format!("{reason}"), text);
    }
}

#[test]
fn assumption_kind_display_all_nine() {
    let expected = [
        (AssumptionKind::BoundedIteration, "bounded_iteration"),
        (AssumptionKind::NoEval, "no_eval"),
        (AssumptionKind::StaticDispatch, "static_dispatch"),
        (AssumptionKind::StablePrototypes, "stable_prototypes"),
        (
            AssumptionKind::HostcallBoundsDeclared,
            "hostcall_bounds_declared",
        ),
        (AssumptionKind::NoWithStatement, "no_with_statement"),
        (AssumptionKind::NoProxyTraps, "no_proxy_traps"),
        (AssumptionKind::BoundedStackDepth, "bounded_stack_depth"),
        (AssumptionKind::BoundedInputSize, "bounded_input_size"),
    ];
    for (kind, text) in expected {
        assert_eq!(format!("{kind}"), text);
    }
}

#[test]
fn certificate_verdict_display_all_four() {
    let expected = [
        (CertificateVerdict::Certified, "certified"),
        (CertificateVerdict::Provisional, "provisional"),
        (CertificateVerdict::Abstained, "abstained"),
        (CertificateVerdict::Violated, "violated"),
    ];
    for (v, text) in expected {
        assert_eq!(format!("{v}"), text);
    }
}

// =========================================================================
// 15. Chained composition
// =========================================================================

#[test]
fn three_way_effect_summary_composition() {
    let s1 = EffectSummary::build(
        "a",
        vec![mk_entry(EffectKind::Allocation, "a:1", MILLION, true)],
        vec![],
    );
    let s2 = EffectSummary::build(
        "b",
        vec![mk_entry(EffectKind::Hostcall, "b:1", 2 * MILLION, true)],
        vec![],
    );
    let s3 = EffectSummary::build(
        "c",
        vec![mk_entry(EffectKind::GlobalWrite, "c:1", 3 * MILLION, true)],
        vec![mk_abstention(
            "c:2",
            AbstentionReason::WithStatement,
            "with",
        )],
    );
    let composed = s1.compose(&s2).compose(&s3);
    assert_eq!(composed.entries.len(), 3);
    assert_eq!(composed.total_effect_count(), 6 * MILLION);
    assert!(!composed.is_complete);
    assert_eq!(composed.region_id, "a+b+c");
}

#[test]
fn resource_bound_chained_composition() {
    let b1 = mk_bound(ResourceDimension::HeapMemory, 5 * MILLION, MILLION, true);
    let b2 = mk_bound(ResourceDimension::HeapMemory, 3 * MILLION, 950_000, true);
    let b3 = mk_bound(ResourceDimension::HeapMemory, 2 * MILLION, 800_000, false);
    let composed = b1.compose(&b2).unwrap().compose(&b3).unwrap();
    assert_eq!(composed.upper_bound_millionths, 10 * MILLION);
    assert_eq!(composed.confidence_millionths, 800_000);
    assert!(!composed.is_tight); // b3 is not tight
}

// =========================================================================
// 16. Verdict priority (violated > abstained > provisional > certified)
// =========================================================================

#[test]
fn violated_takes_priority_over_abstentions() {
    // Both invalid potential AND abstention points
    let cert = mk_cert(
        "c-prio1",
        "fn:prio1",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:prio1", vec![], vec![]),
        vec![],
        vec![mk_abstention("p1", AbstentionReason::UnboundedLoop, "loop")],
        vec![mk_potential(
            "fn:prio1",
            ResourceDimension::Time,
            MILLION,
            &[("bad", -1)],
        )],
    );
    // Invalid potential causes Violated, even though abstention points exist
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
}

#[test]
fn violated_takes_priority_over_negative_bound() {
    let cert = mk_cert(
        "c-prio2",
        "fn:prio2",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, -MILLION, MILLION, true)],
        EffectSummary::build("fn:prio2", vec![], vec![]),
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
}

// =========================================================================
// 17. Schema version propagation
// =========================================================================

#[test]
fn effect_summary_schema_version_set() {
    let s = EffectSummary::build("fn:sv", vec![], vec![]);
    assert_eq!(s.schema_version, EFFECT_SUMMARY_SCHEMA_VERSION);
}

#[test]
fn symbolic_potential_schema_version_set() {
    let p = mk_potential("fn:sv", ResourceDimension::Time, MILLION, &[]);
    assert_eq!(p.schema_version, POTENTIAL_SCHEMA_VERSION);
}

#[test]
fn certificate_schema_version_set() {
    let c = mk_cert(
        "c-sv",
        "fn:sv",
        epoch(1),
        vec![mk_bound(ResourceDimension::Time, MILLION, MILLION, true)],
        EffectSummary::build("fn:sv", vec![], vec![]),
        vec![],
        vec![],
        vec![mk_potential(
            "fn:sv",
            ResourceDimension::Time,
            MILLION,
            &[("e", 1)],
        )],
    );
    assert_eq!(c.schema_version, CERTIFICATE_SCHEMA_VERSION);
}

#[test]
fn bundle_schema_version_set() {
    let b = CertificateBundle::build("b-sv", epoch(1), vec![]);
    assert_eq!(b.schema_version, BUNDLE_SCHEMA_VERSION);
}

// =========================================================================
// 18. End-to-end multi-region pipeline
// =========================================================================

#[test]
fn end_to_end_multi_region_certification_pipeline() {
    // Region 1: Pure compute -- certified
    let compute_effects = EffectSummary::build("compute", vec![], vec![]);
    let compute_pot = mk_potential(
        "compute",
        ResourceDimension::Time,
        5 * MILLION,
        &[
            ("loop_head", 4 * MILLION),
            ("loop_body", 2 * MILLION),
            ("exit", MILLION),
        ],
    );
    let compute_cert = mk_cert(
        "cert-compute",
        "compute",
        epoch(7),
        vec![mk_bound(
            ResourceDimension::Time,
            4 * MILLION,
            MILLION,
            true,
        )],
        compute_effects,
        vec![mk_assumption(
            "bounded_iter",
            AssumptionKind::BoundedIteration,
            true,
        )],
        vec![],
        vec![compute_pot],
    );
    assert_eq!(compute_cert.verdict, CertificateVerdict::Certified);

    // Region 2: IO-heavy -- certified with lower confidence
    let io_entries = vec![
        mk_entry(EffectKind::Hostcall, "io:read", 10 * MILLION, false),
        mk_entry(EffectKind::Hostcall, "io:write", 5 * MILLION, false),
        mk_entry(EffectKind::Allocation, "io:buf", 2 * MILLION, true),
    ];
    let io_effects = EffectSummary::build("io_handler", io_entries, vec![]);
    let io_pot = mk_potential(
        "io_handler",
        ResourceDimension::IoOperationCount,
        20 * MILLION,
        &[
            ("read", 10 * MILLION),
            ("write", 5 * MILLION),
            ("done", MILLION),
        ],
    );
    let io_cert = mk_cert(
        "cert-io",
        "io_handler",
        epoch(7),
        vec![
            mk_bound(
                ResourceDimension::IoOperationCount,
                15 * MILLION,
                950_000,
                false,
            ),
            mk_bound(ResourceDimension::HeapMemory, 2 * MILLION, MILLION, true),
        ],
        io_effects,
        vec![
            mk_assumption("hc_bounds", AssumptionKind::HostcallBoundsDeclared, true),
            mk_assumption("bounded_input", AssumptionKind::BoundedInputSize, false),
        ],
        vec![],
        vec![io_pot],
    );
    assert_eq!(io_cert.verdict, CertificateVerdict::Certified);
    assert_eq!(io_cert.certified_dimension_count(), 2);

    // Region 3: Has eval -- abstained
    let eval_effects = EffectSummary::build(
        "config_loader",
        vec![mk_entry(
            EffectKind::DynamicCodeGen,
            "eval:1",
            MILLION,
            true,
        )],
        vec![mk_abstention(
            "eval:1",
            AbstentionReason::DynamicCodeGen,
            "eval() in config",
        )],
    );
    let eval_cert = mk_cert(
        "cert-config",
        "config_loader",
        epoch(7),
        vec![],
        eval_effects,
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(eval_cert.verdict, CertificateVerdict::Abstained);

    // Bundle all three
    let bundle = CertificateBundle::build(
        "module-bundle",
        epoch(7),
        vec![compute_cert, io_cert, eval_cert],
    );
    assert_eq!(bundle.total_count(), 3);
    assert_eq!(bundle.certified_count, 2);
    assert_eq!(bundle.abstained_count, 1);
    assert_eq!(bundle.violated_count, 0);
    // 2 out of 3 certified = 666_666
    let rate = bundle.certification_rate_millionths();
    assert!(rate > 600_000 && rate < 700_000);
    assert!(!bundle.passes(900_000));
    assert!(bundle.passes(600_000));

    // Serde round-trip the whole bundle
    let json = serde_json::to_string(&bundle).unwrap();
    let back: CertificateBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// =========================================================================
// 19. ResourceDimension ordering stability
// =========================================================================

#[test]
fn resource_dimension_ordering_is_stable() {
    let mut dims: Vec<ResourceDimension> = vec![
        ResourceDimension::IoOperationCount,
        ResourceDimension::Time,
        ResourceDimension::GcPressure,
        ResourceDimension::HeapMemory,
        ResourceDimension::ModuleLoadCount,
        ResourceDimension::StackDepth,
        ResourceDimension::HostcallCount,
    ];
    dims.sort();
    assert_eq!(dims, ResourceDimension::ALL);
}

#[test]
fn resource_dimension_in_btreeset_preserves_order() {
    let set: BTreeSet<ResourceDimension> = ResourceDimension::ALL.iter().copied().collect();
    let ordered: Vec<ResourceDimension> = set.into_iter().collect();
    assert_eq!(ordered.as_slice(), ResourceDimension::ALL);
}
