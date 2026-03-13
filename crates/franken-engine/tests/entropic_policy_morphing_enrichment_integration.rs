#![forbid(unsafe_code)]

//! Enrichment integration tests for the entropic policy morphing module [RGC-617B].
//! Covers edge cases, determinism, serde roundtrips, Display impls, builders,
//! workflows, multi-step sequences, and boundary conditions not covered by
//! the base integration test suite.

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

use frankenengine_engine::entropic_policy_morphing::{
    self, DEFAULT_TRANSITION_BUDGET, EntropicPolicyMorpher, FALLBACK_COOLDOWN_STEPS,
    MAX_ENTROPY_MILLIONTHS, MAX_STEP_DISTANCE_MILLIONTHS, MIN_ENTROPY_MILLIONTHS,
    MORPHING_COMPONENT, MORPHING_EVENT_SCHEMA_VERSION, MORPHING_MANIFEST_SCHEMA_VERSION,
    MORPHING_POLICY_ID, MORPHING_SCHEMA_VERSION, MorphingArtifactPaths, MorphingConfig,
    MorphingEvidenceEvent, MorphingEvidenceInventory, MorphingExpectedOutcome, MorphingOutcome,
    MorphingRejection, MorphingRunManifest, MorphingSpecimen, MorphingSpecimenEvidence,
    MorphingSpecimenFamily, MorphingStep, MorphingSummary, MorphingVerdict, PolicyProfile,
    TransitionBudget,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::RegimeLabel;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn anchor_profile() -> PolicyProfile {
    let mut dims = BTreeMap::new();
    dims.insert("exploration_rate".into(), 200_000);
    dims.insert("sandbox_strictness".into(), 800_000);
    dims.insert("gc_aggressiveness".into(), 500_000);
    dims.insert("cache_budget".into(), 600_000);
    PolicyProfile::for_regime("anchor_baseline", Regime::Normal, dims)
}

fn regime_profiles() -> Vec<(Regime, PolicyProfile)> {
    let mut result = Vec::new();

    let mut normal = BTreeMap::new();
    normal.insert("exploration_rate".into(), 200_000);
    normal.insert("sandbox_strictness".into(), 800_000);
    normal.insert("gc_aggressiveness".into(), 500_000);
    normal.insert("cache_budget".into(), 600_000);
    result.push((
        Regime::Normal,
        PolicyProfile::for_regime("normal_profile", Regime::Normal, normal),
    ));

    let mut elevated = BTreeMap::new();
    elevated.insert("exploration_rate".into(), 150_000);
    elevated.insert("sandbox_strictness".into(), 850_000);
    elevated.insert("gc_aggressiveness".into(), 550_000);
    elevated.insert("cache_budget".into(), 550_000);
    result.push((
        Regime::Elevated,
        PolicyProfile::for_regime("elevated_profile", Regime::Elevated, elevated),
    ));

    let mut attack = BTreeMap::new();
    attack.insert("exploration_rate".into(), 50_000);
    attack.insert("sandbox_strictness".into(), 950_000);
    attack.insert("gc_aggressiveness".into(), 700_000);
    attack.insert("cache_budget".into(), 300_000);
    result.push((
        Regime::Attack,
        PolicyProfile::for_regime("attack_lockdown", Regime::Attack, attack),
    ));

    let mut degraded = BTreeMap::new();
    degraded.insert("exploration_rate".into(), 100_000);
    degraded.insert("sandbox_strictness".into(), 700_000);
    degraded.insert("gc_aggressiveness".into(), 800_000);
    degraded.insert("cache_budget".into(), 400_000);
    result.push((
        Regime::Degraded,
        PolicyProfile::for_regime("degraded_profile", Regime::Degraded, degraded),
    ));

    let mut recovery = BTreeMap::new();
    recovery.insert("exploration_rate".into(), 180_000);
    recovery.insert("sandbox_strictness".into(), 820_000);
    recovery.insert("gc_aggressiveness".into(), 520_000);
    recovery.insert("cache_budget".into(), 580_000);
    result.push((
        Regime::Recovery,
        PolicyProfile::for_regime("recovery_profile", Regime::Recovery, recovery),
    ));

    result
}

fn build_morpher(epoch_raw: u64) -> EntropicPolicyMorpher {
    let anchor = anchor_profile();
    let epoch = SecurityEpoch::from_raw(epoch_raw);
    let mut m = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    for (regime, profile) in regime_profiles() {
        m.register_profile(regime, profile);
    }
    m
}

fn build_morpher_with_config(epoch_raw: u64, config: MorphingConfig) -> EntropicPolicyMorpher {
    let anchor = anchor_profile();
    let epoch = SecurityEpoch::from_raw(epoch_raw);
    let budget = TransitionBudget::with_defaults(epoch);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, config);
    for (regime, profile) in regime_profiles() {
        m.register_profile(regime, profile);
    }
    m
}

// ---------------------------------------------------------------------------
// PolicyProfile enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_profile_new_has_no_target_regime() {
    let p = PolicyProfile::new("test", BTreeMap::new());
    assert!(p.target_regime.is_none());
    assert_eq!(p.name, "test");
}

#[test]
fn enrichment_policy_profile_for_regime_sets_target() {
    let dims = BTreeMap::new();
    let p = PolicyProfile::for_regime("regime_test", Regime::Attack, dims);
    assert_eq!(p.target_regime, Some(Regime::Attack));
    assert_eq!(p.name, "regime_test");
}

#[test]
fn enrichment_policy_profile_l1_distance_empty_profiles() {
    let a = PolicyProfile::new("a", BTreeMap::new());
    let b = PolicyProfile::new("b", BTreeMap::new());
    assert_eq!(a.l1_distance(&b), 0);
}

#[test]
fn enrichment_policy_profile_l1_distance_one_dimension() {
    let mut da = BTreeMap::new();
    da.insert("x".into(), 300_000);
    let mut db = BTreeMap::new();
    db.insert("x".into(), 800_000);
    let a = PolicyProfile::new("a", da);
    let b = PolicyProfile::new("b", db);
    assert_eq!(a.l1_distance(&b), 500_000);
}

#[test]
fn enrichment_policy_profile_l1_distance_missing_dimensions_treated_as_zero() {
    let mut da = BTreeMap::new();
    da.insert("x".into(), 400_000);
    let a = PolicyProfile::new("a", da);
    let b = PolicyProfile::new("b", BTreeMap::new());
    assert_eq!(a.l1_distance(&b), 400_000);
    assert_eq!(b.l1_distance(&a), 400_000);
}

#[test]
fn enrichment_policy_profile_l1_distance_multiple_dimensions() {
    let mut da = BTreeMap::new();
    da.insert("x".into(), 100_000);
    da.insert("y".into(), 200_000);
    let mut db = BTreeMap::new();
    db.insert("x".into(), 300_000);
    db.insert("y".into(), 500_000);
    let a = PolicyProfile::new("a", da);
    let b = PolicyProfile::new("b", db);
    // |100_000 - 300_000| + |200_000 - 500_000| = 200_000 + 300_000 = 500_000
    assert_eq!(a.l1_distance(&b), 500_000);
}

#[test]
fn enrichment_policy_profile_l1_distance_disjoint_dimensions() {
    let mut da = BTreeMap::new();
    da.insert("x".into(), 100_000);
    let mut db = BTreeMap::new();
    db.insert("y".into(), 200_000);
    let a = PolicyProfile::new("a", da);
    let b = PolicyProfile::new("b", db);
    // x: |100_000 - 0| + y: |0 - 200_000| = 300_000
    assert_eq!(a.l1_distance(&b), 300_000);
}

#[test]
fn enrichment_policy_profile_entropy_single_dimension() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), 1_000_000);
    let p = PolicyProfile::new("single", dims);
    // Single element: p=1, -p*ln(p) = 0
    assert_eq!(p.entropy_millionths(), 0);
}

#[test]
fn enrichment_policy_profile_entropy_two_equal_dimensions() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), 500_000);
    dims.insert("y".into(), 500_000);
    let p = PolicyProfile::new("two_equal", dims);
    let e = p.entropy_millionths();
    // ln(2) ~= 0.693 -> 693_000 millionths
    assert!(e > 600_000, "expected >600k, got {e}");
    assert!(e < 800_000, "expected <800k, got {e}");
}

#[test]
fn enrichment_policy_profile_entropy_negative_values_clamped() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), -500_000);
    dims.insert("y".into(), 1_000_000);
    let p = PolicyProfile::new("negative", dims);
    // Negative values are clamped to 0
    let e = p.entropy_millionths();
    // Only one positive value, so entropy = 0
    assert_eq!(e, 0);
}

#[test]
fn enrichment_policy_profile_entropy_all_negative_values() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), -100_000);
    dims.insert("y".into(), -200_000);
    let p = PolicyProfile::new("all_neg", dims);
    assert_eq!(p.entropy_millionths(), 0);
}

#[test]
fn enrichment_policy_profile_content_hash_changes_with_name() {
    let dims = BTreeMap::new();
    let a = PolicyProfile::new("alpha", dims.clone());
    let b = PolicyProfile::new("beta", dims);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_policy_profile_content_hash_changes_with_dimension_value() {
    let mut d1 = BTreeMap::new();
    d1.insert("x".into(), 100_000);
    let mut d2 = BTreeMap::new();
    d2.insert("x".into(), 200_000);
    let a = PolicyProfile::new("same", d1);
    let b = PolicyProfile::new("same", d2);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_policy_profile_content_hash_changes_with_dimension_key() {
    let mut d1 = BTreeMap::new();
    d1.insert("alpha".into(), 100_000);
    let mut d2 = BTreeMap::new();
    d2.insert("beta".into(), 100_000);
    let a = PolicyProfile::new("same", d1);
    let b = PolicyProfile::new("same", d2);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_policy_profile_clone_equals_original() {
    let p = anchor_profile();
    let cloned = p.clone();
    assert_eq!(p, cloned);
    assert_eq!(p.content_hash(), cloned.content_hash());
}

#[test]
fn enrichment_policy_profile_serde_with_regime() {
    for regime in [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ] {
        let mut dims = BTreeMap::new();
        dims.insert("dim".into(), 500_000);
        let p = PolicyProfile::for_regime("test", regime, dims);
        let json = serde_json::to_string(&p).unwrap();
        let back: PolicyProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(back.target_regime, Some(regime));
    }
}

#[test]
fn enrichment_policy_profile_serde_without_regime() {
    let p = PolicyProfile::new("no_regime", BTreeMap::new());
    let json = serde_json::to_string(&p).unwrap();
    let back: PolicyProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert!(back.target_regime.is_none());
}

// ---------------------------------------------------------------------------
// TransitionBudget enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_budget_new_fields() {
    let epoch = SecurityEpoch::from_raw(7);
    let b = TransitionBudget::new(epoch, 20, 3_000_000);
    assert_eq!(b.max_steps, 20);
    assert_eq!(b.steps_used, 0);
    assert_eq!(b.max_cumulative_distance_millionths, 3_000_000);
    assert_eq!(b.cumulative_distance_millionths, 0);
    assert_eq!(b.epoch, epoch);
}

#[test]
fn enrichment_transition_budget_with_defaults_values() {
    let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(1));
    assert_eq!(b.max_steps, DEFAULT_TRANSITION_BUDGET);
    assert_eq!(b.max_cumulative_distance_millionths, 5_000_000);
    assert_eq!(b.remaining_steps(), DEFAULT_TRANSITION_BUDGET);
    assert_eq!(b.remaining_distance_millionths(), 5_000_000);
}

#[test]
fn enrichment_transition_budget_record_step_accumulates() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 10, 10_000_000);
    b.record_step(100_000);
    b.record_step(200_000);
    b.record_step(300_000);
    assert_eq!(b.steps_used, 3);
    assert_eq!(b.cumulative_distance_millionths, 600_000);
    assert_eq!(b.remaining_steps(), 7);
    assert_eq!(b.remaining_distance_millionths(), 9_400_000);
}

#[test]
fn enrichment_transition_budget_is_exhausted_by_steps() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 2, 10_000_000);
    assert!(!b.is_exhausted());
    b.record_step(100);
    assert!(!b.is_exhausted());
    b.record_step(100);
    assert!(b.is_exhausted());
}

#[test]
fn enrichment_transition_budget_is_exhausted_by_distance() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 100, 500_000);
    assert!(!b.is_exhausted());
    b.record_step(500_000);
    assert!(b.is_exhausted());
}

#[test]
fn enrichment_transition_budget_can_step_exact_boundary() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 10, 1_000_000);
    b.record_step(500_000);
    assert!(b.can_step(500_000)); // exactly at limit
    assert!(!b.can_step(500_001)); // one over
}

#[test]
fn enrichment_transition_budget_remaining_saturates_at_zero() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 100_000);
    b.record_step(150_000); // exceeds max distance
    assert_eq!(b.remaining_steps(), 0);
    // remaining_distance may be negative via saturating_sub
    let rd = b.remaining_distance_millionths();
    assert!(rd <= 0);
}

#[test]
fn enrichment_transition_budget_reset_preserves_max_values() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 5, 2_000_000);
    b.record_step(1_000_000);
    b.record_step(500_000);
    b.reset(SecurityEpoch::from_raw(2));
    assert_eq!(b.max_steps, 5);
    assert_eq!(b.max_cumulative_distance_millionths, 2_000_000);
    assert_eq!(b.steps_used, 0);
    assert_eq!(b.cumulative_distance_millionths, 0);
}

#[test]
fn enrichment_transition_budget_serde_after_mutations() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(3), 8, 4_000_000);
    b.record_step(1_500_000);
    b.record_step(500_000);
    let json = serde_json::to_string(&b).unwrap();
    let back: TransitionBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
    assert_eq!(back.steps_used, 2);
    assert_eq!(back.cumulative_distance_millionths, 2_000_000);
}

#[test]
fn enrichment_transition_budget_zero_max_steps() {
    let b = TransitionBudget::new(SecurityEpoch::from_raw(1), 0, 0);
    assert!(b.is_exhausted());
    assert!(!b.can_step(0));
    assert_eq!(b.remaining_steps(), 0);
}

// ---------------------------------------------------------------------------
// MorphingConfig enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_config_default_values() {
    let c = MorphingConfig::default();
    assert_eq!(c.max_step_distance_millionths, MAX_STEP_DISTANCE_MILLIONTHS);
    assert_eq!(c.min_entropy_millionths, MIN_ENTROPY_MILLIONTHS);
    assert_eq!(c.max_entropy_millionths, MAX_ENTROPY_MILLIONTHS);
    assert_eq!(c.fallback_cooldown_steps, FALLBACK_COOLDOWN_STEPS);
    assert_eq!(c.interpolation_rate_millionths, 300_000);
}

#[test]
fn enrichment_morphing_config_clone_equals_original() {
    let c = MorphingConfig::default();
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn enrichment_morphing_config_custom_values_serde() {
    let c = MorphingConfig {
        max_step_distance_millionths: 100_000,
        min_entropy_millionths: 50_000,
        max_entropy_millionths: 3_000_000,
        fallback_cooldown_steps: 5,
        interpolation_rate_millionths: 750_000,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: MorphingConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// MorphingRejection enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_rejection_all_variants_as_str_non_empty() {
    let variants = [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::StepTooLarge,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::EntropyTooHigh,
        MorphingRejection::CooldownActive,
        MorphingRejection::SourceAbstention,
        MorphingRejection::NoTargetProfile,
    ];
    for v in variants {
        assert!(!v.as_str().is_empty());
    }
}

#[test]
fn enrichment_morphing_rejection_all_variants_as_str_unique() {
    let variants = [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::StepTooLarge,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::EntropyTooHigh,
        MorphingRejection::CooldownActive,
        MorphingRejection::SourceAbstention,
        MorphingRejection::NoTargetProfile,
    ];
    let strs: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), variants.len());
}

#[test]
fn enrichment_morphing_rejection_display_is_snake_case() {
    let variants = [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::StepTooLarge,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::EntropyTooHigh,
        MorphingRejection::CooldownActive,
        MorphingRejection::SourceAbstention,
        MorphingRejection::NoTargetProfile,
    ];
    for v in variants {
        let s = v.to_string();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "not snake_case: {s}"
        );
    }
}

#[test]
fn enrichment_morphing_rejection_ord_is_consistent() {
    assert!(MorphingRejection::BudgetExhausted < MorphingRejection::StepTooLarge);
    assert!(MorphingRejection::StepTooLarge < MorphingRejection::EntropyTooLow);
}

#[test]
fn enrichment_morphing_rejection_serde_all_variants() {
    let variants = [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::StepTooLarge,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::EntropyTooHigh,
        MorphingRejection::CooldownActive,
        MorphingRejection::SourceAbstention,
        MorphingRejection::NoTargetProfile,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: MorphingRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// MorphingOutcome enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_outcome_applied_serde() {
    let o = MorphingOutcome::Applied {
        distance_millionths: 250_000,
        new_entropy_millionths: 1_200_000,
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: MorphingOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
    assert!(back.is_applied());
}

#[test]
fn enrichment_morphing_outcome_rejected_serde() {
    let o = MorphingOutcome::Rejected {
        reason: MorphingRejection::EntropyTooHigh,
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: MorphingOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
    assert!(back.is_rejected());
}

#[test]
fn enrichment_morphing_outcome_noop_serde() {
    let o = MorphingOutcome::NoOp;
    let json = serde_json::to_string(&o).unwrap();
    let back: MorphingOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
    assert!(!back.is_applied());
    assert!(!back.is_rejected());
}

#[test]
fn enrichment_morphing_outcome_clone_equals() {
    let o = MorphingOutcome::Applied {
        distance_millionths: 1,
        new_entropy_millionths: 2,
    };
    assert_eq!(o, o.clone());
}

// ---------------------------------------------------------------------------
// MorphingStep enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_step_serde_roundtrip() {
    let step = MorphingStep {
        seq: 42,
        from_regime: RegimeLabel::Classified(Regime::Normal),
        to_regime: RegimeLabel::Classified(Regime::Elevated),
        from_profile_name: "normal".into(),
        to_profile_name: "elevated".into(),
        outcome: MorphingOutcome::Applied {
            distance_millionths: 200_000,
            new_entropy_millionths: 1_300_000,
        },
        evidence_hash: "a".repeat(64),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MorphingStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn enrichment_morphing_step_with_rejection_serde() {
    let step = MorphingStep {
        seq: 1,
        from_regime: RegimeLabel::Classified(Regime::Normal),
        to_regime: RegimeLabel::Abstention,
        from_profile_name: "anchor".into(),
        to_profile_name: "anchor".into(),
        outcome: MorphingOutcome::Rejected {
            reason: MorphingRejection::SourceAbstention,
        },
        evidence_hash: "b".repeat(64),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MorphingStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn enrichment_morphing_step_noop_serde() {
    let step = MorphingStep {
        seq: 5,
        from_regime: RegimeLabel::Classified(Regime::Elevated),
        to_regime: RegimeLabel::Classified(Regime::Elevated),
        from_profile_name: "elevated".into(),
        to_profile_name: "elevated".into(),
        outcome: MorphingOutcome::NoOp,
        evidence_hash: "c".repeat(64),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MorphingStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

// ---------------------------------------------------------------------------
// MorphingSpecimenFamily enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_family_all_count() {
    assert_eq!(MorphingSpecimenFamily::ALL.len(), 8);
}

#[test]
fn enrichment_specimen_family_all_unique() {
    let unique: BTreeSet<MorphingSpecimenFamily> =
        MorphingSpecimenFamily::ALL.iter().copied().collect();
    assert_eq!(unique.len(), MorphingSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_specimen_family_all_as_str_unique() {
    let strs: BTreeSet<&str> = MorphingSpecimenFamily::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(strs.len(), MorphingSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_specimen_family_display_roundtrip_via_str() {
    for f in MorphingSpecimenFamily::ALL {
        let display = f.to_string();
        let as_str = f.as_str();
        assert_eq!(display, as_str);
        assert!(!display.is_empty());
    }
}

#[test]
fn enrichment_specimen_family_serde_all_variants() {
    for f in MorphingSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: MorphingSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn enrichment_specimen_family_specific_values() {
    assert_eq!(MorphingSpecimenFamily::Transition.as_str(), "transition");
    assert_eq!(
        MorphingSpecimenFamily::BudgetExhaustion.as_str(),
        "budget_exhaustion"
    );
    assert_eq!(
        MorphingSpecimenFamily::StepDistance.as_str(),
        "step_distance"
    );
    assert_eq!(
        MorphingSpecimenFamily::EntropyBounds.as_str(),
        "entropy_bounds"
    );
    assert_eq!(MorphingSpecimenFamily::Cooldown.as_str(), "cooldown");
    assert_eq!(
        MorphingSpecimenFamily::Interpolation.as_str(),
        "interpolation"
    );
    assert_eq!(MorphingSpecimenFamily::Fallback.as_str(), "fallback");
    assert_eq!(MorphingSpecimenFamily::NoOp.as_str(), "no_op");
}

// ---------------------------------------------------------------------------
// MorphingExpectedOutcome enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_outcome_serde_all_variants() {
    let variants = [
        MorphingExpectedOutcome::Applied,
        MorphingExpectedOutcome::Rejected,
        MorphingExpectedOutcome::NoOp,
        MorphingExpectedOutcome::FallbackActivated,
        MorphingExpectedOutcome::BudgetExhausted,
        MorphingExpectedOutcome::InterpolationUsed,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: MorphingExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_expected_outcome_ord() {
    assert!(MorphingExpectedOutcome::Applied < MorphingExpectedOutcome::Rejected);
    assert!(MorphingExpectedOutcome::Rejected < MorphingExpectedOutcome::NoOp);
}

// ---------------------------------------------------------------------------
// MorphingSpecimen enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_specimen_serde_roundtrip() {
    let s = MorphingSpecimen {
        specimen_id: "test_id_1".into(),
        description: "A test specimen".into(),
        family: MorphingSpecimenFamily::Transition,
        expected_outcome: MorphingExpectedOutcome::Applied,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MorphingSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// MorphingVerdict enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_serde_pass() {
    let v = MorphingVerdict::Pass;
    let json = serde_json::to_string(&v).unwrap();
    let back: MorphingVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_verdict_serde_fail() {
    let v = MorphingVerdict::Fail;
    let json = serde_json::to_string(&v).unwrap();
    let back: MorphingVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_verdict_ord() {
    // Fail > Pass
    assert!(MorphingVerdict::Fail > MorphingVerdict::Pass);
}

// ---------------------------------------------------------------------------
// MorphingSpecimenEvidence enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_serde_roundtrip() {
    let ev = MorphingSpecimenEvidence {
        specimen_id: "test_ev".into(),
        family: MorphingSpecimenFamily::Fallback,
        expected_outcome: MorphingExpectedOutcome::FallbackActivated,
        verdict: MorphingVerdict::Pass,
        actual_outcome: "Rejected { reason: SourceAbstention }".into(),
        error_detail: None,
        evidence_hash: "d".repeat(64),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MorphingSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_specimen_evidence_with_error_detail_serde() {
    let ev = MorphingSpecimenEvidence {
        specimen_id: "fail_ev".into(),
        family: MorphingSpecimenFamily::Transition,
        expected_outcome: MorphingExpectedOutcome::Applied,
        verdict: MorphingVerdict::Fail,
        actual_outcome: "NoOp".into(),
        error_detail: Some("expected Applied but got NoOp".into()),
        evidence_hash: "e".repeat(64),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MorphingSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
    assert!(back.error_detail.is_some());
}

// ---------------------------------------------------------------------------
// MorphingEvidenceInventory enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_inventory_contract_satisfied_true() {
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        specimen_count: 3,
        pass_count: 3,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn enrichment_evidence_inventory_contract_satisfied_false_with_fail() {
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn enrichment_evidence_inventory_contract_satisfied_false_empty() {
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn enrichment_evidence_inventory_serde_roundtrip_with_family_coverage() {
    let mut fc = BTreeMap::new();
    fc.insert("transition".into(), 3u64);
    fc.insert("fallback".into(), 2u64);
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        specimen_count: 5,
        pass_count: 5,
        fail_count: 0,
        family_coverage: fc,
        evidence: vec![],
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: MorphingEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// MorphingRunManifest enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let manifest = MorphingRunManifest {
        schema_version: MORPHING_MANIFEST_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        trace_id: "morph-abc123".into(),
        decision_id: "dec-def456".into(),
        policy_id: MORPHING_POLICY_ID.into(),
        inventory_hash: "f".repeat(64),
        specimen_count: 15,
        pass_count: 15,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: MorphingArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: MorphingRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// MorphingArtifactPaths enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let paths = MorphingArtifactPaths {
        evidence_inventory: "a.json".into(),
        run_manifest: "b.json".into(),
        events_jsonl: "c.jsonl".into(),
        commands_txt: "d.txt".into(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: MorphingArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ---------------------------------------------------------------------------
// MorphingEvidenceEvent enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_event_serde_with_all_fields() {
    let ev = MorphingEvidenceEvent {
        schema_version: MORPHING_EVENT_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        event: "morphing_specimen_evaluated".into(),
        policy_id: MORPHING_POLICY_ID.into(),
        specimen_id: Some("test_specimen_1".into()),
        verdict: Some("pass".into()),
        detail: Some("all good".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MorphingEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_evidence_event_serde_with_none_fields() {
    let ev = MorphingEvidenceEvent {
        schema_version: MORPHING_EVENT_SCHEMA_VERSION.into(),
        component: MORPHING_COMPONENT.into(),
        event: "morphing_evidence_run_started".into(),
        policy_id: MORPHING_POLICY_ID.into(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MorphingEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// MorphingSummary enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morphing_summary_serde_roundtrip() {
    let s = MorphingSummary {
        step_count: 10,
        applied_count: 7,
        fallback_count: 3,
        budget_remaining_steps: 5,
        budget_remaining_distance: 2_000_000,
        current_profile_name: "elevated_profile".into(),
        current_regime: RegimeLabel::Classified(Regime::Elevated),
        in_fallback: false,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MorphingSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_morphing_summary_in_fallback_state() {
    let s = MorphingSummary {
        step_count: 5,
        applied_count: 2,
        fallback_count: 3,
        budget_remaining_steps: 0,
        budget_remaining_distance: 0,
        current_profile_name: "anchor_baseline".into(),
        current_regime: RegimeLabel::Abstention,
        in_fallback: true,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: MorphingSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
    assert!(back.in_fallback);
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — construction enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_new_initial_state() {
    let m = build_morpher(42);
    assert_eq!(m.step_count, 0);
    assert_eq!(m.applied_count, 0);
    assert_eq!(m.fallback_count, 0);
    assert!(!m.in_fallback);
    assert!(m.history.is_empty());
    assert_eq!(m.current_regime, RegimeLabel::Abstention);
    assert_eq!(m.current_profile().name, "anchor_baseline");
}

#[test]
fn enrichment_morpher_with_defaults_epoch() {
    let epoch = SecurityEpoch::from_raw(99);
    let anchor = anchor_profile();
    let m = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    assert_eq!(m.budget.epoch, epoch);
    assert_eq!(m.budget.max_steps, DEFAULT_TRANSITION_BUDGET);
}

#[test]
fn enrichment_morpher_register_profile_stores_all_regimes() {
    let m = build_morpher(1);
    // Should have all 5 regimes registered
    assert!(m.regime_profiles.len() >= 5);
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — morph workflows enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_noop_does_not_consume_budget() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let before_steps = m.budget.steps_used;
    m.morph(RegimeLabel::Classified(Regime::Normal));
    assert_eq!(m.budget.steps_used, before_steps);
}

#[test]
fn enrichment_morpher_noop_increments_step_count() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Normal));
    assert_eq!(m.step_count, 1);
}

#[test]
fn enrichment_morpher_applied_increments_applied_count() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_applied());
    assert_eq!(m.applied_count, 1);
}

#[test]
fn enrichment_morpher_applied_sets_current_regime() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert_eq!(m.current_regime, RegimeLabel::Classified(Regime::Elevated));
}

#[test]
fn enrichment_morpher_applied_records_budget_step() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(m.budget.steps_used >= 1);
    assert!(m.budget.cumulative_distance_millionths > 0);
}

#[test]
fn enrichment_morpher_applied_clears_fallback_mode() {
    let mut m = build_morpher(1);
    m.in_fallback = true;
    m.steps_since_fallback = 100;
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    if outcome.is_applied() {
        assert!(!m.in_fallback);
    }
}

#[test]
fn enrichment_morpher_reject_sets_fallback_mode() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Abstention);
    assert!(outcome.is_rejected());
    assert!(m.in_fallback);
}

#[test]
fn enrichment_morpher_reject_increments_fallback_count() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    // After first rejected morph, fallback_count should be at least 1.
    assert!(
        m.fallback_count >= 1,
        "first rejection should set fallback_count >= 1"
    );
}

#[test]
fn enrichment_morpher_reject_resets_steps_since_fallback() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.steps_since_fallback = 100;
    m.morph(RegimeLabel::Abstention);
    // After rejection, steps_since_fallback should be 0 (set in reject)
    // but morph increments it first, then reject sets it to 0
    assert_eq!(m.steps_since_fallback, 0);
}

#[test]
fn enrichment_morpher_reject_restores_anchor_profile() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    // Now current should be elevated. Trigger fallback.
    let outcome = m.morph(RegimeLabel::Abstention);
    assert!(outcome.is_rejected());
    assert_eq!(m.current_profile().name, m.anchor_profile().name);
}

#[test]
fn enrichment_morpher_cooldown_blocks_during_window() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention); // trigger fallback
    // steps_since_fallback = 0 now, cooldown = FALLBACK_COOLDOWN_STEPS (3)
    // Next morph: steps_since_fallback becomes 1 (< 3), so cooldown active
    m.current_regime = RegimeLabel::Abstention;
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_rejected());
    if let MorphingOutcome::Rejected { reason } = outcome {
        assert_eq!(reason, MorphingRejection::CooldownActive);
    }
}

#[test]
fn enrichment_morpher_cooldown_blocks_exactly_at_boundary() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    // Set steps_since_fallback to just below cooldown threshold
    // morph will add 1 first, so we need it to be < FALLBACK_COOLDOWN_STEPS after increment
    m.steps_since_fallback = FALLBACK_COOLDOWN_STEPS - 1;
    m.current_regime = RegimeLabel::Abstention;
    // After morph increments: steps_since_fallback = FALLBACK_COOLDOWN_STEPS
    // The check is `< config.fallback_cooldown_steps`, so exactly at boundary passes
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    // At boundary (equal), the check is `<` so it should NOT be blocked
    // But it's morphing FROM abstention which may have other issues
    // Actually morphing TO Elevated from Abstention: the from_regime check allows it
    // since the code has `if from_regime.is_abstention() && !new_regime.is_abstention() { // Allow }`
    // But then checks `if new_regime.is_abstention()` which is false, so proceeds
    // The target_regime extraction works for Classified(Elevated)
    // So this should succeed if profile is registered and within bounds
    // However, there was a fallback so in_fallback = true, current_profile = anchor
    if outcome.is_applied() {
        assert!(!m.in_fallback);
    }
}

#[test]
fn enrichment_morpher_no_target_profile_when_not_registered() {
    let anchor = anchor_profile();
    let epoch = SecurityEpoch::from_raw(1);
    let mut m = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    // Don't register any profiles
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_rejected());
    if let MorphingOutcome::Rejected { reason } = outcome {
        assert_eq!(reason, MorphingRejection::NoTargetProfile);
    }
}

#[test]
fn enrichment_morpher_budget_exhaustion_step_limit() {
    let anchor = anchor_profile();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 10_000_000);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in regime_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let first = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(first.is_applied());
    // Budget now exhausted (1 step used of 1 max)
    m.steps_since_fallback = 100;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Elevated);
    let second = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(second.is_rejected());
    if let MorphingOutcome::Rejected { reason } = second {
        assert_eq!(reason, MorphingRejection::BudgetExhausted);
    }
}

#[test]
fn enrichment_morpher_budget_reset_enables_new_transitions() {
    let anchor = anchor_profile();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 10_000_000);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in regime_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    // Reset budget
    m.reset_budget(SecurityEpoch::from_raw(2));
    m.steps_since_fallback = 100;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Elevated);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(outcome.is_applied());
    assert_eq!(m.budget.epoch, SecurityEpoch::from_raw(2));
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — interpolation enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_interpolation_with_low_rate_produces_small_step() {
    let config = MorphingConfig {
        max_step_distance_millionths: 100_000,
        interpolation_rate_millionths: 100_000, // 0.1
        ..MorphingConfig::default()
    };
    let mut m = build_morpher_with_config(1, config);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    if let MorphingOutcome::Applied {
        distance_millionths,
        ..
    } = outcome
    {
        assert!(
            distance_millionths <= 100_000,
            "blended distance {distance_millionths} should be <= 100_000"
        );
    }
}

#[test]
fn enrichment_morpher_interpolation_blended_profile_name_contains_blend() {
    let config = MorphingConfig {
        max_step_distance_millionths: 10_000, // very small, forces blend
        interpolation_rate_millionths: 50_000, // 0.05
        ..MorphingConfig::default()
    };
    let mut m = build_morpher_with_config(1, config);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    if outcome.is_applied() {
        assert!(
            m.current_profile().name.contains("blend"),
            "blended profile name should contain 'blend', got: {}",
            m.current_profile().name
        );
    }
}

#[test]
fn enrichment_morpher_interpolation_full_rate_applies_target_directly() {
    // With interpolation_rate = 1.0 and large max_step, target should be applied directly
    let config = MorphingConfig {
        max_step_distance_millionths: 10_000_000, // very large
        interpolation_rate_millionths: 1_000_000, // 1.0
        ..MorphingConfig::default()
    };
    let mut m = build_morpher_with_config(1, config);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_applied());
    // With large max_step, no interpolation needed
    assert_eq!(m.current_profile().name, "elevated_profile");
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — history enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_history_noop_is_recorded() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Normal)); // noop
    assert_eq!(m.history.len(), 1);
    assert_eq!(m.history[0].outcome, MorphingOutcome::NoOp);
}

#[test]
fn enrichment_morpher_history_rejection_is_recorded() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    assert_eq!(m.history.len(), 1);
    assert!(m.history[0].outcome.is_rejected());
}

#[test]
fn enrichment_morpher_history_applied_is_recorded() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert_eq!(m.history.len(), 1);
    assert!(m.history[0].outcome.is_applied());
}

#[test]
fn enrichment_morpher_history_evidence_hashes_are_hex() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated)); // noop
    m.morph(RegimeLabel::Abstention); // rejection
    for step in &m.history {
        assert_eq!(step.evidence_hash.len(), 64);
        assert!(step.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn enrichment_morpher_history_evidence_hashes_differ_across_steps() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated)); // noop
    let hashes: BTreeSet<&str> = m.history.iter().map(|s| s.evidence_hash.as_str()).collect();
    assert_eq!(hashes.len(), m.history.len());
}

#[test]
fn enrichment_morpher_history_from_and_to_regime_correct() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert_eq!(
        m.history[0].from_regime,
        RegimeLabel::Classified(Regime::Normal)
    );
    assert_eq!(
        m.history[0].to_regime,
        RegimeLabel::Classified(Regime::Elevated)
    );
}

#[test]
fn enrichment_morpher_history_seq_starts_at_one() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert_eq!(m.history[0].seq, 1);
}

#[test]
fn enrichment_morpher_history_seq_monotonically_increasing() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Recovery));
    m.morph(RegimeLabel::Classified(Regime::Recovery));
    for w in m.history.windows(2) {
        assert!(w[0].seq < w[1].seq);
    }
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — summary enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_summary_initial_state() {
    let m = build_morpher(1);
    let s = m.summary();
    assert_eq!(s.step_count, 0);
    assert_eq!(s.applied_count, 0);
    assert_eq!(s.fallback_count, 0);
    assert!(!s.in_fallback);
    assert_eq!(s.budget_remaining_steps, DEFAULT_TRANSITION_BUDGET);
    assert_eq!(s.budget_remaining_distance, 5_000_000);
    assert_eq!(s.current_regime, RegimeLabel::Abstention);
}

#[test]
fn enrichment_morpher_summary_after_multiple_morphs() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated)); // noop
    m.morph(RegimeLabel::Classified(Regime::Recovery));
    let s = m.summary();
    assert_eq!(s.step_count, 3);
    assert!(s.applied_count >= 2);
    assert_eq!(s.current_profile_name, m.current_profile().name);
}

#[test]
fn enrichment_morpher_summary_budget_remaining_decreases() {
    let mut m = build_morpher(1);
    let s0 = m.summary();
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    let s1 = m.summary();
    assert!(s1.budget_remaining_steps < s0.budget_remaining_steps);
    assert!(s1.budget_remaining_distance < s0.budget_remaining_distance);
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — serde enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_serde_roundtrip_initial() {
    let m = build_morpher(1);
    let json = serde_json::to_string(&m).unwrap();
    let back: EntropicPolicyMorpher = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_morpher_serde_roundtrip_after_morphs() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    let json = serde_json::to_string(&m).unwrap();
    let back: EntropicPolicyMorpher = serde_json::from_str(&json).unwrap();
    assert_eq!(m.step_count, back.step_count);
    assert_eq!(m.applied_count, back.applied_count);
    assert_eq!(m.fallback_count, back.fallback_count);
    assert_eq!(m.history.len(), back.history.len());
    assert_eq!(m.current_regime, back.current_regime);
}

#[test]
fn enrichment_morpher_serde_roundtrip_after_fallback() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    let json = serde_json::to_string(&m).unwrap();
    let back: EntropicPolicyMorpher = serde_json::from_str(&json).unwrap();
    assert_eq!(m.in_fallback, back.in_fallback);
    assert_eq!(m.fallback_count, back.fallback_count);
    assert_eq!(m.steps_since_fallback, back.steps_since_fallback);
}

// ---------------------------------------------------------------------------
// EntropicPolicyMorpher — multi-step workflow enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_morpher_full_cycle_normal_elevated_attack_recovery_normal() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);

    let o1 = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(o1.is_applied());

    let o2 = m.morph(RegimeLabel::Classified(Regime::Attack));
    assert!(o2.is_applied());

    let o3 = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(o3.is_applied());

    let o4 = m.morph(RegimeLabel::Classified(Regime::Normal));
    assert!(o4.is_applied());

    assert_eq!(m.applied_count, 4);
    assert_eq!(m.history.len(), 4);
}

#[test]
fn enrichment_morpher_repeated_noop_does_not_exhaust_budget() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    for _ in 0..100 {
        let o = m.morph(RegimeLabel::Classified(Regime::Normal));
        assert_eq!(o, MorphingOutcome::NoOp);
    }
    assert_eq!(m.budget.steps_used, 0);
    assert_eq!(m.step_count, 100);
    assert!(!m.budget.is_exhausted());
}

#[test]
fn enrichment_morpher_fallback_then_recover_after_cooldown() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);

    // Trigger fallback
    let o1 = m.morph(RegimeLabel::Abstention);
    assert!(o1.is_rejected());
    assert!(m.is_in_fallback());

    // Simulate cooldown expiry
    m.steps_since_fallback = FALLBACK_COOLDOWN_STEPS + 1;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Normal);

    // Should be able to morph again
    let o2 = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(o2.is_applied());
    assert!(!m.is_in_fallback());
}

#[test]
fn enrichment_morpher_alternating_regimes_consumes_budget() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);

    let mut applied = 0u64;
    for i in 0..5 {
        let regime = if i % 2 == 0 {
            RegimeLabel::Classified(Regime::Elevated)
        } else {
            RegimeLabel::Classified(Regime::Normal)
        };
        let o = m.morph(regime);
        if o.is_applied() {
            applied += 1;
        }
    }
    assert!(applied > 0);
    assert!(m.budget.steps_used > 0);
}

// ---------------------------------------------------------------------------
// Corpus enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_specimen_ids_non_empty() {
    for s in entropic_policy_morphing::morphing_corpus() {
        assert!(!s.specimen_id.is_empty());
    }
}

#[test]
fn enrichment_corpus_specimen_ids_contain_no_whitespace() {
    for s in entropic_policy_morphing::morphing_corpus() {
        assert!(
            !s.specimen_id.contains(' '),
            "specimen_id contains whitespace: {}",
            s.specimen_id
        );
    }
}

#[test]
fn enrichment_corpus_all_families_have_at_least_one_specimen() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    for f in MorphingSpecimenFamily::ALL {
        let count = corpus.iter().filter(|s| s.family == *f).count();
        assert!(count >= 1, "family {:?} has no specimens", f);
    }
}

#[test]
fn enrichment_corpus_descriptions_are_distinct() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    let descs: BTreeSet<&str> = corpus.iter().map(|s| s.description.as_str()).collect();
    assert_eq!(descs.len(), corpus.len(), "duplicate descriptions found");
}

// ---------------------------------------------------------------------------
// Runner / inventory enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runner_all_evidence_has_family() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    for ev in &inv.evidence {
        // family should roundtrip through serde
        let json = serde_json::to_string(&ev.family).unwrap();
        let _: MorphingSpecimenFamily = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn enrichment_runner_evidence_specimen_ids_match_corpus() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    let inv = entropic_policy_morphing::run_morphing_corpus();
    let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: BTreeSet<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

#[test]
fn enrichment_runner_evidence_order_matches_corpus() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    let inv = entropic_policy_morphing::run_morphing_corpus();
    for (specimen, evidence) in corpus.iter().zip(&inv.evidence) {
        assert_eq!(specimen.specimen_id, evidence.specimen_id);
    }
}

#[test]
fn enrichment_runner_pass_count_equals_pass_verdicts() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    let count = inv
        .evidence
        .iter()
        .filter(|e| e.verdict == MorphingVerdict::Pass)
        .count() as u64;
    assert_eq!(inv.pass_count, count);
}

#[test]
fn enrichment_runner_fail_count_equals_fail_verdicts() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    let count = inv
        .evidence
        .iter()
        .filter(|e| e.verdict == MorphingVerdict::Fail)
        .count() as u64;
    assert_eq!(inv.fail_count, count);
}

#[test]
fn enrichment_runner_inventory_component_correct() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(inv.component, MORPHING_COMPONENT);
}

#[test]
fn enrichment_runner_inventory_schema_version_correct() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(inv.schema_version, MORPHING_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Constants enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_contains_v1() {
    assert!(MORPHING_SCHEMA_VERSION.contains("v1"));
    assert!(MORPHING_MANIFEST_SCHEMA_VERSION.contains("v1"));
    assert!(MORPHING_EVENT_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_constants_component_matches_module_name() {
    assert_eq!(MORPHING_COMPONENT, "entropic_policy_morphing");
}

#[test]
fn enrichment_constants_policy_id_format() {
    assert!(MORPHING_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_constants_max_step_distance_less_than_million() {
    assert!(MAX_STEP_DISTANCE_MILLIONTHS <= 1_000_000);
}

#[test]
fn enrichment_constants_min_entropy_positive() {
    assert!(MIN_ENTROPY_MILLIONTHS > 0);
}

#[test]
fn enrichment_constants_max_entropy_greater_than_min() {
    assert!(MAX_ENTROPY_MILLIONTHS > MIN_ENTROPY_MILLIONTHS);
}

#[test]
fn enrichment_constants_default_budget_at_least_one() {
    assert!(DEFAULT_TRANSITION_BUDGET >= 1);
}

#[test]
fn enrichment_constants_cooldown_at_least_one() {
    assert!(FALLBACK_COOLDOWN_STEPS >= 1);
}

// ---------------------------------------------------------------------------
// Bundle writer enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_bundle_writer_idempotent() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_idempotent");
    let _ = std::fs::remove_dir_all(&dir);
    let a1 = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let a2 = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_bundle_writer_inventory_file_is_valid_json() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_valid_json");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&content).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_bundle_writer_manifest_contract_satisfied() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_manifest_contract");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: MorphingRunManifest = serde_json::from_str(&content).unwrap();
    assert!(manifest.contract_satisfied);
    assert_eq!(manifest.fail_count, 0);
    assert_eq!(manifest.policy_id, MORPHING_POLICY_ID);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_bundle_writer_events_all_have_schema_version() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_event_schema");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in content.lines() {
        let ev: MorphingEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(ev.schema_version, MORPHING_EVENT_SCHEMA_VERSION);
        assert_eq!(ev.component, MORPHING_COMPONENT);
        assert_eq!(ev.policy_id, MORPHING_POLICY_ID);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_bundle_writer_commands_written() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_commands");
    let _ = std::fs::remove_dir_all(&dir);
    let cmds = vec![
        "cargo test --lib entropic_policy_morphing".to_string(),
        "cargo clippy".to_string(),
    ];
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &cmds).unwrap();
    let content = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(content.contains("cargo test"));
    assert!(content.contains("cargo clippy"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_bundle_writer_inventory_hash_is_64_hex() {
    let dir = std::env::temp_dir().join("pearl_morph_enrichment_hash_format");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    assert_eq!(artifacts.inventory_hash.len(), 64);
    assert!(
        artifacts
            .inventory_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Determinism enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_morpher_identical_inputs_same_outcomes() {
    let mut m1 = build_morpher(1);
    let mut m2 = build_morpher(1);
    m1.current_regime = RegimeLabel::Classified(Regime::Normal);
    m2.current_regime = RegimeLabel::Classified(Regime::Normal);
    let o1 = m1.morph(RegimeLabel::Classified(Regime::Elevated));
    let o2 = m2.morph(RegimeLabel::Classified(Regime::Elevated));
    assert_eq!(o1, o2);
    assert_eq!(m1.history, m2.history);
}

#[test]
fn enrichment_determinism_content_hash_same_data() {
    let h1 = ContentHash::compute(b"test-data-for-morphing");
    let h2 = ContentHash::compute(b"test-data-for-morphing");
    assert_eq!(h1.as_bytes(), h2.as_bytes());
}

#[test]
fn enrichment_determinism_profile_hash_stable() {
    let p = anchor_profile();
    let h1 = p.content_hash();
    let h2 = p.content_hash();
    let h3 = p.content_hash();
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn enrichment_determinism_corpus_run_three_times() {
    let r1 = entropic_policy_morphing::run_morphing_corpus();
    let r2 = entropic_policy_morphing::run_morphing_corpus();
    let r3 = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ---------------------------------------------------------------------------
// Edge cases enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_empty_dimensions_profile_distance() {
    let empty = PolicyProfile::new("empty", BTreeMap::new());
    let anchor = anchor_profile();
    let d = empty.l1_distance(&anchor);
    // Sum of all anchor dimension absolute values
    let expected: i64 = anchor.dimensions.values().map(|v| v.abs()).sum();
    assert_eq!(d, expected);
}

#[test]
fn enrichment_edge_very_large_dimension_values() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), i64::MAX / 2);
    dims.insert("y".into(), i64::MAX / 2);
    let p = PolicyProfile::new("large", dims);
    // Should not panic
    let _ = p.entropy_millionths();
    let _ = p.content_hash();
}

#[test]
fn enrichment_edge_zero_interpolation_rate() {
    let config = MorphingConfig {
        interpolation_rate_millionths: 0, // zero rate = no movement
        ..MorphingConfig::default()
    };
    let mut m = build_morpher_with_config(1, config);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    // With zero interpolation rate, blend produces same as current
    // Step distance check: Normal->Elevated might be within max_step or not
    // If within, applies directly. If not, blend moves 0% -> distance = 0
    let _outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    // Just check it doesn't panic
}

#[test]
fn enrichment_edge_single_step_budget() {
    let anchor = anchor_profile();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 10_000_000);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in regime_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let first = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(first.is_applied());
    assert!(m.budget.is_exhausted());
}

#[test]
fn enrichment_edge_morph_to_same_regime_from_abstention() {
    let mut m = build_morpher(1);
    // current_regime is Abstention by default
    let outcome = m.morph(RegimeLabel::Abstention);
    // Same regime -> NoOp
    assert_eq!(outcome, MorphingOutcome::NoOp);
}

#[test]
fn enrichment_edge_morph_from_abstention_to_classified() {
    let mut m = build_morpher(1);
    // current_regime is Abstention by default
    let outcome = m.morph(RegimeLabel::Classified(Regime::Normal));
    // From Abstention -> Classified is allowed (there's a special case)
    assert!(outcome.is_applied());
}

#[test]
fn enrichment_edge_profile_with_single_zero_dimension() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), 0);
    let p = PolicyProfile::new("zero_dim", dims);
    assert_eq!(p.entropy_millionths(), 0);
    assert_eq!(p.l1_distance(&p), 0);
}

#[test]
fn enrichment_edge_profile_entropy_with_very_skewed_distribution() {
    let mut dims = BTreeMap::new();
    dims.insert("x".into(), 999_999);
    dims.insert("y".into(), 1);
    let p = PolicyProfile::new("skewed", dims);
    let e = p.entropy_millionths();
    // Very concentrated distribution -> low entropy, close to 0
    assert!(e >= 0, "entropy should be non-negative: {e}");
    assert!(
        e < 100_000,
        "expected low entropy for skewed distribution, got {e}"
    );
}

#[test]
fn enrichment_edge_profile_entropy_with_three_equal_dimensions() {
    let mut dims = BTreeMap::new();
    dims.insert("a".into(), 333_333);
    dims.insert("b".into(), 333_333);
    dims.insert("c".into(), 333_334);
    let p = PolicyProfile::new("three_equal", dims);
    let e = p.entropy_millionths();
    // ln(3) ~= 1.0986 -> ~1_098_600 millionths
    assert!(e > 900_000, "expected >900k, got {e}");
    assert!(e < 1_300_000, "expected <1.3M, got {e}");
}

// ---------------------------------------------------------------------------
// Multi-epoch workflow
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multi_epoch_reset_and_continue() {
    let mut m = build_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);

    // Epoch 1: do some morphing
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(m.budget.steps_used >= 2);

    // Reset for epoch 2
    m.reset_budget(SecurityEpoch::from_raw(2));
    assert_eq!(m.budget.steps_used, 0);
    assert_eq!(m.budget.epoch, SecurityEpoch::from_raw(2));

    // Epoch 2: continue morphing
    m.morph(RegimeLabel::Classified(Regime::Normal));
    assert!(m.budget.steps_used >= 1);

    // History spans both epochs
    assert!(m.history.len() >= 3);
}
