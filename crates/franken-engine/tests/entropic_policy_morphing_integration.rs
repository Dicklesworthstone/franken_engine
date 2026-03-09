#![forbid(unsafe_code)]

//! Integration tests for the entropic policy morphing module [RGC-617B].

use std::collections::BTreeMap;

use frankenengine_engine::entropic_policy_morphing::{
    self, DEFAULT_TRANSITION_BUDGET, EntropicPolicyMorpher, FALLBACK_COOLDOWN_STEPS,
    MAX_ENTROPY_MILLIONTHS, MAX_STEP_DISTANCE_MILLIONTHS, MIN_ENTROPY_MILLIONTHS,
    MORPHING_COMPONENT, MORPHING_EVENT_SCHEMA_VERSION, MORPHING_MANIFEST_SCHEMA_VERSION,
    MORPHING_POLICY_ID, MORPHING_SCHEMA_VERSION, MorphingConfig, MorphingEvidenceInventory,
    MorphingExpectedOutcome, MorphingOutcome, MorphingRejection, MorphingSpecimenFamily,
    MorphingVerdict, PolicyProfile, TransitionBudget,
};
use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::RegimeLabel;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_anchor() -> PolicyProfile {
    let mut dims = BTreeMap::new();
    dims.insert("exploration_rate".into(), 200_000);
    dims.insert("sandbox_strictness".into(), 800_000);
    dims.insert("gc_aggressiveness".into(), 500_000);
    dims.insert("cache_budget".into(), 600_000);
    PolicyProfile::for_regime("anchor_baseline", Regime::Normal, dims)
}

fn make_profiles() -> Vec<(Regime, PolicyProfile)> {
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

fn make_morpher(epoch_raw: u64) -> EntropicPolicyMorpher {
    let anchor = make_anchor();
    let epoch = SecurityEpoch::from_raw(epoch_raw);
    let mut m = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    for (regime, profile) in make_profiles() {
        m.register_profile(regime, profile);
    }
    m
}

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    assert!(!entropic_policy_morphing::morphing_corpus().is_empty());
}

#[test]
fn corpus_ids_unique() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    let ids: BTreeMap<&str, usize> = corpus
        .iter()
        .enumerate()
        .map(|(i, s)| (s.specimen_id.as_str(), i))
        .collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_descriptions_non_empty() {
    for s in entropic_policy_morphing::morphing_corpus() {
        assert!(
            !s.description.is_empty(),
            "empty description for {}",
            s.specimen_id
        );
    }
}

#[test]
fn corpus_covers_all_families() {
    let corpus = entropic_policy_morphing::morphing_corpus();
    let covered: std::collections::BTreeSet<MorphingSpecimenFamily> =
        corpus.iter().map(|s| s.family).collect();
    for f in MorphingSpecimenFamily::ALL {
        assert!(covered.contains(f), "missing family {:?}", f);
    }
}

// ---------------------------------------------------------------------------
// Runner / inventory
// ---------------------------------------------------------------------------

#[test]
fn runner_produces_inventory() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert!(inv.specimen_count > 0);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn all_specimens_pass() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            MorphingVerdict::Pass,
            "specimen {} failed: {:?}",
            ev.specimen_id,
            ev.error_detail
        );
    }
}

#[test]
fn contract_satisfied() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn counts_consistent() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
}

#[test]
fn family_coverage_sums_to_specimen_count() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    let total: u64 = inv.family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn deterministic_runs() {
    let inv1 = entropic_policy_morphing::run_morphing_corpus();
    let inv2 = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(inv1, inv2);
}

// ---------------------------------------------------------------------------
// Evidence hashes
// ---------------------------------------------------------------------------

#[test]
fn evidence_hashes_present() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    for ev in &inv.evidence {
        assert!(!ev.evidence_hash.is_empty());
    }
}

#[test]
fn evidence_hashes_are_64_hex() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    for ev in &inv.evidence {
        assert_eq!(ev.evidence_hash.len(), 64, "specimen {}", ev.specimen_id);
        assert!(
            ev.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "non-hex hash for {}",
            ev.specimen_id
        );
    }
}

#[test]
fn evidence_hashes_deterministic() {
    let inv1 = entropic_policy_morphing::run_morphing_corpus();
    let inv2 = entropic_policy_morphing::run_morphing_corpus();
    for (a, b) in inv1.evidence.iter().zip(&inv2.evidence) {
        assert_eq!(
            a.evidence_hash, b.evidence_hash,
            "specimen {}",
            a.specimen_id
        );
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: MorphingEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn policy_profile_serde_roundtrip() {
    let p = make_anchor();
    let json = serde_json::to_string(&p).unwrap();
    let back: PolicyProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn transition_budget_serde_roundtrip() {
    let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(42));
    let json = serde_json::to_string(&b).unwrap();
    let back: TransitionBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn morphing_config_serde_roundtrip() {
    let c = MorphingConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: MorphingConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn regime_label_serde_roundtrip_in_morpher() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    let json = serde_json::to_string(&m).unwrap();
    let back: EntropicPolicyMorpher = serde_json::from_str(&json).unwrap();
    assert_eq!(m.step_count, back.step_count);
    assert_eq!(m.applied_count, back.applied_count);
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_non_empty() {
    assert!(!MORPHING_SCHEMA_VERSION.is_empty());
    assert!(!MORPHING_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!MORPHING_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_prefixed() {
    assert!(MORPHING_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MORPHING_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MORPHING_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_and_policy_id_non_empty() {
    assert!(!MORPHING_COMPONENT.is_empty());
    assert!(!MORPHING_POLICY_ID.is_empty());
    assert_eq!(MORPHING_POLICY_ID, "RGC-617B");
}

#[test]
fn inventory_schema_matches_constant() {
    let inv = entropic_policy_morphing::run_morphing_corpus();
    assert_eq!(inv.schema_version, MORPHING_SCHEMA_VERSION);
    assert_eq!(inv.component, MORPHING_COMPONENT);
}

// ---------------------------------------------------------------------------
// PolicyProfile tests
// ---------------------------------------------------------------------------

#[test]
fn profile_l1_distance_self_zero() {
    let p = make_anchor();
    assert_eq!(p.l1_distance(&p), 0);
}

#[test]
fn profile_l1_distance_symmetric() {
    let profiles = make_profiles();
    let a = &profiles[0].1;
    let b = &profiles[2].1; // attack
    assert_eq!(a.l1_distance(b), b.l1_distance(a));
}

#[test]
fn profile_l1_distance_triangle_inequality() {
    let profiles = make_profiles();
    let a = &profiles[0].1;
    let b = &profiles[1].1;
    let c = &profiles[2].1;
    let ab = a.l1_distance(b);
    let bc = b.l1_distance(c);
    let ac = a.l1_distance(c);
    assert!(
        ac <= ab + bc,
        "triangle inequality violated: {ac} > {ab} + {bc}"
    );
}

#[test]
fn profile_entropy_positive_for_valid() {
    let p = make_anchor();
    let e = p.entropy_millionths();
    assert!(e > 0, "entropy should be positive, got {e}");
}

#[test]
fn profile_entropy_zero_for_empty() {
    let p = PolicyProfile::new("empty", BTreeMap::new());
    assert_eq!(p.entropy_millionths(), 0);
}

#[test]
fn profile_entropy_zero_for_all_zeros() {
    let mut dims = BTreeMap::new();
    dims.insert("a".into(), 0);
    dims.insert("b".into(), 0);
    let p = PolicyProfile::new("zeros", dims);
    assert_eq!(p.entropy_millionths(), 0);
}

#[test]
fn profile_entropy_max_for_uniform() {
    // Uniform distribution over N items has max entropy = ln(N).
    let mut dims = BTreeMap::new();
    for i in 0..4 {
        dims.insert(format!("dim_{i}"), 1_000_000);
    }
    let p = PolicyProfile::new("uniform", dims);
    let e = p.entropy_millionths();
    // ln(4) ≈ 1.386 → 1_386_000 millionths
    assert!(e > 1_000_000, "uniform entropy too low: {e}");
    assert!(e < 2_000_000, "uniform entropy too high: {e}");
}

#[test]
fn profile_content_hash_deterministic() {
    let p = make_anchor();
    assert_eq!(p.content_hash(), p.content_hash());
}

#[test]
fn profile_content_hash_differs_for_different_profiles() {
    let profiles = make_profiles();
    let h0 = profiles[0].1.content_hash();
    let h1 = profiles[2].1.content_hash();
    assert_ne!(h0, h1);
}

#[test]
fn profile_content_hash_is_64_hex() {
    let p = make_anchor();
    let h = p.content_hash();
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

// ---------------------------------------------------------------------------
// TransitionBudget tests
// ---------------------------------------------------------------------------

#[test]
fn budget_defaults_match_constants() {
    let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(1));
    assert_eq!(b.max_steps, DEFAULT_TRANSITION_BUDGET);
    assert_eq!(b.steps_used, 0);
    assert_eq!(b.cumulative_distance_millionths, 0);
}

#[test]
fn budget_can_step_when_fresh() {
    let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(1));
    assert!(b.can_step(100_000));
}

#[test]
fn budget_cannot_step_when_exhausted() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 5_000_000);
    b.record_step(100_000);
    assert!(!b.can_step(100_000));
}

#[test]
fn budget_remaining_steps_decrements() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 5, 10_000_000);
    assert_eq!(b.remaining_steps(), 5);
    b.record_step(100_000);
    assert_eq!(b.remaining_steps(), 4);
}

#[test]
fn budget_remaining_distance_decrements() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 100, 1_000_000);
    b.record_step(300_000);
    assert_eq!(b.remaining_distance_millionths(), 700_000);
}

#[test]
fn budget_reset_clears_state() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 5, 5_000_000);
    b.record_step(100_000);
    b.record_step(200_000);
    b.reset(SecurityEpoch::from_raw(2));
    assert_eq!(b.steps_used, 0);
    assert_eq!(b.cumulative_distance_millionths, 0);
    assert_eq!(b.epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn budget_distance_limit_blocks() {
    let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 100, 500_000);
    b.record_step(400_000);
    assert!(!b.can_step(200_000)); // would exceed 500_000
    assert!(b.can_step(100_000)); // exactly at limit
}

// ---------------------------------------------------------------------------
// Morpher — basic transitions
// ---------------------------------------------------------------------------

#[test]
fn morpher_noop_same_regime() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Normal));
    assert_eq!(outcome, MorphingOutcome::NoOp);
    assert_eq!(m.step_count, 1);
}

#[test]
fn morpher_applies_normal_to_elevated() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_applied());
    assert_eq!(m.current_regime, RegimeLabel::Classified(Regime::Elevated));
}

#[test]
fn morpher_applies_normal_to_recovery() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(outcome.is_applied());
}

#[test]
fn morpher_applies_through_multiple_regimes() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(m.applied_count >= 1);
    m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(m.applied_count >= 2);
}

// ---------------------------------------------------------------------------
// Morpher — fallback
// ---------------------------------------------------------------------------

#[test]
fn morpher_fallback_on_abstention_target() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Abstention);
    assert!(outcome.is_rejected());
    assert!(m.is_in_fallback());
    assert_eq!(m.current_profile().name, m.anchor_profile().name);
}

#[test]
fn morpher_fallback_on_zero_budget() {
    let anchor = make_anchor();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 0, 0);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in make_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_rejected());
    assert!(m.is_in_fallback());
}

#[test]
fn morpher_fallback_increments_count() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    assert_eq!(m.fallback_count, 0);
    m.morph(RegimeLabel::Abstention);
    assert_eq!(m.fallback_count, 1);
}

// ---------------------------------------------------------------------------
// Morpher — cooldown
// ---------------------------------------------------------------------------

#[test]
fn morpher_cooldown_blocks_after_fallback() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    // Trigger fallback.
    m.morph(RegimeLabel::Abstention);
    assert!(m.is_in_fallback());
    // Immediate morph should be blocked by cooldown.
    m.current_regime = RegimeLabel::Abstention;
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_rejected());
}

#[test]
fn morpher_cooldown_expires() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    // Simulate cooldown expiry.
    m.steps_since_fallback = FALLBACK_COOLDOWN_STEPS + 1;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_applied());
}

// ---------------------------------------------------------------------------
// Morpher — budget exhaustion
// ---------------------------------------------------------------------------

#[test]
fn morpher_budget_exhaustion_after_max_steps() {
    let anchor = make_anchor();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 10_000_000);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in make_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    // Skip cooldown.
    m.steps_since_fallback = 100;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Elevated);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(outcome.is_rejected());
}

#[test]
fn morpher_budget_reset_allows_new_transitions() {
    let anchor = make_anchor();
    let budget = TransitionBudget::new(SecurityEpoch::from_raw(1), 1, 10_000_000);
    let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
    for (regime, profile) in make_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    // Reset budget.
    m.reset_budget(SecurityEpoch::from_raw(2));
    m.steps_since_fallback = 100;
    m.in_fallback = false;
    m.current_regime = RegimeLabel::Classified(Regime::Elevated);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Recovery));
    assert!(outcome.is_applied());
}

// ---------------------------------------------------------------------------
// Morpher — history tracking
// ---------------------------------------------------------------------------

#[test]
fn morpher_history_records_all_steps() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated)); // noop
    assert_eq!(m.history.len(), 2);
}

#[test]
fn morpher_history_step_seq_monotonic() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    m.morph(RegimeLabel::Classified(Regime::Recovery));

    let seqs: Vec<u64> = m.history.iter().map(|s| s.seq).collect();
    for w in seqs.windows(2) {
        assert!(w[0] < w[1], "non-monotonic: {} >= {}", w[0], w[1]);
    }
}

#[test]
fn morpher_history_evidence_hashes_present() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    for step in &m.history {
        assert!(!step.evidence_hash.is_empty());
        assert_eq!(step.evidence_hash.len(), 64);
    }
}

// ---------------------------------------------------------------------------
// Morpher — summary
// ---------------------------------------------------------------------------

#[test]
fn morpher_summary_reflects_state() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Classified(Regime::Elevated));
    let s = m.summary();
    assert_eq!(s.step_count, 1);
    assert_eq!(s.applied_count, m.applied_count);
    assert_eq!(s.fallback_count, 0);
    assert!(!s.in_fallback);
}

#[test]
fn morpher_summary_after_fallback() {
    let mut m = make_morpher(1);
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    m.morph(RegimeLabel::Abstention);
    let s = m.summary();
    assert_eq!(s.fallback_count, 1);
    assert!(s.in_fallback);
}

// ---------------------------------------------------------------------------
// MorphingRejection Display and as_str
// ---------------------------------------------------------------------------

#[test]
fn rejection_display_matches_as_str() {
    let rejections = [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::StepTooLarge,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::EntropyTooHigh,
        MorphingRejection::CooldownActive,
        MorphingRejection::SourceAbstention,
        MorphingRejection::NoTargetProfile,
    ];
    for r in rejections {
        assert_eq!(r.to_string(), r.as_str());
        assert!(!r.as_str().is_empty());
    }
}

#[test]
fn rejection_serde_roundtrip() {
    for r in [
        MorphingRejection::BudgetExhausted,
        MorphingRejection::EntropyTooLow,
        MorphingRejection::NoTargetProfile,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: MorphingRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ---------------------------------------------------------------------------
// MorphingOutcome predicates
// ---------------------------------------------------------------------------

#[test]
fn outcome_applied_predicates() {
    let o = MorphingOutcome::Applied {
        distance_millionths: 100,
        new_entropy_millionths: 500_000,
    };
    assert!(o.is_applied());
    assert!(!o.is_rejected());
}

#[test]
fn outcome_rejected_predicates() {
    let o = MorphingOutcome::Rejected {
        reason: MorphingRejection::BudgetExhausted,
    };
    assert!(o.is_rejected());
    assert!(!o.is_applied());
}

#[test]
fn outcome_noop_predicates() {
    let o = MorphingOutcome::NoOp;
    assert!(!o.is_applied());
    assert!(!o.is_rejected());
}

// ---------------------------------------------------------------------------
// MorphingSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_display_matches_as_str() {
    for f in MorphingSpecimenFamily::ALL {
        assert_eq!(f.to_string(), f.as_str());
    }
}

#[test]
fn specimen_family_serde_roundtrip() {
    for f in MorphingSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: MorphingSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn default_transition_budget_positive() {
    assert!(DEFAULT_TRANSITION_BUDGET > 0);
}

#[test]
fn max_step_distance_positive() {
    assert!(MAX_STEP_DISTANCE_MILLIONTHS > 0);
}

#[test]
fn entropy_bounds_ordered() {
    assert!(MIN_ENTROPY_MILLIONTHS < MAX_ENTROPY_MILLIONTHS);
}

#[test]
fn cooldown_steps_positive() {
    assert!(FALLBACK_COOLDOWN_STEPS > 0);
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

#[test]
fn bundle_writer_creates_four_files() {
    let dir = std::env::temp_dir().join("pearl_morphing_bundle_test_1");
    let _ = std::fs::remove_dir_all(&dir);
    let result = entropic_policy_morphing::write_morphing_evidence_bundle(
        &dir,
        &["cargo test --lib entropic_policy_morphing".to_string()],
    );
    assert!(result.is_ok(), "bundle writer failed: {:?}", result.err());
    let artifacts = result.unwrap();
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_json_is_valid() {
    let dir = std::env::temp_dir().join("pearl_morphing_bundle_test_2");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let json = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: MorphingEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert!(inv.contract_satisfied());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_manifest_has_correct_policy_id() {
    let dir = std::env::temp_dir().join("pearl_morphing_bundle_test_3");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest["policy_id"].as_str().unwrap(), MORPHING_POLICY_ID);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_events_jsonl_has_start_and_end() {
    let dir = std::env::temp_dir().join("pearl_morphing_bundle_test_4");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = entropic_policy_morphing::write_morphing_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 2);
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(first["event"].as_str().unwrap().contains("started"));
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert!(last["event"].as_str().unwrap().contains("completed"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_hash_deterministic() {
    let dir1 = std::env::temp_dir().join("pearl_morphing_bundle_test_5a");
    let dir2 = std::env::temp_dir().join("pearl_morphing_bundle_test_5b");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
    let a = entropic_policy_morphing::write_morphing_evidence_bundle(&dir1, &[]).unwrap();
    let b = entropic_policy_morphing::write_morphing_evidence_bundle(&dir2, &[]).unwrap();
    assert_eq!(a.inventory_hash, b.inventory_hash);
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

// ---------------------------------------------------------------------------
// No-target-profile rejection
// ---------------------------------------------------------------------------

#[test]
fn morpher_rejects_unknown_regime_profile() {
    let anchor = make_anchor();
    let epoch = SecurityEpoch::from_raw(1);
    let mut m = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    // Don't register any profiles.
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    assert!(outcome.is_rejected());
}

// ---------------------------------------------------------------------------
// Interpolation
// ---------------------------------------------------------------------------

#[test]
fn interpolation_reduces_step_distance() {
    let anchor = make_anchor();
    let epoch = SecurityEpoch::from_raw(1);
    let config = MorphingConfig {
        max_step_distance_millionths: 100_000,
        interpolation_rate_millionths: 200_000,
        ..MorphingConfig::default()
    };
    let mut m = EntropicPolicyMorpher::new(anchor, TransitionBudget::with_defaults(epoch), config);
    for (regime, profile) in make_profiles() {
        m.register_profile(regime, profile);
    }
    m.current_regime = RegimeLabel::Classified(Regime::Normal);
    let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
    // With interpolation rate 0.2, the blended profile should be close to current.
    assert!(outcome.is_applied());
}

// ---------------------------------------------------------------------------
// Contract satisfaction edge cases
// ---------------------------------------------------------------------------

#[test]
fn contract_not_satisfied_with_failures() {
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 4,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_zero_specimens() {
    let inv = MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}
