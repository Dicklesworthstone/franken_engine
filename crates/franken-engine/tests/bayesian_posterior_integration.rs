#![forbid(unsafe_code)]

//! Comprehensive integration tests for the `bayesian_posterior` module.
//!
//! Covers: RiskState, Posterior, Evidence, LikelihoodModel, UpdateResult,
//! CalibrationResult, ChangePointDetector, BayesianPosteriorUpdater,
//! UpdaterStore. Validates serde roundtrips, Display impls, determinism,
//! edge cases, and error-handling paths.

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

use std::collections::BTreeMap;

use frankenengine_engine::bayesian_posterior::{
    BayesianPosteriorUpdater, CalibrationResult, ChangePointDetector, Evidence, LikelihoodModel,
    Posterior, RiskState, UpdateResult, UpdaterStore,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants (mirrors from the source; kept local for test assertions)
// ---------------------------------------------------------------------------
const MILLION: i64 = 1_000_000;
const FLOOR_MASS: i64 = 100;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn benign_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-test".to_string(),
        hostcall_rate_millionths: 10_000_000,
        distinct_capabilities: 3,
        resource_score_millionths: 200_000,
        timing_anomaly_millionths: 50_000,
        denial_rate_millionths: 10_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn malicious_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-test".to_string(),
        hostcall_rate_millionths: 800_000_000,
        distinct_capabilities: 12,
        resource_score_millionths: 900_000,
        timing_anomaly_millionths: 800_000,
        denial_rate_millionths: 400_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn anomalous_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-test".to_string(),
        hostcall_rate_millionths: 200_000_000,
        distinct_capabilities: 6,
        resource_score_millionths: 500_000,
        timing_anomaly_millionths: 300_000,
        denial_rate_millionths: 100_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

// ============================================================================
// 1. RiskState tests
// ============================================================================

#[test]
fn risk_state_display_all_variants() {
    assert_eq!(RiskState::Benign.to_string(), "benign");
    assert_eq!(RiskState::Anomalous.to_string(), "anomalous");
    assert_eq!(RiskState::Malicious.to_string(), "malicious");
    assert_eq!(RiskState::Unknown.to_string(), "unknown");
}

#[test]
fn risk_state_all_has_four_variants() {
    assert_eq!(RiskState::ALL.len(), 4);
    assert_eq!(RiskState::ALL[0], RiskState::Benign);
    assert_eq!(RiskState::ALL[1], RiskState::Anomalous);
    assert_eq!(RiskState::ALL[2], RiskState::Malicious);
    assert_eq!(RiskState::ALL[3], RiskState::Unknown);
}

#[test]
fn risk_state_serde_roundtrip_all_variants() {
    for state in &RiskState::ALL {
        let json = serde_json::to_string(state).expect("serialize");
        let restored: RiskState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*state, restored);
    }
}

#[test]
fn risk_state_ord_is_consistent() {
    // Ord derives from variant order: Benign < Anomalous < Malicious < Unknown
    assert!(RiskState::Benign < RiskState::Anomalous);
    assert!(RiskState::Anomalous < RiskState::Malicious);
    assert!(RiskState::Malicious < RiskState::Unknown);
}

#[test]
fn risk_state_clone_and_eq() {
    let a = RiskState::Malicious;
    let b = a;
    assert_eq!(a, b);
}

// ============================================================================
// 2. Posterior tests
// ============================================================================

#[test]
fn posterior_default_prior_sums_to_million() {
    let p = Posterior::default_prior();
    assert!(p.is_valid());
    assert_eq!(
        p.p_benign + p.p_anomalous + p.p_malicious + p.p_unknown,
        MILLION
    );
}

#[test]
fn posterior_uniform_all_equal() {
    let p = Posterior::uniform();
    assert!(p.is_valid());
    assert_eq!(p.p_benign, 250_000);
    assert_eq!(p.p_anomalous, 250_000);
    assert_eq!(p.p_malicious, 250_000);
    assert_eq!(p.p_unknown, 250_000);
}

#[test]
fn posterior_from_millionths_normalizes_to_million() {
    let p = Posterior::from_millionths(500, 300, 100, 100);
    assert!(p.is_valid());
}

#[test]
fn posterior_from_millionths_zero_inputs_valid() {
    let p = Posterior::from_millionths(0, 0, 0, 0);
    assert!(p.is_valid());
}

#[test]
fn posterior_from_millionths_negative_inputs_clamped() {
    let p = Posterior::from_millionths(-100, -200, -300, 1_000_000);
    assert!(p.is_valid());
    // Negatives clamped to 0, then floor applied, then normalized.
    // The dominant state (unknown) should hold most mass.
    assert!(p.p_unknown > 900_000);
}

#[test]
fn posterior_from_millionths_large_values() {
    // Use values large enough to test proportional scaling without
    // overflowing i64 during `value * MILLION / total` normalization.
    let big = 1_000_000_000_i64;
    let p = Posterior::from_millionths(big, big, big, big);
    assert!(p.is_valid());
    // Equal inputs -> uniform after normalization.
    assert_eq!(p.p_benign, p.p_anomalous);
}

#[test]
fn posterior_from_millionths_one_dominant() {
    let p = Posterior::from_millionths(MILLION, 0, 0, 0);
    assert!(p.is_valid());
    assert_eq!(p.map_estimate(), RiskState::Benign);
    assert!(p.p_benign > 990_000);
    // Floor ensures others are > 0
    assert!(p.p_anomalous > 0);
    assert!(p.p_malicious > 0);
    assert!(p.p_unknown > 0);
}

#[test]
fn posterior_probability_accessor_matches_fields() {
    let p = Posterior::default_prior();
    assert_eq!(p.probability(RiskState::Benign), p.p_benign);
    assert_eq!(p.probability(RiskState::Anomalous), p.p_anomalous);
    assert_eq!(p.probability(RiskState::Malicious), p.p_malicious);
    assert_eq!(p.probability(RiskState::Unknown), p.p_unknown);
}

#[test]
fn posterior_map_estimate_picks_highest() {
    let p = Posterior::default_prior();
    assert_eq!(p.map_estimate(), RiskState::Benign);

    let p = Posterior::from_millionths(100, 100, 800, 100);
    assert_eq!(p.map_estimate(), RiskState::Malicious);

    let p = Posterior::from_millionths(100, 800, 100, 100);
    assert_eq!(p.map_estimate(), RiskState::Anomalous);

    let p = Posterior::from_millionths(100, 100, 100, 800);
    assert_eq!(p.map_estimate(), RiskState::Unknown);
}

#[test]
fn posterior_display_contains_all_labels() {
    let p = Posterior::default_prior();
    let s = p.to_string();
    assert!(s.contains("B="), "should contain B=");
    assert!(s.contains("A="), "should contain A=");
    assert!(s.contains("M="), "should contain M=");
    assert!(s.contains("U="), "should contain U=");
    assert!(s.contains('%'), "should contain percent signs");
}

#[test]
fn posterior_display_format_stable_across_calls() {
    let p = Posterior::default_prior();
    let s1 = p.to_string();
    let s2 = p.to_string();
    assert_eq!(s1, s2);
}

#[test]
fn posterior_serde_roundtrip() {
    let p = Posterior::default_prior();
    let json = serde_json::to_string(&p).expect("serialize");
    let restored: Posterior = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, restored);
}

#[test]
fn posterior_serde_roundtrip_uniform() {
    let p = Posterior::uniform();
    let json = serde_json::to_string(&p).expect("serialize");
    let restored: Posterior = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, restored);
}

// ============================================================================
// 3. Evidence tests
// ============================================================================

#[test]
fn evidence_serde_roundtrip() {
    let ev = benign_evidence();
    let json = serde_json::to_string(&ev).expect("serialize");
    let restored: Evidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev, restored);
}

#[test]
fn evidence_serde_roundtrip_malicious() {
    let ev = malicious_evidence();
    let json = serde_json::to_string(&ev).expect("serialize");
    let restored: Evidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev, restored);
}

#[test]
fn evidence_clone_eq() {
    let a = benign_evidence();
    let b = a.clone();
    assert_eq!(a, b);
}

// ============================================================================
// 4. LikelihoodModel tests
// ============================================================================

#[test]
fn likelihood_model_default_thresholds_well_ordered() {
    let model = LikelihoodModel::default();
    assert!(model.benign_rate_ceiling > 0);
    assert!(model.anomalous_rate_floor > model.benign_rate_ceiling);
    assert!(model.malicious_denial_floor > model.benign_denial_ceiling);
}

#[test]
fn likelihood_model_benign_evidence_favors_benign() {
    let model = LikelihoodModel::default();
    let l = model.compute_likelihoods(&benign_evidence());
    assert!(
        l[0] >= l[2],
        "benign likelihood {} should >= malicious {} for benign evidence",
        l[0],
        l[2]
    );
}

#[test]
fn likelihood_model_malicious_evidence_favors_malicious() {
    let model = LikelihoodModel::default();
    let l = model.compute_likelihoods(&malicious_evidence());
    assert!(
        l[2] > l[0],
        "malicious likelihood {} should > benign {} for malicious evidence",
        l[2],
        l[0]
    );
}

#[test]
fn likelihood_model_anomalous_evidence_elevates_anomalous() {
    let model = LikelihoodModel::default();
    let l = model.compute_likelihoods(&anomalous_evidence());
    // Anomalous evidence should boost anomalous likelihood above benign.
    assert!(
        l[1] > l[0],
        "anomalous likelihood {} should > benign {} for anomalous evidence",
        l[1],
        l[0]
    );
}

#[test]
fn likelihood_model_floor_prevents_zero() {
    let model = LikelihoodModel::default();
    let l = model.compute_likelihoods(&malicious_evidence());
    for (i, ll) in l.iter().enumerate() {
        assert!(*ll >= FLOOR_MASS, "likelihood[{i}] = {ll} must be >= floor");
    }
}

#[test]
fn likelihood_model_unknown_is_always_million() {
    let model = LikelihoodModel::default();
    let l_benign = model.compute_likelihoods(&benign_evidence());
    let l_mal = model.compute_likelihoods(&malicious_evidence());
    let l_anom = model.compute_likelihoods(&anomalous_evidence());
    // Unknown likelihood is always MILLION (uniform).
    assert_eq!(l_benign[3], MILLION);
    assert_eq!(l_mal[3], MILLION);
    assert_eq!(l_anom[3], MILLION);
}

#[test]
fn likelihood_model_serde_roundtrip() {
    let model = LikelihoodModel::default();
    let json = serde_json::to_string(&model).expect("serialize");
    let restored: LikelihoodModel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(model, restored);
}

#[test]
fn likelihood_model_zero_evidence_features_all_at_million() {
    let model = LikelihoodModel::default();
    let ev = Evidence {
        extension_id: "ext-z".to_string(),
        hostcall_rate_millionths: 0,
        distinct_capabilities: 0,
        resource_score_millionths: 0,
        timing_anomaly_millionths: 0,
        denial_rate_millionths: 0,
        epoch: SecurityEpoch::GENESIS,
    };
    let l = model.compute_likelihoods(&ev);
    // All features below threshold -> all likelihoods stay at MILLION.
    assert_eq!(l[0], MILLION);
    assert_eq!(l[1], MILLION);
    assert_eq!(l[2], MILLION);
    assert_eq!(l[3], MILLION);
}

#[test]
fn likelihood_model_deterministic_same_evidence_same_output() {
    let model = LikelihoodModel::default();
    let ev = malicious_evidence();
    let l1 = model.compute_likelihoods(&ev);
    let l2 = model.compute_likelihoods(&ev);
    assert_eq!(l1, l2);
}

// ============================================================================
// 5. ChangePointDetector tests
// ============================================================================

#[test]
fn change_detector_initial_state() {
    let det = ChangePointDetector::new(50_000, 50);
    assert_eq!(det.change_point_probability(), MILLION);
    assert_eq!(det.map_run_length(), 0);
}

#[test]
fn change_detector_stable_regime_decreases_change_prob() {
    let mut det = ChangePointDetector::new(50_000, 50);
    for _ in 0..10 {
        det.update(MILLION, MILLION);
    }
    assert!(
        det.change_point_probability() < 200_000,
        "stable regime should have low change-point prob: {}",
        det.change_point_probability()
    );
    assert!(det.map_run_length() > 0);
}

#[test]
fn change_detector_reset_restores_initial_state() {
    let mut det = ChangePointDetector::new(50_000, 50);
    for _ in 0..10 {
        det.update(MILLION, MILLION);
    }
    det.reset();
    assert_eq!(det.change_point_probability(), MILLION);
    assert_eq!(det.map_run_length(), 0);
}

#[test]
fn change_detector_serde_roundtrip() {
    let mut det = ChangePointDetector::new(50_000, 50);
    det.update(MILLION, MILLION);
    let json = serde_json::to_string(&det).expect("serialize");
    let restored: ChangePointDetector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(det, restored);
}

#[test]
fn change_detector_high_hazard_stays_near_change_point() {
    // With very high hazard rate (90%), the detector should keep high
    // change-point probability even after updates.
    let mut det = ChangePointDetector::new(900_000, 20);
    for _ in 0..10 {
        det.update(MILLION, MILLION);
    }
    // With 90% hazard, change-point probability remains substantial.
    assert!(
        det.change_point_probability() > 100_000,
        "high hazard should maintain elevated change-point prob: {}",
        det.change_point_probability()
    );
}

#[test]
fn change_detector_zero_hazard_no_change_points() {
    // With 0% hazard, all mass stays at growing run length.
    let mut det = ChangePointDetector::new(0, 20);
    for _ in 0..10 {
        det.update(MILLION, MILLION);
    }
    // change_point_probability at r=0 should be ~0.
    assert_eq!(det.change_point_probability(), 0);
    assert!(det.map_run_length() > 0);
}

#[test]
fn change_detector_max_run_length_clamps() {
    let mut det = ChangePointDetector::new(10_000, 5);
    for _ in 0..20 {
        det.update(MILLION, MILLION);
    }
    // Run length cannot exceed max.
    assert!(det.map_run_length() <= 5);
}

// ============================================================================
// 6. BayesianPosteriorUpdater tests
// ============================================================================

#[test]
fn updater_new_initial_state() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    assert!(updater.posterior().is_valid());
    assert_eq!(updater.update_count(), 0);
    assert_eq!(updater.extension_id(), "ext-001");
    assert_eq!(updater.log_likelihood_ratio(), 0);
    assert!(updater.evidence_hashes().is_empty());
}

#[test]
fn updater_single_benign_update_stays_benign() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let result = updater.update(&benign_evidence());
    assert!(result.posterior.is_valid());
    assert_eq!(result.posterior.map_estimate(), RiskState::Benign);
    assert_eq!(result.update_count, 1);
}

#[test]
fn updater_single_malicious_update_increases_malicious_prob() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let before = updater.posterior().p_malicious;
    updater.update(&malicious_evidence());
    let after = updater.posterior().p_malicious;
    assert!(
        after > before,
        "malicious evidence should increase P(Malicious)"
    );
}

#[test]
fn updater_multiple_malicious_updates_converge_to_malicious() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..10 {
        updater.update(&malicious_evidence());
    }
    assert_eq!(updater.posterior().map_estimate(), RiskState::Malicious);
}

#[test]
fn updater_multiple_benign_updates_remain_benign() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..10 {
        updater.update(&benign_evidence());
    }
    assert_eq!(updater.posterior().map_estimate(), RiskState::Benign);
    assert!(updater.posterior().p_benign > 800_000);
}

#[test]
fn updater_anomalous_evidence_shifts_toward_anomalous() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::uniform(), "ext-001");
    for _ in 0..5 {
        updater.update(&anomalous_evidence());
    }
    let p = updater.posterior();
    assert!(
        p.p_anomalous > p.p_benign,
        "anomalous evidence should push P(Anomalous) above P(Benign)"
    );
}

#[test]
fn updater_update_count_increments_correctly() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for i in 0..7 {
        assert_eq!(updater.update_count(), i);
        updater.update(&benign_evidence());
    }
    assert_eq!(updater.update_count(), 7);
}

#[test]
fn updater_evidence_hashes_tracked() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.update(&benign_evidence());
    updater.update(&malicious_evidence());
    updater.update(&anomalous_evidence());
    assert_eq!(updater.evidence_hashes().len(), 3);
}

#[test]
fn updater_reset_clears_all_state() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..5 {
        updater.update(&malicious_evidence());
    }
    let prior = Posterior::default_prior();
    updater.reset(prior.clone());
    assert_eq!(updater.update_count(), 0);
    assert_eq!(updater.log_likelihood_ratio(), 0);
    assert!(updater.evidence_hashes().is_empty());
    assert_eq!(*updater.posterior(), prior);
    assert_eq!(updater.change_point_probability(), MILLION);
}

#[test]
fn updater_set_epoch() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.set_epoch(SecurityEpoch::from_raw(42));
    // No public getter for epoch on updater; just verify it doesn't panic.
}

#[test]
fn updater_llr_positive_for_malicious_evidence() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.update(&malicious_evidence());
    assert!(
        updater.log_likelihood_ratio() > 0,
        "LLR should be positive for malicious evidence: {}",
        updater.log_likelihood_ratio()
    );
}

#[test]
fn updater_llr_nonpositive_for_benign_evidence() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.update(&benign_evidence());
    assert!(
        updater.log_likelihood_ratio() <= 0,
        "LLR should be <= 0 for benign evidence: {}",
        updater.log_likelihood_ratio()
    );
}

#[test]
fn updater_deterministic_same_inputs_same_outputs() {
    let ev = benign_evidence();
    let mut u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let mut u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");

    u1.update(&ev);
    u2.update(&ev);

    assert_eq!(u1.posterior(), u2.posterior());
    assert_eq!(u1.log_likelihood_ratio(), u2.log_likelihood_ratio());
    assert_eq!(u1.content_hash(), u2.content_hash());
    assert_eq!(u1.update_count(), u2.update_count());
}

#[test]
fn updater_content_hash_deterministic_at_creation() {
    let u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    assert_eq!(u1.content_hash(), u2.content_hash());
}

#[test]
fn updater_content_hash_changes_after_update() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let hash_before = updater.content_hash();
    updater.update(&malicious_evidence());
    let hash_after = updater.content_hash();
    assert_ne!(hash_before, hash_after);
}

#[test]
fn updater_content_hash_changes_with_different_extension_id() {
    let u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-002");
    assert_ne!(u1.content_hash(), u2.content_hash());
}

#[test]
fn updater_with_model_uses_custom_model() {
    let model = LikelihoodModel {
        benign_rate_ceiling: 50_000_000,
        anomalous_rate_floor: 200_000_000,
        benign_denial_ceiling: 25_000,
        malicious_denial_floor: 100_000,
        timing_anomaly_threshold: 250_000,
        resource_threshold: 350_000,
    };
    let mut updater =
        BayesianPosteriorUpdater::with_model(Posterior::default_prior(), "ext-custom", model);
    let result = updater.update(&benign_evidence());
    assert!(result.posterior.is_valid());
}

#[test]
fn updater_serde_roundtrip() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.update(&benign_evidence());
    updater.update(&malicious_evidence());
    let json = serde_json::to_string(&updater).expect("serialize");
    let restored: BayesianPosteriorUpdater = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(updater.posterior(), restored.posterior());
    assert_eq!(updater.update_count(), restored.update_count());
    assert_eq!(
        updater.log_likelihood_ratio(),
        restored.log_likelihood_ratio()
    );
    assert_eq!(updater.extension_id(), restored.extension_id());
    assert_eq!(
        updater.evidence_hashes().len(),
        restored.evidence_hashes().len()
    );
}

#[test]
fn updater_posterior_always_valid_after_updates() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..50 {
        updater.update(&malicious_evidence());
        assert!(updater.posterior().is_valid());
    }
    for _ in 0..50 {
        updater.update(&benign_evidence());
        assert!(updater.posterior().is_valid());
    }
}

// ============================================================================
// 7. UpdateResult tests
// ============================================================================

#[test]
fn update_result_serde_roundtrip() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let result = updater.update(&benign_evidence());
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: UpdateResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn update_result_contains_correct_update_count() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for i in 1..=5 {
        let result = updater.update(&benign_evidence());
        assert_eq!(result.update_count, i);
    }
}

#[test]
fn update_result_likelihoods_match_model() {
    let model = LikelihoodModel::default();
    let ev = benign_evidence();
    let expected = model.compute_likelihoods(&ev);

    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let result = updater.update(&ev);
    assert_eq!(result.likelihoods, expected);
}

// ============================================================================
// 8. CalibrationResult tests
// ============================================================================

#[test]
fn calibration_check_benign_correct() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..5 {
        updater.update(&benign_evidence());
    }
    let cal = updater.calibration_check(RiskState::Benign);
    assert!(cal.map_correct);
    assert!(cal.assigned_probability > 500_000);
    assert!(cal.brier_component_millionths < 500_000);
    assert_eq!(cal.ground_truth, RiskState::Benign);
}

#[test]
fn calibration_check_malicious_after_default_prior() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let cal = updater.calibration_check(RiskState::Malicious);
    assert!(!cal.map_correct);
    assert!(cal.assigned_probability < 100_000);
    assert_eq!(cal.ground_truth, RiskState::Malicious);
}

#[test]
fn calibration_check_all_ground_truths() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for state in &RiskState::ALL {
        let cal = updater.calibration_check(*state);
        assert_eq!(cal.ground_truth, *state);
        assert!(cal.assigned_probability >= 0);
        assert!(cal.brier_component_millionths >= 0);
    }
}

#[test]
fn calibration_result_serde_roundtrip() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let cal = updater.calibration_check(RiskState::Benign);
    let json = serde_json::to_string(&cal).expect("serialize");
    let restored: CalibrationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cal, restored);
}

#[test]
fn calibration_brier_score_zero_for_perfect() {
    // If posterior is 100% on the ground truth, Brier component should be ~0.
    // With floor mass, we cannot get exactly 0, but should be very small.
    let p = Posterior::from_millionths(MILLION, 0, 0, 0);
    let updater = BayesianPosteriorUpdater::new(p, "ext-001");
    // Don't update, just calibrate.
    let cal = updater.calibration_check(RiskState::Benign);
    // p_benign is >99%, so Brier is very small.
    assert!(cal.brier_component_millionths < 1000);
}

// ============================================================================
// 9. UpdaterStore tests
// ============================================================================

#[test]
fn store_new_is_empty() {
    let store = UpdaterStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn store_get_or_create_creates_new() {
    let mut store = UpdaterStore::new();
    let updater = store.get_or_create("ext-001");
    assert_eq!(updater.extension_id(), "ext-001");
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn store_get_or_create_returns_existing() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    let updater = store.get_or_create("ext-001");
    updater.update(&benign_evidence());
    assert_eq!(store.len(), 1);
    assert_eq!(store.get("ext-001").unwrap().update_count(), 1);
}

#[test]
fn store_multiple_extensions() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    store.get_or_create("ext-003");
    assert_eq!(store.len(), 3);
}

#[test]
fn store_get_nonexistent_returns_none() {
    let store = UpdaterStore::new();
    assert!(store.get("ext-999").is_none());
}

#[test]
fn store_risky_extensions() {
    let mut store = UpdaterStore::new();
    let u1 = store.get_or_create("ext-001");
    for _ in 0..10 {
        u1.update(&malicious_evidence());
    }
    store.get_or_create("ext-002"); // Default prior (benign)

    let risky = store.risky_extensions(500_000);
    assert_eq!(risky.len(), 1);
    assert_eq!(risky[0].0, "ext-001");
}

#[test]
fn store_risky_extensions_empty_when_all_benign() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    // Default priors are 85% benign, well above 50%.
    let risky = store.risky_extensions(500_000);
    assert!(risky.is_empty());
}

#[test]
fn store_summary_returns_btreemap() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    let u2 = store.get_or_create("ext-002");
    for _ in 0..10 {
        u2.update(&malicious_evidence());
    }

    let summary: BTreeMap<String, RiskState> = store.summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary.get("ext-001"), Some(&RiskState::Benign));
    assert_eq!(summary.get("ext-002"), Some(&RiskState::Malicious));
}

#[test]
fn store_serde_roundtrip() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    let json = serde_json::to_string(&store).expect("serialize");
    let restored: UpdaterStore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(store.len(), restored.len());
    assert!(restored.get("ext-001").is_some());
    assert!(restored.get("ext-002").is_some());
}

// ============================================================================
// 10. BOCPD integration with updater
// ============================================================================

#[test]
fn bocpd_regime_shift_detected() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    // Establish benign regime.
    for _ in 0..20 {
        updater.update(&benign_evidence());
    }
    let cp_before = updater.change_point_probability();

    // Switch to malicious.
    for _ in 0..5 {
        updater.update(&malicious_evidence());
    }
    let cp_after = updater.change_point_probability();

    // The regime change should be detectable: either change-point probability
    // increases or the MAP estimate shifts.
    assert!(
        cp_after != cp_before || updater.posterior().map_estimate() != RiskState::Benign,
        "regime change should be detectable"
    );
}

// ============================================================================
// 11. Edge cases
// ============================================================================

#[test]
fn zero_evidence_features_no_panic() {
    let ev = Evidence {
        extension_id: "ext-zero".to_string(),
        hostcall_rate_millionths: 0,
        distinct_capabilities: 0,
        resource_score_millionths: 0,
        timing_anomaly_millionths: 0,
        denial_rate_millionths: 0,
        epoch: SecurityEpoch::GENESIS,
    };
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-zero");
    let result = updater.update(&ev);
    assert!(result.posterior.is_valid());
}

#[test]
fn extreme_values_no_panic() {
    let ev = Evidence {
        extension_id: "ext-extreme".to_string(),
        hostcall_rate_millionths: i64::MAX / 2,
        distinct_capabilities: u32::MAX,
        resource_score_millionths: MILLION,
        timing_anomaly_millionths: MILLION,
        denial_rate_millionths: MILLION,
        epoch: SecurityEpoch::from_raw(u64::MAX),
    };
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-extreme");
    let result = updater.update(&ev);
    assert!(result.posterior.is_valid());
}

#[test]
fn updater_many_sequential_updates_no_overflow() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-stress");
    for _ in 0..200 {
        updater.update(&malicious_evidence());
        assert!(updater.posterior().is_valid());
    }
    for _ in 0..200 {
        updater.update(&benign_evidence());
        assert!(updater.posterior().is_valid());
    }
}

#[test]
fn updater_alternating_evidence_stays_valid() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-alt");
    for i in 0u64..50 {
        if i.is_multiple_of(2) {
            updater.update(&benign_evidence());
        } else {
            updater.update(&malicious_evidence());
        }
        assert!(updater.posterior().is_valid());
    }
}

#[test]
fn empty_extension_id_is_allowed() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "");
    assert_eq!(updater.extension_id(), "");
}

#[test]
fn store_multiple_independent_updaters_do_not_interfere() {
    let mut store = UpdaterStore::new();
    let u1 = store.get_or_create("ext-001");
    for _ in 0..5 {
        u1.update(&malicious_evidence());
    }
    let u2 = store.get_or_create("ext-002");
    for _ in 0..5 {
        u2.update(&benign_evidence());
    }

    // Verify independent posteriors.
    let p1 = store.get("ext-001").unwrap().posterior();
    let p2 = store.get("ext-002").unwrap().posterior();
    assert_ne!(p1.map_estimate(), p2.map_estimate());
}

// ============================================================================
// 12. Determinism across serde boundary
// ============================================================================

#[test]
fn updater_serde_preserves_determinism() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    updater.update(&benign_evidence());
    updater.update(&malicious_evidence());

    let json = serde_json::to_string(&updater).expect("serialize");
    let mut restored: BayesianPosteriorUpdater = serde_json::from_str(&json).expect("deserialize");

    // Both should produce the same result for the same next evidence.
    let ev = anomalous_evidence();
    let r1 = updater.update(&ev);
    let r2 = restored.update(&ev);

    assert_eq!(r1.posterior, r2.posterior);
    assert_eq!(r1.likelihoods, r2.likelihoods);
    assert_eq!(r1.cumulative_llr_millionths, r2.cumulative_llr_millionths);
    assert_eq!(r1.update_count, r2.update_count);
}

// ============================================================================
// 13. Posterior normalization invariants
// ============================================================================

#[test]
fn posterior_from_millionths_equal_inputs_produces_uniform() {
    let p = Posterior::from_millionths(100, 100, 100, 100);
    assert!(p.is_valid());
    assert_eq!(p.p_benign, p.p_anomalous);
    assert_eq!(p.p_anomalous, p.p_malicious);
}

#[test]
fn posterior_from_millionths_single_nonzero() {
    let p = Posterior::from_millionths(0, 0, 1_000_000, 0);
    assert!(p.is_valid());
    assert_eq!(p.map_estimate(), RiskState::Malicious);
}

#[test]
fn posterior_probability_sum_of_all_states_is_million() {
    let p = Posterior::from_millionths(333_333, 333_333, 333_333, 1);
    let total: i64 = RiskState::ALL.iter().map(|s| p.probability(*s)).sum();
    assert_eq!(total, MILLION);
}
