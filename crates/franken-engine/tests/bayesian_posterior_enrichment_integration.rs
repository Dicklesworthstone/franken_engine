//! Enrichment integration tests for bayesian_posterior.

use frankenengine_engine::bayesian_posterior::{
    BayesianPosteriorUpdater, CalibrationResult, ChangePointDetector, Evidence, LikelihoodModel,
    Posterior, RiskState, UpdateResult, UpdaterStore,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn benign_evidence() -> Evidence {
    Evidence {
        extension_id: "ext-001".to_string(),
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
        extension_id: "ext-001".to_string(),
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
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: 200_000_000,
        distinct_capabilities: 6,
        resource_score_millionths: 500_000,
        timing_anomaly_millionths: 300_000,
        denial_rate_millionths: 100_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

// ---------------------------------------------------------------------------
// Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_state_copy() {
    let a = RiskState::Benign;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Clone independence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_posterior_clone_independence() {
    let a = Posterior::default_prior();
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.p_benign, b.p_benign);
}

#[test]
fn enrichment_evidence_clone_independence() {
    let a = benign_evidence();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_likelihood_model_clone_independence() {
    let a = LikelihoodModel::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_change_point_detector_clone_independence() {
    let a = ChangePointDetector::new(50_000, 50);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_updater_clone_independence() {
    let a = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let _b = a.clone();
    // Updater doesn't impl PartialEq — just verify clone compiles
    assert_eq!(a.update_count(), 0);
}

#[test]
fn enrichment_update_result_clone_independence() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let a = u.update(&benign_evidence());
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_calibration_result_clone_independence() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let a = u.calibration_check(RiskState::Benign);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_updater_store_clone_independence() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    let cloned = store.clone();
    assert_eq!(store.len(), cloned.len());
}

// ---------------------------------------------------------------------------
// BTreeSet ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_state_btreeset() {
    let set: BTreeSet<RiskState> = RiskState::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// Debug nonempty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_state_debug_nonempty() {
    for s in &RiskState::ALL {
        assert!(!format!("{:?}", s).is_empty());
    }
}

#[test]
fn enrichment_posterior_debug() {
    assert!(!format!("{:?}", Posterior::default_prior()).is_empty());
}

#[test]
fn enrichment_evidence_debug() {
    assert!(!format!("{:?}", benign_evidence()).is_empty());
}

#[test]
fn enrichment_likelihood_model_debug() {
    assert!(!format!("{:?}", LikelihoodModel::default()).is_empty());
}

#[test]
fn enrichment_change_point_detector_debug() {
    assert!(!format!("{:?}", ChangePointDetector::new(50_000, 10)).is_empty());
}

#[test]
fn enrichment_updater_debug() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    assert!(!format!("{:?}", u).is_empty());
}

#[test]
fn enrichment_update_result_debug() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&benign_evidence());
    assert!(!format!("{:?}", r).is_empty());
}

#[test]
fn enrichment_calibration_result_debug() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let c = u.calibration_check(RiskState::Benign);
    assert!(!format!("{:?}", c).is_empty());
}

#[test]
fn enrichment_updater_store_debug() {
    assert!(!format!("{:?}", UpdaterStore::new()).is_empty());
}

// ---------------------------------------------------------------------------
// Display all-unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_state_display_all_unique() {
    let displays: BTreeSet<String> = RiskState::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// Display coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_posterior_display_contains_markers() {
    let p = Posterior::default_prior();
    let s = p.to_string();
    assert!(s.contains("B="));
    assert!(s.contains("A="));
    assert!(s.contains("M="));
    assert!(s.contains("U="));
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

#[test]
fn enrichment_likelihood_model_default_positive_fields() {
    let m = LikelihoodModel::default();
    assert!(m.benign_rate_ceiling > 0);
    assert!(m.anomalous_rate_floor > m.benign_rate_ceiling);
    assert!(m.benign_denial_ceiling > 0);
    assert!(m.malicious_denial_floor > m.benign_denial_ceiling);
    assert!(m.timing_anomaly_threshold > 0);
    assert!(m.resource_threshold > 0);
}

#[test]
fn enrichment_updater_store_default() {
    let store = UpdaterStore::default();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

// ---------------------------------------------------------------------------
// JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_posterior_json_fields() {
    let p = Posterior::default_prior();
    let json = serde_json::to_string(&p).unwrap();
    for field in ["p_benign", "p_anomalous", "p_malicious", "p_unknown"] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_evidence_json_fields() {
    let ev = benign_evidence();
    let json = serde_json::to_string(&ev).unwrap();
    for field in [
        "extension_id",
        "hostcall_rate_millionths",
        "distinct_capabilities",
        "resource_score_millionths",
        "timing_anomaly_millionths",
        "denial_rate_millionths",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_likelihood_model_json_fields() {
    let m = LikelihoodModel::default();
    let json = serde_json::to_string(&m).unwrap();
    for field in [
        "benign_rate_ceiling",
        "anomalous_rate_floor",
        "benign_denial_ceiling",
        "malicious_denial_floor",
        "timing_anomaly_threshold",
        "resource_threshold",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_update_result_json_fields() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&benign_evidence());
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "posterior",
        "likelihoods",
        "cumulative_llr_millionths",
        "update_count",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_calibration_result_json_fields() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let c = u.calibration_check(RiskState::Benign);
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "ground_truth",
        "assigned_probability",
        "map_correct",
        "brier_component_millionths",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_change_point_detector_json_fields() {
    let d = ChangePointDetector::new(50_000, 10);
    let json = serde_json::to_string(&d).unwrap();
    for field in ["run_length_probs", "hazard_rate", "max_run_length"] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_state_serde_all() {
    for s in &RiskState::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: RiskState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_posterior_serde_roundtrip() {
    let p = Posterior::uniform();
    let json = serde_json::to_string(&p).unwrap();
    let back: Posterior = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_evidence_serde_roundtrip() {
    let ev = benign_evidence();
    let json = serde_json::to_string(&ev).unwrap();
    let back: Evidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_likelihood_model_serde_roundtrip() {
    let m = LikelihoodModel::default();
    let json = serde_json::to_string(&m).unwrap();
    let back: LikelihoodModel = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_update_result_serde_roundtrip() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&benign_evidence());
    let json = serde_json::to_string(&r).unwrap();
    let back: UpdateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_calibration_result_serde_roundtrip() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let c = u.calibration_check(RiskState::Malicious);
    let json = serde_json::to_string(&c).unwrap();
    let back: CalibrationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_change_point_detector_serde_roundtrip() {
    let mut d = ChangePointDetector::new(50_000, 20);
    d.update(1_000_000, 1_000_000);
    let json = serde_json::to_string(&d).unwrap();
    let back: ChangePointDetector = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_updater_store_serde_roundtrip() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    let json = serde_json::to_string(&store).unwrap();
    let back: UpdaterStore = serde_json::from_str(&json).unwrap();
    assert_eq!(store.len(), back.len());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_update_determinism_20_runs() {
    let ev = benign_evidence();
    let mut first = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r1 = first.update(&ev);
    for _ in 1..20 {
        let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let r = u.update(&ev);
        assert_eq!(r1, r);
    }
}

#[test]
fn enrichment_content_hash_determinism() {
    let u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    assert_eq!(u1.content_hash(), u2.content_hash());
}

// ---------------------------------------------------------------------------
// Posterior methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_posterior_default_prior_valid() {
    let p = Posterior::default_prior();
    assert!(p.is_valid());
    assert_eq!(p.map_estimate(), RiskState::Benign);
}

#[test]
fn enrichment_posterior_uniform_valid() {
    let p = Posterior::uniform();
    assert!(p.is_valid());
    assert_eq!(p.p_benign, 250_000);
    assert_eq!(p.p_anomalous, 250_000);
}

#[test]
fn enrichment_posterior_from_millionths_normalizes() {
    let p = Posterior::from_millionths(500, 300, 100, 100);
    assert!(p.is_valid());
}

#[test]
fn enrichment_posterior_from_millionths_zeros() {
    let p = Posterior::from_millionths(0, 0, 0, 0);
    assert!(p.is_valid());
}

#[test]
fn enrichment_posterior_from_millionths_negatives() {
    let p = Posterior::from_millionths(-100, -200, -300, -400);
    assert!(p.is_valid());
}

#[test]
fn enrichment_posterior_from_millionths_large_values() {
    let p = Posterior::from_millionths(10_000_000, 5_000_000, 3_000_000, 2_000_000);
    assert!(p.is_valid());
    assert_eq!(p.map_estimate(), RiskState::Benign);
}

#[test]
fn enrichment_posterior_probability_accessor() {
    let p = Posterior::default_prior();
    assert_eq!(p.probability(RiskState::Benign), p.p_benign);
    assert_eq!(p.probability(RiskState::Anomalous), p.p_anomalous);
    assert_eq!(p.probability(RiskState::Malicious), p.p_malicious);
    assert_eq!(p.probability(RiskState::Unknown), p.p_unknown);
}

#[test]
fn enrichment_posterior_map_malicious_dominant() {
    let p = Posterior::from_millionths(100, 100, 800, 100);
    assert_eq!(p.map_estimate(), RiskState::Malicious);
}

#[test]
fn enrichment_posterior_one_dominant() {
    let p = Posterior::from_millionths(1_000_000, 0, 0, 0);
    assert!(p.is_valid());
    assert_eq!(p.map_estimate(), RiskState::Benign);
    assert!(p.p_benign > 990_000);
    // Floor mass should ensure minor states > 0
    assert!(p.p_anomalous > 0);
    assert!(p.p_malicious > 0);
    assert!(p.p_unknown > 0);
}

// ---------------------------------------------------------------------------
// LikelihoodModel methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_likelihoods_benign_evidence() {
    let m = LikelihoodModel::default();
    let l = m.compute_likelihoods(&benign_evidence());
    assert!(
        l[0] >= l[2],
        "benign likelihood should >= malicious for benign evidence"
    );
}

#[test]
fn enrichment_likelihoods_malicious_evidence() {
    let m = LikelihoodModel::default();
    let l = m.compute_likelihoods(&malicious_evidence());
    assert!(
        l[2] > l[0],
        "malicious likelihood should > benign for malicious evidence"
    );
}

#[test]
fn enrichment_likelihoods_floor_prevents_zero() {
    let m = LikelihoodModel::default();
    let l = m.compute_likelihoods(&malicious_evidence());
    for ll in &l {
        assert!(*ll > 0, "likelihood must be > 0: {ll}");
    }
}

#[test]
fn enrichment_likelihoods_unknown_always_million() {
    let m = LikelihoodModel::default();
    // Unknown likelihood is always uniform
    let l = m.compute_likelihoods(&benign_evidence());
    assert_eq!(l[3], 1_000_000);
}

#[test]
fn enrichment_likelihoods_anomalous_evidence() {
    let m = LikelihoodModel::default();
    let l = m.compute_likelihoods(&anomalous_evidence());
    // For elevated-rate evidence, anomalous likelihood should be > benign
    assert!(
        l[1] > l[0],
        "anomalous likelihood should > benign for anomalous evidence"
    );
}

// ---------------------------------------------------------------------------
// BayesianPosteriorUpdater methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_updater_new_initial_state() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    assert!(u.posterior().is_valid());
    assert_eq!(u.update_count(), 0);
    assert_eq!(u.extension_id(), "ext-001");
    assert_eq!(u.log_likelihood_ratio(), 0);
    assert!(u.evidence_hashes().is_empty());
}

#[test]
fn enrichment_updater_with_model() {
    let model = LikelihoodModel::default();
    let u = BayesianPosteriorUpdater::with_model(Posterior::uniform(), "ext-002", model);
    assert_eq!(u.extension_id(), "ext-002");
    assert_eq!(u.posterior().p_benign, 250_000);
}

#[test]
fn enrichment_updater_single_benign_stays_benign() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&benign_evidence());
    assert!(r.posterior.is_valid());
    assert_eq!(r.posterior.map_estimate(), RiskState::Benign);
    assert_eq!(r.update_count, 1);
}

#[test]
fn enrichment_updater_malicious_shifts_toward_malicious() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let before = u.posterior().p_malicious;
    u.update(&malicious_evidence());
    assert!(u.posterior().p_malicious > before);
}

#[test]
fn enrichment_updater_10_malicious_converges() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..10 {
        u.update(&malicious_evidence());
    }
    assert_eq!(u.posterior().map_estimate(), RiskState::Malicious);
}

#[test]
fn enrichment_updater_10_benign_remains_benign() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..10 {
        u.update(&benign_evidence());
    }
    assert_eq!(u.posterior().map_estimate(), RiskState::Benign);
    assert!(u.posterior().p_benign > 800_000);
}

#[test]
fn enrichment_updater_count_increments() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&benign_evidence());
    u.update(&malicious_evidence());
    u.update(&anomalous_evidence());
    assert_eq!(u.update_count(), 3);
}

#[test]
fn enrichment_updater_evidence_hashes_tracked() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&benign_evidence());
    u.update(&malicious_evidence());
    assert_eq!(u.evidence_hashes().len(), 2);
    assert_ne!(u.evidence_hashes()[0], u.evidence_hashes()[1]);
}

#[test]
fn enrichment_updater_reset_clears_state() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&malicious_evidence());
    u.update(&malicious_evidence());
    u.reset(Posterior::default_prior());
    assert_eq!(u.update_count(), 0);
    assert_eq!(u.log_likelihood_ratio(), 0);
    assert!(u.evidence_hashes().is_empty());
    assert_eq!(*u.posterior(), Posterior::default_prior());
}

#[test]
fn enrichment_updater_set_epoch() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.set_epoch(SecurityEpoch::from_raw(42));
    // No getter for epoch on public API, but set_epoch shouldn't panic
}

#[test]
fn enrichment_updater_content_hash_changes_after_update() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let h1 = u.content_hash();
    u.update(&benign_evidence());
    let h2 = u.content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_updater_content_hash_varies_by_extension() {
    let u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-002");
    assert_ne!(u1.content_hash(), u2.content_hash());
}

// ---------------------------------------------------------------------------
// LLR direction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_llr_positive_malicious() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&malicious_evidence());
    assert!(u.log_likelihood_ratio() > 0);
}

#[test]
fn enrichment_llr_negative_benign() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&benign_evidence());
    assert!(u.log_likelihood_ratio() <= 0);
}

// ---------------------------------------------------------------------------
// ChangePointDetector
// ---------------------------------------------------------------------------

#[test]
fn enrichment_change_detector_initial() {
    let d = ChangePointDetector::new(50_000, 50);
    assert_eq!(d.change_point_probability(), 1_000_000);
    assert_eq!(d.map_run_length(), 0);
}

#[test]
fn enrichment_change_detector_stable_regime() {
    let mut d = ChangePointDetector::new(50_000, 50);
    for _ in 0..10 {
        d.update(1_000_000, 1_000_000);
    }
    assert!(d.change_point_probability() < 200_000);
    assert!(d.map_run_length() > 0);
}

#[test]
fn enrichment_change_detector_reset() {
    let mut d = ChangePointDetector::new(50_000, 50);
    for _ in 0..10 {
        d.update(1_000_000, 1_000_000);
    }
    d.reset();
    assert_eq!(d.change_point_probability(), 1_000_000);
    assert_eq!(d.map_run_length(), 0);
}

#[test]
fn enrichment_change_detector_min_run_length() {
    let d = ChangePointDetector::new(50_000, 1);
    assert_eq!(d.change_point_probability(), 1_000_000);
}

// ---------------------------------------------------------------------------
// CalibrationResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_calibration_benign_correct() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..5 {
        u.update(&benign_evidence());
    }
    let c = u.calibration_check(RiskState::Benign);
    assert!(c.map_correct);
    assert!(c.assigned_probability > 500_000);
    assert!(c.brier_component_millionths < 500_000);
}

#[test]
fn enrichment_calibration_wrong_map() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let c = u.calibration_check(RiskState::Malicious);
    assert!(!c.map_correct);
    assert!(c.assigned_probability < 100_000);
}

#[test]
fn enrichment_calibration_all_states() {
    let u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for s in &RiskState::ALL {
        let c = u.calibration_check(*s);
        assert_eq!(c.ground_truth, *s);
        assert!(c.brier_component_millionths >= 0);
    }
}

// ---------------------------------------------------------------------------
// UpdaterStore
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_new_empty() {
    let store = UpdaterStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn enrichment_store_get_or_create_idempotent() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    assert_eq!(store.len(), 1);
    store.get_or_create("ext-001");
    assert_eq!(store.len(), 1);
}

#[test]
fn enrichment_store_multiple_extensions() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    store.get_or_create("ext-003");
    assert_eq!(store.len(), 3);
    assert!(!store.is_empty());
}

#[test]
fn enrichment_store_get_readonly() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    assert!(store.get("ext-001").is_some());
    assert!(store.get("ext-999").is_none());
}

#[test]
fn enrichment_store_risky_extensions() {
    let mut store = UpdaterStore::new();
    let u1 = store.get_or_create("ext-001");
    for _ in 0..10 {
        u1.update(&malicious_evidence());
    }
    store.get_or_create("ext-002");
    let risky = store.risky_extensions(500_000);
    assert_eq!(risky.len(), 1);
    assert_eq!(risky[0].0, "ext-001");
}

#[test]
fn enrichment_store_risky_extensions_none() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    store.get_or_create("ext-002");
    let risky = store.risky_extensions(500_000);
    assert!(risky.is_empty());
}

#[test]
fn enrichment_store_summary() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-001");
    let u2 = store.get_or_create("ext-002");
    for _ in 0..10 {
        u2.update(&malicious_evidence());
    }
    let summary = store.summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary.get("ext-001"), Some(&RiskState::Benign));
    assert_eq!(summary.get("ext-002"), Some(&RiskState::Malicious));
}

// ---------------------------------------------------------------------------
// BOCPD regime change
// ---------------------------------------------------------------------------

#[test]
fn enrichment_bocpd_regime_change_detectable() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for _ in 0..20 {
        u.update(&benign_evidence());
    }
    let cp_before = u.change_point_probability();
    for _ in 0..5 {
        u.update(&malicious_evidence());
    }
    let cp_after = u.change_point_probability();
    assert!(
        cp_after != cp_before || u.posterior().map_estimate() != RiskState::Benign,
        "regime change should be detectable"
    );
}

// ---------------------------------------------------------------------------
// Posterior invariant after mixed updates
// ---------------------------------------------------------------------------

#[test]
fn enrichment_posterior_valid_after_mixed_updates() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&benign_evidence());
    u.update(&malicious_evidence());
    u.update(&anomalous_evidence());
    u.update(&benign_evidence());
    assert!(u.posterior().is_valid());
}

#[test]
fn enrichment_posterior_valid_after_50_updates() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    for i in 0..50 {
        if i % 3 == 0 {
            u.update(&malicious_evidence());
        } else {
            u.update(&benign_evidence());
        }
    }
    assert!(u.posterior().is_valid());
    assert_eq!(u.update_count(), 50);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_zero_evidence_features() {
    let ev = Evidence {
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: 0,
        distinct_capabilities: 0,
        resource_score_millionths: 0,
        timing_anomaly_millionths: 0,
        denial_rate_millionths: 0,
        epoch: SecurityEpoch::GENESIS,
    };
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&ev);
    assert!(r.posterior.is_valid());
}

#[test]
fn enrichment_extreme_values_no_panic() {
    let ev = Evidence {
        extension_id: "ext-001".to_string(),
        hostcall_rate_millionths: i64::MAX / 2,
        distinct_capabilities: u32::MAX,
        resource_score_millionths: 1_000_000,
        timing_anomaly_millionths: 1_000_000,
        denial_rate_millionths: 1_000_000,
        epoch: SecurityEpoch::from_raw(u64::MAX),
    };
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    let r = u.update(&ev);
    assert!(r.posterior.is_valid());
}

#[test]
fn enrichment_anomalous_shifts_from_uniform() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::uniform(), "ext-001");
    for _ in 0..5 {
        u.update(&anomalous_evidence());
    }
    assert!(u.posterior().p_anomalous > u.posterior().p_benign);
}

#[test]
fn enrichment_updater_serde_preserves_state() {
    let mut u = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
    u.update(&benign_evidence());
    u.update(&malicious_evidence());
    let json = serde_json::to_string(&u).unwrap();
    let restored: BayesianPosteriorUpdater = serde_json::from_str(&json).unwrap();
    assert_eq!(u.posterior(), restored.posterior());
    assert_eq!(u.update_count(), restored.update_count());
    assert_eq!(u.log_likelihood_ratio(), restored.log_likelihood_ratio());
    assert_eq!(u.content_hash(), restored.content_hash());
}
