#![forbid(unsafe_code)]

//! Metamorphic test for FrankenEngine decision determinism invariant.
//!
//! Tests the critical semantic property that decision-making functions produce
//! identical outputs when given identical inputs, regardless of:
//! - Execution timing
//! - Memory layout
//! - System state variations
//! - Thread scheduling differences
//!
//! This test exercises the real engine's runtime_decision_core without mocks.

use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

use frankenengine_engine::runtime_decision_core::{
    AsymmetricLossPolicy, RegimeEstimate, RiskDimension, default_routing_loss_policy,
};

/// Number of decision iterations to test determinism
const DETERMINISM_TEST_ITERATIONS: usize = 100;

/// Number of concurrent threads to stress test determinism under parallelism
const CONCURRENT_THREADS: usize = 8;

#[test]
fn test_decision_determinism_under_identical_conditions() {
    // Metamorphic property: Identical inputs → Identical outputs (always)
    println!("Testing decision determinism metamorphic property...");

    let policy = create_test_loss_policy();
    let risk_posteriors = create_test_risk_posteriors();
    let regime = RegimeEstimate::Normal;

    let candidates = vec![
        "select:baseline_deterministic_profile".to_string(),
        "select:baseline_throughput_profile".to_string(),
        "fallback:safe_mode".to_string(),
        "hold".to_string(),
    ];

    // First decision as reference
    let reference_decision = policy.select_min_loss_action(&candidates, &risk_posteriors, regime);

    println!("Reference decision: {:?}", reference_decision);

    // Test determinism across multiple iterations
    for iteration in 1..=DETERMINISM_TEST_ITERATIONS {
        let decision = policy.select_min_loss_action(&candidates, &risk_posteriors, regime);

        assert_eq!(
            reference_decision, decision,
            "DETERMINISM VIOLATION: iteration {} produced different decision.\n\
             Reference: {:?}\n\
             Current:   {:?}\n\
             This violates the core deterministic execution invariant!",
            iteration, reference_decision, decision
        );
    }

    println!(
        "✅ Decision determinism verified across {} iterations",
        DETERMINISM_TEST_ITERATIONS
    );
}

#[test]
fn test_decision_determinism_across_different_regimes() {
    // Metamorphic property: Same inputs + different regimes → predictable transformation
    println!("Testing decision determinism across regime changes...");

    let policy = create_comprehensive_loss_policy();
    let risk_posteriors = create_test_risk_posteriors();

    let candidates = vec![
        "select:baseline_deterministic_profile".to_string(),
        "select:baseline_throughput_profile".to_string(),
        "fallback:safe_mode".to_string(),
    ];

    let regimes = [
        RegimeEstimate::Normal,
        RegimeEstimate::Elevated,
        RegimeEstimate::Attack,
        RegimeEstimate::Degraded,
        RegimeEstimate::Recovery,
    ];

    // Create deterministic baseline for each regime
    let mut regime_decisions = BTreeMap::new();

    for regime in &regimes {
        let decision = policy.select_min_loss_action(&candidates, &risk_posteriors, *regime);
        regime_decisions.insert(*regime, decision.clone());
        println!("Regime {:?}: {:?}", regime, decision);
    }

    // Test determinism within each regime (metamorphic invariant)
    for regime in &regimes {
        for iteration in 1..=20 {
            let decision = policy.select_min_loss_action(&candidates, &risk_posteriors, *regime);

            let reference = &regime_decisions[regime];
            assert_eq!(
                reference, &decision,
                "REGIME DETERMINISM VIOLATION: regime {:?} iteration {} inconsistent.\n\
                 Reference: {:?}\n\
                 Current:   {:?}",
                regime, iteration, reference, decision
            );
        }
    }

    println!("✅ Decision determinism verified across all regime types");
}

#[test]
fn test_decision_determinism_under_concurrent_access() {
    // Metamorphic property: Concurrent identical calls → identical results
    println!("Testing decision determinism under concurrent access...");

    let policy = create_test_loss_policy();
    let risk_posteriors = create_test_risk_posteriors();
    let regime = RegimeEstimate::Normal;

    let candidates = vec![
        "select:baseline_deterministic_profile".to_string(),
        "select:baseline_throughput_profile".to_string(),
        "fallback:safe_mode".to_string(),
    ];

    // Get reference decision
    let reference_decision = policy.select_min_loss_action(&candidates, &risk_posteriors, regime);

    println!("Reference decision: {:?}", reference_decision);

    // Spawn concurrent threads making identical decisions
    let mut handles = Vec::new();

    for thread_id in 0..CONCURRENT_THREADS {
        let policy_clone = policy.clone();
        let posteriors_clone = risk_posteriors.clone();
        let candidates_clone = candidates.clone();
        let reference_clone = reference_decision.clone();

        let handle = thread::spawn(move || {
            for iteration in 0..20 {
                // Add slight timing variation to stress test
                if iteration % 3 == 0 {
                    thread::sleep(Duration::from_nanos(100));
                }

                let decision = policy_clone.select_min_loss_action(
                    &candidates_clone,
                    &posteriors_clone,
                    regime,
                );

                assert_eq!(
                    reference_clone, decision,
                    "CONCURRENCY DETERMINISM VIOLATION: thread {} iteration {} inconsistent.\n\
                     Reference: {:?}\n\
                     Current:   {:?}",
                    thread_id, iteration, reference_clone, decision
                );
            }

            println!("Thread {} completed with consistent decisions", thread_id);
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    println!("✅ Decision determinism verified under concurrent access");
}

#[test]
fn test_decision_loss_computation_determinism() {
    // Metamorphic property: Same action/posteriors/regime → same loss (always)
    println!("Testing loss computation determinism...");

    let policy = create_comprehensive_loss_policy();
    let risk_posteriors = create_varying_risk_posteriors();

    let test_actions = [
        "select:baseline_deterministic_profile",
        "select:baseline_throughput_profile",
        "fallback:safe_mode",
        "hold",
    ];

    let test_regimes = [
        RegimeEstimate::Normal,
        RegimeEstimate::Attack,
        RegimeEstimate::Degraded,
    ];

    for action in &test_actions {
        for regime in &test_regimes {
            // Compute reference loss
            let reference_loss = policy.expected_loss(action, &risk_posteriors, *regime);

            // Test determinism across multiple computations
            for iteration in 1..=50 {
                let loss = policy.expected_loss(action, &risk_posteriors, *regime);

                assert_eq!(
                    reference_loss, loss,
                    "LOSS COMPUTATION DETERMINISM VIOLATION:\n\
                     Action: {}\n\
                     Regime: {:?}\n\
                     Iteration: {}\n\
                     Reference loss: {}\n\
                     Current loss: {}",
                    action, regime, iteration, reference_loss, loss
                );
            }

            println!(
                "Action {} regime {:?}: loss = {} (deterministic)",
                action, regime, reference_loss
            );
        }
    }

    println!("✅ Loss computation determinism verified");
}

#[test]
fn test_metamorphic_risk_scaling_invariant() {
    // Metamorphic property: Scaling all risks by same factor → predictable decision change
    println!("Testing metamorphic risk scaling invariant...");

    let policy = create_test_loss_policy();
    let base_posteriors = create_test_risk_posteriors();
    let regime = RegimeEstimate::Normal;

    let candidates = vec![
        "select:baseline_deterministic_profile".to_string(),
        "select:baseline_throughput_profile".to_string(),
        "fallback:safe_mode".to_string(),
    ];

    // Get baseline decision
    let baseline_decision = policy.select_min_loss_action(&candidates, &base_posteriors, regime);

    // Scale all risks by 2x, 4x, 8x
    let scale_factors = [2, 4, 8];

    for &scale_factor in &scale_factors {
        let scaled_posteriors: BTreeMap<String, i64> = base_posteriors
            .iter()
            .map(|(k, v)| (k.clone(), v * scale_factor))
            .collect();

        let scaled_decision =
            policy.select_min_loss_action(&candidates, &scaled_posteriors, regime);

        // For this test, scaling all risks equally should preserve relative ordering
        // So the decision should remain the same (metamorphic invariant)
        assert_eq!(
            baseline_decision, scaled_decision,
            "METAMORPHIC SCALING INVARIANT VIOLATION:\n\
             Scale factor: {}x\n\
             Baseline decision: {:?}\n\
             Scaled decision: {:?}\n\
             Scaling all risks equally should preserve decision ordering!",
            scale_factor, baseline_decision, scaled_decision
        );
    }

    println!("✅ Metamorphic risk scaling invariant verified");
}

// Test data creation helpers
fn create_test_loss_policy() -> AsymmetricLossPolicy {
    default_routing_loss_policy()
}

fn create_comprehensive_loss_policy() -> AsymmetricLossPolicy {
    let mut policy = create_test_loss_policy();

    // Add regime multipliers to test regime-dependent behavior
    policy.set_regime_multiplier(RegimeEstimate::Attack, 2_000_000); // 2x multiplier
    policy.set_regime_multiplier(RegimeEstimate::Degraded, 1_500_000); // 1.5x multiplier

    policy
}

fn create_test_risk_posteriors() -> BTreeMap<String, i64> {
    let mut posteriors = BTreeMap::new();

    // Risk posteriors in millionths (1_000_000 = 100% probability)
    posteriors.insert("Compatibility".to_string(), 300_000); // 30%
    posteriors.insert("Latency".to_string(), 200_000); // 20%
    posteriors.insert("Memory".to_string(), 150_000); // 15%
    posteriors.insert("IncidentSeverity".to_string(), 100_000); // 10%

    posteriors
}

fn create_varying_risk_posteriors() -> BTreeMap<String, i64> {
    let mut posteriors = BTreeMap::new();

    // Different risk profile for variety
    posteriors.insert("Compatibility".to_string(), 500_000); // 50%
    posteriors.insert("Latency".to_string(), 400_000); // 40%
    posteriors.insert("Memory".to_string(), 300_000); // 30%
    posteriors.insert("IncidentSeverity".to_string(), 250_000); // 25%

    posteriors
}
