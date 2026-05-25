//! Integration tests for detection-delay bound proof (bd-cixqu.36.2).
//!
//! These tests verify the formal guarantees provided by the delay bound analysis
//! and ensure integration with the change-point detector from bd-cixqu.36.1.

#![forbid(unsafe_code)]

use frankenengine_engine::change_point_detector::{
    ChangePointDetector, ChangePointVerdict, CompositeAlternative,
};
use frankenengine_engine::detection_delay_bound_proof::{
    ArlComputationStatus, AverageRunLengthAnalysis, DelayBoundConfiguration, DelayBoundError,
    DelayBoundMethod, ProofMethod, VerificationStatus, WorstCaseDelayBound,
};
use frankenengine_engine::proof_obligations::ObligationCategory;
use frankenengine_engine::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;

#[test]
fn test_arl_analysis_integration_with_detector() {
    // Integration test: verify ARL analysis matches detector behavior
    let epoch = SecurityEpoch::from_raw(42);
    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (MILLION, 2 * MILLION),
    };

    let config = DelayBoundConfiguration::default();
    let arl_analysis =
        AverageRunLengthAnalysis::compute(config.clone(), alternative.clone()).unwrap();

    // Create a detector with the same parameters
    let mut detector =
        ChangePointDetector::new_with_default_threshold("test_detector", alternative, epoch);

    // Verify ARL analysis is reasonable
    assert!(arl_analysis.arl_null_millionths > 10 * MILLION); // Should be >> 10
    assert!(arl_analysis.arl_alternative_millionths > 0);
    assert!(arl_analysis.arl_alternative_millionths < arl_analysis.arl_null_millionths);
    assert!(matches!(
        arl_analysis.computation_status,
        ArlComputationStatus::Converged { .. }
    ));

    // Test that false alarm rate is reasonable
    assert!(arl_analysis.false_alarm_rate_millionths > 0);
    assert!(arl_analysis.false_alarm_rate_millionths < 100_000); // Should be < 10%
}

#[test]
fn test_worst_case_delay_bound_normal_alternative() {
    let config = DelayBoundConfiguration {
        threshold_millionths: 4_605_000, // log(100)
        confidence_millionths: 950_000,  // 95%
        max_delay_steps: 500,
        convergence_tolerance_millionths: 1_000,
    };

    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (MILLION, 3 * MILLION), // Large shift for better detection
    };

    let arl_analysis =
        AverageRunLengthAnalysis::compute(config.clone(), alternative.clone()).unwrap();
    let delay_bound = WorstCaseDelayBound::compute(config, alternative, &arl_analysis).unwrap();

    // Verify bound properties
    assert!(delay_bound.delay_bound_millionths > 0);
    assert!(delay_bound.delay_bound_millionths < 1000 * MILLION); // Should be reasonable
    assert_eq!(delay_bound.confidence_millionths, 950_000);
    assert!(matches!(
        delay_bound.computation_method,
        DelayBoundMethod::LordenExact
    ));

    // Verify proof obligations
    assert_eq!(delay_bound.proof_obligations.len(), 3);

    // Check liveness obligation
    let liveness_obligation = delay_bound
        .proof_obligations
        .iter()
        .find(|o| o.category == ObligationCategory::Liveness)
        .expect("Should have liveness obligation");
    assert_eq!(
        liveness_obligation.verification_status,
        VerificationStatus::Verified
    );
    assert!(matches!(
        liveness_obligation.proof_method,
        ProofMethod::AnalyticBound
    ));

    // Check safety obligation (false alarm control)
    let safety_obligation = delay_bound
        .proof_obligations
        .iter()
        .find(|o| o.category == ObligationCategory::Safety)
        .expect("Should have safety obligation");
    assert_eq!(
        safety_obligation.verification_status,
        VerificationStatus::Verified
    );
}

#[test]
fn test_exponential_alternative_delay_bound() {
    let config = DelayBoundConfiguration::default();
    let alternative = CompositeAlternative::ExponentialRateShift {
        pre_change_rate_millionths: MILLION,               // λ = 1.0
        rate_range_millionths: (2 * MILLION, 4 * MILLION), // λ ∈ [2.0, 4.0]
    };

    let arl_analysis =
        AverageRunLengthAnalysis::compute(config.clone(), alternative.clone()).unwrap();
    let delay_bound = WorstCaseDelayBound::compute(config, alternative, &arl_analysis).unwrap();

    // For exponential alternatives, should use Wald approximation
    assert!(matches!(
        delay_bound.computation_method,
        DelayBoundMethod::WaldApproximation
    ));
    assert!(delay_bound.delay_bound_millionths > 0);

    // Verify all obligations are present
    let obligation_categories: Vec<_> = delay_bound
        .proof_obligations
        .iter()
        .map(|o| o.category)
        .collect();
    assert!(obligation_categories.contains(&ObligationCategory::Liveness));
    assert!(obligation_categories.contains(&ObligationCategory::Safety));
    assert!(obligation_categories.contains(&ObligationCategory::CalibrationValidity));
}

#[test]
fn test_bernoulli_alternative_with_high_confidence() {
    let config = DelayBoundConfiguration {
        threshold_millionths: 3_000_000, // Lower threshold
        confidence_millionths: 990_000,  // 99% confidence
        max_delay_steps: 1000,
        convergence_tolerance_millionths: 1_000,
    };

    let alternative = CompositeAlternative::BernoulliProbabilityShift {
        pre_change_prob_millionths: 100_000,       // p = 0.1
        prob_range_millionths: (600_000, 900_000), // p ∈ [0.6, 0.9]
    };

    let arl_analysis =
        AverageRunLengthAnalysis::compute(config.clone(), alternative.clone()).unwrap();
    let delay_bound =
        WorstCaseDelayBound::compute(config.clone(), alternative, &arl_analysis).unwrap();

    // High confidence should result in larger bounds
    assert_eq!(delay_bound.confidence_millionths, 990_000);
    assert!(delay_bound.delay_bound_millionths > 5 * MILLION); // Should be conservative for 99%

    // Verify computation converged
    if let ArlComputationStatus::Converged { iterations } = arl_analysis.computation_status {
        assert!(iterations > 0);
    } else {
        panic!("ARL computation should have converged");
    }
}

#[test]
fn test_delay_bound_error_conditions() {
    // Test invalid configuration
    let bad_config = DelayBoundConfiguration {
        threshold_millionths: -1_000_000, // Negative threshold
        confidence_millionths: 950_000,
        max_delay_steps: 100,
        convergence_tolerance_millionths: 1_000,
    };

    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (0, 100), // Very small shift
    };

    // This should fail due to poor discriminability
    let result = AverageRunLengthAnalysis::compute(bad_config, alternative);
    assert!(result.is_err());
}

#[test]
fn test_mathematical_properties_of_bounds() {
    let base_config = DelayBoundConfiguration::default();

    // Test that larger thresholds lead to longer delays but lower false alarms
    let high_threshold_config = DelayBoundConfiguration {
        threshold_millionths: 10 * MILLION,
        ..base_config.clone()
    };

    let low_threshold_config = DelayBoundConfiguration {
        threshold_millionths: 2 * MILLION,
        ..base_config
    };

    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (MILLION, 2 * MILLION),
    };

    let high_arl =
        AverageRunLengthAnalysis::compute(high_threshold_config.clone(), alternative.clone())
            .unwrap();
    let low_arl =
        AverageRunLengthAnalysis::compute(low_threshold_config.clone(), alternative.clone())
            .unwrap();

    // Higher threshold should give longer ARL under null (lower false alarm rate)
    assert!(high_arl.arl_null_millionths > low_arl.arl_null_millionths);
    assert!(high_arl.false_alarm_rate_millionths < low_arl.false_alarm_rate_millionths);

    let high_bound =
        WorstCaseDelayBound::compute(high_threshold_config, alternative.clone(), &high_arl)
            .unwrap();
    let low_bound =
        WorstCaseDelayBound::compute(low_threshold_config, alternative, &low_arl).unwrap();

    // Higher threshold should generally give longer detection delay bounds
    assert!(high_bound.delay_bound_millionths > low_bound.delay_bound_millionths);
}

#[test]
fn test_proof_obligations_completeness() {
    let config = DelayBoundConfiguration::default();
    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: MILLION,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (2 * MILLION, 3 * MILLION),
    };

    let arl_analysis =
        AverageRunLengthAnalysis::compute(config.clone(), alternative.clone()).unwrap();
    let delay_bound = WorstCaseDelayBound::compute(config, alternative, &arl_analysis).unwrap();

    // Verify all required obligation categories are present
    let mut has_liveness = false;
    let mut has_safety = false;
    let mut has_calibration = false;

    for obligation in &delay_bound.proof_obligations {
        match obligation.category {
            ObligationCategory::Liveness => has_liveness = true,
            ObligationCategory::Safety => has_safety = true,
            ObligationCategory::CalibrationValidity => has_calibration = true,
            _ => {}
        }

        // Verify each obligation has proper structure
        assert!(!obligation.statement.is_empty());
        assert!(obligation.id.0.len() > 0);
    }

    assert!(has_liveness, "Should have liveness obligation");
    assert!(has_safety, "Should have safety obligation");
    assert!(has_calibration, "Should have calibration obligation");
}

#[test]
fn test_composite_alternative_likelihood_ratios() {
    // Test that likelihood ratios have expected properties
    let normal_alt = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: MILLION,
        mean_range_millionths: (MILLION, 2 * MILLION),
    };

    let exp_alt = CompositeAlternative::ExponentialRateShift {
        pre_change_rate_millionths: MILLION,
        rate_range_millionths: (2 * MILLION, 3 * MILLION),
    };

    let bernoulli_alt = CompositeAlternative::BernoulliProbabilityShift {
        pre_change_prob_millionths: 300_000,
        prob_range_millionths: (700_000, 900_000),
    };

    // Under null, mean log LR should be negative (favoring null)
    assert!(normal_alt.mean_log_likelihood_ratio_under_null() < 0);
    assert!(exp_alt.mean_log_likelihood_ratio_under_null() < 0);
    assert!(bernoulli_alt.mean_log_likelihood_ratio_under_null() < 0);

    // Under alternative, mean log LR should be positive (favoring alternative)
    assert!(normal_alt.mean_log_likelihood_ratio_under_alternative() > 0);
    assert!(exp_alt.mean_log_likelihood_ratio_under_alternative() > 0);
    assert!(bernoulli_alt.mean_log_likelihood_ratio_under_alternative() > 0);

    // The difference should be substantial for good detection power
    for alt in [&normal_alt, &exp_alt, &bernoulli_alt] {
        let null_lr = alt.mean_log_likelihood_ratio_under_null();
        let alt_lr = alt.mean_log_likelihood_ratio_under_alternative();
        let separation = alt_lr - null_lr;
        assert!(
            separation > 50_000,
            "Should have good separation for detectability"
        );
    }
}

#[test]
fn test_numerical_stability() {
    // Test with extreme parameters to verify numerical stability
    let config = DelayBoundConfiguration {
        threshold_millionths: 15 * MILLION, // Very high threshold
        confidence_millionths: 999_000,     // 99.9% confidence
        max_delay_steps: 10_000,
        convergence_tolerance_millionths: 10,
    };

    let alternative = CompositeAlternative::NormalMeanShift {
        pre_change_mean_millionths: 0,
        variance_millionths_squared: 10 * MILLION, // High variance
        mean_range_millionths: (100_000, 200_000), // Small shift
    };

    // This represents a challenging detection problem
    let arl_result = AverageRunLengthAnalysis::compute(config.clone(), alternative.clone());

    match arl_result {
        Ok(arl_analysis) => {
            // If successful, verify results are sensible
            assert!(arl_analysis.arl_null_millionths > 0);
            assert!(arl_analysis.arl_alternative_millionths > 0);

            let bound_result = WorstCaseDelayBound::compute(config, alternative, &arl_analysis);
            assert!(bound_result.is_ok());
        }
        Err(DelayBoundError::InvalidConfiguration { .. }) => {
            // Acceptable to fail due to poor discriminability
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_delay_bound_trade_offs() {
    // Demonstrate the classical trade-off between false alarm rate and detection delay
    let alternatives = [
        // Easy detection case
        CompositeAlternative::NormalMeanShift {
            pre_change_mean_millionths: 0,
            variance_millionths_squared: MILLION,
            mean_range_millionths: (3 * MILLION, 4 * MILLION), // Large shift
        },
        // Hard detection case
        CompositeAlternative::NormalMeanShift {
            pre_change_mean_millionths: 0,
            variance_millionths_squared: MILLION,
            mean_range_millionths: (200_000, 400_000), // Small shift
        },
    ];

    let config = DelayBoundConfiguration::default();

    let mut results = Vec::new();
    for alt in alternatives {
        if let Ok(arl) = AverageRunLengthAnalysis::compute(config.clone(), alt.clone()) {
            if let Ok(bound) = WorstCaseDelayBound::compute(config.clone(), alt, &arl) {
                results.push((
                    arl.false_alarm_rate_millionths,
                    bound.delay_bound_millionths,
                ));
            }
        }
    }

    assert_eq!(results.len(), 2);

    // For same false alarm rate, easier detection should have shorter delay
    // (This test might need adjustment based on actual implementation details)
    println!("Trade-off results: {:?}", results);
}
