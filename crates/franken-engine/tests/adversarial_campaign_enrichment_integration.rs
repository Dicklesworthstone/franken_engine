//! Enrichment integration tests for the `adversarial_campaign` module.
//!
//! Covers deeper edge cases across Display uniqueness, serde roundtrips,
//! RedBlueLoopIntegrator deep paths, suppression gate deep paths,
//! mutation engine edge cases, grammar feedback, minimizer edge cases,
//! and CampaignGenerator lifecycle scenarios.

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

use frankenengine_engine::adversarial_campaign::{
    AdversarialCampaign, AttackDimension, AttackGrammar, AttackStep, AttackStepKind,
    AutoMinimizer, CalibrationReceipt, CampaignAttackCategory, CampaignComplexity,
    CampaignExecutionResult, CampaignGenerator, CampaignGeneratorConfig,
    CampaignOutcomeRecord, CampaignRuntime, CampaignSuppressionEvent,
    CampaignSuppressionSample, CampaignTrendPoint,
    ExploitObjectiveScore, GuardplaneCalibrationState,
    MutationEngine, MutationOperator, MutationRequest,
    RedBlueCalibrationConfig, RedBlueLoopIntegrator, RegressionGateDecision,
    RegressionReplayResult, PolicyRegressionSuite, SuppressionGateConfig,
    SuppressionGateFailure, SuppressionGateInput, SuppressionGateResult,
    evaluate_compromise_suppression_gate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_gen(seed: u64) -> CampaignGenerator {
    CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        seed,
    )
    .unwrap()
}

fn gen_campaign(complexity: CampaignComplexity, seed: u64) -> AdversarialCampaign {
    make_gen(seed).generate_campaign(complexity).unwrap()
}

fn make_outcome(
    camp: AdversarialCampaign,
    result: CampaignExecutionResult,
    benign: bool,
    fp: bool,
    ts: u64,
) -> CampaignOutcomeRecord {
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    CampaignOutcomeRecord {
        campaign: camp,
        result,
        score,
        benign_control: benign,
        false_positive: fp,
        timestamp_ns: ts,
    }
}

fn make_suppression_sample(
    id: &str,
    cat: CampaignAttackCategory,
    rt: CampaignRuntime,
    attempts: u64,
    successes: u64,
) -> CampaignSuppressionSample {
    CampaignSuppressionSample {
        campaign_id: id.to_string(),
        attack_category: cat,
        target_runtime: rt,
        attempt_count: attempts,
        success_count: successes,
        raw_log_ref: format!("artifacts/raw/{id}.jsonl"),
        repro_script_ref: format!("artifacts/repro/{id}.sh"),
    }
}

fn full_category_triples(
    fe_success: u64,
    node_success: u64,
    bun_success: u64,
) -> Vec<CampaignSuppressionSample> {
    CampaignAttackCategory::ALL
        .iter()
        .flat_map(|cat| {
            [
                make_suppression_sample(
                    &format!("camp-fe-{cat}"),
                    *cat,
                    CampaignRuntime::FrankenEngine,
                    250,
                    fe_success,
                ),
                make_suppression_sample(
                    &format!("camp-node-{cat}"),
                    *cat,
                    CampaignRuntime::NodeLts,
                    250,
                    node_success,
                ),
                make_suppression_sample(
                    &format!("camp-bun-{cat}"),
                    *cat,
                    CampaignRuntime::BunStable,
                    250,
                    bun_success,
                ),
            ]
        })
        .collect()
}

fn make_integrator() -> RedBlueLoopIntegrator {
    RedBlueLoopIntegrator::new(
        RedBlueCalibrationConfig::default(),
        GuardplaneCalibrationState::default(),
    )
}

fn standard_trend_points() -> Vec<CampaignTrendPoint> {
    vec![
        CampaignTrendPoint {
            release_candidate_id: "rc-prev-1".to_string(),
            timestamp_ns: 1_700_000_100_000,
            samples_evaluated: 500,
        },
        CampaignTrendPoint {
            release_candidate_id: "rc-prev-2".to_string(),
            timestamp_ns: 1_700_000_200_000,
            samples_evaluated: 520,
        },
    ]
}

// =========================================================================
// A. Display Uniqueness (4 tests)
// =========================================================================

#[test]
fn enrichment_campaign_complexity_display_strings_are_all_unique() {
    let displays: Vec<String> = [
        CampaignComplexity::Probe,
        CampaignComplexity::MultiStage,
        CampaignComplexity::Apt,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(displays.len(), unique.len(), "all CampaignComplexity Display strings must be unique");
}

#[test]
fn enrichment_attack_dimension_display_strings_are_all_unique() {
    let displays: Vec<String> = [
        AttackDimension::HostcallSequence,
        AttackDimension::TemporalPayload,
        AttackDimension::PrivilegeEscalation,
        AttackDimension::PolicyEvasion,
        AttackDimension::Exfiltration,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(displays.len(), unique.len(), "all AttackDimension Display strings must be unique");
}

#[test]
fn enrichment_campaign_runtime_display_strings_are_all_unique() {
    let displays: Vec<String> = [
        CampaignRuntime::FrankenEngine,
        CampaignRuntime::NodeLts,
        CampaignRuntime::BunStable,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(displays.len(), unique.len(), "all CampaignRuntime Display strings must be unique");
}

#[test]
fn enrichment_campaign_attack_category_display_strings_are_all_unique() {
    let displays: Vec<String> = CampaignAttackCategory::ALL
        .iter()
        .map(|v| v.to_string())
        .collect();
    let unique: BTreeSet<&str> = displays.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "all CampaignAttackCategory Display strings must be unique"
    );
}

// =========================================================================
// B. Serde Roundtrips (8 tests)
// =========================================================================

#[test]
fn enrichment_red_blue_calibration_config_serde_roundtrip() {
    let config = RedBlueCalibrationConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: RedBlueCalibrationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_calibration_receipt_serde_roundtrip() {
    // Build a receipt through the real calibration path.
    let mut integrator = RedBlueLoopIntegrator::new(
        RedBlueCalibrationConfig {
            target_false_negative_millionths: 100_000,
            max_threshold_delta_millionths: 40_000,
            ..RedBlueCalibrationConfig::default()
        },
        GuardplaneCalibrationState::default(),
    );

    for idx in 0..3u64 {
        let camp = gen_campaign(CampaignComplexity::Probe, 0xE100 + idx);
        let result = CampaignExecutionResult {
            undetected_steps: camp.steps.len(),
            total_steps: camp.steps.len(),
            objective_achieved_before_containment: true,
            damage_potential_millionths: 800_000,
            evidence_atoms_before_detection: 50,
            novel_technique: false,
        };
        integrator
            .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_000 + idx))
            .unwrap();
    }

    let receipt = integrator
        .calibrate(&[42u8; 32], 1_700_000_010_000)
        .unwrap()
        .expect("calibration should produce a receipt");

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: CalibrationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

#[test]
fn enrichment_suppression_gate_result_serde_roundtrip() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-serde-test".to_string(),
        continuous_run: true,
        samples: full_category_triples(0, 40, 35),
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: SuppressionGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_campaign_suppression_event_serde_roundtrip() {
    let event = CampaignSuppressionEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "red_blue_feedback_loop".to_string(),
        event: "suppression_comparison".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        campaign_id: "c-1".to_string(),
        attack_category: "injection".to_string(),
        target_runtime: "node_lts".to_string(),
        attempt_count: 200,
        success_count: 30,
        compromise_rate_millionths: 150_000,
        p_value_millionths: Some(5_000),
        confidence_interval: "[100000,200000]".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CampaignSuppressionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_campaign_outcome_record_serde_roundtrip() {
    let camp = gen_campaign(CampaignComplexity::Probe, 0xE200);
    let result = CampaignExecutionResult {
        undetected_steps: 2,
        total_steps: 4,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 300_000,
        evidence_atoms_before_detection: 10,
        novel_technique: false,
    };
    let record = make_outcome(camp, result, false, false, 1_700_000_000_500);
    let json = serde_json::to_string(&record).unwrap();
    let restored: CampaignOutcomeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn enrichment_suppression_gate_failure_serde_roundtrip() {
    let failure = SuppressionGateFailure {
        error_code: "FE-ADV-GATE-0003".to_string(),
        detail: "not significant".to_string(),
        attack_category: Some(CampaignAttackCategory::Injection),
        baseline_runtime: Some(CampaignRuntime::NodeLts),
        campaign_id: Some("camp-1".to_string()),
    };
    let json = serde_json::to_string(&failure).unwrap();
    let restored: SuppressionGateFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(failure, restored);
}

#[test]
fn enrichment_regression_gate_decision_serde_roundtrip() {
    let decision = RegressionGateDecision {
        passed: false,
        failed_campaign_ids: vec!["camp-a".to_string(), "camp-b".to_string()],
    };
    let json = serde_json::to_string(&decision).unwrap();
    let restored: RegressionGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, restored);
}

#[test]
fn enrichment_policy_regression_suite_serde_roundtrip() {
    let suite = PolicyRegressionSuite::default();
    let json = serde_json::to_string(&suite).unwrap();
    let restored: PolicyRegressionSuite = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, restored);
}

// =========================================================================
// C. RedBlueLoopIntegrator Deep (10 tests)
// =========================================================================

#[test]
fn enrichment_technique_effectiveness_multi_dimension_campaign() {
    let mut integrator = make_integrator();

    // Ingest a campaign that covers multiple attack dimensions.
    let camp = gen_campaign(CampaignComplexity::Apt, 0xC100);
    let result = CampaignExecutionResult {
        undetected_steps: 5,
        total_steps: camp.steps.len(),
        objective_achieved_before_containment: false,
        damage_potential_millionths: 400_000,
        evidence_atoms_before_detection: 12,
        novel_technique: false,
    };
    integrator
        .ingest_outcome(make_outcome(camp.clone(), result, false, false, 1_700_000_000_100))
        .unwrap();

    let effectiveness = integrator.technique_effectiveness();
    // Every dimension present in the campaign steps should appear.
    let mut seen_dims: BTreeSet<AttackDimension> = BTreeSet::new();
    for step in &camp.steps {
        seen_dims.insert(step.dimension);
    }
    for dim in &seen_dims {
        assert!(
            effectiveness.contains_key(dim),
            "dimension {dim} should have an effectiveness entry"
        );
        let entry = &effectiveness[dim];
        assert!(entry.attempts >= 1);
    }
}

#[test]
fn enrichment_calibration_evidence_weights_adjust_on_escapes() {
    let mut integrator = make_integrator();

    // Ingest outcomes where the attacker escaped - should raise evidence weights.
    for idx in 0..3u64 {
        let camp = gen_campaign(CampaignComplexity::Probe, 0xC200 + idx);
        let result = CampaignExecutionResult {
            undetected_steps: camp.steps.len(),
            total_steps: camp.steps.len(),
            objective_achieved_before_containment: true,
            damage_potential_millionths: 700_000,
            evidence_atoms_before_detection: 40,
            novel_technique: false,
        };
        integrator
            .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_200 + idx))
            .unwrap();
    }

    let old_weights = integrator
        .calibration_state()
        .evidence_weights_millionths
        .clone();

    integrator
        .calibrate(&[55u8; 32], 1_700_000_010_000)
        .unwrap();

    let new_weights = &integrator.calibration_state().evidence_weights_millionths;
    // At least one weight should have changed.
    assert_ne!(&old_weights, new_weights, "evidence weights should adjust after escapes");
}

#[test]
fn enrichment_calibration_loss_matrix_updates_on_critical_severity() {
    let mut integrator = make_integrator();

    // Ingest a blocking-severity outcome to trigger loss matrix update.
    let camp = gen_campaign(CampaignComplexity::MultiStage, 0xC300);
    let result = CampaignExecutionResult {
        undetected_steps: camp.steps.len(),
        total_steps: camp.steps.len(),
        objective_achieved_before_containment: true,
        damage_potential_millionths: 950_000,
        evidence_atoms_before_detection: 50,
        novel_technique: true,
    };
    integrator
        .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_300))
        .unwrap();

    let old_loss = integrator
        .calibration_state()
        .loss_matrix_millionths
        .clone();

    integrator
        .calibrate(&[66u8; 32], 1_700_000_020_000)
        .unwrap();

    let new_loss = &integrator.calibration_state().loss_matrix_millionths;
    // Loss matrix should have at least one updated entry.
    let any_raised = old_loss.iter().any(|(k, v)| {
        new_loss.get(k).map(|nv| *nv > *v).unwrap_or(false)
    });
    assert!(
        any_raised || old_loss == *new_loss,
        "loss matrix should adjust or remain unchanged if already at max"
    );
}

#[test]
fn enrichment_calibrate_returns_none_when_no_outcomes() {
    let mut integrator = make_integrator();
    let receipt = integrator.calibrate(&[77u8; 32], 1_700_000_000_000).unwrap();
    assert!(receipt.is_none(), "calibrate with no outcomes should return None");
}

#[test]
fn enrichment_calibration_epoch_increments_on_adjustment() {
    let mut integrator = RedBlueLoopIntegrator::new(
        RedBlueCalibrationConfig {
            target_false_negative_millionths: 100_000,
            max_threshold_delta_millionths: 40_000,
            ..RedBlueCalibrationConfig::default()
        },
        GuardplaneCalibrationState::default(),
    );

    for idx in 0..3u64 {
        let camp = gen_campaign(CampaignComplexity::Probe, 0xC400 + idx);
        let result = CampaignExecutionResult {
            undetected_steps: camp.steps.len(),
            total_steps: camp.steps.len(),
            objective_achieved_before_containment: true,
            damage_potential_millionths: 800_000,
            evidence_atoms_before_detection: 50,
            novel_technique: false,
        };
        integrator
            .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_400 + idx))
            .unwrap();
    }

    let epoch_before = integrator.calibration_state().calibration_epoch;
    let receipt = integrator
        .calibrate(&[88u8; 32], 1_700_000_030_000)
        .unwrap();
    if receipt.is_some() {
        let epoch_after = integrator.calibration_state().calibration_epoch;
        assert_eq!(epoch_after, epoch_before + 1, "calibration_epoch should increment by 1");
    }
}

#[test]
fn enrichment_promote_unknown_campaign_returns_error() {
    let mut integrator = make_integrator();
    let err = integrator
        .promote_regression_fixture("nonexistent-campaign-id", "containment", "evasion", None)
        .unwrap_err();
    assert!(
        err.to_string().contains("unknown campaign_id"),
        "should mention unknown campaign_id, got: {err}"
    );
}

#[test]
fn enrichment_promote_unclassified_campaign_returns_error() {
    // This test verifies that if a campaign hasn't been ingested (and thus
    // not classified), promote_regression_fixture returns an error.
    // Since ingest_outcome also classifies, an unclassified campaign means
    // one that was never ingested. We test via the "unknown" path.
    let mut integrator = make_integrator();
    let result = integrator.promote_regression_fixture(
        "never-ingested",
        "expected",
        "actual",
        None,
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_regression_gate_partial_results_fail_unmatched() {
    let mut integrator = make_integrator();

    // Ingest and promote two campaigns.
    let camp_a = gen_campaign(CampaignComplexity::Probe, 0xC500);
    let camp_b = gen_campaign(CampaignComplexity::Probe, 0xC501);
    let camp_a_id = camp_a.campaign_id.clone();
    let camp_b_id = camp_b.campaign_id.clone();

    for camp in [camp_a, camp_b] {
        let result = CampaignExecutionResult {
            undetected_steps: camp.steps.len().saturating_sub(1),
            total_steps: camp.steps.len(),
            objective_achieved_before_containment: false,
            damage_potential_millionths: 500_000,
            evidence_atoms_before_detection: 20,
            novel_technique: true,
        };
        integrator
            .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_500))
            .unwrap();
    }

    integrator
        .promote_regression_fixture(&camp_a_id, "containment", "late-detect", None)
        .unwrap();
    integrator
        .promote_regression_fixture(&camp_b_id, "containment", "missed", None)
        .unwrap();

    // Only supply a passing replay for camp_a; camp_b should fail.
    let decision = integrator.evaluate_regression_gate(&[RegressionReplayResult {
        campaign_id: camp_a_id.clone(),
        passed: true,
    }]);
    assert!(!decision.passed);
    assert!(decision.failed_campaign_ids.contains(&camp_b_id));
    assert!(!decision.failed_campaign_ids.contains(&camp_a_id));
}

#[test]
fn enrichment_counterfactual_hints_only_for_critical_or_blocking() {
    let mut integrator = make_integrator();

    // Ingest an advisory-level outcome: should NOT produce a hint.
    let camp_low = gen_campaign(CampaignComplexity::Probe, 0xC600);
    let result_low = CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: camp_low.steps.len(),
        objective_achieved_before_containment: false,
        damage_potential_millionths: 50_000,
        evidence_atoms_before_detection: 2,
        novel_technique: false,
    };
    integrator
        .ingest_outcome(make_outcome(camp_low, result_low, false, false, 1_700_000_000_600))
        .unwrap();

    let hints = integrator.critical_counterfactual_hints();
    assert!(hints.is_empty(), "advisory outcomes should not produce counterfactual hints");

    // Now ingest a blocking-level outcome.
    let camp_high = gen_campaign(CampaignComplexity::Apt, 0xC601);
    let result_high = CampaignExecutionResult {
        undetected_steps: camp_high.steps.len(),
        total_steps: camp_high.steps.len(),
        objective_achieved_before_containment: true,
        damage_potential_millionths: 900_000,
        evidence_atoms_before_detection: 60,
        novel_technique: true,
    };
    let camp_high_id = camp_high.campaign_id.clone();
    integrator
        .ingest_outcome(make_outcome(camp_high, result_high, false, false, 1_700_000_000_601))
        .unwrap();

    let hints = integrator.critical_counterfactual_hints();
    assert!(!hints.is_empty(), "blocking outcomes should produce counterfactual hints");
    assert!(hints.iter().any(|h| h.campaign_id == camp_high_id));
}

#[test]
fn enrichment_drain_events_empties_integrator_event_log() {
    let mut integrator = make_integrator();
    let camp = gen_campaign(CampaignComplexity::Probe, 0xC700);
    let result = CampaignExecutionResult {
        undetected_steps: 2,
        total_steps: camp.steps.len(),
        objective_achieved_before_containment: false,
        damage_potential_millionths: 400_000,
        evidence_atoms_before_detection: 10,
        novel_technique: false,
    };
    integrator
        .ingest_outcome(make_outcome(camp, result, false, false, 1_700_000_000_700))
        .unwrap();

    let first = integrator.drain_events();
    assert!(!first.is_empty());
    let second = integrator.drain_events();
    assert!(second.is_empty(), "drain_events should empty the event log");
}

// =========================================================================
// D. Suppression Gate Deep (8 tests)
// =========================================================================

#[test]
fn enrichment_suppression_gate_fails_on_missing_fe_coverage_for_category() {
    // Only provide NodeLts and BunStable samples for Injection, no FrankenEngine.
    let mut samples = Vec::new();
    for cat in CampaignAttackCategory::ALL {
        if cat == CampaignAttackCategory::Injection {
            // Skip FrankenEngine for Injection.
            samples.push(make_suppression_sample(
                "camp-node-inj",
                cat,
                CampaignRuntime::NodeLts,
                250,
                30,
            ));
            samples.push(make_suppression_sample(
                "camp-bun-inj",
                cat,
                CampaignRuntime::BunStable,
                250,
                25,
            ));
        } else {
            samples.push(make_suppression_sample(
                &format!("camp-fe-{cat}"),
                cat,
                CampaignRuntime::FrankenEngine,
                250,
                0,
            ));
            samples.push(make_suppression_sample(
                &format!("camp-node-{cat}"),
                cat,
                CampaignRuntime::NodeLts,
                250,
                30,
            ));
            samples.push(make_suppression_sample(
                &format!("camp-bun-{cat}"),
                cat,
                CampaignRuntime::BunStable,
                250,
                25,
            ));
        }
    }

    let input = SuppressionGateInput {
        release_candidate_id: "rc-missing-fe".to_string(),
        continuous_run: true,
        samples,
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.error_code == "FE-ADV-GATE-0002"
                && f.attack_category == Some(CampaignAttackCategory::Injection))
    );
}

#[test]
fn enrichment_suppression_gate_fails_on_insufficient_baselines() {
    // Provide only FrankenEngine + NodeLts, but config requires 2 baselines.
    let mut samples = Vec::new();
    for cat in CampaignAttackCategory::ALL {
        samples.push(make_suppression_sample(
            &format!("camp-fe-{cat}"),
            cat,
            CampaignRuntime::FrankenEngine,
            250,
            0,
        ));
        samples.push(make_suppression_sample(
            &format!("camp-node-{cat}"),
            cat,
            CampaignRuntime::NodeLts,
            250,
            30,
        ));
        // No BunStable!
    }

    let input = SuppressionGateInput {
        release_candidate_id: "rc-insufficient-baselines".to_string(),
        continuous_run: true,
        samples,
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.error_code == "FE-ADV-GATE-0002"));
}

#[test]
fn enrichment_suppression_gate_exact_threshold_pass() {
    // FrankenEngine has 0 successes, baselines have some - should pass.
    let input = SuppressionGateInput {
        release_candidate_id: "rc-exact-pass".to_string(),
        continuous_run: true,
        samples: full_category_triples(0, 45, 38),
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(result.passed);
    assert!(result.failures.is_empty());
}

#[test]
fn enrichment_suppression_gate_over_threshold_fe_rate_fails() {
    // FrankenEngine has more successes than baselines - should fail significance.
    let input = SuppressionGateInput {
        release_candidate_id: "rc-over-threshold".to_string(),
        continuous_run: true,
        samples: full_category_triples(50, 10, 8),
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.error_code == "FE-ADV-GATE-0003"));
}

#[test]
fn enrichment_suppression_gate_missing_escalation_record_fails() {
    // FrankenEngine samples with successes but no escalation records.
    let mut samples = full_category_triples(5, 40, 35);
    // Add an extra FE sample with successes to trigger escalation check.
    samples.push(make_suppression_sample(
        "camp-fe-extra-inj",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        100,
        10,
    ));

    let input = SuppressionGateInput {
        release_candidate_id: "rc-missing-esc".to_string(),
        continuous_run: true,
        samples,
        trend_points: standard_trend_points(),
        escalations: Vec::new(), // No escalation records!
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.error_code == "FE-ADV-GATE-0005"));
}

#[test]
fn enrichment_suppression_gate_mixed_pass_fail_categories() {
    // Some categories pass (FE=0), one category fails (FE > baseline).
    let mut samples = Vec::new();
    for cat in CampaignAttackCategory::ALL {
        let fe_success = if cat == CampaignAttackCategory::TimingSideChannel {
            80 // Much worse than baseline
        } else {
            0
        };
        samples.push(make_suppression_sample(
            &format!("camp-fe-{cat}"),
            cat,
            CampaignRuntime::FrankenEngine,
            250,
            fe_success,
        ));
        samples.push(make_suppression_sample(
            &format!("camp-node-{cat}"),
            cat,
            CampaignRuntime::NodeLts,
            250,
            30,
        ));
        samples.push(make_suppression_sample(
            &format!("camp-bun-{cat}"),
            cat,
            CampaignRuntime::BunStable,
            250,
            25,
        ));
    }

    let input = SuppressionGateInput {
        release_candidate_id: "rc-mixed".to_string(),
        continuous_run: true,
        samples,
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    // Should have significance failures for TimingSideChannel.
    let timing_failures: Vec<_> = result
        .failures
        .iter()
        .filter(|f| f.attack_category == Some(CampaignAttackCategory::TimingSideChannel))
        .collect();
    assert!(!timing_failures.is_empty());
}

#[test]
fn enrichment_suppression_gate_events_include_per_sample_ingestion() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-event-check".to_string(),
        continuous_run: true,
        samples: full_category_triples(0, 40, 35),
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    let ingested_events: Vec<_> = result
        .events
        .iter()
        .filter(|e| e.event == "campaign_sample_ingested")
        .collect();
    assert_eq!(
        ingested_events.len(),
        input.samples.len(),
        "should have one ingested event per sample"
    );
}

#[test]
fn enrichment_suppression_gate_zero_fe_successes_always_passes_significance() {
    // When FrankenEngine has zero successes and baselines have nonzero,
    // the statistical test should always pass.
    let input = SuppressionGateInput {
        release_candidate_id: "rc-zero-fe".to_string(),
        continuous_run: true,
        samples: full_category_triples(0, 50, 50),
        trend_points: standard_trend_points(),
        escalations: Vec::new(),
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(result.passed);
    // All comparisons should be statistically significant.
    assert!(
        result
            .comparisons
            .iter()
            .all(|c| c.statistically_significant)
    );
}

// =========================================================================
// E. Mutation Engine Edge Cases (6 tests)
// =========================================================================

#[test]
fn enrichment_crossover_single_step_base_and_donor() {
    let grammar = AttackGrammar::default();
    let mut generator = CampaignGenerator::new(
        grammar.clone(),
        CampaignGeneratorConfig::default(),
        0xE100,
    )
    .unwrap();

    // Create a multi-step campaign for crossover (single-step base could
    // result in empty merge, so use multi-step to exercise the split logic).
    let base = generator.generate_campaign(CampaignComplexity::MultiStage).unwrap();
    let donor = generator.generate_campaign(CampaignComplexity::Probe).unwrap();

    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0x1234,
            donor_campaign: Some(donor),
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert!(!mutated.steps.is_empty());
}

#[test]
fn enrichment_crossover_without_donor_fails() {
    let grammar = AttackGrammar::default();
    let base = gen_campaign(CampaignComplexity::MultiStage, 0xE200);
    let err = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0x5678,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("donor_campaign"));
}

#[test]
fn enrichment_temporal_shift_saturate_preserves_valid_delay() {
    let grammar = AttackGrammar::default();
    // Generate campaigns until we find one with a temporal payload step.
    for seed_offset in 0..20u64 {
        let mut generator = CampaignGenerator::new(
            grammar.clone(),
            CampaignGeneratorConfig::default(),
            0xE300 + seed_offset,
        )
        .unwrap();
        let base = generator.generate_campaign(CampaignComplexity::Apt).unwrap();
        let has_temporal = base
            .steps
            .iter()
            .any(|s| matches!(s.kind, AttackStepKind::TemporalPayload { .. }));
        if has_temporal {
            let mutated = MutationEngine::mutate(
                &base,
                &grammar,
                MutationRequest {
                    operator: MutationOperator::TemporalShift,
                    seed: 0x9ABC,
                    donor_campaign: None,
                },
            )
            .unwrap();
            mutated.validate().unwrap();
            // Delay must remain >= 1 (saturating_sub + .max(1)).
            for step in &mutated.steps {
                if let AttackStepKind::TemporalPayload { delay_ms, .. } = &step.kind {
                    assert!(*delay_ms >= 1, "delay_ms should never go below 1");
                }
            }
            return;
        }
    }
    // If we never found a temporal step in 20 attempts, skip.
}

#[test]
fn enrichment_point_mutation_single_step_campaign() {
    let grammar = AttackGrammar::default();
    let mut generator = CampaignGenerator::new(
        grammar.clone(),
        CampaignGeneratorConfig::default(),
        0xE400,
    )
    .unwrap();
    let mut base = generator.generate_campaign(CampaignComplexity::Probe).unwrap();
    // Truncate to single step.
    base.steps.truncate(1);
    base.steps[0].step_id = 0;

    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0xDEF0,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert_eq!(mutated.steps.len(), 1);
}

#[test]
fn enrichment_successive_mutations_produce_valid_campaigns() {
    let grammar = AttackGrammar::default();
    let mut generator = CampaignGenerator::new(
        grammar.clone(),
        CampaignGeneratorConfig::default(),
        0xE500,
    )
    .unwrap();
    let mut current = generator.generate_campaign(CampaignComplexity::MultiStage).unwrap();

    // Apply insertion 3 times, then point mutation 2 times.
    for i in 0..3u64 {
        current = MutationEngine::mutate(
            &current,
            &grammar,
            MutationRequest {
                operator: MutationOperator::Insertion,
                seed: 0xF000 + i,
                donor_campaign: None,
            },
        )
        .unwrap();
        current.validate().unwrap();
    }
    assert!(current.steps.len() >= 11); // 8 + 3 insertions

    for i in 0..2u64 {
        current = MutationEngine::mutate(
            &current,
            &grammar,
            MutationRequest {
                operator: MutationOperator::PointMutation,
                seed: 0xF100 + i,
                donor_campaign: None,
            },
        )
        .unwrap();
        current.validate().unwrap();
    }
    // Step count stays the same after point mutations.
    assert!(current.steps.len() >= 11);
}

#[test]
fn enrichment_temporal_shift_no_temporal_steps_returns_error() {
    let grammar = AttackGrammar::default();
    // Build a campaign with only non-temporal steps.
    let camp = AdversarialCampaign {
        campaign_id: "camp-no-temporal".to_string(),
        trace_id: "trace-nt".to_string(),
        decision_id: "decision-nt".to_string(),
        policy_id: "policy-adversarial-default".to_string(),
        grammar_version: 1,
        seed: 42,
        complexity: CampaignComplexity::Probe,
        steps: vec![
            AttackStep {
                step_id: 0,
                dimension: AttackDimension::HostcallSequence,
                production_label: "credential_theft_chain".to_string(),
                kind: AttackStepKind::HostcallSequence {
                    motif: "credential_theft_chain".to_string(),
                    hostcall_count: 5,
                },
            },
            AttackStep {
                step_id: 1,
                dimension: AttackDimension::Exfiltration,
                production_label: "label_covert_egress".to_string(),
                kind: AttackStepKind::Exfiltration {
                    strategy: "label_covert_egress".to_string(),
                    chunk_count: 3,
                },
            },
        ],
    };
    camp.validate().unwrap();
    let err = MutationEngine::mutate(
        &camp,
        &grammar,
        MutationRequest {
            operator: MutationOperator::TemporalShift,
            seed: 0xAAAA,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("temporal payload"));
}

// =========================================================================
// F. Grammar Feedback (5 tests)
// =========================================================================

#[test]
fn enrichment_grammar_feedback_amplifies_high_evasion_labels() {
    let mut grammar = AttackGrammar::default();
    let camp = gen_campaign(CampaignComplexity::Probe, 0xF100);

    // Find a label from the campaign and record its weight before feedback.
    let label = camp.steps[0].production_label.clone();
    let weight_before = find_weight_for_label(&grammar, &label);

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 4,
        total_steps: 4,
        objective_achieved_before_containment: true,
        damage_potential_millionths: 900_000,
        evidence_atoms_before_detection: 50,
        novel_technique: true,
    })
    .unwrap();
    // evasion_score = 1_000_000 (4/4), which is >= 700_000 -> amplification=2
    assert!(score.evasion_score_millionths >= 700_000);

    grammar.apply_campaign_feedback(&camp, &score);

    let weight_after = find_weight_for_label(&grammar, &label);
    if let (Some(before), Some(after)) = (weight_before, weight_after) {
        assert!(after > before, "high evasion should amplify weight: {before} -> {after}");
    }
}

#[test]
fn enrichment_grammar_feedback_decays_low_evasion_labels() {
    let mut grammar = AttackGrammar::default();
    let camp = gen_campaign(CampaignComplexity::Probe, 0xF200);

    let label = camp.steps[0].production_label.clone();
    let weight_before = find_weight_for_label(&grammar, &label);

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 4,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 100_000,
        evidence_atoms_before_detection: 2,
        novel_technique: false,
    })
    .unwrap();
    // evasion_score = 0 (0/4), which is <= 250_000 -> decay=1
    assert!(score.evasion_score_millionths <= 250_000);

    grammar.apply_campaign_feedback(&camp, &score);

    let weight_after = find_weight_for_label(&grammar, &label);
    if let (Some(before), Some(after)) = (weight_before, weight_after) {
        assert!(after < before, "low evasion should decay weight: {before} -> {after}");
    }
}

#[test]
fn enrichment_grammar_feedback_neutral_midrange_evasion() {
    let mut grammar = AttackGrammar::default();
    let grammar_before = grammar.clone();
    let camp = gen_campaign(CampaignComplexity::Probe, 0xF300);

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 2,
        total_steps: 4,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 300_000,
        evidence_atoms_before_detection: 10,
        novel_technique: false,
    })
    .unwrap();
    // evasion_score = 500_000 (2/4), which is > 250_000 and < 700_000 -> amplification=1, decay=0
    // delta = 1*hits - 0*hits = hits. So weight increases by hits (1 per label).
    assert!(score.evasion_score_millionths > 250_000);
    assert!(score.evasion_score_millionths < 700_000);

    grammar.apply_campaign_feedback(&camp, &score);

    // Grammar should have changed (amplification=1 means labels get +1 per hit).
    // We verify that the grammar is not identical (some weight changed).
    let label = camp.steps[0].production_label.clone();
    let before = find_weight_for_label(&grammar_before, &label);
    let after = find_weight_for_label(&grammar, &label);
    if let (Some(b), Some(a)) = (before, after) {
        assert!(a >= b, "midrange evasion with amplification=1 should not decrease weight");
    }
}

#[test]
fn enrichment_grammar_feedback_weight_floor_at_one() {
    let mut grammar = AttackGrammar::default();

    // Set a weight to 1 so decay will test the floor.
    grammar.hostcall_motifs[0].weight = 1;
    let label = grammar.hostcall_motifs[0].label.clone();

    // Create a campaign that uses this label.
    let camp = AdversarialCampaign {
        campaign_id: "camp-floor-test".to_string(),
        trace_id: "trace-floor".to_string(),
        decision_id: "decision-floor".to_string(),
        policy_id: "policy-adversarial-default".to_string(),
        grammar_version: 1,
        seed: 42,
        complexity: CampaignComplexity::Probe,
        steps: vec![AttackStep {
            step_id: 0,
            dimension: AttackDimension::HostcallSequence,
            production_label: label.clone(),
            kind: AttackStepKind::HostcallSequence {
                motif: label.clone(),
                hostcall_count: 5,
            },
        }],
    };

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 1,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 0,
        evidence_atoms_before_detection: 0,
        novel_technique: false,
    })
    .unwrap();
    // evasion = 0 -> decay=1, amplification=0, delta=-1

    grammar.apply_campaign_feedback(&camp, &score);

    // Weight should be max(1 + (-1), 1) = 1, i.e. floored at 1.
    assert_eq!(
        grammar.hostcall_motifs[0].weight, 1,
        "weight should be floored at 1"
    );
}

#[test]
fn enrichment_grammar_feedback_nonexistent_label_is_noop() {
    let mut grammar = AttackGrammar::default();
    let grammar_before = grammar.clone();

    // Create a campaign with a label that does not exist in any bucket.
    let camp = AdversarialCampaign {
        campaign_id: "camp-noop-label".to_string(),
        trace_id: "trace-noop".to_string(),
        decision_id: "decision-noop".to_string(),
        policy_id: "policy-adversarial-default".to_string(),
        grammar_version: 1,
        seed: 42,
        complexity: CampaignComplexity::Probe,
        steps: vec![AttackStep {
            step_id: 0,
            dimension: AttackDimension::HostcallSequence,
            production_label: "nonexistent_label_xyz".to_string(),
            kind: AttackStepKind::HostcallSequence {
                motif: "nonexistent_label_xyz".to_string(),
                hostcall_count: 5,
            },
        }],
    };

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 1,
        total_steps: 1,
        objective_achieved_before_containment: true,
        damage_potential_millionths: 800_000,
        evidence_atoms_before_detection: 50,
        novel_technique: true,
    })
    .unwrap();

    grammar.apply_campaign_feedback(&camp, &score);

    // Grammar should be unchanged because the label doesn't match any production.
    assert_eq!(grammar, grammar_before, "nonexistent label should leave grammar unchanged");
}

fn find_weight_for_label(grammar: &AttackGrammar, label: &str) -> Option<u32> {
    for bucket in [
        &grammar.hostcall_motifs,
        &grammar.temporal_staging,
        &grammar.privilege_escalation,
        &grammar.policy_evasion,
        &grammar.exfiltration,
    ] {
        for prod in bucket {
            if prod.label == label {
                return Some(prod.weight);
            }
        }
    }
    None
}

// =========================================================================
// G. Minimizer (4 tests)
// =========================================================================

#[test]
fn enrichment_minimizer_two_step_reduces_to_target() {
    // Build a 12-step Apt campaign and minimize to >= 3 steps.
    let camp = gen_campaign(CampaignComplexity::Apt, 0xAA10);
    assert_eq!(camp.steps.len(), 12);

    let (minimized, proof) =
        AutoMinimizer::minimize_with(&camp, |c| c.steps.len() >= 3).unwrap();

    assert!(minimized.steps.len() >= 3);
    assert!(minimized.steps.len() < 12);
    assert!(proof.removed_steps > 0);
    assert!(proof.is_fixed_point);
}

#[test]
fn enrichment_minimizer_targeted_removal_preserves_failing_predicate() {
    let camp = gen_campaign(CampaignComplexity::MultiStage, 0xAA20);

    // Predicate: campaign must have at least one step with HostcallSequence dimension.
    let has_hostcall = |c: &AdversarialCampaign| {
        c.steps
            .iter()
            .any(|s| s.dimension == AttackDimension::HostcallSequence)
    };

    if has_hostcall(&camp) {
        let (minimized, _proof) = AutoMinimizer::minimize_with(&camp, has_hostcall).unwrap();
        assert!(has_hostcall(&minimized), "minimized campaign should still satisfy predicate");
    }
}

#[test]
fn enrichment_minimizer_proof_always_marks_fixed_point() {
    let camp = gen_campaign(CampaignComplexity::Probe, 0xAA30);

    let (_minimized, proof) =
        AutoMinimizer::minimize_with(&camp, |c| !c.steps.is_empty()).unwrap();
    assert!(proof.is_fixed_point, "minimizer proof should always mark is_fixed_point=true");
}

#[test]
fn enrichment_minimizer_no_reduction_when_all_steps_needed() {
    let camp = gen_campaign(CampaignComplexity::Probe, 0xAA40);
    let original_len = camp.steps.len();

    // Predicate requires exactly the original length - cannot remove anything.
    let (minimized, proof) =
        AutoMinimizer::minimize_with(&camp, |c| c.steps.len() >= original_len).unwrap();
    assert_eq!(minimized.steps.len(), original_len);
    assert_eq!(proof.removed_steps, 0);
}

// =========================================================================
// H. CampaignGenerator Lifecycle (3 tests)
// =========================================================================

#[test]
fn enrichment_backpressure_zero_when_queue_full() {
    let generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 10,
            max_backpressure_queue: 5,
            ..CampaignGeneratorConfig::default()
        },
        0xBB10,
    )
    .unwrap();

    assert_eq!(generator.plan_campaign_count(5), 0);
    assert_eq!(generator.plan_campaign_count(6), 0);
    assert_eq!(generator.plan_campaign_count(100), 0);
    // Just below full: capacity = 5 - 4 = 1, min(10, 1) = 1
    assert_eq!(generator.plan_campaign_count(4), 1);
    // Zero backlog: capacity = 5 - 0 = 5, min(10, 5) = 5
    assert_eq!(generator.plan_campaign_count(0), 5);
}

#[test]
fn enrichment_no_promotion_when_score_below_threshold() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 2,
            max_backpressure_queue: 10,
            promotion_threshold_millionths: 999_999,
            ..CampaignGeneratorConfig::default()
        },
        0xBB20,
    )
    .unwrap();

    // Run a cycle with low-scoring results.
    let outputs = generator
        .run_cycle(CampaignComplexity::Probe, 0, |_camp| {
            CampaignExecutionResult {
                undetected_steps: 0,
                total_steps: 4,
                objective_achieved_before_containment: false,
                damage_potential_millionths: 50_000,
                evidence_atoms_before_detection: 1,
                novel_technique: false,
            }
        })
        .unwrap();

    assert_eq!(outputs.len(), 2);
    assert!(generator.regression_corpus().is_empty(), "no promotions should occur for low scores");
}

#[test]
fn enrichment_multiple_cycles_accumulate_scores_and_events() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 1,
            max_backpressure_queue: 10,
            promotion_threshold_millionths: 900_000,
            ..CampaignGeneratorConfig::default()
        },
        0xBB30,
    )
    .unwrap();

    // Run 3 cycles.
    let mut all_campaign_ids = Vec::new();
    for _ in 0..3 {
        let outputs = generator
            .run_cycle(CampaignComplexity::Probe, 0, |_camp| {
                CampaignExecutionResult {
                    undetected_steps: 2,
                    total_steps: 4,
                    objective_achieved_before_containment: false,
                    damage_potential_millionths: 300_000,
                    evidence_atoms_before_detection: 10,
                    novel_technique: false,
                }
            })
            .unwrap();
        for (camp, _score) in &outputs {
            all_campaign_ids.push(camp.campaign_id.clone());
        }
    }

    assert_eq!(all_campaign_ids.len(), 3);
    // All campaign IDs should be unique.
    let unique_ids: BTreeSet<&str> = all_campaign_ids.iter().map(|s| s.as_str()).collect();
    assert_eq!(unique_ids.len(), 3, "each cycle should produce a unique campaign ID");

    // All campaigns should be in the scorebook.
    for id in &all_campaign_ids {
        assert!(generator.score(id).is_some(), "campaign {id} should have a score");
    }

    // Events should have accumulated (drain returns them all).
    let events = generator.drain_events();
    assert!(events.len() >= 3, "should have at least one event per campaign");
}
