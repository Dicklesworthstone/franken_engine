//! Integration tests for `adversarial_campaign` — edge cases not covered by
//! the 14 inline unit tests.
//!
//! Focus areas:
//! - CampaignError Display exact messages + error_code() + std::error::Error
//! - DeterministicRng edge cases (seed 0, choose_index 0, range_u64 boundaries)
//! - All Display trait impls (10 enums)
//! - AttackGrammar validation (version 0, all 5 empty buckets)
//! - AdversarialCampaign validation (8 error paths)
//! - CampaignExecutionResult validation (3 error paths)
//! - ExploitObjectiveScore difficulty classification
//! - All 5 MutationOperator variants
//! - AutoMinimizer edge cases (already minimal, build_fixture)
//! - RegressionCorpus API
//! - RedBlueLoopIntegrator technique_effectiveness, batch ingest, no-op calibration
//! - Suppression gate validation failures
//! - CampaignOutcomeRecord validation
//! - Serde roundtrips for key types
//! - Determinism verification

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

use frankenengine_engine::adversarial_campaign::{
    AdversarialCampaign, AttackDimension, AttackGrammar, AutoMinimizer, CampaignAttackCategory,
    CampaignComplexity, CampaignError, CampaignExecutionResult, CampaignGenerator,
    CampaignGeneratorConfig, CampaignOutcomeRecord, CampaignRuntime, CampaignSeverity,
    CampaignSuppressionSample, CampaignTrendPoint, ContainmentDifficulty, DefenseSubsystem,
    DeterministicRng, ExploitEscalationRecord, ExploitObjectiveScore, GuardplaneCalibrationState,
    MinimizationProof, MutationEngine, MutationOperator, MutationRequest, RedBlueCalibrationConfig,
    RedBlueLoopIntegrator, RegressionCorpus, RegressionReplayResult, SuppressionGateConfig,
    SuppressionGateInput, ThreatCategory, evaluate_compromise_suppression_gate,
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

fn campaign(complexity: CampaignComplexity, seed: u64) -> AdversarialCampaign {
    make_gen(seed).generate_campaign(complexity).unwrap()
}

fn result_ok() -> CampaignExecutionResult {
    CampaignExecutionResult {
        undetected_steps: 3,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 420_000,
        evidence_atoms_before_detection: 14,
        novel_technique: true,
    }
}

fn outcome(
    camp: AdversarialCampaign,
    result: CampaignExecutionResult,
    benign: bool,
    fp: bool,
) -> CampaignOutcomeRecord {
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    CampaignOutcomeRecord {
        campaign: camp,
        result,
        score,
        benign_control: benign,
        false_positive: fp,
        timestamp_ns: 1_700_000_000_000,
    }
}

fn suppression_sample(
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

fn all_category_triples(
    fe_success: u64,
    node_success: u64,
    bun_success: u64,
) -> Vec<CampaignSuppressionSample> {
    CampaignAttackCategory::ALL
        .iter()
        .flat_map(|cat| {
            [
                suppression_sample(
                    &format!("camp-fe-{cat}"),
                    *cat,
                    CampaignRuntime::FrankenEngine,
                    250,
                    fe_success,
                ),
                suppression_sample(
                    &format!("camp-node-{cat}"),
                    *cat,
                    CampaignRuntime::NodeLts,
                    250,
                    node_success,
                ),
                suppression_sample(
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

// =========================================================================
// 1. CampaignError Display exact messages
// =========================================================================

#[test]
fn campaign_error_display_invalid_grammar() {
    let err = CampaignError::InvalidGrammar {
        detail: "bucket empty".to_string(),
    };
    assert_eq!(err.to_string(), "invalid grammar: bucket empty");
}

#[test]
fn campaign_error_display_invalid_campaign() {
    let err = CampaignError::InvalidCampaign {
        detail: "no steps".to_string(),
    };
    assert_eq!(err.to_string(), "invalid campaign: no steps");
}

#[test]
fn campaign_error_display_invalid_execution_result() {
    let err = CampaignError::InvalidExecutionResult {
        detail: "zero total".to_string(),
    };
    assert_eq!(err.to_string(), "invalid execution result: zero total");
}

#[test]
fn campaign_error_display_invalid_mutation() {
    let err = CampaignError::InvalidMutation {
        detail: "bad operator".to_string(),
    };
    assert_eq!(err.to_string(), "invalid mutation: bad operator");
}

#[test]
fn campaign_error_display_invalid_seed() {
    assert_eq!(
        CampaignError::InvalidSeed.to_string(),
        "seed must be non-zero"
    );
}

#[test]
fn campaign_error_display_invalid_calibration() {
    let err = CampaignError::InvalidCalibration {
        detail: "no outcomes".to_string(),
    };
    assert_eq!(err.to_string(), "invalid calibration: no outcomes");
}

// =========================================================================
// 2. CampaignError error_code() all variants
// =========================================================================

#[test]
fn campaign_error_code_all_variants() {
    assert_eq!(
        CampaignError::InvalidGrammar {
            detail: String::new()
        }
        .error_code(),
        "FE-ADV-CAMP-0001"
    );
    assert_eq!(
        CampaignError::InvalidCampaign {
            detail: String::new()
        }
        .error_code(),
        "FE-ADV-CAMP-0002"
    );
    assert_eq!(
        CampaignError::InvalidExecutionResult {
            detail: String::new()
        }
        .error_code(),
        "FE-ADV-CAMP-0003"
    );
    assert_eq!(
        CampaignError::InvalidMutation {
            detail: String::new()
        }
        .error_code(),
        "FE-ADV-CAMP-0004"
    );
    assert_eq!(CampaignError::InvalidSeed.error_code(), "FE-ADV-CAMP-0005");
    assert_eq!(
        CampaignError::InvalidCalibration {
            detail: String::new()
        }
        .error_code(),
        "FE-ADV-CAMP-0006"
    );
}

// =========================================================================
// 3. CampaignError implements std::error::Error
// =========================================================================

#[test]
fn campaign_error_implements_std_error() {
    let err: &dyn std::error::Error = &CampaignError::InvalidSeed;
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// 4. DeterministicRng edge cases
// =========================================================================

#[test]
fn rng_rejects_seed_zero() {
    let err = DeterministicRng::new(0).unwrap_err();
    assert_eq!(err, CampaignError::InvalidSeed);
}

#[test]
fn rng_accepts_seed_one() {
    let mut rng = DeterministicRng::new(1).unwrap();
    let val = rng.next_u64();
    assert_ne!(val, 0); // xorshift64* with seed=1 should produce non-zero.
}

#[test]
fn rng_accepts_seed_max() {
    let mut rng = DeterministicRng::new(u64::MAX).unwrap();
    let _ = rng.next_u64();
}

#[test]
fn rng_choose_index_zero_len() {
    let mut rng = DeterministicRng::new(42).unwrap();
    assert_eq!(rng.choose_index(0), 0);
}

#[test]
fn rng_choose_index_single_element() {
    let mut rng = DeterministicRng::new(42).unwrap();
    assert_eq!(rng.choose_index(1), 0);
}

#[test]
fn rng_range_u64_degenerate() {
    let mut rng = DeterministicRng::new(42).unwrap();
    // end <= start returns start.
    assert_eq!(rng.range_u64(10, 10), 10);
    assert_eq!(rng.range_u64(10, 5), 10);
}

#[test]
fn rng_range_u64_single_value() {
    let mut rng = DeterministicRng::new(42).unwrap();
    let val = rng.range_u64(7, 8);
    assert_eq!(val, 7);
}

#[test]
fn rng_deterministic_sequence() {
    let mut a = DeterministicRng::new(0xBEEF).unwrap();
    let mut b = DeterministicRng::new(0xBEEF).unwrap();
    for _ in 0..100 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

// =========================================================================
// 5. Display traits — all enum variants
// =========================================================================

#[test]
fn campaign_complexity_display() {
    assert_eq!(CampaignComplexity::Probe.to_string(), "probe");
    assert_eq!(CampaignComplexity::MultiStage.to_string(), "multi_stage");
    assert_eq!(CampaignComplexity::Apt.to_string(), "apt");
}

#[test]
fn attack_dimension_display() {
    assert_eq!(
        AttackDimension::HostcallSequence.to_string(),
        "hostcall_sequence"
    );
    assert_eq!(
        AttackDimension::TemporalPayload.to_string(),
        "temporal_payload"
    );
    assert_eq!(
        AttackDimension::PrivilegeEscalation.to_string(),
        "privilege_escalation"
    );
    assert_eq!(AttackDimension::PolicyEvasion.to_string(), "policy_evasion");
    assert_eq!(AttackDimension::Exfiltration.to_string(), "exfiltration");
}

#[test]
fn containment_difficulty_display() {
    assert_eq!(ContainmentDifficulty::Easy.to_string(), "easy");
    assert_eq!(ContainmentDifficulty::Moderate.to_string(), "moderate");
    assert_eq!(ContainmentDifficulty::Hard.to_string(), "hard");
    assert_eq!(ContainmentDifficulty::Critical.to_string(), "critical");
}

#[test]
fn mutation_operator_display() {
    assert_eq!(
        MutationOperator::PointMutation.to_string(),
        "point_mutation"
    );
    assert_eq!(MutationOperator::Crossover.to_string(), "crossover");
    assert_eq!(MutationOperator::Insertion.to_string(), "insertion");
    assert_eq!(MutationOperator::Deletion.to_string(), "deletion");
    assert_eq!(
        MutationOperator::TemporalShift.to_string(),
        "temporal_shift"
    );
}

#[test]
fn defense_subsystem_display() {
    assert_eq!(DefenseSubsystem::Sentinel.to_string(), "sentinel");
    assert_eq!(DefenseSubsystem::Containment.to_string(), "containment");
    assert_eq!(
        DefenseSubsystem::EvidenceAccumulation.to_string(),
        "evidence_accumulation"
    );
    assert_eq!(
        DefenseSubsystem::FleetConvergence.to_string(),
        "fleet_convergence"
    );
}

#[test]
fn threat_category_display() {
    assert_eq!(
        ThreatCategory::CredentialTheft.to_string(),
        "credential_theft"
    );
    assert_eq!(
        ThreatCategory::PrivilegeEscalation.to_string(),
        "privilege_escalation"
    );
    assert_eq!(ThreatCategory::Persistence.to_string(), "persistence");
    assert_eq!(ThreatCategory::Exfiltration.to_string(), "exfiltration");
    assert_eq!(ThreatCategory::PolicyEvasion.to_string(), "policy_evasion");
}

#[test]
fn campaign_severity_display() {
    assert_eq!(CampaignSeverity::Advisory.to_string(), "advisory");
    assert_eq!(CampaignSeverity::Moderate.to_string(), "moderate");
    assert_eq!(CampaignSeverity::Critical.to_string(), "critical");
    assert_eq!(CampaignSeverity::Blocking.to_string(), "blocking");
}

#[test]
fn campaign_runtime_display() {
    assert_eq!(CampaignRuntime::FrankenEngine.to_string(), "franken_engine");
    assert_eq!(CampaignRuntime::NodeLts.to_string(), "node_lts");
    assert_eq!(CampaignRuntime::BunStable.to_string(), "bun_stable");
}

#[test]
fn campaign_attack_category_display() {
    assert_eq!(CampaignAttackCategory::Injection.to_string(), "injection");
    assert_eq!(
        CampaignAttackCategory::PrototypePollution.to_string(),
        "prototype_pollution"
    );
    assert_eq!(
        CampaignAttackCategory::SupplyChain.to_string(),
        "supply_chain"
    );
    assert_eq!(
        CampaignAttackCategory::CapabilityEscape.to_string(),
        "capability_escape"
    );
    assert_eq!(
        CampaignAttackCategory::TimingSideChannel.to_string(),
        "timing_side_channel"
    );
}

// =========================================================================
// 6. AttackGrammar validation edge cases
// =========================================================================

#[test]
fn grammar_validation_rejects_version_zero() {
    let grammar = AttackGrammar {
        version: 0,
        ..AttackGrammar::default()
    };
    let err = grammar.validate().unwrap_err();
    assert!(err.to_string().contains("version"));
}

#[test]
fn grammar_validation_rejects_each_empty_bucket() {
    let buckets = [
        "hostcall_motifs",
        "temporal_staging",
        "privilege_escalation",
        "policy_evasion",
        "exfiltration",
    ];

    for bucket_name in &buckets {
        let mut grammar = AttackGrammar::default();
        match *bucket_name {
            "hostcall_motifs" => grammar.hostcall_motifs = vec![],
            "temporal_staging" => grammar.temporal_staging = vec![],
            "privilege_escalation" => grammar.privilege_escalation = vec![],
            "policy_evasion" => grammar.policy_evasion = vec![],
            "exfiltration" => grammar.exfiltration = vec![],
            _ => unreachable!(),
        }
        let err = grammar.validate().unwrap_err();
        assert!(
            err.to_string().contains(bucket_name),
            "Expected error mentioning {bucket_name}, got: {err}"
        );
    }
}

#[test]
fn grammar_default_validates() {
    AttackGrammar::default().validate().unwrap();
}

// =========================================================================
// 7. AdversarialCampaign validation edge cases
// =========================================================================

#[test]
fn campaign_validation_rejects_empty_campaign_id() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA1);
    camp.campaign_id.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("campaign_id"));
}

#[test]
fn campaign_validation_rejects_empty_trace_id() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA2);
    camp.trace_id.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn campaign_validation_rejects_empty_decision_id() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA3);
    camp.decision_id.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn campaign_validation_rejects_empty_policy_id() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA4);
    camp.policy_id.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn campaign_validation_rejects_grammar_version_zero() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA5);
    camp.grammar_version = 0;
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("grammar_version"));
}

#[test]
fn campaign_validation_rejects_seed_zero() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA6);
    camp.seed = 0;
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("seed"));
}

#[test]
fn campaign_validation_rejects_empty_steps() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA7);
    camp.steps.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("at least one step"));
}

#[test]
fn campaign_validation_rejects_non_contiguous_step_ids() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA8);
    if camp.steps.len() >= 2 {
        camp.steps[1].step_id = 5; // Break contiguity.
        let err = camp.validate().unwrap_err();
        assert!(err.to_string().contains("contiguous"));
    }
}

#[test]
fn campaign_validation_rejects_empty_production_label() {
    let mut camp = campaign(CampaignComplexity::Probe, 0xA9);
    camp.steps[0].production_label.clear();
    let err = camp.validate().unwrap_err();
    assert!(err.to_string().contains("production_label"));
}

// =========================================================================
// 8. CampaignExecutionResult validation edge cases
// =========================================================================

#[test]
fn result_validation_rejects_zero_total_steps() {
    let result = CampaignExecutionResult {
        total_steps: 0,
        ..result_ok()
    };
    let err = result.validate().unwrap_err();
    assert!(err.to_string().contains("total_steps"));
}

#[test]
fn result_validation_rejects_undetected_exceeding_total() {
    let result = CampaignExecutionResult {
        undetected_steps: 6,
        total_steps: 5,
        ..result_ok()
    };
    let err = result.validate().unwrap_err();
    assert!(err.to_string().contains("undetected_steps"));
}

#[test]
fn result_validation_rejects_damage_over_million() {
    let result = CampaignExecutionResult {
        damage_potential_millionths: 1_000_001,
        ..result_ok()
    };
    let err = result.validate().unwrap_err();
    assert!(err.to_string().contains("damage_potential"));
}

#[test]
fn result_validation_accepts_boundary_values() {
    // All zeroes except total_steps.
    let result = CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 1,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 0,
        evidence_atoms_before_detection: 0,
        novel_technique: false,
    };
    result.validate().unwrap();
}

#[test]
fn result_validation_accepts_max_damage() {
    let result = CampaignExecutionResult {
        damage_potential_millionths: 1_000_000,
        ..result_ok()
    };
    result.validate().unwrap();
}

// =========================================================================
// 9. ExploitObjectiveScore difficulty classification
// =========================================================================

#[test]
fn score_easy_difficulty() {
    let result = CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 10,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 100_000,
        evidence_atoms_before_detection: 2,
        novel_technique: false,
    };
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    assert_eq!(score.difficulty, ContainmentDifficulty::Easy);
}

#[test]
fn score_deterministic_on_identical_input() {
    let a = ExploitObjectiveScore::from_result(&result_ok()).unwrap();
    let b = ExploitObjectiveScore::from_result(&result_ok()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.composite_score_millionths, b.composite_score_millionths);
}

// =========================================================================
// 10. All 5 MutationOperator variants
// =========================================================================

#[test]
fn mutation_point_mutation() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::Probe, 0xAA01);
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0xBEEF,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
}

#[test]
fn mutation_crossover_without_donor_is_rejected() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::MultiStage, 0xAA02);
    let err = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0xCAFE,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("donor_campaign"));
}

#[test]
fn mutation_crossover_with_donor() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::MultiStage, 0xAA03);
    let donor = campaign(CampaignComplexity::Apt, 0xD0);
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0xCAFE,
            donor_campaign: Some(donor),
        },
    )
    .unwrap();
    mutated.validate().unwrap();
}

#[test]
fn mutation_insertion() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::Probe, 0xAA04);
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Insertion,
            seed: 0xD00D,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert!(mutated.steps.len() >= base.steps.len());
}

#[test]
fn mutation_deletion() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::Apt, 0xAA05);
    let original_len = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Deletion,
            seed: 0xFACE,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    // Deletion should remove steps (or keep at minimum 1).
    assert!(mutated.steps.len() <= original_len);
}

#[test]
fn mutation_temporal_shift() {
    let grammar = AttackGrammar::default();
    let base = campaign(CampaignComplexity::MultiStage, 0xAA06);
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::TemporalShift,
            seed: 0xFEED,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert_eq!(mutated.steps.len(), base.steps.len());
}

// =========================================================================
// 11. AutoMinimizer edge cases
// =========================================================================

#[test]
fn minimizer_on_already_minimal_campaign() {
    let camp = campaign(CampaignComplexity::Probe, 0xCC01);
    // "still_fails" requires exactly 1 step — minimizer cannot remove below 1.
    let (minimized, proof) = AutoMinimizer::minimize_with(&camp, |c| !c.steps.is_empty()).unwrap();
    assert!(!minimized.steps.is_empty());
    assert!(proof.is_fixed_point || proof.rounds > 0);
}

#[test]
fn minimizer_build_fixture_preserves_fields() {
    let camp = campaign(CampaignComplexity::Probe, 0xCC02);
    let proof = MinimizationProof {
        rounds: 3,
        removed_steps: 1,
        is_fixed_point: true,
    };
    let fixture =
        AutoMinimizer::build_fixture(&camp, "expected-defense", "actual-defense", proof.clone());
    assert_eq!(fixture.campaign_id, camp.campaign_id);
    assert_eq!(fixture.seed, camp.seed);
    assert_eq!(fixture.expected_defense_response, "expected-defense");
    assert_eq!(fixture.actual_defense_response, "actual-defense");
    assert_eq!(fixture.minimality_proof, proof);
}

// =========================================================================
// 12. RegressionCorpus API
// =========================================================================

#[test]
fn regression_corpus_initially_empty() {
    let corpus = RegressionCorpus::default();
    assert!(corpus.is_empty());
    assert_eq!(corpus.len(), 0);
}

#[test]
fn regression_corpus_promote_and_lookup() {
    let camp = campaign(CampaignComplexity::Probe, 0xCC03);
    let campaign_id = camp.campaign_id.clone();
    let proof = MinimizationProof {
        rounds: 1,
        removed_steps: 0,
        is_fixed_point: true,
    };
    let fixture = AutoMinimizer::build_fixture(&camp, "expected", "actual", proof);

    let mut corpus = RegressionCorpus::default();
    corpus.promote(fixture.clone());
    assert_eq!(corpus.len(), 1);
    assert!(!corpus.is_empty());

    let found = corpus.fixture(&campaign_id).unwrap();
    assert_eq!(found.campaign_id, campaign_id);
}

#[test]
fn regression_corpus_missing_fixture_returns_none() {
    let corpus = RegressionCorpus::default();
    assert!(corpus.fixture("nonexistent").is_none());
}

// =========================================================================
// 13. Campaign generation — all complexity levels
// =========================================================================

#[test]
fn generate_probe_campaign() {
    let camp = campaign(CampaignComplexity::Probe, 0xBB01);
    camp.validate().unwrap();
    assert!(!camp.steps.is_empty());
}

#[test]
fn generate_multi_stage_campaign() {
    let camp = campaign(CampaignComplexity::MultiStage, 0xBB02);
    camp.validate().unwrap();
    assert!(camp.steps.len() > 1);
}

#[test]
fn generate_apt_campaign() {
    let camp = campaign(CampaignComplexity::Apt, 0xBB03);
    camp.validate().unwrap();
    assert!(camp.steps.len() >= 4);
}

// =========================================================================
// 14. CampaignGenerator plan_campaign_count
// =========================================================================

#[test]
fn plan_campaign_count_zero_backlog_allows_generation() {
    let g = make_gen(0xDD01);
    let count = g.plan_campaign_count(0);
    assert!(count > 0);
}

#[test]
fn plan_campaign_count_at_max_returns_zero() {
    let g = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            max_backpressure_queue: 10,
            ..CampaignGeneratorConfig::default()
        },
        0xDD02,
    )
    .unwrap();
    assert_eq!(g.plan_campaign_count(10), 0);
}

#[test]
fn plan_campaign_count_above_max_returns_zero() {
    let g = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            max_backpressure_queue: 5,
            ..CampaignGeneratorConfig::default()
        },
        0xDD03,
    )
    .unwrap();
    assert_eq!(g.plan_campaign_count(100), 0);
}

// =========================================================================
// 15. CampaignGenerator score and record_campaign_outcome
// =========================================================================

#[test]
fn score_campaign_and_record_outcome() {
    let mut g = make_gen(0xEE01);
    let camp = g.generate_campaign(CampaignComplexity::Probe).unwrap();
    let result = result_ok();
    let score = g.score_campaign(&camp, &result).unwrap();
    assert!(score.composite_score_millionths > 0);

    g.record_campaign_outcome(&camp, &score).unwrap();
    assert!(g.score(&camp.campaign_id).is_some());
    assert_eq!(g.score(&camp.campaign_id).unwrap(), &score);
}

#[test]
fn score_missing_campaign_returns_none() {
    let g = make_gen(0xEE02);
    assert!(g.score("nonexistent").is_none());
}

// =========================================================================
// 16. CampaignGenerator promote_failure_fixture
// =========================================================================

#[test]
fn promote_failure_fixture_adds_to_corpus() {
    let mut g = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            promotion_threshold_millionths: 0, // Promote everything.
            ..CampaignGeneratorConfig::default()
        },
        0xFF01,
    )
    .unwrap();
    let camp = g.generate_campaign(CampaignComplexity::Probe).unwrap();
    let result = CampaignExecutionResult {
        undetected_steps: camp.steps.len(),
        total_steps: camp.steps.len(),
        objective_achieved_before_containment: true,
        damage_potential_millionths: 900_000,
        evidence_atoms_before_detection: 50,
        novel_technique: true,
    };
    let score = g.score_campaign(&camp, &result).unwrap();
    g.record_campaign_outcome(&camp, &score).unwrap();

    let fixture = g
        .promote_failure_fixture(&camp, "expected", "actual", |c| !c.steps.is_empty())
        .unwrap();
    // Minimized campaign may have "-min" suffix.
    assert!(fixture.campaign_id.starts_with(&camp.campaign_id[..12]));
    assert!(!g.regression_corpus().is_empty());
}

// =========================================================================
// 17. RedBlueLoopIntegrator — technique effectiveness
// =========================================================================

#[test]
fn technique_effectiveness_initially_empty() {
    let integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let eff = integrator.technique_effectiveness();
    assert!(eff.is_empty());
}

#[test]
fn technique_effectiveness_after_ingest() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let camp = campaign(CampaignComplexity::Probe, 0xFF02);
    let result = result_ok();
    integrator
        .ingest_outcome(outcome(camp, result, false, false))
        .unwrap();

    let eff = integrator.technique_effectiveness();
    assert!(!eff.is_empty());
}

// =========================================================================
// 18. RedBlueLoopIntegrator — batch ingest
// =========================================================================

#[test]
fn ingest_outcomes_batch() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());

    let outcomes: Vec<_> = (0..5u64)
        .map(|i| {
            let camp = campaign(CampaignComplexity::Probe, 0xBA + i);
            outcome(camp, result_ok(), false, false)
        })
        .collect();

    let classifications = integrator.ingest_outcomes(&outcomes).unwrap();
    assert_eq!(classifications.len(), 5);

    let events = integrator.drain_events();
    assert_eq!(events.len(), 5);
}

// =========================================================================
// 19. RedBlueLoopIntegrator — calibration no-op
// =========================================================================

#[test]
fn calibration_with_no_outcomes_returns_none() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let signing_key = [0x42u8; 32];
    let receipt = integrator.calibrate(&signing_key, 1_000_000).unwrap();
    assert!(receipt.is_none());
}

// =========================================================================
// 20. Regression gate edge cases
// =========================================================================

#[test]
fn regression_gate_passes_when_no_fixtures() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let decision = integrator.evaluate_regression_gate(&[]);
    // No fixtures → no regressions → pass.
    assert!(decision.passed);
}

#[test]
fn regression_gate_fails_when_fixture_missing_from_results() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());

    let camp = campaign(CampaignComplexity::Probe, 0xFF03);
    let campaign_id = camp.campaign_id.clone();
    let result = result_ok();
    integrator
        .ingest_outcome(outcome(camp, result, false, false))
        .unwrap();

    let _ = integrator
        .promote_regression_fixture(&campaign_id, "expected", "actual", None)
        .unwrap();
    assert_eq!(integrator.regression_suite().len(), 1);

    // Empty replay results → fixture is missing → fail.
    let decision = integrator.evaluate_regression_gate(&[]);
    assert!(!decision.passed);
    assert!(decision.failed_campaign_ids.contains(&campaign_id));
}

#[test]
fn regression_gate_passes_when_all_replay_pass() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());

    let camp = campaign(CampaignComplexity::Probe, 0xFF04);
    let campaign_id = camp.campaign_id.clone();
    let result = result_ok();
    integrator
        .ingest_outcome(outcome(camp, result, false, false))
        .unwrap();

    let _ = integrator
        .promote_regression_fixture(&campaign_id, "expected", "actual", None)
        .unwrap();

    let decision = integrator.evaluate_regression_gate(&[RegressionReplayResult {
        campaign_id,
        passed: true,
    }]);
    assert!(decision.passed);
}

// =========================================================================
// 21. Counterfactual hints — empty when no critical outcomes
// =========================================================================

#[test]
fn counterfactual_hints_empty_with_no_outcomes() {
    let integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    assert!(integrator.critical_counterfactual_hints().is_empty());
}

// =========================================================================
// 22. Suppression gate — validation failures
// =========================================================================

#[test]
fn suppression_gate_rejects_empty_release_candidate_id() {
    let input = SuppressionGateInput {
        release_candidate_id: String::new(),
        continuous_run: true,
        samples: all_category_triples(0, 45, 38),
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-1".to_string(),
                timestamp_ns: 1_000,
                samples_evaluated: 100,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-2".to_string(),
                timestamp_ns: 2_000,
                samples_evaluated: 100,
            },
        ],
        escalations: Vec::new(),
    };
    let err = evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default())
        .unwrap_err();
    assert!(err.to_string().contains("release_candidate_id"));
}

#[test]
fn suppression_gate_rejects_empty_samples() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-test".to_string(),
        continuous_run: true,
        samples: vec![],
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-1".to_string(),
                timestamp_ns: 1_000,
                samples_evaluated: 100,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-2".to_string(),
                timestamp_ns: 2_000,
                samples_evaluated: 100,
            },
        ],
        escalations: Vec::new(),
    };
    let err = evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default())
        .unwrap_err();
    assert!(err.to_string().contains("sample"));
}

#[test]
fn suppression_gate_fails_on_insufficient_trend_points() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-trend".to_string(),
        continuous_run: true,
        samples: all_category_triples(0, 45, 38),
        trend_points: vec![CampaignTrendPoint {
            release_candidate_id: "rc-1".to_string(),
            timestamp_ns: 1_000,
            samples_evaluated: 100,
        }],
        escalations: Vec::new(),
    };
    // Config requires minimum_trend_points=2.
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    // Should fail because only 1 trend point < required 2.
    assert!(!result.passed);
}

// =========================================================================
// 23. CampaignOutcomeRecord validation
// =========================================================================

#[test]
fn outcome_record_rejects_false_positive_without_benign() {
    let camp = campaign(CampaignComplexity::Probe, 0xFF05);
    let result = result_ok();
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    let record = CampaignOutcomeRecord {
        campaign: camp,
        result,
        score,
        benign_control: false,
        false_positive: true,
        timestamp_ns: 1_000,
    };
    let err = record.validate().unwrap_err();
    assert!(err.to_string().contains("false_positive"));
}

// =========================================================================
// 24. CampaignSuppressionSample validation
// =========================================================================

#[test]
fn suppression_sample_rejects_empty_campaign_id() {
    let sample = CampaignSuppressionSample {
        campaign_id: String::new(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        attempt_count: 100,
        success_count: 5,
        raw_log_ref: "log".to_string(),
        repro_script_ref: "repro".to_string(),
    };
    let err = sample.validate().unwrap_err();
    assert!(err.to_string().contains("campaign_id"));
}

#[test]
fn suppression_sample_rejects_zero_attempt_count() {
    let sample = CampaignSuppressionSample {
        campaign_id: "camp-1".to_string(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        attempt_count: 0,
        success_count: 0,
        raw_log_ref: "log".to_string(),
        repro_script_ref: "repro".to_string(),
    };
    let err = sample.validate().unwrap_err();
    assert!(err.to_string().contains("attempt_count"));
}

// =========================================================================
// 25. ExploitEscalationRecord validation
// =========================================================================

#[test]
fn escalation_rejects_empty_campaign_id() {
    let esc = ExploitEscalationRecord {
        campaign_id: String::new(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: false,
        escalation_triggered: false,
        escalation_latency_seconds: None,
    };
    let err = esc.validate().unwrap_err();
    assert!(err.to_string().contains("campaign_id"));
}

#[test]
fn escalation_rejects_triggered_without_latency() {
    let esc = ExploitEscalationRecord {
        campaign_id: "camp-1".to_string(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: true,
        escalation_triggered: true,
        escalation_latency_seconds: None,
    };
    let err = esc.validate().unwrap_err();
    assert!(err.to_string().contains("latency"));
}

// =========================================================================
// 26. CampaignAttackCategory::ALL is exhaustive
// =========================================================================

#[test]
fn attack_category_all_has_five_elements() {
    assert_eq!(CampaignAttackCategory::ALL.len(), 5);
}

// =========================================================================
// 27. Serde roundtrips for key types
// =========================================================================

#[test]
fn campaign_error_serde_roundtrip() {
    let errors = vec![
        CampaignError::InvalidGrammar {
            detail: "test".to_string(),
        },
        CampaignError::InvalidCampaign {
            detail: "test".to_string(),
        },
        CampaignError::InvalidExecutionResult {
            detail: "test".to_string(),
        },
        CampaignError::InvalidMutation {
            detail: "test".to_string(),
        },
        CampaignError::InvalidSeed,
        CampaignError::InvalidCalibration {
            detail: "test".to_string(),
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: CampaignError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }
}

#[test]
fn campaign_complexity_serde_roundtrip() {
    for c in [
        CampaignComplexity::Probe,
        CampaignComplexity::MultiStage,
        CampaignComplexity::Apt,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let deser: CampaignComplexity = serde_json::from_str(&json).unwrap();
        assert_eq!(c, deser);
    }
}

#[test]
fn attack_dimension_serde_roundtrip() {
    for d in [
        AttackDimension::HostcallSequence,
        AttackDimension::TemporalPayload,
        AttackDimension::PrivilegeEscalation,
        AttackDimension::PolicyEvasion,
        AttackDimension::Exfiltration,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let deser: AttackDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(d, deser);
    }
}

#[test]
fn containment_difficulty_serde_roundtrip() {
    for d in [
        ContainmentDifficulty::Easy,
        ContainmentDifficulty::Moderate,
        ContainmentDifficulty::Hard,
        ContainmentDifficulty::Critical,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let deser: ContainmentDifficulty = serde_json::from_str(&json).unwrap();
        assert_eq!(d, deser);
    }
}

#[test]
fn mutation_operator_serde_roundtrip() {
    for op in [
        MutationOperator::PointMutation,
        MutationOperator::Crossover,
        MutationOperator::Insertion,
        MutationOperator::Deletion,
        MutationOperator::TemporalShift,
    ] {
        let json = serde_json::to_string(&op).unwrap();
        let deser: MutationOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(op, deser);
    }
}

#[test]
fn campaign_severity_serde_roundtrip() {
    for s in [
        CampaignSeverity::Advisory,
        CampaignSeverity::Moderate,
        CampaignSeverity::Critical,
        CampaignSeverity::Blocking,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let deser: CampaignSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, deser);
    }
}

#[test]
fn generated_campaign_serde_roundtrip() {
    let camp = campaign(CampaignComplexity::MultiStage, 0xFF06);
    let json = serde_json::to_string(&camp).unwrap();
    let deser: AdversarialCampaign = serde_json::from_str(&json).unwrap();
    assert_eq!(camp, deser);
}

#[test]
fn exploit_objective_score_serde_roundtrip() {
    let score = ExploitObjectiveScore::from_result(&result_ok()).unwrap();
    let json = serde_json::to_string(&score).unwrap();
    let deser: ExploitObjectiveScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, deser);
}

#[test]
fn minimization_proof_serde_roundtrip() {
    let proof = MinimizationProof {
        rounds: 5,
        removed_steps: 3,
        is_fixed_point: true,
    };
    let json = serde_json::to_string(&proof).unwrap();
    let deser: MinimizationProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, deser);
}

// =========================================================================
// 28. Events emitted from CampaignGenerator
// =========================================================================

#[test]
fn generator_drains_events_after_cycle() {
    let mut g = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 2,
            max_backpressure_queue: 10,
            ..CampaignGeneratorConfig::default()
        },
        0xFF07,
    )
    .unwrap();

    let _ = g.run_cycle(CampaignComplexity::Probe, 0, |_| CampaignExecutionResult {
        undetected_steps: 1,
        total_steps: 3,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 200_000,
        evidence_atoms_before_detection: 5,
        novel_technique: false,
    });

    let events = g.drain_events();
    assert!(!events.is_empty());

    // Second drain should be empty.
    let events2 = g.drain_events();
    assert!(events2.is_empty());
}

// =========================================================================
// 29. Determinism — different seeds produce different campaigns
// =========================================================================

#[test]
fn different_seeds_produce_different_campaigns() {
    let camp_a = campaign(CampaignComplexity::Probe, 0x1111);
    let camp_b = campaign(CampaignComplexity::Probe, 0x2222);
    // They should differ (campaign_id, steps, etc.)
    assert_ne!(camp_a.campaign_id, camp_b.campaign_id);
}

// =========================================================================
// 30. GuardplaneCalibrationState default
// =========================================================================

#[test]
fn guardplane_calibration_state_default_values() {
    let state = GuardplaneCalibrationState::default();
    assert_eq!(state.detection_threshold_millionths, 700_000);
    assert_eq!(state.calibration_epoch, 0);
    assert!(!state.evidence_weights_millionths.is_empty());
    assert!(!state.loss_matrix_millionths.is_empty());
}

// =========================================================================
// 31. RedBlueCalibrationConfig default
// =========================================================================

#[test]
fn red_blue_calibration_config_default_values() {
    let config = RedBlueCalibrationConfig::default();
    assert_eq!(config.target_false_negative_millionths, 10_000);
    assert_eq!(config.target_false_positive_millionths, 10_000);
    assert_eq!(config.max_threshold_delta_millionths, 50_000);
    assert_eq!(config.evidence_weight_delta_millionths, 20_000);
    assert_eq!(config.max_evidence_weight_millionths, 950_000);
}

// =========================================================================
// 32. SuppressionGateConfig default
// =========================================================================

#[test]
fn suppression_gate_config_default_values() {
    let config = SuppressionGateConfig::default();
    assert_eq!(config.required_categories.len(), 5);
    assert_eq!(config.minimum_baseline_runtimes, 2);
    assert_eq!(config.max_p_value_millionths, 50_000);
    assert!(config.require_continuous_run);
    assert_eq!(config.minimum_trend_points, 2);
    assert_eq!(config.max_escalation_latency_seconds, 3_600);
}

// =========================================================================
// 33. CampaignGeneratorConfig default
// =========================================================================

#[test]
fn campaign_generator_config_default_values() {
    let config = CampaignGeneratorConfig::default();
    assert_eq!(config.policy_id, "policy-adversarial-default");
    assert_eq!(config.campaigns_per_hour, 12);
    assert_eq!(config.max_backpressure_queue, 24);
    assert_eq!(config.promotion_threshold_millionths, 700_000);
}

// =========================================================================
// 34. RedBlue classify without ingest
// =========================================================================

#[test]
fn classify_benign_as_advisory() {
    let integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let camp = campaign(CampaignComplexity::Probe, 0xFF08);
    let result = CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: camp.steps.len(),
        objective_achieved_before_containment: false,
        damage_potential_millionths: 50_000,
        evidence_atoms_before_detection: 2,
        novel_technique: false,
    };
    let o = outcome(camp, result, true, false);
    let classification = integrator.classify(&o);
    // Benign control with low scores should be advisory or moderate.
    assert!(
        classification.severity == CampaignSeverity::Advisory
            || classification.severity == CampaignSeverity::Moderate
    );
}
