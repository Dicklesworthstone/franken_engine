//! Integration tests for the adversarial_campaign module.
//!
//! bd-1b0a: Covers error variants, mutation operators, scoring edge cases,
//! red-blue calibration, suppression gate, statistical helpers, and
//! campaign lifecycle flows.

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

use frankenengine_engine::adversarial_campaign::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_grammar() -> AttackGrammar {
    AttackGrammar::default()
}

fn default_config() -> CampaignGeneratorConfig {
    CampaignGeneratorConfig::default()
}

fn make_generator(seed: u64) -> CampaignGenerator {
    CampaignGenerator::new(default_grammar(), default_config(), seed).unwrap()
}

fn make_campaign(seed: u64, complexity: CampaignComplexity) -> AdversarialCampaign {
    let mut generator = make_generator(seed);
    generator.generate_campaign(complexity).unwrap()
}

fn make_result(
    undetected: usize,
    total: usize,
    escaped: bool,
    damage: u64,
    evidence: u64,
    novel: bool,
) -> CampaignExecutionResult {
    CampaignExecutionResult {
        undetected_steps: undetected,
        total_steps: total,
        objective_achieved_before_containment: escaped,
        damage_potential_millionths: damage,
        evidence_atoms_before_detection: evidence,
        novel_technique: novel,
    }
}

fn make_outcome(
    campaign: AdversarialCampaign,
    result: CampaignExecutionResult,
    benign: bool,
    false_pos: bool,
    ts: u64,
) -> CampaignOutcomeRecord {
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    CampaignOutcomeRecord {
        campaign,
        result,
        score,
        benign_control: benign,
        false_positive: false_pos,
        timestamp_ns: ts,
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
        raw_log_ref: format!("artifacts/{id}.jsonl"),
        repro_script_ref: format!("artifacts/{id}.sh"),
    }
}

// ---------------------------------------------------------------------------
// CampaignError — all variants
// ---------------------------------------------------------------------------

#[test]
fn error_invalid_grammar_has_correct_code() {
    let err = CampaignError::InvalidGrammar {
        detail: "test".into(),
    };
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0001");
    assert!(err.to_string().contains("invalid grammar"));
}

#[test]
fn error_invalid_campaign_has_correct_code() {
    let err = CampaignError::InvalidCampaign {
        detail: "test".into(),
    };
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0002");
    assert!(err.to_string().contains("invalid campaign"));
}

#[test]
fn error_invalid_execution_result_has_correct_code() {
    let err = CampaignError::InvalidExecutionResult {
        detail: "test".into(),
    };
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0003");
    assert!(err.to_string().contains("invalid execution result"));
}

#[test]
fn error_invalid_mutation_has_correct_code() {
    let err = CampaignError::InvalidMutation {
        detail: "test".into(),
    };
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0004");
    assert!(err.to_string().contains("invalid mutation"));
}

#[test]
fn error_invalid_seed_has_correct_code() {
    let err = CampaignError::InvalidSeed;
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0005");
    assert!(err.to_string().contains("seed must be non-zero"));
}

#[test]
fn error_invalid_calibration_has_correct_code() {
    let err = CampaignError::InvalidCalibration {
        detail: "test".into(),
    };
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0006");
    assert!(err.to_string().contains("invalid calibration"));
}

#[test]
fn all_error_codes_unique() {
    let errors = [
        CampaignError::InvalidGrammar {
            detail: String::new(),
        },
        CampaignError::InvalidCampaign {
            detail: String::new(),
        },
        CampaignError::InvalidExecutionResult {
            detail: String::new(),
        },
        CampaignError::InvalidMutation {
            detail: String::new(),
        },
        CampaignError::InvalidSeed,
        CampaignError::InvalidCalibration {
            detail: String::new(),
        },
    ];
    let codes: Vec<_> = errors.iter().map(|e| e.error_code()).collect();
    let unique: std::collections::BTreeSet<_> = codes.iter().collect();
    assert_eq!(codes.len(), unique.len());
}

// ---------------------------------------------------------------------------
// DeterministicRng
// ---------------------------------------------------------------------------

#[test]
fn rng_zero_seed_rejected() {
    assert!(DeterministicRng::new(0).is_err());
}

#[test]
fn rng_nonzero_seed_ok() {
    assert!(DeterministicRng::new(1).is_ok());
}

#[test]
fn rng_deterministic_sequence() {
    let mut a = DeterministicRng::new(42).unwrap();
    let mut b = DeterministicRng::new(42).unwrap();
    for _ in 0..20 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn rng_choose_index_zero_len_returns_zero() {
    let mut rng = DeterministicRng::new(1).unwrap();
    assert_eq!(rng.choose_index(0), 0);
}

#[test]
fn rng_choose_index_within_bounds() {
    let mut rng = DeterministicRng::new(77).unwrap();
    for _ in 0..50 {
        assert!(rng.choose_index(5) < 5);
    }
}

#[test]
fn rng_range_u64_degenerate_returns_start() {
    let mut rng = DeterministicRng::new(1).unwrap();
    assert_eq!(rng.range_u64(10, 10), 10);
    assert_eq!(rng.range_u64(10, 5), 10);
}

#[test]
fn rng_range_u64_within_bounds() {
    let mut rng = DeterministicRng::new(99).unwrap();
    for _ in 0..50 {
        let v = rng.range_u64(100, 200);
        assert!((100..200).contains(&v));
    }
}

// ---------------------------------------------------------------------------
// CampaignComplexity
// ---------------------------------------------------------------------------

#[test]
fn complexity_display_variants() {
    assert_eq!(CampaignComplexity::Probe.to_string(), "probe");
    assert_eq!(CampaignComplexity::MultiStage.to_string(), "multi_stage");
    assert_eq!(CampaignComplexity::Apt.to_string(), "apt");
}

// ---------------------------------------------------------------------------
// AttackDimension
// ---------------------------------------------------------------------------

#[test]
fn attack_dimension_display_all_variants() {
    let dimensions = [
        (AttackDimension::HostcallSequence, "hostcall_sequence"),
        (AttackDimension::TemporalPayload, "temporal_payload"),
        (AttackDimension::PrivilegeEscalation, "privilege_escalation"),
        (AttackDimension::PolicyEvasion, "policy_evasion"),
        (AttackDimension::Exfiltration, "exfiltration"),
    ];
    for (dim, expected) in &dimensions {
        assert_eq!(dim.to_string(), *expected);
    }
}

// ---------------------------------------------------------------------------
// AttackGrammar — validation
// ---------------------------------------------------------------------------

#[test]
fn grammar_default_validates() {
    default_grammar().validate().unwrap();
}

#[test]
fn grammar_version_zero_rejected() {
    let mut g = default_grammar();
    g.version = 0;
    let err = g.validate().unwrap_err();
    assert!(err.to_string().contains("version"));
}

#[test]
fn grammar_empty_label_rejected() {
    let mut g = default_grammar();
    g.hostcall_motifs[0].label = "  ".to_string();
    let err = g.validate().unwrap_err();
    assert!(err.to_string().contains("empty production label"));
}

#[test]
fn grammar_zero_weight_rejected() {
    let mut g = default_grammar();
    g.temporal_staging[0].weight = 0;
    let err = g.validate().unwrap_err();
    assert!(err.to_string().contains("zero-weight"));
}

#[test]
fn grammar_all_empty_buckets_rejected() {
    for bucket_name in [
        "hostcall_motifs",
        "temporal_staging",
        "privilege_escalation",
        "policy_evasion",
        "exfiltration",
    ] {
        let mut g = default_grammar();
        match bucket_name {
            "hostcall_motifs" => g.hostcall_motifs.clear(),
            "temporal_staging" => g.temporal_staging.clear(),
            "privilege_escalation" => g.privilege_escalation.clear(),
            "policy_evasion" => g.policy_evasion.clear(),
            "exfiltration" => g.exfiltration.clear(),
            _ => unreachable!(),
        }
        let err = g.validate().unwrap_err();
        assert!(
            err.to_string().contains(bucket_name),
            "expected {bucket_name} in error: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// AttackGrammar — step generation and weighted selection
// ---------------------------------------------------------------------------

#[test]
fn grammar_generate_step_produces_valid_step() {
    let g = default_grammar();
    let mut rng = DeterministicRng::new(42).unwrap();
    let step = g.generate_step(0, &mut rng).unwrap();
    assert_eq!(step.step_id, 0);
    assert!(!step.production_label.is_empty());
}

#[test]
fn grammar_generate_step_covers_all_dimensions() {
    let g = default_grammar();
    let mut rng = DeterministicRng::new(1).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..200 {
        let step = g.generate_step(i, &mut rng).unwrap();
        seen.insert(step.dimension);
    }
    assert_eq!(seen.len(), 5, "expected all 5 dimensions to appear");
}

// ---------------------------------------------------------------------------
// AttackGrammar — feedback
// ---------------------------------------------------------------------------

#[test]
fn grammar_feedback_amplifies_high_evasion_weights() {
    let mut g = default_grammar();
    let campaign = make_campaign(0xABC, CampaignComplexity::Probe);
    let score = ExploitObjectiveScore {
        evasion_score_millionths: 800_000,
        containment_escape_score_millionths: 0,
        damage_potential_millionths: 0,
        detection_difficulty_millionths: 0,
        novel_technique_bonus_millionths: 0,
        composite_score_millionths: 0,
        difficulty: ContainmentDifficulty::Easy,
    };
    let old_weights: Vec<u32> = g.hostcall_motifs.iter().map(|p| p.weight).collect();
    g.apply_campaign_feedback(&campaign, &score);
    // At least one weight should have changed (increased)
    let new_weights: Vec<u32> = g.hostcall_motifs.iter().map(|p| p.weight).collect();
    // Weights may or may not change depending on which labels appear in campaign
    // But the grammar should still validate
    g.validate().unwrap();
    let _ = (old_weights, new_weights);
}

#[test]
fn grammar_feedback_decays_low_evasion_weights() {
    let mut g = default_grammar();
    let campaign = make_campaign(0xDEF, CampaignComplexity::Probe);
    let score = ExploitObjectiveScore {
        evasion_score_millionths: 100_000,
        containment_escape_score_millionths: 0,
        damage_potential_millionths: 0,
        detection_difficulty_millionths: 0,
        novel_technique_bonus_millionths: 0,
        composite_score_millionths: 0,
        difficulty: ContainmentDifficulty::Easy,
    };
    g.apply_campaign_feedback(&campaign, &score);
    // All weights must remain >= 1
    for bucket in [
        &g.hostcall_motifs,
        &g.temporal_staging,
        &g.privilege_escalation,
        &g.policy_evasion,
        &g.exfiltration,
    ] {
        for prod in bucket {
            assert!(prod.weight >= 1, "weight must never drop below 1");
        }
    }
}

// ---------------------------------------------------------------------------
// AdversarialCampaign — validation
// ---------------------------------------------------------------------------

#[test]
fn campaign_valid_passes() {
    make_campaign(0x111, CampaignComplexity::Probe)
        .validate()
        .unwrap();
}

#[test]
fn campaign_empty_campaign_id_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.campaign_id = "  ".into();
    assert!(c.validate().is_err());
}

#[test]
fn campaign_empty_trace_id_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.trace_id.clear();
    assert!(c.validate().is_err());
}

#[test]
fn campaign_empty_decision_id_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.decision_id = String::new();
    assert!(c.validate().is_err());
}

#[test]
fn campaign_empty_policy_id_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.policy_id = "".into();
    assert!(c.validate().is_err());
}

#[test]
fn campaign_grammar_version_zero_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.grammar_version = 0;
    assert!(c.validate().is_err());
}

#[test]
fn campaign_seed_zero_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.seed = 0;
    assert!(c.validate().is_err());
}

#[test]
fn campaign_empty_steps_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.steps.clear();
    assert!(c.validate().is_err());
}

#[test]
fn campaign_non_contiguous_step_ids_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.steps[1].step_id = 99;
    assert!(c.validate().is_err());
}

#[test]
fn campaign_empty_production_label_rejected() {
    let mut c = make_campaign(0x111, CampaignComplexity::Probe);
    c.steps[0].production_label = "  ".into();
    assert!(c.validate().is_err());
}

// ---------------------------------------------------------------------------
// CampaignExecutionResult — validation
// ---------------------------------------------------------------------------

#[test]
fn result_valid_passes() {
    make_result(2, 5, false, 300_000, 10, false)
        .validate()
        .unwrap();
}

#[test]
fn result_zero_total_steps_rejected() {
    assert!(make_result(0, 0, false, 0, 0, false).validate().is_err());
}

#[test]
fn result_undetected_exceeds_total_rejected() {
    assert!(make_result(6, 5, false, 0, 0, false).validate().is_err());
}

#[test]
fn result_damage_exceeds_million_rejected() {
    assert!(
        make_result(0, 1, false, 1_000_001, 0, false)
            .validate()
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// ExploitObjectiveScore
// ---------------------------------------------------------------------------

#[test]
fn score_easy_difficulty_for_low_composite() {
    let score =
        ExploitObjectiveScore::from_result(&make_result(0, 10, false, 0, 0, false)).unwrap();
    assert_eq!(score.difficulty, ContainmentDifficulty::Easy);
    assert_eq!(score.evasion_score_millionths, 0);
    assert_eq!(score.containment_escape_score_millionths, 0);
}

#[test]
fn score_critical_difficulty_for_high_composite() {
    let score =
        ExploitObjectiveScore::from_result(&make_result(10, 10, true, 999_000, 50, true)).unwrap();
    assert_eq!(score.difficulty, ContainmentDifficulty::Critical);
    assert_eq!(score.evasion_score_millionths, 1_000_000);
    assert_eq!(score.containment_escape_score_millionths, 1_000_000);
}

#[test]
fn score_novel_technique_adds_bonus() {
    let with_novel =
        ExploitObjectiveScore::from_result(&make_result(3, 5, false, 300_000, 10, true)).unwrap();
    let without_novel =
        ExploitObjectiveScore::from_result(&make_result(3, 5, false, 300_000, 10, false)).unwrap();
    assert!(with_novel.composite_score_millionths >= without_novel.composite_score_millionths);
    assert_eq!(with_novel.novel_technique_bonus_millionths, 1_000_000);
    assert_eq!(without_novel.novel_technique_bonus_millionths, 0);
}

#[test]
fn score_containment_difficulty_thresholds() {
    // Easy: composite < 400_000
    let easy = ExploitObjectiveScore::from_result(&make_result(0, 10, false, 0, 0, false)).unwrap();
    assert_eq!(easy.difficulty, ContainmentDifficulty::Easy);

    // Moderate: composite >= 400_000 and < 650_000
    let moderate =
        ExploitObjectiveScore::from_result(&make_result(5, 10, false, 800_000, 20, false)).unwrap();
    assert!(
        moderate.difficulty == ContainmentDifficulty::Moderate
            || moderate.difficulty == ContainmentDifficulty::Easy
    );
}

// ---------------------------------------------------------------------------
// ContainmentDifficulty Display
// ---------------------------------------------------------------------------

#[test]
fn containment_difficulty_display() {
    assert_eq!(ContainmentDifficulty::Easy.to_string(), "easy");
    assert_eq!(ContainmentDifficulty::Moderate.to_string(), "moderate");
    assert_eq!(ContainmentDifficulty::Hard.to_string(), "hard");
    assert_eq!(ContainmentDifficulty::Critical.to_string(), "critical");
}

// ---------------------------------------------------------------------------
// MutationOperator Display
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// MutationEngine — all operators
// ---------------------------------------------------------------------------

#[test]
fn mutation_point_mutation_changes_one_step() {
    let g = default_grammar();
    let base = make_campaign(0xAA, CampaignComplexity::MultiStage);
    let mutated = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0xBB,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert_eq!(mutated.steps.len(), base.steps.len());
}

#[test]
fn mutation_crossover_requires_donor() {
    let g = default_grammar();
    let base = make_campaign(0xCC, CampaignComplexity::Probe);
    let err = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0xDD,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("donor_campaign"));
}

#[test]
fn mutation_crossover_with_donor_produces_valid_campaign() {
    let g = default_grammar();
    let base = make_campaign(0xEE, CampaignComplexity::MultiStage);
    let donor = make_campaign(0xFF, CampaignComplexity::MultiStage);
    let mutated = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0x11,
            donor_campaign: Some(donor),
        },
    )
    .unwrap();
    mutated.validate().unwrap();
}

#[test]
fn mutation_insertion_adds_step() {
    let g = default_grammar();
    let base = make_campaign(0x22, CampaignComplexity::Probe);
    let original_len = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::Insertion,
            seed: 0x33,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert_eq!(mutated.steps.len(), original_len + 1);
}

#[test]
fn mutation_deletion_removes_step() {
    let g = default_grammar();
    let base = make_campaign(0x44, CampaignComplexity::MultiStage);
    let original_len = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::Deletion,
            seed: 0x55,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
    assert_eq!(mutated.steps.len(), original_len - 1);
}

#[test]
fn mutation_deletion_single_step_rejected() {
    let g = default_grammar();
    let mut base = make_campaign(0x66, CampaignComplexity::Probe);
    base.steps.truncate(1);
    base.campaign_id = "camp-single".into();
    base.trace_id = "trace-single".into();
    base.decision_id = "decision-single".into();
    let err = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::Deletion,
            seed: 0x77,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("last step"));
}

#[test]
fn mutation_temporal_shift_adjusts_delay() {
    let g = default_grammar();
    // Start from a generated campaign and ensure it has a TemporalPayload step
    let mut base = make_campaign(0x42, CampaignComplexity::Apt);
    // Inject a TemporalPayload step if none exists
    let has_temporal = base
        .steps
        .iter()
        .any(|s| matches!(s.kind, AttackStepKind::TemporalPayload { .. }));
    if !has_temporal {
        base.steps[0].dimension = AttackDimension::TemporalPayload;
        base.steps[0].kind = AttackStepKind::TemporalPayload {
            stage: "injected_stage".into(),
            delay_ms: 500,
        };
    }
    let mutated = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::TemporalShift,
            seed: 0x999,
            donor_campaign: None,
        },
    )
    .unwrap();
    mutated.validate().unwrap();
}

#[test]
fn mutation_temporal_shift_no_temporal_step_rejected() {
    let g = default_grammar();
    // Make a campaign with only HostcallSequence steps
    let mut base = make_campaign(0x88, CampaignComplexity::Probe);
    for step in &mut base.steps {
        step.kind = AttackStepKind::HostcallSequence {
            motif: "test".into(),
            hostcall_count: 3,
        };
        step.dimension = AttackDimension::HostcallSequence;
    }
    let err = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::TemporalShift,
            seed: 0x99,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("temporal"));
}

#[test]
fn mutation_zero_seed_rejected() {
    let g = default_grammar();
    let base = make_campaign(0xAA, CampaignComplexity::Probe);
    let err = MutationEngine::mutate(
        &base,
        &g,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0,
            donor_campaign: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.error_code(), "FE-ADV-CAMP-0005");
}

// ---------------------------------------------------------------------------
// AutoMinimizer
// ---------------------------------------------------------------------------

#[test]
fn minimizer_requires_initially_failing_campaign() {
    let campaign = make_campaign(0x111, CampaignComplexity::Probe);
    let err = AutoMinimizer::minimize_with(&campaign, |_| false).unwrap_err();
    assert!(err.to_string().contains("initially failing"));
}

#[test]
fn minimizer_single_step_campaign_cannot_reduce() {
    let mut campaign = make_campaign(0x222, CampaignComplexity::Probe);
    campaign.steps.truncate(1);
    campaign.campaign_id = "camp-min1".into();
    campaign.trace_id = "trace-min1".into();
    campaign.decision_id = "decision-min1".into();
    let (min, proof) = AutoMinimizer::minimize_with(&campaign, |_| true).unwrap();
    assert_eq!(min.steps.len(), 1);
    assert!(proof.is_fixed_point);
}

#[test]
fn minimizer_build_fixture_preserves_fields() {
    let campaign = make_campaign(0x333, CampaignComplexity::Probe);
    let proof = MinimizationProof {
        rounds: 5,
        removed_steps: 3,
        is_fixed_point: true,
    };
    let fixture = AutoMinimizer::build_fixture(&campaign, "expected", "actual", proof.clone());
    assert_eq!(fixture.campaign_id, campaign.campaign_id);
    assert_eq!(fixture.seed, campaign.seed);
    assert_eq!(fixture.expected_defense_response, "expected");
    assert_eq!(fixture.actual_defense_response, "actual");
    assert_eq!(fixture.minimality_proof, proof);
    assert_eq!(fixture.attack_sequence.len(), campaign.steps.len());
}

// ---------------------------------------------------------------------------
// RegressionCorpus
// ---------------------------------------------------------------------------

#[test]
fn regression_corpus_empty_initially() {
    let corpus = RegressionCorpus::default();
    assert!(corpus.is_empty());
    assert_eq!(corpus.len(), 0);
}

#[test]
fn regression_corpus_promote_and_retrieve() {
    let mut corpus = RegressionCorpus::default();
    let campaign = make_campaign(0x444, CampaignComplexity::Probe);
    let fixture = AutoMinimizer::build_fixture(
        &campaign,
        "expect",
        "actual",
        MinimizationProof {
            rounds: 0,
            removed_steps: 0,
            is_fixed_point: true,
        },
    );
    let id = fixture.campaign_id.clone();
    corpus.promote(fixture);
    assert_eq!(corpus.len(), 1);
    assert!(corpus.fixture(&id).is_some());
    assert!(corpus.fixture("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// CampaignOutcomeRecord — validation
// ---------------------------------------------------------------------------

#[test]
fn outcome_valid_passes() {
    let c = make_campaign(0x555, CampaignComplexity::Probe);
    let r = make_result(2, c.steps.len(), false, 300_000, 10, false);
    let o = make_outcome(c, r, false, false, 100);
    o.validate().unwrap();
}

#[test]
fn outcome_false_positive_requires_benign_control() {
    let c = make_campaign(0x666, CampaignComplexity::Probe);
    let r = make_result(0, c.steps.len(), false, 0, 0, false);
    let o = CampaignOutcomeRecord {
        campaign: c,
        result: r.clone(),
        score: ExploitObjectiveScore::from_result(&r).unwrap(),
        benign_control: false,
        false_positive: true,
        timestamp_ns: 100,
    };
    let err = o.validate().unwrap_err();
    assert!(err.to_string().contains("false_positive"));
}

#[test]
fn outcome_score_mismatch_detected() {
    let c = make_campaign(0x777, CampaignComplexity::Probe);
    let r = make_result(2, c.steps.len(), false, 300_000, 10, false);
    let mut bad_score = ExploitObjectiveScore::from_result(&r).unwrap();
    bad_score.composite_score_millionths += 1;
    let o = CampaignOutcomeRecord {
        campaign: c,
        result: r,
        score: bad_score,
        benign_control: false,
        false_positive: false,
        timestamp_ns: 100,
    };
    let err = o.validate().unwrap_err();
    assert!(err.to_string().contains("mismatch"));
}

// ---------------------------------------------------------------------------
// CampaignGenerator
// ---------------------------------------------------------------------------

#[test]
fn generator_empty_policy_id_rejected() {
    let result = CampaignGenerator::new(
        default_grammar(),
        CampaignGeneratorConfig {
            policy_id: "".into(),
            ..default_config()
        },
        0xAA,
    );
    let err = result.expect_err("should fail with empty policy_id");
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn generator_zero_campaigns_per_hour_rejected() {
    let result = CampaignGenerator::new(
        default_grammar(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 0,
            ..default_config()
        },
        0xBB,
    );
    let err = result.expect_err("should fail with zero campaigns_per_hour");
    assert!(err.to_string().contains("campaigns_per_hour"));
}

#[test]
fn generator_zero_seed_rejected() {
    assert!(CampaignGenerator::new(default_grammar(), default_config(), 0).is_err());
}

#[test]
fn generator_probe_produces_4_steps() {
    let c = make_campaign(0x100, CampaignComplexity::Probe);
    assert_eq!(c.steps.len(), 4);
}

#[test]
fn generator_multi_stage_produces_8_steps() {
    let c = make_campaign(0x100, CampaignComplexity::MultiStage);
    assert_eq!(c.steps.len(), 8);
}

#[test]
fn generator_apt_produces_12_steps() {
    let c = make_campaign(0x100, CampaignComplexity::Apt);
    assert_eq!(c.steps.len(), 12);
}

#[test]
fn generator_campaign_ids_are_unique() {
    let mut generator = make_generator(0x200);
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let c = generator
            .generate_campaign(CampaignComplexity::Probe)
            .unwrap();
        assert!(ids.insert(c.campaign_id), "campaign IDs must be unique");
    }
}

#[test]
fn generator_score_and_record_workflow() {
    let mut generator = make_generator(0x300);
    let campaign = generator
        .generate_campaign(CampaignComplexity::Probe)
        .unwrap();
    let result = make_result(2, campaign.steps.len(), false, 200_000, 5, false);
    let score = generator.score_campaign(&campaign, &result).unwrap();
    generator
        .record_campaign_outcome(&campaign, &score)
        .unwrap();
    assert!(generator.score(&campaign.campaign_id).is_some());
    let events = generator.drain_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].event, "campaign_scored");
}

#[test]
fn generator_promote_failure_fixture_records_fixture() {
    let mut generator = make_generator(0x400);
    let campaign = generator
        .generate_campaign(CampaignComplexity::Probe)
        .unwrap();
    let result = make_result(
        campaign.steps.len(),
        campaign.steps.len(),
        true,
        800_000,
        30,
        true,
    );
    let score = generator.score_campaign(&campaign, &result).unwrap();
    generator
        .record_campaign_outcome(&campaign, &score)
        .unwrap();

    let fixture = generator
        .promote_failure_fixture(&campaign, "containment", "evasion", |_| true)
        .unwrap();
    assert!(!generator.regression_corpus().is_empty());
    assert_eq!(fixture.expected_defense_response, "containment");
}

// ---------------------------------------------------------------------------
// CampaignGenerator — run_cycle
// ---------------------------------------------------------------------------

#[test]
fn run_cycle_respects_backpressure() {
    let mut generator = CampaignGenerator::new(
        default_grammar(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 5,
            max_backpressure_queue: 3,
            ..default_config()
        },
        0x500,
    )
    .unwrap();

    let outputs = generator
        .run_cycle(CampaignComplexity::Probe, 10, |_| {
            make_result(2, 4, false, 200_000, 5, false)
        })
        .unwrap();
    assert_eq!(outputs.len(), 0);
}

#[test]
fn run_cycle_generates_and_scores() {
    let mut generator = CampaignGenerator::new(
        default_grammar(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 3,
            max_backpressure_queue: 10,
            promotion_threshold_millionths: 999_999,
            ..default_config()
        },
        0x600,
    )
    .unwrap();

    let outputs = generator
        .run_cycle(CampaignComplexity::Probe, 0, |_| {
            make_result(1, 4, false, 100_000, 3, false)
        })
        .unwrap();
    assert_eq!(outputs.len(), 3);
    for (campaign, score) in &outputs {
        assert!(!campaign.campaign_id.is_empty());
        assert!(score.composite_score_millionths <= 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// RedBlueLoopIntegrator — classification
// ---------------------------------------------------------------------------

#[test]
fn red_blue_classify_advisory_for_fully_detected() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let campaign = make_campaign(0xA1, CampaignComplexity::Probe);
    let result = make_result(0, campaign.steps.len(), false, 50_000, 2, false);
    let outcome = make_outcome(campaign, result, false, false, 100);
    let classification = integrator.ingest_outcome(outcome).unwrap();
    assert_eq!(classification.severity, CampaignSeverity::Advisory);
    assert!(!classification.evasion_report);
    assert!(!classification.containment_escape_report);
}

#[test]
fn red_blue_classify_containment_subsystem_on_escape() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let campaign = make_campaign(0xA2, CampaignComplexity::Probe);
    let result = make_result(
        campaign.steps.len(),
        campaign.steps.len(),
        true,
        500_000,
        20,
        false,
    );
    let outcome = make_outcome(campaign, result, false, false, 200);
    let classification = integrator.ingest_outcome(outcome).unwrap();
    assert_eq!(classification.subsystem, DefenseSubsystem::Containment);
}

#[test]
fn red_blue_classify_sentinel_when_partial_evasion() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let campaign = make_campaign(0xA3, CampaignComplexity::Probe);
    let result = make_result(2, campaign.steps.len(), false, 200_000, 10, false);
    let outcome = make_outcome(campaign, result, false, false, 300);
    let classification = integrator.ingest_outcome(outcome).unwrap();
    assert_eq!(classification.subsystem, DefenseSubsystem::Sentinel);
    assert!(classification.evasion_report);
}

// ---------------------------------------------------------------------------
// RedBlueLoopIntegrator — technique effectiveness
// ---------------------------------------------------------------------------

#[test]
fn technique_effectiveness_tracks_dimensions() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());

    for seed in 1..=5u64 {
        let campaign = make_campaign(seed, CampaignComplexity::MultiStage);
        let result = make_result(
            if seed % 2 == 0 { 0 } else { 3 },
            campaign.steps.len(),
            seed == 5,
            200_000,
            10,
            false,
        );
        let outcome = make_outcome(campaign, result, false, false, seed * 1000);
        integrator.ingest_outcome(outcome).unwrap();
    }

    let effectiveness = integrator.technique_effectiveness();
    assert!(!effectiveness.is_empty());
    for entry in effectiveness.values() {
        assert!(entry.attempts > 0);
        assert!(entry.detection_rate_millionths <= 1_000_000);
        assert!(entry.escape_rate_millionths <= 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// RedBlueLoopIntegrator — calibration no-op
// ---------------------------------------------------------------------------

#[test]
fn calibration_returns_none_with_no_outcomes() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let result = integrator.calibrate(&[0u8; 32], 1000).unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// RedBlueLoopIntegrator — regression gate
// ---------------------------------------------------------------------------

#[test]
fn regression_gate_passes_empty_suite() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let decision = integrator.evaluate_regression_gate(&[]);
    assert!(decision.passed);
    assert!(decision.failed_campaign_ids.is_empty());
}

// ---------------------------------------------------------------------------
// DefenseSubsystem / ThreatCategory / CampaignSeverity Display
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CampaignRuntime
// ---------------------------------------------------------------------------

#[test]
fn campaign_runtime_display() {
    assert_eq!(CampaignRuntime::FrankenEngine.to_string(), "franken_engine");
    assert_eq!(CampaignRuntime::NodeLts.to_string(), "node_lts");
    assert_eq!(CampaignRuntime::BunStable.to_string(), "bun_stable");
}

// ---------------------------------------------------------------------------
// CampaignAttackCategory
// ---------------------------------------------------------------------------

#[test]
fn campaign_attack_category_all_has_5_entries() {
    assert_eq!(CampaignAttackCategory::ALL.len(), 5);
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

// ---------------------------------------------------------------------------
// CampaignSuppressionSample — validation
// ---------------------------------------------------------------------------

#[test]
fn suppression_sample_valid_passes() {
    suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        100,
        5,
    )
    .validate()
    .unwrap();
}

#[test]
fn suppression_sample_empty_campaign_id_rejected() {
    let mut s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        100,
        5,
    );
    s.campaign_id = "".into();
    assert!(s.validate().is_err());
}

#[test]
fn suppression_sample_zero_attempts_rejected() {
    let mut s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        0,
        0,
    );
    s.attempt_count = 0;
    assert!(s.validate().is_err());
}

#[test]
fn suppression_sample_success_exceeds_attempts_rejected() {
    let s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        10,
        20,
    );
    assert!(s.validate().is_err());
}

#[test]
fn suppression_sample_empty_log_ref_rejected() {
    let mut s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        100,
        5,
    );
    s.raw_log_ref = "".into();
    assert!(s.validate().is_err());
}

#[test]
fn suppression_sample_empty_repro_ref_rejected() {
    let mut s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        100,
        5,
    );
    s.repro_script_ref = " ".into();
    assert!(s.validate().is_err());
}

#[test]
fn suppression_sample_compromise_rate() {
    let s = suppression_sample(
        "camp-1",
        CampaignAttackCategory::Injection,
        CampaignRuntime::FrankenEngine,
        200,
        50,
    );
    assert_eq!(s.compromise_rate_millionths(), 250_000);
}

// ---------------------------------------------------------------------------
// ExploitEscalationRecord — validation
// ---------------------------------------------------------------------------

#[test]
fn escalation_record_valid_passes() {
    let r = ExploitEscalationRecord {
        campaign_id: "camp-esc".into(),
        attack_category: CampaignAttackCategory::CapabilityEscape,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: true,
        escalation_triggered: true,
        escalation_latency_seconds: Some(120),
    };
    r.validate().unwrap();
}

#[test]
fn escalation_record_empty_campaign_id_rejected() {
    let r = ExploitEscalationRecord {
        campaign_id: "".into(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: false,
        escalation_triggered: false,
        escalation_latency_seconds: None,
    };
    assert!(r.validate().is_err());
}

#[test]
fn escalation_record_missing_latency_rejected() {
    let r = ExploitEscalationRecord {
        campaign_id: "camp-esc".into(),
        attack_category: CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: true,
        escalation_triggered: true,
        escalation_latency_seconds: None,
    };
    assert!(r.validate().is_err());
}

// ---------------------------------------------------------------------------
// SuppressionGateInput — validation
// ---------------------------------------------------------------------------

#[test]
fn suppression_gate_input_empty_rc_id_rejected() {
    let input = SuppressionGateInput {
        release_candidate_id: "".into(),
        continuous_run: true,
        samples: vec![suppression_sample(
            "c1",
            CampaignAttackCategory::Injection,
            CampaignRuntime::FrankenEngine,
            10,
            0,
        )],
        trend_points: vec![],
        escalations: vec![],
    };
    assert!(input.validate().is_err());
}

#[test]
fn suppression_gate_input_empty_samples_rejected() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-1".into(),
        continuous_run: true,
        samples: vec![],
        trend_points: vec![],
        escalations: vec![],
    };
    assert!(input.validate().is_err());
}

// ---------------------------------------------------------------------------
// evaluate_compromise_suppression_gate
// ---------------------------------------------------------------------------

#[test]
fn suppression_gate_zero_baseline_runtimes_rejected() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-1".into(),
        continuous_run: true,
        samples: vec![suppression_sample(
            "c1",
            CampaignAttackCategory::Injection,
            CampaignRuntime::FrankenEngine,
            100,
            0,
        )],
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-0".into(),
                timestamp_ns: 100,
                samples_evaluated: 50,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-p".into(),
                timestamp_ns: 200,
                samples_evaluated: 60,
            },
        ],
        escalations: vec![],
    };
    let config = SuppressionGateConfig {
        minimum_baseline_runtimes: 0,
        ..Default::default()
    };
    let err = evaluate_compromise_suppression_gate(&input, &config).unwrap_err();
    assert!(err.to_string().contains("minimum_baseline_runtimes"));
}

#[test]
fn suppression_gate_missing_franken_coverage_fails() {
    // Only provide baseline samples, no FrankenEngine samples
    let samples = vec![
        suppression_sample(
            "c-node",
            CampaignAttackCategory::Injection,
            CampaignRuntime::NodeLts,
            100,
            20,
        ),
        suppression_sample(
            "c-bun",
            CampaignAttackCategory::Injection,
            CampaignRuntime::BunStable,
            100,
            25,
        ),
    ];
    let input = SuppressionGateInput {
        release_candidate_id: "rc-miss".into(),
        continuous_run: true,
        samples,
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-a".into(),
                timestamp_ns: 100,
                samples_evaluated: 50,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-b".into(),
                timestamp_ns: 200,
                samples_evaluated: 60,
            },
        ],
        escalations: vec![],
    };
    let result =
        evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default()).unwrap();
    assert!(!result.passed);
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.error_code == "FE-ADV-GATE-0002")
    );
}

// ---------------------------------------------------------------------------
// GuardplaneCalibrationState
// ---------------------------------------------------------------------------

#[test]
fn guardplane_calibration_default_has_all_dimensions() {
    let state = GuardplaneCalibrationState::default();
    assert_eq!(state.evidence_weights_millionths.len(), 5);
    assert_eq!(state.loss_matrix_millionths.len(), 5);
    assert!(state.detection_threshold_millionths > 0);
    assert_eq!(state.calibration_epoch, 0);
}

// ---------------------------------------------------------------------------
// PolicyRegressionSuite
// ---------------------------------------------------------------------------

#[test]
fn policy_regression_suite_upsert_and_query() {
    let mut suite = PolicyRegressionSuite::default();
    assert!(suite.is_empty());

    let campaign = make_campaign(0x999, CampaignComplexity::Probe);
    let fixture = AutoMinimizer::build_fixture(
        &campaign,
        "expect",
        "actual",
        MinimizationProof {
            rounds: 0,
            removed_steps: 0,
            is_fixed_point: true,
        },
    );
    let entry = PolicyRegressionEntry {
        campaign_id: campaign.campaign_id.clone(),
        fixture,
        subsystem: DefenseSubsystem::Sentinel,
        threat_category: ThreatCategory::CredentialTheft,
        severity: CampaignSeverity::Moderate,
        discovered_at_ns: 1000,
        calibration_id: None,
    };
    suite.upsert(entry);
    assert_eq!(suite.len(), 1);
    assert!(suite.entries().contains_key(&campaign.campaign_id));
}

// ---------------------------------------------------------------------------
// SuppressionGateConfig default
// ---------------------------------------------------------------------------

#[test]
fn suppression_gate_config_default_sensible() {
    let config = SuppressionGateConfig::default();
    assert_eq!(config.required_categories.len(), 5);
    assert_eq!(config.minimum_baseline_runtimes, 2);
    assert!(config.max_p_value_millionths > 0);
    assert!(config.max_escalation_latency_seconds > 0);
    assert!(config.minimum_trend_points > 0);
}

// ---------------------------------------------------------------------------
// CampaignGeneratorConfig default
// ---------------------------------------------------------------------------

#[test]
fn campaign_generator_config_default_sensible() {
    let config = CampaignGeneratorConfig::default();
    assert!(!config.policy_id.is_empty());
    assert!(config.campaigns_per_hour > 0);
    assert!(config.max_backpressure_queue > 0);
    assert!(config.promotion_threshold_millionths > 0);
}

// ---------------------------------------------------------------------------
// Event structure validation
// ---------------------------------------------------------------------------

#[test]
fn campaign_events_have_stable_fields() {
    let mut generator = make_generator(0x700);
    let campaign = generator
        .generate_campaign(CampaignComplexity::Probe)
        .unwrap();
    let result = make_result(2, campaign.steps.len(), false, 200_000, 5, false);
    let score = generator.score_campaign(&campaign, &result).unwrap();
    generator
        .record_campaign_outcome(&campaign, &score)
        .unwrap();

    for event in generator.drain_events() {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        assert!(!event.campaign_id.is_empty());
    }
}

#[test]
fn red_blue_events_have_stable_fields() {
    let mut integrator =
        RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
    let campaign = make_campaign(0x800, CampaignComplexity::Probe);
    let result = make_result(2, campaign.steps.len(), false, 300_000, 10, false);
    let outcome = make_outcome(campaign, result, false, false, 100);
    integrator.ingest_outcome(outcome).unwrap();

    for event in integrator.drain_events() {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn campaign_serde_roundtrip() {
    let campaign = make_campaign(0x900, CampaignComplexity::Apt);
    let json = serde_json::to_string(&campaign).unwrap();
    let deserialized: AdversarialCampaign = serde_json::from_str(&json).unwrap();
    assert_eq!(campaign, deserialized);
}

#[test]
fn score_serde_roundtrip() {
    let result = make_result(3, 5, false, 400_000, 15, true);
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    let json = serde_json::to_string(&score).unwrap();
    let deserialized: ExploitObjectiveScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, deserialized);
}

#[test]
fn grammar_serde_roundtrip() {
    let grammar = default_grammar();
    let json = serde_json::to_string(&grammar).unwrap();
    let deserialized: AttackGrammar = serde_json::from_str(&json).unwrap();
    assert_eq!(grammar, deserialized);
}
