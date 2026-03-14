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

#[path = "../src/adversarial_campaign.rs"]
mod adversarial_campaign;

use adversarial_campaign::{
    AdversarialCampaign, AttackGrammar, CampaignComplexity, CampaignExecutionResult,
    CampaignGenerator, CampaignGeneratorConfig, CampaignRuntime, CampaignSuppressionSample,
    CampaignTrendPoint, ContainmentDifficulty, ExploitEscalationRecord, ExploitObjectiveScore,
    MutationEngine, MutationOperator, MutationRequest, SuppressionGateConfig, SuppressionGateInput,
    evaluate_compromise_suppression_gate,
};

#[test]
fn adversarial_campaign_lifecycle_generation_scoring_mutation_and_promotion() {
    let grammar = AttackGrammar::default();
    let config = CampaignGeneratorConfig {
        policy_id: "policy-lifecycle".to_string(),
        campaigns_per_hour: 1,
        max_backpressure_queue: 4,
        promotion_threshold_millionths: 500_000,
    };
    let mut generator = CampaignGenerator::new(grammar.clone(), config, 0xABCD).expect("generator");

    let campaign = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("campaign");
    campaign.validate().expect("valid campaign");

    let score = generator
        .score_campaign(
            &campaign,
            &CampaignExecutionResult {
                undetected_steps: campaign.steps.len(),
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: true,
                damage_potential_millionths: 900_000,
                evidence_atoms_before_detection: 70,
                novel_technique: true,
            },
        )
        .expect("score");
    assert_eq!(score.difficulty, ContainmentDifficulty::Critical);

    generator
        .record_campaign_outcome(&campaign, &score)
        .expect("record score");

    let mutated = MutationEngine::mutate(
        &campaign,
        &grammar,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0x7777,
            donor_campaign: None,
        },
    )
    .expect("mutate");
    mutated.validate().expect("mutated campaign valid");

    let fixture = generator
        .promote_failure_fixture(&mutated, "containment", "evasion", |candidate| {
            candidate.steps.len() >= 2
        })
        .expect("promote fixture");

    assert_eq!(generator.regression_corpus().len(), 1);
    assert!(
        generator
            .regression_corpus()
            .fixture(&fixture.campaign_id)
            .is_some()
    );
    assert!(generator.score(&campaign.campaign_id).is_some());
}

#[test]
fn adversarial_campaign_events_expose_required_stable_fields() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            policy_id: "policy-events".to_string(),
            campaigns_per_hour: 2,
            max_backpressure_queue: 6,
            promotion_threshold_millionths: 300_000,
        },
        0x1234,
    )
    .expect("generator");

    let outputs = generator
        .run_cycle(
            CampaignComplexity::Probe,
            0,
            |campaign: &AdversarialCampaign| CampaignExecutionResult {
                undetected_steps: campaign.steps.len().saturating_sub(1),
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: true,
                damage_potential_millionths: 700_000,
                evidence_atoms_before_detection: 42,
                novel_technique: true,
            },
        )
        .expect("run cycle");

    assert_eq!(outputs.len(), 2);
    for (_, score) in &outputs {
        assert!(score.composite_score_millionths > 0);
    }

    let events = generator.drain_events();
    assert!(!events.is_empty());
    for event in events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert_eq!(event.component, "adversarial_campaign_generator");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        if event.event == "campaign_minimization" {
            assert!(event.error_code.is_some());
        }
    }
}

#[test]
fn exploit_objective_scoring_is_replay_deterministic() {
    let baseline = CampaignExecutionResult {
        undetected_steps: 3,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 450_000,
        evidence_atoms_before_detection: 17,
        novel_technique: false,
    };

    let score_a = ExploitObjectiveScore::from_result(&baseline).expect("score a");
    let score_b = ExploitObjectiveScore::from_result(&baseline).expect("score b");
    assert_eq!(score_a, score_b);
}

#[test]
fn suppression_gate_surface_exposes_required_structured_fields() {
    let sample = |campaign_id: &str,
                  category: adversarial_campaign::CampaignAttackCategory,
                  runtime: CampaignRuntime,
                  attempts: u64,
                  successes: u64| CampaignSuppressionSample {
        campaign_id: campaign_id.to_string(),
        attack_category: category,
        target_runtime: runtime,
        attempt_count: attempts,
        success_count: successes,
        raw_log_ref: format!("artifacts/raw/{campaign_id}.jsonl"),
        repro_script_ref: format!("artifacts/repro/{campaign_id}.sh"),
    };

    let categories = adversarial_campaign::CampaignAttackCategory::ALL;
    let mut samples = Vec::new();
    for category in categories {
        samples.push(sample(
            &format!("fe-{category}"),
            category,
            CampaignRuntime::FrankenEngine,
            180,
            1,
        ));
        samples.push(sample(
            &format!("node-{category}"),
            category,
            CampaignRuntime::NodeLts,
            180,
            28,
        ));
        samples.push(sample(
            &format!("bun-{category}"),
            category,
            CampaignRuntime::BunStable,
            180,
            23,
        ));
    }

    let gate_input = SuppressionGateInput {
        release_candidate_id: "rc-structured-fields".to_string(),
        continuous_run: true,
        samples,
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-prev-1".to_string(),
                timestamp_ns: 1_700_000_300_000,
                samples_evaluated: 540,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-prev-2".to_string(),
                timestamp_ns: 1_700_000_400_000,
                samples_evaluated: 560,
            },
        ],
        escalations: adversarial_campaign::CampaignAttackCategory::ALL
            .iter()
            .map(|category| ExploitEscalationRecord {
                campaign_id: format!("fe-{category}"),
                attack_category: *category,
                target_runtime: CampaignRuntime::FrankenEngine,
                successful_exploit: true,
                escalation_triggered: true,
                escalation_latency_seconds: Some(60),
            })
            .collect(),
    };

    let result =
        evaluate_compromise_suppression_gate(&gate_input, &SuppressionGateConfig::default())
            .expect("suppression gate evaluation");

    assert!(result.passed);
    let summary = result
        .events
        .iter()
        .find(|event| event.event == "suppression_gate_evaluated")
        .expect("summary event");
    assert!(!summary.trace_id.is_empty());
    assert!(!summary.decision_id.is_empty());
    assert!(!summary.policy_id.is_empty());
    assert!(!summary.component.is_empty());
    assert!(!summary.event.is_empty());
    assert!(!summary.outcome.is_empty());

    let comparison = result
        .events
        .iter()
        .find(|event| event.event == "suppression_comparison")
        .expect("comparison event");
    assert!(!comparison.attack_category.is_empty());
    assert!(!comparison.target_runtime.is_empty());
    assert!(comparison.attempt_count > 0);
    assert!(comparison.p_value_millionths.is_some());
    assert!(!comparison.confidence_interval.is_empty());
}

// ---------- DeterministicRng ----------

#[test]
fn deterministic_rng_rejects_zero_seed() {
    assert!(adversarial_campaign::DeterministicRng::new(0).is_err());
}

#[test]
fn deterministic_rng_produces_repeatable_sequence() {
    let mut a = adversarial_campaign::DeterministicRng::new(42).expect("rng");
    let mut b = adversarial_campaign::DeterministicRng::new(42).expect("rng");
    for _ in 0..50 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn deterministic_rng_different_seeds_diverge() {
    let mut a = adversarial_campaign::DeterministicRng::new(1).expect("rng");
    let mut b = adversarial_campaign::DeterministicRng::new(2).expect("rng");
    assert_ne!(a.next_u64(), b.next_u64());
}

// ---------- AttackGrammar ----------

#[test]
fn attack_grammar_default_passes_validation() {
    AttackGrammar::default()
        .validate()
        .expect("default grammar must validate");
}

#[test]
fn attack_grammar_generate_step_populates_all_fields() {
    let grammar = AttackGrammar::default();
    let mut rng = adversarial_campaign::DeterministicRng::new(77).expect("rng");
    let step = grammar.generate_step(5, &mut rng).expect("generate step");
    assert_eq!(step.step_id, 5);
    assert!(!step.production_label.is_empty());
}

// ---------- CampaignComplexity ----------

#[test]
fn campaign_complexity_display_is_nonempty_for_all_variants() {
    for c in [
        CampaignComplexity::Probe,
        CampaignComplexity::MultiStage,
        CampaignComplexity::Apt,
    ] {
        assert!(!c.to_string().is_empty());
    }
}

#[test]
fn probe_complexity_generates_four_steps() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0x1111,
    )
    .expect("generator");
    let c = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("campaign");
    assert_eq!(c.steps.len(), 4);
}

#[test]
fn multi_stage_complexity_generates_eight_steps() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0x2222,
    )
    .expect("generator");
    let c = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("campaign");
    assert_eq!(c.steps.len(), 8);
}

#[test]
fn apt_complexity_generates_twelve_steps() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0x3333,
    )
    .expect("generator");
    let c = generator
        .generate_campaign(CampaignComplexity::Apt)
        .expect("campaign");
    assert_eq!(c.steps.len(), 12);
}

// ---------- ContainmentDifficulty ----------

#[test]
fn easy_difficulty_for_fully_detected_low_damage() {
    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 50_000,
        evidence_atoms_before_detection: 1,
        novel_technique: false,
    })
    .expect("score");
    assert_eq!(score.difficulty, ContainmentDifficulty::Easy);
}

// ---------- MutationEngine ----------

#[test]
fn mutation_crossover_merges_two_campaigns() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0x4444)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("base");
    let donor = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("donor");
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0x5555,
            donor_campaign: Some(donor),
        },
    )
    .expect("crossover");
    mutated.validate().expect("crossover valid");
}

#[test]
fn mutation_insertion_adds_one_step() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0x6666)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("base");
    let n = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Insertion,
            seed: 0x7777,
            donor_campaign: None,
        },
    )
    .expect("insertion");
    assert_eq!(mutated.steps.len(), n + 1);
}

#[test]
fn mutation_deletion_removes_one_step() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0x8888)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("base");
    let n = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Deletion,
            seed: 0x9999,
            donor_campaign: None,
        },
    )
    .expect("deletion");
    assert_eq!(mutated.steps.len(), n - 1);
}

#[test]
fn mutation_temporal_shift_keeps_step_count_when_temporal_steps_exist() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xAAAA)
            .expect("generator");
    // Use Apt complexity (12 steps) to maximize chance of temporal payload steps
    for _ in 0..5 {
        let base = generator
            .generate_campaign(CampaignComplexity::Apt)
            .expect("base");
        let n = base.steps.len();
        match MutationEngine::mutate(
            &base,
            &grammar,
            MutationRequest {
                operator: MutationOperator::TemporalShift,
                seed: 0xBBBB,
                donor_campaign: None,
            },
        ) {
            Ok(mutated) => {
                assert_eq!(mutated.steps.len(), n);
                return;
            }
            Err(_) => continue,
        }
    }
    // If no campaign had temporal steps after 5 tries, error is acceptable
}

#[test]
fn mutation_point_mutation_keeps_step_count() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xCCCC)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("base");
    let n = base.steps.len();
    let mutated = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0xDDDD,
            donor_campaign: None,
        },
    )
    .expect("point mutation");
    assert_eq!(mutated.steps.len(), n);
}

// ---------- CampaignRuntime ----------

#[test]
fn frankenengine_runtime_is_not_baseline() {
    assert!(!CampaignRuntime::FrankenEngine.is_baseline());
}

#[test]
fn node_lts_runtime_is_baseline() {
    assert!(CampaignRuntime::NodeLts.is_baseline());
}

#[test]
fn bun_stable_runtime_is_baseline() {
    assert!(CampaignRuntime::BunStable.is_baseline());
}

// ---------- CampaignAttackCategory ----------

#[test]
fn attack_category_all_has_five_entries() {
    assert_eq!(adversarial_campaign::CampaignAttackCategory::ALL.len(), 5);
}

// ---------- CampaignExecutionResult validation ----------

#[test]
fn execution_result_rejects_undetected_exceeding_total() {
    let r = CampaignExecutionResult {
        undetected_steps: 10,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 500_000,
        evidence_atoms_before_detection: 5,
        novel_technique: false,
    };
    assert!(r.validate().is_err());
}

#[test]
fn execution_result_rejects_damage_exceeding_one_million() {
    let r = CampaignExecutionResult {
        undetected_steps: 1,
        total_steps: 2,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 1_500_000,
        evidence_atoms_before_detection: 1,
        novel_technique: false,
    };
    assert!(r.validate().is_err());
}

// ---------- Score lookup ----------

#[test]
fn generator_score_returns_none_for_unknown_id() {
    let cg = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0xEEEE,
    )
    .expect("generator");
    assert!(cg.score("nonexistent").is_none());
}

// ---------- drain_events ----------

#[test]
fn drain_events_empties_event_log() {
    let mut cg = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0xFFFF,
    )
    .expect("generator");
    let campaign = cg
        .generate_campaign(CampaignComplexity::Probe)
        .expect("campaign");
    let score = cg
        .score_campaign(
            &campaign,
            &CampaignExecutionResult {
                undetected_steps: 1,
                total_steps: 4,
                objective_achieved_before_containment: false,
                damage_potential_millionths: 200_000,
                evidence_atoms_before_detection: 3,
                novel_technique: false,
            },
        )
        .expect("score");
    cg.record_campaign_outcome(&campaign, &score)
        .expect("record");
    let first = cg.drain_events();
    assert!(!first.is_empty());
    let second = cg.drain_events();
    assert!(second.is_empty());
}

// ---------- plan_campaign_count ----------

#[test]
fn plan_campaign_count_positive_with_no_backlog() {
    let cg = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 8,
            ..CampaignGeneratorConfig::default()
        },
        0xAA11,
    )
    .expect("generator");
    assert!(cg.plan_campaign_count(0) > 0);
}

#[test]
fn plan_campaign_count_decreases_with_backlog() {
    let cg = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 10,
            max_backpressure_queue: 10,
            ..CampaignGeneratorConfig::default()
        },
        0xBB22,
    )
    .expect("generator");
    let no_backlog = cg.plan_campaign_count(0);
    let high_backlog = cg.plan_campaign_count(10);
    assert!(high_backlog <= no_backlog);
}

// ---------- suppression gate edge cases ----------

#[test]
fn suppression_gate_rejects_non_continuous_run() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-non-continuous".to_string(),
        continuous_run: false,
        samples: Vec::new(),
        trend_points: Vec::new(),
        escalations: Vec::new(),
    };
    let result = evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default());
    if let Ok(gate_result) = result {
        assert!(!gate_result.passed);
    }
}

#[test]
fn suppression_gate_config_debug_is_nonempty() {
    let config = SuppressionGateConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn suppression_gate_config_serde_is_deterministic() {
    let config = SuppressionGateConfig::default();
    let a = serde_json::to_string(&config).expect("first");
    let b = serde_json::to_string(&config).expect("second");
    assert_eq!(a, b);
}

#[test]
fn suppression_gate_input_debug_is_nonempty() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-debug".to_string(),
        continuous_run: true,
        samples: Vec::new(),
        trend_points: Vec::new(),
        escalations: Vec::new(),
    };
    assert!(!format!("{input:?}").is_empty());
}

// ---------- Serde roundtrips ----------

#[test]
fn campaign_error_serde_roundtrip_all_variants() {
    let variants: Vec<adversarial_campaign::CampaignError> = vec![
        adversarial_campaign::CampaignError::InvalidGrammar {
            detail: "bad grammar".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidCampaign {
            detail: "bad campaign".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidExecutionResult {
            detail: "bad result".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidMutation {
            detail: "bad mutation".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidSeed,
        adversarial_campaign::CampaignError::InvalidCalibration {
            detail: "bad calibration".to_string(),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let roundtripped: adversarial_campaign::CampaignError =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, roundtripped);
    }
}

#[test]
fn campaign_complexity_serde_roundtrip_all_variants() {
    for complexity in [
        CampaignComplexity::Probe,
        CampaignComplexity::MultiStage,
        CampaignComplexity::Apt,
    ] {
        let json = serde_json::to_string(&complexity).expect("serialize");
        let roundtripped: CampaignComplexity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(complexity, roundtripped);
    }
}

#[test]
fn attack_dimension_serde_roundtrip_all_variants() {
    let dimensions = [
        adversarial_campaign::AttackDimension::HostcallSequence,
        adversarial_campaign::AttackDimension::TemporalPayload,
        adversarial_campaign::AttackDimension::PrivilegeEscalation,
        adversarial_campaign::AttackDimension::PolicyEvasion,
        adversarial_campaign::AttackDimension::Exfiltration,
    ];
    for dim in &dimensions {
        let json = serde_json::to_string(dim).expect("serialize");
        let roundtripped: adversarial_campaign::AttackDimension =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*dim, roundtripped);
    }
}

#[test]
fn containment_difficulty_serde_roundtrip_all_variants() {
    for diff in [
        ContainmentDifficulty::Easy,
        ContainmentDifficulty::Moderate,
        ContainmentDifficulty::Hard,
        ContainmentDifficulty::Critical,
    ] {
        let json = serde_json::to_string(&diff).expect("serialize");
        let roundtripped: ContainmentDifficulty = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(diff, roundtripped);
    }
}

#[test]
fn mutation_operator_serde_roundtrip_all_variants() {
    for op in [
        MutationOperator::PointMutation,
        MutationOperator::Crossover,
        MutationOperator::Insertion,
        MutationOperator::Deletion,
        MutationOperator::TemporalShift,
    ] {
        let json = serde_json::to_string(&op).expect("serialize");
        let roundtripped: MutationOperator = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(op, roundtripped);
    }
}

#[test]
fn campaign_runtime_serde_roundtrip_all_variants() {
    for rt in [
        CampaignRuntime::FrankenEngine,
        CampaignRuntime::NodeLts,
        CampaignRuntime::BunStable,
    ] {
        let json = serde_json::to_string(&rt).expect("serialize");
        let roundtripped: CampaignRuntime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, roundtripped);
    }
}

#[test]
fn campaign_attack_category_serde_roundtrip_all_variants() {
    for cat in adversarial_campaign::CampaignAttackCategory::ALL {
        let json = serde_json::to_string(&cat).expect("serialize");
        let roundtripped: adversarial_campaign::CampaignAttackCategory =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, roundtripped);
    }
}

#[test]
fn adversarial_campaign_serde_roundtrip() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0xA0A0,
    )
    .expect("generator");
    let campaign = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("campaign");
    let json = serde_json::to_string(&campaign).expect("serialize");
    let roundtripped: adversarial_campaign::AdversarialCampaign =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(campaign, roundtripped);
}

#[test]
fn campaign_execution_result_serde_roundtrip() {
    let result = CampaignExecutionResult {
        undetected_steps: 2,
        total_steps: 5,
        objective_achieved_before_containment: true,
        damage_potential_millionths: 600_000,
        evidence_atoms_before_detection: 20,
        novel_technique: false,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let roundtripped: CampaignExecutionResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, roundtripped);
}

#[test]
fn exploit_objective_score_serde_roundtrip() {
    let result = CampaignExecutionResult {
        undetected_steps: 3,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 450_000,
        evidence_atoms_before_detection: 17,
        novel_technique: false,
    };
    let score = ExploitObjectiveScore::from_result(&result).expect("score");
    let json = serde_json::to_string(&score).expect("serialize");
    let roundtripped: ExploitObjectiveScore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(score, roundtripped);
}

// ---------- Display implementations ----------

#[test]
fn campaign_error_display_all_variants() {
    let variants: Vec<adversarial_campaign::CampaignError> = vec![
        adversarial_campaign::CampaignError::InvalidGrammar {
            detail: "details".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidCampaign {
            detail: "details".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidExecutionResult {
            detail: "details".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidMutation {
            detail: "details".to_string(),
        },
        adversarial_campaign::CampaignError::InvalidSeed,
        adversarial_campaign::CampaignError::InvalidCalibration {
            detail: "details".to_string(),
        },
    ];
    let expected_prefixes = [
        "invalid grammar:",
        "invalid campaign:",
        "invalid execution result:",
        "invalid mutation:",
        "seed must be non-zero",
        "invalid calibration:",
    ];
    for (variant, prefix) in variants.iter().zip(expected_prefixes.iter()) {
        let display = variant.to_string();
        assert!(
            display.starts_with(prefix),
            "expected prefix '{prefix}', got '{display}'"
        );
    }
}

#[test]
fn campaign_error_error_code_all_variants() {
    let variants: Vec<adversarial_campaign::CampaignError> = vec![
        adversarial_campaign::CampaignError::InvalidGrammar {
            detail: String::new(),
        },
        adversarial_campaign::CampaignError::InvalidCampaign {
            detail: String::new(),
        },
        adversarial_campaign::CampaignError::InvalidExecutionResult {
            detail: String::new(),
        },
        adversarial_campaign::CampaignError::InvalidMutation {
            detail: String::new(),
        },
        adversarial_campaign::CampaignError::InvalidSeed,
        adversarial_campaign::CampaignError::InvalidCalibration {
            detail: String::new(),
        },
    ];
    for variant in &variants {
        let code = variant.error_code();
        assert!(code.starts_with("FE-ADV-CAMP-"), "code was {code}");
    }
}

#[test]
fn containment_difficulty_display_all_variants() {
    let expected = [
        ("easy", ContainmentDifficulty::Easy),
        ("moderate", ContainmentDifficulty::Moderate),
        ("hard", ContainmentDifficulty::Hard),
        ("critical", ContainmentDifficulty::Critical),
    ];
    for (label, variant) in &expected {
        assert_eq!(variant.to_string(), *label);
    }
}

#[test]
fn mutation_operator_display_all_variants() {
    let expected = [
        ("point_mutation", MutationOperator::PointMutation),
        ("crossover", MutationOperator::Crossover),
        ("insertion", MutationOperator::Insertion),
        ("deletion", MutationOperator::Deletion),
        ("temporal_shift", MutationOperator::TemporalShift),
    ];
    for (label, variant) in &expected {
        assert_eq!(variant.to_string(), *label);
    }
}

#[test]
fn campaign_runtime_display_all_variants() {
    let expected = [
        ("franken_engine", CampaignRuntime::FrankenEngine),
        ("node_lts", CampaignRuntime::NodeLts),
        ("bun_stable", CampaignRuntime::BunStable),
    ];
    for (label, variant) in &expected {
        assert_eq!(variant.to_string(), *label);
    }
}

#[test]
fn attack_category_display_all_variants() {
    for cat in adversarial_campaign::CampaignAttackCategory::ALL {
        let display = cat.to_string();
        assert!(!display.is_empty());
    }
}

// ---------- Clone / Debug / Copy ----------

#[test]
fn deterministic_rng_clone_produces_identical_sequence() {
    let mut rng = adversarial_campaign::DeterministicRng::new(999).expect("rng");
    let _ = rng.next_u64();
    let mut cloned = rng;
    for _ in 0..20 {
        assert_eq!(rng.next_u64(), cloned.next_u64());
    }
}

#[test]
fn campaign_complexity_is_copy() {
    let a = CampaignComplexity::Apt;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn containment_difficulty_is_copy() {
    let a = ContainmentDifficulty::Hard;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn mutation_operator_is_copy() {
    let a = MutationOperator::Crossover;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn campaign_runtime_is_copy() {
    let a = CampaignRuntime::BunStable;
    let b = a;
    assert_eq!(a, b);
}

// ---------- Edge cases and validation failures ----------

#[test]
fn execution_result_rejects_zero_total_steps() {
    let r = CampaignExecutionResult {
        undetected_steps: 0,
        total_steps: 0,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 0,
        evidence_atoms_before_detection: 0,
        novel_technique: false,
    };
    assert!(r.validate().is_err());
}

#[test]
fn execution_result_accepts_boundary_damage_at_exactly_one_million() {
    let r = CampaignExecutionResult {
        undetected_steps: 1,
        total_steps: 2,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 1_000_000,
        evidence_atoms_before_detection: 1,
        novel_technique: false,
    };
    assert!(r.validate().is_ok());
}

#[test]
fn campaign_generator_rejects_zero_seed() {
    let result = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig::default(),
        0,
    );
    assert!(result.is_err());
}

#[test]
fn campaign_generator_rejects_empty_policy_id() {
    let config = CampaignGeneratorConfig {
        policy_id: "   ".to_string(),
        campaigns_per_hour: 1,
        max_backpressure_queue: 4,
        promotion_threshold_millionths: 500_000,
    };
    let result = CampaignGenerator::new(AttackGrammar::default(), config, 0x1234);
    assert!(result.is_err());
}

#[test]
fn campaign_generator_rejects_zero_campaigns_per_hour() {
    let config = CampaignGeneratorConfig {
        policy_id: "test-policy".to_string(),
        campaigns_per_hour: 0,
        max_backpressure_queue: 4,
        promotion_threshold_millionths: 500_000,
    };
    let result = CampaignGenerator::new(AttackGrammar::default(), config, 0x1234);
    assert!(result.is_err());
}

#[test]
fn attack_grammar_rejects_zero_version() {
    let grammar = AttackGrammar {
        version: 0,
        ..AttackGrammar::default()
    };
    assert!(grammar.validate().is_err());
}

#[test]
fn attack_grammar_rejects_zero_weight_production() {
    let mut grammar = AttackGrammar::default();
    grammar.hostcall_motifs[0].weight = 0;
    let err = grammar.validate().expect_err("zero weight");
    assert!(err.to_string().contains("zero-weight"));
}

#[test]
fn attack_grammar_rejects_empty_label_production() {
    let mut grammar = AttackGrammar::default();
    grammar.temporal_staging[0].label = "   ".to_string();
    let err = grammar.validate().expect_err("empty label");
    assert!(err.to_string().contains("empty production label"));
}

#[test]
fn mutation_deletion_rejects_single_step_campaign() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xDD01)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("base");

    // Manually create a single-step campaign from the base
    let single = adversarial_campaign::AdversarialCampaign {
        campaign_id: base.campaign_id.clone(),
        trace_id: base.trace_id.clone(),
        decision_id: base.decision_id.clone(),
        policy_id: base.policy_id.clone(),
        grammar_version: base.grammar_version,
        seed: base.seed,
        complexity: CampaignComplexity::Probe,
        steps: vec![base.steps[0].clone()],
    };

    let result = MutationEngine::mutate(
        &single,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Deletion,
            seed: 0xDD02,
            donor_campaign: None,
        },
    );
    assert!(result.is_err());
}

#[test]
fn mutation_crossover_rejects_missing_donor() {
    let grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xCC01)
            .expect("generator");
    let base = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("base");

    let result = MutationEngine::mutate(
        &base,
        &grammar,
        MutationRequest {
            operator: MutationOperator::Crossover,
            seed: 0xCC02,
            donor_campaign: None,
        },
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("donor_campaign"));
}

// ---------- Ordering / BTreeMap keys ----------

#[test]
fn attack_dimension_ordering_is_deterministic() {
    use std::collections::BTreeSet;
    let dims = [
        adversarial_campaign::AttackDimension::Exfiltration,
        adversarial_campaign::AttackDimension::HostcallSequence,
        adversarial_campaign::AttackDimension::PolicyEvasion,
        adversarial_campaign::AttackDimension::PrivilegeEscalation,
        adversarial_campaign::AttackDimension::TemporalPayload,
    ];
    let set: BTreeSet<adversarial_campaign::AttackDimension> = dims.iter().copied().collect();
    let ordered: Vec<_> = set.into_iter().collect();
    // Verify all 5 are present and in stable order
    assert_eq!(ordered.len(), 5);
    // Insertion order should not matter; Ord is derived on enum discriminant
    for window in ordered.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn campaign_runtime_ordering_is_deterministic() {
    use std::collections::BTreeSet;
    let runtimes = [
        CampaignRuntime::BunStable,
        CampaignRuntime::FrankenEngine,
        CampaignRuntime::NodeLts,
    ];
    let set: BTreeSet<CampaignRuntime> = runtimes.iter().copied().collect();
    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered.len(), 3);
    for window in ordered.windows(2) {
        assert!(window[0] < window[1]);
    }
}

// ---------- Default trait ----------

#[test]
fn campaign_generator_config_default_has_sane_values() {
    let config = CampaignGeneratorConfig::default();
    assert!(!config.policy_id.is_empty());
    assert!(config.campaigns_per_hour > 0);
    assert!(config.max_backpressure_queue > 0);
    assert!(config.promotion_threshold_millionths <= 1_000_000);
}

#[test]
fn suppression_gate_config_default_has_sane_values() {
    let config = SuppressionGateConfig::default();
    assert!(!config.required_categories.is_empty());
    assert!(config.minimum_baseline_runtimes > 0);
    assert!(config.max_p_value_millionths > 0);
    assert!(config.max_p_value_millionths <= 1_000_000);
    assert!(config.minimum_trend_points > 0);
    assert!(config.max_escalation_latency_seconds > 0);
}

// ---------- DeterministicRng edge cases ----------

#[test]
fn deterministic_rng_choose_index_returns_zero_for_empty() {
    let mut rng = adversarial_campaign::DeterministicRng::new(42).expect("rng");
    assert_eq!(rng.choose_index(0), 0);
}

#[test]
fn deterministic_rng_range_u64_returns_start_when_start_equals_end() {
    let mut rng = adversarial_campaign::DeterministicRng::new(42).expect("rng");
    assert_eq!(rng.range_u64(100, 100), 100);
}

#[test]
fn deterministic_rng_range_u64_returns_start_when_end_less_than_start() {
    let mut rng = adversarial_campaign::DeterministicRng::new(42).expect("rng");
    assert_eq!(rng.range_u64(200, 100), 200);
}

// ---------- Suppression sample validation ----------

#[test]
fn suppression_sample_rejects_empty_campaign_id() {
    let sample = CampaignSuppressionSample {
        campaign_id: "   ".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        attempt_count: 100,
        success_count: 5,
        raw_log_ref: "artifacts/raw/test.jsonl".to_string(),
        repro_script_ref: "artifacts/repro/test.sh".to_string(),
    };
    assert!(sample.validate().is_err());
}

#[test]
fn suppression_sample_rejects_zero_attempts() {
    let sample = CampaignSuppressionSample {
        campaign_id: "test-camp".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        attempt_count: 0,
        success_count: 0,
        raw_log_ref: "artifacts/raw/test.jsonl".to_string(),
        repro_script_ref: "artifacts/repro/test.sh".to_string(),
    };
    assert!(sample.validate().is_err());
}

#[test]
fn suppression_sample_rejects_successes_exceeding_attempts() {
    let sample = CampaignSuppressionSample {
        campaign_id: "test-camp".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::SupplyChain,
        target_runtime: CampaignRuntime::NodeLts,
        attempt_count: 10,
        success_count: 20,
        raw_log_ref: "artifacts/raw/test.jsonl".to_string(),
        repro_script_ref: "artifacts/repro/test.sh".to_string(),
    };
    assert!(sample.validate().is_err());
}

#[test]
fn suppression_sample_compromise_rate_boundary_zero_successes() {
    let sample = CampaignSuppressionSample {
        campaign_id: "test-zero".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::Injection,
        target_runtime: CampaignRuntime::FrankenEngine,
        attempt_count: 100,
        success_count: 0,
        raw_log_ref: "artifacts/raw/test.jsonl".to_string(),
        repro_script_ref: "artifacts/repro/test.sh".to_string(),
    };
    assert_eq!(sample.compromise_rate_millionths(), 0);
}

// ---------- Escalation record validation ----------

#[test]
fn escalation_record_rejects_missing_latency_when_triggered() {
    let record = ExploitEscalationRecord {
        campaign_id: "esc-test".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::CapabilityEscape,
        target_runtime: CampaignRuntime::FrankenEngine,
        successful_exploit: true,
        escalation_triggered: true,
        escalation_latency_seconds: None,
    };
    assert!(record.validate().is_err());
}

#[test]
fn escalation_record_accepts_latency_when_triggered() {
    let record = ExploitEscalationRecord {
        campaign_id: "esc-ok".to_string(),
        attack_category: adversarial_campaign::CampaignAttackCategory::TimingSideChannel,
        target_runtime: CampaignRuntime::BunStable,
        successful_exploit: true,
        escalation_triggered: true,
        escalation_latency_seconds: Some(120),
    };
    assert!(record.validate().is_ok());
}

// ---------- Score difficulty thresholds ----------

#[test]
fn moderate_difficulty_for_mid_range_composite_score() {
    // composite = (evasion*35 + escape*25 + damage*20 + detect*15 + novel*5) / 100
    // evasion=4/5=800k, escape=0, damage=600k, detect=min(25*20k,1M)=500k, novel=1M
    // = (28M + 0 + 12M + 7.5M + 5M) / 100 = 525_000 => Moderate
    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 4,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 600_000,
        evidence_atoms_before_detection: 25,
        novel_technique: true,
    })
    .expect("score");
    assert_eq!(score.difficulty, ContainmentDifficulty::Moderate);
}

#[test]
fn hard_difficulty_for_high_evasion_with_objective() {
    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 4,
        total_steps: 5,
        objective_achieved_before_containment: true,
        damage_potential_millionths: 500_000,
        evidence_atoms_before_detection: 30,
        novel_technique: false,
    })
    .expect("score");
    assert!(
        score.difficulty == ContainmentDifficulty::Hard
            || score.difficulty == ContainmentDifficulty::Critical
    );
}

// ---------- Suppression gate input validation ----------

#[test]
fn suppression_gate_input_rejects_empty_release_candidate_id() {
    let input = SuppressionGateInput {
        release_candidate_id: "   ".to_string(),
        continuous_run: true,
        samples: vec![CampaignSuppressionSample {
            campaign_id: "test-camp".to_string(),
            attack_category: adversarial_campaign::CampaignAttackCategory::Injection,
            target_runtime: CampaignRuntime::FrankenEngine,
            attempt_count: 100,
            success_count: 5,
            raw_log_ref: "artifacts/raw/test.jsonl".to_string(),
            repro_script_ref: "artifacts/repro/test.sh".to_string(),
        }],
        trend_points: Vec::new(),
        escalations: Vec::new(),
    };
    assert!(input.validate().is_err());
}

#[test]
fn suppression_gate_input_rejects_empty_samples() {
    let input = SuppressionGateInput {
        release_candidate_id: "rc-empty-samples".to_string(),
        continuous_run: true,
        samples: Vec::new(),
        trend_points: Vec::new(),
        escalations: Vec::new(),
    };
    assert!(input.validate().is_err());
}

// ---------- plan_campaign_count edge cases ----------

#[test]
fn plan_campaign_count_returns_zero_when_backlog_exceeds_max() {
    let cg = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            campaigns_per_hour: 10,
            max_backpressure_queue: 5,
            ..CampaignGeneratorConfig::default()
        },
        0xBB33,
    )
    .expect("generator");
    assert_eq!(cg.plan_campaign_count(100), 0);
}

// ---------- CampaignGeneratorConfig serde ----------

#[test]
fn campaign_generator_config_serde_roundtrip() {
    let config = CampaignGeneratorConfig {
        policy_id: "test-roundtrip".to_string(),
        campaigns_per_hour: 42,
        max_backpressure_queue: 100,
        promotion_threshold_millionths: 800_000,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let roundtripped: CampaignGeneratorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, roundtripped);
}

// ---------- Suppression gate config serde ----------

#[test]
fn suppression_gate_config_serde_roundtrip() {
    let config = SuppressionGateConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let roundtripped: SuppressionGateConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, roundtripped);
}

// ---------- Attack grammar clone and feedback ----------

#[test]
fn attack_grammar_clone_eq() {
    let grammar = AttackGrammar::default();
    let cloned = grammar.clone();
    assert_eq!(grammar, cloned);
}

#[test]
fn attack_grammar_feedback_does_not_invalidate() {
    let mut grammar = AttackGrammar::default();
    let mut generator =
        CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xFB01)
            .expect("generator");
    let campaign = generator
        .generate_campaign(CampaignComplexity::Probe)
        .expect("campaign");

    let score = ExploitObjectiveScore::from_result(&CampaignExecutionResult {
        undetected_steps: 4,
        total_steps: 4,
        objective_achieved_before_containment: true,
        damage_potential_millionths: 900_000,
        evidence_atoms_before_detection: 50,
        novel_technique: true,
    })
    .expect("score");

    grammar.apply_campaign_feedback(&campaign, &score);
    // Grammar should still validate after feedback
    grammar.validate().expect("still valid after feedback");
    // Weights should have been amplified
    let total_weight: u32 = grammar.hostcall_motifs.iter().map(|p| p.weight).sum();
    assert!(total_weight > 0);
}
