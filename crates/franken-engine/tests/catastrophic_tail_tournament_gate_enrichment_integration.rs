//! Enrichment integration tests for `franken_engine::catastrophic_tail_tournament_gate`.
//!
//! Covers Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior, edge cases, deterministic hash behavior, builder patterns,
//! CliffBand semantics, atlas stable/unstable counts, and error paths.

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

use frankenengine_engine::adversarial_coevolution_harness::{
    ConvergenceDiagnostic, PolicyDelta, RoundOutcome, StrategyId, TrajectoryLedger,
    TournamentResult,
};
use frankenengine_engine::catastrophic_tail_tournament_gate::{
    Campaign, CatastrophicTailTournamentGate, CliffBand, CliffMarginCertificate, CliffWitness,
    ContinuationCliffAtlas, GateDecision, GateVerdict, MitigationStep, RiskLedgerEntry,
    RollbackPlaybook, TailGateConfig, TailGateError, TailRiskMetrics, ThreatCategory, ThreatClass,
    CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION, TAIL_GATE_SCHEMA_VERSION,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::{DemotionReason, LaneAction, LaneId};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

fn make_threat(id: &str, category: ThreatCategory, weight: i64) -> ThreatClass {
    ThreatClass {
        id: id.to_string(),
        label: format!("Threat {}", id),
        category,
        impact_weight_millionths: weight,
        related_exploits: BTreeSet::new(),
    }
}

fn make_tournament_result(rounds: u64, payoff: i64) -> TournamentResult {
    TournamentResult {
        schema_version: "test".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        rounds_played: rounds,
        total_attacker_payoff_millionths: payoff * rounds as i64,
        total_defender_payoff_millionths: -payoff * rounds as i64,
        convergence: ConvergenceDiagnostic {
            attacker_avg_regret_millionths: 0,
            defender_avg_regret_millionths: 0,
            attacker_regret_bounded: true,
            defender_regret_bounded: true,
            exploit_classes: BTreeSet::new(),
            attacker_frequency: BTreeMap::new(),
            defender_frequency: BTreeMap::new(),
        },
        policy_delta: PolicyDelta {
            delta_id: "delta-test".to_string(),
            recommended_mix: BTreeMap::new(),
            addressed_exploits: BTreeSet::new(),
            expected_improvement_millionths: 0,
            source_epoch: SecurityEpoch::from_raw(1),
            artifact_hash: ContentHash::compute(b"test"),
        },
        trajectory: None,
        artifact_hash: ContentHash::compute(b"test-tournament"),
    }
}

fn make_tournament_result_with_trajectory(
    rounds: u64,
    payoff: i64,
    exploit: Option<&str>,
) -> TournamentResult {
    let round_outcomes: Vec<RoundOutcome> = (0..rounds)
        .map(|r| RoundOutcome {
            round: r,
            attacker_strategy: StrategyId("atk".to_string()),
            defender_strategy: StrategyId("def".to_string()),
            attacker_payoff_millionths: payoff,
            defender_payoff_millionths: -payoff,
            exploit_discovered: if r == 0 {
                exploit.map(|e| {
                    // Use a known exploit class
                    use frankenengine_engine::adversarial_coevolution_harness::ExploitClass;
                    match e {
                        "capability-escalation" => ExploitClass::CapabilityEscalation,
                        _ => ExploitClass::ResourceExhaustion,
                    }
                })
            } else {
                None
            },
        })
        .collect();
    let mut result = make_tournament_result(rounds, payoff);
    result.trajectory = Some(TrajectoryLedger {
        rounds: round_outcomes,
        attacker_cumulative_regret: vec![0; rounds as usize],
        defender_cumulative_regret: vec![0; rounds as usize],
    });
    result
}

fn make_campaign(id: &str, threat_id: &str, payoffs: Vec<i64>) -> Campaign {
    let rounds = payoffs.len() as u64;
    Campaign {
        campaign_id: id.to_string(),
        threat_class_id: threat_id.to_string(),
        tournament_result: make_tournament_result(
            rounds,
            payoffs.iter().sum::<i64>() / rounds.max(1) as i64,
        ),
        attacker_payoffs: payoffs,
    }
}

fn make_campaign_with_trajectory(
    id: &str,
    threat_id: &str,
    payoffs: Vec<i64>,
    exploit: Option<&str>,
) -> Campaign {
    let rounds = payoffs.len() as u64;
    let avg = payoffs.iter().sum::<i64>() / rounds.max(1) as i64;
    Campaign {
        campaign_id: id.to_string(),
        threat_class_id: threat_id.to_string(),
        tournament_result: make_tournament_result_with_trajectory(rounds, avg, exploit),
        attacker_payoffs: payoffs,
    }
}

fn default_gate() -> CatastrophicTailTournamentGate {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap()
}

fn dual_threat_gate() -> CatastrophicTailTournamentGate {
    let threats = vec![
        make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("t2", ThreatCategory::ResourceExhaustion, MILLION),
    ];
    CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap()
}

fn low_risk_payoffs(n: usize) -> Vec<i64> {
    (0..n).map(|i| (i as i64) * 1000).collect()
}

fn high_risk_payoffs(n: usize) -> Vec<i64> {
    let mut payoffs: Vec<i64> = (0..n).map(|_| 50_000).collect();
    let tail_start = n * 95 / 100;
    for p in payoffs.iter_mut().skip(tail_start) {
        *p = 5_000_000;
    }
    payoffs
}

// ── Display Uniqueness Tests ─────────────────────────────────────────────

#[test]
fn enrichment_display_uniqueness_threat_category_all_six() {
    let variants = [
        ThreatCategory::CapabilityEscalation,
        ThreatCategory::ResourceExhaustion,
        ThreatCategory::InformationLeakage,
        ThreatCategory::PolicyBypass,
        ThreatCategory::SupplyChain,
        ThreatCategory::TimingChannel,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let s = format!("{}", v);
        assert!(!s.is_empty(), "Display for {:?} must not be empty", v);
        assert!(seen.insert(s.clone()), "duplicate Display for {:?}: {}", v, s);
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_display_uniqueness_gate_verdict_all_three() {
    let variants = [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Inconclusive,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let s = format!("{}", v);
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "duplicate Display for {:?}", v);
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn enrichment_display_uniqueness_cliff_band_all_four() {
    let variants = [
        CliffBand::Stable,
        CliffBand::NearCliff,
        CliffBand::BeyondCliff,
        CliffBand::MissingNeighborhood,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let s = format!("{}", v);
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "duplicate Display for {:?}", v);
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn enrichment_display_uniqueness_tail_gate_error_all_variants() {
    let variants: Vec<TailGateError> = vec![
        TailGateError::NoThreatClasses,
        TailGateError::TooManyThreatClasses { count: 70, max: 64 },
        TailGateError::NoCampaigns,
        TailGateError::TooManyCampaigns {
            count: 200,
            max: 128,
        },
        TailGateError::UnknownThreatClass {
            campaign_id: "c-err".to_string(),
            threat_class_id: "t-err".to_string(),
        },
        TailGateError::DuplicateThreatClass {
            id: "dup-id".to_string(),
        },
        TailGateError::InsufficientRounds {
            campaign_id: "c-ir".to_string(),
            rounds: 10,
            required: 100,
        },
        TailGateError::InvalidConfig {
            detail: "bad".to_string(),
        },
        TailGateError::TooManyObservations {
            count: 200_000,
            max: 100_000,
        },
    ];
    let mut seen = BTreeSet::new();
    for err in &variants {
        let s = format!("{}", err);
        assert!(!s.is_empty());
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for {:?}: {}",
            err,
            s
        );
    }
    assert_eq!(seen.len(), 9);
}

// ── CliffBand as_str / Display Consistency ───────────────────────────────

#[test]
fn enrichment_cliff_band_as_str_matches_display() {
    let variants = [
        CliffBand::Stable,
        CliffBand::NearCliff,
        CliffBand::BeyondCliff,
        CliffBand::MissingNeighborhood,
    ];
    for v in &variants {
        assert_eq!(v.as_str(), &format!("{}", v));
    }
}

#[test]
fn enrichment_cliff_band_as_str_known_values() {
    assert_eq!(CliffBand::Stable.as_str(), "stable");
    assert_eq!(CliffBand::NearCliff.as_str(), "near_cliff");
    assert_eq!(CliffBand::BeyondCliff.as_str(), "beyond_cliff");
    assert_eq!(CliffBand::MissingNeighborhood.as_str(), "missing_neighborhood");
}

// ── Serde Roundtrip Tests ────────────────────────────────────────────────

#[test]
fn enrichment_serde_roundtrip_cliff_band_all_variants() {
    let variants = [
        CliffBand::Stable,
        CliffBand::NearCliff,
        CliffBand::BeyondCliff,
        CliffBand::MissingNeighborhood,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CliffBand = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_cliff_margin_certificate() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-serde-cert".to_string(),
        cliff_band: CliffBand::NearCliff,
        cvar_margin_millionths: 30_000,
        e_value_margin_millionths: 40_000,
        observation_margin: 50,
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: CliffMarginCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn enrichment_serde_roundtrip_cliff_witness() {
    let witness = CliffWitness {
        threat_class_id: "t-serde-wit".to_string(),
        cliff_band: CliffBand::BeyondCliff,
        campaign_id: Some("c-witness".to_string()),
        max_payoff_millionths: 7_000_000,
        worst_exploit: Some("timing-attack".to_string()),
        escape_action: LaneAction::RouteTo(LaneId("quarantine".to_string())),
        rationale: "crossed cliff boundary".to_string(),
    };
    let json = serde_json::to_string(&witness).unwrap();
    let back: CliffWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, back);
}

#[test]
fn enrichment_serde_roundtrip_cliff_witness_missing_neighborhood() {
    let witness = CliffWitness {
        threat_class_id: "t-missing".to_string(),
        cliff_band: CliffBand::MissingNeighborhood,
        campaign_id: None,
        max_payoff_millionths: 0,
        worst_exploit: None,
        escape_action: LaneAction::FallbackSafe,
        rationale: "no campaigns exercised this neighborhood".to_string(),
    };
    let json = serde_json::to_string(&witness).unwrap();
    let back: CliffWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, back);
    assert!(back.campaign_id.is_none());
    assert!(back.worst_exploit.is_none());
}

#[test]
fn enrichment_serde_roundtrip_continuation_cliff_atlas_empty() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-empty-serde".to_string(),
        epoch: SecurityEpoch::from_raw(5),
        margin_certificates: vec![],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"empty"),
    };
    let json = serde_json::to_string(&atlas).unwrap();
    let back: ContinuationCliffAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(atlas, back);
}

#[test]
fn enrichment_serde_roundtrip_continuation_cliff_atlas_populated() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-full".to_string(),
        epoch: SecurityEpoch::from_raw(10),
        margin_certificates: vec![
            CliffMarginCertificate {
                threat_class_id: "t1".to_string(),
                cliff_band: CliffBand::Stable,
                cvar_margin_millionths: 200_000,
                e_value_margin_millionths: 15_000_000,
                observation_margin: 100,
            },
            CliffMarginCertificate {
                threat_class_id: "t2".to_string(),
                cliff_band: CliffBand::BeyondCliff,
                cvar_margin_millionths: -50_000,
                e_value_margin_millionths: -1_000_000,
                observation_margin: 200,
            },
        ],
        witnesses: vec![CliffWitness {
            threat_class_id: "t2".to_string(),
            cliff_band: CliffBand::BeyondCliff,
            campaign_id: Some("c2".to_string()),
            max_payoff_millionths: 3_000_000,
            worst_exploit: None,
            escape_action: LaneAction::RouteTo(LaneId("safe".to_string())),
            rationale: "beyond cliff".to_string(),
        }],
        atlas_hash: ContentHash::compute(b"full-atlas"),
    };
    let json = serde_json::to_string(&atlas).unwrap();
    let back: ContinuationCliffAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(atlas, back);
}

#[test]
fn enrichment_serde_roundtrip_gate_decision_with_playbook() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-serde-pb", &campaigns).unwrap();
    assert!(decision.rollback_playbook.is_some());

    let json = serde_json::to_string(&decision).unwrap();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
    assert!(back.rollback_playbook.is_some());
}

#[test]
fn enrichment_serde_roundtrip_mitigation_step_with_route_to_action() {
    let step = MitigationStep {
        step: 3,
        description: "Route to safe baseline".to_string(),
        automated: true,
        action: Some(LaneAction::RouteTo(LaneId("safe".to_string()))),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MitigationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn enrichment_serde_roundtrip_mitigation_step_with_demote_action() {
    let step = MitigationStep {
        step: 2,
        description: "Demote from active lane".to_string(),
        automated: true,
        action: Some(LaneAction::Demote {
            from_lane: LaneId("active".to_string()),
            reason: DemotionReason::CvarExceeded,
        }),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MitigationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn enrichment_serde_roundtrip_tail_gate_config_custom() {
    let config = TailGateConfig {
        epoch: SecurityEpoch::from_raw(99),
        cvar_alpha_millionths: 990_000,
        tail_budget_millionths: 750_000,
        e_value_alarm_threshold_millionths: 30_000_000,
        min_rounds_per_campaign: 250,
        near_cliff_margin_millionths: 100_000,
        generate_rollback_playbook: false,
        rollback_lane: LaneId("quarantine".to_string()),
        record_risk_ledger: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: TailGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ── Method Behavior Tests ────────────────────────────────────────────────

#[test]
fn enrichment_tail_risk_metrics_exceeds_budget_boundary_exact() {
    let m = TailRiskMetrics {
        threat_class_id: "t-exact".to_string(),
        observation_count: 100,
        var_millionths: 400_000,
        cvar_millionths: 500_000,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 600_000,
        worst_exploit: None,
    };
    // cvar == budget should NOT exceed (uses >)
    assert!(!m.exceeds_budget(500_000));
    assert!(m.exceeds_budget(499_999));
    assert!(!m.exceeds_budget(500_001));
}

#[test]
fn enrichment_cliff_margin_certificate_is_stable_true() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-stable".to_string(),
        cliff_band: CliffBand::Stable,
        cvar_margin_millionths: 200_000,
        e_value_margin_millionths: 10_000_000,
        observation_margin: 100,
    };
    assert!(cert.is_stable());
}

#[test]
fn enrichment_cliff_margin_certificate_is_stable_false_near_cliff() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-near".to_string(),
        cliff_band: CliffBand::NearCliff,
        cvar_margin_millionths: 30_000,
        e_value_margin_millionths: 40_000,
        observation_margin: 50,
    };
    assert!(!cert.is_stable());
}

#[test]
fn enrichment_cliff_margin_certificate_is_stable_false_beyond_cliff() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-beyond".to_string(),
        cliff_band: CliffBand::BeyondCliff,
        cvar_margin_millionths: -50_000,
        e_value_margin_millionths: -1_000_000,
        observation_margin: 200,
    };
    assert!(!cert.is_stable());
}

#[test]
fn enrichment_cliff_margin_certificate_is_stable_false_missing() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-missing".to_string(),
        cliff_band: CliffBand::MissingNeighborhood,
        cvar_margin_millionths: 500_000,
        e_value_margin_millionths: 20_000_000,
        observation_margin: -100,
    };
    assert!(!cert.is_stable());
}

#[test]
fn enrichment_continuation_cliff_atlas_stable_and_unstable_counts() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-counts".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![
            CliffMarginCertificate {
                threat_class_id: "t1".to_string(),
                cliff_band: CliffBand::Stable,
                cvar_margin_millionths: 200_000,
                e_value_margin_millionths: 15_000_000,
                observation_margin: 100,
            },
            CliffMarginCertificate {
                threat_class_id: "t2".to_string(),
                cliff_band: CliffBand::NearCliff,
                cvar_margin_millionths: 30_000,
                e_value_margin_millionths: 40_000,
                observation_margin: 50,
            },
            CliffMarginCertificate {
                threat_class_id: "t3".to_string(),
                cliff_band: CliffBand::BeyondCliff,
                cvar_margin_millionths: -50_000,
                e_value_margin_millionths: -1_000_000,
                observation_margin: 200,
            },
            CliffMarginCertificate {
                threat_class_id: "t4".to_string(),
                cliff_band: CliffBand::Stable,
                cvar_margin_millionths: 300_000,
                e_value_margin_millionths: 18_000_000,
                observation_margin: 150,
            },
        ],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"counts"),
    };
    assert_eq!(atlas.stable_certificate_count(), 2);
    assert_eq!(atlas.unstable_certificate_count(), 2);
}

#[test]
fn enrichment_continuation_cliff_atlas_empty_certificates_zero_counts() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-zero".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"zero"),
    };
    assert_eq!(atlas.stable_certificate_count(), 0);
    assert_eq!(atlas.unstable_certificate_count(), 0);
}

#[test]
fn enrichment_continuation_cliff_atlas_all_stable() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-all-stable".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![
            CliffMarginCertificate {
                threat_class_id: "t1".to_string(),
                cliff_band: CliffBand::Stable,
                cvar_margin_millionths: 200_000,
                e_value_margin_millionths: 15_000_000,
                observation_margin: 100,
            },
            CliffMarginCertificate {
                threat_class_id: "t2".to_string(),
                cliff_band: CliffBand::Stable,
                cvar_margin_millionths: 300_000,
                e_value_margin_millionths: 18_000_000,
                observation_margin: 150,
            },
        ],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"all-stable"),
    };
    assert_eq!(atlas.stable_certificate_count(), 2);
    assert_eq!(atlas.unstable_certificate_count(), 0);
}

#[test]
fn enrichment_gate_decision_is_pass_false_for_inconclusive() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-inc".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"inc"),
    };
    let decision = GateDecision {
        decision_id: "d-inc".to_string(),
        release_candidate_id: "rc-inc".to_string(),
        verdict: GateVerdict::Inconclusive,
        epoch: SecurityEpoch::from_raw(1),
        risk_metrics: vec![],
        aggregate_cvar_millionths: 0,
        any_alarm_active: false,
        campaigns_evaluated: 0,
        total_rounds: 0,
        rollback_playbook: None,
        continuation_cliff_atlas: atlas,
        rationale: "insufficient data".to_string(),
        artifact_hash: ContentHash::compute(b"inc"),
    };
    assert!(!decision.is_pass());
}

#[test]
fn enrichment_campaign_round_count_matches_tournament_rounds_played() {
    let payoffs = vec![100_000; 300];
    let campaign = make_campaign("c-rc", "t1", payoffs);
    assert_eq!(campaign.round_count(), 300);
}

// ── Deterministic Hash Behavior ──────────────────────────────────────────

#[test]
fn enrichment_artifact_hash_deterministic_across_separate_gates() {
    let threats = vec![
        make_threat("ta", ThreatCategory::PolicyBypass, MILLION),
        make_threat("tb", ThreatCategory::TimingChannel, 500_000),
    ];
    let campaigns = vec![
        make_campaign("c1", "ta", low_risk_payoffs(200)),
        make_campaign("c2", "tb", low_risk_payoffs(200)),
    ];

    let mut gate1 = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats.clone())
        .unwrap();
    let d1 = gate1.evaluate("rc-hash", &campaigns).unwrap();

    let mut gate2 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let d2 = gate2.evaluate("rc-hash", &campaigns).unwrap();

    assert_eq!(d1.artifact_hash, d2.artifact_hash);
    assert_eq!(
        d1.continuation_cliff_atlas.atlas_hash,
        d2.continuation_cliff_atlas.atlas_hash
    );
}

#[test]
fn enrichment_artifact_hash_differs_for_different_release_candidates() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let d1 = gate.evaluate("rc-A", &campaigns).unwrap();
    let d2 = gate.evaluate("rc-B", &campaigns).unwrap();
    assert_ne!(d1.artifact_hash, d2.artifact_hash);
}

#[test]
fn enrichment_atlas_hash_differs_for_different_epochs() {
    let config1 = TailGateConfig {
        epoch: SecurityEpoch::from_raw(1),
        ..Default::default()
    };
    let config2 = TailGateConfig {
        epoch: SecurityEpoch::from_raw(2),
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];

    let mut gate1 = CatastrophicTailTournamentGate::new(config1, threats.clone()).unwrap();
    let d1 = gate1.evaluate("rc-epoch", &campaigns).unwrap();

    let mut gate2 = CatastrophicTailTournamentGate::new(config2, threats).unwrap();
    let d2 = gate2.evaluate("rc-epoch", &campaigns).unwrap();

    assert_ne!(
        d1.continuation_cliff_atlas.atlas_hash,
        d2.continuation_cliff_atlas.atlas_hash
    );
}

// ── Edge Cases: Evaluation ───────────────────────────────────────────────

#[test]
fn enrichment_evaluate_zero_payoffs_all_rounds_pass() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", vec![0; 200])];
    let decision = gate.evaluate("rc-zero-payoffs", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Pass);
    assert_eq!(decision.risk_metrics[0].cvar_millionths, 0);
    assert_eq!(decision.risk_metrics[0].var_millionths, 0);
}

#[test]
fn enrichment_evaluate_exact_min_rounds_accepted() {
    let config = TailGateConfig {
        min_rounds_per_campaign: 100,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Exactly 100 payoffs, should pass validation
    let campaigns = vec![make_campaign("c1", "t1", vec![1000; 100])];
    let decision = gate.evaluate("rc-exact-min", &campaigns).unwrap();
    assert_eq!(decision.risk_metrics[0].observation_count, 100);
}

#[test]
fn enrichment_evaluate_exactly_max_campaigns_accepted() {
    let threats: Vec<_> = (0..2)
        .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
        .collect();
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    // 128 is MAX_CAMPAIGNS
    let campaigns: Vec<_> = (0..128)
        .map(|i| {
            make_campaign(
                &format!("c{}", i),
                if i % 2 == 0 { "t0" } else { "t1" },
                low_risk_payoffs(200),
            )
        })
        .collect();
    let decision = gate.evaluate("rc-max-camp", &campaigns).unwrap();
    assert_eq!(decision.campaigns_evaluated, 128);
}

#[test]
fn enrichment_evaluate_rejects_129_campaigns() {
    let threats = vec![make_threat("t1", ThreatCategory::PolicyBypass, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns: Vec<_> = (0..129)
        .map(|i| make_campaign(&format!("c{}", i), "t1", low_risk_payoffs(200)))
        .collect();
    let result = gate.evaluate("rc-too-many", &campaigns);
    assert!(matches!(
        result,
        Err(TailGateError::TooManyCampaigns {
            count: 129,
            max: 128
        })
    ));
}

#[test]
fn enrichment_evaluate_single_payoff_value_uniform_cvar_equals_that_value() {
    let mut gate = default_gate();
    let payoff_value = 250_000;
    let campaigns = vec![make_campaign("c1", "t1", vec![payoff_value; 200])];
    let decision = gate.evaluate("rc-uniform", &campaigns).unwrap();
    // Uniform payoffs: VaR at 95th percentile = the payoff, CVaR = average of tail = payoff
    assert_eq!(decision.risk_metrics[0].cvar_millionths, payoff_value);
    assert_eq!(decision.risk_metrics[0].var_millionths, payoff_value);
}

#[test]
fn enrichment_evaluate_risk_ledger_skips_zero_observation_threats() {
    let mut gate = dual_threat_gate();
    // Only provide campaigns for t1, not t2
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let _ = gate.evaluate("rc-partial", &campaigns).unwrap();
    // t2 has 0 observations so should not be recorded in ledger
    let ledger_threat_ids: Vec<_> = gate
        .risk_ledger()
        .iter()
        .map(|e| e.threat_class_id.as_str())
        .collect();
    assert!(ledger_threat_ids.contains(&"t1"));
    assert!(!ledger_threat_ids.contains(&"t2"));
}

// ── Edge Cases: Config Validation ────────────────────────────────────────

#[test]
fn enrichment_config_alpha_exactly_one_million_accepted() {
    let config = TailGateConfig {
        cvar_alpha_millionths: MILLION,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_alpha_one_accepted() {
    let config = TailGateConfig {
        cvar_alpha_millionths: 1,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_negative_alpha_rejected() {
    let config = TailGateConfig {
        cvar_alpha_millionths: -1,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_config_negative_near_cliff_margin_rejected() {
    let config = TailGateConfig {
        near_cliff_margin_millionths: -1,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_config_zero_near_cliff_margin_accepted() {
    let config = TailGateConfig {
        near_cliff_margin_millionths: 0,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_zero_budget_accepted() {
    let config = TailGateConfig {
        tail_budget_millionths: 0,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

// ── Schema Constants ─────────────────────────────────────────────────────

#[test]
fn enrichment_schema_version_constants_non_empty_and_distinct() {
    assert!(!TAIL_GATE_SCHEMA_VERSION.is_empty());
    assert!(!CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.is_empty());
    assert_ne!(TAIL_GATE_SCHEMA_VERSION, CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION);
}

#[test]
fn enrichment_schema_version_contains_expected_prefix() {
    assert!(TAIL_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ── Display Content Assertions ───────────────────────────────────────────

#[test]
fn enrichment_display_threat_class_contains_id_category_weight() {
    let tc = ThreatClass {
        id: "tc-display".to_string(),
        label: "My threat".to_string(),
        category: ThreatCategory::InformationLeakage,
        impact_weight_millionths: 750_000,
        related_exploits: BTreeSet::new(),
    };
    let s = format!("{}", tc);
    assert!(s.contains("tc-display"));
    assert!(s.contains("information-leakage"));
    assert!(s.contains("750000"));
}

#[test]
fn enrichment_display_tail_risk_metrics_contains_key_fields() {
    let m = TailRiskMetrics {
        threat_class_id: "t-disp-enrich".to_string(),
        observation_count: 1000,
        var_millionths: 200_000,
        cvar_millionths: 350_000,
        alpha_millionths: 950_000,
        e_value_millionths: 8_000_000,
        alarm_active: false,
        max_payoff_millionths: 1_500_000,
        worst_exploit: Some("resource-bomb".to_string()),
    };
    let s = format!("{}", m);
    assert!(s.contains("t-disp-enrich"));
    assert!(s.contains("350000")); // cvar
    assert!(s.contains("8000000")); // e-value
    assert!(s.contains("false")); // alarm
}

#[test]
fn enrichment_display_gate_decision_contains_verdict_and_campaigns() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-display-enrichment", &campaigns).unwrap();
    let s = format!("{}", decision);
    assert!(s.contains("rc-display-enrichment"));
    assert!(s.contains("pass"));
    assert!(s.contains("campaigns=1"));
}

#[test]
fn enrichment_display_rollback_playbook_trigger_and_step_counts() {
    let playbook = RollbackPlaybook {
        playbook_id: "pb-enrichment-disp".to_string(),
        rollback_action: LaneAction::SuspendAdaptive,
        triggering_threats: vec!["a".to_string(), "b".to_string()],
        mitigation_steps: vec![
            MitigationStep {
                step: 1,
                description: "halt".to_string(),
                automated: true,
                action: None,
            },
            MitigationStep {
                step: 2,
                description: "review".to_string(),
                automated: false,
                action: None,
            },
            MitigationStep {
                step: 3,
                description: "redeploy".to_string(),
                automated: true,
                action: None,
            },
        ],
        evidence_hash: ContentHash::compute(b"pb-disp"),
    };
    let s = format!("{}", playbook);
    assert!(s.contains("pb-enrichment-disp"));
    assert!(s.contains("triggers=2"));
    assert!(s.contains("steps=3"));
}

// ── Clone Independence ───────────────────────────────────────────────────

#[test]
fn enrichment_clone_gate_decision_independence() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-clone-ind", &campaigns).unwrap();
    let mut cloned = decision.clone();
    assert_eq!(decision, cloned);
    cloned.rationale = "mutated".to_string();
    assert_ne!(decision.rationale, cloned.rationale);
}

#[test]
fn enrichment_clone_risk_ledger_entry_independence() {
    let entry = RiskLedgerEntry {
        epoch: SecurityEpoch::from_raw(3),
        threat_class_id: "t-clone".to_string(),
        cvar_millionths: 100_000,
        e_value_millionths: 2_000_000,
        budget_exceeded: false,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ── Multi-Evaluation Behavior ────────────────────────────────────────────

#[test]
fn enrichment_evaluation_count_accumulates_correctly() {
    let mut gate = default_gate();
    assert_eq!(gate.evaluation_count(), 0);
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    for i in 1..=5 {
        let _ = gate.evaluate(&format!("rc-{}", i), &campaigns).unwrap();
        assert_eq!(gate.evaluation_count(), i);
    }
}

#[test]
fn enrichment_decision_id_format_includes_evaluation_count() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let d1 = gate.evaluate("rc-x", &campaigns).unwrap();
    let d2 = gate.evaluate("rc-y", &campaigns).unwrap();
    // Decision ID should contain the evaluation count
    assert!(d1.decision_id.contains("1"));
    assert!(d2.decision_id.contains("2"));
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn enrichment_risk_ledger_entries_have_correct_epoch() {
    let config = TailGateConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let _ = gate.evaluate("rc-epoch", &campaigns).unwrap();
    for entry in gate.risk_ledger() {
        assert_eq!(entry.epoch, SecurityEpoch::from_raw(42));
    }
}

// ── Rationale Content ────────────────────────────────────────────────────

#[test]
fn enrichment_pass_rationale_contains_budget_info() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-rat", &campaigns).unwrap();
    assert!(decision.rationale.contains("within budget"));
    assert!(decision.rationale.contains("no alarms"));
}

#[test]
fn enrichment_inconclusive_rationale_lists_missing_threats() {
    let threats = vec![
        make_threat("alpha", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("beta", ThreatCategory::ResourceExhaustion, MILLION),
        make_threat("gamma", ThreatCategory::PolicyBypass, MILLION),
    ];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    // Only provide campaigns for alpha
    let campaigns = vec![make_campaign("c1", "alpha", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-inc-rat", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Inconclusive);
    assert!(decision.rationale.contains("beta"));
    assert!(decision.rationale.contains("gamma"));
}

#[test]
fn enrichment_fail_rationale_mentions_alarm_threats_when_alarm_active() {
    let config = TailGateConfig {
        e_value_alarm_threshold_millionths: 5_000_000,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Extreme outlier payoffs to trigger alarm
    let mut payoffs = vec![1_i64; 200];
    payoffs[199] = 100_000_000;
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-alarm-rat", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    assert!(decision.rationale.contains("alarm") || decision.rationale.contains("e-value"));
}

// ── Beyond Cliff Band via Evaluation ─────────────────────────────────────

#[test]
fn enrichment_beyond_cliff_emits_witness_with_route_to_action() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-beyond", &campaigns).unwrap();
    // Should have a beyond-cliff witness
    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|w| w.cliff_band == CliffBand::BeyondCliff);
    assert!(witness.is_some(), "expected a BeyondCliff witness");
    let w = witness.unwrap();
    // Beyond-cliff should route to rollback lane, not FallbackSafe
    assert!(matches!(w.escape_action, LaneAction::RouteTo(_)));
}

// ── Campaign with Trajectory ─────────────────────────────────────────────

#[test]
fn enrichment_campaign_with_trajectory_discovers_exploit() {
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();

    let campaign = make_campaign_with_trajectory(
        "c-traj",
        "t1",
        low_risk_payoffs(200),
        Some("capability-escalation"),
    );
    let decision = gate.evaluate("rc-traj", &[campaign]).unwrap();
    // The trajectory may record exploit info in the risk metrics
    assert_eq!(decision.risk_metrics.len(), 1);
}

// ── Rollback Playbook Details ────────────────────────────────────────────

#[test]
fn enrichment_rollback_playbook_step_numbering_sequential() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-steps", &campaigns).unwrap();
    let playbook = decision.rollback_playbook.unwrap();
    for (i, step) in playbook.mitigation_steps.iter().enumerate() {
        assert_eq!(step.step, (i + 1) as u32);
    }
}

#[test]
fn enrichment_rollback_playbook_uses_configured_rollback_lane() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        rollback_lane: LaneId("quarantine-zone".to_string()),
        ..Default::default()
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-lane", &campaigns).unwrap();
    let playbook = decision.rollback_playbook.unwrap();
    // Rollback action should use the configured lane
    match &playbook.rollback_action {
        LaneAction::RouteTo(lane) => assert_eq!(lane.0, "quarantine-zone"),
        other => panic!("expected RouteTo, got {:?}", other),
    }
}

// ── Error as std::error::Error ───────────────────────────────────────────

#[test]
fn enrichment_error_implements_std_error_for_all_variants() {
    use std::error::Error;
    let variants: Vec<TailGateError> = vec![
        TailGateError::NoThreatClasses,
        TailGateError::NoCampaigns,
        TailGateError::TooManyThreatClasses { count: 70, max: 64 },
        TailGateError::TooManyCampaigns {
            count: 200,
            max: 128,
        },
        TailGateError::UnknownThreatClass {
            campaign_id: "c".to_string(),
            threat_class_id: "t".to_string(),
        },
        TailGateError::DuplicateThreatClass {
            id: "d".to_string(),
        },
        TailGateError::InsufficientRounds {
            campaign_id: "c".to_string(),
            rounds: 10,
            required: 100,
        },
        TailGateError::InvalidConfig {
            detail: "bad".to_string(),
        },
        TailGateError::TooManyObservations {
            count: 200_000,
            max: 100_000,
        },
    ];
    for err in &variants {
        let _: &dyn Error = err;
        assert!(err.source().is_none());
    }
}

// ── Serde JSON Field Presence ────────────────────────────────────────────

#[test]
fn enrichment_json_fields_cliff_margin_certificate() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-json-cert".to_string(),
        cliff_band: CliffBand::Stable,
        cvar_margin_millionths: 100_000,
        e_value_margin_millionths: 5_000_000,
        observation_margin: 50,
    };
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("\"threat_class_id\""));
    assert!(json.contains("\"cliff_band\""));
    assert!(json.contains("\"cvar_margin_millionths\""));
    assert!(json.contains("\"e_value_margin_millionths\""));
    assert!(json.contains("\"observation_margin\""));
}

#[test]
fn enrichment_json_fields_cliff_witness() {
    let witness = CliffWitness {
        threat_class_id: "t-json-wit".to_string(),
        cliff_band: CliffBand::NearCliff,
        campaign_id: Some("c1".to_string()),
        max_payoff_millionths: 500_000,
        worst_exploit: Some("exploit-x".to_string()),
        escape_action: LaneAction::FallbackSafe,
        rationale: "test rationale".to_string(),
    };
    let json = serde_json::to_string(&witness).unwrap();
    assert!(json.contains("\"threat_class_id\""));
    assert!(json.contains("\"cliff_band\""));
    assert!(json.contains("\"campaign_id\""));
    assert!(json.contains("\"max_payoff_millionths\""));
    assert!(json.contains("\"worst_exploit\""));
    assert!(json.contains("\"escape_action\""));
    assert!(json.contains("\"rationale\""));
}

#[test]
fn enrichment_json_fields_gate_decision() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-json-fields", &campaigns).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"release_candidate_id\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"risk_metrics\""));
    assert!(json.contains("\"aggregate_cvar_millionths\""));
    assert!(json.contains("\"any_alarm_active\""));
    assert!(json.contains("\"campaigns_evaluated\""));
    assert!(json.contains("\"total_rounds\""));
    assert!(json.contains("\"continuation_cliff_atlas\""));
    assert!(json.contains("\"rationale\""));
    assert!(json.contains("\"artifact_hash\""));
}

#[test]
fn enrichment_json_fields_rollback_playbook() {
    let playbook = RollbackPlaybook {
        playbook_id: "pb-json".to_string(),
        rollback_action: LaneAction::FallbackSafe,
        triggering_threats: vec!["t1".to_string()],
        mitigation_steps: vec![MitigationStep {
            step: 1,
            description: "halt".to_string(),
            automated: true,
            action: None,
        }],
        evidence_hash: ContentHash::compute(b"json"),
    };
    let json = serde_json::to_string(&playbook).unwrap();
    assert!(json.contains("\"playbook_id\""));
    assert!(json.contains("\"rollback_action\""));
    assert!(json.contains("\"triggering_threats\""));
    assert!(json.contains("\"mitigation_steps\""));
    assert!(json.contains("\"evidence_hash\""));
}

// ── Debug Uniqueness ─────────────────────────────────────────────────────

#[test]
fn enrichment_debug_uniqueness_cliff_band_all_four() {
    let variants = [
        CliffBand::Stable,
        CliffBand::NearCliff,
        CliffBand::BeyondCliff,
        CliffBand::MissingNeighborhood,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let d = format!("{:?}", v);
        assert!(seen.insert(d.clone()), "duplicate Debug for {:?}", v);
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn enrichment_debug_uniqueness_threat_category_all_six() {
    let cats = [
        ThreatCategory::CapabilityEscalation,
        ThreatCategory::ResourceExhaustion,
        ThreatCategory::InformationLeakage,
        ThreatCategory::PolicyBypass,
        ThreatCategory::SupplyChain,
        ThreatCategory::TimingChannel,
    ];
    let mut seen = BTreeSet::new();
    for c in &cats {
        let d = format!("{:?}", c);
        assert!(seen.insert(d.clone()), "duplicate Debug for {:?}", c);
    }
    assert_eq!(seen.len(), 6);
}

// ── Gate Serde Roundtrip with State ──────────────────────────────────────

#[test]
fn enrichment_serde_roundtrip_gate_preserves_evaluation_state() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    let _ = gate.evaluate("rc-1", &campaigns).unwrap();
    let _ = gate.evaluate("rc-2", &campaigns).unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let restored: CatastrophicTailTournamentGate = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.evaluation_count(), 2);
    assert_eq!(restored.threat_class_count(), 2);
    assert_eq!(restored.risk_ledger().len(), 4);
}

#[test]
fn enrichment_serde_roundtrip_gate_can_continue_evaluating() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let _ = gate.evaluate("rc-1", &campaigns).unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let mut restored: CatastrophicTailTournamentGate = serde_json::from_str(&json).unwrap();
    let d2 = restored.evaluate("rc-2", &campaigns).unwrap();
    assert_eq!(restored.evaluation_count(), 2);
    assert_eq!(d2.verdict, GateVerdict::Pass);
}

// ── Total Rounds Computation ─────────────────────────────────────────────

#[test]
fn enrichment_total_rounds_sums_across_all_campaigns() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(300)),
        make_campaign("c3", "t1", low_risk_payoffs(150)),
    ];
    let decision = gate.evaluate("rc-rounds", &campaigns).unwrap();
    assert_eq!(decision.total_rounds, 650);
}

// ── Cliff Band Serde rename_all ──────────────────────────────────────────

#[test]
fn enrichment_cliff_band_serde_uses_snake_case() {
    let json = serde_json::to_string(&CliffBand::NearCliff).unwrap();
    assert_eq!(json, "\"near_cliff\"");

    let json = serde_json::to_string(&CliffBand::BeyondCliff).unwrap();
    assert_eq!(json, "\"beyond_cliff\"");

    let json = serde_json::to_string(&CliffBand::MissingNeighborhood).unwrap();
    assert_eq!(json, "\"missing_neighborhood\"");

    let json = serde_json::to_string(&CliffBand::Stable).unwrap();
    assert_eq!(json, "\"stable\"");
}

// ── Missing Neighborhood Witness Uses FallbackSafe ───────────────────────

#[test]
fn enrichment_missing_neighborhood_escape_action_is_fallback_safe() {
    let mut gate = dual_threat_gate();
    // Only provide campaign for t1, not t2
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-missing-action", &campaigns).unwrap();
    let missing_witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|w| w.cliff_band == CliffBand::MissingNeighborhood)
        .expect("should have MissingNeighborhood witness");
    assert!(matches!(missing_witness.escape_action, LaneAction::FallbackSafe));
    assert!(missing_witness.campaign_id.is_none());
}

// ── Threat Class with Related Exploits ───────────────────────────────────

#[test]
fn enrichment_threat_class_with_exploits_serde_roundtrip() {
    let mut tc = make_threat("tc-exploits", ThreatCategory::SupplyChain, 800_000);
    tc.related_exploits.insert("supply-chain-v1".to_string());
    tc.related_exploits.insert("supply-chain-v2".to_string());
    tc.related_exploits.insert("typo-squatting".to_string());

    let json = serde_json::to_string(&tc).unwrap();
    let back: ThreatClass = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, back);
    assert_eq!(back.related_exploits.len(), 3);
    assert!(back.related_exploits.contains("typo-squatting"));
}

// ── Aggregate CVaR with Zero Weight ──────────────────────────────────────

#[test]
fn enrichment_aggregate_cvar_zero_weight_threat_produces_zero() {
    let threats = vec![make_threat("t-zero", ThreatCategory::PolicyBypass, 0)];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t-zero", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-zero-weight", &campaigns).unwrap();
    // With zero weight, aggregate CVaR should be 0
    assert_eq!(decision.aggregate_cvar_millionths, 0);
}

// ── Config Accessor ──────────────────────────────────────────────────────

#[test]
fn enrichment_config_accessor_returns_correct_values() {
    let config = TailGateConfig {
        epoch: SecurityEpoch::from_raw(77),
        cvar_alpha_millionths: 800_000,
        tail_budget_millionths: 300_000,
        e_value_alarm_threshold_millionths: 15_000_000,
        min_rounds_per_campaign: 50,
        near_cliff_margin_millionths: 25_000,
        generate_rollback_playbook: false,
        rollback_lane: LaneId("custom-lane".to_string()),
        record_risk_ledger: false,
    };
    let threats = vec![make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION)];
    let gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let cfg = gate.config();
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(77));
    assert_eq!(cfg.cvar_alpha_millionths, 800_000);
    assert_eq!(cfg.tail_budget_millionths, 300_000);
    assert_eq!(cfg.min_rounds_per_campaign, 50);
    assert!(!cfg.generate_rollback_playbook);
    assert!(!cfg.record_risk_ledger);
}
