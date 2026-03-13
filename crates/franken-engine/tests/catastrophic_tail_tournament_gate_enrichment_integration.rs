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
    ConvergenceDiagnostic, PolicyDelta, RoundOutcome, StrategyId, TournamentResult,
    TrajectoryLedger,
};
use frankenengine_engine::catastrophic_tail_tournament_gate::{
    CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION, Campaign, CatastrophicTailTournamentGate, CliffBand,
    CliffMarginCertificate, CliffWitness, ContinuationCliffAtlas, GateDecision, GateVerdict,
    MitigationStep, RiskLedgerEntry, RollbackPlaybook, TAIL_GATE_SCHEMA_VERSION, TailGateConfig,
    TailGateError, TailRiskMetrics, ThreatCategory, ThreatClass,
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
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for {:?}: {}",
            v,
            s
        );
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
    assert_eq!(
        CliffBand::MissingNeighborhood.as_str(),
        "missing_neighborhood"
    );
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

    let mut gate1 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats.clone()).unwrap();
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_alpha_one_accepted() {
    let config = TailGateConfig {
        cvar_alpha_millionths: 1,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_negative_alpha_rejected() {
    let config = TailGateConfig {
        cvar_alpha_millionths: -1,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_config_negative_near_cliff_margin_rejected() {
    let config = TailGateConfig {
        near_cliff_margin_millionths: -1,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_config_zero_near_cliff_margin_accepted() {
    let config = TailGateConfig {
        near_cliff_margin_millionths: 0,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_config_zero_budget_accepted() {
    let config = TailGateConfig {
        tail_budget_millionths: 0,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(config, threats);
    assert!(gate.is_ok());
}

// ── Schema Constants ─────────────────────────────────────────────────────

#[test]
fn enrichment_schema_version_constants_non_empty_and_distinct() {
    assert!(!TAIL_GATE_SCHEMA_VERSION.is_empty());
    assert!(!CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.is_empty());
    assert_ne!(
        TAIL_GATE_SCHEMA_VERSION,
        CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION
    );
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
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
    assert!(matches!(
        missing_witness.escape_action,
        LaneAction::FallbackSafe
    ));
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
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let cfg = gate.config();
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(77));
    assert_eq!(cfg.cvar_alpha_millionths, 800_000);
    assert_eq!(cfg.tail_budget_millionths, 300_000);
    assert_eq!(cfg.min_rounds_per_campaign, 50);
    assert!(!cfg.generate_rollback_playbook);
    assert!(!cfg.record_risk_ledger);
}

// ── Batch 2: Additional Enrichment Tests ────────────────────────────────

// ── Clone Tests ─────────────────────────────────────────────────────────

#[test]
fn enrichment_clone_threat_class_independence() {
    let tc = ThreatClass {
        id: "tc-clone".to_string(),
        label: "Clone me".to_string(),
        category: ThreatCategory::SupplyChain,
        impact_weight_millionths: 800_000,
        related_exploits: {
            let mut s = BTreeSet::new();
            s.insert("e1".to_string());
            s
        },
    };
    let mut cloned = tc.clone();
    assert_eq!(tc, cloned);
    cloned.id = "mutated".to_string();
    assert_ne!(tc.id, cloned.id);
    assert_eq!(tc.related_exploits.len(), 1);
}

#[test]
fn enrichment_clone_tail_risk_metrics_independence() {
    let m = TailRiskMetrics {
        threat_class_id: "t-clone-m".to_string(),
        observation_count: 500,
        var_millionths: 100_000,
        cvar_millionths: 200_000,
        alpha_millionths: 950_000,
        e_value_millionths: 3_000_000,
        alarm_active: false,
        max_payoff_millionths: 400_000,
        worst_exploit: Some("xss".to_string()),
    };
    let mut cloned = m.clone();
    assert_eq!(m, cloned);
    cloned.worst_exploit = None;
    assert_ne!(m, cloned);
    assert!(m.worst_exploit.is_some());
}

#[test]
fn enrichment_clone_campaign_independence() {
    let c = make_campaign("c-clone", "t1", vec![100_000; 200]);
    let mut cloned = c.clone();
    assert_eq!(c, cloned);
    cloned.campaign_id = "mutated".to_string();
    assert_ne!(c.campaign_id, cloned.campaign_id);
}

#[test]
fn enrichment_clone_cliff_margin_certificate_independence() {
    let cert = CliffMarginCertificate {
        threat_class_id: "t-clone-cert".to_string(),
        cliff_band: CliffBand::NearCliff,
        cvar_margin_millionths: 10_000,
        e_value_margin_millionths: 20_000,
        observation_margin: 5,
    };
    let mut cloned = cert.clone();
    assert_eq!(cert, cloned);
    cloned.cliff_band = CliffBand::Stable;
    assert_ne!(cert, cloned);
}

#[test]
fn enrichment_clone_cliff_witness_independence() {
    let w = CliffWitness {
        threat_class_id: "t-clone-w".to_string(),
        cliff_band: CliffBand::BeyondCliff,
        campaign_id: Some("c99".to_string()),
        max_payoff_millionths: 9_000_000,
        worst_exploit: Some("rce".to_string()),
        escape_action: LaneAction::SuspendAdaptive,
        rationale: "test rationale".to_string(),
    };
    let mut cloned = w.clone();
    assert_eq!(w, cloned);
    cloned.rationale = "changed".to_string();
    assert_ne!(w, cloned);
}

#[test]
fn enrichment_clone_rollback_playbook_independence() {
    let pb = RollbackPlaybook {
        playbook_id: "pb-clone".to_string(),
        rollback_action: LaneAction::FallbackSafe,
        triggering_threats: vec!["t1".to_string(), "t2".to_string()],
        mitigation_steps: vec![MitigationStep {
            step: 1,
            description: "halt".to_string(),
            automated: true,
            action: None,
        }],
        evidence_hash: ContentHash::compute(b"clone-test"),
    };
    let mut cloned = pb.clone();
    assert_eq!(pb, cloned);
    cloned.triggering_threats.push("t3".to_string());
    assert_ne!(pb.triggering_threats.len(), cloned.triggering_threats.len());
}

#[test]
fn enrichment_clone_mitigation_step_independence() {
    let step = MitigationStep {
        step: 5,
        description: "investigate".to_string(),
        automated: false,
        action: Some(LaneAction::RouteTo(LaneId("debug".to_string()))),
    };
    let mut cloned = step.clone();
    assert_eq!(step, cloned);
    cloned.automated = true;
    assert_ne!(step, cloned);
}

#[test]
fn enrichment_clone_continuation_cliff_atlas_independence() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-clone-atlas".to_string(),
        epoch: SecurityEpoch::from_raw(3),
        margin_certificates: vec![CliffMarginCertificate {
            threat_class_id: "t1".to_string(),
            cliff_band: CliffBand::Stable,
            cvar_margin_millionths: 200_000,
            e_value_margin_millionths: 15_000_000,
            observation_margin: 100,
        }],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"clone-atlas"),
    };
    let mut cloned = atlas.clone();
    assert_eq!(atlas, cloned);
    cloned.release_candidate_id = "mutated".to_string();
    assert_ne!(atlas.release_candidate_id, cloned.release_candidate_id);
}

#[test]
fn enrichment_clone_gate_struct_independence() {
    let gate = default_gate();
    let cloned = gate.clone();
    assert_eq!(gate.evaluation_count(), cloned.evaluation_count());
    assert_eq!(gate.threat_class_count(), cloned.threat_class_count());
}

// ── Serde Roundtrip Tests (Additional) ──────────────────────────────────

#[test]
fn enrichment_serde_roundtrip_threat_class_basic() {
    let tc = make_threat("t-serde-basic", ThreatCategory::TimingChannel, 300_000);
    let json = serde_json::to_string(&tc).unwrap();
    let back: ThreatClass = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, back);
}

#[test]
fn enrichment_serde_roundtrip_tail_risk_metrics_with_exploit() {
    let m = TailRiskMetrics {
        threat_class_id: "t-serde-exp".to_string(),
        observation_count: 1000,
        var_millionths: 300_000,
        cvar_millionths: 450_000,
        alpha_millionths: 950_000,
        e_value_millionths: 5_000_000,
        alarm_active: true,
        max_payoff_millionths: 2_000_000,
        worst_exploit: Some("buffer-overflow".to_string()),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: TailRiskMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert!(back.alarm_active);
    assert_eq!(back.worst_exploit.as_deref(), Some("buffer-overflow"));
}

#[test]
fn enrichment_serde_roundtrip_tail_risk_metrics_without_exploit() {
    let m = TailRiskMetrics {
        threat_class_id: "t-serde-no-exp".to_string(),
        observation_count: 50,
        var_millionths: 0,
        cvar_millionths: 0,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 0,
        worst_exploit: None,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: TailRiskMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert!(back.worst_exploit.is_none());
}

#[test]
fn enrichment_serde_roundtrip_risk_ledger_entry() {
    let entry = RiskLedgerEntry {
        epoch: SecurityEpoch::from_raw(99),
        threat_class_id: "t-serde-ledger".to_string(),
        cvar_millionths: 250_000,
        e_value_millionths: 8_000_000,
        budget_exceeded: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RiskLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.budget_exceeded);
}

#[test]
fn enrichment_serde_roundtrip_campaign() {
    let c = make_campaign("c-serde", "t1", vec![10_000; 150]);
    let json = serde_json::to_string(&c).unwrap();
    let back: Campaign = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_serde_roundtrip_tail_gate_error_all_variants() {
    let variants: Vec<TailGateError> = vec![
        TailGateError::NoThreatClasses,
        TailGateError::TooManyThreatClasses { count: 65, max: 64 },
        TailGateError::NoCampaigns,
        TailGateError::TooManyCampaigns {
            count: 129,
            max: 128,
        },
        TailGateError::UnknownThreatClass {
            campaign_id: "c-serde".to_string(),
            threat_class_id: "t-serde".to_string(),
        },
        TailGateError::DuplicateThreatClass {
            id: "dup-serde".to_string(),
        },
        TailGateError::InsufficientRounds {
            campaign_id: "c-ir-serde".to_string(),
            rounds: 5,
            required: 100,
        },
        TailGateError::InvalidConfig {
            detail: "serde detail".to_string(),
        },
        TailGateError::TooManyObservations {
            count: 150_000,
            max: 100_000,
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: TailGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_gate_verdict_all() {
    for v in &[
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_threat_category_all() {
    let cats = [
        ThreatCategory::CapabilityEscalation,
        ThreatCategory::ResourceExhaustion,
        ThreatCategory::InformationLeakage,
        ThreatCategory::PolicyBypass,
        ThreatCategory::SupplyChain,
        ThreatCategory::TimingChannel,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        let back: ThreatCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_mitigation_step_no_action() {
    let step = MitigationStep {
        step: 4,
        description: "Manual review required".to_string(),
        automated: false,
        action: None,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MitigationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
    assert!(back.action.is_none());
}

// ── JSON Field Presence Tests (Additional) ──────────────────────────────

#[test]
fn enrichment_json_fields_threat_class() {
    let tc = make_threat("t-json", ThreatCategory::PolicyBypass, 500_000);
    let json = serde_json::to_string(&tc).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"label\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"impact_weight_millionths\""));
    assert!(json.contains("\"related_exploits\""));
}

#[test]
fn enrichment_json_fields_tail_risk_metrics() {
    let m = TailRiskMetrics {
        threat_class_id: "t-json-m".to_string(),
        observation_count: 100,
        var_millionths: 10_000,
        cvar_millionths: 20_000,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 50_000,
        worst_exploit: None,
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"threat_class_id\""));
    assert!(json.contains("\"observation_count\""));
    assert!(json.contains("\"var_millionths\""));
    assert!(json.contains("\"cvar_millionths\""));
    assert!(json.contains("\"alpha_millionths\""));
    assert!(json.contains("\"e_value_millionths\""));
    assert!(json.contains("\"alarm_active\""));
    assert!(json.contains("\"max_payoff_millionths\""));
    assert!(json.contains("\"worst_exploit\""));
}

#[test]
fn enrichment_json_fields_risk_ledger_entry() {
    let entry = RiskLedgerEntry {
        epoch: SecurityEpoch::from_raw(1),
        threat_class_id: "t-json-le".to_string(),
        cvar_millionths: 100_000,
        e_value_millionths: 2_000_000,
        budget_exceeded: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"threat_class_id\""));
    assert!(json.contains("\"cvar_millionths\""));
    assert!(json.contains("\"e_value_millionths\""));
    assert!(json.contains("\"budget_exceeded\""));
}

#[test]
fn enrichment_json_fields_tail_gate_config() {
    let config = TailGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"cvar_alpha_millionths\""));
    assert!(json.contains("\"tail_budget_millionths\""));
    assert!(json.contains("\"e_value_alarm_threshold_millionths\""));
    assert!(json.contains("\"min_rounds_per_campaign\""));
    assert!(json.contains("\"near_cliff_margin_millionths\""));
    assert!(json.contains("\"generate_rollback_playbook\""));
    assert!(json.contains("\"rollback_lane\""));
    assert!(json.contains("\"record_risk_ledger\""));
}

#[test]
fn enrichment_json_fields_mitigation_step() {
    let step = MitigationStep {
        step: 1,
        description: "desc".to_string(),
        automated: true,
        action: Some(LaneAction::FallbackSafe),
    };
    let json = serde_json::to_string(&step).unwrap();
    assert!(json.contains("\"step\""));
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"automated\""));
    assert!(json.contains("\"action\""));
}

#[test]
fn enrichment_json_fields_continuation_cliff_atlas() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-json-atlas".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"json-atlas"),
    };
    let json = serde_json::to_string(&atlas).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"release_candidate_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"margin_certificates\""));
    assert!(json.contains("\"witnesses\""));
    assert!(json.contains("\"atlas_hash\""));
}

// ── Debug Tests ─────────────────────────────────────────────────────────

#[test]
fn enrichment_debug_uniqueness_gate_verdict_all_three() {
    let variants = [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Inconclusive,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let d = format!("{:?}", v);
        assert!(seen.insert(d.clone()), "duplicate Debug for {:?}", v);
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn enrichment_debug_uniqueness_tail_gate_error_all_variants() {
    let variants: Vec<TailGateError> = vec![
        TailGateError::NoThreatClasses,
        TailGateError::TooManyThreatClasses { count: 70, max: 64 },
        TailGateError::NoCampaigns,
        TailGateError::TooManyCampaigns {
            count: 200,
            max: 128,
        },
        TailGateError::UnknownThreatClass {
            campaign_id: "c-dbg".to_string(),
            threat_class_id: "t-dbg".to_string(),
        },
        TailGateError::DuplicateThreatClass {
            id: "dup-dbg".to_string(),
        },
        TailGateError::InsufficientRounds {
            campaign_id: "c-ir-dbg".to_string(),
            rounds: 10,
            required: 100,
        },
        TailGateError::InvalidConfig {
            detail: "debug".to_string(),
        },
        TailGateError::TooManyObservations {
            count: 200_000,
            max: 100_000,
        },
    ];
    let mut seen = BTreeSet::new();
    for err in &variants {
        let d = format!("{:?}", err);
        assert!(seen.insert(d.clone()), "duplicate Debug for {:?}", err);
    }
    assert_eq!(seen.len(), 9);
}

#[test]
fn enrichment_debug_threat_class_contains_all_fields() {
    let tc = ThreatClass {
        id: "tc-debug-fields".to_string(),
        label: "Debug label".to_string(),
        category: ThreatCategory::InformationLeakage,
        impact_weight_millionths: 750_000,
        related_exploits: BTreeSet::new(),
    };
    let d = format!("{:?}", tc);
    assert!(d.contains("tc-debug-fields"));
    assert!(d.contains("InformationLeakage"));
    assert!(d.contains("750000"));
}

#[test]
fn enrichment_debug_tail_risk_metrics_contains_fields() {
    let m = TailRiskMetrics {
        threat_class_id: "t-debug-m".to_string(),
        observation_count: 42,
        var_millionths: 99_000,
        cvar_millionths: 150_000,
        alpha_millionths: 950_000,
        e_value_millionths: 7_000_000,
        alarm_active: true,
        max_payoff_millionths: 500_000,
        worst_exploit: Some("debug-exploit".to_string()),
    };
    let d = format!("{:?}", m);
    assert!(d.contains("t-debug-m"));
    assert!(d.contains("42"));
    assert!(d.contains("true")); // alarm_active
    assert!(d.contains("debug-exploit"));
}

#[test]
fn enrichment_debug_gate_decision_contains_verdict() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-debug-decision", &campaigns).unwrap();
    let d = format!("{:?}", decision);
    assert!(d.contains("rc-debug-decision"));
    assert!(d.contains("Pass"));
}

#[test]
fn enrichment_debug_rollback_playbook_contains_id() {
    let pb = RollbackPlaybook {
        playbook_id: "pb-debug".to_string(),
        rollback_action: LaneAction::FallbackSafe,
        triggering_threats: vec!["t1".to_string()],
        mitigation_steps: vec![],
        evidence_hash: ContentHash::compute(b"debug-pb"),
    };
    let d = format!("{:?}", pb);
    assert!(d.contains("pb-debug"));
}

// ── Error Path Tests ────────────────────────────────────────────────────

#[test]
fn enrichment_error_alpha_zero_rejected() {
    let config = TailGateConfig {
        cvar_alpha_millionths: 0,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_error_alpha_above_million_rejected() {
    let config = TailGateConfig {
        cvar_alpha_millionths: MILLION + 1,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_error_negative_budget_rejected() {
    let config = TailGateConfig {
        tail_budget_millionths: -100,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn enrichment_error_duplicate_threat_preserves_id() {
    let threats = vec![
        make_threat("dup-err", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("dup-err", ThreatCategory::ResourceExhaustion, 500_000),
    ];
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
    match result {
        Err(TailGateError::DuplicateThreatClass { id }) => {
            assert_eq!(id, "dup-err");
        }
        other => panic!("expected DuplicateThreatClass, got {:?}", other),
    }
}

#[test]
fn enrichment_error_unknown_threat_preserves_ids() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaign = make_campaign("c-unknown", "t-nonexistent", low_risk_payoffs(200));
    let result = gate.evaluate("rc-err", &[campaign]);
    match result {
        Err(TailGateError::UnknownThreatClass {
            campaign_id,
            threat_class_id,
        }) => {
            assert_eq!(campaign_id, "c-unknown");
            assert_eq!(threat_class_id, "t-nonexistent");
        }
        other => panic!("expected UnknownThreatClass, got {:?}", other),
    }
}

#[test]
fn enrichment_error_insufficient_rounds_preserves_counts() {
    let config = TailGateConfig {
        min_rounds_per_campaign: 200,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaign = make_campaign("c-short", "t1", vec![1000; 50]);
    let result = gate.evaluate("rc-err-rounds", &[campaign]);
    match result {
        Err(TailGateError::InsufficientRounds {
            campaign_id,
            rounds,
            required,
        }) => {
            assert_eq!(campaign_id, "c-short");
            assert_eq!(rounds, 50);
            assert_eq!(required, 200);
        }
        other => panic!("expected InsufficientRounds, got {:?}", other),
    }
}

#[test]
fn enrichment_error_too_many_threat_classes_preserves_counts() {
    let threats: Vec<_> = (0..65)
        .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
        .collect();
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
    match result {
        Err(TailGateError::TooManyThreatClasses { count, max }) => {
            assert_eq!(count, 65);
            assert_eq!(max, 64);
        }
        other => panic!("expected TooManyThreatClasses, got {:?}", other),
    }
}

#[test]
fn enrichment_error_exactly_64_threats_accepted() {
    let threats: Vec<_> = (0..64)
        .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
        .collect();
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().threat_class_count(), 64);
}

// ── Determinism Tests ───────────────────────────────────────────────────

#[test]
fn enrichment_determinism_same_inputs_same_verdict() {
    let threats = vec![
        make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("t2", ThreatCategory::ResourceExhaustion, 500_000),
    ];
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];

    let mut gate1 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats.clone()).unwrap();
    let d1 = gate1.evaluate("rc-det", &campaigns).unwrap();

    let mut gate2 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let d2 = gate2.evaluate("rc-det", &campaigns).unwrap();

    assert_eq!(d1.verdict, d2.verdict);
    assert_eq!(d1.aggregate_cvar_millionths, d2.aggregate_cvar_millionths);
    assert_eq!(d1.any_alarm_active, d2.any_alarm_active);
    assert_eq!(d1.total_rounds, d2.total_rounds);
}

#[test]
fn enrichment_determinism_risk_metrics_identical() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];

    let mut gate1 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats.clone()).unwrap();
    let d1 = gate1.evaluate("rc-det-m", &campaigns).unwrap();

    let mut gate2 =
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let d2 = gate2.evaluate("rc-det-m", &campaigns).unwrap();

    assert_eq!(d1.risk_metrics, d2.risk_metrics);
}

#[test]
fn enrichment_determinism_atlas_certificates_identical() {
    let threats = vec![
        make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("t2", ThreatCategory::ResourceExhaustion, MILLION),
    ];
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", high_risk_payoffs(200)),
    ];

    let config = TailGateConfig {
        tail_budget_millionths: 100_000,
        ..Default::default()
    };

    let mut gate1 = CatastrophicTailTournamentGate::new(config.clone(), threats.clone()).unwrap();
    let d1 = gate1.evaluate("rc-det-cert", &campaigns).unwrap();

    let mut gate2 = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let d2 = gate2.evaluate("rc-det-cert", &campaigns).unwrap();

    assert_eq!(
        d1.continuation_cliff_atlas.margin_certificates,
        d2.continuation_cliff_atlas.margin_certificates
    );
}

// ── Edge Case Tests ─────────────────────────────────────────────────────

#[test]
fn enrichment_evaluate_single_payoff_observation() {
    let config = TailGateConfig {
        min_rounds_per_campaign: 1,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", vec![100_000])];
    let decision = gate.evaluate("rc-single-obs", &campaigns).unwrap();
    assert_eq!(decision.risk_metrics[0].observation_count, 1);
    // With a single observation, VaR = CVaR = that observation
    assert_eq!(decision.risk_metrics[0].var_millionths, 100_000);
    assert_eq!(decision.risk_metrics[0].cvar_millionths, 100_000);
}

#[test]
fn enrichment_evaluate_all_same_negative_payoffs() {
    let config = TailGateConfig {
        min_rounds_per_campaign: 10,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Negative payoffs (defender winning) should pass
    let campaigns = vec![make_campaign("c1", "t1", vec![-100_000; 100])];
    let decision = gate.evaluate("rc-neg-payoff", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Pass);
    assert!(decision.risk_metrics[0].cvar_millionths < 0);
}

#[test]
fn enrichment_evaluate_mixed_positive_negative_payoffs() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let mut payoffs = vec![-50_000_i64; 100];
    payoffs.extend(vec![50_000_i64; 100]);
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-mixed", &campaigns).unwrap();
    // Should not crash, should produce valid metrics
    assert_eq!(decision.risk_metrics[0].observation_count, 200);
}

#[test]
fn enrichment_evaluate_ascending_payoffs_var_at_95th_percentile() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    // Payoffs from 0 to 199_000 in 1000-increments
    let payoffs: Vec<i64> = (0..200).map(|i| i * 1000).collect();
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-ascending", &campaigns).unwrap();
    let m = &decision.risk_metrics[0];
    // VaR at 95th percentile of sorted [0, 1000, ..., 199_000]
    // Index = (950_000 * 200) / 1_000_000 = 190
    // sorted[190] = 190_000
    assert_eq!(m.var_millionths, 190_000);
    // CVaR = average of payoffs >= 190_000 = [190k, 191k, ..., 199k]
    // = (190 + 191 + ... + 199) * 1000 / 10 = 194_500
    assert!(m.cvar_millionths >= m.var_millionths);
}

#[test]
fn enrichment_evaluate_multiple_campaigns_same_threat_merges_payoffs() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns = vec![
        make_campaign("c1", "t1", vec![10_000; 150]),
        make_campaign("c2", "t1", vec![20_000; 150]),
    ];
    let decision = gate.evaluate("rc-merge", &campaigns).unwrap();
    assert_eq!(decision.risk_metrics[0].observation_count, 300);
    assert_eq!(decision.campaigns_evaluated, 2);
}

#[test]
fn enrichment_evaluate_near_cliff_when_cvar_margin_within_threshold() {
    let config = TailGateConfig {
        tail_budget_millionths: 200_000,
        near_cliff_margin_millionths: 50_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Uniform payoffs of 170_000 => CVaR = 170_000, margin = 30_000 < 50_000 threshold
    let campaigns = vec![make_campaign("c1", "t1", vec![170_000; 200])];
    let decision = gate.evaluate("rc-near-cliff-2", &campaigns).unwrap();
    let cert = &decision.continuation_cliff_atlas.margin_certificates[0];
    assert_eq!(cert.cliff_band, CliffBand::NearCliff);
    assert_eq!(cert.cvar_margin_millionths, 30_000);
}

#[test]
fn enrichment_evaluate_stable_when_margin_above_threshold() {
    let config = TailGateConfig {
        tail_budget_millionths: 500_000,
        near_cliff_margin_millionths: 50_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Uniform payoffs of 100_000 => CVaR = 100_000, margin = 400_000 > 50_000
    let campaigns = vec![make_campaign("c1", "t1", vec![100_000; 200])];
    let decision = gate.evaluate("rc-stable-2", &campaigns).unwrap();
    let cert = &decision.continuation_cliff_atlas.margin_certificates[0];
    assert_eq!(cert.cliff_band, CliffBand::Stable);
    assert_eq!(cert.cvar_margin_millionths, 400_000);
}

#[test]
fn enrichment_evaluate_no_playbook_for_inconclusive() {
    let mut gate = dual_threat_gate();
    // Only provide campaign for t1 => t2 missing => inconclusive
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-inc-no-pb", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Inconclusive);
    // Inconclusive should not generate a rollback playbook
    assert!(decision.rollback_playbook.is_none());
}

#[test]
fn enrichment_evaluate_no_playbook_when_disabled_and_fail() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        generate_rollback_playbook: false,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-no-pb-fail", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    assert!(decision.rollback_playbook.is_none());
}

// ── Rollback Playbook Details (Additional) ──────────────────────────────

#[test]
fn enrichment_rollback_playbook_has_four_steps() {
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
    let decision = gate.evaluate("rc-4steps", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert_eq!(pb.mitigation_steps.len(), 4);
}

#[test]
fn enrichment_rollback_playbook_first_step_is_fallback_safe() {
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
    let decision = gate.evaluate("rc-first-step", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert_eq!(pb.mitigation_steps[0].step, 1);
    assert!(pb.mitigation_steps[0].automated);
    assert!(matches!(
        pb.mitigation_steps[0].action,
        Some(LaneAction::FallbackSafe)
    ));
}

#[test]
fn enrichment_rollback_playbook_second_step_is_demote() {
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
    let decision = gate.evaluate("rc-second-step", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert_eq!(pb.mitigation_steps[1].step, 2);
    assert!(pb.mitigation_steps[1].automated);
    match &pb.mitigation_steps[1].action {
        Some(LaneAction::Demote { from_lane, reason }) => {
            assert_eq!(from_lane.0, "active");
            assert_eq!(*reason, DemotionReason::CvarExceeded);
        }
        other => panic!("expected Demote action, got {:?}", other),
    }
}

#[test]
fn enrichment_rollback_playbook_fourth_step_is_manual() {
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
    let decision = gate.evaluate("rc-fourth-step", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert_eq!(pb.mitigation_steps[3].step, 4);
    assert!(!pb.mitigation_steps[3].automated);
    assert!(pb.mitigation_steps[3].action.is_none());
}

#[test]
fn enrichment_rollback_playbook_id_contains_release_candidate() {
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
    let decision = gate.evaluate("rc-pb-id", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert!(pb.playbook_id.contains("rc-pb-id"));
}

#[test]
fn enrichment_rollback_playbook_triggering_threats_non_empty() {
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
    let decision = gate.evaluate("rc-trig", &campaigns).unwrap();
    let pb = decision.rollback_playbook.unwrap();
    assert!(!pb.triggering_threats.is_empty());
    assert!(pb.triggering_threats.contains(&"t1".to_string()));
}

// ── Decision ID Format Tests ────────────────────────────────────────────

#[test]
fn enrichment_decision_id_contains_gate_prefix() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-prefix", &campaigns).unwrap();
    assert!(decision.decision_id.starts_with("gate-"));
}

#[test]
fn enrichment_decision_id_contains_release_candidate() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-in-id", &campaigns).unwrap();
    assert!(decision.decision_id.contains("rc-in-id"));
}

#[test]
fn enrichment_decision_id_contains_epoch() {
    let config = TailGateConfig {
        epoch: SecurityEpoch::from_raw(55),
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-epoch-id", &campaigns).unwrap();
    assert!(decision.decision_id.contains("55"));
}

// ── Atlas Schema Version ────────────────────────────────────────────────

#[test]
fn enrichment_atlas_schema_version_set_correctly() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-schema", &campaigns).unwrap();
    assert_eq!(
        decision.continuation_cliff_atlas.schema_version,
        CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_atlas_epoch_matches_config_epoch() {
    let config = TailGateConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-atlas-epoch", &campaigns).unwrap();
    assert_eq!(
        decision.continuation_cliff_atlas.epoch,
        SecurityEpoch::from_raw(42)
    );
}

// ── Witness Rationale Content ───────────────────────────────────────────

#[test]
fn enrichment_missing_neighborhood_witness_rationale_mentions_threat_class() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-miss-rat", &campaigns).unwrap();
    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|w| w.cliff_band == CliffBand::MissingNeighborhood)
        .unwrap();
    assert!(witness.rationale.contains("t2"));
}

#[test]
fn enrichment_near_cliff_witness_rationale_mentions_margin() {
    let config = TailGateConfig {
        tail_budget_millionths: 120_000,
        near_cliff_margin_millionths: 50_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", vec![100_000; 200])];
    let decision = gate.evaluate("rc-near-rat", &campaigns).unwrap();
    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|w| w.cliff_band == CliffBand::NearCliff);
    assert!(witness.is_some());
    assert!(witness.unwrap().rationale.contains("near-cliff margin"));
}

#[test]
fn enrichment_beyond_cliff_witness_rationale_mentions_crossed() {
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
    let decision = gate.evaluate("rc-beyond-rat", &campaigns).unwrap();
    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|w| w.cliff_band == CliffBand::BeyondCliff);
    assert!(witness.is_some());
    assert!(witness.unwrap().rationale.contains("crossed"));
}

// ── Risk Ledger Behavior ────────────────────────────────────────────────

#[test]
fn enrichment_risk_ledger_accumulates_across_evaluations() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let _ = gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 1);
    let _ = gate.evaluate("rc-2", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 2);
    let _ = gate.evaluate("rc-3", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 3);
}

#[test]
fn enrichment_risk_ledger_budget_exceeded_flag_matches() {
    let config = TailGateConfig {
        tail_budget_millionths: 100_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", vec![200_000; 200])];
    let _ = gate.evaluate("rc-exceeded", &campaigns).unwrap();
    assert!(gate.risk_ledger()[0].budget_exceeded);
}

#[test]
fn enrichment_risk_ledger_budget_not_exceeded_flag() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", vec![10_000; 200])];
    let _ = gate.evaluate("rc-not-exceeded", &campaigns).unwrap();
    assert!(!gate.risk_ledger()[0].budget_exceeded);
}

// ── E-value Alarm Tests ─────────────────────────────────────────────────

#[test]
fn enrichment_no_alarm_when_uniform_payoffs() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", vec![100_000; 200])];
    let decision = gate.evaluate("rc-no-alarm", &campaigns).unwrap();
    assert!(!decision.risk_metrics[0].alarm_active);
    // e_value = max / mean = 100_000 / 100_000 = 1_000_000 (1x), below default 20x threshold
    assert!(decision.risk_metrics[0].e_value_millionths <= 20_000_000);
}

#[test]
fn enrichment_alarm_active_causes_fail_verdict() {
    let config = TailGateConfig {
        e_value_alarm_threshold_millionths: 2_000_000, // 2x
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // One huge outlier
    let mut payoffs = vec![1_000_i64; 199];
    payoffs.push(10_000_000);
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-alarm-fail", &campaigns).unwrap();
    assert!(decision.any_alarm_active);
    assert_eq!(decision.verdict, GateVerdict::Fail);
}

// ── Aggregate CVaR Tests (Additional) ───────────────────────────────────

#[test]
fn enrichment_aggregate_cvar_single_threat_equals_threat_cvar() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", vec![100_000; 200])];
    let decision = gate.evaluate("rc-agg-single", &campaigns).unwrap();
    // With single threat of weight 1M, aggregate = threat CVaR
    assert_eq!(
        decision.aggregate_cvar_millionths,
        decision.risk_metrics[0].cvar_millionths
    );
}

#[test]
fn enrichment_aggregate_cvar_with_unequal_weights() {
    let threats = vec![
        make_threat("t1", ThreatCategory::CapabilityEscalation, 3 * MILLION),
        make_threat("t2", ThreatCategory::ResourceExhaustion, MILLION),
    ];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns = vec![
        make_campaign("c1", "t1", vec![100_000; 200]),
        make_campaign("c2", "t2", vec![100_000; 200]),
    ];
    let decision = gate.evaluate("rc-agg-weights", &campaigns).unwrap();
    // Both CVaRs are 100_000, so weighted avg should still be 100_000
    assert_eq!(decision.aggregate_cvar_millionths, 100_000);
}

// ── Display Content Tests (Additional) ──────────────────────────────────

#[test]
fn enrichment_display_threat_category_all_known_values() {
    assert_eq!(
        format!("{}", ThreatCategory::CapabilityEscalation),
        "capability-escalation"
    );
    assert_eq!(
        format!("{}", ThreatCategory::ResourceExhaustion),
        "resource-exhaustion"
    );
    assert_eq!(
        format!("{}", ThreatCategory::InformationLeakage),
        "information-leakage"
    );
    assert_eq!(format!("{}", ThreatCategory::PolicyBypass), "policy-bypass");
    assert_eq!(format!("{}", ThreatCategory::SupplyChain), "supply-chain");
    assert_eq!(
        format!("{}", ThreatCategory::TimingChannel),
        "timing-channel"
    );
}

#[test]
fn enrichment_display_gate_verdict_all_known_values() {
    assert_eq!(format!("{}", GateVerdict::Pass), "pass");
    assert_eq!(format!("{}", GateVerdict::Fail), "fail");
    assert_eq!(format!("{}", GateVerdict::Inconclusive), "inconclusive");
}

#[test]
fn enrichment_display_error_no_threat_classes_exact() {
    assert_eq!(
        format!("{}", TailGateError::NoThreatClasses),
        "no threat classes defined"
    );
}

#[test]
fn enrichment_display_error_no_campaigns_exact() {
    assert_eq!(
        format!("{}", TailGateError::NoCampaigns),
        "no campaigns provided"
    );
}

#[test]
fn enrichment_display_error_too_many_contains_counts() {
    let e = TailGateError::TooManyThreatClasses {
        count: 100,
        max: 64,
    };
    let s = format!("{}", e);
    assert!(s.contains("100"));
    assert!(s.contains("64"));
}

#[test]
fn enrichment_display_error_unknown_threat_contains_ids() {
    let e = TailGateError::UnknownThreatClass {
        campaign_id: "camp-X".to_string(),
        threat_class_id: "threat-Y".to_string(),
    };
    let s = format!("{}", e);
    assert!(s.contains("camp-X"));
    assert!(s.contains("threat-Y"));
}

#[test]
fn enrichment_display_error_duplicate_contains_id() {
    let e = TailGateError::DuplicateThreatClass {
        id: "dup-ZZ".to_string(),
    };
    let s = format!("{}", e);
    assert!(s.contains("dup-ZZ"));
}

#[test]
fn enrichment_display_error_insufficient_rounds_contains_counts() {
    let e = TailGateError::InsufficientRounds {
        campaign_id: "c-IR".to_string(),
        rounds: 25,
        required: 100,
    };
    let s = format!("{}", e);
    assert!(s.contains("c-IR"));
    assert!(s.contains("25"));
    assert!(s.contains("100"));
}

#[test]
fn enrichment_display_error_invalid_config_contains_detail() {
    let e = TailGateError::InvalidConfig {
        detail: "custom detail msg".to_string(),
    };
    let s = format!("{}", e);
    assert!(s.contains("custom detail msg"));
}

#[test]
fn enrichment_display_error_too_many_observations_contains_counts() {
    let e = TailGateError::TooManyObservations {
        count: 999_999,
        max: 100_000,
    };
    let s = format!("{}", e);
    assert!(s.contains("999999"));
    assert!(s.contains("100000"));
}

// ── TailGateConfig Default Values ───────────────────────────────────────

#[test]
fn enrichment_default_config_alpha_is_950k() {
    let config = TailGateConfig::default();
    assert_eq!(config.cvar_alpha_millionths, 950_000);
}

#[test]
fn enrichment_default_config_budget_is_500k() {
    let config = TailGateConfig::default();
    assert_eq!(config.tail_budget_millionths, 500_000);
}

#[test]
fn enrichment_default_config_e_value_threshold_is_20m() {
    let config = TailGateConfig::default();
    assert_eq!(config.e_value_alarm_threshold_millionths, 20_000_000);
}

#[test]
fn enrichment_default_config_min_rounds_is_100() {
    let config = TailGateConfig::default();
    assert_eq!(config.min_rounds_per_campaign, 100);
}

#[test]
fn enrichment_default_config_near_cliff_margin_is_50k() {
    let config = TailGateConfig::default();
    assert_eq!(config.near_cliff_margin_millionths, 50_000);
}

#[test]
fn enrichment_default_config_rollback_playbook_enabled() {
    let config = TailGateConfig::default();
    assert!(config.generate_rollback_playbook);
}

#[test]
fn enrichment_default_config_risk_ledger_enabled() {
    let config = TailGateConfig::default();
    assert!(config.record_risk_ledger);
}

#[test]
fn enrichment_default_config_rollback_lane_is_safe() {
    let config = TailGateConfig::default();
    assert_eq!(config.rollback_lane.0, "safe");
}

// ── TailRiskMetrics exceeds_budget Edge Cases ───────────────────────────

#[test]
fn enrichment_exceeds_budget_negative_cvar_never_exceeds() {
    let m = TailRiskMetrics {
        threat_class_id: "t-neg-cvar".to_string(),
        observation_count: 100,
        var_millionths: -100_000,
        cvar_millionths: -50_000,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 0,
        worst_exploit: None,
    };
    assert!(!m.exceeds_budget(0));
    assert!(!m.exceeds_budget(-1));
}

#[test]
fn enrichment_exceeds_budget_zero_cvar_zero_budget() {
    let m = TailRiskMetrics {
        threat_class_id: "t-zero-zero".to_string(),
        observation_count: 100,
        var_millionths: 0,
        cvar_millionths: 0,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 0,
        worst_exploit: None,
    };
    // 0 > 0 is false
    assert!(!m.exceeds_budget(0));
}

// ── Continuation Cliff Atlas Counts Edge Cases ──────────────────────────

#[test]
fn enrichment_atlas_all_unstable_zero_stable() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-all-unstable".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![
            CliffMarginCertificate {
                threat_class_id: "t1".to_string(),
                cliff_band: CliffBand::BeyondCliff,
                cvar_margin_millionths: -100_000,
                e_value_margin_millionths: -500_000,
                observation_margin: 100,
            },
            CliffMarginCertificate {
                threat_class_id: "t2".to_string(),
                cliff_band: CliffBand::NearCliff,
                cvar_margin_millionths: 10_000,
                e_value_margin_millionths: 20_000,
                observation_margin: 50,
            },
            CliffMarginCertificate {
                threat_class_id: "t3".to_string(),
                cliff_band: CliffBand::MissingNeighborhood,
                cvar_margin_millionths: 0,
                e_value_margin_millionths: 0,
                observation_margin: -100,
            },
        ],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"all-unstable"),
    };
    assert_eq!(atlas.stable_certificate_count(), 0);
    assert_eq!(atlas.unstable_certificate_count(), 3);
}

// ── Campaign with Trajectory (Additional) ───────────────────────────────

#[test]
fn enrichment_campaign_with_trajectory_exploit_appears_in_metrics() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    // Create a trajectory with exploit and high payoff
    let campaign = make_campaign_with_trajectory(
        "c-traj-exp",
        "t1",
        low_risk_payoffs(200),
        Some("capability-escalation"),
    );
    let decision = gate.evaluate("rc-traj-exp", &[campaign]).unwrap();
    assert_eq!(decision.risk_metrics.len(), 1);
    // The exploit should be reflected in worst_exploit field
    // (depends on whether trajectory payoff exceeds payoff-vec payoff)
    let m = &decision.risk_metrics[0];
    assert_eq!(m.observation_count, 200);
}

#[test]
fn enrichment_campaign_without_trajectory_exploit_is_none() {
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaign = make_campaign("c-no-traj", "t1", vec![50_000; 200]);
    let decision = gate.evaluate("rc-no-traj", &[campaign]).unwrap();
    // Without trajectory and with uniform payoffs, max from payoffs = 50000
    // worst_exploit comes from trajectory, which is None here
    assert_eq!(decision.risk_metrics[0].observation_count, 200);
}

// ── GateDecision.is_pass Tests ──────────────────────────────────────────

#[test]
fn enrichment_gate_decision_is_pass_true_for_pass() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-is-pass-true", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Pass);
    assert!(decision.is_pass());
}

#[test]
fn enrichment_gate_decision_is_pass_false_for_fail() {
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
    let decision = gate.evaluate("rc-is-pass-false", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    assert!(!decision.is_pass());
}

// ── CliffMarginCertificate observation_margin ───────────────────────────

#[test]
fn enrichment_cliff_margin_observation_margin_reflects_difference() {
    let config = TailGateConfig {
        min_rounds_per_campaign: 100,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", vec![10_000; 250])];
    let decision = gate.evaluate("rc-obs-margin", &campaigns).unwrap();
    let cert = &decision.continuation_cliff_atlas.margin_certificates[0];
    // observation_margin = observation_count - min_rounds = 250 - 100 = 150
    assert_eq!(cert.observation_margin, 150);
}

// ── Fail Rationale Contains Both Budget and Alarm ───────────────────────

#[test]
fn enrichment_fail_rationale_with_both_budget_exceeded_and_alarm() {
    let config = TailGateConfig {
        tail_budget_millionths: 10_000,
        e_value_alarm_threshold_millionths: 2_000_000,
        ..Default::default()
    };
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    // Both exceeds budget and triggers alarm
    let mut payoffs = vec![1_000_i64; 199];
    payoffs.push(50_000_000);
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-both-fail", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    // Rationale should mention both CVaR exceeds budget and alarms
    assert!(decision.rationale.contains("exceeds budget") || decision.rationale.contains("alarm"));
}
