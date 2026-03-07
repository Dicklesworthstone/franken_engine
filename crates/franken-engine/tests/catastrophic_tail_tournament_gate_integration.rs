//! Integration tests for `franken_engine::catastrophic_tail_tournament_gate`.
//!
//! Exercises the catastrophic-tail adversarial tournament gate from the public
//! crate boundary, covering threat classes, campaigns, tail-risk metrics,
//! gate decisions, rollback playbooks, and risk ledger accumulation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use frankenengine_engine::adversarial_coevolution_harness::{
    ConvergenceDiagnostic, PolicyDelta, TournamentResult,
};
use frankenengine_engine::catastrophic_tail_tournament_gate::{
    CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION, Campaign, CatastrophicTailTournamentGate, CliffBand,
    CliffMarginCertificate, CliffWitness, ContinuationCliffAtlas, GateDecision, GateVerdict,
    MitigationStep, RiskLedgerEntry, RollbackPlaybook, TAIL_GATE_SCHEMA_VERSION, TailGateConfig,
    TailGateError, TailRiskMetrics, ThreatCategory, ThreatClass,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId};
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

fn empty_cliff_atlas() -> ContinuationCliffAtlas {
    ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-empty".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        margin_certificates: vec![],
        witnesses: vec![],
        atlas_hash: ContentHash::compute(b"empty-cliff-atlas"),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

// ── Schema Version ──────────────────────────────────────────────────────

#[test]
fn schema_version_is_set() {
    assert!(!TAIL_GATE_SCHEMA_VERSION.is_empty());
    assert!(TAIL_GATE_SCHEMA_VERSION.contains("catastrophic-tail"));
}

// ── ThreatCategory ──────────────────────────────────────────────────────

#[test]
fn threat_category_all_variants() {
    let categories = [
        ThreatCategory::CapabilityEscalation,
        ThreatCategory::ResourceExhaustion,
        ThreatCategory::InformationLeakage,
        ThreatCategory::PolicyBypass,
        ThreatCategory::SupplyChain,
        ThreatCategory::TimingChannel,
    ];
    assert_eq!(categories.len(), 6);
}

#[test]
fn threat_category_display() {
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
fn threat_category_serde_roundtrip() {
    let cat = ThreatCategory::PolicyBypass;
    let json = serde_json::to_string(&cat).unwrap();
    let back: ThreatCategory = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cat);
}

// ── ThreatClass ─────────────────────────────────────────────────────────

#[test]
fn threat_class_display() {
    let tc = make_threat("tc-1", ThreatCategory::SupplyChain, 500_000);
    let display = format!("{}", tc);
    assert!(display.contains("tc-1"));
    assert!(display.contains("supply-chain"));
    assert!(display.contains("500000"));
}

#[test]
fn threat_class_serde_roundtrip() {
    let mut tc = make_threat("tc-2", ThreatCategory::TimingChannel, MILLION);
    tc.related_exploits.insert("timing-attack-v1".to_string());
    let json = serde_json::to_string(&tc).unwrap();
    let back: ThreatClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tc);
    assert!(back.related_exploits.contains("timing-attack-v1"));
}

// ── Campaign ────────────────────────────────────────────────────────────

#[test]
fn campaign_round_count() {
    let campaign = make_campaign("c1", "t1", vec![100; 200]);
    assert_eq!(campaign.round_count(), 200);
}

#[test]
fn campaign_serde_roundtrip() {
    let campaign = make_campaign("c1", "t1", low_risk_payoffs(150));
    let json = serde_json::to_string(&campaign).unwrap();
    let back: Campaign = serde_json::from_str(&json).unwrap();
    assert_eq!(back.campaign_id, "c1");
    assert_eq!(back.threat_class_id, "t1");
    assert_eq!(back.attacker_payoffs.len(), 150);
}

// ── TailRiskMetrics ─────────────────────────────────────────────────────

#[test]
fn tail_risk_metrics_exceeds_budget() {
    let metrics = TailRiskMetrics {
        threat_class_id: "t1".to_string(),
        observation_count: 100,
        var_millionths: 400_000,
        cvar_millionths: 600_000,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 800_000,
        worst_exploit: None,
    };
    assert!(metrics.exceeds_budget(500_000));
    assert!(!metrics.exceeds_budget(600_000));
    assert!(!metrics.exceeds_budget(700_000));
}

#[test]
fn tail_risk_metrics_display() {
    let metrics = TailRiskMetrics {
        threat_class_id: "threat-a".to_string(),
        observation_count: 50,
        var_millionths: 100_000,
        cvar_millionths: 200_000,
        alpha_millionths: 950_000,
        e_value_millionths: 5_000_000,
        alarm_active: true,
        max_payoff_millionths: 300_000,
        worst_exploit: Some("xss-v1".to_string()),
    };
    let s = format!("{}", metrics);
    assert!(s.contains("threat-a"));
    assert!(s.contains("200000"));
    assert!(s.contains("alarm=true"));
}

#[test]
fn tail_risk_metrics_serde_roundtrip() {
    let metrics = TailRiskMetrics {
        threat_class_id: "t1".to_string(),
        observation_count: 100,
        var_millionths: 300_000,
        cvar_millionths: 450_000,
        alpha_millionths: 950_000,
        e_value_millionths: MILLION,
        alarm_active: false,
        max_payoff_millionths: 500_000,
        worst_exploit: None,
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let back: TailRiskMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, metrics);
}

// ── GateVerdict ─────────────────────────────────────────────────────────

#[test]
fn gate_verdict_display() {
    assert_eq!(format!("{}", GateVerdict::Pass), "pass");
    assert_eq!(format!("{}", GateVerdict::Fail), "fail");
    assert_eq!(format!("{}", GateVerdict::Inconclusive), "inconclusive");
}

#[test]
fn gate_verdict_serde_roundtrip() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Fail,
        GateVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ── GateDecision ────────────────────────────────────────────────────────

#[test]
fn gate_decision_is_pass() {
    let decision = GateDecision {
        decision_id: "d1".to_string(),
        release_candidate_id: "rc-1".to_string(),
        verdict: GateVerdict::Pass,
        epoch: SecurityEpoch::from_raw(1),
        risk_metrics: vec![],
        aggregate_cvar_millionths: 100_000,
        any_alarm_active: false,
        campaigns_evaluated: 2,
        total_rounds: 400,
        rollback_playbook: None,
        continuation_cliff_atlas: empty_cliff_atlas(),
        rationale: "within budget".to_string(),
        artifact_hash: ContentHash::compute(b"test"),
    };
    assert!(decision.is_pass());
}

#[test]
fn gate_decision_is_not_pass_for_fail() {
    let decision = GateDecision {
        decision_id: "d2".to_string(),
        release_candidate_id: "rc-2".to_string(),
        verdict: GateVerdict::Fail,
        epoch: SecurityEpoch::from_raw(1),
        risk_metrics: vec![],
        aggregate_cvar_millionths: 600_000,
        any_alarm_active: true,
        campaigns_evaluated: 1,
        total_rounds: 200,
        rollback_playbook: None,
        continuation_cliff_atlas: empty_cliff_atlas(),
        rationale: "exceeded".to_string(),
        artifact_hash: ContentHash::compute(b"test2"),
    };
    assert!(!decision.is_pass());
}

#[test]
fn gate_decision_display() {
    let decision = GateDecision {
        decision_id: "d3".to_string(),
        release_candidate_id: "rc-3".to_string(),
        verdict: GateVerdict::Inconclusive,
        epoch: SecurityEpoch::from_raw(2),
        risk_metrics: vec![],
        aggregate_cvar_millionths: 0,
        any_alarm_active: false,
        campaigns_evaluated: 3,
        total_rounds: 600,
        rollback_playbook: None,
        continuation_cliff_atlas: empty_cliff_atlas(),
        rationale: "insufficient data".to_string(),
        artifact_hash: ContentHash::compute(b"test3"),
    };
    let s = format!("{}", decision);
    assert!(s.contains("rc-3"));
    assert!(s.contains("campaigns=3"));
}

#[test]
fn gate_decision_serde_roundtrip() {
    let decision = GateDecision {
        decision_id: "d4".to_string(),
        release_candidate_id: "rc-4".to_string(),
        verdict: GateVerdict::Pass,
        epoch: SecurityEpoch::from_raw(1),
        risk_metrics: vec![],
        aggregate_cvar_millionths: 100_000,
        any_alarm_active: false,
        campaigns_evaluated: 1,
        total_rounds: 200,
        rollback_playbook: None,
        continuation_cliff_atlas: empty_cliff_atlas(),
        rationale: "ok".to_string(),
        artifact_hash: ContentHash::compute(b"d4"),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decision_id, "d4");
    assert_eq!(back.verdict, GateVerdict::Pass);
    assert_eq!(
        back.continuation_cliff_atlas.schema_version,
        CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION
    );
}

// ── MitigationStep ──────────────────────────────────────────────────────

#[test]
fn mitigation_step_serde_roundtrip() {
    let step = MitigationStep {
        step: 1,
        description: "Route to safe lane".to_string(),
        automated: true,
        action: Some(LaneAction::FallbackSafe),
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MitigationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back.step, 1);
    assert!(back.automated);
    assert!(back.action.is_some());
}

#[test]
fn mitigation_step_manual_no_action() {
    let step = MitigationStep {
        step: 4,
        description: "Review evidence".to_string(),
        automated: false,
        action: None,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MitigationStep = serde_json::from_str(&json).unwrap();
    assert!(!back.automated);
    assert!(back.action.is_none());
}

// ── RollbackPlaybook ────────────────────────────────────────────────────

#[test]
fn rollback_playbook_display() {
    let playbook = RollbackPlaybook {
        playbook_id: "pb-1".to_string(),
        rollback_action: LaneAction::RouteTo(LaneId("safe".to_string())),
        triggering_threats: vec!["t1".to_string(), "t2".to_string()],
        mitigation_steps: vec![
            MitigationStep {
                step: 1,
                description: "Step 1".to_string(),
                automated: true,
                action: Some(LaneAction::FallbackSafe),
            },
            MitigationStep {
                step: 2,
                description: "Step 2".to_string(),
                automated: false,
                action: None,
            },
        ],
        evidence_hash: ContentHash::compute(b"evidence"),
    };
    let s = format!("{}", playbook);
    assert!(s.contains("pb-1"));
    assert!(s.contains("triggers=2"));
    assert!(s.contains("steps=2"));
}

#[test]
fn rollback_playbook_serde_roundtrip() {
    let playbook = RollbackPlaybook {
        playbook_id: "pb-2".to_string(),
        rollback_action: LaneAction::FallbackSafe,
        triggering_threats: vec!["threat-a".to_string()],
        mitigation_steps: vec![MitigationStep {
            step: 1,
            description: "Fallback".to_string(),
            automated: true,
            action: Some(LaneAction::FallbackSafe),
        }],
        evidence_hash: ContentHash::compute(b"pb-2"),
    };
    let json = serde_json::to_string(&playbook).unwrap();
    let back: RollbackPlaybook = serde_json::from_str(&json).unwrap();
    assert_eq!(back.playbook_id, "pb-2");
    assert_eq!(back.triggering_threats.len(), 1);
}

// ── RiskLedgerEntry ─────────────────────────────────────────────────────

#[test]
fn risk_ledger_entry_serde_roundtrip() {
    let entry = RiskLedgerEntry {
        epoch: SecurityEpoch::from_raw(3),
        threat_class_id: "t1".to_string(),
        cvar_millionths: 300_000,
        e_value_millionths: 5_000_000,
        budget_exceeded: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RiskLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.epoch, SecurityEpoch::from_raw(3));
    assert_eq!(back.threat_class_id, "t1");
    assert!(!back.budget_exceeded);
}

// ── TailGateConfig ──────────────────────────────────────────────────────

#[test]
fn tail_gate_config_defaults() {
    let config = TailGateConfig::default();
    assert_eq!(config.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(config.cvar_alpha_millionths, 950_000);
    assert_eq!(config.tail_budget_millionths, 500_000);
    assert_eq!(config.e_value_alarm_threshold_millionths, 20_000_000);
    assert_eq!(config.min_rounds_per_campaign, 100);
    assert_eq!(config.near_cliff_margin_millionths, 50_000);
    assert!(config.generate_rollback_playbook);
    assert!(config.record_risk_ledger);
}

#[test]
fn tail_gate_config_serde_roundtrip() {
    let config = TailGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: TailGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ── TailGateError ───────────────────────────────────────────────────────

#[test]
fn tail_gate_error_display_variants() {
    let err = TailGateError::NoThreatClasses;
    assert!(format!("{}", err).contains("no threat classes"));

    let err = TailGateError::NoCampaigns;
    assert!(format!("{}", err).contains("no campaigns"));

    let err = TailGateError::TooManyThreatClasses { count: 65, max: 64 };
    assert!(format!("{}", err).contains("65"));

    let err = TailGateError::TooManyCampaigns {
        count: 129,
        max: 128,
    };
    assert!(format!("{}", err).contains("129"));

    let err = TailGateError::UnknownThreatClass {
        campaign_id: "c1".to_string(),
        threat_class_id: "t999".to_string(),
    };
    assert!(format!("{}", err).contains("t999"));

    let err = TailGateError::DuplicateThreatClass {
        id: "dup".to_string(),
    };
    assert!(format!("{}", err).contains("dup"));

    let err = TailGateError::InsufficientRounds {
        campaign_id: "c1".to_string(),
        rounds: 50,
        required: 100,
    };
    assert!(format!("{}", err).contains("50"));

    let err = TailGateError::InvalidConfig {
        detail: "bad alpha".to_string(),
    };
    assert!(format!("{}", err).contains("bad alpha"));

    let err = TailGateError::TooManyObservations {
        count: 200_000,
        max: 100_000,
    };
    assert!(format!("{}", err).contains("200000"));
}

#[test]
fn tail_gate_error_serde_roundtrip() {
    let err = TailGateError::InsufficientRounds {
        campaign_id: "c-test".to_string(),
        rounds: 42,
        required: 100,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TailGateError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ── Constructor ─────────────────────────────────────────────────────────

#[test]
fn new_creates_gate_with_valid_inputs() {
    let gate = default_gate();
    assert_eq!(gate.threat_class_count(), 1);
    assert_eq!(gate.evaluation_count(), 0);
    assert!(gate.risk_ledger().is_empty());
}

#[test]
fn new_rejects_empty_threats() {
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), vec![]);
    assert!(matches!(result, Err(TailGateError::NoThreatClasses)));
}

#[test]
fn new_rejects_too_many_threats() {
    let threats: Vec<_> = (0..65)
        .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
        .collect();
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
    assert!(matches!(
        result,
        Err(TailGateError::TooManyThreatClasses { count: 65, max: 64 })
    ));
}

#[test]
fn new_rejects_duplicate_threat_ids() {
    let threats = vec![
        make_threat("dup", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("dup", ThreatCategory::ResourceExhaustion, MILLION),
    ];
    let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
    assert!(matches!(
        result,
        Err(TailGateError::DuplicateThreatClass { .. })
    ));
}

#[test]
fn new_rejects_zero_alpha() {
    let mut config = TailGateConfig::default();
    config.cvar_alpha_millionths = 0;
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn new_rejects_alpha_above_million() {
    let mut config = TailGateConfig::default();
    config.cvar_alpha_millionths = MILLION + 1;
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn new_rejects_negative_budget() {
    let mut config = TailGateConfig::default();
    config.tail_budget_millionths = -1;
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let result = CatastrophicTailTournamentGate::new(config, threats);
    assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
}

#[test]
fn new_accepts_single_threat() {
    let threats = vec![make_threat(
        "only",
        ThreatCategory::InformationLeakage,
        MILLION,
    )];
    let gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    assert_eq!(gate.threat_class_count(), 1);
}

#[test]
fn new_accepts_max_threats() {
    let threats: Vec<_> = (0..64)
        .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
        .collect();
    let gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    assert_eq!(gate.threat_class_count(), 64);
}

// ── Evaluate: Error Paths ───────────────────────────────────────────────

#[test]
fn evaluate_rejects_no_campaigns() {
    let mut gate = default_gate();
    let result = gate.evaluate("rc-1", &[]);
    assert!(matches!(result, Err(TailGateError::NoCampaigns)));
}

#[test]
fn evaluate_rejects_unknown_threat_class() {
    let mut gate = default_gate();
    let campaign = make_campaign("c1", "unknown-threat", low_risk_payoffs(200));
    let result = gate.evaluate("rc-1", &[campaign]);
    assert!(matches!(
        result,
        Err(TailGateError::UnknownThreatClass { .. })
    ));
}

#[test]
fn evaluate_rejects_insufficient_rounds() {
    let mut gate = default_gate();
    // Default min_rounds = 100, but only 50 payoffs → 50 rounds
    let campaign = make_campaign("c1", "t1", low_risk_payoffs(50));
    let result = gate.evaluate("rc-1", &[campaign]);
    assert!(matches!(
        result,
        Err(TailGateError::InsufficientRounds {
            rounds: 50,
            required: 100,
            ..
        })
    ));
}

// ── Evaluate: Pass ──────────────────────────────────────────────────────

#[test]
fn evaluate_low_risk_passes() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    let decision = gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Pass);
    assert!(decision.is_pass());
    assert!(!decision.any_alarm_active);
    assert!(decision.rollback_playbook.is_none());
    assert_eq!(decision.campaigns_evaluated, 2);
    assert!(decision.rationale.contains("within budget"));
}

#[test]
fn evaluate_pass_increments_evaluation_count() {
    let mut gate = default_gate();
    assert_eq!(gate.evaluation_count(), 0);
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(gate.evaluation_count(), 1);
    gate.evaluate("rc-2", &campaigns).unwrap();
    assert_eq!(gate.evaluation_count(), 2);
}

#[test]
fn evaluate_pass_decision_id_includes_rc_and_epoch() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-alpha", &campaigns).unwrap();
    assert!(decision.decision_id.contains("rc-alpha"));
    assert!(decision.decision_id.contains("1")); // epoch
}

#[test]
fn evaluate_pass_has_risk_metrics_per_threat() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    let decision = gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(decision.risk_metrics.len(), 2);
    let ids: Vec<_> = decision
        .risk_metrics
        .iter()
        .map(|m| m.threat_class_id.as_str())
        .collect();
    assert!(ids.contains(&"t1"));
    assert!(ids.contains(&"t2"));
}

// ── Evaluate: Fail (CVaR exceeded) ──────────────────────────────────────

#[test]
fn evaluate_high_risk_fails() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", high_risk_payoffs(200)),
        make_campaign("c2", "t2", high_risk_payoffs(200)),
    ];
    let decision = gate.evaluate("rc-bad", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    assert!(!decision.is_pass());
    assert!(decision.aggregate_cvar_millionths > gate.config().tail_budget_millionths);
}

#[test]
fn evaluate_fail_generates_rollback_playbook() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-bad", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    let playbook = decision.rollback_playbook.as_ref().unwrap();
    assert!(!playbook.triggering_threats.is_empty());
    assert!(!playbook.mitigation_steps.is_empty());
    // First step should be automated fallback
    assert!(playbook.mitigation_steps[0].automated);
    // Last step should be manual review
    let last = playbook.mitigation_steps.last().unwrap();
    assert!(!last.automated);
    assert!(last.action.is_none());
}

#[test]
fn evaluate_fail_playbook_has_4_steps() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-bad", &campaigns).unwrap();
    let playbook = decision.rollback_playbook.unwrap();
    assert_eq!(playbook.mitigation_steps.len(), 4);
    // Steps should be numbered 1-4
    for (i, step) in playbook.mitigation_steps.iter().enumerate() {
        assert_eq!(step.step, (i + 1) as u32);
    }
}

#[test]
fn evaluate_fail_no_playbook_when_disabled() {
    let mut config = TailGateConfig::default();
    config.generate_rollback_playbook = false;
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
    let decision = gate.evaluate("rc-bad", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Fail);
    assert!(decision.rollback_playbook.is_none());
}

// ── Evaluate: Risk Ledger ───────────────────────────────────────────────

#[test]
fn evaluate_records_risk_ledger_entries() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 2);
    let threat_ids: Vec<_> = gate
        .risk_ledger()
        .iter()
        .map(|e| e.threat_class_id.as_str())
        .collect();
    assert!(threat_ids.contains(&"t1"));
    assert!(threat_ids.contains(&"t2"));
}

#[test]
fn evaluate_risk_ledger_accumulates_across_evaluations() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    gate.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 1);
    gate.evaluate("rc-2", &campaigns).unwrap();
    assert_eq!(gate.risk_ledger().len(), 2);
}

#[test]
fn evaluate_no_risk_ledger_when_disabled() {
    let mut config = TailGateConfig::default();
    config.record_risk_ledger = false;
    let threats = vec![make_threat(
        "t1",
        ThreatCategory::CapabilityEscalation,
        MILLION,
    )];
    let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    gate.evaluate("rc-1", &campaigns).unwrap();
    assert!(gate.risk_ledger().is_empty());
}

// ── Evaluate: Artifact Hash Determinism ─────────────────────────────────

#[test]
fn evaluate_artifact_hash_deterministic() {
    let mut gate1 = default_gate();
    let mut gate2 = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let d1 = gate1.evaluate("rc-1", &campaigns).unwrap();
    let d2 = gate2.evaluate("rc-1", &campaigns).unwrap();
    assert_eq!(d1.artifact_hash, d2.artifact_hash);
}

#[test]
fn evaluate_different_rc_different_hash() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let d1 = gate.evaluate("rc-1", &campaigns).unwrap();
    let d2 = gate.evaluate("rc-2", &campaigns).unwrap();
    assert_ne!(d1.artifact_hash, d2.artifact_hash);
}

// ── Evaluate: E-value Alarm ─────────────────────────────────────────────

#[test]
fn evaluate_e_value_alarm_triggers_fail() {
    // Construct payoffs with extreme max/mean ratio to trigger e-value alarm
    let mut payoffs = vec![1_i64; 200];
    payoffs[199] = 100_000_000; // extreme tail event
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", payoffs)];
    let decision = gate.evaluate("rc-alarm", &campaigns).unwrap();
    // The extreme outlier should push e-value above threshold
    assert!(decision.any_alarm_active);
    assert_eq!(decision.verdict, GateVerdict::Fail);
}

// ── Evaluate: Multiple Campaigns Same Threat ────────────────────────────

#[test]
fn evaluate_multiple_campaigns_same_threat_class() {
    let mut gate = default_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(150)),
        make_campaign("c2", "t1", low_risk_payoffs(150)),
    ];
    let decision = gate.evaluate("rc-1", &campaigns).unwrap();
    // Both campaigns target t1 — should produce a single metric entry for t1
    assert_eq!(decision.risk_metrics.len(), 1);
    assert_eq!(decision.risk_metrics[0].threat_class_id, "t1");
    // Observation count should combine both campaigns
    assert_eq!(decision.risk_metrics[0].observation_count, 300);
}

// ── Evaluate: Weighted Aggregate CVaR ───────────────────────────────────

#[test]
fn evaluate_aggregate_cvar_weights_threats() {
    // One threat with high weight, one with low weight
    let threats = vec![
        make_threat("high-weight", ThreatCategory::CapabilityEscalation, MILLION),
        make_threat("low-weight", ThreatCategory::ResourceExhaustion, 100_000),
    ];
    let mut gate = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
    let campaigns = vec![
        make_campaign("c1", "high-weight", low_risk_payoffs(200)),
        make_campaign("c2", "low-weight", high_risk_payoffs(200)),
    ];
    let decision = gate.evaluate("rc-1", &campaigns).unwrap();
    // Aggregate CVaR should be weighted toward the high-weight threat (low risk)
    // rather than the low-weight threat (high risk)
    assert!(decision.risk_metrics.len() == 2);
}

// ── Gate Serde Roundtrip ────────────────────────────────────────────────

#[test]
fn gate_serde_roundtrip() {
    let mut gate = default_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    gate.evaluate("rc-1", &campaigns).unwrap();

    let json = serde_json::to_string(&gate).unwrap();
    let back: CatastrophicTailTournamentGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.threat_class_count(), 1);
    assert_eq!(back.risk_ledger().len(), gate.risk_ledger().len());
}

// ── Full Lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_pass_then_fail_then_pass() {
    let mut gate = dual_threat_gate();

    // 1. First candidate passes
    let low_campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    let d1 = gate.evaluate("rc-v1.0", &low_campaigns).unwrap();
    assert_eq!(d1.verdict, GateVerdict::Pass);
    assert_eq!(gate.evaluation_count(), 1);
    assert_eq!(gate.risk_ledger().len(), 2);

    // 2. Second candidate fails (high tail risk)
    let high_campaigns = vec![
        make_campaign("c3", "t1", high_risk_payoffs(200)),
        make_campaign("c4", "t2", high_risk_payoffs(200)),
    ];
    let d2 = gate.evaluate("rc-v1.1-bad", &high_campaigns).unwrap();
    assert_eq!(d2.verdict, GateVerdict::Fail);
    assert!(d2.rollback_playbook.is_some());
    assert_eq!(gate.evaluation_count(), 2);
    assert_eq!(gate.risk_ledger().len(), 4);

    // 3. Third candidate passes again
    let d3 = gate.evaluate("rc-v1.1-fixed", &low_campaigns).unwrap();
    assert_eq!(d3.verdict, GateVerdict::Pass);
    assert_eq!(gate.evaluation_count(), 3);
    assert_eq!(gate.risk_ledger().len(), 6);

    // Verify distinct artifact hashes
    assert_ne!(d1.artifact_hash, d2.artifact_hash);
    assert_ne!(d2.artifact_hash, d3.artifact_hash);
    assert_ne!(d1.artifact_hash, d3.artifact_hash);
}

#[test]
fn full_lifecycle_serde_preserves_state() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![
        make_campaign("c1", "t1", low_risk_payoffs(200)),
        make_campaign("c2", "t2", low_risk_payoffs(200)),
    ];
    gate.evaluate("rc-1", &campaigns).unwrap();
    gate.evaluate("rc-2", &campaigns).unwrap();

    // Serialize and deserialize
    let json = serde_json::to_string(&gate).unwrap();
    let mut restored: CatastrophicTailTournamentGate = serde_json::from_str(&json).unwrap();

    // State should be preserved
    assert_eq!(restored.evaluation_count(), 2);
    assert_eq!(restored.risk_ledger().len(), 4);

    // Evaluations should continue from deserialized state
    let d3 = restored.evaluate("rc-3", &campaigns).unwrap();
    assert_eq!(d3.verdict, GateVerdict::Pass);
    assert_eq!(restored.evaluation_count(), 3);
}

#[test]
fn evaluate_missing_neighborhood_is_inconclusive_and_emits_witness() {
    let mut gate = dual_threat_gate();
    let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
    let decision = gate.evaluate("rc-gap", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Inconclusive);
    assert!(decision.rationale.contains("t2"));
    assert_eq!(decision.risk_metrics.len(), 2);

    let missing = decision
        .risk_metrics
        .iter()
        .find(|metrics| metrics.threat_class_id == "t2")
        .expect("missing threat metrics should be present");
    assert_eq!(missing.observation_count, 0);

    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|witness| witness.threat_class_id == "t2")
        .expect("missing neighborhood should emit a witness");
    assert_eq!(witness.cliff_band, CliffBand::MissingNeighborhood);
    assert!(witness.campaign_id.is_none());
    assert!(matches!(witness.escape_action, LaneAction::FallbackSafe));
}

#[test]
fn evaluate_near_cliff_band_warns_without_failing() {
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
    let decision = gate.evaluate("rc-near", &campaigns).unwrap();
    assert_eq!(decision.verdict, GateVerdict::Pass);

    let certificate = decision
        .continuation_cliff_atlas
        .margin_certificates
        .iter()
        .find(|certificate| certificate.threat_class_id == "t1")
        .expect("certificate");
    assert_eq!(certificate.cliff_band, CliffBand::NearCliff);
    assert_eq!(certificate.cvar_margin_millionths, 20_000);

    let witness = decision
        .continuation_cliff_atlas
        .witnesses
        .iter()
        .find(|witness| witness.threat_class_id == "t1")
        .expect("near-cliff witness");
    assert_eq!(witness.cliff_band, CliffBand::NearCliff);
    assert_eq!(witness.campaign_id.as_deref(), Some("c1"));
}

#[test]
fn continuation_cliff_atlas_serde_roundtrip() {
    let atlas = ContinuationCliffAtlas {
        schema_version: CONTINUATION_CLIFF_ATLAS_SCHEMA_VERSION.to_string(),
        release_candidate_id: "rc-atlas".to_string(),
        epoch: SecurityEpoch::from_raw(9),
        margin_certificates: vec![CliffMarginCertificate {
            threat_class_id: "t1".to_string(),
            cliff_band: CliffBand::NearCliff,
            cvar_margin_millionths: 10_000,
            e_value_margin_millionths: 20_000,
            observation_margin: 100,
        }],
        witnesses: vec![CliffWitness {
            threat_class_id: "t1".to_string(),
            cliff_band: CliffBand::NearCliff,
            campaign_id: Some("campaign-1".to_string()),
            max_payoff_millionths: 140_000,
            worst_exploit: Some("policy_bypass".to_string()),
            escape_action: LaneAction::RouteTo(LaneId("safe".to_string())),
            rationale: "near cliff".to_string(),
        }],
        atlas_hash: ContentHash::compute(b"atlas"),
    };
    let json = serde_json::to_string(&atlas).unwrap();
    let back: ContinuationCliffAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(back, atlas);
}

#[test]
fn continuation_cliff_atlas_contract_doc_mentions_fail_closed_missing_neighborhoods() {
    let path = repo_root().join("docs/RGC_CONTINUATION_CLIFF_ATLAS_V1.md");
    let doc = std::fs::read_to_string(path).expect("contract doc should exist");
    assert!(doc.contains("missing_neighborhood"));
    assert!(doc.contains("fail closed"));
    assert!(doc.contains("./scripts/run_rgc_continuation_cliff_atlas_suite.sh ci"));
}

#[test]
fn continuation_cliff_atlas_contract_json_is_machine_readable() {
    let path = repo_root().join("docs/rgc_continuation_cliff_atlas_v1.json");
    let json = std::fs::read_to_string(path).expect("contract json should exist");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(
        value["schema_version"].as_str(),
        Some("franken-engine.continuation-cliff-atlas.contract.v1")
    );
    assert_eq!(value["primary_bead"].as_str(), Some("bd-1lsy.7.19"));
}

#[test]
fn continuation_cliff_atlas_gate_script_exists_and_uses_rch() {
    let path = repo_root().join("scripts/run_rgc_continuation_cliff_atlas_suite.sh");
    let script = std::fs::read_to_string(path).expect("gate script should exist");
    assert!(script.contains("rch exec"));
    assert!(script.contains("CARGO_BUILD_JOBS"));
    assert!(script.contains("evaluate_missing_neighborhood_is_inconclusive_and_emits_witness"));
    assert!(script.contains("continuation_cliff_atlas_hash_uses_escape_action_display_contract"));
}
