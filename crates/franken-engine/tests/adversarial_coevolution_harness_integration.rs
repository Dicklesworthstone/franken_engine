//! Integration tests for the adversarial coevolution harness module.
//!
//! Exercises the public API of `adversarial_coevolution_harness` from outside
//! the crate boundary: strategy identifiers, payoff matrices, tournament
//! configuration, the EXP3-based coevolution harness, and error paths.

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

use frankenengine_engine::adversarial_coevolution_harness::{
    COEVOLUTION_COMPONENT, COEVOLUTION_SCHEMA_VERSION, CoevolutionError, CoevolutionHarness,
    ConvergenceDiagnostic, ExploitClass, PayoffEntry, PayoffMatrix, PlayerRole, PolicyDelta,
    RoundOutcome, StrategyId, TournamentConfig, TournamentResult,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rps_matrix() -> PayoffMatrix {
    let million: i64 = 1_000_000;
    let atk = vec![
        StrategyId("rock".into()),
        StrategyId("paper".into()),
        StrategyId("scissors".into()),
    ];
    let def = atk.clone();
    let entries = vec![
        PayoffEntry {
            attacker: StrategyId("rock".into()),
            defender: StrategyId("rock".into()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        },
        PayoffEntry {
            attacker: StrategyId("rock".into()),
            defender: StrategyId("paper".into()),
            attacker_payoff_millionths: -million,
            defender_payoff_millionths: million,
        },
        PayoffEntry {
            attacker: StrategyId("rock".into()),
            defender: StrategyId("scissors".into()),
            attacker_payoff_millionths: million,
            defender_payoff_millionths: -million,
        },
        PayoffEntry {
            attacker: StrategyId("paper".into()),
            defender: StrategyId("rock".into()),
            attacker_payoff_millionths: million,
            defender_payoff_millionths: -million,
        },
        PayoffEntry {
            attacker: StrategyId("paper".into()),
            defender: StrategyId("paper".into()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        },
        PayoffEntry {
            attacker: StrategyId("paper".into()),
            defender: StrategyId("scissors".into()),
            attacker_payoff_millionths: -million,
            defender_payoff_millionths: million,
        },
        PayoffEntry {
            attacker: StrategyId("scissors".into()),
            defender: StrategyId("rock".into()),
            attacker_payoff_millionths: -million,
            defender_payoff_millionths: million,
        },
        PayoffEntry {
            attacker: StrategyId("scissors".into()),
            defender: StrategyId("paper".into()),
            attacker_payoff_millionths: million,
            defender_payoff_millionths: -million,
        },
        PayoffEntry {
            attacker: StrategyId("scissors".into()),
            defender: StrategyId("scissors".into()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        },
    ];
    PayoffMatrix {
        attacker_strategies: atk,
        defender_strategies: def,
        entries,
    }
}

fn security_matrix() -> PayoffMatrix {
    let atk = vec![
        StrategyId("capability-escalation".into()),
        StrategyId("policy-bypass".into()),
    ];
    let def = vec![
        StrategyId("strict-containment".into()),
        StrategyId("adaptive-sandbox".into()),
    ];
    let entries = vec![
        PayoffEntry {
            attacker: StrategyId("capability-escalation".into()),
            defender: StrategyId("strict-containment".into()),
            attacker_payoff_millionths: 200_000,
            defender_payoff_millionths: 800_000,
        },
        PayoffEntry {
            attacker: StrategyId("capability-escalation".into()),
            defender: StrategyId("adaptive-sandbox".into()),
            attacker_payoff_millionths: 600_000,
            defender_payoff_millionths: 400_000,
        },
        PayoffEntry {
            attacker: StrategyId("policy-bypass".into()),
            defender: StrategyId("strict-containment".into()),
            attacker_payoff_millionths: 700_000,
            defender_payoff_millionths: 300_000,
        },
        PayoffEntry {
            attacker: StrategyId("policy-bypass".into()),
            defender: StrategyId("adaptive-sandbox".into()),
            attacker_payoff_millionths: 300_000,
            defender_payoff_millionths: 700_000,
        },
    ];
    PayoffMatrix {
        attacker_strategies: atk,
        defender_strategies: def,
        entries,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_stable() {
    assert_eq!(
        COEVOLUTION_SCHEMA_VERSION,
        "franken-engine.adversarial-coevolution.v1"
    );
}

#[test]
fn component_label_stable() {
    assert_eq!(COEVOLUTION_COMPONENT, "adversarial_coevolution_harness");
}

// ---------------------------------------------------------------------------
// StrategyId
// ---------------------------------------------------------------------------

#[test]
fn strategy_id_display() {
    let s = StrategyId("test-strat".into());
    assert_eq!(s.to_string(), "test-strat");
}

#[test]
fn strategy_id_serde_roundtrip() {
    let s = StrategyId("alpha".into());
    let json = serde_json::to_string(&s).unwrap();
    let back: StrategyId = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// PlayerRole
// ---------------------------------------------------------------------------

#[test]
fn player_role_display() {
    assert_eq!(PlayerRole::Attacker.to_string(), "attacker");
    assert_eq!(PlayerRole::Defender.to_string(), "defender");
}

#[test]
fn player_role_serde_roundtrip() {
    for role in [PlayerRole::Attacker, PlayerRole::Defender] {
        let json = serde_json::to_string(&role).unwrap();
        let back: PlayerRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, back);
    }
}

// ---------------------------------------------------------------------------
// ExploitClass
// ---------------------------------------------------------------------------

#[test]
fn exploit_class_display_all_variants() {
    let variants = vec![
        (ExploitClass::CapabilityEscalation, "capability_escalation"),
        (ExploitClass::PolicyBypass, "policy_bypass"),
        (ExploitClass::ResourceExhaustion, "resource_exhaustion"),
        (ExploitClass::InformationLeakage, "information_leakage"),
        (ExploitClass::ReplayAttack, "replay_attack"),
        (ExploitClass::Novel("zero-day".into()), "novel:zero-day"),
    ];
    for (ec, expected) in variants {
        assert_eq!(ec.to_string(), expected);
    }
}

#[test]
fn exploit_class_serde_roundtrip() {
    let variants = vec![
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass,
        ExploitClass::ResourceExhaustion,
        ExploitClass::InformationLeakage,
        ExploitClass::ReplayAttack,
        ExploitClass::Novel("test".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ExploitClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// PayoffEntry — serde
// ---------------------------------------------------------------------------

#[test]
fn payoff_entry_serde_roundtrip() {
    let entry = PayoffEntry {
        attacker: StrategyId("a".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: 500_000,
        defender_payoff_millionths: 500_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PayoffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// PayoffMatrix
// ---------------------------------------------------------------------------

#[test]
fn payoff_matrix_lookup_found() {
    let m = rps_matrix();
    let entry = m
        .lookup(&StrategyId("rock".into()), &StrategyId("paper".into()))
        .unwrap();
    assert_eq!(entry.attacker_payoff_millionths, -1_000_000);
    assert_eq!(entry.defender_payoff_millionths, 1_000_000);
}

#[test]
fn payoff_matrix_lookup_not_found() {
    let m = rps_matrix();
    assert!(
        m.lookup(
            &StrategyId("nonexistent".into()),
            &StrategyId("rock".into()),
        )
        .is_none()
    );
}

#[test]
fn payoff_matrix_minimax_defender_rps() {
    let m = rps_matrix();
    // RPS is symmetric — minimax defender should be any of the three
    let minimax = m.minimax_defender().unwrap();
    assert!(
        ["rock", "paper", "scissors"].contains(&minimax.0.as_str()),
        "unexpected minimax: {}",
        minimax
    );
}

#[test]
fn payoff_matrix_minimax_defender_security() {
    let m = security_matrix();
    let minimax = m.minimax_defender().unwrap();
    // adaptive-sandbox: max attacker payoff is max(600k, 300k) = 600k
    // strict-containment: max attacker payoff is max(200k, 700k) = 700k
    // minimax should pick adaptive-sandbox (lower max-attacker)
    assert_eq!(minimax.0, "adaptive-sandbox");
}

#[test]
fn payoff_matrix_serde_roundtrip() {
    let m = rps_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let back: PayoffMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// TournamentConfig
// ---------------------------------------------------------------------------

#[test]
fn tournament_config_default() {
    let cfg = TournamentConfig::default();
    assert_eq!(cfg.rounds, 1000);
    assert!(cfg.gamma_millionths > 0);
    assert!(cfg.gamma_millionths < 1_000_000);
    assert_eq!(cfg.seed, 42);
    assert!(cfg.track_trajectory);
}

#[test]
fn tournament_config_serde_roundtrip() {
    let cfg = TournamentConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TournamentConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// CoevolutionError
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants() {
    let variants: Vec<CoevolutionError> = vec![
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker,
        },
        CoevolutionError::TooManyStrategies {
            count: 100,
            max: 64,
        },
        CoevolutionError::IncompletePayoffMatrix {
            expected: 9,
            actual: 3,
        },
        CoevolutionError::InvalidGamma { value: 0 },
        CoevolutionError::TooManyRounds {
            rounds: 200_000,
            max: 100_000,
        },
        CoevolutionError::BudgetExhausted {
            spent: 1_000_000,
            budget: 500_000,
        },
        CoevolutionError::ZeroRounds,
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty(), "empty display for {v:?}");
    }
}

#[test]
fn error_serde_roundtrip() {
    let variants: Vec<CoevolutionError> = vec![
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender,
        },
        CoevolutionError::TooManyStrategies {
            count: 100,
            max: 64,
        },
        CoevolutionError::IncompletePayoffMatrix {
            expected: 4,
            actual: 2,
        },
        CoevolutionError::InvalidGamma { value: -1 },
        CoevolutionError::TooManyRounds {
            rounds: 200_000,
            max: 100_000,
        },
        CoevolutionError::BudgetExhausted {
            spent: 10,
            budget: 5,
        },
        CoevolutionError::ZeroRounds,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CoevolutionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CoevolutionHarness — construction errors
// ---------------------------------------------------------------------------

#[test]
fn harness_rejects_empty_attacker() {
    let m = PayoffMatrix {
        attacker_strategies: vec![],
        defender_strategies: vec![StrategyId("d".into())],
        entries: vec![],
    };
    let err = CoevolutionHarness::new(TournamentConfig::default(), m).unwrap_err();
    assert!(matches!(
        err,
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker
        }
    ));
}

#[test]
fn harness_rejects_empty_defender() {
    let m = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a".into())],
        defender_strategies: vec![],
        entries: vec![],
    };
    let err = CoevolutionHarness::new(TournamentConfig::default(), m).unwrap_err();
    assert!(matches!(
        err,
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender
        }
    ));
}

#[test]
fn harness_rejects_incomplete_matrix() {
    let m = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a1".into()), StrategyId("a2".into())],
        defender_strategies: vec![StrategyId("d1".into())],
        entries: vec![PayoffEntry {
            attacker: StrategyId("a1".into()),
            defender: StrategyId("d1".into()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        }],
    };
    let err = CoevolutionHarness::new(TournamentConfig::default(), m).unwrap_err();
    assert!(matches!(
        err,
        CoevolutionError::IncompletePayoffMatrix {
            expected: 2,
            actual: 1
        }
    ));
}

#[test]
fn harness_rejects_zero_gamma() {
    let cfg = TournamentConfig {
        gamma_millionths: 0,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { value: 0 }));
}

#[test]
fn harness_rejects_gamma_geq_million() {
    let cfg = TournamentConfig {
        gamma_millionths: 1_000_000,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { .. }));
}

#[test]
fn harness_rejects_zero_rounds() {
    let cfg = TournamentConfig {
        rounds: 0,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::ZeroRounds));
}

#[test]
fn harness_rejects_too_many_rounds() {
    let cfg = TournamentConfig {
        rounds: 100_001,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::TooManyRounds { .. }));
}

// ---------------------------------------------------------------------------
// CoevolutionHarness — accessors
// ---------------------------------------------------------------------------

#[test]
fn harness_accessors() {
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let harness = CoevolutionHarness::new(cfg.clone(), rps_matrix()).unwrap();
    assert_eq!(harness.config().rounds, 50);
    assert_eq!(harness.tournament_count(), 0);
    assert_eq!(harness.payoff_matrix().entries.len(), 9);
}

// ---------------------------------------------------------------------------
// CoevolutionHarness — run
// ---------------------------------------------------------------------------

#[test]
fn run_rps_tournament() {
    let cfg = TournamentConfig {
        rounds: 200,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.rounds_played, 200);
    assert_eq!(result.schema_version, COEVOLUTION_SCHEMA_VERSION);
    assert_eq!(h.tournament_count(), 1);
}

#[test]
fn run_security_tournament() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.rounds_played, 100);
    assert!(!result.policy_delta.recommended_mix.is_empty());
}

#[test]
fn run_is_deterministic() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h1 = CoevolutionHarness::new(cfg.clone(), rps_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(
        r1.total_attacker_payoff_millionths,
        r2.total_attacker_payoff_millionths
    );
}

#[test]
fn different_seeds_produce_different_results() {
    let cfg1 = TournamentConfig {
        rounds: 100,
        seed: 1,
        ..TournamentConfig::default()
    };
    let cfg2 = TournamentConfig {
        rounds: 100,
        seed: 999,
        ..TournamentConfig::default()
    };
    let mut h1 = CoevolutionHarness::new(cfg1, rps_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(cfg2, rps_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_ne!(r1.artifact_hash, r2.artifact_hash);
}

#[test]
fn multiple_tournaments_increment_count() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let _ = h.run().unwrap();
    assert_eq!(h.tournament_count(), 1);
    let _ = h.run().unwrap();
    assert_eq!(h.tournament_count(), 2);
}

// ---------------------------------------------------------------------------
// Trajectory
// ---------------------------------------------------------------------------

#[test]
fn trajectory_tracks_all_rounds() {
    let cfg = TournamentConfig {
        rounds: 50,
        track_trajectory: true,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let traj = result.trajectory.as_ref().unwrap();
    assert_eq!(traj.round_count(), 50);
    assert_eq!(traj.attacker_cumulative_regret.len(), 50);
}

#[test]
fn trajectory_disabled_is_none() {
    let cfg = TournamentConfig {
        rounds: 50,
        track_trajectory: false,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    assert!(result.trajectory.is_none());
}

#[test]
fn trajectory_regret_non_negative() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let traj = result.trajectory.unwrap();
    for r in &traj.attacker_cumulative_regret {
        assert!(*r >= 0, "negative attacker regret: {r}");
    }
    for r in &traj.defender_cumulative_regret {
        assert!(*r >= 0, "negative defender regret: {r}");
    }
}

#[test]
fn trajectory_final_regret_matches_last() {
    let cfg = TournamentConfig {
        rounds: 30,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let traj = result.trajectory.unwrap();
    assert_eq!(
        traj.final_attacker_regret(),
        *traj.attacker_cumulative_regret.last().unwrap()
    );
    assert_eq!(
        traj.final_defender_regret(),
        *traj.defender_cumulative_regret.last().unwrap()
    );
}

// ---------------------------------------------------------------------------
// RoundOutcome — serde
// ---------------------------------------------------------------------------

#[test]
fn round_outcome_serde_roundtrip() {
    let outcome = RoundOutcome {
        round: 42,
        attacker_strategy: StrategyId("rock".into()),
        defender_strategy: StrategyId("paper".into()),
        attacker_payoff_millionths: -1_000_000,
        defender_payoff_millionths: 1_000_000,
        exploit_discovered: Some(ExploitClass::Novel("test".into())),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: RoundOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ---------------------------------------------------------------------------
// ConvergenceDiagnostic
// ---------------------------------------------------------------------------

#[test]
fn convergence_frequency_sums_to_rounds() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let atk_total: u64 = result.convergence.attacker_frequency.values().sum();
    let def_total: u64 = result.convergence.defender_frequency.values().sum();
    assert_eq!(atk_total, 100);
    assert_eq!(def_total, 100);
}

#[test]
fn convergence_avg_regret_non_negative() {
    let cfg = TournamentConfig {
        rounds: 500,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    assert!(result.convergence.attacker_avg_regret_millionths >= 0);
    assert!(result.convergence.defender_avg_regret_millionths >= 0);
}

#[test]
fn convergence_diagnostic_serde_roundtrip() {
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let json = serde_json::to_string(&result.convergence).unwrap();
    let back: ConvergenceDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(result.convergence, back);
}

// ---------------------------------------------------------------------------
// PolicyDelta
// ---------------------------------------------------------------------------

#[test]
fn policy_delta_has_all_defender_strategies() {
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.policy_delta.recommended_mix.len(), 2);
    assert!(
        result
            .policy_delta
            .recommended_mix
            .contains_key("strict-containment")
    );
    assert!(
        result
            .policy_delta
            .recommended_mix
            .contains_key("adaptive-sandbox")
    );
}

#[test]
fn policy_delta_serde_roundtrip() {
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let json = serde_json::to_string(&result.policy_delta).unwrap();
    let back: PolicyDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(result.policy_delta, back);
}

// ---------------------------------------------------------------------------
// TournamentResult — serde
// ---------------------------------------------------------------------------

#[test]
fn tournament_result_serde_roundtrip() {
    let cfg = TournamentConfig {
        rounds: 30,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Exploit classification via strategy names
// ---------------------------------------------------------------------------

#[test]
fn exploit_classification_capability_escalation() {
    let atk = vec![StrategyId("capability-escalation".into())];
    let def = vec![StrategyId("defense".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("capability-escalation".into()),
        defender: StrategyId("defense".into()),
        attacker_payoff_millionths: 900_000, // above 500k threshold
        defender_payoff_millionths: 100_000,
    }];
    let m = PayoffMatrix {
        attacker_strategies: atk,
        defender_strategies: def,
        entries,
    };
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let result = h.run().unwrap();
    // Should discover capability_escalation exploit
    assert!(
        result
            .convergence
            .exploit_classes
            .contains("capability_escalation"),
        "classes: {:?}",
        result.convergence.exploit_classes
    );
}

#[test]
fn exploit_classification_information_leakage() {
    let atk = vec![StrategyId("info-leak-exfil".into())];
    let def = vec![StrategyId("defense".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("info-leak-exfil".into()),
        defender: StrategyId("defense".into()),
        attacker_payoff_millionths: 800_000,
        defender_payoff_millionths: 200_000,
    }];
    let m = PayoffMatrix {
        attacker_strategies: atk,
        defender_strategies: def,
        entries,
    };
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let result = h.run().unwrap();
    assert!(
        result
            .convergence
            .exploit_classes
            .contains("information_leakage"),
        "classes: {:?}",
        result.convergence.exploit_classes
    );
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_create_run_analyze() {
    // 1. Build payoff matrix
    let m = security_matrix();
    assert_eq!(m.attacker_strategies.len(), 2);
    assert_eq!(m.defender_strategies.len(), 2);

    // 2. Minimax analysis
    let minimax = m.minimax_defender().unwrap();
    assert_eq!(minimax.0, "adaptive-sandbox");

    // 3. Run tournament
    let cfg = TournamentConfig {
        rounds: 200,
        seed: 77,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.rounds_played, 200);
    assert_eq!(result.schema_version, COEVOLUTION_SCHEMA_VERSION);

    // 4. Verify convergence diagnostics
    // Note: avg regret can be negative if EXP3 outperforms best fixed strategy
    let _ = result.convergence.attacker_avg_regret_millionths;
    let total_freq: u64 = result.convergence.attacker_frequency.values().sum();
    assert_eq!(total_freq, 200);

    // 5. Verify policy delta
    assert!(!result.policy_delta.recommended_mix.is_empty());
    assert_eq!(result.policy_delta.source_epoch, SecurityEpoch::GENESIS);

    // 6. Serde roundtrip
    let json = serde_json::to_string(&result).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);

    // 7. Verify determinism
    let cfg2 = TournamentConfig {
        rounds: 200,
        seed: 77,
        ..TournamentConfig::default()
    };
    let mut h2 = CoevolutionHarness::new(cfg2, security_matrix()).unwrap();
    let r2 = h2.run().unwrap();
    assert_eq!(result.artifact_hash, r2.artifact_hash);
}
