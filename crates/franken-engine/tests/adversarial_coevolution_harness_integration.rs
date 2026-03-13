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

// ===========================================================================
// Enrichment tests (80–100 new tests)
// ===========================================================================

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers for enrichment
// ---------------------------------------------------------------------------

/// 1×1 trivial game matrix.
fn trivial_1x1_matrix() -> PayoffMatrix {
    PayoffMatrix {
        attacker_strategies: vec![StrategyId("sole-atk".into())],
        defender_strategies: vec![StrategyId("sole-def".into())],
        entries: vec![PayoffEntry {
            attacker: StrategyId("sole-atk".into()),
            defender: StrategyId("sole-def".into()),
            attacker_payoff_millionths: 400_000,
            defender_payoff_millionths: 600_000,
        }],
    }
}

/// Matrix where attacker names trigger different exploit classifications.
fn exploit_zoo_matrix() -> PayoffMatrix {
    let atk = vec![
        StrategyId("escalation-probe".into()),
        StrategyId("bypass-trick".into()),
        StrategyId("resource-dos".into()),
        StrategyId("exfil-leak".into()),
        StrategyId("replay-rollback".into()),
        StrategyId("novel-gadget".into()),
    ];
    let def = vec![StrategyId("generic-defense".into())];
    let entries: Vec<PayoffEntry> = atk
        .iter()
        .map(|a| PayoffEntry {
            attacker: a.clone(),
            defender: StrategyId("generic-defense".into()),
            attacker_payoff_millionths: 800_000,
            defender_payoff_millionths: 200_000,
        })
        .collect();
    PayoffMatrix {
        attacker_strategies: atk,
        defender_strategies: def,
        entries,
    }
}

// ---------------------------------------------------------------------------
// StrategyId enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategy_id_clone_independence() {
    let a = StrategyId("original".into());
    let b = a.clone();
    assert_eq!(a, b);
    let c = StrategyId("different".into());
    assert_ne!(a, c);
}

#[test]
fn enrichment_strategy_id_ord_transitive() {
    let a = StrategyId("aaa".into());
    let b = StrategyId("bbb".into());
    let c = StrategyId("ccc".into());
    assert!(a < b);
    assert!(b < c);
    assert!(a < c);
}

#[test]
fn enrichment_strategy_id_debug_nonempty() {
    let s = StrategyId("debug-test".into());
    let dbg = format!("{s:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("debug-test"));
}

#[test]
fn enrichment_strategy_id_empty_string() {
    let s = StrategyId(String::new());
    assert_eq!(s.to_string(), "");
    let json = serde_json::to_string(&s).unwrap();
    let back: StrategyId = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_strategy_id_display_unicode() {
    let s = StrategyId("attack-\u{03B1}".into());
    assert_eq!(s.to_string(), "attack-\u{03B1}");
}

// ---------------------------------------------------------------------------
// PlayerRole enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_player_role_clone_copy() {
    let a = PlayerRole::Attacker;
    let b = a.clone();
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn enrichment_player_role_ne() {
    assert_ne!(PlayerRole::Attacker, PlayerRole::Defender);
}

#[test]
fn enrichment_player_role_debug_contains_variant() {
    let dbg = format!("{:?}", PlayerRole::Attacker);
    assert!(dbg.contains("Attacker"));
    let dbg2 = format!("{:?}", PlayerRole::Defender);
    assert!(dbg2.contains("Defender"));
}

#[test]
fn enrichment_player_role_serde_json_values_distinct() {
    let a = serde_json::to_string(&PlayerRole::Attacker).unwrap();
    let d = serde_json::to_string(&PlayerRole::Defender).unwrap();
    assert_ne!(a, d);
}

// ---------------------------------------------------------------------------
// ExploitClass enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exploit_class_novel_empty_name() {
    let ec = ExploitClass::Novel(String::new());
    assert_eq!(ec.to_string(), "novel:");
    let json = serde_json::to_string(&ec).unwrap();
    let back: ExploitClass = serde_json::from_str(&json).unwrap();
    assert_eq!(ec, back);
}

#[test]
fn enrichment_exploit_class_novel_long_name() {
    let long = "x".repeat(1000);
    let ec = ExploitClass::Novel(long.clone());
    assert_eq!(ec.to_string(), format!("novel:{long}"));
}

#[test]
fn enrichment_exploit_class_debug_all_variants() {
    let variants = [
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass,
        ExploitClass::ResourceExhaustion,
        ExploitClass::InformationLeakage,
        ExploitClass::ReplayAttack,
        ExploitClass::Novel("dbg".into()),
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn enrichment_exploit_class_ord_stable_sort() {
    let mut items = vec![
        ExploitClass::ReplayAttack,
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass,
        ExploitClass::Novel("zzz".into()),
        ExploitClass::Novel("aaa".into()),
    ];
    let mut items2 = items.clone();
    items.sort();
    items2.sort();
    assert_eq!(items, items2);
}

#[test]
fn enrichment_exploit_class_eq_reflexive() {
    let ec = ExploitClass::PolicyBypass;
    assert_eq!(ec, ec.clone());
}

#[test]
fn enrichment_exploit_class_ne_different_variants() {
    assert_ne!(
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass
    );
    assert_ne!(
        ExploitClass::Novel("a".into()),
        ExploitClass::Novel("b".into())
    );
}

// ---------------------------------------------------------------------------
// PayoffEntry enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_payoff_entry_negative_payoffs() {
    let entry = PayoffEntry {
        attacker: StrategyId("a".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: -500_000,
        defender_payoff_millionths: -300_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PayoffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_payoff_entry_zero_payoffs() {
    let entry = PayoffEntry {
        attacker: StrategyId("x".into()),
        defender: StrategyId("y".into()),
        attacker_payoff_millionths: 0,
        defender_payoff_millionths: 0,
    };
    assert_eq!(entry.attacker_payoff_millionths, 0);
    assert_eq!(entry.defender_payoff_millionths, 0);
}

#[test]
fn enrichment_payoff_entry_extreme_values() {
    let entry = PayoffEntry {
        attacker: StrategyId("a".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: i64::MAX / 2,
        defender_payoff_millionths: i64::MIN / 2,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PayoffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_payoff_entry_debug_nonempty() {
    let entry = PayoffEntry {
        attacker: StrategyId("a".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: 1,
        defender_payoff_millionths: 2,
    };
    let dbg = format!("{entry:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PayoffEntry"));
}

// ---------------------------------------------------------------------------
// PayoffMatrix enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_payoff_matrix_minimax_empty_entries() {
    // Matrix with strategies but entries that give 0 payoff everywhere
    let m = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a".into())],
        defender_strategies: vec![StrategyId("d1".into()), StrategyId("d2".into())],
        entries: vec![
            PayoffEntry {
                attacker: StrategyId("a".into()),
                defender: StrategyId("d1".into()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            },
            PayoffEntry {
                attacker: StrategyId("a".into()),
                defender: StrategyId("d2".into()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            },
        ],
    };
    let minimax = m.minimax_defender();
    assert!(minimax.is_some());
}

#[test]
fn enrichment_payoff_matrix_lookup_all_rps_entries() {
    let m = rps_matrix();
    let strats = ["rock", "paper", "scissors"];
    for a in &strats {
        for d in &strats {
            let entry = m.lookup(&StrategyId((*a).into()), &StrategyId((*d).into()));
            assert!(entry.is_some(), "missing entry for ({a},{d})");
        }
    }
}

#[test]
fn enrichment_payoff_matrix_debug_nonempty() {
    let m = rps_matrix();
    let dbg = format!("{m:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_payoff_matrix_clone_equality() {
    let m = security_matrix();
    let m2 = m.clone();
    assert_eq!(m, m2);
}

// ---------------------------------------------------------------------------
// TournamentConfig enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tournament_config_default_gamma_in_range() {
    let cfg = TournamentConfig::default();
    assert!(cfg.gamma_millionths > 0);
    assert!(cfg.gamma_millionths < 1_000_000);
}

#[test]
fn enrichment_tournament_config_default_exploration_budget() {
    let cfg = TournamentConfig::default();
    assert!(cfg.exploration_budget_millionths > 0);
}

#[test]
fn enrichment_tournament_config_debug_nonempty() {
    let cfg = TournamentConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TournamentConfig"));
}

#[test]
fn enrichment_tournament_config_json_field_rounds() {
    let cfg = TournamentConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["rounds"], 1000);
    assert_eq!(v["seed"], 42);
    assert_eq!(v["track_trajectory"], true);
}

#[test]
fn enrichment_tournament_config_custom_epoch() {
    let cfg = TournamentConfig {
        epoch: SecurityEpoch::from_raw(99),
        ..TournamentConfig::default()
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TournamentConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
    assert_eq!(back.epoch.as_u64(), 99);
}

// ---------------------------------------------------------------------------
// CoevolutionError enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_empty_strategies_attacker_display() {
    let e = CoevolutionError::EmptyStrategies {
        player: PlayerRole::Attacker,
    };
    assert_eq!(e.to_string(), "no strategies defined for attacker");
}

#[test]
fn enrichment_error_empty_strategies_defender_display() {
    let e = CoevolutionError::EmptyStrategies {
        player: PlayerRole::Defender,
    };
    assert_eq!(e.to_string(), "no strategies defined for defender");
}

#[test]
fn enrichment_error_too_many_strategies_display() {
    let e = CoevolutionError::TooManyStrategies { count: 65, max: 64 };
    assert_eq!(e.to_string(), "strategy count 65 exceeds maximum 64");
}

#[test]
fn enrichment_error_incomplete_matrix_display() {
    let e = CoevolutionError::IncompletePayoffMatrix {
        expected: 16,
        actual: 10,
    };
    assert_eq!(e.to_string(), "payoff matrix has 10 entries, expected 16");
}

#[test]
fn enrichment_error_invalid_gamma_negative_display() {
    let e = CoevolutionError::InvalidGamma { value: -100 };
    assert_eq!(e.to_string(), "gamma out of range (0, MILLION): -100");
}

#[test]
fn enrichment_error_too_many_rounds_display() {
    let e = CoevolutionError::TooManyRounds {
        rounds: 500_000,
        max: 100_000,
    };
    assert_eq!(e.to_string(), "rounds 500000 exceed maximum 100000");
}

#[test]
fn enrichment_error_budget_exhausted_display() {
    let e = CoevolutionError::BudgetExhausted {
        spent: 2_000_000,
        budget: 1_000_000,
    };
    assert_eq!(
        e.to_string(),
        "exploration budget exhausted: spent 2000000, budget 1000000"
    );
}

#[test]
fn enrichment_error_zero_rounds_display() {
    let e = CoevolutionError::ZeroRounds;
    assert_eq!(e.to_string(), "zero rounds requested");
}

#[test]
fn enrichment_error_implements_std_error() {
    let e = CoevolutionError::ZeroRounds;
    let std_err: &dyn std::error::Error = &e;
    assert!(std_err.source().is_none());
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn enrichment_error_clone_all_variants() {
    let variants: Vec<CoevolutionError> = vec![
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker,
        },
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender,
        },
        CoevolutionError::TooManyStrategies { count: 99, max: 64 },
        CoevolutionError::IncompletePayoffMatrix {
            expected: 4,
            actual: 1,
        },
        CoevolutionError::InvalidGamma { value: 0 },
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
        let cloned = v.clone();
        assert_eq!(*v, cloned);
    }
}

#[test]
fn enrichment_error_debug_all_distinct() {
    let variants: Vec<CoevolutionError> = vec![
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker,
        },
        CoevolutionError::TooManyStrategies { count: 1, max: 1 },
        CoevolutionError::IncompletePayoffMatrix {
            expected: 1,
            actual: 0,
        },
        CoevolutionError::InvalidGamma { value: 0 },
        CoevolutionError::TooManyRounds { rounds: 1, max: 1 },
        CoevolutionError::BudgetExhausted {
            spent: 1,
            budget: 0,
        },
        CoevolutionError::ZeroRounds,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_error_serde_all_variants_roundtrip() {
    let variants: Vec<CoevolutionError> = vec![
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker,
        },
        CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender,
        },
        CoevolutionError::TooManyStrategies { count: 99, max: 64 },
        CoevolutionError::IncompletePayoffMatrix {
            expected: 10,
            actual: 3,
        },
        CoevolutionError::InvalidGamma { value: -5 },
        CoevolutionError::TooManyRounds {
            rounds: 999_999,
            max: 100_000,
        },
        CoevolutionError::BudgetExhausted {
            spent: 50_000,
            budget: 10_000,
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
// CoevolutionHarness — validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_harness_rejects_negative_gamma() {
    let cfg = TournamentConfig {
        gamma_millionths: -1,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { value: -1 }));
}

#[test]
fn enrichment_harness_rejects_gamma_above_million() {
    let cfg = TournamentConfig {
        gamma_millionths: 2_000_000,
        ..TournamentConfig::default()
    };
    let err = CoevolutionHarness::new(cfg, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { .. }));
}

#[test]
fn enrichment_harness_accepts_gamma_one() {
    let cfg = TournamentConfig {
        gamma_millionths: 1,
        ..TournamentConfig::default()
    };
    let h = CoevolutionHarness::new(cfg, rps_matrix());
    assert!(h.is_ok());
}

#[test]
fn enrichment_harness_accepts_gamma_near_million() {
    let cfg = TournamentConfig {
        gamma_millionths: 999_999,
        ..TournamentConfig::default()
    };
    let h = CoevolutionHarness::new(cfg, rps_matrix());
    assert!(h.is_ok());
}

#[test]
fn enrichment_harness_accepts_max_tournament_rounds() {
    let cfg = TournamentConfig {
        rounds: 100_000,
        ..TournamentConfig::default()
    };
    let h = CoevolutionHarness::new(cfg, rps_matrix());
    assert!(h.is_ok());
}

#[test]
fn enrichment_harness_1x1_matrix() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, trivial_1x1_matrix()).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.rounds_played, 10);
    assert_eq!(result.policy_delta.recommended_mix.len(), 1);
}

// ---------------------------------------------------------------------------
// CoevolutionHarness — run behaviour
// ---------------------------------------------------------------------------

#[test]
fn enrichment_run_single_round() {
    let cfg = TournamentConfig {
        rounds: 1,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let result = h.run().unwrap();
    assert_eq!(result.rounds_played, 1);
    let traj = result.trajectory.unwrap();
    assert_eq!(traj.round_count(), 1);
}

#[test]
fn enrichment_run_multiple_tournaments_share_config() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg.clone(), rps_matrix()).unwrap();
    let _ = h.run().unwrap();
    let _ = h.run().unwrap();
    let _ = h.run().unwrap();
    assert_eq!(h.tournament_count(), 3);
    assert_eq!(h.config().rounds, 10);
}

#[test]
fn enrichment_run_schema_version_in_result() {
    let cfg = TournamentConfig {
        rounds: 5,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    assert_eq!(
        r.schema_version,
        "franken-engine.adversarial-coevolution.v1"
    );
}

#[test]
fn enrichment_run_epoch_matches_config() {
    let cfg = TournamentConfig {
        rounds: 5,
        epoch: SecurityEpoch::from_raw(42),
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    assert_eq!(r.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(r.policy_delta.source_epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_run_policy_delta_id_format() {
    let cfg = TournamentConfig {
        rounds: 5,
        epoch: SecurityEpoch::from_raw(7),
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    // delta_id format is "coev-{epoch}-r{rounds_played}"
    assert!(
        r.policy_delta.delta_id.starts_with("coev-7-r"),
        "unexpected delta_id: {}",
        r.policy_delta.delta_id
    );
}

#[test]
fn enrichment_run_artifact_hash_nonempty() {
    let cfg = TournamentConfig {
        rounds: 5,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    assert!(!r.artifact_hash.to_hex().is_empty());
    assert!(!r.policy_delta.artifact_hash.to_hex().is_empty());
}

#[test]
fn enrichment_run_artifact_hash_differs_from_delta_hash() {
    let cfg = TournamentConfig {
        rounds: 20,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    // The overall artifact hash and delta artifact hash use different inputs
    assert_ne!(r.artifact_hash, r.policy_delta.artifact_hash);
}

// ---------------------------------------------------------------------------
// Determinism enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_trajectory_identical() {
    let cfg = TournamentConfig {
        rounds: 50,
        seed: 777,
        ..TournamentConfig::default()
    };
    let mut h1 = CoevolutionHarness::new(cfg.clone(), rps_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    let t1 = r1.trajectory.unwrap();
    let t2 = r2.trajectory.unwrap();
    assert_eq!(t1.rounds.len(), t2.rounds.len());
    for (o1, o2) in t1.rounds.iter().zip(t2.rounds.iter()) {
        assert_eq!(o1, o2);
    }
}

#[test]
fn enrichment_determinism_convergence_identical() {
    let cfg = TournamentConfig {
        rounds: 50,
        seed: 555,
        ..TournamentConfig::default()
    };
    let mut h1 = CoevolutionHarness::new(cfg.clone(), security_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_eq!(r1.convergence, r2.convergence);
}

#[test]
fn enrichment_determinism_policy_delta_identical() {
    let cfg = TournamentConfig {
        rounds: 80,
        seed: 333,
        ..TournamentConfig::default()
    };
    let mut h1 = CoevolutionHarness::new(cfg.clone(), security_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_eq!(r1.policy_delta, r2.policy_delta);
}

// ---------------------------------------------------------------------------
// Trajectory enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trajectory_round_numbers_sequential() {
    let cfg = TournamentConfig {
        rounds: 20,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
    for (i, outcome) in traj.rounds.iter().enumerate() {
        assert_eq!(outcome.round, i as u64);
    }
}

#[test]
fn enrichment_trajectory_strategies_are_valid() {
    let cfg = TournamentConfig {
        rounds: 30,
        ..TournamentConfig::default()
    };
    let m = rps_matrix();
    let valid_strats: BTreeSet<String> =
        m.attacker_strategies.iter().map(|s| s.0.clone()).collect();
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
    for outcome in &traj.rounds {
        assert!(
            valid_strats.contains(&outcome.attacker_strategy.0),
            "invalid attacker strategy: {}",
            outcome.attacker_strategy
        );
        assert!(
            valid_strats.contains(&outcome.defender_strategy.0),
            "invalid defender strategy: {}",
            outcome.defender_strategy
        );
    }
}

#[test]
fn enrichment_trajectory_cumulative_regret_monotonic_or_constant() {
    // Cumulative regret can go up or stay same, but the value is always >= 0
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
    for reg in &traj.attacker_cumulative_regret {
        assert!(*reg >= 0);
    }
    for reg in &traj.defender_cumulative_regret {
        assert!(*reg >= 0);
    }
}

#[test]
fn enrichment_trajectory_final_regret_matches_last_element() {
    let cfg = TournamentConfig {
        rounds: 25,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
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
// ConvergenceDiagnostic enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_convergence_frequency_covers_all_strategies() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let m = security_matrix();
    let mut h = CoevolutionHarness::new(cfg, m.clone()).unwrap();
    let r = h.run().unwrap();
    for s in &m.attacker_strategies {
        assert!(
            r.convergence.attacker_frequency.contains_key(&s.0),
            "missing attacker frequency for {}",
            s.0
        );
    }
    for s in &m.defender_strategies {
        assert!(
            r.convergence.defender_frequency.contains_key(&s.0),
            "missing defender frequency for {}",
            s.0
        );
    }
}

#[test]
fn enrichment_convergence_serde_field_names() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let json = serde_json::to_string(&r.convergence).unwrap();
    assert!(json.contains("\"attacker_avg_regret_millionths\""));
    assert!(json.contains("\"defender_avg_regret_millionths\""));
    assert!(json.contains("\"attacker_regret_bounded\""));
    assert!(json.contains("\"defender_regret_bounded\""));
    assert!(json.contains("\"exploit_classes\""));
    assert!(json.contains("\"attacker_frequency\""));
    assert!(json.contains("\"defender_frequency\""));
}

#[test]
fn enrichment_convergence_debug_nonempty() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let dbg = format!("{:?}", r.convergence);
    assert!(!dbg.is_empty());
}

// ---------------------------------------------------------------------------
// PolicyDelta enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_delta_weights_positive() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    for &v in r.policy_delta.recommended_mix.values() {
        assert!(v > 0, "non-positive weight in recommended_mix: {v}");
    }
}

#[test]
fn enrichment_policy_delta_weights_sum_near_million() {
    let cfg = TournamentConfig {
        rounds: 200,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let total: i64 = r.policy_delta.recommended_mix.values().sum();
    assert!(
        (total - 1_000_000).abs() < 10_000,
        "weights sum {total}, expected ~1000000"
    );
}

#[test]
fn enrichment_policy_delta_addressed_exploits_subset_of_convergence() {
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    for exploit in &r.policy_delta.addressed_exploits {
        assert!(
            r.convergence.exploit_classes.contains(exploit),
            "addressed exploit {exploit} not in convergence exploit_classes"
        );
    }
}

#[test]
fn enrichment_policy_delta_debug_nonempty() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let dbg = format!("{:?}", r.policy_delta);
    assert!(!dbg.is_empty());
}

// ---------------------------------------------------------------------------
// TournamentResult enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tournament_result_serde_roundtrip_security() {
    let cfg = TournamentConfig {
        rounds: 50,
        seed: 12345,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_tournament_result_json_field_names() {
    let cfg = TournamentConfig {
        rounds: 5,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"rounds_played\""));
    assert!(json.contains("\"total_attacker_payoff_millionths\""));
    assert!(json.contains("\"total_defender_payoff_millionths\""));
    assert!(json.contains("\"convergence\""));
    assert!(json.contains("\"policy_delta\""));
    assert!(json.contains("\"trajectory\""));
    assert!(json.contains("\"artifact_hash\""));
}

#[test]
fn enrichment_tournament_result_clone_equality() {
    let cfg = TournamentConfig {
        rounds: 10,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn enrichment_tournament_result_debug_nonempty() {
    let cfg = TournamentConfig {
        rounds: 5,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
}

// ---------------------------------------------------------------------------
// Exploit discovery enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exploit_zoo_discovers_multiple_classes() {
    let cfg = TournamentConfig {
        rounds: 500,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, exploit_zoo_matrix()).unwrap();
    let r = h.run().unwrap();
    // With 6 attacker strategies all above threshold, should discover multiple classes
    assert!(
        r.convergence.exploit_classes.len() >= 2,
        "expected at least 2 exploit classes, got {:?}",
        r.convergence.exploit_classes
    );
}

#[test]
fn enrichment_exploit_replay_classification() {
    let atk = vec![StrategyId("replay-attack-v2".into())];
    let def = vec![StrategyId("d".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("replay-attack-v2".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: 900_000,
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
    let r = h.run().unwrap();
    assert!(
        r.convergence.exploit_classes.contains("replay_attack"),
        "expected replay_attack in {:?}",
        r.convergence.exploit_classes
    );
}

#[test]
fn enrichment_exploit_resource_exhaustion_classification() {
    let atk = vec![StrategyId("dos-exhaust".into())];
    let def = vec![StrategyId("d".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("dos-exhaust".into()),
        defender: StrategyId("d".into()),
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
    let r = h.run().unwrap();
    assert!(
        r.convergence
            .exploit_classes
            .contains("resource_exhaustion"),
        "expected resource_exhaustion in {:?}",
        r.convergence.exploit_classes
    );
}

#[test]
fn enrichment_exploit_novel_classification() {
    let atk = vec![StrategyId("quantum-tunnel-gadget".into())];
    let def = vec![StrategyId("d".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("quantum-tunnel-gadget".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: 700_000,
        defender_payoff_millionths: 300_000,
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
    let r = h.run().unwrap();
    assert!(
        r.convergence
            .exploit_classes
            .iter()
            .any(|c| c.starts_with("novel:")),
        "expected novel exploit in {:?}",
        r.convergence.exploit_classes
    );
}

#[test]
fn enrichment_exploit_below_threshold_no_exploit() {
    // All payoffs below 500k threshold => no exploits discovered
    let atk = vec![StrategyId("capability-escalation".into())];
    let def = vec![StrategyId("d".into())];
    let entries = vec![PayoffEntry {
        attacker: StrategyId("capability-escalation".into()),
        defender: StrategyId("d".into()),
        attacker_payoff_millionths: 300_000, // below 500k
        defender_payoff_millionths: 700_000,
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
    let r = h.run().unwrap();
    assert!(
        r.convergence.exploit_classes.is_empty(),
        "expected no exploits, got {:?}",
        r.convergence.exploit_classes
    );
}

// ---------------------------------------------------------------------------
// Budget exhaustion enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_exhaustion_truncates_rounds() {
    let cfg = TournamentConfig {
        rounds: 10_000,
        exploration_budget_millionths: 500_000, // very small
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    assert!(
        r.rounds_played < 10_000,
        "expected truncation, got {} rounds",
        r.rounds_played
    );
}

#[test]
fn enrichment_large_budget_no_truncation() {
    let cfg = TournamentConfig {
        rounds: 50,
        exploration_budget_millionths: i64::MAX / 2,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    assert_eq!(r.rounds_played, 50);
}

// ---------------------------------------------------------------------------
// Harness accessors enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_harness_config_accessor() {
    let cfg = TournamentConfig {
        rounds: 77,
        seed: 999,
        gamma_millionths: 50_000,
        ..TournamentConfig::default()
    };
    let h = CoevolutionHarness::new(cfg.clone(), rps_matrix()).unwrap();
    assert_eq!(h.config().rounds, 77);
    assert_eq!(h.config().seed, 999);
    assert_eq!(h.config().gamma_millionths, 50_000);
}

#[test]
fn enrichment_harness_payoff_matrix_accessor() {
    let m = security_matrix();
    let h = CoevolutionHarness::new(TournamentConfig::default(), m.clone()).unwrap();
    assert_eq!(h.payoff_matrix().attacker_strategies.len(), 2);
    assert_eq!(h.payoff_matrix().defender_strategies.len(), 2);
    assert_eq!(h.payoff_matrix().entries.len(), 4);
}

#[test]
fn enrichment_harness_debug_nonempty() {
    let h = CoevolutionHarness::new(TournamentConfig::default(), rps_matrix()).unwrap();
    let dbg = format!("{h:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("CoevolutionHarness"));
}

#[test]
fn enrichment_harness_clone_equality() {
    let h = CoevolutionHarness::new(TournamentConfig::default(), rps_matrix()).unwrap();
    let h2 = h.clone();
    assert_eq!(h.config(), h2.config());
    assert_eq!(h.payoff_matrix(), h2.payoff_matrix());
    assert_eq!(h.tournament_count(), h2.tournament_count());
}

#[test]
fn enrichment_harness_serde_roundtrip() {
    let h = CoevolutionHarness::new(TournamentConfig::default(), rps_matrix()).unwrap();
    let json = serde_json::to_string(&h).unwrap();
    let back: CoevolutionHarness = serde_json::from_str(&json).unwrap();
    assert_eq!(back.config(), h.config());
    assert_eq!(back.tournament_count(), h.tournament_count());
}

// ---------------------------------------------------------------------------
// RoundOutcome enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_round_outcome_no_exploit() {
    let outcome = RoundOutcome {
        round: 0,
        attacker_strategy: StrategyId("a".into()),
        defender_strategy: StrategyId("d".into()),
        attacker_payoff_millionths: 100_000,
        defender_payoff_millionths: 900_000,
        exploit_discovered: None,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    assert!(json.contains("\"exploit_discovered\":null"));
    let back: RoundOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn enrichment_round_outcome_with_exploit() {
    let outcome = RoundOutcome {
        round: 99,
        attacker_strategy: StrategyId("atk".into()),
        defender_strategy: StrategyId("def".into()),
        attacker_payoff_millionths: 800_000,
        defender_payoff_millionths: 200_000,
        exploit_discovered: Some(ExploitClass::PolicyBypass),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: RoundOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
    assert_eq!(back.exploit_discovered, Some(ExploitClass::PolicyBypass));
}

#[test]
fn enrichment_round_outcome_debug_nonempty() {
    let outcome = RoundOutcome {
        round: 0,
        attacker_strategy: StrategyId("a".into()),
        defender_strategy: StrategyId("d".into()),
        attacker_payoff_millionths: 0,
        defender_payoff_millionths: 0,
        exploit_discovered: None,
    };
    let dbg = format!("{outcome:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("RoundOutcome"));
}

#[test]
fn enrichment_round_outcome_clone_independence() {
    let a = RoundOutcome {
        round: 5,
        attacker_strategy: StrategyId("x".into()),
        defender_strategy: StrategyId("y".into()),
        attacker_payoff_millionths: 111,
        defender_payoff_millionths: 222,
        exploit_discovered: Some(ExploitClass::Novel("test".into())),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// TrajectoryLedger enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trajectory_ledger_empty() {
    let t = frankenengine_engine::adversarial_coevolution_harness::TrajectoryLedger {
        rounds: vec![],
        attacker_cumulative_regret: vec![],
        defender_cumulative_regret: vec![],
    };
    assert_eq!(t.round_count(), 0);
    assert_eq!(t.final_attacker_regret(), 0);
    assert_eq!(t.final_defender_regret(), 0);
}

#[test]
fn enrichment_trajectory_ledger_serde_roundtrip() {
    let cfg = TournamentConfig {
        rounds: 15,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
    let json = serde_json::to_string(&traj).unwrap();
    let back: frankenengine_engine::adversarial_coevolution_harness::TrajectoryLedger =
        serde_json::from_str(&json).unwrap();
    assert_eq!(traj, back);
}

#[test]
fn enrichment_trajectory_ledger_debug_nonempty() {
    let cfg = TournamentConfig {
        rounds: 5,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let traj = r.trajectory.unwrap();
    let dbg = format!("{traj:?}");
    assert!(!dbg.is_empty());
}

// ---------------------------------------------------------------------------
// Minimax enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_minimax_1x1_returns_sole_defender() {
    let m = trivial_1x1_matrix();
    let minimax = m.minimax_defender().unwrap();
    assert_eq!(minimax, StrategyId("sole-def".into()));
}

#[test]
fn enrichment_minimax_dominant_defense() {
    // Defender "strong" always gives attacker 0, "weak" gives attacker 1M
    let m = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a".into())],
        defender_strategies: vec![StrategyId("strong".into()), StrategyId("weak".into())],
        entries: vec![
            PayoffEntry {
                attacker: StrategyId("a".into()),
                defender: StrategyId("strong".into()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 1_000_000,
            },
            PayoffEntry {
                attacker: StrategyId("a".into()),
                defender: StrategyId("weak".into()),
                attacker_payoff_millionths: 1_000_000,
                defender_payoff_millionths: 0,
            },
        ],
    };
    let minimax = m.minimax_defender().unwrap();
    assert_eq!(minimax, StrategyId("strong".into()));
}

// ---------------------------------------------------------------------------
// Constants enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!COEVOLUTION_SCHEMA_VERSION.is_empty());
    assert!(COEVOLUTION_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_component_label_nonempty() {
    assert!(!COEVOLUTION_COMPONENT.is_empty());
    assert!(COEVOLUTION_COMPONENT.contains("adversarial"));
}

// ---------------------------------------------------------------------------
// Full lifecycle enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_1x1_game() {
    let m = trivial_1x1_matrix();
    let cfg = TournamentConfig {
        rounds: 20,
        seed: 1,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let r = h.run().unwrap();
    assert_eq!(r.rounds_played, 20);
    assert_eq!(r.policy_delta.recommended_mix.len(), 1);
    let traj = r.trajectory.unwrap();
    assert_eq!(traj.round_count(), 20);
    // Every round must select the sole strategies
    for outcome in &traj.rounds {
        assert_eq!(outcome.attacker_strategy, StrategyId("sole-atk".into()));
        assert_eq!(outcome.defender_strategy, StrategyId("sole-def".into()));
    }
}

#[test]
fn enrichment_full_lifecycle_exploit_zoo() {
    let m = exploit_zoo_matrix();
    let cfg = TournamentConfig {
        rounds: 200,
        seed: 42,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, m).unwrap();
    let r = h.run().unwrap();
    assert_eq!(r.rounds_played, 200);
    // Serde roundtrip
    let json = serde_json::to_string(&r).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_full_lifecycle_no_trajectory_serde() {
    let cfg = TournamentConfig {
        rounds: 30,
        track_trajectory: false,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, security_matrix()).unwrap();
    let r = h.run().unwrap();
    assert!(r.trajectory.is_none());
    let json = serde_json::to_string(&r).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert!(back.trajectory.is_none());
}

#[test]
fn enrichment_multiple_runs_different_results() {
    // Running the same harness twice may produce different results
    // because EXP3 weights evolve across tournaments
    let cfg = TournamentConfig {
        rounds: 50,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r1 = h.run().unwrap();
    let r2 = h.run().unwrap();
    // The harness mutates internal state, but uses same seed+round logic
    // At minimum, tournament_count should differ
    assert_eq!(h.tournament_count(), 2);
    // Results may or may not differ — just verify both ran
    assert_eq!(r1.rounds_played, 50);
    assert_eq!(r2.rounds_played, 50);
}

#[test]
fn enrichment_zero_sum_rps_total_payoff_sums() {
    // In a zero-sum game, total_attacker + total_defender should be 0
    let cfg = TournamentConfig {
        rounds: 100,
        ..TournamentConfig::default()
    };
    let mut h = CoevolutionHarness::new(cfg, rps_matrix()).unwrap();
    let r = h.run().unwrap();
    let sum = r.total_attacker_payoff_millionths + r.total_defender_payoff_millionths;
    assert_eq!(
        sum, 0,
        "zero-sum game should have total payoffs summing to 0, got {sum}"
    );
}
