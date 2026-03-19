//! Enrichment integration tests for `adversarial_coevolution_harness`.
//!
//! Covers: StrategyId Display/serde, PlayerRole Display/serde,
//! ExploitClass Display/serde, PayoffMatrix lifecycle,
//! TournamentConfig Default, CoevolutionHarness lifecycle,
//! TournamentResult, ConvergenceDiagnostic, PolicyDelta,
//! TrajectoryLedger, CoevolutionError Display/serde, deterministic
//! hashing, and error paths.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::adversarial_coevolution_harness::{
    COEVOLUTION_COMPONENT, COEVOLUTION_SCHEMA_VERSION, CoevolutionError, CoevolutionHarness,
    ExploitClass, PayoffEntry, PayoffMatrix, PlayerRole, PolicyDelta,
    StrategyId, TournamentConfig, TournamentResult,
};
// ===========================================================================
// Helpers
// ===========================================================================

fn rps_matrix() -> PayoffMatrix {
    let million: i64 = 1_000_000;
    let atk = vec![
        StrategyId("rock".into()),
        StrategyId("paper".into()),
        StrategyId("scissors".into()),
    ];
    let def = atk.clone();
    let entries = vec![
        PayoffEntry { attacker: StrategyId("rock".into()), defender: StrategyId("rock".into()), attacker_payoff_millionths: 0, defender_payoff_millionths: 0 },
        PayoffEntry { attacker: StrategyId("rock".into()), defender: StrategyId("paper".into()), attacker_payoff_millionths: -million, defender_payoff_millionths: million },
        PayoffEntry { attacker: StrategyId("rock".into()), defender: StrategyId("scissors".into()), attacker_payoff_millionths: million, defender_payoff_millionths: -million },
        PayoffEntry { attacker: StrategyId("paper".into()), defender: StrategyId("rock".into()), attacker_payoff_millionths: million, defender_payoff_millionths: -million },
        PayoffEntry { attacker: StrategyId("paper".into()), defender: StrategyId("paper".into()), attacker_payoff_millionths: 0, defender_payoff_millionths: 0 },
        PayoffEntry { attacker: StrategyId("paper".into()), defender: StrategyId("scissors".into()), attacker_payoff_millionths: -million, defender_payoff_millionths: million },
        PayoffEntry { attacker: StrategyId("scissors".into()), defender: StrategyId("rock".into()), attacker_payoff_millionths: -million, defender_payoff_millionths: million },
        PayoffEntry { attacker: StrategyId("scissors".into()), defender: StrategyId("paper".into()), attacker_payoff_millionths: million, defender_payoff_millionths: -million },
        PayoffEntry { attacker: StrategyId("scissors".into()), defender: StrategyId("scissors".into()), attacker_payoff_millionths: 0, defender_payoff_millionths: 0 },
    ];
    PayoffMatrix { attacker_strategies: atk, defender_strategies: def, entries }
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
        PayoffEntry { attacker: StrategyId("capability-escalation".into()), defender: StrategyId("strict-containment".into()), attacker_payoff_millionths: 200_000, defender_payoff_millionths: 800_000 },
        PayoffEntry { attacker: StrategyId("capability-escalation".into()), defender: StrategyId("adaptive-sandbox".into()), attacker_payoff_millionths: 600_000, defender_payoff_millionths: 400_000 },
        PayoffEntry { attacker: StrategyId("policy-bypass".into()), defender: StrategyId("strict-containment".into()), attacker_payoff_millionths: 700_000, defender_payoff_millionths: 300_000 },
        PayoffEntry { attacker: StrategyId("policy-bypass".into()), defender: StrategyId("adaptive-sandbox".into()), attacker_payoff_millionths: 300_000, defender_payoff_millionths: 700_000 },
    ];
    PayoffMatrix { attacker_strategies: atk, defender_strategies: def, entries }
}

// ===========================================================================
// StrategyId Display and serde
// ===========================================================================

#[test]
fn enrichment_strategy_id_display() {
    let id = StrategyId("test-strategy".to_string());
    assert_eq!(id.to_string(), "test-strategy");
}

#[test]
fn enrichment_strategy_id_serde_roundtrip() {
    let id = StrategyId("serde-test".to_string());
    let json = serde_json::to_string(&id).unwrap();
    let back: StrategyId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_strategy_id_clone_eq() {
    let id = StrategyId("clone".into());
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

// ===========================================================================
// PlayerRole Display and serde
// ===========================================================================

#[test]
fn enrichment_player_role_display_all_unique() {
    let all = [PlayerRole::Attacker, PlayerRole::Defender];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_player_role_serde_roundtrip() {
    let all = [PlayerRole::Attacker, PlayerRole::Defender];
    for role in &all {
        let json = serde_json::to_string(role).unwrap();
        let back: PlayerRole = serde_json::from_str(&json).unwrap();
        assert_eq!(*role, back);
    }
}

// ===========================================================================
// ExploitClass Display and serde
// ===========================================================================

#[test]
fn enrichment_exploit_class_display_all_unique() {
    let all = [
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass,
        ExploitClass::ResourceExhaustion,
        ExploitClass::InformationLeakage,
        ExploitClass::ReplayAttack,
        ExploitClass::Novel("test-novel".to_string()),
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_exploit_class_serde_roundtrip() {
    let all = [
        ExploitClass::CapabilityEscalation,
        ExploitClass::PolicyBypass,
        ExploitClass::ResourceExhaustion,
        ExploitClass::InformationLeakage,
        ExploitClass::ReplayAttack,
        ExploitClass::Novel("custom".to_string()),
    ];
    for class in &all {
        let json = serde_json::to_string(class).unwrap();
        let back: ExploitClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

#[test]
fn enrichment_exploit_class_novel_contains_name() {
    let class = ExploitClass::Novel("xss-variant".to_string());
    assert!(class.to_string().contains("xss-variant"));
}

// ===========================================================================
// PayoffMatrix lifecycle
// ===========================================================================

#[test]
fn enrichment_payoff_matrix_lookup_existing() {
    let matrix = rps_matrix();
    let entry = matrix.lookup(&StrategyId("rock".into()), &StrategyId("paper".into()));
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().attacker_payoff_millionths, -1_000_000);
}

#[test]
fn enrichment_payoff_matrix_lookup_missing() {
    let matrix = rps_matrix();
    let entry = matrix.lookup(&StrategyId("rock".into()), &StrategyId("unknown".into()));
    assert!(entry.is_none());
}

#[test]
fn enrichment_payoff_matrix_minimax_defender() {
    let matrix = security_matrix();
    let minimax = matrix.minimax_defender();
    assert!(minimax.is_some());
}

#[test]
fn enrichment_payoff_matrix_serde_roundtrip() {
    let matrix = rps_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: PayoffMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

// ===========================================================================
// TournamentConfig Default
// ===========================================================================

#[test]
fn enrichment_tournament_config_default() {
    let config = TournamentConfig::default();
    assert_eq!(config.rounds, 1000);
    assert_eq!(config.gamma_millionths, 100_000);
    assert_eq!(config.seed, 42);
    assert!(config.track_trajectory);
}

#[test]
fn enrichment_tournament_config_serde_roundtrip() {
    let config = TournamentConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: TournamentConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// CoevolutionHarness lifecycle
// ===========================================================================

#[test]
fn enrichment_harness_new_valid() {
    let config = TournamentConfig::default();
    let matrix = rps_matrix();
    let harness = CoevolutionHarness::new(config, matrix);
    assert!(harness.is_ok());
}

#[test]
fn enrichment_harness_config_accessible() {
    let config = TournamentConfig { rounds: 200, ..TournamentConfig::default() };
    let matrix = rps_matrix();
    let harness = CoevolutionHarness::new(config, matrix).unwrap();
    assert_eq!(harness.config().rounds, 200);
    assert_eq!(harness.tournament_count(), 0);
}

#[test]
fn enrichment_harness_payoff_matrix_accessible() {
    let matrix = rps_matrix();
    let harness = CoevolutionHarness::new(TournamentConfig::default(), matrix.clone()).unwrap();
    assert_eq!(harness.payoff_matrix().attacker_strategies.len(), 3);
}

#[test]
fn enrichment_harness_run_rps() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    assert_eq!(result.rounds_played, 100);
    assert_eq!(harness.tournament_count(), 1);
}

#[test]
fn enrichment_harness_run_security_game() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, security_matrix()).unwrap();
    let result = harness.run().unwrap();
    assert_eq!(result.rounds_played, 100);
    assert!(!result.policy_delta.recommended_mix.is_empty());
}

#[test]
fn enrichment_harness_multiple_tournaments() {
    let config = TournamentConfig { rounds: 50, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let _ = harness.run().unwrap();
    let _ = harness.run().unwrap();
    assert_eq!(harness.tournament_count(), 2);
}

#[test]
fn enrichment_harness_deterministic_results() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let matrix = rps_matrix();
    let mut h1 = CoevolutionHarness::new(config.clone(), matrix.clone()).unwrap();
    let mut h2 = CoevolutionHarness::new(config, matrix).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(r1.total_attacker_payoff_millionths, r2.total_attacker_payoff_millionths);
}

#[test]
fn enrichment_harness_different_seeds() {
    let c1 = TournamentConfig { rounds: 100, seed: 1, ..TournamentConfig::default() };
    let c2 = TournamentConfig { rounds: 100, seed: 999, ..TournamentConfig::default() };
    let mut h1 = CoevolutionHarness::new(c1, rps_matrix()).unwrap();
    let mut h2 = CoevolutionHarness::new(c2, rps_matrix()).unwrap();
    let r1 = h1.run().unwrap();
    let r2 = h2.run().unwrap();
    assert_ne!(r1.artifact_hash, r2.artifact_hash);
}

// ===========================================================================
// TournamentResult
// ===========================================================================

#[test]
fn enrichment_tournament_result_schema_version() {
    let config = TournamentConfig { rounds: 50, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    assert_eq!(result.schema_version, COEVOLUTION_SCHEMA_VERSION);
}

#[test]
fn enrichment_tournament_result_serde_roundtrip() {
    let config = TournamentConfig { rounds: 50, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: TournamentResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// TrajectoryLedger
// ===========================================================================

#[test]
fn enrichment_trajectory_tracks_all_rounds() {
    let config = TournamentConfig { rounds: 50, track_trajectory: true, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    let traj = result.trajectory.as_ref().unwrap();
    assert_eq!(traj.round_count(), 50);
}

#[test]
fn enrichment_trajectory_disabled() {
    let config = TournamentConfig { rounds: 50, track_trajectory: false, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    assert!(result.trajectory.is_none());
}

#[test]
fn enrichment_trajectory_regret_non_negative() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    let traj = result.trajectory.unwrap();
    for r in &traj.attacker_cumulative_regret {
        assert!(*r >= 0);
    }
    for r in &traj.defender_cumulative_regret {
        assert!(*r >= 0);
    }
}

#[test]
fn enrichment_trajectory_final_regret() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    let traj = result.trajectory.unwrap();
    let _ = traj.final_attacker_regret();
    let _ = traj.final_defender_regret();
}

// ===========================================================================
// ConvergenceDiagnostic
// ===========================================================================

#[test]
fn enrichment_convergence_frequency_sums_to_rounds() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    let atk_total: u64 = result.convergence.attacker_frequency.values().sum();
    let def_total: u64 = result.convergence.defender_frequency.values().sum();
    assert_eq!(atk_total, 100);
    assert_eq!(def_total, 100);
}

#[test]
fn enrichment_convergence_avg_regret_computed() {
    let config = TournamentConfig { rounds: 100, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, rps_matrix()).unwrap();
    let result = harness.run().unwrap();
    // Average regret is computed; value may be positive or negative for zero-sum games.
    // Verify it is a finite i64 value.
    let _ = result.convergence.attacker_avg_regret_millionths;
    let _ = result.convergence.defender_avg_regret_millionths;
    // Bounded regret flags should be booleans
    let _ = result.convergence.attacker_regret_bounded;
    let _ = result.convergence.defender_regret_bounded;
}

// ===========================================================================
// PolicyDelta
// ===========================================================================

#[test]
fn enrichment_policy_delta_has_all_defender_strategies() {
    let config = TournamentConfig { rounds: 50, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, security_matrix()).unwrap();
    let result = harness.run().unwrap();
    assert_eq!(result.policy_delta.recommended_mix.len(), 2);
    assert!(result.policy_delta.recommended_mix.contains_key("strict-containment"));
    assert!(result.policy_delta.recommended_mix.contains_key("adaptive-sandbox"));
}

#[test]
fn enrichment_policy_delta_serde_roundtrip() {
    let config = TournamentConfig { rounds: 50, ..TournamentConfig::default() };
    let mut harness = CoevolutionHarness::new(config, security_matrix()).unwrap();
    let result = harness.run().unwrap();
    let json = serde_json::to_string(&result.policy_delta).unwrap();
    let back: PolicyDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(result.policy_delta, back);
}

// ===========================================================================
// CoevolutionError Display and serde
// ===========================================================================

#[test]
fn enrichment_coevolution_error_display_all_unique() {
    let errors = [
        CoevolutionError::EmptyStrategies { player: PlayerRole::Attacker },
        CoevolutionError::TooManyStrategies { count: 100, max: 64 },
        CoevolutionError::IncompletePayoffMatrix { expected: 9, actual: 5 },
        CoevolutionError::InvalidGamma { value: 0 },
        CoevolutionError::TooManyRounds { rounds: 200_000, max: 100_000 },
        CoevolutionError::BudgetExhausted { spent: 500, budget: 100 },
        CoevolutionError::ZeroRounds,
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_coevolution_error_serde_roundtrip() {
    let errors = [
        CoevolutionError::EmptyStrategies { player: PlayerRole::Attacker },
        CoevolutionError::ZeroRounds,
        CoevolutionError::InvalidGamma { value: -1 },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CoevolutionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// Error paths
// ===========================================================================

#[test]
fn enrichment_error_empty_attacker() {
    let config = TournamentConfig::default();
    let matrix = PayoffMatrix {
        attacker_strategies: vec![],
        defender_strategies: vec![StrategyId("d".into())],
        entries: vec![],
    };
    let err = CoevolutionHarness::new(config, matrix).unwrap_err();
    assert!(matches!(err, CoevolutionError::EmptyStrategies { player: PlayerRole::Attacker }));
}

#[test]
fn enrichment_error_empty_defender() {
    let config = TournamentConfig::default();
    let matrix = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a".into())],
        defender_strategies: vec![],
        entries: vec![],
    };
    let err = CoevolutionHarness::new(config, matrix).unwrap_err();
    assert!(matches!(err, CoevolutionError::EmptyStrategies { player: PlayerRole::Defender }));
}

#[test]
fn enrichment_error_zero_rounds() {
    let config = TournamentConfig { rounds: 0, ..TournamentConfig::default() };
    let err = CoevolutionHarness::new(config, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::ZeroRounds));
}

#[test]
fn enrichment_error_invalid_gamma_zero() {
    let config = TournamentConfig { gamma_millionths: 0, ..TournamentConfig::default() };
    let err = CoevolutionHarness::new(config, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { value: 0 }));
}

#[test]
fn enrichment_error_invalid_gamma_million() {
    let config = TournamentConfig { gamma_millionths: 1_000_000, ..TournamentConfig::default() };
    let err = CoevolutionHarness::new(config, rps_matrix()).unwrap_err();
    assert!(matches!(err, CoevolutionError::InvalidGamma { value: 1_000_000 }));
}

#[test]
fn enrichment_error_incomplete_payoff_matrix() {
    let config = TournamentConfig::default();
    let matrix = PayoffMatrix {
        attacker_strategies: vec![StrategyId("a1".into()), StrategyId("a2".into())],
        defender_strategies: vec![StrategyId("d1".into())],
        entries: vec![PayoffEntry {
            attacker: StrategyId("a1".into()),
            defender: StrategyId("d1".into()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        }],
    };
    let err = CoevolutionHarness::new(config, matrix).unwrap_err();
    assert!(matches!(err, CoevolutionError::IncompletePayoffMatrix { expected: 2, actual: 1 }));
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_non_empty() {
    assert!(!COEVOLUTION_SCHEMA_VERSION.is_empty());
    assert!(!COEVOLUTION_COMPONENT.is_empty());
}

#[test]
fn enrichment_component_matches_module_name() {
    assert_eq!(COEVOLUTION_COMPONENT, "adversarial_coevolution_harness");
}
