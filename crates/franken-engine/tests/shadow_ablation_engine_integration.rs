#![forbid(unsafe_code)]

//! Integration tests for `shadow_ablation_engine` module.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shadow_ablation_engine::{
    AblationFailureClass, AblationSearchStage, AblationSearchStrategy,
    ShadowAblationCandidateRequest, ShadowAblationConfig, ShadowAblationEngine,
    ShadowAblationError, ShadowAblationEvaluationRecord, ShadowAblationLogEvent,
    ShadowAblationObservation, ShadowAblationRunResult, ShadowAblationTranscriptInput,
    SignedShadowAblationTranscript,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::static_authority_analyzer::{
    AnalysisMethod, Capability, PrecisionEstimate, StaticAnalysisReport,
};
use frankenengine_engine::synthesis_budget::{PhaseConsumption, SynthesisBudgetContract};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn make_config(seed: u64) -> ShadowAblationConfig {
    ShadowAblationConfig {
        trace_id: "trace-integ".to_string(),
        decision_id: "decision-integ".to_string(),
        policy_id: "policy-integ".to_string(),
        extension_id: "ext-integ".to_string(),
        replay_corpus_id: "corpus-integ".to_string(),
        randomness_snapshot_id: "rng-integ".to_string(),
        deterministic_seed: seed,
        strategy: AblationSearchStrategy::LatticeGreedy,
        required_invariants: BTreeSet::new(),
        max_pair_trials: 256,
        max_block_trials: 128,
        zone: "test-zone".to_string(),
    }
}

fn make_static_report(extension_id: &str, caps: BTreeSet<Capability>) -> StaticAnalysisReport {
    StaticAnalysisReport {
        report_id: EngineObjectId([0xCC; 32]),
        extension_id: extension_id.to_string(),
        upper_bound_capabilities: caps,
        per_capability_evidence: Vec::new(),
        primary_analysis_method: AnalysisMethod::LatticeReachability,
        precision: PrecisionEstimate {
            upper_bound_size: 0,
            manifest_declared_size: 0,
            ratio_millionths: 1_000_000,
            excluded_by_path_sensitivity: 0,
        },
        analysis_duration_ns: 0,
        timed_out: false,
        path_sensitive: false,
        effect_graph_hash: ContentHash::compute(b"test-effect-graph"),
        manifest_hash: ContentHash::compute(b"test-manifest"),
        epoch: SecurityEpoch::GENESIS,
        timestamp_ns: 0,
        zone: "test-zone".to_string(),
    }
}

fn passing_observation() -> ShadowAblationObservation {
    ShadowAblationObservation {
        correctness_score_millionths: 999_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::new(),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 500_000,
        consumed: PhaseConsumption::zero(),
        replay_pointer: "replay://ok".to_string(),
        evidence_pointer: "evidence://ok".to_string(),
        execution_trace_hash: ContentHash::compute(b"pass"),
        failure_detail: None,
    }
}

fn failing_correctness_observation() -> ShadowAblationObservation {
    ShadowAblationObservation {
        correctness_score_millionths: 100_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::new(),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 500_000,
        consumed: PhaseConsumption::zero(),
        replay_pointer: "replay://fail".to_string(),
        evidence_pointer: "evidence://fail".to_string(),
        execution_trace_hash: ContentHash::compute(b"fail-correct"),
        failure_detail: None,
    }
}

fn make_transcript_input() -> ShadowAblationTranscriptInput {
    ShadowAblationTranscriptInput {
        trace_id: "trace-tx".to_string(),
        decision_id: "decision-tx".to_string(),
        policy_id: "policy-tx".to_string(),
        extension_id: "ext-tx".to_string(),
        static_report_id: EngineObjectId([0xAA; 32]),
        replay_corpus_id: "corpus-tx".to_string(),
        randomness_snapshot_id: "rng-tx".to_string(),
        deterministic_seed: 42,
        search_strategy: AblationSearchStrategy::LatticeGreedy,
        initial_capabilities: BTreeSet::from([cap("clock"), cap("net")]),
        final_capabilities: BTreeSet::from([cap("net")]),
        evaluations: Vec::new(),
        fallback: None,
        budget_utilization: BTreeMap::new(),
    }
}

fn sample_evaluation(cid: &str) -> ShadowAblationEvaluationRecord {
    ShadowAblationEvaluationRecord {
        sequence: 1,
        candidate_id: cid.to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        removed_capabilities: BTreeSet::from([cap("fs_read")]),
        candidate_capabilities: BTreeSet::from([cap("net_outbound")]),
        pass: true,
        correctness_score_millionths: 995_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::from([("no_exfil".to_string(), true)]),
        invariant_failures: Vec::new(),
        risk_score_millionths: 100_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 10_000,
            compute: 10,
            depth: 1,
        },
        replay_pointer: "replay://cand".to_string(),
        evidence_pointer: "evidence://cand".to_string(),
        execution_trace_hash: ContentHash::compute(b"trace-sample"),
        failure_class: None,
        failure_detail: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. AblationSearchStrategy — construction, Display, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn search_strategy_lattice_greedy_display() {
    assert_eq!(
        AblationSearchStrategy::LatticeGreedy.to_string(),
        "lattice_greedy"
    );
}

#[test]
fn search_strategy_binary_guided_display() {
    assert_eq!(
        AblationSearchStrategy::BinaryGuided.to_string(),
        "binary_guided"
    );
}

#[test]
fn search_strategy_serde_round_trip_lattice_greedy() {
    let variant = AblationSearchStrategy::LatticeGreedy;
    let json = serde_json::to_string(&variant).unwrap();
    let back: AblationSearchStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(variant, back);
}

#[test]
fn search_strategy_serde_round_trip_binary_guided() {
    let variant = AblationSearchStrategy::BinaryGuided;
    let json = serde_json::to_string(&variant).unwrap();
    let back: AblationSearchStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(variant, back);
}

#[test]
fn search_strategy_ord() {
    assert!(AblationSearchStrategy::LatticeGreedy < AblationSearchStrategy::BinaryGuided);
}

#[test]
fn search_strategy_clone_eq() {
    let a = AblationSearchStrategy::LatticeGreedy;
    let b = a;
    assert_eq!(a, b);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. AblationSearchStage — construction, Display, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn search_stage_single_capability_display() {
    assert_eq!(
        AblationSearchStage::SingleCapability.to_string(),
        "single_capability"
    );
}

#[test]
fn search_stage_correlated_pair_display() {
    assert_eq!(
        AblationSearchStage::CorrelatedPair.to_string(),
        "correlated_pair"
    );
}

#[test]
fn search_stage_binary_block_display() {
    assert_eq!(AblationSearchStage::BinaryBlock.to_string(), "binary_block");
}

#[test]
fn search_stage_serde_round_trip_all_variants() {
    for variant in [
        AblationSearchStage::SingleCapability,
        AblationSearchStage::CorrelatedPair,
        AblationSearchStage::BinaryBlock,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: AblationSearchStage = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn search_stage_ord() {
    assert!(AblationSearchStage::SingleCapability < AblationSearchStage::CorrelatedPair);
    assert!(AblationSearchStage::CorrelatedPair < AblationSearchStage::BinaryBlock);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. AblationFailureClass — construction, Display, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn failure_class_display_all_variants() {
    let cases = [
        (
            AblationFailureClass::CorrectnessRegression,
            "ablation_correctness_regression",
        ),
        (
            AblationFailureClass::InvariantViolation,
            "ablation_invariant_violation",
        ),
        (
            AblationFailureClass::RiskBudgetExceeded,
            "ablation_risk_budget_exceeded",
        ),
        (
            AblationFailureClass::ExecutionFailure,
            "ablation_execution_failure",
        ),
        (AblationFailureClass::OracleError, "ablation_oracle_error"),
        (
            AblationFailureClass::InvalidOracleResult,
            "ablation_invalid_oracle_result",
        ),
        (
            AblationFailureClass::BudgetExhausted,
            "ablation_budget_exhausted",
        ),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
    }
}

#[test]
fn failure_class_serde_round_trip_all_variants() {
    let all = [
        AblationFailureClass::CorrectnessRegression,
        AblationFailureClass::InvariantViolation,
        AblationFailureClass::RiskBudgetExceeded,
        AblationFailureClass::ExecutionFailure,
        AblationFailureClass::OracleError,
        AblationFailureClass::InvalidOracleResult,
        AblationFailureClass::BudgetExhausted,
    ];
    for variant in all {
        let json = serde_json::to_string(&variant).unwrap();
        let back: AblationFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn failure_class_ord() {
    assert!(AblationFailureClass::CorrectnessRegression < AblationFailureClass::InvariantViolation);
    assert!(AblationFailureClass::OracleError < AblationFailureClass::BudgetExhausted);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. ShadowAblationConfig — construction, Default, serde, validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn config_default_has_valid_fields() {
    let config = ShadowAblationConfig::default();
    assert!(!config.trace_id.is_empty());
    assert!(!config.decision_id.is_empty());
    assert!(!config.policy_id.is_empty());
    assert!(!config.extension_id.is_empty());
    assert!(!config.replay_corpus_id.is_empty());
    assert!(!config.randomness_snapshot_id.is_empty());
    assert!(!config.zone.is_empty());
    assert_eq!(config.strategy, AblationSearchStrategy::LatticeGreedy);
    assert_eq!(config.max_pair_trials, 256);
    assert_eq!(config.max_block_trials, 128);
}

#[test]
fn config_serde_round_trip() {
    let config = make_config(42);
    let json = serde_json::to_string(&config).unwrap();
    let back: ShadowAblationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn config_default_serde_round_trip() {
    let config = ShadowAblationConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ShadowAblationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn config_validation_rejects_empty_trace_id() {
    let mut config = make_config(1);
    config.trace_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn config_validation_rejects_whitespace_trace_id() {
    let mut config = make_config(1);
    config.trace_id = "   ".to_string();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn config_validation_rejects_empty_decision_id() {
    let mut config = make_config(1);
    config.decision_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn config_validation_rejects_empty_policy_id() {
    let mut config = make_config(1);
    config.policy_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn config_validation_rejects_empty_extension_id() {
    let mut config = make_config(1);
    config.extension_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("extension_id"));
}

#[test]
fn config_validation_rejects_empty_replay_corpus_id() {
    let mut config = make_config(1);
    config.replay_corpus_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("replay_corpus_id"));
}

#[test]
fn config_validation_rejects_empty_randomness_snapshot_id() {
    let mut config = make_config(1);
    config.randomness_snapshot_id = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("randomness_snapshot_id"));
}

#[test]
fn config_validation_rejects_empty_zone() {
    let mut config = make_config(1);
    config.zone = String::new();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
    assert!(err.to_string().contains("zone"));
}

#[test]
fn config_validation_all_empty_fields_yield_invalid_config_variant() {
    let fields = [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "replay_corpus_id",
        "randomness_snapshot_id",
        "zone",
    ];
    for field in fields {
        let mut config = make_config(1);
        match field {
            "trace_id" => config.trace_id.clear(),
            "decision_id" => config.decision_id.clear(),
            "policy_id" => config.policy_id.clear(),
            "extension_id" => config.extension_id.clear(),
            "replay_corpus_id" => config.replay_corpus_id.clear(),
            "randomness_snapshot_id" => config.randomness_snapshot_id.clear(),
            "zone" => config.zone.clear(),
            _ => unreachable!(),
        }
        let err =
            ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap_err();
        assert!(
            matches!(err, ShadowAblationError::InvalidConfig { .. }),
            "expected InvalidConfig for field {field}, got: {err:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. ShadowAblationObservation — validation edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn observation_serde_round_trip() {
    let obs = passing_observation();
    let json = serde_json::to_string(&obs).unwrap();
    let back: ShadowAblationObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn observation_with_failure_detail_serde() {
    let mut obs = passing_observation();
    obs.failure_detail = Some("some failure".to_string());
    let json = serde_json::to_string(&obs).unwrap();
    let back: ShadowAblationObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs.failure_detail, back.failure_detail);
}

#[test]
fn observation_negative_correctness_threshold_rejected() {
    let obs = ShadowAblationObservation {
        correctness_threshold_millionths: -1,
        ..passing_observation()
    };
    // Run the engine with this observation to trigger validation
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a"), cap("b")]));
    let key = SigningKey::from_bytes([0x01; 32]);
    let result = engine.run(&report, &key, |_| Ok(obs.clone())).unwrap();
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

#[test]
fn observation_negative_risk_threshold_rejected() {
    let obs = ShadowAblationObservation {
        risk_threshold_millionths: -1,
        ..passing_observation()
    };
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);
    let result = engine.run(&report, &key, |_| Ok(obs.clone())).unwrap();
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

#[test]
fn observation_empty_replay_pointer_rejected() {
    let obs = ShadowAblationObservation {
        replay_pointer: String::new(),
        ..passing_observation()
    };
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);
    let result = engine.run(&report, &key, |_| Ok(obs.clone())).unwrap();
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

#[test]
fn observation_empty_evidence_pointer_rejected() {
    let obs = ShadowAblationObservation {
        evidence_pointer: String::new(),
        ..passing_observation()
    };
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);
    let result = engine.run(&report, &key, |_| Ok(obs.clone())).unwrap();
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

#[test]
fn observation_zero_trace_hash_rejected() {
    let obs = ShadowAblationObservation {
        execution_trace_hash: ContentHash([0u8; 32]),
        ..passing_observation()
    };
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);
    let result = engine.run(&report, &key, |_| Ok(obs.clone())).unwrap();
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. ShadowAblationEngine::new() and config accessor
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_new_succeeds_with_valid_config() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    assert_eq!(engine.config(), &config);
}

#[test]
fn engine_new_rejects_invalid_config() {
    let mut config = make_config(1);
    config.trace_id.clear();
    let result = ShadowAblationEngine::new(config, SynthesisBudgetContract::default());
    assert!(result.is_err());
}

#[test]
fn engine_config_accessor_returns_exact_ref() {
    let config = make_config(99);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    assert_eq!(engine.config().deterministic_seed, 99);
    assert_eq!(engine.config().trace_id, "trace-integ");
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Engine::run() — oracle happy path (all caps removed)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_oracle_happy_path_removes_all_removable_capabilities() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c")]);
    let report = make_static_report(&config.extension_id, caps.clone());
    let key = SigningKey::from_bytes([0x01; 32]);

    // Oracle always passes -- all capabilities can be removed
    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    // All capabilities should be removed since every ablation succeeds
    assert!(
        result.minimal_capabilities.len() < caps.len(),
        "expected some caps removed, got: {:?}",
        result.minimal_capabilities
    );
    assert!(!result.budget_exhausted);
    assert!(result.fallback.is_none());
    // Transcript should verify
    result.transcript.verify_signature().unwrap();
}

#[test]
fn run_oracle_happy_path_with_single_cap_removes_it() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    // Single cap removed since oracle passes
    assert!(result.minimal_capabilities.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 7b. Engine::run() — oracle error path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_oracle_error_records_oracle_error_failure_class() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a"), cap("b")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Err(ShadowAblationError::Budget {
                detail: "oracle boom".to_string(),
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::OracleError) })
    );
    // Capabilities unchanged
    assert_eq!(result.minimal_capabilities, result.initial_capabilities);
}

#[test]
fn run_oracle_error_preserves_all_capabilities() {
    let config = make_config(7);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("x"), cap("y"), cap("z")]);
    let report = make_static_report(&config.extension_id, caps.clone());
    let key = SigningKey::from_bytes([0x02; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Err(ShadowAblationError::InvalidOracleResult {
                detail: "bad observation".to_string(),
            })
        })
        .unwrap();

    assert_eq!(result.minimal_capabilities, caps);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7c. Engine::run() — invalid observations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_invalid_observation_all_rejected_as_invalid_oracle_result() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(
        &config.extension_id,
        BTreeSet::from([cap("fs"), cap("net")]),
    );
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                correctness_threshold_millionths: -1,
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .all(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Engine::run() — LatticeGreedy and BinaryGuided strategies
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_lattice_greedy_strategy_basic() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c")]);
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    assert_eq!(
        result.search_strategy,
        AblationSearchStrategy::LatticeGreedy
    );
    // All single removals failed, capabilities remain
    assert_eq!(result.minimal_capabilities.len(), 3);
}

#[test]
fn run_binary_guided_strategy_uses_block_stage() {
    let mut config = make_config(42);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_pair_trials = 10;
    config.max_block_trials = 10;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([
        cap("a"),
        cap("b"),
        cap("c"),
        cap("d"),
        cap("e"),
        cap("f"),
        cap("g"),
        cap("h"),
    ]);
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x02; 32]);

    // Reject single removals, accept blocks of size >= 2
    let result = engine
        .run(&report, &key, |req| {
            let pass = req.removed_capabilities.len() >= 2;
            let score = if pass { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                ..passing_observation()
            })
        })
        .unwrap();

    assert_eq!(result.search_strategy, AblationSearchStrategy::BinaryGuided);
    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::BinaryBlock)
    );
}

#[test]
fn run_binary_guided_with_all_passing_oracle() {
    let mut config = make_config(99);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_pair_trials = 10;
    config.max_block_trials = 10;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c"), cap("d")]);
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x03; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    // All caps should be removed since oracle always passes
    assert!(result.minimal_capabilities.is_empty());
    assert!(!result.budget_exhausted);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Search stages in evaluation records
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn single_capability_stage_appears_in_evaluations() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::SingleCapability)
    );
}

#[test]
fn correlated_pair_stage_appears_in_evaluations() {
    let mut config = make_config(42);
    config.max_pair_trials = 100;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(
        &config.extension_id,
        BTreeSet::from([cap("a"), cap("b"), cap("c")]),
    );
    let key = SigningKey::from_bytes([0x03; 32]);

    // Reject single removals, accept pair removal
    let result = engine
        .run(&report, &key, |req| {
            let pass = req.removed_capabilities.len() >= 2;
            let score = if pass { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::CorrelatedPair)
    );
}

#[test]
fn binary_block_stage_appears_in_evaluations() {
    let mut config = make_config(42);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_block_trials = 50;
    config.max_pair_trials = 10;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps: BTreeSet<_> = (0..8).map(|i| cap(&format!("cap_{i}"))).collect();
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x04; 32]);

    // Reject everything (so all stages are tried)
    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::BinaryBlock)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Failure classes triggered by specific oracle responses
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn failure_class_correctness_regression() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 100_000,
                correctness_threshold_millionths: 900_000,
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::CorrectnessRegression) })
    );
}

#[test]
fn failure_class_invariant_violation() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                invariants: BTreeMap::from([("must_hold".to_string(), false)]),
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::InvariantViolation) })
    );
}

#[test]
fn failure_class_invariant_violation_with_required_invariants() {
    let mut config = make_config(1);
    config.required_invariants = BTreeSet::from(["must_hold".to_string()]);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    // Oracle returns invariants without "must_hold" => treated as missing => fails
    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                invariants: BTreeMap::new(), // required invariant missing
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::InvariantViolation) })
    );
}

#[test]
fn failure_class_risk_budget_exceeded() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                risk_score_millionths: 999_000,
                risk_threshold_millionths: 100_000,
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::RiskBudgetExceeded) })
    );
}

#[test]
fn failure_class_execution_failure() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                failure_detail: Some("crash".to_string()),
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::ExecutionFailure) })
    );
}

#[test]
fn failure_class_oracle_error() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Err(ShadowAblationError::Budget {
                detail: "oracle crash".to_string(),
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::OracleError) })
    );
}

#[test]
fn failure_class_invalid_oracle_result() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                execution_trace_hash: ContentHash([0u8; 32]),
                ..passing_observation()
            })
        })
        .unwrap();

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| { e.failure_class == Some(AblationFailureClass::InvalidOracleResult) })
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. SignedShadowAblationTranscript
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn transcript_create_signed_and_verify() {
    let key = SigningKey::from_bytes([0x41; 32]);
    let input = make_transcript_input();
    let transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();

    assert!(transcript.transcript_id.starts_with("shadow-ablation-"));
    assert_eq!(transcript.trace_id, "trace-tx");
    assert_eq!(transcript.decision_id, "decision-tx");
    transcript.verify_signature().unwrap();
}

#[test]
fn transcript_verify_signature_roundtrip() {
    let key = SigningKey::from_bytes([0x42; 32]);
    let input = make_transcript_input();
    let transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    // Verify twice to ensure idempotence
    transcript.verify_signature().unwrap();
    transcript.verify_signature().unwrap();
}

#[test]
fn transcript_unsigned_bytes_deterministic() {
    let key = SigningKey::from_bytes([0x50; 32]);
    let t1 = SignedShadowAblationTranscript::create_signed(make_transcript_input(), &key).unwrap();
    let t2 = SignedShadowAblationTranscript::create_signed(make_transcript_input(), &key).unwrap();

    assert_eq!(t1.unsigned_bytes(), t2.unsigned_bytes());
    assert_eq!(t1.transcript_hash, t2.transcript_hash);
    assert_eq!(t1.transcript_id, t2.transcript_id);
}

#[test]
fn transcript_unsigned_bytes_differ_with_different_input() {
    let key = SigningKey::from_bytes([0x50; 32]);
    let input_a = make_transcript_input();
    let mut input_b = make_transcript_input();
    input_b.trace_id = "trace-different".to_string();

    let t1 = SignedShadowAblationTranscript::create_signed(input_a, &key).unwrap();
    let t2 = SignedShadowAblationTranscript::create_signed(input_b, &key).unwrap();

    assert_ne!(t1.unsigned_bytes(), t2.unsigned_bytes());
    assert_ne!(t1.transcript_hash, t2.transcript_hash);
}

#[test]
fn transcript_tamper_detection_extension_id() {
    let key = SigningKey::from_bytes([0x42; 32]);
    let input = make_transcript_input();
    let mut transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    transcript.extension_id = "ext-evil".to_string();
    let err = transcript.verify_signature().unwrap_err();
    assert!(
        matches!(err, ShadowAblationError::SignatureInvalid { .. })
            || matches!(err, ShadowAblationError::IntegrityFailure { .. })
    );
}

#[test]
fn transcript_tamper_detection_trace_id() {
    let key = SigningKey::from_bytes([0x42; 32]);
    let input = make_transcript_input();
    let mut transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    transcript.trace_id = "tampered-trace".to_string();
    assert!(transcript.verify_signature().is_err());
}

#[test]
fn transcript_tamper_detection_seed() {
    let key = SigningKey::from_bytes([0x42; 32]);
    let input = make_transcript_input();
    let mut transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    transcript.deterministic_seed = 99999;
    assert!(transcript.verify_signature().is_err());
}

#[test]
fn transcript_tamper_detection_capabilities() {
    let key = SigningKey::from_bytes([0x42; 32]);
    let input = make_transcript_input();
    let mut transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    transcript.final_capabilities.insert(cap("extra"));
    assert!(transcript.verify_signature().is_err());
}

#[test]
fn transcript_with_evaluations() {
    let key = SigningKey::from_bytes([0x43; 32]);
    let mut input = make_transcript_input();
    input.evaluations = vec![sample_evaluation("cand-1"), sample_evaluation("cand-2")];
    let transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    transcript.verify_signature().unwrap();
    assert_eq!(transcript.evaluations.len(), 2);
}

#[test]
fn transcript_serde_round_trip() {
    let key = SigningKey::from_bytes([0x44; 32]);
    let transcript =
        SignedShadowAblationTranscript::create_signed(make_transcript_input(), &key).unwrap();
    let json = serde_json::to_string(&transcript).unwrap();
    let back: SignedShadowAblationTranscript = serde_json::from_str(&json).unwrap();
    assert_eq!(transcript, back);
    back.verify_signature().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. ShadowAblationError Display formatting all 8 variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_empty_static_upper_bound() {
    let err = ShadowAblationError::EmptyStaticUpperBound {
        extension_id: "ext-1".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-1"));
    assert!(msg.contains("empty"));
}

#[test]
fn error_display_extension_mismatch() {
    let err = ShadowAblationError::ExtensionMismatch {
        expected: "ext-a".to_string(),
        found: "ext-b".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-a"));
    assert!(msg.contains("ext-b"));
    assert!(msg.contains("mismatch"));
}

#[test]
fn error_display_invalid_config() {
    let err = ShadowAblationError::InvalidConfig {
        detail: "bad field".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("bad field"));
    assert!(msg.contains("invalid"));
}

#[test]
fn error_display_invalid_oracle_result() {
    let err = ShadowAblationError::InvalidOracleResult {
        detail: "negative threshold".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("negative threshold"));
    assert!(msg.contains("oracle"));
}

#[test]
fn error_display_budget() {
    let err = ShadowAblationError::Budget {
        detail: "compute exceeded".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("compute exceeded"));
    assert!(msg.contains("budget"));
}

#[test]
fn error_display_signature_failed() {
    let err = ShadowAblationError::SignatureFailed {
        detail: "key error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("key error"));
    assert!(msg.contains("sign"));
}

#[test]
fn error_display_signature_invalid() {
    let err = ShadowAblationError::SignatureInvalid {
        detail: "tampered".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("tampered"));
    assert!(msg.contains("invalid"));
}

#[test]
fn error_display_integrity_failure() {
    let err = ShadowAblationError::IntegrityFailure {
        expected: "aabb".to_string(),
        actual: "ccdd".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("aabb"));
    assert!(msg.contains("ccdd"));
    assert!(msg.contains("hash mismatch"));
}

#[test]
fn error_serde_round_trip_all_variants() {
    let variants: Vec<ShadowAblationError> = vec![
        ShadowAblationError::EmptyStaticUpperBound {
            extension_id: "ext".to_string(),
        },
        ShadowAblationError::ExtensionMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        },
        ShadowAblationError::InvalidConfig {
            detail: "bad".to_string(),
        },
        ShadowAblationError::InvalidOracleResult {
            detail: "neg".to_string(),
        },
        ShadowAblationError::Budget {
            detail: "exceeded".to_string(),
        },
        ShadowAblationError::SignatureFailed {
            detail: "fail".to_string(),
        },
        ShadowAblationError::SignatureInvalid {
            detail: "inv".to_string(),
        },
        ShadowAblationError::IntegrityFailure {
            expected: "aa".to_string(),
            actual: "bb".to_string(),
        },
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ShadowAblationError = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn error_is_std_error() {
    let err = ShadowAblationError::Budget {
        detail: "test".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Determinism: same seed produces same run results
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_same_seed_same_result() {
    let config = make_config(42);
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c")]);

    let run_once = || {
        let engine =
            ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
        let report = make_static_report(&config.extension_id, caps.clone());
        let key = SigningKey::from_bytes([0x01; 32]);
        engine
            .run(&report, &key, |_| Ok(passing_observation()))
            .unwrap()
    };

    let r1 = run_once();
    let r2 = run_once();

    assert_eq!(r1.minimal_capabilities, r2.minimal_capabilities);
    assert_eq!(r1.evaluations.len(), r2.evaluations.len());
    for (e1, e2) in r1.evaluations.iter().zip(r2.evaluations.iter()) {
        assert_eq!(e1.candidate_id, e2.candidate_id);
        assert_eq!(e1.pass, e2.pass);
        assert_eq!(e1.search_stage, e2.search_stage);
    }
    assert_eq!(r1.transcript.transcript_hash, r2.transcript.transcript_hash);
}

#[test]
fn determinism_different_seed_may_differ() {
    let run_with_seed = |seed: u64| {
        let config = make_config(seed);
        let engine =
            ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
        let caps = BTreeSet::from([cap("a"), cap("b"), cap("c"), cap("d"), cap("e")]);
        let report = make_static_report(&config.extension_id, caps);
        let key = SigningKey::from_bytes([0x01; 32]);
        // Reject all so we can compare candidate ordering
        engine
            .run(&report, &key, |_| Ok(failing_correctness_observation()))
            .unwrap()
    };

    let r1 = run_with_seed(1);
    let r2 = run_with_seed(999);

    // With different seeds, candidate ordering should differ,
    // which means candidate_ids differ
    let ids_1: Vec<_> = r1.evaluations.iter().map(|e| &e.candidate_id).collect();
    let ids_2: Vec<_> = r2.evaluations.iter().map(|e| &e.candidate_id).collect();
    assert_ne!(ids_1, ids_2);
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. Cross-concern integration scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_rejects_empty_static_upper_bound() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::new());
    let key = SigningKey::from_bytes([0x01; 32]);

    let err = engine.run(&report, &key, |_| unreachable!()).unwrap_err();
    assert!(matches!(
        err,
        ShadowAblationError::EmptyStaticUpperBound { .. }
    ));
}

#[test]
fn run_rejects_extension_mismatch() {
    let config = make_config(1);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report("wrong-ext", BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let err = engine.run(&report, &key, |_| unreachable!()).unwrap_err();
    assert!(matches!(err, ShadowAblationError::ExtensionMismatch { .. }));
}

#[test]
fn run_result_has_correct_ids() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    assert_eq!(result.trace_id, "trace-integ");
    assert_eq!(result.decision_id, "decision-integ");
    assert_eq!(result.policy_id, "policy-integ");
    assert_eq!(result.extension_id, "ext-integ");
    assert_eq!(result.static_report_id, EngineObjectId([0xCC; 32]));
}

#[test]
fn run_result_logs_start_and_complete() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    assert!(
        result
            .logs
            .iter()
            .any(|l| l.event == "shadow_ablation_started")
    );
    assert!(
        result
            .logs
            .iter()
            .any(|l| l.event == "shadow_ablation_completed")
    );
}

#[test]
fn run_result_transcript_verifies() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a"), cap("b")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    result.transcript.verify_signature().unwrap();
}

#[test]
fn run_result_serde_round_trip() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: ShadowAblationRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.trace_id, back.trace_id);
    assert_eq!(result.minimal_capabilities, back.minimal_capabilities);
    assert_eq!(result.evaluations.len(), back.evaluations.len());
}

#[test]
fn run_evaluation_records_have_non_empty_candidate_ids() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a"), cap("b")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    for eval in &result.evaluations {
        assert!(!eval.candidate_id.is_empty());
        assert!(eval.candidate_id.starts_with("ablate-"));
    }
}

#[test]
fn run_with_invariant_failure_detail_in_record() {
    let mut config = make_config(1);
    config.required_invariants = BTreeSet::from(["inv_a".to_string(), "inv_b".to_string()]);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                invariants: BTreeMap::from([
                    ("inv_a".to_string(), true),
                    ("inv_b".to_string(), false),
                ]),
                ..passing_observation()
            })
        })
        .unwrap();

    let eval = &result.evaluations[0];
    assert!(eval.invariant_failures.contains(&"inv_b".to_string()));
    assert!(!eval.invariant_failures.contains(&"inv_a".to_string()));
}

#[test]
fn run_pair_trials_capped_by_max() {
    let mut config = make_config(42);
    config.max_pair_trials = 2;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c"), cap("d")]);
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x01; 32]);

    // All fail so pair phase is entered
    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    let pair_count = result
        .evaluations
        .iter()
        .filter(|e| e.search_stage == AblationSearchStage::CorrelatedPair)
        .count();
    assert!(
        pair_count as u64 <= config.max_pair_trials,
        "pair_count={pair_count} > max_pair_trials={}",
        config.max_pair_trials
    );
}

#[test]
fn run_block_trials_capped_by_max() {
    let mut config = make_config(42);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_block_trials = 2;
    config.max_pair_trials = 0;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps: BTreeSet<_> = (0..8).map(|i| cap(&format!("c{i}"))).collect();
    let report = make_static_report(&config.extension_id, caps);
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    let block_count = result
        .evaluations
        .iter()
        .filter(|e| e.search_stage == AblationSearchStage::BinaryBlock)
        .count();
    assert!(
        block_count as u64 <= config.max_block_trials,
        "block_count={block_count} > max_block_trials={}",
        config.max_block_trials
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Struct serde round-trips (additional)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn evaluation_record_serde_round_trip() {
    let record = sample_evaluation("test-cand");
    let json = serde_json::to_string(&record).unwrap();
    let back: ShadowAblationEvaluationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn evaluation_record_with_failure_serde_round_trip() {
    let mut record = sample_evaluation("fail-cand");
    record.pass = false;
    record.failure_class = Some(AblationFailureClass::CorrectnessRegression);
    record.failure_detail = Some("score too low".to_string());
    let json = serde_json::to_string(&record).unwrap();
    let back: ShadowAblationEvaluationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn log_event_serde_round_trip() {
    let event = ShadowAblationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "shadow_ablation_engine".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        search_stage: Some("single_capability".to_string()),
        candidate_id: Some("cand-1".to_string()),
        removed_capabilities: vec!["cap_a".to_string()],
        remaining_capability_count: Some(3),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ShadowAblationLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn log_event_with_error_code_serde_round_trip() {
    let event = ShadowAblationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "shadow_ablation_engine".to_string(),
        event: "fail_event".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("ablation_oracle_error".to_string()),
        search_stage: None,
        candidate_id: None,
        removed_capabilities: Vec::new(),
        remaining_capability_count: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ShadowAblationLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn candidate_request_serde_round_trip() {
    let req = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::CorrelatedPair,
        sequence: 5,
        candidate_id: "ablate-test".to_string(),
        removed_capabilities: BTreeSet::from([cap("a"), cap("b")]),
        candidate_capabilities: BTreeSet::from([cap("c")]),
        replay_corpus_id: "corpus".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 99,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: ShadowAblationCandidateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn transcript_input_serde_round_trip() {
    let input = make_transcript_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: ShadowAblationTranscriptInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases and special scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn run_with_zero_max_pair_and_block_trials() {
    let mut config = make_config(42);
    config.max_pair_trials = 0;
    config.max_block_trials = 0;

    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a"), cap("b")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    // All single attempts fail => no pair/block trials
    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    // Only single-stage evaluations
    assert!(
        result
            .evaluations
            .iter()
            .all(|e| e.search_stage == AblationSearchStage::SingleCapability)
    );
}

#[test]
fn run_single_cap_all_rejected_keeps_original() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    assert_eq!(result.minimal_capabilities, BTreeSet::from([cap("only")]));
}

#[test]
fn run_oracle_receives_correct_request_fields() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |req| {
            assert_eq!(req.trace_id, "trace-integ");
            assert_eq!(req.decision_id, "decision-integ");
            assert_eq!(req.policy_id, "policy-integ");
            assert_eq!(req.extension_id, "ext-integ");
            assert_eq!(req.replay_corpus_id, "corpus-integ");
            assert_eq!(req.randomness_snapshot_id, "rng-integ");
            assert_eq!(req.deterministic_seed, 42);
            assert!(req.sequence > 0);
            assert!(!req.candidate_id.is_empty());
            Ok(passing_observation())
        })
        .unwrap();

    assert!(result.minimal_capabilities.is_empty());
}

#[test]
fn run_result_initial_capabilities_match_report() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let caps = BTreeSet::from([cap("a"), cap("b"), cap("c")]);
    let report = make_static_report(&config.extension_id, caps.clone());
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(failing_correctness_observation()))
        .unwrap();

    assert_eq!(result.initial_capabilities, caps);
}

#[test]
fn run_non_budget_exhausted_has_no_fallback() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    assert!(!result.budget_exhausted);
    assert!(result.fallback.is_none());
}

#[test]
fn config_with_required_invariants_serde_round_trip() {
    let mut config = make_config(42);
    config.required_invariants = BTreeSet::from([
        "inv_a".to_string(),
        "inv_b".to_string(),
        "inv_c".to_string(),
    ]);
    let json = serde_json::to_string(&config).unwrap();
    let back: ShadowAblationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.required_invariants, back.required_invariants);
}

#[test]
fn run_execution_failure_detail_propagated_to_record() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                failure_detail: Some("segfault in sandbox".to_string()),
                ..passing_observation()
            })
        })
        .unwrap();

    let eval = &result.evaluations[0];
    assert_eq!(
        eval.failure_class,
        Some(AblationFailureClass::ExecutionFailure)
    );
    assert_eq!(eval.failure_detail.as_deref(), Some("segfault in sandbox"));
}

#[test]
fn run_log_events_have_component_field() {
    let config = make_config(42);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("a")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| Ok(passing_observation()))
        .unwrap();

    for log in &result.logs {
        assert_eq!(log.component, "shadow_ablation_engine");
    }
}

#[test]
fn run_correctness_detail_message_when_no_failure_detail() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 100_000,
                correctness_threshold_millionths: 900_000,
                ..passing_observation()
            })
        })
        .unwrap();

    let eval = &result.evaluations[0];
    assert!(
        eval.failure_detail
            .as_ref()
            .unwrap()
            .contains("correctness")
    );
    assert!(
        eval.failure_detail
            .as_ref()
            .unwrap()
            .contains("below threshold")
    );
}

#[test]
fn run_risk_detail_message_when_no_failure_detail() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                risk_score_millionths: 999_000,
                risk_threshold_millionths: 100_000,
                ..passing_observation()
            })
        })
        .unwrap();

    let eval = &result.evaluations[0];
    assert!(eval.failure_detail.as_ref().unwrap().contains("risk"));
    assert!(
        eval.failure_detail
            .as_ref()
            .unwrap()
            .contains("above threshold")
    );
}

#[test]
fn run_invariant_failure_detail_message() {
    let config = make_config(1);
    let engine =
        ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default()).unwrap();
    let report = make_static_report(&config.extension_id, BTreeSet::from([cap("x")]));
    let key = SigningKey::from_bytes([0x01; 32]);

    let result = engine
        .run(&report, &key, |_| {
            Ok(ShadowAblationObservation {
                invariants: BTreeMap::from([("safety".to_string(), false)]),
                ..passing_observation()
            })
        })
        .unwrap();

    let eval = &result.evaluations[0];
    assert!(
        eval.failure_detail
            .as_ref()
            .unwrap()
            .contains("invariants failed")
    );
    assert!(eval.failure_detail.as_ref().unwrap().contains("safety"));
}

#[test]
fn config_default_passes_validation() {
    let config = ShadowAblationConfig::default();
    ShadowAblationEngine::new(config, SynthesisBudgetContract::default()).unwrap();
}
