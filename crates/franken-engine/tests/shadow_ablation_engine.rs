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
    AnalysisConfig, Capability, EffectEdge, EffectGraph, EffectNode, EffectNodeKind,
    ManifestIntents, StaticAnalysisReport, StaticAuthorityAnalyzer,
};
use frankenengine_engine::synthesis_budget::{
    FallbackQuality, PhaseConsumption, SynthesisBudgetContract,
};

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn cap_set(names: &[&str]) -> BTreeSet<Capability> {
    names.iter().map(|name| cap(name)).collect()
}

fn make_static_report(extension_id: &str, capabilities: &[&str]) -> StaticAnalysisReport {
    let mut graph = EffectGraph::new(extension_id);
    graph.add_node(EffectNode {
        node_id: "entry".to_string(),
        kind: EffectNodeKind::Entry,
        source_location: Some("main.rs:1".to_string()),
    });

    let mut previous = "entry".to_string();
    for (index, capability) in capabilities.iter().enumerate() {
        let node_id = format!("hostcall-{index}");
        graph.add_node(EffectNode {
            node_id: node_id.clone(),
            kind: EffectNodeKind::HostcallSite {
                capability: cap(capability),
            },
            source_location: Some(format!("main.rs:{}", index + 2)),
        });
        graph.add_edge(EffectEdge {
            from: previous.clone(),
            to: node_id.clone(),
            provably_dead: false,
        });
        previous = node_id;
    }

    graph.add_node(EffectNode {
        node_id: "exit".to_string(),
        kind: EffectNodeKind::Exit,
        source_location: Some("main.rs:999".to_string()),
    });
    graph.add_edge(EffectEdge {
        from: previous,
        to: "exit".to_string(),
        provably_dead: false,
    });

    let manifest = ManifestIntents {
        extension_id: extension_id.to_string(),
        declared_capabilities: cap_set(capabilities),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(AnalysisConfig {
        time_budget_ns: 1_000_000,
        path_sensitive: true,
        zone: "test-zone".to_string(),
    });
    analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(7), 99)
        .expect("static analysis report")
}

fn base_config(extension_id: &str, seed: u64) -> ShadowAblationConfig {
    ShadowAblationConfig {
        trace_id: format!("trace-{extension_id}"),
        decision_id: format!("decision-{extension_id}"),
        policy_id: format!("policy-{extension_id}"),
        extension_id: extension_id.to_string(),
        replay_corpus_id: "replay-corpus-v1".to_string(),
        randomness_snapshot_id: "rng-snapshot-v1".to_string(),
        deterministic_seed: seed,
        strategy: AblationSearchStrategy::LatticeGreedy,
        required_invariants: BTreeSet::from([
            "no_exfiltration".to_string(),
            "deterministic_replay".to_string(),
        ]),
        max_pair_trials: 64,
        max_block_trials: 64,
        zone: "test-zone".to_string(),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x2Au8; 32])
}

#[test]
fn finds_minimal_capability_set_and_signs_transcript() {
    let extension_id = "ext-minimal";
    let report = make_static_report(extension_id, &["clock", "env", "fs_read", "net_outbound"]);
    let config = base_config(extension_id, 4242);
    let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
        .expect("engine construction");

    let required = cap_set(&["clock", "net_outbound"]);
    let result = engine
        .run(&report, &signing_key(), move |request| {
            let has_required = required.is_subset(&request.candidate_capabilities);
            Ok(ShadowAblationObservation {
                correctness_score_millionths: if has_required { 992_000 } else { 410_000 },
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), has_required),
                    ("deterministic_replay".to_string(), true),
                ]),
                risk_score_millionths: if has_required { 180_000 } else { 880_000 },
                risk_threshold_millionths: 300_000,
                consumed: PhaseConsumption {
                    time_ns: 15_000,
                    compute: 8,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: if has_required {
                    None
                } else {
                    Some("required capability missing".to_string())
                },
            })
        })
        .expect("ablation run");

    assert_eq!(
        result.minimal_capabilities,
        cap_set(&["clock", "net_outbound"])
    );
    assert!(!result.budget_exhausted);
    assert!(result.fallback.is_none());
    assert!(!result.evaluations.is_empty());

    assert!(result.logs.iter().all(|event| {
        event.trace_id == config.trace_id
            && event.decision_id == config.decision_id
            && event.policy_id == config.policy_id
            && event.component == "shadow_ablation_engine"
    }));

    result
        .transcript
        .verify_signature()
        .expect("signed transcript must verify");
}

#[test]
fn deterministic_ordering_replays_identically_for_same_seed() {
    let extension_id = "ext-deterministic";
    let report = make_static_report(
        extension_id,
        &["clock", "env", "fs_read", "net_outbound", "telemetry_emit"],
    );
    let mut config = base_config(extension_id, 77);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();

    let run_once = |cfg: ShadowAblationConfig| {
        let engine = ShadowAblationEngine::new(cfg, SynthesisBudgetContract::default())
            .expect("engine construction");
        engine
            .run(&report, &signing_key(), |request| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 500_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 900_000,
                    risk_threshold_millionths: 300_000,
                    consumed: PhaseConsumption {
                        time_ns: 5_000,
                        compute: 2,
                        depth: 1,
                    },
                    replay_pointer: format!("replay://{}", request.candidate_id),
                    evidence_pointer: format!("evidence://{}", request.candidate_id),
                    execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                    failure_detail: Some("candidate fails deterministically".to_string()),
                })
            })
            .expect("ablation run")
    };

    let first = run_once(config.clone());
    let second = run_once(config.clone());
    let mut different_seed = config.clone();
    different_seed.deterministic_seed = 78;
    let third = run_once(different_seed);

    let first_ids = first
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();
    let second_ids = second
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();
    let third_ids = third
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();

    assert_eq!(first_ids, second_ids);
    assert_ne!(first_ids, third_ids);
    assert_eq!(
        first.transcript.transcript_hash,
        second.transcript.transcript_hash
    );
    assert_eq!(
        first.transcript.unsigned_bytes(),
        second.transcript.unsigned_bytes()
    );
}

#[test]
fn adversarial_probe_behavior_forces_capability_retention() {
    let extension_id = "ext-adversarial";
    let report = make_static_report(extension_id, &["clock", "net_outbound", "env_probe"]);
    let mut config = base_config(extension_id, 101);
    config.required_invariants = BTreeSet::from([
        "no_exfiltration".to_string(),
        "anti_probe_tamper".to_string(),
    ]);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let required = cap_set(&["clock", "net_outbound"]);
    let result = engine
        .run(&report, &signing_key(), move |request| {
            let has_required = required.is_subset(&request.candidate_capabilities);
            let anti_probe = request.candidate_capabilities.contains(&cap("env_probe"));
            Ok(ShadowAblationObservation {
                correctness_score_millionths: if has_required { 970_000 } else { 300_000 },
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), has_required),
                    ("anti_probe_tamper".to_string(), anti_probe),
                ]),
                risk_score_millionths: if anti_probe { 190_000 } else { 760_000 },
                risk_threshold_millionths: 320_000,
                consumed: PhaseConsumption {
                    time_ns: 20_000,
                    compute: 9,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: if anti_probe {
                    None
                } else {
                    Some("capability-probe evasion detected".to_string())
                },
            })
        })
        .expect("ablation run");

    assert_eq!(
        result.minimal_capabilities,
        cap_set(&["clock", "net_outbound", "env_probe"])
    );
    assert!(result.evaluations.iter().any(|evaluation| {
        evaluation.failure_class == Some(AblationFailureClass::InvariantViolation)
    }));
}

#[test]
fn budget_exhaustion_returns_fail_closed_fallback() {
    let extension_id = "ext-budget";
    let report = make_static_report(extension_id, &["clock", "net_outbound", "fs_read"]);
    let mut config = base_config(extension_id, 88);
    config.max_pair_trials = 0;

    let tight_budget = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000,
        global_compute_cap: 3,
        global_depth_cap: 1,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
    };
    let engine = ShadowAblationEngine::new(config, tight_budget).expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |request| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 960_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), true),
                    ("deterministic_replay".to_string(), true),
                ]),
                risk_score_millionths: 180_000,
                risk_threshold_millionths: 300_000,
                consumed: PhaseConsumption {
                    time_ns: 2_000,
                    compute: 5,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("ablation run");

    assert!(result.budget_exhausted);
    assert_eq!(result.minimal_capabilities, report.upper_bound_capabilities);
    let fallback = result.fallback.expect("fallback must exist");
    assert_eq!(
        fallback.quality.to_string(),
        frankenengine_engine::synthesis_budget::FallbackQuality::StaticBound.to_string()
    );
    assert!(
        result
            .logs
            .iter()
            .any(|event| { event.error_code.as_deref() == Some("ablation_budget_exhausted") })
    );
    result
        .transcript
        .verify_signature()
        .expect("signed transcript must verify");
}

#[test]
fn engine_rejects_extension_mismatch() {
    let report = make_static_report("ext-report", &["clock"]);
    let config = base_config("ext-config", 1);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");
    let err = engine
        .run(&report, &signing_key(), |_request| {
            Err(ShadowAblationError::InvalidOracleResult {
                detail: "not used".to_string(),
            })
        })
        .expect_err("mismatch must fail");
    assert!(err.to_string().contains("extension mismatch"));
}

// ── Enrichment: PearlTower 2026-03-04 ────────────────────────────────

fn passing_observation(request: &ShadowAblationCandidateRequest) -> ShadowAblationObservation {
    ShadowAblationObservation {
        correctness_score_millionths: 999_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::from([
            ("no_exfiltration".to_string(), true),
            ("deterministic_replay".to_string(), true),
        ]),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 5_000,
            compute: 2,
            depth: 1,
        },
        replay_pointer: format!("replay://{}", request.candidate_id),
        evidence_pointer: format!("evidence://{}", request.candidate_id),
        execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
        failure_detail: None,
    }
}

fn failing_observation(request: &ShadowAblationCandidateRequest) -> ShadowAblationObservation {
    ShadowAblationObservation {
        correctness_score_millionths: 100_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::from([
            ("no_exfiltration".to_string(), true),
            ("deterministic_replay".to_string(), true),
        ]),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 5_000,
            compute: 2,
            depth: 1,
        },
        replay_pointer: format!("replay://{}", request.candidate_id),
        evidence_pointer: format!("evidence://{}", request.candidate_id),
        execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
        failure_detail: None,
    }
}

// ── Engine error paths ───────────────────────────────────────────────

#[test]
fn engine_rejects_empty_static_upper_bound() {
    let extension_id = "ext-empty-bound";
    let report = make_static_report(extension_id, &[]);
    let config = base_config(extension_id, 1);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");
    let err = engine
        .run(&report, &signing_key(), |_| unreachable!())
        .expect_err("empty upper bound must fail");
    assert!(matches!(
        err,
        ShadowAblationError::EmptyStaticUpperBound { .. }
    ));
    assert!(err.to_string().contains(extension_id));
}

#[test]
fn oracle_error_records_oracle_error_failure_class() {
    let extension_id = "ext-oracle-err";
    let report = make_static_report(extension_id, &["clock", "net_outbound"]);
    let mut config = base_config(extension_id, 42);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |_| {
            Err(ShadowAblationError::Budget {
                detail: "oracle boom".to_string(),
            })
        })
        .expect("run should succeed even when oracle fails");

    assert!(
        result
            .evaluations
            .iter()
            .all(|e| e.failure_class == Some(AblationFailureClass::OracleError))
    );
    assert_eq!(result.minimal_capabilities, result.initial_capabilities);
    result
        .transcript
        .verify_signature()
        .expect("valid signature");
}

#[test]
fn invalid_observation_negative_threshold_records_invalid_oracle_result() {
    let extension_id = "ext-invalid-obs";
    let report = make_static_report(extension_id, &["clock", "net"]);
    let mut config = base_config(extension_id, 10);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 900_000,
                correctness_threshold_millionths: -1, // invalid
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 0,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert!(
        result
            .evaluations
            .iter()
            .all(|e| e.failure_class == Some(AblationFailureClass::InvalidOracleResult))
    );
    assert_eq!(result.minimal_capabilities, result.initial_capabilities);
}

#[test]
fn correctness_regression_retains_all_capabilities() {
    let extension_id = "ext-correctness-reg";
    let report = make_static_report(extension_id, &["clock", "net_outbound"]);
    let mut config = base_config(extension_id, 5);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 100_000, // below threshold
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert_eq!(result.minimal_capabilities, result.initial_capabilities);
    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.failure_class == Some(AblationFailureClass::CorrectnessRegression))
    );
}

#[test]
fn risk_budget_exceeded_retains_all_capabilities() {
    let extension_id = "ext-risk-exceeded";
    let report = make_static_report(extension_id, &["clock", "fs_read"]);
    let mut config = base_config(extension_id, 6);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 999_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 999_000, // above threshold
                risk_threshold_millionths: 100_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert_eq!(result.minimal_capabilities, result.initial_capabilities);
    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.failure_class == Some(AblationFailureClass::RiskBudgetExceeded))
    );
}

#[test]
fn execution_failure_with_detail_retains_capabilities() {
    let extension_id = "ext-exec-fail";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 7);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 999_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: Some("runtime crash in shadow env".to_string()),
            })
        })
        .expect("run completes");

    assert_eq!(result.minimal_capabilities.len(), 1);
    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.failure_class == Some(AblationFailureClass::ExecutionFailure))
    );
}

// ── Strategy variants ────────────────────────────────────────────────

#[test]
fn binary_guided_strategy_uses_block_removal() {
    let extension_id = "ext-binary-guided";
    let report = make_static_report(extension_id, &["a", "b", "c", "d", "e", "f", "g", "h"]);
    let mut config = base_config(extension_id, 42);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_pair_trials = 10;
    config.max_block_trials = 10;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            // Reject single removals, accept block removals (>= 2 removed)
            let pass = req.removed_capabilities.len() >= 2;
            let score = if pass { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert_eq!(result.search_strategy, AblationSearchStrategy::BinaryGuided);
    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::BinaryBlock)
    );
    assert!(!result.budget_exhausted);
    result
        .transcript
        .verify_signature()
        .expect("valid signature");
}

#[test]
fn binary_guided_with_two_caps_skips_block_phase() {
    let extension_id = "ext-binary-two";
    let report = make_static_report(extension_id, &["x", "y"]);
    let mut config = base_config(extension_id, 5);
    config.strategy = AblationSearchStrategy::BinaryGuided;
    config.max_block_trials = 10;
    config.max_pair_trials = 10;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
        .expect("run completes");

    // With only 2 caps, highest_power_of_two_leq(2/2)=1, block_size < 2 => no block phase
    assert!(
        !result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::BinaryBlock),
        "block phase should be skipped with only 2 capabilities"
    );
}

// ── Pair removal ─────────────────────────────────────────────────────

#[test]
fn pair_removal_discovers_correlated_dependency() {
    let extension_id = "ext-pair-corr";
    let report = make_static_report(extension_id, &["a", "b", "c"]);
    let mut config = base_config(extension_id, 42);
    config.max_pair_trials = 100;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let call_count = std::cell::Cell::new(0u32);
    let result = engine
        .run(&report, &signing_key(), move |req| {
            let count = call_count.get();
            call_count.set(count + 1);
            // Reject single removals but accept pair removal
            let pass = req.removed_capabilities.len() >= 2 || count > 10;
            let score = if pass { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert!(
        result
            .evaluations
            .iter()
            .any(|e| e.search_stage == AblationSearchStage::CorrelatedPair)
    );
}

#[test]
fn max_pair_trials_limits_pair_evaluation_count() {
    let extension_id = "ext-pair-limit";
    let report = make_static_report(extension_id, &["a", "b", "c", "d"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 2;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let pair_count = std::cell::Cell::new(0u32);
    let result = engine
        .run(&report, &signing_key(), |req| {
            if req.search_stage == AblationSearchStage::CorrelatedPair {
                pair_count.set(pair_count.get() + 1);
            }
            Ok(failing_observation(req))
        })
        .expect("run completes");

    assert!(
        pair_count.get() <= 2,
        "pair phase should stop after max_pair_trials=2, got {}",
        pair_count.get()
    );
    assert_eq!(result.minimal_capabilities.len(), 4);
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn single_capability_retained_when_oracle_rejects() {
    let extension_id = "ext-single-reject";
    let report = make_static_report(extension_id, &["only_cap"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
        .expect("run completes");

    assert_eq!(result.minimal_capabilities.len(), 1);
    assert!(result.minimal_capabilities.contains(&cap("only_cap")));
}

#[test]
fn single_capability_removed_when_oracle_accepts() {
    let extension_id = "ext-single-accept";
    let report = make_static_report(extension_id, &["removable"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    assert!(
        result.minimal_capabilities.is_empty(),
        "single cap should be removed when oracle accepts"
    );
}

#[test]
fn all_capabilities_removable_reduces_to_empty_set() {
    let extension_id = "ext-all-removable";
    let report = make_static_report(extension_id, &["a", "b", "c", "d"]);
    let mut config = base_config(extension_id, 7);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    assert!(
        result.minimal_capabilities.is_empty(),
        "all caps should be removed when oracle always accepts"
    );
    assert!(!result.budget_exhausted);
    result
        .transcript
        .verify_signature()
        .expect("valid signature");
}

#[test]
fn selective_removal_keeps_essential_caps() {
    let extension_id = "ext-selective";
    let report = make_static_report(extension_id, &["clock", "env", "fs_read", "net_outbound"]);
    let mut config = base_config(extension_id, 4242);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let essential = cap_set(&["clock", "net_outbound"]);
    let result = engine
        .run(&report, &signing_key(), move |req| {
            let has_essential = essential.is_subset(&req.candidate_capabilities);
            let score = if has_essential { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert!(result.minimal_capabilities.contains(&cap("clock")));
    assert!(result.minimal_capabilities.contains(&cap("net_outbound")));
    assert!(
        result.minimal_capabilities.len() < result.initial_capabilities.len(),
        "should have removed non-essential caps"
    );
}

// ── Invariants ───────────────────────────────────────────────────────

#[test]
fn required_invariant_absent_from_observation_causes_violation() {
    let extension_id = "ext-inv-absent";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.required_invariants = BTreeSet::from(["missing_invariant".to_string()]);
    config.max_pair_trials = 0;
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 999_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::new(), // missing_invariant not present
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert_eq!(result.minimal_capabilities.len(), 1);
    assert!(result.evaluations.iter().any(|e| {
        e.failure_class == Some(AblationFailureClass::InvariantViolation)
            && e.invariant_failures
                .contains(&"missing_invariant".to_string())
    }));
}

#[test]
fn empty_required_invariants_checks_all_reported_invariants() {
    let extension_id = "ext-inv-all";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.required_invariants = BTreeSet::new(); // empty => check all
    config.max_pair_trials = 0;
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 999_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("inv_a".to_string(), true),
                    ("inv_b".to_string(), false), // fails
                ]),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 2,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    assert_eq!(result.minimal_capabilities.len(), 1);
    assert!(result.evaluations.iter().any(|e| e.failure_class
        == Some(AblationFailureClass::InvariantViolation)
        && e.invariant_failures.contains(&"inv_b".to_string())));
}

// ── Budget/fallback ──────────────────────────────────────────────────

#[test]
fn partial_ablation_fallback_quality_when_some_caps_removed_before_budget() {
    let extension_id = "ext-partial-fb";
    let report = make_static_report(extension_id, &["a", "b", "c"]);
    let mut config = base_config(extension_id, 88);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();

    let tight_budget = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 20_000,
        global_compute_cap: 10,
        global_depth_cap: 100,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
    };
    let engine = ShadowAblationEngine::new(config, tight_budget).expect("engine construction");

    let call_count = std::cell::Cell::new(0u32);
    let result = engine
        .run(&report, &signing_key(), |req| {
            let count = call_count.get();
            call_count.set(count + 1);
            // Accept first removal, then consume lots of compute to exhaust budget
            let score = if count == 0 { 999_000 } else { 100_000 };
            Ok(ShadowAblationObservation {
                correctness_score_millionths: score,
                correctness_threshold_millionths: 500_000,
                invariants: BTreeMap::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 500_000,
                consumed: PhaseConsumption {
                    time_ns: 5_000,
                    compute: 5,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", req.candidate_id),
                evidence_pointer: format!("evidence://{}", req.candidate_id),
                execution_trace_hash: ContentHash::compute(req.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("run completes");

    if result.budget_exhausted {
        let fallback = result.fallback.as_ref().expect("fallback must exist");
        if result.minimal_capabilities.len() < result.initial_capabilities.len() {
            assert_eq!(fallback.quality, FallbackQuality::PartialAblation);
        } else {
            assert_eq!(fallback.quality, FallbackQuality::StaticBound);
        }
    }
}

// ── Transcript ───────────────────────────────────────────────────────

#[test]
fn transcript_tamper_detection_catches_modified_trace_id() {
    let extension_id = "ext-tamper";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let mut result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    // Tamper with the transcript
    result.transcript.trace_id = "tampered-trace".to_string();
    let err = result
        .transcript
        .verify_signature()
        .expect_err("tampered must fail");
    assert!(
        matches!(err, ShadowAblationError::SignatureInvalid { .. })
            || matches!(err, ShadowAblationError::IntegrityFailure { .. })
    );
}

#[test]
fn transcript_verify_signature_succeeds_for_valid_run() {
    let extension_id = "ext-verify-ok";
    let report = make_static_report(extension_id, &["clock", "net"]);
    let mut config = base_config(extension_id, 42);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    result
        .transcript
        .verify_signature()
        .expect("valid signature");
    assert!(
        result
            .transcript
            .transcript_id
            .starts_with("shadow-ablation-")
    );
}

// ── Run result structure ─────────────────────────────────────────────

#[test]
fn run_result_contains_start_and_completed_log_events() {
    let extension_id = "ext-logs";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

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
    assert!(
        result
            .logs
            .iter()
            .all(|l| l.component == "shadow_ablation_engine")
    );
    assert!(result.logs.iter().all(|l| l.trace_id == config.trace_id));
}

#[test]
fn run_result_evaluation_ids_start_with_ablate_prefix() {
    let extension_id = "ext-eval-ids";
    let report = make_static_report(extension_id, &["a", "b"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
        .expect("run completes");

    assert!(!result.evaluations.is_empty());
    for eval in &result.evaluations {
        assert!(
            eval.candidate_id.starts_with("ablate-"),
            "candidate_id should start with 'ablate-', got: {}",
            eval.candidate_id
        );
    }
}

#[test]
fn run_result_trace_ids_match_config() {
    let extension_id = "ext-trace-ids";
    let report = make_static_report(extension_id, &["clock"]);
    let config = base_config(extension_id, 1);
    let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    assert_eq!(result.trace_id, config.trace_id);
    assert_eq!(result.decision_id, config.decision_id);
    assert_eq!(result.policy_id, config.policy_id);
    assert_eq!(result.extension_id, config.extension_id);
    assert_eq!(result.transcript.trace_id, config.trace_id);
    assert_eq!(result.transcript.decision_id, config.decision_id);
}

// ── Serde roundtrips ─────────────────────────────────────────────────

#[test]
fn run_result_serde_roundtrip() {
    let extension_id = "ext-serde-rr";
    let report = make_static_report(extension_id, &["clock", "net"]);
    let mut config = base_config(extension_id, 42);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    let json = serde_json::to_string(&result).expect("serialize");
    let restored: ShadowAblationRunResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn config_serde_roundtrip() {
    let config = base_config("ext-serde-cfg", 99);
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: ShadowAblationConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

#[test]
fn observation_serde_roundtrip() {
    let obs = ShadowAblationObservation {
        correctness_score_millionths: 900_000,
        correctness_threshold_millionths: 800_000,
        invariants: BTreeMap::from([("inv_a".to_string(), true), ("inv_b".to_string(), false)]),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 10_000,
            compute: 5,
            depth: 2,
        },
        replay_pointer: "replay://obs-test".to_string(),
        evidence_pointer: "evidence://obs-test".to_string(),
        execution_trace_hash: ContentHash::compute(b"obs-test"),
        failure_detail: Some("test failure".to_string()),
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let restored: ShadowAblationObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, restored);
}

#[test]
fn log_event_serde_roundtrip() {
    let event = ShadowAblationLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "shadow_ablation_engine".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("test_code".to_string()),
        search_stage: Some("single_capability".to_string()),
        candidate_id: Some("cand-1".to_string()),
        removed_capabilities: vec!["cap_a".to_string()],
        remaining_capability_count: Some(3),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: ShadowAblationLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn evaluation_record_serde_roundtrip() {
    let record = ShadowAblationEvaluationRecord {
        sequence: 1,
        candidate_id: "ablate-test".to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        removed_capabilities: BTreeSet::from([cap("a")]),
        candidate_capabilities: BTreeSet::from([cap("b"), cap("c")]),
        pass: true,
        correctness_score_millionths: 990_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::from([("inv".to_string(), true)]),
        invariant_failures: Vec::new(),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 10_000,
            compute: 5,
            depth: 2,
        },
        replay_pointer: "replay://test".to_string(),
        evidence_pointer: "evidence://test".to_string(),
        execution_trace_hash: ContentHash::compute(b"test"),
        failure_class: None,
        failure_detail: None,
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let restored: ShadowAblationEvaluationRecord =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, restored);
}

#[test]
fn candidate_request_serde_roundtrip() {
    let req = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::CorrelatedPair,
        sequence: 42,
        candidate_id: "ablate-test".to_string(),
        removed_capabilities: BTreeSet::from([cap("a"), cap("b")]),
        candidate_capabilities: BTreeSet::from([cap("c")]),
        replay_corpus_id: "corpus".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 7,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: ShadowAblationCandidateRequest =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, restored);
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors: Vec<ShadowAblationError> = vec![
        ShadowAblationError::EmptyStaticUpperBound {
            extension_id: "ext-1".to_string(),
        },
        ShadowAblationError::ExtensionMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        },
        ShadowAblationError::InvalidConfig {
            detail: "bad".to_string(),
        },
        ShadowAblationError::InvalidOracleResult {
            detail: "invalid".to_string(),
        },
        ShadowAblationError::Budget {
            detail: "exhausted".to_string(),
        },
        ShadowAblationError::SignatureFailed {
            detail: "failed".to_string(),
        },
        ShadowAblationError::SignatureInvalid {
            detail: "invalid".to_string(),
        },
        ShadowAblationError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ShadowAblationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ── Clone independence ───────────────────────────────────────────────

#[test]
fn run_result_clone_independence() {
    let extension_id = "ext-clone-rr";
    let report = make_static_report(extension_id, &["clock", "net"]);
    let mut config = base_config(extension_id, 42);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    let mut cloned = result.clone();
    cloned.trace_id = "modified-trace".to_string();
    assert_ne!(result.trace_id, cloned.trace_id);
    assert_eq!(result.decision_id, cloned.decision_id);
}

#[test]
fn config_clone_independence() {
    let config = base_config("ext-clone-cfg", 42);
    let mut cloned = config.clone();
    cloned.trace_id = "modified".to_string();
    assert_ne!(config.trace_id, cloned.trace_id);
    assert_eq!(config.decision_id, cloned.decision_id);
}

#[test]
fn observation_clone_independence() {
    let obs = ShadowAblationObservation {
        correctness_score_millionths: 900_000,
        correctness_threshold_millionths: 800_000,
        invariants: BTreeMap::from([("inv".to_string(), true)]),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 10_000,
            compute: 5,
            depth: 2,
        },
        replay_pointer: "replay://clone".to_string(),
        evidence_pointer: "evidence://clone".to_string(),
        execution_trace_hash: ContentHash::compute(b"clone"),
        failure_detail: None,
    };
    let mut cloned = obs.clone();
    cloned.correctness_score_millionths = 0;
    assert_ne!(
        obs.correctness_score_millionths,
        cloned.correctness_score_millionths
    );
}

// ── Display uniqueness ───────────────────────────────────────────────

#[test]
fn search_strategy_display_values_unique() {
    let variants = [
        AblationSearchStrategy::LatticeGreedy,
        AblationSearchStrategy::BinaryGuided,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn search_stage_display_values_unique() {
    let variants = [
        AblationSearchStage::SingleCapability,
        AblationSearchStage::CorrelatedPair,
        AblationSearchStage::BinaryBlock,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn failure_class_display_values_unique() {
    let variants = [
        AblationFailureClass::CorrectnessRegression,
        AblationFailureClass::InvariantViolation,
        AblationFailureClass::RiskBudgetExceeded,
        AblationFailureClass::ExecutionFailure,
        AblationFailureClass::OracleError,
        AblationFailureClass::InvalidOracleResult,
        AblationFailureClass::BudgetExhausted,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn error_display_contains_relevant_details() {
    let err = ShadowAblationError::ExtensionMismatch {
        expected: "ext-A".to_string(),
        found: "ext-B".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-A"));
    assert!(msg.contains("ext-B"));

    let err2 = ShadowAblationError::EmptyStaticUpperBound {
        extension_id: "ext-empty".to_string(),
    };
    assert!(err2.to_string().contains("ext-empty"));
}

// ── JSON field contracts ─────────────────────────────────────────────

#[test]
fn run_result_json_field_names() {
    let extension_id = "ext-json-rr";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    let json: serde_json::Value = serde_json::to_value(&result).expect("to_value");
    let obj = json.as_object().expect("must be object");
    let expected_fields = [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "static_report_id",
        "search_strategy",
        "initial_capabilities",
        "minimal_capabilities",
        "evaluations",
        "logs",
        "budget_exhausted",
        "fallback",
        "budget_utilization",
        "transcript",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
}

#[test]
fn config_json_field_names() {
    let config = base_config("ext-json-cfg", 42);
    let json: serde_json::Value = serde_json::to_value(&config).expect("to_value");
    let obj = json.as_object().expect("must be object");
    let expected_fields = [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "replay_corpus_id",
        "randomness_snapshot_id",
        "deterministic_seed",
        "strategy",
        "required_invariants",
        "max_pair_trials",
        "max_block_trials",
        "zone",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
    assert_eq!(obj.len(), expected_fields.len());
}

#[test]
fn evaluation_record_json_field_names() {
    let record = ShadowAblationEvaluationRecord {
        sequence: 1,
        candidate_id: "ablate-test".to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        removed_capabilities: BTreeSet::from([cap("a")]),
        candidate_capabilities: BTreeSet::from([cap("b")]),
        pass: true,
        correctness_score_millionths: 990_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::new(),
        invariant_failures: Vec::new(),
        risk_score_millionths: 50_000,
        risk_threshold_millionths: 300_000,
        consumed: PhaseConsumption {
            time_ns: 10_000,
            compute: 5,
            depth: 2,
        },
        replay_pointer: "replay://test".to_string(),
        evidence_pointer: "evidence://test".to_string(),
        execution_trace_hash: ContentHash::compute(b"test"),
        failure_class: None,
        failure_detail: None,
    };
    let json: serde_json::Value = serde_json::to_value(&record).expect("to_value");
    let obj = json.as_object().expect("must be object");
    let expected_fields = [
        "sequence",
        "candidate_id",
        "search_stage",
        "removed_capabilities",
        "candidate_capabilities",
        "pass",
        "correctness_score_millionths",
        "correctness_threshold_millionths",
        "invariants",
        "invariant_failures",
        "risk_score_millionths",
        "risk_threshold_millionths",
        "consumed",
        "replay_pointer",
        "evidence_pointer",
        "execution_trace_hash",
        "failure_class",
        "failure_detail",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
    assert_eq!(obj.len(), expected_fields.len());
}

// ── Ordering ─────────────────────────────────────────────────────────

#[test]
fn failure_class_ordering_matches_severity() {
    assert!(AblationFailureClass::CorrectnessRegression < AblationFailureClass::InvariantViolation);
    assert!(AblationFailureClass::InvariantViolation < AblationFailureClass::RiskBudgetExceeded);
    assert!(AblationFailureClass::RiskBudgetExceeded < AblationFailureClass::ExecutionFailure);
    assert!(AblationFailureClass::ExecutionFailure < AblationFailureClass::OracleError);
    assert!(AblationFailureClass::OracleError < AblationFailureClass::InvalidOracleResult);
    assert!(AblationFailureClass::InvalidOracleResult < AblationFailureClass::BudgetExhausted);
}

#[test]
fn search_strategy_ordering() {
    assert!(AblationSearchStrategy::LatticeGreedy < AblationSearchStrategy::BinaryGuided);
}

#[test]
fn search_stage_ordering() {
    assert!(AblationSearchStage::SingleCapability < AblationSearchStage::CorrelatedPair);
    assert!(AblationSearchStage::CorrelatedPair < AblationSearchStage::BinaryBlock);
}

// ── Config validation (integration) ──────────────────────────────────

#[test]
fn config_validation_rejects_empty_trace_id() {
    let mut config = base_config("ext-val", 1);
    config.trace_id.clear();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect_err("empty trace_id must be rejected");
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn config_validation_rejects_whitespace_zone() {
    let mut config = base_config("ext-val-zone", 1);
    config.zone = "   ".to_string();
    let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect_err("whitespace zone must be rejected");
    assert!(err.to_string().contains("zone"));
}

#[test]
fn config_default_constructs_valid_engine() {
    let config = ShadowAblationConfig::default();
    let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default());
    assert!(engine.is_ok());
    assert_eq!(engine.unwrap().config(), &config);
}

// ── Deterministic replay ─────────────────────────────────────────────

#[test]
fn same_seed_same_config_produces_identical_transcripts() {
    let extension_id = "ext-replay";
    let report = make_static_report(extension_id, &["a", "b", "c"]);
    let mut config = base_config(extension_id, 777);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();

    let run_once = |cfg: ShadowAblationConfig| {
        let engine = ShadowAblationEngine::new(cfg, SynthesisBudgetContract::default())
            .expect("engine construction");
        engine
            .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
            .expect("run completes")
    };

    let first = run_once(config.clone());
    let second = run_once(config.clone());

    assert_eq!(
        first.transcript.transcript_hash,
        second.transcript.transcript_hash
    );
    assert_eq!(
        first.transcript.unsigned_bytes(),
        second.transcript.unsigned_bytes()
    );
    assert_eq!(
        first
            .evaluations
            .iter()
            .map(|e| &e.candidate_id)
            .collect::<Vec<_>>(),
        second
            .evaluations
            .iter()
            .map(|e| &e.candidate_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn different_seed_produces_different_evaluation_order() {
    let extension_id = "ext-diff-seed";
    let report = make_static_report(extension_id, &["a", "b", "c", "d", "e"]);
    let mut config_a = base_config(extension_id, 100);
    config_a.max_pair_trials = 0;
    config_a.required_invariants = BTreeSet::new();
    let mut config_b = config_a.clone();
    config_b.deterministic_seed = 200;

    let run_once = |cfg: ShadowAblationConfig| {
        let engine = ShadowAblationEngine::new(cfg, SynthesisBudgetContract::default())
            .expect("engine construction");
        engine
            .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
            .expect("run completes")
    };

    let first = run_once(config_a);
    let second = run_once(config_b);

    let first_ids: Vec<_> = first.evaluations.iter().map(|e| &e.candidate_id).collect();
    let second_ids: Vec<_> = second.evaluations.iter().map(|e| &e.candidate_id).collect();
    assert_ne!(first_ids, second_ids);
}

// ── Evaluation sequence numbering ────────────────────────────────────

#[test]
fn evaluation_sequence_numbers_are_monotonically_increasing() {
    let extension_id = "ext-seq-mono";
    let report = make_static_report(extension_id, &["a", "b", "c"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 10;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
        .expect("run completes");

    for window in result.evaluations.windows(2) {
        assert!(
            window[0].sequence < window[1].sequence,
            "sequence numbers must be monotonically increasing: {} vs {}",
            window[0].sequence,
            window[1].sequence
        );
    }
}

// ── Log event structure ──────────────────────────────────────────────

#[test]
fn log_events_for_evaluated_candidates_have_search_stage() {
    let extension_id = "ext-log-stage";
    let report = make_static_report(extension_id, &["a", "b"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 5;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(failing_observation(req)))
        .expect("run completes");

    let eval_logs: Vec<_> = result
        .logs
        .iter()
        .filter(|l| l.event == "shadow_ablation_candidate_evaluated")
        .collect();
    assert!(!eval_logs.is_empty());
    for log in &eval_logs {
        assert!(
            log.search_stage.is_some(),
            "eval log must have search_stage"
        );
        assert!(
            log.candidate_id.is_some(),
            "eval log must have candidate_id"
        );
    }
}

// ── Transcript input roundtrip ───────────────────────────────────────

#[test]
fn transcript_input_serde_roundtrip() {
    let input = ShadowAblationTranscriptInput {
        trace_id: "t-rt".to_string(),
        decision_id: "d-rt".to_string(),
        policy_id: "p-rt".to_string(),
        extension_id: "e-rt".to_string(),
        static_report_id: EngineObjectId([0x11; 32]),
        replay_corpus_id: "corpus-rt".to_string(),
        randomness_snapshot_id: "rng-rt".to_string(),
        deterministic_seed: 42,
        search_strategy: AblationSearchStrategy::BinaryGuided,
        initial_capabilities: BTreeSet::from([cap("a"), cap("b")]),
        final_capabilities: BTreeSet::from([cap("a")]),
        evaluations: Vec::new(),
        fallback: None,
        budget_utilization: BTreeMap::new(),
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: ShadowAblationTranscriptInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

// ── Signed transcript serde ──────────────────────────────────────────

#[test]
fn signed_transcript_serde_roundtrip() {
    let extension_id = "ext-st-serde";
    let report = make_static_report(extension_id, &["clock"]);
    let mut config = base_config(extension_id, 1);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |req| Ok(passing_observation(req)))
        .expect("run completes");

    let json = serde_json::to_string(&result.transcript).expect("serialize");
    let restored: SignedShadowAblationTranscript =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result.transcript, restored);
}
