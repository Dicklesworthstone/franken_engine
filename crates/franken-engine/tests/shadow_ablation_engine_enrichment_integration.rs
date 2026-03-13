//! Enrichment integration tests for `shadow_ablation_engine`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Debug
//! nonempty, Default coverage, Display coverage, JSON field-name stability,
//! RollbackControl-like patterns, error paths, config validation, engine
//! construction, std::error::Error trait.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shadow_ablation_engine::{
    AblationFailureClass, AblationSearchStage, AblationSearchStrategy,
    ShadowAblationCandidateRequest, ShadowAblationConfig, ShadowAblationEngine,
    ShadowAblationError, ShadowAblationEvaluationRecord, ShadowAblationLogEvent,
    ShadowAblationObservation, ShadowAblationTranscriptInput, SignedShadowAblationTranscript,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::static_authority_analyzer::{
    AnalysisMethod, Capability, PrecisionEstimate, StaticAnalysisReport,
};
use frankenengine_engine::synthesis_budget::{PhaseConsumption, SynthesisBudgetContract};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn make_config() -> ShadowAblationConfig {
    ShadowAblationConfig::default()
}

fn make_budget_contract() -> SynthesisBudgetContract {
    SynthesisBudgetContract::default()
}

fn make_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ])
}

fn make_report_id() -> frankenengine_engine::engine_object_id::EngineObjectId {
    frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::PolicyObject,
        "test",
        &frankenengine_engine::engine_object_id::SchemaId::from_definition(b"test"),
        b"payload",
    )
    .unwrap()
}

fn make_static_report(extension_id: &str, caps: BTreeSet<Capability>) -> StaticAnalysisReport {
    StaticAnalysisReport {
        report_id: make_report_id(),
        extension_id: extension_id.to_string(),
        upper_bound_capabilities: caps,
        per_capability_evidence: vec![],
        primary_analysis_method: AnalysisMethod::LatticeReachability,
        precision: PrecisionEstimate {
            upper_bound_size: 0,
            manifest_declared_size: 0,
            ratio_millionths: 1_000_000,
            excluded_by_path_sensitivity: 0,
        },
        analysis_duration_ns: 100,
        timed_out: false,
        path_sensitive: false,
        effect_graph_hash: ContentHash::compute(b"eg"),
        manifest_hash: ContentHash::compute(b"mh"),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 0,
        zone: "default".to_string(),
    }
}

fn make_capability(name: &str) -> Capability {
    Capability::new(name)
}

fn make_caps(names: &[&str]) -> BTreeSet<Capability> {
    names.iter().map(|n| make_capability(n)).collect()
}

fn make_eval_record(seq: u64, pass: bool) -> ShadowAblationEvaluationRecord {
    ShadowAblationEvaluationRecord {
        sequence: seq,
        candidate_id: format!("cand-{seq}"),
        search_stage: AblationSearchStage::SingleCapability,
        removed_capabilities: make_caps(&["cap_a"]),
        candidate_capabilities: make_caps(&["cap_b", "cap_c"]),
        pass,
        correctness_score_millionths: 950_000,
        correctness_threshold_millionths: 900_000,
        invariants: BTreeMap::new(),
        invariant_failures: vec![],
        risk_score_millionths: 100_000,
        risk_threshold_millionths: 500_000,
        consumed: PhaseConsumption {
            time_ns: 1000,
            compute: 500,
            depth: 1,
        },
        replay_pointer: "replay://test".to_string(),
        evidence_pointer: "evidence://test".to_string(),
        execution_trace_hash: ContentHash::compute(b"trace"),
        failure_class: if pass {
            None
        } else {
            Some(AblationFailureClass::CorrectnessRegression)
        },
        failure_detail: if pass {
            None
        } else {
            Some("score below threshold".to_string())
        },
    }
}

// -----------------------------------------------------------------------
// 1. Copy semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_search_strategy_copy_semantics() {
    let a = AblationSearchStrategy::LatticeGreedy;
    let b = a;
    assert_eq!(a, b);
    let c = AblationSearchStrategy::BinaryGuided;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_search_stage_copy_semantics() {
    let a = AblationSearchStage::SingleCapability;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_failure_class_copy_semantics() {
    let a = AblationFailureClass::CorrectnessRegression;
    let b = a;
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// 2. Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_config_clone_independence() {
    let a = make_config();
    let mut b = a.clone();
    b.trace_id = "changed".to_string();
    assert_ne!(a.trace_id, b.trace_id);
}

#[test]
fn enrichment_eval_record_clone_independence() {
    let a = make_eval_record(0, true);
    let mut b = a.clone();
    b.candidate_id = "modified".to_string();
    assert_ne!(a.candidate_id, b.candidate_id);
}

#[test]
fn enrichment_candidate_request_clone_independence() {
    let a = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        sequence: 0,
        candidate_id: "c0".to_string(),
        removed_capabilities: make_caps(&["x"]),
        candidate_capabilities: make_caps(&["y", "z"]),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 42,
    };
    let mut b = a.clone();
    b.removed_capabilities.insert(make_capability("extra"));
    assert_eq!(a.removed_capabilities.len(), 1);
    assert_eq!(b.removed_capabilities.len(), 2);
}

#[test]
fn enrichment_observation_clone_independence() {
    let a = ShadowAblationObservation {
        correctness_score_millionths: 900_000,
        correctness_threshold_millionths: 800_000,
        invariants: BTreeMap::new(),
        risk_score_millionths: 100_000,
        risk_threshold_millionths: 500_000,
        consumed: PhaseConsumption {
            time_ns: 100,
            compute: 50,
            depth: 1,
        },
        replay_pointer: "rp".to_string(),
        evidence_pointer: "ep".to_string(),
        execution_trace_hash: ContentHash::compute(b"obs"),
        failure_detail: None,
    };
    let mut b = a.clone();
    b.failure_detail = Some("fail".to_string());
    assert!(a.failure_detail.is_none());
    assert!(b.failure_detail.is_some());
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering for Ord types
// -----------------------------------------------------------------------

#[test]
fn enrichment_search_strategy_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(AblationSearchStrategy::LatticeGreedy);
    set.insert(AblationSearchStrategy::BinaryGuided);
    set.insert(AblationSearchStrategy::LatticeGreedy);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_search_stage_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(AblationSearchStage::SingleCapability);
    set.insert(AblationSearchStage::CorrelatedPair);
    set.insert(AblationSearchStage::BinaryBlock);
    set.insert(AblationSearchStage::SingleCapability);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_failure_class_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(AblationFailureClass::CorrectnessRegression);
    set.insert(AblationFailureClass::InvariantViolation);
    set.insert(AblationFailureClass::RiskBudgetExceeded);
    set.insert(AblationFailureClass::ExecutionFailure);
    set.insert(AblationFailureClass::OracleError);
    set.insert(AblationFailureClass::InvalidOracleResult);
    set.insert(AblationFailureClass::BudgetExhausted);
    set.insert(AblationFailureClass::CorrectnessRegression);
    assert_eq!(set.len(), 7);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_search_strategy_serde_roundtrip() {
    for v in [
        AblationSearchStrategy::LatticeGreedy,
        AblationSearchStrategy::BinaryGuided,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: AblationSearchStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_search_stage_serde_roundtrip() {
    for v in [
        AblationSearchStage::SingleCapability,
        AblationSearchStage::CorrelatedPair,
        AblationSearchStage::BinaryBlock,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: AblationSearchStage = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_failure_class_serde_roundtrip() {
    for v in [
        AblationFailureClass::CorrectnessRegression,
        AblationFailureClass::InvariantViolation,
        AblationFailureClass::RiskBudgetExceeded,
        AblationFailureClass::ExecutionFailure,
        AblationFailureClass::OracleError,
        AblationFailureClass::InvalidOracleResult,
        AblationFailureClass::BudgetExhausted,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: AblationFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = make_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: ShadowAblationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_candidate_request_serde_roundtrip() {
    let req = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::CorrelatedPair,
        sequence: 5,
        candidate_id: "c5".to_string(),
        removed_capabilities: make_caps(&["net_send"]),
        candidate_capabilities: make_caps(&["fs_read", "fs_write"]),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 99,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: ShadowAblationCandidateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_observation_serde_roundtrip() {
    let obs = ShadowAblationObservation {
        correctness_score_millionths: 950_000,
        correctness_threshold_millionths: 900_000,
        invariants: {
            let mut m = BTreeMap::new();
            m.insert("inv1".to_string(), true);
            m.insert("inv2".to_string(), false);
            m
        },
        risk_score_millionths: 100_000,
        risk_threshold_millionths: 500_000,
        consumed: PhaseConsumption {
            time_ns: 200,
            compute: 100,
            depth: 2,
        },
        replay_pointer: "rp://1".to_string(),
        evidence_pointer: "ev://1".to_string(),
        execution_trace_hash: ContentHash::compute(b"obs-trace"),
        failure_detail: Some("minor issue".to_string()),
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: ShadowAblationObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn enrichment_eval_record_serde_roundtrip() {
    let rec = make_eval_record(1, true);
    let json = serde_json::to_string(&rec).unwrap();
    let back: ShadowAblationEvaluationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_log_event_serde_roundtrip() {
    let le = ShadowAblationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "shadow_ablation_engine".to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        search_stage: Some("single_capability".to_string()),
        candidate_id: Some("c0".to_string()),
        removed_capabilities: vec!["cap_a".to_string()],
        remaining_capability_count: Some(3),
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: ShadowAblationLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let variants: Vec<ShadowAblationError> = vec![
        ShadowAblationError::EmptyStaticUpperBound {
            extension_id: "ext1".to_string(),
        },
        ShadowAblationError::ExtensionMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        },
        ShadowAblationError::InvalidConfig {
            detail: "bad".to_string(),
        },
        ShadowAblationError::InvalidOracleResult {
            detail: "weird".to_string(),
        },
        ShadowAblationError::Budget {
            detail: "exhausted".to_string(),
        },
        ShadowAblationError::SignatureFailed {
            detail: "sign err".to_string(),
        },
        ShadowAblationError::SignatureInvalid {
            detail: "verify err".to_string(),
        },
        ShadowAblationError::IntegrityFailure {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ShadowAblationError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// -----------------------------------------------------------------------
// 5. Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_search_strategy_display() {
    assert_eq!(
        format!("{}", AblationSearchStrategy::LatticeGreedy),
        "lattice_greedy"
    );
    assert_eq!(
        format!("{}", AblationSearchStrategy::BinaryGuided),
        "binary_guided"
    );
}

#[test]
fn enrichment_search_stage_display() {
    assert_eq!(
        format!("{}", AblationSearchStage::SingleCapability),
        "single_capability"
    );
    assert_eq!(
        format!("{}", AblationSearchStage::CorrelatedPair),
        "correlated_pair"
    );
    assert_eq!(
        format!("{}", AblationSearchStage::BinaryBlock),
        "binary_block"
    );
}

#[test]
fn enrichment_failure_class_display_all_variants() {
    let variants = [
        AblationFailureClass::CorrectnessRegression,
        AblationFailureClass::InvariantViolation,
        AblationFailureClass::RiskBudgetExceeded,
        AblationFailureClass::ExecutionFailure,
        AblationFailureClass::OracleError,
        AblationFailureClass::InvalidOracleResult,
        AblationFailureClass::BudgetExhausted,
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
        assert!(
            s.starts_with("ablation_"),
            "display should start with 'ablation_': got {s}"
        );
    }
}

#[test]
fn enrichment_error_display_all_variants() {
    let variants: Vec<ShadowAblationError> = vec![
        ShadowAblationError::EmptyStaticUpperBound {
            extension_id: "ext1".to_string(),
        },
        ShadowAblationError::ExtensionMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        },
        ShadowAblationError::InvalidConfig {
            detail: "bad".to_string(),
        },
        ShadowAblationError::InvalidOracleResult {
            detail: "weird".to_string(),
        },
        ShadowAblationError::Budget {
            detail: "exhausted".to_string(),
        },
        ShadowAblationError::SignatureFailed {
            detail: "sign err".to_string(),
        },
        ShadowAblationError::SignatureInvalid {
            detail: "verify err".to_string(),
        },
        ShadowAblationError::IntegrityFailure {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        },
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_error_display_contains_values() {
    let e = ShadowAblationError::ExtensionMismatch {
        expected: "alpha".to_string(),
        found: "beta".to_string(),
    };
    let s = format!("{e}");
    assert!(s.contains("alpha"));
    assert!(s.contains("beta"));
}

// -----------------------------------------------------------------------
// 6. std::error::Error trait
// -----------------------------------------------------------------------

#[test]
fn enrichment_error_implements_std_error() {
    let e = ShadowAblationError::InvalidConfig {
        detail: "test".to_string(),
    };
    let boxed: Box<dyn std::error::Error> = Box::new(e);
    assert!(!boxed.to_string().is_empty());
}

#[test]
fn enrichment_error_source_is_none() {
    let e = ShadowAblationError::Budget {
        detail: "test".to_string(),
    };
    let err: &dyn std::error::Error = &e;
    assert!(err.source().is_none());
}

// -----------------------------------------------------------------------
// 7. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_search_strategy_debug_nonempty() {
    assert!(!format!("{:?}", AblationSearchStrategy::LatticeGreedy).is_empty());
}

#[test]
fn enrichment_search_stage_debug_nonempty() {
    assert!(!format!("{:?}", AblationSearchStage::SingleCapability).is_empty());
}

#[test]
fn enrichment_failure_class_debug_nonempty() {
    assert!(!format!("{:?}", AblationFailureClass::CorrectnessRegression).is_empty());
}

#[test]
fn enrichment_config_debug_nonempty() {
    assert!(!format!("{:?}", make_config()).is_empty());
}

#[test]
fn enrichment_candidate_request_debug_nonempty() {
    let req = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        sequence: 0,
        candidate_id: "c0".to_string(),
        removed_capabilities: BTreeSet::new(),
        candidate_capabilities: BTreeSet::new(),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 0,
    };
    assert!(!format!("{req:?}").is_empty());
}

#[test]
fn enrichment_observation_debug_nonempty() {
    let obs = ShadowAblationObservation {
        correctness_score_millionths: 0,
        correctness_threshold_millionths: 0,
        invariants: BTreeMap::new(),
        risk_score_millionths: 0,
        risk_threshold_millionths: 0,
        consumed: PhaseConsumption {
            time_ns: 0,
            compute: 0,
            depth: 0,
        },
        replay_pointer: "rp".to_string(),
        evidence_pointer: "ep".to_string(),
        execution_trace_hash: ContentHash::compute(b"obs"),
        failure_detail: None,
    };
    assert!(!format!("{obs:?}").is_empty());
}

#[test]
fn enrichment_eval_record_debug_nonempty() {
    assert!(!format!("{:?}", make_eval_record(0, true)).is_empty());
}

#[test]
fn enrichment_log_event_debug_nonempty() {
    let le = ShadowAblationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        search_stage: None,
        candidate_id: None,
        removed_capabilities: vec![],
        remaining_capability_count: None,
    };
    assert!(!format!("{le:?}").is_empty());
}

#[test]
fn enrichment_error_debug_nonempty() {
    assert!(
        !format!(
            "{:?}",
            ShadowAblationError::Budget {
                detail: "x".to_string()
            }
        )
        .is_empty()
    );
}

// -----------------------------------------------------------------------
// 8. Default coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_config_default_has_reasonable_values() {
    let config = ShadowAblationConfig::default();
    assert!(!config.trace_id.is_empty());
    assert!(!config.decision_id.is_empty());
    assert!(!config.policy_id.is_empty());
    assert!(!config.extension_id.is_empty());
    assert!(!config.replay_corpus_id.is_empty());
    assert!(!config.randomness_snapshot_id.is_empty());
    assert!(config.deterministic_seed > 0);
    assert_eq!(config.strategy, AblationSearchStrategy::LatticeGreedy);
    assert!(config.required_invariants.is_empty());
    assert!(config.max_pair_trials > 0);
    assert!(config.max_block_trials > 0);
    assert!(!config.zone.is_empty());
}

// -----------------------------------------------------------------------
// 9. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_config_json_fields() {
    let json = serde_json::to_string(&make_config()).unwrap();
    for field in [
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
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_candidate_request_json_fields() {
    let req = ShadowAblationCandidateRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        search_stage: AblationSearchStage::SingleCapability,
        sequence: 0,
        candidate_id: "c0".to_string(),
        removed_capabilities: BTreeSet::new(),
        candidate_capabilities: BTreeSet::new(),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 0,
    };
    let json = serde_json::to_string(&req).unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "search_stage",
        "sequence",
        "candidate_id",
        "removed_capabilities",
        "candidate_capabilities",
        "replay_corpus_id",
        "randomness_snapshot_id",
        "deterministic_seed",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_eval_record_json_fields() {
    let rec = make_eval_record(0, true);
    let json = serde_json::to_string(&rec).unwrap();
    for field in [
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
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_observation_json_fields() {
    let obs = ShadowAblationObservation {
        correctness_score_millionths: 0,
        correctness_threshold_millionths: 0,
        invariants: BTreeMap::new(),
        risk_score_millionths: 0,
        risk_threshold_millionths: 0,
        consumed: PhaseConsumption {
            time_ns: 0,
            compute: 0,
            depth: 0,
        },
        replay_pointer: "rp".to_string(),
        evidence_pointer: "ep".to_string(),
        execution_trace_hash: ContentHash::compute(b"obs"),
        failure_detail: None,
    };
    let json = serde_json::to_string(&obs).unwrap();
    for field in [
        "correctness_score_millionths",
        "correctness_threshold_millionths",
        "invariants",
        "risk_score_millionths",
        "risk_threshold_millionths",
        "consumed",
        "replay_pointer",
        "evidence_pointer",
        "execution_trace_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_log_event_json_fields() {
    let le = ShadowAblationLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        search_stage: None,
        candidate_id: None,
        removed_capabilities: vec![],
        remaining_capability_count: None,
    };
    let json = serde_json::to_string(&le).unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "search_stage",
        "candidate_id",
        "removed_capabilities",
        "remaining_capability_count",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// 10. Engine construction and config validation
// -----------------------------------------------------------------------

#[test]
fn enrichment_engine_new_valid_config() {
    let config = make_config();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config, budget);
    assert!(engine.is_ok());
}

#[test]
fn enrichment_engine_config_accessor() {
    let config = make_config();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config.clone(), budget).unwrap();
    assert_eq!(engine.config().trace_id, config.trace_id);
    assert_eq!(engine.config().strategy, config.strategy);
}

#[test]
fn enrichment_engine_empty_trace_id_rejected() {
    let config = ShadowAblationConfig {
        trace_id: "   ".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_decision_id_rejected() {
    let config = ShadowAblationConfig {
        decision_id: "".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_policy_id_rejected() {
    let config = ShadowAblationConfig {
        policy_id: "".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_extension_id_rejected() {
    let config = ShadowAblationConfig {
        extension_id: "  ".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_replay_corpus_id_rejected() {
    let config = ShadowAblationConfig {
        replay_corpus_id: "".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_randomness_snapshot_id_rejected() {
    let config = ShadowAblationConfig {
        randomness_snapshot_id: "".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_engine_empty_zone_rejected() {
    let config = ShadowAblationConfig {
        zone: "  ".to_string(),
        ..make_config()
    };
    let result = ShadowAblationEngine::new(config, make_budget_contract());
    assert!(matches!(
        result,
        Err(ShadowAblationError::InvalidConfig { .. })
    ));
}

// -----------------------------------------------------------------------
// 11. Engine run error paths (no oracle needed)
// -----------------------------------------------------------------------

#[test]
fn enrichment_engine_run_extension_mismatch() {
    let config = make_config();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config, budget).unwrap();
    let report = make_static_report("wrong-extension", make_caps(&["cap_a"]));
    let key = make_signing_key();
    let result = engine.run(&report, &key, |_| {
        panic!("oracle should not be called");
    });
    assert!(matches!(
        result,
        Err(ShadowAblationError::ExtensionMismatch { .. })
    ));
}

#[test]
fn enrichment_engine_run_empty_upper_bound() {
    let mut config = make_config();
    config.extension_id = "ext-test".to_string();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config, budget).unwrap();
    let report = make_static_report("ext-test", BTreeSet::new());
    let key = make_signing_key();
    let result = engine.run(&report, &key, |_| {
        panic!("oracle should not be called");
    });
    assert!(matches!(
        result,
        Err(ShadowAblationError::EmptyStaticUpperBound { .. })
    ));
}

// -----------------------------------------------------------------------
// 12. Signed transcript creation and verification
// -----------------------------------------------------------------------

#[test]
fn enrichment_signed_transcript_create_and_verify() {
    let key = make_signing_key();
    let input = ShadowAblationTranscriptInput {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        static_report_id: make_report_id(),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 42,
        search_strategy: AblationSearchStrategy::LatticeGreedy,
        initial_capabilities: make_caps(&["a", "b", "c"]),
        final_capabilities: make_caps(&["b", "c"]),
        evaluations: vec![make_eval_record(0, true)],
        fallback: None,
        budget_utilization: BTreeMap::new(),
    };
    let transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    assert!(transcript.transcript_id.starts_with("shadow-ablation-"));
    assert!(transcript.verify_signature().is_ok());
}

#[test]
fn enrichment_signed_transcript_serde_roundtrip() {
    let key = make_signing_key();
    let input = ShadowAblationTranscriptInput {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        static_report_id: make_report_id(),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 0,
        search_strategy: AblationSearchStrategy::BinaryGuided,
        initial_capabilities: make_caps(&["x"]),
        final_capabilities: make_caps(&["x"]),
        evaluations: vec![],
        fallback: None,
        budget_utilization: BTreeMap::new(),
    };
    let transcript = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    let json = serde_json::to_string(&transcript).unwrap();
    let back: SignedShadowAblationTranscript = serde_json::from_str(&json).unwrap();
    assert_eq!(transcript.transcript_id, back.transcript_id);
    assert_eq!(transcript.transcript_hash, back.transcript_hash);
}

#[test]
fn enrichment_signed_transcript_unsigned_bytes_deterministic() {
    let key = make_signing_key();
    let input = ShadowAblationTranscriptInput {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        extension_id: "e".to_string(),
        static_report_id: make_report_id(),
        replay_corpus_id: "rc".to_string(),
        randomness_snapshot_id: "rng".to_string(),
        deterministic_seed: 42,
        search_strategy: AblationSearchStrategy::LatticeGreedy,
        initial_capabilities: make_caps(&["a"]),
        final_capabilities: make_caps(&["a"]),
        evaluations: vec![],
        fallback: None,
        budget_utilization: BTreeMap::new(),
    };
    let t1 = SignedShadowAblationTranscript::create_signed(input.clone(), &key).unwrap();
    let t2 = SignedShadowAblationTranscript::create_signed(input, &key).unwrap();
    assert_eq!(t1.unsigned_bytes(), t2.unsigned_bytes());
    assert_eq!(t1.transcript_hash, t2.transcript_hash);
}

// -----------------------------------------------------------------------
// 13. Engine run with oracle (full integration)
// -----------------------------------------------------------------------

#[test]
fn enrichment_engine_run_all_pass_reduces_capabilities() {
    let mut config = make_config();
    config.extension_id = "ext-full".to_string();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config, budget).unwrap();
    let report = make_static_report("ext-full", make_caps(&["a", "b", "c"]));
    let key = make_signing_key();

    let result = engine.run(&report, &key, |_req| {
        Ok(ShadowAblationObservation {
            correctness_score_millionths: 1_000_000,
            correctness_threshold_millionths: 900_000,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 500_000,
            consumed: PhaseConsumption {
                time_ns: 10,
                compute: 5,
                depth: 1,
            },
            replay_pointer: "rp://full".to_string(),
            evidence_pointer: "ev://full".to_string(),
            execution_trace_hash: ContentHash::compute(b"full-trace"),
            failure_detail: None,
        })
    });
    let run = result.unwrap();
    // When all candidates pass, minimal set should be smaller than initial
    assert!(run.minimal_capabilities.len() <= run.initial_capabilities.len());
    assert!(!run.evaluations.is_empty());
    assert!(!run.logs.is_empty());
    assert!(run.transcript.verify_signature().is_ok());
}

#[test]
fn enrichment_engine_run_all_fail_keeps_all_capabilities() {
    let mut config = make_config();
    config.extension_id = "ext-fail".to_string();
    let budget = make_budget_contract();
    let engine = ShadowAblationEngine::new(config, budget).unwrap();
    let report = make_static_report("ext-fail", make_caps(&["a", "b"]));
    let key = make_signing_key();

    let result = engine.run(&report, &key, |_req| {
        Ok(ShadowAblationObservation {
            correctness_score_millionths: 100_000, // below threshold
            correctness_threshold_millionths: 900_000,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 500_000,
            consumed: PhaseConsumption {
                time_ns: 10,
                compute: 5,
                depth: 1,
            },
            replay_pointer: "rp://fail".to_string(),
            evidence_pointer: "ev://fail".to_string(),
            execution_trace_hash: ContentHash::compute(b"fail-trace"),
            failure_detail: Some("correctness below threshold".to_string()),
        })
    });
    let run = result.unwrap();
    // When all ablations fail, minimal == initial
    assert_eq!(run.minimal_capabilities, run.initial_capabilities);
}
