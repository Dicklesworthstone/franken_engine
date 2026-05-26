//! Deterministic shadow ablation engine for PLAS capability tightening.
//!
//! This module implements the dynamic complement to static authority analysis:
//! it starts from the static upper-bound capability set and runs deterministic
//! subtraction experiments in a shadow environment to find a tighter minimal
//! set that still preserves correctness, policy invariants, and risk budgets.
//!
//! Plan reference: Section 10.15 item 3 (`bd-1kdc`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};
use crate::static_authority_analyzer::{Capability, StaticAnalysisReport};
use crate::synthesis_budget::{
    BudgetDimension, BudgetError, BudgetMonitor, ExhaustionReason, FallbackQuality, FallbackResult,
    PhaseConsumption, SynthesisBudgetContract, SynthesisPhase,
};

const SHADOW_ABLATION_COMPONENT: &str = "shadow_ablation_engine";
const SHADOW_ABLATION_TRANSCRIPT_DOMAIN: &[u8] = b"FrankenEngine.ShadowAblationTranscript.v1";

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn capability_names(capabilities: &BTreeSet<Capability>) -> Vec<String> {
    capabilities
        .iter()
        .map(|cap| cap.as_str().to_string())
        .collect()
}

fn capability_set_digest(capabilities: &BTreeSet<Capability>) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"shadow-ablation-set|");
    for cap in capabilities {
        bytes.extend_from_slice(cap.as_str().as_bytes());
        bytes.push(b'|');
    }
    to_hex(ContentHash::compute(&bytes).as_bytes())
}

fn capability_value(capabilities: &BTreeSet<Capability>) -> CanonicalValue {
    CanonicalValue::Array(
        capabilities
            .iter()
            .map(|cap| CanonicalValue::String(cap.as_str().to_string()))
            .collect(),
    )
}

fn string_map_value(values: &BTreeMap<String, bool>) -> CanonicalValue {
    let mut out = BTreeMap::new();
    for (key, value) in values {
        out.insert(key.clone(), CanonicalValue::Bool(*value));
    }
    CanonicalValue::Map(out)
}

fn phase_consumption_value(consumed: &PhaseConsumption) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert("time_ns".to_string(), CanonicalValue::U64(consumed.time_ns));
    map.insert("compute".to_string(), CanonicalValue::U64(consumed.compute));
    map.insert("depth".to_string(), CanonicalValue::U64(consumed.depth));
    CanonicalValue::Map(map)
}

fn utilization_value(values: &BTreeMap<BudgetDimension, i64>) -> CanonicalValue {
    let mut map = BTreeMap::new();
    for (dimension, value) in values {
        map.insert(dimension.to_string(), CanonicalValue::I64(*value));
    }
    CanonicalValue::Map(map)
}

fn fallback_value(fallback: &Option<FallbackResult>) -> CanonicalValue {
    match fallback {
        None => CanonicalValue::Null,
        Some(result) => {
            let mut reason = BTreeMap::new();
            reason.insert(
                "exceeded_dimensions".to_string(),
                CanonicalValue::Array(
                    result
                        .exhaustion_reason
                        .exceeded_dimensions
                        .iter()
                        .map(|dimension| CanonicalValue::String(dimension.to_string()))
                        .collect(),
                ),
            );
            reason.insert(
                "phase".to_string(),
                CanonicalValue::String(result.exhaustion_reason.phase.to_string()),
            );
            reason.insert(
                "global_limit_hit".to_string(),
                CanonicalValue::Bool(result.exhaustion_reason.global_limit_hit),
            );
            reason.insert(
                "limit_value".to_string(),
                CanonicalValue::U64(result.exhaustion_reason.limit_value),
            );
            reason.insert(
                "consumption".to_string(),
                phase_consumption_value(&result.exhaustion_reason.consumption),
            );

            let mut map = BTreeMap::new();
            map.insert(
                "quality".to_string(),
                CanonicalValue::String(result.quality.to_string()),
            );
            map.insert(
                "result_digest".to_string(),
                CanonicalValue::String(result.result_digest.clone()),
            );
            map.insert(
                "increase_likely_helpful".to_string(),
                CanonicalValue::Bool(result.increase_likely_helpful),
            );
            map.insert(
                "recommended_multiplier".to_string(),
                match result.recommended_multiplier {
                    Some(multiplier) => CanonicalValue::I64(multiplier),
                    None => CanonicalValue::Null,
                },
            );
            map.insert("exhaustion_reason".to_string(), CanonicalValue::Map(reason));
            CanonicalValue::Map(map)
        }
    }
}

/// Multi-capability search strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AblationSearchStrategy {
    /// Deterministic lattice-guided subtraction (single + correlated pairs).
    LatticeGreedy,
    /// Lattice-guided subtraction plus deterministic binary-style block removal.
    BinaryGuided,
}

impl fmt::Display for AblationSearchStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatticeGreedy => f.write_str("lattice_greedy"),
            Self::BinaryGuided => f.write_str("binary_guided"),
        }
    }
}

/// Search stage for an ablation candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AblationSearchStage {
    SingleCapability,
    CorrelatedPair,
    BinaryBlock,
}

impl fmt::Display for AblationSearchStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleCapability => f.write_str("single_capability"),
            Self::CorrelatedPair => f.write_str("correlated_pair"),
            Self::BinaryBlock => f.write_str("binary_block"),
        }
    }
}

/// Candidate-level failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AblationFailureClass {
    CorrectnessRegression,
    InvariantViolation,
    RiskBudgetExceeded,
    ExecutionFailure,
    OracleError,
    InvalidOracleResult,
    BudgetExhausted,
}

impl AblationFailureClass {
    fn error_code(self) -> &'static str {
        match self {
            Self::CorrectnessRegression => "ablation_correctness_regression",
            Self::InvariantViolation => "ablation_invariant_violation",
            Self::RiskBudgetExceeded => "ablation_risk_budget_exceeded",
            Self::ExecutionFailure => "ablation_execution_failure",
            Self::OracleError => "ablation_oracle_error",
            Self::InvalidOracleResult => "ablation_invalid_oracle_result",
            Self::BudgetExhausted => "ablation_budget_exhausted",
        }
    }
}

impl fmt::Display for AblationFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Configuration for an ablation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationConfig {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub replay_corpus_id: String,
    pub randomness_snapshot_id: String,
    pub deterministic_seed: u64,
    pub strategy: AblationSearchStrategy,
    pub required_invariants: BTreeSet<String>,
    pub max_pair_trials: u64,
    pub max_block_trials: u64,
    pub zone: String,
}

impl Default for ShadowAblationConfig {
    fn default() -> Self {
        Self {
            trace_id: "trace-shadow-ablation-default".to_string(),
            decision_id: "decision-shadow-ablation-default".to_string(),
            policy_id: "policy-shadow-ablation-default".to_string(),
            extension_id: "extension-shadow-ablation-default".to_string(),
            replay_corpus_id: "replay-corpus-default".to_string(),
            randomness_snapshot_id: "rng-snapshot-default".to_string(),
            deterministic_seed: 0x5EED_AB1A_7100u64,
            strategy: AblationSearchStrategy::LatticeGreedy,
            required_invariants: BTreeSet::new(),
            max_pair_trials: 256,
            max_block_trials: 128,
            zone: "default".to_string(),
        }
    }
}

impl ShadowAblationConfig {
    fn validate(&self) -> Result<(), ShadowAblationError> {
        if self.trace_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.extension_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "extension_id must not be empty".to_string(),
            });
        }
        if self.replay_corpus_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "replay_corpus_id must not be empty".to_string(),
            });
        }
        if self.randomness_snapshot_id.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "randomness_snapshot_id must not be empty".to_string(),
            });
        }
        if self.zone.trim().is_empty() {
            return Err(ShadowAblationError::InvalidConfig {
                detail: "zone must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Candidate request provided to the shadow execution oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationCandidateRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub search_stage: AblationSearchStage,
    pub sequence: u64,
    pub candidate_id: String,
    pub removed_capabilities: BTreeSet<Capability>,
    pub candidate_capabilities: BTreeSet<Capability>,
    pub replay_corpus_id: String,
    pub randomness_snapshot_id: String,
    pub deterministic_seed: u64,
}

/// Oracle observation from a shadow candidate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationObservation {
    pub correctness_score_millionths: i64,
    pub correctness_threshold_millionths: i64,
    pub invariants: BTreeMap<String, bool>,
    pub risk_score_millionths: i64,
    pub risk_threshold_millionths: i64,
    pub consumed: PhaseConsumption,
    pub replay_pointer: String,
    pub evidence_pointer: String,
    pub execution_trace_hash: ContentHash,
    pub failure_detail: Option<String>,
}

impl ShadowAblationObservation {
    fn validate(&self) -> Result<(), ShadowAblationError> {
        if self.correctness_threshold_millionths < 0 {
            return Err(ShadowAblationError::InvalidOracleResult {
                detail: "correctness_threshold_millionths must be >= 0".to_string(),
            });
        }
        if self.risk_threshold_millionths < 0 {
            return Err(ShadowAblationError::InvalidOracleResult {
                detail: "risk_threshold_millionths must be >= 0".to_string(),
            });
        }
        if self.replay_pointer.trim().is_empty() {
            return Err(ShadowAblationError::InvalidOracleResult {
                detail: "replay_pointer must not be empty".to_string(),
            });
        }
        if self.evidence_pointer.trim().is_empty() {
            return Err(ShadowAblationError::InvalidOracleResult {
                detail: "evidence_pointer must not be empty".to_string(),
            });
        }
        if *self.execution_trace_hash.as_bytes() == [0u8; 32] {
            return Err(ShadowAblationError::InvalidOracleResult {
                detail: "execution_trace_hash must not be all zeros".to_string(),
            });
        }
        Ok(())
    }
}

/// Structured per-candidate evaluation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationEvaluationRecord {
    pub sequence: u64,
    pub candidate_id: String,
    pub search_stage: AblationSearchStage,
    pub removed_capabilities: BTreeSet<Capability>,
    pub candidate_capabilities: BTreeSet<Capability>,
    pub pass: bool,
    pub correctness_score_millionths: i64,
    pub correctness_threshold_millionths: i64,
    pub invariants: BTreeMap<String, bool>,
    pub invariant_failures: Vec<String>,
    pub risk_score_millionths: i64,
    pub risk_threshold_millionths: i64,
    pub consumed: PhaseConsumption,
    pub replay_pointer: String,
    pub evidence_pointer: String,
    pub execution_trace_hash: ContentHash,
    pub failure_class: Option<AblationFailureClass>,
    pub failure_detail: Option<String>,
}

impl ShadowAblationEvaluationRecord {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert(
            "candidate_id".to_string(),
            CanonicalValue::String(self.candidate_id.clone()),
        );
        map.insert(
            "search_stage".to_string(),
            CanonicalValue::String(self.search_stage.to_string()),
        );
        map.insert(
            "removed_capabilities".to_string(),
            capability_value(&self.removed_capabilities),
        );
        map.insert(
            "candidate_capabilities".to_string(),
            capability_value(&self.candidate_capabilities),
        );
        map.insert("pass".to_string(), CanonicalValue::Bool(self.pass));
        map.insert(
            "correctness_score_millionths".to_string(),
            CanonicalValue::I64(self.correctness_score_millionths),
        );
        map.insert(
            "correctness_threshold_millionths".to_string(),
            CanonicalValue::I64(self.correctness_threshold_millionths),
        );
        map.insert("invariants".to_string(), string_map_value(&self.invariants));
        map.insert(
            "invariant_failures".to_string(),
            CanonicalValue::Array(
                self.invariant_failures
                    .iter()
                    .map(|name| CanonicalValue::String(name.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "risk_score_millionths".to_string(),
            CanonicalValue::I64(self.risk_score_millionths),
        );
        map.insert(
            "risk_threshold_millionths".to_string(),
            CanonicalValue::I64(self.risk_threshold_millionths),
        );
        map.insert(
            "consumed".to_string(),
            phase_consumption_value(&self.consumed),
        );
        map.insert(
            "replay_pointer".to_string(),
            CanonicalValue::String(self.replay_pointer.clone()),
        );
        map.insert(
            "evidence_pointer".to_string(),
            CanonicalValue::String(self.evidence_pointer.clone()),
        );
        map.insert(
            "execution_trace_hash".to_string(),
            CanonicalValue::Bytes(self.execution_trace_hash.as_bytes().to_vec()),
        );
        map.insert(
            "failure_class".to_string(),
            match self.failure_class {
                Some(class) => CanonicalValue::String(class.to_string()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "failure_detail".to_string(),
            match &self.failure_detail {
                Some(detail) => CanonicalValue::String(detail.clone()),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }
}

/// Structured log event for shadow ablation decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub search_stage: Option<String>,
    pub candidate_id: Option<String>,
    pub removed_capabilities: Vec<String>,
    pub remaining_capability_count: Option<u64>,
}

/// Final result of an ablation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationRunResult {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub static_report_id: EngineObjectId,
    pub search_strategy: AblationSearchStrategy,
    pub initial_capabilities: BTreeSet<Capability>,
    pub minimal_capabilities: BTreeSet<Capability>,
    pub evaluations: Vec<ShadowAblationEvaluationRecord>,
    pub logs: Vec<ShadowAblationLogEvent>,
    pub budget_exhausted: bool,
    pub fallback: Option<FallbackResult>,
    pub budget_utilization: BTreeMap<BudgetDimension, i64>,
    pub transcript: SignedShadowAblationTranscript,
}

/// Unsigned transcript material produced by a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAblationTranscriptInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub static_report_id: EngineObjectId,
    pub replay_corpus_id: String,
    pub randomness_snapshot_id: String,
    pub deterministic_seed: u64,
    pub search_strategy: AblationSearchStrategy,
    pub initial_capabilities: BTreeSet<Capability>,
    pub final_capabilities: BTreeSet<Capability>,
    pub evaluations: Vec<ShadowAblationEvaluationRecord>,
    pub fallback: Option<FallbackResult>,
    pub budget_utilization: BTreeMap<BudgetDimension, i64>,
}

/// Signed transcript artifact for audit and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedShadowAblationTranscript {
    pub transcript_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub static_report_id: EngineObjectId,
    pub replay_corpus_id: String,
    pub randomness_snapshot_id: String,
    pub deterministic_seed: u64,
    pub search_strategy: AblationSearchStrategy,
    pub initial_capabilities: BTreeSet<Capability>,
    pub final_capabilities: BTreeSet<Capability>,
    pub evaluations: Vec<ShadowAblationEvaluationRecord>,
    pub fallback: Option<FallbackResult>,
    pub budget_utilization: BTreeMap<BudgetDimension, i64>,
    pub transcript_hash: ContentHash,
    pub signer: VerificationKey,
    pub signature: Signature,
}

impl SignedShadowAblationTranscript {
    pub fn create_signed(
        input: ShadowAblationTranscriptInput,
        signing_key: &SigningKey,
    ) -> Result<Self, ShadowAblationError> {
        let signer = signing_key.verification_key();
        let unsigned = transcript_unsigned_bytes(&input, &signer);
        let transcript_hash = ContentHash::compute(&unsigned);
        let signature = sign_preimage(signing_key, &unsigned).map_err(|error| {
            ShadowAblationError::SignatureFailed {
                detail: error.to_string(),
            }
        })?;
        let transcript_id = format!(
            "shadow-ablation-{}",
            to_hex(&transcript_hash.as_bytes()[..16])
        );

        Ok(Self {
            transcript_id,
            trace_id: input.trace_id,
            decision_id: input.decision_id,
            policy_id: input.policy_id,
            extension_id: input.extension_id,
            static_report_id: input.static_report_id,
            replay_corpus_id: input.replay_corpus_id,
            randomness_snapshot_id: input.randomness_snapshot_id,
            deterministic_seed: input.deterministic_seed,
            search_strategy: input.search_strategy,
            initial_capabilities: input.initial_capabilities,
            final_capabilities: input.final_capabilities,
            evaluations: input.evaluations,
            fallback: input.fallback,
            budget_utilization: input.budget_utilization,
            transcript_hash,
            signer,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<(), ShadowAblationError> {
        let input = self.as_unsigned_input();
        let unsigned = transcript_unsigned_bytes(&input, &self.signer);
        verify_signature(&self.signer, &unsigned, &self.signature).map_err(|error| {
            ShadowAblationError::SignatureInvalid {
                detail: error.to_string(),
            }
        })?;

        let actual_hash = ContentHash::compute(&unsigned);
        if actual_hash != self.transcript_hash {
            return Err(ShadowAblationError::IntegrityFailure {
                expected: to_hex(self.transcript_hash.as_bytes()),
                actual: to_hex(actual_hash.as_bytes()),
            });
        }

        Ok(())
    }

    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let input = self.as_unsigned_input();
        transcript_unsigned_bytes(&input, &self.signer)
    }

    fn as_unsigned_input(&self) -> ShadowAblationTranscriptInput {
        ShadowAblationTranscriptInput {
            trace_id: self.trace_id.clone(),
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            extension_id: self.extension_id.clone(),
            static_report_id: self.static_report_id.clone(),
            replay_corpus_id: self.replay_corpus_id.clone(),
            randomness_snapshot_id: self.randomness_snapshot_id.clone(),
            deterministic_seed: self.deterministic_seed,
            search_strategy: self.search_strategy,
            initial_capabilities: self.initial_capabilities.clone(),
            final_capabilities: self.final_capabilities.clone(),
            evaluations: self.evaluations.clone(),
            fallback: self.fallback.clone(),
            budget_utilization: self.budget_utilization.clone(),
        }
    }
}

fn transcript_unsigned_bytes(
    input: &ShadowAblationTranscriptInput,
    signer: &VerificationKey,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );
    map.insert(
        "decision_id".to_string(),
        CanonicalValue::String(input.decision_id.clone()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert(
        "extension_id".to_string(),
        CanonicalValue::String(input.extension_id.clone()),
    );
    map.insert(
        "static_report_id".to_string(),
        CanonicalValue::Bytes(input.static_report_id.as_bytes().to_vec()),
    );
    map.insert(
        "replay_corpus_id".to_string(),
        CanonicalValue::String(input.replay_corpus_id.clone()),
    );
    map.insert(
        "randomness_snapshot_id".to_string(),
        CanonicalValue::String(input.randomness_snapshot_id.clone()),
    );
    map.insert(
        "deterministic_seed".to_string(),
        CanonicalValue::U64(input.deterministic_seed),
    );
    map.insert(
        "search_strategy".to_string(),
        CanonicalValue::String(input.search_strategy.to_string()),
    );
    map.insert(
        "initial_capabilities".to_string(),
        capability_value(&input.initial_capabilities),
    );
    map.insert(
        "final_capabilities".to_string(),
        capability_value(&input.final_capabilities),
    );
    map.insert(
        "evaluations".to_string(),
        CanonicalValue::Array(
            input
                .evaluations
                .iter()
                .map(ShadowAblationEvaluationRecord::canonical_value)
                .collect(),
        ),
    );
    map.insert("fallback".to_string(), fallback_value(&input.fallback));
    map.insert(
        "budget_utilization".to_string(),
        utilization_value(&input.budget_utilization),
    );
    map.insert(
        "signer".to_string(),
        CanonicalValue::Bytes(signer.as_bytes().to_vec()),
    );

    let payload = deterministic_serde::encode_value(&CanonicalValue::Map(map));
    let mut preimage =
        Vec::with_capacity(SHADOW_ABLATION_TRANSCRIPT_DOMAIN.len() + 1 + payload.len());
    preimage.extend_from_slice(SHADOW_ABLATION_TRANSCRIPT_DOMAIN);
    preimage.push(b'|');
    preimage.extend_from_slice(&payload);
    preimage
}

/// Run-time ablation errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowAblationError {
    EmptyStaticUpperBound { extension_id: String },
    ExtensionMismatch { expected: String, found: String },
    InvalidConfig { detail: String },
    InvalidOracleResult { detail: String },
    Budget { detail: String },
    SignatureFailed { detail: String },
    SignatureInvalid { detail: String },
    IntegrityFailure { expected: String, actual: String },
}

impl fmt::Display for ShadowAblationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStaticUpperBound { extension_id } => {
                write!(
                    f,
                    "static upper bound is empty for extension `{extension_id}`"
                )
            }
            Self::ExtensionMismatch { expected, found } => write!(
                f,
                "extension mismatch: expected `{expected}` but static report is `{found}`"
            ),
            Self::InvalidConfig { detail } => write!(f, "invalid shadow ablation config: {detail}"),
            Self::InvalidOracleResult { detail } => {
                write!(f, "invalid shadow oracle result: {detail}")
            }
            Self::Budget { detail } => write!(f, "budget monitor error: {detail}"),
            Self::SignatureFailed { detail } => {
                write!(f, "failed to sign shadow ablation transcript: {detail}")
            }
            Self::SignatureInvalid { detail } => {
                write!(f, "invalid shadow ablation transcript signature: {detail}")
            }
            Self::IntegrityFailure { expected, actual } => write!(
                f,
                "shadow ablation transcript hash mismatch: expected={expected}, actual={actual}"
            ),
        }
    }
}

impl std::error::Error for ShadowAblationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateEvaluationOutcome {
    Accepted,
    Rejected,
    BudgetExhausted(ExhaustionReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SearchStepOutcome {
    Removed(BTreeSet<Capability>),
    Stable,
    BudgetExhausted(ExhaustionReason),
}

/// Deterministic shadow ablation engine.
#[derive(Debug, Clone)]
pub struct ShadowAblationEngine {
    config: ShadowAblationConfig,
    budget_contract: SynthesisBudgetContract,
}

impl ShadowAblationEngine {
    pub fn new(
        config: ShadowAblationConfig,
        budget_contract: SynthesisBudgetContract,
    ) -> Result<Self, ShadowAblationError> {
        config.validate()?;
        Ok(Self {
            config,
            budget_contract,
        })
    }

    pub fn config(&self) -> &ShadowAblationConfig {
        &self.config
    }

    pub fn run<F>(
        &self,
        static_report: &StaticAnalysisReport,
        signing_key: &SigningKey,
        mut oracle: F,
    ) -> Result<ShadowAblationRunResult, ShadowAblationError>
    where
        F: FnMut(
            &ShadowAblationCandidateRequest,
        ) -> Result<ShadowAblationObservation, ShadowAblationError>,
    {
        if static_report.extension_id != self.config.extension_id {
            return Err(ShadowAblationError::ExtensionMismatch {
                expected: self.config.extension_id.clone(),
                found: static_report.extension_id.clone(),
            });
        }
        if static_report.upper_bound_capabilities.is_empty() {
            return Err(ShadowAblationError::EmptyStaticUpperBound {
                extension_id: static_report.extension_id.clone(),
            });
        }

        let initial_capabilities = static_report.upper_bound_capabilities.clone();
        let mut current_capabilities = initial_capabilities.clone();
        let mut evaluations = Vec::new();
        let mut logs = Vec::new();
        let mut sequence = 0u64;
        let mut monitor = BudgetMonitor::new(self.budget_contract.clone());
        monitor
            .begin_phase(SynthesisPhase::Ablation)
            .map_err(|error| ShadowAblationError::Budget {
                detail: error.to_string(),
            })?;

        logs.push(log_event(
            &self.config,
            "shadow_ablation_started",
            "start",
            None,
            None,
            None,
            &BTreeSet::new(),
            Some(current_capabilities.len() as u64),
        ));

        let mut exhaustion: Option<ExhaustionReason> = None;
        let mut single_round = 0u64;

        loop {
            match try_single_removal(
                &self.config,
                &mut sequence,
                &current_capabilities,
                &mut monitor,
                single_round,
                &mut oracle,
                &mut evaluations,
                &mut logs,
            )? {
                SearchStepOutcome::Removed(removed) => {
                    for capability in &removed {
                        current_capabilities.remove(capability);
                    }
                    single_round = single_round.wrapping_add(1);
                }
                SearchStepOutcome::Stable => break,
                SearchStepOutcome::BudgetExhausted(reason) => {
                    exhaustion = Some(reason);
                    break;
                }
            }
        }

        if exhaustion.is_none() && self.config.strategy == AblationSearchStrategy::BinaryGuided {
            let mut block_trials = 0u64;
            let mut block_size = highest_power_of_two_leq(current_capabilities.len() / 2);
            let mut block_round = 0u64;
            while block_size >= 2 {
                match try_block_removal(
                    &self.config,
                    &mut sequence,
                    &current_capabilities,
                    &mut monitor,
                    block_size,
                    &mut block_trials,
                    block_round,
                    &mut oracle,
                    &mut evaluations,
                    &mut logs,
                )? {
                    SearchStepOutcome::Removed(removed) => {
                        for capability in &removed {
                            current_capabilities.remove(capability);
                        }
                        loop {
                            match try_single_removal(
                                &self.config,
                                &mut sequence,
                                &current_capabilities,
                                &mut monitor,
                                single_round,
                                &mut oracle,
                                &mut evaluations,
                                &mut logs,
                            )? {
                                SearchStepOutcome::Removed(single_removed) => {
                                    for capability in &single_removed {
                                        current_capabilities.remove(capability);
                                    }
                                    single_round = single_round.wrapping_add(1);
                                }
                                SearchStepOutcome::Stable => break,
                                SearchStepOutcome::BudgetExhausted(reason) => {
                                    exhaustion = Some(reason);
                                    break;
                                }
                            }
                        }
                        if exhaustion.is_some() {
                            break;
                        }
                        block_round = block_round.wrapping_add(1);
                    }
                    SearchStepOutcome::Stable => {
                        block_size /= 2;
                    }
                    SearchStepOutcome::BudgetExhausted(reason) => {
                        exhaustion = Some(reason);
                        break;
                    }
                }
                if block_trials >= self.config.max_block_trials {
                    break;
                }
            }
        }

        if exhaustion.is_none() {
            let mut pair_trials = 0u64;
            let mut pair_round = 0u64;
            loop {
                match try_pair_removal(
                    &self.config,
                    &mut sequence,
                    &current_capabilities,
                    &mut monitor,
                    &mut pair_trials,
                    pair_round,
                    &mut oracle,
                    &mut evaluations,
                    &mut logs,
                )? {
                    SearchStepOutcome::Removed(removed) => {
                        for capability in &removed {
                            current_capabilities.remove(capability);
                        }
                        loop {
                            match try_single_removal(
                                &self.config,
                                &mut sequence,
                                &current_capabilities,
                                &mut monitor,
                                single_round,
                                &mut oracle,
                                &mut evaluations,
                                &mut logs,
                            )? {
                                SearchStepOutcome::Removed(single_removed) => {
                                    for capability in &single_removed {
                                        current_capabilities.remove(capability);
                                    }
                                    single_round = single_round.wrapping_add(1);
                                }
                                SearchStepOutcome::Stable => break,
                                SearchStepOutcome::BudgetExhausted(reason) => {
                                    exhaustion = Some(reason);
                                    break;
                                }
                            }
                        }
                        if exhaustion.is_some() {
                            break;
                        }
                        pair_round = pair_round.wrapping_add(1);
                    }
                    SearchStepOutcome::Stable => break,
                    SearchStepOutcome::BudgetExhausted(reason) => {
                        exhaustion = Some(reason);
                        break;
                    }
                }
                if pair_trials >= self.config.max_pair_trials {
                    break;
                }
            }
        }

        let fallback = exhaustion
            .as_ref()
            .map(|reason| fallback_for(reason, &initial_capabilities, &current_capabilities));
        let budget_exhausted = fallback.is_some();
        let budget_utilization = monitor.utilization();

        logs.push(log_event(
            &self.config,
            "shadow_ablation_completed",
            if budget_exhausted { "fallback" } else { "pass" },
            fallback.as_ref().map(|result| result.quality.to_string()),
            None,
            None,
            &BTreeSet::new(),
            Some(current_capabilities.len() as u64),
        ));

        let transcript_input = ShadowAblationTranscriptInput {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            extension_id: self.config.extension_id.clone(),
            static_report_id: static_report.report_id.clone(),
            replay_corpus_id: self.config.replay_corpus_id.clone(),
            randomness_snapshot_id: self.config.randomness_snapshot_id.clone(),
            deterministic_seed: self.config.deterministic_seed,
            search_strategy: self.config.strategy,
            initial_capabilities: initial_capabilities.clone(),
            final_capabilities: current_capabilities.clone(),
            evaluations: evaluations.clone(),
            fallback: fallback.clone(),
            budget_utilization: budget_utilization.clone(),
        };
        let transcript =
            SignedShadowAblationTranscript::create_signed(transcript_input, signing_key)?;

        Ok(ShadowAblationRunResult {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            extension_id: self.config.extension_id.clone(),
            static_report_id: static_report.report_id.clone(),
            search_strategy: self.config.strategy,
            initial_capabilities,
            minimal_capabilities: current_capabilities,
            evaluations,
            logs,
            budget_exhausted,
            fallback,
            budget_utilization,
            transcript,
        })
    }
}

fn fallback_for(
    reason: &ExhaustionReason,
    initial_capabilities: &BTreeSet<Capability>,
    current_capabilities: &BTreeSet<Capability>,
) -> FallbackResult {
    let quality = if current_capabilities == initial_capabilities {
        FallbackQuality::StaticBound
    } else {
        FallbackQuality::PartialAblation
    };

    let increase_likely_helpful = reason.exceeded_dimensions.iter().any(|dimension| {
        matches!(
            dimension,
            BudgetDimension::Time | BudgetDimension::Compute | BudgetDimension::Depth
        )
    });

    FallbackResult {
        quality,
        result_digest: capability_set_digest(current_capabilities),
        exhaustion_reason: reason.clone(),
        increase_likely_helpful,
        recommended_multiplier: if increase_likely_helpful {
            Some(1_500_000)
        } else {
            None
        },
    }
}

fn highest_power_of_two_leq(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut power = 1usize;
    while power.saturating_mul(2) <= n {
        power = power.saturating_mul(2);
    }
    power
}

fn seeded_capability_order(capabilities: &BTreeSet<Capability>, seed: u64) -> Vec<Capability> {
    let mut weighted = capabilities
        .iter()
        .map(|capability| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&seed.to_be_bytes());
            bytes.extend_from_slice(capability.as_str().as_bytes());
            let weight = ContentHash::compute(&bytes);
            (weight, capability.clone())
        })
        .collect::<Vec<_>>();

    weighted.sort_by(|(left_weight, left_cap), (right_weight, right_cap)| {
        left_weight
            .as_bytes()
            .cmp(right_weight.as_bytes())
            .then_with(|| left_cap.cmp(right_cap))
    });

    weighted
        .into_iter()
        .map(|(_, capability)| capability)
        .collect()
}

fn candidate_id(
    config: &ShadowAblationConfig,
    stage: AblationSearchStage,
    sequence: u64,
    removed_capabilities: &BTreeSet<Capability>,
    candidate_capabilities: &BTreeSet<Capability>,
) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(config.trace_id.clone()),
    );
    map.insert(
        "decision_id".to_string(),
        CanonicalValue::String(config.decision_id.clone()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(config.policy_id.clone()),
    );
    map.insert(
        "search_stage".to_string(),
        CanonicalValue::String(stage.to_string()),
    );
    map.insert("sequence".to_string(), CanonicalValue::U64(sequence));
    map.insert(
        "deterministic_seed".to_string(),
        CanonicalValue::U64(config.deterministic_seed),
    );
    map.insert(
        "removed_capabilities".to_string(),
        capability_value(removed_capabilities),
    );
    map.insert(
        "candidate_capabilities".to_string(),
        capability_value(candidate_capabilities),
    );

    let encoded = deterministic_serde::encode_value(&CanonicalValue::Map(map));
    let digest = ContentHash::compute(&encoded);
    format!("ablate-{}", to_hex(&digest.as_bytes()[..12]))
}

#[allow(clippy::too_many_arguments)]
fn log_event(
    config: &ShadowAblationConfig,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    search_stage: Option<AblationSearchStage>,
    candidate_id: Option<String>,
    removed_capabilities: &BTreeSet<Capability>,
    remaining_capability_count: Option<u64>,
) -> ShadowAblationLogEvent {
    ShadowAblationLogEvent {
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        component: SHADOW_ABLATION_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        search_stage: search_stage.map(|stage| stage.to_string()),
        candidate_id,
        removed_capabilities: capability_names(removed_capabilities),
        remaining_capability_count,
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_candidate<F>(
    config: &ShadowAblationConfig,
    stage: AblationSearchStage,
    sequence: &mut u64,
    current_capabilities: &BTreeSet<Capability>,
    removed_capabilities: &BTreeSet<Capability>,
    monitor: &mut BudgetMonitor,
    oracle: &mut F,
    evaluations: &mut Vec<ShadowAblationEvaluationRecord>,
    logs: &mut Vec<ShadowAblationLogEvent>,
) -> Result<CandidateEvaluationOutcome, ShadowAblationError>
where
    F: FnMut(
        &ShadowAblationCandidateRequest,
    ) -> Result<ShadowAblationObservation, ShadowAblationError>,
{
    let candidate_capabilities = current_capabilities
        .difference(removed_capabilities)
        .cloned()
        .collect::<BTreeSet<_>>();
    *sequence = sequence.saturating_add(1);
    let sequence_number = *sequence;
    let candidate_id = candidate_id(
        config,
        stage,
        sequence_number,
        removed_capabilities,
        &candidate_capabilities,
    );
    let request = ShadowAblationCandidateRequest {
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        extension_id: config.extension_id.clone(),
        search_stage: stage,
        sequence: sequence_number,
        candidate_id: candidate_id.clone(),
        removed_capabilities: removed_capabilities.clone(),
        candidate_capabilities: candidate_capabilities.clone(),
        replay_corpus_id: config.replay_corpus_id.clone(),
        randomness_snapshot_id: config.randomness_snapshot_id.clone(),
        deterministic_seed: config.deterministic_seed,
    };

    let observation = match oracle(&request) {
        Ok(observation) => observation,
        Err(error) => {
            let detail = error.to_string();
            let record = ShadowAblationEvaluationRecord {
                sequence: sequence_number,
                candidate_id: candidate_id.clone(),
                search_stage: stage,
                removed_capabilities: removed_capabilities.clone(),
                candidate_capabilities,
                pass: false,
                correctness_score_millionths: 0,
                correctness_threshold_millionths: 0,
                invariants: BTreeMap::new(),
                invariant_failures: Vec::new(),
                risk_score_millionths: 0,
                risk_threshold_millionths: 0,
                consumed: PhaseConsumption::zero(),
                replay_pointer: String::new(),
                evidence_pointer: String::new(),
                execution_trace_hash: ContentHash::compute(candidate_id.as_bytes()),
                failure_class: Some(AblationFailureClass::OracleError),
                failure_detail: Some(detail),
            };
            evaluations.push(record);
            logs.push(log_event(
                config,
                "shadow_ablation_candidate_evaluated",
                "fail",
                Some(AblationFailureClass::OracleError.error_code().to_string()),
                Some(stage),
                Some(candidate_id),
                removed_capabilities,
                Some(current_capabilities.len() as u64),
            ));
            return Ok(CandidateEvaluationOutcome::Rejected);
        }
    };

    if let Err(error) = observation.validate() {
        let record = ShadowAblationEvaluationRecord {
            sequence: sequence_number,
            candidate_id: candidate_id.clone(),
            search_stage: stage,
            removed_capabilities: removed_capabilities.clone(),
            candidate_capabilities,
            pass: false,
            correctness_score_millionths: observation.correctness_score_millionths,
            correctness_threshold_millionths: observation.correctness_threshold_millionths,
            invariants: observation.invariants.clone(),
            invariant_failures: Vec::new(),
            risk_score_millionths: observation.risk_score_millionths,
            risk_threshold_millionths: observation.risk_threshold_millionths,
            consumed: observation.consumed.clone(),
            replay_pointer: observation.replay_pointer.clone(),
            evidence_pointer: observation.evidence_pointer.clone(),
            execution_trace_hash: observation.execution_trace_hash,
            failure_class: Some(AblationFailureClass::InvalidOracleResult),
            failure_detail: Some(error.to_string()),
        };
        evaluations.push(record);
        logs.push(log_event(
            config,
            "shadow_ablation_candidate_evaluated",
            "fail",
            Some(
                AblationFailureClass::InvalidOracleResult
                    .error_code()
                    .to_string(),
            ),
            Some(stage),
            Some(candidate_id),
            removed_capabilities,
            Some(current_capabilities.len() as u64),
        ));
        return Ok(CandidateEvaluationOutcome::Rejected);
    }

    match monitor.record_consumption(
        observation.consumed.time_ns,
        observation.consumed.compute,
        observation.consumed.depth,
    ) {
        Ok(()) => {}
        Err(BudgetError::Exhausted(reason)) => {
            let record = ShadowAblationEvaluationRecord {
                sequence: sequence_number,
                candidate_id: candidate_id.clone(),
                search_stage: stage,
                removed_capabilities: removed_capabilities.clone(),
                candidate_capabilities,
                pass: false,
                correctness_score_millionths: observation.correctness_score_millionths,
                correctness_threshold_millionths: observation.correctness_threshold_millionths,
                invariants: observation.invariants.clone(),
                invariant_failures: Vec::new(),
                risk_score_millionths: observation.risk_score_millionths,
                risk_threshold_millionths: observation.risk_threshold_millionths,
                consumed: observation.consumed.clone(),
                replay_pointer: observation.replay_pointer.clone(),
                evidence_pointer: observation.evidence_pointer.clone(),
                execution_trace_hash: observation.execution_trace_hash,
                failure_class: Some(AblationFailureClass::BudgetExhausted),
                failure_detail: Some(reason.to_string()),
            };
            evaluations.push(record);
            logs.push(log_event(
                config,
                "shadow_ablation_candidate_evaluated",
                "fail",
                Some(
                    AblationFailureClass::BudgetExhausted
                        .error_code()
                        .to_string(),
                ),
                Some(stage),
                Some(candidate_id),
                removed_capabilities,
                Some(current_capabilities.len() as u64),
            ));
            return Ok(CandidateEvaluationOutcome::BudgetExhausted(reason));
        }
        Err(other) => {
            return Err(ShadowAblationError::Budget {
                detail: other.to_string(),
            });
        }
    }

    let mut invariant_failures = Vec::new();
    if config.required_invariants.is_empty() {
        for (invariant, passed) in &observation.invariants {
            if !passed {
                invariant_failures.push(invariant.clone());
            }
        }
    } else {
        for invariant in &config.required_invariants {
            if !observation
                .invariants
                .get(invariant)
                .copied()
                .unwrap_or(false)
            {
                invariant_failures.push(invariant.clone());
            }
        }
    }
    invariant_failures.sort();

    let correctness_pass =
        observation.correctness_score_millionths >= observation.correctness_threshold_millionths;
    let risk_pass = observation.risk_score_millionths <= observation.risk_threshold_millionths;
    let execution_failure = observation
        .failure_detail
        .as_ref()
        .map(|detail| !detail.trim().is_empty())
        .unwrap_or(false);
    let pass = correctness_pass && invariant_failures.is_empty() && risk_pass && !execution_failure;

    let failure_class = if pass {
        None
    } else if !correctness_pass {
        Some(AblationFailureClass::CorrectnessRegression)
    } else if !invariant_failures.is_empty() {
        Some(AblationFailureClass::InvariantViolation)
    } else if !risk_pass {
        Some(AblationFailureClass::RiskBudgetExceeded)
    } else {
        Some(AblationFailureClass::ExecutionFailure)
    };

    let failure_detail = if pass {
        None
    } else if let Some(detail) = observation.failure_detail.clone() {
        Some(detail)
    } else if !correctness_pass {
        Some(format!(
            "correctness {} below threshold {}",
            observation.correctness_score_millionths, observation.correctness_threshold_millionths
        ))
    } else if !invariant_failures.is_empty() {
        Some(format!(
            "invariants failed: {}",
            invariant_failures.join(",")
        ))
    } else if !risk_pass {
        Some(format!(
            "risk {} above threshold {}",
            observation.risk_score_millionths, observation.risk_threshold_millionths
        ))
    } else {
        Some("candidate failed shadow execution".to_string())
    };

    let record = ShadowAblationEvaluationRecord {
        sequence: sequence_number,
        candidate_id: candidate_id.clone(),
        search_stage: stage,
        removed_capabilities: removed_capabilities.clone(),
        candidate_capabilities,
        pass,
        correctness_score_millionths: observation.correctness_score_millionths,
        correctness_threshold_millionths: observation.correctness_threshold_millionths,
        invariants: observation.invariants.clone(),
        invariant_failures,
        risk_score_millionths: observation.risk_score_millionths,
        risk_threshold_millionths: observation.risk_threshold_millionths,
        consumed: observation.consumed,
        replay_pointer: observation.replay_pointer,
        evidence_pointer: observation.evidence_pointer,
        execution_trace_hash: observation.execution_trace_hash,
        failure_class,
        failure_detail,
    };
    evaluations.push(record);
    logs.push(log_event(
        config,
        "shadow_ablation_candidate_evaluated",
        if pass { "pass" } else { "fail" },
        failure_class.map(|class| class.error_code().to_string()),
        Some(stage),
        Some(candidate_id),
        removed_capabilities,
        Some(current_capabilities.len() as u64),
    ));

    if pass {
        Ok(CandidateEvaluationOutcome::Accepted)
    } else {
        Ok(CandidateEvaluationOutcome::Rejected)
    }
}

#[allow(clippy::too_many_arguments)]
fn try_single_removal<F>(
    config: &ShadowAblationConfig,
    sequence: &mut u64,
    current_capabilities: &BTreeSet<Capability>,
    monitor: &mut BudgetMonitor,
    round: u64,
    oracle: &mut F,
    evaluations: &mut Vec<ShadowAblationEvaluationRecord>,
    logs: &mut Vec<ShadowAblationLogEvent>,
) -> Result<SearchStepOutcome, ShadowAblationError>
where
    F: FnMut(
        &ShadowAblationCandidateRequest,
    ) -> Result<ShadowAblationObservation, ShadowAblationError>,
{
    let seed = config
        .deterministic_seed
        .wrapping_add(0x9E37_79B9_7F4A_7C15u64)
        .wrapping_add(round);
    for capability in seeded_capability_order(current_capabilities, seed) {
        let mut removed = BTreeSet::new();
        removed.insert(capability);
        match evaluate_candidate(
            config,
            AblationSearchStage::SingleCapability,
            sequence,
            current_capabilities,
            &removed,
            monitor,
            oracle,
            evaluations,
            logs,
        )? {
            CandidateEvaluationOutcome::Accepted => {
                return Ok(SearchStepOutcome::Removed(removed));
            }
            CandidateEvaluationOutcome::Rejected => {}
            CandidateEvaluationOutcome::BudgetExhausted(reason) => {
                return Ok(SearchStepOutcome::BudgetExhausted(reason));
            }
        }
    }
    Ok(SearchStepOutcome::Stable)
}

#[allow(clippy::too_many_arguments)]
fn try_pair_removal<F>(
    config: &ShadowAblationConfig,
    sequence: &mut u64,
    current_capabilities: &BTreeSet<Capability>,
    monitor: &mut BudgetMonitor,
    trials_used: &mut u64,
    round: u64,
    oracle: &mut F,
    evaluations: &mut Vec<ShadowAblationEvaluationRecord>,
    logs: &mut Vec<ShadowAblationLogEvent>,
) -> Result<SearchStepOutcome, ShadowAblationError>
where
    F: FnMut(
        &ShadowAblationCandidateRequest,
    ) -> Result<ShadowAblationObservation, ShadowAblationError>,
{
    if current_capabilities.len() < 2 || *trials_used >= config.max_pair_trials {
        return Ok(SearchStepOutcome::Stable);
    }
    let seed = config
        .deterministic_seed
        .wrapping_add(0xD1CE_11ED_F00D_4444u64)
        .wrapping_add(round);
    let ordered = seeded_capability_order(current_capabilities, seed);
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            if *trials_used >= config.max_pair_trials {
                return Ok(SearchStepOutcome::Stable);
            }
            *trials_used = trials_used.saturating_add(1);

            let mut removed = BTreeSet::new();
            removed.insert(ordered[i].clone());
            removed.insert(ordered[j].clone());

            match evaluate_candidate(
                config,
                AblationSearchStage::CorrelatedPair,
                sequence,
                current_capabilities,
                &removed,
                monitor,
                oracle,
                evaluations,
                logs,
            )? {
                CandidateEvaluationOutcome::Accepted => {
                    return Ok(SearchStepOutcome::Removed(removed));
                }
                CandidateEvaluationOutcome::Rejected => {}
                CandidateEvaluationOutcome::BudgetExhausted(reason) => {
                    return Ok(SearchStepOutcome::BudgetExhausted(reason));
                }
            }
        }
    }

    Ok(SearchStepOutcome::Stable)
}

#[allow(clippy::too_many_arguments)]
fn try_block_removal<F>(
    config: &ShadowAblationConfig,
    sequence: &mut u64,
    current_capabilities: &BTreeSet<Capability>,
    monitor: &mut BudgetMonitor,
    block_size: usize,
    trials_used: &mut u64,
    round: u64,
    oracle: &mut F,
    evaluations: &mut Vec<ShadowAblationEvaluationRecord>,
    logs: &mut Vec<ShadowAblationLogEvent>,
) -> Result<SearchStepOutcome, ShadowAblationError>
where
    F: FnMut(
        &ShadowAblationCandidateRequest,
    ) -> Result<ShadowAblationObservation, ShadowAblationError>,
{
    if block_size < 2
        || current_capabilities.len() < block_size
        || *trials_used >= config.max_block_trials
    {
        return Ok(SearchStepOutcome::Stable);
    }

    let seed = config
        .deterministic_seed
        .wrapping_add(0xB10C_0000_0000_0000u64)
        .wrapping_add(round)
        .wrapping_add(block_size as u64);
    let ordered = seeded_capability_order(current_capabilities, seed);
    let mut start = 0usize;

    while start + block_size <= ordered.len() {
        if *trials_used >= config.max_block_trials {
            return Ok(SearchStepOutcome::Stable);
        }
        *trials_used = trials_used.saturating_add(1);

        let removed = ordered[start..start + block_size]
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        match evaluate_candidate(
            config,
            AblationSearchStage::BinaryBlock,
            sequence,
            current_capabilities,
            &removed,
            monitor,
            oracle,
            evaluations,
            logs,
        )? {
            CandidateEvaluationOutcome::Accepted => {
                return Ok(SearchStepOutcome::Removed(removed));
            }
            CandidateEvaluationOutcome::Rejected => {}
            CandidateEvaluationOutcome::BudgetExhausted(reason) => {
                return Ok(SearchStepOutcome::BudgetExhausted(reason));
            }
        }
        start = start.saturating_add(block_size);
    }

    Ok(SearchStepOutcome::Stable)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::security_epoch::SecurityEpoch;
    use crate::static_authority_analyzer::{AnalysisMethod, PrecisionEstimate};

    fn cap(name: &str) -> Capability {
        Capability::new(name)
    }

    fn test_static_report(extension_id: &str, caps: BTreeSet<Capability>) -> StaticAnalysisReport {
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

    fn config_with_seed(seed: u64) -> ShadowAblationConfig {
        ShadowAblationConfig {
            trace_id: "trace-seeded-order".to_string(),
            decision_id: "decision-seeded-order".to_string(),
            policy_id: "policy-seeded-order".to_string(),
            extension_id: "ext-seeded-order".to_string(),
            replay_corpus_id: "corpus-seeded-order".to_string(),
            randomness_snapshot_id: "rng-seeded-order".to_string(),
            deterministic_seed: seed,
            strategy: AblationSearchStrategy::LatticeGreedy,
            required_invariants: BTreeSet::new(),
            max_pair_trials: 0,
            max_block_trials: 0,
            zone: "test-zone".to_string(),
        }
    }

    fn sample_evaluation(candidate_id: &str) -> ShadowAblationEvaluationRecord {
        let mut removed = BTreeSet::new();
        removed.insert(cap("fs_read"));
        let mut remaining = BTreeSet::new();
        remaining.insert(cap("net_outbound"));
        ShadowAblationEvaluationRecord {
            sequence: 1,
            candidate_id: candidate_id.to_string(),
            search_stage: AblationSearchStage::SingleCapability,
            removed_capabilities: removed,
            candidate_capabilities: remaining,
            pass: true,
            correctness_score_millionths: 995_000,
            correctness_threshold_millionths: 900_000,
            invariants: BTreeMap::from([("no_exfiltration".to_string(), true)]),
            invariant_failures: Vec::new(),
            risk_score_millionths: 100_000,
            risk_threshold_millionths: 300_000,
            consumed: PhaseConsumption {
                time_ns: 10_000,
                compute: 10,
                depth: 1,
            },
            replay_pointer: "replay://candidate-1".to_string(),
            evidence_pointer: "evidence://candidate-1".to_string(),
            execution_trace_hash: ContentHash::compute(b"trace-1"),
            failure_class: None,
            failure_detail: None,
        }
    }

    #[test]
    fn seeded_order_deterministic_for_same_seed() {
        let mut capabilities = BTreeSet::new();
        capabilities.insert(cap("clock"));
        capabilities.insert(cap("env"));
        capabilities.insert(cap("fs_read"));
        capabilities.insert(cap("net_outbound"));
        capabilities.insert(cap("telemetry_emit"));

        let order_a = seeded_capability_order(&capabilities, 7);
        let order_b = seeded_capability_order(&capabilities, 7);
        assert_eq!(order_a, order_b);
    }

    #[test]
    fn seeded_order_changes_with_different_seed() {
        let mut capabilities = BTreeSet::new();
        capabilities.insert(cap("clock"));
        capabilities.insert(cap("env"));
        capabilities.insert(cap("fs_read"));
        capabilities.insert(cap("net_outbound"));
        capabilities.insert(cap("telemetry_emit"));

        let order_a = seeded_capability_order(&capabilities, 7);
        let order_b = seeded_capability_order(&capabilities, 11);
        assert_ne!(order_a, order_b);
    }

    #[test]
    fn transcript_sign_verify_roundtrip() {
        let signing_key =
            SigningKey::from_bytes([0x41; 32]).expect("operation should succeed for valid inputs");
        let report_id = EngineObjectId([0xAA; 32]);
        let mut initial = BTreeSet::new();
        initial.insert(cap("clock"));
        initial.insert(cap("net_outbound"));
        let final_set = initial.clone();

        let input = ShadowAblationTranscriptInput {
            trace_id: "trace-transcript".to_string(),
            decision_id: "decision-transcript".to_string(),
            policy_id: "policy-transcript".to_string(),
            extension_id: "ext-transcript".to_string(),
            static_report_id: report_id,
            replay_corpus_id: "corpus-transcript".to_string(),
            randomness_snapshot_id: "rng-transcript".to_string(),
            deterministic_seed: 42,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: initial,
            final_capabilities: final_set,
            evaluations: vec![sample_evaluation("candidate-1")],
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };

        let transcript =
            SignedShadowAblationTranscript::create_signed(input, &signing_key).expect("sign");
        transcript.verify_signature().expect("verify");
    }

    #[test]
    fn fallback_quality_static_vs_partial() {
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Compute],
            phase: SynthesisPhase::Ablation,
            global_limit_hit: false,
            consumption: PhaseConsumption {
                time_ns: 0,
                compute: 101,
                depth: 3,
            },
            limit_value: 100,
        };

        let mut initial = BTreeSet::new();
        initial.insert(cap("clock"));
        initial.insert(cap("net_outbound"));

        let static_fallback = fallback_for(&reason, &initial, &initial);
        assert_eq!(static_fallback.quality, FallbackQuality::StaticBound);

        let mut partial = initial.clone();
        partial.remove(&cap("clock"));
        let partial_fallback = fallback_for(&reason, &initial, &partial);
        assert_eq!(partial_fallback.quality, FallbackQuality::PartialAblation);
    }

    #[test]
    fn config_validation_rejects_empty_ids() {
        let mut config = config_with_seed(1);
        config.trace_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("trace_id must be rejected");
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn config_validation_rejects_empty_decision_id() {
        let mut config = config_with_seed(1);
        config.decision_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("decision_id must be rejected");
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn config_validation_rejects_empty_policy_id() {
        let mut config = config_with_seed(1);
        config.policy_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("policy_id must be rejected");
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn config_validation_rejects_empty_extension_id() {
        let mut config = config_with_seed(1);
        config.extension_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("extension_id must be rejected");
        assert!(err.to_string().contains("extension_id"));
    }

    #[test]
    fn config_validation_rejects_empty_replay_corpus_id() {
        let mut config = config_with_seed(1);
        config.replay_corpus_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("replay_corpus_id must be rejected");
        assert!(err.to_string().contains("replay_corpus_id"));
    }

    #[test]
    fn config_validation_rejects_empty_randomness_snapshot_id() {
        let mut config = config_with_seed(1);
        config.randomness_snapshot_id.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("randomness_snapshot_id must be rejected");
        assert!(err.to_string().contains("randomness_snapshot_id"));
    }

    #[test]
    fn config_validation_rejects_empty_zone() {
        let mut config = config_with_seed(1);
        config.zone.clear();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("zone must be rejected");
        assert!(err.to_string().contains("zone"));
    }

    // ── Error Display ──────────────────────────────────────────────
    #[test]
    fn error_display_empty_static_upper_bound() {
        let err = ShadowAblationError::EmptyStaticUpperBound {
            extension_id: "ext-1".to_string(),
        };
        assert!(err.to_string().contains("ext-1"));
        assert!(err.to_string().contains("empty"));
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
    }

    #[test]
    fn error_display_invalid_config() {
        let err = ShadowAblationError::InvalidConfig {
            detail: "bad field".to_string(),
        };
        assert!(err.to_string().contains("bad field"));
    }

    #[test]
    fn error_display_invalid_oracle_result() {
        let err = ShadowAblationError::InvalidOracleResult {
            detail: "negative threshold".to_string(),
        };
        assert!(err.to_string().contains("negative threshold"));
    }

    #[test]
    fn error_display_budget() {
        let err = ShadowAblationError::Budget {
            detail: "compute exceeded".to_string(),
        };
        assert!(err.to_string().contains("compute exceeded"));
    }

    #[test]
    fn error_display_signature_failed() {
        let err = ShadowAblationError::SignatureFailed {
            detail: "key error".to_string(),
        };
        assert!(err.to_string().contains("key error"));
    }

    #[test]
    fn error_display_signature_invalid() {
        let err = ShadowAblationError::SignatureInvalid {
            detail: "tampered".to_string(),
        };
        assert!(err.to_string().contains("tampered"));
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
    }

    #[test]
    fn error_is_std_error() {
        let err = ShadowAblationError::Budget {
            detail: "test".to_string(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ── Enum Display ───────────────────────────────────────────────
    #[test]
    fn search_strategy_display() {
        assert_eq!(
            AblationSearchStrategy::LatticeGreedy.to_string(),
            "lattice_greedy"
        );
        assert_eq!(
            AblationSearchStrategy::BinaryGuided.to_string(),
            "binary_guided"
        );
    }

    #[test]
    fn search_stage_display() {
        assert_eq!(
            AblationSearchStage::SingleCapability.to_string(),
            "single_capability"
        );
        assert_eq!(
            AblationSearchStage::CorrelatedPair.to_string(),
            "correlated_pair"
        );
        assert_eq!(AblationSearchStage::BinaryBlock.to_string(), "binary_block");
    }

    #[test]
    fn failure_class_display() {
        assert_eq!(
            AblationFailureClass::CorrectnessRegression.to_string(),
            "ablation_correctness_regression"
        );
        assert_eq!(
            AblationFailureClass::InvariantViolation.to_string(),
            "ablation_invariant_violation"
        );
        assert_eq!(
            AblationFailureClass::RiskBudgetExceeded.to_string(),
            "ablation_risk_budget_exceeded"
        );
        assert_eq!(
            AblationFailureClass::ExecutionFailure.to_string(),
            "ablation_execution_failure"
        );
        assert_eq!(
            AblationFailureClass::OracleError.to_string(),
            "ablation_oracle_error"
        );
        assert_eq!(
            AblationFailureClass::InvalidOracleResult.to_string(),
            "ablation_invalid_oracle_result"
        );
        assert_eq!(
            AblationFailureClass::BudgetExhausted.to_string(),
            "ablation_budget_exhausted"
        );
    }

    // ── Serde round-trips ──────────────────────────────────────────
    #[test]
    fn search_strategy_serde_round_trip() {
        for variant in [
            AblationSearchStrategy::LatticeGreedy,
            AblationSearchStrategy::BinaryGuided,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: AblationSearchStrategy =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn search_stage_serde_round_trip() {
        for variant in [
            AblationSearchStage::SingleCapability,
            AblationSearchStage::CorrelatedPair,
            AblationSearchStage::BinaryBlock,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: AblationSearchStage =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn failure_class_serde_round_trip() {
        for variant in [
            AblationFailureClass::CorrectnessRegression,
            AblationFailureClass::InvariantViolation,
            AblationFailureClass::RiskBudgetExceeded,
            AblationFailureClass::ExecutionFailure,
            AblationFailureClass::OracleError,
            AblationFailureClass::InvalidOracleResult,
            AblationFailureClass::BudgetExhausted,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: AblationFailureClass =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn config_serde_round_trip() {
        let config = config_with_seed(42);
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let back: ShadowAblationConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(config, back);
    }

    #[test]
    fn config_default_values() {
        let config = ShadowAblationConfig::default();
        assert!(!config.trace_id.is_empty());
        assert_eq!(config.max_pair_trials, 256);
        assert_eq!(config.max_block_trials, 128);
        assert_eq!(config.strategy, AblationSearchStrategy::LatticeGreedy);
    }

    #[test]
    fn evaluation_record_serde_round_trip() {
        let record = sample_evaluation("test-candidate");
        let json = serde_json::to_string(&record).expect("serialize derived Serialize");
        let back: ShadowAblationEvaluationRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(record, back);
    }

    // ── Observation validation ─────────────────────────────────────
    #[test]
    fn observation_validate_negative_correctness_threshold_fails() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: -1,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 0,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://test".to_string(),
            evidence_pointer: "evidence://test".to_string(),
            execution_trace_hash: ContentHash::compute(b"test"),
            failure_detail: None,
        };
        let err = obs.validate().unwrap_err();
        assert!(err.to_string().contains("correctness_threshold"));
    }

    #[test]
    fn observation_validate_negative_risk_threshold_fails() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 0,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: -1,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://test".to_string(),
            evidence_pointer: "evidence://test".to_string(),
            execution_trace_hash: ContentHash::compute(b"test"),
            failure_detail: None,
        };
        let err = obs.validate().unwrap_err();
        assert!(err.to_string().contains("risk_threshold"));
    }

    #[test]
    fn observation_validate_empty_replay_pointer_fails() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 0,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 0,
            consumed: PhaseConsumption::zero(),
            replay_pointer: String::new(),
            evidence_pointer: "evidence://test".to_string(),
            execution_trace_hash: ContentHash::compute(b"test"),
            failure_detail: None,
        };
        let err = obs.validate().unwrap_err();
        assert!(err.to_string().contains("replay_pointer"));
    }

    #[test]
    fn observation_validate_empty_evidence_pointer_fails() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 0,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 0,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://test".to_string(),
            evidence_pointer: String::new(),
            execution_trace_hash: ContentHash::compute(b"test"),
            failure_detail: None,
        };
        let err = obs.validate().unwrap_err();
        assert!(err.to_string().contains("evidence_pointer"));
    }

    #[test]
    fn observation_validate_zero_trace_hash_fails() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 0,
            invariants: BTreeMap::new(),
            risk_score_millionths: 0,
            risk_threshold_millionths: 0,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://test".to_string(),
            evidence_pointer: "evidence://test".to_string(),
            execution_trace_hash: ContentHash([0u8; 32]),
            failure_detail: None,
        };
        let err = obs.validate().unwrap_err();
        assert!(err.to_string().contains("execution_trace_hash"));
    }

    #[test]
    fn observation_validate_valid() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 800_000,
            invariants: BTreeMap::new(),
            risk_score_millionths: 100_000,
            risk_threshold_millionths: 300_000,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://test".to_string(),
            evidence_pointer: "evidence://test".to_string(),
            execution_trace_hash: ContentHash::compute(b"test"),
            failure_detail: None,
        };
        obs.validate().expect("should be valid");
    }

    // ── Transcript tamper detection ────────────────────────────────
    #[test]
    fn tampered_transcript_fails_verification() {
        let signing_key =
            SigningKey::from_bytes([0x42; 32]).expect("operation should succeed for valid inputs");
        let input = ShadowAblationTranscriptInput {
            trace_id: "trace-tamper".to_string(),
            decision_id: "decision-tamper".to_string(),
            policy_id: "policy-tamper".to_string(),
            extension_id: "ext-tamper".to_string(),
            static_report_id: EngineObjectId([0xBB; 32]),
            replay_corpus_id: "corpus-tamper".to_string(),
            randomness_snapshot_id: "rng-tamper".to_string(),
            deterministic_seed: 99,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("clock")]),
            final_capabilities: BTreeSet::from([cap("clock")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let mut transcript = SignedShadowAblationTranscript::create_signed(input, &signing_key)
            .expect("operation should succeed for valid inputs");
        // Tamper with the transcript — signature check catches it first
        transcript.extension_id = "ext-evil".to_string();
        let err = transcript.verify_signature().unwrap_err();
        assert!(
            matches!(err, ShadowAblationError::SignatureInvalid { .. })
                || matches!(err, ShadowAblationError::IntegrityFailure { .. })
        );
    }

    // ── highest_power_of_two_leq ───────────────────────────────────
    #[test]
    fn highest_power_of_two_leq_values() {
        assert_eq!(highest_power_of_two_leq(0), 0);
        assert_eq!(highest_power_of_two_leq(1), 1);
        assert_eq!(highest_power_of_two_leq(2), 2);
        assert_eq!(highest_power_of_two_leq(3), 2);
        assert_eq!(highest_power_of_two_leq(4), 4);
        assert_eq!(highest_power_of_two_leq(7), 4);
        assert_eq!(highest_power_of_two_leq(8), 8);
        assert_eq!(highest_power_of_two_leq(15), 8);
        assert_eq!(highest_power_of_two_leq(16), 16);
    }

    // ── Engine run: empty static upper bound ───────────────────────
    #[test]
    fn run_rejects_empty_static_upper_bound() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::new());
        let signing_key =
            SigningKey::from_bytes([0x01; 32]).expect("operation should succeed for valid inputs");
        let err = engine
            .run(&report, &signing_key, |_| unreachable!())
            .unwrap_err();
        assert!(matches!(
            err,
            ShadowAblationError::EmptyStaticUpperBound { .. }
        ));
    }

    // ── Engine run: extension mismatch ─────────────────────────────
    #[test]
    fn run_rejects_extension_mismatch() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report("wrong-ext", BTreeSet::from([cap("fs_read")]));
        let signing_key =
            SigningKey::from_bytes([0x01; 32]).expect("operation should succeed for valid inputs");
        let err = engine
            .run(&report, &signing_key, |_| unreachable!())
            .unwrap_err();
        assert!(matches!(err, ShadowAblationError::ExtensionMismatch { .. }));
    }

    // ── Engine run: oracle error produces OracleError class ────────
    #[test]
    fn run_oracle_error_records_failure_class() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("fs_read"), cap("net")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x01; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Err(ShadowAblationError::Budget {
                    detail: "oracle boom".to_string(),
                })
            })
            .expect("operation should succeed for valid inputs");
        // All single-removal attempts should fail with OracleError class
        assert!(
            result
                .evaluations
                .iter()
                .all(|e| e.failure_class == Some(AblationFailureClass::OracleError))
        );
        // Capabilities unchanged since all oracle calls failed
        assert_eq!(result.minimal_capabilities, result.initial_capabilities);
    }

    // ── Engine run: invalid observation triggers InvalidOracleResult ──
    #[test]
    fn run_invalid_observation_records_failure() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("fs_read"), cap("net")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x01; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 900_000,
                    correctness_threshold_millionths: -1, // invalid
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 0,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://test".to_string(),
                    evidence_pointer: "evidence://test".to_string(),
                    execution_trace_hash: ContentHash::compute(b"test"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .evaluations
                .iter()
                .all(|e| e.failure_class == Some(AblationFailureClass::InvalidOracleResult))
        );
    }

    // ── Engine run: BinaryGuided strategy ──────────────────────────
    #[test]
    fn run_binary_guided_strategy_removes_capabilities() {
        let mut config = config_with_seed(42);
        config.strategy = AblationSearchStrategy::BinaryGuided;
        config.max_pair_trials = 10;
        config.max_block_trials = 10;
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
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
        let report = test_static_report(&config.extension_id, caps.clone());
        let signing_key =
            SigningKey::from_bytes([0x02; 32]).expect("operation should succeed for valid inputs");
        // Oracle that rejects single removals but accepts block removals (>= 2),
        // so that single-phase leaves caps intact and block phase actually runs.
        let result = engine
            .run(&report, &signing_key, |req| {
                let pass = req.removed_capabilities.len() >= 2;
                let score = if pass { 999_000 } else { 100_000 };
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: score,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.search_strategy, AblationSearchStrategy::BinaryGuided);
        // Should have BinaryBlock evaluations since single removals fail
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.search_stage == AblationSearchStage::BinaryBlock)
        );
        assert!(!result.budget_exhausted);
    }

    // ── Engine run: correctness regression ──────────────────────────
    #[test]
    fn run_correctness_regression_retains_capability() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only_cap")]));
        let signing_key =
            SigningKey::from_bytes([0x02; 32]).expect("operation should succeed for valid inputs");
        // Correctness below threshold => regression
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 100_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.minimal_capabilities.len(), 1);
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.failure_class == Some(AblationFailureClass::CorrectnessRegression))
        );
    }

    // ── Engine run: risk budget exceeded ────────────────────────────
    #[test]
    fn run_risk_budget_exceeded_retains_capability() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only_cap")]));
        let signing_key =
            SigningKey::from_bytes([0x02; 32]).expect("operation should succeed for valid inputs");
        // Risk above threshold
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 999_000,
                    risk_threshold_millionths: 100_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.minimal_capabilities.len(), 1);
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.failure_class == Some(AblationFailureClass::RiskBudgetExceeded))
        );
    }

    // ── Engine run: pair removal with successful pair ───────────────
    #[test]
    fn run_pair_removal_successful() {
        let mut config = config_with_seed(42);
        config.max_pair_trials = 100;
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("a"), cap("b"), cap("c")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x03; 32]).expect("operation should succeed for valid inputs");
        let call_count = std::cell::Cell::new(0u32);
        let result = engine
            .run(&report, &signing_key, |req| {
                let count = call_count.get();
                call_count.set(count + 1);
                // Reject single removals but accept pair removal
                let pass = req.removed_capabilities.len() >= 2 || count > 5;
                let score = if pass { 999_000 } else { 100_000 };
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: score,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        // Should have at least attempted pair removal
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.search_stage == AblationSearchStage::CorrelatedPair)
        );
    }

    // ── Unsigned bytes deterministic ───────────────────────────────
    #[test]
    fn transcript_unsigned_bytes_deterministic() {
        let signing_key =
            SigningKey::from_bytes([0x50; 32]).expect("operation should succeed for valid inputs");
        let input = || ShadowAblationTranscriptInput {
            trace_id: "trace-bytes".to_string(),
            decision_id: "decision-bytes".to_string(),
            policy_id: "policy-bytes".to_string(),
            extension_id: "ext-bytes".to_string(),
            static_report_id: EngineObjectId([0x11; 32]),
            replay_corpus_id: "corpus-bytes".to_string(),
            randomness_snapshot_id: "rng-bytes".to_string(),
            deterministic_seed: 7,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("x")]),
            final_capabilities: BTreeSet::from([cap("x")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let t1 = SignedShadowAblationTranscript::create_signed(input(), &signing_key)
            .expect("operation should succeed for valid inputs");
        let t2 = SignedShadowAblationTranscript::create_signed(input(), &signing_key)
            .expect("operation should succeed for valid inputs");
        assert_eq!(t1.unsigned_bytes(), t2.unsigned_bytes());
        assert_eq!(t1.transcript_hash, t2.transcript_hash);
    }

    // ── Log event and run result serde ─────────────────────────────
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
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: ShadowAblationLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, back);
    }

    #[test]
    fn candidate_request_serde_round_trip() {
        let req = ShadowAblationCandidateRequest {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            extension_id: "e".to_string(),
            search_stage: AblationSearchStage::SingleCapability,
            sequence: 1,
            candidate_id: "cand-1".to_string(),
            removed_capabilities: BTreeSet::from([cap("a")]),
            candidate_capabilities: BTreeSet::from([cap("b")]),
            replay_corpus_id: "corpus".to_string(),
            randomness_snapshot_id: "rng".to_string(),
            deterministic_seed: 42,
        };
        let json = serde_json::to_string(&req).expect("serialize derived Serialize");
        let back: ShadowAblationCandidateRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(req, back);
    }

    #[test]
    fn observation_serde_round_trip() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 900_000,
            correctness_threshold_millionths: 800_000,
            invariants: BTreeMap::from([("inv_a".to_string(), true)]),
            risk_score_millionths: 50_000,
            risk_threshold_millionths: 300_000,
            consumed: PhaseConsumption::zero(),
            replay_pointer: "replay://obs".to_string(),
            evidence_pointer: "evidence://obs".to_string(),
            execution_trace_hash: ContentHash::compute(b"obs"),
            failure_detail: None,
        };
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: ShadowAblationObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(obs, back);
    }

    // ── Engine config accessor ─────────────────────────────────────
    #[test]
    fn engine_config_accessor() {
        let config = config_with_seed(99);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        assert_eq!(engine.config(), &config);
    }

    // ── Enrichment: serde roundtrips for remaining types ───────────

    #[test]
    fn shadow_ablation_error_serde_round_trip() {
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
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let restored: ShadowAblationError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn transcript_input_serde_round_trip() {
        let input = ShadowAblationTranscriptInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            extension_id: "e".to_string(),
            static_report_id: EngineObjectId([0x11; 32]),
            replay_corpus_id: "corpus".to_string(),
            randomness_snapshot_id: "rng".to_string(),
            deterministic_seed: 42,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("a"), cap("b")]),
            final_capabilities: BTreeSet::from([cap("a")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let json = serde_json::to_string(&input).expect("serialize derived Serialize");
        let restored: ShadowAblationTranscriptInput =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(input, restored);
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

    #[test]
    fn failure_class_ordering() {
        assert!(
            AblationFailureClass::CorrectnessRegression < AblationFailureClass::InvariantViolation
        );
    }

    // -- Enrichment: missing serde roundtrips --

    #[test]
    fn run_result_serde_roundtrip() {
        use crate::hash_tiers::ContentHash;

        let result = ShadowAblationRunResult {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            extension_id: "ext-1".to_string(),
            static_report_id: EngineObjectId([0xAA; 32]),
            search_strategy: AblationSearchStrategy::BinaryGuided,
            initial_capabilities: BTreeSet::from([
                Capability("cap-a".to_string()),
                Capability("cap-b".to_string()),
            ]),
            minimal_capabilities: BTreeSet::from([Capability("cap-a".to_string())]),
            evaluations: vec![],
            logs: vec![],
            budget_exhausted: false,
            fallback: None,
            budget_utilization: BTreeMap::new(),
            transcript: SignedShadowAblationTranscript {
                transcript_id: "tx-1".to_string(),
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                extension_id: "ext-1".to_string(),
                static_report_id: EngineObjectId([0xAA; 32]),
                replay_corpus_id: "corpus-1".to_string(),
                randomness_snapshot_id: "rng-1".to_string(),
                deterministic_seed: 42,
                search_strategy: AblationSearchStrategy::BinaryGuided,
                initial_capabilities: BTreeSet::from([
                    Capability("cap-a".to_string()),
                    Capability("cap-b".to_string()),
                ]),
                final_capabilities: BTreeSet::from([Capability("cap-a".to_string())]),
                evaluations: vec![],
                fallback: None,
                budget_utilization: BTreeMap::new(),
                transcript_hash: ContentHash::compute(b"test-hash"),
                signer: SigningKey::from_bytes([1u8; 32])
                    .expect("operation should succeed for valid inputs")
                    .verification_key(),
                signature: Signature::from_bytes([0u8; 64]),
            },
        };
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let restored: ShadowAblationRunResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(result, restored);
    }

    #[test]
    fn signed_transcript_serde_roundtrip() {
        use crate::hash_tiers::ContentHash;

        let transcript = SignedShadowAblationTranscript {
            transcript_id: "tx-2".to_string(),
            trace_id: "t2".to_string(),
            decision_id: "d2".to_string(),
            policy_id: "p2".to_string(),
            extension_id: "ext-2".to_string(),
            static_report_id: EngineObjectId([0xCC; 32]),
            replay_corpus_id: "corpus-2".to_string(),
            randomness_snapshot_id: "rng-2".to_string(),
            deterministic_seed: 99,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([
                Capability("read".to_string()),
                Capability("write".to_string()),
            ]),
            final_capabilities: BTreeSet::from([Capability("read".to_string())]),
            evaluations: vec![],
            fallback: None,
            budget_utilization: BTreeMap::new(),
            transcript_hash: ContentHash::compute(b"tx-hash-2"),
            signer: SigningKey::from_bytes([2u8; 32])
                .expect("operation should succeed for valid inputs")
                .verification_key(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let json = serde_json::to_string(&transcript).expect("serialize derived Serialize");
        let restored: SignedShadowAblationTranscript =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(transcript, restored);
    }

    #[test]
    fn failure_class_error_codes() {
        assert_eq!(
            AblationFailureClass::CorrectnessRegression.error_code(),
            "ablation_correctness_regression"
        );
        assert_eq!(
            AblationFailureClass::BudgetExhausted.error_code(),
            "ablation_budget_exhausted"
        );
    }

    #[test]
    fn ablation_search_strategy_ord() {
        assert!(AblationSearchStrategy::LatticeGreedy < AblationSearchStrategy::BinaryGuided);
    }

    #[test]
    fn ablation_search_stage_ord() {
        assert!(AblationSearchStage::SingleCapability < AblationSearchStage::CorrelatedPair);
        assert!(AblationSearchStage::CorrelatedPair < AblationSearchStage::BinaryBlock);
    }

    #[test]
    fn ablation_failure_class_ord() {
        assert!(
            AblationFailureClass::CorrectnessRegression < AblationFailureClass::InvariantViolation
        );
        assert!(
            AblationFailureClass::InvariantViolation < AblationFailureClass::RiskBudgetExceeded
        );
        assert!(AblationFailureClass::ExecutionFailure < AblationFailureClass::OracleError);
        assert!(AblationFailureClass::InvalidOracleResult < AblationFailureClass::BudgetExhausted);
    }

    // -----------------------------------------------------------------------
    // Enrichment: helper function coverage
    // -----------------------------------------------------------------------

    #[test]
    fn to_hex_empty_bytes() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_known_values() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x0a, 0xb3]), "00ff0ab3");
    }

    #[test]
    fn capability_names_preserves_btree_order() {
        let mut caps = BTreeSet::new();
        caps.insert(cap("z_last"));
        caps.insert(cap("a_first"));
        caps.insert(cap("m_mid"));
        let names = capability_names(&caps);
        assert_eq!(names, vec!["a_first", "m_mid", "z_last"]);
    }

    #[test]
    fn capability_names_empty_set() {
        let caps = BTreeSet::new();
        assert!(capability_names(&caps).is_empty());
    }

    #[test]
    fn capability_set_digest_deterministic() {
        let mut caps = BTreeSet::new();
        caps.insert(cap("alpha"));
        caps.insert(cap("beta"));
        let d1 = capability_set_digest(&caps);
        let d2 = capability_set_digest(&caps);
        assert_eq!(d1, d2, "digest must be deterministic");
    }

    #[test]
    fn capability_set_digest_differs_for_different_sets() {
        let mut a = BTreeSet::new();
        a.insert(cap("alpha"));
        let mut b = BTreeSet::new();
        b.insert(cap("beta"));
        assert_ne!(capability_set_digest(&a), capability_set_digest(&b));
    }

    #[test]
    fn capability_value_produces_array() {
        let mut caps = BTreeSet::new();
        caps.insert(cap("read"));
        caps.insert(cap("write"));
        let val = capability_value(&caps);
        if let CanonicalValue::Array(arr) = &val {
            assert_eq!(arr.len(), 2);
        } else {
            panic!("expected Array, got {val:?}");
        }
    }

    #[test]
    fn string_map_value_produces_map() {
        let mut m = BTreeMap::new();
        m.insert("enabled".to_string(), true);
        m.insert("verbose".to_string(), false);
        let val = string_map_value(&m);
        if let CanonicalValue::Map(map) = &val {
            assert_eq!(map.len(), 2);
            assert_eq!(map["enabled"], CanonicalValue::Bool(true));
            assert_eq!(map["verbose"], CanonicalValue::Bool(false));
        } else {
            panic!("expected Map, got {val:?}");
        }
    }

    #[test]
    fn phase_consumption_value_fields() {
        let pc = PhaseConsumption {
            time_ns: 42,
            compute: 7,
            depth: 3,
        };
        let val = phase_consumption_value(&pc);
        if let CanonicalValue::Map(map) = &val {
            assert_eq!(map["time_ns"], CanonicalValue::U64(42));
            assert_eq!(map["compute"], CanonicalValue::U64(7));
            assert_eq!(map["depth"], CanonicalValue::U64(3));
        } else {
            panic!("expected Map, got {val:?}");
        }
    }

    #[test]
    fn utilization_value_all_dimensions() {
        let mut m = BTreeMap::new();
        m.insert(BudgetDimension::Time, 100);
        m.insert(BudgetDimension::Compute, -50);
        m.insert(BudgetDimension::Depth, 0);
        let val = utilization_value(&m);
        if let CanonicalValue::Map(map) = &val {
            assert_eq!(map.len(), 3);
        } else {
            panic!("expected Map, got {val:?}");
        }
    }

    #[test]
    fn fallback_value_none_is_null() {
        assert_eq!(fallback_value(&None), CanonicalValue::Null);
    }

    #[test]
    fn fallback_value_some_has_quality_key() {
        let result = FallbackResult {
            quality: FallbackQuality::StaticBound,
            result_digest: "digest-001".to_string(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Time],
                phase: SynthesisPhase::Ablation,
                global_limit_hit: false,
                consumption: PhaseConsumption {
                    time_ns: 999,
                    compute: 0,
                    depth: 0,
                },
                limit_value: 1000,
            },
            increase_likely_helpful: true,
            recommended_multiplier: Some(2_000_000),
        };
        let val = fallback_value(&Some(result));
        if let CanonicalValue::Map(map) = &val {
            assert!(map.contains_key("quality"));
            assert!(map.contains_key("result_digest"));
            assert!(map.contains_key("exhaustion_reason"));
            assert!(map.contains_key("increase_likely_helpful"));
        } else {
            panic!("expected Map, got {val:?}");
        }
    }

    #[test]
    fn capability_as_str_returns_inner_name() {
        let c = cap("network.http");
        assert_eq!(c.as_str(), "network.http");
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn fallback_for_non_helpful_dimensions_no_multiplier() {
        // When exceeded_dimensions are not Time/Compute/Depth,
        // increase_likely_helpful should be false and recommended_multiplier None.
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![], // empty => no helpful dimension
            phase: SynthesisPhase::Ablation,
            global_limit_hit: true,
            consumption: PhaseConsumption {
                time_ns: 0,
                compute: 0,
                depth: 0,
            },
            limit_value: 50,
        };
        let initial = BTreeSet::from([cap("a"), cap("b")]);
        let current = BTreeSet::from([cap("a")]); // partial
        let result = fallback_for(&reason, &initial, &current);
        assert_eq!(result.quality, FallbackQuality::PartialAblation);
        assert!(!result.increase_likely_helpful);
        assert_eq!(result.recommended_multiplier, None);
    }

    #[test]
    fn fallback_for_time_dimension_recommends_multiplier() {
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time],
            phase: SynthesisPhase::Ablation,
            global_limit_hit: false,
            consumption: PhaseConsumption {
                time_ns: 1000,
                compute: 0,
                depth: 0,
            },
            limit_value: 500,
        };
        let initial = BTreeSet::from([cap("x")]);
        let result = fallback_for(&reason, &initial, &initial);
        assert!(result.increase_likely_helpful);
        assert_eq!(result.recommended_multiplier, Some(1_500_000));
    }

    #[test]
    fn candidate_id_deterministic_for_same_inputs() {
        let config = config_with_seed(42);
        let removed = BTreeSet::from([cap("a")]);
        let candidate = BTreeSet::from([cap("b"), cap("c")]);
        let id1 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &removed,
            &candidate,
        );
        let id2 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &removed,
            &candidate,
        );
        assert_eq!(id1, id2);
        assert!(id1.starts_with("ablate-"));
    }

    #[test]
    fn candidate_id_differs_for_different_stage() {
        let config = config_with_seed(42);
        let removed = BTreeSet::from([cap("a")]);
        let candidate = BTreeSet::from([cap("b")]);
        let id_single = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &removed,
            &candidate,
        );
        let id_pair = candidate_id(
            &config,
            AblationSearchStage::CorrelatedPair,
            1,
            &removed,
            &candidate,
        );
        assert_ne!(id_single, id_pair);
    }

    #[test]
    fn candidate_id_differs_for_different_sequence() {
        let config = config_with_seed(42);
        let removed = BTreeSet::from([cap("a")]);
        let candidate = BTreeSet::from([cap("b")]);
        let id1 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &removed,
            &candidate,
        );
        let id2 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            2,
            &removed,
            &candidate,
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn log_event_helper_populates_fields() {
        let config = config_with_seed(7);
        let removed = BTreeSet::from([cap("net")]);
        let event = log_event(
            &config,
            "test_event",
            "pass",
            Some("code-1".to_string()),
            Some(AblationSearchStage::BinaryBlock),
            Some("cand-99".to_string()),
            &removed,
            Some(5),
        );
        assert_eq!(event.trace_id, config.trace_id);
        assert_eq!(event.decision_id, config.decision_id);
        assert_eq!(event.policy_id, config.policy_id);
        assert_eq!(event.component, SHADOW_ABLATION_COMPONENT);
        assert_eq!(event.event, "test_event");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code, Some("code-1".to_string()));
        assert_eq!(event.search_stage, Some("binary_block".to_string()));
        assert_eq!(event.candidate_id, Some("cand-99".to_string()));
        assert_eq!(event.removed_capabilities, vec!["net".to_string()]);
        assert_eq!(event.remaining_capability_count, Some(5));
    }

    #[test]
    fn evaluation_record_canonical_value_contains_all_keys() {
        let record = sample_evaluation("canonical-test");
        let val = record.canonical_value();
        if let CanonicalValue::Map(map) = &val {
            let expected_keys = [
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
            for key in expected_keys {
                assert!(map.contains_key(key), "missing key: {key}");
            }
            assert_eq!(map.len(), expected_keys.len());
        } else {
            panic!("expected Map from canonical_value");
        }
    }

    #[test]
    fn run_invariant_violation_retains_capability() {
        let mut config = config_with_seed(1);
        config.required_invariants = BTreeSet::from(["must_hold".to_string()]);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
        let signing_key =
            SigningKey::from_bytes([0x04; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::from([("must_hold".to_string(), false)]),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://inv".to_string(),
                    evidence_pointer: "evidence://inv".to_string(),
                    execution_trace_hash: ContentHash::compute(b"inv"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.minimal_capabilities.len(), 1);
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.failure_class == Some(AblationFailureClass::InvariantViolation))
        );
    }

    #[test]
    fn run_execution_failure_retains_capability() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
        let signing_key =
            SigningKey::from_bytes([0x05; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://exec".to_string(),
                    evidence_pointer: "evidence://exec".to_string(),
                    execution_trace_hash: ContentHash::compute(b"exec"),
                    failure_detail: Some("runtime crash".to_string()),
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.minimal_capabilities.len(), 1);
        assert!(
            result
                .evaluations
                .iter()
                .any(|e| e.failure_class == Some(AblationFailureClass::ExecutionFailure))
        );
    }

    #[test]
    fn run_successful_single_removal_reduces_capabilities() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("essential"), cap("removable")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x06; 32]).expect("operation should succeed for valid inputs");
        // Oracle: accept removal of "removable", reject removal of "essential"
        let result = engine
            .run(&report, &signing_key, |req| {
                let pass = !req.removed_capabilities.contains(&cap("essential"));
                let score = if pass { 999_000 } else { 100_000 };
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: score,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert!(
            result.minimal_capabilities.len() < result.initial_capabilities.len(),
            "should have removed at least one capability"
        );
        assert!(result.minimal_capabilities.contains(&cap("essential")));
        assert!(!result.budget_exhausted);
    }

    #[test]
    fn config_validation_rejects_whitespace_only_trace_id() {
        let mut config = config_with_seed(1);
        config.trace_id = "   ".to_string();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("whitespace-only trace_id must be rejected");
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn config_with_required_invariants_serde_roundtrip() {
        let mut config = config_with_seed(99);
        config.required_invariants = BTreeSet::from([
            "no_exfiltration".to_string(),
            "no_side_channels".to_string(),
        ]);
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let restored: ShadowAblationConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(config, restored);
        assert_eq!(restored.required_invariants.len(), 2);
    }

    #[test]
    fn transcript_hash_sensitive_to_trace_id() {
        let key = SigningKey::from_bytes([0x60; 32]).expect("operation should succeed for valid inputs");
        let make_input = |trace: &str| ShadowAblationTranscriptInput {
            trace_id: trace.to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            extension_id: "e".to_string(),
            static_report_id: EngineObjectId([0x11; 32]),
            replay_corpus_id: "c".to_string(),
            randomness_snapshot_id: "r".to_string(),
            deterministic_seed: 1,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("a")]),
            final_capabilities: BTreeSet::from([cap("a")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let t1 = SignedShadowAblationTranscript::create_signed(make_input("trace-A"), &key)
            .expect("operation should succeed for valid inputs");
        let t2 = SignedShadowAblationTranscript::create_signed(make_input("trace-B"), &key)
            .expect("operation should succeed for valid inputs");
        assert_ne!(t1.transcript_hash, t2.transcript_hash);
    }

    #[test]
    fn transcript_hash_sensitive_to_seed() {
        let key = SigningKey::from_bytes([0x61; 32]).expect("operation should succeed for valid inputs");
        let make_input = |seed: u64| ShadowAblationTranscriptInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            extension_id: "e".to_string(),
            static_report_id: EngineObjectId([0x22; 32]),
            replay_corpus_id: "c".to_string(),
            randomness_snapshot_id: "r".to_string(),
            deterministic_seed: seed,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("x")]),
            final_capabilities: BTreeSet::from([cap("x")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let t1 = SignedShadowAblationTranscript::create_signed(make_input(1), &key)
            .expect("operation should succeed for valid inputs");
        let t2 = SignedShadowAblationTranscript::create_signed(make_input(2), &key)
            .expect("operation should succeed for valid inputs");
        assert_ne!(t1.transcript_hash, t2.transcript_hash);
    }

    #[test]
    fn seeded_capability_order_single_element() {
        let caps = BTreeSet::from([cap("singleton")]);
        let order = seeded_capability_order(&caps, 0);
        assert_eq!(order.len(), 1);
        assert_eq!(order[0], cap("singleton"));
    }

    #[test]
    fn highest_power_of_two_leq_large_values() {
        assert_eq!(highest_power_of_two_leq(1023), 512);
        assert_eq!(highest_power_of_two_leq(1024), 1024);
        assert_eq!(highest_power_of_two_leq(1025), 1024);
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26 session 2
    // -----------------------------------------------------------------------

    #[test]
    fn shadow_ablation_component_constant() {
        assert_eq!(SHADOW_ABLATION_COMPONENT, "shadow_ablation_engine");
    }

    #[test]
    fn shadow_ablation_transcript_domain_constant() {
        assert_eq!(
            SHADOW_ABLATION_TRANSCRIPT_DOMAIN,
            b"FrankenEngine.ShadowAblationTranscript.v1"
        );
    }

    #[test]
    fn config_default_all_fields() {
        let config = ShadowAblationConfig::default();
        assert_eq!(config.trace_id, "trace-shadow-ablation-default");
        assert_eq!(config.decision_id, "decision-shadow-ablation-default");
        assert_eq!(config.policy_id, "policy-shadow-ablation-default");
        assert_eq!(config.extension_id, "extension-shadow-ablation-default");
        assert_eq!(config.replay_corpus_id, "replay-corpus-default");
        assert_eq!(config.randomness_snapshot_id, "rng-snapshot-default");
        assert_eq!(config.deterministic_seed, 0x5EED_AB1A_7100u64);
        assert_eq!(config.strategy, AblationSearchStrategy::LatticeGreedy);
        assert!(config.required_invariants.is_empty());
        assert_eq!(config.max_pair_trials, 256);
        assert_eq!(config.max_block_trials, 128);
        assert_eq!(config.zone, "default");
    }

    #[test]
    fn failure_class_error_codes_all_variants() {
        let codes = [
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
        let mut seen = BTreeSet::new();
        for (class, expected) in &codes {
            assert_eq!(class.error_code(), *expected);
            seen.insert(class.error_code());
        }
        assert_eq!(seen.len(), codes.len(), "all error codes must be distinct");
    }

    #[test]
    fn seeded_capability_order_empty_set() {
        let caps = BTreeSet::new();
        let order = seeded_capability_order(&caps, 42);
        assert!(order.is_empty());
    }

    #[test]
    fn capability_set_digest_empty_set() {
        let a = BTreeSet::new();
        let digest = capability_set_digest(&a);
        assert!(!digest.is_empty());
    }

    #[test]
    fn transcript_id_format_starts_with_prefix() {
        let signing_key =
            SigningKey::from_bytes([0x70; 32]).expect("operation should succeed for valid inputs");
        let input = ShadowAblationTranscriptInput {
            trace_id: "t-prefix".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            extension_id: "e".to_string(),
            static_report_id: EngineObjectId([0x33; 32]),
            replay_corpus_id: "c".to_string(),
            randomness_snapshot_id: "r".to_string(),
            deterministic_seed: 1,
            search_strategy: AblationSearchStrategy::LatticeGreedy,
            initial_capabilities: BTreeSet::from([cap("x")]),
            final_capabilities: BTreeSet::from([cap("x")]),
            evaluations: Vec::new(),
            fallback: None,
            budget_utilization: BTreeMap::new(),
        };
        let transcript = SignedShadowAblationTranscript::create_signed(input, &signing_key)
            .expect("operation should succeed for valid inputs");
        assert!(
            transcript.transcript_id.starts_with("shadow-ablation-"),
            "transcript_id should start with 'shadow-ablation-', got: {}",
            transcript.transcript_id,
        );
    }

    #[test]
    fn evaluation_record_canonical_value_with_failure() {
        let mut record = sample_evaluation("fail-record");
        record.pass = false;
        record.failure_class = Some(AblationFailureClass::CorrectnessRegression);
        record.failure_detail = Some("score below threshold".to_string());
        let val = record.canonical_value();
        if let CanonicalValue::Map(map) = &val {
            assert_eq!(
                map.get("failure_class"),
                Some(&CanonicalValue::String(
                    "ablation_correctness_regression".to_string()
                ))
            );
            assert_eq!(
                map.get("failure_detail"),
                Some(&CanonicalValue::String("score below threshold".to_string()))
            );
            assert_eq!(map.get("pass"), Some(&CanonicalValue::Bool(false)));
        } else {
            panic!("expected Map from canonical_value");
        }
    }

    #[test]
    fn observation_with_failure_detail_serde() {
        let obs = ShadowAblationObservation {
            correctness_score_millionths: 500_000,
            correctness_threshold_millionths: 800_000,
            invariants: BTreeMap::from([("inv".to_string(), false)]),
            risk_score_millionths: 200_000,
            risk_threshold_millionths: 300_000,
            consumed: PhaseConsumption {
                time_ns: 10,
                compute: 5,
                depth: 2,
            },
            replay_pointer: "replay://detail".to_string(),
            evidence_pointer: "evidence://detail".to_string(),
            execution_trace_hash: ContentHash::compute(b"detail"),
            failure_detail: Some("bad things happened".to_string()),
        };
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: ShadowAblationObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(obs, back);
        assert_eq!(back.failure_detail.as_deref(), Some("bad things happened"));
    }

    #[test]
    fn candidate_id_differs_for_different_removed_capabilities() {
        let config = config_with_seed(42);
        let candidate = BTreeSet::from([cap("b")]);
        let id1 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &BTreeSet::from([cap("a")]),
            &candidate,
        );
        let id2 = candidate_id(
            &config,
            AblationSearchStage::SingleCapability,
            1,
            &BTreeSet::from([cap("c")]),
            &candidate,
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn run_result_logs_contain_start_and_complete() {
        let config = config_with_seed(1);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
        let signing_key =
            SigningKey::from_bytes([0x07; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .logs
                .iter()
                .any(|l| l.event == "shadow_ablation_started"),
            "must have start log"
        );
        assert!(
            result
                .logs
                .iter()
                .any(|l| l.event == "shadow_ablation_completed"),
            "must have completion log"
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 session 7 --

    #[test]
    fn config_validation_rejects_whitespace_only_zone() {
        let mut config = config_with_seed(1);
        config.zone = "  \t ".to_string();
        let err = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
            .expect_err("whitespace-only zone must be rejected");
        assert!(err.to_string().contains("zone"));
    }

    #[test]
    fn run_all_caps_removable_reduces_to_empty() {
        // When oracle accepts every single removal, the minimal set should be empty.
        let config = config_with_seed(7);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("a"), cap("b"), cap("c")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x08; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert!(
            result.minimal_capabilities.is_empty(),
            "all caps should be removed when oracle always accepts"
        );
        assert!(!result.budget_exhausted);
    }

    #[test]
    fn run_max_pair_trials_limits_pair_search() {
        // With max_pair_trials=1 and single removals rejected, pair phase should stop after 1 trial.
        let mut config = config_with_seed(1);
        config.max_pair_trials = 1;
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(
            &config.extension_id,
            BTreeSet::from([cap("a"), cap("b"), cap("c")]),
        );
        let signing_key =
            SigningKey::from_bytes([0x09; 32]).expect("operation should succeed for valid inputs");
        let pair_count = std::cell::Cell::new(0u32);
        let result = engine
            .run(&report, &signing_key, |req| {
                if req.search_stage == AblationSearchStage::CorrelatedPair {
                    pair_count.set(pair_count.get() + 1);
                }
                // Reject all removals
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 100_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert!(
            pair_count.get() <= 1,
            "pair phase should stop after max_pair_trials=1, but got {}",
            pair_count.get()
        );
        assert_eq!(
            result.minimal_capabilities.len(),
            3,
            "no caps should be removed"
        );
    }

    #[test]
    fn fallback_value_none_recommended_multiplier() {
        let result = FallbackResult {
            quality: FallbackQuality::PartialAblation,
            result_digest: "digest-none".to_string(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![], // no helpful dimension → None multiplier
                phase: SynthesisPhase::Ablation,
                global_limit_hit: true,
                consumption: PhaseConsumption::zero(),
                limit_value: 100,
            },
            increase_likely_helpful: false,
            recommended_multiplier: None,
        };
        let val = fallback_value(&Some(result));
        if let CanonicalValue::Map(map) = &val {
            assert_eq!(
                map.get("recommended_multiplier"),
                Some(&CanonicalValue::Null),
                "None recommended_multiplier should map to CanonicalValue::Null"
            );
        } else {
            panic!("expected Map, got {val:?}");
        }
    }

    #[test]
    fn transcript_as_unsigned_input_roundtrip() {
        let signing_key =
            SigningKey::from_bytes([0x0A; 32]).expect("operation should succeed for valid inputs");
        let original_input = ShadowAblationTranscriptInput {
            trace_id: "trace-roundtrip".to_string(),
            decision_id: "decision-roundtrip".to_string(),
            policy_id: "policy-roundtrip".to_string(),
            extension_id: "ext-roundtrip".to_string(),
            static_report_id: EngineObjectId([0xDD; 32]),
            replay_corpus_id: "corpus-roundtrip".to_string(),
            randomness_snapshot_id: "rng-roundtrip".to_string(),
            deterministic_seed: 77,
            search_strategy: AblationSearchStrategy::BinaryGuided,
            initial_capabilities: BTreeSet::from([cap("a"), cap("b")]),
            final_capabilities: BTreeSet::from([cap("a")]),
            evaluations: vec![sample_evaluation("rt-1")],
            fallback: None,
            budget_utilization: BTreeMap::from([(BudgetDimension::Compute, 42)]),
        };
        let transcript =
            SignedShadowAblationTranscript::create_signed(original_input.clone(), &signing_key)
                .expect("operation should succeed for valid inputs");
        let recovered = transcript.as_unsigned_input();
        assert_eq!(recovered, original_input);
    }

    #[test]
    fn run_binary_guided_two_caps_block_size_zero() {
        // With exactly 2 capabilities, highest_power_of_two_leq(2/2) = 1 < 2,
        // so block phase should be skipped (block_size starts at 1, loop requires >= 2).
        let mut config = config_with_seed(5);
        config.strategy = AblationSearchStrategy::BinaryGuided;
        config.max_pair_trials = 10;
        config.max_block_trials = 10;
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("x"), cap("y")]));
        let signing_key =
            SigningKey::from_bytes([0x0B; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                // Reject all removals
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 100_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://ok".to_string(),
                    evidence_pointer: "evidence://ok".to_string(),
                    execution_trace_hash: ContentHash::compute(b"ok"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        // No block evaluations should exist because block_size < 2
        assert!(
            !result
                .evaluations
                .iter()
                .any(|e| e.search_stage == AblationSearchStage::BinaryBlock),
            "binary block phase should not run with only 2 capabilities"
        );
        assert_eq!(result.minimal_capabilities.len(), 2);
    }

    #[test]
    fn evaluation_record_canonical_value_with_invariant_failures() {
        let mut record = sample_evaluation("inv-fail");
        record.pass = false;
        record.failure_class = Some(AblationFailureClass::InvariantViolation);
        record.invariant_failures = vec!["no_exfil".to_string(), "no_side_channel".to_string()];
        record.invariants = BTreeMap::from([
            ("no_exfil".to_string(), false),
            ("no_side_channel".to_string(), false),
        ]);
        let val = record.canonical_value();
        if let CanonicalValue::Map(map) = &val {
            if let Some(CanonicalValue::Array(failures)) = map.get("invariant_failures") {
                assert_eq!(failures.len(), 2);
                assert_eq!(failures[0], CanonicalValue::String("no_exfil".to_string()));
            } else {
                panic!("invariant_failures should be an Array");
            }
            if let Some(CanonicalValue::Map(inv_map)) = map.get("invariants") {
                assert_eq!(inv_map.get("no_exfil"), Some(&CanonicalValue::Bool(false)));
            } else {
                panic!("invariants should be a Map");
            }
        } else {
            panic!("expected Map from canonical_value");
        }
    }

    #[test]
    fn run_required_invariant_absent_from_observation_fails() {
        // When a required invariant is missing from the observation's invariant map,
        // it should default to false and produce InvariantViolation.
        let mut config = config_with_seed(1);
        config.required_invariants = BTreeSet::from(["missing_inv".to_string()]);
        let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
            .expect("operation should succeed for valid inputs");
        let report = test_static_report(&config.extension_id, BTreeSet::from([cap("only")]));
        let signing_key =
            SigningKey::from_bytes([0x0C; 32]).expect("operation should succeed for valid inputs");
        let result = engine
            .run(&report, &signing_key, |_| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 999_000,
                    correctness_threshold_millionths: 500_000,
                    invariants: BTreeMap::new(), // missing_inv not present
                    risk_score_millionths: 0,
                    risk_threshold_millionths: 500_000,
                    consumed: PhaseConsumption::zero(),
                    replay_pointer: "replay://inv".to_string(),
                    evidence_pointer: "evidence://inv".to_string(),
                    execution_trace_hash: ContentHash::compute(b"inv"),
                    failure_detail: None,
                })
            })
            .expect("operation should succeed for valid inputs");
        assert_eq!(
            result.minimal_capabilities.len(),
            1,
            "cap should be retained"
        );
        assert!(
            result.evaluations.iter().any(|e| e.failure_class
                == Some(AblationFailureClass::InvariantViolation)
                && e.invariant_failures.contains(&"missing_inv".to_string())),
            "missing required invariant should cause InvariantViolation with failure listed"
        );
    }
}
