//! Flow envelope synthesis: the set of source-label → sink-clearance flows
//! actually required by an extension.
//!
//! Extends PLAS (Provably Least-Authority Synthesis) to synthesize minimal
//! flow envelopes alongside capability envelopes.  Given an extension's
//! static flow analysis and dynamic ablation results, produces a tight
//! flow envelope with confidence bounds.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//!
//! Plan reference: Section 10.15 item 9I.7, bd-1v90.
//! Dependencies: bd-2w9w (capability_witness), bd-3hkk (declassification),
//!               bd-1ovk (IFC artifacts).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{FlowRule, Label};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ENVELOPE_ZONE: &str = "flow_envelope";
const ENVELOPE_SCHEMA_DEF: &[u8] = b"FlowEnvelope.v1";

/// Fixed-point unit: 1_000_000 = 1.0.
#[allow(dead_code)]
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Flow requirement (enriched flow rule with provenance)
// ---------------------------------------------------------------------------

/// A flow requirement with provenance tracking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowRequirement {
    /// The source → sink flow rule.
    pub rule: FlowRule,
    /// How this requirement was discovered.
    pub discovery_method: FlowDiscoveryMethod,
    /// Code location where the flow originates (if known).
    pub source_location: Option<String>,
    /// Code location where the flow terminates (if known).
    pub sink_location: Option<String>,
}

/// How a flow requirement was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlowDiscoveryMethod {
    /// Derived from static IR analysis.
    StaticAnalysis,
    /// Confirmed through dynamic ablation.
    DynamicAblation,
    /// Discovered at runtime through label-propagation check.
    RuntimeObservation,
    /// Upper bound from manifest declaration.
    ManifestDeclaration,
}

impl fmt::Display for FlowDiscoveryMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticAnalysis => write!(f, "static_analysis"),
            Self::DynamicAblation => write!(f, "dynamic_ablation"),
            Self::RuntimeObservation => write!(f, "runtime_observation"),
            Self::ManifestDeclaration => write!(f, "manifest_declaration"),
        }
    }
}

// ---------------------------------------------------------------------------
// Flow proof obligation
// ---------------------------------------------------------------------------

/// An obligation to provide proof for a flow in the envelope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowProofObligation {
    /// The flow rule requiring proof.
    pub rule: FlowRule,
    /// Required proof method.
    pub required_method: FlowProofMethod,
    /// Human-readable justification for why proof is needed.
    pub justification: String,
    /// Content hash of the proof artifact (if satisfied).
    pub proof_artifact_hash: Option<ContentHash>,
}

/// Method required to prove a flow is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlowProofMethod {
    /// Static analysis proves the flow is safe.
    StaticAnalysis,
    /// Runtime check enforces the flow constraint.
    RuntimeCheck,
    /// Declassification receipt authorizes the flow.
    Declassification,
    /// Operator attestation authorizes the flow.
    OperatorAttestation,
}

impl fmt::Display for FlowProofMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticAnalysis => write!(f, "static_analysis"),
            Self::RuntimeCheck => write!(f, "runtime_check"),
            Self::Declassification => write!(f, "declassification"),
            Self::OperatorAttestation => write!(f, "operator_attestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Confidence interval
// ---------------------------------------------------------------------------

/// Confidence interval for envelope tightness (Wilson score).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowConfidenceInterval {
    /// Lower bound in millionths (950_000 = 0.95).
    pub lower_millionths: i64,
    /// Upper bound in millionths.
    pub upper_millionths: i64,
    /// Number of ablation trials.
    pub n_trials: u32,
    /// Number of trials where removing a flow caused breakage.
    pub n_essential: u32,
}

// ---------------------------------------------------------------------------
// Synthesis pass result
// ---------------------------------------------------------------------------

/// Result of a single synthesis pass (static or dynamic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisPassResult {
    /// Which pass produced this result.
    pub pass: SynthesisPass,
    /// Flows identified as required by this pass.
    pub required_flows: BTreeSet<FlowRule>,
    /// Flows identified as not-required (can be denied).
    pub removable_flows: BTreeSet<FlowRule>,
    /// Time consumed by this pass in nanoseconds.
    pub time_consumed_ns: u64,
    /// Whether the pass completed or was truncated by budget.
    pub completed: bool,
}

/// Synthesis pass type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SynthesisPass {
    /// Static flow-label analysis from IR2.
    StaticFlowAnalysis,
    /// Dynamic ablation of flow candidates.
    DynamicFlowAblation,
}

impl fmt::Display for SynthesisPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticFlowAnalysis => write!(f, "static_flow_analysis"),
            Self::DynamicFlowAblation => write!(f, "dynamic_flow_ablation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Flow envelope
// ---------------------------------------------------------------------------

/// A minimal flow envelope for an extension: the tightest set of
/// source-label → sink-clearance flows that the extension actually requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEnvelope {
    /// Content-addressable identifier.
    pub envelope_id: EngineObjectId,
    /// Extension this envelope covers.
    pub extension_id: String,
    /// Flows required by the extension (the minimal set).
    pub required_flows: BTreeSet<FlowRule>,
    /// Flows explicitly denied (removed from upper bound).
    pub denied_flows: BTreeSet<FlowRule>,
    /// Proof obligations for flows in the envelope.
    pub proof_obligations: Vec<FlowProofObligation>,
    /// Confidence interval for the envelope tightness.
    pub confidence: FlowConfidenceInterval,
    /// Per-pass synthesis results.
    pub pass_results: Vec<SynthesisPassResult>,
    /// Epoch under which this envelope is valid.
    pub validity_epoch: SecurityEpoch,
    /// Policy ID this envelope was synthesized against.
    pub policy_id: String,
    /// Whether the envelope was produced from a fallback (budget exhaustion).
    pub is_fallback: bool,
    /// Fallback quality if `is_fallback` is true.
    pub fallback_quality: Option<FallbackQuality>,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Cryptographic signature.
    pub signature: Signature,
}

/// Quality of fallback envelope when budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackQuality {
    /// Static upper bound only — no dynamic tightening.
    StaticBound,
    /// Partial ablation completed before budget exhaustion.
    PartialAblation,
}

impl fmt::Display for FallbackQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticBound => write!(f, "static_bound"),
            Self::PartialAblation => write!(f, "partial_ablation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

fn envelope_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(ENVELOPE_SCHEMA_DEF));
    &HASH
}

fn schema_id() -> SchemaId {
    SchemaId::from_definition(b"flow_envelope_v1")
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error from envelope construction or validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeError {
    /// Extension ID is empty.
    EmptyExtensionId,
    /// No flows in the upper bound — nothing to synthesize.
    EmptyUpperBound,
    /// Required and denied flows overlap.
    OverlappingFlows { overlap_count: usize },
    /// A required flow has no proof obligation.
    MissingProofObligation { rule: FlowRule },
    /// ID derivation failed.
    IdDerivation(String),
    /// Signature operation failed.
    SignatureError(String),
    /// Budget exhausted during synthesis.
    BudgetExhausted { phase: String },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExtensionId => write!(f, "extension_id is empty"),
            Self::EmptyUpperBound => write!(f, "upper bound has no flows"),
            Self::OverlappingFlows { overlap_count } => {
                write!(f, "{overlap_count} flows in both required and denied sets")
            }
            Self::MissingProofObligation { rule } => {
                write!(
                    f,
                    "flow {} -> {} has no proof obligation",
                    rule.source_label, rule.sink_clearance
                )
            }
            Self::IdDerivation(msg) => write!(f, "id derivation: {msg}"),
            Self::SignatureError(msg) => write!(f, "signature: {msg}"),
            Self::BudgetExhausted { phase } => {
                write!(f, "budget exhausted during {phase}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Stable error codes for structured logging.
pub fn error_code(err: &EnvelopeError) -> &'static str {
    match err {
        EnvelopeError::EmptyExtensionId => "ENVELOPE_EMPTY_EXTENSION_ID",
        EnvelopeError::EmptyUpperBound => "ENVELOPE_EMPTY_UPPER_BOUND",
        EnvelopeError::OverlappingFlows { .. } => "ENVELOPE_OVERLAPPING_FLOWS",
        EnvelopeError::MissingProofObligation { .. } => "ENVELOPE_MISSING_PROOF",
        EnvelopeError::IdDerivation(_) => "ENVELOPE_ID_DERIVATION",
        EnvelopeError::SignatureError(_) => "ENVELOPE_SIGNATURE_ERROR",
        EnvelopeError::BudgetExhausted { .. } => "ENVELOPE_BUDGET_EXHAUSTED",
    }
}

// ---------------------------------------------------------------------------
// Builder input
// ---------------------------------------------------------------------------

/// Input for synthesizing a flow envelope.
#[derive(Debug, Clone)]
pub struct EnvelopeInput {
    /// Extension being analyzed.
    pub extension_id: String,
    /// Static upper bound: all flows the extension *could* require.
    pub static_upper_bound: BTreeSet<FlowRule>,
    /// Flows confirmed required through ablation.
    pub ablation_required: BTreeSet<FlowRule>,
    /// Flows confirmed removable through ablation.
    pub ablation_removable: BTreeSet<FlowRule>,
    /// Proof obligations for required flows.
    pub proof_obligations: Vec<FlowProofObligation>,
    /// Confidence interval from ablation.
    pub confidence: FlowConfidenceInterval,
    /// Per-pass synthesis results.
    pub pass_results: Vec<SynthesisPassResult>,
    /// Validity epoch.
    pub validity_epoch: SecurityEpoch,
    /// Policy ID.
    pub policy_id: String,
    /// Whether this is a fallback (budget exhaustion).
    pub is_fallback: bool,
    /// Fallback quality.
    pub fallback_quality: Option<FallbackQuality>,
    /// Timestamp.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl FlowEnvelope {
    /// Build a new flow envelope from validated inputs.
    pub fn build(input: EnvelopeInput) -> Result<Self, EnvelopeError> {
        Self::validate_inputs(&input)?;

        let required_flows = if input.ablation_required.is_empty() {
            // No ablation results — use static upper bound.
            input.static_upper_bound.clone()
        } else {
            input.ablation_required.clone()
        };

        let denied_flows = if input.ablation_removable.is_empty() {
            BTreeSet::new()
        } else {
            input.ablation_removable.clone()
        };

        let mut envelope = Self {
            envelope_id: EngineObjectId([0u8; 32]),
            extension_id: input.extension_id,
            required_flows,
            denied_flows,
            proof_obligations: input.proof_obligations,
            confidence: input.confidence,
            pass_results: input.pass_results,
            validity_epoch: input.validity_epoch,
            policy_id: input.policy_id,
            is_fallback: input.is_fallback,
            fallback_quality: input.fallback_quality,
            timestamp_ns: input.timestamp_ns,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        // Derive content-addressed ID.
        let canonical = deterministic_serde::encode_value(&envelope.unsigned_view());
        let id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            ENVELOPE_ZONE,
            &schema_id(),
            &canonical,
        )
        .map_err(|e| EnvelopeError::IdDerivation(format!("{e}")))?;
        envelope.envelope_id = id;

        Ok(envelope)
    }

    /// Sign this envelope.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), EnvelopeError> {
        self.signature =
            sign_object(self, key).map_err(|e| EnvelopeError::SignatureError(format!("{e}")))?;
        Ok(())
    }

    /// Verify the signature.
    pub fn verify(&self, key: &VerificationKey) -> Result<(), EnvelopeError> {
        verify_signature(key, &self.preimage_bytes(), &self.signature)
            .map_err(|e| EnvelopeError::SignatureError(format!("{e}")))?;
        Ok(())
    }

    /// Re-derive and verify the content-addressed ID.
    pub fn verify_content_address(&self) -> bool {
        let canonical = deterministic_serde::encode_value(&self.unsigned_view());
        let Ok(expected) = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            ENVELOPE_ZONE,
            &schema_id(),
            &canonical,
        ) else {
            return false;
        };
        expected == self.envelope_id
    }

    /// Whether this envelope is valid at the given epoch.
    pub fn is_valid_at_epoch(&self, epoch: SecurityEpoch) -> bool {
        self.validity_epoch == epoch
    }

    /// Whether a given flow is within the envelope (allowed).
    pub fn allows_flow(&self, rule: &FlowRule) -> bool {
        self.required_flows.contains(rule)
    }

    /// Whether a given flow is explicitly denied.
    pub fn denies_flow(&self, rule: &FlowRule) -> bool {
        self.denied_flows.contains(rule)
    }

    /// Whether a given flow is out-of-envelope (not in required, not in denied).
    pub fn is_out_of_envelope(&self, rule: &FlowRule) -> bool {
        !self.required_flows.contains(rule) && !self.denied_flows.contains(rule)
    }

    /// All labels that appear as sources in required flows.
    pub fn source_labels(&self) -> BTreeSet<&Label> {
        self.required_flows
            .iter()
            .map(|r| &r.source_label)
            .collect()
    }

    /// All labels that appear as sink clearances in required flows.
    pub fn sink_clearances(&self) -> BTreeSet<&Label> {
        self.required_flows
            .iter()
            .map(|r| &r.sink_clearance)
            .collect()
    }

    /// Count of unsatisfied proof obligations.
    pub fn unsatisfied_obligations(&self) -> usize {
        self.proof_obligations
            .iter()
            .filter(|o| o.proof_artifact_hash.is_none())
            .count()
    }

    fn validate_inputs(input: &EnvelopeInput) -> Result<(), EnvelopeError> {
        if input.extension_id.is_empty() {
            return Err(EnvelopeError::EmptyExtensionId);
        }
        if input.static_upper_bound.is_empty() && input.ablation_required.is_empty() {
            return Err(EnvelopeError::EmptyUpperBound);
        }
        // Check overlap between required and removable.
        let overlap: BTreeSet<_> = input
            .ablation_required
            .intersection(&input.ablation_removable)
            .collect();
        if !overlap.is_empty() {
            return Err(EnvelopeError::OverlappingFlows {
                overlap_count: overlap.len(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SignaturePreimage
// ---------------------------------------------------------------------------

impl SignaturePreimage for FlowEnvelope {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        envelope_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();

        // Confidence.
        let mut conf = BTreeMap::new();
        conf.insert(
            "lower_millionths".to_string(),
            CanonicalValue::I64(self.confidence.lower_millionths),
        );
        conf.insert(
            "n_essential".to_string(),
            CanonicalValue::U64(self.confidence.n_essential as u64),
        );
        conf.insert(
            "n_trials".to_string(),
            CanonicalValue::U64(self.confidence.n_trials as u64),
        );
        conf.insert(
            "upper_millionths".to_string(),
            CanonicalValue::I64(self.confidence.upper_millionths),
        );
        map.insert("confidence".to_string(), CanonicalValue::Map(conf));

        // Denied flows.
        let denied: Vec<CanonicalValue> =
            self.denied_flows.iter().map(flow_rule_canonical).collect();
        map.insert("denied_flows".to_string(), CanonicalValue::Array(denied));

        // Extension ID.
        map.insert(
            "extension_id".to_string(),
            CanonicalValue::String(self.extension_id.clone()),
        );

        // Fallback quality.
        map.insert(
            "fallback_quality".to_string(),
            self.fallback_quality
                .as_ref()
                .map_or(CanonicalValue::Null, |q| {
                    CanonicalValue::String(q.to_string())
                }),
        );

        // Is fallback.
        map.insert(
            "is_fallback".to_string(),
            CanonicalValue::Bool(self.is_fallback),
        );

        // Policy ID.
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );

        // Required flows.
        let required: Vec<CanonicalValue> = self
            .required_flows
            .iter()
            .map(flow_rule_canonical)
            .collect();
        map.insert(
            "required_flows".to_string(),
            CanonicalValue::Array(required),
        );

        // Signature sentinel.
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );

        // Timestamp.
        map.insert(
            "timestamp_ns".to_string(),
            CanonicalValue::U64(self.timestamp_ns),
        );

        // Validity epoch.
        map.insert(
            "validity_epoch".to_string(),
            CanonicalValue::U64(self.validity_epoch.as_u64()),
        );

        CanonicalValue::Map(map)
    }
}

fn flow_rule_canonical(rule: &FlowRule) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "sink_clearance".to_string(),
        CanonicalValue::String(rule.sink_clearance.to_string()),
    );
    map.insert(
        "source_label".to_string(),
        CanonicalValue::String(rule.source_label.to_string()),
    );
    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// Flow envelope synthesizer
// ---------------------------------------------------------------------------

/// Synthesizes minimal flow envelopes using static + dynamic passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEnvelopeSynthesizer {
    /// Extension being analyzed.
    pub extension_id: String,
    /// Time budget for flow synthesis in nanoseconds.
    pub time_budget_ns: u64,
    /// Epoch for the synthesis.
    pub epoch: SecurityEpoch,
    /// Events emitted during synthesis.
    pub events: Vec<EnvelopeEvent>,
}

/// Event emitted during envelope synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: Option<String>,
    pub flow_count: Option<usize>,
}

impl FlowEnvelopeSynthesizer {
    pub fn new(extension_id: impl Into<String>, time_budget_ns: u64, epoch: SecurityEpoch) -> Self {
        Self {
            extension_id: extension_id.into(),
            time_budget_ns,
            epoch,
            events: Vec::new(),
        }
    }

    /// Run static flow analysis pass.
    ///
    /// Takes the manifest-declared upper bound of flows and returns the
    /// statically-confirmed subset.
    pub fn static_pass(
        &mut self,
        upper_bound: &BTreeSet<FlowRule>,
        trace_id: &str,
    ) -> SynthesisPassResult {
        self.push_event(trace_id, "static_pass_start", "starting", None);

        // Static analysis: confirm flows where source.level() <= sink.level()
        // (these are inherently safe and always required).
        let mut required = BTreeSet::new();
        let mut removable = BTreeSet::new();

        for rule in upper_bound {
            if rule.source_label.can_flow_to(&rule.sink_clearance) {
                // Safe flow — always allowed without declassification.
                required.insert(rule.clone());
            } else {
                // Requires declassification — mark as removable by default
                // (dynamic pass may promote back to required).
                removable.insert(rule.clone());
            }
        }

        self.push_event(trace_id, "static_pass_complete", "ok", None);

        SynthesisPassResult {
            pass: SynthesisPass::StaticFlowAnalysis,
            required_flows: required,
            removable_flows: removable,
            time_consumed_ns: 0, // Synthetic — actual timing in budget monitor.
            completed: true,
        }
    }

    /// Run dynamic ablation pass.
    ///
    /// For each flow in the removable set, tests whether removing it breaks
    /// the extension.  Flows that cause breakage when removed are promoted
    /// to required.
    pub fn dynamic_pass(
        &mut self,
        static_result: &SynthesisPassResult,
        oracle: &dyn Fn(&FlowRule) -> bool,
        trace_id: &str,
    ) -> SynthesisPassResult {
        self.push_event(trace_id, "dynamic_pass_start", "starting", None);

        let mut required = static_result.required_flows.clone();
        let mut still_removable = BTreeSet::new();

        for candidate in &static_result.removable_flows {
            // Oracle returns true if removing this flow causes breakage.
            if oracle(candidate) {
                required.insert(candidate.clone());
            } else {
                still_removable.insert(candidate.clone());
            }
        }

        self.push_event(trace_id, "dynamic_pass_complete", "ok", None);

        SynthesisPassResult {
            pass: SynthesisPass::DynamicFlowAblation,
            required_flows: required,
            removable_flows: still_removable,
            time_consumed_ns: 0,
            completed: true,
        }
    }

    /// Synthesize a complete flow envelope from static + dynamic passes.
    pub fn synthesize(
        &mut self,
        upper_bound: &BTreeSet<FlowRule>,
        oracle: &dyn Fn(&FlowRule) -> bool,
        policy_id: &str,
        timestamp_ns: u64,
        trace_id: &str,
    ) -> Result<FlowEnvelope, EnvelopeError> {
        if self.extension_id.is_empty() {
            return Err(EnvelopeError::EmptyExtensionId);
        }
        if upper_bound.is_empty() {
            return Err(EnvelopeError::EmptyUpperBound);
        }

        self.push_event(trace_id, "synthesis_start", "starting", None);

        // 1. Static pass.
        let static_result = self.static_pass(upper_bound, trace_id);

        // 2. Dynamic pass.
        let dynamic_result = self.dynamic_pass(&static_result, oracle, trace_id);

        // 3. Build proof obligations for all required flows.
        let proof_obligations: Vec<FlowProofObligation> = dynamic_result
            .required_flows
            .iter()
            .map(|rule| {
                let method = if rule.source_label.can_flow_to(&rule.sink_clearance) {
                    FlowProofMethod::StaticAnalysis
                } else {
                    FlowProofMethod::Declassification
                };
                FlowProofObligation {
                    rule: rule.clone(),
                    required_method: method,
                    justification: format!(
                        "flow {} -> {} required by extension",
                        rule.source_label, rule.sink_clearance
                    ),
                    proof_artifact_hash: None,
                }
            })
            .collect();

        // 4. Compute confidence (ablation-only: excludes statically-safe flows).
        let n_trials = static_result.removable_flows.len() as u32;
        let n_essential =
            (dynamic_result.required_flows.len() - static_result.required_flows.len()) as u32;
        let confidence = FlowConfidenceInterval {
            lower_millionths: if n_trials > 0 {
                ((n_essential as i64) * 1_000_000) / (n_trials as i64)
            } else {
                0
            },
            upper_millionths: 1_000_000,
            n_trials,
            n_essential,
        };

        let input = EnvelopeInput {
            extension_id: self.extension_id.clone(),
            static_upper_bound: upper_bound.clone(),
            ablation_required: dynamic_result.required_flows.clone(),
            ablation_removable: dynamic_result.removable_flows.clone(),
            proof_obligations,
            confidence,
            pass_results: vec![static_result, dynamic_result],
            validity_epoch: self.epoch,
            policy_id: policy_id.to_string(),
            is_fallback: false,
            fallback_quality: None,
            timestamp_ns,
        };

        let envelope = FlowEnvelope::build(input)?;

        self.push_event(trace_id, "synthesis_complete", "ok", None);

        Ok(envelope)
    }

    /// Synthesize a fallback envelope from static analysis only.
    ///
    /// Used when the dynamic pass budget is exhausted.
    pub fn synthesize_fallback(
        &mut self,
        upper_bound: &BTreeSet<FlowRule>,
        policy_id: &str,
        timestamp_ns: u64,
        quality: FallbackQuality,
        trace_id: &str,
    ) -> Result<FlowEnvelope, EnvelopeError> {
        if self.extension_id.is_empty() {
            return Err(EnvelopeError::EmptyExtensionId);
        }
        if upper_bound.is_empty() {
            return Err(EnvelopeError::EmptyUpperBound);
        }

        self.push_event(trace_id, "fallback_synthesis_start", "starting", None);

        let static_result = self.static_pass(upper_bound, trace_id);

        // For fallback, all flows in the upper bound are required
        // (conservative — no tightening).
        let proof_obligations: Vec<FlowProofObligation> = upper_bound
            .iter()
            .map(|rule| FlowProofObligation {
                rule: rule.clone(),
                required_method: FlowProofMethod::RuntimeCheck,
                justification: "fallback: static upper bound".to_string(),
                proof_artifact_hash: None,
            })
            .collect();

        let confidence = FlowConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 1_000_000,
            n_trials: 0,
            n_essential: 0,
        };

        let input = EnvelopeInput {
            extension_id: self.extension_id.clone(),
            static_upper_bound: upper_bound.clone(),
            ablation_required: BTreeSet::new(),
            ablation_removable: BTreeSet::new(),
            proof_obligations,
            confidence,
            pass_results: vec![static_result],
            validity_epoch: self.epoch,
            policy_id: policy_id.to_string(),
            is_fallback: true,
            fallback_quality: Some(quality),
            timestamp_ns,
        };

        let envelope = FlowEnvelope::build(input)?;

        self.push_event(trace_id, "fallback_synthesis_complete", "ok", None);

        Ok(envelope)
    }

    fn push_event(&mut self, trace_id: &str, event: &str, outcome: &str, err_code: Option<&str>) {
        self.events.push(EnvelopeEvent {
            trace_id: trace_id.to_string(),
            component: "flow_envelope".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
            extension_id: Some(self.extension_id.clone()),
            flow_count: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Witness extension: flow_envelope_ref
// ---------------------------------------------------------------------------

/// Reference from a capability witness to its associated flow envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEnvelopeRef {
    /// ID of the referenced flow envelope.
    pub envelope_id: EngineObjectId,
    /// Content hash of the referenced envelope.
    pub envelope_hash: ContentHash,
    /// Epoch at which the envelope was synthesized.
    pub envelope_epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- test helpers -------------------------------------------------------

    fn rule(source: Label, sink: Label) -> FlowRule {
        FlowRule {
            source_label: source,
            sink_clearance: sink,
        }
    }

    fn test_upper_bound() -> BTreeSet<FlowRule> {
        let mut flows = BTreeSet::new();
        // Safe: Public → Internal (upward in lattice).
        flows.insert(rule(Label::Public, Label::Internal));
        // Safe: Internal → Confidential.
        flows.insert(rule(Label::Internal, Label::Confidential));
        // Requires declassification: Confidential → Public.
        flows.insert(rule(Label::Confidential, Label::Public));
        // Requires declassification: Secret → Internal.
        flows.insert(rule(Label::Secret, Label::Internal));
        flows
    }

    fn test_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        bytes[31] = 0xFF;
        SigningKey::from_bytes(bytes)
    }

    fn valid_input() -> EnvelopeInput {
        let upper = test_upper_bound();
        let required: BTreeSet<FlowRule> = upper
            .iter()
            .filter(|r| r.source_label.can_flow_to(&r.sink_clearance))
            .cloned()
            .collect();
        let denied: BTreeSet<FlowRule> = upper
            .iter()
            .filter(|r| !r.source_label.can_flow_to(&r.sink_clearance))
            .cloned()
            .collect();

        let obligations: Vec<FlowProofObligation> = required
            .iter()
            .map(|r| FlowProofObligation {
                rule: r.clone(),
                required_method: FlowProofMethod::StaticAnalysis,
                justification: "test".to_string(),
                proof_artifact_hash: None,
            })
            .collect();

        EnvelopeInput {
            extension_id: "ext-test-001".to_string(),
            static_upper_bound: upper,
            ablation_required: required,
            ablation_removable: denied,
            proof_obligations: obligations,
            confidence: FlowConfidenceInterval {
                lower_millionths: 950_000,
                upper_millionths: 1_000_000,
                n_trials: 4,
                n_essential: 2,
            },
            pass_results: Vec::new(),
            validity_epoch: SecurityEpoch::from_raw(1),
            policy_id: "policy-001".to_string(),
            is_fallback: false,
            fallback_quality: None,
            timestamp_ns: 1_700_000_000_000_000_000,
        }
    }

    // -- build tests --------------------------------------------------------

    #[test]
    fn build_valid_envelope() {
        let envelope = FlowEnvelope::build(valid_input()).expect("build");
        assert_eq!(envelope.extension_id, "ext-test-001");
        assert_eq!(envelope.required_flows.len(), 2);
        assert_eq!(envelope.denied_flows.len(), 2);
        assert!(!envelope.is_fallback);
        assert!(envelope.verify_content_address());
    }

    #[test]
    fn build_rejects_empty_extension_id() {
        let mut input = valid_input();
        input.extension_id = String::new();
        let err = FlowEnvelope::build(input).unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyExtensionId);
        assert_eq!(error_code(&err), "ENVELOPE_EMPTY_EXTENSION_ID");
    }

    #[test]
    fn build_rejects_empty_upper_bound() {
        let mut input = valid_input();
        input.static_upper_bound = BTreeSet::new();
        input.ablation_required = BTreeSet::new();
        let err = FlowEnvelope::build(input).unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyUpperBound);
    }

    #[test]
    fn build_rejects_overlapping_flows() {
        let mut input = valid_input();
        let overlap_rule = rule(Label::Public, Label::Internal);
        input.ablation_required.insert(overlap_rule.clone());
        input.ablation_removable.insert(overlap_rule);
        let err = FlowEnvelope::build(input).unwrap_err();
        assert!(matches!(err, EnvelopeError::OverlappingFlows { .. }));
        assert_eq!(error_code(&err), "ENVELOPE_OVERLAPPING_FLOWS");
    }

    // -- content addressing -------------------------------------------------

    #[test]
    fn content_address_is_deterministic() {
        let e1 = FlowEnvelope::build(valid_input()).unwrap();
        let e2 = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(e1.envelope_id, e2.envelope_id);
    }

    #[test]
    fn different_inputs_produce_different_ids() {
        let e1 = FlowEnvelope::build(valid_input()).unwrap();
        let mut input2 = valid_input();
        input2.extension_id = "ext-different".to_string();
        let e2 = FlowEnvelope::build(input2).unwrap();
        assert_ne!(e1.envelope_id, e2.envelope_id);
    }

    #[test]
    fn verify_content_address_detects_tampering() {
        let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
        assert!(envelope.verify_content_address());
        envelope.timestamp_ns = 999;
        assert!(!envelope.verify_content_address());
    }

    // -- signing / verification ---------------------------------------------

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = test_signing_key();
        let vk = key.verification_key();
        let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
        envelope.sign(&key).expect("sign");
        envelope.verify(&vk).expect("verify");
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key = test_signing_key();
        let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
        envelope.sign(&key).expect("sign");
        let wrong = SigningKey::from_bytes([0xBB; 32]);
        assert!(envelope.verify(&wrong.verification_key()).is_err());
    }

    // -- epoch validity -----------------------------------------------------

    #[test]
    fn is_valid_at_correct_epoch() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        assert!(envelope.is_valid_at_epoch(SecurityEpoch::from_raw(1)));
    }

    #[test]
    fn is_invalid_at_different_epoch() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(2)));
    }

    // -- flow queries -------------------------------------------------------

    #[test]
    fn allows_flow_for_required() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let safe = rule(Label::Public, Label::Internal);
        assert!(envelope.allows_flow(&safe));
    }

    #[test]
    fn denies_flow_for_denied() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let denied = rule(Label::Confidential, Label::Public);
        assert!(envelope.denies_flow(&denied));
    }

    #[test]
    fn is_out_of_envelope_for_unknown_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let unknown = rule(Label::Secret, Label::Secret);
        assert!(envelope.is_out_of_envelope(&unknown));
    }

    #[test]
    fn source_labels_extracted() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let labels = envelope.source_labels();
        assert!(labels.contains(&Label::Public));
        assert!(labels.contains(&Label::Internal));
    }

    #[test]
    fn sink_clearances_extracted() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let clearances = envelope.sink_clearances();
        assert!(clearances.contains(&Label::Internal));
        assert!(clearances.contains(&Label::Confidential));
    }

    #[test]
    fn unsatisfied_obligations_count() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(envelope.unsatisfied_obligations(), 2); // All unsatisfied.
    }

    // -- serde roundtrips ---------------------------------------------------

    #[test]
    fn envelope_serde_roundtrip() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, deser);
    }

    #[test]
    fn flow_requirement_serde_roundtrip() {
        let req = FlowRequirement {
            rule: rule(Label::Confidential, Label::Public),
            discovery_method: FlowDiscoveryMethod::DynamicAblation,
            source_location: Some("src/handler.rs:42".to_string()),
            sink_location: Some("src/output.rs:10".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deser);
    }

    #[test]
    fn flow_discovery_method_serde_roundtrip() {
        for m in [
            FlowDiscoveryMethod::StaticAnalysis,
            FlowDiscoveryMethod::DynamicAblation,
            FlowDiscoveryMethod::RuntimeObservation,
            FlowDiscoveryMethod::ManifestDeclaration,
        ] {
            let json = serde_json::to_string(&m).unwrap();
            let deser: FlowDiscoveryMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(m, deser);
        }
    }

    #[test]
    fn flow_proof_method_serde_roundtrip() {
        for m in [
            FlowProofMethod::StaticAnalysis,
            FlowProofMethod::RuntimeCheck,
            FlowProofMethod::Declassification,
            FlowProofMethod::OperatorAttestation,
        ] {
            let json = serde_json::to_string(&m).unwrap();
            let deser: FlowProofMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(m, deser);
        }
    }

    #[test]
    fn synthesis_pass_serde_roundtrip() {
        for p in [
            SynthesisPass::StaticFlowAnalysis,
            SynthesisPass::DynamicFlowAblation,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let deser: SynthesisPass = serde_json::from_str(&json).unwrap();
            assert_eq!(p, deser);
        }
    }

    #[test]
    fn fallback_quality_serde_roundtrip() {
        for q in [
            FallbackQuality::StaticBound,
            FallbackQuality::PartialAblation,
        ] {
            let json = serde_json::to_string(&q).unwrap();
            let deser: FallbackQuality = serde_json::from_str(&json).unwrap();
            assert_eq!(q, deser);
        }
    }

    #[test]
    fn envelope_error_serde_roundtrip() {
        let errors = [
            EnvelopeError::EmptyExtensionId,
            EnvelopeError::EmptyUpperBound,
            EnvelopeError::OverlappingFlows { overlap_count: 3 },
            EnvelopeError::MissingProofObligation {
                rule: rule(Label::Secret, Label::Public),
            },
            EnvelopeError::IdDerivation("test".to_string()),
            EnvelopeError::SignatureError("test".to_string()),
            EnvelopeError::BudgetExhausted {
                phase: "dynamic".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: EnvelopeError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deser);
        }
    }

    #[test]
    fn envelope_event_serde_roundtrip() {
        let ev = EnvelopeEvent {
            trace_id: "t1".to_string(),
            component: "flow_envelope".to_string(),
            event: "synthesis_complete".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            extension_id: Some("ext-001".to_string()),
            flow_count: Some(4),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let deser: EnvelopeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deser);
    }

    #[test]
    fn flow_envelope_ref_serde_roundtrip() {
        let r = FlowEnvelopeRef {
            envelope_id: EngineObjectId([0xAA; 32]),
            envelope_hash: ContentHash::compute(b"test"),
            envelope_epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&r).unwrap();
        let deser: FlowEnvelopeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, deser);
    }

    #[test]
    fn confidence_interval_serde_roundtrip() {
        let ci = FlowConfidenceInterval {
            lower_millionths: 950_000,
            upper_millionths: 1_000_000,
            n_trials: 100,
            n_essential: 80,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, deser);
    }

    // -- display tests ------------------------------------------------------

    #[test]
    fn flow_discovery_method_display() {
        assert_eq!(
            FlowDiscoveryMethod::StaticAnalysis.to_string(),
            "static_analysis"
        );
        assert_eq!(
            FlowDiscoveryMethod::DynamicAblation.to_string(),
            "dynamic_ablation"
        );
        assert_eq!(
            FlowDiscoveryMethod::RuntimeObservation.to_string(),
            "runtime_observation"
        );
        assert_eq!(
            FlowDiscoveryMethod::ManifestDeclaration.to_string(),
            "manifest_declaration"
        );
    }

    #[test]
    fn flow_proof_method_display() {
        assert_eq!(
            FlowProofMethod::StaticAnalysis.to_string(),
            "static_analysis"
        );
        assert_eq!(FlowProofMethod::RuntimeCheck.to_string(), "runtime_check");
        assert_eq!(
            FlowProofMethod::Declassification.to_string(),
            "declassification"
        );
        assert_eq!(
            FlowProofMethod::OperatorAttestation.to_string(),
            "operator_attestation"
        );
    }

    #[test]
    fn synthesis_pass_display() {
        assert_eq!(
            SynthesisPass::StaticFlowAnalysis.to_string(),
            "static_flow_analysis"
        );
        assert_eq!(
            SynthesisPass::DynamicFlowAblation.to_string(),
            "dynamic_flow_ablation"
        );
    }

    #[test]
    fn fallback_quality_display() {
        assert_eq!(FallbackQuality::StaticBound.to_string(), "static_bound");
        assert_eq!(
            FallbackQuality::PartialAblation.to_string(),
            "partial_ablation"
        );
    }

    #[test]
    fn error_display_coverage() {
        let err = EnvelopeError::EmptyExtensionId;
        assert!(err.to_string().contains("empty"));
        let err = EnvelopeError::OverlappingFlows { overlap_count: 5 };
        assert!(err.to_string().contains("5"));
        let err = EnvelopeError::BudgetExhausted {
            phase: "dynamic".to_string(),
        };
        assert!(err.to_string().contains("dynamic"));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            error_code(&EnvelopeError::EmptyExtensionId),
            "ENVELOPE_EMPTY_EXTENSION_ID"
        );
        assert_eq!(
            error_code(&EnvelopeError::EmptyUpperBound),
            "ENVELOPE_EMPTY_UPPER_BOUND"
        );
        assert_eq!(
            error_code(&EnvelopeError::OverlappingFlows { overlap_count: 1 }),
            "ENVELOPE_OVERLAPPING_FLOWS"
        );
        assert_eq!(
            error_code(&EnvelopeError::MissingProofObligation {
                rule: rule(Label::Public, Label::Public),
            }),
            "ENVELOPE_MISSING_PROOF"
        );
        assert_eq!(
            error_code(&EnvelopeError::IdDerivation(String::new())),
            "ENVELOPE_ID_DERIVATION"
        );
        assert_eq!(
            error_code(&EnvelopeError::SignatureError(String::new())),
            "ENVELOPE_SIGNATURE_ERROR"
        );
        assert_eq!(
            error_code(&EnvelopeError::BudgetExhausted {
                phase: String::new()
            }),
            "ENVELOPE_BUDGET_EXHAUSTED"
        );
    }

    // -- synthesizer tests --------------------------------------------------

    #[test]
    fn synthesizer_static_pass() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-001", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let result = synth.static_pass(&upper, "trace-1");

        assert!(result.completed);
        assert_eq!(result.pass, SynthesisPass::StaticFlowAnalysis);
        // 2 safe flows (Public→Internal, Internal→Confidential).
        assert_eq!(result.required_flows.len(), 2);
        // 2 declassification flows (Confidential→Public, Secret→Internal).
        assert_eq!(result.removable_flows.len(), 2);
    }

    #[test]
    fn synthesizer_dynamic_pass_promotes_essential_flows() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-001", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let static_result = synth.static_pass(&upper, "trace-2");

        // Oracle says Confidential→Public is essential, Secret→Internal is not.
        let oracle = |r: &FlowRule| {
            r.source_label == Label::Confidential && r.sink_clearance == Label::Public
        };
        let dynamic_result = synth.dynamic_pass(&static_result, &oracle, "trace-2");

        // 3 required: 2 safe + 1 promoted.
        assert_eq!(dynamic_result.required_flows.len(), 3);
        // 1 still removable: Secret→Internal.
        assert_eq!(dynamic_result.removable_flows.len(), 1);
        assert!(
            dynamic_result
                .required_flows
                .contains(&rule(Label::Confidential, Label::Public))
        );
    }

    #[test]
    fn synthesizer_full_synthesis() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-001", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let oracle = |_: &FlowRule| false; // Nothing is essential.
        let envelope = synth
            .synthesize(
                &upper,
                &oracle,
                "policy-001",
                1_700_000_000_000_000_000,
                "trace-3",
            )
            .unwrap();

        assert_eq!(envelope.extension_id, "ext-001");
        assert!(!envelope.is_fallback);
        assert!(envelope.verify_content_address());
        // 2 safe flows required, 2 denied (nothing promoted by oracle).
        assert_eq!(envelope.required_flows.len(), 2);
        assert_eq!(envelope.denied_flows.len(), 2);
    }

    #[test]
    fn synthesizer_full_synthesis_with_essential_flows() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-002", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let oracle = |_: &FlowRule| true; // Everything is essential.
        let envelope = synth
            .synthesize(
                &upper,
                &oracle,
                "policy-002",
                1_700_000_000_000_000_000,
                "trace-4",
            )
            .unwrap();

        // All 4 flows required, none denied.
        assert_eq!(envelope.required_flows.len(), 4);
        assert_eq!(envelope.denied_flows.len(), 0);
    }

    #[test]
    fn synthesizer_fallback() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-003", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let envelope = synth
            .synthesize_fallback(
                &upper,
                "policy-003",
                1_700_000_000_000_000_000,
                FallbackQuality::StaticBound,
                "trace-5",
            )
            .unwrap();

        assert!(envelope.is_fallback);
        assert_eq!(
            envelope.fallback_quality,
            Some(FallbackQuality::StaticBound)
        );
        // Fallback uses full upper bound — all 4 flows required.
        assert_eq!(envelope.required_flows.len(), 4);
        assert_eq!(envelope.denied_flows.len(), 0);
        assert!(envelope.verify_content_address());
    }

    #[test]
    fn synthesizer_rejects_empty_extension_id() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let oracle = |_: &FlowRule| false;
        let err = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyExtensionId);
    }

    #[test]
    fn synthesizer_rejects_empty_upper_bound() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-004", 30_000_000_000, SecurityEpoch::from_raw(1));
        let empty = BTreeSet::new();
        let oracle = |_: &FlowRule| false;
        let err = synth.synthesize(&empty, &oracle, "p", 0, "t").unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyUpperBound);
    }

    #[test]
    fn synthesizer_events_emitted() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-005", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let oracle = |_: &FlowRule| false;
        synth
            .synthesize(&upper, &oracle, "p", 0, "trace-ev")
            .unwrap();

        // Should have events for: synthesis_start, static_pass_start,
        // static_pass_complete, dynamic_pass_start, dynamic_pass_complete,
        // synthesis_complete.
        assert!(synth.events.len() >= 5);
        assert_eq!(synth.events[0].event, "synthesis_start");
        assert_eq!(synth.events.last().unwrap().event, "synthesis_complete");
    }

    // -- determinism --------------------------------------------------------

    #[test]
    fn unsigned_view_is_deterministic() {
        let e1 = FlowEnvelope::build(valid_input()).unwrap();
        let e2 = FlowEnvelope::build(valid_input()).unwrap();
        let v1 = deterministic_serde::encode_value(&e1.unsigned_view());
        let v2 = deterministic_serde::encode_value(&e2.unsigned_view());
        assert_eq!(v1, v2);
    }

    #[test]
    fn preimage_bytes_are_deterministic() {
        let e1 = FlowEnvelope::build(valid_input()).unwrap();
        let e2 = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(e1.preimage_bytes(), e2.preimage_bytes());
    }

    #[test]
    fn signature_domain_is_evidence_record() {
        let e = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(e.signature_domain(), ObjectDomain::EvidenceRecord);
    }

    // -- synthesizer determinism --------------------------------------------

    #[test]
    fn synthesis_is_deterministic() {
        let oracle = |_: &FlowRule| false;
        let upper = test_upper_bound();

        let mut s1 =
            FlowEnvelopeSynthesizer::new("ext-det", 30_000_000_000, SecurityEpoch::from_raw(1));
        let e1 = s1.synthesize(&upper, &oracle, "p1", 100, "t1").unwrap();

        let mut s2 =
            FlowEnvelopeSynthesizer::new("ext-det", 30_000_000_000, SecurityEpoch::from_raw(1));
        let e2 = s2.synthesize(&upper, &oracle, "p1", 100, "t2").unwrap();

        assert_eq!(e1.envelope_id, e2.envelope_id);
        assert_eq!(e1.required_flows, e2.required_flows);
        assert_eq!(e1.denied_flows, e2.denied_flows);
    }

    // -- flow proof obligation tests ----------------------------------------

    #[test]
    fn proof_obligation_serde_roundtrip() {
        let obl = FlowProofObligation {
            rule: rule(Label::Secret, Label::Public),
            required_method: FlowProofMethod::Declassification,
            justification: "needs declass".to_string(),
            proof_artifact_hash: Some(ContentHash::compute(b"proof")),
        };
        let json = serde_json::to_string(&obl).unwrap();
        let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(obl, deser);
    }

    // -- synthesis pass result tests ----------------------------------------

    #[test]
    fn synthesis_pass_result_serde_roundtrip() {
        let result = SynthesisPassResult {
            pass: SynthesisPass::StaticFlowAnalysis,
            required_flows: {
                let mut s = BTreeSet::new();
                s.insert(rule(Label::Public, Label::Internal));
                s
            },
            removable_flows: BTreeSet::new(),
            time_consumed_ns: 42_000,
            completed: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: SynthesisPassResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deser);
    }

    // -- enrichment tests ---------------------------------------------------

    #[test]
    fn determinism_build_100_times() {
        let first = FlowEnvelope::build(valid_input()).unwrap();
        for _ in 0..100 {
            let e = FlowEnvelope::build(valid_input()).unwrap();
            assert_eq!(e.envelope_id, first.envelope_id);
            assert_eq!(e.required_flows, first.required_flows);
            assert_eq!(e.denied_flows, first.denied_flows);
        }
    }

    #[test]
    fn synthesizer_determinism_100_times() {
        let oracle = |_: &FlowRule| false;
        let upper = test_upper_bound();
        let mut first_synth =
            FlowEnvelopeSynthesizer::new("ext-det-100", 30_000_000_000, SecurityEpoch::from_raw(1));
        let first = first_synth
            .synthesize(&upper, &oracle, "p1", 100, "t1")
            .unwrap();

        for _ in 0..100 {
            let mut synth = FlowEnvelopeSynthesizer::new(
                "ext-det-100",
                30_000_000_000,
                SecurityEpoch::from_raw(1),
            );
            let e = synth.synthesize(&upper, &oracle, "p1", 100, "t2").unwrap();
            assert_eq!(e.envelope_id, first.envelope_id);
            assert_eq!(e.required_flows, first.required_flows);
        }
    }

    #[test]
    fn envelope_blocks_exfiltration_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        // Secret→Internal is in the denied set (requires declassification).
        let exfil_flow = rule(Label::Secret, Label::Internal);
        assert!(envelope.denies_flow(&exfil_flow));
        assert!(!envelope.allows_flow(&exfil_flow));
    }

    #[test]
    fn envelope_allows_safe_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        // Public→Internal is safe (upward in lattice).
        let safe_flow = rule(Label::Public, Label::Internal);
        assert!(envelope.allows_flow(&safe_flow));
        assert!(!envelope.denies_flow(&safe_flow));
    }

    #[test]
    fn out_of_envelope_flow_detected() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        // This flow was never in the upper bound at all.
        let unknown_flow = rule(Label::Secret, Label::Secret);
        assert!(envelope.is_out_of_envelope(&unknown_flow));
    }

    #[test]
    fn source_and_sink_labels_complete() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let sources = envelope.source_labels();
        let sinks = envelope.sink_clearances();
        // Required flows: Public→Internal, Internal→Confidential
        assert!(sources.contains(&Label::Public));
        assert!(sources.contains(&Label::Internal));
        assert!(sinks.contains(&Label::Internal));
        assert!(sinks.contains(&Label::Confidential));
    }

    #[test]
    fn epoch_validity_check() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        assert!(envelope.is_valid_at_epoch(SecurityEpoch::from_raw(1)));
        assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(2)));
    }

    #[test]
    fn fallback_envelope_machine_readable() {
        let mut input = valid_input();
        input.is_fallback = true;
        input.fallback_quality = Some(FallbackQuality::StaticBound);
        let envelope = FlowEnvelope::build(input).unwrap();
        assert!(envelope.is_fallback);
        assert_eq!(
            envelope.fallback_quality,
            Some(FallbackQuality::StaticBound)
        );
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"is_fallback\":true"));
    }

    #[test]
    fn synthesizer_events_trace_id_preserved() {
        let oracle = |_: &FlowRule| false;
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-trace", 30_000_000_000, SecurityEpoch::from_raw(1));
        synth
            .synthesize(&upper, &oracle, "policy-1", 100, "my-trace-42")
            .unwrap();
        // All events should carry the trace ID.
        for event in &synth.events {
            assert_eq!(event.trace_id, "my-trace-42");
        }
    }

    #[test]
    fn content_address_stable_across_sign_unsign() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let id_before = envelope.envelope_id.clone();
        let mut signed = envelope.clone();
        signed.sign(&test_signing_key()).unwrap();
        // Signing changes the signature field but not the envelope_id.
        assert_eq!(signed.envelope_id, id_before);
        // Content address verification should still pass.
        assert!(signed.verify_content_address());
    }

    // -- Enrichment: std::error --

    #[test]
    fn envelope_error_implements_std_error() {
        let variants: [Box<dyn std::error::Error>; 6] = [
            Box::new(EnvelopeError::EmptyExtensionId),
            Box::new(EnvelopeError::EmptyUpperBound),
            Box::new(EnvelopeError::OverlappingFlows { overlap_count: 3 }),
            Box::new(EnvelopeError::IdDerivation("bad id".into())),
            Box::new(EnvelopeError::SignatureError("bad sig".into())),
            Box::new(EnvelopeError::BudgetExhausted {
                phase: "static".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 variants produce distinct messages"
        );
    }

    #[test]
    fn dynamic_pass_promotes_essential_flow_to_required() {
        // Oracle says: removing Secret→Internal breaks the extension.
        let oracle = |r: &FlowRule| r.source_label == Label::Secret;
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-promo", 30_000_000_000, SecurityEpoch::from_raw(1));
        let envelope = synth.synthesize(&upper, &oracle, "p1", 100, "t1").unwrap();
        // Secret→Internal was in removable after static pass, but oracle
        // said it's essential, so it should be in required now.
        let secret_flow = rule(Label::Secret, Label::Internal);
        assert!(envelope.allows_flow(&secret_flow));
        assert!(!envelope.denies_flow(&secret_flow));
    }

    // -- Copy/Clone semantics -----------------------------------------------

    #[test]
    fn flow_discovery_method_is_copy() {
        let m = FlowDiscoveryMethod::StaticAnalysis;
        let copy = m;
        // Both are usable after copy.
        assert_eq!(m, copy);
        assert_eq!(m, FlowDiscoveryMethod::StaticAnalysis);
    }

    #[test]
    fn flow_proof_method_is_copy() {
        let m = FlowProofMethod::Declassification;
        let copy = m;
        assert_eq!(m, copy);
        assert_eq!(copy, FlowProofMethod::Declassification);
    }

    #[test]
    fn synthesis_pass_is_copy() {
        let p = SynthesisPass::DynamicFlowAblation;
        let copy = p;
        assert_eq!(p, copy);
        assert_eq!(copy, SynthesisPass::DynamicFlowAblation);
    }

    #[test]
    fn fallback_quality_is_copy() {
        let q = FallbackQuality::PartialAblation;
        let copy = q;
        assert_eq!(q, copy);
        assert_eq!(copy, FallbackQuality::PartialAblation);
    }

    #[test]
    fn flow_confidence_interval_is_copy() {
        let ci = FlowConfidenceInterval {
            lower_millionths: 900_000,
            upper_millionths: 1_000_000,
            n_trials: 10,
            n_essential: 9,
        };
        let copy = ci;
        assert_eq!(ci, copy);
    }

    // -- Debug output is non-empty and distinct across variants --------------

    #[test]
    fn flow_discovery_method_debug_distinct() {
        let variants = [
            FlowDiscoveryMethod::StaticAnalysis,
            FlowDiscoveryMethod::DynamicAblation,
            FlowDiscoveryMethod::RuntimeObservation,
            FlowDiscoveryMethod::ManifestDeclaration,
        ];
        let mut debugs: BTreeSet<String> = BTreeSet::new();
        for v in variants {
            let s = format!("{v:?}");
            assert!(!s.is_empty());
            debugs.insert(s);
        }
        assert_eq!(debugs.len(), 4);
    }

    #[test]
    fn flow_proof_method_debug_distinct() {
        let variants = [
            FlowProofMethod::StaticAnalysis,
            FlowProofMethod::RuntimeCheck,
            FlowProofMethod::Declassification,
            FlowProofMethod::OperatorAttestation,
        ];
        let mut debugs: BTreeSet<String> = BTreeSet::new();
        for v in variants {
            let s = format!("{v:?}");
            assert!(!s.is_empty());
            debugs.insert(s);
        }
        assert_eq!(debugs.len(), 4);
    }

    #[test]
    fn synthesis_pass_debug_distinct() {
        let variants = [
            SynthesisPass::StaticFlowAnalysis,
            SynthesisPass::DynamicFlowAblation,
        ];
        let mut debugs: BTreeSet<String> = BTreeSet::new();
        for v in variants {
            let s = format!("{v:?}");
            assert!(!s.is_empty());
            debugs.insert(s);
        }
        assert_eq!(debugs.len(), 2);
    }

    #[test]
    fn fallback_quality_debug_distinct() {
        let a = format!("{:?}", FallbackQuality::StaticBound);
        let b = format!("{:?}", FallbackQuality::PartialAblation);
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        assert_ne!(a, b);
    }

    #[test]
    fn envelope_error_debug_distinct() {
        let errors: [EnvelopeError; 7] = [
            EnvelopeError::EmptyExtensionId,
            EnvelopeError::EmptyUpperBound,
            EnvelopeError::OverlappingFlows { overlap_count: 2 },
            EnvelopeError::MissingProofObligation {
                rule: rule(Label::Public, Label::Internal),
            },
            EnvelopeError::IdDerivation("x".into()),
            EnvelopeError::SignatureError("y".into()),
            EnvelopeError::BudgetExhausted { phase: "p".into() },
        ];
        let mut debugs: BTreeSet<String> = BTreeSet::new();
        for e in &errors {
            let s = format!("{e:?}");
            assert!(!s.is_empty());
            debugs.insert(s);
        }
        assert_eq!(debugs.len(), errors.len());
    }

    // -- Serde variant distinctness -----------------------------------------

    #[test]
    fn flow_discovery_method_serializes_distinctly() {
        let variants = [
            FlowDiscoveryMethod::StaticAnalysis,
            FlowDiscoveryMethod::DynamicAblation,
            FlowDiscoveryMethod::RuntimeObservation,
            FlowDiscoveryMethod::ManifestDeclaration,
        ];
        let mut serialized: BTreeSet<String> = BTreeSet::new();
        for v in variants {
            serialized.insert(serde_json::to_string(&v).unwrap());
        }
        assert_eq!(serialized.len(), 4);
    }

    #[test]
    fn flow_proof_method_serializes_distinctly() {
        let variants = [
            FlowProofMethod::StaticAnalysis,
            FlowProofMethod::RuntimeCheck,
            FlowProofMethod::Declassification,
            FlowProofMethod::OperatorAttestation,
        ];
        let mut serialized: BTreeSet<String> = BTreeSet::new();
        for v in variants {
            serialized.insert(serde_json::to_string(&v).unwrap());
        }
        assert_eq!(serialized.len(), 4);
    }

    #[test]
    fn synthesis_pass_serializes_distinctly() {
        let a = serde_json::to_string(&SynthesisPass::StaticFlowAnalysis).unwrap();
        let b = serde_json::to_string(&SynthesisPass::DynamicFlowAblation).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fallback_quality_serializes_distinctly() {
        let a = serde_json::to_string(&FallbackQuality::StaticBound).unwrap();
        let b = serde_json::to_string(&FallbackQuality::PartialAblation).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn envelope_error_all_variants_serialize_distinctly() {
        let errors: [EnvelopeError; 7] = [
            EnvelopeError::EmptyExtensionId,
            EnvelopeError::EmptyUpperBound,
            EnvelopeError::OverlappingFlows { overlap_count: 1 },
            EnvelopeError::MissingProofObligation {
                rule: rule(Label::Secret, Label::Public),
            },
            EnvelopeError::IdDerivation("id".into()),
            EnvelopeError::SignatureError("sig".into()),
            EnvelopeError::BudgetExhausted {
                phase: "dyn".into(),
            },
        ];
        let mut serialized: BTreeSet<String> = BTreeSet::new();
        for e in &errors {
            serialized.insert(serde_json::to_string(e).unwrap());
        }
        assert_eq!(serialized.len(), errors.len());
    }

    // -- Clone independence -------------------------------------------------

    #[test]
    fn flow_envelope_clone_independence() {
        let original = FlowEnvelope::build(valid_input()).unwrap();
        let mut cloned = original.clone();
        cloned.extension_id = "mutated".to_string();
        assert_eq!(original.extension_id, "ext-test-001");
        assert_eq!(cloned.extension_id, "mutated");
    }

    #[test]
    fn flow_requirement_clone_independence() {
        let original = FlowRequirement {
            rule: rule(Label::Public, Label::Internal),
            discovery_method: FlowDiscoveryMethod::StaticAnalysis,
            source_location: Some("a.rs".to_string()),
            sink_location: None,
        };
        let mut cloned = original.clone();
        cloned.source_location = Some("b.rs".to_string());
        assert_eq!(original.source_location, Some("a.rs".to_string()));
    }

    #[test]
    fn flow_proof_obligation_clone_independence() {
        let original = FlowProofObligation {
            rule: rule(Label::Secret, Label::Public),
            required_method: FlowProofMethod::Declassification,
            justification: "original justification".to_string(),
            proof_artifact_hash: None,
        };
        let mut cloned = original.clone();
        cloned.justification = "mutated".to_string();
        assert_eq!(original.justification, "original justification");
    }

    #[test]
    fn synthesis_pass_result_clone_independence() {
        let original = SynthesisPassResult {
            pass: SynthesisPass::StaticFlowAnalysis,
            required_flows: {
                let mut s = BTreeSet::new();
                s.insert(rule(Label::Public, Label::Internal));
                s
            },
            removable_flows: BTreeSet::new(),
            time_consumed_ns: 100,
            completed: true,
        };
        let mut cloned = original.clone();
        cloned.time_consumed_ns = 999;
        assert_eq!(original.time_consumed_ns, 100);
    }

    // -- JSON field-name stability ------------------------------------------

    #[test]
    fn flow_confidence_interval_json_field_names() {
        let ci = FlowConfidenceInterval {
            lower_millionths: 800_000,
            upper_millionths: 1_000_000,
            n_trials: 50,
            n_essential: 40,
        };
        let json = serde_json::to_string(&ci).unwrap();
        assert!(json.contains("\"lower_millionths\""));
        assert!(json.contains("\"upper_millionths\""));
        assert!(json.contains("\"n_trials\""));
        assert!(json.contains("\"n_essential\""));
    }

    #[test]
    fn flow_proof_obligation_json_field_names() {
        let obl = FlowProofObligation {
            rule: rule(Label::Public, Label::Internal),
            required_method: FlowProofMethod::StaticAnalysis,
            justification: "j".to_string(),
            proof_artifact_hash: None,
        };
        let json = serde_json::to_string(&obl).unwrap();
        assert!(json.contains("\"rule\""));
        assert!(json.contains("\"required_method\""));
        assert!(json.contains("\"justification\""));
        assert!(json.contains("\"proof_artifact_hash\""));
    }

    #[test]
    fn envelope_event_json_field_names() {
        let ev = EnvelopeEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            extension_id: None,
            flow_count: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"flow_count\""));
    }

    #[test]
    fn flow_envelope_ref_json_field_names() {
        let r = FlowEnvelopeRef {
            envelope_id: EngineObjectId([0u8; 32]),
            envelope_hash: ContentHash::compute(b"x"),
            envelope_epoch: SecurityEpoch::from_raw(5),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"envelope_id\""));
        assert!(json.contains("\"envelope_hash\""));
        assert!(json.contains("\"envelope_epoch\""));
    }

    #[test]
    fn flow_envelope_json_field_names() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"envelope_id\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"required_flows\""));
        assert!(json.contains("\"denied_flows\""));
        assert!(json.contains("\"confidence\""));
        assert!(json.contains("\"is_fallback\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"validity_epoch\""));
    }

    // -- Hash consistency ---------------------------------------------------

    #[test]
    fn flow_discovery_method_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_val<T: Hash>(v: &T) -> u64 {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        }

        let m = FlowDiscoveryMethod::StaticAnalysis;
        assert_eq!(hash_val(&m), hash_val(&FlowDiscoveryMethod::StaticAnalysis));
        assert_ne!(
            hash_val(&FlowDiscoveryMethod::StaticAnalysis),
            hash_val(&FlowDiscoveryMethod::DynamicAblation)
        );
    }

    #[test]
    fn flow_proof_method_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_val<T: Hash>(v: &T) -> u64 {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        }

        let m = FlowProofMethod::RuntimeCheck;
        assert_eq!(hash_val(&m), hash_val(&FlowProofMethod::RuntimeCheck));
        assert_ne!(
            hash_val(&FlowProofMethod::RuntimeCheck),
            hash_val(&FlowProofMethod::Declassification)
        );
    }

    #[test]
    fn synthesis_pass_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_val<T: Hash>(v: &T) -> u64 {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        }

        assert_eq!(
            hash_val(&SynthesisPass::StaticFlowAnalysis),
            hash_val(&SynthesisPass::StaticFlowAnalysis)
        );
        assert_ne!(
            hash_val(&SynthesisPass::StaticFlowAnalysis),
            hash_val(&SynthesisPass::DynamicFlowAblation)
        );
    }

    // -- Boundary / edge cases ---------------------------------------------

    #[test]
    fn confidence_interval_zero_trials() {
        let ci = FlowConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 0,
            n_trials: 0,
            n_essential: 0,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, deser);
    }

    #[test]
    fn confidence_interval_max_values() {
        let ci = FlowConfidenceInterval {
            lower_millionths: i64::MAX,
            upper_millionths: i64::MAX,
            n_trials: u32::MAX,
            n_essential: u32::MAX,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, deser);
    }

    #[test]
    fn confidence_interval_negative_lower_bound() {
        let ci = FlowConfidenceInterval {
            lower_millionths: -500_000,
            upper_millionths: 1_000_000,
            n_trials: 20,
            n_essential: 8,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, deser);
    }

    #[test]
    fn envelope_event_with_all_optional_fields_populated() {
        let ev = EnvelopeEvent {
            trace_id: "long-trace-id-xyz-123".to_string(),
            component: "flow_envelope".to_string(),
            event: "budget_exhausted".to_string(),
            outcome: "error".to_string(),
            error_code: Some("ENVELOPE_BUDGET_EXHAUSTED".to_string()),
            extension_id: Some("ext-edge".to_string()),
            flow_count: Some(0),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let deser: EnvelopeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deser);
        assert!(json.contains("\"flow_count\":0"));
    }

    #[test]
    fn flow_requirement_all_location_none() {
        let req = FlowRequirement {
            rule: rule(Label::TopSecret, Label::Public),
            discovery_method: FlowDiscoveryMethod::ManifestDeclaration,
            source_location: None,
            sink_location: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deser);
        assert!(json.contains("null"));
    }

    #[test]
    fn flow_proof_obligation_with_satisfied_hash() {
        let obl = FlowProofObligation {
            rule: rule(Label::Internal, Label::Confidential),
            required_method: FlowProofMethod::StaticAnalysis,
            justification: "proven safe".to_string(),
            proof_artifact_hash: Some(ContentHash::compute(b"proof-artifact-bytes")),
        };
        let json = serde_json::to_string(&obl).unwrap();
        let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(obl, deser);
        assert!(obl.proof_artifact_hash.is_some());
    }

    #[test]
    fn synthesis_pass_result_empty_sets() {
        let result = SynthesisPassResult {
            pass: SynthesisPass::DynamicFlowAblation,
            required_flows: BTreeSet::new(),
            removable_flows: BTreeSet::new(),
            time_consumed_ns: 0,
            completed: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: SynthesisPassResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deser);
        assert!(!deser.completed);
    }

    // -- Error trait checks -------------------------------------------------

    #[test]
    fn envelope_error_source_is_none() {
        use std::error::Error;
        // EnvelopeError has no chained source (no #[source] attribute).
        let e = EnvelopeError::EmptyExtensionId;
        assert!(e.source().is_none());
    }

    #[test]
    fn envelope_error_display_contains_meaningful_fields() {
        let err = EnvelopeError::OverlappingFlows { overlap_count: 7 };
        let msg = format!("{err}");
        assert!(msg.contains("7"));

        let err = EnvelopeError::MissingProofObligation {
            rule: rule(Label::TopSecret, Label::Public),
        };
        let msg = format!("{err}");
        assert!(msg.contains("top_secret") || msg.contains("TopSecret"));

        let err = EnvelopeError::BudgetExhausted {
            phase: "ablation".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("ablation"));
    }

    #[test]
    fn all_error_codes_unique() {
        let errors = [
            EnvelopeError::EmptyExtensionId,
            EnvelopeError::EmptyUpperBound,
            EnvelopeError::OverlappingFlows { overlap_count: 1 },
            EnvelopeError::MissingProofObligation {
                rule: rule(Label::Public, Label::Public),
            },
            EnvelopeError::IdDerivation(String::new()),
            EnvelopeError::SignatureError(String::new()),
            EnvelopeError::BudgetExhausted {
                phase: String::new(),
            },
        ];
        let codes: BTreeSet<&'static str> = errors.iter().map(error_code).collect();
        assert_eq!(codes.len(), errors.len());
    }

    // -- Additional synthesizer/build coverage ------------------------------

    #[test]
    fn synthesizer_new_stores_fields() {
        let synth = FlowEnvelopeSynthesizer::new("my-ext", 5_000_000, SecurityEpoch::from_raw(7));
        assert_eq!(synth.extension_id, "my-ext");
        assert_eq!(synth.time_budget_ns, 5_000_000);
        assert_eq!(synth.epoch, SecurityEpoch::from_raw(7));
        assert!(synth.events.is_empty());
    }

    #[test]
    fn synthesizer_serde_roundtrip() {
        let synth =
            FlowEnvelopeSynthesizer::new("ext-serde", 1_000_000_000, SecurityEpoch::from_raw(3));
        let json = serde_json::to_string(&synth).unwrap();
        let deser: FlowEnvelopeSynthesizer = serde_json::from_str(&json).unwrap();
        assert_eq!(synth.extension_id, deser.extension_id);
        assert_eq!(synth.time_budget_ns, deser.time_budget_ns);
        assert_eq!(synth.epoch, deser.epoch);
        assert_eq!(synth.events.len(), deser.events.len());
    }

    #[test]
    fn synthesizer_fallback_partial_ablation_quality() {
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-fb2", 30_000_000_000, SecurityEpoch::from_raw(2));
        let envelope = synth
            .synthesize_fallback(
                &upper,
                "policy-fb",
                9_999,
                FallbackQuality::PartialAblation,
                "trace-fb",
            )
            .unwrap();
        assert!(envelope.is_fallback);
        assert_eq!(
            envelope.fallback_quality,
            Some(FallbackQuality::PartialAblation)
        );
        assert!(envelope.verify_content_address());
    }

    #[test]
    fn fallback_envelope_uses_runtime_check_proof_method() {
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-fb3", 30_000_000_000, SecurityEpoch::from_raw(1));
        let envelope = synth
            .synthesize_fallback(&upper, "policy-fb", 0, FallbackQuality::StaticBound, "t")
            .unwrap();
        for obl in &envelope.proof_obligations {
            assert_eq!(obl.required_method, FlowProofMethod::RuntimeCheck);
        }
    }

    #[test]
    fn synthesizer_fallback_rejects_empty_extension_id() {
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
        let err = synth
            .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t")
            .unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyExtensionId);
    }

    #[test]
    fn synthesizer_fallback_rejects_empty_upper_bound() {
        let empty: BTreeSet<FlowRule> = BTreeSet::new();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-ok", 30_000_000_000, SecurityEpoch::from_raw(1));
        let err = synth
            .synthesize_fallback(&empty, "p", 0, FallbackQuality::StaticBound, "t")
            .unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyUpperBound);
    }

    #[test]
    fn envelope_with_ablation_required_uses_ablation_set() {
        // When ablation_required is non-empty, it should take precedence over
        // static_upper_bound for required_flows.
        let mut input = valid_input();
        // Limit ablation_required to just one flow.
        let single_flow = rule(Label::Public, Label::Internal);
        let mut just_one: BTreeSet<FlowRule> = BTreeSet::new();
        just_one.insert(single_flow.clone());
        input.ablation_required = just_one;
        input.ablation_removable = BTreeSet::new();
        let envelope = FlowEnvelope::build(input).unwrap();
        assert_eq!(envelope.required_flows.len(), 1);
        assert!(envelope.allows_flow(&single_flow));
    }

    #[test]
    fn envelope_with_empty_ablation_required_falls_back_to_static_upper_bound() {
        let mut input = valid_input();
        input.ablation_required = BTreeSet::new();
        input.ablation_removable = BTreeSet::new();
        let envelope = FlowEnvelope::build(input).unwrap();
        // Falls back to static_upper_bound (4 flows).
        assert_eq!(envelope.required_flows.len(), 4);
    }

    #[test]
    fn unsatisfied_obligations_decreases_when_hash_set() {
        let mut input = valid_input();
        // Give one obligation a satisfied hash.
        if let Some(first) = input.proof_obligations.first_mut() {
            first.proof_artifact_hash = Some(ContentHash::compute(b"satisfied"));
        }
        let envelope = FlowEnvelope::build(input).unwrap();
        // We have 2 obligations total, one satisfied → 1 unsatisfied.
        assert_eq!(envelope.unsatisfied_obligations(), 1);
    }

    #[test]
    fn unsatisfied_obligations_zero_when_all_satisfied() {
        let mut input = valid_input();
        for obl in &mut input.proof_obligations {
            obl.proof_artifact_hash = Some(ContentHash::compute(b"done"));
        }
        let envelope = FlowEnvelope::build(input).unwrap();
        assert_eq!(envelope.unsatisfied_obligations(), 0);
    }

    #[test]
    fn envelope_ref_clone_independence() {
        let original = FlowEnvelopeRef {
            envelope_id: EngineObjectId([0xBB; 32]),
            envelope_hash: ContentHash::compute(b"ref-hash"),
            envelope_epoch: SecurityEpoch::from_raw(3),
        };
        let mut cloned = original.clone();
        cloned.envelope_epoch = SecurityEpoch::from_raw(99);
        assert_eq!(original.envelope_epoch, SecurityEpoch::from_raw(3));
        assert_eq!(cloned.envelope_epoch, SecurityEpoch::from_raw(99));
    }

    #[test]
    fn static_pass_only_marks_safe_flows_required() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-sp", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        let result = synth.static_pass(&upper, "t");
        // Safe flows: Public→Internal, Internal→Confidential
        assert!(
            result
                .required_flows
                .contains(&rule(Label::Public, Label::Internal))
        );
        assert!(
            result
                .required_flows
                .contains(&rule(Label::Internal, Label::Confidential))
        );
        // Declassification flows go to removable.
        assert!(
            result
                .removable_flows
                .contains(&rule(Label::Confidential, Label::Public))
        );
        assert!(
            result
                .removable_flows
                .contains(&rule(Label::Secret, Label::Internal))
        );
    }

    #[test]
    fn dynamic_pass_with_empty_removable_returns_static_required() {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-dp", 30_000_000_000, SecurityEpoch::from_raw(1));
        let upper = test_upper_bound();
        // Build a static result with empty removable set.
        let static_result = SynthesisPassResult {
            pass: SynthesisPass::StaticFlowAnalysis,
            required_flows: {
                let mut s = BTreeSet::new();
                s.insert(rule(Label::Public, Label::Internal));
                s
            },
            removable_flows: BTreeSet::new(),
            time_consumed_ns: 0,
            completed: true,
        };
        let oracle = |_: &FlowRule| true; // Should not be called.
        let dynamic = synth.dynamic_pass(&static_result, &oracle, "t");
        assert_eq!(dynamic.required_flows.len(), 1);
        assert!(dynamic.removable_flows.is_empty());
        let _ = upper; // suppress unused warning
    }

    #[test]
    fn synthesize_confidence_reflects_essential_ratio() {
        let oracle = |r: &FlowRule| {
            // Only Confidential→Public is essential.
            r.source_label == Label::Confidential && r.sink_clearance == Label::Public
        };
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-conf", 30_000_000_000, SecurityEpoch::from_raw(1));
        let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();

        // 2 ablation trials (Confidential→Public, Secret→Internal), 1 essential
        assert_eq!(envelope.confidence.n_trials, 2);
        assert_eq!(envelope.confidence.n_essential, 1);
        // lower = 1_000_000 / 2 = 500_000
        assert_eq!(envelope.confidence.lower_millionths, 500_000);
    }

    #[test]
    fn flow_envelope_debug_is_non_empty() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let dbg = format!("{envelope:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("FlowEnvelope"));
    }

    #[test]
    fn synthesizer_events_after_fallback_contain_trace_id() {
        let upper = test_upper_bound();
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-evfb", 30_000_000_000, SecurityEpoch::from_raw(1));
        synth
            .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "fb-trace-99")
            .unwrap();
        for ev in &synth.events {
            assert_eq!(ev.trace_id, "fb-trace-99");
        }
    }

    #[test]
    fn is_out_of_envelope_false_for_required_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let safe = rule(Label::Public, Label::Internal);
        assert!(!envelope.is_out_of_envelope(&safe));
    }

    #[test]
    fn is_out_of_envelope_false_for_denied_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        let denied = rule(Label::Confidential, Label::Public);
        assert!(!envelope.is_out_of_envelope(&denied));
    }

    #[test]
    fn allows_and_denies_are_mutually_exclusive_for_any_known_flow() {
        let envelope = FlowEnvelope::build(valid_input()).unwrap();
        for r in &envelope.required_flows {
            assert!(envelope.allows_flow(r));
            assert!(!envelope.denies_flow(r));
        }
        for r in &envelope.denied_flows {
            assert!(envelope.denies_flow(r));
            assert!(!envelope.allows_flow(r));
        }
    }
}
