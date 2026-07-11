//! Replay vaccines: turn one incident into a signed, replayable behavioral
//! vaccine (bd-fqlfw.10.1, E10.T1).
//!
//! A vaccine is richer than an IOC (hash/domain/CVE). It packages:
//!
//! 1. the minimal causal **behavior motif** derived from the incident trace
//!    (the harmful decision steps plus immediate same-extension context);
//! 2. a proposed **intervention** (revoke token / add flow prohibition /
//!    tighten declassification / change loss threshold / force sandbox /
//!    quarantine) expressed both as its enforcement payload and as a
//!    counterfactual lens over [`CounterfactualConfig`];
//! 3. a deterministic **counterfactual proof** — replaying the incident trace
//!    through [`CounterfactualReplayEngine::compare`] under the intervention
//!    and requiring every harmful step to be neutralized — interventions that
//!    do not stop the incident are rejected;
//! 4. a **collateral estimate** over clean traces: the vaccine only fires
//!    where the motif completes, so the false-positive rate is motif-scoped
//!    (firings per clean decision), with the engine's unscoped divergence
//!    rate retained as a conservative upper bound;
//! 5. an Ed25519 **signature** over the canonical package via
//!    [`SignaturePreimage`], with a content-derived vaccine id.
//!
//! v1 is LOCAL-ONLY (`DistributionScope::LocalOnly` is the only variant):
//! vaccines are derived from local incidents, tested on local clean traces,
//! applied in shadow, and enforcement requires a signed
//! [`OperatorApproval`]. The [`VaccineRegistry`] fails closed: an engaged
//! safe-mode kill switch suppresses both shadow matching and enforcement,
//! and every enforcement precondition failure is a typed
//! [`EnforcementRefusal`]. Cross-tenant sharing is deliberately out of scope;
//! the [`commit_vaccine_to_transparency_log`] seam is where later epics
//! attach fleet distribution (freshness / quorum / transparency).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causal_replay::{CounterfactualConfig, DecisionSnapshot, TraceRecord};
use crate::counterfactual_evaluator::PolicyId;
use crate::counterfactual_replay_engine::{
    AlternatePolicy, CounterfactualReplayEngine, PolicyComparisonReport, ReplayEngineConfig,
    ReplayEngineError, ReplayScope,
};
use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignatureError, SignaturePreimage, SigningKey, VerificationKey,
    sign_object, verify_signature,
};
use crate::transparency_log::{TransparencyLog, TransparencyLogError};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the signed vaccine package.
pub const REPLAY_VACCINE_SCHEMA_VERSION: &str = "franken-engine.replay-vaccine.v1";

/// Schema version for the behavior motif.
pub const BEHAVIOR_MOTIF_SCHEMA_VERSION: &str = "franken-engine.behavior-motif.v1";

/// Schema version for the counterfactual proof summary.
pub const VACCINE_PROOF_SCHEMA_VERSION: &str = "franken-engine.vaccine-counterfactual-proof.v1";

/// Schema version for the collateral estimate.
pub const VACCINE_COLLATERAL_SCHEMA_VERSION: &str = "franken-engine.vaccine-collateral-estimate.v1";

/// Schema version for the operator enforcement approval.
pub const OPERATOR_APPROVAL_SCHEMA_VERSION: &str = "franken-engine.vaccine-operator-approval.v1";

/// Zone for motif object ids.
pub const MOTIF_ZONE: &str = "e10.behavior-motif.v1";

/// Zone for vaccine object ids.
pub const VACCINE_ZONE: &str = "e10.replay-vaccine.v1";

/// Fixed-point unit: 1.0 == 1_000_000.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Canonical byte helpers (length-prefixed)
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_i64(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn append_str(buf: &mut Vec<u8>, value: &str) {
    append_bytes(buf, value.as_bytes());
}

// ---------------------------------------------------------------------------
// Behavior motif
// ---------------------------------------------------------------------------

/// One step of a behavior motif.
///
/// `source_decision_index` locates the step in the originating incident trace
/// for proof evaluation; it is deliberately EXCLUDED from the motif-id
/// preimage so the id stays run-independent (E9.T1 precedent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MotifStep {
    /// Extension involved at this step.
    pub extension_id: String,
    /// Action the runtime chose at this step.
    pub chosen_action: String,
    /// Sorted evidence hashes available at the decision.
    pub evidence_hashes: Vec<ContentHash>,
    /// Tick delta from the previous motif step (0 for the first step).
    pub tick_delta: u64,
    /// Observed outcome (fixed-point millionths; negative = harm).
    pub outcome_millionths: i64,
    /// Whether this step crossed the harm threshold.
    pub harmful: bool,
    /// Decision index within the source incident trace (run coordinate;
    /// excluded from the motif id).
    pub source_decision_index: u64,
}

/// The minimal causal behavior motif derived from one incident trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorMotif {
    /// Schema version.
    pub schema_version: String,
    /// Run-independent content-derived motif id (hex).
    pub motif_id_hex: String,
    /// Incident this motif was derived from.
    pub incident_id: String,
    /// Source trace id (run coordinate; excluded from the motif id).
    pub source_trace_id: String,
    /// Ordered motif steps.
    pub steps: Vec<MotifStep>,
    /// Harm threshold used at derivation (outcome < threshold == harmful).
    pub harm_threshold_millionths: i64,
}

impl BehaviorMotif {
    /// Canonical run-independent bytes: step content with tick DELTAS, never
    /// trace ids, absolute ticks, or decision indices.
    fn id_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_i64(&mut buf, self.harm_threshold_millionths);
        append_u64(&mut buf, self.steps.len() as u64);
        for step in &self.steps {
            append_str(&mut buf, &step.extension_id);
            append_str(&mut buf, &step.chosen_action);
            append_u64(&mut buf, step.evidence_hashes.len() as u64);
            for hash in &step.evidence_hashes {
                append_bytes(&mut buf, hash.as_bytes());
            }
            append_u64(&mut buf, step.tick_delta);
            append_i64(&mut buf, step.outcome_millionths);
            append_u64(&mut buf, u64::from(step.harmful));
        }
        buf
    }

    fn derive_motif_id(&self) -> Result<EngineObjectId, IdError> {
        let schema = SchemaId::from_definition(BEHAVIOR_MOTIF_SCHEMA_VERSION.as_bytes());
        derive_id(
            ObjectDomain::EvidenceRecord,
            MOTIF_ZONE,
            &schema,
            &self.id_preimage(),
        )
    }

    /// Distinct harmful action strings in the motif (the counterfactual
    /// lens remaps exactly these).
    pub fn harmful_actions(&self) -> BTreeSet<String> {
        self.steps
            .iter()
            .filter(|s| s.harmful)
            .map(|s| s.chosen_action.clone())
            .collect()
    }

    /// Indices (in the source trace) of the harmful steps.
    pub fn harmful_source_indices(&self) -> Vec<u64> {
        self.steps
            .iter()
            .filter(|s| s.harmful)
            .map(|s| s.source_decision_index)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Interventions
// ---------------------------------------------------------------------------

/// The intervention a vaccine carries.
///
/// Each variant carries its real enforcement payload; the counterfactual
/// proof evaluates the variant through its *lens* — the closest expression of
/// the intervention in [`CounterfactualConfig`] vocabulary. Action-remap
/// lenses force the motif's harmful actions to a containment action;
/// [`VaccineIntervention::ChangeLossThreshold`] only overrides the decision
/// threshold, which in the replay engine's semantics never changes the chosen
/// action — its proof therefore honestly reports `stopped_incident == false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaccineIntervention {
    /// Revoke the capability token the incident abused (lens: harmful
    /// actions forced to `suspend`).
    RevokeCapabilityToken {
        /// Token to revoke on enforcement.
        token_id: String,
    },
    /// Add an IFC flow prohibition (lens: harmful actions forced to
    /// `sandbox`).
    AddFlowProhibition {
        /// Source label name.
        source_label: String,
        /// Sink label name.
        sink_label: String,
    },
    /// Tighten (remove) a declassification route (lens: harmful actions
    /// forced to `sandbox`).
    TightenDeclassification {
        /// Declassification route to tighten.
        route_id: String,
    },
    /// Change the decision threshold (lens: threshold override only; cannot
    /// remap actions, so it cannot stop an action-shaped incident).
    ChangeLossThreshold {
        /// New threshold (fixed-point millionths).
        threshold_millionths: i64,
    },
    /// Force the offending pattern into a sandbox.
    ForceSandbox,
    /// Quarantine the offending pattern.
    Quarantine,
}

impl VaccineIntervention {
    /// Stable slug for ids and policy names.
    pub fn kind_slug(&self) -> &'static str {
        match self {
            Self::RevokeCapabilityToken { .. } => "revoke-capability-token",
            Self::AddFlowProhibition { .. } => "add-flow-prohibition",
            Self::TightenDeclassification { .. } => "tighten-declassification",
            Self::ChangeLossThreshold { .. } => "change-loss-threshold",
            Self::ForceSandbox => "force-sandbox",
            Self::Quarantine => "quarantine",
        }
    }

    /// The containment action this intervention forces at motif-matched
    /// decisions (`None` for threshold-only lenses).
    pub fn forced_action(&self) -> Option<&'static str> {
        match self {
            Self::RevokeCapabilityToken { .. } => Some("suspend"),
            Self::AddFlowProhibition { .. } | Self::TightenDeclassification { .. } => {
                Some("sandbox")
            }
            Self::ChangeLossThreshold { .. } => None,
            Self::ForceSandbox => Some("sandbox"),
            Self::Quarantine => Some("quarantine"),
        }
    }

    /// Canonical bytes for the vaccine-id preimage.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, self.kind_slug());
        match self {
            Self::RevokeCapabilityToken { token_id } => append_str(&mut buf, token_id),
            Self::AddFlowProhibition {
                source_label,
                sink_label,
            } => {
                append_str(&mut buf, source_label);
                append_str(&mut buf, sink_label);
            }
            Self::TightenDeclassification { route_id } => append_str(&mut buf, route_id),
            Self::ChangeLossThreshold {
                threshold_millionths,
            } => append_i64(&mut buf, *threshold_millionths),
            Self::ForceSandbox | Self::Quarantine => {}
        }
        buf
    }

    /// Express this intervention as an alternate policy over the motif's
    /// harmful actions for counterfactual replay.
    pub fn to_alternate_policy(&self, motif: &BehaviorMotif) -> AlternatePolicy {
        let mut containment_overrides = BTreeMap::new();
        if let Some(target) = self.forced_action() {
            for action in motif.harmful_actions() {
                containment_overrides.insert(action, target.to_string());
            }
        }
        let threshold_override_millionths = match self {
            Self::ChangeLossThreshold {
                threshold_millionths,
            } => Some(*threshold_millionths),
            _ => None,
        };
        let policy_id = format!(
            "vaccine-{}-{}",
            self.kind_slug(),
            &motif.motif_id_hex[..motif.motif_id_hex.len().min(16)]
        );
        AlternatePolicy {
            policy_id: PolicyId(policy_id.clone()),
            description: format!(
                "replay-vaccine lens: {} over motif {}",
                self.kind_slug(),
                motif.motif_id_hex
            ),
            counterfactual_config: CounterfactualConfig {
                branch_id: policy_id,
                threshold_override_millionths,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides,
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: None,
        }
    }
}

impl fmt::Display for VaccineIntervention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_slug())
    }
}

// ---------------------------------------------------------------------------
// Counterfactual proof
// ---------------------------------------------------------------------------

/// Summary of the deterministic counterfactual replay proving (or failing to
/// prove) that the intervention stops the incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaccineCounterfactualProof {
    /// Schema version.
    pub schema_version: String,
    /// Alternate policy id the lens ran under.
    pub lens_policy_id: String,
    /// Incident trace replayed.
    pub incident_trace_id: String,
    /// Motif the proof is anchored to.
    pub motif_id_hex: String,
    /// Whether every harmful motif step was neutralized AND net improvement
    /// was positive.
    pub stopped_incident: bool,
    /// Harmful steps in the motif.
    pub harmful_steps_total: u64,
    /// Harmful steps neutralized under the intervention.
    pub harmful_steps_neutralized: u64,
    /// Net improvement (counterfactual minus original, millionths).
    pub net_improvement_millionths: i64,
    /// Whether the report's confidence envelope was `Safe`.
    pub confident: bool,
    /// Divergent decision indices within the incident trace.
    pub divergent_decision_indices: Vec<u64>,
    /// Artifact hash of the underlying [`PolicyComparisonReport`].
    pub report_artifact_hash: ContentHash,
}

impl VaccineCounterfactualProof {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.lens_policy_id);
        append_str(&mut buf, &self.incident_trace_id);
        append_str(&mut buf, &self.motif_id_hex);
        append_u64(&mut buf, u64::from(self.stopped_incident));
        append_u64(&mut buf, self.harmful_steps_total);
        append_u64(&mut buf, self.harmful_steps_neutralized);
        append_i64(&mut buf, self.net_improvement_millionths);
        append_u64(&mut buf, u64::from(self.confident));
        append_u64(&mut buf, self.divergent_decision_indices.len() as u64);
        for index in &self.divergent_decision_indices {
            append_u64(&mut buf, *index);
        }
        append_bytes(&mut buf, self.report_artifact_hash.as_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Collateral estimate
// ---------------------------------------------------------------------------

/// Motif-scoped false-positive estimate over clean traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralEstimate {
    /// Schema version.
    pub schema_version: String,
    /// Clean traces evaluated.
    pub clean_traces_evaluated: u64,
    /// Total clean decisions scanned.
    pub clean_decisions_evaluated: u64,
    /// Motif completions ("firings") observed on clean traffic.
    pub motif_firings: u64,
    /// Motif-scoped collateral rate: firings per clean decision (millionths).
    /// This is the deployment-semantic rate the enforcement budget checks.
    pub collateral_rate_millionths: i64,
    /// Unscoped divergence rate reported by the replay engine under the blunt
    /// lens (conservative upper bound; diagnostic only).
    pub unscoped_divergence_rate_millionths: i64,
    /// Extensions whose clean decisions the motif fired on.
    pub affected_extensions: BTreeSet<String>,
}

impl CollateralEstimate {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_u64(&mut buf, self.clean_traces_evaluated);
        append_u64(&mut buf, self.clean_decisions_evaluated);
        append_u64(&mut buf, self.motif_firings);
        append_i64(&mut buf, self.collateral_rate_millionths);
        append_i64(&mut buf, self.unscoped_divergence_rate_millionths);
        append_u64(&mut buf, self.affected_extensions.len() as u64);
        for ext in &self.affected_extensions {
            append_str(&mut buf, ext);
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Motif matcher (shared by collateral estimation and shadow observation)
// ---------------------------------------------------------------------------

/// Deterministic subsequence matcher: each motif step matches the first
/// subsequent decision with the same `(extension_id, chosen_action)`. A full
/// match is a "firing"; the cursor then resets so a motif can fire repeatedly.
#[derive(Debug, Clone, Default)]
pub struct MotifMatcher {
    cursor: usize,
}

impl MotifMatcher {
    /// Create a fresh matcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance on one decision; returns true when the motif completes.
    pub fn observe(&mut self, motif: &BehaviorMotif, snapshot: &DecisionSnapshot) -> bool {
        let Some(step) = motif.steps.get(self.cursor) else {
            self.cursor = 0;
            return false;
        };
        if step.extension_id == snapshot.extension_id
            && step.chosen_action == snapshot.chosen_action
        {
            self.cursor += 1;
            if self.cursor == motif.steps.len() {
                self.cursor = 0;
                return true;
            }
        }
        false
    }

    /// Steps currently matched.
    pub fn progress(&self) -> usize {
        self.cursor
    }
}

// ---------------------------------------------------------------------------
// Signed vaccine package
// ---------------------------------------------------------------------------

/// Distribution scope. v1 is local-only by construction; fleet distribution
/// arrives with later epics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionScope {
    /// Derived, proven, and applied on this node only.
    LocalOnly,
}

/// The signed behavioral vaccine package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayVaccine {
    /// Schema version.
    pub schema_version: String,
    /// Content-derived vaccine id (hex); excludes itself and the signature.
    pub vaccine_id_hex: String,
    /// Incident the vaccine was derived from.
    pub incident_id: String,
    /// Epoch of the incident trace's end.
    pub epoch: SecurityEpoch,
    /// Caller-supplied creation timestamp (nanoseconds).
    pub created_at_ns: u64,
    /// Hex id of the producer verification key.
    pub producer_key_id: String,
    /// The behavior motif.
    pub motif: BehaviorMotif,
    /// The proven intervention.
    pub intervention: VaccineIntervention,
    /// Counterfactual proof summary.
    pub proof: VaccineCounterfactualProof,
    /// Clean-trace collateral estimate.
    pub collateral: CollateralEstimate,
    /// Distribution scope (v1: local-only).
    pub distribution_scope: DistributionScope,
    /// Ed25519 signature over the canonical unsigned view.
    pub signature: Signature,
}

fn replay_vaccine_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(REPLAY_VACCINE_SCHEMA_VERSION.as_bytes()));
    &HASH
}

fn operator_approval_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(OPERATOR_APPROVAL_SCHEMA_VERSION.as_bytes()));
    &HASH
}

impl SignaturePreimage for ReplayVaccine {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        replay_vaccine_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).expect("serialization should succeed"))
    }
}

impl ReplayVaccine {
    /// Canonical bytes the vaccine id is derived from: everything except the
    /// id field itself and the signature.
    fn id_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.incident_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.created_at_ns);
        append_str(&mut buf, &self.producer_key_id);
        append_bytes(&mut buf, &self.motif.id_preimage());
        append_bytes(&mut buf, &self.intervention.canonical_bytes());
        append_bytes(&mut buf, &self.proof.canonical_bytes());
        append_bytes(&mut buf, &self.collateral.canonical_bytes());
        append_str(&mut buf, "local-only");
        buf
    }

    fn derive_vaccine_id(&self) -> Result<EngineObjectId, IdError> {
        let schema = SchemaId::from_definition(REPLAY_VACCINE_SCHEMA_VERSION.as_bytes());
        derive_id(
            ObjectDomain::PolicyObject,
            VACCINE_ZONE,
            &schema,
            &self.id_preimage(),
        )
    }

    /// Sign the package (fills `signature`).
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), SignatureError> {
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the package signature.
    pub fn verify(&self, key: &VerificationKey) -> Result<(), SignatureError> {
        verify_signature(key, &self.preimage_bytes(), &self.signature)
    }

    /// Verify that `vaccine_id_hex` matches the content it claims to bind.
    pub fn verify_id(&self) -> Result<bool, IdError> {
        Ok(self.derive_vaccine_id()?.to_hex() == self.vaccine_id_hex)
    }

    /// Content hash of the full signed package (transparency-log receipt).
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = self.id_preimage();
        append_str(&mut buf, &self.vaccine_id_hex);
        append_bytes(&mut buf, &self.signature.to_bytes());
        ContentHash::compute(&buf)
    }
}

/// Append the vaccine's content hash to a transparency log so later fleet
/// distribution can prove inclusion.
pub fn commit_vaccine_to_transparency_log(
    vaccine: &ReplayVaccine,
    log: &mut TransparencyLog,
    appended_at_ns: u64,
) -> Result<u64, TransparencyLogError> {
    log.append_receipt(vaccine.content_hash(), appended_at_ns)
}

// ---------------------------------------------------------------------------
// Operator approval
// ---------------------------------------------------------------------------

/// A signed operator approval authorizing enforcement of one vaccine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorApproval {
    /// Schema version.
    pub schema_version: String,
    /// The exact vaccine this approval binds to.
    pub vaccine_id_hex: String,
    /// Hex id of the operator verification key.
    pub operator_key_id: String,
    /// Epoch at approval time.
    pub approval_epoch: SecurityEpoch,
    /// Ed25519 signature by the operator key.
    pub signature: Signature,
}

impl SignaturePreimage for OperatorApproval {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        operator_approval_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).expect("serialization should succeed"))
    }
}

impl OperatorApproval {
    /// Build and sign an approval for a vaccine.
    pub fn create(
        vaccine_id_hex: String,
        approval_epoch: SecurityEpoch,
        operator_key: &SigningKey,
    ) -> Result<Self, SignatureError> {
        let mut approval = Self {
            schema_version: OPERATOR_APPROVAL_SCHEMA_VERSION.to_string(),
            vaccine_id_hex,
            operator_key_id: operator_key.verification_key().to_hex(),
            approval_epoch,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        approval.signature = sign_object(&approval, operator_key)?;
        Ok(approval)
    }

    /// Verify the approval signature.
    pub fn verify(&self, key: &VerificationKey) -> Result<(), SignatureError> {
        verify_signature(key, &self.preimage_bytes(), &self.signature)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures while deriving, proving, or packaging a vaccine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaccineError {
    /// The incident trace contains no harmful decisions at the configured
    /// threshold.
    NoHarmfulDecisions {
        /// Threshold used.
        harm_threshold_millionths: i64,
    },
    /// The incident trace has no incident id set.
    MissingIncidentId,
    /// Not enough clean evidence to estimate collateral.
    InsufficientCleanEvidence {
        /// Clean decisions found.
        found: u64,
        /// Minimum required.
        required: u64,
    },
    /// The counterfactual replay engine failed.
    ReplayEngine(String),
    /// Object-id derivation failed.
    Id(String),
    /// Signing failed.
    Signature(String),
}

impl fmt::Display for VaccineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHarmfulDecisions {
                harm_threshold_millionths,
            } => write!(
                f,
                "no harmful decisions below threshold {harm_threshold_millionths}"
            ),
            Self::MissingIncidentId => write!(f, "incident trace has no incident id"),
            Self::InsufficientCleanEvidence { found, required } => write!(
                f,
                "insufficient clean evidence: found {found}, required {required}"
            ),
            Self::ReplayEngine(msg) => write!(f, "replay engine error: {msg}"),
            Self::Id(msg) => write!(f, "id derivation error: {msg}"),
            Self::Signature(msg) => write!(f, "signature error: {msg}"),
        }
    }
}

impl std::error::Error for VaccineError {}

impl From<ReplayEngineError> for VaccineError {
    fn from(err: ReplayEngineError) -> Self {
        Self::ReplayEngine(err.to_string())
    }
}

impl From<IdError> for VaccineError {
    fn from(err: IdError) -> Self {
        Self::Id(format!("{err:?}"))
    }
}

impl From<SignatureError> for VaccineError {
    fn from(err: SignatureError) -> Self {
        Self::Signature(format!("{err:?}"))
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Configuration for vaccine derivation and acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaccineFactoryConfig {
    /// Outcomes strictly below this are harmful (default 0).
    pub harm_threshold_millionths: i64,
    /// Counterfactual outcomes at or above this neutralize a harmful step
    /// (default 0).
    pub neutralization_threshold_millionths: i64,
    /// Maximum motif steps retained (closest to the harm; default 8).
    pub max_motif_steps: usize,
    /// Include the immediately preceding same-extension decision before each
    /// harmful step as context (default true).
    pub include_context_step: bool,
    /// Minimum clean decisions required for a collateral estimate
    /// (default 5).
    pub min_clean_decisions: u64,
    /// Maximum motif-scoped collateral rate accepted at build time
    /// (millionths; default 100_000 == 10%).
    pub max_collateral_millionths: i64,
}

impl Default for VaccineFactoryConfig {
    fn default() -> Self {
        Self {
            harm_threshold_millionths: 0,
            neutralization_threshold_millionths: 0,
            max_motif_steps: 8,
            include_context_step: true,
            min_clean_decisions: 5,
            max_collateral_millionths: 100_000,
        }
    }
}

/// Why a candidate intervention was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateRejection {
    /// The counterfactual replay did not neutralize every harmful step.
    DidNotStopIncident {
        /// Steps neutralized.
        neutralized: u64,
        /// Harmful steps total.
        total: u64,
    },
    /// Motif-scoped collateral exceeded the configured budget.
    CollateralExceedsBudget {
        /// Observed rate (millionths).
        observed_millionths: i64,
        /// Budget (millionths).
        max_millionths: i64,
    },
}

impl fmt::Display for CandidateRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DidNotStopIncident { neutralized, total } => {
                write!(
                    f,
                    "did not stop incident ({neutralized}/{total} neutralized)"
                )
            }
            Self::CollateralExceedsBudget {
                observed_millionths,
                max_millionths,
            } => write!(
                f,
                "collateral {observed_millionths} exceeds budget {max_millionths}"
            ),
        }
    }
}

/// A rejected candidate with its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedCandidate {
    /// The intervention that was tried.
    pub intervention: VaccineIntervention,
    /// Why it was rejected.
    pub rejection: CandidateRejection,
}

/// Outcome of a build attempt over a candidate list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaccineBuildOutcome {
    /// The first candidate that stopped the incident within budget, packaged
    /// and signed; `None` when every candidate was rejected.
    pub vaccine: Option<ReplayVaccine>,
    /// Candidates rejected before (or instead of) success, in try order.
    pub rejected: Vec<RejectedCandidate>,
}

impl VaccineBuildOutcome {
    /// Whether a vaccine was produced.
    pub fn is_success(&self) -> bool {
        self.vaccine.is_some()
    }
}

/// Derives motifs, proves interventions counterfactually, estimates
/// collateral, and packages signed vaccines.
#[derive(Debug)]
pub struct VaccineFactory {
    config: VaccineFactoryConfig,
    engine: CounterfactualReplayEngine,
}

impl VaccineFactory {
    /// Create a factory.
    pub fn new(config: VaccineFactoryConfig) -> Self {
        Self {
            config,
            engine: CounterfactualReplayEngine::new(ReplayEngineConfig::default()),
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &VaccineFactoryConfig {
        &self.config
    }

    /// Derive the behavior motif from an incident trace: the harmful
    /// decisions (outcome below the harm threshold) plus, optionally, the
    /// immediately preceding same-extension decision as context, capped at
    /// `max_motif_steps` closest to the harm.
    pub fn derive_motif(&self, trace: &TraceRecord) -> Result<BehaviorMotif, VaccineError> {
        let incident_id = trace
            .incident_id
            .clone()
            .ok_or(VaccineError::MissingIncidentId)?;
        let snapshots: Vec<&DecisionSnapshot> = trace.entries.iter().map(|e| &e.decision).collect();

        let mut selected_indices = BTreeSet::new();
        for (pos, snapshot) in snapshots.iter().enumerate() {
            if snapshot.outcome_millionths < self.config.harm_threshold_millionths {
                selected_indices.insert(pos);
                if self.config.include_context_step
                    && let Some(prev_pos) = snapshots[..pos]
                        .iter()
                        .rposition(|s| s.extension_id == snapshot.extension_id)
                {
                    selected_indices.insert(prev_pos);
                }
            }
        }
        if !snapshots
            .iter()
            .any(|s| s.outcome_millionths < self.config.harm_threshold_millionths)
        {
            return Err(VaccineError::NoHarmfulDecisions {
                harm_threshold_millionths: self.config.harm_threshold_millionths,
            });
        }

        // Keep the last `max_motif_steps` selected positions (closest to
        // the harm), preserving order.
        let ordered: Vec<usize> = selected_indices.into_iter().collect();
        let keep_from = ordered.len().saturating_sub(self.config.max_motif_steps);
        let kept = &ordered[keep_from..];

        let mut steps = Vec::with_capacity(kept.len());
        let mut prev_tick: Option<u64> = None;
        for &pos in kept {
            let snapshot = snapshots[pos];
            let mut evidence = snapshot.evidence_hashes.clone();
            evidence.sort();
            steps.push(MotifStep {
                extension_id: snapshot.extension_id.clone(),
                chosen_action: snapshot.chosen_action.clone(),
                evidence_hashes: evidence,
                tick_delta: prev_tick.map_or(0, |t| snapshot.tick.saturating_sub(t)),
                outcome_millionths: snapshot.outcome_millionths,
                harmful: snapshot.outcome_millionths < self.config.harm_threshold_millionths,
                source_decision_index: snapshot.decision_index,
            });
            prev_tick = Some(snapshot.tick);
        }

        let mut motif = BehaviorMotif {
            schema_version: BEHAVIOR_MOTIF_SCHEMA_VERSION.to_string(),
            motif_id_hex: String::new(),
            incident_id,
            source_trace_id: trace.trace_id.clone(),
            steps,
            harm_threshold_millionths: self.config.harm_threshold_millionths,
        };
        motif.motif_id_hex = motif.derive_motif_id()?.to_hex();
        Ok(motif)
    }

    /// Auto-proposable interventions for a motif, least blast radius first.
    /// Only action-remap kinds are derivable from a motif alone; payload
    /// kinds (revoke token, flow prohibition, declassification) require
    /// operator-supplied context and enter via [`Self::build_best`] directly.
    pub fn propose_interventions(&self, _motif: &BehaviorMotif) -> Vec<VaccineIntervention> {
        vec![
            VaccineIntervention::ForceSandbox,
            VaccineIntervention::Quarantine,
        ]
    }

    /// Counterfactually replay the incident under one intervention.
    pub fn prove(
        &mut self,
        incident_trace: &TraceRecord,
        motif: &BehaviorMotif,
        intervention: &VaccineIntervention,
    ) -> Result<VaccineCounterfactualProof, VaccineError> {
        let alternate = intervention.to_alternate_policy(motif);
        let mut incident_filter = BTreeSet::new();
        incident_filter.insert(motif.incident_id.clone());
        let scope = ReplayScope {
            incident_filter,
            ..ReplayScope::default()
        };
        let result = self.engine.compare(
            std::slice::from_ref(incident_trace),
            std::slice::from_ref(&alternate),
            &scope,
            None,
        )?;
        let report = result
            .policy_reports
            .first()
            .ok_or_else(|| VaccineError::ReplayEngine("empty policy report list".to_string()))?;
        Ok(build_proof(report, motif, incident_trace, &self.config))
    }

    /// Estimate motif-scoped collateral over clean traces, with the engine's
    /// unscoped divergence rate as an upper-bound diagnostic.
    pub fn estimate_collateral(
        &mut self,
        clean_traces: &[TraceRecord],
        motif: &BehaviorMotif,
        intervention: &VaccineIntervention,
    ) -> Result<CollateralEstimate, VaccineError> {
        let clean_decisions: u64 = clean_traces.iter().map(|t| t.entries.len() as u64).sum();
        if clean_decisions < self.config.min_clean_decisions {
            return Err(VaccineError::InsufficientCleanEvidence {
                found: clean_decisions,
                required: self.config.min_clean_decisions,
            });
        }

        // Motif-scoped firings: the vaccine only acts where the motif
        // completes.
        let mut firings = 0u64;
        let mut affected = BTreeSet::new();
        for trace in clean_traces {
            let mut matcher = MotifMatcher::new();
            for entry in &trace.entries {
                if matcher.observe(motif, &entry.decision) {
                    firings += 1;
                    affected.insert(entry.decision.extension_id.clone());
                }
            }
        }
        let collateral_rate_millionths =
            ((firings as i128 * MILLION as i128) / clean_decisions as i128) as i64;

        // Unscoped upper bound from the replay engine's blunt lens.
        let alternate = intervention.to_alternate_policy(motif);
        let unscoped_divergence_rate_millionths = match self.engine.compare(
            clean_traces,
            std::slice::from_ref(&alternate),
            &ReplayScope::default(),
            None,
        ) {
            Ok(result) => result
                .policy_reports
                .first()
                .map_or(0, PolicyComparisonReport::divergence_rate_millionths),
            // A clean corpus with no in-scope decisions is not an error for
            // the diagnostic bound; record zero divergence.
            Err(ReplayEngineError::EmptyScope) => 0,
            Err(err) => return Err(err.into()),
        };

        Ok(CollateralEstimate {
            schema_version: VACCINE_COLLATERAL_SCHEMA_VERSION.to_string(),
            clean_traces_evaluated: clean_traces.len() as u64,
            clean_decisions_evaluated: clean_decisions,
            motif_firings: firings,
            collateral_rate_millionths,
            unscoped_divergence_rate_millionths,
            affected_extensions: affected,
        })
    }

    /// Try candidates in order; the first that stops the incident within the
    /// collateral budget is packaged and signed. Rejected candidates are
    /// recorded with typed reasons.
    pub fn build_best(
        &mut self,
        incident_trace: &TraceRecord,
        clean_traces: &[TraceRecord],
        candidates: &[VaccineIntervention],
        producer_key: &SigningKey,
        created_at_ns: u64,
    ) -> Result<VaccineBuildOutcome, VaccineError> {
        let motif = self.derive_motif(incident_trace)?;
        let mut rejected = Vec::new();

        for intervention in candidates {
            let proof = self.prove(incident_trace, &motif, intervention)?;
            if !proof.stopped_incident {
                rejected.push(RejectedCandidate {
                    intervention: intervention.clone(),
                    rejection: CandidateRejection::DidNotStopIncident {
                        neutralized: proof.harmful_steps_neutralized,
                        total: proof.harmful_steps_total,
                    },
                });
                continue;
            }
            let collateral = self.estimate_collateral(clean_traces, &motif, intervention)?;
            if collateral.collateral_rate_millionths > self.config.max_collateral_millionths {
                rejected.push(RejectedCandidate {
                    intervention: intervention.clone(),
                    rejection: CandidateRejection::CollateralExceedsBudget {
                        observed_millionths: collateral.collateral_rate_millionths,
                        max_millionths: self.config.max_collateral_millionths,
                    },
                });
                continue;
            }

            let mut vaccine = ReplayVaccine {
                schema_version: REPLAY_VACCINE_SCHEMA_VERSION.to_string(),
                vaccine_id_hex: String::new(),
                incident_id: motif.incident_id.clone(),
                epoch: incident_trace.end_epoch,
                created_at_ns,
                producer_key_id: producer_key.verification_key().to_hex(),
                motif: motif.clone(),
                intervention: intervention.clone(),
                proof,
                collateral,
                distribution_scope: DistributionScope::LocalOnly,
                signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            };
            vaccine.vaccine_id_hex = vaccine.derive_vaccine_id()?.to_hex();
            vaccine.sign(producer_key)?;
            return Ok(VaccineBuildOutcome {
                vaccine: Some(vaccine),
                rejected,
            });
        }

        Ok(VaccineBuildOutcome {
            vaccine: None,
            rejected,
        })
    }
}

/// Evaluate the proof from a comparison report against the motif's harmful
/// steps. A harmful step is neutralized when the replay diverged at its
/// decision index and the counterfactual outcome cleared the neutralization
/// threshold.
fn build_proof(
    report: &PolicyComparisonReport,
    motif: &BehaviorMotif,
    incident_trace: &TraceRecord,
    config: &VaccineFactoryConfig,
) -> VaccineCounterfactualProof {
    let divergent: BTreeMap<u64, i64> = report
        .divergent_decisions
        .iter()
        .map(|d| (d.decision_index, d.counterfactual_outcome_millionths))
        .collect();

    let harmful = motif.harmful_source_indices();
    let neutralized = harmful
        .iter()
        .filter(|index| {
            divergent
                .get(index)
                .is_some_and(|outcome| *outcome >= config.neutralization_threshold_millionths)
        })
        .count() as u64;
    let total = harmful.len() as u64;
    let stopped = total > 0 && neutralized == total && report.net_improvement_millionths > 0;

    VaccineCounterfactualProof {
        schema_version: VACCINE_PROOF_SCHEMA_VERSION.to_string(),
        lens_policy_id: report.alternate_policy_id.0.clone(),
        incident_trace_id: incident_trace.trace_id.clone(),
        motif_id_hex: motif.motif_id_hex.clone(),
        stopped_incident: stopped,
        harmful_steps_total: total,
        harmful_steps_neutralized: neutralized,
        net_improvement_millionths: report.net_improvement_millionths,
        confident: report.is_confident_improvement(),
        divergent_decision_indices: divergent.keys().copied().collect(),
        report_artifact_hash: report.artifact_hash,
    }
}

// ---------------------------------------------------------------------------
// Registry: shadow application + operator-approved enforcement
// ---------------------------------------------------------------------------

/// Lifecycle state of a registered vaccine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaccineState {
    /// Matching and recording only; no enforcement.
    Shadow,
    /// Operator-approved for enforcement.
    Enforced,
    /// Withdrawn by the operator.
    Retired,
}

/// A motif completion observed while a vaccine is registered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowMatchEvent {
    /// Vaccine that matched.
    pub vaccine_id_hex: String,
    /// Trace the triggering decision belongs to.
    pub trace_id: String,
    /// Tick of the triggering decision.
    pub matched_at_tick: u64,
    /// Decision index of the triggering decision.
    pub trigger_decision_index: u64,
    /// State the vaccine was in when it matched.
    pub state: VaccineState,
    /// Action the intervention would force (`None` for threshold lenses).
    pub would_apply_action: Option<String>,
}

/// Receipt for an approved enforcement transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    /// Vaccine enforced.
    pub vaccine_id_hex: String,
    /// Operator key that approved.
    pub operator_key_id: String,
    /// Epoch of the approval.
    pub approval_epoch: SecurityEpoch,
    /// Content hash binding this receipt.
    pub receipt_hash: ContentHash,
}

/// Typed, fail-closed enforcement refusals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementRefusal {
    /// Safe-mode kill switch is engaged.
    SafeModeEngaged,
    /// No vaccine registered under this id.
    UnknownVaccine,
    /// The vaccine is not in shadow state (already enforced or retired).
    NotInShadowState {
        /// Current state.
        state: VaccineState,
    },
    /// The packaged proof did not stop the incident.
    ProofDidNotStopIncident,
    /// The packaged collateral exceeds the registry budget.
    CollateralExceedsBudget {
        /// Observed rate (millionths).
        observed_millionths: i64,
        /// Budget (millionths).
        max_millionths: i64,
    },
    /// The approval names a different vaccine.
    ApprovalVaccineMismatch,
    /// The approval signature does not verify against the operator key.
    ApprovalSignatureInvalid,
    /// The approval epoch predates the vaccine epoch.
    ApprovalEpochStale {
        /// Approval epoch.
        approval_epoch: SecurityEpoch,
        /// Vaccine epoch.
        vaccine_epoch: SecurityEpoch,
    },
}

impl fmt::Display for EnforcementRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SafeModeEngaged => write!(f, "safe-mode kill switch engaged"),
            Self::UnknownVaccine => write!(f, "unknown vaccine"),
            Self::NotInShadowState { state } => write!(f, "not in shadow state ({state:?})"),
            Self::ProofDidNotStopIncident => write!(f, "proof did not stop incident"),
            Self::CollateralExceedsBudget {
                observed_millionths,
                max_millionths,
            } => write!(
                f,
                "collateral {observed_millionths} exceeds budget {max_millionths}"
            ),
            Self::ApprovalVaccineMismatch => write!(f, "approval names a different vaccine"),
            Self::ApprovalSignatureInvalid => write!(f, "approval signature invalid"),
            Self::ApprovalEpochStale {
                approval_epoch,
                vaccine_epoch,
            } => write!(
                f,
                "approval epoch {} predates vaccine epoch {}",
                approval_epoch.as_u64(),
                vaccine_epoch.as_u64()
            ),
        }
    }
}

/// Registry configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Maximum packaged collateral rate acceptable for enforcement
    /// (millionths; default 100_000 == 10%).
    pub max_collateral_millionths: i64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_collateral_millionths: 100_000,
        }
    }
}

#[derive(Debug, Clone)]
struct RegisteredVaccine {
    vaccine: ReplayVaccine,
    state: VaccineState,
    matcher: MotifMatcher,
}

/// Local vaccine registry: verifies, shadow-applies, matches, and gates
/// enforcement behind operator approval. Fails closed throughout; the
/// safe-mode kill switch suppresses both matching and enforcement.
#[derive(Debug)]
pub struct VaccineRegistry {
    config: RegistryConfig,
    producer_key: VerificationKey,
    operator_key: VerificationKey,
    vaccines: BTreeMap<String, RegisteredVaccine>,
    safe_mode: bool,
}

impl VaccineRegistry {
    /// Create a registry trusting one producer key and one operator key.
    pub fn new(
        config: RegistryConfig,
        producer_key: VerificationKey,
        operator_key: VerificationKey,
    ) -> Self {
        Self {
            config,
            producer_key,
            operator_key,
            vaccines: BTreeMap::new(),
            safe_mode: false,
        }
    }

    /// Engage or release the safe-mode kill switch.
    pub fn set_safe_mode(&mut self, engaged: bool) {
        self.safe_mode = engaged;
    }

    /// Whether safe mode is engaged.
    pub fn safe_mode(&self) -> bool {
        self.safe_mode
    }

    /// Current state of a registered vaccine.
    pub fn state(&self, vaccine_id_hex: &str) -> Option<VaccineState> {
        self.vaccines.get(vaccine_id_hex).map(|r| r.state)
    }

    /// Number of registered vaccines.
    pub fn len(&self) -> usize {
        self.vaccines.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.vaccines.is_empty()
    }

    /// Register a vaccine in shadow state. Verifies the producer signature
    /// and the content-derived id; anything invalid is refused.
    pub fn register_shadow(&mut self, vaccine: ReplayVaccine) -> Result<(), VaccineError> {
        vaccine.verify(&self.producer_key)?;
        if !vaccine.verify_id()? {
            return Err(VaccineError::Id(
                "vaccine id does not match content".to_string(),
            ));
        }
        self.vaccines.insert(
            vaccine.vaccine_id_hex.clone(),
            RegisteredVaccine {
                vaccine,
                state: VaccineState::Shadow,
                matcher: MotifMatcher::new(),
            },
        );
        Ok(())
    }

    /// Feed one live decision to every registered, non-retired vaccine.
    /// Returns motif-completion events. Suppressed entirely in safe mode.
    pub fn observe_decision(&mut self, snapshot: &DecisionSnapshot) -> Vec<ShadowMatchEvent> {
        if self.safe_mode {
            return Vec::new();
        }
        let mut events = Vec::new();
        for registered in self.vaccines.values_mut() {
            if registered.state == VaccineState::Retired {
                continue;
            }
            if registered
                .matcher
                .observe(&registered.vaccine.motif, snapshot)
            {
                events.push(ShadowMatchEvent {
                    vaccine_id_hex: registered.vaccine.vaccine_id_hex.clone(),
                    trace_id: snapshot.trace_id.clone(),
                    matched_at_tick: snapshot.tick,
                    trigger_decision_index: snapshot.decision_index,
                    state: registered.state,
                    would_apply_action: registered
                        .vaccine
                        .intervention
                        .forced_action()
                        .map(str::to_string),
                });
            }
        }
        events
    }

    /// Approve enforcement of a shadow vaccine. Every precondition failure is
    /// a typed refusal; nothing is enforced implicitly.
    pub fn approve_enforcement(
        &mut self,
        vaccine_id_hex: &str,
        approval: &OperatorApproval,
    ) -> Result<EnforcementReceipt, EnforcementRefusal> {
        if self.safe_mode {
            return Err(EnforcementRefusal::SafeModeEngaged);
        }
        let registered = self
            .vaccines
            .get_mut(vaccine_id_hex)
            .ok_or(EnforcementRefusal::UnknownVaccine)?;
        if registered.state != VaccineState::Shadow {
            return Err(EnforcementRefusal::NotInShadowState {
                state: registered.state,
            });
        }
        if !registered.vaccine.proof.stopped_incident {
            return Err(EnforcementRefusal::ProofDidNotStopIncident);
        }
        let observed = registered.vaccine.collateral.collateral_rate_millionths;
        if observed > self.config.max_collateral_millionths {
            return Err(EnforcementRefusal::CollateralExceedsBudget {
                observed_millionths: observed,
                max_millionths: self.config.max_collateral_millionths,
            });
        }
        if approval.vaccine_id_hex != vaccine_id_hex {
            return Err(EnforcementRefusal::ApprovalVaccineMismatch);
        }
        if approval.verify(&self.operator_key).is_err() {
            return Err(EnforcementRefusal::ApprovalSignatureInvalid);
        }
        if approval.approval_epoch < registered.vaccine.epoch {
            return Err(EnforcementRefusal::ApprovalEpochStale {
                approval_epoch: approval.approval_epoch,
                vaccine_epoch: registered.vaccine.epoch,
            });
        }

        registered.state = VaccineState::Enforced;
        let mut buf = Vec::new();
        append_str(&mut buf, vaccine_id_hex);
        append_str(&mut buf, &approval.operator_key_id);
        append_u64(&mut buf, approval.approval_epoch.as_u64());
        Ok(EnforcementReceipt {
            vaccine_id_hex: vaccine_id_hex.to_string(),
            operator_key_id: approval.operator_key_id.clone(),
            approval_epoch: approval.approval_epoch,
            receipt_hash: ContentHash::compute(&buf),
        })
    }

    /// Retire a vaccine (operator rollback path). Idempotent.
    pub fn retire(&mut self, vaccine_id_hex: &str) -> bool {
        match self.vaccines.get_mut(vaccine_id_hex) {
            Some(registered) => {
                registered.state = VaccineState::Retired;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal_replay::{RecorderConfig, RecordingMode, TraceRecorder};

    fn signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_add(1);
        SigningKey::from_bytes(bytes).expect("non-zero key")
    }

    fn loss_matrix() -> BTreeMap<String, i64> {
        let mut m = BTreeMap::new();
        m.insert("allow".to_string(), 900_000);
        m.insert("sandbox".to_string(), 50_000);
        m.insert("quarantine".to_string(), 100_000);
        m.insert("suspend".to_string(), 80_000);
        m
    }

    fn snapshot(
        index: u64,
        trace_id: &str,
        extension: &str,
        action: &str,
        outcome: i64,
    ) -> DecisionSnapshot {
        DecisionSnapshot {
            decision_index: index,
            trace_id: trace_id.to_string(),
            decision_id: format!("decision-{index}"),
            policy_id: "baseline".to_string(),
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(3),
            tick: 100 + index * 10,
            threshold_millionths: 500_000,
            loss_matrix: loss_matrix(),
            evidence_hashes: vec![ContentHash::compute(format!("ev-{index}").as_bytes())],
            chosen_action: action.to_string(),
            outcome_millionths: outcome,
            extension_id: extension.to_string(),
            nondeterminism_range: (0, 0),
        }
    }

    fn record_trace(
        trace_id: &str,
        incident_id: Option<&str>,
        decisions: &[DecisionSnapshot],
    ) -> TraceRecord {
        let mut recorder = TraceRecorder::new(RecorderConfig {
            trace_id: trace_id.to_string(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(3),
            start_tick: 100,
            signing_key: vec![7u8; 32],
        });
        if let Some(id) = incident_id {
            recorder.set_incident_id(id.to_string());
        }
        for decision in decisions {
            recorder.record_decision(decision.clone());
        }
        recorder.finalize()
    }

    /// Incident: ext-mal probes then leaks (two harmful allow decisions).
    fn incident_trace(trace_id: &str) -> TraceRecord {
        record_trace(
            trace_id,
            Some("incident-7"),
            &[
                snapshot(0, trace_id, "ext-ok", "allow", 400_000),
                snapshot(1, trace_id, "ext-mal", "allow", 200_000),
                snapshot(2, trace_id, "ext-mal", "allow", -600_000),
                snapshot(3, trace_id, "ext-mal", "allow", -800_000),
            ],
        )
    }

    /// Clean trace: benign extensions, non-negative outcomes.
    fn clean_trace(trace_id: &str, extension: &str) -> TraceRecord {
        record_trace(
            trace_id,
            None,
            &[
                snapshot(0, trace_id, extension, "allow", 300_000),
                snapshot(1, trace_id, extension, "allow", 350_000),
                snapshot(2, trace_id, extension, "sandbox", 250_000),
                snapshot(3, trace_id, extension, "allow", 400_000),
                snapshot(4, trace_id, extension, "allow", 380_000),
            ],
        )
    }

    fn factory() -> VaccineFactory {
        VaccineFactory::new(VaccineFactoryConfig::default())
    }

    // ── Motif derivation ─────────────────────────────────────────

    #[test]
    fn motif_selects_harmful_steps_and_context() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        // Harmful: indices 2 and 3; context: index 1 (same extension).
        let indices: Vec<u64> = motif
            .steps
            .iter()
            .map(|s| s.source_decision_index)
            .collect();
        assert_eq!(indices, vec![1, 2, 3]);
        assert_eq!(motif.harmful_source_indices(), vec![2, 3]);
        assert!(!motif.steps[0].harmful);
        assert!(motif.steps[1].harmful && motif.steps[2].harmful);
    }

    #[test]
    fn motif_without_context_step() {
        let config = VaccineFactoryConfig {
            include_context_step: false,
            ..VaccineFactoryConfig::default()
        };
        let motif = VaccineFactory::new(config)
            .derive_motif(&incident_trace("t1"))
            .unwrap();
        let indices: Vec<u64> = motif
            .steps
            .iter()
            .map(|s| s.source_decision_index)
            .collect();
        assert_eq!(indices, vec![2, 3]);
    }

    #[test]
    fn motif_requires_harmful_decision() {
        let trace = clean_trace("t-clean", "ext-a");
        let mut trace = trace;
        trace.incident_id = Some("incident-x".to_string());
        let err = factory().derive_motif(&trace).unwrap_err();
        assert!(matches!(err, VaccineError::NoHarmfulDecisions { .. }));
    }

    #[test]
    fn motif_requires_incident_id() {
        let trace = record_trace(
            "t-no-id",
            None,
            &[snapshot(0, "t-no-id", "ext-mal", "allow", -500_000)],
        );
        let err = factory().derive_motif(&trace).unwrap_err();
        assert_eq!(err, VaccineError::MissingIncidentId);
    }

    #[test]
    fn motif_step_cap_keeps_steps_closest_to_harm() {
        let mut decisions = Vec::new();
        for i in 0..12 {
            decisions.push(snapshot(
                i,
                "t-big",
                "ext-mal",
                "allow",
                -100_000 - i as i64,
            ));
        }
        let trace = record_trace("t-big", Some("incident-big"), &decisions);
        let motif = factory().derive_motif(&trace).unwrap();
        assert_eq!(motif.steps.len(), 8);
        assert_eq!(motif.steps.last().unwrap().source_decision_index, 11);
        assert_eq!(motif.steps.first().unwrap().source_decision_index, 4);
    }

    #[test]
    fn motif_id_is_run_independent() {
        // Same behavior recorded under different trace ids and shifted ticks
        // must produce the same motif id.
        let motif_a = factory().derive_motif(&incident_trace("t-a")).unwrap();

        let shifted: Vec<DecisionSnapshot> = incident_trace("t-b")
            .entries
            .iter()
            .map(|e| {
                let mut s = e.decision.clone();
                s.tick += 5_000; // uniform shift preserves deltas
                s.decision_id = format!("other-{}", s.decision_index);
                s
            })
            .collect();
        let trace_b = record_trace("t-b", Some("incident-7"), &shifted);
        let motif_b = factory().derive_motif(&trace_b).unwrap();

        assert_ne!(motif_a.source_trace_id, motif_b.source_trace_id);
        assert_eq!(motif_a.motif_id_hex, motif_b.motif_id_hex);
    }

    #[test]
    fn motif_id_changes_with_behavior() {
        let motif_a = factory().derive_motif(&incident_trace("t-a")).unwrap();
        let trace = record_trace(
            "t-c",
            Some("incident-7"),
            &[
                snapshot(0, "t-c", "ext-mal", "allow", 200_000),
                snapshot(1, "t-c", "ext-mal", "allow", -600_000),
            ],
        );
        let motif_c = factory().derive_motif(&trace).unwrap();
        assert_ne!(motif_a.motif_id_hex, motif_c.motif_id_hex);
    }

    // ── Intervention lenses ──────────────────────────────────────

    #[test]
    fn lens_remaps_harmful_actions_only() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        let alt = VaccineIntervention::Quarantine.to_alternate_policy(&motif);
        assert_eq!(
            alt.counterfactual_config.containment_overrides.get("allow"),
            Some(&"quarantine".to_string())
        );
        assert_eq!(alt.counterfactual_config.containment_overrides.len(), 1);
        assert!(
            alt.counterfactual_config
                .threshold_override_millionths
                .is_none()
        );
        assert!(alt.default_action.is_none());
    }

    #[test]
    fn threshold_lens_has_no_action_remap() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        let alt = VaccineIntervention::ChangeLossThreshold {
            threshold_millionths: 200_000,
        }
        .to_alternate_policy(&motif);
        assert!(alt.counterfactual_config.containment_overrides.is_empty());
        assert_eq!(
            alt.counterfactual_config.threshold_override_millionths,
            Some(200_000)
        );
    }

    #[test]
    fn forced_actions_per_kind() {
        assert_eq!(
            VaccineIntervention::RevokeCapabilityToken {
                token_id: "tok".into()
            }
            .forced_action(),
            Some("suspend")
        );
        assert_eq!(
            VaccineIntervention::AddFlowProhibition {
                source_label: "Secret".into(),
                sink_label: "Public".into()
            }
            .forced_action(),
            Some("sandbox")
        );
        assert_eq!(
            VaccineIntervention::TightenDeclassification {
                route_id: "route".into()
            }
            .forced_action(),
            Some("sandbox")
        );
        assert_eq!(
            VaccineIntervention::ChangeLossThreshold {
                threshold_millionths: 1
            }
            .forced_action(),
            None
        );
        assert_eq!(
            VaccineIntervention::ForceSandbox.forced_action(),
            Some("sandbox")
        );
        assert_eq!(
            VaccineIntervention::Quarantine.forced_action(),
            Some("quarantine")
        );
    }

    #[test]
    fn proposals_are_deterministic_and_ascending_severity() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        let proposals = factory().propose_interventions(&motif);
        assert_eq!(
            proposals,
            vec![
                VaccineIntervention::ForceSandbox,
                VaccineIntervention::Quarantine
            ]
        );
    }

    // ── Counterfactual proof ─────────────────────────────────────

    #[test]
    fn quarantine_proof_stops_incident() {
        let trace = incident_trace("t1");
        let mut factory = factory();
        let motif = factory.derive_motif(&trace).unwrap();
        let proof = factory
            .prove(&trace, &motif, &VaccineIntervention::Quarantine)
            .unwrap();
        assert!(proof.stopped_incident);
        assert_eq!(proof.harmful_steps_total, 2);
        assert_eq!(proof.harmful_steps_neutralized, 2);
        assert!(proof.net_improvement_millionths > 0);
        assert_eq!(proof.motif_id_hex, motif.motif_id_hex);
    }

    #[test]
    fn threshold_proof_honestly_reports_not_stopped() {
        let trace = incident_trace("t1");
        let mut factory = factory();
        let motif = factory.derive_motif(&trace).unwrap();
        let proof = factory
            .prove(
                &trace,
                &motif,
                &VaccineIntervention::ChangeLossThreshold {
                    threshold_millionths: 100_000,
                },
            )
            .unwrap();
        assert!(!proof.stopped_incident);
        assert_eq!(proof.harmful_steps_neutralized, 0);
    }

    #[test]
    fn proof_is_deterministic() {
        let trace = incident_trace("t1");
        let mut f1 = factory();
        let motif1 = f1.derive_motif(&trace).unwrap();
        let p1 = f1
            .prove(&trace, &motif1, &VaccineIntervention::Quarantine)
            .unwrap();
        let mut f2 = factory();
        let motif2 = f2.derive_motif(&trace).unwrap();
        let p2 = f2
            .prove(&trace, &motif2, &VaccineIntervention::Quarantine)
            .unwrap();
        assert_eq!(p1, p2);
    }

    // ── Collateral estimation ────────────────────────────────────

    #[test]
    fn collateral_zero_when_motif_never_fires_on_clean_traffic() {
        let trace = incident_trace("t1");
        let clean = vec![clean_trace("c1", "ext-a"), clean_trace("c2", "ext-b")];
        let mut factory = factory();
        let motif = factory.derive_motif(&trace).unwrap();
        let estimate = factory
            .estimate_collateral(&clean, &motif, &VaccineIntervention::Quarantine)
            .unwrap();
        // The motif requires ext-mal decisions; clean traffic has none.
        assert_eq!(estimate.motif_firings, 0);
        assert_eq!(estimate.collateral_rate_millionths, 0);
        assert_eq!(estimate.clean_decisions_evaluated, 10);
        // The blunt lens remaps every clean "allow": upper bound is nonzero.
        assert!(estimate.unscoped_divergence_rate_millionths > 0);
        assert!(estimate.affected_extensions.is_empty());
    }

    #[test]
    fn collateral_counts_motif_firings_on_matching_clean_traffic() {
        let trace = incident_trace("t1");
        // A clean trace where ext-mal repeats the same action sequence.
        let lookalike = record_trace(
            "c-lookalike",
            None,
            &[
                snapshot(0, "c-lookalike", "ext-mal", "allow", 100_000),
                snapshot(1, "c-lookalike", "ext-mal", "allow", 200_000),
                snapshot(2, "c-lookalike", "ext-mal", "allow", 150_000),
                snapshot(3, "c-lookalike", "ext-mal", "allow", 120_000),
                snapshot(4, "c-lookalike", "ext-mal", "allow", 130_000),
            ],
        );
        let mut factory = factory();
        let motif = factory.derive_motif(&trace).unwrap();
        let estimate = factory
            .estimate_collateral(
                std::slice::from_ref(&lookalike),
                &motif,
                &VaccineIntervention::Quarantine,
            )
            .unwrap();
        // Motif is 3 allow-steps by ext-mal: fires at indices 2 (steps 0,1,2)
        // then resets and needs 3 more; only 2 remain. Exactly one firing.
        assert_eq!(estimate.motif_firings, 1);
        assert_eq!(estimate.collateral_rate_millionths, MILLION / 5);
        assert!(estimate.affected_extensions.contains("ext-mal"));
    }

    #[test]
    fn collateral_requires_minimum_clean_evidence() {
        let trace = incident_trace("t1");
        let tiny = record_trace(
            "c-tiny",
            None,
            &[snapshot(0, "c-tiny", "ext-a", "allow", 100_000)],
        );
        let mut factory = factory();
        let motif = factory.derive_motif(&trace).unwrap();
        let err = factory
            .estimate_collateral(
                std::slice::from_ref(&tiny),
                &motif,
                &VaccineIntervention::Quarantine,
            )
            .unwrap_err();
        assert_eq!(
            err,
            VaccineError::InsufficientCleanEvidence {
                found: 1,
                required: 5
            }
        );
    }

    // ── Build pipeline ───────────────────────────────────────────

    #[test]
    fn build_best_picks_first_stopping_intervention() {
        let trace = incident_trace("t1");
        let clean = vec![clean_trace("c1", "ext-a")];
        let mut factory = factory();
        let key = signing_key(11);
        let candidates = [
            VaccineIntervention::ChangeLossThreshold {
                threshold_millionths: 100_000,
            },
            VaccineIntervention::ForceSandbox,
            VaccineIntervention::Quarantine,
        ];
        let outcome = factory
            .build_best(&trace, &clean, &candidates, &key, 1_000)
            .unwrap();
        assert!(outcome.is_success());
        let vaccine = outcome.vaccine.unwrap();
        assert_eq!(vaccine.intervention, VaccineIntervention::ForceSandbox);
        assert_eq!(outcome.rejected.len(), 1);
        assert!(matches!(
            outcome.rejected[0].rejection,
            CandidateRejection::DidNotStopIncident { .. }
        ));
        assert_eq!(vaccine.distribution_scope, DistributionScope::LocalOnly);
        assert_eq!(vaccine.incident_id, "incident-7");
    }

    #[test]
    fn build_best_rejects_all_when_nothing_stops() {
        let trace = incident_trace("t1");
        let clean = vec![clean_trace("c1", "ext-a")];
        let mut factory = factory();
        let key = signing_key(11);
        let candidates = [VaccineIntervention::ChangeLossThreshold {
            threshold_millionths: 100_000,
        }];
        let outcome = factory
            .build_best(&trace, &clean, &candidates, &key, 1_000)
            .unwrap();
        assert!(!outcome.is_success());
        assert_eq!(outcome.rejected.len(), 1);
    }

    #[test]
    fn build_best_rejects_over_budget_collateral() {
        let trace = incident_trace("t1");
        // Clean traffic that repeats the motif → 100% lookalike firing rate
        // far above any sane budget once decisions repeat.
        let lookalike = record_trace(
            "c-lookalike",
            None,
            &[
                snapshot(0, "c-lookalike", "ext-mal", "allow", 100_000),
                snapshot(1, "c-lookalike", "ext-mal", "allow", 200_000),
                snapshot(2, "c-lookalike", "ext-mal", "allow", 150_000),
                snapshot(3, "c-lookalike", "ext-mal", "allow", 120_000),
                snapshot(4, "c-lookalike", "ext-mal", "allow", 130_000),
                snapshot(5, "c-lookalike", "ext-mal", "allow", 140_000),
            ],
        );
        let config = VaccineFactoryConfig {
            max_collateral_millionths: 100_000, // 10%
            ..VaccineFactoryConfig::default()
        };
        let mut factory = VaccineFactory::new(config);
        let key = signing_key(11);
        let outcome = factory
            .build_best(
                &trace,
                std::slice::from_ref(&lookalike),
                &[VaccineIntervention::Quarantine],
                &key,
                1_000,
            )
            .unwrap();
        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.rejected[0].rejection,
            CandidateRejection::CollateralExceedsBudget { .. }
        ));
    }

    // ── Signing & identity ───────────────────────────────────────

    fn build_vaccine(producer: &SigningKey) -> ReplayVaccine {
        let trace = incident_trace("t1");
        let clean = vec![clean_trace("c1", "ext-a")];
        let mut factory = factory();
        factory
            .build_best(
                &trace,
                &clean,
                &[VaccineIntervention::Quarantine],
                producer,
                42_000,
            )
            .unwrap()
            .vaccine
            .unwrap()
    }

    #[test]
    fn vaccine_signature_roundtrip() {
        let producer = signing_key(21);
        let vaccine = build_vaccine(&producer);
        assert!(vaccine.verify(&producer.verification_key()).is_ok());
        assert!(vaccine.verify_id().unwrap());
        assert!(!vaccine.signature.is_sentinel());
    }

    #[test]
    fn tampered_vaccine_fails_verification() {
        let producer = signing_key(21);
        let mut vaccine = build_vaccine(&producer);
        assert_ne!(vaccine.collateral.collateral_rate_millionths, 999_999);
        vaccine.collateral.collateral_rate_millionths = 999_999;
        assert!(vaccine.verify(&producer.verification_key()).is_err());
    }

    #[test]
    fn tampered_id_fails_id_check() {
        let producer = signing_key(21);
        let mut vaccine = build_vaccine(&producer);
        vaccine.vaccine_id_hex = format!("00{}", &vaccine.vaccine_id_hex[2..]);
        assert!(!vaccine.verify_id().unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let producer = signing_key(21);
        let vaccine = build_vaccine(&producer);
        let other = signing_key(22);
        assert!(vaccine.verify(&other.verification_key()).is_err());
    }

    #[test]
    fn vaccine_commits_to_transparency_log() {
        let producer = signing_key(21);
        let vaccine = build_vaccine(&producer);
        let mut log = TransparencyLog::new("vaccine-log".to_string());
        let leaf = commit_vaccine_to_transparency_log(&vaccine, &mut log, 99).unwrap();
        assert_eq!(leaf, 0);
        assert_eq!(log.tree_length(), 1);
        assert_eq!(log.entries()[0].receipt_hash, vaccine.content_hash());
    }

    // ── Registry: shadow + enforcement ───────────────────────────

    fn registry(producer: &SigningKey, operator: &SigningKey) -> VaccineRegistry {
        VaccineRegistry::new(
            RegistryConfig::default(),
            producer.verification_key(),
            operator.verification_key(),
        )
    }

    #[test]
    fn register_shadow_verifies_signature() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        assert_eq!(
            registry.state(&vaccine.vaccine_id_hex),
            Some(VaccineState::Shadow)
        );

        // A registry trusting a different producer refuses the same vaccine.
        let mut wrong = registry_with_producer(&signing_key(22), &operator);
        assert!(wrong.register_shadow(vaccine).is_err());
    }

    fn registry_with_producer(producer: &SigningKey, operator: &SigningKey) -> VaccineRegistry {
        VaccineRegistry::new(
            RegistryConfig::default(),
            producer.verification_key(),
            operator.verification_key(),
        )
    }

    #[test]
    fn register_shadow_refuses_tampered_id() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let mut vaccine = build_vaccine(&producer);
        // Re-sign with a mismatched id: signature is valid but the id no
        // longer binds the content.
        vaccine.vaccine_id_hex = format!("00{}", &vaccine.vaccine_id_hex[2..]);
        vaccine.sign(&producer).unwrap();
        let mut registry = registry(&producer, &operator);
        let err = registry.register_shadow(vaccine).unwrap_err();
        assert!(matches!(err, VaccineError::Id(_)));
    }

    #[test]
    fn shadow_matching_fires_on_motif_completion() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();

        // Motif: ext-mal allow ×3 (context + two harmful).
        let mut events = Vec::new();
        for i in 0..3 {
            events.extend(
                registry.observe_decision(&snapshot(i, "live-1", "ext-mal", "allow", 100_000)),
            );
        }
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.vaccine_id_hex, vaccine.vaccine_id_hex);
        assert_eq!(event.state, VaccineState::Shadow);
        assert_eq!(event.would_apply_action.as_deref(), Some("quarantine"));
        assert_eq!(event.trigger_decision_index, 2);
    }

    #[test]
    fn shadow_matching_ignores_non_matching_traffic() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine).unwrap();

        let mut events = Vec::new();
        for i in 0..6 {
            events.extend(registry.observe_decision(&snapshot(
                i,
                "live-2",
                "ext-benign",
                "allow",
                100_000,
            )));
        }
        assert!(events.is_empty());
    }

    #[test]
    fn safe_mode_suppresses_matching_and_enforcement() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        registry.set_safe_mode(true);

        for i in 0..3 {
            let events =
                registry.observe_decision(&snapshot(i, "live-3", "ext-mal", "allow", 100_000));
            assert!(events.is_empty());
        }

        let approval = OperatorApproval::create(
            vaccine.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(4),
            &operator,
        )
        .unwrap();
        let err = registry
            .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
            .unwrap_err();
        assert_eq!(err, EnforcementRefusal::SafeModeEngaged);
    }

    #[test]
    fn enforcement_happy_path() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();

        let approval = OperatorApproval::create(
            vaccine.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(4),
            &operator,
        )
        .unwrap();
        let receipt = registry
            .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
            .unwrap();
        assert_eq!(receipt.vaccine_id_hex, vaccine.vaccine_id_hex);
        assert_eq!(
            registry.state(&vaccine.vaccine_id_hex),
            Some(VaccineState::Enforced)
        );

        // Second approval refuses: not in shadow state any more.
        let err = registry
            .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
            .unwrap_err();
        assert!(matches!(err, EnforcementRefusal::NotInShadowState { .. }));
    }

    #[test]
    fn enforcement_refuses_unknown_vaccine() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let mut registry = registry(&producer, &operator);
        let approval =
            OperatorApproval::create("missing".to_string(), SecurityEpoch::from_raw(4), &operator)
                .unwrap();
        assert_eq!(
            registry
                .approve_enforcement("missing", &approval)
                .unwrap_err(),
            EnforcementRefusal::UnknownVaccine
        );
    }

    #[test]
    fn enforcement_refuses_approval_mismatch() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        let approval = OperatorApproval::create(
            "some-other-vaccine".to_string(),
            SecurityEpoch::from_raw(4),
            &operator,
        )
        .unwrap();
        assert_eq!(
            registry
                .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
                .unwrap_err(),
            EnforcementRefusal::ApprovalVaccineMismatch
        );
    }

    #[test]
    fn enforcement_refuses_bad_approval_signature() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        // Signed by a key the registry does not trust as operator.
        let impostor = signing_key(99);
        let approval = OperatorApproval::create(
            vaccine.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(4),
            &impostor,
        )
        .unwrap();
        assert_eq!(
            registry
                .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
                .unwrap_err(),
            EnforcementRefusal::ApprovalSignatureInvalid
        );
    }

    #[test]
    fn enforcement_refuses_stale_approval_epoch() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        // Vaccine epoch is 3; approve from epoch 1.
        let approval = OperatorApproval::create(
            vaccine.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(1),
            &operator,
        )
        .unwrap();
        assert!(matches!(
            registry
                .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
                .unwrap_err(),
            EnforcementRefusal::ApprovalEpochStale { .. }
        ));
    }

    #[test]
    fn enforcement_refuses_unproven_or_over_budget_packages() {
        let producer = signing_key(21);
        let operator = signing_key(31);

        // Hand-build a shadow package whose proof did not stop the incident.
        let mut vaccine = build_vaccine(&producer);
        vaccine.proof.stopped_incident = false;
        vaccine.vaccine_id_hex = vaccine.derive_vaccine_id().unwrap().to_hex();
        vaccine.sign(&producer).unwrap();
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        let approval = OperatorApproval::create(
            vaccine.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(4),
            &operator,
        )
        .unwrap();
        assert_eq!(
            registry
                .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
                .unwrap_err(),
            EnforcementRefusal::ProofDidNotStopIncident
        );

        // And one whose packaged collateral exceeds the registry budget.
        let mut over = build_vaccine(&producer);
        over.collateral.collateral_rate_millionths = 900_000;
        over.vaccine_id_hex = over.derive_vaccine_id().unwrap().to_hex();
        over.sign(&producer).unwrap();
        registry.register_shadow(over.clone()).unwrap();
        let approval = OperatorApproval::create(
            over.vaccine_id_hex.clone(),
            SecurityEpoch::from_raw(4),
            &operator,
        )
        .unwrap();
        assert!(matches!(
            registry
                .approve_enforcement(&over.vaccine_id_hex, &approval)
                .unwrap_err(),
            EnforcementRefusal::CollateralExceedsBudget { .. }
        ));
    }

    #[test]
    fn retire_is_idempotent_and_stops_matching() {
        let producer = signing_key(21);
        let operator = signing_key(31);
        let vaccine = build_vaccine(&producer);
        let mut registry = registry(&producer, &operator);
        registry.register_shadow(vaccine.clone()).unwrap();
        assert!(registry.retire(&vaccine.vaccine_id_hex));
        assert!(registry.retire(&vaccine.vaccine_id_hex));
        assert!(!registry.retire("missing"));
        assert_eq!(
            registry.state(&vaccine.vaccine_id_hex),
            Some(VaccineState::Retired)
        );

        for i in 0..3 {
            let events =
                registry.observe_decision(&snapshot(i, "live-4", "ext-mal", "allow", 100_000));
            assert!(events.is_empty());
        }
    }

    // ── Matcher unit behavior ────────────────────────────────────

    #[test]
    fn matcher_is_subsequence_not_contiguous() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        let mut matcher = MotifMatcher::new();
        // Interleave non-matching decisions; the motif still completes.
        let stream = [
            snapshot(0, "s", "ext-mal", "allow", 1),
            snapshot(1, "s", "ext-other", "sandbox", 1),
            snapshot(2, "s", "ext-mal", "allow", 1),
            snapshot(3, "s", "ext-other", "allow", 1),
            snapshot(4, "s", "ext-mal", "allow", 1),
        ];
        let mut fired = 0;
        for s in &stream {
            if matcher.observe(&motif, s) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1);
        assert_eq!(matcher.progress(), 0);
    }

    #[test]
    fn matcher_resets_after_firing() {
        let motif = factory().derive_motif(&incident_trace("t1")).unwrap();
        let mut matcher = MotifMatcher::new();
        let mut fired = 0;
        for i in 0..6 {
            if matcher.observe(&motif, &snapshot(i, "s", "ext-mal", "allow", 1)) {
                fired += 1;
            }
        }
        assert_eq!(fired, 2);
    }

    // ── Misc surfaces ────────────────────────────────────────────

    #[test]
    fn display_impls_are_stable() {
        assert_eq!(VaccineIntervention::Quarantine.to_string(), "quarantine");
        assert_eq!(
            VaccineIntervention::ForceSandbox.to_string(),
            "force-sandbox"
        );
        let refusal = EnforcementRefusal::SafeModeEngaged;
        assert_eq!(refusal.to_string(), "safe-mode kill switch engaged");
        let rejection = CandidateRejection::DidNotStopIncident {
            neutralized: 1,
            total: 2,
        };
        assert_eq!(
            rejection.to_string(),
            "did not stop incident (1/2 neutralized)"
        );
    }

    #[test]
    fn vaccine_serde_roundtrip() {
        let producer = signing_key(21);
        let vaccine = build_vaccine(&producer);
        let json = serde_json::to_string(&vaccine).unwrap();
        let back: ReplayVaccine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vaccine);
        assert!(back.verify(&producer.verification_key()).is_ok());
    }

    #[test]
    fn content_hash_binds_signature() {
        let producer = signing_key(21);
        let vaccine = build_vaccine(&producer);
        let mut copy = vaccine.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        assert_ne!(vaccine.content_hash(), copy.content_hash());
    }
}
