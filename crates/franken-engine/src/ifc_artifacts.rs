//! Information Flow Control (IFC) artifact schemas.
//!
//! Defines the data structures for machine-verifiable information flow
//! control: `FlowPolicy`, `FlowProof`, `DeclassificationReceipt`, and
//! `ConfinementClaim`. Together these artifacts enable deterministic
//! exfiltration resistance with auditable provenance.
//!
//! ## Lattice-Based Model
//!
//! Labels form a lattice: every pair of labels has a unique join (least
//! upper bound) and meet (greatest lower bound). Information may flow
//! from source label `L_s` to sink clearance `L_k` only if `L_s <= L_k`
//! in the lattice ordering, or if an approved declassification route
//! exists.
//!
//! ## Artifact Lifecycle
//!
//! 1. **FlowPolicy** — administrator defines allowed/prohibited flows.
//! 2. **FlowProof** — analyzer proves a specific flow is legal.
//! 3. **DeclassificationReceipt** — signed record of cross-label flow.
//! 4. **ConfinementClaim** — aggregate assertion: all flows are confined.
//!
//! Plan reference: Section 10.15 item 9I.7, bd-1ovk.
//! Dependencies: 10.2 (IR2 flow labels), 10.5 (decision contracts),
//!               10.10 (deterministic serialization).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

/// Schema version for IFC artifacts (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IfcSchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl IfcSchemaVersion {
    /// Current schema version.
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Create a new schema version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Check backward compatibility: same major version, higher or equal minor.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for IfcSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Label / Clearance types
// ---------------------------------------------------------------------------

/// A sensitivity label in the IFC lattice.
///
/// Labels are ordered: `Public < Internal < Confidential < Secret < TopSecret`.
/// Custom labels use the `Custom` variant with explicit level for ordering.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Label {
    /// Public data — lowest sensitivity.
    Public,
    /// Internal data — limited to authorized components.
    Internal,
    /// Confidential data — restricted access.
    Confidential,
    /// Secret data — credentials, API keys, auth tokens.
    Secret,
    /// TopSecret data — key material, signing keys, policy secrets.
    TopSecret,
    /// Custom label with explicit lattice level (0 = lowest).
    Custom { name: String, level: u32 },
}

// Manual Ord implementation based on level() to ensure security-correct
// ordering. The derived Ord would order by discriminant, placing Custom
// (discriminant 5) above TopSecret regardless of its level, which breaks
// IFC invariants when Custom labels have level < 5.
impl Ord for Label {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.level().cmp(&other.level()).then_with(|| {
            // Tiebreak for same-level labels: named variants before Custom,
            // and Custom labels ordered by name for BTreeMap determinism.
            match (self, other) {
                (Self::Custom { name: a, .. }, Self::Custom { name: b, .. }) => a.cmp(b),
                (Self::Custom { .. }, _) => std::cmp::Ordering::Greater,
                (_, Self::Custom { .. }) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Equal,
            }
        })
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Label {
    /// Lattice level for ordering.
    pub fn level(&self) -> u32 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Secret => 3,
            Self::TopSecret => 4,
            Self::Custom { level, .. } => *level,
        }
    }

    /// Join (least upper bound) of two labels.
    pub fn join(&self, other: &Self) -> Self {
        if self.level() >= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Meet (greatest lower bound) of two labels.
    pub fn meet(&self, other: &Self) -> Self {
        if self.level() <= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Whether this label can flow to the given clearance (label <= clearance).
    pub fn can_flow_to(&self, clearance: &Label) -> bool {
        self.level() <= clearance.level()
    }

    /// Join (least upper bound) of an iterator of labels.
    ///
    /// Returns `None` if the iterator is empty.
    pub fn join_all(labels: impl IntoIterator<Item = Label>) -> Option<Label> {
        labels.into_iter().reduce(|acc, l| acc.join(&l))
    }

    /// Meet (greatest lower bound) of an iterator of labels.
    ///
    /// Returns `None` if the iterator is empty.
    pub fn meet_all(labels: impl IntoIterator<Item = Label>) -> Option<Label> {
        labels.into_iter().reduce(|acc, l| acc.meet(&l))
    }

    /// All built-in labels in ascending order.
    pub fn all_builtin() -> [Label; 5] {
        [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
            Label::TopSecret,
        ]
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Internal => write!(f, "internal"),
            Self::Confidential => write!(f, "confidential"),
            Self::Secret => write!(f, "secret"),
            Self::TopSecret => write!(f, "top_secret"),
            Self::Custom { name, level } => write!(f, "custom({name}, level={level})"),
        }
    }
}

// ---------------------------------------------------------------------------
// ClearanceClass — sink permission levels
// ---------------------------------------------------------------------------

/// Clearance classification for data sinks.
///
/// Ordered by restrictiveness: `OpenSink < RestrictedSink < AuditedSink < SealedSink < NeverSink`.
/// Higher clearance classes are *more restrictive* about what data they accept.
///
/// - `OpenSink` can receive data up to `TopSecret` (with redaction applied).
/// - `RestrictedSink` can receive data up to `Internal`.
/// - `AuditedSink` can receive data up to `Confidential` with audit trail.
/// - `SealedSink` can receive data up to `Secret` with explicit declassification.
/// - `NeverSink` can receive only `Public`; anything more sensitive requires declassification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClearanceClass {
    /// Can receive any data (e.g., stdout logging with redaction).
    OpenSink,
    /// Can receive up to Internal (e.g., metrics export).
    RestrictedSink,
    /// Can receive up to Confidential with audit trail (e.g., authorized API calls).
    AuditedSink,
    /// Can receive up to Secret with explicit declassification (e.g., key derivation output).
    SealedSink,
    /// Can receive only `Public` (e.g., raw network egress after declassification to public).
    NeverSink,
}

impl ClearanceClass {
    /// Ordinal level for this clearance (0 = least restrictive).
    pub fn level(&self) -> u32 {
        match self {
            Self::OpenSink => 0,
            Self::RestrictedSink => 1,
            Self::AuditedSink => 2,
            Self::SealedSink => 3,
            Self::NeverSink => 4,
        }
    }

    /// Maximum label level this clearance can receive without declassification.
    pub fn max_receivable_label_level(&self) -> Option<u32> {
        match self {
            Self::OpenSink => Some(4),       // up to TopSecret
            Self::RestrictedSink => Some(1), // up to Internal
            Self::AuditedSink => Some(2),    // up to Confidential
            Self::SealedSink => Some(3),     // up to Secret
            Self::NeverSink => Some(0),      // only Public without declassification
        }
    }

    /// Whether this clearance class can receive data with the given label.
    pub fn can_receive(&self, label: &Label) -> bool {
        match self.max_receivable_label_level() {
            Some(max_level) => label.level() <= max_level,
            None => false,
        }
    }

    /// All clearance classes in ascending order (least to most restrictive).
    pub fn all() -> [ClearanceClass; 5] {
        [
            ClearanceClass::OpenSink,
            ClearanceClass::RestrictedSink,
            ClearanceClass::AuditedSink,
            ClearanceClass::SealedSink,
            ClearanceClass::NeverSink,
        ]
    }

    /// Stable string identifier for serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenSink => "open_sink",
            Self::RestrictedSink => "restricted_sink",
            Self::AuditedSink => "audited_sink",
            Self::SealedSink => "sealed_sink",
            Self::NeverSink => "never_sink",
        }
    }
}

impl fmt::Display for ClearanceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DeclassificationObligation — structured cross-label flow authorization
// ---------------------------------------------------------------------------

/// A structured obligation that must be fulfilled for a cross-label data flow
/// to be authorized via declassification.
///
/// Unlike `DeclassificationRoute` (which defines *possible* routes), an obligation
/// represents the concrete requirements that must be satisfied before data at
/// `source_label` can flow to a sink with `target_clearance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationObligation {
    /// Unique obligation identifier.
    pub obligation_id: String,
    /// Source label of the data requiring declassification.
    pub source_label: Label,
    /// Target clearance class the data must be declassified to.
    pub target_clearance: ClearanceClass,
    /// Conditions that must be met (e.g., "audit_approval", "ciso_sign_off").
    pub required_conditions: Vec<String>,
    /// Maximum acceptable expected loss (millionths, 1_000_000 = 1.0).
    pub max_loss_milli: u64,
    /// Whether an audit trail entry is required for this declassification.
    pub audit_trail_required: bool,
    /// Identifier of the authority that must approve this declassification.
    pub approval_authority: String,
    /// Epoch after which this obligation expires (None = no expiry).
    pub expiry_epoch: Option<u64>,
}

impl DeclassificationObligation {
    /// Check whether all required conditions are satisfied by the given condition set.
    pub fn conditions_satisfied(&self, satisfied: &BTreeSet<String>) -> bool {
        self.required_conditions
            .iter()
            .all(|c| satisfied.contains(c))
    }

    /// Whether this obligation has expired at the given epoch.
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        self.expiry_epoch
            .is_some_and(|expiry| current_epoch > expiry)
    }
}

// ---------------------------------------------------------------------------
// IR2 Label Assignment — rules for assigning labels to IR2 nodes
// ---------------------------------------------------------------------------

/// Source classification for IR2 label assignment.
///
/// Each IR2 node's data label is determined by its source:
/// - Literal values → `Public`
/// - Environment variable reads → `Secret`
/// - Credential path reads → `Secret` or `TopSecret` based on policy
/// - Hostcall return values → label from hostcall clearance declaration
/// - Computed values → `join` of all input labels (taint propagation)
/// - Declassified values → label explicitly lowered by declassification receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ir2LabelSource {
    /// Literal value (string, number, boolean) — always `Public`.
    Literal,
    /// Environment variable read — defaults to `Secret`.
    EnvironmentVariable,
    /// File read from a credential path — `Secret` or `TopSecret`.
    CredentialPath {
        /// Whether this path contains key material (TopSecret) vs credentials (Secret).
        is_key_material: bool,
    },
    /// Return value from a hostcall — labeled by the hostcall's clearance.
    HostcallReturn {
        /// The label assigned by the hostcall's clearance declaration.
        clearance_label: Label,
    },
    /// Computed value — taint-propagated from inputs.
    Computed {
        /// Labels of all inputs to this computation.
        input_labels: Vec<Label>,
    },
    /// Value whose label was explicitly lowered by a declassification receipt.
    Declassified {
        /// Reference to the authorizing declassification receipt.
        receipt_ref: String,
        /// The effective label after declassification.
        effective_label: Label,
    },
}

impl Ir2LabelSource {
    /// Assign a label based on this source classification.
    pub fn assign_label(&self) -> Label {
        match self {
            Self::Literal => Label::Public,
            Self::EnvironmentVariable => Label::Secret,
            Self::CredentialPath { is_key_material } => {
                if *is_key_material {
                    Label::TopSecret
                } else {
                    Label::Secret
                }
            }
            Self::HostcallReturn { clearance_label } => clearance_label.clone(),
            Self::Computed { input_labels } => {
                Label::join_all(input_labels.iter().cloned()).unwrap_or(Label::Public)
            }
            Self::Declassified {
                effective_label, ..
            } => effective_label.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// FlowEnvelope — PLAS integration for flow constraints
// ---------------------------------------------------------------------------

/// Flow envelope synthesized by PLAS, specifying the IFC constraints for an
/// extension.
///
/// Extends capability envelopes (Section 9I.5) with flow-specific constraints:
/// which labels the extension may produce, which clearance levels it may access,
/// and which declassification paths are authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEnvelope {
    /// Content-addressable envelope identifier.
    pub envelope_id: String,
    /// Extension this envelope applies to.
    pub extension_id: String,
    /// Labels the extension is authorized to produce (data sources).
    pub producible_labels: BTreeSet<Label>,
    /// Clearance classes the extension may access (data sinks).
    pub accessible_clearances: BTreeSet<ClearanceClass>,
    /// Obligation IDs for authorized declassification paths.
    pub authorized_declassifications: Vec<String>,
    /// Reference to the governing flow policy.
    pub policy_ref: String,
    /// Security epoch this envelope is valid for.
    pub epoch_id: u64,
    /// Schema version.
    pub schema_version: IfcSchemaVersion,
}

/// Advisory surfaced when a flow is in scope but still lacks the explicit
/// authorization material needed to produce a concrete declassification
/// obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowAuthorizationAdvisory {
    /// Secret data can only reach `SealedSink` when the envelope carries an
    /// explicit authorization reference.
    ExplicitAuthorizationRequired {
        source_label: Label,
        sink_clearance: ClearanceClass,
    },
    /// The flow would require a concrete declassification obligation before it
    /// can be enforced safely.
    DeclassificationObligationRequired {
        source_label: Label,
        sink_clearance: ClearanceClass,
    },
}

/// Structured flow review result that exposes both the legacy predicate and
/// the effective fail-closed authorization outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowAuthorizationAssessment {
    /// Result from the legacy envelope-membership and clearance predicate.
    pub envelope_authorized: bool,
    /// Whether the flow may proceed immediately without additional
    /// declassification handling.
    pub flow_authorized: bool,
    /// Concrete declassification obligation for flows that are in scope but
    /// still require explicit authorization before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declassification_obligation: Option<DeclassificationObligation>,
    /// Additional review items callers should treat as blocking until the
    /// richer enforcement path is satisfied.
    pub advisories: Vec<FlowAuthorizationAdvisory>,
}

impl FlowAuthorizationAssessment {
    /// Whether the flow needs follow-up review before it is safe to honor.
    pub fn has_advisories(&self) -> bool {
        !self.advisories.is_empty()
    }

    /// Whether the flow requires an explicit declassification step.
    pub fn requires_declassification(&self) -> bool {
        self.declassification_obligation.is_some()
    }
}

impl FlowEnvelope {
    /// Check whether this envelope authorizes a flow from `source` to
    /// `sink_clearance`.
    ///
    /// This now reflects immediate authorization only. Flows that still
    /// require declassification return `false`; call
    /// `assess_flow_authorization` to obtain the concrete obligation.
    pub fn is_flow_authorized(&self, source: &Label, sink_clearance: &ClearanceClass) -> bool {
        self.assess_flow_authorization(source, sink_clearance)
            .flow_authorized
    }

    fn materialize_declassification_obligation(
        &self,
        source: &Label,
        sink_clearance: &ClearanceClass,
    ) -> Option<DeclassificationObligation> {
        let obligation_id = self
            .authorized_declassifications
            .iter()
            .find(|id| !id.trim().is_empty())?
            .clone();

        Some(DeclassificationObligation {
            obligation_id,
            source_label: source.clone(),
            target_clearance: *sink_clearance,
            required_conditions: vec![
                format!("extension_id={}", self.extension_id),
                format!("source_label={source}"),
                format!("sink_clearance={sink_clearance}"),
            ],
            max_loss_milli: 0,
            audit_trail_required: true,
            approval_authority: self.policy_ref.clone(),
            expiry_epoch: Some(self.epoch_id),
        })
    }

    /// Assess a flow against the legacy envelope predicate plus the currently
    /// enforced SealedSink authorization rules.
    pub fn assess_flow_authorization(
        &self,
        source: &Label,
        sink_clearance: &ClearanceClass,
    ) -> FlowAuthorizationAssessment {
        let flow_in_scope = self.producible_labels.contains(source)
            && self.accessible_clearances.contains(sink_clearance);
        let envelope_authorized = flow_in_scope && sink_clearance.can_receive(source);
        let mut advisories = Vec::new();
        let mut declassification_obligation = None;

        if flow_in_scope
            && *sink_clearance == ClearanceClass::SealedSink
            && matches!(source, Label::Secret | Label::TopSecret)
        {
            declassification_obligation =
                self.materialize_declassification_obligation(source, sink_clearance);

            if declassification_obligation.is_none() {
                let advisory = match source {
                    Label::Secret => FlowAuthorizationAdvisory::ExplicitAuthorizationRequired {
                        source_label: source.clone(),
                        sink_clearance: *sink_clearance,
                    },
                    _ => FlowAuthorizationAdvisory::DeclassificationObligationRequired {
                        source_label: source.clone(),
                        sink_clearance: *sink_clearance,
                    },
                };
                advisories.push(advisory);
            }
        }

        let flow_authorized =
            advisories.is_empty() && declassification_obligation.is_none() && envelope_authorized;

        FlowAuthorizationAssessment {
            envelope_authorized,
            flow_authorized,
            declassification_obligation,
            advisories,
        }
    }

    /// Content-addressable identity.
    pub fn content_hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).expect("FlowEnvelope must serialize for content hash");
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// FlowRule — allowed/prohibited flow specification
// ---------------------------------------------------------------------------

/// A rule specifying an allowed or prohibited information flow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowRule {
    /// Source sensitivity label.
    pub source_label: Label,
    /// Sink clearance label.
    pub sink_clearance: Label,
}

/// An approved declassification route for cross-label flows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclassificationRoute {
    /// Unique route identifier.
    pub route_id: String,
    /// Source label being declassified from.
    pub source_label: Label,
    /// Target clearance being declassified to.
    pub target_clearance: Label,
    /// Conditions for this declassification (human-readable).
    pub conditions: Vec<String>,
}

// ---------------------------------------------------------------------------
// FlowPolicy — defines allowed information flows
// ---------------------------------------------------------------------------

/// An IFC policy defining allowed information flows for an extension/component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowPolicy {
    /// Content-addressable policy identifier.
    pub policy_id: String,
    /// Extension or component this policy applies to.
    pub extension_id: String,
    /// Source sensitivity label classes.
    pub label_classes: BTreeSet<Label>,
    /// Sink authorization clearance classes.
    pub clearance_classes: BTreeSet<Label>,
    /// Allowed flows (lattice-legal by default if source <= sink).
    pub allowed_flows: Vec<FlowRule>,
    /// Explicitly prohibited flows (override lattice legality).
    pub prohibited_flows: Vec<FlowRule>,
    /// Approved cross-label declassification routes.
    pub declassification_routes: Vec<DeclassificationRoute>,
    /// Security epoch this policy is valid for.
    pub epoch_id: u64,
    /// Schema version.
    pub schema_version: IfcSchemaVersion,
    /// Signature over canonical encoding.
    pub signature: Signature,
}

impl FlowPolicy {
    /// Compute content-addressable identity from canonical bytes.
    pub fn content_hash(&self) -> ContentHash {
        let bytes = self.preimage_bytes();
        ContentHash::compute(&bytes)
    }

    /// Check whether a flow from source to sink is allowed under this policy.
    pub fn is_flow_allowed(&self, source: &Label, sink: &Label) -> FlowCheckResult {
        // Check explicit prohibitions first
        for rule in &self.prohibited_flows {
            if rule.source_label == *source && rule.sink_clearance == *sink {
                return FlowCheckResult::Prohibited;
            }
        }

        // Check explicit allowed flows
        for rule in &self.allowed_flows {
            if rule.source_label == *source && rule.sink_clearance == *sink {
                return FlowCheckResult::Allowed;
            }
        }

        // Check lattice legality
        if source.can_flow_to(sink) {
            return FlowCheckResult::LatticeAllowed;
        }

        // Check declassification routes
        for route in &self.declassification_routes {
            if route.source_label == *source && route.target_clearance == *sink {
                return FlowCheckResult::DeclassificationRequired {
                    route_id: route.route_id.clone(),
                };
            }
        }

        FlowCheckResult::Denied
    }

    /// Sign this policy with the given key.
    pub fn sign(
        &mut self,
        key: &SigningKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the signature on this policy.
    pub fn verify(
        &self,
        key: &VerificationKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        let preimage = self.preimage_bytes();
        verify_signature(key, &preimage, &self.signature)
    }
}

fn flow_policy_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"ifc_flow_policy_v1"));
    &HASH
}

impl SignaturePreimage for FlowPolicy {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        flow_policy_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).unwrap_or_default())
    }
}

/// Result of checking a flow against a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowCheckResult {
    /// Explicitly allowed by policy rule.
    Allowed,
    /// Allowed by lattice ordering (source <= sink).
    LatticeAllowed,
    /// Requires declassification via the specified route.
    DeclassificationRequired { route_id: String },
    /// Explicitly prohibited by policy rule.
    Prohibited,
    /// Denied (no matching rule, not lattice-legal, no declassification route).
    Denied,
}

// ---------------------------------------------------------------------------
// ProofMethod — how a flow was proven legal
// ---------------------------------------------------------------------------

/// Method by which a flow was proven legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProofMethod {
    /// Proven by static analysis of IR.
    StaticAnalysis,
    /// Verified by runtime check.
    RuntimeCheck,
    /// Authorized via declassification route.
    Declassification,
}

impl fmt::Display for ProofMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticAnalysis => write!(f, "static_analysis"),
            Self::RuntimeCheck => write!(f, "runtime_check"),
            Self::Declassification => write!(f, "declassification"),
        }
    }
}

// ---------------------------------------------------------------------------
// FlowProof — proves a specific flow is legal
// ---------------------------------------------------------------------------

/// Evidence artifact proving a specific information flow is legal under the
/// active policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowProof {
    /// Content-addressable proof identifier.
    pub proof_id: String,
    /// Source label of the flow.
    pub flow_source_label: Label,
    /// Source location (module/function/IR node).
    pub flow_source_location: String,
    /// Sink clearance of the flow.
    pub flow_sink_clearance: Label,
    /// Sink location (module/function/IR node).
    pub flow_sink_location: String,
    /// Reference to the governing policy.
    pub policy_ref: String,
    /// How the flow was proven legal.
    pub proof_method: ProofMethod,
    /// Evidence references (IR nodes, execution trace refs).
    pub proof_evidence: Vec<String>,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
    /// Schema version.
    pub schema_version: IfcSchemaVersion,
    /// Signature over canonical encoding.
    pub signature: Signature,
}

impl FlowProof {
    /// Compute content-addressable identity.
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.preimage_bytes())
    }

    /// Sign this proof.
    pub fn sign(
        &mut self,
        key: &SigningKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the signature.
    pub fn verify(
        &self,
        key: &VerificationKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        verify_signature(key, &self.preimage_bytes(), &self.signature)
    }
}

fn flow_proof_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"ifc_flow_proof_v1"));
    &HASH
}

impl SignaturePreimage for FlowProof {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        flow_proof_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// DeclassificationReceipt — signed record of cross-label flow
// ---------------------------------------------------------------------------

/// Decision for a declassification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DeclassificationDecision {
    /// Declassification allowed.
    Allow,
    /// Declassification denied.
    Deny,
}

impl fmt::Display for DeclassificationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Signed record of an approved (or denied) cross-label data flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    /// Content-addressable receipt identifier.
    pub receipt_id: String,
    /// Source label being declassified from.
    pub source_label: Label,
    /// Sink clearance being declassified to.
    pub sink_clearance: Label,
    /// Reference to the declassification route in the governing policy.
    pub declassification_route_ref: String,
    /// Decision contract that authorized this declassification.
    pub decision_contract_id: String,
    /// Summary of the policy evaluation.
    pub policy_evaluation_summary: String,
    /// Loss assessment (expected loss in millionths, 1_000_000 = 1.0).
    pub loss_assessment_milli: u64,
    /// Decision: allow or deny.
    pub decision: DeclassificationDecision,
    /// Verification key of the authorizer.
    pub authorized_by: VerificationKey,
    /// Replay linkage (trace_id or decision_id reference).
    pub replay_linkage: String,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
    /// Schema version.
    pub schema_version: IfcSchemaVersion,
    /// Signature (decision-contract-level signing).
    pub signature: Signature,
}

impl DeclassificationReceipt {
    /// Compute content-addressable identity.
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.preimage_bytes())
    }

    /// Validate receipt linkage fields required for deterministic replay and
    /// decision-contract provenance.
    pub fn validate(&self) -> Result<(), IfcValidationError> {
        let artifact_id = trimmed_artifact_id(&self.receipt_id, "<empty-receipt-id>");

        validate_required_field(
            "declassification_receipt",
            artifact_id,
            "receipt_id",
            &self.receipt_id,
        )?;
        validate_required_field(
            "declassification_receipt",
            artifact_id,
            "declassification_route_ref",
            &self.declassification_route_ref,
        )?;
        validate_required_field(
            "declassification_receipt",
            artifact_id,
            "decision_contract_id",
            &self.decision_contract_id,
        )?;
        validate_required_field(
            "declassification_receipt",
            artifact_id,
            "policy_evaluation_summary",
            &self.policy_evaluation_summary,
        )?;
        validate_required_field(
            "declassification_receipt",
            artifact_id,
            "replay_linkage",
            &self.replay_linkage,
        )?;
        Ok(())
    }

    /// Sign this receipt.
    pub fn sign(
        &mut self,
        key: &SigningKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.validate().map_err(signature_error_from_validation)?;
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the signature.
    pub fn verify(
        &self,
        key: &VerificationKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.validate().map_err(signature_error_from_validation)?;
        verify_signature(key, &self.preimage_bytes(), &self.signature)
    }

    /// Deterministic operator command for receipt-linked triage on the shipped
    /// CLI surface.
    ///
    /// `frankenctl verify receipt` currently verifies optimizer `OptReceipt`
    /// payloads, not IFC `DeclassificationReceipt` records, so IFC receipts
    /// must anchor operators on the shipped trace replay surface instead.
    pub fn replay_command(&self) -> String {
        "frankenctl replay run --trace <trace.json> --mode strict".to_string()
    }
}

fn trimmed_artifact_id<'a>(artifact_id: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn validate_required_field(
    artifact_kind: &str,
    artifact_id: &str,
    field_name: &str,
    value: &str,
) -> Result<(), IfcValidationError> {
    if value.trim().is_empty() {
        return Err(IfcValidationError::EmptyRequiredField {
            artifact_kind: artifact_kind.to_string(),
            artifact_id: artifact_id.to_string(),
            field_name: field_name.to_string(),
        });
    }
    Ok(())
}

fn signature_error_from_validation(
    error: IfcValidationError,
) -> crate::signature_preimage::SignatureError {
    crate::signature_preimage::SignatureError::NonCanonicalObject {
        detail: error.to_string(),
    }
}

fn declassification_receipt_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"ifc_declassification_receipt_v2"));
    &HASH
}

impl SignaturePreimage for DeclassificationReceipt {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        declassification_receipt_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// ConfinementClaim — aggregate assertion of full flow confinement
// ---------------------------------------------------------------------------

/// Strength of a confinement claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClaimStrength {
    /// All flows are proven confined.
    Full,
    /// Some flows are proven, but uncovered flows remain.
    Partial,
}

impl fmt::Display for ClaimStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Partial => write!(f, "partial"),
        }
    }
}

/// Aggregate assertion that a component's data flows are fully confined
/// within its authorized flow policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementClaim {
    /// Content-addressable claim identifier.
    pub claim_id: String,
    /// Component this claim applies to.
    pub component_id: String,
    /// Reference to the governing flow policy.
    pub policy_ref: String,
    /// Flow proof IDs covering all known flows.
    pub flow_proofs: Vec<String>,
    /// Any flows not yet covered by proofs.
    pub uncovered_flows: Vec<FlowRule>,
    /// Strength of the claim.
    pub claim_strength: ClaimStrength,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
    /// Schema version.
    pub schema_version: IfcSchemaVersion,
    /// Signature over canonical encoding.
    pub signature: Signature,
}

impl ConfinementClaim {
    /// Compute content-addressable identity.
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.preimage_bytes())
    }

    /// Whether this is a full confinement claim (no uncovered flows).
    pub fn is_full(&self) -> bool {
        self.claim_strength == ClaimStrength::Full && self.uncovered_flows.is_empty()
    }

    /// Validate claim consistency: full claims must have no uncovered flows.
    pub fn validate(&self) -> Result<(), IfcValidationError> {
        if self.claim_strength == ClaimStrength::Full && !self.uncovered_flows.is_empty() {
            return Err(IfcValidationError::FullClaimHasUncoveredFlows {
                claim_id: self.claim_id.clone(),
                uncovered_count: self.uncovered_flows.len(),
            });
        }
        if self.flow_proofs.is_empty() && self.uncovered_flows.is_empty() {
            return Err(IfcValidationError::EmptyClaim {
                claim_id: self.claim_id.clone(),
            });
        }
        Ok(())
    }

    /// Sign this claim.
    pub fn sign(
        &mut self,
        key: &SigningKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the signature.
    pub fn verify(
        &self,
        key: &VerificationKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        verify_signature(key, &self.preimage_bytes(), &self.signature)
    }
}

fn confinement_claim_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"ifc_confinement_claim_v1"));
    &HASH
}

impl SignaturePreimage for ConfinementClaim {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        confinement_claim_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// Validation errors for IFC artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcValidationError {
    /// A full confinement claim has uncovered flows.
    FullClaimHasUncoveredFlows {
        claim_id: String,
        uncovered_count: usize,
    },
    /// A confinement claim has no proofs and no uncovered flows.
    EmptyClaim { claim_id: String },
    /// Schema version incompatibility.
    IncompatibleSchema {
        expected: IfcSchemaVersion,
        actual: IfcSchemaVersion,
    },
    /// A required artifact field is empty after trimming.
    EmptyRequiredField {
        artifact_kind: String,
        artifact_id: String,
        field_name: String,
    },
    /// Flow is prohibited by policy.
    FlowProhibited { source: Label, sink: Label },
}

impl fmt::Display for IfcValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullClaimHasUncoveredFlows {
                claim_id,
                uncovered_count,
            } => {
                write!(
                    f,
                    "full confinement claim {claim_id} has {uncovered_count} uncovered flows"
                )
            }
            Self::EmptyClaim { claim_id } => {
                write!(f, "confinement claim {claim_id} is empty")
            }
            Self::IncompatibleSchema { expected, actual } => {
                write!(
                    f,
                    "schema version {actual} incompatible with expected {expected}"
                )
            }
            Self::EmptyRequiredField {
                artifact_kind,
                artifact_id,
                field_name,
            } => {
                write!(
                    f,
                    "{artifact_kind} {artifact_id} has empty required field {field_name}"
                )
            }
            Self::FlowProhibited { source, sink } => {
                write!(f, "flow from {source} to {sink} is prohibited")
            }
        }
    }
}

impl std::error::Error for IfcValidationError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SignatureError;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn sentinel_sig() -> Signature {
        Signature::from_bytes(SIGNATURE_SENTINEL)
    }

    fn make_flow_policy() -> FlowPolicy {
        FlowPolicy {
            policy_id: "pol-001".to_string(),
            extension_id: "ext-abc".to_string(),
            label_classes: [Label::Public, Label::Internal, Label::Confidential]
                .into_iter()
                .collect(),
            clearance_classes: [Label::Public, Label::Internal, Label::Confidential]
                .into_iter()
                .collect(),
            allowed_flows: vec![FlowRule {
                source_label: Label::Internal,
                sink_clearance: Label::Confidential,
            }],
            prohibited_flows: vec![FlowRule {
                source_label: Label::Confidential,
                sink_clearance: Label::Public,
            }],
            declassification_routes: vec![DeclassificationRoute {
                route_id: "declass-1".to_string(),
                source_label: Label::Secret,
                target_clearance: Label::Internal,
                conditions: vec!["audit_approval".to_string()],
            }],
            epoch_id: 1,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        }
    }

    fn make_flow_proof() -> FlowProof {
        FlowProof {
            proof_id: "proof-001".to_string(),
            flow_source_label: Label::Public,
            flow_source_location: "module::read_data".to_string(),
            flow_sink_clearance: Label::Internal,
            flow_sink_location: "module::write_output".to_string(),
            policy_ref: "pol-001".to_string(),
            proof_method: ProofMethod::StaticAnalysis,
            proof_evidence: vec!["ir_node_42".to_string(), "ir_node_43".to_string()],
            timestamp_ms: 1_700_000_000_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        }
    }

    fn make_receipt() -> DeclassificationReceipt {
        DeclassificationReceipt {
            receipt_id: "receipt-001".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::Internal,
            declassification_route_ref: "declass-1".to_string(),
            decision_contract_id: "decision-contract-1".to_string(),
            policy_evaluation_summary: "approved by security team".to_string(),
            loss_assessment_milli: 5000,
            decision: DeclassificationDecision::Allow,
            authorized_by: test_key().verification_key(),
            replay_linkage: "trace-abc".to_string(),
            timestamp_ms: 1_700_000_000_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        }
    }

    fn make_claim(strength: ClaimStrength) -> ConfinementClaim {
        ConfinementClaim {
            claim_id: "claim-001".to_string(),
            component_id: "component-abc".to_string(),
            policy_ref: "pol-001".to_string(),
            flow_proofs: vec!["proof-001".to_string(), "proof-002".to_string()],
            uncovered_flows: if strength == ClaimStrength::Full {
                vec![]
            } else {
                vec![FlowRule {
                    source_label: Label::Confidential,
                    sink_clearance: Label::Internal,
                }]
            },
            claim_strength: strength,
            timestamp_ms: 1_700_000_000_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        }
    }

    // -- IfcSchemaVersion tests --

    #[test]
    fn schema_version_display() {
        assert_eq!(IfcSchemaVersion::CURRENT.to_string(), "1.0.0");
        assert_eq!(IfcSchemaVersion::new(2, 3, 4).to_string(), "2.3.4");
    }

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = IfcSchemaVersion::new(1, 0, 0);
        let v1_1 = IfcSchemaVersion::new(1, 1, 0);
        let v2_0 = IfcSchemaVersion::new(2, 0, 0);

        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v1_1));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn schema_version_serde_roundtrip() {
        let v = IfcSchemaVersion::CURRENT;
        let json = serde_json::to_string(&v).unwrap();
        let parsed: IfcSchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    // -- Label tests --

    #[test]
    fn label_ordering() {
        assert!(Label::Public.level() < Label::Internal.level());
        assert!(Label::Internal.level() < Label::Confidential.level());
        assert!(Label::Confidential.level() < Label::Secret.level());
        assert!(Label::Secret.level() < Label::TopSecret.level());
    }

    #[test]
    fn label_can_flow_to() {
        assert!(Label::Public.can_flow_to(&Label::Internal));
        assert!(Label::Public.can_flow_to(&Label::Public));
        assert!(!Label::Secret.can_flow_to(&Label::Public));
        assert!(!Label::Confidential.can_flow_to(&Label::Internal));
        // TopSecret tests
        assert!(Label::Public.can_flow_to(&Label::TopSecret));
        assert!(Label::Secret.can_flow_to(&Label::TopSecret));
        assert!(Label::TopSecret.can_flow_to(&Label::TopSecret));
        assert!(!Label::TopSecret.can_flow_to(&Label::Secret));
        assert!(!Label::TopSecret.can_flow_to(&Label::Public));
    }

    #[test]
    fn label_join() {
        assert_eq!(Label::Public.join(&Label::Secret), Label::Secret);
        assert_eq!(Label::Secret.join(&Label::Public), Label::Secret);
        assert_eq!(Label::Internal.join(&Label::Internal), Label::Internal);
    }

    #[test]
    fn label_meet() {
        assert_eq!(Label::Public.meet(&Label::Secret), Label::Public);
        assert_eq!(Label::Secret.meet(&Label::Public), Label::Public);
        assert_eq!(Label::Internal.meet(&Label::Internal), Label::Internal);
    }

    #[test]
    fn custom_label_level() {
        let custom = Label::Custom {
            name: "ultra_secret".to_string(),
            level: 10,
        };
        assert!(custom.level() > Label::TopSecret.level());
        assert!(!Label::TopSecret.can_flow_to(&Label::Secret));
        assert!(Label::Public.can_flow_to(&custom));
    }

    #[test]
    fn label_display() {
        assert_eq!(Label::Public.to_string(), "public");
        assert_eq!(Label::Secret.to_string(), "secret");
        assert_eq!(Label::TopSecret.to_string(), "top_secret");
        let custom = Label::Custom {
            name: "ts".to_string(),
            level: 5,
        };
        assert_eq!(custom.to_string(), "custom(ts, level=5)");
    }

    #[test]
    fn label_serde_roundtrip() {
        for label in [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
            Label::TopSecret,
            Label::Custom {
                name: "test".to_string(),
                level: 7,
            },
        ] {
            let json = serde_json::to_string(&label).unwrap();
            let parsed: Label = serde_json::from_str(&json).unwrap();
            assert_eq!(label, parsed);
        }
    }

    // -- FlowPolicy tests --

    #[test]
    fn flow_policy_serde_roundtrip() {
        let policy = make_flow_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: FlowPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }

    #[test]
    fn flow_policy_content_hash_deterministic() {
        let p1 = make_flow_policy();
        let p2 = make_flow_policy();
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn flow_policy_content_hash_changes_on_mutation() {
        let p1 = make_flow_policy();
        let mut p2 = make_flow_policy();
        p2.epoch_id = 999;
        assert_ne!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn flow_policy_sign_and_verify() {
        let key = test_key();
        let mut policy = make_flow_policy();
        policy.sign(&key).unwrap();
        assert!(!policy.signature.is_sentinel());
        policy.verify(&key.verification_key()).unwrap();
    }

    #[test]
    fn flow_policy_verify_fails_wrong_key() {
        let key = test_key();
        let wrong_key = SigningKey::from_bytes([99u8; 32]);
        let mut policy = make_flow_policy();
        policy.sign(&key).unwrap();
        assert!(policy.verify(&wrong_key.verification_key()).is_err());
    }

    #[test]
    fn flow_check_allowed() {
        let policy = make_flow_policy();
        // Explicitly allowed
        assert_eq!(
            policy.is_flow_allowed(&Label::Internal, &Label::Confidential),
            FlowCheckResult::Allowed
        );
    }

    #[test]
    fn flow_check_lattice_allowed() {
        let policy = make_flow_policy();
        // Lattice-legal (public -> internal)
        assert_eq!(
            policy.is_flow_allowed(&Label::Public, &Label::Internal),
            FlowCheckResult::LatticeAllowed
        );
    }

    #[test]
    fn flow_check_prohibited() {
        let policy = make_flow_policy();
        assert_eq!(
            policy.is_flow_allowed(&Label::Confidential, &Label::Public),
            FlowCheckResult::Prohibited
        );
    }

    #[test]
    fn flow_check_declassification_required() {
        let policy = make_flow_policy();
        assert_eq!(
            policy.is_flow_allowed(&Label::Secret, &Label::Internal),
            FlowCheckResult::DeclassificationRequired {
                route_id: "declass-1".to_string()
            }
        );
    }

    #[test]
    fn flow_check_denied() {
        let policy = make_flow_policy();
        // No rule, not lattice-legal, no declassification
        assert_eq!(
            policy.is_flow_allowed(&Label::Secret, &Label::Public),
            FlowCheckResult::Denied
        );
    }

    // -- FlowProof tests --

    #[test]
    fn flow_proof_serde_roundtrip() {
        let proof = make_flow_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: FlowProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    #[test]
    fn flow_proof_content_hash_deterministic() {
        let p1 = make_flow_proof();
        let p2 = make_flow_proof();
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn flow_proof_sign_and_verify() {
        let key = test_key();
        let mut proof = make_flow_proof();
        proof.sign(&key).unwrap();
        assert!(!proof.signature.is_sentinel());
        proof.verify(&key.verification_key()).unwrap();
    }

    // -- ProofMethod tests --

    #[test]
    fn proof_method_display() {
        assert_eq!(ProofMethod::StaticAnalysis.to_string(), "static_analysis");
        assert_eq!(ProofMethod::RuntimeCheck.to_string(), "runtime_check");
        assert_eq!(
            ProofMethod::Declassification.to_string(),
            "declassification"
        );
    }

    #[test]
    fn proof_method_serde_roundtrip() {
        for method in [
            ProofMethod::StaticAnalysis,
            ProofMethod::RuntimeCheck,
            ProofMethod::Declassification,
        ] {
            let json = serde_json::to_string(&method).unwrap();
            let parsed: ProofMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, parsed);
        }
    }

    // -- DeclassificationReceipt tests --

    #[test]
    fn receipt_serde_roundtrip() {
        let receipt = make_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn receipt_content_hash_deterministic() {
        let r1 = make_receipt();
        let r2 = make_receipt();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn receipt_sign_and_verify() {
        let key = test_key();
        let mut receipt = make_receipt();
        receipt.sign(&key).unwrap();
        assert!(!receipt.signature.is_sentinel());
        receipt.verify(&key.verification_key()).unwrap();
    }

    #[test]
    fn receipt_validate_accepts_linked_receipt() {
        let receipt = make_receipt();
        receipt.validate().unwrap();
    }

    #[test]
    fn receipt_validate_rejects_blank_replay_linkage() {
        let mut receipt = make_receipt();
        receipt.replay_linkage = " \t ".to_string();

        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            IfcValidationError::EmptyRequiredField {
                artifact_kind: "declassification_receipt".to_string(),
                artifact_id: "receipt-001".to_string(),
                field_name: "replay_linkage".to_string(),
            }
        );
    }

    #[test]
    fn receipt_sign_rejects_blank_decision_contract_id() {
        let key = test_key();
        let mut receipt = make_receipt();
        receipt.decision_contract_id = String::new();

        let err = receipt.sign(&key).unwrap_err();
        assert!(matches!(
            err,
            SignatureError::NonCanonicalObject { detail }
            if detail.contains("decision_contract_id")
        ));
    }

    #[test]
    fn receipt_verify_rejects_blank_replay_linkage_after_signing() {
        let key = test_key();
        let mut receipt = make_receipt();
        receipt.sign(&key).unwrap();
        receipt.replay_linkage = "\n".to_string();

        let err = receipt.verify(&key.verification_key()).unwrap_err();
        assert!(matches!(
            err,
            SignatureError::NonCanonicalObject { detail }
            if detail.contains("replay_linkage")
        ));
    }

    #[test]
    fn receipt_replay_command_matches_shipped_trace_replay_surface() {
        let receipt = make_receipt();
        let command = receipt.replay_command();
        assert_eq!(
            command,
            "frankenctl replay run --trace <trace.json> --mode strict"
        );
        assert!(!command.contains("frankenctl verify receipt"));
        assert!(!command.contains("--receipt-id"));
    }

    #[test]
    fn receipt_decision_serde_roundtrip() {
        for d in [
            DeclassificationDecision::Allow,
            DeclassificationDecision::Deny,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let parsed: DeclassificationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, parsed);
        }
    }

    #[test]
    fn receipt_decision_display() {
        assert_eq!(DeclassificationDecision::Allow.to_string(), "allow");
        assert_eq!(DeclassificationDecision::Deny.to_string(), "deny");
    }

    // -- ConfinementClaim tests --

    #[test]
    fn claim_full_validates() {
        let claim = make_claim(ClaimStrength::Full);
        assert!(claim.validate().is_ok());
        assert!(claim.is_full());
    }

    #[test]
    fn claim_partial_validates() {
        let claim = make_claim(ClaimStrength::Partial);
        assert!(claim.validate().is_ok());
        assert!(!claim.is_full());
    }

    #[test]
    fn claim_full_with_uncovered_fails_validation() {
        let mut claim = make_claim(ClaimStrength::Full);
        claim.uncovered_flows.push(FlowRule {
            source_label: Label::Secret,
            sink_clearance: Label::Public,
        });
        let err = claim.validate().unwrap_err();
        assert!(matches!(
            err,
            IfcValidationError::FullClaimHasUncoveredFlows { .. }
        ));
    }

    #[test]
    fn claim_empty_fails_validation() {
        let claim = ConfinementClaim {
            claim_id: "empty".to_string(),
            component_id: "comp".to_string(),
            policy_ref: "pol".to_string(),
            flow_proofs: vec![],
            uncovered_flows: vec![],
            claim_strength: ClaimStrength::Full,
            timestamp_ms: 0,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        };
        let err = claim.validate().unwrap_err();
        assert!(matches!(err, IfcValidationError::EmptyClaim { .. }));
    }

    #[test]
    fn claim_serde_roundtrip() {
        for strength in [ClaimStrength::Full, ClaimStrength::Partial] {
            let claim = make_claim(strength);
            let json = serde_json::to_string(&claim).unwrap();
            let parsed: ConfinementClaim = serde_json::from_str(&json).unwrap();
            assert_eq!(claim, parsed);
        }
    }

    #[test]
    fn claim_content_hash_deterministic() {
        let c1 = make_claim(ClaimStrength::Full);
        let c2 = make_claim(ClaimStrength::Full);
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn claim_sign_and_verify() {
        let key = test_key();
        let mut claim = make_claim(ClaimStrength::Full);
        claim.sign(&key).unwrap();
        assert!(!claim.signature.is_sentinel());
        claim.verify(&key.verification_key()).unwrap();
    }

    #[test]
    fn claim_strength_display() {
        assert_eq!(ClaimStrength::Full.to_string(), "full");
        assert_eq!(ClaimStrength::Partial.to_string(), "partial");
    }

    #[test]
    fn claim_strength_serde_roundtrip() {
        for s in [ClaimStrength::Full, ClaimStrength::Partial] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: ClaimStrength = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }

    // -- Validation error tests --

    #[test]
    fn validation_error_display() {
        let err = IfcValidationError::FullClaimHasUncoveredFlows {
            claim_id: "c1".to_string(),
            uncovered_count: 3,
        };
        assert!(err.to_string().contains("3 uncovered flows"));

        let err = IfcValidationError::EmptyClaim {
            claim_id: "c1".to_string(),
        };
        assert!(err.to_string().contains("empty"));

        let err = IfcValidationError::FlowProhibited {
            source: Label::Secret,
            sink: Label::Public,
        };
        assert!(err.to_string().contains("prohibited"));

        let err = IfcValidationError::EmptyRequiredField {
            artifact_kind: "declassification_receipt".to_string(),
            artifact_id: "receipt-1".to_string(),
            field_name: "replay_linkage".to_string(),
        };
        assert!(err.to_string().contains("replay_linkage"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let errors = vec![
            IfcValidationError::FullClaimHasUncoveredFlows {
                claim_id: "c1".to_string(),
                uncovered_count: 2,
            },
            IfcValidationError::EmptyClaim {
                claim_id: "c2".to_string(),
            },
            IfcValidationError::IncompatibleSchema {
                expected: IfcSchemaVersion::CURRENT,
                actual: IfcSchemaVersion::new(2, 0, 0),
            },
            IfcValidationError::EmptyRequiredField {
                artifact_kind: "declassification_receipt".to_string(),
                artifact_id: "receipt-1".to_string(),
                field_name: "replay_linkage".to_string(),
            },
            IfcValidationError::FlowProhibited {
                source: Label::Secret,
                sink: Label::Public,
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let parsed: IfcValidationError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, parsed);
        }
    }

    // -- FlowRule tests --

    #[test]
    fn flow_rule_serde_roundtrip() {
        let rule = FlowRule {
            source_label: Label::Internal,
            sink_clearance: Label::Confidential,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: FlowRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, parsed);
    }

    // -- DeclassificationRoute tests --

    #[test]
    fn declassification_route_serde_roundtrip() {
        let route = DeclassificationRoute {
            route_id: "route-1".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Internal,
            conditions: vec!["audit_approval".to_string(), "ciso_sign_off".to_string()],
        };
        let json = serde_json::to_string(&route).unwrap();
        let parsed: DeclassificationRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(route, parsed);
    }

    // -- FlowCheckResult tests --

    #[test]
    fn flow_check_result_serde_roundtrip() {
        let results = vec![
            FlowCheckResult::Allowed,
            FlowCheckResult::LatticeAllowed,
            FlowCheckResult::DeclassificationRequired {
                route_id: "r1".to_string(),
            },
            FlowCheckResult::Prohibited,
            FlowCheckResult::Denied,
        ];
        for r in results {
            let json = serde_json::to_string(&r).unwrap();
            let parsed: FlowCheckResult = serde_json::from_str(&json).unwrap();
            assert_eq!(r, parsed);
        }
    }

    // -- Full lifecycle test --

    #[test]
    fn full_ifc_lifecycle() {
        let key = test_key();

        // 1. Define policy
        let mut policy = make_flow_policy();
        policy.sign(&key).unwrap();
        policy.verify(&key.verification_key()).unwrap();

        // 2. Prove a flow
        let mut proof = make_flow_proof();
        proof.policy_ref = policy.policy_id.clone();
        proof.sign(&key).unwrap();
        proof.verify(&key.verification_key()).unwrap();

        // 3. Issue declassification receipt
        let mut receipt = make_receipt();
        receipt.sign(&key).unwrap();
        receipt.verify(&key.verification_key()).unwrap();

        // 4. Make confinement claim
        let mut claim = ConfinementClaim {
            claim_id: "lifecycle-claim".to_string(),
            component_id: "comp-lifecycle".to_string(),
            policy_ref: policy.policy_id.clone(),
            flow_proofs: vec![proof.proof_id.clone()],
            uncovered_flows: vec![],
            claim_strength: ClaimStrength::Full,
            timestamp_ms: 1_700_000_001_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: sentinel_sig(),
        };
        claim.validate().unwrap();
        claim.sign(&key).unwrap();
        claim.verify(&key.verification_key()).unwrap();
        assert!(claim.is_full());
    }

    // -- Content-addressable identity determinism --

    #[test]
    fn all_artifact_hashes_are_deterministic() {
        for _ in 0..100 {
            let p1 = make_flow_policy();
            let p2 = make_flow_policy();
            assert_eq!(p1.content_hash(), p2.content_hash());

            let fp1 = make_flow_proof();
            let fp2 = make_flow_proof();
            assert_eq!(fp1.content_hash(), fp2.content_hash());

            let r1 = make_receipt();
            let r2 = make_receipt();
            assert_eq!(r1.content_hash(), r2.content_hash());

            let c1 = make_claim(ClaimStrength::Full);
            let c2 = make_claim(ClaimStrength::Full);
            assert_eq!(c1.content_hash(), c2.content_hash());
        }
    }

    // -- TopSecret label tests --

    #[test]
    fn top_secret_label_level() {
        assert_eq!(Label::TopSecret.level(), 4);
        assert!(Label::TopSecret.level() > Label::Secret.level());
    }

    #[test]
    fn top_secret_join() {
        assert_eq!(Label::Secret.join(&Label::TopSecret), Label::TopSecret);
        assert_eq!(Label::TopSecret.join(&Label::Public), Label::TopSecret);
        assert_eq!(Label::TopSecret.join(&Label::TopSecret), Label::TopSecret);
    }

    #[test]
    fn top_secret_meet() {
        assert_eq!(Label::Secret.meet(&Label::TopSecret), Label::Secret);
        assert_eq!(Label::TopSecret.meet(&Label::Public), Label::Public);
        assert_eq!(Label::TopSecret.meet(&Label::TopSecret), Label::TopSecret);
    }

    #[test]
    fn top_secret_all_builtin() {
        let all = Label::all_builtin();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], Label::Public);
        assert_eq!(all[4], Label::TopSecret);
        for i in 0..all.len() - 1 {
            assert!(all[i].level() < all[i + 1].level());
        }
    }

    // -- Lattice algebraic property tests --

    #[test]
    fn lattice_join_commutativity() {
        let labels = Label::all_builtin();
        for a in &labels {
            for b in &labels {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "join must be commutative: {a} join {b}"
                );
            }
        }
    }

    #[test]
    fn lattice_meet_commutativity() {
        let labels = Label::all_builtin();
        for a in &labels {
            for b in &labels {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet must be commutative: {a} meet {b}"
                );
            }
        }
    }

    #[test]
    fn lattice_join_associativity() {
        let labels = Label::all_builtin();
        for a in &labels {
            for b in &labels {
                for c in &labels {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(&b.join(c)),
                        "join must be associative: ({a} join {b}) join {c}"
                    );
                }
            }
        }
    }

    #[test]
    fn lattice_meet_associativity() {
        let labels = Label::all_builtin();
        for a in &labels {
            for b in &labels {
                for c in &labels {
                    assert_eq!(
                        a.meet(b).meet(c),
                        a.meet(&b.meet(c)),
                        "meet must be associative: ({a} meet {b}) meet {c}"
                    );
                }
            }
        }
    }

    #[test]
    fn lattice_join_idempotency() {
        let labels = Label::all_builtin();
        for a in &labels {
            assert_eq!(a.join(a), *a, "join must be idempotent: {a} join {a}");
        }
    }

    #[test]
    fn lattice_meet_idempotency() {
        let labels = Label::all_builtin();
        for a in &labels {
            assert_eq!(a.meet(a), *a, "meet must be idempotent: {a} meet {a}");
        }
    }

    #[test]
    fn lattice_absorption() {
        let labels = Label::all_builtin();
        for a in &labels {
            for b in &labels {
                // a join (a meet b) = a
                assert_eq!(
                    a.join(&a.meet(b)),
                    *a,
                    "absorption: {a} join ({a} meet {b})"
                );
                // a meet (a join b) = a
                assert_eq!(
                    a.meet(&a.join(b)),
                    *a,
                    "absorption: {a} meet ({a} join {b})"
                );
            }
        }
    }

    #[test]
    fn lattice_join_all_empty() {
        assert_eq!(Label::join_all(std::iter::empty()), None);
    }

    #[test]
    fn lattice_join_all_single() {
        assert_eq!(Label::join_all([Label::Internal]), Some(Label::Internal));
    }

    #[test]
    fn lattice_join_all_multiple() {
        assert_eq!(
            Label::join_all([Label::Public, Label::Secret, Label::Internal]),
            Some(Label::Secret)
        );
        assert_eq!(
            Label::join_all([Label::Confidential, Label::TopSecret, Label::Public]),
            Some(Label::TopSecret)
        );
    }

    #[test]
    fn lattice_meet_all_empty() {
        assert_eq!(Label::meet_all(std::iter::empty()), None);
    }

    #[test]
    fn lattice_meet_all_multiple() {
        assert_eq!(
            Label::meet_all([Label::Secret, Label::Internal, Label::TopSecret]),
            Some(Label::Internal)
        );
        assert_eq!(
            Label::meet_all([Label::TopSecret, Label::Confidential, Label::Public]),
            Some(Label::Public)
        );
    }

    // -- ClearanceClass tests --

    #[test]
    fn clearance_class_ordering() {
        assert!(ClearanceClass::OpenSink.level() < ClearanceClass::RestrictedSink.level());
        assert!(ClearanceClass::RestrictedSink.level() < ClearanceClass::AuditedSink.level());
        assert!(ClearanceClass::AuditedSink.level() < ClearanceClass::SealedSink.level());
        assert!(ClearanceClass::SealedSink.level() < ClearanceClass::NeverSink.level());
    }

    #[test]
    fn clearance_class_can_receive() {
        // OpenSink accepts everything
        assert!(ClearanceClass::OpenSink.can_receive(&Label::Public));
        assert!(ClearanceClass::OpenSink.can_receive(&Label::TopSecret));

        // RestrictedSink accepts up to Internal
        assert!(ClearanceClass::RestrictedSink.can_receive(&Label::Public));
        assert!(ClearanceClass::RestrictedSink.can_receive(&Label::Internal));
        assert!(!ClearanceClass::RestrictedSink.can_receive(&Label::Confidential));
        assert!(!ClearanceClass::RestrictedSink.can_receive(&Label::Secret));

        // AuditedSink accepts up to Confidential
        assert!(ClearanceClass::AuditedSink.can_receive(&Label::Confidential));
        assert!(!ClearanceClass::AuditedSink.can_receive(&Label::Secret));

        // SealedSink accepts up to Secret
        assert!(ClearanceClass::SealedSink.can_receive(&Label::Secret));
        assert!(!ClearanceClass::SealedSink.can_receive(&Label::TopSecret));

        // NeverSink accepts only Public
        assert!(ClearanceClass::NeverSink.can_receive(&Label::Public));
        assert!(!ClearanceClass::NeverSink.can_receive(&Label::TopSecret));
    }

    #[test]
    fn clearance_class_display() {
        assert_eq!(ClearanceClass::OpenSink.to_string(), "open_sink");
        assert_eq!(
            ClearanceClass::RestrictedSink.to_string(),
            "restricted_sink"
        );
        assert_eq!(ClearanceClass::AuditedSink.to_string(), "audited_sink");
        assert_eq!(ClearanceClass::SealedSink.to_string(), "sealed_sink");
        assert_eq!(ClearanceClass::NeverSink.to_string(), "never_sink");
    }

    #[test]
    fn clearance_class_serde_roundtrip() {
        for cc in ClearanceClass::all() {
            let json = serde_json::to_string(&cc).unwrap();
            let parsed: ClearanceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(cc, parsed);
        }
    }

    #[test]
    fn clearance_class_all_ascending() {
        let all = ClearanceClass::all();
        for i in 0..all.len() - 1 {
            assert!(all[i].level() < all[i + 1].level());
        }
    }

    #[test]
    fn clearance_max_receivable_levels() {
        assert_eq!(
            ClearanceClass::OpenSink.max_receivable_label_level(),
            Some(4)
        );
        assert_eq!(
            ClearanceClass::RestrictedSink.max_receivable_label_level(),
            Some(1)
        );
        assert_eq!(
            ClearanceClass::AuditedSink.max_receivable_label_level(),
            Some(2)
        );
        assert_eq!(
            ClearanceClass::SealedSink.max_receivable_label_level(),
            Some(3)
        );
        assert_eq!(
            ClearanceClass::NeverSink.max_receivable_label_level(),
            Some(0)
        );
    }

    // -- DeclassificationObligation tests --

    fn make_obligation() -> DeclassificationObligation {
        DeclassificationObligation {
            obligation_id: "obl-001".to_string(),
            source_label: Label::TopSecret,
            target_clearance: ClearanceClass::SealedSink,
            required_conditions: vec!["ciso_sign_off".to_string(), "audit_approval".to_string()],
            max_loss_milli: 10_000,
            audit_trail_required: true,
            approval_authority: "security_team".to_string(),
            expiry_epoch: Some(100),
        }
    }

    #[test]
    fn obligation_serde_roundtrip() {
        let obl = make_obligation();
        let json = serde_json::to_string(&obl).unwrap();
        let parsed: DeclassificationObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(obl, parsed);
    }

    #[test]
    fn obligation_conditions_satisfied() {
        let obl = make_obligation();
        let mut satisfied = BTreeSet::new();
        assert!(!obl.conditions_satisfied(&satisfied));

        satisfied.insert("ciso_sign_off".to_string());
        assert!(!obl.conditions_satisfied(&satisfied));

        satisfied.insert("audit_approval".to_string());
        assert!(obl.conditions_satisfied(&satisfied));

        // Extra conditions don't matter
        satisfied.insert("extra_condition".to_string());
        assert!(obl.conditions_satisfied(&satisfied));
    }

    #[test]
    fn obligation_conditions_empty() {
        let obl = DeclassificationObligation {
            obligation_id: "obl-empty".to_string(),
            source_label: Label::Internal,
            target_clearance: ClearanceClass::OpenSink,
            required_conditions: vec![],
            max_loss_milli: 0,
            audit_trail_required: false,
            approval_authority: "auto".to_string(),
            expiry_epoch: None,
        };
        assert!(obl.conditions_satisfied(&BTreeSet::new()));
    }

    #[test]
    fn obligation_expiry() {
        let obl = make_obligation();
        assert!(!obl.is_expired(50));
        assert!(!obl.is_expired(100));
        assert!(obl.is_expired(101));
    }

    #[test]
    fn obligation_no_expiry() {
        let obl = DeclassificationObligation {
            expiry_epoch: None,
            ..make_obligation()
        };
        assert!(!obl.is_expired(u64::MAX));
    }

    // -- Ir2LabelSource tests --

    #[test]
    fn ir2_label_literal() {
        assert_eq!(Ir2LabelSource::Literal.assign_label(), Label::Public);
    }

    #[test]
    fn ir2_label_env_var() {
        assert_eq!(
            Ir2LabelSource::EnvironmentVariable.assign_label(),
            Label::Secret
        );
    }

    #[test]
    fn ir2_label_credential_path() {
        assert_eq!(
            Ir2LabelSource::CredentialPath {
                is_key_material: false
            }
            .assign_label(),
            Label::Secret
        );
        assert_eq!(
            Ir2LabelSource::CredentialPath {
                is_key_material: true
            }
            .assign_label(),
            Label::TopSecret
        );
    }

    #[test]
    fn ir2_label_hostcall_return() {
        assert_eq!(
            Ir2LabelSource::HostcallReturn {
                clearance_label: Label::Confidential
            }
            .assign_label(),
            Label::Confidential
        );
    }

    #[test]
    fn ir2_label_computed_taint_propagation() {
        // join(Public, Secret) = Secret
        assert_eq!(
            Ir2LabelSource::Computed {
                input_labels: vec![Label::Public, Label::Secret]
            }
            .assign_label(),
            Label::Secret
        );
        // join(Confidential, TopSecret) = TopSecret
        assert_eq!(
            Ir2LabelSource::Computed {
                input_labels: vec![Label::Confidential, Label::TopSecret]
            }
            .assign_label(),
            Label::TopSecret
        );
        // Empty inputs → Public
        assert_eq!(
            Ir2LabelSource::Computed {
                input_labels: vec![]
            }
            .assign_label(),
            Label::Public
        );
    }

    #[test]
    fn ir2_label_declassified() {
        assert_eq!(
            Ir2LabelSource::Declassified {
                receipt_ref: "receipt-001".to_string(),
                effective_label: Label::Internal
            }
            .assign_label(),
            Label::Internal
        );
    }

    #[test]
    fn ir2_label_source_serde_roundtrip() {
        let sources = vec![
            Ir2LabelSource::Literal,
            Ir2LabelSource::EnvironmentVariable,
            Ir2LabelSource::CredentialPath {
                is_key_material: true,
            },
            Ir2LabelSource::HostcallReturn {
                clearance_label: Label::Secret,
            },
            Ir2LabelSource::Computed {
                input_labels: vec![Label::Public, Label::Internal],
            },
            Ir2LabelSource::Declassified {
                receipt_ref: "r1".to_string(),
                effective_label: Label::Public,
            },
        ];
        for source in sources {
            let json = serde_json::to_string(&source).unwrap();
            let parsed: Ir2LabelSource = serde_json::from_str(&json).unwrap();
            assert_eq!(source, parsed);
        }
    }

    // -- FlowEnvelope tests --

    fn make_flow_envelope() -> FlowEnvelope {
        FlowEnvelope {
            envelope_id: "env-001".to_string(),
            extension_id: "ext-abc".to_string(),
            producible_labels: [Label::Public, Label::Internal].into_iter().collect(),
            accessible_clearances: [ClearanceClass::OpenSink, ClearanceClass::RestrictedSink]
                .into_iter()
                .collect(),
            authorized_declassifications: vec!["obl-001".to_string()],
            policy_ref: "pol-001".to_string(),
            epoch_id: 1,
            schema_version: IfcSchemaVersion::CURRENT,
        }
    }

    #[test]
    fn flow_envelope_serde_roundtrip() {
        let env = make_flow_envelope();
        let json = serde_json::to_string(&env).unwrap();
        let parsed: FlowEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, parsed);
    }

    #[test]
    fn flow_envelope_content_hash_deterministic() {
        let e1 = make_flow_envelope();
        let e2 = make_flow_envelope();
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn flow_envelope_authorized_flow() {
        let env = make_flow_envelope();
        // Public -> OpenSink: authorized (label in producible, clearance in accessible, can receive)
        assert!(env.is_flow_authorized(&Label::Public, &ClearanceClass::OpenSink));
        // Internal -> RestrictedSink: authorized (Internal level=1 <= RestrictedSink max=1)
        assert!(env.is_flow_authorized(&Label::Internal, &ClearanceClass::RestrictedSink));
    }

    #[test]
    fn flow_envelope_unauthorized_label() {
        let env = make_flow_envelope();
        // Secret not in producible_labels
        assert!(!env.is_flow_authorized(&Label::Secret, &ClearanceClass::OpenSink));
    }

    #[test]
    fn flow_envelope_unauthorized_clearance() {
        let env = make_flow_envelope();
        // AuditedSink not in accessible_clearances
        assert!(!env.is_flow_authorized(&Label::Public, &ClearanceClass::AuditedSink));
    }

    #[test]
    fn flow_envelope_clearance_rejects_too_sensitive() {
        // Even if labels and clearances are in the sets, the clearance must be able to receive
        let env = FlowEnvelope {
            envelope_id: "env-002".to_string(),
            extension_id: "ext-xyz".to_string(),
            producible_labels: [Label::Secret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::RestrictedSink].into_iter().collect(),
            authorized_declassifications: vec![],
            policy_ref: "pol-002".to_string(),
            epoch_id: 1,
            schema_version: IfcSchemaVersion::CURRENT,
        };
        // Secret (level=3) cannot flow to RestrictedSink (max=1)
        assert!(!env.is_flow_authorized(&Label::Secret, &ClearanceClass::RestrictedSink));
    }

    #[test]
    fn flow_assessment_flags_secret_to_sealed_sink_without_explicit_authorization() {
        let env = FlowEnvelope {
            envelope_id: "env-secret-sealed".to_string(),
            extension_id: "ext-secret-sealed".to_string(),
            producible_labels: [Label::Secret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::SealedSink].into_iter().collect(),
            authorized_declassifications: vec![],
            policy_ref: "pol-secret-sealed".to_string(),
            epoch_id: 7,
            schema_version: IfcSchemaVersion::CURRENT,
        };

        let assessment = env.assess_flow_authorization(&Label::Secret, &ClearanceClass::SealedSink);
        assert!(assessment.envelope_authorized);
        assert!(!assessment.flow_authorized);
        assert!(!assessment.requires_declassification());
        assert!(assessment.has_advisories());
        assert_eq!(
            assessment.advisories,
            vec![FlowAuthorizationAdvisory::ExplicitAuthorizationRequired {
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::SealedSink,
            }]
        );
    }

    #[test]
    fn flow_assessment_clears_secret_to_sealed_sink_when_authorization_ref_exists() {
        let env = FlowEnvelope {
            envelope_id: "env-secret-sealed-ok".to_string(),
            extension_id: "ext-secret-sealed-ok".to_string(),
            producible_labels: [Label::Secret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::SealedSink].into_iter().collect(),
            authorized_declassifications: vec!["obl-sealed-secret".to_string()],
            policy_ref: "pol-secret-sealed-ok".to_string(),
            epoch_id: 7,
            schema_version: IfcSchemaVersion::CURRENT,
        };

        let assessment = env.assess_flow_authorization(&Label::Secret, &ClearanceClass::SealedSink);
        assert!(assessment.envelope_authorized);
        assert!(!assessment.flow_authorized);
        assert!(assessment.requires_declassification());
        assert!(!assessment.has_advisories());
        let obligation = assessment
            .declassification_obligation
            .expect("secret sealed sink should materialize obligation");
        assert_eq!(obligation.obligation_id, "obl-sealed-secret");
        assert_eq!(obligation.source_label, Label::Secret);
        assert_eq!(obligation.target_clearance, ClearanceClass::SealedSink);
        assert_eq!(obligation.approval_authority, "pol-secret-sealed-ok");
        assert_eq!(obligation.expiry_epoch, Some(7));
    }

    #[test]
    fn flow_assessment_materializes_top_secret_to_sealed_sink_obligation() {
        let env = FlowEnvelope {
            envelope_id: "env-top-secret-sealed".to_string(),
            extension_id: "ext-top-secret-sealed".to_string(),
            producible_labels: [Label::TopSecret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::SealedSink].into_iter().collect(),
            authorized_declassifications: vec!["obl-sealed-secret".to_string()],
            policy_ref: "pol-top-secret-sealed".to_string(),
            epoch_id: 7,
            schema_version: IfcSchemaVersion::CURRENT,
        };

        let assessment =
            env.assess_flow_authorization(&Label::TopSecret, &ClearanceClass::SealedSink);
        assert!(!assessment.envelope_authorized);
        assert!(!assessment.flow_authorized);
        assert!(assessment.requires_declassification());
        assert!(!assessment.has_advisories());
        let obligation = assessment
            .declassification_obligation
            .expect("top secret sealed sink should materialize obligation");
        assert_eq!(obligation.obligation_id, "obl-sealed-secret");
        assert_eq!(obligation.source_label, Label::TopSecret);
        assert_eq!(obligation.target_clearance, ClearanceClass::SealedSink);
    }

    // -- Exfiltration scenario test --

    #[test]
    fn exfiltration_scenario_blocked() {
        // Simulates: env var read (Secret) combined with literal ("Bearer ") → sent to network
        let api_key_label = Ir2LabelSource::EnvironmentVariable.assign_label();
        let prefix_label = Ir2LabelSource::Literal.assign_label();
        let header_label = Ir2LabelSource::Computed {
            input_labels: vec![prefix_label, api_key_label],
        }
        .assign_label();

        // header_label should be Secret (join of Public and Secret)
        assert_eq!(header_label, Label::Secret);

        // NeverSink (raw network egress) cannot receive Secret
        assert!(!ClearanceClass::NeverSink.can_receive(&header_label));

        // SealedSink can receive Secret at the clearance layer, but the flow
        // still needs explicit authorization material before it can proceed.
        let env = FlowEnvelope {
            envelope_id: "env-exfil-secret".to_string(),
            extension_id: "ext-exfil-secret".to_string(),
            producible_labels: [Label::Secret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::SealedSink].into_iter().collect(),
            authorized_declassifications: vec![],
            policy_ref: "pol-exfil-secret".to_string(),
            epoch_id: 9,
            schema_version: IfcSchemaVersion::CURRENT,
        };
        let assessment = env.assess_flow_authorization(&header_label, &ClearanceClass::SealedSink);
        assert!(ClearanceClass::SealedSink.can_receive(&header_label));
        assert!(!assessment.flow_authorized);
        assert!(!assessment.requires_declassification());
        assert_eq!(
            assessment.advisories,
            vec![FlowAuthorizationAdvisory::ExplicitAuthorizationRequired {
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::SealedSink,
            }]
        );
    }

    #[test]
    fn exfiltration_scenario_with_declassification() {
        // TopSecret key material being sent through an audited declassification
        let key_label = Ir2LabelSource::CredentialPath {
            is_key_material: true,
        }
        .assign_label();
        assert_eq!(key_label, Label::TopSecret);

        // Cannot flow to any sink except OpenSink without declassification
        assert!(!ClearanceClass::SealedSink.can_receive(&key_label));
        assert!(ClearanceClass::OpenSink.can_receive(&key_label));

        // TopSecret -> SealedSink now materializes a concrete obligation when
        // the envelope carries explicit authorization material.
        let env = FlowEnvelope {
            envelope_id: "env-exfil-top-secret".to_string(),
            extension_id: "ext-exfil-top-secret".to_string(),
            producible_labels: [Label::TopSecret].into_iter().collect(),
            accessible_clearances: [ClearanceClass::SealedSink].into_iter().collect(),
            authorized_declassifications: vec!["obl-key-export".to_string()],
            policy_ref: "pol-exfil-top-secret".to_string(),
            epoch_id: 50,
            schema_version: IfcSchemaVersion::CURRENT,
        };
        let assessment = env.assess_flow_authorization(&key_label, &ClearanceClass::SealedSink);
        assert!(!assessment.flow_authorized);
        assert!(assessment.requires_declassification());
        assert!(assessment.advisories.is_empty());
        let obligation = assessment
            .declassification_obligation
            .expect("top secret exfiltration should require concrete obligation");
        assert_eq!(obligation.obligation_id, "obl-key-export");
        assert_eq!(obligation.source_label, Label::TopSecret);
        assert_eq!(obligation.target_clearance, ClearanceClass::SealedSink);
    }

    // -- Cross-type integration --

    #[test]
    fn flow_policy_with_top_secret() {
        let mut policy = make_flow_policy();
        policy.label_classes.insert(Label::TopSecret);
        policy.clearance_classes.insert(Label::TopSecret);

        // TopSecret -> TopSecret is lattice-legal
        assert_eq!(
            policy.is_flow_allowed(&Label::TopSecret, &Label::TopSecret),
            FlowCheckResult::LatticeAllowed
        );
        // TopSecret -> Public is denied (no declassification route)
        assert_eq!(
            policy.is_flow_allowed(&Label::TopSecret, &Label::Public),
            FlowCheckResult::Denied
        );
    }

    // -- Enrichment: std::error --

    #[test]
    fn ifc_validation_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(IfcValidationError::FullClaimHasUncoveredFlows {
                claim_id: "c-1".into(),
                uncovered_count: 3,
            }),
            Box::new(IfcValidationError::EmptyClaim {
                claim_id: "c-2".into(),
            }),
            Box::new(IfcValidationError::IncompatibleSchema {
                expected: IfcSchemaVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                actual: IfcSchemaVersion {
                    major: 2,
                    minor: 0,
                    patch: 0,
                },
            }),
            Box::new(IfcValidationError::FlowProhibited {
                source: Label::Secret,
                sink: Label::Public,
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
            4,
            "all 4 variants produce distinct messages"
        );
    }
}
