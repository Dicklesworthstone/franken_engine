//! Incident replay artifact bundle format and standalone verifier.
//!
//! Provides a self-contained, portable, content-addressed archive for
//! security-incident investigations.  An external auditor can reproduce
//! and verify all claims without trusting FrankenEngine runtime internals.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: 10.12 item 8, 9H.3, 9F.3.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causal_replay::{
    ActionDeltaReport, CausalReplayEngine, CounterfactualConfig, NondeterminismLog, TraceRecord,
};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::evidence_ledger::EvidenceEntry;
use crate::fleet_immune_protocol::QuorumCheckpoint;
use crate::hash_tiers::ContentHash;
use crate::proof_schema::OptReceipt;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature as sig_verify,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BUNDLE_SCHEMA_DEF: &[u8] = b"IncidentReplayBundle.v1";
const BUNDLE_ZONE: &str = "incident-replay-bundle";

/// Current bundle format version.
pub const BUNDLE_FORMAT_VERSION: BundleFormatVersion = BundleFormatVersion { major: 1, minor: 0 };

// ---------------------------------------------------------------------------
// BundleFormatVersion
// ---------------------------------------------------------------------------

/// Semantic version for the bundle format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BundleFormatVersion {
    pub major: u32,
    pub minor: u32,
}

impl BundleFormatVersion {
    /// Compatible if same major and reader minor >= bundle minor.
    pub fn is_compatible_with(&self, bundle_version: &Self) -> bool {
        self.major == bundle_version.major && self.minor >= bundle_version.minor
    }
}

impl fmt::Display for BundleFormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// BundleError
// ---------------------------------------------------------------------------

/// Errors from the incident replay bundle subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleError {
    /// Bundle integrity check failed (Merkle root mismatch).
    IntegrityFailure { expected: String, actual: String },
    /// Artifact content hash mismatch.
    ArtifactHashMismatch { artifact_id: String },
    /// Bundle signature verification failed.
    SignatureInvalid,
    /// Replay produced different results from bundled verdict.
    ReplayDivergence { details: String },
    /// Receipt verification failed.
    ReceiptInvalid { receipt_id: String, reason: String },
    /// Incompatible bundle format version.
    IncompatibleVersion {
        bundle: BundleFormatVersion,
        reader: BundleFormatVersion,
    },
    /// Bundle is empty (no artifacts).
    EmptyBundle,
    /// Trace not found in bundle.
    TraceNotFound { trace_id: String },
    /// ID derivation failed.
    IdDerivation(String),
    /// Replay engine error.
    ReplayFailed(String),
    /// Redaction violated integrity (non-redactable field was modified).
    RedactionViolation { field: String },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegrityFailure { expected, actual } => {
                write!(f, "integrity failure: expected {expected}, got {actual}")
            }
            Self::ArtifactHashMismatch { artifact_id } => {
                write!(f, "artifact hash mismatch: {artifact_id}")
            }
            Self::SignatureInvalid => f.write_str("bundle signature invalid"),
            Self::ReplayDivergence { details } => {
                write!(f, "replay divergence: {details}")
            }
            Self::ReceiptInvalid { receipt_id, reason } => {
                write!(f, "receipt invalid ({receipt_id}): {reason}")
            }
            Self::IncompatibleVersion { bundle, reader } => {
                write!(f, "incompatible version: bundle={bundle}, reader={reader}")
            }
            Self::EmptyBundle => f.write_str("empty bundle"),
            Self::TraceNotFound { trace_id } => {
                write!(f, "trace not found: {trace_id}")
            }
            Self::IdDerivation(msg) => write!(f, "id derivation: {msg}"),
            Self::ReplayFailed(msg) => write!(f, "replay failed: {msg}"),
            Self::RedactionViolation { field } => {
                write!(f, "redaction violation: {field}")
            }
        }
    }
}

impl std::error::Error for BundleError {}

// ---------------------------------------------------------------------------
// RedactionPolicy — controls what can be stripped for privacy
// ---------------------------------------------------------------------------

/// Controls which fields may be redacted from bundle artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Redact extension identifiers (replace with deterministic placeholders).
    pub redact_extension_ids: bool,
    /// Redact raw evidence entry metadata.
    pub redact_evidence_metadata: bool,
    /// Redact nondeterminism log values (replace with zero-length placeholders).
    pub redact_nondeterminism_values: bool,
    /// Redact fleet node identifiers.
    pub redact_node_ids: bool,
    /// Additional custom redaction keys.
    pub custom_redaction_keys: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// BundleArtifactKind — typed artifact categories
// ---------------------------------------------------------------------------

/// Category of artifact stored in a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BundleArtifactKind {
    /// Deterministic trace record from causal replay.
    Trace,
    /// Evidence ledger entry.
    Evidence,
    /// Optimization receipt.
    OptReceipt,
    /// Fleet quorum checkpoint.
    QuorumCheckpoint,
    /// Nondeterminism log.
    NondeterminismLog,
    /// Counterfactual analysis result.
    CounterfactualResult,
    /// Policy snapshot (serialized policy config).
    PolicySnapshot,
}

impl fmt::Display for BundleArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => f.write_str("trace"),
            Self::Evidence => f.write_str("evidence"),
            Self::OptReceipt => f.write_str("opt-receipt"),
            Self::QuorumCheckpoint => f.write_str("quorum-checkpoint"),
            Self::NondeterminismLog => f.write_str("nondeterminism-log"),
            Self::CounterfactualResult => f.write_str("counterfactual-result"),
            Self::PolicySnapshot => f.write_str("policy-snapshot"),
        }
    }
}

// ---------------------------------------------------------------------------
// ArtifactEntry — inventory entry in manifest
// ---------------------------------------------------------------------------

/// A single artifact entry in the bundle manifest's content inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Unique artifact identifier within this bundle.
    pub artifact_id: String,
    /// Category of this artifact.
    pub kind: BundleArtifactKind,
    /// Content hash of the serialized artifact.
    pub content_hash: ContentHash,
    /// Whether this artifact has been redacted.
    pub redacted: bool,
    /// Size in bytes of the serialized artifact.
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// BundleManifest — top-level metadata and integrity root
// ---------------------------------------------------------------------------

/// Top-level bundle manifest containing content inventory and integrity root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle format version.
    pub format_version: BundleFormatVersion,
    /// Unique bundle identifier.
    pub bundle_id: EngineObjectId,
    /// Incident identifier this bundle describes.
    pub incident_id: String,
    /// Security epoch at bundle creation.
    pub creation_epoch: SecurityEpoch,
    /// Timestamp of bundle creation (nanoseconds).
    pub created_at_ns: u64,
    /// Producing node's verification key identifier.
    pub producer_key_id: String,
    /// Merkle root over all artifact content hashes.
    pub merkle_root: ContentHash,
    /// Ordered content inventory (deterministic by artifact_id).
    pub artifacts: BTreeMap<String, ArtifactEntry>,
    /// Redaction policy applied to this bundle.
    pub redaction_policy: RedactionPolicy,
    /// Trace time window: start tick.
    pub window_start_tick: u64,
    /// Trace time window: end tick.
    pub window_end_tick: u64,
    /// Free-form metadata (deterministic ordering).
    pub metadata: BTreeMap<String, String>,
    /// Bundle signature over the manifest (excluding this field).
    pub signature: Vec<u8>,
}

impl BundleManifest {
    /// Bytes used for signing (everything except the signature field itself).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.format_version.major.to_be_bytes());
        buf.extend_from_slice(&self.format_version.minor.to_be_bytes());
        buf.extend_from_slice(self.bundle_id.as_bytes());
        buf.extend_from_slice(self.incident_id.as_bytes());
        buf.extend_from_slice(&self.creation_epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.created_at_ns.to_be_bytes());
        buf.extend_from_slice(self.producer_key_id.as_bytes());
        buf.extend_from_slice(self.merkle_root.as_bytes());
        for (aid, entry) in &self.artifacts {
            buf.extend_from_slice(aid.as_bytes());
            buf.extend_from_slice(entry.content_hash.as_bytes());
        }
        buf.extend_from_slice(&self.window_start_tick.to_be_bytes());
        buf.extend_from_slice(&self.window_end_tick.to_be_bytes());
        for (k, v) in &self.metadata {
            buf.extend_from_slice(k.as_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// PolicySnapshot — serialized policy configuration
// ---------------------------------------------------------------------------

/// A serialized policy configuration active during the incident window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// Policy identifier.
    pub policy_id: String,
    /// Policy version string.
    pub policy_version: String,
    /// Security epoch this policy was active at.
    pub active_epoch: SecurityEpoch,
    /// Content hash of the full policy configuration.
    pub config_hash: ContentHash,
    /// Serialized policy configuration (opaque bytes).
    pub config_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// CounterfactualResult — bundled counterfactual analysis
// ---------------------------------------------------------------------------

/// A counterfactual analysis result stored in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualResult {
    /// The configuration used for this counterfactual run.
    pub config: CounterfactualConfig,
    /// The action delta report produced.
    pub delta_report: ActionDeltaReport,
    /// Trace ID this analysis was performed on.
    pub source_trace_id: String,
}

// ---------------------------------------------------------------------------
// IncidentReplayBundle — the complete bundle
// ---------------------------------------------------------------------------

/// A self-contained incident replay artifact bundle.
///
/// Contains all artifacts needed for an external auditor to independently
/// verify security incident investigations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReplayBundle {
    /// Bundle manifest with integrity root and inventory.
    pub manifest: BundleManifest,
    /// Deterministic trace records.
    pub traces: BTreeMap<String, TraceRecord>,
    /// Evidence ledger entries.
    pub evidence_entries: BTreeMap<String, EvidenceEntry>,
    /// Optimization receipts.
    pub opt_receipts: BTreeMap<String, OptReceipt>,
    /// Fleet quorum checkpoints.
    pub quorum_checkpoints: BTreeMap<String, QuorumCheckpoint>,
    /// Nondeterminism logs (keyed by trace ID).
    pub nondeterminism_logs: BTreeMap<String, NondeterminismLog>,
    /// Counterfactual analysis results.
    pub counterfactual_results: BTreeMap<String, CounterfactualResult>,
    /// Policy snapshots active during the incident.
    pub policy_snapshots: BTreeMap<String, PolicySnapshot>,
}

// ---------------------------------------------------------------------------
// Merkle tree — content-addressed integrity over artifacts
// ---------------------------------------------------------------------------

/// Compute a Merkle root from an ordered sequence of content hashes.
///
/// Empty input yields the hash of an empty byte slice.  A single leaf
/// is its own root.  Internal nodes hash the concatenation of their
/// children.
pub fn compute_merkle_root(leaves: &[ContentHash]) -> ContentHash {
    if leaves.is_empty() {
        return ContentHash::compute(b"");
    }
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let mut current_level: Vec<ContentHash> = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(current_level[i].as_bytes());
                combined.extend_from_slice(current_level[i + 1].as_bytes());
                next_level.push(ContentHash::compute(&combined));
            } else {
                // Odd leaf: promote unchanged.
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
    }
    current_level.into_iter().next().unwrap()
}

/// Build a Merkle proof (sibling hashes) for the leaf at `index`.
pub fn build_merkle_proof(leaves: &[ContentHash], index: usize) -> Vec<(ContentHash, bool)> {
    if leaves.len() <= 1 || index >= leaves.len() {
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut current_level: Vec<ContentHash> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        if sibling_idx < current_level.len() {
            // true = sibling is on the right
            proof.push((current_level[sibling_idx].clone(), idx.is_multiple_of(2)));
        }

        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(current_level[i].as_bytes());
                combined.extend_from_slice(current_level[i + 1].as_bytes());
                next_level.push(ContentHash::compute(&combined));
            } else {
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
        idx /= 2;
    }
    proof
}

/// Verify a Merkle proof for a given leaf against an expected root.
pub fn verify_merkle_proof(
    leaf: &ContentHash,
    proof: &[(ContentHash, bool)],
    expected_root: &ContentHash,
) -> bool {
    let mut current = leaf.clone();
    for (sibling, sibling_is_right) in proof {
        let mut combined = Vec::with_capacity(64);
        if *sibling_is_right {
            combined.extend_from_slice(current.as_bytes());
            combined.extend_from_slice(sibling.as_bytes());
        } else {
            combined.extend_from_slice(sibling.as_bytes());
            combined.extend_from_slice(current.as_bytes());
        }
        current = ContentHash::compute(&combined);
    }
    &current == expected_root
}

fn serialized_content_hash<T: Serialize>(value: &T) -> Result<ContentHash, serde_json::Error> {
    let json = serde_json::to_vec(value)?;
    Ok(ContentHash::compute(&json))
}

fn serialized_content_hash_and_size<T: Serialize>(
    value: &T,
) -> Result<(ContentHash, u64), serde_json::Error> {
    let json = serde_json::to_vec(value)?;
    Ok((ContentHash::compute(&json), json.len() as u64))
}

// ---------------------------------------------------------------------------
// VerificationCheck — individual check result
// ---------------------------------------------------------------------------

/// Outcome of a single verification check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome {
    /// Check passed.
    Pass,
    /// Check failed with details.
    Fail { reason: String },
    /// Check was skipped (e.g., redacted artifacts).
    Skipped { reason: String },
}

impl CheckOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
}

/// A single verification check within a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheck {
    /// Human-readable check name.
    pub name: String,
    /// Check category.
    pub category: VerificationCategory,
    /// Outcome of this check.
    pub outcome: CheckOutcome,
}

/// Category of verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationCategory {
    /// Bundle-level integrity (Merkle root, signatures).
    Integrity,
    /// Artifact-level content hash checks.
    ArtifactHash,
    /// Replay fidelity checks.
    Replay,
    /// Receipt signature chain checks.
    ReceiptChain,
    /// Counterfactual analysis checks.
    Counterfactual,
    /// Format and version compatibility.
    Compatibility,
}

impl fmt::Display for VerificationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integrity => f.write_str("integrity"),
            Self::ArtifactHash => f.write_str("artifact-hash"),
            Self::Replay => f.write_str("replay"),
            Self::ReceiptChain => f.write_str("receipt-chain"),
            Self::Counterfactual => f.write_str("counterfactual"),
            Self::Compatibility => f.write_str("compatibility"),
        }
    }
}

// ---------------------------------------------------------------------------
// VerificationReport — structured verification output
// ---------------------------------------------------------------------------

/// Structured report from a verification operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Bundle identifier that was verified.
    pub bundle_id: EngineObjectId,
    /// Incident identifier.
    pub incident_id: String,
    /// Overall pass/fail.
    pub passed: bool,
    /// Individual check results.
    pub checks: Vec<VerificationCheck>,
    /// Summary counts by category.
    pub summary: BTreeMap<String, CategorySummary>,
    /// Timestamp of verification (nanoseconds).
    pub verified_at_ns: u64,
    /// Verifier version.
    pub verifier_version: BundleFormatVersion,
}

/// Summary counts for a verification category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategorySummary {
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
}

impl VerificationReport {
    fn new(bundle_id: EngineObjectId, incident_id: String, verified_at_ns: u64) -> Self {
        Self {
            bundle_id,
            incident_id,
            passed: true,
            checks: Vec::new(),
            summary: BTreeMap::new(),
            verified_at_ns,
            verifier_version: BUNDLE_FORMAT_VERSION,
        }
    }

    fn add_check(&mut self, check: VerificationCheck) {
        let cat = check.category.to_string();
        let entry = self.summary.entry(cat).or_insert(CategorySummary {
            passed: 0,
            failed: 0,
            skipped: 0,
        });
        match &check.outcome {
            CheckOutcome::Pass => entry.passed += 1,
            CheckOutcome::Fail { .. } => {
                entry.failed += 1;
                self.passed = false;
            }
            CheckOutcome::Skipped { .. } => entry.skipped += 1,
        }
        self.checks.push(check);
    }

    /// Count of passed checks.
    pub fn pass_count(&self) -> u64 {
        self.checks.iter().filter(|c| c.outcome.is_pass()).count() as u64
    }

    /// Count of failed checks.
    pub fn fail_count(&self) -> u64 {
        self.checks.iter().filter(|c| c.outcome.is_fail()).count() as u64
    }
}

// ---------------------------------------------------------------------------
// BundleInspection — human-readable summary
// ---------------------------------------------------------------------------

/// Human-readable summary of bundle contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInspection {
    /// Bundle identifier.
    pub bundle_id: EngineObjectId,
    /// Incident identifier.
    pub incident_id: String,
    /// Format version.
    pub format_version: BundleFormatVersion,
    /// Creation timestamp (nanoseconds).
    pub created_at_ns: u64,
    /// Creation epoch.
    pub creation_epoch: SecurityEpoch,
    /// Producer key identifier.
    pub producer_key_id: String,
    /// Trace window (start_tick, end_tick).
    pub window: (u64, u64),
    /// Artifact counts by kind.
    pub artifact_counts: BTreeMap<String, u64>,
    /// Total artifact size in bytes.
    pub total_size_bytes: u64,
    /// Number of redacted artifacts.
    pub redacted_count: u64,
    /// Trace IDs included.
    pub trace_ids: Vec<String>,
    /// Epochs covered.
    pub epochs: BTreeSet<u64>,
    /// Metadata.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// BundleBuilder — ergonomic bundle construction
// ---------------------------------------------------------------------------

/// Builder for constructing an `IncidentReplayBundle`.
pub struct BundleBuilder {
    incident_id: String,
    creation_epoch: SecurityEpoch,
    created_at_ns: u64,
    producer_key_id: String,
    signing_key: SigningKey,
    redaction_policy: RedactionPolicy,
    window_start_tick: u64,
    window_end_tick: u64,
    metadata: BTreeMap<String, String>,
    traces: BTreeMap<String, TraceRecord>,
    evidence_entries: BTreeMap<String, EvidenceEntry>,
    opt_receipts: BTreeMap<String, OptReceipt>,
    quorum_checkpoints: BTreeMap<String, QuorumCheckpoint>,
    nondeterminism_logs: BTreeMap<String, NondeterminismLog>,
    counterfactual_results: BTreeMap<String, CounterfactualResult>,
    policy_snapshots: BTreeMap<String, PolicySnapshot>,
}

impl BundleBuilder {
    /// Create a new builder for an incident bundle.
    pub fn new(
        incident_id: String,
        creation_epoch: SecurityEpoch,
        created_at_ns: u64,
        producer_key_id: String,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            incident_id,
            creation_epoch,
            created_at_ns,
            producer_key_id,
            signing_key,
            redaction_policy: RedactionPolicy::default(),
            window_start_tick: 0,
            window_end_tick: 0,
            metadata: BTreeMap::new(),
            traces: BTreeMap::new(),
            evidence_entries: BTreeMap::new(),
            opt_receipts: BTreeMap::new(),
            quorum_checkpoints: BTreeMap::new(),
            nondeterminism_logs: BTreeMap::new(),
            counterfactual_results: BTreeMap::new(),
            policy_snapshots: BTreeMap::new(),
        }
    }

    /// Set the trace time window.
    pub fn window(mut self, start_tick: u64, end_tick: u64) -> Self {
        self.window_start_tick = start_tick;
        self.window_end_tick = end_tick;
        self
    }

    /// Set the redaction policy.
    pub fn redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }

    /// Add a metadata entry.
    pub fn meta(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add a trace record.
    pub fn trace(mut self, id: String, trace: TraceRecord) -> Self {
        self.traces.insert(id, trace);
        self
    }

    /// Add an evidence entry.
    pub fn evidence(mut self, id: String, entry: EvidenceEntry) -> Self {
        self.evidence_entries.insert(id, entry);
        self
    }

    /// Add an optimization receipt.
    pub fn receipt(mut self, id: String, receipt: OptReceipt) -> Self {
        self.opt_receipts.insert(id, receipt);
        self
    }

    /// Add a quorum checkpoint.
    pub fn checkpoint(mut self, id: String, cp: QuorumCheckpoint) -> Self {
        self.quorum_checkpoints.insert(id, cp);
        self
    }

    /// Add a nondeterminism log.
    pub fn nondeterminism(mut self, trace_id: String, log: NondeterminismLog) -> Self {
        self.nondeterminism_logs.insert(trace_id, log);
        self
    }

    /// Add a counterfactual result.
    pub fn counterfactual(mut self, id: String, result: CounterfactualResult) -> Self {
        self.counterfactual_results.insert(id, result);
        self
    }

    /// Add a policy snapshot.
    pub fn policy(mut self, id: String, snapshot: PolicySnapshot) -> Self {
        self.policy_snapshots.insert(id, snapshot);
        self
    }

    /// Build the bundle with computed Merkle root and signature.
    pub fn build(self) -> Result<IncidentReplayBundle, BundleError> {
        let mut artifact_entries = BTreeMap::new();

        // Collect all artifact entries with composite keys ("{kind}:{id}") to
        // prevent collisions across artifact types sharing the same user-id.
        for (id, trace) in &self.traces {
            let (hash, size_bytes) = serialized_content_hash_and_size(trace)
                .map_err(|e| BundleError::IdDerivation(format!("serialize trace {id}: {e}")))?;
            let key = format!("{}:{id}", BundleArtifactKind::Trace);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::Trace,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, entry) in &self.evidence_entries {
            let (hash, size_bytes) = serialized_content_hash_and_size(entry).map_err(|e| {
                BundleError::IdDerivation(format!("serialize evidence entry {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::Evidence);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::Evidence,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, receipt) in &self.opt_receipts {
            let (hash, size_bytes) = serialized_content_hash_and_size(receipt).map_err(|e| {
                BundleError::IdDerivation(format!("serialize optimization receipt {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::OptReceipt);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::OptReceipt,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, cp) in &self.quorum_checkpoints {
            let (hash, size_bytes) = serialized_content_hash_and_size(cp).map_err(|e| {
                BundleError::IdDerivation(format!("serialize quorum checkpoint {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::QuorumCheckpoint);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::QuorumCheckpoint,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, log) in &self.nondeterminism_logs {
            let (hash, size_bytes) = serialized_content_hash_and_size(log).map_err(|e| {
                BundleError::IdDerivation(format!("serialize nondeterminism log {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::NondeterminismLog);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::NondeterminismLog,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, cf) in &self.counterfactual_results {
            let (hash, size_bytes) = serialized_content_hash_and_size(cf).map_err(|e| {
                BundleError::IdDerivation(format!("serialize counterfactual result {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::CounterfactualResult);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::CounterfactualResult,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        for (id, snap) in &self.policy_snapshots {
            let (hash, size_bytes) = serialized_content_hash_and_size(snap).map_err(|e| {
                BundleError::IdDerivation(format!("serialize policy snapshot {id}: {e}"))
            })?;
            let key = format!("{}:{id}", BundleArtifactKind::PolicySnapshot);
            artifact_entries.insert(
                key,
                ArtifactEntry {
                    artifact_id: id.clone(),
                    kind: BundleArtifactKind::PolicySnapshot,
                    content_hash: hash,
                    redacted: false,
                    size_bytes,
                },
            );
        }

        if artifact_entries.is_empty() {
            return Err(BundleError::EmptyBundle);
        }

        // Leaf hashes in BTreeMap order — matches verify_integrity() which
        // also iterates artifact_entries.values() in sorted-key order.
        let leaf_hashes: Vec<ContentHash> =
            artifact_entries.values().map(|e| e.content_hash).collect();
        let merkle_root = compute_merkle_root(&leaf_hashes);

        // Derive bundle ID.
        let schema_id = SchemaId::from_definition(BUNDLE_SCHEMA_DEF);
        let mut canonical = Vec::new();
        canonical.extend_from_slice(self.incident_id.as_bytes());
        canonical.extend_from_slice(&self.creation_epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(&self.created_at_ns.to_be_bytes());
        canonical.extend_from_slice(merkle_root.as_bytes());

        let bundle_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            BUNDLE_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| BundleError::IdDerivation(e.to_string()))?;

        let mut manifest = BundleManifest {
            format_version: BUNDLE_FORMAT_VERSION,
            bundle_id,
            incident_id: self.incident_id,
            creation_epoch: self.creation_epoch,
            created_at_ns: self.created_at_ns,
            producer_key_id: self.producer_key_id,
            merkle_root,
            artifacts: artifact_entries,
            redaction_policy: self.redaction_policy,
            window_start_tick: self.window_start_tick,
            window_end_tick: self.window_end_tick,
            metadata: self.metadata,
            signature: Vec::new(),
        };

        // Sign the manifest using the proper signature scheme.
        let signing_bytes = manifest.signing_bytes();
        let sig = sign_preimage(&self.signing_key, &signing_bytes)
            .map_err(|e| BundleError::IdDerivation(format!("signature: {e}")))?;
        manifest.signature = sig.to_bytes().to_vec();

        Ok(IncidentReplayBundle {
            manifest,
            traces: self.traces,
            evidence_entries: self.evidence_entries,
            opt_receipts: self.opt_receipts,
            quorum_checkpoints: self.quorum_checkpoints,
            nondeterminism_logs: self.nondeterminism_logs,
            counterfactual_results: self.counterfactual_results,
            policy_snapshots: self.policy_snapshots,
        })
    }
}

// ---------------------------------------------------------------------------
// BundleVerifier — standalone verification engine
// ---------------------------------------------------------------------------

/// Standalone verifier for incident replay bundles.
///
/// Does not require a running FrankenEngine instance.
pub struct BundleVerifier {
    /// Supported format version.
    supported_version: BundleFormatVersion,
}

impl Default for BundleVerifier {
    fn default() -> Self {
        Self {
            supported_version: BUNDLE_FORMAT_VERSION,
        }
    }
}

impl BundleVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify bundle integrity: format version, Merkle root, artifact hashes.
    pub fn verify_integrity(
        &self,
        bundle: &IncidentReplayBundle,
        current_ns: u64,
    ) -> VerificationReport {
        let mut report = VerificationReport::new(
            bundle.manifest.bundle_id.clone(),
            bundle.manifest.incident_id.clone(),
            current_ns,
        );

        // Check version compatibility.
        report.add_check(VerificationCheck {
            name: "format-version-compatible".to_string(),
            category: VerificationCategory::Compatibility,
            outcome: if self
                .supported_version
                .is_compatible_with(&bundle.manifest.format_version)
            {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail {
                    reason: format!(
                        "bundle version {} not compatible with reader {}",
                        bundle.manifest.format_version, self.supported_version
                    ),
                }
            },
        });

        // Verify individual artifact content hashes.
        self.verify_artifact_hashes(bundle, &mut report);

        // Verify Merkle root.
        let leaf_hashes: Vec<ContentHash> = bundle
            .manifest
            .artifacts
            .values()
            .map(|a| a.content_hash)
            .collect();
        let computed_root = compute_merkle_root(&leaf_hashes);
        report.add_check(VerificationCheck {
            name: "merkle-root-valid".to_string(),
            category: VerificationCategory::Integrity,
            outcome: if computed_root == bundle.manifest.merkle_root {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail {
                    reason: format!(
                        "computed root {} != manifest root {}",
                        computed_root.to_hex(),
                        bundle.manifest.merkle_root.to_hex()
                    ),
                }
            },
        });

        // Check bundle is non-empty.
        report.add_check(VerificationCheck {
            name: "bundle-non-empty".to_string(),
            category: VerificationCategory::Integrity,
            outcome: if bundle.manifest.artifacts.is_empty() {
                CheckOutcome::Fail {
                    reason: "bundle contains no artifacts".to_string(),
                }
            } else {
                CheckOutcome::Pass
            },
        });

        report
    }

    /// Verify bundle signature against a provided verification key.
    pub fn verify_signature(
        &self,
        bundle: &IncidentReplayBundle,
        verification_key: &VerificationKey,
        current_ns: u64,
    ) -> VerificationReport {
        let mut report = VerificationReport::new(
            bundle.manifest.bundle_id.clone(),
            bundle.manifest.incident_id.clone(),
            current_ns,
        );

        let signing_bytes = bundle.manifest.signing_bytes();
        let sig_valid = if bundle.manifest.signature.len() == 64 {
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&bundle.manifest.signature);
            let sig = Signature::from_bytes(sig_bytes);
            sig_verify(verification_key, &signing_bytes, &sig).is_ok()
        } else {
            false
        };

        report.add_check(VerificationCheck {
            name: "bundle-signature-valid".to_string(),
            category: VerificationCategory::Integrity,
            outcome: if sig_valid {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail {
                    reason: "signature does not match verification key".to_string(),
                }
            },
        });

        report
    }

    /// Re-execute traces from the bundle and verify bit-for-bit replay fidelity.
    pub fn verify_replay(
        &self,
        bundle: &IncidentReplayBundle,
        current_ns: u64,
    ) -> VerificationReport {
        let mut report = VerificationReport::new(
            bundle.manifest.bundle_id.clone(),
            bundle.manifest.incident_id.clone(),
            current_ns,
        );

        if bundle.traces.is_empty() {
            report.add_check(VerificationCheck {
                name: "replay-traces-present".to_string(),
                category: VerificationCategory::Replay,
                outcome: CheckOutcome::Skipped {
                    reason: "no traces in bundle".to_string(),
                },
            });
            return report;
        }

        let engine = CausalReplayEngine::new();

        for (trace_id, trace) in &bundle.traces {
            // Chain integrity.
            let chain_ok = trace.verify_chain_integrity().is_ok();
            report.add_check(VerificationCheck {
                name: format!("trace-chain-integrity:{trace_id}"),
                category: VerificationCategory::Replay,
                outcome: if chain_ok {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail {
                        reason: "trace chain integrity broken".to_string(),
                    }
                },
            });

            // Replay fidelity.
            match engine.replay(trace) {
                Ok(verdict) => {
                    report.add_check(VerificationCheck {
                        name: format!("replay-fidelity:{trace_id}"),
                        category: VerificationCategory::Replay,
                        outcome: if verdict.is_identical() {
                            CheckOutcome::Pass
                        } else {
                            CheckOutcome::Fail {
                                reason: format!(
                                    "replay diverged with {} differences",
                                    verdict.divergence_count()
                                ),
                            }
                        },
                    });
                }
                Err(e) => {
                    report.add_check(VerificationCheck {
                        name: format!("replay-fidelity:{trace_id}"),
                        category: VerificationCategory::Replay,
                        outcome: CheckOutcome::Fail {
                            reason: format!("replay error: {e}"),
                        },
                    });
                }
            }
        }

        report
    }

    /// Validate all optimization receipt signatures in the bundle.
    pub fn verify_receipts(
        &self,
        bundle: &IncidentReplayBundle,
        verification_keys: &BTreeMap<EngineObjectId, VerificationKey>,
        current_epoch: SecurityEpoch,
        current_ns: u64,
    ) -> VerificationReport {
        let mut report = VerificationReport::new(
            bundle.manifest.bundle_id.clone(),
            bundle.manifest.incident_id.clone(),
            current_ns,
        );

        if bundle.opt_receipts.is_empty() {
            report.add_check(VerificationCheck {
                name: "receipts-present".to_string(),
                category: VerificationCategory::ReceiptChain,
                outcome: CheckOutcome::Skipped {
                    reason: "no receipts in bundle".to_string(),
                },
            });
            return report;
        }

        for (receipt_id, receipt) in &bundle.opt_receipts {
            // Check if we have the signing key for this receipt.
            if let Some(vk) = verification_keys.get(&receipt.signer_key_id) {
                let sig_valid = receipt.verify_signature(vk.as_bytes());
                report.add_check(VerificationCheck {
                    name: format!("receipt-signature:{receipt_id}"),
                    category: VerificationCategory::ReceiptChain,
                    outcome: if sig_valid {
                        CheckOutcome::Pass
                    } else {
                        CheckOutcome::Fail {
                            reason: "receipt signature invalid".to_string(),
                        }
                    },
                });
            } else {
                report.add_check(VerificationCheck {
                    name: format!("receipt-signature:{receipt_id}"),
                    category: VerificationCategory::ReceiptChain,
                    outcome: CheckOutcome::Skipped {
                        reason: format!("no verification key for signer {}", receipt.signer_key_id),
                    },
                });
            }

            // Check epoch validity.
            report.add_check(VerificationCheck {
                name: format!("receipt-epoch:{receipt_id}"),
                category: VerificationCategory::ReceiptChain,
                outcome: if receipt.policy_epoch <= current_epoch {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail {
                        reason: format!(
                            "receipt epoch {} is in the future (current: {})",
                            receipt.policy_epoch.as_u64(),
                            current_epoch.as_u64()
                        ),
                    }
                },
            });
        }

        report
    }

    /// Re-run counterfactual analysis with auditor-specified parameters.
    pub fn verify_counterfactual(
        &self,
        bundle: &IncidentReplayBundle,
        configs: &[CounterfactualConfig],
        current_ns: u64,
    ) -> VerificationReport {
        let mut report = VerificationReport::new(
            bundle.manifest.bundle_id.clone(),
            bundle.manifest.incident_id.clone(),
            current_ns,
        );

        let engine = CausalReplayEngine::new();

        for config in configs {
            let branch_id = &config.branch_id;

            // Find the source trace.
            let trace_id_key = bundle
                .counterfactual_results
                .values()
                .find(|r| r.config.branch_id == *branch_id)
                .map(|r| r.source_trace_id.clone());

            let trace_id = match trace_id_key {
                Some(ref tid) => tid,
                None => {
                    // No existing result for this branch — run fresh.
                    // Pick the first trace as default.
                    match bundle.traces.keys().next() {
                        Some(tid) => tid,
                        None => {
                            report.add_check(VerificationCheck {
                                name: format!("counterfactual:{branch_id}"),
                                category: VerificationCategory::Counterfactual,
                                outcome: CheckOutcome::Fail {
                                    reason: "no traces available for counterfactual".to_string(),
                                },
                            });
                            continue;
                        }
                    }
                }
            };

            if let Some(trace) = bundle.traces.get(trace_id) {
                match engine.counterfactual_branch(trace, config.clone()) {
                    Ok(fresh_report) => {
                        // If there's a bundled result, compare.
                        if let Some(bundled) = bundle.counterfactual_results.get(branch_id) {
                            let divergence_match = fresh_report.divergence_count()
                                == bundled.delta_report.divergence_count();
                            let improvement_match = fresh_report.is_improvement()
                                == bundled.delta_report.is_improvement();

                            report.add_check(VerificationCheck {
                                name: format!("counterfactual-match:{branch_id}"),
                                category: VerificationCategory::Counterfactual,
                                outcome: if divergence_match && improvement_match {
                                    CheckOutcome::Pass
                                } else {
                                    CheckOutcome::Fail {
                                        reason: format!(
                                            "fresh analysis differs: divergence_count {}!={}, improvement {}!={}",
                                            fresh_report.divergence_count(),
                                            bundled.delta_report.divergence_count(),
                                            fresh_report.is_improvement(),
                                            bundled.delta_report.is_improvement(),
                                        ),
                                    }
                                },
                            });
                        } else {
                            report.add_check(VerificationCheck {
                                name: format!("counterfactual-fresh:{branch_id}"),
                                category: VerificationCategory::Counterfactual,
                                outcome: CheckOutcome::Pass,
                            });
                        }
                    }
                    Err(e) => {
                        report.add_check(VerificationCheck {
                            name: format!("counterfactual:{branch_id}"),
                            category: VerificationCategory::Counterfactual,
                            outcome: CheckOutcome::Fail {
                                reason: format!("counterfactual error: {e}"),
                            },
                        });
                    }
                }
            } else {
                report.add_check(VerificationCheck {
                    name: format!("counterfactual:{branch_id}"),
                    category: VerificationCategory::Counterfactual,
                    outcome: CheckOutcome::Fail {
                        reason: format!("trace {trace_id} not found in bundle"),
                    },
                });
            }
        }

        report
    }

    /// Generate a human-readable inspection of bundle contents.
    pub fn inspect(&self, bundle: &IncidentReplayBundle) -> BundleInspection {
        let mut artifact_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut total_size_bytes = 0u64;
        let mut redacted_count = 0u64;

        for entry in bundle.manifest.artifacts.values() {
            *artifact_counts.entry(entry.kind.to_string()).or_insert(0) += 1;
            total_size_bytes += entry.size_bytes;
            if entry.redacted {
                redacted_count += 1;
            }
        }

        let trace_ids: Vec<String> = bundle.traces.keys().cloned().collect();

        let mut epochs = BTreeSet::new();
        epochs.insert(bundle.manifest.creation_epoch.as_u64());
        for trace in bundle.traces.values() {
            epochs.insert(trace.start_epoch.as_u64());
            epochs.insert(trace.end_epoch.as_u64());
        }

        BundleInspection {
            bundle_id: bundle.manifest.bundle_id.clone(),
            incident_id: bundle.manifest.incident_id.clone(),
            format_version: bundle.manifest.format_version,
            created_at_ns: bundle.manifest.created_at_ns,
            creation_epoch: bundle.manifest.creation_epoch,
            producer_key_id: bundle.manifest.producer_key_id.clone(),
            window: (
                bundle.manifest.window_start_tick,
                bundle.manifest.window_end_tick,
            ),
            artifact_counts,
            total_size_bytes,
            redacted_count,
            trace_ids,
            epochs,
            metadata: bundle.manifest.metadata.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn verify_artifact_hashes(
        &self,
        bundle: &IncidentReplayBundle,
        report: &mut VerificationReport,
    ) {
        for entry in bundle.manifest.artifacts.values() {
            let aid = &entry.artifact_id;
            let check_name = format!("artifact-hash:{}:{aid}", entry.kind);
            let computed_hash: Result<Option<ContentHash>, String> = match entry.kind {
                BundleArtifactKind::Trace => bundle
                    .traces
                    .get(aid)
                    .map(|t| {
                        serialized_content_hash(t)
                            .map_err(|e| format!("failed to serialize trace artifact {aid}: {e}"))
                    })
                    .transpose(),
                BundleArtifactKind::Evidence => bundle
                    .evidence_entries
                    .get(aid)
                    .map(|e| {
                        serialized_content_hash(e).map_err(|err| {
                            format!("failed to serialize evidence artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
                BundleArtifactKind::OptReceipt => bundle
                    .opt_receipts
                    .get(aid)
                    .map(|r| {
                        serialized_content_hash(r).map_err(|err| {
                            format!("failed to serialize receipt artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
                BundleArtifactKind::QuorumCheckpoint => bundle
                    .quorum_checkpoints
                    .get(aid)
                    .map(|c| {
                        serialized_content_hash(c).map_err(|err| {
                            format!("failed to serialize quorum artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
                BundleArtifactKind::NondeterminismLog => bundle
                    .nondeterminism_logs
                    .get(aid)
                    .map(|l| {
                        serialized_content_hash(l).map_err(|err| {
                            format!("failed to serialize nondeterminism artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
                BundleArtifactKind::CounterfactualResult => bundle
                    .counterfactual_results
                    .get(aid)
                    .map(|r| {
                        serialized_content_hash(r).map_err(|err| {
                            format!("failed to serialize counterfactual artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
                BundleArtifactKind::PolicySnapshot => bundle
                    .policy_snapshots
                    .get(aid)
                    .map(|s| {
                        serialized_content_hash(s).map_err(|err| {
                            format!("failed to serialize policy artifact {aid}: {err}")
                        })
                    })
                    .transpose(),
            };

            match computed_hash {
                Ok(Some(hash)) => {
                    report.add_check(VerificationCheck {
                        name: check_name.clone(),
                        category: VerificationCategory::ArtifactHash,
                        outcome: if hash == entry.content_hash {
                            CheckOutcome::Pass
                        } else {
                            CheckOutcome::Fail {
                                reason: format!(
                                    "hash mismatch: computed {} != manifest {}",
                                    hash.to_hex(),
                                    entry.content_hash.to_hex()
                                ),
                            }
                        },
                    });
                }
                Ok(None) => {
                    report.add_check(VerificationCheck {
                        name: check_name.clone(),
                        category: VerificationCategory::ArtifactHash,
                        outcome: if entry.redacted {
                            CheckOutcome::Skipped {
                                reason: "artifact redacted".to_string(),
                            }
                        } else {
                            CheckOutcome::Fail {
                                reason: "artifact missing from bundle data".to_string(),
                            }
                        },
                    });
                }
                Err(reason) => {
                    report.add_check(VerificationCheck {
                        name: check_name,
                        category: VerificationCategory::ArtifactHash,
                        outcome: CheckOutcome::Fail { reason },
                    });
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal_replay::{
        DecisionSnapshot, NondeterminismSource, RecorderConfig, RecordingMode, TraceRecorder,
    };
    use crate::evidence_ledger::EvidenceEntryBuilder;
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::SigningKey;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_signing_key() -> SigningKey {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        SigningKey::from_bytes(key)
    }

    fn test_verification_key() -> VerificationKey {
        test_signing_key().verification_key()
    }

    fn make_trace(trace_id: &str, num_decisions: usize) -> TraceRecord {
        let key = test_signing_key();
        let config = RecorderConfig {
            trace_id: trace_id.to_string(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(100),
            start_tick: 1000,
            signing_key: key.as_bytes().to_vec(),
        };
        let mut recorder = TraceRecorder::new(config);

        recorder.record_nondeterminism(
            NondeterminismSource::Timestamp,
            vec![0, 0, 0, 0, 0, 0, 3, 232],
            1001,
            None,
        );

        for i in 0..num_decisions {
            let snapshot = DecisionSnapshot {
                decision_index: i as u64,
                trace_id: trace_id.to_string(),
                decision_id: format!("decision-{i}"),
                policy_id: "test-policy".to_string(),
                policy_version: 1,
                epoch: SecurityEpoch::from_raw(100),
                tick: 1000 + i as u64,
                threshold_millionths: 500_000,
                loss_matrix: BTreeMap::new(),
                evidence_hashes: Vec::new(),
                chosen_action: "allow".to_string(),
                outcome_millionths: 100_000,
                extension_id: "ext-001".to_string(),
                nondeterminism_range: (0, 0),
            };
            recorder.record_decision(snapshot);
        }

        recorder.finalize()
    }

    fn make_evidence_entry(_entry_id: &str) -> EvidenceEntry {
        use crate::evidence_ledger::{ChosenAction, DecisionType};
        EvidenceEntryBuilder::new(
            "trace-001",
            "decision-001",
            "policy-001",
            SecurityEpoch::from_raw(100),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1000)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "test rationale".to_string(),
        })
        .build()
        .unwrap()
    }

    fn make_policy_snapshot(policy_id: &str) -> PolicySnapshot {
        PolicySnapshot {
            policy_id: policy_id.to_string(),
            policy_version: "1.0".to_string(),
            active_epoch: SecurityEpoch::from_raw(100),
            config_hash: ContentHash::compute(b"test-policy-config"),
            config_bytes: b"test-policy-config".to_vec(),
        }
    }

    fn make_nondeterminism_log() -> NondeterminismLog {
        let mut log = NondeterminismLog::new();
        log.append(
            NondeterminismSource::Timestamp,
            vec![0, 0, 0, 0, 0, 0, 3, 232],
            1001,
            None,
        );
        log.append(
            NondeterminismSource::RandomValue,
            vec![42, 43, 44],
            1002,
            Some("ext-001".to_string()),
        );
        log
    }

    fn build_test_bundle() -> IncidentReplayBundle {
        let key = test_signing_key();
        BundleBuilder::new(
            "incident-001".to_string(),
            SecurityEpoch::from_raw(100),
            5000,
            "producer-key-1".to_string(),
            key,
        )
        .window(1000, 2000)
        .meta("severity".to_string(), "high".to_string())
        .trace("trace-001".to_string(), make_trace("trace-001", 3))
        .evidence("evidence-001".to_string(), make_evidence_entry("ev-001"))
        .nondeterminism("trace-001".to_string(), make_nondeterminism_log())
        .policy("policy-001".to_string(), make_policy_snapshot("policy-001"))
        .build()
        .expect("bundle build should succeed")
    }

    // -----------------------------------------------------------------------
    // BundleFormatVersion
    // -----------------------------------------------------------------------

    #[test]
    fn version_compatibility_same_version() {
        let v1 = BundleFormatVersion { major: 1, minor: 0 };
        assert!(v1.is_compatible_with(&v1));
    }

    #[test]
    fn version_compatibility_higher_minor() {
        let reader = BundleFormatVersion { major: 1, minor: 1 };
        let bundle = BundleFormatVersion { major: 1, minor: 0 };
        assert!(reader.is_compatible_with(&bundle));
    }

    #[test]
    fn version_incompatibility_lower_minor() {
        let reader = BundleFormatVersion { major: 1, minor: 0 };
        let bundle = BundleFormatVersion { major: 1, minor: 1 };
        assert!(!reader.is_compatible_with(&bundle));
    }

    #[test]
    fn version_incompatibility_different_major() {
        let reader = BundleFormatVersion { major: 2, minor: 0 };
        let bundle = BundleFormatVersion { major: 1, minor: 0 };
        assert!(!reader.is_compatible_with(&bundle));
    }

    #[test]
    fn version_display() {
        let v = BundleFormatVersion { major: 1, minor: 2 };
        assert_eq!(v.to_string(), "1.2");
    }

    // -----------------------------------------------------------------------
    // Merkle tree
    // -----------------------------------------------------------------------

    #[test]
    fn merkle_root_empty_leaves() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, ContentHash::compute(b""));
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = ContentHash::compute(b"hello");
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = ContentHash::compute(b"a");
        let b = ContentHash::compute(b"b");
        let root = compute_merkle_root(&[a.clone(), b.clone()]);

        let mut combined = Vec::new();
        combined.extend_from_slice(a.as_bytes());
        combined.extend_from_slice(b.as_bytes());
        assert_eq!(root, ContentHash::compute(&combined));
    }

    #[test]
    fn merkle_root_deterministic() {
        let leaves: Vec<ContentHash> = (0..7)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let root1 = compute_merkle_root(&leaves);
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root1, root2);
    }

    #[test]
    fn merkle_root_odd_leaves() {
        let leaves: Vec<ContentHash> = (0..5)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = compute_merkle_root(&leaves);
        // Should not panic, should produce a valid root.
        assert_ne!(root, ContentHash::compute(b""));
    }

    #[test]
    fn merkle_proof_roundtrip() {
        let leaves: Vec<ContentHash> = (0..8)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = compute_merkle_root(&leaves);

        for idx in 0..leaves.len() {
            let proof = build_merkle_proof(&leaves, idx);
            assert!(
                verify_merkle_proof(&leaves[idx], &proof, &root),
                "proof failed for index {idx}"
            );
        }
    }

    #[test]
    fn merkle_proof_detects_wrong_leaf() {
        let leaves: Vec<ContentHash> = (0..4)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = compute_merkle_root(&leaves);
        let proof = build_merkle_proof(&leaves, 0);

        let wrong_leaf = ContentHash::compute(b"wrong");
        assert!(!verify_merkle_proof(&wrong_leaf, &proof, &root));
    }

    #[test]
    fn merkle_proof_single_leaf() {
        let leaf = ContentHash::compute(b"only");
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        let proof = build_merkle_proof(std::slice::from_ref(&leaf), 0);
        assert!(proof.is_empty());
        assert!(verify_merkle_proof(&leaf, &proof, &root));
    }

    #[test]
    fn merkle_proof_odd_tree() {
        let leaves: Vec<ContentHash> = (0..5)
            .map(|i| ContentHash::compute(format!("odd-{i}").as_bytes()))
            .collect();
        let root = compute_merkle_root(&leaves);

        for idx in 0..leaves.len() {
            let proof = build_merkle_proof(&leaves, idx);
            assert!(
                verify_merkle_proof(&leaves[idx], &proof, &root),
                "odd tree proof failed for index {idx}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // BundleBuilder
    // -----------------------------------------------------------------------

    #[test]
    fn build_minimal_bundle() {
        let key = test_signing_key();
        let bundle = BundleBuilder::new(
            "incident-min".to_string(),
            SecurityEpoch::from_raw(1),
            1000,
            "key-1".to_string(),
            key,
        )
        .trace("t1".to_string(), make_trace("t1", 1))
        .build()
        .expect("build should succeed");

        assert_eq!(bundle.manifest.incident_id, "incident-min");
        assert_eq!(bundle.manifest.format_version, BUNDLE_FORMAT_VERSION);
        assert_eq!(bundle.manifest.artifacts.len(), 1);
        assert!(!bundle.manifest.signature.is_empty());
    }

    #[test]
    fn build_empty_bundle_fails() {
        let key = test_signing_key();
        let result = BundleBuilder::new(
            "empty".to_string(),
            SecurityEpoch::from_raw(1),
            1000,
            "key-1".to_string(),
            key,
        )
        .build();
        assert!(matches!(result, Err(BundleError::EmptyBundle)));
    }

    #[test]
    fn build_full_bundle() {
        let bundle = build_test_bundle();
        assert_eq!(bundle.manifest.incident_id, "incident-001");
        assert_eq!(bundle.traces.len(), 1);
        assert_eq!(bundle.evidence_entries.len(), 1);
        assert_eq!(bundle.nondeterminism_logs.len(), 1);
        assert_eq!(bundle.policy_snapshots.len(), 1);
        assert_eq!(bundle.manifest.artifacts.len(), 4);
        assert_eq!(bundle.manifest.window_start_tick, 1000);
        assert_eq!(bundle.manifest.window_end_tick, 2000);
        assert_eq!(
            bundle.manifest.metadata.get("severity"),
            Some(&"high".to_string())
        );
    }

    #[test]
    fn bundle_id_is_deterministic() {
        let b1 = build_test_bundle();
        let b2 = build_test_bundle();
        assert_eq!(b1.manifest.bundle_id, b2.manifest.bundle_id);
    }

    #[test]
    fn bundle_merkle_root_is_deterministic() {
        let b1 = build_test_bundle();
        let b2 = build_test_bundle();
        assert_eq!(b1.manifest.merkle_root, b2.manifest.merkle_root);
    }

    // -----------------------------------------------------------------------
    // BundleVerifier — integrity
    // -----------------------------------------------------------------------

    #[test]
    fn verify_integrity_passes_for_valid_bundle() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(report.passed, "report should pass: {report:?}");
        assert!(report.pass_count() > 0);
        assert_eq!(report.fail_count(), 0);
    }

    #[test]
    fn verify_integrity_detects_merkle_tampering() {
        let mut bundle = build_test_bundle();
        // Tamper with the Merkle root.
        bundle.manifest.merkle_root = ContentHash::compute(b"tampered");

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(!report.passed);
        assert!(report.fail_count() > 0);

        let merkle_check = report
            .checks
            .iter()
            .find(|c| c.name == "merkle-root-valid")
            .unwrap();
        assert!(merkle_check.outcome.is_fail());
    }

    #[test]
    fn verify_integrity_detects_artifact_hash_tampering() {
        let mut bundle = build_test_bundle();
        // Tamper with the stored content hash of a trace artifact so the
        // verifier detects a mismatch when it recomputes the hash.
        if let Some(entry) = bundle
            .manifest
            .artifacts
            .values_mut()
            .find(|e| e.kind == BundleArtifactKind::Trace)
        {
            entry.content_hash = ContentHash::compute(b"tampered-hash");
        }

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(!report.passed);
        let hash_failures: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.category == VerificationCategory::ArtifactHash && c.outcome.is_fail())
            .collect();
        assert!(!hash_failures.is_empty());
    }

    #[test]
    fn verify_integrity_detects_trace_metadata_tampering() {
        let mut bundle = build_test_bundle();
        bundle
            .traces
            .get_mut("trace-001")
            .unwrap()
            .metadata
            .insert("tampered".to_string(), "true".to_string());

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(!report.passed);
        let trace_hash_check = report
            .checks
            .iter()
            .find(|c| c.name == "artifact-hash:trace:trace-001")
            .unwrap();
        assert!(trace_hash_check.outcome.is_fail());
    }

    #[test]
    fn verify_integrity_detects_incompatible_version() {
        let mut bundle = build_test_bundle();
        bundle.manifest.format_version = BundleFormatVersion {
            major: 99,
            minor: 0,
        };

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        let version_check = report
            .checks
            .iter()
            .find(|c| c.name == "format-version-compatible")
            .unwrap();
        assert!(version_check.outcome.is_fail());
    }

    // -----------------------------------------------------------------------
    // BundleVerifier — signature
    // -----------------------------------------------------------------------

    #[test]
    fn verify_signature_passes_with_correct_key() {
        let bundle = build_test_bundle();
        let vk = test_verification_key();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_signature(&bundle, &vk, 6000);

        assert!(report.passed);
    }

    #[test]
    fn verify_signature_fails_with_wrong_key() {
        let bundle = build_test_bundle();
        let wrong_key = SigningKey::from_bytes([99u8; 32]).verification_key();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_signature(&bundle, &wrong_key, 6000);

        assert!(!report.passed);
    }

    // -----------------------------------------------------------------------
    // BundleVerifier — replay
    // -----------------------------------------------------------------------

    #[test]
    fn verify_replay_passes_for_valid_traces() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_replay(&bundle, 6000);

        assert!(report.passed);
        let replay_checks: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.category == VerificationCategory::Replay)
            .collect();
        assert!(!replay_checks.is_empty());
    }

    #[test]
    fn verify_replay_skips_empty_traces() {
        let key = test_signing_key();
        let bundle = BundleBuilder::new(
            "no-traces".to_string(),
            SecurityEpoch::from_raw(1),
            1000,
            "key-1".to_string(),
            key,
        )
        .policy("p1".to_string(), make_policy_snapshot("p1"))
        .build()
        .unwrap();

        let verifier = BundleVerifier::new();
        let report = verifier.verify_replay(&bundle, 6000);

        assert!(report.passed);
        let replay_checks: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.category == VerificationCategory::Replay)
            .collect();
        assert_eq!(replay_checks.len(), 1);
        assert!(matches!(
            replay_checks[0].outcome,
            CheckOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn verify_replay_detects_chain_tampering() {
        let mut bundle = build_test_bundle();
        // Tamper with a trace entry's hash to break chain integrity.
        if let Some(trace) = bundle.traces.values_mut().next()
            && let Some(entry) = trace.entries.first_mut()
        {
            entry.entry_hash = ContentHash::compute(b"tampered-hash");
        }

        let verifier = BundleVerifier::new();
        let report = verifier.verify_replay(&bundle, 6000);

        let chain_checks: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.name.starts_with("trace-chain-integrity"))
            .collect();
        assert!(!chain_checks.is_empty());
        // At least one chain integrity check should fail.
        assert!(chain_checks.iter().any(|c| c.outcome.is_fail()));
    }

    // -----------------------------------------------------------------------
    // BundleVerifier — inspect
    // -----------------------------------------------------------------------

    #[test]
    fn inspect_bundle_summary() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        assert_eq!(inspection.incident_id, "incident-001");
        assert_eq!(inspection.format_version, BUNDLE_FORMAT_VERSION);
        assert_eq!(inspection.window, (1000, 2000));
        assert_eq!(inspection.trace_ids, vec!["trace-001".to_string()]);
        assert!(inspection.total_size_bytes > 0);
        assert_eq!(inspection.redacted_count, 0);
        assert!(inspection.artifact_counts.contains_key("trace"));
        assert!(inspection.artifact_counts.contains_key("evidence"));
        assert_eq!(
            inspection.metadata.get("severity"),
            Some(&"high".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_serde_roundtrip() {
        let bundle = build_test_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let restored: IncidentReplayBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.manifest.bundle_id, restored.manifest.bundle_id);
        assert_eq!(bundle.manifest.merkle_root, restored.manifest.merkle_root);
        assert_eq!(bundle.traces.len(), restored.traces.len());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let bundle = build_test_bundle();
        let json = serde_json::to_string(&bundle.manifest).unwrap();
        let restored: BundleManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.manifest, restored);
    }

    #[test]
    fn verification_report_serde_roundtrip() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        let json = serde_json::to_string(&report).unwrap();
        let restored: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
    }

    #[test]
    fn inspection_serde_roundtrip() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        let json = serde_json::to_string(&inspection).unwrap();
        let restored: BundleInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(inspection, restored);
    }

    // -----------------------------------------------------------------------
    // RedactionPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn default_redaction_policy_redacts_nothing() {
        let policy = RedactionPolicy::default();
        assert!(!policy.redact_extension_ids);
        assert!(!policy.redact_evidence_metadata);
        assert!(!policy.redact_nondeterminism_values);
        assert!(!policy.redact_node_ids);
        assert!(policy.custom_redaction_keys.is_empty());
    }

    #[test]
    fn redaction_policy_serde_roundtrip() {
        let mut policy = RedactionPolicy {
            redact_extension_ids: true,
            ..RedactionPolicy::default()
        };
        policy.custom_redaction_keys.insert("tenant_id".to_string());

        let json = serde_json::to_string(&policy).unwrap();
        let restored: RedactionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errors = vec![
            BundleError::IntegrityFailure {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
            BundleError::ArtifactHashMismatch {
                artifact_id: "t1".to_string(),
            },
            BundleError::SignatureInvalid,
            BundleError::ReplayDivergence {
                details: "mismatch".to_string(),
            },
            BundleError::ReceiptInvalid {
                receipt_id: "r1".to_string(),
                reason: "sig".to_string(),
            },
            BundleError::IncompatibleVersion {
                bundle: BundleFormatVersion { major: 2, minor: 0 },
                reader: BundleFormatVersion { major: 1, minor: 0 },
            },
            BundleError::EmptyBundle,
            BundleError::TraceNotFound {
                trace_id: "t1".to_string(),
            },
            BundleError::IdDerivation("bad".to_string()),
            BundleError::ReplayFailed("boom".to_string()),
            BundleError::RedactionViolation {
                field: "secret".to_string(),
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "error display should not be empty: {e:?}");
        }
    }

    // -----------------------------------------------------------------------
    // BundleArtifactKind display
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_kind_display() {
        assert_eq!(BundleArtifactKind::Trace.to_string(), "trace");
        assert_eq!(BundleArtifactKind::Evidence.to_string(), "evidence");
        assert_eq!(BundleArtifactKind::OptReceipt.to_string(), "opt-receipt");
        assert_eq!(
            BundleArtifactKind::QuorumCheckpoint.to_string(),
            "quorum-checkpoint"
        );
        assert_eq!(
            BundleArtifactKind::NondeterminismLog.to_string(),
            "nondeterminism-log"
        );
        assert_eq!(
            BundleArtifactKind::CounterfactualResult.to_string(),
            "counterfactual-result"
        );
        assert_eq!(
            BundleArtifactKind::PolicySnapshot.to_string(),
            "policy-snapshot"
        );
    }

    // -----------------------------------------------------------------------
    // CheckOutcome
    // -----------------------------------------------------------------------

    #[test]
    fn check_outcome_methods() {
        assert!(CheckOutcome::Pass.is_pass());
        assert!(!CheckOutcome::Pass.is_fail());

        let fail = CheckOutcome::Fail {
            reason: "bad".to_string(),
        };
        assert!(fail.is_fail());
        assert!(!fail.is_pass());

        let skip = CheckOutcome::Skipped {
            reason: "n/a".to_string(),
        };
        assert!(!skip.is_pass());
        assert!(!skip.is_fail());
    }

    // -----------------------------------------------------------------------
    // VerificationCategory display
    // -----------------------------------------------------------------------

    #[test]
    fn verification_category_display() {
        assert_eq!(VerificationCategory::Integrity.to_string(), "integrity");
        assert_eq!(
            VerificationCategory::ArtifactHash.to_string(),
            "artifact-hash"
        );
        assert_eq!(VerificationCategory::Replay.to_string(), "replay");
        assert_eq!(
            VerificationCategory::ReceiptChain.to_string(),
            "receipt-chain"
        );
        assert_eq!(
            VerificationCategory::Counterfactual.to_string(),
            "counterfactual"
        );
        assert_eq!(
            VerificationCategory::Compatibility.to_string(),
            "compatibility"
        );
    }

    // -----------------------------------------------------------------------
    // PolicySnapshot
    // -----------------------------------------------------------------------

    #[test]
    fn policy_snapshot_serde_roundtrip() {
        let snap = make_policy_snapshot("p1");
        let json = serde_json::to_string(&snap).unwrap();
        let restored: PolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
    }

    // -----------------------------------------------------------------------
    // Multiple traces and artifacts
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_with_multiple_traces() {
        let key = test_signing_key();
        let bundle = BundleBuilder::new(
            "multi-trace".to_string(),
            SecurityEpoch::from_raw(100),
            5000,
            "key-1".to_string(),
            key,
        )
        .trace("trace-A".to_string(), make_trace("trace-A", 2))
        .trace("trace-B".to_string(), make_trace("trace-B", 4))
        .trace("trace-C".to_string(), make_trace("trace-C", 1))
        .build()
        .unwrap();

        assert_eq!(bundle.traces.len(), 3);
        assert_eq!(bundle.manifest.artifacts.len(), 3);

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);
        assert!(report.passed);
    }

    #[test]
    fn bundle_with_all_artifact_types() {
        let key = test_signing_key();
        let bundle = BundleBuilder::new(
            "all-types".to_string(),
            SecurityEpoch::from_raw(100),
            5000,
            "key-1".to_string(),
            key,
        )
        .trace("t1".to_string(), make_trace("t1", 2))
        .evidence("ev1".to_string(), make_evidence_entry("ev1"))
        .nondeterminism("t1".to_string(), make_nondeterminism_log())
        .policy("p1".to_string(), make_policy_snapshot("p1"))
        .build()
        .unwrap();

        let verifier = BundleVerifier::new();
        let integrity = verifier.verify_integrity(&bundle, 6000);
        assert!(integrity.passed, "integrity: {integrity:?}");

        let replay = verifier.verify_replay(&bundle, 6000);
        assert!(replay.passed, "replay: {replay:?}");
    }

    // -----------------------------------------------------------------------
    // Manifest signing bytes determinism
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_signing_bytes_deterministic() {
        let b1 = build_test_bundle();
        let b2 = build_test_bundle();
        assert_eq!(b1.manifest.signing_bytes(), b2.manifest.signing_bytes());
    }

    // -----------------------------------------------------------------------
    // VerificationReport counts
    // -----------------------------------------------------------------------

    #[test]
    fn report_category_summaries() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(report.summary.contains_key("integrity"));
        assert!(report.summary.contains_key("compatibility"));
        assert!(report.summary.contains_key("artifact-hash"));

        let total_from_summary: u64 = report
            .summary
            .values()
            .map(|s| s.passed + s.failed + s.skipped)
            .sum();
        assert_eq!(total_from_summary, report.checks.len() as u64);
    }

    // -----------------------------------------------------------------------
    // CounterfactualResult
    // -----------------------------------------------------------------------

    #[test]
    fn counterfactual_result_serde_roundtrip() {
        let result = CounterfactualResult {
            config: CounterfactualConfig {
                branch_id: "branch-1".to_string(),
                threshold_override_millionths: Some(300_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            delta_report: ActionDeltaReport {
                config: CounterfactualConfig {
                    branch_id: "branch-1".to_string(),
                    threshold_override_millionths: Some(300_000),
                    loss_matrix_overrides: BTreeMap::new(),
                    policy_version_override: None,
                    containment_overrides: BTreeMap::new(),
                    evidence_weight_overrides: BTreeMap::new(),
                    branch_from_index: 0,
                },
                harm_prevented_delta_millionths: 50_000,
                false_positive_cost_delta_millionths: -10_000,
                containment_latency_delta_ticks: -5,
                resource_cost_delta_millionths: 20_000,
                affected_extensions: BTreeSet::new(),
                divergence_points: Vec::new(),
                decisions_evaluated: 10,
            },
            source_trace_id: "trace-001".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: CounterfactualResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleError serde roundtrip (all 11 variants)
    // -------------------------------------------------------------------

    #[test]
    fn bundle_error_serde_all_variants() {
        let errors: Vec<BundleError> = vec![
            BundleError::IntegrityFailure {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
            BundleError::ArtifactHashMismatch {
                artifact_id: "t1".to_string(),
            },
            BundleError::SignatureInvalid,
            BundleError::ReplayDivergence {
                details: "mismatch".to_string(),
            },
            BundleError::ReceiptInvalid {
                receipt_id: "r1".to_string(),
                reason: "sig".to_string(),
            },
            BundleError::IncompatibleVersion {
                bundle: BundleFormatVersion { major: 2, minor: 0 },
                reader: BundleFormatVersion { major: 1, minor: 0 },
            },
            BundleError::EmptyBundle,
            BundleError::TraceNotFound {
                trace_id: "t1".to_string(),
            },
            BundleError::IdDerivation("bad".to_string()),
            BundleError::ReplayFailed("boom".to_string()),
            BundleError::RedactionViolation {
                field: "secret".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: BundleError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleError Display content verification
    // -------------------------------------------------------------------

    #[test]
    fn bundle_error_display_content_verified() {
        let cases: Vec<(BundleError, &str)> = vec![
            (
                BundleError::IntegrityFailure {
                    expected: "aaa".to_string(),
                    actual: "bbb".to_string(),
                },
                "integrity failure: expected aaa, got bbb",
            ),
            (
                BundleError::ArtifactHashMismatch {
                    artifact_id: "t1".to_string(),
                },
                "artifact hash mismatch: t1",
            ),
            (BundleError::SignatureInvalid, "bundle signature invalid"),
            (
                BundleError::ReplayDivergence {
                    details: "m".to_string(),
                },
                "replay divergence: m",
            ),
            (
                BundleError::ReceiptInvalid {
                    receipt_id: "r".to_string(),
                    reason: "s".to_string(),
                },
                "receipt invalid (r): s",
            ),
            (
                BundleError::IncompatibleVersion {
                    bundle: BundleFormatVersion { major: 2, minor: 1 },
                    reader: BundleFormatVersion { major: 1, minor: 0 },
                },
                "incompatible version: bundle=2.1, reader=1.0",
            ),
            (BundleError::EmptyBundle, "empty bundle"),
            (
                BundleError::TraceNotFound {
                    trace_id: "t".to_string(),
                },
                "trace not found: t",
            ),
            (
                BundleError::IdDerivation("x".to_string()),
                "id derivation: x",
            ),
            (
                BundleError::ReplayFailed("y".to_string()),
                "replay failed: y",
            ),
            (
                BundleError::RedactionViolation {
                    field: "f".to_string(),
                },
                "redaction violation: f",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.to_string(), *expected, "mismatch for {err:?}");
        }
    }

    // -------------------------------------------------------------------
    // Enrichment: leaf type serde roundtrips
    // -------------------------------------------------------------------

    #[test]
    fn bundle_format_version_serde_roundtrip() {
        let v = BundleFormatVersion { major: 3, minor: 7 };
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: BundleFormatVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    #[test]
    fn bundle_artifact_kind_serde_roundtrip() {
        for variant in [
            BundleArtifactKind::Trace,
            BundleArtifactKind::Evidence,
            BundleArtifactKind::OptReceipt,
            BundleArtifactKind::QuorumCheckpoint,
            BundleArtifactKind::NondeterminismLog,
            BundleArtifactKind::CounterfactualResult,
            BundleArtifactKind::PolicySnapshot,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: BundleArtifactKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn check_outcome_serde_roundtrip() {
        let outcomes = vec![
            CheckOutcome::Pass,
            CheckOutcome::Fail {
                reason: "bad".to_string(),
            },
            CheckOutcome::Skipped {
                reason: "n/a".to_string(),
            },
        ];
        for outcome in &outcomes {
            let json = serde_json::to_string(outcome).expect("serialize");
            let restored: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*outcome, restored);
        }
    }

    #[test]
    fn verification_category_serde_roundtrip() {
        for variant in [
            VerificationCategory::Integrity,
            VerificationCategory::ArtifactHash,
            VerificationCategory::Replay,
            VerificationCategory::ReceiptChain,
            VerificationCategory::Counterfactual,
            VerificationCategory::Compatibility,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: VerificationCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn verification_check_serde_roundtrip() {
        let check = VerificationCheck {
            name: "test-check".to_string(),
            category: VerificationCategory::Integrity,
            outcome: CheckOutcome::Pass,
        };
        let json = serde_json::to_string(&check).expect("serialize");
        let restored: VerificationCheck = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(check, restored);
    }

    #[test]
    fn category_summary_serde_roundtrip() {
        let summary = CategorySummary {
            passed: 5,
            failed: 2,
            skipped: 1,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        let restored: CategorySummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(summary, restored);
    }

    #[test]
    fn artifact_entry_serde_roundtrip() {
        let entry = ArtifactEntry {
            artifact_id: "t1".to_string(),
            kind: BundleArtifactKind::Trace,
            content_hash: ContentHash::compute(b"test-data"),
            redacted: false,
            size_bytes: 128,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: ArtifactEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ordering tests
    // -------------------------------------------------------------------

    #[test]
    fn bundle_artifact_kind_ordering() {
        let mut kinds = [
            BundleArtifactKind::PolicySnapshot,
            BundleArtifactKind::Trace,
            BundleArtifactKind::CounterfactualResult,
            BundleArtifactKind::Evidence,
        ];
        kinds.sort();
        assert_eq!(kinds[0], BundleArtifactKind::Trace);
        assert_eq!(kinds[3], BundleArtifactKind::PolicySnapshot);
    }

    #[test]
    fn verification_category_ordering() {
        let mut cats = [
            VerificationCategory::Compatibility,
            VerificationCategory::Integrity,
            VerificationCategory::Counterfactual,
            VerificationCategory::Replay,
        ];
        cats.sort();
        assert_eq!(cats[0], VerificationCategory::Integrity);
        assert_eq!(cats[3], VerificationCategory::Compatibility);
    }

    #[test]
    fn bundle_format_version_ordering() {
        let v10 = BundleFormatVersion { major: 1, minor: 0 };
        let v11 = BundleFormatVersion { major: 1, minor: 1 };
        let v20 = BundleFormatVersion { major: 2, minor: 0 };
        assert!(v10 < v11);
        assert!(v11 < v20);
    }

    #[test]
    fn bundle_artifact_kind_ord() {
        assert!(BundleArtifactKind::Trace < BundleArtifactKind::Evidence);
        assert!(BundleArtifactKind::Evidence < BundleArtifactKind::OptReceipt);
        assert!(BundleArtifactKind::OptReceipt < BundleArtifactKind::QuorumCheckpoint);
        assert!(BundleArtifactKind::QuorumCheckpoint < BundleArtifactKind::NondeterminismLog);
        assert!(BundleArtifactKind::CounterfactualResult < BundleArtifactKind::PolicySnapshot);
    }

    #[test]
    fn verification_category_ord() {
        assert!(VerificationCategory::Integrity < VerificationCategory::ArtifactHash);
        assert!(VerificationCategory::ArtifactHash < VerificationCategory::Replay);
        assert!(VerificationCategory::Replay < VerificationCategory::ReceiptChain);
        assert!(VerificationCategory::ReceiptChain < VerificationCategory::Counterfactual);
        assert!(VerificationCategory::Counterfactual < VerificationCategory::Compatibility);
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleFormatVersion behavior
    // -------------------------------------------------------------------

    #[test]
    fn bundle_format_version_display() {
        let v = BundleFormatVersion { major: 2, minor: 3 };
        assert_eq!(v.to_string(), "2.3");
    }

    #[test]
    fn bundle_format_version_compatible_same_major_higher_minor() {
        let reader = BundleFormatVersion { major: 1, minor: 2 };
        let bundle = BundleFormatVersion { major: 1, minor: 1 };
        assert!(reader.is_compatible_with(&bundle));
    }

    #[test]
    fn bundle_format_version_incompatible_lower_minor() {
        let reader = BundleFormatVersion { major: 1, minor: 0 };
        let bundle = BundleFormatVersion { major: 1, minor: 1 };
        assert!(!reader.is_compatible_with(&bundle));
    }

    #[test]
    fn bundle_format_version_incompatible_different_major() {
        let reader = BundleFormatVersion { major: 2, minor: 0 };
        let bundle = BundleFormatVersion { major: 1, minor: 0 };
        assert!(!reader.is_compatible_with(&bundle));
    }

    #[test]
    fn bundle_format_version_compatible_same_version() {
        let v = BundleFormatVersion { major: 1, minor: 0 };
        assert!(v.is_compatible_with(&v));
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleError std::error::Error
    // -------------------------------------------------------------------

    #[test]
    fn bundle_error_implements_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BundleError::IntegrityFailure {
                expected: "a".into(),
                actual: "b".into(),
            }),
            Box::new(BundleError::SignatureInvalid),
            Box::new(BundleError::EmptyBundle),
            Box::new(BundleError::TraceNotFound {
                trace_id: "t".into(),
            }),
            Box::new(BundleError::IdDerivation("x".into())),
            Box::new(BundleError::ReplayFailed("y".into())),
            Box::new(BundleError::RedactionViolation { field: "f".into() }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(displays.len(), 7, "all 7 variants have distinct messages");
    }

    // -------------------------------------------------------------------
    // Enrichment: RedactionPolicy
    // -------------------------------------------------------------------

    #[test]
    fn redaction_policy_default_all_false() {
        let policy = RedactionPolicy::default();
        assert!(!policy.redact_extension_ids);
        assert!(!policy.redact_evidence_metadata);
        assert!(!policy.redact_nondeterminism_values);
        assert!(!policy.redact_node_ids);
        assert!(policy.custom_redaction_keys.is_empty());
    }

    #[test]
    fn redaction_policy_serde_with_custom_keys() {
        let mut policy = RedactionPolicy {
            redact_extension_ids: true,
            redact_node_ids: true,
            ..RedactionPolicy::default()
        };
        policy.custom_redaction_keys.insert("api-key".to_string());
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: RedactionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: CheckOutcome helpers
    // -------------------------------------------------------------------

    #[test]
    fn check_outcome_is_pass_and_is_fail() {
        assert!(CheckOutcome::Pass.is_pass());
        assert!(!CheckOutcome::Pass.is_fail());

        let fail = CheckOutcome::Fail {
            reason: "bad".to_string(),
        };
        assert!(!fail.is_pass());
        assert!(fail.is_fail());

        let skipped = CheckOutcome::Skipped {
            reason: "n/a".to_string(),
        };
        assert!(!skipped.is_pass());
        assert!(!skipped.is_fail());
    }

    // -------------------------------------------------------------------
    // Enrichment: Merkle tree edge cases
    // -------------------------------------------------------------------

    #[test]
    fn merkle_root_empty_is_hash_of_empty() {
        let root = compute_merkle_root(&[]);
        let expected = ContentHash::compute(b"");
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_single_leaf_is_leaf() {
        let leaf = ContentHash::compute(b"only-one");
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_proof_build_and_verify() {
        let leaves: Vec<ContentHash> = (0..5)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = compute_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = build_merkle_proof(&leaves, i);
            assert!(
                verify_merkle_proof(&leaves[i], &proof, &root),
                "proof for leaf {i} should verify"
            );
        }
    }

    #[test]
    fn merkle_proof_wrong_root_fails() {
        let leaves: Vec<ContentHash> = (0..3)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let proof = build_merkle_proof(&leaves, 0);
        let wrong_root = ContentHash::compute(b"not-a-real-root");
        assert!(!verify_merkle_proof(&leaves[0], &proof, &wrong_root));
    }

    #[test]
    fn merkle_proof_empty_for_single_leaf() {
        let leaf = ContentHash::compute(b"alone");
        let proof = build_merkle_proof(std::slice::from_ref(&leaf), 0);
        assert!(proof.is_empty());
    }

    #[test]
    fn merkle_proof_out_of_bounds_returns_empty() {
        let leaves: Vec<ContentHash> = (0..3)
            .map(|i| ContentHash::compute(format!("leaf-{i}").as_bytes()))
            .collect();
        let proof = build_merkle_proof(&leaves, 10);
        assert!(proof.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleInspection serde
    // -------------------------------------------------------------------

    #[test]
    fn bundle_inspection_serde_roundtrip() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);
        let json = serde_json::to_string(&inspection).expect("serialize");
        let restored: BundleInspection = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inspection, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: VerificationReport pass/fail counting
    // -------------------------------------------------------------------

    #[test]
    fn verification_report_pass_fail_counts() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);

        assert!(report.passed);
        assert!(report.pass_count() > 0);
        assert_eq!(report.fail_count(), 0);
        assert_eq!(
            report.pass_count()
                + report.fail_count()
                + report
                    .checks
                    .iter()
                    .filter(|c| matches!(c.outcome, CheckOutcome::Skipped { .. }))
                    .count() as u64,
            report.checks.len() as u64
        );
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleArtifactKind Display all variants
    // -------------------------------------------------------------------

    #[test]
    fn bundle_artifact_kind_display_all_variants() {
        let cases = [
            (BundleArtifactKind::Trace, "trace"),
            (BundleArtifactKind::Evidence, "evidence"),
            (BundleArtifactKind::OptReceipt, "opt-receipt"),
            (BundleArtifactKind::QuorumCheckpoint, "quorum-checkpoint"),
            (BundleArtifactKind::NondeterminismLog, "nondeterminism-log"),
            (
                BundleArtifactKind::CounterfactualResult,
                "counterfactual-result",
            ),
            (BundleArtifactKind::PolicySnapshot, "policy-snapshot"),
        ];
        for (kind, expected) in &cases {
            assert_eq!(kind.to_string(), *expected);
        }
    }

    // -------------------------------------------------------------------
    // Enrichment: format version constant
    // -------------------------------------------------------------------

    #[test]
    fn bundle_format_version_constant_is_1_0() {
        assert_eq!(BUNDLE_FORMAT_VERSION.major, 1);
        assert_eq!(BUNDLE_FORMAT_VERSION.minor, 0);
    }

    // -------------------------------------------------------------------
    // Enrichment: verify_receipts empty bundle
    // -------------------------------------------------------------------

    #[test]
    fn verify_receipts_skips_when_no_receipts() {
        let bundle = build_test_bundle();
        // build_test_bundle doesn't add opt_receipts, so this should skip.
        let verifier = BundleVerifier::new();
        let report = verifier.verify_receipts(
            &bundle,
            &BTreeMap::new(),
            SecurityEpoch::from_raw(100),
            6000,
        );
        assert!(report.passed);
        assert_eq!(report.checks.len(), 1);
        assert!(matches!(
            &report.checks[0].outcome,
            CheckOutcome::Skipped { .. }
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: inspect metadata and epochs
    // -------------------------------------------------------------------

    #[test]
    fn inspect_metadata_propagated() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        assert_eq!(inspection.metadata.get("severity").unwrap(), "high");
    }

    #[test]
    fn inspect_epochs_collects_from_traces() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        // Should include creation epoch and trace start/end epochs.
        assert!(inspection.epochs.contains(&100));
    }

    #[test]
    fn inspect_window_matches_builder() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        assert_eq!(inspection.window, (1000, 2000));
    }

    #[test]
    fn inspect_trace_ids_collected() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let inspection = verifier.inspect(&bundle);

        assert!(inspection.trace_ids.contains(&"trace-001".to_string()));
    }

    // -------------------------------------------------------------------
    // Enrichment: CheckOutcome::Skipped behavior
    // -------------------------------------------------------------------

    #[test]
    fn check_outcome_skipped_is_neither_pass_nor_fail() {
        let skipped = CheckOutcome::Skipped {
            reason: "test".to_string(),
        };
        assert!(!skipped.is_pass());
        assert!(!skipped.is_fail());
    }

    // -------------------------------------------------------------------
    // Enrichment: builder with custom redaction policy
    // -------------------------------------------------------------------

    #[test]
    fn builder_with_custom_redaction_policy() {
        let key = test_signing_key();
        let mut custom_keys = BTreeSet::new();
        custom_keys.insert("pii-field".to_string());
        let policy = RedactionPolicy {
            redact_extension_ids: true,
            redact_evidence_metadata: false,
            redact_nondeterminism_values: true,
            redact_node_ids: false,
            custom_redaction_keys: custom_keys,
        };

        let bundle = BundleBuilder::new(
            "incident-002".to_string(),
            SecurityEpoch::from_raw(50),
            9000,
            "producer-2".to_string(),
            key,
        )
        .redaction_policy(policy.clone())
        .trace("t-1".to_string(), make_trace("t-1", 1))
        .build()
        .unwrap();

        assert_eq!(bundle.manifest.redaction_policy, policy);
        assert!(bundle.manifest.redaction_policy.redact_extension_ids);
        assert!(
            bundle
                .manifest
                .redaction_policy
                .custom_redaction_keys
                .contains("pii-field")
        );
    }

    // -------------------------------------------------------------------
    // Enrichment: merkle proof for last leaf in even tree
    // -------------------------------------------------------------------

    #[test]
    fn merkle_proof_last_leaf_even_tree() {
        let leaves: Vec<ContentHash> = (0..4u8).map(|i| ContentHash::compute(&[i])).collect();
        let root = compute_merkle_root(&leaves);
        let proof = build_merkle_proof(&leaves, 3);
        assert!(!proof.is_empty());
        assert!(verify_merkle_proof(&leaves[3], &proof, &root));
    }

    // -------------------------------------------------------------------
    // Enrichment: signing_bytes includes incident_id
    // -------------------------------------------------------------------

    #[test]
    fn signing_bytes_includes_incident_id() {
        let bundle = build_test_bundle();
        let bytes = bundle.manifest.signing_bytes();
        // incident_id "incident-001" should appear in the signing bytes.
        let incident_bytes = b"incident-001";
        // Check that the signing bytes contain the incident_id substring.
        let found = bytes
            .windows(incident_bytes.len())
            .any(|w| w == incident_bytes);
        assert!(found, "signing_bytes should include incident_id");
    }

    // -------------------------------------------------------------------
    // Enrichment: verify_counterfactual with empty configs
    // -------------------------------------------------------------------

    #[test]
    fn verify_counterfactual_empty_configs() {
        let bundle = build_test_bundle();
        let verifier = BundleVerifier::new();
        let report = verifier.verify_counterfactual(&bundle, &[], 6000);
        // No configs => no checks => report passes by default.
        assert!(report.passed);
        assert!(report.checks.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: BundleVerifier default
    // -------------------------------------------------------------------

    #[test]
    fn bundle_verifier_default_matches_new() {
        let v1 = BundleVerifier::new();
        let v2 = BundleVerifier::default();
        assert_eq!(v1.supported_version, v2.supported_version);
    }

    // -------------------------------------------------------------------
    // Enrichment: multiple traces bundle integrity
    // -------------------------------------------------------------------

    #[test]
    fn verify_integrity_multiple_traces_all_pass() {
        let key = test_signing_key();
        let bundle = BundleBuilder::new(
            "incident-multi".to_string(),
            SecurityEpoch::from_raw(100),
            5000,
            "producer-key-1".to_string(),
            key,
        )
        .window(1000, 3000)
        .trace("trace-a".to_string(), make_trace("trace-a", 2))
        .trace("trace-b".to_string(), make_trace("trace-b", 4))
        .trace("trace-c".to_string(), make_trace("trace-c", 1))
        .build()
        .unwrap();

        let verifier = BundleVerifier::new();
        let report = verifier.verify_integrity(&bundle, 6000);
        assert!(report.passed);
        assert_eq!(report.fail_count(), 0);
    }
}
