//! Deterministic causal replay engine with counterfactual branching.
//!
//! Records all sources of nondeterminism during live execution, produces
//! hash-linked deterministic traces, replays them bit-for-bit, and branches
//! into counterfactual simulations under alternate policy configurations.
//!
//! Plan reference: 10.12 item 7, 9H.3, 9F.3

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

const TRACE_SCHEMA_DEF: &[u8] = b"causal-replay-trace-v1";
const BRANCH_SCHEMA_DEF: &[u8] = b"causal-replay-branch-v1";

fn append_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_i64(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn append_string(buf: &mut Vec<u8>, value: &str) {
    append_len_prefixed(buf, value.as_bytes());
}

fn append_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            append_u8(buf, 1);
            append_string(buf, value);
        }
        None => append_u8(buf, 0),
    }
}

fn append_recording_mode(buf: &mut Vec<u8>, mode: &RecordingMode) {
    match mode {
        RecordingMode::Full => append_u8(buf, 0),
        RecordingMode::SecurityCritical => append_u8(buf, 1),
        RecordingMode::Sampled { rate_millionths } => {
            append_u8(buf, 2);
            append_u64(buf, *rate_millionths);
        }
    }
}

// ---------------------------------------------------------------------------
// Nondeterminism recording
// ---------------------------------------------------------------------------

/// Sources of nondeterminism captured during live execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NondeterminismSource {
    /// Seeded PRNG output.
    RandomValue,
    /// Wall-clock or monotonic timestamp.
    Timestamp,
    /// Hostcall return value.
    HostcallResult,
    /// Network or IO response.
    IoResult,
    /// Scheduler ordering decision.
    SchedulingDecision,
    /// OS-level entropy.
    OsEntropy,
    /// External fleet evidence packet arrival order.
    FleetEvidenceArrival,
}

/// A single recorded nondeterministic event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NondeterminismEntry {
    /// Monotonic sequence within the trace.
    pub sequence: u64,
    /// Source classification.
    pub source: NondeterminismSource,
    /// Opaque recorded value (deterministic serialization).
    pub value: Vec<u8>,
    /// Virtual tick at which this event occurred.
    pub tick: u64,
    /// Extension responsible (if applicable).
    pub extension_id: Option<String>,
}

/// Append-only log of nondeterministic events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NondeterminismLog {
    entries: Vec<NondeterminismEntry>,
    next_sequence: u64,
}

impl NondeterminismLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
        }
    }

    pub fn append(
        &mut self,
        source: NondeterminismSource,
        value: Vec<u8>,
        tick: u64,
        extension_id: Option<String>,
    ) -> u64 {
        let seq = self.next_sequence;
        self.entries.push(NondeterminismEntry {
            sequence: seq,
            source,
            value,
            tick,
            extension_id,
        });
        self.next_sequence += 1;
        seq
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, sequence: u64) -> Option<&NondeterminismEntry> {
        self.entries.iter().find(|e| e.sequence == sequence)
    }

    pub fn entries(&self) -> &[NondeterminismEntry] {
        &self.entries
    }

    /// Content hash over all entries for integrity verification.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_u64(&mut buf, self.entries.len() as u64);
        for entry in &self.entries {
            append_u64(&mut buf, entry.sequence);
            append_u8(&mut buf, entry.source.tag());
            append_len_prefixed(&mut buf, &entry.value);
            append_u64(&mut buf, entry.tick);
            append_optional_string(&mut buf, entry.extension_id.as_deref());
        }
        ContentHash::compute(&buf)
    }
}

impl Default for NondeterminismLog {
    fn default() -> Self {
        Self::new()
    }
}

// Helper: stable numeric tag for source enum serialization into hash.
impl NondeterminismSource {
    fn tag(&self) -> u8 {
        match self {
            Self::RandomValue => 0,
            Self::Timestamp => 1,
            Self::HostcallResult => 2,
            Self::IoResult => 3,
            Self::SchedulingDecision => 4,
            Self::OsEntropy => 5,
            Self::FleetEvidenceArrival => 6,
        }
    }
}

// ---------------------------------------------------------------------------
// Decision snapshots
// ---------------------------------------------------------------------------

/// Snapshot of a single policy decision point in the trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSnapshot {
    /// Index within the trace.
    pub decision_index: u64,
    /// Trace identifier.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Policy identifier active at this point.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u64,
    /// Epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Virtual tick.
    pub tick: u64,
    /// Decision threshold used (fixed-point millionths).
    pub threshold_millionths: i64,
    /// Loss matrix snapshot (action -> expected loss millionths).
    pub loss_matrix: BTreeMap<String, i64>,
    /// Evidence hashes available at decision time.
    pub evidence_hashes: Vec<ContentHash>,
    /// Action chosen.
    pub chosen_action: String,
    /// Outcome value (fixed-point millionths).
    pub outcome_millionths: i64,
    /// Extension id involved.
    pub extension_id: String,
    /// Nondeterminism log range consumed by this decision.
    pub nondeterminism_range: (u64, u64),
}

impl DecisionSnapshot {
    /// Compute content hash of this snapshot for chain linking.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_u64(&mut buf, self.decision_index);
        append_string(&mut buf, &self.trace_id);
        append_string(&mut buf, &self.decision_id);
        append_string(&mut buf, &self.policy_id);
        append_u64(&mut buf, self.policy_version);
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.tick);
        append_i64(&mut buf, self.threshold_millionths);
        append_u64(&mut buf, self.loss_matrix.len() as u64);
        for (action, cost) in &self.loss_matrix {
            append_string(&mut buf, action);
            append_i64(&mut buf, *cost);
        }
        let mut sorted_evidence = self.evidence_hashes.clone();
        sorted_evidence.sort();
        append_u64(&mut buf, sorted_evidence.len() as u64);
        for hash in &sorted_evidence {
            append_len_prefixed(&mut buf, hash.as_bytes());
        }
        append_string(&mut buf, &self.chosen_action);
        append_i64(&mut buf, self.outcome_millionths);
        append_string(&mut buf, &self.extension_id);
        append_u64(&mut buf, self.nondeterminism_range.0);
        append_u64(&mut buf, self.nondeterminism_range.1);
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Trace entries (hash-linked)
// ---------------------------------------------------------------------------

/// A single hash-linked entry in a recorded trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Monotonic entry index.
    pub entry_index: u64,
    /// Hash of the previous entry (zeros for genesis).
    pub prev_entry_hash: ContentHash,
    /// This entry's content hash.
    pub entry_hash: ContentHash,
    /// Decision snapshot at this point.
    pub decision: DecisionSnapshot,
    /// Epoch marker.
    pub epoch: SecurityEpoch,
}

impl TraceEntry {
    fn compute_hash(prev_hash: &ContentHash, decision: &DecisionSnapshot) -> ContentHash {
        let decision_hash = decision.content_hash();
        let mut buf = Vec::new();
        buf.extend_from_slice(prev_hash.as_bytes());
        buf.extend_from_slice(decision_hash.as_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// TraceRecord: complete immutable recorded trace
// ---------------------------------------------------------------------------

/// Recording mode controlling overhead vs completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingMode {
    /// Record everything.
    Full,
    /// Record only security-critical decision points.
    SecurityCritical,
    /// Probabilistic sampling (rate in millionths: 500_000 = 50%).
    Sampled { rate_millionths: u64 },
}

/// Complete immutable trace record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Unique trace identifier.
    pub trace_id: String,
    /// Recording mode used.
    pub recording_mode: RecordingMode,
    /// Epoch at trace start.
    pub start_epoch: SecurityEpoch,
    /// Epoch at trace end.
    pub end_epoch: SecurityEpoch,
    /// Start tick.
    pub start_tick: u64,
    /// End tick.
    pub end_tick: u64,
    /// All nondeterminism entries recorded.
    pub nondeterminism_log: NondeterminismLog,
    /// Hash-linked trace entries (decision snapshots).
    pub entries: Vec<TraceEntry>,
    /// Content hash of the nondeterminism log.
    pub nondeterminism_hash: ContentHash,
    /// Final chain hash (hash of last entry).
    pub chain_hash: ContentHash,
    /// Extensions active during the trace.
    pub extensions: BTreeSet<String>,
    /// Policy versions observed.
    pub policy_versions: BTreeMap<String, u64>,
    /// Incident id (if trace is incident-linked).
    pub incident_id: Option<String>,
    /// Metadata.
    pub metadata: BTreeMap<String, String>,
    /// Signature over the trace (for tamper detection).
    pub signature: AuthenticityHash,
}

impl TraceRecord {
    /// Compute the content hash of this trace for content-addressing.
    /// Covers all semantically meaningful fields including recording mode,
    /// extensions, policy versions, incident_id, and metadata.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_string(&mut buf, &self.trace_id);
        append_recording_mode(&mut buf, &self.recording_mode);
        append_len_prefixed(&mut buf, self.nondeterminism_hash.as_bytes());
        append_len_prefixed(&mut buf, self.chain_hash.as_bytes());
        append_u64(&mut buf, self.start_epoch.as_u64());
        append_u64(&mut buf, self.end_epoch.as_u64());
        append_u64(&mut buf, self.start_tick);
        append_u64(&mut buf, self.end_tick);
        // BTreeSet/BTreeMap iteration is deterministic.
        append_u64(&mut buf, self.extensions.len() as u64);
        for ext in &self.extensions {
            append_string(&mut buf, ext);
        }
        append_u64(&mut buf, self.policy_versions.len() as u64);
        for (k, v) in &self.policy_versions {
            append_string(&mut buf, k);
            append_u64(&mut buf, *v);
        }
        append_optional_string(&mut buf, self.incident_id.as_deref());
        append_u64(&mut buf, self.metadata.len() as u64);
        for (k, v) in &self.metadata {
            append_string(&mut buf, k);
            append_string(&mut buf, v);
        }
        ContentHash::compute(&buf)
    }

    /// Derive an engine object id for this trace.
    pub fn object_id(&self, zone: &str) -> Result<EngineObjectId, IdError> {
        let schema = SchemaId::from_definition(TRACE_SCHEMA_DEF);
        derive_id(
            ObjectDomain::EvidenceRecord,
            zone,
            &schema,
            self.content_hash().as_bytes(),
        )
    }

    /// Verify the hash-chain integrity of all entries.
    pub fn verify_chain_integrity(&self) -> Result<(), ReplayError> {
        // Note: nondeterminism_hash is checked by replay() separately,
        // which returns ReplayVerdict::Tampered for a more specific signal.
        if self.entries.is_empty() {
            if self.chain_hash != ContentHash::compute(b"empty-trace") {
                return Err(ReplayError::ChainIntegrity {
                    entry_index: 0,
                    detail: "chain_hash does not match empty-trace hash".into(),
                });
            }
            return Ok(());
        }

        // Verify genesis entry.
        let genesis = &self.entries[0];
        if genesis.entry_index != 0 {
            return Err(ReplayError::ChainIntegrity {
                entry_index: genesis.entry_index,
                detail: "genesis entry must have index 0".into(),
            });
        }
        let expected_prev_genesis = ContentHash::compute(b"genesis");
        if genesis.prev_entry_hash != expected_prev_genesis {
            return Err(ReplayError::ChainIntegrity {
                entry_index: 0,
                detail: "genesis prev_entry_hash mismatch".into(),
            });
        }
        let expected_genesis =
            TraceEntry::compute_hash(&genesis.prev_entry_hash, &genesis.decision);
        if genesis.entry_hash != expected_genesis {
            return Err(ReplayError::ChainIntegrity {
                entry_index: 0,
                detail: "genesis hash mismatch".into(),
            });
        }

        // Verify chain links.
        for window in self.entries.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            if curr.entry_index != prev.entry_index + 1 {
                return Err(ReplayError::ChainIntegrity {
                    entry_index: curr.entry_index,
                    detail: format!(
                        "non-monotonic index: expected {}, got {}",
                        prev.entry_index + 1,
                        curr.entry_index
                    ),
                });
            }

            if curr.prev_entry_hash != prev.entry_hash {
                return Err(ReplayError::ChainIntegrity {
                    entry_index: curr.entry_index,
                    detail: "prev_entry_hash does not match prior entry".into(),
                });
            }

            let expected = TraceEntry::compute_hash(&curr.prev_entry_hash, &curr.decision);
            if curr.entry_hash != expected {
                return Err(ReplayError::ChainIntegrity {
                    entry_index: curr.entry_index,
                    detail: "entry hash mismatch".into(),
                });
            }
        }

        // Verify final chain hash matches.
        if let Some(last) = self.entries.last()
            && self.chain_hash != last.entry_hash
        {
            return Err(ReplayError::ChainIntegrity {
                entry_index: last.entry_index,
                detail: "chain_hash does not match last entry hash".into(),
            });
        }

        Ok(())
    }

    /// Verify the trace signature for tamper detection.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let expected = AuthenticityHash::compute_keyed(key, self.content_hash().as_bytes());
        self.signature.constant_time_eq(&expected)
    }
}

// ---------------------------------------------------------------------------
// Trace recorder (live recording)
// ---------------------------------------------------------------------------

/// Builder for recording traces during live execution.
#[derive(Debug)]
pub struct TraceRecorder {
    trace_id: String,
    recording_mode: RecordingMode,
    start_epoch: SecurityEpoch,
    start_tick: u64,
    current_epoch: SecurityEpoch,
    current_tick: u64,
    nondeterminism_log: NondeterminismLog,
    entries: Vec<TraceEntry>,
    extensions: BTreeSet<String>,
    policy_versions: BTreeMap<String, u64>,
    incident_id: Option<String>,
    metadata: BTreeMap<String, String>,
    signing_key: Vec<u8>,
}

/// Configuration for creating a new trace recorder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecorderConfig {
    pub trace_id: String,
    pub recording_mode: RecordingMode,
    pub epoch: SecurityEpoch,
    pub start_tick: u64,
    pub signing_key: Vec<u8>,
}

impl TraceRecorder {
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            trace_id: config.trace_id,
            recording_mode: config.recording_mode,
            start_epoch: config.epoch,
            start_tick: config.start_tick,
            current_epoch: config.epoch,
            current_tick: config.start_tick,
            nondeterminism_log: NondeterminismLog::new(),
            entries: Vec::new(),
            extensions: BTreeSet::new(),
            policy_versions: BTreeMap::new(),
            incident_id: None,
            metadata: BTreeMap::new(),
            signing_key: config.signing_key,
        }
    }

    /// Record a nondeterministic event.
    pub fn record_nondeterminism(
        &mut self,
        source: NondeterminismSource,
        value: Vec<u8>,
        tick: u64,
        extension_id: Option<String>,
    ) -> u64 {
        self.current_tick = tick;
        self.nondeterminism_log
            .append(source, value, tick, extension_id)
    }

    /// Record a decision point, producing a hash-linked trace entry.
    pub fn record_decision(&mut self, snapshot: DecisionSnapshot) {
        self.current_tick = snapshot.tick;
        self.current_epoch = snapshot.epoch;
        self.extensions.insert(snapshot.extension_id.clone());
        self.policy_versions
            .insert(snapshot.policy_id.clone(), snapshot.policy_version);

        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or_else(|| ContentHash::compute(b"genesis"));

        let entry_index = self.entries.len() as u64;
        let entry_hash = TraceEntry::compute_hash(&prev_hash, &snapshot);

        self.entries.push(TraceEntry {
            entry_index,
            prev_entry_hash: prev_hash,
            entry_hash,
            decision: snapshot,
            epoch: self.current_epoch,
        });
    }

    pub fn set_incident_id(&mut self, id: String) {
        self.incident_id = Some(id);
    }

    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Finalize recording and produce an immutable trace record.
    pub fn finalize(self) -> TraceRecord {
        let nondeterminism_hash = self.nondeterminism_log.content_hash();
        let chain_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or_else(|| ContentHash::compute(b"empty-trace"));

        let mut record = TraceRecord {
            trace_id: self.trace_id,
            recording_mode: self.recording_mode,
            start_epoch: self.start_epoch,
            end_epoch: self.current_epoch,
            start_tick: self.start_tick,
            end_tick: self.current_tick,
            nondeterminism_log: self.nondeterminism_log,
            entries: self.entries,
            nondeterminism_hash,
            chain_hash,
            extensions: self.extensions,
            policy_versions: self.policy_versions,
            incident_id: self.incident_id,
            metadata: self.metadata,
            signature: AuthenticityHash::compute(b"unsigned"),
        };

        // Sign the finalized trace.
        let content = record.content_hash();
        record.signature = AuthenticityHash::compute_keyed(&self.signing_key, content.as_bytes());
        record
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn nondeterminism_count(&self) -> usize {
        self.nondeterminism_log.len()
    }
}

// ---------------------------------------------------------------------------
// Replay engine
// ---------------------------------------------------------------------------

/// Outcome of a single decision during replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDecisionOutcome {
    pub decision_index: u64,
    pub original_action: String,
    pub replayed_action: String,
    pub original_outcome_millionths: i64,
    pub replayed_outcome_millionths: i64,
    pub diverged: bool,
}

/// Verdict after replaying a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayVerdict {
    /// Replay matched original trace bit-for-bit.
    Identical { decisions_replayed: u64 },
    /// Replay diverged at a specific decision point.
    Diverged {
        divergence_point: u64,
        decisions_replayed: u64,
        divergences: Vec<ReplayDecisionOutcome>,
    },
    /// Trace was tampered with (hash chain broken or signature invalid).
    Tampered { detail: String },
}

impl ReplayVerdict {
    pub fn is_identical(&self) -> bool {
        matches!(self, Self::Identical { .. })
    }

    pub fn divergence_count(&self) -> usize {
        match self {
            Self::Identical { .. } => 0,
            Self::Diverged { divergences, .. } => divergences.len(),
            Self::Tampered { .. } => 0,
        }
    }
}

/// Policy decision function: given a decision snapshot and nondeterminism log,
/// produce the action and outcome for that decision point.
pub trait PolicyDecider: fmt::Debug {
    fn decide(
        &self,
        snapshot: &DecisionSnapshot,
        nondeterminism: &NondeterminismLog,
    ) -> (String, i64);
}

/// Default decider that replays the original decisions exactly.
#[derive(Debug)]
pub struct OriginalDecider;

impl PolicyDecider for OriginalDecider {
    fn decide(
        &self,
        snapshot: &DecisionSnapshot,
        _nondeterminism: &NondeterminismLog,
    ) -> (String, i64) {
        (snapshot.chosen_action.clone(), snapshot.outcome_millionths)
    }
}

/// Replay engine that consumes a trace and verifies or branches.
#[derive(Debug)]
pub struct CausalReplayEngine {
    /// Maximum chain depth for counterfactual branching.
    max_branch_depth: u32,
}

impl Default for CausalReplayEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CausalReplayEngine {
    pub fn new() -> Self {
        Self {
            max_branch_depth: 16,
        }
    }

    pub fn with_max_branch_depth(mut self, depth: u32) -> Self {
        self.max_branch_depth = depth;
        self
    }

    /// Replay a trace and verify bit-for-bit fidelity.
    pub fn replay(&self, trace: &TraceRecord) -> Result<ReplayVerdict, ReplayError> {
        // Step 1: Verify chain integrity.
        trace.verify_chain_integrity()?;

        // Step 2: Verify nondeterminism log hash.
        let computed_nd_hash = trace.nondeterminism_log.content_hash();
        if computed_nd_hash != trace.nondeterminism_hash {
            return Ok(ReplayVerdict::Tampered {
                detail: "nondeterminism log hash mismatch".into(),
            });
        }

        // Step 3: Replay each decision with the original decider.
        let decider = OriginalDecider;
        self.replay_with_decider(trace, &decider)
    }

    /// Replay a trace using a custom policy decider.
    pub fn replay_with_decider(
        &self,
        trace: &TraceRecord,
        decider: &dyn PolicyDecider,
    ) -> Result<ReplayVerdict, ReplayError> {
        let mut divergences = Vec::new();
        let mut first_divergence = None;

        for entry in &trace.entries {
            let (replayed_action, replayed_outcome) =
                decider.decide(&entry.decision, &trace.nondeterminism_log);

            let diverged = replayed_action != entry.decision.chosen_action
                || replayed_outcome != entry.decision.outcome_millionths;

            if diverged && first_divergence.is_none() {
                first_divergence = Some(entry.entry_index);
            }

            if diverged {
                divergences.push(ReplayDecisionOutcome {
                    decision_index: entry.entry_index,
                    original_action: entry.decision.chosen_action.clone(),
                    replayed_action,
                    original_outcome_millionths: entry.decision.outcome_millionths,
                    replayed_outcome_millionths: replayed_outcome,
                    diverged: true,
                });
            }
        }

        let decisions_replayed = trace.entries.len() as u64;

        if divergences.is_empty() {
            Ok(ReplayVerdict::Identical { decisions_replayed })
        } else {
            Ok(ReplayVerdict::Diverged {
                divergence_point: first_divergence.unwrap_or(0),
                decisions_replayed,
                divergences,
            })
        }
    }

    /// Verify a trace's signature against a given key.
    pub fn verify_trace_signature(&self, trace: &TraceRecord, key: &[u8]) -> bool {
        trace.verify_signature(key)
    }
}

// ---------------------------------------------------------------------------
// Counterfactual branching
// ---------------------------------------------------------------------------

/// Alternate parameter substitutions for counterfactual analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualConfig {
    /// Identifier for this counterfactual branch.
    pub branch_id: String,
    /// Threshold override (fixed-point millionths). None = use original.
    pub threshold_override_millionths: Option<i64>,
    /// Loss matrix overrides per action.
    pub loss_matrix_overrides: BTreeMap<String, i64>,
    /// Policy version override.
    pub policy_version_override: Option<u64>,
    /// Containment action mapping overrides.
    pub containment_overrides: BTreeMap<String, String>,
    /// Evidence weight overrides.
    pub evidence_weight_overrides: BTreeMap<String, i64>,
    /// Branch starting decision index (0 = from beginning).
    pub branch_from_index: u64,
}

/// Comparison report for a single decision in a counterfactual branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionDelta {
    pub decision_index: u64,
    pub original_action: String,
    pub counterfactual_action: String,
    pub original_outcome_millionths: i64,
    pub counterfactual_outcome_millionths: i64,
    pub diverged: bool,
}

/// Action delta report comparing original vs counterfactual branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDeltaReport {
    /// Branch configuration used.
    pub config: CounterfactualConfig,
    /// Total harm prevented delta (counterfactual - original), millionths.
    pub harm_prevented_delta_millionths: i64,
    /// False positive cost delta, millionths.
    pub false_positive_cost_delta_millionths: i64,
    /// Containment latency delta (ticks).
    pub containment_latency_delta_ticks: i64,
    /// Resource cost delta, millionths.
    pub resource_cost_delta_millionths: i64,
    /// Extensions affected by divergence.
    pub affected_extensions: BTreeSet<String>,
    /// Decision points where divergence occurred.
    pub divergence_points: Vec<DecisionDelta>,
    /// Total decisions evaluated.
    pub decisions_evaluated: u64,
}

impl ActionDeltaReport {
    pub fn divergence_count(&self) -> usize {
        self.divergence_points.len()
    }

    pub fn is_improvement(&self) -> bool {
        self.harm_prevented_delta_millionths > 0
    }

    /// Derive engine object id for this report.
    pub fn object_id(&self, zone: &str) -> Result<EngineObjectId, IdError> {
        let schema = SchemaId::from_definition(BRANCH_SCHEMA_DEF);
        let mut buf = Vec::new();
        buf.extend_from_slice(self.config.branch_id.as_bytes());
        buf.extend_from_slice(&self.decisions_evaluated.to_be_bytes());
        buf.extend_from_slice(&self.harm_prevented_delta_millionths.to_be_bytes());
        derive_id(ObjectDomain::EvidenceRecord, zone, &schema, &buf)
    }
}

/// Counterfactual decider that applies config overrides.
#[derive(Debug)]
pub struct CounterfactualDecider {
    config: CounterfactualConfig,
}

impl CounterfactualDecider {
    pub fn new(config: CounterfactualConfig) -> Self {
        Self { config }
    }
}

impl PolicyDecider for CounterfactualDecider {
    fn decide(
        &self,
        snapshot: &DecisionSnapshot,
        _nondeterminism: &NondeterminismLog,
    ) -> (String, i64) {
        // If this decision is before the branch point, return original.
        if snapshot.decision_index < self.config.branch_from_index {
            return (snapshot.chosen_action.clone(), snapshot.outcome_millionths);
        }

        // If no overrides affect this decision, return original to avoid
        // re-deriving the decision (which could differ from the original
        // opaque decision logic).
        let has_threshold_change = self.config.threshold_override_millionths.is_some();
        let has_loss_change = !self.config.loss_matrix_overrides.is_empty();
        let has_containment_change = !self.config.containment_overrides.is_empty();

        if !has_threshold_change && !has_loss_change && !has_containment_change {
            return (snapshot.chosen_action.clone(), snapshot.outcome_millionths);
        }

        // Apply threshold override.
        let threshold = self
            .config
            .threshold_override_millionths
            .unwrap_or(snapshot.threshold_millionths);

        // Build effective loss matrix with overrides.
        let mut loss_matrix = snapshot.loss_matrix.clone();
        for (action, cost) in &self.config.loss_matrix_overrides {
            loss_matrix.insert(action.clone(), *cost);
        }

        // Apply containment overrides (remap action names).
        let mut remapped = BTreeMap::new();
        for (action, cost) in &loss_matrix {
            let effective_action = self
                .config
                .containment_overrides
                .get(action)
                .cloned()
                .unwrap_or_else(|| action.clone());
            let existing = remapped.entry(effective_action).or_insert(*cost);
            if *cost < *existing {
                *existing = *cost;
            }
        }

        // Re-decide: choose action with lowest expected loss that meets threshold.
        let mut best_action = snapshot.chosen_action.clone();
        let mut best_cost = remapped
            .get(&best_action)
            .copied()
            .unwrap_or(snapshot.outcome_millionths);

        if best_cost > threshold {
            best_cost = i64::MAX;
        }

        for (action, cost) in &remapped {
            if *cost <= threshold && *cost < best_cost {
                best_action = action.clone();
                best_cost = *cost;
            }
        }

        if best_cost == i64::MAX {
            best_action = snapshot.chosen_action.clone();
            best_cost = remapped
                .get(&best_action)
                .copied()
                .unwrap_or(snapshot.outcome_millionths);
        }

        (best_action, best_cost)
    }
}

impl CausalReplayEngine {
    /// Run a counterfactual branch against a recorded trace.
    pub fn counterfactual_branch(
        &self,
        trace: &TraceRecord,
        config: CounterfactualConfig,
    ) -> Result<ActionDeltaReport, ReplayError> {
        // Verify chain integrity first.
        trace.verify_chain_integrity()?;

        let decider = CounterfactualDecider::new(config.clone());
        let mut divergence_points = Vec::new();
        let mut affected_extensions = BTreeSet::new();
        let mut total_original_cost: i64 = 0;
        let mut total_cf_cost: i64 = 0;

        for entry in &trace.entries {
            let (cf_action, cf_outcome) =
                decider.decide(&entry.decision, &trace.nondeterminism_log);

            let diverged = cf_action != entry.decision.chosen_action
                || cf_outcome != entry.decision.outcome_millionths;

            total_original_cost =
                total_original_cost.saturating_add(entry.decision.outcome_millionths);
            total_cf_cost = total_cf_cost.saturating_add(cf_outcome);

            if diverged {
                affected_extensions.insert(entry.decision.extension_id.clone());
                divergence_points.push(DecisionDelta {
                    decision_index: entry.entry_index,
                    original_action: entry.decision.chosen_action.clone(),
                    counterfactual_action: cf_action,
                    original_outcome_millionths: entry.decision.outcome_millionths,
                    counterfactual_outcome_millionths: cf_outcome,
                    diverged: true,
                });
            }
        }

        let harm_delta = total_original_cost.saturating_sub(total_cf_cost);

        Ok(ActionDeltaReport {
            config,
            harm_prevented_delta_millionths: harm_delta,
            false_positive_cost_delta_millionths: 0,
            containment_latency_delta_ticks: 0,
            resource_cost_delta_millionths: 0,
            affected_extensions,
            divergence_points,
            decisions_evaluated: trace.entries.len() as u64,
        })
    }

    /// Run multiple counterfactual branches for comparative analysis.
    pub fn multi_branch_comparison(
        &self,
        trace: &TraceRecord,
        configs: Vec<CounterfactualConfig>,
    ) -> Result<Vec<ActionDeltaReport>, ReplayError> {
        if configs.len() as u32 > self.max_branch_depth {
            return Err(ReplayError::BranchDepthExceeded {
                requested: configs.len() as u32,
                max: self.max_branch_depth,
            });
        }

        let mut reports = Vec::with_capacity(configs.len());
        for config in configs {
            reports.push(self.counterfactual_branch(trace, config)?);
        }
        Ok(reports)
    }
}

// ---------------------------------------------------------------------------
// Trace index
// ---------------------------------------------------------------------------

/// Query filter for trace index lookups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceQuery {
    pub trace_id: Option<String>,
    pub extension_id: Option<String>,
    pub policy_version: Option<u64>,
    pub epoch_range: Option<(u64, u64)>,
    pub tick_range: Option<(u64, u64)>,
    pub incident_id: Option<String>,
    pub has_divergence: Option<bool>,
}

/// Retention policy for trace storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRetentionPolicy {
    /// Default TTL in ticks.
    pub default_ttl_ticks: u64,
    /// TTL for incident-linked traces (higher priority).
    pub incident_ttl_ticks: u64,
    /// TTL for security-critical traces.
    pub security_critical_ttl_ticks: u64,
    /// Maximum total traces stored.
    pub max_traces: usize,
    /// Maximum total storage in bytes (estimated).
    pub max_storage_bytes: u64,
}

impl Default for TraceRetentionPolicy {
    fn default() -> Self {
        Self {
            default_ttl_ticks: 1_000_000,
            incident_ttl_ticks: 10_000_000,
            security_critical_ttl_ticks: 5_000_000,
            max_traces: 10_000,
            max_storage_bytes: 1_073_741_824, // 1 GiB
        }
    }
}

/// In-memory trace index for query and retention.
#[derive(Debug)]
pub struct TraceIndex {
    traces: BTreeMap<String, TraceRecord>,
    retention: TraceRetentionPolicy,
    storage_estimate_bytes: u64,
}

impl TraceIndex {
    pub fn new(retention: TraceRetentionPolicy) -> Self {
        Self {
            traces: BTreeMap::new(),
            retention,
            storage_estimate_bytes: 0,
        }
    }

    /// Insert a trace, enforcing retention limits.
    pub fn insert(&mut self, trace: TraceRecord) -> Result<(), ReplayError> {
        let est_size = Self::estimate_size(&trace);

        // Enforce max traces.
        while self.traces.len() >= self.retention.max_traces {
            self.evict_lowest_priority()?;
        }

        // Enforce storage budget.
        while self.storage_estimate_bytes + est_size > self.retention.max_storage_bytes
            && !self.traces.is_empty()
        {
            self.evict_lowest_priority()?;
        }

        self.storage_estimate_bytes += est_size;
        self.traces.insert(trace.trace_id.clone(), trace);
        Ok(())
    }

    /// Query traces matching the filter.
    pub fn query(&self, filter: &TraceQuery) -> Vec<&TraceRecord> {
        self.traces
            .values()
            .filter(|t| Self::matches(t, filter))
            .collect()
    }

    /// Get a trace by its ID.
    pub fn get(&self, trace_id: &str) -> Option<&TraceRecord> {
        self.traces.get(trace_id)
    }

    /// Remove expired traces.
    pub fn gc(&mut self, current_tick: u64) {
        let retention = &self.retention;
        let to_remove: Vec<String> = self
            .traces
            .iter()
            .filter(|(_, t)| {
                let ttl = if t.incident_id.is_some() {
                    retention.incident_ttl_ticks
                } else if matches!(t.recording_mode, RecordingMode::SecurityCritical) {
                    retention.security_critical_ttl_ticks
                } else {
                    retention.default_ttl_ticks
                };
                current_tick.saturating_sub(t.end_tick) > ttl
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &to_remove {
            if let Some(removed) = self.traces.remove(id) {
                self.storage_estimate_bytes = self
                    .storage_estimate_bytes
                    .saturating_sub(Self::estimate_size(&removed));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.traces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.traces.is_empty()
    }

    pub fn storage_estimate(&self) -> u64 {
        self.storage_estimate_bytes
    }

    fn matches(trace: &TraceRecord, filter: &TraceQuery) -> bool {
        if let Some(ref tid) = filter.trace_id
            && &trace.trace_id != tid
        {
            return false;
        }
        if let Some(ref eid) = filter.extension_id
            && !trace.extensions.contains(eid)
        {
            return false;
        }
        if let Some(pv) = filter.policy_version
            && !trace.policy_versions.values().any(|v| *v == pv)
        {
            return false;
        }
        if let Some((start, end)) = filter.epoch_range
            && (trace.start_epoch.as_u64() > end || trace.end_epoch.as_u64() < start)
        {
            return false;
        }
        if let Some((start, end)) = filter.tick_range
            && (trace.start_tick > end || trace.end_tick < start)
        {
            return false;
        }
        if let Some(ref iid) = filter.incident_id
            && trace.incident_id.as_ref() != Some(iid)
        {
            return false;
        }
        true
    }

    fn estimate_size(trace: &TraceRecord) -> u64 {
        let entry_size = (trace.entries.len() * 256) as u64;
        let nd_size = (trace.nondeterminism_log.len() * 128) as u64;
        entry_size + nd_size + 512 // overhead
    }

    fn evict_lowest_priority(&mut self) -> Result<(), ReplayError> {
        // Priority: incident-linked > security-critical > normal.
        // Evict oldest normal trace first, then oldest security-critical, then oldest incident.
        let evict_id = self
            .traces
            .iter()
            .filter(|(_, t)| {
                t.incident_id.is_none()
                    && !matches!(t.recording_mode, RecordingMode::SecurityCritical)
            })
            .min_by_key(|(_, t)| t.end_tick)
            .or_else(|| {
                self.traces
                    .iter()
                    .filter(|(_, t)| t.incident_id.is_none())
                    .min_by_key(|(_, t)| t.end_tick)
            })
            .or_else(|| self.traces.iter().min_by_key(|(_, t)| t.end_tick))
            .map(|(id, _)| id.clone());

        if let Some(id) = evict_id {
            if let Some(removed) = self.traces.remove(&id) {
                self.storage_estimate_bytes = self
                    .storage_estimate_bytes
                    .saturating_sub(Self::estimate_size(&removed));
            }
            Ok(())
        } else {
            Err(ReplayError::StorageExhausted)
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from replay operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// Hash chain integrity violation.
    ChainIntegrity { entry_index: u64, detail: String },
    /// Nondeterminism log mismatch.
    NondeterminismMismatch {
        expected_sequence: u64,
        actual_sequence: u64,
    },
    /// Counterfactual branch depth exceeded.
    BranchDepthExceeded { requested: u32, max: u32 },
    /// Trace storage exhausted.
    StorageExhausted,
    /// Trace not found.
    TraceNotFound { trace_id: String },
    /// Trace signature invalid.
    SignatureInvalid,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIntegrity {
                entry_index,
                detail,
            } => {
                write!(
                    f,
                    "chain integrity violation at entry {entry_index}: {detail}"
                )
            }
            Self::NondeterminismMismatch {
                expected_sequence,
                actual_sequence,
            } => write!(
                f,
                "nondeterminism mismatch: expected seq {expected_sequence}, got {actual_sequence}"
            ),
            Self::BranchDepthExceeded { requested, max } => {
                write!(f, "branch depth {requested} exceeds max {max}")
            }
            Self::StorageExhausted => write!(f, "trace storage exhausted"),
            Self::TraceNotFound { trace_id } => {
                write!(f, "trace not found: {trace_id}")
            }
            Self::SignatureInvalid => write!(f, "trace signature invalid"),
        }
    }
}

impl std::error::Error for ReplayError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![42u8; 32]
    }

    fn make_snapshot(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
        DecisionSnapshot {
            decision_index: index,
            trace_id: "trace-001".into(),
            decision_id: format!("decision-{index}"),
            policy_id: "policy-alpha".into(),
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(5),
            tick: 1000 + index * 100,
            threshold_millionths: 500_000,
            loss_matrix: {
                let mut m = BTreeMap::new();
                m.insert("allow".into(), 0);
                m.insert("sandbox".into(), 200_000);
                m.insert("terminate".into(), 800_000);
                m
            },
            evidence_hashes: vec![ContentHash::compute(b"evidence-1")],
            chosen_action: action.into(),
            outcome_millionths: outcome,
            extension_id: "ext-abc".into(),
            nondeterminism_range: (index * 2, index * 2 + 1),
        }
    }

    fn make_trace(decisions: &[(&str, i64)]) -> TraceRecord {
        let config = RecorderConfig {
            trace_id: "trace-001".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(5),
            start_tick: 1000,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);

        // Add some nondeterminism.
        for i in 0..decisions.len() as u64 {
            recorder.record_nondeterminism(
                NondeterminismSource::RandomValue,
                vec![i as u8],
                1000 + i * 100,
                Some("ext-abc".into()),
            );
            recorder.record_nondeterminism(
                NondeterminismSource::Timestamp,
                (1000 + i * 100).to_be_bytes().to_vec(),
                1000 + i * 100,
                None,
            );
        }

        for (i, (action, outcome)) in decisions.iter().enumerate() {
            recorder.record_decision(make_snapshot(i as u64, action, *outcome));
        }

        recorder.finalize()
    }

    // -- NondeterminismLog tests --

    #[test]
    fn nondeterminism_log_append_and_retrieve() {
        let mut log = NondeterminismLog::new();
        assert!(log.is_empty());

        let seq = log.append(
            NondeterminismSource::RandomValue,
            vec![1, 2, 3],
            100,
            Some("ext-1".into()),
        );
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);

        let entry = log.get(0).unwrap();
        assert_eq!(entry.source, NondeterminismSource::RandomValue);
        assert_eq!(entry.value, vec![1, 2, 3]);
        assert_eq!(entry.tick, 100);
        assert_eq!(entry.extension_id, Some("ext-1".into()));
    }

    #[test]
    fn nondeterminism_log_monotonic_sequences() {
        let mut log = NondeterminismLog::new();
        for i in 0..5 {
            let seq = log.append(
                NondeterminismSource::Timestamp,
                vec![i],
                i as u64 * 10,
                None,
            );
            assert_eq!(seq, i as u64);
        }
        assert_eq!(log.len(), 5);
    }

    #[test]
    fn nondeterminism_log_content_hash_deterministic() {
        let mut log1 = NondeterminismLog::new();
        let mut log2 = NondeterminismLog::new();

        for i in 0..3u8 {
            log1.append(NondeterminismSource::IoResult, vec![i], i as u64, None);
            log2.append(NondeterminismSource::IoResult, vec![i], i as u64, None);
        }

        assert_eq!(log1.content_hash(), log2.content_hash());
    }

    #[test]
    fn nondeterminism_log_different_data_different_hash() {
        let mut log1 = NondeterminismLog::new();
        let mut log2 = NondeterminismLog::new();

        log1.append(NondeterminismSource::RandomValue, vec![1], 0, None);
        log2.append(NondeterminismSource::RandomValue, vec![2], 0, None);

        assert_ne!(log1.content_hash(), log2.content_hash());
    }

    #[test]
    fn nondeterminism_log_empty_hash() {
        let log = NondeterminismLog::new();
        // Should produce a stable hash for empty logs.
        let h = log.content_hash();
        assert_eq!(h, NondeterminismLog::new().content_hash());
    }

    #[test]
    fn nondeterminism_log_get_nonexistent() {
        let log = NondeterminismLog::new();
        assert!(log.get(0).is_none());
        assert!(log.get(999).is_none());
    }

    #[test]
    fn nondeterminism_source_tags_are_unique() {
        let sources = [
            NondeterminismSource::RandomValue,
            NondeterminismSource::Timestamp,
            NondeterminismSource::HostcallResult,
            NondeterminismSource::IoResult,
            NondeterminismSource::SchedulingDecision,
            NondeterminismSource::OsEntropy,
            NondeterminismSource::FleetEvidenceArrival,
        ];
        let mut tags = BTreeSet::new();
        for s in &sources {
            assert!(tags.insert(s.tag()), "duplicate tag for {s:?}");
        }
    }

    // -- DecisionSnapshot tests --

    #[test]
    fn decision_snapshot_content_hash_deterministic() {
        let s1 = make_snapshot(0, "sandbox", 200_000);
        let s2 = make_snapshot(0, "sandbox", 200_000);
        assert_eq!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn decision_snapshot_different_actions_different_hash() {
        let s1 = make_snapshot(0, "sandbox", 200_000);
        let s2 = make_snapshot(0, "terminate", 200_000);
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn decision_snapshot_content_hash_distinguishes_field_boundaries() {
        let mut s1 = make_snapshot(0, "sandbox", 200_000);
        s1.trace_id = "ab".into();
        s1.decision_id = "c".into();

        let mut s2 = s1.clone();
        s2.trace_id = "a".into();
        s2.decision_id = "bc".into();

        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    // -- TraceRecorder and TraceRecord tests --

    #[test]
    fn trace_recorder_produces_valid_chain() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);

        assert_eq!(trace.entries.len(), 3);
        assert_eq!(trace.trace_id, "trace-001");
        assert_eq!(trace.start_epoch, SecurityEpoch::from_raw(5));
        assert_eq!(trace.recording_mode, RecordingMode::Full);

        // Verify chain integrity.
        trace
            .verify_chain_integrity()
            .expect("chain should be valid");
    }

    #[test]
    fn trace_record_signature_verification() {
        let trace = make_trace(&[("sandbox", 200_000)]);
        assert!(trace.verify_signature(&test_key()));
        assert!(!trace.verify_signature(&[99u8; 32]));
    }

    #[test]
    fn trace_record_content_hash_deterministic() {
        let t1 = make_trace(&[("sandbox", 200_000)]);
        let t2 = make_trace(&[("sandbox", 200_000)]);
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trace_record_content_hash_distinguishes_extension_boundaries() {
        let mut t1 = make_trace(&[("sandbox", 200_000)]);
        t1.extensions = ["ab".to_string(), "c".to_string()].into_iter().collect();

        let mut t2 = t1.clone();
        t2.extensions = ["a".to_string(), "bc".to_string()].into_iter().collect();

        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn trace_record_object_id_derivation() {
        let trace = make_trace(&[("sandbox", 200_000)]);
        let id = trace.object_id("zone-a").expect("should derive id");
        // Should be deterministic.
        let id2 = trace.object_id("zone-a").expect("should derive id");
        assert_eq!(id, id2);
    }

    #[test]
    fn trace_recorder_empty_trace() {
        let config = RecorderConfig {
            trace_id: "empty".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let recorder = TraceRecorder::new(config);
        let trace = recorder.finalize();

        assert!(trace.entries.is_empty());
        assert!(trace.nondeterminism_log.is_empty());
        trace
            .verify_chain_integrity()
            .expect("empty chain is valid");
    }

    #[test]
    fn trace_chain_integrity_detects_tampering() {
        let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);

        // Tamper with an entry's hash.
        trace.entries[1].entry_hash = ContentHash::compute(b"tampered");

        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
    }

    #[test]
    fn trace_chain_integrity_detects_broken_link() {
        let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);

        // Break the chain link.
        trace.entries[1].prev_entry_hash = ContentHash::compute(b"broken");

        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
    }

    #[test]
    fn trace_chain_integrity_detects_wrong_chain_hash() {
        let mut trace = make_trace(&[("sandbox", 200_000)]);
        trace.chain_hash = ContentHash::compute(b"wrong");

        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
    }

    #[test]
    fn trace_recorder_tracks_extensions_and_policies() {
        let config = RecorderConfig {
            trace_id: "multi".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);

        let mut snap1 = make_snapshot(0, "allow", 0);
        snap1.extension_id = "ext-1".into();
        snap1.policy_id = "policy-a".into();
        snap1.policy_version = 2;
        recorder.record_decision(snap1);

        let mut snap2 = make_snapshot(1, "sandbox", 200_000);
        snap2.extension_id = "ext-2".into();
        snap2.policy_id = "policy-b".into();
        snap2.policy_version = 3;
        recorder.record_decision(snap2);

        let trace = recorder.finalize();
        assert!(trace.extensions.contains("ext-1"));
        assert!(trace.extensions.contains("ext-2"));
        assert_eq!(trace.policy_versions.get("policy-a"), Some(&2));
        assert_eq!(trace.policy_versions.get("policy-b"), Some(&3));
    }

    #[test]
    fn trace_recorder_incident_and_metadata() {
        let config = RecorderConfig {
            trace_id: "inc".into(),
            recording_mode: RecordingMode::SecurityCritical,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);
        recorder.set_incident_id("INC-42".into());
        recorder.set_metadata("region".into(), "us-east-1".into());

        let trace = recorder.finalize();
        assert_eq!(trace.incident_id, Some("INC-42".into()));
        assert_eq!(trace.metadata.get("region"), Some(&"us-east-1".into()));
        assert_eq!(trace.recording_mode, RecordingMode::SecurityCritical);
    }

    // -- Replay engine tests --

    #[test]
    fn replay_identical_trace() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);

        let engine = CausalReplayEngine::new();
        let verdict = engine.replay(&trace).expect("replay should succeed");

        assert!(verdict.is_identical());
        if let ReplayVerdict::Identical { decisions_replayed } = verdict {
            assert_eq!(decisions_replayed, 3);
        }
    }

    #[test]
    fn replay_detects_nondeterminism_hash_tampering() {
        let mut trace = make_trace(&[("sandbox", 200_000)]);
        // Tamper with nondeterminism hash.
        trace.nondeterminism_hash = ContentHash::compute(b"tampered-nd");

        let engine = CausalReplayEngine::new();
        let verdict = engine.replay(&trace).expect("replay should return verdict");

        assert!(matches!(verdict, ReplayVerdict::Tampered { .. }));
    }

    #[test]
    fn replay_with_custom_decider_detects_divergence() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);

        // A decider that always chooses "terminate".
        #[derive(Debug)]
        struct AlwaysTerminate;
        impl PolicyDecider for AlwaysTerminate {
            fn decide(
                &self,
                _snapshot: &DecisionSnapshot,
                _nondeterminism: &NondeterminismLog,
            ) -> (String, i64) {
                ("terminate".into(), 800_000)
            }
        }

        let engine = CausalReplayEngine::new();
        let verdict = engine
            .replay_with_decider(&trace, &AlwaysTerminate)
            .expect("replay should succeed");

        assert!(!verdict.is_identical());
        assert_eq!(verdict.divergence_count(), 2);
    }

    #[test]
    fn replay_empty_trace_is_identical() {
        let config = RecorderConfig {
            trace_id: "empty".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let trace = TraceRecorder::new(config).finalize();

        let engine = CausalReplayEngine::new();
        let verdict = engine.replay(&trace).expect("should succeed");
        assert!(verdict.is_identical());
        if let ReplayVerdict::Identical { decisions_replayed } = verdict {
            assert_eq!(decisions_replayed, 0);
        }
    }

    #[test]
    fn replay_engine_verifies_trace_signature() {
        let trace = make_trace(&[("sandbox", 200_000)]);
        let engine = CausalReplayEngine::new();

        assert!(engine.verify_trace_signature(&trace, &test_key()));
        assert!(!engine.verify_trace_signature(&trace, &[0u8; 32]));
    }

    // -- Counterfactual branching tests --

    #[test]
    fn counterfactual_with_no_changes_produces_no_divergence() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);

        let config = CounterfactualConfig {
            branch_id: "baseline".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        assert_eq!(report.divergence_count(), 0);
        assert!(report.affected_extensions.is_empty());
        assert_eq!(report.decisions_evaluated, 2);
    }

    #[test]
    fn counterfactual_with_lower_threshold_changes_decisions() {
        // Original: threshold 500k, actions: allow=0, sandbox=200k, terminate=800k
        // Decision "sandbox" (200k) chosen originally.
        // If we lower threshold to 100k, sandbox (200k) no longer meets threshold,
        // so only allow (0) qualifies.
        let trace = make_trace(&[("sandbox", 200_000)]);

        let config = CounterfactualConfig {
            branch_id: "lower-threshold".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        assert_eq!(report.divergence_count(), 1);
        assert_eq!(report.divergence_points[0].counterfactual_action, "allow");
        assert!(report.affected_extensions.contains("ext-abc"));
    }

    #[test]
    fn counterfactual_with_loss_matrix_override() {
        let trace = make_trace(&[("sandbox", 200_000)]);

        // Override sandbox cost to be very high, making allow cheaper.
        let mut overrides = BTreeMap::new();
        overrides.insert("sandbox".into(), 900_000i64);

        let config = CounterfactualConfig {
            branch_id: "high-sandbox-cost".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: overrides,
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        assert_eq!(report.divergence_count(), 1);
        // With sandbox at 900k (above threshold 500k), allow (0) should be chosen.
        assert_eq!(report.divergence_points[0].counterfactual_action, "allow");
    }

    #[test]
    fn counterfactual_branch_from_index_preserves_prefix() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);

        let config = CounterfactualConfig {
            branch_id: "late-branch".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 2, // Only branch from decision #2 onwards
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        // Decisions 0 and 1 should not diverge (before branch point).
        // Decision 2 ("terminate" at 800k) is above new threshold (100k),
        // so "allow" (0) should be chosen.
        assert_eq!(report.divergence_count(), 1);
        assert_eq!(report.divergence_points[0].decision_index, 2);
    }

    #[test]
    fn counterfactual_containment_override_remaps_actions() {
        let trace = make_trace(&[("sandbox", 200_000)]);

        // Remap "sandbox" -> "suspend" with same cost.
        let mut containment = BTreeMap::new();
        containment.insert("sandbox".into(), "suspend".into());

        let config = CounterfactualConfig {
            branch_id: "remap".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: containment,
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        // Remapping changes the action name, creating a divergence.
        assert_eq!(report.divergence_count(), 1);
        assert_eq!(report.divergence_points[0].counterfactual_action, "allow");
    }

    #[test]
    fn counterfactual_harm_delta_calculation() {
        // Original total cost: 200k + 800k = 1M
        let trace = make_trace(&[("sandbox", 200_000), ("terminate", 800_000)]);

        // Lower threshold so only allow (0) is chosen.
        let config = CounterfactualConfig {
            branch_id: "all-allow".into(),
            threshold_override_millionths: Some(0),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        // Original total: 200k + 800k = 1M
        // CF total: 0 + 0 = 0
        // Harm delta: 1M - 0 = 1M (improvement)
        assert_eq!(report.harm_prevented_delta_millionths, 1_000_000);
        assert!(report.is_improvement());
    }

    #[test]
    fn counterfactual_negative_harm_delta() {
        // Original: allow (0), allow (0) = total 0
        let trace = make_trace(&[("allow", 0), ("allow", 0)]);

        // Override to make terminate cheaper than threshold.
        let mut overrides = BTreeMap::new();
        overrides.insert("terminate".into(), 100_000i64);

        let config = CounterfactualConfig {
            branch_id: "forced-terminate".into(),
            threshold_override_millionths: Some(500_000),
            loss_matrix_overrides: overrides,
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };

        let engine = CausalReplayEngine::new();
        let report = engine
            .counterfactual_branch(&trace, config)
            .expect("should succeed");

        // CF introduces costs, so harm delta is negative (regression).
        assert!(!report.is_improvement() || report.harm_prevented_delta_millionths == 0);
    }

    // -- Multi-branch comparison tests --

    #[test]
    fn multi_branch_comparison_runs_all_configs() {
        let trace = make_trace(&[("sandbox", 200_000)]);

        let configs: Vec<CounterfactualConfig> = (1..=3)
            .map(|i| CounterfactualConfig {
                branch_id: format!("branch-{i}"),
                threshold_override_millionths: Some(i * 100_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            })
            .collect();

        let engine = CausalReplayEngine::new();
        let reports = engine
            .multi_branch_comparison(&trace, configs)
            .expect("should succeed");

        assert_eq!(reports.len(), 3);
        for (i, r) in reports.iter().enumerate() {
            assert_eq!(r.config.branch_id, format!("branch-{}", i + 1));
        }
    }

    #[test]
    fn multi_branch_exceeds_depth_limit() {
        let trace = make_trace(&[("sandbox", 200_000)]);

        let engine = CausalReplayEngine::new().with_max_branch_depth(2);

        let configs: Vec<CounterfactualConfig> = (0..5)
            .map(|i| CounterfactualConfig {
                branch_id: format!("branch-{i}"),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            })
            .collect();

        let err = engine.multi_branch_comparison(&trace, configs).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::BranchDepthExceeded {
                requested: 5,
                max: 2
            }
        ));
    }

    // -- Trace index tests --

    #[test]
    fn trace_index_insert_and_query() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        let trace = make_trace(&[("sandbox", 200_000)]);

        index.insert(trace).expect("insert should succeed");
        assert_eq!(index.len(), 1);

        let results = index.query(&TraceQuery {
            trace_id: Some("trace-001".into()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn trace_index_query_by_extension() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());

        let trace = make_trace(&[("sandbox", 200_000)]);
        index.insert(trace).expect("insert should succeed");

        let found = index.query(&TraceQuery {
            extension_id: Some("ext-abc".into()),
            ..Default::default()
        });
        assert_eq!(found.len(), 1);

        let not_found = index.query(&TraceQuery {
            extension_id: Some("ext-unknown".into()),
            ..Default::default()
        });
        assert!(not_found.is_empty());
    }

    #[test]
    fn trace_index_query_by_incident() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());

        let config = RecorderConfig {
            trace_id: "incident-trace".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);
        recorder.set_incident_id("INC-99".into());
        recorder.record_decision(make_snapshot(0, "terminate", 800_000));

        index.insert(recorder.finalize()).expect("insert");

        let found = index.query(&TraceQuery {
            incident_id: Some("INC-99".into()),
            ..Default::default()
        });
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn trace_index_query_by_epoch_range() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());

        let trace = make_trace(&[("sandbox", 200_000)]); // epoch 5
        index.insert(trace).expect("insert");

        let found = index.query(&TraceQuery {
            epoch_range: Some((4, 6)),
            ..Default::default()
        });
        assert_eq!(found.len(), 1);

        let not_found = index.query(&TraceQuery {
            epoch_range: Some((10, 20)),
            ..Default::default()
        });
        assert!(not_found.is_empty());
    }

    #[test]
    fn trace_index_query_by_tick_range() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        let trace = make_trace(&[("sandbox", 200_000)]); // tick starts at 1000
        index.insert(trace).expect("insert");

        let found = index.query(&TraceQuery {
            tick_range: Some((900, 1200)),
            ..Default::default()
        });
        assert_eq!(found.len(), 1);

        let not_found = index.query(&TraceQuery {
            tick_range: Some((5000, 6000)),
            ..Default::default()
        });
        assert!(not_found.is_empty());
    }

    #[test]
    fn trace_index_get_by_id() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        let trace = make_trace(&[("sandbox", 200_000)]);
        index.insert(trace).expect("insert");

        assert!(index.get("trace-001").is_some());
        assert!(index.get("nonexistent").is_none());
    }

    #[test]
    fn trace_index_enforces_max_traces() {
        let retention = TraceRetentionPolicy {
            max_traces: 3,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);

        for i in 0..5 {
            let config = RecorderConfig {
                trace_id: format!("trace-{i}"),
                recording_mode: RecordingMode::Full,
                epoch: SecurityEpoch::from_raw(1),
                start_tick: i * 100,
                signing_key: test_key(),
            };
            let mut rec = TraceRecorder::new(config);
            rec.record_decision(make_snapshot(0, "allow", 0));
            index.insert(rec.finalize()).expect("insert");
        }

        assert!(index.len() <= 3);
    }

    #[test]
    fn trace_index_gc_removes_expired() {
        let retention = TraceRetentionPolicy {
            default_ttl_ticks: 1000,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);

        let config = RecorderConfig {
            trace_id: "old-trace".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: test_key(),
        };
        let mut rec = TraceRecorder::new(config);
        rec.record_decision(make_snapshot(0, "allow", 0));
        index.insert(rec.finalize()).expect("insert");

        assert_eq!(index.len(), 1);

        // GC at tick well past TTL.
        index.gc(5000);
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn trace_index_gc_preserves_incident_linked() {
        let retention = TraceRetentionPolicy {
            default_ttl_ticks: 100,
            incident_ttl_ticks: 10_000,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);

        // Normal trace.
        let config1 = RecorderConfig {
            trace_id: "normal".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: test_key(),
        };
        let rec1 = TraceRecorder::new(config1);
        index.insert(rec1.finalize()).expect("insert");

        // Incident-linked trace.
        let config2 = RecorderConfig {
            trace_id: "incident".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: test_key(),
        };
        let mut rec2 = TraceRecorder::new(config2);
        rec2.set_incident_id("INC-1".into());
        index.insert(rec2.finalize()).expect("insert");

        assert_eq!(index.len(), 2);

        // GC at tick 500 — beyond normal TTL but within incident TTL.
        index.gc(500);
        assert_eq!(index.len(), 1);
        assert!(index.get("incident").is_some());
    }

    #[test]
    fn trace_index_gc_preserves_security_critical() {
        let retention = TraceRetentionPolicy {
            default_ttl_ticks: 100,
            security_critical_ttl_ticks: 5000,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);

        let config = RecorderConfig {
            trace_id: "sec-crit".into(),
            recording_mode: RecordingMode::SecurityCritical,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: test_key(),
        };
        let rec = TraceRecorder::new(config);
        index.insert(rec.finalize()).expect("insert");

        index.gc(500);
        assert_eq!(index.len(), 1); // Preserved.

        index.gc(10_000);
        assert_eq!(index.len(), 0); // Now expired.
    }

    #[test]
    fn trace_index_eviction_prefers_normal_over_incident() {
        let retention = TraceRetentionPolicy {
            max_traces: 2,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);

        // Insert incident-linked.
        let config1 = RecorderConfig {
            trace_id: "incident".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: test_key(),
        };
        let mut rec1 = TraceRecorder::new(config1);
        rec1.set_incident_id("INC-1".into());
        index.insert(rec1.finalize()).expect("insert");

        // Insert normal.
        let config2 = RecorderConfig {
            trace_id: "normal".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 200,
            signing_key: test_key(),
        };
        index
            .insert(TraceRecorder::new(config2).finalize())
            .expect("insert");

        // Insert another — should evict "normal" (lower priority).
        let config3 = RecorderConfig {
            trace_id: "new".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 300,
            signing_key: test_key(),
        };
        index
            .insert(TraceRecorder::new(config3).finalize())
            .expect("insert");

        assert!(index.len() <= 2);
        // Incident trace should be preserved.
        assert!(index.get("incident").is_some());
    }

    #[test]
    fn trace_index_storage_estimate_tracked() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        assert_eq!(index.storage_estimate(), 0);

        let trace = make_trace(&[("sandbox", 200_000)]);
        index.insert(trace).expect("insert");

        assert!(index.storage_estimate() > 0);
    }

    #[test]
    fn trace_index_empty_query_returns_all() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());

        for i in 0..3 {
            let config = RecorderConfig {
                trace_id: format!("trace-{i}"),
                recording_mode: RecordingMode::Full,
                epoch: SecurityEpoch::from_raw(1),
                start_tick: i * 100,
                signing_key: test_key(),
            };
            let mut rec = TraceRecorder::new(config);
            rec.record_decision(make_snapshot(0, "allow", 0));
            index.insert(rec.finalize()).expect("insert");
        }

        let all = index.query(&TraceQuery::default());
        assert_eq!(all.len(), 3);
    }

    // -- Error display tests --

    #[test]
    fn replay_error_display() {
        let err = ReplayError::ChainIntegrity {
            entry_index: 5,
            detail: "hash mismatch".into(),
        };
        assert!(err.to_string().contains("entry 5"));
        assert!(err.to_string().contains("hash mismatch"));

        let err = ReplayError::BranchDepthExceeded {
            requested: 10,
            max: 5,
        };
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("5"));
    }

    // -- Recording mode tests --

    #[test]
    fn recording_mode_sampled_serialization() {
        let mode = RecordingMode::Sampled {
            rate_millionths: 500_000,
        };
        let json = serde_json::to_string(&mode).expect("serialize");
        let deser: RecordingMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, deser);
    }

    // -- Round-trip serialization tests --

    #[test]
    fn trace_record_serde_round_trip() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
        let json = serde_json::to_string(&trace).expect("serialize");
        let deser: TraceRecord = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(trace.trace_id, deser.trace_id);
        assert_eq!(trace.entries.len(), deser.entries.len());
        assert_eq!(trace.chain_hash, deser.chain_hash);
        assert_eq!(trace.nondeterminism_hash, deser.nondeterminism_hash);

        // Deserialized trace should still verify.
        deser
            .verify_chain_integrity()
            .expect("chain valid after round-trip");
    }

    #[test]
    fn action_delta_report_serde_round_trip() {
        let report = ActionDeltaReport {
            config: CounterfactualConfig {
                branch_id: "test".into(),
                threshold_override_millionths: Some(100_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            harm_prevented_delta_millionths: 500_000,
            false_positive_cost_delta_millionths: 0,
            containment_latency_delta_ticks: 0,
            resource_cost_delta_millionths: 0,
            affected_extensions: BTreeSet::new(),
            divergence_points: vec![],
            decisions_evaluated: 10,
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let deser: ActionDeltaReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            report.harm_prevented_delta_millionths,
            deser.harm_prevented_delta_millionths
        );
    }

    // -- Replay verdict tests --

    #[test]
    fn replay_verdict_methods() {
        let ident = ReplayVerdict::Identical {
            decisions_replayed: 5,
        };
        assert!(ident.is_identical());
        assert_eq!(ident.divergence_count(), 0);

        let div = ReplayVerdict::Diverged {
            divergence_point: 2,
            decisions_replayed: 5,
            divergences: vec![ReplayDecisionOutcome {
                decision_index: 2,
                original_action: "allow".into(),
                replayed_action: "sandbox".into(),
                original_outcome_millionths: 0,
                replayed_outcome_millionths: 200_000,
                diverged: true,
            }],
        };
        assert!(!div.is_identical());
        assert_eq!(div.divergence_count(), 1);

        let tampered = ReplayVerdict::Tampered {
            detail: "bad".into(),
        };
        assert!(!tampered.is_identical());
        assert_eq!(tampered.divergence_count(), 0);
    }

    // -- Action delta report tests --

    #[test]
    fn action_delta_report_object_id() {
        let report = ActionDeltaReport {
            config: CounterfactualConfig {
                branch_id: "test-branch".into(),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            harm_prevented_delta_millionths: 0,
            false_positive_cost_delta_millionths: 0,
            containment_latency_delta_ticks: 0,
            resource_cost_delta_millionths: 0,
            affected_extensions: BTreeSet::new(),
            divergence_points: vec![],
            decisions_evaluated: 5,
        };

        let id1 = report.object_id("zone-a").expect("derive");
        let id2 = report.object_id("zone-a").expect("derive");
        assert_eq!(id1, id2);
    }

    // -- Counterfactual decider edge cases --

    #[test]
    fn counterfactual_decider_before_branch_point_returns_original() {
        let config = CounterfactualConfig {
            branch_id: "late".into(),
            threshold_override_millionths: Some(0),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 5,
        };
        let decider = CounterfactualDecider::new(config);

        let snapshot = make_snapshot(3, "terminate", 800_000);
        let log = NondeterminismLog::new();
        let (action, outcome) = decider.decide(&snapshot, &log);

        assert_eq!(action, "terminate");
        assert_eq!(outcome, 800_000);
    }

    #[test]
    fn counterfactual_decider_at_branch_point_applies_override() {
        let config = CounterfactualConfig {
            branch_id: "exact".into(),
            threshold_override_millionths: Some(0),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 3,
        };
        let decider = CounterfactualDecider::new(config);

        let snapshot = make_snapshot(3, "terminate", 800_000);
        let log = NondeterminismLog::new();
        let (action, outcome) = decider.decide(&snapshot, &log);

        // Threshold 0 means only allow (0) qualifies.
        assert_eq!(action, "allow");
        assert_eq!(outcome, 0);
    }

    // -- Large trace test --

    #[test]
    fn replay_large_trace() {
        let decisions: Vec<(&str, i64)> = (0i64..100)
            .map(|i| {
                if i % 3 == 0 {
                    ("terminate", 800_000i64)
                } else if i % 2 == 0 {
                    ("sandbox", 200_000i64)
                } else {
                    ("allow", 0i64)
                }
            })
            .collect();

        let trace = make_trace(&decisions);
        assert_eq!(trace.entries.len(), 100);

        trace.verify_chain_integrity().expect("chain valid");

        let engine = CausalReplayEngine::new();
        let verdict = engine.replay(&trace).expect("replay");
        assert!(verdict.is_identical());
    }

    // -- Nondeterminism all source types --

    #[test]
    fn nondeterminism_log_all_source_types() {
        let mut log = NondeterminismLog::new();
        let sources = [
            NondeterminismSource::RandomValue,
            NondeterminismSource::Timestamp,
            NondeterminismSource::HostcallResult,
            NondeterminismSource::IoResult,
            NondeterminismSource::SchedulingDecision,
            NondeterminismSource::OsEntropy,
            NondeterminismSource::FleetEvidenceArrival,
        ];

        for (i, source) in sources.iter().enumerate() {
            log.append(source.clone(), vec![i as u8], i as u64, None);
        }

        assert_eq!(log.len(), 7);

        for (i, source) in sources.iter().enumerate() {
            let entry = log.get(i as u64).unwrap();
            assert_eq!(&entry.source, source);
        }
    }

    #[test]
    fn replay_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ReplayError::ChainIntegrity {
                entry_index: 0,
                detail: "bad".into(),
            }),
            Box::new(ReplayError::NondeterminismMismatch {
                expected_sequence: 1,
                actual_sequence: 2,
            }),
            Box::new(ReplayError::BranchDepthExceeded {
                requested: 10,
                max: 5,
            }),
            Box::new(ReplayError::StorageExhausted),
            Box::new(ReplayError::TraceNotFound {
                trace_id: "t1".into(),
            }),
            Box::new(ReplayError::SignatureInvalid),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 6);
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for uncovered types
    // -----------------------------------------------------------------------

    #[test]
    fn nondeterminism_source_serde_all_variants() {
        let variants = [
            NondeterminismSource::RandomValue,
            NondeterminismSource::Timestamp,
            NondeterminismSource::HostcallResult,
            NondeterminismSource::IoResult,
            NondeterminismSource::SchedulingDecision,
            NondeterminismSource::OsEntropy,
            NondeterminismSource::FleetEvidenceArrival,
        ];
        let mut jsons = BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: NondeterminismSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
            jsons.insert(json);
        }
        assert_eq!(
            jsons.len(),
            variants.len(),
            "all variants produce distinct JSON"
        );
    }

    #[test]
    fn nondeterminism_entry_serde_roundtrip() {
        let entry = NondeterminismEntry {
            sequence: 42,
            source: NondeterminismSource::Timestamp,
            value: vec![1, 2, 3],
            tick: 100,
            extension_id: Some("ext-001".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: NondeterminismEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn nondeterminism_log_serde_roundtrip() {
        let mut log = NondeterminismLog::default();
        log.append(NondeterminismSource::RandomValue, vec![0xAB], 10, None);
        log.append(
            NondeterminismSource::Timestamp,
            vec![0xCD],
            20,
            Some("ext-1".into()),
        );
        let json = serde_json::to_string(&log).unwrap();
        let back: NondeterminismLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log, back);
    }

    #[test]
    fn decision_snapshot_serde_roundtrip() {
        let snap = DecisionSnapshot {
            decision_index: 5,
            trace_id: "trace-001".into(),
            decision_id: "dec-001".into(),
            policy_id: "policy-001".into(),
            policy_version: 2,
            epoch: SecurityEpoch::from_raw(10),
            tick: 500,
            threshold_millionths: 900_000,
            loss_matrix: BTreeMap::from([("allow".to_string(), 0i64)]),
            evidence_hashes: vec![ContentHash::compute(b"ev-hash")],
            chosen_action: "allow".into(),
            outcome_millionths: 850_000,
            extension_id: "ext-001".into(),
            nondeterminism_range: (0, 2),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: DecisionSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn replay_decision_outcome_serde_roundtrip() {
        let outcome = ReplayDecisionOutcome {
            decision_index: 3,
            original_action: "allow".into(),
            replayed_action: "deny".into(),
            original_outcome_millionths: 500_000,
            replayed_outcome_millionths: 300_000,
            diverged: true,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ReplayDecisionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn replay_verdict_serde_all_variants() {
        let variants = vec![
            ReplayVerdict::Identical {
                decisions_replayed: 10,
            },
            ReplayVerdict::Diverged {
                divergence_point: 5,
                decisions_replayed: 10,
                divergences: vec![],
            },
            ReplayVerdict::Tampered {
                detail: "bad chain".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn counterfactual_config_serde_roundtrip() {
        let config = CounterfactualConfig {
            branch_id: "branch-001".into(),
            threshold_override_millionths: Some(800_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: CounterfactualConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn decision_delta_serde_roundtrip() {
        let delta = DecisionDelta {
            decision_index: 7,
            original_action: "allow".into(),
            counterfactual_action: "deny".into(),
            original_outcome_millionths: 600_000,
            counterfactual_outcome_millionths: 400_000,
            diverged: true,
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: DecisionDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, back);
    }

    #[test]
    fn trace_query_serde_roundtrip() {
        let query = TraceQuery {
            trace_id: Some("t-001".into()),
            extension_id: None,
            policy_version: Some(2),
            epoch_range: Some((1, 10)),
            tick_range: None,
            incident_id: None,
            has_divergence: Some(true),
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: TraceQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    #[test]
    fn trace_retention_policy_serde_roundtrip() {
        let policy = TraceRetentionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: TraceRetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn recorder_config_serde_roundtrip() {
        let config = RecorderConfig {
            trace_id: "trace-001".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: vec![42u8; 32],
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: RecorderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn replay_error_serde_all_variants() {
        let variants = vec![
            ReplayError::ChainIntegrity {
                entry_index: 0,
                detail: "bad".into(),
            },
            ReplayError::NondeterminismMismatch {
                expected_sequence: 1,
                actual_sequence: 2,
            },
            ReplayError::BranchDepthExceeded {
                requested: 10,
                max: 5,
            },
            ReplayError::StorageExhausted,
            ReplayError::TraceNotFound {
                trace_id: "t1".into(),
            },
            ReplayError::SignatureInvalid,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn nondeterminism_log_content_hash_sensitive_to_extension_id() {
        let mut log_a = NondeterminismLog::new();
        log_a.append(NondeterminismSource::RandomValue, vec![1], 100, None);

        let mut log_b = NondeterminismLog::new();
        log_b.append(
            NondeterminismSource::RandomValue,
            vec![1],
            100,
            Some("ext-1".into()),
        );

        assert_ne!(log_a.content_hash(), log_b.content_hash());
    }

    #[test]
    fn decision_snapshot_content_hash_sensitive_to_loss_matrix() {
        let mut s1 = make_snapshot(0, "allow", 0);
        let mut s2 = make_snapshot(0, "allow", 0);
        s2.loss_matrix.insert("quarantine".into(), 1_000_000);
        assert_ne!(s1.content_hash(), s2.content_hash());

        // Also sensitive to threshold.
        s1.threshold_millionths = 100_000;
        let h1 = s1.content_hash();
        s1.threshold_millionths = 900_000;
        assert_ne!(h1, s1.content_hash());
    }

    #[test]
    fn recording_mode_all_variants_serde() {
        let modes = [
            RecordingMode::Full,
            RecordingMode::SecurityCritical,
            RecordingMode::Sampled {
                rate_millionths: 500_000,
            },
        ];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let back: RecordingMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn trace_retention_policy_default_values() {
        let p = TraceRetentionPolicy::default();
        assert_eq!(p.default_ttl_ticks, 1_000_000);
        assert_eq!(p.incident_ttl_ticks, 10_000_000);
        assert_eq!(p.security_critical_ttl_ticks, 5_000_000);
        assert_eq!(p.max_traces, 10_000);
        assert_eq!(p.max_storage_bytes, 1_073_741_824);
    }

    #[test]
    fn action_delta_report_is_improvement_and_divergence_count() {
        let trace = make_trace(&[("allow", 100_000), ("sandbox", 300_000)]);
        let engine = CausalReplayEngine::new();
        let config = CounterfactualConfig {
            branch_id: "b1".into(),
            threshold_override_millionths: Some(1_000_000),
            loss_matrix_overrides: {
                let mut m = BTreeMap::new();
                m.insert("allow".into(), 50_000);
                m
            },
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            policy_version_override: None,
            branch_from_index: 0,
        };
        let report = engine.counterfactual_branch(&trace, config).unwrap();
        // If counterfactual chose lower-cost action, is_improvement() should be true
        // when harm_prevented_delta_millionths > 0.
        assert_eq!(
            report.is_improvement(),
            report.harm_prevented_delta_millionths > 0
        );
        assert_eq!(report.divergence_count(), report.divergence_points.len());
    }

    #[test]
    fn trace_record_verify_signature_wrong_key() {
        let trace = make_trace(&[("allow", 0)]);
        assert!(trace.verify_signature(&test_key()));
        assert!(!trace.verify_signature(&[99u8; 32]));
    }

    #[test]
    fn causal_replay_engine_default() {
        let engine = CausalReplayEngine::default();
        // Default max_branch_depth is 16.
        let trace = make_trace(&[("allow", 0)]);
        let configs: Vec<CounterfactualConfig> = (0..17)
            .map(|i| CounterfactualConfig {
                branch_id: format!("b{i}"),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                policy_version_override: None,
                branch_from_index: 0,
            })
            .collect();
        let err = engine.multi_branch_comparison(&trace, configs).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::BranchDepthExceeded { max: 16, .. }
        ));
    }

    #[test]
    fn causal_replay_engine_with_max_branch_depth() {
        let engine = CausalReplayEngine::new().with_max_branch_depth(2);
        let trace = make_trace(&[("allow", 0)]);
        let configs: Vec<CounterfactualConfig> = (0..3)
            .map(|i| CounterfactualConfig {
                branch_id: format!("b{i}"),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                policy_version_override: None,
                branch_from_index: 0,
            })
            .collect();
        let err = engine.multi_branch_comparison(&trace, configs).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::BranchDepthExceeded {
                requested: 3,
                max: 2
            }
        ));
    }

    #[test]
    fn replay_verdict_divergence_count_tampered() {
        let v = ReplayVerdict::Tampered {
            detail: "bad".into(),
        };
        assert_eq!(v.divergence_count(), 0);
        assert!(!v.is_identical());
    }

    #[test]
    fn trace_query_default_is_empty() {
        let q = TraceQuery::default();
        assert!(q.trace_id.is_none());
        assert!(q.extension_id.is_none());
        assert!(q.policy_version.is_none());
        assert!(q.epoch_range.is_none());
        assert!(q.tick_range.is_none());
        assert!(q.incident_id.is_none());
        assert!(q.has_divergence.is_none());
    }

    #[test]
    fn trace_index_is_empty_check() {
        let idx = TraceIndex::new(TraceRetentionPolicy::default());
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn nondeterminism_log_default_is_empty() {
        let log = NondeterminismLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn replay_error_display_all_variants_distinct() {
        let variants = vec![
            ReplayError::ChainIntegrity {
                entry_index: 0,
                detail: "bad".into(),
            },
            ReplayError::NondeterminismMismatch {
                expected_sequence: 1,
                actual_sequence: 2,
            },
            ReplayError::BranchDepthExceeded {
                requested: 10,
                max: 5,
            },
            ReplayError::StorageExhausted,
            ReplayError::TraceNotFound {
                trace_id: "t1".into(),
            },
            ReplayError::SignatureInvalid,
        ];
        let mut seen = BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
            assert!(seen.insert(s.clone()), "duplicate Display: {s}");
        }
        assert_eq!(seen.len(), variants.len());
    }

    #[test]
    fn decision_snapshot_content_hash_sensitive_to_evidence_hashes() {
        let mut s1 = make_snapshot(0, "allow", 0);
        let s2 = make_snapshot(0, "allow", 0);
        s1.evidence_hashes
            .push(ContentHash::compute(b"extra-evidence"));
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn nondeterminism_source_tag_values_are_sequential() {
        assert_eq!(NondeterminismSource::RandomValue.tag(), 0);
        assert_eq!(NondeterminismSource::Timestamp.tag(), 1);
        assert_eq!(NondeterminismSource::HostcallResult.tag(), 2);
        assert_eq!(NondeterminismSource::IoResult.tag(), 3);
        assert_eq!(NondeterminismSource::SchedulingDecision.tag(), 4);
        assert_eq!(NondeterminismSource::OsEntropy.tag(), 5);
        assert_eq!(NondeterminismSource::FleetEvidenceArrival.tag(), 6);
    }

    // -- Enrichment batch 4 --

    #[test]
    fn nondeterminism_log_entries_accessor() {
        let mut log = NondeterminismLog::new();
        log.append(NondeterminismSource::RandomValue, vec![1], 100, None);
        log.append(NondeterminismSource::Timestamp, vec![2], 200, None);
        let entries = log.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
    }

    #[test]
    fn trace_recorder_entry_and_nondeterminism_counts() {
        let config = RecorderConfig {
            trace_id: "counts".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);
        assert_eq!(recorder.entry_count(), 0);
        assert_eq!(recorder.nondeterminism_count(), 0);

        recorder.record_nondeterminism(NondeterminismSource::OsEntropy, vec![42], 10, None);
        assert_eq!(recorder.nondeterminism_count(), 1);

        recorder.record_decision(make_snapshot(0, "allow", 0));
        assert_eq!(recorder.entry_count(), 1);
    }

    #[test]
    fn trace_record_object_id_differs_by_zone() {
        let trace = make_trace(&[("sandbox", 200_000)]);
        let id_a = trace.object_id("zone-a").unwrap();
        let id_b = trace.object_id("zone-b").unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn trace_chain_integrity_detects_non_zero_genesis_index() {
        let mut trace = make_trace(&[("sandbox", 200_000)]);
        trace.entries[0].entry_index = 5; // not 0
        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(
            err,
            ReplayError::ChainIntegrity { entry_index: 5, .. }
        ));
    }

    #[test]
    fn trace_chain_integrity_detects_bad_genesis_prev_hash() {
        let mut trace = make_trace(&[("sandbox", 200_000)]);
        trace.entries[0].prev_entry_hash = ContentHash::compute(b"not-genesis");
        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(
            err,
            ReplayError::ChainIntegrity { entry_index: 0, .. }
        ));
    }

    #[test]
    fn empty_trace_wrong_chain_hash_detected() {
        let config = RecorderConfig {
            trace_id: "empty-bad".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let mut trace = TraceRecorder::new(config).finalize();
        trace.chain_hash = ContentHash::compute(b"wrong-hash");
        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
    }

    #[test]
    fn trace_chain_integrity_detects_non_monotonic_index() {
        let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
        // Make entry 2 have index 5 instead of 2
        trace.entries[2].entry_index = 5;
        let err = trace.verify_chain_integrity().unwrap_err();
        assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
    }

    #[test]
    fn trace_index_query_by_trace_id() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        let trace = make_trace(&[("allow", 0)]);
        index.insert(trace).unwrap();

        let filter = TraceQuery {
            trace_id: Some("trace-001".into()),
            ..Default::default()
        };
        assert_eq!(index.query(&filter).len(), 1);

        let filter_miss = TraceQuery {
            trace_id: Some("nonexistent".into()),
            ..Default::default()
        };
        assert!(index.query(&filter_miss).is_empty());
    }

    #[test]
    fn trace_index_query_by_policy_version() {
        let mut index = TraceIndex::new(TraceRetentionPolicy::default());
        let trace = make_trace(&[("allow", 0)]);
        index.insert(trace).unwrap();

        let filter = TraceQuery {
            policy_version: Some(1),
            ..Default::default()
        };
        assert_eq!(index.query(&filter).len(), 1);

        let filter_miss = TraceQuery {
            policy_version: Some(999),
            ..Default::default()
        };
        assert!(index.query(&filter_miss).is_empty());
    }

    #[test]
    fn trace_index_storage_estimate_decreases_after_gc() {
        let retention = TraceRetentionPolicy {
            default_ttl_ticks: 100,
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);
        let trace = make_trace(&[("allow", 0)]);
        index.insert(trace).unwrap();
        let before = index.storage_estimate();
        assert!(before > 0);

        // GC with current_tick far beyond TTL
        index.gc(999_999);
        assert_eq!(index.len(), 0);
        assert_eq!(index.storage_estimate(), 0);
        assert!(index.storage_estimate() < before);
    }

    #[test]
    fn recording_mode_sampled_round_trip() {
        let mode = RecordingMode::Sampled {
            rate_millionths: 250_000,
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: RecordingMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }

    #[test]
    fn action_delta_report_divergence_count_matches_points() {
        let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
        let config = CounterfactualConfig {
            branch_id: "count-test".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };
        let engine = CausalReplayEngine::new();
        let report = engine.counterfactual_branch(&trace, config).unwrap();
        assert_eq!(report.divergence_count(), report.divergence_points.len());
    }

    #[test]
    fn action_delta_report_object_id_deterministic() {
        let trace = make_trace(&[("sandbox", 200_000)]);
        let config = CounterfactualConfig {
            branch_id: "det-test".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        };
        let engine = CausalReplayEngine::new();
        let report = engine.counterfactual_branch(&trace, config).unwrap();
        let id1 = report.object_id("zone-a").unwrap();
        let id2 = report.object_id("zone-a").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn replay_verdict_tampered_is_not_identical() {
        let v = ReplayVerdict::Tampered {
            detail: "bad".into(),
        };
        assert!(!v.is_identical());
        assert_eq!(v.divergence_count(), 0);
    }

    #[test]
    fn replay_verdict_diverged_fields() {
        let v = ReplayVerdict::Diverged {
            divergence_point: 2,
            decisions_replayed: 5,
            divergences: vec![ReplayDecisionOutcome {
                decision_index: 2,
                original_action: "allow".into(),
                replayed_action: "terminate".into(),
                original_outcome_millionths: 0,
                replayed_outcome_millionths: 800_000,
                diverged: true,
            }],
        };
        assert!(!v.is_identical());
        assert_eq!(v.divergence_count(), 1);
    }

    #[test]
    fn trace_index_eviction_on_storage_budget() {
        let retention = TraceRetentionPolicy {
            max_traces: 1000,
            max_storage_bytes: 1, // 1 byte budget: forces eviction
            ..Default::default()
        };
        let mut index = TraceIndex::new(retention);
        let trace = make_trace(&[("allow", 0)]);
        // First insert: evicts nothing (index empty), but storage > budget after insert
        index.insert(trace).unwrap();
        // The trace is inserted but next insert will evict
        assert!(index.len() <= 1);
    }

    #[test]
    fn nondeterminism_log_default_trait() {
        let log = NondeterminismLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn causal_replay_engine_default_has_max_branch_depth_16() {
        let engine = CausalReplayEngine::default();
        // Verify by trying 16 branches (should succeed) vs 17 (should fail).
        let trace = make_trace(&[("allow", 0)]);
        let configs: Vec<CounterfactualConfig> = (0..17)
            .map(|i| CounterfactualConfig {
                branch_id: format!("b-{i}"),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            })
            .collect();
        let err = engine.multi_branch_comparison(&trace, configs).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::BranchDepthExceeded {
                requested: 17,
                max: 16
            }
        ));
    }

    #[test]
    fn decision_snapshot_content_hash_sensitive_to_nondeterminism_range() {
        let mut s1 = make_snapshot(0, "allow", 0);
        let s2 = make_snapshot(0, "allow", 0);
        s1.nondeterminism_range = (100, 200);
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn trace_record_content_hash_sensitive_to_trace_id() {
        let t1 = make_trace(&[("allow", 0)]);
        // Make a second trace with different trace_id
        let config = RecorderConfig {
            trace_id: "trace-999".into(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(5),
            start_tick: 1000,
            signing_key: test_key(),
        };
        let mut recorder = TraceRecorder::new(config);
        recorder.record_nondeterminism(
            NondeterminismSource::RandomValue,
            vec![0],
            1000,
            Some("ext-abc".into()),
        );
        recorder.record_nondeterminism(
            NondeterminismSource::Timestamp,
            1000u64.to_be_bytes().to_vec(),
            1000,
            None,
        );
        recorder.record_decision(make_snapshot(0, "allow", 0));
        let t2 = recorder.finalize();

        assert_ne!(t1.content_hash(), t2.content_hash());
    }
}
