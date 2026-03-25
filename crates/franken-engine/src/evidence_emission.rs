//! Canonical evidence emission for all high-impact extension-host actions.
//!
//! Wires `franken-evidence` into the extension-host subsystem so that every
//! high-impact action emits a structured, tamper-evident evidence entry.
//! Each entry is linked to `trace_id`, `decision_id`, `policy_id`, and an
//! artifact content hash.
//!
//! # Action categories
//!
//! | Category                | Source                                 |
//! |-------------------------|----------------------------------------|
//! | `DecisionContract`      | Safety actions from bd-3a5e            |
//! | `RegionLifecycle`       | Region create/destroy from bd-1ukb     |
//! | `Cancellation`          | Cancel events from bd-2wz9             |
//! | `ObligationLifecycle`   | Obligation CRUD from bd-m9pa           |
//! | `ExtensionLifecycle`    | Extension load/unload/transition       |
//! | `ContainmentAction`     | Sandbox/suspend/terminate/quarantine   |
//!
//! Plan reference: Section 10.13, item 10, bd-uvmm.
//! Cross-refs: bd-3a5e (decision contracts), bd-1ukb (regions), bd-2sbb
//! (replay checks), bd-36of (dashboard).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::{
    ContextAdapter, DecisionId, EvidenceLedger, EvidenceLedgerBuilder, PolicyId, TraceId,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT_NAME: &str = "evidence-emission";
const SCHEMA_VERSION: &str = "evidence-v1";

/// Default bounded-buffer capacity for evidence entries.
const DEFAULT_BUFFER_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// ActionCategory — taxonomy of high-impact actions
// ---------------------------------------------------------------------------

/// Categories of high-impact actions that require evidence emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    /// Safety decision contract evaluation (bd-3a5e).
    DecisionContract,
    /// Region creation or destruction (bd-1ukb).
    RegionLifecycle,
    /// Cancellation event (bd-2wz9).
    Cancellation,
    /// Obligation creation, fulfillment, or failure (bd-m9pa).
    ObligationLifecycle,
    /// Extension load, unload, lifecycle transition.
    ExtensionLifecycle,
    /// Containment action (sandbox, suspend, terminate, quarantine).
    ContainmentAction,
}

impl ActionCategory {
    pub const ALL: [ActionCategory; 6] = [
        Self::DecisionContract,
        Self::RegionLifecycle,
        Self::Cancellation,
        Self::ObligationLifecycle,
        Self::ExtensionLifecycle,
        Self::ContainmentAction,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecisionContract => "decision_contract",
            Self::RegionLifecycle => "region_lifecycle",
            Self::Cancellation => "cancellation",
            Self::ObligationLifecycle => "obligation_lifecycle",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::ContainmentAction => "containment_action",
        }
    }
}

impl fmt::Display for ActionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EvidenceEntryId — unique identifier for each entry
// ---------------------------------------------------------------------------

/// Unique, deterministic evidence entry identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceEntryId(String);

impl EvidenceEntryId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EvidenceEntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// EvidenceEmissionRequest — input for emitting evidence
// ---------------------------------------------------------------------------

/// All information needed to emit a canonical evidence entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEmissionRequest {
    /// Which category of high-impact action triggered this.
    pub category: ActionCategory,
    /// Human-readable action name (e.g., "extension_quarantine", "region_create").
    pub action_name: String,
    /// Trace ID linking to the originating operation.
    pub trace_id: TraceId,
    /// Decision ID linking to the authorizing decision contract.
    pub decision_id: DecisionId,
    /// Policy ID identifying the policy version evaluated.
    pub policy_id: PolicyId,
    /// Monotonic timestamp in milliseconds (for deterministic replay).
    pub ts_unix_ms: u64,
    /// Posterior probability distribution (if available).
    pub posterior: Vec<f64>,
    /// Expected losses by action (if available).
    pub expected_losses: BTreeMap<String, f64>,
    /// Expected loss of the chosen action.
    pub chosen_expected_loss: f64,
    /// Calibration score [0, 1].
    pub calibration_score: f64,
    /// Whether a fallback heuristic was used.
    pub fallback_active: bool,
    /// Top features influencing the decision.
    pub top_features: Vec<(String, f64)>,
    /// Arbitrary metadata for this evidence entry.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// CanonicalEvidenceEntry — the emitted entry with integrity hash
// ---------------------------------------------------------------------------

/// A canonical evidence entry with tamper-detection hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEvidenceEntry {
    /// Unique entry identifier.
    pub entry_id: EvidenceEntryId,
    /// Sequence number in the ledger.
    pub sequence: u64,
    /// Action category.
    pub category: ActionCategory,
    /// Action name.
    pub action_name: String,
    /// Trace ID.
    pub trace_id: String,
    /// Decision ID.
    pub decision_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Timestamp (monotonic ms).
    pub ts_unix_ms: u64,
    /// Security epoch at emission time.
    pub epoch: SecurityEpoch,
    /// Content hash of the underlying EvidenceLedger payload.
    pub artifact_hash: ContentHash,
    /// The franken-evidence ledger entry.
    pub ledger_entry: EvidenceLedger,
    /// Chain hash linking to the previous entry (tamper-evidence).
    pub chain_hash: ContentHash,
    /// Metadata.
    pub metadata: BTreeMap<String, String>,
}

impl CanonicalEvidenceEntry {
    /// Verify the artifact hash matches the ledger entry content.
    pub fn verify_artifact_integrity(&self) -> bool {
        let mut payload = serde_json::to_vec(&self.ledger_entry).unwrap_or_default();
        if let Ok(meta_bytes) = serde_json::to_vec(&self.metadata) {
            payload.extend_from_slice(&meta_bytes);
        }
        let computed = ContentHash::compute(&payload);
        self.artifact_hash == computed
    }

    /// Verify this entry's chain hash is correct given the previous entry.
    pub fn verify_chain_link(&self, prev: Option<&CanonicalEvidenceEntry>) -> bool {
        let expected = compute_chain_hash(prev.map(|e| &e.chain_hash), &self.artifact_hash);
        self.chain_hash == expected
    }
}

// ---------------------------------------------------------------------------
// EvidenceEmissionError
// ---------------------------------------------------------------------------

/// Errors from evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceEmissionError {
    /// The bounded buffer is full; back-pressure applied.
    BufferFull { capacity: usize },
    /// Budget exhausted before evidence could be emitted.
    BudgetExhausted { requested_ms: u64 },
    /// Failed to build the ledger entry.
    BuildError { detail: String },
    /// Ledger entry failed schema validation.
    ValidationFailed { errors: Vec<String> },
}

impl fmt::Display for EvidenceEmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferFull { capacity } => {
                write!(f, "evidence buffer full (capacity={capacity})")
            }
            Self::BudgetExhausted { requested_ms } => {
                write!(f, "budget exhausted ({requested_ms}ms)")
            }
            Self::BuildError { detail } => write!(f, "evidence build error: {detail}"),
            Self::ValidationFailed { errors } => {
                write!(f, "validation failed: {}", errors.join(", "))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceEmissionEvent — structured log event
// ---------------------------------------------------------------------------

/// Structured log event emitted for every evidence action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEmissionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// CanonicalEvidenceEmitter — the main emitter
// ---------------------------------------------------------------------------

/// Configuration for the evidence emitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitterConfig {
    /// Maximum entries in the bounded buffer.
    pub buffer_capacity: usize,
    /// Budget cost (ms) per evidence emission.
    pub budget_cost_ms: u64,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
            budget_cost_ms: 1,
        }
    }
}

/// Bounded-buffer canonical evidence emitter with chain-hash integrity.
///
/// Every emitted entry is linked to its predecessor via a chain hash,
/// making the ledger tamper-evident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvidenceEmitter {
    config: EmitterConfig,
    entries: Vec<CanonicalEvidenceEntry>,
    events: Vec<EvidenceEmissionEvent>,
    epoch: SecurityEpoch,
    next_sequence: u64,
    /// Rolling hash of all entries (for quick integrity check).
    rolling_hash: ContentHash,
    /// Per-category emission counts.
    category_counts: BTreeMap<ActionCategory, u64>,
}

impl CanonicalEvidenceEmitter {
    pub fn new(config: EmitterConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            events: Vec::new(),
            epoch: SecurityEpoch::from_raw(0),
            next_sequence: 0,
            rolling_hash: ContentHash::compute(b"evidence-genesis"),
            category_counts: BTreeMap::new(),
        }
    }

    /// Set the security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Emit a canonical evidence entry for a high-impact action.
    ///
    /// Consumes budget from the context adapter, builds the franken-evidence
    /// ledger entry, computes artifact and chain hashes, and appends to the
    /// bounded buffer.
    pub fn emit<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        request: &EvidenceEmissionRequest,
    ) -> Result<EvidenceEntryId, EvidenceEmissionError> {
        // Back-pressure: reject if buffer is full.
        if self.entries.len() >= self.config.buffer_capacity {
            self.push_event(request, "evidence_emit", "rejected", Some("buffer_full"));
            return Err(EvidenceEmissionError::BufferFull {
                capacity: self.config.buffer_capacity,
            });
        }

        // Consume budget.
        cx.consume_budget(self.config.budget_cost_ms).map_err(|_| {
            self.push_event(
                request,
                "evidence_emit",
                "rejected",
                Some("budget_exhausted"),
            );
            EvidenceEmissionError::BudgetExhausted {
                requested_ms: self.config.budget_cost_ms,
            }
        })?;

        // Build the franken-evidence ledger entry.
        let ledger_entry = self.build_ledger_entry(request)?;

        // Validate.
        let validation_errors = ledger_entry.validate();
        if !validation_errors.is_empty() {
            let error_strs: Vec<String> =
                validation_errors.iter().map(|e| format!("{e:?}")).collect();
            self.push_event(
                request,
                "evidence_emit",
                "rejected",
                Some("validation_failed"),
            );
            return Err(EvidenceEmissionError::ValidationFailed { errors: error_strs });
        }

        // Compute artifact hash covering both ledger entry AND metadata so
        // neither can be tampered with independently.
        let mut hash_input = serde_json::to_vec(&ledger_entry).unwrap_or_default();
        if let Ok(meta_bytes) = serde_json::to_vec(&request.metadata) {
            hash_input.extend_from_slice(&meta_bytes);
        }
        let artifact_hash = ContentHash::compute(&hash_input);

        // Compute chain hash.
        let prev_chain = self.entries.last().map(|e| &e.chain_hash);
        let chain_hash = compute_chain_hash(prev_chain, &artifact_hash);

        // Build the canonical entry.
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let entry_id = EvidenceEntryId::new(format!(
            "ev-{}-{}-{}",
            request.category, sequence, request.ts_unix_ms
        ));

        let canonical = CanonicalEvidenceEntry {
            entry_id: entry_id.clone(),
            sequence,
            category: request.category,
            action_name: request.action_name.clone(),
            trace_id: request.trace_id.to_string(),
            decision_id: request.decision_id.to_string(),
            policy_id: request.policy_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            ts_unix_ms: request.ts_unix_ms,
            epoch: self.epoch,
            artifact_hash,
            ledger_entry,
            chain_hash,
            metadata: request.metadata.clone(),
        };

        self.entries.push(canonical);
        *self.category_counts.entry(request.category).or_insert(0) += 1;

        // Update rolling hash.
        let mut hash_input = self.rolling_hash.as_bytes().to_vec();
        hash_input.extend_from_slice(artifact_hash.as_bytes());
        self.rolling_hash = ContentHash::compute(&hash_input);

        self.push_event(request, "evidence_emit", "ok", None);

        Ok(entry_id)
    }

    /// Verify the entire chain is tamper-free.
    pub fn verify_chain_integrity(&self) -> bool {
        let mut prev: Option<&CanonicalEvidenceEntry> = None;
        for entry in &self.entries {
            if !entry.verify_artifact_integrity() {
                return false;
            }
            if !entry.verify_chain_link(prev) {
                return false;
            }
            prev = Some(entry);
        }
        true
    }

    /// All emitted entries.
    pub fn entries(&self) -> &[CanonicalEvidenceEntry] {
        &self.entries
    }

    /// Get an entry by sequence number.
    pub fn get(&self, sequence: u64) -> Option<&CanonicalEvidenceEntry> {
        self.entries.iter().find(|e| e.sequence == sequence)
    }

    /// All structured log events.
    pub fn events(&self) -> &[EvidenceEmissionEvent] {
        &self.events
    }

    /// Number of entries emitted.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the emitter is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remaining buffer capacity.
    pub fn remaining_capacity(&self) -> usize {
        self.config
            .buffer_capacity
            .saturating_sub(self.entries.len())
    }

    /// Rolling hash of all entries.
    pub fn rolling_hash(&self) -> &ContentHash {
        &self.rolling_hash
    }

    /// Per-category emission counts.
    pub fn category_counts(&self) -> &BTreeMap<ActionCategory, u64> {
        &self.category_counts
    }

    /// Entries filtered by category.
    pub fn by_category(&self, category: ActionCategory) -> Vec<&CanonicalEvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Entries filtered by trace ID.
    pub fn by_trace_id(&self, trace_id: &str) -> Vec<&CanonicalEvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .collect()
    }

    /// Entries filtered by decision ID.
    pub fn by_decision_id(&self, decision_id: &str) -> Vec<&CanonicalEvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.decision_id == decision_id)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn build_ledger_entry(
        &self,
        request: &EvidenceEmissionRequest,
    ) -> Result<EvidenceLedger, EvidenceEmissionError> {
        let mut builder = EvidenceLedgerBuilder::new()
            .ts_unix_ms(request.ts_unix_ms)
            .component(format!("{}:{}", COMPONENT_NAME, request.category))
            .action(&request.action_name)
            .chosen_expected_loss(request.chosen_expected_loss)
            .calibration_score(request.calibration_score)
            .fallback_active(request.fallback_active);

        if !request.posterior.is_empty() {
            builder = builder.posterior(request.posterior.clone());
        } else {
            // Default uniform posterior for actions without Bayesian evaluation.
            builder = builder.posterior(vec![0.5, 0.5]);
        }

        for (action, loss) in &request.expected_losses {
            builder = builder.expected_loss(action, *loss);
        }

        if request.expected_losses.is_empty() {
            builder = builder.expected_loss(&request.action_name, request.chosen_expected_loss);
        }

        for (name, weight) in &request.top_features {
            builder = builder.top_feature(name, *weight);
        }

        builder
            .build()
            .map_err(|e| EvidenceEmissionError::BuildError {
                detail: format!("{e:?}"),
            })
    }

    fn push_event(
        &mut self,
        request: &EvidenceEmissionRequest,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(EvidenceEmissionEvent {
            trace_id: request.trace_id.to_string(),
            decision_id: request.decision_id.to_string(),
            policy_id: request.policy_id.to_string(),
            component: COMPONENT_NAME.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Chain hash computation
// ---------------------------------------------------------------------------

pub(crate) fn compute_chain_hash(prev: Option<&ContentHash>, current: &ContentHash) -> ContentHash {
    let mut input = Vec::with_capacity(64);
    match prev {
        Some(p) => input.extend_from_slice(p.as_bytes()),
        None => input.extend_from_slice(b"genesis"),
    }
    input.extend_from_slice(current.as_bytes());
    ContentHash::compute(&input)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn emitter() -> CanonicalEvidenceEmitter {
        CanonicalEvidenceEmitter::new(EmitterConfig::default())
    }

    fn small_emitter(capacity: usize) -> CanonicalEvidenceEmitter {
        CanonicalEvidenceEmitter::new(EmitterConfig {
            buffer_capacity: capacity,
            ..EmitterConfig::default()
        })
    }

    fn mock_cx() -> MockCx {
        MockCx::new(trace_id_from_seed(1), MockBudget::new(10_000))
    }

    fn make_request(category: ActionCategory, action: &str) -> EvidenceEmissionRequest {
        EvidenceEmissionRequest {
            category,
            action_name: action.to_string(),
            trace_id: trace_id_from_seed(1),
            decision_id: decision_id_from_seed(1),
            policy_id: policy_id_from_seed(1),
            ts_unix_ms: 1_700_000_000_000,
            posterior: vec![0.7, 0.3],
            expected_losses: {
                let mut m = BTreeMap::new();
                m.insert("allow".to_string(), 0.1);
                m.insert("deny".to_string(), 0.9);
                // Include the action itself so validation passes for
                // dynamically-named actions like "decision_contract_action".
                m.insert(action.to_string(), 0.1);
                m
            },
            chosen_expected_loss: 0.1,
            calibration_score: 0.85,
            fallback_active: false,
            top_features: vec![
                ("severity".to_string(), 0.6),
                ("frequency".to_string(), 0.3),
            ],
            metadata: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // ActionCategory tests
    // -----------------------------------------------------------------------

    #[test]
    fn action_category_all_returns_six() {
        assert_eq!(ActionCategory::ALL.len(), 6);
    }

    #[test]
    fn action_category_display_matches_as_str() {
        for cat in &ActionCategory::ALL {
            assert_eq!(cat.to_string(), cat.as_str());
        }
    }

    #[test]
    fn action_category_serde_roundtrip() {
        for cat in &ActionCategory::ALL {
            let json = serde_json::to_string(cat).unwrap();
            let back: ActionCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn action_category_ordering_is_deterministic() {
        let mut cats = ActionCategory::ALL.to_vec();
        cats.sort();
        assert_eq!(cats, ActionCategory::ALL);
    }

    // -----------------------------------------------------------------------
    // EvidenceEntryId tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_entry_id_display() {
        let id = EvidenceEntryId::new("ev-42");
        assert_eq!(id.to_string(), "ev-42");
        assert_eq!(id.as_str(), "ev-42");
    }

    // -----------------------------------------------------------------------
    // EmitterConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let cfg = EmitterConfig::default();
        assert_eq!(cfg.buffer_capacity, DEFAULT_BUFFER_CAPACITY);
        assert_eq!(cfg.budget_cost_ms, 1);
    }

    // -----------------------------------------------------------------------
    // Basic emission
    // -----------------------------------------------------------------------

    #[test]
    fn emit_single_entry() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "extension_quarantine");
        let id = em.emit(&mut cx, &req).unwrap();
        assert_eq!(em.len(), 1);
        assert!(!em.is_empty());
        assert!(id.as_str().contains("decision_contract"));
    }

    #[test]
    fn emit_populates_all_fields() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "extension_quarantine");
        em.emit(&mut cx, &req).unwrap();

        let entry = &em.entries()[0];
        assert_eq!(entry.category, ActionCategory::DecisionContract);
        assert_eq!(entry.action_name, "extension_quarantine");
        assert_eq!(entry.schema_version, SCHEMA_VERSION);
        assert_eq!(entry.ts_unix_ms, 1_700_000_000_000);
        assert!(!entry.trace_id.is_empty());
        assert!(!entry.decision_id.is_empty());
        assert!(!entry.policy_id.is_empty());
    }

    #[test]
    fn emit_links_trace_decision_policy() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "capability_revocation");
        em.emit(&mut cx, &req).unwrap();

        let entry = &em.entries()[0];
        assert_eq!(entry.trace_id, req.trace_id.to_string());
        assert_eq!(entry.decision_id, req.decision_id.to_string());
        assert_eq!(entry.policy_id, req.policy_id.to_string());
    }

    // -----------------------------------------------------------------------
    // Artifact hash (tamper detection)
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_hash_matches_ledger_content() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::ExtensionLifecycle, "extension_load");
        em.emit(&mut cx, &req).unwrap();

        let entry = &em.entries()[0];
        assert!(entry.verify_artifact_integrity());
    }

    #[test]
    fn tampered_entry_detected() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::ExtensionLifecycle, "extension_load");
        em.emit(&mut cx, &req).unwrap();

        let mut entry = em.entries()[0].clone();
        entry.ledger_entry.ts_unix_ms = 999; // tamper
        assert!(!entry.verify_artifact_integrity());
    }

    // -----------------------------------------------------------------------
    // Chain hash integrity
    // -----------------------------------------------------------------------

    #[test]
    fn chain_integrity_passes_for_valid_ledger() {
        let mut em = emitter();
        let mut cx = mock_cx();
        for i in 0..5 {
            let req = make_request(ActionCategory::DecisionContract, &format!("action_{i}"));
            em.emit(&mut cx, &req).unwrap();
        }
        assert!(em.verify_chain_integrity());
    }

    #[test]
    fn chain_integrity_fails_on_tampered_chain_hash() {
        let mut em = emitter();
        let mut cx = mock_cx();
        for i in 0..3 {
            let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
            em.emit(&mut cx, &req).unwrap();
        }

        // Tamper with chain hash of middle entry.
        em.entries[1].chain_hash = ContentHash::compute(b"tampered");
        assert!(!em.verify_chain_integrity());
    }

    // -----------------------------------------------------------------------
    // Bounded buffer (back-pressure)
    // -----------------------------------------------------------------------

    #[test]
    fn buffer_full_returns_error() {
        let mut em = small_emitter(2);
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::Cancellation, "cancel_op");

        em.emit(&mut cx, &req).unwrap();
        em.emit(&mut cx, &req).unwrap();
        let err = em.emit(&mut cx, &req).unwrap_err();
        assert_eq!(err, EvidenceEmissionError::BufferFull { capacity: 2 });
    }

    #[test]
    fn remaining_capacity_decreases() {
        let mut em = small_emitter(5);
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::Cancellation, "cancel_op");

        assert_eq!(em.remaining_capacity(), 5);
        em.emit(&mut cx, &req).unwrap();
        assert_eq!(em.remaining_capacity(), 4);
    }

    // -----------------------------------------------------------------------
    // Budget consumption
    // -----------------------------------------------------------------------

    #[test]
    fn emit_consumes_budget() {
        let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
            budget_cost_ms: 5,
            ..EmitterConfig::default()
        });
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
        let req = make_request(ActionCategory::DecisionContract, "allow");

        em.emit(&mut cx, &req).unwrap();
        assert_eq!(cx.budget().remaining_ms(), 5);
    }

    #[test]
    fn budget_exhaustion_returns_error() {
        let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
            budget_cost_ms: 100,
            ..EmitterConfig::default()
        });
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(50));
        let req = make_request(ActionCategory::DecisionContract, "deny");

        let err = em.emit(&mut cx, &req).unwrap_err();
        assert_eq!(
            err,
            EvidenceEmissionError::BudgetExhausted { requested_ms: 100 }
        );
    }

    // -----------------------------------------------------------------------
    // Category filtering
    // -----------------------------------------------------------------------

    #[test]
    fn by_category_filters_correctly() {
        let mut em = emitter();
        let mut cx = mock_cx();

        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "quarantine"),
        )
        .unwrap();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::ExtensionLifecycle, "load"),
        )
        .unwrap();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "revoke"),
        )
        .unwrap();

        assert_eq!(em.by_category(ActionCategory::DecisionContract).len(), 2);
        assert_eq!(em.by_category(ActionCategory::ExtensionLifecycle).len(), 1);
        assert_eq!(em.by_category(ActionCategory::Cancellation).len(), 0);
    }

    #[test]
    fn category_counts_tracked() {
        let mut em = emitter();
        let mut cx = mock_cx();

        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "b"),
        )
        .unwrap();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::ContainmentAction, "c"),
        )
        .unwrap();

        let counts = em.category_counts();
        assert_eq!(counts[&ActionCategory::DecisionContract], 2);
        assert_eq!(counts[&ActionCategory::ContainmentAction], 1);
    }

    // -----------------------------------------------------------------------
    // Trace/decision ID filtering
    // -----------------------------------------------------------------------

    #[test]
    fn by_trace_id_filters() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let req = make_request(ActionCategory::DecisionContract, "allow");
        em.emit(&mut cx, &req).unwrap();

        let trace_str = trace_id_from_seed(1).to_string();
        assert_eq!(em.by_trace_id(&trace_str).len(), 1);
        assert_eq!(em.by_trace_id("nonexistent").len(), 0);
    }

    #[test]
    fn by_decision_id_filters() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let req = make_request(ActionCategory::DecisionContract, "deny");
        em.emit(&mut cx, &req).unwrap();

        let dec_str = decision_id_from_seed(1).to_string();
        assert_eq!(em.by_decision_id(&dec_str).len(), 1);
    }

    // -----------------------------------------------------------------------
    // Sequence numbering
    // -----------------------------------------------------------------------

    #[test]
    fn sequence_numbers_increment() {
        let mut em = emitter();
        let mut cx = mock_cx();

        for i in 0..3 {
            let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
            em.emit(&mut cx, &req).unwrap();
        }

        assert_eq!(em.entries()[0].sequence, 0);
        assert_eq!(em.entries()[1].sequence, 1);
        assert_eq!(em.entries()[2].sequence, 2);
    }

    #[test]
    fn get_by_sequence() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let req = make_request(ActionCategory::DecisionContract, "test");
        em.emit(&mut cx, &req).unwrap();

        assert!(em.get(0).is_some());
        assert!(em.get(1).is_none());
    }

    // -----------------------------------------------------------------------
    // Epoch propagation
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_propagated_to_entries() {
        let mut em = emitter();
        em.set_epoch(SecurityEpoch::from_raw(42));
        let mut cx = mock_cx();

        let req = make_request(ActionCategory::DecisionContract, "allow");
        em.emit(&mut cx, &req).unwrap();

        assert_eq!(em.entries()[0].epoch, SecurityEpoch::from_raw(42));
    }

    // -----------------------------------------------------------------------
    // Rolling hash
    // -----------------------------------------------------------------------

    #[test]
    fn rolling_hash_changes_with_each_entry() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let h0 = *em.rolling_hash();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        let h1 = *em.rolling_hash();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "b"),
        )
        .unwrap();
        let h2 = *em.rolling_hash();

        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_ne!(h0, h2);
    }

    // -----------------------------------------------------------------------
    // Structured events
    // -----------------------------------------------------------------------

    #[test]
    fn events_emitted_for_success() {
        let mut em = emitter();
        let mut cx = mock_cx();

        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "allow"),
        )
        .unwrap();

        assert_eq!(em.events().len(), 1);
        assert_eq!(em.events()[0].event, "evidence_emit");
        assert_eq!(em.events()[0].outcome, "ok");
        assert!(em.events()[0].error_code.is_none());
    }

    #[test]
    fn events_emitted_for_buffer_full() {
        let mut em = small_emitter(1);
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "a");

        em.emit(&mut cx, &req).unwrap();
        let _ = em.emit(&mut cx, &req);

        assert_eq!(em.events().len(), 2);
        assert_eq!(em.events()[1].outcome, "rejected");
        assert_eq!(em.events()[1].error_code.as_deref(), Some("buffer_full"));
    }

    // -----------------------------------------------------------------------
    // All categories can emit
    // -----------------------------------------------------------------------

    #[test]
    fn all_categories_emit_successfully() {
        let mut em = emitter();
        let mut cx = mock_cx();

        for cat in &ActionCategory::ALL {
            let req = make_request(*cat, &format!("{cat}_action"));
            em.emit(&mut cx, &req).unwrap();
        }

        assert_eq!(em.len(), 6);
        assert_eq!(em.category_counts().len(), 6);
    }

    // -----------------------------------------------------------------------
    // Default posterior for actions without Bayesian evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn empty_posterior_defaults_to_uniform() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let mut req = make_request(ActionCategory::ExtensionLifecycle, "load");
        req.posterior = vec![]; // no Bayesian evaluation
        em.emit(&mut cx, &req).unwrap();

        assert_eq!(em.entries()[0].ledger_entry.posterior, vec![0.5, 0.5]);
    }

    // -----------------------------------------------------------------------
    // Metadata passthrough
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_preserved_in_entry() {
        let mut em = emitter();
        let mut cx = mock_cx();

        let mut req = make_request(ActionCategory::DecisionContract, "allow");
        req.metadata
            .insert("extension_id".to_string(), "ext-001".to_string());
        em.emit(&mut cx, &req).unwrap();

        assert_eq!(
            em.entries()[0].metadata.get("extension_id"),
            Some(&"ext-001".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_entry_serde_roundtrip() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "allow"),
        )
        .unwrap();

        let entry = &em.entries()[0];
        let json = serde_json::to_string(entry).unwrap();
        let back: CanonicalEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, back);
    }

    #[test]
    fn emission_error_serde_roundtrip() {
        let err = EvidenceEmissionError::BufferFull { capacity: 42 };
        let json = serde_json::to_string(&err).unwrap();
        let back: EvidenceEmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn emission_event_serde_roundtrip() {
        let event = EvidenceEmissionEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "c1".to_string(),
            event: "emit".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: EvidenceEmissionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn emitter_config_serde_roundtrip() {
        let cfg = EmitterConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: EmitterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_identical_inputs() {
        let run = || {
            let mut em = emitter();
            em.set_epoch(SecurityEpoch::from_raw(1));
            let mut cx = mock_cx();

            for i in 0..3 {
                let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
                em.emit(&mut cx, &req).unwrap();
            }
            (em.entries().to_vec(), *em.rolling_hash())
        };

        let (entries_a, hash_a) = run();
        let (entries_b, hash_b) = run();
        assert_eq!(entries_a, entries_b);
        assert_eq!(hash_a, hash_b);
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    // -- Enrichment: Ord --

    #[test]
    fn action_category_ordering() {
        assert!(ActionCategory::DecisionContract < ActionCategory::RegionLifecycle);
        assert!(ActionCategory::RegionLifecycle < ActionCategory::Cancellation);
        assert!(ActionCategory::Cancellation < ActionCategory::ObligationLifecycle);
        assert!(ActionCategory::ObligationLifecycle < ActionCategory::ExtensionLifecycle);
        assert!(ActionCategory::ExtensionLifecycle < ActionCategory::ContainmentAction);
    }

    #[test]
    fn error_display_messages() {
        let e = EvidenceEmissionError::BufferFull { capacity: 10 };
        assert!(e.to_string().contains("10"));

        let e = EvidenceEmissionError::BudgetExhausted { requested_ms: 50 };
        assert!(e.to_string().contains("50"));

        let e = EvidenceEmissionError::BuildError {
            detail: "bad".to_string(),
        };
        assert!(e.to_string().contains("bad"));

        let e = EvidenceEmissionError::ValidationFailed {
            errors: vec!["x".to_string()],
        };
        assert!(e.to_string().contains("x"));
    }

    // -- Enrichment batch 2: Display uniqueness, boundary, integrity --

    #[test]
    fn action_category_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let set: BTreeSet<String> = ActionCategory::ALL.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            set.len(),
            ActionCategory::ALL.len(),
            "all ActionCategory Display strings must be unique"
        );
    }

    #[test]
    fn error_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let errors = [
            EvidenceEmissionError::BufferFull { capacity: 1 },
            EvidenceEmissionError::BudgetExhausted { requested_ms: 1 },
            EvidenceEmissionError::BuildError {
                detail: "x".to_string(),
            },
            EvidenceEmissionError::ValidationFailed {
                errors: vec!["x".to_string()],
            },
        ];
        let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            set.len(),
            errors.len(),
            "all EvidenceEmissionError Display strings must be unique"
        );
    }

    #[test]
    fn evidence_entry_id_serde_roundtrip() {
        let id = EvidenceEntryId::new("ev-test-42");
        let json = serde_json::to_string(&id).unwrap();
        let back: EvidenceEntryId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn emitter_starts_empty() {
        let em = emitter();
        assert!(em.is_empty());
        assert_eq!(em.len(), 0);
        assert_eq!(em.remaining_capacity(), DEFAULT_BUFFER_CAPACITY);
        assert!(em.entries().is_empty());
        assert!(em.events().is_empty());
        assert!(em.category_counts().is_empty());
    }

    #[test]
    fn chain_integrity_on_empty_emitter() {
        let em = emitter();
        assert!(em.verify_chain_integrity());
    }

    #[test]
    fn chain_integrity_single_entry() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "allow");
        em.emit(&mut cx, &req).unwrap();
        assert!(em.verify_chain_integrity());
        let entry = &em.entries()[0];
        assert!(entry.verify_artifact_integrity());
        assert!(entry.verify_chain_link(None));
    }

    #[test]
    fn metadata_with_multiple_keys() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let mut req = make_request(ActionCategory::ContainmentAction, "quarantine");
        req.metadata
            .insert("ext".to_string(), "ext-001".to_string());
        req.metadata.insert("region".to_string(), "r-1".to_string());
        em.emit(&mut cx, &req).unwrap();

        let entry = &em.entries()[0];
        assert_eq!(entry.metadata.get("ext"), Some(&"ext-001".to_string()));
        assert_eq!(entry.metadata.get("region"), Some(&"r-1".to_string()));
    }

    #[test]
    fn emitter_serde_roundtrip() {
        let mut em = emitter();
        em.set_epoch(SecurityEpoch::from_raw(5));
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "allow"),
        )
        .unwrap();

        let json = serde_json::to_string(&em).unwrap();
        let back: CanonicalEvidenceEmitter = serde_json::from_str(&json).unwrap();
        assert_eq!(em.len(), back.len());
        assert_eq!(em.rolling_hash(), back.rolling_hash());
    }

    // -- Enrichment batch 3: clone, serde, boundary, mid-stream epoch --

    #[test]
    fn request_serde_roundtrip() {
        let req = make_request(ActionCategory::DecisionContract, "allow");
        let json = serde_json::to_string(&req).unwrap();
        let back: EvidenceEmissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn request_clone_equality() {
        let req = make_request(ActionCategory::Cancellation, "cancel_op");
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn canonical_entry_clone_equality() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        let entry = em.entries()[0].clone();
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn error_clone_equality() {
        let errors = [
            EvidenceEmissionError::BufferFull { capacity: 42 },
            EvidenceEmissionError::BudgetExhausted { requested_ms: 99 },
            EvidenceEmissionError::BuildError {
                detail: "fail".to_string(),
            },
            EvidenceEmissionError::ValidationFailed {
                errors: vec!["bad".to_string()],
            },
        ];
        for e in &errors {
            assert_eq!(*e, e.clone());
        }
    }

    #[test]
    fn event_clone_equality() {
        let event = EvidenceEmissionEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "c".to_string(),
            event: "emit".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("e1".to_string()),
        };
        assert_eq!(event, event.clone());
    }

    #[test]
    fn error_serde_all_four_variants() {
        let variants = [
            EvidenceEmissionError::BufferFull { capacity: 1 },
            EvidenceEmissionError::BudgetExhausted { requested_ms: 2 },
            EvidenceEmissionError::BuildError {
                detail: "d".to_string(),
            },
            EvidenceEmissionError::ValidationFailed {
                errors: vec!["v".to_string()],
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EvidenceEmissionError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn by_trace_id_multiple_matches() {
        let mut em = emitter();
        let mut cx = mock_cx();
        for i in 0..3 {
            let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
            em.emit(&mut cx, &req).unwrap();
        }
        let trace_str = trace_id_from_seed(1).to_string();
        assert_eq!(em.by_trace_id(&trace_str).len(), 3);
    }

    #[test]
    fn by_decision_id_multiple_matches() {
        let mut em = emitter();
        let mut cx = mock_cx();
        for i in 0..4 {
            let req = make_request(ActionCategory::RegionLifecycle, &format!("r{i}"));
            em.emit(&mut cx, &req).unwrap();
        }
        let dec_str = decision_id_from_seed(1).to_string();
        assert_eq!(em.by_decision_id(&dec_str).len(), 4);
    }

    #[test]
    fn entry_json_field_presence() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        let json = serde_json::to_string(&em.entries()[0]).unwrap();
        for field in &[
            "entry_id",
            "sequence",
            "category",
            "action_name",
            "trace_id",
            "decision_id",
            "policy_id",
            "schema_version",
            "ts_unix_ms",
            "epoch",
            "artifact_hash",
            "chain_hash",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn fallback_active_preserved_in_ledger() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let mut req = make_request(ActionCategory::DecisionContract, "allow");
        req.fallback_active = true;
        em.emit(&mut cx, &req).unwrap();
        assert!(em.entries()[0].ledger_entry.fallback_active);
    }

    #[test]
    fn top_features_preserved_in_ledger() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::DecisionContract, "allow");
        em.emit(&mut cx, &req).unwrap();
        let features = &em.entries()[0].ledger_entry.top_features;
        assert!(!features.is_empty());
    }

    #[test]
    fn epoch_midstream_change_affects_subsequent() {
        let mut em = emitter();
        em.set_epoch(SecurityEpoch::from_raw(1));
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        em.set_epoch(SecurityEpoch::from_raw(2));
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "b"),
        )
        .unwrap();
        assert_eq!(em.entries()[0].epoch, SecurityEpoch::from_raw(1));
        assert_eq!(em.entries()[1].epoch, SecurityEpoch::from_raw(2));
    }

    #[test]
    fn budget_exact_boundary_succeeds() {
        let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
            budget_cost_ms: 10,
            ..EmitterConfig::default()
        });
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
        let req = make_request(ActionCategory::DecisionContract, "allow");
        em.emit(&mut cx, &req).unwrap();
        assert_eq!(em.len(), 1);
        assert_eq!(cx.budget().remaining_ms(), 0);
    }

    #[test]
    fn empty_expected_losses_uses_action_name() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let mut req = make_request(ActionCategory::ExtensionLifecycle, "load");
        req.expected_losses.clear();
        em.emit(&mut cx, &req).unwrap();
        let losses = &em.entries()[0].ledger_entry.expected_loss_by_action;
        assert!(
            losses.iter().any(|(k, _)| k == "load"),
            "expected_loss_by_action should contain the action_name key"
        );
    }

    #[test]
    fn request_metadata_btreemap_ordering() {
        let mut req = make_request(ActionCategory::DecisionContract, "allow");
        req.metadata.insert("z_key".to_string(), "z".to_string());
        req.metadata.insert("a_key".to_string(), "a".to_string());
        req.metadata.insert("m_key".to_string(), "m".to_string());
        let keys: Vec<&String> = req.metadata.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: Copy, Hash, JSON fields, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_action_category_copy_semantics() {
        let a = ActionCategory::ContainmentAction;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_eq!(b.as_str(), "containment_action");
    }

    #[test]
    fn enrichment_action_category_hash_in_btreeset() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for cat in &ActionCategory::ALL {
            assert!(set.insert(*cat));
        }
        assert_eq!(set.len(), 6);
        // Duplicate insertion returns false
        assert!(!set.insert(ActionCategory::DecisionContract));
    }

    #[test]
    fn enrichment_evidence_entry_id_clone_eq() {
        let a = EvidenceEntryId::new("ev-clone-test");
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn enrichment_emitter_config_clone_eq() {
        let a = EmitterConfig {
            buffer_capacity: 100,
            budget_cost_ms: 5,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_event_json_fields_present() {
        let event = EvidenceEmissionEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "evidence-emission".to_string(),
            event: "evidence_emit".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("buffer_full".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        for field in &[
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn enrichment_config_json_fields_present() {
        let cfg = EmitterConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("buffer_capacity"));
        assert!(json.contains("budget_cost_ms"));
    }

    #[test]
    fn enrichment_request_json_fields_present() {
        let req = make_request(ActionCategory::DecisionContract, "allow");
        let json = serde_json::to_string(&req).unwrap();
        for field in &[
            "category",
            "action_name",
            "trace_id",
            "decision_id",
            "policy_id",
            "ts_unix_ms",
            "posterior",
            "expected_losses",
            "chosen_expected_loss",
            "calibration_score",
            "fallback_active",
            "top_features",
            "metadata",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn enrichment_entry_id_format_contains_category_and_sequence() {
        let mut em = emitter();
        let mut cx = mock_cx();
        let req = make_request(ActionCategory::ExtensionLifecycle, "load");
        let id = em.emit(&mut cx, &req).unwrap();
        let s = id.as_str();
        assert!(s.starts_with("ev-"), "entry ID should start with ev-");
        assert!(
            s.contains("extension_lifecycle"),
            "entry ID should contain category"
        );
        assert!(s.contains("-0-"), "entry ID should contain sequence 0");
    }

    #[test]
    fn enrichment_rolling_hash_genesis_is_deterministic() {
        let em1 = emitter();
        let em2 = emitter();
        assert_eq!(em1.rolling_hash(), em2.rolling_hash());
    }

    #[test]
    fn enrichment_schema_version_constant() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        assert_eq!(em.entries()[0].schema_version, "evidence-v1");
    }

    #[test]
    fn enrichment_component_name_in_ledger() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::Cancellation, "cancel"),
        )
        .unwrap();
        let component = &em.entries()[0].ledger_entry.component;
        assert!(
            component.contains("evidence-emission"),
            "ledger component should reference evidence-emission"
        );
        assert!(
            component.contains("cancellation"),
            "ledger component should reference category"
        );
    }

    #[test]
    fn enrichment_events_for_budget_exhaustion() {
        let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
            budget_cost_ms: 100,
            ..EmitterConfig::default()
        });
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(50));
        let req = make_request(ActionCategory::DecisionContract, "deny");
        let _ = em.emit(&mut cx, &req);

        assert_eq!(em.events().len(), 1);
        assert_eq!(em.events()[0].outcome, "rejected");
        assert_eq!(
            em.events()[0].error_code.as_deref(),
            Some("budget_exhausted")
        );
    }

    #[test]
    fn enrichment_by_category_empty_for_unused() {
        let mut em = emitter();
        let mut cx = mock_cx();
        em.emit(
            &mut cx,
            &make_request(ActionCategory::DecisionContract, "a"),
        )
        .unwrap();
        assert!(
            em.by_category(ActionCategory::ObligationLifecycle)
                .is_empty()
        );
    }

    #[test]
    fn enrichment_evidence_entry_id_ord_deterministic() {
        use std::collections::BTreeSet;
        let ids: Vec<EvidenceEntryId> = (0..5)
            .map(|i| EvidenceEntryId::new(format!("ev-{i}")))
            .collect();
        let set: BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 5);
    }
}
