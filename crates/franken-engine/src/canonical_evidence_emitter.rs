//! Canonical evidence emission for high-impact extension-host actions.
//!
//! Wires `franken_evidence`-backed evidence entries into the extension-host
//! subsystem so every high-impact action emits a structured, linked entry.
//! Each entry carries `trace_id`, `decision_id`, `policy_id`, `schema_version`,
//! and an artifact hash for tamper detection.
//!
//! Plan reference: Section 10.13 item 10, bd-uvmm.
//! Dependencies: bd-3a5e (decision contracts), bd-33h (evidence schema),
//!               bd-23om (adapter layer), bd-2ygl (Cx threading).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntry, EvidenceEntryBuilder,
    Witness,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// HighImpactAction — taxonomy of actions requiring evidence
// ---------------------------------------------------------------------------

/// Actions that require mandatory evidence emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HighImpactAction {
    // -- Security containment --
    /// Sandbox an extension (restrict capabilities).
    Sandbox,
    /// Suspend extension execution.
    Suspend,
    /// Terminate extension (cooperative then forced).
    Terminate,
    /// Quarantine extension with forensic snapshot.
    Quarantine,

    // -- Extension lifecycle --
    /// Load an extension.
    ExtensionLoad,
    /// Unload an extension.
    ExtensionUnload,
    /// Start extension execution.
    ExtensionStart,
    /// Stop extension execution.
    ExtensionStop,

    // -- Policy and epoch --
    /// Update or rotate policy.
    PolicyUpdate,
    /// Transition security epoch.
    EpochTransition,

    // -- Capability and authorization --
    /// Grant a capability.
    CapabilityGrant,
    /// Revoke a credential, key, or capability.
    Revocation,

    // -- Obligation lifecycle --
    /// Create an obligation.
    ObligationCreate,
    /// Fulfill an obligation.
    ObligationFulfill,
    /// Obligation failure.
    ObligationFailure,

    // -- Region lifecycle --
    /// Create an execution region.
    RegionCreate,
    /// Destroy an execution region.
    RegionDestroy,

    // -- Cancellation --
    /// Cancellation event.
    Cancellation,

    // -- Contract evaluation --
    /// Decision contract evaluation.
    ContractEvaluation,

    // -- Remote authorization --
    /// Remote operation authorization.
    RemoteAuthorization,
}

impl HighImpactAction {
    /// All variants for exhaustive iteration.
    pub const ALL: [HighImpactAction; 20] = [
        Self::Sandbox,
        Self::Suspend,
        Self::Terminate,
        Self::Quarantine,
        Self::ExtensionLoad,
        Self::ExtensionUnload,
        Self::ExtensionStart,
        Self::ExtensionStop,
        Self::PolicyUpdate,
        Self::EpochTransition,
        Self::CapabilityGrant,
        Self::Revocation,
        Self::ObligationCreate,
        Self::ObligationFulfill,
        Self::ObligationFailure,
        Self::RegionCreate,
        Self::RegionDestroy,
        Self::Cancellation,
        Self::ContractEvaluation,
        Self::RemoteAuthorization,
    ];

    /// Map to the evidence-ledger `DecisionType`.
    pub fn decision_type(&self) -> DecisionType {
        match self {
            Self::Sandbox | Self::Suspend | Self::Terminate | Self::Quarantine => {
                DecisionType::SecurityAction
            }
            Self::ExtensionLoad
            | Self::ExtensionUnload
            | Self::ExtensionStart
            | Self::ExtensionStop => DecisionType::ExtensionLifecycle,
            Self::PolicyUpdate => DecisionType::PolicyUpdate,
            Self::EpochTransition => DecisionType::EpochTransition,
            Self::CapabilityGrant => DecisionType::CapabilityDecision,
            Self::Revocation => DecisionType::Revocation,
            Self::ObligationCreate | Self::ObligationFulfill | Self::ObligationFailure => {
                DecisionType::ContractEvaluation
            }
            Self::RegionCreate | Self::RegionDestroy => DecisionType::ExtensionLifecycle,
            Self::Cancellation => DecisionType::SecurityAction,
            Self::ContractEvaluation => DecisionType::ContractEvaluation,
            Self::RemoteAuthorization => DecisionType::RemoteAuthorization,
        }
    }

    /// Component name for structured logging.
    pub fn component(&self) -> &'static str {
        match self {
            Self::Sandbox | Self::Suspend | Self::Terminate | Self::Quarantine => "containment",
            Self::ExtensionLoad
            | Self::ExtensionUnload
            | Self::ExtensionStart
            | Self::ExtensionStop => "lifecycle",
            Self::PolicyUpdate => "policy",
            Self::EpochTransition => "epoch",
            Self::CapabilityGrant | Self::Revocation => "capability",
            Self::ObligationCreate | Self::ObligationFulfill | Self::ObligationFailure => {
                "obligation"
            }
            Self::RegionCreate | Self::RegionDestroy => "region",
            Self::Cancellation => "cancellation",
            Self::ContractEvaluation => "contract",
            Self::RemoteAuthorization => "remote_auth",
        }
    }
}

impl fmt::Display for HighImpactAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Sandbox => "sandbox",
            Self::Suspend => "suspend",
            Self::Terminate => "terminate",
            Self::Quarantine => "quarantine",
            Self::ExtensionLoad => "extension_load",
            Self::ExtensionUnload => "extension_unload",
            Self::ExtensionStart => "extension_start",
            Self::ExtensionStop => "extension_stop",
            Self::PolicyUpdate => "policy_update",
            Self::EpochTransition => "epoch_transition",
            Self::CapabilityGrant => "capability_grant",
            Self::Revocation => "revocation",
            Self::ObligationCreate => "obligation_create",
            Self::ObligationFulfill => "obligation_fulfill",
            Self::ObligationFailure => "obligation_failure",
            Self::RegionCreate => "region_create",
            Self::RegionDestroy => "region_destroy",
            Self::Cancellation => "cancellation",
            Self::ContractEvaluation => "contract_evaluation",
            Self::RemoteAuthorization => "remote_authorization",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// EmissionContext — context for producing an evidence entry
// ---------------------------------------------------------------------------

/// Context required to produce a canonical evidence entry.
///
/// Captures the linkage fields (`trace_id`, `decision_id`, `policy_id`)
/// and the decision metadata (candidates, constraints, witnesses).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmissionContext {
    /// Correlation trace identifier (from Cx).
    pub trace_id: String,
    /// Decision contract instance identifier.
    pub decision_id: String,
    /// Policy version identifier.
    pub policy_id: String,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// The high-impact action being taken.
    pub action: HighImpactAction,
    /// Target identifier (e.g., extension ID, region ID).
    pub target_id: String,
}

// ---------------------------------------------------------------------------
// EmissionPolicy — configurable emission rules
// ---------------------------------------------------------------------------

/// Policy controlling which actions require evidence and at what level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmissionPolicy {
    /// Actions that always require evidence emission.
    pub mandatory_actions: Vec<HighImpactAction>,
    /// Maximum witnesses per entry.
    pub max_witnesses: usize,
    /// Maximum candidates per entry.
    pub max_candidates: usize,
    /// Whether to include full metadata in entries.
    pub include_metadata: bool,
    /// Buffer capacity for async emission.
    pub buffer_capacity: usize,
}

impl Default for EmissionPolicy {
    fn default() -> Self {
        Self {
            mandatory_actions: HighImpactAction::ALL.to_vec(),
            max_witnesses: 256,
            max_candidates: 64,
            include_metadata: true,
            buffer_capacity: 1024,
        }
    }
}

impl EmissionPolicy {
    /// Whether a given action requires evidence emission.
    pub fn requires_evidence(&self, action: HighImpactAction) -> bool {
        self.mandatory_actions.contains(&action)
    }
}

// ---------------------------------------------------------------------------
// EmissionError — errors from evidence emission
// ---------------------------------------------------------------------------

/// Errors from canonical evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmissionError {
    /// Missing required context field.
    MissingField { field: String },
    /// Ledger write failure.
    LedgerWriteFailure { reason: String },
    /// Entry validation failure.
    ValidationFailure { reason: String },
    /// Buffer full (backpressure).
    BufferFull { capacity: usize },
    /// Action not in mandatory set (policy does not require evidence).
    NotRequired { action: HighImpactAction },
}

impl fmt::Display for EmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
            Self::LedgerWriteFailure { reason } => write!(f, "ledger write failure: {reason}"),
            Self::ValidationFailure { reason } => write!(f, "validation failure: {reason}"),
            Self::BufferFull { capacity } => {
                write!(f, "emission buffer full (capacity={capacity})")
            }
            Self::NotRequired { action } => write!(f, "evidence not required for {action}"),
        }
    }
}

impl std::error::Error for EmissionError {}

// ---------------------------------------------------------------------------
// EmissionReceipt — confirmation of evidence emission
// ---------------------------------------------------------------------------

/// Receipt confirming successful evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmissionReceipt {
    /// Entry ID of the emitted evidence.
    pub entry_id: String,
    /// Content hash of the entry (artifact hash for tamper detection).
    pub artifact_hash: ContentHash,
    /// Decision type recorded.
    pub decision_type: DecisionType,
    /// Action that was evidenced.
    pub action: HighImpactAction,
    /// Trace ID for correlation.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// StructuredLogEvent — structured log for evidence emission
// ---------------------------------------------------------------------------

/// Structured log event emitted alongside every evidence entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// CanonicalEvidenceEmitter — the main emission engine
// ---------------------------------------------------------------------------

/// Emitter that produces canonical evidence entries for high-impact actions.
///
/// Composes emission context, evidence-ledger entry construction, artifact
/// hashing, and structured logging into a single cross-cutting concern.
#[derive(Debug)]
pub struct CanonicalEvidenceEmitter {
    policy: EmissionPolicy,
    /// Emitted entries (append-only ledger).
    ledger: Vec<EvidenceEntry>,
    /// Entry IDs for deduplication.
    entry_ids: Vec<String>,
    /// Structured log events.
    log_events: Vec<StructuredLogEvent>,
    /// Emission receipts.
    receipts: Vec<EmissionReceipt>,
    /// Whether the ledger is in a failed state (simulates disk-full).
    failed: bool,
}

impl CanonicalEvidenceEmitter {
    /// Create a new emitter with the given policy.
    pub fn new(policy: EmissionPolicy) -> Self {
        Self {
            policy,
            ledger: Vec::new(),
            entry_ids: Vec::new(),
            log_events: Vec::new(),
            receipts: Vec::new(),
            failed: false,
        }
    }

    /// Create with default policy.
    pub fn with_defaults() -> Self {
        Self::new(EmissionPolicy::default())
    }

    /// Emit an evidence entry for a high-impact action.
    ///
    /// Validates the context, constructs the entry, computes the artifact
    /// hash, writes to the ledger, and emits a structured log event.
    pub fn emit(
        &mut self,
        context: &EmissionContext,
        candidates: Vec<CandidateAction>,
        constraints: Vec<Constraint>,
        chosen: ChosenAction,
        witnesses: Vec<Witness>,
        metadata: BTreeMap<String, String>,
    ) -> Result<EmissionReceipt, EmissionError> {
        // 1. Check emission policy.
        if !self.policy.requires_evidence(context.action) {
            return Err(EmissionError::NotRequired {
                action: context.action,
            });
        }

        // 2. Validate context.
        self.validate_context(context)?;

        // 3. Check buffer capacity.
        if self.ledger.len() >= self.policy.buffer_capacity {
            self.emit_log(context, "buffer_full", None);
            return Err(EmissionError::BufferFull {
                capacity: self.policy.buffer_capacity,
            });
        }

        // 4. Check ledger health.
        if self.failed {
            self.emit_log(context, "ledger_write_failure", Some("ledger_failed"));
            return Err(EmissionError::LedgerWriteFailure {
                reason: "ledger is in failed state".to_string(),
            });
        }

        // 5. Truncate witnesses and candidates per policy.
        let truncated_witnesses: Vec<Witness> = witnesses
            .into_iter()
            .take(self.policy.max_witnesses)
            .collect();
        let truncated_candidates: Vec<CandidateAction> = candidates
            .into_iter()
            .take(self.policy.max_candidates)
            .collect();

        // 6. Build the evidence entry.
        let mut builder = EvidenceEntryBuilder::new(
            &context.trace_id,
            &context.decision_id,
            &context.policy_id,
            context.epoch,
            context.action.decision_type(),
        )
        .timestamp_ns(context.timestamp_ns);

        for candidate in &truncated_candidates {
            builder = builder.candidate(candidate.clone());
        }
        for constraint in &constraints {
            builder = builder.constraint(constraint.clone());
        }
        for witness in &truncated_witnesses {
            builder = builder.witness(witness.clone());
        }

        let mut entry_metadata = metadata;
        if self.policy.include_metadata {
            entry_metadata.insert("action".to_string(), context.action.to_string());
            entry_metadata.insert("target_id".to_string(), context.target_id.clone());
            entry_metadata.insert(
                "component".to_string(),
                context.action.component().to_string(),
            );
        }
        for (k, v) in &entry_metadata {
            builder = builder.meta(k.clone(), v.clone());
        }

        let entry =
            builder
                .chosen(chosen)
                .build()
                .map_err(|e| EmissionError::ValidationFailure {
                    reason: format!("builder: {e}"),
                })?;

        // 7. Compute artifact hash.
        let entry_json =
            serde_json::to_string(&entry).unwrap_or_else(|_| "serialization_error".to_string());
        let artifact_hash = ContentHash::compute(entry_json.as_bytes());

        // 8. Check deduplication.
        if self.entry_ids.contains(&entry.entry_id) {
            // Idempotent: return existing receipt.
            if let Some(existing) = self.receipts.iter().find(|r| r.entry_id == entry.entry_id) {
                return Ok(existing.clone());
            }
        }

        // 9. Create receipt.
        let receipt = EmissionReceipt {
            entry_id: entry.entry_id.clone(),
            artifact_hash,
            decision_type: context.action.decision_type(),
            action: context.action,
            trace_id: context.trace_id.clone(),
        };

        // 10. Append to ledger.
        self.entry_ids.push(entry.entry_id.clone());
        self.ledger.push(entry);
        self.receipts.push(receipt.clone());

        // 11. Emit structured log.
        self.emit_log(context, "evidence_emitted", None);

        Ok(receipt)
    }

    /// Number of entries in the ledger.
    pub fn ledger_len(&self) -> usize {
        self.ledger.len()
    }

    /// All entries in the ledger.
    pub fn ledger(&self) -> &[EvidenceEntry] {
        &self.ledger
    }

    /// All emission receipts.
    pub fn receipts(&self) -> &[EmissionReceipt] {
        &self.receipts
    }

    /// All structured log events.
    pub fn log_events(&self) -> &[StructuredLogEvent] {
        &self.log_events
    }

    /// Policy in use.
    pub fn policy(&self) -> &EmissionPolicy {
        &self.policy
    }

    /// Entries by decision type.
    pub fn entries_by_type(&self, decision_type: DecisionType) -> Vec<&EvidenceEntry> {
        self.ledger
            .iter()
            .filter(|e| e.decision_type == decision_type)
            .collect()
    }

    /// Entries by trace ID.
    pub fn entries_by_trace(&self, trace_id: &str) -> Vec<&EvidenceEntry> {
        self.ledger
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .collect()
    }

    /// Verify integrity of an entry by recomputing its artifact hash.
    pub fn verify_integrity(&self, entry: &EvidenceEntry) -> Result<ContentHash, EmissionError> {
        let json = serde_json::to_string(entry).map_err(|e| EmissionError::ValidationFailure {
            reason: format!("serialization: {e}"),
        })?;
        Ok(ContentHash::compute(json.as_bytes()))
    }

    /// Simulate ledger failure (for testing).
    pub fn set_failed(&mut self, failed: bool) {
        self.failed = failed;
    }

    /// Clear the ledger and all state.
    pub fn clear(&mut self) {
        self.ledger.clear();
        self.entry_ids.clear();
        self.log_events.clear();
        self.receipts.clear();
        self.failed = false;
    }

    // -- Internal helpers --

    fn validate_context(&self, context: &EmissionContext) -> Result<(), EmissionError> {
        if context.trace_id.trim().is_empty() {
            return Err(EmissionError::MissingField {
                field: "trace_id".to_string(),
            });
        }
        if context.decision_id.trim().is_empty() {
            return Err(EmissionError::MissingField {
                field: "decision_id".to_string(),
            });
        }
        if context.policy_id.trim().is_empty() {
            return Err(EmissionError::MissingField {
                field: "policy_id".to_string(),
            });
        }
        Ok(())
    }

    fn emit_log(&mut self, context: &EmissionContext, event: &str, error_code: Option<&str>) {
        self.log_events.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.action.component().to_string(),
            event: event.to_string(),
            outcome: if error_code.is_some() {
                "failure".to_string()
            } else {
                "success".to_string()
            },
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_ledger::current_schema_version;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_context(action: HighImpactAction) -> EmissionContext {
        EmissionContext {
            trace_id: "trace-001".to_string(),
            decision_id: "dec-001".to_string(),
            policy_id: "pol-001".to_string(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000_000,
            action,
            target_id: "ext-001".to_string(),
        }
    }

    fn test_candidates() -> Vec<CandidateAction> {
        vec![
            CandidateAction::new("allow", 100_000),
            CandidateAction::new("sandbox", 300_000),
            CandidateAction::new("terminate", 800_000),
        ]
    }

    fn test_constraints() -> Vec<Constraint> {
        vec![Constraint {
            constraint_id: "max-risk".to_string(),
            description: "risk threshold exceeded".to_string(),
            active: true,
        }]
    }

    fn test_chosen() -> ChosenAction {
        ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 300_000,
            rationale: "proportional response to elevated risk".to_string(),
        }
    }

    fn test_witnesses() -> Vec<Witness> {
        vec![
            Witness {
                witness_id: "w-001".to_string(),
                witness_type: "posterior".to_string(),
                value: "P(malicious)=0.35".to_string(),
            },
            Witness {
                witness_id: "w-002".to_string(),
                witness_type: "hostcall_rate".to_string(),
                value: "500_calls_per_sec".to_string(),
            },
        ]
    }

    fn test_metadata() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("extension_version".to_string(), "1.2.3".to_string());
        m
    }

    fn emit_standard(emitter: &mut CanonicalEvidenceEmitter) -> EmissionReceipt {
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                test_metadata(),
            )
            .unwrap()
    }

    // -----------------------------------------------------------------------
    // HighImpactAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn action_all_variants_count() {
        assert_eq!(HighImpactAction::ALL.len(), 20);
    }

    #[test]
    fn action_display() {
        assert_eq!(HighImpactAction::Sandbox.to_string(), "sandbox");
        assert_eq!(
            HighImpactAction::ExtensionLoad.to_string(),
            "extension_load"
        );
        assert_eq!(HighImpactAction::Cancellation.to_string(), "cancellation");
    }

    #[test]
    fn action_decision_type_mapping() {
        assert_eq!(
            HighImpactAction::Sandbox.decision_type(),
            DecisionType::SecurityAction
        );
        assert_eq!(
            HighImpactAction::ExtensionLoad.decision_type(),
            DecisionType::ExtensionLifecycle
        );
        assert_eq!(
            HighImpactAction::PolicyUpdate.decision_type(),
            DecisionType::PolicyUpdate
        );
        assert_eq!(
            HighImpactAction::EpochTransition.decision_type(),
            DecisionType::EpochTransition
        );
        assert_eq!(
            HighImpactAction::CapabilityGrant.decision_type(),
            DecisionType::CapabilityDecision
        );
        assert_eq!(
            HighImpactAction::Revocation.decision_type(),
            DecisionType::Revocation
        );
        assert_eq!(
            HighImpactAction::RemoteAuthorization.decision_type(),
            DecisionType::RemoteAuthorization
        );
    }

    #[test]
    fn action_component_names() {
        assert_eq!(HighImpactAction::Sandbox.component(), "containment");
        assert_eq!(HighImpactAction::ExtensionLoad.component(), "lifecycle");
        assert_eq!(HighImpactAction::PolicyUpdate.component(), "policy");
        assert_eq!(HighImpactAction::EpochTransition.component(), "epoch");
        assert_eq!(HighImpactAction::CapabilityGrant.component(), "capability");
        assert_eq!(HighImpactAction::ObligationCreate.component(), "obligation");
        assert_eq!(HighImpactAction::RegionCreate.component(), "region");
        assert_eq!(HighImpactAction::Cancellation.component(), "cancellation");
    }

    #[test]
    fn action_serde_roundtrip() {
        for action in &HighImpactAction::ALL {
            let json = serde_json::to_string(action).unwrap();
            let restored: HighImpactAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, restored);
        }
    }

    // -----------------------------------------------------------------------
    // EmissionPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_policy_requires_all_actions() {
        let policy = EmissionPolicy::default();
        for action in &HighImpactAction::ALL {
            assert!(policy.requires_evidence(*action));
        }
    }

    #[test]
    fn custom_policy_subset() {
        let policy = EmissionPolicy {
            mandatory_actions: vec![HighImpactAction::Terminate, HighImpactAction::Quarantine],
            ..Default::default()
        };
        assert!(policy.requires_evidence(HighImpactAction::Terminate));
        assert!(policy.requires_evidence(HighImpactAction::Quarantine));
        assert!(!policy.requires_evidence(HighImpactAction::Sandbox));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = EmissionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // -----------------------------------------------------------------------
    // CanonicalEvidenceEmitter — basic emission
    // -----------------------------------------------------------------------

    #[test]
    fn emit_produces_entry_and_receipt() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);

        assert!(!receipt.entry_id.is_empty());
        assert_eq!(receipt.action, HighImpactAction::Sandbox);
        assert_eq!(receipt.decision_type, DecisionType::SecurityAction);
        assert_eq!(receipt.trace_id, "trace-001");
        assert_eq!(emitter.ledger_len(), 1);
    }

    #[test]
    fn emitted_entry_has_correct_linkage() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);

        let entry = &emitter.ledger()[0];
        assert_eq!(entry.trace_id, "trace-001");
        assert_eq!(entry.decision_id, "dec-001");
        assert_eq!(entry.policy_id, "pol-001");
        assert_eq!(entry.epoch_id, SecurityEpoch::GENESIS);
        assert_eq!(entry.timestamp_ns, 1_000_000);
        assert_eq!(entry.schema_version, current_schema_version());
    }

    #[test]
    fn emitted_entry_has_candidates_and_witnesses() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);

        let entry = &emitter.ledger()[0];
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.constraints.len(), 1);
        assert_eq!(entry.witnesses.len(), 2);
        assert_eq!(entry.chosen_action.action_name, "sandbox");
    }

    #[test]
    fn emitted_entry_has_metadata() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);

        let entry = &emitter.ledger()[0];
        assert_eq!(
            entry.metadata.get("extension_version"),
            Some(&"1.2.3".to_string())
        );
        assert_eq!(entry.metadata.get("action"), Some(&"sandbox".to_string()));
        assert_eq!(
            entry.metadata.get("target_id"),
            Some(&"ext-001".to_string())
        );
        assert_eq!(
            entry.metadata.get("component"),
            Some(&"containment".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Structured log events
    // -----------------------------------------------------------------------

    #[test]
    fn emit_produces_structured_log() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);

        let logs = emitter.log_events();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].trace_id, "trace-001");
        assert_eq!(logs[0].decision_id, "dec-001");
        assert_eq!(logs[0].policy_id, "pol-001");
        assert_eq!(logs[0].component, "containment");
        assert_eq!(logs[0].event, "evidence_emitted");
        assert_eq!(logs[0].outcome, "success");
        assert!(logs[0].error_code.is_none());
    }

    // -----------------------------------------------------------------------
    // Validation failures
    // -----------------------------------------------------------------------

    #[test]
    fn empty_trace_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.trace_id.clear();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "trace_id"));
    }

    #[test]
    fn whitespace_trace_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.trace_id = "   ".to_string();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "trace_id"));
    }

    #[test]
    fn empty_decision_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.decision_id.clear();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "decision_id"));
    }

    #[test]
    fn whitespace_decision_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.decision_id = "\t\n".to_string();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "decision_id"));
    }

    #[test]
    fn empty_policy_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.policy_id.clear();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "policy_id"));
    }

    #[test]
    fn whitespace_policy_id_rejected() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.policy_id = "   ".to_string();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "policy_id"));
    }

    // -----------------------------------------------------------------------
    // Buffer capacity / backpressure
    // -----------------------------------------------------------------------

    #[test]
    fn buffer_full_returns_error() {
        let policy = EmissionPolicy {
            buffer_capacity: 2,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);

        // Emit 2 entries OK.
        let mut ctx1 = test_context(HighImpactAction::Sandbox);
        ctx1.decision_id = "dec-001".to_string();
        emitter
            .emit(
                &ctx1,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        let mut ctx2 = test_context(HighImpactAction::Terminate);
        ctx2.decision_id = "dec-002".to_string();
        emitter
            .emit(
                &ctx2,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        // 3rd should fail.
        let mut ctx3 = test_context(HighImpactAction::Suspend);
        ctx3.decision_id = "dec-003".to_string();
        let err = emitter
            .emit(
                &ctx3,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::BufferFull { capacity: 2 }));
    }

    // -----------------------------------------------------------------------
    // Ledger failure simulation
    // -----------------------------------------------------------------------

    #[test]
    fn ledger_failure_returns_error() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter.set_failed(true);

        let err = emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::LedgerWriteFailure { .. }));
    }

    #[test]
    fn ledger_failure_emits_log_with_error_code() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter.set_failed(true);

        let _ = emitter.emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            BTreeMap::new(),
        );

        let logs = emitter.log_events();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].outcome, "failure");
        assert!(logs[0].error_code.is_some());
    }

    // -----------------------------------------------------------------------
    // Policy filtering
    // -----------------------------------------------------------------------

    #[test]
    fn non_required_action_returns_not_required() {
        let policy = EmissionPolicy {
            mandatory_actions: vec![HighImpactAction::Terminate],
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);

        let err = emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::NotRequired { .. }));
    }

    // -----------------------------------------------------------------------
    // Integrity verification
    // -----------------------------------------------------------------------

    #[test]
    fn verify_integrity_matches_receipt() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);

        let entry = &emitter.ledger()[0];
        let recomputed = emitter.verify_integrity(entry).unwrap();
        assert_eq!(recomputed, receipt.artifact_hash);
    }

    #[test]
    fn tampered_entry_fails_integrity() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);

        let mut tampered = emitter.ledger()[0].clone();
        tampered.chosen_action.rationale = "tampered rationale".to_string();

        let recomputed = emitter.verify_integrity(&tampered).unwrap();
        assert_ne!(recomputed, receipt.artifact_hash);
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    #[test]
    fn entries_by_type_filters() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();

        let mut ctx1 = test_context(HighImpactAction::Sandbox);
        ctx1.decision_id = "dec-001".to_string();
        emitter
            .emit(
                &ctx1,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        let mut ctx2 = test_context(HighImpactAction::ExtensionLoad);
        ctx2.decision_id = "dec-002".to_string();
        emitter
            .emit(
                &ctx2,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(
            emitter.entries_by_type(DecisionType::SecurityAction).len(),
            1
        );
        assert_eq!(
            emitter
                .entries_by_type(DecisionType::ExtensionLifecycle)
                .len(),
            1
        );
    }

    #[test]
    fn entries_by_trace_filters() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();

        let mut ctx1 = test_context(HighImpactAction::Sandbox);
        ctx1.trace_id = "trace-A".to_string();
        ctx1.decision_id = "dec-001".to_string();
        emitter
            .emit(
                &ctx1,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        let mut ctx2 = test_context(HighImpactAction::Terminate);
        ctx2.trace_id = "trace-B".to_string();
        ctx2.decision_id = "dec-002".to_string();
        emitter
            .emit(
                &ctx2,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(emitter.entries_by_trace("trace-A").len(), 1);
        assert_eq!(emitter.entries_by_trace("trace-B").len(), 1);
        assert_eq!(emitter.entries_by_trace("trace-C").len(), 0);
    }

    // -----------------------------------------------------------------------
    // Witness truncation
    // -----------------------------------------------------------------------

    #[test]
    fn witness_truncation() {
        let policy = EmissionPolicy {
            max_witnesses: 1,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);

        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(), // 2 witnesses
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(emitter.ledger()[0].witnesses.len(), 1);
    }

    #[test]
    fn candidate_truncation() {
        let policy = EmissionPolicy {
            max_candidates: 2,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);

        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(), // 3 candidates
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(emitter.ledger()[0].candidates.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Clear
    // -----------------------------------------------------------------------

    #[test]
    fn clear_resets_state() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);
        assert_eq!(emitter.ledger_len(), 1);

        emitter.clear();
        assert_eq!(emitter.ledger_len(), 0);
        assert!(emitter.log_events().is_empty());
        assert!(emitter.receipts().is_empty());
    }

    // -----------------------------------------------------------------------
    // Deterministic output
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_emission() {
        let mut e1 = CanonicalEvidenceEmitter::with_defaults();
        let mut e2 = CanonicalEvidenceEmitter::with_defaults();

        let r1 = emit_standard(&mut e1);
        let r2 = emit_standard(&mut e2);

        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(r1.entry_id, r2.entry_id);
        assert_eq!(e1.ledger()[0], e2.ledger()[0]);
    }

    // -----------------------------------------------------------------------
    // Full lifecycle coverage
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_emits_evidence_for_all_phases() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let lifecycle_actions = [
            HighImpactAction::ExtensionLoad,
            HighImpactAction::ExtensionStart,
            HighImpactAction::Sandbox,
            HighImpactAction::ExtensionStop,
            HighImpactAction::ExtensionUnload,
        ];

        for (i, action) in lifecycle_actions.iter().enumerate() {
            let mut ctx = test_context(*action);
            ctx.decision_id = format!("dec-{:03}", i);
            ctx.timestamp_ns = (i as u64 + 1) * 1_000_000;
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }

        assert_eq!(emitter.ledger_len(), 5);
        // Verify monotonic timestamps.
        for i in 1..emitter.ledger().len() {
            assert!(emitter.ledger()[i].timestamp_ns > emitter.ledger()[i - 1].timestamp_ns);
        }
    }

    // -----------------------------------------------------------------------
    // All high-impact actions can be emitted
    // -----------------------------------------------------------------------

    #[test]
    fn all_high_impact_actions_emit_successfully() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();

        for (i, action) in HighImpactAction::ALL.iter().enumerate() {
            let mut ctx = test_context(*action);
            ctx.decision_id = format!("dec-{:03}", i);
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }

        assert_eq!(emitter.ledger_len(), 20);
    }

    // -----------------------------------------------------------------------
    // Serialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn emission_context_serde_roundtrip() {
        let ctx = test_context(HighImpactAction::Sandbox);
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: EmissionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }

    #[test]
    fn emission_error_serde_roundtrip() {
        let errors = vec![
            EmissionError::MissingField {
                field: "trace_id".to_string(),
            },
            EmissionError::LedgerWriteFailure {
                reason: "disk full".to_string(),
            },
            EmissionError::ValidationFailure {
                reason: "bad schema".to_string(),
            },
            EmissionError::BufferFull { capacity: 100 },
            EmissionError::NotRequired {
                action: HighImpactAction::Sandbox,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: EmissionError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn emission_receipt_serde_roundtrip() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: EmissionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn structured_log_serde_roundtrip() {
        let log = StructuredLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "success".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&log).unwrap();
        let restored: StructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(log, restored);
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        assert_eq!(
            EmissionError::MissingField {
                field: "trace_id".to_string()
            }
            .to_string(),
            "missing required field: trace_id"
        );
        assert_eq!(
            EmissionError::BufferFull { capacity: 10 }.to_string(),
            "emission buffer full (capacity=10)"
        );
        assert_eq!(
            EmissionError::NotRequired {
                action: HighImpactAction::Sandbox
            }
            .to_string(),
            "evidence not required for sandbox"
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: empty witnesses and candidates
    // -----------------------------------------------------------------------

    #[test]
    fn empty_witnesses_and_candidates_ok() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter
            .emit(
                &test_context(HighImpactAction::PolicyUpdate),
                vec![],
                vec![],
                ChosenAction {
                    action_name: "update_policy".to_string(),
                    expected_loss_millionths: 0,
                    rationale: "scheduled rotation".to_string(),
                },
                vec![],
                BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(emitter.ledger_len(), 1);
        assert!(emitter.ledger()[0].candidates.is_empty());
        assert!(emitter.ledger()[0].witnesses.is_empty());
    }

    #[test]
    fn emission_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(EmissionError::MissingField {
                field: "ctx".into(),
            }),
            Box::new(EmissionError::LedgerWriteFailure {
                reason: "disk".into(),
            }),
            Box::new(EmissionError::ValidationFailure {
                reason: "bad".into(),
            }),
            Box::new(EmissionError::BufferFull { capacity: 64 }),
            Box::new(EmissionError::NotRequired {
                action: HighImpactAction::Sandbox,
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn high_impact_action_ord() {
        assert!(HighImpactAction::Sandbox < HighImpactAction::Suspend);
        assert!(HighImpactAction::Suspend < HighImpactAction::Terminate);
        assert!(HighImpactAction::Terminate < HighImpactAction::Quarantine);
        assert!(HighImpactAction::ExtensionLoad < HighImpactAction::ExtensionUnload);
        assert!(HighImpactAction::PolicyUpdate < HighImpactAction::EpochTransition);
        assert!(HighImpactAction::Cancellation < HighImpactAction::ContractEvaluation);
        assert!(HighImpactAction::ContractEvaluation < HighImpactAction::RemoteAuthorization);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, metadata, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_display_all_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for action in HighImpactAction::ALL {
            seen.insert(action.to_string());
        }
        assert_eq!(
            seen.len(),
            20,
            "all 20 HighImpactAction Display strings must be unique"
        );
    }

    #[test]
    fn high_impact_action_all_serde_roundtrip() {
        for action in HighImpactAction::ALL {
            let json = serde_json::to_string(&action).unwrap();
            let restored: HighImpactAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, restored);
        }
    }

    #[test]
    fn emission_policy_default_values() {
        let policy = EmissionPolicy::default();
        assert!(policy.buffer_capacity > 0);
        assert!(policy.max_candidates > 0);
        assert!(policy.max_witnesses > 0);
        assert_eq!(policy.mandatory_actions.len(), HighImpactAction::ALL.len());
    }

    #[test]
    fn emission_policy_serde_roundtrip() {
        let policy = EmissionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn receipts_accumulate_across_emissions() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        for i in 0..3 {
            let mut ctx = test_context(HighImpactAction::Sandbox);
            ctx.decision_id = format!("dec-{i:03}");
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }
        assert_eq!(emitter.receipts().len(), 3);
    }

    #[test]
    fn log_events_accumulate_on_success() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);
        let logs = emitter.log_events();
        assert!(!logs.is_empty());
        assert_eq!(logs[0].outcome, "success");
        assert!(logs[0].error_code.is_none());
    }

    #[test]
    fn metadata_passed_through_to_entry() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                metadata,
            )
            .unwrap();

        let entry = &emitter.ledger()[0];
        assert_eq!(entry.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn empty_decision_id_rejected_via_validation() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.decision_id.clear();

        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::MissingField { field } if field == "decision_id"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_decision_type_all_variants() {
        for action in &HighImpactAction::ALL {
            let dt = action.decision_type();
            let name = dt.to_string();
            assert!(
                !name.is_empty(),
                "decision_type() for {action} should have a non-empty Display"
            );
        }
        // Spot-check specific mappings.
        assert_eq!(
            HighImpactAction::Sandbox.decision_type(),
            DecisionType::SecurityAction
        );
        assert_eq!(
            HighImpactAction::ExtensionLoad.decision_type(),
            DecisionType::ExtensionLifecycle
        );
        assert_eq!(
            HighImpactAction::PolicyUpdate.decision_type(),
            DecisionType::PolicyUpdate
        );
        assert_eq!(
            HighImpactAction::EpochTransition.decision_type(),
            DecisionType::EpochTransition
        );
        assert_eq!(
            HighImpactAction::CapabilityGrant.decision_type(),
            DecisionType::CapabilityDecision
        );
        assert_eq!(
            HighImpactAction::Revocation.decision_type(),
            DecisionType::Revocation
        );
        assert_eq!(
            HighImpactAction::RemoteAuthorization.decision_type(),
            DecisionType::RemoteAuthorization
        );
    }

    #[test]
    fn high_impact_action_component_all_non_empty() {
        let mut components = std::collections::BTreeSet::new();
        for action in &HighImpactAction::ALL {
            let comp = action.component();
            assert!(
                !comp.is_empty(),
                "component() for {action} should not be empty"
            );
            components.insert(comp);
        }
        // There should be multiple distinct components.
        assert!(
            components.len() >= 5,
            "at least 5 distinct components expected"
        );
    }

    #[test]
    fn set_failed_causes_ledger_write_failure() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter.set_failed(true);
        let ctx = test_context(HighImpactAction::Sandbox);
        let err = emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::LedgerWriteFailure { .. }));
    }

    #[test]
    fn set_failed_false_restores_normal_operation() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter.set_failed(true);
        emitter.set_failed(false);
        let ctx = test_context(HighImpactAction::Sandbox);
        assert!(
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .is_ok()
        );
    }

    #[test]
    fn ledger_len_tracks_emissions() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        assert_eq!(emitter.ledger_len(), 0);
        let ctx = test_context(HighImpactAction::Sandbox);
        emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(emitter.ledger_len(), 1);
    }

    #[test]
    fn entries_by_type_empty_for_unmatched_type() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let ctx = test_context(HighImpactAction::Sandbox);
        emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        // Sandbox maps to SecurityAction; RemoteAuthorization entries should be empty.
        let filtered = emitter.entries_by_type(DecisionType::RemoteAuthorization);
        assert!(filtered.is_empty());
    }

    #[test]
    fn entries_by_trace_empty_for_unknown_trace() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let ctx = test_context(HighImpactAction::Sandbox);
        emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        let filtered = emitter.entries_by_trace("nonexistent-trace");
        assert!(filtered.is_empty());
    }

    #[test]
    fn policy_requires_evidence_custom_subset() {
        let policy = EmissionPolicy {
            mandatory_actions: vec![HighImpactAction::Sandbox, HighImpactAction::Terminate],
            max_witnesses: 256,
            max_candidates: 64,
            include_metadata: true,
            buffer_capacity: 1024,
        };
        assert!(policy.requires_evidence(HighImpactAction::Sandbox));
        assert!(policy.requires_evidence(HighImpactAction::Terminate));
        assert!(!policy.requires_evidence(HighImpactAction::ExtensionLoad));
    }

    #[test]
    fn high_impact_action_all_has_twenty_variants() {
        assert_eq!(HighImpactAction::ALL.len(), 20);
    }

    #[test]
    fn policy_accessor_returns_configured_policy() {
        let emitter = CanonicalEvidenceEmitter::with_defaults();
        let policy = emitter.policy();
        assert_eq!(policy.mandatory_actions.len(), 20);
        assert!(policy.include_metadata);
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-28 — Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_copy_semantics() {
        let a = HighImpactAction::Sandbox;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn high_impact_action_copy_all_variants() {
        for action in HighImpactAction::ALL {
            let copied = action;
            let again = action;
            assert_eq!(copied, again);
        }
    }

    #[test]
    fn high_impact_action_copy_into_fn() {
        fn consume(a: HighImpactAction) -> HighImpactAction {
            a
        }
        let a = HighImpactAction::Terminate;
        let b = consume(a);
        // a is still valid because it's Copy:
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_debug_all_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for action in HighImpactAction::ALL {
            let dbg = format!("{action:?}");
            assert!(seen.insert(dbg.clone()), "duplicate Debug for {action:?}");
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn emission_error_debug_all_distinct() {
        let variants = vec![
            EmissionError::MissingField { field: "f".into() },
            EmissionError::LedgerWriteFailure { reason: "r".into() },
            EmissionError::ValidationFailure { reason: "v".into() },
            EmissionError::BufferFull { capacity: 1 },
            EmissionError::NotRequired {
                action: HighImpactAction::Sandbox,
            },
        ];
        let mut debugs = std::collections::BTreeSet::new();
        for v in &variants {
            debugs.insert(format!("{v:?}"));
        }
        assert_eq!(debugs.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_serde_all_distinct_json() {
        let mut seen = std::collections::BTreeSet::new();
        for action in HighImpactAction::ALL {
            let json = serde_json::to_string(&action).unwrap();
            assert!(seen.insert(json.clone()), "duplicate JSON for {action:?}");
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn emission_error_serde_variants_distinct() {
        let variants = vec![
            EmissionError::MissingField { field: "x".into() },
            EmissionError::LedgerWriteFailure { reason: "y".into() },
            EmissionError::ValidationFailure { reason: "z".into() },
            EmissionError::BufferFull { capacity: 42 },
            EmissionError::NotRequired {
                action: HighImpactAction::Quarantine,
            },
        ];
        let mut jsons = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            jsons.insert(json);
        }
        assert_eq!(jsons.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn emission_context_clone_independence() {
        let original = test_context(HighImpactAction::Sandbox);
        let mut cloned = original.clone();
        cloned.trace_id = "modified-trace".to_string();
        cloned.target_id = "modified-target".to_string();
        cloned.timestamp_ns = u64::MAX;
        assert_eq!(original.trace_id, "trace-001");
        assert_eq!(original.target_id, "ext-001");
        assert_eq!(original.timestamp_ns, 1_000_000);
    }

    #[test]
    fn emission_policy_clone_independence() {
        let original = EmissionPolicy::default();
        let mut cloned = original.clone();
        cloned.mandatory_actions.clear();
        cloned.max_witnesses = 0;
        cloned.buffer_capacity = 0;
        assert_eq!(original.mandatory_actions.len(), 20);
        assert_eq!(original.max_witnesses, 256);
        assert_eq!(original.buffer_capacity, 1024);
    }

    #[test]
    fn emission_error_clone_independence() {
        let original = EmissionError::MissingField {
            field: "trace_id".into(),
        };
        let mut cloned = original.clone();
        if let EmissionError::MissingField { ref mut field } = cloned {
            *field = "mutated".into();
        }
        assert_eq!(
            original,
            EmissionError::MissingField {
                field: "trace_id".into()
            }
        );
    }

    #[test]
    fn emission_receipt_clone_independence() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);
        let mut cloned = receipt.clone();
        cloned.trace_id = "cloned-trace".to_string();
        cloned.entry_id = "cloned-entry".to_string();
        assert_eq!(receipt.trace_id, "trace-001");
        assert_ne!(receipt.entry_id, "cloned-entry");
    }

    #[test]
    fn structured_log_clone_independence() {
        let original = StructuredLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "success".into(),
            error_code: Some("ec".into()),
        };
        let mut cloned = original.clone();
        cloned.trace_id = "modified".into();
        cloned.error_code = None;
        assert_eq!(original.trace_id, "t");
        assert_eq!(original.error_code, Some("ec".into()));
    }

    // -----------------------------------------------------------------------
    // JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn emission_context_json_field_names() {
        let ctx = test_context(HighImpactAction::Sandbox);
        let json = serde_json::to_string(&ctx).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("timestamp_ns"));
        assert!(obj.contains_key("action"));
        assert!(obj.contains_key("target_id"));
        assert_eq!(obj.len(), 7, "EmissionContext should have exactly 7 fields");
    }

    #[test]
    fn emission_policy_json_field_names() {
        let policy = EmissionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("mandatory_actions"));
        assert!(obj.contains_key("max_witnesses"));
        assert!(obj.contains_key("max_candidates"));
        assert!(obj.contains_key("include_metadata"));
        assert!(obj.contains_key("buffer_capacity"));
        assert_eq!(obj.len(), 5, "EmissionPolicy should have exactly 5 fields");
    }

    #[test]
    fn emission_receipt_json_field_names() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let receipt = emit_standard(&mut emitter);
        let json = serde_json::to_string(&receipt).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("entry_id"));
        assert!(obj.contains_key("artifact_hash"));
        assert!(obj.contains_key("decision_type"));
        assert!(obj.contains_key("action"));
        assert!(obj.contains_key("trace_id"));
        assert_eq!(obj.len(), 5, "EmissionReceipt should have exactly 5 fields");
    }

    #[test]
    fn structured_log_event_json_field_names() {
        let log = StructuredLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("error_code"));
        assert_eq!(
            obj.len(),
            7,
            "StructuredLogEvent should have exactly 7 fields"
        );
    }

    #[test]
    fn emission_error_missing_field_json_field_names() {
        let err = EmissionError::MissingField { field: "x".into() };
        let json = serde_json::to_string(&err).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("MissingField"),
            "JSON should have MissingField key"
        );
    }

    #[test]
    fn emission_error_buffer_full_json_field_names() {
        let err = EmissionError::BufferFull { capacity: 99 };
        let json = serde_json::to_string(&err).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            obj.contains_key("BufferFull"),
            "JSON should have BufferFull key"
        );
    }

    // -----------------------------------------------------------------------
    // Display format checks
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_display_all_lowercase_underscore() {
        for action in HighImpactAction::ALL {
            let display = action.to_string();
            assert!(
                !display.is_empty(),
                "Display should not be empty for {action:?}"
            );
            for ch in display.chars() {
                assert!(
                    ch.is_ascii_lowercase() || ch == '_',
                    "Display for {action:?} should be lowercase+underscore, got '{ch}'"
                );
            }
        }
    }

    #[test]
    fn emission_error_display_all_variants_nonempty() {
        let variants = vec![
            EmissionError::MissingField { field: "f".into() },
            EmissionError::LedgerWriteFailure { reason: "r".into() },
            EmissionError::ValidationFailure { reason: "v".into() },
            EmissionError::BufferFull { capacity: 0 },
            EmissionError::NotRequired {
                action: HighImpactAction::Sandbox,
            },
        ];
        for v in &variants {
            let display = v.to_string();
            assert!(!display.is_empty(), "Display should not be empty for {v:?}");
        }
    }

    #[test]
    fn emission_error_display_missing_field_contains_field_name() {
        let err = EmissionError::MissingField {
            field: "my_field".into(),
        };
        assert!(err.to_string().contains("my_field"));
    }

    #[test]
    fn emission_error_display_ledger_write_failure_contains_reason() {
        let err = EmissionError::LedgerWriteFailure {
            reason: "disk full".into(),
        };
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn emission_error_display_validation_failure_contains_reason() {
        let err = EmissionError::ValidationFailure {
            reason: "bad schema".into(),
        };
        assert!(err.to_string().contains("bad schema"));
    }

    #[test]
    fn emission_error_display_buffer_full_contains_capacity() {
        let err = EmissionError::BufferFull { capacity: 512 };
        assert!(err.to_string().contains("512"));
    }

    #[test]
    fn emission_error_display_not_required_contains_action_name() {
        let err = EmissionError::NotRequired {
            action: HighImpactAction::Terminate,
        };
        assert!(err.to_string().contains("terminate"));
    }

    // -----------------------------------------------------------------------
    // Hash consistency (HighImpactAction)
    // -----------------------------------------------------------------------

    #[test]
    fn high_impact_action_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for action in HighImpactAction::ALL {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            action.hash(&mut h1);
            action.hash(&mut h2);
            assert_eq!(
                h1.finish(),
                h2.finish(),
                "Hash should be consistent for {action:?}"
            );
        }
    }

    #[test]
    fn high_impact_action_hash_distinct_variants() {
        use std::hash::{Hash, Hasher};
        let mut hashes = std::collections::BTreeSet::new();
        for action in HighImpactAction::ALL {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            action.hash(&mut hasher);
            hashes.insert(hasher.finish());
        }
        // At minimum most should be distinct (hash collisions possible but very unlikely for 20)
        assert!(
            hashes.len() >= 18,
            "expected at least 18 distinct hashes out of 20"
        );
    }

    // -----------------------------------------------------------------------
    // Boundary / edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn emission_context_max_timestamp_ns() {
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.timestamp_ns = u64::MAX;
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: EmissionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.timestamp_ns, u64::MAX);
    }

    #[test]
    fn emission_context_zero_timestamp_ns() {
        let mut ctx = test_context(HighImpactAction::Sandbox);
        ctx.timestamp_ns = 0;
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: EmissionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.timestamp_ns, 0);
    }

    #[test]
    fn emission_policy_empty_mandatory_actions() {
        let policy = EmissionPolicy {
            mandatory_actions: vec![],
            ..Default::default()
        };
        for action in HighImpactAction::ALL {
            assert!(!policy.requires_evidence(action));
        }
    }

    #[test]
    fn emission_policy_zero_buffer_capacity() {
        let policy = EmissionPolicy {
            buffer_capacity: 0,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        let err = emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::BufferFull { capacity: 0 }));
    }

    #[test]
    fn emission_policy_zero_max_witnesses() {
        let policy = EmissionPolicy {
            max_witnesses: 0,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        assert!(emitter.ledger()[0].witnesses.is_empty());
    }

    #[test]
    fn emission_policy_zero_max_candidates() {
        let policy = EmissionPolicy {
            max_candidates: 0,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        assert!(emitter.ledger()[0].candidates.is_empty());
    }

    #[test]
    fn buffer_full_capacity_one() {
        let policy = EmissionPolicy {
            buffer_capacity: 1,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        let mut ctx2 = test_context(HighImpactAction::Terminate);
        ctx2.decision_id = "dec-002".into();
        let err = emitter
            .emit(
                &ctx2,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap_err();
        assert!(matches!(err, EmissionError::BufferFull { capacity: 1 }));
    }

    #[test]
    fn emission_with_empty_metadata() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        // Metadata still has injected fields (action, target_id, component).
        let entry = &emitter.ledger()[0];
        assert!(entry.metadata.contains_key("action"));
        assert!(entry.metadata.contains_key("target_id"));
        assert!(entry.metadata.contains_key("component"));
    }

    #[test]
    fn emission_with_no_metadata_flag_off() {
        let policy = EmissionPolicy {
            include_metadata: false,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        let entry = &emitter.ledger()[0];
        // When include_metadata is false, injected fields should NOT be present.
        assert!(!entry.metadata.contains_key("action"));
        assert!(!entry.metadata.contains_key("target_id"));
        assert!(!entry.metadata.contains_key("component"));
    }

    #[test]
    fn emission_context_with_long_strings() {
        let long = "a".repeat(10_000);
        let ctx = EmissionContext {
            trace_id: long.clone(),
            decision_id: long.clone(),
            policy_id: long.clone(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 42,
            action: HighImpactAction::Sandbox,
            target_id: long.clone(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: EmissionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }

    #[test]
    fn emission_error_buffer_full_capacity_max() {
        let err = EmissionError::BufferFull {
            capacity: usize::MAX,
        };
        let display = err.to_string();
        assert!(display.contains(&usize::MAX.to_string()));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips (complex structs)
    // -----------------------------------------------------------------------

    #[test]
    fn emission_context_all_actions_serde_roundtrip() {
        for action in HighImpactAction::ALL {
            let ctx = test_context(action);
            let json = serde_json::to_string(&ctx).unwrap();
            let restored: EmissionContext = serde_json::from_str(&json).unwrap();
            assert_eq!(ctx, restored, "roundtrip failed for action {action:?}");
        }
    }

    #[test]
    fn emission_policy_custom_serde_roundtrip() {
        let policy = EmissionPolicy {
            mandatory_actions: vec![HighImpactAction::Sandbox, HighImpactAction::Terminate],
            max_witnesses: 1,
            max_candidates: 2,
            include_metadata: false,
            buffer_capacity: 3,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn emission_error_not_required_all_actions_roundtrip() {
        for action in HighImpactAction::ALL {
            let err = EmissionError::NotRequired { action };
            let json = serde_json::to_string(&err).unwrap();
            let restored: EmissionError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, restored);
        }
    }

    #[test]
    fn structured_log_event_with_error_code_roundtrip() {
        let log = StructuredLogEvent {
            trace_id: "trace-rt".into(),
            decision_id: "dec-rt".into(),
            policy_id: "pol-rt".into(),
            component: "containment".into(),
            event: "buffer_full".into(),
            outcome: "failure".into(),
            error_code: Some("BUFFER_OVERFLOW".into()),
        };
        let json = serde_json::to_string(&log).unwrap();
        let restored: StructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(log, restored);
    }

    // -----------------------------------------------------------------------
    // Additional emitter behavioral edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn clear_followed_by_new_emission_works() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emit_standard(&mut emitter);
        assert_eq!(emitter.ledger_len(), 1);
        emitter.clear();
        assert_eq!(emitter.ledger_len(), 0);
        // Emit again after clear.
        emit_standard(&mut emitter);
        assert_eq!(emitter.ledger_len(), 1);
    }

    #[test]
    fn clear_resets_failed_state() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        emitter.set_failed(true);
        emitter.clear();
        // After clear, failed should be reset.
        let result = emitter.emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            BTreeMap::new(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn multiple_actions_same_trace_id() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        let actions = [
            HighImpactAction::Sandbox,
            HighImpactAction::Suspend,
            HighImpactAction::Terminate,
        ];
        for (i, action) in actions.iter().enumerate() {
            let mut ctx = test_context(*action);
            ctx.trace_id = "shared-trace".into();
            ctx.decision_id = format!("dec-{i:03}");
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }
        let found = emitter.entries_by_trace("shared-trace");
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn receipts_match_ledger_entries() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        for i in 0..5 {
            let mut ctx = test_context(HighImpactAction::ALL[i]);
            ctx.decision_id = format!("dec-{i:03}");
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }
        assert_eq!(emitter.receipts().len(), emitter.ledger_len());
        for (receipt, entry) in emitter.receipts().iter().zip(emitter.ledger().iter()) {
            assert_eq!(receipt.entry_id, entry.entry_id);
            assert_eq!(receipt.trace_id, entry.trace_id);
        }
    }

    #[test]
    fn verify_integrity_all_entries() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        for i in 0..5 {
            let mut ctx = test_context(HighImpactAction::ALL[i]);
            ctx.decision_id = format!("dec-{i:03}");
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }
        for (entry, receipt) in emitter.ledger().iter().zip(emitter.receipts().iter()) {
            let hash = emitter.verify_integrity(entry).unwrap();
            assert_eq!(hash, receipt.artifact_hash);
        }
    }

    #[test]
    fn log_events_count_matches_successful_emissions() {
        let mut emitter = CanonicalEvidenceEmitter::with_defaults();
        for i in 0..4 {
            let mut ctx = test_context(HighImpactAction::ALL[i]);
            ctx.decision_id = format!("dec-{i:03}");
            emitter
                .emit(
                    &ctx,
                    test_candidates(),
                    test_constraints(),
                    test_chosen(),
                    test_witnesses(),
                    BTreeMap::new(),
                )
                .unwrap();
        }
        // Each successful emission produces one log event.
        assert_eq!(emitter.log_events().len(), 4);
        for log in emitter.log_events() {
            assert_eq!(log.outcome, "success");
            assert!(log.error_code.is_none());
        }
    }

    #[test]
    fn buffer_full_log_event_is_emitted() {
        let policy = EmissionPolicy {
            buffer_capacity: 1,
            ..Default::default()
        };
        let mut emitter = CanonicalEvidenceEmitter::new(policy);
        emitter
            .emit(
                &test_context(HighImpactAction::Sandbox),
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                BTreeMap::new(),
            )
            .unwrap();
        let mut ctx2 = test_context(HighImpactAction::Terminate);
        ctx2.decision_id = "dec-002".into();
        let _ = emitter.emit(
            &ctx2,
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            BTreeMap::new(),
        );
        // The buffer_full attempt should also produce a log event.
        assert!(emitter.log_events().len() >= 2);
        let last = emitter.log_events().last().unwrap();
        assert_eq!(last.event, "buffer_full");
    }

    #[test]
    fn decision_type_mapping_exhaustive() {
        // Every variant in ALL should map to a known DecisionType.
        let known_types = [
            DecisionType::SecurityAction,
            DecisionType::ExtensionLifecycle,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::CapabilityDecision,
            DecisionType::Revocation,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ];
        for action in HighImpactAction::ALL {
            let dt = action.decision_type();
            assert!(
                known_types.contains(&dt),
                "decision_type() for {action:?} returned unexpected type"
            );
        }
    }

    #[test]
    fn component_mapping_exhaustive() {
        let known_components = [
            "containment",
            "lifecycle",
            "policy",
            "epoch",
            "capability",
            "obligation",
            "region",
            "cancellation",
            "contract",
            "remote_auth",
        ];
        for action in HighImpactAction::ALL {
            let comp = action.component();
            assert!(
                known_components.contains(&comp),
                "component() for {action:?} returned unexpected '{comp}'"
            );
        }
    }

    #[test]
    fn emission_error_not_required_display_includes_action() {
        for action in HighImpactAction::ALL {
            let err = EmissionError::NotRequired { action };
            let display = err.to_string();
            assert!(
                display.contains(&action.to_string()),
                "NotRequired display should contain action name for {action:?}"
            );
        }
    }

    #[test]
    fn emitter_with_defaults_starts_empty() {
        let emitter = CanonicalEvidenceEmitter::with_defaults();
        assert_eq!(emitter.ledger_len(), 0);
        assert!(emitter.ledger().is_empty());
        assert!(emitter.receipts().is_empty());
        assert!(emitter.log_events().is_empty());
    }

    #[test]
    fn emission_context_unicode_strings_roundtrip() {
        let ctx = EmissionContext {
            trace_id: "\u{1F600} trace".into(),
            decision_id: "\u{00E9}tat".into(),
            policy_id: "\u{4E16}\u{754C}".into(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 42,
            action: HighImpactAction::PolicyUpdate,
            target_id: "\u{0410}\u{0411}\u{0412}".into(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: EmissionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }
}
