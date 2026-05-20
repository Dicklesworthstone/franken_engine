//! Revocation freshness policy with degraded-mode behavior.
//!
//! When the local revocation head is stale (behind the expected latest),
//! the system enters degraded mode with conservative defaults:
//! - Safe operations (read-only) continue normally.
//! - Revocation-dependent operations (token acceptance, extension activation)
//!   are denied by default.
//! - Override-gated operations require a signed, short-lived override token.
//!
//! State machine: `Fresh -> Stale -> Degraded -> Recovering -> Fresh`
//!
//! Every decision under degraded mode emits a structured audit event.
//!
//! Plan references: Section 10.10 item 19, 9E.7.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::signature_preimage::{
    sign_preimage, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const OVERRIDE_SCHEMA_DEF: &[u8] = b"FrankenEngine.DegradedModeOverride.v1";
const CONTROLLER_SCHEMA_DEF: &[u8] = b"FrankenEngine.RevocationFreshnessController.v1";
const OVERRIDE_NONCE_LEN: usize = 32;

pub type OverrideNonce = [u8; OVERRIDE_NONCE_LEN];

fn override_schema_id() -> SchemaId {
    SchemaId::from_definition(OVERRIDE_SCHEMA_DEF)
}

fn controller_schema_id() -> SchemaId {
    SchemaId::from_definition(CONTROLLER_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// FreshnessState — state machine
// ---------------------------------------------------------------------------

/// Freshness state of the revocation chain.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum FreshnessState {
    /// Revocation head is up-to-date.
    #[default]
    Fresh,
    /// Staleness detected but threshold not yet exceeded.
    Stale,
    /// Threshold exceeded — degraded mode active.
    Degraded,
    /// Head caught up but holdoff period not yet elapsed.
    Recovering,
}

impl fmt::Display for FreshnessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh => write!(f, "fresh"),
            Self::Stale => write!(f, "stale"),
            Self::Degraded => write!(f, "degraded"),
            Self::Recovering => write!(f, "recovering"),
        }
    }
}

// ---------------------------------------------------------------------------
// OperationType — classification of operations
// ---------------------------------------------------------------------------

/// Operation types for freshness policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OperationType {
    /// Read-only operations unaffected by revocation state.
    SafeOperation,
    /// Accepting a capability token (requires fresh revocation state).
    TokenAcceptance,
    /// Activating an extension (requires fresh revocation state).
    ExtensionActivation,
    /// High-risk operations (policy changes, key ops, data export).
    HighRiskOperation,
    /// Health check or diagnostic (always allowed).
    HealthCheck,
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SafeOperation => write!(f, "safe_operation"),
            Self::TokenAcceptance => write!(f, "token_acceptance"),
            Self::ExtensionActivation => write!(f, "extension_activation"),
            Self::HighRiskOperation => write!(f, "high_risk_operation"),
            Self::HealthCheck => write!(f, "health_check"),
        }
    }
}

// ---------------------------------------------------------------------------
// Decision outcomes
// ---------------------------------------------------------------------------

/// Outcome of a freshness-aware decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessDecision {
    /// Operation proceeds normally (fresh state or safe operation).
    Proceed,
    /// Operation denied due to stale revocation state.
    Denied(DegradedDenial),
    /// Operation allowed via operator override.
    OverrideGranted {
        override_id: EngineObjectId,
        operator_id: String,
    },
}

/// Details of a degraded-mode denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedDenial {
    pub operation_type: OperationType,
    pub local_head_seq: u64,
    pub expected_head_seq: u64,
    pub staleness_gap: u64,
}

impl fmt::Display for DegradedDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "degraded mode denial: {} denied, local_seq={}, expected_seq={}, gap={}",
            self.operation_type, self.local_head_seq, self.expected_head_seq, self.staleness_gap,
        )
    }
}

impl std::error::Error for DegradedDenial {}

// ---------------------------------------------------------------------------
// Override errors
// ---------------------------------------------------------------------------

/// Errors when validating a degraded-mode override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverrideError {
    /// Override token has expired.
    Expired {
        expiry: DeterministicTimestamp,
        current: DeterministicTimestamp,
    },
    /// Operation type in override doesn't match the requested operation.
    OperationMismatch {
        requested: OperationType,
        override_type: OperationType,
    },
    /// Override signature is invalid.
    SignatureInvalid { detail: String },
    /// Operator is not authorized for overrides.
    UnauthorizedOperator { operator_id: String },
    /// Override token was already consumed.
    AlreadyConsumed { override_id: EngineObjectId },
    /// Override token was minted for a different controller zone.
    ZoneMismatch {
        controller_zone: String,
        override_zone: String,
    },
    /// Override token was minted for a different controller policy/cell.
    PolicyMismatch {
        controller_policy_id: EngineObjectId,
        override_policy_id: EngineObjectId,
    },
    /// Not in degraded mode — override not applicable.
    NotDegraded { current_state: FreshnessState },
}

impl fmt::Display for OverrideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { expiry, current } => {
                write!(
                    f,
                    "override expired: expiry={}, current={}",
                    expiry.0, current.0
                )
            }
            Self::OperationMismatch {
                requested,
                override_type,
            } => write!(
                f,
                "operation mismatch: requested={requested}, override={override_type}"
            ),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::UnauthorizedOperator { operator_id } => {
                write!(f, "unauthorized operator: {operator_id}")
            }
            Self::AlreadyConsumed { override_id } => {
                write!(f, "override already consumed: {override_id}")
            }
            Self::ZoneMismatch {
                controller_zone,
                override_zone,
            } => write!(
                f,
                "override zone mismatch: controller={controller_zone}, override={override_zone}"
            ),
            Self::PolicyMismatch {
                controller_policy_id,
                override_policy_id,
            } => write!(
                f,
                "override policy mismatch: controller={controller_policy_id}, override={override_policy_id}"
            ),
            Self::NotDegraded { current_state } => {
                write!(f, "not in degraded mode: state={current_state}")
            }
        }
    }
}

impl std::error::Error for OverrideError {}

// ---------------------------------------------------------------------------
// DegradedModeOverride — signed override token
// ---------------------------------------------------------------------------

/// A signed, short-lived override token allowing a specific operation
/// during degraded mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeOverride {
    /// Unique override identifier.
    pub override_id: EngineObjectId,
    /// Which operation this override authorizes.
    pub operation_type: OperationType,
    /// ID of the operator issuing the override.
    pub operator_id: String,
    /// Human-readable justification.
    pub justification: String,
    /// When this override expires.
    pub expiry: DeterministicTimestamp,
    /// Zone this override applies to.
    pub zone: String,
    /// One-time nonce bound into both the override id and signature.
    #[serde(default)]
    pub nonce: OverrideNonce,
    /// Controller policy/cell id this override is authorized for.
    #[serde(default)]
    pub target_policy_id: EngineObjectId,
    /// Signature of the override.
    pub signature: Signature,
}

impl DegradedModeOverride {
    /// Create a new override token, signing it with the operator's key.
    pub fn create(
        operation_type: OperationType,
        operator_id: &str,
        justification: &str,
        expiry: DeterministicTimestamp,
        zone: &str,
        target_policy_id: &EngineObjectId,
        signing_key: &SigningKey,
    ) -> Self {
        let mut nonce = [0u8; OVERRIDE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Self::create_with_nonce(
            operation_type,
            operator_id,
            justification,
            expiry,
            zone,
            target_policy_id,
            nonce,
            signing_key,
        )
    }

    /// Create a new override token with a caller-supplied nonce for deterministic
    /// replay fixtures.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_nonce(
        operation_type: OperationType,
        operator_id: &str,
        justification: &str,
        expiry: DeterministicTimestamp,
        zone: &str,
        target_policy_id: &EngineObjectId,
        nonce: OverrideNonce,
        signing_key: &SigningKey,
    ) -> Self {
        let canonical_bytes = Self::build_canonical(
            operation_type,
            operator_id,
            justification,
            expiry,
            zone,
            target_policy_id,
            &nonce,
        );
        let override_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            zone,
            &override_schema_id(),
            &canonical_bytes,
        )
        .expect("serde deserialization should succeed");

        let mut token = Self {
            override_id,
            operation_type,
            operator_id: operator_id.to_string(),
            justification: justification.to_string(),
            expiry,
            zone: zone.to_string(),
            nonce,
            target_policy_id: target_policy_id.clone(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        let preimage = token.preimage_bytes();
        let sig = sign_preimage(signing_key, &preimage).expect("signing should not fail");
        token.signature = sig;
        token
    }

    fn build_canonical(
        operation_type: OperationType,
        operator_id: &str,
        justification: &str,
        expiry: DeterministicTimestamp,
        zone: &str,
        target_policy_id: &EngineObjectId,
        nonce: &OverrideNonce,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::push_len_prefixed(&mut buf, operation_type.to_string().as_bytes());
        Self::push_len_prefixed(&mut buf, operator_id.as_bytes());
        Self::push_len_prefixed(&mut buf, justification.as_bytes());
        buf.extend_from_slice(&expiry.0.to_be_bytes());
        Self::push_len_prefixed(&mut buf, zone.as_bytes());
        buf.extend_from_slice(target_policy_id.as_bytes());
        buf.extend_from_slice(nonce);
        buf
    }

    fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).expect("canonical field length exceeds u32");
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(bytes);
    }
}

impl SignaturePreimage for DegradedModeOverride {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &crate::deterministic_serde::SchemaHash {
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> crate::deterministic_serde::CanonicalValue {
        use crate::deterministic_serde::CanonicalValue;
        let mut map = BTreeMap::new();
        map.insert("expiry".to_string(), CanonicalValue::U64(self.expiry.0));
        map.insert(
            "operation_type".to_string(),
            CanonicalValue::String(self.operation_type.to_string()),
        );
        map.insert(
            "operator_id".to_string(),
            CanonicalValue::String(self.operator_id.clone()),
        );
        map.insert(
            "justification".to_string(),
            CanonicalValue::String(self.justification.clone()),
        );
        map.insert(
            "nonce".to_string(),
            CanonicalValue::Bytes(self.nonce.to_vec()),
        );
        map.insert(
            "override_id".to_string(),
            CanonicalValue::Bytes(self.override_id.as_bytes().to_vec()),
        );
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "target_policy_id".to_string(),
            CanonicalValue::Bytes(self.target_policy_id.as_bytes().to_vec()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        use crate::deterministic_serde::{self, SchemaHash};
        let domain_tag = self.signature_domain().tag();
        let schema = SchemaHash::from_definition(OVERRIDE_SCHEMA_DEF);
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Audit event for freshness state changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessStateChangeEvent {
    pub from_state: FreshnessState,
    pub to_state: FreshnessState,
    pub local_head_seq: u64,
    pub expected_head_seq: u64,
    pub staleness_gap: u64,
    pub threshold: u64,
    pub trace_id: String,
    pub timestamp: DeterministicTimestamp,
}

/// Audit event for degraded-mode decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeDecisionEvent {
    pub operation_type: OperationType,
    pub outcome: String,
    pub local_head_seq: u64,
    pub expected_head_seq: u64,
    pub override_id: Option<EngineObjectId>,
    pub operator_id: Option<String>,
    pub trace_id: String,
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// FreshnessConfig — policy configuration
// ---------------------------------------------------------------------------

/// Configuration for the revocation freshness policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessConfig {
    /// Maximum sequence gap before declaring staleness.
    pub staleness_threshold: u64,
    /// Number of ticks the system must remain fresh in Recovering before
    /// transitioning back to Fresh.
    pub holdoff_ticks: u64,
    /// Operation types that are eligible for operator override.
    pub override_eligible: BTreeSet<OperationType>,
    /// Authorized operator IDs.
    pub authorized_operators: BTreeSet<String>,
    /// Verification key pinned to each authorized operator ID.
    pub authorized_operator_keys: BTreeMap<String, VerificationKey>,
}

impl Default for FreshnessConfig {
    fn default() -> Self {
        let mut override_eligible = BTreeSet::new();
        override_eligible.insert(OperationType::ExtensionActivation);

        Self {
            staleness_threshold: 5,
            holdoff_ticks: 10,
            override_eligible,
            authorized_operators: BTreeSet::new(),
            authorized_operator_keys: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// RevocationFreshnessController — main controller
// ---------------------------------------------------------------------------

/// Controls freshness state machine and enforces degraded-mode policy.
#[derive(Debug)]
pub struct RevocationFreshnessController {
    config: FreshnessConfig,
    policy_id: EngineObjectId,
    state: FreshnessState,
    local_head_seq: u64,
    expected_head_seq: u64,
    current_tick: u64,
    /// Tick at which recovery started (for holdoff enforcement).
    recovery_start_tick: Option<u64>,
    /// State change events.
    state_events: Vec<FreshnessStateChangeEvent>,
    /// Decision events.
    decision_events: Vec<DegradedModeDecisionEvent>,
    /// Override tokens already consumed by this controller.
    consumed_override_ids: BTreeSet<EngineObjectId>,
    /// Per-outcome counters.
    outcome_counts: BTreeMap<String, u64>,
    /// Zone for this controller.
    zone: String,
}

impl RevocationFreshnessController {
    /// Create a new controller.
    pub fn new(config: FreshnessConfig, zone: &str) -> Self {
        let mut nonce = [0u8; OVERRIDE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let policy_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            zone,
            &controller_schema_id(),
            &nonce,
        )
        .expect("controller policy id derivation should succeed");
        Self::new_with_policy_id(config, zone, policy_id)
    }

    /// Create a controller with a caller-supplied policy id for deterministic
    /// fixtures and externally identified policy cells.
    pub fn new_with_policy_id(
        config: FreshnessConfig,
        zone: &str,
        policy_id: EngineObjectId,
    ) -> Self {
        Self {
            config,
            policy_id,
            state: FreshnessState::Fresh,
            local_head_seq: 0,
            expected_head_seq: 0,
            current_tick: 0,
            recovery_start_tick: None,
            state_events: Vec::new(),
            decision_events: Vec::new(),
            consumed_override_ids: BTreeSet::new(),
            outcome_counts: BTreeMap::new(),
            zone: zone.to_string(),
        }
    }

    /// Policy/cell id override tokens must target.
    pub fn policy_id(&self) -> &EngineObjectId {
        &self.policy_id
    }

    /// The zone this controller manages.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Current freshness state.
    pub fn state(&self) -> FreshnessState {
        self.state
    }

    /// Whether the system is in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.state == FreshnessState::Degraded
    }

    /// Whether the system is fresh.
    pub fn is_fresh(&self) -> bool {
        self.state == FreshnessState::Fresh
    }

    /// Current staleness gap.
    pub fn staleness_gap(&self) -> u64 {
        self.expected_head_seq.saturating_sub(self.local_head_seq)
    }

    /// Update the current tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Update the local head sequence (e.g. after chain sync).
    pub fn update_local_head(&mut self, seq: u64, trace_id: &str) {
        self.local_head_seq = seq;
        self.reevaluate_state(trace_id);
    }

    /// Update the expected head sequence (e.g. from peer gossip).
    pub fn update_expected_head(&mut self, seq: u64, trace_id: &str) {
        self.expected_head_seq = seq;
        self.reevaluate_state(trace_id);
    }

    /// Check freshness and update state machine.
    pub fn check_freshness(&mut self, trace_id: &str) -> FreshnessState {
        self.reevaluate_state(trace_id);
        self.state
    }

    /// Evaluate whether an operation should proceed.
    pub fn evaluate(
        &mut self,
        operation: OperationType,
        trace_id: &str,
    ) -> Result<FreshnessDecision, DegradedDenial> {
        // Safe operations and health checks always proceed.
        if operation == OperationType::SafeOperation || operation == OperationType::HealthCheck {
            let decision = FreshnessDecision::Proceed;
            self.emit_decision(operation, "safe_proceed", None, None, trace_id);
            return Ok(decision);
        }

        // In fresh state, all operations proceed.
        if self.state == FreshnessState::Fresh {
            let decision = FreshnessDecision::Proceed;
            self.emit_decision(operation, "proceed", None, None, trace_id);
            return Ok(decision);
        }

        // In stale state, allow but warn (not yet degraded).
        if self.state == FreshnessState::Stale {
            let decision = FreshnessDecision::Proceed;
            self.emit_decision(operation, "proceed_stale", None, None, trace_id);
            return Ok(decision);
        }

        // Degraded or Recovering mode — deny revocation-dependent operations.
        let denial = DegradedDenial {
            operation_type: operation,
            local_head_seq: self.local_head_seq,
            expected_head_seq: self.expected_head_seq,
            staleness_gap: self.staleness_gap(),
        };
        self.emit_decision(operation, "denied", None, None, trace_id);
        *self.outcome_counts.entry("denied".to_string()).or_insert(0) += 1;
        Err(denial)
    }

    /// Evaluate an operation with an operator override token.
    pub fn evaluate_with_override(
        &mut self,
        operation: OperationType,
        override_token: &DegradedModeOverride,
        operator_verification_key: &VerificationKey,
        trace_id: &str,
    ) -> Result<FreshnessDecision, OverrideError> {
        // Must be in degraded mode.
        if self.state != FreshnessState::Degraded {
            return Err(OverrideError::NotDegraded {
                current_state: self.state,
            });
        }

        // Check operation type match.
        if override_token.operation_type != operation {
            return Err(OverrideError::OperationMismatch {
                requested: operation,
                override_type: override_token.operation_type,
            });
        }

        if override_token.zone != self.zone {
            return Err(OverrideError::ZoneMismatch {
                controller_zone: self.zone.clone(),
                override_zone: override_token.zone.clone(),
            });
        }

        if override_token.target_policy_id != self.policy_id {
            return Err(OverrideError::PolicyMismatch {
                controller_policy_id: self.policy_id.clone(),
                override_policy_id: override_token.target_policy_id.clone(),
            });
        }

        // Check expiry.
        if override_token.expiry.0 <= self.current_tick {
            return Err(OverrideError::Expired {
                expiry: override_token.expiry,
                current: DeterministicTimestamp(self.current_tick),
            });
        }

        // Check operator authorization.
        if !self
            .config
            .authorized_operators
            .contains(&override_token.operator_id)
        {
            return Err(OverrideError::UnauthorizedOperator {
                operator_id: override_token.operator_id.clone(),
            });
        }
        let Some(authorized_verification_key) = self
            .config
            .authorized_operator_keys
            .get(&override_token.operator_id)
        else {
            return Err(OverrideError::UnauthorizedOperator {
                operator_id: override_token.operator_id.clone(),
            });
        };
        if authorized_verification_key != operator_verification_key {
            return Err(OverrideError::SignatureInvalid {
                detail: "operator verification key does not match authorized operator".to_string(),
            });
        }

        // Check operation is override-eligible.
        if !self.config.override_eligible.contains(&operation) {
            return Err(OverrideError::OperationMismatch {
                requested: operation,
                override_type: override_token.operation_type,
            });
        }

        // Verify signature.
        let preimage = override_token.preimage_bytes();
        verify_signature(
            authorized_verification_key,
            &preimage,
            &override_token.signature,
        )
        .map_err(|e| OverrideError::SignatureInvalid {
            detail: e.to_string(),
        })?;

        if self
            .consumed_override_ids
            .contains(&override_token.override_id)
        {
            return Err(OverrideError::AlreadyConsumed {
                override_id: override_token.override_id.clone(),
            });
        }
        self.consumed_override_ids
            .insert(override_token.override_id.clone());

        // Override granted.
        let decision = FreshnessDecision::OverrideGranted {
            override_id: override_token.override_id.clone(),
            operator_id: override_token.operator_id.clone(),
        };
        self.emit_decision(
            operation,
            "override_granted",
            Some(override_token.override_id.clone()),
            Some(override_token.operator_id.clone()),
            trace_id,
        );
        *self
            .outcome_counts
            .entry("override_granted".to_string())
            .or_insert(0) += 1;
        Ok(decision)
    }

    /// Drain state change events.
    pub fn drain_state_events(&mut self) -> Vec<FreshnessStateChangeEvent> {
        std::mem::take(&mut self.state_events)
    }

    /// Drain decision events.
    pub fn drain_decision_events(&mut self) -> Vec<DegradedModeDecisionEvent> {
        std::mem::take(&mut self.decision_events)
    }

    /// Outcome counts for metrics.
    pub fn outcome_counts(&self) -> &BTreeMap<String, u64> {
        &self.outcome_counts
    }

    /// Access configuration.
    pub fn config(&self) -> &FreshnessConfig {
        &self.config
    }

    // -------------------------------------------------------------------
    // State machine transitions
    // -------------------------------------------------------------------

    fn reevaluate_state(&mut self, trace_id: &str) {
        // Loop until the state stabilizes — a single gap can span multiple
        // state transitions (e.g. Fresh -> Stale -> Degraded).
        loop {
            let gap = self.staleness_gap();
            let old_state = self.state;

            let new_state = match self.state {
                FreshnessState::Fresh => {
                    if gap > 0 {
                        FreshnessState::Stale
                    } else {
                        FreshnessState::Fresh
                    }
                }
                FreshnessState::Stale => {
                    if gap > self.config.staleness_threshold {
                        FreshnessState::Degraded
                    } else if gap == 0 {
                        FreshnessState::Fresh
                    } else {
                        FreshnessState::Stale
                    }
                }
                FreshnessState::Degraded => {
                    if gap <= self.config.staleness_threshold {
                        self.recovery_start_tick = Some(self.current_tick);
                        FreshnessState::Recovering
                    } else {
                        FreshnessState::Degraded
                    }
                }
                FreshnessState::Recovering => {
                    if gap > self.config.staleness_threshold {
                        self.recovery_start_tick = None;
                        FreshnessState::Degraded
                    } else if let Some(start) = self.recovery_start_tick {
                        if self.current_tick >= start + self.config.holdoff_ticks {
                            self.recovery_start_tick = None;
                            FreshnessState::Fresh
                        } else {
                            FreshnessState::Recovering
                        }
                    } else {
                        // No recovery start tick — shouldn't happen, but be safe.
                        self.recovery_start_tick = Some(self.current_tick);
                        FreshnessState::Recovering
                    }
                }
            };

            if new_state == old_state {
                break;
            }

            self.state = new_state;
            self.state_events.push(FreshnessStateChangeEvent {
                from_state: old_state,
                to_state: new_state,
                local_head_seq: self.local_head_seq,
                expected_head_seq: self.expected_head_seq,
                staleness_gap: gap,
                threshold: self.config.staleness_threshold,
                trace_id: trace_id.to_string(),
                timestamp: DeterministicTimestamp(self.current_tick),
            });
        }
    }

    fn emit_decision(
        &mut self,
        operation: OperationType,
        outcome: &str,
        override_id: Option<EngineObjectId>,
        operator_id: Option<String>,
        trace_id: &str,
    ) {
        self.decision_events.push(DegradedModeDecisionEvent {
            operation_type: operation,
            outcome: outcome.to_string(),
            local_head_seq: self.local_head_seq,
            expected_head_seq: self.expected_head_seq,
            override_id,
            operator_id,
            trace_id: trace_id.to_string(),
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ZONE: &str = "test-zone";

    fn operator_key() -> SigningKey {
        SigningKey::from_bytes([
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
            0xBD, 0xBE, 0xBF, 0xC0,
        ])
        .expect("serde deserialization should succeed")
    }

    fn make_config() -> FreshnessConfig {
        let mut authorized = BTreeSet::new();
        authorized.insert("ops-admin-01".to_string());
        let mut authorized_operator_keys = BTreeMap::new();
        authorized_operator_keys.insert(
            "ops-admin-01".to_string(),
            operator_key().verification_key(),
        );

        let mut override_eligible = BTreeSet::new();
        override_eligible.insert(OperationType::ExtensionActivation);
        override_eligible.insert(OperationType::TokenAcceptance);

        FreshnessConfig {
            staleness_threshold: 5,
            holdoff_ticks: 10,
            override_eligible,
            authorized_operators: authorized,
            authorized_operator_keys,
        }
    }

    fn test_policy_id() -> EngineObjectId {
        EngineObjectId([0x61; 32])
    }

    fn other_policy_id() -> EngineObjectId {
        EngineObjectId([0x62; 32])
    }

    fn make_controller() -> RevocationFreshnessController {
        RevocationFreshnessController::new_with_policy_id(
            make_config(),
            TEST_ZONE,
            test_policy_id(),
        )
    }

    fn make_override(operation: OperationType, expiry_tick: u64) -> DegradedModeOverride {
        let sk = operator_key();
        DegradedModeOverride::create(
            operation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(expiry_tick),
            TEST_ZONE,
            &test_policy_id(),
            &sk,
        )
    }

    fn make_override_for_zone(
        operation: OperationType,
        expiry_tick: u64,
        zone: &str,
    ) -> DegradedModeOverride {
        let sk = operator_key();
        DegradedModeOverride::create(
            operation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(expiry_tick),
            zone,
            &test_policy_id(),
            &sk,
        )
    }

    fn unpinned_operator_key() -> SigningKey {
        SigningKey::from_bytes([
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
            0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
            0x4D, 0x4E, 0x4F, 0x50,
        ])
        .expect("serde deserialization should succeed")
    }

    // ---------------------------------------------------------------
    // Initial state
    // ---------------------------------------------------------------

    #[test]
    fn new_controller_starts_fresh() {
        let ctrl = make_controller();
        assert_eq!(ctrl.state(), FreshnessState::Fresh);
        assert!(ctrl.is_fresh());
        assert!(!ctrl.is_degraded());
    }

    // ---------------------------------------------------------------
    // Staleness detection
    // ---------------------------------------------------------------

    #[test]
    fn detects_staleness_when_gap_within_threshold() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(3, "t-stale");
        assert_eq!(ctrl.state(), FreshnessState::Stale);
        assert_eq!(ctrl.staleness_gap(), 3);
    }

    #[test]
    fn detects_degraded_when_gap_exceeds_threshold() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degraded");
        assert_eq!(ctrl.state(), FreshnessState::Degraded);
        assert!(ctrl.is_degraded());
        assert_eq!(ctrl.staleness_gap(), 10);
    }

    #[test]
    fn no_staleness_when_gap_is_zero() {
        let mut ctrl = make_controller();
        ctrl.update_local_head(5, "t-local");
        ctrl.update_expected_head(5, "t-expected");
        assert_eq!(ctrl.state(), FreshnessState::Fresh);
        assert_eq!(ctrl.staleness_gap(), 0);
    }

    // ---------------------------------------------------------------
    // Safe operations always proceed
    // ---------------------------------------------------------------

    #[test]
    fn safe_operations_proceed_in_fresh() {
        let mut ctrl = make_controller();
        let result = ctrl.evaluate(OperationType::SafeOperation, "t-safe");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("serde deserialization should succeed"),
            FreshnessDecision::Proceed
        );
    }

    #[test]
    fn safe_operations_proceed_in_degraded() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");
        assert!(ctrl.is_degraded());

        let result = ctrl.evaluate(OperationType::SafeOperation, "t-safe-deg");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("serde deserialization should succeed"),
            FreshnessDecision::Proceed
        );
    }

    #[test]
    fn health_check_always_proceeds() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        let result = ctrl.evaluate(OperationType::HealthCheck, "t-health");
        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------
    // Revocation-dependent ops denied in degraded mode
    // ---------------------------------------------------------------

    #[test]
    fn token_acceptance_denied_in_degraded() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        let result = ctrl.evaluate(OperationType::TokenAcceptance, "t-token");
        assert!(result.is_err());
        let denial = result.unwrap_err();
        assert_eq!(denial.operation_type, OperationType::TokenAcceptance);
        assert_eq!(denial.local_head_seq, 0);
        assert_eq!(denial.expected_head_seq, 10);
        assert_eq!(denial.staleness_gap, 10);
    }

    #[test]
    fn extension_activation_denied_in_degraded() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        let result = ctrl.evaluate(OperationType::ExtensionActivation, "t-ext");
        assert!(result.is_err());
        let denial = result.unwrap_err();
        assert_eq!(denial.operation_type, OperationType::ExtensionActivation);
    }

    #[test]
    fn high_risk_denied_in_degraded() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        let result = ctrl.evaluate(OperationType::HighRiskOperation, "t-hr");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Operations proceed in fresh state
    // ---------------------------------------------------------------

    #[test]
    fn token_acceptance_proceeds_in_fresh() {
        let mut ctrl = make_controller();
        let result = ctrl.evaluate(OperationType::TokenAcceptance, "t-fresh-token");
        assert!(result.is_ok());
    }

    #[test]
    fn extension_activation_proceeds_in_fresh() {
        let mut ctrl = make_controller();
        let result = ctrl.evaluate(OperationType::ExtensionActivation, "t-fresh-ext");
        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------
    // Override tokens
    // ---------------------------------------------------------------

    #[test]
    fn valid_override_grants_access() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token = make_override(OperationType::ExtensionActivation, 2000);
        let vk = operator_key().verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override",
        );
        assert!(result.is_ok());
        match result.expect("serde deserialization should succeed") {
            FreshnessDecision::OverrideGranted { operator_id, .. } => {
                assert_eq!(operator_id, "ops-admin-01");
            }
            // SAFETY: Test-only panic to validate freshness override evaluation
            // expects specific RevocationFreshnessResult::OverrideGranted from test scenario
            other => panic!("expected OverrideGranted, got {other:?}"),
        }
    }

    #[test]
    fn same_override_token_is_rejected_on_second_use() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token = make_override(OperationType::ExtensionActivation, 2000);
        let vk = operator_key().verification_key();

        ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override-first",
        )
        .expect("first override presentation should be granted");

        let replay = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override-replay",
        );

        assert!(matches!(
            replay,
            Err(OverrideError::AlreadyConsumed { override_id })
                if override_id == override_token.override_id
        ));
    }

    #[test]
    fn override_token_for_other_zone_is_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token =
            make_override_for_zone(OperationType::ExtensionActivation, 2000, "zone-other");
        let vk = operator_key().verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override-zone-replay",
        );

        assert!(matches!(
            result,
            Err(OverrideError::ZoneMismatch {
                controller_zone,
                override_zone,
            }) if controller_zone == TEST_ZONE && override_zone == "zone-other"
        ));
    }

    #[test]
    fn override_token_for_other_policy_is_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let sk = operator_key();
        let override_token = DegradedModeOverride::create(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &other_policy_id(),
            &sk,
        );
        let vk = sk.verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override-policy-replay",
        );

        assert!(matches!(
            result,
            Err(OverrideError::PolicyMismatch {
                controller_policy_id,
                override_policy_id,
            }) if controller_policy_id == test_policy_id() && override_policy_id == other_policy_id()
        ));
    }

    #[test]
    fn authorized_operator_id_signed_by_unpinned_key_is_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let unpinned = unpinned_operator_key();
        let override_token = DegradedModeOverride::create(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "forged authorized operator id",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            &unpinned,
        );

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &unpinned.verification_key(),
            "t-unpinned-key",
        );
        assert!(matches!(
            result,
            Err(OverrideError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn expired_override_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(2000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token = make_override(OperationType::ExtensionActivation, 1000);
        let vk = operator_key().verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-expired",
        );
        assert!(matches!(result, Err(OverrideError::Expired { .. })));
    }

    #[test]
    fn operation_mismatch_override_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token = make_override(OperationType::TokenAcceptance, 2000);
        let vk = operator_key().verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-mismatch",
        );
        assert!(matches!(
            result,
            Err(OverrideError::OperationMismatch { .. })
        ));
    }

    #[test]
    fn unauthorized_operator_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        // Create override with unauthorized operator
        let sk = operator_key();
        let override_token = DegradedModeOverride::create(
            OperationType::ExtensionActivation,
            "unauthorized-user",
            "trying to sneak in",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            &sk,
        );
        let vk = sk.verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-unauth",
        );
        assert!(matches!(
            result,
            Err(OverrideError::UnauthorizedOperator { .. })
        ));
    }

    #[test]
    fn override_rejected_when_not_degraded() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);

        let override_token = make_override(OperationType::ExtensionActivation, 2000);
        let vk = operator_key().verification_key();

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-not-degraded",
        );
        assert!(matches!(result, Err(OverrideError::NotDegraded { .. })));
    }

    #[test]
    fn invalid_signature_override_rejected() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");

        let override_token = make_override(OperationType::ExtensionActivation, 2000);
        let wrong_vk =
            VerificationKey::from_bytes([0xFF; 32]).expect("serde deserialization should succeed");

        let result = ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &wrong_vk,
            "t-bad-sig",
        );
        assert!(matches!(
            result,
            Err(OverrideError::SignatureInvalid { .. })
        ));
    }

    // ---------------------------------------------------------------
    // Recovery
    // ---------------------------------------------------------------

    #[test]
    fn recovery_from_degraded_to_recovering() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");
        assert!(ctrl.is_degraded());

        // Local catches up.
        ctrl.update_local_head(10, "t-recover");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);
    }

    #[test]
    fn recovery_requires_holdoff() {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);
        ctrl.update_expected_head(10, "t-degrade");

        // Catch up.
        ctrl.update_local_head(10, "t-recover");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);

        // Before holdoff expires — still recovering.
        ctrl.set_tick(105);
        ctrl.check_freshness("t-holdoff-check");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);

        // After holdoff expires.
        ctrl.set_tick(110);
        ctrl.check_freshness("t-holdoff-done");
        assert_eq!(ctrl.state(), FreshnessState::Fresh);
    }

    #[test]
    fn re_degradation_during_recovery() {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);
        ctrl.update_expected_head(10, "t-degrade");
        ctrl.update_local_head(10, "t-recover");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);

        // Expected advances again during recovery.
        ctrl.update_expected_head(20, "t-re-degrade");
        assert_eq!(ctrl.state(), FreshnessState::Degraded);
    }

    // ---------------------------------------------------------------
    // Full lifecycle
    // ---------------------------------------------------------------

    #[test]
    fn full_lifecycle_fresh_stale_degraded_recovering_fresh() {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);

        // Start fresh.
        assert_eq!(ctrl.state(), FreshnessState::Fresh);

        // Become stale.
        ctrl.update_expected_head(3, "t-stale");
        assert_eq!(ctrl.state(), FreshnessState::Stale);

        // Exceed threshold -> degraded.
        ctrl.update_expected_head(10, "t-degraded");
        assert_eq!(ctrl.state(), FreshnessState::Degraded);

        // Catch up -> recovering.
        ctrl.update_local_head(10, "t-catchup");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);

        // Holdoff elapses -> fresh.
        ctrl.set_tick(110);
        ctrl.check_freshness("t-fresh-again");
        assert_eq!(ctrl.state(), FreshnessState::Fresh);

        // Verify state events.
        let events = ctrl.drain_state_events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].from_state, FreshnessState::Fresh);
        assert_eq!(events[0].to_state, FreshnessState::Stale);
        assert_eq!(events[1].from_state, FreshnessState::Stale);
        assert_eq!(events[1].to_state, FreshnessState::Degraded);
        assert_eq!(events[2].from_state, FreshnessState::Degraded);
        assert_eq!(events[2].to_state, FreshnessState::Recovering);
        assert_eq!(events[3].from_state, FreshnessState::Recovering);
        assert_eq!(events[3].to_state, FreshnessState::Fresh);
    }

    // ---------------------------------------------------------------
    // Stale state allows operations
    // ---------------------------------------------------------------

    #[test]
    fn stale_state_allows_operations() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(3, "t-stale");
        assert_eq!(ctrl.state(), FreshnessState::Stale);

        // Operations should proceed in stale state (not yet degraded).
        let result = ctrl.evaluate(OperationType::TokenAcceptance, "t-stale-token");
        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------
    // Recovering state denies operations
    // ---------------------------------------------------------------

    #[test]
    fn recovering_state_denies_operations() {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);
        ctrl.update_expected_head(10, "t-degrade");
        ctrl.update_local_head(10, "t-recover");
        assert_eq!(ctrl.state(), FreshnessState::Recovering);

        let result = ctrl.evaluate(OperationType::TokenAcceptance, "t-recover-token");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Audit events
    // ---------------------------------------------------------------

    #[test]
    fn state_change_emits_audit_event() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-audit");

        let events = ctrl.drain_state_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].from_state, FreshnessState::Fresh);
        assert_eq!(events[0].to_state, FreshnessState::Stale);
        assert_eq!(events[1].from_state, FreshnessState::Stale);
        assert_eq!(events[1].to_state, FreshnessState::Degraded);
        assert_eq!(events[1].staleness_gap, 10);
        assert_eq!(events[1].threshold, 5);
        assert_eq!(events[1].trace_id, "t-audit");
    }

    #[test]
    fn decision_emits_audit_event() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");
        ctrl.drain_state_events();

        ctrl.evaluate(OperationType::TokenAcceptance, "t-decision")
            .unwrap_err();

        let events = ctrl.drain_decision_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_type, OperationType::TokenAcceptance);
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].trace_id, "t-decision");
    }

    #[test]
    fn override_emits_audit_event() {
        let mut ctrl = make_controller();
        ctrl.set_tick(1000);
        ctrl.update_expected_head(10, "t-degrade");
        ctrl.drain_decision_events();

        let override_token = make_override(OperationType::ExtensionActivation, 2000);
        let vk = operator_key().verification_key();

        ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &override_token,
            &vk,
            "t-override-audit",
        )
        .expect("serde deserialization should succeed");

        let events = ctrl.drain_decision_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "override_granted");
        assert_eq!(events[0].operator_id, Some("ops-admin-01".to_string()));
        assert!(events[0].override_id.is_some());
    }

    // ---------------------------------------------------------------
    // Outcome counts
    // ---------------------------------------------------------------

    #[test]
    fn outcome_counts_tracked() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        // 3 denials
        for i in 0..3 {
            let _ = ctrl.evaluate(OperationType::TokenAcceptance, &format!("t-deny-{i}"));
        }

        let counts = ctrl.outcome_counts();
        assert_eq!(counts.get("denied"), Some(&3));
    }

    // ---------------------------------------------------------------
    // Serialization round-trips
    // ---------------------------------------------------------------

    #[test]
    fn freshness_state_serialization() {
        let states = [
            FreshnessState::Fresh,
            FreshnessState::Stale,
            FreshnessState::Degraded,
            FreshnessState::Recovering,
        ];
        for s in &states {
            let json = serde_json::to_string(s).expect("serde deserialization should succeed");
            let restored: FreshnessState =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*s, restored);
        }
    }

    #[test]
    fn operation_type_serialization() {
        let ops = [
            OperationType::SafeOperation,
            OperationType::TokenAcceptance,
            OperationType::ExtensionActivation,
            OperationType::HighRiskOperation,
            OperationType::HealthCheck,
        ];
        for o in &ops {
            let json = serde_json::to_string(o).expect("serde deserialization should succeed");
            let restored: OperationType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*o, restored);
        }
    }

    #[test]
    fn degraded_denial_serialization() {
        let denial = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 50,
            expected_head_seq: 60,
            staleness_gap: 10,
        };
        let json = serde_json::to_string(&denial).expect("serde deserialization should succeed");
        let restored: DegradedDenial =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(denial, restored);
    }

    #[test]
    fn override_token_serialization() {
        let token = make_override(OperationType::ExtensionActivation, 2000);
        let json = serde_json::to_string(&token).expect("serde deserialization should succeed");
        let restored: DegradedModeOverride =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(token, restored);
    }

    #[test]
    fn freshness_config_serialization() {
        let config = make_config();
        let json = serde_json::to_string(&config).expect("serde deserialization should succeed");
        let restored: FreshnessConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(config, restored);
    }

    #[test]
    fn state_change_event_serialization() {
        let event = FreshnessStateChangeEvent {
            from_state: FreshnessState::Fresh,
            to_state: FreshnessState::Degraded,
            local_head_seq: 50,
            expected_head_seq: 60,
            staleness_gap: 10,
            threshold: 5,
            trace_id: "t-ser".to_string(),
            timestamp: DeterministicTimestamp(1000),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: FreshnessStateChangeEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    #[test]
    fn decision_event_serialization() {
        let event = DegradedModeDecisionEvent {
            operation_type: OperationType::TokenAcceptance,
            outcome: "denied".to_string(),
            local_head_seq: 50,
            expected_head_seq: 60,
            override_id: None,
            operator_id: None,
            trace_id: "t-ser".to_string(),
            timestamp: DeterministicTimestamp(1000),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: DegradedModeDecisionEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    // ---------------------------------------------------------------
    // Display implementations
    // ---------------------------------------------------------------

    #[test]
    fn freshness_state_display() {
        assert_eq!(FreshnessState::Fresh.to_string(), "fresh");
        assert_eq!(FreshnessState::Stale.to_string(), "stale");
        assert_eq!(FreshnessState::Degraded.to_string(), "degraded");
        assert_eq!(FreshnessState::Recovering.to_string(), "recovering");
    }

    #[test]
    fn operation_type_display() {
        assert_eq!(OperationType::SafeOperation.to_string(), "safe_operation");
        assert_eq!(
            OperationType::TokenAcceptance.to_string(),
            "token_acceptance"
        );
        assert_eq!(
            OperationType::ExtensionActivation.to_string(),
            "extension_activation"
        );
        assert_eq!(
            OperationType::HighRiskOperation.to_string(),
            "high_risk_operation"
        );
        assert_eq!(OperationType::HealthCheck.to_string(), "health_check");
    }

    #[test]
    fn degraded_denial_display() {
        let denial = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 50,
            expected_head_seq: 60,
            staleness_gap: 10,
        };
        let display = denial.to_string();
        assert!(display.contains("token_acceptance"));
        assert!(display.contains("50"));
        assert!(display.contains("60"));
    }

    #[test]
    fn override_error_display() {
        let err = OverrideError::Expired {
            expiry: DeterministicTimestamp(1000),
            current: DeterministicTimestamp(2000),
        };
        assert!(err.to_string().contains("expired"));

        let err2 = OverrideError::UnauthorizedOperator {
            operator_id: "bad-actor".to_string(),
        };
        assert!(err2.to_string().contains("bad-actor"));
    }

    // ---------------------------------------------------------------
    // Determinism
    // ---------------------------------------------------------------

    #[test]
    fn freshness_controller_is_deterministic() {
        let run = || {
            let mut ctrl = make_controller();
            ctrl.set_tick(100);
            ctrl.update_expected_head(10, "t-det");
            let r1 = ctrl.evaluate(OperationType::TokenAcceptance, "t-det-1");
            ctrl.update_local_head(10, "t-det-recover");
            ctrl.set_tick(110);
            ctrl.check_freshness("t-det-fresh");
            let r2 = ctrl.evaluate(OperationType::TokenAcceptance, "t-det-2");
            let events = ctrl.drain_state_events();
            (r1, r2, events)
        };

        let (r1a, r2a, events_a) = run();
        let (r1b, r2b, events_b) = run();

        assert_eq!(format!("{r1a:?}"), format!("{r1b:?}"));
        assert_eq!(r2a, r2b);
        assert_eq!(events_a, events_b);
    }

    // ---------------------------------------------------------------
    // Override token nonce binding
    // ---------------------------------------------------------------

    #[test]
    fn override_token_signature_binds_nonce() {
        let t1 = make_override(OperationType::ExtensionActivation, 2000);
        let t2 = make_override(OperationType::ExtensionActivation, 2000);
        assert_ne!(t1.nonce, t2.nonce);
        assert_ne!(t1.signature, t2.signature);
        assert_ne!(t1.override_id, t2.override_id);
    }

    #[test]
    fn override_token_signature_is_deterministic_with_fixed_nonce() {
        let sk = operator_key();
        let nonce = [0xD4; OVERRIDE_NONCE_LEN];
        let t1 = DegradedModeOverride::create_with_nonce(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            nonce,
            &sk,
        );
        let t2 = DegradedModeOverride::create_with_nonce(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            nonce,
            &sk,
        );
        assert_eq!(t1.signature, t2.signature);
        assert_eq!(t1.override_id, t2.override_id);
    }

    // ---------------------------------------------------------------
    // Override error serialization
    // ---------------------------------------------------------------

    #[test]
    fn override_error_serialization() {
        let errors: Vec<OverrideError> = vec![
            OverrideError::Expired {
                expiry: DeterministicTimestamp(1000),
                current: DeterministicTimestamp(2000),
            },
            OverrideError::OperationMismatch {
                requested: OperationType::TokenAcceptance,
                override_type: OperationType::ExtensionActivation,
            },
            OverrideError::SignatureInvalid {
                detail: "bad sig".to_string(),
            },
            OverrideError::UnauthorizedOperator {
                operator_id: "intruder".to_string(),
            },
            OverrideError::AlreadyConsumed {
                override_id: EngineObjectId([9; 32]),
            },
            OverrideError::ZoneMismatch {
                controller_zone: "zone-a".to_string(),
                override_zone: "zone-b".to_string(),
            },
            OverrideError::PolicyMismatch {
                controller_policy_id: EngineObjectId([10; 32]),
                override_policy_id: EngineObjectId([11; 32]),
            },
            OverrideError::NotDegraded {
                current_state: FreshnessState::Fresh,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: OverrideError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    // ---------------------------------------------------------------
    // Stale -> Fresh (gap closes without degraded)
    // ---------------------------------------------------------------

    #[test]
    fn stale_to_fresh_on_catchup() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(3, "t-stale");
        assert_eq!(ctrl.state(), FreshnessState::Stale);

        ctrl.update_local_head(3, "t-catchup");
        assert_eq!(ctrl.state(), FreshnessState::Fresh);
    }

    // ---------------------------------------------------------------
    // Default config
    // ---------------------------------------------------------------

    #[test]
    fn default_config() {
        let config = FreshnessConfig::default();
        assert_eq!(config.staleness_threshold, 5);
        assert_eq!(config.holdoff_ticks, 10);
        assert!(config
            .override_eligible
            .contains(&OperationType::ExtensionActivation));
        assert!(config.authorized_operators.is_empty());
        assert!(config.authorized_operator_keys.is_empty());
    }

    // ---------------------------------------------------------------
    // FreshnessDecision equality
    // ---------------------------------------------------------------

    #[test]
    fn freshness_decision_serialization() {
        let decisions = vec![
            FreshnessDecision::Proceed,
            FreshnessDecision::Denied(DegradedDenial {
                operation_type: OperationType::TokenAcceptance,
                local_head_seq: 50,
                expected_head_seq: 60,
                staleness_gap: 10,
            }),
            FreshnessDecision::OverrideGranted {
                override_id: EngineObjectId([1; 32]),
                operator_id: "ops-admin-01".to_string(),
            },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).expect("serde deserialization should succeed");
            let restored: FreshnessDecision =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*d, restored);
        }
    }

    // ---------------------------------------------------------------
    // Override preimage determinism
    // ---------------------------------------------------------------

    // -- Enrichment: Ord --

    #[test]
    fn freshness_state_ordering() {
        assert!(FreshnessState::Fresh < FreshnessState::Stale);
        assert!(FreshnessState::Stale < FreshnessState::Degraded);
        assert!(FreshnessState::Degraded < FreshnessState::Recovering);
    }

    #[test]
    fn operation_type_ordering() {
        assert!(OperationType::SafeOperation < OperationType::TokenAcceptance);
        assert!(OperationType::TokenAcceptance < OperationType::ExtensionActivation);
        assert!(OperationType::ExtensionActivation < OperationType::HighRiskOperation);
        assert!(OperationType::HighRiskOperation < OperationType::HealthCheck);
    }

    #[test]
    fn override_preimage_is_deterministic() {
        let sk = operator_key();
        let nonce = [0xAB; OVERRIDE_NONCE_LEN];
        let t1 = DegradedModeOverride::create_with_nonce(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            nonce,
            &sk,
        );
        let t2 = DegradedModeOverride::create_with_nonce(
            OperationType::ExtensionActivation,
            "ops-admin-01",
            "emergency deploy",
            DeterministicTimestamp(2000),
            TEST_ZONE,
            &test_policy_id(),
            nonce,
            &sk,
        );
        assert_eq!(t1.preimage_bytes(), t2.preimage_bytes());
    }

    // ---------------------------------------------------------------
    // Enrichment: Display uniqueness via BTreeSet
    // ---------------------------------------------------------------

    #[test]
    fn freshness_state_display_uniqueness() {
        let displays: BTreeSet<String> = [
            FreshnessState::Fresh,
            FreshnessState::Stale,
            FreshnessState::Degraded,
            FreshnessState::Recovering,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn operation_type_display_uniqueness() {
        let displays: BTreeSet<String> = [
            OperationType::SafeOperation,
            OperationType::TokenAcceptance,
            OperationType::ExtensionActivation,
            OperationType::HighRiskOperation,
            OperationType::HealthCheck,
        ]
        .iter()
        .map(|o| o.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // ---------------------------------------------------------------
    // Enrichment: std::error::Error impls
    // ---------------------------------------------------------------

    #[test]
    fn degraded_denial_implements_std_error() {
        let denial = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 0,
            expected_head_seq: 10,
            staleness_gap: 10,
        };
        let err: Box<dyn std::error::Error> = Box::new(denial);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn override_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(OverrideError::Expired {
            expiry: DeterministicTimestamp(1000),
            current: DeterministicTimestamp(2000),
        });
        assert!(!err.to_string().is_empty());
    }

    // ---------------------------------------------------------------
    // Enrichment: default FreshnessState
    // ---------------------------------------------------------------

    #[test]
    fn freshness_state_default_is_fresh() {
        assert_eq!(FreshnessState::default(), FreshnessState::Fresh);
    }

    // ---------------------------------------------------------------
    // Enrichment: override schema id determinism
    // ---------------------------------------------------------------

    #[test]
    fn override_schema_id_is_deterministic() {
        let id1 = override_schema_id();
        let id2 = override_schema_id();
        assert_eq!(id1, id2);
    }

    // ---------------------------------------------------------------
    // Enrichment: outcome count accumulation across types
    // ---------------------------------------------------------------

    #[test]
    fn outcome_counts_track_multiple_denied_types() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");

        // Generate denials for different operation types in degraded mode.
        let _ = ctrl.evaluate(OperationType::TokenAcceptance, "t-deny-ta");
        let _ = ctrl.evaluate(OperationType::ExtensionActivation, "t-deny-ea");
        let _ = ctrl.evaluate(OperationType::HighRiskOperation, "t-deny-hr");

        let counts = ctrl.outcome_counts();
        assert_eq!(counts.get("denied"), Some(&3));
    }

    // ---------------------------------------------------------------
    // Enrichment: double drain empties events
    // ---------------------------------------------------------------

    #[test]
    fn drain_state_events_idempotent() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-drain");
        let first = ctrl.drain_state_events();
        assert!(!first.is_empty());
        let second = ctrl.drain_state_events();
        assert!(second.is_empty());
    }

    #[test]
    fn drain_decision_events_idempotent() {
        let mut ctrl = make_controller();
        ctrl.update_expected_head(10, "t-degrade");
        let _ = ctrl.evaluate(OperationType::TokenAcceptance, "t-dec");
        let first = ctrl.drain_decision_events();
        assert!(!first.is_empty());
        let second = ctrl.drain_decision_events();
        assert!(second.is_empty());
    }

    // ── Enrichment: Copy/Clone/Debug/Serde/Hash/Display/Edge ──

    #[test]
    fn freshness_state_copy_semantics() {
        let a = FreshnessState::Fresh;
        let b = a;
        assert_eq!(a, b);
        let c = FreshnessState::Degraded;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn operation_type_copy_semantics() {
        let a = OperationType::SafeOperation;
        let b = a;
        assert_eq!(a, b);
        let c = OperationType::HighRiskOperation;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn freshness_state_debug_distinct() {
        let variants = [
            FreshnessState::Fresh,
            FreshnessState::Stale,
            FreshnessState::Degraded,
            FreshnessState::Recovering,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn operation_type_debug_distinct() {
        let variants = [
            OperationType::SafeOperation,
            OperationType::TokenAcceptance,
            OperationType::ExtensionActivation,
            OperationType::HighRiskOperation,
            OperationType::HealthCheck,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn override_error_debug_distinct() {
        let variants: Vec<OverrideError> = vec![
            OverrideError::Expired {
                expiry: DeterministicTimestamp(1),
                current: DeterministicTimestamp(2),
            },
            OverrideError::OperationMismatch {
                requested: OperationType::TokenAcceptance,
                override_type: OperationType::HealthCheck,
            },
            OverrideError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            OverrideError::UnauthorizedOperator {
                operator_id: "op".to_string(),
            },
            OverrideError::AlreadyConsumed {
                override_id: EngineObjectId([3; 32]),
            },
            OverrideError::ZoneMismatch {
                controller_zone: "controller".to_string(),
                override_zone: "token".to_string(),
            },
            OverrideError::PolicyMismatch {
                controller_policy_id: EngineObjectId([5; 32]),
                override_policy_id: EngineObjectId([6; 32]),
            },
            OverrideError::NotDegraded {
                current_state: FreshnessState::Fresh,
            },
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn freshness_state_serde_variant_distinct() {
        let variants = [
            FreshnessState::Fresh,
            FreshnessState::Stale,
            FreshnessState::Degraded,
            FreshnessState::Recovering,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn operation_type_serde_variant_distinct() {
        let variants = [
            OperationType::SafeOperation,
            OperationType::TokenAcceptance,
            OperationType::ExtensionActivation,
            OperationType::HighRiskOperation,
            OperationType::HealthCheck,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn override_error_serde_variant_distinct() {
        let variants: Vec<OverrideError> = vec![
            OverrideError::Expired {
                expiry: DeterministicTimestamp(0),
                current: DeterministicTimestamp(0),
            },
            OverrideError::OperationMismatch {
                requested: OperationType::SafeOperation,
                override_type: OperationType::SafeOperation,
            },
            OverrideError::SignatureInvalid {
                detail: "x".to_string(),
            },
            OverrideError::UnauthorizedOperator {
                operator_id: "x".to_string(),
            },
            OverrideError::AlreadyConsumed {
                override_id: EngineObjectId([4; 32]),
            },
            OverrideError::ZoneMismatch {
                controller_zone: "a".to_string(),
                override_zone: "b".to_string(),
            },
            OverrideError::PolicyMismatch {
                controller_policy_id: EngineObjectId([5; 32]),
                override_policy_id: EngineObjectId([6; 32]),
            },
            OverrideError::NotDegraded {
                current_state: FreshnessState::Fresh,
            },
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn degraded_denial_clone_independence() {
        let a = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 5,
            expected_head_seq: 15,
            staleness_gap: 10,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn override_error_clone_independence() {
        let a = OverrideError::SignatureInvalid {
            detail: "bad sig".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_config_clone_independence() {
        let a = FreshnessConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_state_change_event_clone_independence() {
        let a = FreshnessStateChangeEvent {
            from_state: FreshnessState::Fresh,
            to_state: FreshnessState::Stale,
            local_head_seq: 0,
            expected_head_seq: 10,
            staleness_gap: 10,
            threshold: 5,
            trace_id: "t".to_string(),
            timestamp: DeterministicTimestamp(100),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn degraded_denial_json_field_names() {
        let d = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 0,
            expected_head_seq: 5,
            staleness_gap: 5,
        };
        let json = serde_json::to_string(&d).expect("serde deserialization should succeed");
        assert!(json.contains("\"operation_type\""));
        assert!(json.contains("\"local_head_seq\""));
        assert!(json.contains("\"expected_head_seq\""));
        assert!(json.contains("\"staleness_gap\""));
    }

    #[test]
    fn freshness_config_json_field_names() {
        let c = FreshnessConfig::default();
        let json = serde_json::to_string(&c).expect("serde deserialization should succeed");
        assert!(json.contains("\"staleness_threshold\""));
        assert!(json.contains("\"holdoff_ticks\""));
        assert!(json.contains("\"override_eligible\""));
        assert!(json.contains("\"authorized_operators\""));
        assert!(json.contains("\"authorized_operator_keys\""));
    }

    #[test]
    fn freshness_state_change_event_json_field_names() {
        let e = FreshnessStateChangeEvent {
            from_state: FreshnessState::Fresh,
            to_state: FreshnessState::Stale,
            local_head_seq: 0,
            expected_head_seq: 10,
            staleness_gap: 10,
            threshold: 5,
            trace_id: "t".to_string(),
            timestamp: DeterministicTimestamp(0),
        };
        let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
        assert!(json.contains("\"from_state\""));
        assert!(json.contains("\"to_state\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn degraded_denial_display_exact() {
        let d = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 3,
            expected_head_seq: 10,
            staleness_gap: 7,
        };
        assert_eq!(
            d.to_string(),
            "degraded mode denial: token_acceptance denied, local_seq=3, expected_seq=10, gap=7"
        );
    }

    #[test]
    fn override_error_display_expired() {
        let e = OverrideError::Expired {
            expiry: DeterministicTimestamp(100),
            current: DeterministicTimestamp(200),
        };
        assert_eq!(e.to_string(), "override expired: expiry=100, current=200");
    }

    #[test]
    fn override_error_display_operation_mismatch() {
        let e = OverrideError::OperationMismatch {
            requested: OperationType::TokenAcceptance,
            override_type: OperationType::ExtensionActivation,
        };
        assert_eq!(
            e.to_string(),
            "operation mismatch: requested=token_acceptance, override=extension_activation"
        );
    }

    #[test]
    fn override_error_display_signature_invalid() {
        let e = OverrideError::SignatureInvalid {
            detail: "bad hash".to_string(),
        };
        assert_eq!(e.to_string(), "signature invalid: bad hash");
    }

    #[test]
    fn override_error_display_unauthorized() {
        let e = OverrideError::UnauthorizedOperator {
            operator_id: "alice".to_string(),
        };
        assert_eq!(e.to_string(), "unauthorized operator: alice");
    }

    #[test]
    fn override_error_display_already_consumed() {
        let override_id = EngineObjectId([7; 32]);
        let e = OverrideError::AlreadyConsumed {
            override_id: override_id.clone(),
        };
        assert_eq!(
            e.to_string(),
            format!("override already consumed: {override_id}")
        );
    }

    #[test]
    fn override_error_display_zone_mismatch() {
        let e = OverrideError::ZoneMismatch {
            controller_zone: "zone-a".to_string(),
            override_zone: "zone-b".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "override zone mismatch: controller=zone-a, override=zone-b"
        );
    }

    #[test]
    fn override_error_display_policy_mismatch() {
        let controller_policy_id = EngineObjectId([0x11; 32]);
        let override_policy_id = EngineObjectId([0x22; 32]);
        let e = OverrideError::PolicyMismatch {
            controller_policy_id: controller_policy_id.clone(),
            override_policy_id: override_policy_id.clone(),
        };
        assert_eq!(
            e.to_string(),
            format!(
                "override policy mismatch: controller={controller_policy_id}, override={override_policy_id}"
            )
        );
    }

    #[test]
    fn override_error_display_not_degraded() {
        let e = OverrideError::NotDegraded {
            current_state: FreshnessState::Fresh,
        };
        assert_eq!(e.to_string(), "not in degraded mode: state=fresh");
    }

    #[test]
    fn freshness_state_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = FreshnessState::Degraded;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn operation_type_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = OperationType::HighRiskOperation;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn freshness_state_serde_roundtrip() {
        for state in [
            FreshnessState::Fresh,
            FreshnessState::Stale,
            FreshnessState::Degraded,
            FreshnessState::Recovering,
        ] {
            let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
            let back: FreshnessState =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(state, back);
        }
    }

    #[test]
    fn freshness_config_serde_roundtrip() {
        let c = FreshnessConfig::default();
        let json = serde_json::to_string(&c).expect("serde deserialization should succeed");
        let back: FreshnessConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(c, back);
    }

    #[test]
    fn override_error_serde_roundtrip() {
        let e = OverrideError::Expired {
            expiry: DeterministicTimestamp(100),
            current: DeterministicTimestamp(200),
        };
        let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
        let back: OverrideError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(e, back);
    }

    #[test]
    fn debug_nonempty_freshness_state() {
        assert!(!format!("{:?}", FreshnessState::Fresh).is_empty());
    }

    #[test]
    fn debug_nonempty_operation_type() {
        assert!(!format!("{:?}", OperationType::SafeOperation).is_empty());
    }

    #[test]
    fn debug_nonempty_degraded_denial() {
        let d = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 0,
            expected_head_seq: 5,
            staleness_gap: 5,
        };
        assert!(!format!("{d:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_override_error() {
        let e = OverrideError::SignatureInvalid {
            detail: "x".to_string(),
        };
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_freshness_config() {
        assert!(!format!("{:?}", FreshnessConfig::default()).is_empty());
    }

    #[test]
    fn debug_nonempty_controller() {
        let ctrl = make_controller();
        assert!(!format!("{ctrl:?}").is_empty());
    }

    #[test]
    fn freshness_state_default_variant_is_fresh() {
        assert_eq!(FreshnessState::default(), FreshnessState::Fresh);
    }

    #[test]
    fn freshness_state_display_exact() {
        assert_eq!(FreshnessState::Fresh.to_string(), "fresh");
        assert_eq!(FreshnessState::Stale.to_string(), "stale");
        assert_eq!(FreshnessState::Degraded.to_string(), "degraded");
        assert_eq!(FreshnessState::Recovering.to_string(), "recovering");
    }

    #[test]
    fn operation_type_display_exact() {
        assert_eq!(OperationType::SafeOperation.to_string(), "safe_operation");
        assert_eq!(
            OperationType::TokenAcceptance.to_string(),
            "token_acceptance"
        );
        assert_eq!(
            OperationType::ExtensionActivation.to_string(),
            "extension_activation"
        );
        assert_eq!(
            OperationType::HighRiskOperation.to_string(),
            "high_risk_operation"
        );
        assert_eq!(OperationType::HealthCheck.to_string(), "health_check");
    }

    #[test]
    fn freshness_state_ord_ordering() {
        assert!(FreshnessState::Fresh < FreshnessState::Stale);
        assert!(FreshnessState::Stale < FreshnessState::Degraded);
        assert!(FreshnessState::Degraded < FreshnessState::Recovering);
    }

    #[test]
    fn operation_type_ord_ordering() {
        assert!(OperationType::SafeOperation < OperationType::TokenAcceptance);
    }

    #[test]
    fn degraded_denial_std_error_source_none() {
        let d = DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 0,
            expected_head_seq: 5,
            staleness_gap: 5,
        };
        let e: &dyn std::error::Error = &d;
        assert!(e.source().is_none());
    }

    #[test]
    fn override_error_std_error_source_none() {
        let e: &dyn std::error::Error = &OverrideError::NotDegraded {
            current_state: FreshnessState::Fresh,
        };
        assert!(e.source().is_none());
    }

    #[test]
    fn controller_zone_accessor() {
        let ctrl = make_controller();
        assert_eq!(ctrl.zone(), "test-zone");
    }

    #[test]
    fn controller_is_fresh_initially() {
        let ctrl = make_controller();
        assert!(ctrl.is_fresh());
        assert!(!ctrl.is_degraded());
    }

    #[test]
    fn controller_staleness_gap_zero_initially() {
        let ctrl = make_controller();
        assert_eq!(ctrl.staleness_gap(), 0);
    }

    #[test]
    fn freshness_config_default_staleness_threshold() {
        let c = FreshnessConfig::default();
        assert_eq!(c.staleness_threshold, 5);
        assert_eq!(c.holdoff_ticks, 10);
        assert!(c
            .override_eligible
            .contains(&OperationType::ExtensionActivation));
    }
}
