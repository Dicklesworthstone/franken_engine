//! Measured attestation handshake between execution cells and the policy plane.
//!
//! Implements the mutual trust establishment protocol:
//! 1. Policy plane sends `AttestationChallenge` with nonce and approved measurements.
//! 2. Cell responds with `AttestationResponse` carrying attestation quote + key binding.
//! 3. Policy plane verifies and issues `CellAuthorization` for security-critical ops.
//! 4. Cell verifies policy plane's signing authority before accepting.
//!
//! Supports periodic and event-triggered re-attestation with graceful degradation.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 10, 9H.4, 9I.1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::attested_execution_cell::{
    AttestationQuote, CellFunction, MeasurementDigest, TrustLevel, TrustRootBackend,
};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

const HANDSHAKE_SCHEMA_DEF: &[u8] = b"AttestationHandshake.v1";

fn handshake_schema_id() -> SchemaId {
    SchemaId::from_definition(HANDSHAKE_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// AttestationChallenge — policy plane → cell
// ---------------------------------------------------------------------------

/// Challenge sent from the policy plane to an execution cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationChallenge {
    /// Unique challenge identifier.
    pub challenge_id: EngineObjectId,
    /// Random nonce for freshness.
    pub nonce: [u8; 32],
    /// Set of approved measurement composite hashes.
    pub approved_measurements: BTreeSet<ContentHash>,
    /// Policy version at challenge time.
    pub policy_version: u64,
    /// Timestamp when the challenge was issued (nanoseconds).
    pub challenge_timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Validity window for the response (nanoseconds from issuance).
    pub response_deadline_ns: u64,
    /// Policy plane signature over the challenge.
    pub policy_plane_signature: Vec<u8>,
}

impl AttestationChallenge {
    /// Whether the challenge is still valid at the given time.
    pub fn is_valid_at(&self, current_ns: u64) -> bool {
        current_ns >= self.challenge_timestamp_ns
            && current_ns
                <= self
                    .challenge_timestamp_ns
                    .saturating_add(self.response_deadline_ns)
    }

    /// Canonical bytes for signing/verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.policy_version.to_be_bytes());
        buf.extend_from_slice(&self.challenge_timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.response_deadline_ns.to_be_bytes());
        for m in &self.approved_measurements {
            buf.extend_from_slice(m.as_bytes());
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// AttestationResponse — cell → policy plane
// ---------------------------------------------------------------------------

/// Response from a cell to an attestation challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Cell identifier.
    pub cell_id: String,
    /// The attestation quote from the cell's trust root.
    pub attestation_quote: AttestationQuote,
    /// Public key of the cell's signing key (bound to measurement).
    pub signer_public_key: Vec<u8>,
    /// Proof that the signing key is bound to the attested measurement.
    /// (In software mode: hash of key || measurement.)
    pub key_binding_proof: Vec<u8>,
    /// Capabilities the cell claims.
    pub claimed_capabilities: BTreeSet<String>,
    /// Timestamp of the response (nanoseconds).
    pub response_timestamp_ns: u64,
    /// Cell's function type.
    pub cell_function: CellFunction,
    /// Response signature (signed by cell's key).
    pub response_signature: Vec<u8>,
}

impl AttestationResponse {
    /// Canonical bytes for verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.cell_id.as_bytes());
        append_attestation_quote_canonical_bytes(&mut buf, &self.attestation_quote);
        buf.extend_from_slice(&self.signer_public_key);
        buf.extend_from_slice(&self.key_binding_proof);
        for cap in &self.claimed_capabilities {
            buf.extend_from_slice(cap.as_bytes());
        }
        buf.extend_from_slice(&self.response_timestamp_ns.to_be_bytes());
        buf.push(self.cell_function as u8);
        buf
    }
}

fn append_attestation_quote_canonical_bytes(buf: &mut Vec<u8>, quote: &AttestationQuote) {
    buf.extend_from_slice(&quote.measurement.canonical_bytes());
    buf.extend_from_slice(&quote.nonce);
    buf.extend_from_slice(&quote.issued_at_ns.to_be_bytes());
    buf.extend_from_slice(&quote.validity_window_ns.to_be_bytes());
    buf.push(quote.trust_level as u8);
    buf.push(quote.platform as u8);
    buf.extend_from_slice(&quote.signature_bytes);
    buf.extend_from_slice(quote.signer_key_id.as_bytes());
}

// ---------------------------------------------------------------------------
// CellAuthorization — policy plane → cell (on success)
// ---------------------------------------------------------------------------

/// Authorization issued by the policy plane to an attested cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellAuthorization {
    /// Authorization identifier.
    pub authorization_id: EngineObjectId,
    /// Cell this authorization is for.
    pub cell_id: String,
    /// Operations this cell is authorized to perform.
    pub authorized_operations: BTreeSet<String>,
    /// Security epoch of this authorization.
    pub epoch: SecurityEpoch,
    /// Timestamp when authorization was issued (nanoseconds).
    pub issued_at_ns: u64,
    /// How long this authorization is valid (nanoseconds).
    pub validity_window_ns: u64,
    /// Policy version that granted this authorization.
    pub policy_version: u64,
    /// Measurement hash that was verified.
    pub verified_measurement: ContentHash,
    /// Policy plane signature.
    pub authorization_signature: Vec<u8>,
}

impl CellAuthorization {
    /// Whether this authorization is still valid at the given time.
    pub fn is_valid_at(&self, current_ns: u64) -> bool {
        current_ns >= self.issued_at_ns
            && current_ns <= self.issued_at_ns.saturating_add(self.validity_window_ns)
    }

    /// Whether this authorization covers a specific operation.
    pub fn authorizes(&self, operation: &str) -> bool {
        self.authorized_operations.contains(operation)
    }

    /// Canonical bytes for verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.cell_id.as_bytes());
        buf.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        buf.extend_from_slice(&self.validity_window_ns.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.policy_version.to_be_bytes());
        buf.extend_from_slice(self.verified_measurement.as_bytes());
        for op in &self.authorized_operations {
            buf.extend_from_slice(op.as_bytes());
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// HandshakeError — handshake protocol errors
// ---------------------------------------------------------------------------

/// Errors from the attestation handshake protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeError {
    /// Challenge has expired.
    ChallengeExpired {
        challenge_timestamp_ns: u64,
        deadline_ns: u64,
        current_ns: u64,
    },
    /// Challenge signature invalid.
    ChallengeSignatureInvalid,
    /// Cell measurement not in approved set.
    MeasurementNotApproved { measurement_hash: ContentHash },
    /// Attestation quote verification failed.
    QuoteVerificationFailed { result: String },
    /// Nonce mismatch between challenge and response.
    NonceMismatch,
    /// Key binding proof invalid.
    KeyBindingInvalid,
    /// Response signature invalid.
    ResponseSignatureInvalid,
    /// Authorization expired.
    AuthorizationExpired {
        issued_at_ns: u64,
        validity_window_ns: u64,
        current_ns: u64,
    },
    /// Authorization signature invalid.
    AuthorizationSignatureInvalid,
    /// Operation not authorized.
    OperationNotAuthorized { operation: String },
    /// Cell not found.
    CellNotFound { cell_id: String },
    /// Re-attestation required.
    ReattestationRequired { reason: String },
    /// ID derivation failed.
    IdDerivation(String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChallengeExpired {
                current_ns,
                deadline_ns,
                ..
            } => {
                write!(
                    f,
                    "challenge expired (current: {current_ns}, deadline: {deadline_ns})"
                )
            }
            Self::ChallengeSignatureInvalid => f.write_str("challenge signature invalid"),
            Self::MeasurementNotApproved { measurement_hash } => {
                write!(f, "measurement not approved: {measurement_hash}")
            }
            Self::QuoteVerificationFailed { result } => {
                write!(f, "quote verification failed: {result}")
            }
            Self::NonceMismatch => f.write_str("nonce mismatch"),
            Self::KeyBindingInvalid => f.write_str("key binding proof invalid"),
            Self::ResponseSignatureInvalid => f.write_str("response signature invalid"),
            Self::AuthorizationExpired { current_ns, .. } => {
                write!(f, "authorization expired at {current_ns}")
            }
            Self::AuthorizationSignatureInvalid => f.write_str("authorization signature invalid"),
            Self::OperationNotAuthorized { operation } => {
                write!(f, "operation not authorized: {operation}")
            }
            Self::CellNotFound { cell_id } => write!(f, "cell not found: {cell_id}"),
            Self::ReattestationRequired { reason } => {
                write!(f, "re-attestation required: {reason}")
            }
            Self::IdDerivation(msg) => write!(f, "id derivation: {msg}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

// ---------------------------------------------------------------------------
// HandshakeOutcome — success/failure result for audit
// ---------------------------------------------------------------------------

/// Outcome of a handshake attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeOutcome {
    /// Handshake succeeded; authorization issued.
    Authorized,
    /// Challenge expired before response.
    ChallengeTimeout,
    /// Measurement not in approved set.
    MeasurementRejected,
    /// Quote verification failed.
    QuoteFailed,
    /// Key binding invalid.
    KeyBindingFailed,
    /// Signature verification failed.
    SignatureFailed,
}

impl fmt::Display for HandshakeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized => f.write_str("authorized"),
            Self::ChallengeTimeout => f.write_str("challenge-timeout"),
            Self::MeasurementRejected => f.write_str("measurement-rejected"),
            Self::QuoteFailed => f.write_str("quote-failed"),
            Self::KeyBindingFailed => f.write_str("key-binding-failed"),
            Self::SignatureFailed => f.write_str("signature-failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// HandshakeEvent — audit event
// ---------------------------------------------------------------------------

/// Audit event for handshake operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Cell identifier.
    pub cell_id: String,
    /// Handshake outcome.
    pub outcome: HandshakeOutcome,
    /// Measurement digest hash (if available).
    pub measurement_hash: Option<ContentHash>,
    /// Policy version at handshake time.
    pub policy_version: u64,
    /// Attestation trust level.
    pub trust_level: Option<TrustLevel>,
    /// Failure reason (if not authorized).
    pub failure_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// ReattestationTrigger — why re-attestation was triggered
// ---------------------------------------------------------------------------

/// Trigger for re-attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReattestationTrigger {
    /// Periodic timer expired.
    Periodic,
    /// Policy version changed.
    PolicyChange,
    /// Security epoch transitioned.
    EpochTransition,
    /// Trust root was updated or revoked.
    TrustRootUpdate,
    /// Operator-initiated.
    Manual,
}

impl fmt::Display for ReattestationTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Periodic => f.write_str("periodic"),
            Self::PolicyChange => f.write_str("policy-change"),
            Self::EpochTransition => f.write_str("epoch-transition"),
            Self::TrustRootUpdate => f.write_str("trust-root-update"),
            Self::Manual => f.write_str("manual"),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyPlaneVerifier — verifies attestation responses
// ---------------------------------------------------------------------------

/// The policy plane's attestation verifier.
///
/// Verifies cell responses, issues authorizations, and tracks
/// attested cells.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPlaneVerifier {
    /// Approved measurements (content hashes of acceptable code/config).
    approved_measurements: BTreeSet<ContentHash>,
    /// Current policy version.
    policy_version: u64,
    /// Default validity window for authorizations (nanoseconds).
    default_authorization_window_ns: u64,
    /// Default re-attestation interval (nanoseconds).
    reattestation_interval_ns: u64,
    /// Currently active authorizations.
    active_authorizations: BTreeMap<String, CellAuthorization>,
    /// Secret key bytes for signing challenges/authorizations.
    signing_key: [u8; 32],
    /// Audit events.
    events: Vec<HandshakeEvent>,
    /// Next event sequence number.
    next_seq: u64,
    /// Security epoch.
    epoch: SecurityEpoch,
    /// Zone for ID derivation.
    zone: String,
}

impl PolicyPlaneVerifier {
    /// Create a new policy plane verifier.
    pub fn new(
        signing_key: [u8; 32],
        policy_version: u64,
        epoch: SecurityEpoch,
        zone: &str,
    ) -> Self {
        Self {
            approved_measurements: BTreeSet::new(),
            policy_version,
            default_authorization_window_ns: 300_000_000_000, // 5 minutes
            reattestation_interval_ns: 300_000_000_000,
            active_authorizations: BTreeMap::new(),
            signing_key,
            events: Vec::new(),
            next_seq: 0,
            epoch,
            zone: zone.to_string(),
        }
    }

    /// Add an approved measurement hash.
    pub fn approve_measurement(&mut self, measurement_hash: ContentHash) {
        self.approved_measurements.insert(measurement_hash);
    }

    /// Set the re-attestation interval.
    pub fn set_reattestation_interval(&mut self, interval_ns: u64) {
        self.reattestation_interval_ns = interval_ns;
    }

    /// Set the authorization validity window.
    pub fn set_authorization_window(&mut self, window_ns: u64) {
        self.default_authorization_window_ns = window_ns;
    }

    /// Generate an attestation challenge for a cell.
    pub fn generate_challenge(
        &self,
        nonce: [u8; 32],
        timestamp_ns: u64,
        response_deadline_ns: u64,
    ) -> Result<AttestationChallenge, HandshakeError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&nonce);
        canonical.extend_from_slice(&self.policy_version.to_be_bytes());
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        let challenge_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            &self.zone,
            &handshake_schema_id(),
            &canonical,
        )
        .map_err(|e| HandshakeError::IdDerivation(e.to_string()))?;

        let challenge = AttestationChallenge {
            challenge_id,
            nonce,
            approved_measurements: self.approved_measurements.clone(),
            policy_version: self.policy_version,
            challenge_timestamp_ns: timestamp_ns,
            epoch: self.epoch,
            response_deadline_ns,
            policy_plane_signature: Vec::new(), // Filled below.
        };

        let sig = self.sign(&challenge.canonical_bytes());
        Ok(AttestationChallenge {
            policy_plane_signature: sig,
            ..challenge
        })
    }

    /// Verify a cell's attestation response and issue authorization.
    pub fn verify_and_authorize(
        &mut self,
        challenge: &AttestationChallenge,
        response: &AttestationResponse,
        trust_root: &dyn TrustRootBackend,
        current_ns: u64,
    ) -> Result<CellAuthorization, HandshakeError> {
        // 1. Verify challenge authenticity before using any of its fields.
        let expected_challenge_signature = self.sign(&challenge.canonical_bytes());
        if challenge.policy_plane_signature != expected_challenge_signature {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::SignatureFailed,
                None,
                "challenge signature invalid",
                current_ns,
            );
            return Err(HandshakeError::ChallengeSignatureInvalid);
        }

        // 2. Check challenge freshness.
        if !challenge.is_valid_at(current_ns) {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::ChallengeTimeout,
                None,
                "challenge expired",
                current_ns,
            );
            return Err(HandshakeError::ChallengeExpired {
                challenge_timestamp_ns: challenge.challenge_timestamp_ns,
                deadline_ns: challenge.response_deadline_ns,
                current_ns,
            });
        }

        // 3. Check nonce match.
        if response.attestation_quote.nonce != challenge.nonce {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::SignatureFailed,
                None,
                "nonce mismatch",
                current_ns,
            );
            return Err(HandshakeError::NonceMismatch);
        }

        // 4. Verify attestation quote.
        let measurement = &response.attestation_quote.measurement;
        let verification = trust_root.verify(
            &response.attestation_quote,
            measurement,
            &challenge.nonce,
            current_ns,
        );
        if !verification.is_valid() {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::QuoteFailed,
                Some(measurement.composite_hash()),
                &format!("quote: {verification}"),
                current_ns,
            );
            return Err(HandshakeError::QuoteVerificationFailed {
                result: verification.to_string(),
            });
        }

        // 5. Check measurement against approved set.
        let measurement_hash = measurement.composite_hash();
        if !self.approved_measurements.contains(&measurement_hash) {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::MeasurementRejected,
                Some(measurement_hash.clone()),
                "measurement not approved",
                current_ns,
            );
            return Err(HandshakeError::MeasurementNotApproved { measurement_hash });
        }

        // 6. Verify key binding proof.
        let expected_binding = compute_key_binding(&response.signer_public_key, measurement);
        if response.key_binding_proof != expected_binding {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::KeyBindingFailed,
                Some(measurement_hash.clone()),
                "key binding invalid",
                current_ns,
            );
            return Err(HandshakeError::KeyBindingInvalid);
        }

        // 7. Verify response signature.
        let expected_sig =
            compute_response_signature(&response.signer_public_key, &response.canonical_bytes());
        if response.response_signature != expected_sig {
            self.emit_failure_event(
                &response.cell_id,
                HandshakeOutcome::SignatureFailed,
                Some(measurement_hash.clone()),
                "response signature invalid",
                current_ns,
            );
            return Err(HandshakeError::ResponseSignatureInvalid);
        }

        // 8. Issue authorization.
        let auth = self.issue_authorization(
            &response.cell_id,
            &response.claimed_capabilities,
            measurement_hash.clone(),
            current_ns,
        )?;

        // 9. Record success event.
        self.emit_event(HandshakeEvent {
            seq: 0,
            timestamp_ns: current_ns,
            epoch: self.epoch,
            cell_id: response.cell_id.clone(),
            outcome: HandshakeOutcome::Authorized,
            measurement_hash: Some(measurement_hash),
            policy_version: self.policy_version,
            trust_level: Some(trust_root.trust_level()),
            failure_reason: None,
        });

        Ok(auth)
    }

    /// Check whether a cell is currently authorized for an operation.
    pub fn check_authorization(
        &self,
        cell_id: &str,
        operation: &str,
        current_ns: u64,
    ) -> Result<(), HandshakeError> {
        let auth = self.active_authorizations.get(cell_id).ok_or_else(|| {
            HandshakeError::CellNotFound {
                cell_id: cell_id.to_string(),
            }
        })?;

        let expected_signature = self.sign(&auth.canonical_bytes());
        if auth.authorization_signature != expected_signature {
            return Err(HandshakeError::AuthorizationSignatureInvalid);
        }

        if !auth.is_valid_at(current_ns) {
            return Err(HandshakeError::AuthorizationExpired {
                issued_at_ns: auth.issued_at_ns,
                validity_window_ns: auth.validity_window_ns,
                current_ns,
            });
        }

        if !auth.authorizes(operation) {
            return Err(HandshakeError::OperationNotAuthorized {
                operation: operation.to_string(),
            });
        }

        Ok(())
    }

    /// Revoke a cell's authorization.
    pub fn revoke_authorization(&mut self, cell_id: &str) -> bool {
        self.active_authorizations.remove(cell_id).is_some()
    }

    /// Revoke all authorizations (e.g., on trust root change).
    pub fn revoke_all_authorizations(&mut self) -> usize {
        let count = self.active_authorizations.len();
        self.active_authorizations.clear();
        count
    }

    /// Get all currently authorized cell IDs.
    pub fn authorized_cells(&self) -> Vec<&str> {
        self.active_authorizations
            .keys()
            .map(|s| s.as_str())
            .collect()
    }

    /// Get all authorizations that are still valid at the given time.
    pub fn valid_authorizations_at(&self, current_ns: u64) -> Vec<&CellAuthorization> {
        self.active_authorizations
            .values()
            .filter(|a| a.is_valid_at(current_ns))
            .collect()
    }

    /// Check which cells need re-attestation based on authorization age.
    pub fn cells_needing_reattestation(&self, current_ns: u64) -> Vec<String> {
        self.active_authorizations
            .iter()
            .filter(|(_, auth)| {
                let age = current_ns.saturating_sub(auth.issued_at_ns);
                age >= self.reattestation_interval_ns
            })
            .map(|(cell_id, _)| cell_id.clone())
            .collect()
    }

    /// Bump the policy version (triggers re-attestation requirement).
    pub fn bump_policy_version(&mut self) -> u64 {
        self.policy_version += 1;
        self.policy_version
    }

    /// Advance epoch (triggers re-attestation requirement).
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;
    }

    /// Number of active authorizations.
    pub fn authorization_count(&self) -> usize {
        self.active_authorizations.len()
    }

    /// All audit events.
    pub fn events(&self) -> &[HandshakeEvent] {
        &self.events
    }

    /// Policy version.
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    fn issue_authorization(
        &mut self,
        cell_id: &str,
        capabilities: &BTreeSet<String>,
        measurement_hash: ContentHash,
        current_ns: u64,
    ) -> Result<CellAuthorization, HandshakeError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(cell_id.as_bytes());
        canonical.extend_from_slice(&current_ns.to_be_bytes());
        canonical.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        let auth_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            &self.zone,
            &handshake_schema_id(),
            &canonical,
        )
        .map_err(|e| HandshakeError::IdDerivation(e.to_string()))?;

        let mut auth = CellAuthorization {
            authorization_id: auth_id,
            cell_id: cell_id.to_string(),
            authorized_operations: capabilities.clone(),
            epoch: self.epoch,
            issued_at_ns: current_ns,
            validity_window_ns: self.default_authorization_window_ns,
            policy_version: self.policy_version,
            verified_measurement: measurement_hash,
            authorization_signature: Vec::new(),
        };
        auth.authorization_signature = self.sign(&auth.canonical_bytes());

        self.active_authorizations
            .insert(cell_id.to_string(), auth.clone());
        Ok(auth)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut sig_input = Vec::with_capacity(32 + data.len());
        sig_input.extend_from_slice(&self.signing_key);
        sig_input.extend_from_slice(data);
        ContentHash::compute(&sig_input).as_bytes().to_vec()
    }

    fn emit_event(&mut self, mut event: HandshakeEvent) {
        event.seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(event);
    }

    fn emit_failure_event(
        &mut self,
        cell_id: &str,
        outcome: HandshakeOutcome,
        measurement_hash: Option<ContentHash>,
        reason: &str,
        timestamp_ns: u64,
    ) {
        self.emit_event(HandshakeEvent {
            seq: 0,
            timestamp_ns,
            epoch: self.epoch,
            cell_id: cell_id.to_string(),
            outcome,
            measurement_hash,
            policy_version: self.policy_version,
            trust_level: None,
            failure_reason: Some(reason.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Key binding and signature helpers
// ---------------------------------------------------------------------------

/// Compute the key binding proof: H(public_key || measurement_canonical).
fn compute_key_binding(public_key: &[u8], measurement: &MeasurementDigest) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(public_key);
    input.extend_from_slice(&measurement.canonical_bytes());
    ContentHash::compute(&input).as_bytes().to_vec()
}

/// Compute a response signature: H(public_key || canonical_bytes).
fn compute_response_signature(public_key: &[u8], canonical_bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(public_key);
    input.extend_from_slice(canonical_bytes);
    ContentHash::compute(&input).as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// CellHandshakeClient — cell-side handshake logic
// ---------------------------------------------------------------------------

/// Cell-side participant in the attestation handshake.
///
/// Holds the cell's identity, measurement, and key material needed
/// to respond to challenges.
#[derive(Debug, Clone)]
pub struct CellHandshakeClient {
    /// Cell identifier.
    pub cell_id: String,
    /// Cell function.
    pub cell_function: CellFunction,
    /// Cell's signing public key.
    pub public_key: Vec<u8>,
    /// Claimed capabilities.
    pub capabilities: BTreeSet<String>,
}

impl CellHandshakeClient {
    /// Respond to an attestation challenge using the given trust root.
    pub fn respond(
        &self,
        challenge: &AttestationChallenge,
        measurement: &MeasurementDigest,
        trust_root: &dyn TrustRootBackend,
        validity_window_ns: u64,
        timestamp_ns: u64,
    ) -> AttestationResponse {
        // Generate attestation quote with the challenge nonce.
        let mut quote = trust_root.attest(measurement, challenge.nonce, validity_window_ns);
        quote.issued_at_ns = timestamp_ns;

        // Compute key binding proof.
        let key_binding = compute_key_binding(&self.public_key, measurement);

        // Build response canonical bytes for signing.
        let response = AttestationResponse {
            cell_id: self.cell_id.clone(),
            attestation_quote: quote,
            signer_public_key: self.public_key.clone(),
            key_binding_proof: key_binding,
            claimed_capabilities: self.capabilities.clone(),
            response_timestamp_ns: timestamp_ns,
            cell_function: self.cell_function,
            response_signature: Vec::new(), // Filled below.
        };

        let sig = compute_response_signature(&self.public_key, &response.canonical_bytes());
        AttestationResponse {
            response_signature: sig,
            ..response
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attested_execution_cell::SoftwareTrustRoot;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn test_signing_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        key
    }

    fn test_trust_root() -> SoftwareTrustRoot {
        SoftwareTrustRoot::new("test-key-1", 12345)
    }

    fn test_measurement(root: &SoftwareTrustRoot) -> MeasurementDigest {
        root.measure(
            b"cell-code-v1",
            b"cell-config-v1",
            b"cell-policy-v1",
            b"evidence-schema-v1",
            "1.0.0",
        )
    }

    fn test_verifier() -> PolicyPlaneVerifier {
        PolicyPlaneVerifier::new(test_signing_key(), 1, test_epoch(), "production")
    }

    fn test_client() -> CellHandshakeClient {
        let mut caps = BTreeSet::new();
        caps.insert("sign_receipts".to_string());
        caps.insert("emit_evidence".to_string());
        CellHandshakeClient {
            cell_id: "cell-001".to_string(),
            cell_function: CellFunction::DecisionReceiptSigner,
            public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            capabilities: caps,
        }
    }

    fn do_full_handshake(
        verifier: &mut PolicyPlaneVerifier,
        client: &CellHandshakeClient,
        root: &SoftwareTrustRoot,
        measurement: &MeasurementDigest,
        timestamp_ns: u64,
    ) -> Result<CellAuthorization, HandshakeError> {
        let nonce = [42u8; 32];
        let challenge = verifier.generate_challenge(nonce, timestamp_ns, 10_000_000)?;
        let response = client.respond(&challenge, measurement, root, 10_000_000, timestamp_ns);
        verifier.verify_and_authorize(&challenge, &response, root, timestamp_ns)
    }

    // --- AttestationChallenge ---

    #[test]
    fn challenge_validity() {
        let verifier = test_verifier();
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert!(challenge.is_valid_at(1000));
        assert!(challenge.is_valid_at(1500));
        assert!(!challenge.is_valid_at(1501));
    }

    #[test]
    fn challenge_canonical_bytes_deterministic() {
        let verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        let c2 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert_eq!(c1.canonical_bytes(), c2.canonical_bytes());
    }

    #[test]
    fn challenge_serde_roundtrip() {
        let verifier = test_verifier();
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        let json = serde_json::to_string(&challenge).unwrap();
        let restored: AttestationChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(challenge, restored);
    }

    // --- CellAuthorization ---

    #[test]
    fn authorization_validity() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert!(auth.is_valid_at(1000));
        assert!(auth.is_valid_at(1000 + 300_000_000_000)); // At boundary.
        assert!(!auth.is_valid_at(1001 + 300_000_000_000)); // Past boundary.
    }

    #[test]
    fn authorization_covers_operation() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert!(auth.authorizes("sign_receipts"));
        assert!(auth.authorizes("emit_evidence"));
        assert!(!auth.authorizes("admin_override"));
    }

    #[test]
    fn authorization_serde_roundtrip() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let json = serde_json::to_string(&auth).unwrap();
        let restored: CellAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, restored);
    }

    // --- Full handshake ---

    #[test]
    fn full_handshake_happy_path() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert_eq!(auth.cell_id, "cell-001");
        assert_eq!(auth.policy_version, 1);
        assert_eq!(auth.epoch, test_epoch());
        assert_eq!(verifier.authorization_count(), 1);
    }

    #[test]
    fn handshake_rejects_expired_challenge() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let nonce = [1u8; 32];
        let challenge = verifier.generate_challenge(nonce, 1000, 100).unwrap();
        let client = test_client();
        let response = client.respond(&challenge, &measurement, &root, 10_000, 1200);

        // Verify at time 1200, but challenge deadline was 1000 + 100 = 1100.
        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1200)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::ChallengeExpired { .. }));
    }

    #[test]
    fn handshake_rejects_invalid_challenge_signature() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let mut challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        challenge.policy_plane_signature = vec![0xCA, 0xFE];

        let client = test_client();
        let response = client.respond(&challenge, &measurement, &root, 10_000, 1000);

        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::ChallengeSignatureInvalid));
    }

    #[test]
    fn handshake_rejects_unapproved_measurement() {
        let mut verifier = test_verifier();
        // Don't approve any measurements.
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let client = test_client();

        let err = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap_err();
        assert!(matches!(err, HandshakeError::MeasurementNotApproved { .. }));
    }

    #[test]
    fn handshake_rejects_nonce_mismatch() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client = test_client();

        // Client responds with a different nonce (uses challenge nonce internally,
        // but we tamper the quote nonce directly).
        let mut response = client.respond(&challenge, &measurement, &root, 10_000, 1000);
        response.attestation_quote.nonce = [99u8; 32]; // Tamper.

        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::NonceMismatch));
    }

    #[test]
    fn handshake_rejects_invalid_key_binding() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client = test_client();
        let mut response = client.respond(&challenge, &measurement, &root, 10_000, 1000);
        response.key_binding_proof = vec![0xDE, 0xAD]; // Tamper.

        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::KeyBindingInvalid));
    }

    #[test]
    fn handshake_rejects_invalid_response_signature() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client = test_client();
        let mut response = client.respond(&challenge, &measurement, &root, 10_000, 1000);
        response.response_signature = vec![0xBA, 0xAD]; // Tamper.

        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::ResponseSignatureInvalid));
    }

    #[test]
    fn handshake_rejects_tampered_quote_after_response_signing() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client = test_client();
        let mut response = client.respond(&challenge, &measurement, &root, 10_000, 1000);
        response.attestation_quote.issued_at_ns = 999;

        let err = verifier
            .verify_and_authorize(&challenge, &response, &root, 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::ResponseSignatureInvalid));
    }

    #[test]
    fn handshake_rejects_revoked_trust_root() {
        let mut verifier = test_verifier();
        let mut root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        root.revoke_key("test-key-1"); // Revoke before verification.

        let client = test_client();
        let err = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::QuoteVerificationFailed { .. }
        ));
    }

    // --- Authorization checks ---

    #[test]
    fn check_authorization_happy_path() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert!(
            verifier
                .check_authorization("cell-001", "sign_receipts", 2000)
                .is_ok()
        );
    }

    #[test]
    fn check_authorization_rejects_tampered_authorized_operations() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        verifier
            .active_authorizations
            .get_mut("cell-001")
            .expect("authorization")
            .authorized_operations
            .insert("admin_override".to_string());

        let err = verifier
            .check_authorization("cell-001", "admin_override", 2000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::AuthorizationSignatureInvalid));
    }

    #[test]
    fn check_authorization_expired() {
        let mut verifier = test_verifier();
        verifier.set_authorization_window(100); // 100ns window.
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let err = verifier
            .check_authorization("cell-001", "sign_receipts", 1200)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::AuthorizationExpired { .. }));
    }

    #[test]
    fn check_authorization_unknown_cell() {
        let verifier = test_verifier();
        let err = verifier
            .check_authorization("unknown", "sign_receipts", 1000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::CellNotFound { .. }));
    }

    #[test]
    fn check_authorization_wrong_operation() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let err = verifier
            .check_authorization("cell-001", "admin_override", 2000)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::OperationNotAuthorized { .. }));
    }

    // --- Revocation ---

    #[test]
    fn revoke_authorization() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        assert_eq!(verifier.authorization_count(), 1);

        assert!(verifier.revoke_authorization("cell-001"));
        assert_eq!(verifier.authorization_count(), 0);
        assert!(!verifier.revoke_authorization("cell-001")); // Already revoked.
    }

    #[test]
    fn revoke_all_authorizations() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client1 = test_client();
        do_full_handshake(&mut verifier, &client1, &root, &measurement, 1000).unwrap();

        let mut client2 = test_client();
        client2.cell_id = "cell-002".to_string();
        do_full_handshake(&mut verifier, &client2, &root, &measurement, 2000).unwrap();

        assert_eq!(verifier.authorization_count(), 2);
        let revoked = verifier.revoke_all_authorizations();
        assert_eq!(revoked, 2);
        assert_eq!(verifier.authorization_count(), 0);
    }

    // --- Re-attestation ---

    #[test]
    fn cells_needing_reattestation() {
        let mut verifier = test_verifier();
        verifier.set_reattestation_interval(1000); // 1000ns interval.
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        // At 1500ns, within interval.
        assert!(verifier.cells_needing_reattestation(1500).is_empty());

        // At 2000ns, exactly at interval boundary.
        assert_eq!(verifier.cells_needing_reattestation(2000).len(), 1);
        assert_eq!(verifier.cells_needing_reattestation(2000)[0], "cell-001");
    }

    #[test]
    fn policy_version_bump() {
        let mut verifier = test_verifier();
        assert_eq!(verifier.policy_version(), 1);
        let new_ver = verifier.bump_policy_version();
        assert_eq!(new_ver, 2);
        assert_eq!(verifier.policy_version(), 2);
    }

    // --- Audit events ---

    #[test]
    fn events_on_successful_handshake() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert_eq!(verifier.events().len(), 1);
        assert_eq!(verifier.events()[0].outcome, HandshakeOutcome::Authorized);
        assert_eq!(verifier.events()[0].cell_id, "cell-001");
        assert!(verifier.events()[0].failure_reason.is_none());
    }

    #[test]
    fn events_on_failed_handshake() {
        let mut verifier = test_verifier();
        // No approved measurements → failure.
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let client = test_client();
        let _ = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000);

        assert_eq!(verifier.events().len(), 1);
        assert_eq!(
            verifier.events()[0].outcome,
            HandshakeOutcome::MeasurementRejected
        );
        assert!(verifier.events()[0].failure_reason.is_some());
    }

    #[test]
    fn event_sequence_numbers() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let mut client2 = test_client();
        client2.cell_id = "cell-002".to_string();
        do_full_handshake(&mut verifier, &client2, &root, &measurement, 2000).unwrap();

        assert_eq!(verifier.events()[0].seq, 0);
        assert_eq!(verifier.events()[1].seq, 1);
    }

    // --- HandshakeError display ---

    #[test]
    fn error_display_coverage() {
        let errors = [
            HandshakeError::ChallengeExpired {
                challenge_timestamp_ns: 100,
                deadline_ns: 50,
                current_ns: 200,
            },
            HandshakeError::ChallengeSignatureInvalid,
            HandshakeError::MeasurementNotApproved {
                measurement_hash: ContentHash::compute(b"test"),
            },
            HandshakeError::QuoteVerificationFailed {
                result: "expired".to_string(),
            },
            HandshakeError::NonceMismatch,
            HandshakeError::KeyBindingInvalid,
            HandshakeError::ResponseSignatureInvalid,
            HandshakeError::AuthorizationExpired {
                issued_at_ns: 100,
                validity_window_ns: 50,
                current_ns: 200,
            },
            HandshakeError::AuthorizationSignatureInvalid,
            HandshakeError::OperationNotAuthorized {
                operation: "admin".to_string(),
            },
            HandshakeError::CellNotFound {
                cell_id: "x".to_string(),
            },
            HandshakeError::ReattestationRequired {
                reason: "policy change".to_string(),
            },
            HandshakeError::IdDerivation("test".to_string()),
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "error display should not be empty: {e:?}");
        }
    }

    // --- HandshakeOutcome ---

    #[test]
    fn outcome_display() {
        assert_eq!(HandshakeOutcome::Authorized.to_string(), "authorized");
        assert_eq!(
            HandshakeOutcome::ChallengeTimeout.to_string(),
            "challenge-timeout"
        );
        assert_eq!(
            HandshakeOutcome::MeasurementRejected.to_string(),
            "measurement-rejected"
        );
        assert_eq!(HandshakeOutcome::QuoteFailed.to_string(), "quote-failed");
        assert_eq!(
            HandshakeOutcome::KeyBindingFailed.to_string(),
            "key-binding-failed"
        );
        assert_eq!(
            HandshakeOutcome::SignatureFailed.to_string(),
            "signature-failed"
        );
    }

    // --- ReattestationTrigger ---

    #[test]
    fn trigger_display() {
        assert_eq!(ReattestationTrigger::Periodic.to_string(), "periodic");
        assert_eq!(
            ReattestationTrigger::PolicyChange.to_string(),
            "policy-change"
        );
        assert_eq!(
            ReattestationTrigger::EpochTransition.to_string(),
            "epoch-transition"
        );
        assert_eq!(
            ReattestationTrigger::TrustRootUpdate.to_string(),
            "trust-root-update"
        );
        assert_eq!(ReattestationTrigger::Manual.to_string(), "manual");
    }

    // --- Serde ---

    #[test]
    fn handshake_event_serde_roundtrip() {
        let event = HandshakeEvent {
            seq: 5,
            timestamp_ns: 1000,
            epoch: test_epoch(),
            cell_id: "cell-001".to_string(),
            outcome: HandshakeOutcome::Authorized,
            measurement_hash: Some(ContentHash::compute(b"test")),
            policy_version: 1,
            trust_level: Some(TrustLevel::SoftwareOnly),
            failure_reason: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: HandshakeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn response_serde_roundtrip() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let client = test_client();
        let verifier = test_verifier();
        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let response = client.respond(&challenge, &measurement, &root, 10_000, 1000);

        let json = serde_json::to_string(&response).unwrap();
        let restored: AttestationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, restored);
    }

    // --- Valid authorizations query ---

    #[test]
    fn valid_authorizations_at_filters_expired() {
        let mut verifier = test_verifier();
        verifier.set_authorization_window(100);
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        assert_eq!(verifier.valid_authorizations_at(1050).len(), 1);
        assert_eq!(verifier.valid_authorizations_at(1200).len(), 0);
    }

    // -- serde roundtrips for enum types --------------------------------------

    #[test]
    fn handshake_outcome_serde_roundtrip() {
        for outcome in &[
            HandshakeOutcome::Authorized,
            HandshakeOutcome::ChallengeTimeout,
            HandshakeOutcome::MeasurementRejected,
            HandshakeOutcome::QuoteFailed,
            HandshakeOutcome::KeyBindingFailed,
            HandshakeOutcome::SignatureFailed,
        ] {
            let json = serde_json::to_string(outcome).unwrap();
            let back: HandshakeOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*outcome, back);
        }
    }

    #[test]
    fn reattestation_trigger_serde_roundtrip() {
        for trigger in &[
            ReattestationTrigger::Periodic,
            ReattestationTrigger::PolicyChange,
            ReattestationTrigger::EpochTransition,
            ReattestationTrigger::TrustRootUpdate,
            ReattestationTrigger::Manual,
        ] {
            let json = serde_json::to_string(trigger).unwrap();
            let back: ReattestationTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*trigger, back);
        }
    }

    #[test]
    fn handshake_error_serde_roundtrip() {
        let errors = vec![
            HandshakeError::ChallengeExpired {
                challenge_timestamp_ns: 100,
                deadline_ns: 50,
                current_ns: 200,
            },
            HandshakeError::ChallengeSignatureInvalid,
            HandshakeError::MeasurementNotApproved {
                measurement_hash: ContentHash::compute(b"test"),
            },
            HandshakeError::QuoteVerificationFailed {
                result: "bad".to_string(),
            },
            HandshakeError::NonceMismatch,
            HandshakeError::KeyBindingInvalid,
            HandshakeError::ResponseSignatureInvalid,
            HandshakeError::AuthorizationExpired {
                issued_at_ns: 100,
                validity_window_ns: 50,
                current_ns: 200,
            },
            HandshakeError::AuthorizationSignatureInvalid,
            HandshakeError::OperationNotAuthorized {
                operation: "admin".to_string(),
            },
            HandshakeError::CellNotFound {
                cell_id: "c1".to_string(),
            },
            HandshakeError::ReattestationRequired {
                reason: "policy".to_string(),
            },
            HandshakeError::IdDerivation("err".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: HandshakeError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // -- canonical bytes determinism ------------------------------------------

    #[test]
    fn authorization_canonical_bytes_deterministic() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let bytes1 = auth.canonical_bytes();
        let bytes2 = auth.canonical_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn response_canonical_bytes_deterministic() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let client = test_client();
        let verifier = test_verifier();
        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let response = client.respond(&challenge, &measurement, &root, 10_000, 1000);

        let b1 = response.canonical_bytes();
        let b2 = response.canonical_bytes();
        assert_eq!(b1, b2);
        assert!(!b1.is_empty());
    }

    // -- fresh verifier state -------------------------------------------------

    #[test]
    fn fresh_verifier_has_no_authorizations() {
        let verifier = test_verifier();
        assert_eq!(verifier.authorization_count(), 0);
        assert!(verifier.authorized_cells().is_empty());
        assert!(verifier.events().is_empty());
    }

    // -- authorized_cells list ------------------------------------------------

    #[test]
    fn authorized_cells_returns_cell_ids() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let client = test_client();
        do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();

        let cells = verifier.authorized_cells();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0], "cell-001");
    }

    // -- advance_epoch --------------------------------------------------------

    #[test]
    fn advance_epoch_updates_epoch() {
        let mut verifier = test_verifier();
        assert_eq!(verifier.epoch, SecurityEpoch::from_raw(42));
        verifier.advance_epoch(SecurityEpoch::from_raw(43));
        // Next challenge should use the new epoch.
        let challenge = verifier.generate_challenge([2u8; 32], 5000, 1000).unwrap();
        assert_eq!(challenge.epoch, SecurityEpoch::from_raw(43));
    }

    // -- revoke nonexistent returns false ------------------------------------

    #[test]
    fn revoke_nonexistent_authorization_returns_false() {
        let mut verifier = test_verifier();
        assert!(!verifier.revoke_authorization("nonexistent"));
    }

    // -- revoke_all on empty returns zero -------------------------------------

    // -- Enrichment: std::error, edge cases --

    #[test]
    fn handshake_error_std_error_trait() {
        // ContentHash already in scope via `use super::*`
        let errs: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(HandshakeError::ChallengeExpired {
                challenge_timestamp_ns: 1,
                deadline_ns: 2,
                current_ns: 3,
            }),
            Box::new(HandshakeError::ChallengeSignatureInvalid),
            Box::new(HandshakeError::MeasurementNotApproved {
                measurement_hash: ContentHash::compute(b"x"),
            }),
            Box::new(HandshakeError::QuoteVerificationFailed {
                result: "fail".to_string(),
            }),
            Box::new(HandshakeError::NonceMismatch),
            Box::new(HandshakeError::KeyBindingInvalid),
            Box::new(HandshakeError::ResponseSignatureInvalid),
            Box::new(HandshakeError::AuthorizationExpired {
                issued_at_ns: 1,
                validity_window_ns: 2,
                current_ns: 3,
            }),
            Box::new(HandshakeError::AuthorizationSignatureInvalid),
            Box::new(HandshakeError::OperationNotAuthorized {
                operation: "read".to_string(),
            }),
            Box::new(HandshakeError::CellNotFound {
                cell_id: "c".to_string(),
            }),
            Box::new(HandshakeError::ReattestationRequired {
                reason: "epoch".to_string(),
            }),
            Box::new(HandshakeError::IdDerivation("bad".to_string())),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errs.len(), 13);
    }

    #[test]
    fn handshake_outcome_serde_all_six_variants() {
        let variants = [
            HandshakeOutcome::Authorized,
            HandshakeOutcome::ChallengeTimeout,
            HandshakeOutcome::MeasurementRejected,
            HandshakeOutcome::QuoteFailed,
            HandshakeOutcome::KeyBindingFailed,
            HandshakeOutcome::SignatureFailed,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: HandshakeOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn reattestation_trigger_serde_all_five_variants() {
        let variants = [
            ReattestationTrigger::Periodic,
            ReattestationTrigger::PolicyChange,
            ReattestationTrigger::EpochTransition,
            ReattestationTrigger::TrustRootUpdate,
            ReattestationTrigger::Manual,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: ReattestationTrigger = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn cell_authorization_authorizes_rejects_unknown_op() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());
        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        // Operation not in authorized set should fail
        assert!(!auth.authorizes("nonexistent_op"));
    }

    // -- revoke_all on empty returns zero -------------------------------------

    #[test]
    fn revoke_all_on_empty_returns_zero() {
        let mut verifier = test_verifier();
        assert_eq!(verifier.revoke_all_authorizations(), 0);
    }

    // -- Enrichment: Display uniqueness, edge cases, determinism --

    #[test]
    fn handshake_outcome_display_uniqueness_btreeset() {
        let variants = [
            HandshakeOutcome::Authorized,
            HandshakeOutcome::ChallengeTimeout,
            HandshakeOutcome::MeasurementRejected,
            HandshakeOutcome::QuoteFailed,
            HandshakeOutcome::KeyBindingFailed,
            HandshakeOutcome::SignatureFailed,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(v.to_string());
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 outcomes produce distinct display strings"
        );
    }

    #[test]
    fn reattestation_trigger_display_uniqueness_btreeset() {
        let variants = [
            ReattestationTrigger::Periodic,
            ReattestationTrigger::PolicyChange,
            ReattestationTrigger::EpochTransition,
            ReattestationTrigger::TrustRootUpdate,
            ReattestationTrigger::Manual,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(v.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 triggers produce distinct display strings"
        );
    }

    #[test]
    fn handshake_error_display_uniqueness_btreeset() {
        let errors = [
            HandshakeError::ChallengeExpired {
                challenge_timestamp_ns: 1,
                deadline_ns: 2,
                current_ns: 3,
            },
            HandshakeError::ChallengeSignatureInvalid,
            HandshakeError::MeasurementNotApproved {
                measurement_hash: ContentHash::compute(b"a"),
            },
            HandshakeError::QuoteVerificationFailed {
                result: "bad".to_string(),
            },
            HandshakeError::NonceMismatch,
            HandshakeError::KeyBindingInvalid,
            HandshakeError::ResponseSignatureInvalid,
            HandshakeError::AuthorizationExpired {
                issued_at_ns: 1,
                validity_window_ns: 2,
                current_ns: 3,
            },
            HandshakeError::AuthorizationSignatureInvalid,
            HandshakeError::OperationNotAuthorized {
                operation: "op".to_string(),
            },
            HandshakeError::CellNotFound {
                cell_id: "c".to_string(),
            },
            HandshakeError::ReattestationRequired {
                reason: "r".to_string(),
            },
            HandshakeError::IdDerivation("id".to_string()),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            13,
            "all 13 error variants produce distinct messages"
        );
    }

    #[test]
    fn cell_function_display_coverage() {
        let funcs = [
            CellFunction::DecisionReceiptSigner,
            CellFunction::EvidenceAccumulator,
            CellFunction::PolicyEvaluator,
            CellFunction::ProofValidator,
            CellFunction::ExtensionRuntime,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for f in &funcs {
            displays.insert(f.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 cell functions produce distinct display strings"
        );
    }

    #[test]
    fn challenge_different_nonces_produce_different_ids() {
        let verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        let c2 = verifier.generate_challenge([2u8; 32], 1000, 500).unwrap();
        assert_ne!(c1.challenge_id, c2.challenge_id);
    }

    #[test]
    fn multiple_handshakes_increment_authorization_count() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        for i in 0..3u32 {
            let mut client = test_client();
            client.cell_id = format!("cell-{i:03}");
            do_full_handshake(
                &mut verifier,
                &client,
                &root,
                &measurement,
                1000 + u64::from(i) * 1000,
            )
            .unwrap();
        }
        assert_eq!(verifier.authorization_count(), 3);
        assert_eq!(verifier.authorized_cells().len(), 3);
    }

    #[test]
    fn handshake_event_serde_all_outcomes() {
        let outcomes = [
            HandshakeOutcome::Authorized,
            HandshakeOutcome::ChallengeTimeout,
            HandshakeOutcome::MeasurementRejected,
            HandshakeOutcome::QuoteFailed,
            HandshakeOutcome::KeyBindingFailed,
            HandshakeOutcome::SignatureFailed,
        ];
        for outcome in &outcomes {
            let event = HandshakeEvent {
                seq: 0,
                timestamp_ns: 1000,
                epoch: test_epoch(),
                cell_id: "cell-test".to_string(),
                outcome: *outcome,
                measurement_hash: None,
                policy_version: 1,
                trust_level: None,
                failure_reason: None,
            };
            let json = serde_json::to_string(&event).unwrap();
            let restored: HandshakeEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_is_valid_at_exact_boundary() {
        let verifier = test_verifier();
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        // At exactly timestamp + deadline, should still be valid.
        assert!(challenge.is_valid_at(1500));
        // One past the deadline, invalid.
        assert!(!challenge.is_valid_at(1501));
    }

    #[test]
    fn authorization_is_valid_at_exact_boundary() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());
        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        // At exactly issued_at + validity_window, should still be valid.
        let boundary = auth.issued_at_ns + auth.validity_window_ns;
        assert!(auth.is_valid_at(boundary));
        assert!(!auth.is_valid_at(boundary + 1));
    }

    #[test]
    fn set_reattestation_interval_takes_effect() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());
        verifier.set_reattestation_interval(1000);
        let client = test_client();
        let _auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 100).unwrap();
        // At t=1099, age is 999 < 1000 interval, no reattestation needed.
        assert!(verifier.cells_needing_reattestation(1099).is_empty());
        // At t=1100, age is 1000 >= 1000 interval, reattestation needed.
        assert_eq!(verifier.cells_needing_reattestation(1100).len(), 1);
    }

    #[test]
    fn set_authorization_window_takes_effect() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());
        verifier.set_authorization_window(2000);
        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 100).unwrap();
        assert_eq!(auth.validity_window_ns, 2000);
    }

    #[test]
    fn policy_version_accessor_matches_initial() {
        let verifier = test_verifier();
        assert_eq!(verifier.policy_version(), 1);
    }

    #[test]
    fn policy_version_bumps_sequentially() {
        let mut verifier = test_verifier();
        assert_eq!(verifier.bump_policy_version(), 2);
        assert_eq!(verifier.bump_policy_version(), 3);
        assert_eq!(verifier.policy_version(), 3);
    }

    #[test]
    fn cell_handshake_client_respond_structure() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let client = test_client();
        let verifier = test_verifier();
        let challenge = verifier
            .generate_challenge([99u8; 32], 5000, 10000)
            .unwrap();
        let response = client.respond(&challenge, &measurement, &root, 10000, 5000);
        assert_eq!(response.cell_id, "cell-001");
        assert_eq!(response.cell_function, CellFunction::DecisionReceiptSigner);
        assert!(!response.signer_public_key.is_empty());
        assert!(!response.key_binding_proof.is_empty());
        assert!(!response.response_signature.is_empty());
        assert_eq!(response.response_timestamp_ns, 5000);
        assert!(response.claimed_capabilities.contains("sign_receipts"));
        assert!(response.claimed_capabilities.contains("emit_evidence"));
    }

    #[test]
    fn challenge_canonical_bytes_changes_with_nonce() {
        let verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        let c2 = verifier.generate_challenge([2u8; 32], 1000, 500).unwrap();
        assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
    }

    #[test]
    fn authorization_authorizes_present_capability() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());
        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        assert!(auth.authorizes("sign_receipts"));
        assert!(auth.authorizes("emit_evidence"));
        assert!(!auth.authorizes("delete_data"));
    }

    #[test]
    fn handshake_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(HandshakeError::NonceMismatch);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn handshake_event_with_all_optional_fields() {
        let event = HandshakeEvent {
            seq: 5,
            timestamp_ns: 9000,
            epoch: test_epoch(),
            cell_id: "cell-x".to_string(),
            outcome: HandshakeOutcome::MeasurementRejected,
            measurement_hash: Some(ContentHash::compute(b"test")),
            policy_version: 3,
            trust_level: Some(TrustLevel::SoftwareOnly),
            failure_reason: Some("measurement not approved".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: HandshakeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert!(back.measurement_hash.is_some());
        assert!(back.trust_level.is_some());
        assert!(back.failure_reason.is_some());
    }

    #[test]
    fn cell_authorization_serde_with_operations() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());
        let client = test_client();
        let auth = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        let json = serde_json::to_string(&auth).unwrap();
        let back: CellAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(auth.cell_id, back.cell_id);
        assert_eq!(auth.authorized_operations, back.authorized_operations);
        assert_eq!(auth.epoch, back.epoch);
    }

    #[test]
    fn verifier_serde_roundtrip() {
        let verifier = test_verifier();
        let json = serde_json::to_string(&verifier).unwrap();
        let back: PolicyPlaneVerifier = serde_json::from_str(&json).unwrap();
        assert_eq!(verifier.policy_version(), back.policy_version());
        assert_eq!(verifier.authorization_count(), back.authorization_count());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn challenge_canonical_bytes_sensitive_to_policy_version() {
        let mut verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        verifier.bump_policy_version();
        let c2 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
    }

    #[test]
    fn challenge_canonical_bytes_sensitive_to_timestamp() {
        let verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        let c2 = verifier.generate_challenge([1u8; 32], 2000, 500).unwrap();
        assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
    }

    #[test]
    fn challenge_canonical_bytes_sensitive_to_epoch() {
        let verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        // Epoch is baked into canonical_bytes via the verifier's epoch field.
        // Create a new verifier with different epoch.
        let verifier2 = PolicyPlaneVerifier::new(
            test_signing_key(),
            1,
            SecurityEpoch::from_raw(99),
            "production",
        );
        let c2 = verifier2.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
    }

    #[test]
    fn response_canonical_bytes_sensitive_to_cell_id() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let verifier = test_verifier();
        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client1 = test_client();
        let mut client2 = test_client();
        client2.cell_id = "cell-999".to_string();
        let r1 = client1.respond(&challenge, &measurement, &root, 10_000, 1000);
        let r2 = client2.respond(&challenge, &measurement, &root, 10_000, 1000);
        assert_ne!(r1.canonical_bytes(), r2.canonical_bytes());
    }

    #[test]
    fn response_canonical_bytes_sensitive_to_quote_timestamp() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let verifier = test_verifier();
        let challenge = verifier
            .generate_challenge([1u8; 32], 1000, 10_000)
            .unwrap();
        let client = test_client();
        let r1 = client.respond(&challenge, &measurement, &root, 10_000, 1000);
        let mut r2 = r1.clone();
        r2.attestation_quote.issued_at_ns += 1;
        assert_ne!(r1.canonical_bytes(), r2.canonical_bytes());
    }

    #[test]
    fn re_handshake_same_cell_replaces_authorization() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());
        let client = test_client();
        let auth1 = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000).unwrap();
        let auth2 = do_full_handshake(&mut verifier, &client, &root, &measurement, 2000).unwrap();
        // Still only one authorization (replaced, not accumulated).
        assert_eq!(verifier.authorization_count(), 1);
        // The new one has the later timestamp.
        assert_ne!(auth1.issued_at_ns, auth2.issued_at_ns);
        assert_eq!(auth2.issued_at_ns, 2000);
    }

    #[test]
    fn approve_multiple_measurements() {
        let mut verifier = test_verifier();
        let m1 = ContentHash::compute(b"measurement-1");
        let m2 = ContentHash::compute(b"measurement-2");
        verifier.approve_measurement(m1.clone());
        verifier.approve_measurement(m2.clone());
        // Both should appear in challenges.
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert!(challenge.approved_measurements.contains(&m1));
        assert!(challenge.approved_measurements.contains(&m2));
    }

    #[test]
    fn multiple_cells_needing_reattestation() {
        let mut verifier = test_verifier();
        verifier.set_reattestation_interval(500);
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let c1 = test_client();
        do_full_handshake(&mut verifier, &c1, &root, &measurement, 100).unwrap();
        let mut c2 = test_client();
        c2.cell_id = "cell-002".to_string();
        do_full_handshake(&mut verifier, &c2, &root, &measurement, 200).unwrap();

        // At t=600, cell-001 age=500 (needs reattest), cell-002 age=400 (doesn't).
        let needing = verifier.cells_needing_reattestation(600);
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0], "cell-001");

        // At t=700, both need reattestation.
        let needing = verifier.cells_needing_reattestation(700);
        assert_eq!(needing.len(), 2);
    }

    #[test]
    fn valid_authorizations_at_mixed_valid_expired() {
        let mut verifier = test_verifier();
        verifier.set_authorization_window(500);
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        verifier.approve_measurement(measurement.composite_hash());

        let c1 = test_client();
        do_full_handshake(&mut verifier, &c1, &root, &measurement, 100).unwrap();
        let mut c2 = test_client();
        c2.cell_id = "cell-002".to_string();
        do_full_handshake(&mut verifier, &c2, &root, &measurement, 400).unwrap();

        // At t=601, cell-001 (issued 100, window 500) expired, cell-002 still valid.
        assert_eq!(verifier.valid_authorizations_at(601).len(), 1);
        assert_eq!(verifier.valid_authorizations_at(601)[0].cell_id, "cell-002");
    }

    #[test]
    fn events_accumulate_across_multiple_failures() {
        let mut verifier = test_verifier();
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        // Don't approve measurement → each handshake fails.
        let client = test_client();
        let _ = do_full_handshake(&mut verifier, &client, &root, &measurement, 1000);
        let _ = do_full_handshake(&mut verifier, &client, &root, &measurement, 2000);
        let _ = do_full_handshake(&mut verifier, &client, &root, &measurement, 3000);

        assert_eq!(verifier.events().len(), 3);
        for (i, event) in verifier.events().iter().enumerate() {
            assert_eq!(event.seq, i as u64);
            assert_eq!(event.outcome, HandshakeOutcome::MeasurementRejected);
        }
    }

    #[test]
    fn challenge_validity_with_zero_deadline() {
        let verifier = test_verifier();
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 0).unwrap();
        // With zero deadline, only valid at exact timestamp.
        assert!(challenge.is_valid_at(1000));
        assert!(!challenge.is_valid_at(1001));
    }

    #[test]
    fn challenge_signature_is_non_empty() {
        let verifier = test_verifier();
        let challenge = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert!(
            !challenge.policy_plane_signature.is_empty(),
            "signature should be populated"
        );
    }

    #[test]
    fn authorization_canonical_bytes_sensitive_to_cell_id() {
        let root = test_trust_root();
        let measurement = test_measurement(&root);
        let mut verifier = test_verifier();
        verifier.approve_measurement(measurement.composite_hash());

        let c1 = test_client();
        let auth1 = do_full_handshake(&mut verifier, &c1, &root, &measurement, 1000).unwrap();
        let mut c2 = test_client();
        c2.cell_id = "cell-other".to_string();
        let auth2 = do_full_handshake(&mut verifier, &c2, &root, &measurement, 2000).unwrap();

        assert_ne!(auth1.canonical_bytes(), auth2.canonical_bytes());
    }

    #[test]
    fn advance_epoch_then_challenge_uses_new_epoch() {
        let mut verifier = test_verifier();
        let c1 = verifier.generate_challenge([1u8; 32], 1000, 500).unwrap();
        assert_eq!(c1.epoch, SecurityEpoch::from_raw(42));

        verifier.advance_epoch(SecurityEpoch::from_raw(100));
        let c2 = verifier.generate_challenge([1u8; 32], 2000, 500).unwrap();
        assert_eq!(c2.epoch, SecurityEpoch::from_raw(100));

        // Canonical bytes differ because epoch differs.
        assert_ne!(c1.canonical_bytes(), c2.canonical_bytes());
    }
}
