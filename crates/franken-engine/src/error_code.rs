use std::fmt;

use serde::{Deserialize, Serialize};

use crate::alloc_domain::AllocDomainError;
use crate::anti_entropy::ReconcileError;
use crate::bulkhead::BulkheadError;
use crate::cancel_mask::MaskError;
use crate::canonical_encoding::NonCanonicalError;
use crate::capability::CapabilityDenied;
use crate::capability_token::TokenError;
use crate::checkpoint_frontier::FrontierError;
use crate::deterministic_serde::SerdeError;
use crate::engine_object_id::IdError;
use crate::epoch_barrier::BarrierError;
use crate::eprocess_guardrail::GuardrailError;
use crate::evidence_contract::ContractValidationError;
use crate::evidence_ledger::LedgerError;
use crate::evidence_ordering::OrderingViolation;
use crate::fork_detection::ForkError;
use crate::gc::GcError;
use crate::idempotency_key::IdempotencyError;
use crate::key_derivation::KeyDerivationError;
use crate::lease_tracker::LeaseError;
use crate::marker_stream::ChainIntegrityError;
use crate::mmr_proof::ProofError;
use crate::monitor_scheduler::SchedulerError;
use crate::obligation_channel::ObligationError;
use crate::policy_checkpoint::CheckpointError;
use crate::policy_controller::PolicyControllerError;
use crate::proof_schema::ProofSchemaError;
use crate::recovery_artifact::VerificationError;
use crate::regime_detector::DetectorError;
use crate::region_lifecycle::PhaseOrderViolation;
use crate::remote_capability_gate::{RemoteCapabilityDenied, RemoteTransportError};
use crate::remote_computation_registry::RegistryError;
use crate::saga_orchestrator::SagaError;
use crate::scheduler_lane::LaneError;
use crate::security_epoch::{EpochValidationError, MonotonicityViolation};
use crate::signature_preimage::SignatureError;
use crate::slot_registry::SlotRegistryError;
use crate::sorted_multisig::MultiSigError;
use crate::{EvalError, EvalErrorCode};

pub const ERROR_CODE_REGISTRY_VERSION: u32 = 1;
pub const ERROR_CODE_COMPATIBILITY_POLICY: &str =
    "append-only: assigned codes are permanent, never reused, and may only be marked deprecated";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Critical,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSubsystem {
    SerializationEncoding,
    IdentityAuthentication,
    CapabilityAuthorization,
    CheckpointPolicy,
    Revocation,
    SessionChannel,
    ZoneScope,
    AuditObservability,
    LifecycleMigration,
    Reserved,
}

impl ErrorSubsystem {
    pub const fn includes(self, numeric: u16) -> bool {
        let (start, end) = self.range();
        numeric >= start && numeric <= end
    }

    pub const fn range(self) -> (u16, u16) {
        match self {
            Self::SerializationEncoding => (1, 999),
            Self::IdentityAuthentication => (1000, 1999),
            Self::CapabilityAuthorization => (2000, 2999),
            Self::CheckpointPolicy => (3000, 3999),
            Self::Revocation => (4000, 4999),
            Self::SessionChannel => (5000, 5999),
            Self::ZoneScope => (6000, 6999),
            Self::AuditObservability => (7000, 7999),
            Self::LifecycleMigration => (8000, 8999),
            Self::Reserved => (9000, 9999),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrankenErrorCode {
    NonCanonicalEncodingError = 1,
    DeterministicSerdeError = 2,

    EngineObjectIdError = 1000,
    SignatureVerificationError = 1001,
    MultiSigVerificationError = 1002,
    KeyDerivationFailure = 1003,

    CapabilityDeniedError = 2000,
    CapabilityTokenValidationError = 2001,
    RemoteCapabilityDeniedError = 2002,
    RemoteTransportExecutionError = 2003,
    ComputationRegistryError = 2004,
    CancelMaskPolicyError = 2005,

    PolicyCheckpointValidationError = 3000,
    CheckpointFrontierEnforcementError = 3001,
    ForkDetectionError = 3002,
    EpochWindowValidationError = 3003,
    EpochBarrierTransitionError = 3004,
    PolicyControllerDecisionError = 3005,
    AntiEntropyReconciliationError = 3006,

    RevocationChainIntegrityError = 4000,

    LeaseLifecycleError = 5000,
    ObligationChannelError = 5001,
    IdempotencyWorkflowError = 5002,
    SchedulerLaneAdmissionError = 5003,
    SagaExecutionError = 5004,
    BulkheadIsolationError = 5005,
    MonitorSchedulerError = 5006,

    AllocationDomainBudgetError = 6000,
    RegionPhaseOrderError = 6001,
    SlotRegistryAuthorityError = 6002,
    GarbageCollectionError = 6003,

    EvidenceContractError = 7000,
    EvidenceLedgerError = 7001,
    EvidenceOrderingError = 7002,
    MarkerStreamIntegrityError = 7003,
    MerkleProofVerificationError = 7004,
    RecoveryArtifactVerificationError = 7005,
    ProofSchemaValidationError = 7006,
    EprocessGuardrailError = 7007,
    RegimeDetectionError = 7008,
    EvalRuntimeError = 7009,

    EpochMonotonicityViolation = 8000,
}

pub const ALL_ERROR_CODES: &[FrankenErrorCode] = &[
    FrankenErrorCode::NonCanonicalEncodingError,
    FrankenErrorCode::DeterministicSerdeError,
    FrankenErrorCode::EngineObjectIdError,
    FrankenErrorCode::SignatureVerificationError,
    FrankenErrorCode::MultiSigVerificationError,
    FrankenErrorCode::KeyDerivationFailure,
    FrankenErrorCode::CapabilityDeniedError,
    FrankenErrorCode::CapabilityTokenValidationError,
    FrankenErrorCode::RemoteCapabilityDeniedError,
    FrankenErrorCode::RemoteTransportExecutionError,
    FrankenErrorCode::ComputationRegistryError,
    FrankenErrorCode::CancelMaskPolicyError,
    FrankenErrorCode::PolicyCheckpointValidationError,
    FrankenErrorCode::CheckpointFrontierEnforcementError,
    FrankenErrorCode::ForkDetectionError,
    FrankenErrorCode::EpochWindowValidationError,
    FrankenErrorCode::EpochBarrierTransitionError,
    FrankenErrorCode::PolicyControllerDecisionError,
    FrankenErrorCode::AntiEntropyReconciliationError,
    FrankenErrorCode::RevocationChainIntegrityError,
    FrankenErrorCode::LeaseLifecycleError,
    FrankenErrorCode::ObligationChannelError,
    FrankenErrorCode::IdempotencyWorkflowError,
    FrankenErrorCode::SchedulerLaneAdmissionError,
    FrankenErrorCode::SagaExecutionError,
    FrankenErrorCode::BulkheadIsolationError,
    FrankenErrorCode::MonitorSchedulerError,
    FrankenErrorCode::AllocationDomainBudgetError,
    FrankenErrorCode::RegionPhaseOrderError,
    FrankenErrorCode::SlotRegistryAuthorityError,
    FrankenErrorCode::GarbageCollectionError,
    FrankenErrorCode::EvidenceContractError,
    FrankenErrorCode::EvidenceLedgerError,
    FrankenErrorCode::EvidenceOrderingError,
    FrankenErrorCode::MarkerStreamIntegrityError,
    FrankenErrorCode::MerkleProofVerificationError,
    FrankenErrorCode::RecoveryArtifactVerificationError,
    FrankenErrorCode::ProofSchemaValidationError,
    FrankenErrorCode::EprocessGuardrailError,
    FrankenErrorCode::RegimeDetectionError,
    FrankenErrorCode::EvalRuntimeError,
    FrankenErrorCode::EpochMonotonicityViolation,
];

impl FrankenErrorCode {
    pub const fn numeric(self) -> u16 {
        self as u16
    }

    pub fn stable_code(self) -> String {
        format!("FE-{:04}", self.numeric())
    }

    pub const fn subsystem(self) -> ErrorSubsystem {
        match self.numeric() {
            1..=999 => ErrorSubsystem::SerializationEncoding,
            1000..=1999 => ErrorSubsystem::IdentityAuthentication,
            2000..=2999 => ErrorSubsystem::CapabilityAuthorization,
            3000..=3999 => ErrorSubsystem::CheckpointPolicy,
            4000..=4999 => ErrorSubsystem::Revocation,
            5000..=5999 => ErrorSubsystem::SessionChannel,
            6000..=6999 => ErrorSubsystem::ZoneScope,
            7000..=7999 => ErrorSubsystem::AuditObservability,
            8000..=8999 => ErrorSubsystem::LifecycleMigration,
            _ => ErrorSubsystem::Reserved,
        }
    }

    pub const fn severity(self) -> ErrorSeverity {
        match self {
            Self::PolicyCheckpointValidationError
            | Self::CheckpointFrontierEnforcementError
            | Self::ForkDetectionError
            | Self::RevocationChainIntegrityError
            | Self::EpochMonotonicityViolation => ErrorSeverity::Critical,
            _ => ErrorSeverity::Error,
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::NonCanonicalEncodingError => {
                "Canonical encoding guard rejected non-canonical input."
            }
            Self::DeterministicSerdeError => {
                "Deterministic serializer/deserializer rejected invalid or unstable payload."
            }
            Self::EngineObjectIdError => {
                "Engine object identity derivation or verification failed."
            }
            Self::SignatureVerificationError => {
                "Signature preimage generation or verification failed."
            }
            Self::MultiSigVerificationError => {
                "Multi-signature validation failed due to ordering, quorum, or signature errors."
            }
            Self::KeyDerivationFailure => "Key derivation request failed validation or execution.",
            Self::CapabilityDeniedError => {
                "Capability check denied operation due to insufficient privileges."
            }
            Self::CapabilityTokenValidationError => {
                "Capability token validation failed for signature, audience, temporal, or binding checks."
            }
            Self::RemoteCapabilityDeniedError => {
                "Remote operation denied by capability gate policy."
            }
            Self::RemoteTransportExecutionError => {
                "Remote transport execution failed due to connectivity, timeout, or remote failure."
            }
            Self::ComputationRegistryError => {
                "Remote computation registry rejected registration, lookup, or version/capability checks."
            }
            Self::CancelMaskPolicyError => {
                "Cancellation mask policy rejected operation or lifecycle transition."
            }
            Self::PolicyCheckpointValidationError => {
                "Policy checkpoint validation failed for chain, quorum, sequence, or epoch invariants."
            }
            Self::CheckpointFrontierEnforcementError => {
                "Checkpoint frontier enforcement rejected rollback, linkage, quorum, or persistence operation."
            }
            Self::ForkDetectionError => {
                "Fork detection pipeline identified divergence or safe-mode policy violation."
            }
            Self::EpochWindowValidationError => "Security epoch validity window check failed.",
            Self::EpochBarrierTransitionError => {
                "Epoch barrier transition failed due to monotonicity, guard drain, or transition state."
            }
            Self::PolicyControllerDecisionError => {
                "Policy controller could not produce or emit a valid decision artifact."
            }
            Self::AntiEntropyReconciliationError => {
                "Anti-entropy reconciliation failed verification, peel, or epoch consistency checks."
            }
            Self::RevocationChainIntegrityError => {
                "Revocation chain integrity or sequencing verification failed."
            }
            Self::LeaseLifecycleError => {
                "Lease lifecycle operation failed due to state, epoch, or input constraints."
            }
            Self::ObligationChannelError => {
                "Obligation channel operation failed due to lookup, state, or backpressure constraints."
            }
            Self::IdempotencyWorkflowError => {
                "Idempotency workflow rejected key lifecycle transition or retry policy."
            }
            Self::SchedulerLaneAdmissionError => {
                "Scheduler lane admission or lookup failed due to lane policy or queue state."
            }
            Self::SagaExecutionError => {
                "Saga orchestration rejected transition, compensation, or lifecycle request."
            }
            Self::BulkheadIsolationError => {
                "Bulkhead isolation system rejected permit, queue, or configuration request."
            }
            Self::MonitorSchedulerError => {
                "Monitor scheduler rejected probe registration or retrieval request."
            }
            Self::AllocationDomainBudgetError => {
                "Allocation domain budget accounting rejected request or detected overflow."
            }
            Self::RegionPhaseOrderError => {
                "Region lifecycle phase transition violated strict ordering contract."
            }
            Self::SlotRegistryAuthorityError => {
                "Slot registry authority or transition invariants were violated."
            }
            Self::GarbageCollectionError => {
                "GC subsystem rejected heap/object operation or propagated allocation-domain error."
            }
            Self::EvidenceContractError => {
                "Evidence contract failed semantic validation requirements."
            }
            Self::EvidenceLedgerError => {
                "Evidence ledger rejected entry due to schema, version, or identity constraints."
            }
            Self::EvidenceOrderingError => {
                "Evidence ordering validation failed canonical ordering or bounded-size invariants."
            }
            Self::MarkerStreamIntegrityError => {
                "Marker stream integrity verification failed linkage or monotonicity checks."
            }
            Self::MerkleProofVerificationError => {
                "Merkle proof verification failed root, structure, or consistency checks."
            }
            Self::RecoveryArtifactVerificationError => {
                "Recovery artifact verification failed content identity, signature, or proof requirements."
            }
            Self::ProofSchemaValidationError => {
                "Proof schema artifact failed version, signature, authorization, or epoch checks."
            }
            Self::EprocessGuardrailError => {
                "E-process guardrail rejected update/reset due to state or authorization constraints."
            }
            Self::RegimeDetectionError => {
                "Regime detector rejected observation or metric-stream configuration."
            }
            Self::EvalRuntimeError => "Runtime eval lane rejected request due to invalid input.",
            Self::EpochMonotonicityViolation => {
                "Security epoch monotonicity violation detected (attempted regression)."
            }
        }
    }

    pub const fn operator_action(self) -> &'static str {
        match self {
            Self::NonCanonicalEncodingError => {
                "Reject payload, log trace_id, and re-emit canonical bytes from trusted source."
            }
            Self::DeterministicSerdeError => {
                "Inspect schema hash and payload source; replay with deterministic fixtures."
            }
            Self::EngineObjectIdError => {
                "Recompute canonical preimage and verify schema/domain bindings before retry."
            }
            Self::SignatureVerificationError => {
                "Rotate/verify keys and re-check canonical unsigned view before accepting input."
            }
            Self::MultiSigVerificationError => {
                "Audit signer ordering/quorum policy and re-run signature verification pipeline."
            }
            Self::KeyDerivationFailure => {
                "Validate key material, epoch binding, and requested output parameters."
            }
            Self::CapabilityDeniedError => {
                "Review caller profile and grant only minimal required capabilities."
            }
            Self::CapabilityTokenValidationError => {
                "Reissue token with correct audience/time/checkpoint bindings and verify signer trust."
            }
            Self::RemoteCapabilityDeniedError => {
                "Review remote operation policy and elevate capability only via approved process."
            }
            Self::RemoteTransportExecutionError => {
                "Inspect endpoint health, timeout budgets, and remote service error telemetry."
            }
            Self::ComputationRegistryError => {
                "Re-validate computation metadata, schema versions, and registration policy inputs."
            }
            Self::CancelMaskPolicyError => {
                "Correct operation allowlist configuration and ensure mask lifecycle is valid."
            }
            Self::PolicyCheckpointValidationError => {
                "Enter safe mode, halt advancement, and investigate quorum/chain/epoch evidence."
            }
            Self::CheckpointFrontierEnforcementError => {
                "Reject offered checkpoint, retain frontier, and audit linkage/quorum proofs."
            }
            Self::ForkDetectionError => {
                "Keep safe mode active until incident is acknowledged and resolved with signed evidence."
            }
            Self::EpochWindowValidationError => {
                "Verify epoch clocks and artifact validity bounds; reject future/expired artifacts."
            }
            Self::EpochBarrierTransitionError => {
                "Drain outstanding guards and retry transition with strictly increasing epoch."
            }
            Self::PolicyControllerDecisionError => {
                "Restore valid action/loss configuration and confirm evidence emission path health."
            }
            Self::AntiEntropyReconciliationError => {
                "Re-run reconciliation with matched IBLT sizes and validated remote snapshot epoch."
            }
            Self::RevocationChainIntegrityError => {
                "Treat as security incident; freeze writes and rebuild head from trusted chain evidence."
            }
            Self::LeaseLifecycleError => {
                "Inspect lease state machine, epoch, and TTL input before retrying operation."
            }
            Self::ObligationChannelError => {
                "Resolve or drain pending obligations and verify caller lifecycle sequencing."
            }
            Self::IdempotencyWorkflowError => {
                "Check key epoch/retry policy and ensure idempotency record lifecycle is consistent."
            }
            Self::SchedulerLaneAdmissionError => {
                "Fix lane declaration/trace metadata and relieve queue pressure before resubmission."
            }
            Self::SagaExecutionError => {
                "Inspect saga state transitions and compensation logs; resume from deterministic checkpoint."
            }
            Self::BulkheadIsolationError => {
                "Tune bulkhead capacity/queue configuration and inspect permit lifecycle traces."
            }
            Self::MonitorSchedulerError => {
                "Repair probe registration catalog and verify deterministic probe identifiers."
            }
            Self::AllocationDomainBudgetError => {
                "Audit domain budget allocation and adjust limits without violating ceilings."
            }
            Self::RegionPhaseOrderError => {
                "Enforce correct region phase ordering and retry transition from valid state."
            }
            Self::SlotRegistryAuthorityError => {
                "Review slot authority graph and deny broadening transitions without proof."
            }
            Self::GarbageCollectionError => {
                "Verify heap registration/object ownership and resolve allocation-domain root cause."
            }
            Self::EvidenceContractError => {
                "Correct evidence contract fields/tiering and rerun validation before publication."
            }
            Self::EvidenceLedgerError => {
                "Repair ledger entry schema/version mismatch and deduplicate conflicting entry IDs."
            }
            Self::EvidenceOrderingError => {
                "Canonicalize and bound evidence lists before signing or persisting artifacts."
            }
            Self::MarkerStreamIntegrityError => {
                "Stop chain consumption and rebuild marker stream from last trusted checkpoint."
            }
            Self::MerkleProofVerificationError => {
                "Regenerate proof against trusted root and verify stream consistency history."
            }
            Self::RecoveryArtifactVerificationError => {
                "Reject artifact and collect full proof bundle/signature set for forensic replay."
            }
            Self::ProofSchemaValidationError => {
                "Correct schema version/signer role/epoch data and regenerate proof artifact."
            }
            Self::EprocessGuardrailError => {
                "Investigate guardrail state and require authorized reset evidence before change."
            }
            Self::RegimeDetectionError => {
                "Validate observation bounds and metric-stream configuration before ingestion."
            }
            Self::EvalRuntimeError => {
                "Reject invalid source input and require non-empty canonical source text."
            }
            Self::EpochMonotonicityViolation => {
                "Escalate incident, block regressive epoch writes, and recover from trusted snapshot."
            }
        }
    }

    pub const fn deprecated(self) -> bool {
        false
    }

    pub fn from_numeric(numeric: u16) -> Option<Self> {
        ALL_ERROR_CODES
            .iter()
            .copied()
            .find(|candidate| candidate.numeric() == numeric)
    }

    pub fn to_registry_entry(self) -> ErrorCodeEntry {
        ErrorCodeEntry {
            code: self.stable_code(),
            numeric: self.numeric(),
            subsystem: self.subsystem(),
            severity: self.severity(),
            description: self.description().to_string(),
            operator_action: self.operator_action().to_string(),
            deprecated: self.deprecated(),
        }
    }
}

impl fmt::Display for FrankenErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.stable_code())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCodeEntry {
    pub code: String,
    pub numeric: u16,
    pub subsystem: ErrorSubsystem,
    pub severity: ErrorSeverity,
    pub description: String,
    pub operator_action: String,
    pub deprecated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCodeRegistry {
    pub version: u32,
    pub compatibility_policy: String,
    pub entries: Vec<ErrorCodeEntry>,
}

pub fn error_code_registry() -> ErrorCodeRegistry {
    ErrorCodeRegistry {
        version: ERROR_CODE_REGISTRY_VERSION,
        compatibility_policy: ERROR_CODE_COMPATIBILITY_POLICY.to_string(),
        entries: ALL_ERROR_CODES
            .iter()
            .copied()
            .map(FrankenErrorCode::to_registry_entry)
            .collect(),
    }
}

pub trait HasErrorCode {
    fn error_code(&self) -> FrankenErrorCode;
}

impl HasErrorCode for NonCanonicalError {
    fn error_code(&self) -> FrankenErrorCode {
        FrankenErrorCode::NonCanonicalEncodingError
    }
}

impl HasErrorCode for SerdeError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            SerdeError::SchemaMismatch { .. }
            | SerdeError::UnknownSchema { .. }
            | SerdeError::BufferTooShort { .. }
            | SerdeError::InvalidTag { .. }
            | SerdeError::InvalidBoolEncoding { .. }
            | SerdeError::InvalidUtf8 { .. }
            | SerdeError::DuplicateKey { .. }
            | SerdeError::NonLexicographicKeys { .. }
            | SerdeError::TrailingBytes { .. }
            | SerdeError::RecursionLimitExceeded { .. } => {
                FrankenErrorCode::DeterministicSerdeError
            }
        }
    }
}

impl HasErrorCode for IdError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            IdError::EmptyCanonicalBytes
            | IdError::IdMismatch { .. }
            | IdError::NonCanonicalInput { .. }
            | IdError::InvalidHexLength { .. }
            | IdError::InvalidHexChar { .. } => FrankenErrorCode::EngineObjectIdError,
        }
    }
}

impl HasErrorCode for SignatureError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            SignatureError::VerificationFailed { .. }
            | SignatureError::NonCanonicalObject { .. }
            | SignatureError::PreimageError { .. }
            | SignatureError::InvalidSigningKey
            | SignatureError::InvalidVerificationKey => {
                FrankenErrorCode::SignatureVerificationError
            }
        }
    }
}

impl HasErrorCode for MultiSigError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            MultiSigError::UnsortedSignatureArray { .. }
            | MultiSigError::DuplicateSignerKey { .. }
            | MultiSigError::QuorumNotMet { .. }
            | MultiSigError::EmptyArray
            | MultiSigError::ZeroQuorumThreshold
            | MultiSigError::ThresholdExceedsSignerCount { .. }
            | MultiSigError::SignatureError { .. } => FrankenErrorCode::MultiSigVerificationError,
        }
    }
}

impl HasErrorCode for KeyDerivationError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            KeyDerivationError::EmptyMasterKey
            | KeyDerivationError::ZeroOutputLength
            | KeyDerivationError::OutputTooLong { .. }
            | KeyDerivationError::EpochMismatch { .. }
            | KeyDerivationError::DerivationFailed { .. } => FrankenErrorCode::KeyDerivationFailure,
        }
    }
}

impl HasErrorCode for CapabilityDenied {
    fn error_code(&self) -> FrankenErrorCode {
        FrankenErrorCode::CapabilityDeniedError
    }
}

impl HasErrorCode for TokenError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            TokenError::SignatureInvalid { .. }
            | TokenError::NonCanonical { .. }
            | TokenError::AudienceRejected { .. }
            | TokenError::NotYetValid { .. }
            | TokenError::Expired { .. }
            | TokenError::CheckpointBindingFailed { .. }
            | TokenError::RevocationFreshnessStale { .. }
            | TokenError::UnsupportedVersion { .. }
            | TokenError::IdDerivationFailed { .. }
            | TokenError::InvertedTemporalWindow { .. }
            | TokenError::EmptyCapabilities
            | TokenError::EmptyAudience => FrankenErrorCode::CapabilityTokenValidationError,
        }
    }
}

impl HasErrorCode for RemoteCapabilityDenied {
    fn error_code(&self) -> FrankenErrorCode {
        FrankenErrorCode::RemoteCapabilityDeniedError
    }
}

impl HasErrorCode for RemoteTransportError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            RemoteTransportError::ConnectionFailed { .. }
            | RemoteTransportError::RemoteError { .. }
            | RemoteTransportError::Timeout { .. }
            | RemoteTransportError::CapabilityDenied(_) => {
                FrankenErrorCode::RemoteTransportExecutionError
            }
        }
    }
}

impl HasErrorCode for RegistryError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            RegistryError::InvalidComputationName { .. }
            | RegistryError::DuplicateRegistration { .. }
            | RegistryError::ComputationNotFound { .. }
            | RegistryError::SchemaValidationFailed { .. }
            | RegistryError::CapabilityDenied { .. }
            | RegistryError::VersionIncompatible { .. }
            | RegistryError::ClosureRejected { .. }
            | RegistryError::HotRegistrationDenied { .. } => {
                FrankenErrorCode::ComputationRegistryError
            }
        }
    }
}

impl HasErrorCode for MaskError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            MaskError::NestingDenied
            | MaskError::OperationNotAllowed { .. }
            | MaskError::AlreadyReleased => FrankenErrorCode::CancelMaskPolicyError,
        }
    }
}

impl HasErrorCode for CheckpointError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            CheckpointError::GenesisMustHaveNoPredecessor
            | CheckpointError::MissingPredecessor
            | CheckpointError::NonMonotonicSequence { .. }
            | CheckpointError::GenesisSequenceNotZero { .. }
            | CheckpointError::ChainLinkageBroken { .. }
            | CheckpointError::EmptyPolicyHeads
            | CheckpointError::QuorumNotMet { .. }
            | CheckpointError::DuplicatePolicyType { .. }
            | CheckpointError::IdDerivationFailed { .. }
            | CheckpointError::EpochRegression { .. }
            | CheckpointError::SignatureInvalid { .. } => {
                FrankenErrorCode::PolicyCheckpointValidationError
            }
        }
    }
}

impl HasErrorCode for FrontierError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            FrontierError::RollbackRejected { .. }
            | FrontierError::DuplicateCheckpoint { .. }
            | FrontierError::ChainLinkageFailure { .. }
            | FrontierError::QuorumFailure { .. }
            | FrontierError::UnknownZone { .. }
            | FrontierError::EpochRegression { .. }
            | FrontierError::PersistenceFailed { .. } => {
                FrankenErrorCode::CheckpointFrontierEnforcementError
            }
        }
    }
}

impl HasErrorCode for ForkError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ForkError::ForkDetected { .. }
            | ForkError::SafeModeActive { .. }
            | ForkError::AcknowledgmentRequired { .. }
            | ForkError::InvalidResolution { .. }
            | ForkError::PersistenceFailed { .. } => FrankenErrorCode::ForkDetectionError,
        }
    }
}

impl HasErrorCode for EpochValidationError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            EpochValidationError::NotYetValid { .. }
            | EpochValidationError::Expired { .. }
            | EpochValidationError::FutureArtifact { .. }
            | EpochValidationError::InvertedWindow { .. } => {
                FrankenErrorCode::EpochWindowValidationError
            }
        }
    }
}

impl HasErrorCode for BarrierError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            BarrierError::EpochTransitioning { .. }
            | BarrierError::TransitionAlreadyInProgress { .. }
            | BarrierError::DrainTimeout { .. }
            | BarrierError::NoTransitionInProgress
            | BarrierError::NonMonotonicTransition { .. } => {
                FrankenErrorCode::EpochBarrierTransitionError
            }
        }
    }
}

impl HasErrorCode for PolicyControllerError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            PolicyControllerError::EmptyActionSet
            | PolicyControllerError::NoLossEntries
            | PolicyControllerError::SafeDefaultNotInActionSet { .. }
            | PolicyControllerError::EvidenceEmissionFailed { .. } => {
                FrankenErrorCode::PolicyControllerDecisionError
            }
        }
    }
}

impl HasErrorCode for ReconcileError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ReconcileError::IbltSizeMismatch { .. }
            | ReconcileError::PeelFailed { .. }
            | ReconcileError::EpochMismatch { .. }
            | ReconcileError::VerificationFailed { .. }
            | ReconcileError::EmptyObjectSet => FrankenErrorCode::AntiEntropyReconciliationError,
        }
    }
}

impl HasErrorCode for LeaseError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            LeaseError::LeaseNotFound { .. }
            | LeaseError::LeaseExpired { .. }
            | LeaseError::LeaseReleased { .. }
            | LeaseError::EpochMismatch { .. }
            | LeaseError::ZeroTtl
            | LeaseError::EmptyHolder => FrankenErrorCode::LeaseLifecycleError,
        }
    }
}

impl HasErrorCode for ObligationError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ObligationError::NotFound { .. }
            | ObligationError::AlreadyResolved { .. }
            | ObligationError::Backpressure { .. }
            | ObligationError::Leaked { .. } => FrankenErrorCode::ObligationChannelError,
        }
    }
}

impl HasErrorCode for IdempotencyError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            IdempotencyError::EpochMismatch { .. }
            | IdempotencyError::MaxRetriesExceeded { .. }
            | IdempotencyError::DuplicateInProgress { .. }
            | IdempotencyError::EntryNotFound { .. } => FrankenErrorCode::IdempotencyWorkflowError,
        }
    }
}

impl HasErrorCode for LaneError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            LaneError::LaneMismatch { .. }
            | LaneError::LaneFull { .. }
            | LaneError::TaskNotFound { .. }
            | LaneError::EmptyTraceId => FrankenErrorCode::SchedulerLaneAdmissionError,
        }
    }
}

impl HasErrorCode for SagaError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            SagaError::SagaNotFound { .. }
            | SagaError::SagaAlreadyTerminal { .. }
            | SagaError::StepIndexOutOfBounds { .. }
            | SagaError::EpochMismatch { .. }
            | SagaError::EmptySteps
            | SagaError::InvalidSagaId { .. }
            | SagaError::CompensationFailed { .. }
            | SagaError::ConcurrencyLimitReached { .. }
            | SagaError::SagaAlreadyExists { .. } => FrankenErrorCode::SagaExecutionError,
        }
    }
}

impl HasErrorCode for BulkheadError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            BulkheadError::BulkheadFull { .. }
            | BulkheadError::PermitNotFound { .. }
            | BulkheadError::BulkheadNotFound { .. }
            | BulkheadError::InvalidConfig { .. } => FrankenErrorCode::BulkheadIsolationError,
        }
    }
}

impl HasErrorCode for SchedulerError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            SchedulerError::DuplicateProbe { .. } | SchedulerError::ProbeNotFound { .. } => {
                FrankenErrorCode::MonitorSchedulerError
            }
        }
    }
}

impl HasErrorCode for AllocDomainError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            AllocDomainError::BudgetExceeded { .. }
            | AllocDomainError::BudgetOverflow
            | AllocDomainError::DomainNotFound { .. }
            | AllocDomainError::DuplicateDomain { .. } => {
                FrankenErrorCode::AllocationDomainBudgetError
            }
        }
    }
}

impl HasErrorCode for PhaseOrderViolation {
    fn error_code(&self) -> FrankenErrorCode {
        FrankenErrorCode::RegionPhaseOrderError
    }
}

impl HasErrorCode for SlotRegistryError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            SlotRegistryError::InvalidSlotId { .. }
            | SlotRegistryError::DuplicateSlotId { .. }
            | SlotRegistryError::SlotNotFound { .. }
            | SlotRegistryError::InconsistentAuthority { .. }
            | SlotRegistryError::InvalidTransition { .. }
            | SlotRegistryError::AuthorityBroadening { .. } => {
                FrankenErrorCode::SlotRegistryAuthorityError
            }
        }
    }
}

impl HasErrorCode for GcError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            GcError::HeapNotFound { .. }
            | GcError::DuplicateHeap { .. }
            | GcError::ObjectNotFound { .. }
            | GcError::DomainError(_) => FrankenErrorCode::GarbageCollectionError,
        }
    }
}

impl HasErrorCode for ContractValidationError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ContractValidationError::MissingField { .. }
            | ContractValidationError::EvBelowThreshold { .. }
            | ContractValidationError::EvTierMismatch { .. }
            | ContractValidationError::EmptyRolloutStages
            | ContractValidationError::InvalidRolloutOrder { .. }
            | ContractValidationError::IncompatibleVersion { .. }
            | ContractValidationError::InvalidEvScore => FrankenErrorCode::EvidenceContractError,
        }
    }
}

impl HasErrorCode for LedgerError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            LedgerError::MissingChosenAction
            | LedgerError::SchemaValidationFailed { .. }
            | LedgerError::IncompatibleSchema { .. }
            | LedgerError::DuplicateEntryId { .. } => FrankenErrorCode::EvidenceLedgerError,
        }
    }
}

impl HasErrorCode for OrderingViolation {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            OrderingViolation::CandidatesNotSorted { .. }
            | OrderingViolation::WitnessesNotSorted { .. }
            | OrderingViolation::ConstraintsNotSorted { .. }
            | OrderingViolation::DuplicateWitnessId { .. }
            | OrderingViolation::CandidatesExceedBound { .. }
            | OrderingViolation::WitnessesExceedBound { .. }
            | OrderingViolation::ConstraintsExceedBound { .. } => {
                FrankenErrorCode::EvidenceOrderingError
            }
        }
    }
}

impl HasErrorCode for ChainIntegrityError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ChainIntegrityError::MarkerHashMismatch { .. }
            | ChainIntegrityError::ChainLinkBroken { .. }
            | ChainIntegrityError::EmptyStream
            | ChainIntegrityError::NonMonotonicId { .. }
            | ChainIntegrityError::HeadMismatch => FrankenErrorCode::MarkerStreamIntegrityError,
        }
    }
}

impl HasErrorCode for ProofError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ProofError::IndexOutOfRange { .. }
            | ProofError::RootMismatch { .. }
            | ProofError::InvalidProof { .. }
            | ProofError::EmptyStream
            | ProofError::ConsistencyFailure { .. } => {
                FrankenErrorCode::MerkleProofVerificationError
            }
        }
    }
}

impl HasErrorCode for VerificationError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            VerificationError::ArtifactIdMismatch { .. }
            | VerificationError::SignatureInvalid { .. }
            | VerificationError::EmptyProofBundle
            | VerificationError::MissingProofElement { .. } => {
                FrankenErrorCode::RecoveryArtifactVerificationError
            }
        }
    }
}

impl HasErrorCode for ProofSchemaError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            ProofSchemaError::InvalidSignature { .. }
            | ProofSchemaError::IncompatibleVersion { .. }
            | ProofSchemaError::TokenExpired { .. }
            | ProofSchemaError::MissingField { .. }
            | ProofSchemaError::NonEquivalent { .. }
            | ProofSchemaError::UnauthorizedSigner { .. }
            | ProofSchemaError::EpochMismatch { .. }
            | ProofSchemaError::MissingAttestationBindings { .. }
            | ProofSchemaError::UnexpectedAttestationBindingsForVersion { .. }
            | ProofSchemaError::InvalidAttestationBindings { .. }
            | ProofSchemaError::NonceReplay { .. } => FrankenErrorCode::ProofSchemaValidationError,
        }
    }
}

impl HasErrorCode for GuardrailError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            GuardrailError::Suspended { .. }
            | GuardrailError::AlreadyTriggered { .. }
            | GuardrailError::InvalidObservation { .. }
            | GuardrailError::ResetUnauthorized { .. }
            | GuardrailError::NotTriggered { .. }
            | GuardrailError::EValueOverflow { .. } => FrankenErrorCode::EprocessGuardrailError,
        }
    }
}

impl HasErrorCode for DetectorError {
    fn error_code(&self) -> FrankenErrorCode {
        match self {
            DetectorError::InvalidObservation { .. }
            | DetectorError::UnknownMetricStream { .. } => FrankenErrorCode::RegimeDetectionError,
        }
    }
}

impl HasErrorCode for EvalError {
    fn error_code(&self) -> FrankenErrorCode {
        match self.code {
            EvalErrorCode::EmptySource
            | EvalErrorCode::ParseFailure
            | EvalErrorCode::ResolutionFailure
            | EvalErrorCode::PolicyDenied
            | EvalErrorCode::CapabilityDenied
            | EvalErrorCode::RuntimeFault
            | EvalErrorCode::HostcallFault
            | EvalErrorCode::InvariantViolation => FrankenErrorCode::EvalRuntimeError,
        }
    }
}

impl HasErrorCode for MonotonicityViolation {
    fn error_code(&self) -> FrankenErrorCode {
        FrankenErrorCode::EpochMonotonicityViolation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn assert_has_error_code<T: HasErrorCode>() {}

    #[test]
    fn all_registered_codes_follow_fe_xxxx_format_and_are_unique() {
        let mut seen_numeric = BTreeSet::new();
        let mut seen_codes = BTreeSet::new();

        for code in ALL_ERROR_CODES {
            let stable = code.stable_code();
            assert!(stable.starts_with("FE-"));
            assert_eq!(stable.len(), 7);
            assert!(stable.chars().skip(3).all(|ch| ch.is_ascii_digit()));
            assert!(seen_numeric.insert(code.numeric()));
            assert!(seen_codes.insert(stable));
        }
    }

    #[test]
    fn registry_entries_respect_subsystem_numeric_ranges() {
        let registry = error_code_registry();
        for entry in &registry.entries {
            assert!(entry.subsystem.includes(entry.numeric));
        }
    }

    #[test]
    fn registry_serializes_and_roundtrips_as_machine_readable_json() {
        let registry = error_code_registry();
        let encoded = serde_json::to_string_pretty(&registry).expect("encode registry json");
        let decoded: ErrorCodeRegistry = serde_json::from_str(&encoded).expect("decode registry");
        assert_eq!(decoded, registry);
    }

    #[test]
    fn all_error_types_implement_has_error_code() {
        assert_has_error_code::<AllocDomainError>();
        assert_has_error_code::<BarrierError>();
        assert_has_error_code::<BulkheadError>();
        assert_has_error_code::<CapabilityDenied>();
        assert_has_error_code::<ChainIntegrityError>();
        assert_has_error_code::<CheckpointError>();
        assert_has_error_code::<ContractValidationError>();
        assert_has_error_code::<DetectorError>();
        assert_has_error_code::<EpochValidationError>();
        assert_has_error_code::<EvalError>();
        assert_has_error_code::<ForkError>();
        assert_has_error_code::<FrontierError>();
        assert_has_error_code::<GcError>();
        assert_has_error_code::<GuardrailError>();
        assert_has_error_code::<IdError>();
        assert_has_error_code::<IdempotencyError>();
        assert_has_error_code::<KeyDerivationError>();
        assert_has_error_code::<LaneError>();
        assert_has_error_code::<LeaseError>();
        assert_has_error_code::<LedgerError>();
        assert_has_error_code::<MaskError>();
        assert_has_error_code::<MonotonicityViolation>();
        assert_has_error_code::<MultiSigError>();
        assert_has_error_code::<NonCanonicalError>();
        assert_has_error_code::<ObligationError>();
        assert_has_error_code::<OrderingViolation>();
        assert_has_error_code::<PhaseOrderViolation>();
        assert_has_error_code::<PolicyControllerError>();
        assert_has_error_code::<ProofError>();
        assert_has_error_code::<ProofSchemaError>();
        assert_has_error_code::<ReconcileError>();
        assert_has_error_code::<RecoveryErrorAlias>();
        assert_has_error_code::<RegistryError>();
        assert_has_error_code::<RemoteCapabilityDenied>();
        assert_has_error_code::<RemoteTransportError>();
        assert_has_error_code::<SagaError>();
        assert_has_error_code::<SchedulerError>();
        assert_has_error_code::<SerdeError>();
        assert_has_error_code::<SignatureError>();
        assert_has_error_code::<SlotRegistryError>();
        assert_has_error_code::<TokenError>();
        assert_has_error_code::<VerificationError>();
    }

    type RecoveryErrorAlias = VerificationError;

    #[test]
    fn representative_error_instances_map_to_expected_codes() {
        let token_error = TokenError::EmptyCapabilities;
        assert_eq!(
            token_error.error_code(),
            FrankenErrorCode::CapabilityTokenValidationError
        );

        let eval_error = EvalError {
            code: EvalErrorCode::EmptySource,
            message: "source is empty".to_string(),
            correlation_ids: None,
            location: None,
            stack_frames: Vec::new(),
        };
        assert_eq!(eval_error.error_code(), FrankenErrorCode::EvalRuntimeError);

        assert_eq!(
            FrankenErrorCode::from_numeric(3000),
            Some(FrankenErrorCode::PolicyCheckpointValidationError)
        );
        assert_eq!(FrankenErrorCode::from_numeric(9999), None);
    }

    // -----------------------------------------------------------------------
    // ErrorSubsystem range coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_subsystem_ranges_are_non_overlapping_and_contiguous() {
        let subsystems = [
            ErrorSubsystem::SerializationEncoding,
            ErrorSubsystem::IdentityAuthentication,
            ErrorSubsystem::CapabilityAuthorization,
            ErrorSubsystem::CheckpointPolicy,
            ErrorSubsystem::Revocation,
            ErrorSubsystem::SessionChannel,
            ErrorSubsystem::ZoneScope,
            ErrorSubsystem::AuditObservability,
            ErrorSubsystem::LifecycleMigration,
            ErrorSubsystem::Reserved,
        ];
        let mut prev_end = 0u16;
        for sub in subsystems {
            let (start, end) = sub.range();
            assert_eq!(
                start,
                prev_end + 1,
                "gap between subsystem ranges at {sub:?}"
            );
            assert!(end >= start);
            prev_end = end;
        }
    }

    #[test]
    fn error_subsystem_includes_returns_true_for_boundary_values() {
        let sub = ErrorSubsystem::CapabilityAuthorization;
        let (start, end) = sub.range();
        assert!(sub.includes(start));
        assert!(sub.includes(end));
        assert!(!sub.includes(start - 1));
        assert!(!sub.includes(end + 1));
    }

    // -----------------------------------------------------------------------
    // FrankenErrorCode stable_code format
    // -----------------------------------------------------------------------

    #[test]
    fn stable_code_format_is_fe_four_digits() {
        for code in ALL_ERROR_CODES {
            let stable = code.stable_code();
            assert!(stable.starts_with("FE-"), "{stable} must start with FE-");
            let digits = &stable[3..];
            assert_eq!(
                digits.len(),
                4,
                "stable code {stable} must have 4-digit suffix"
            );
            assert!(digits.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn from_numeric_round_trips_all_codes() {
        for code in ALL_ERROR_CODES {
            let numeric = code.numeric();
            let recovered = FrankenErrorCode::from_numeric(numeric);
            assert_eq!(recovered, Some(*code), "round-trip failed for {code:?}");
        }
    }

    #[test]
    fn from_numeric_returns_none_for_unassigned_values() {
        assert_eq!(FrankenErrorCode::from_numeric(0), None);
        assert_eq!(FrankenErrorCode::from_numeric(999), None);
        assert_eq!(FrankenErrorCode::from_numeric(9999), None);
        assert_eq!(FrankenErrorCode::from_numeric(u16::MAX), None);
    }

    // -----------------------------------------------------------------------
    // Severity assignment
    // -----------------------------------------------------------------------

    #[test]
    fn critical_severity_codes_are_explicitly_listed() {
        let critical_codes = [
            FrankenErrorCode::PolicyCheckpointValidationError,
            FrankenErrorCode::CheckpointFrontierEnforcementError,
            FrankenErrorCode::ForkDetectionError,
            FrankenErrorCode::RevocationChainIntegrityError,
            FrankenErrorCode::EpochMonotonicityViolation,
        ];
        for code in critical_codes {
            assert_eq!(
                code.severity(),
                ErrorSeverity::Critical,
                "{code:?} must be Critical severity"
            );
        }
    }

    #[test]
    fn non_critical_codes_have_error_severity() {
        let non_critical = [
            FrankenErrorCode::NonCanonicalEncodingError,
            FrankenErrorCode::CapabilityDeniedError,
            FrankenErrorCode::EvalRuntimeError,
        ];
        for code in non_critical {
            assert_eq!(
                code.severity(),
                ErrorSeverity::Error,
                "{code:?} should be Error severity"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Description and operator_action non-empty
    // -----------------------------------------------------------------------

    #[test]
    fn every_code_has_non_empty_description_and_operator_action() {
        for code in ALL_ERROR_CODES {
            assert!(
                !code.description().is_empty(),
                "{code:?} has empty description"
            );
            assert!(
                !code.operator_action().is_empty(),
                "{code:?} has empty operator_action"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Deprecated flag
    // -----------------------------------------------------------------------

    #[test]
    fn no_codes_are_currently_deprecated() {
        for code in ALL_ERROR_CODES {
            assert!(!code.deprecated(), "{code:?} should not be deprecated yet");
        }
    }

    // -----------------------------------------------------------------------
    // Registry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_version_is_current() {
        let registry = error_code_registry();
        assert_eq!(registry.version, ERROR_CODE_REGISTRY_VERSION);
    }

    #[test]
    fn registry_has_all_codes() {
        let registry = error_code_registry();
        assert_eq!(registry.entries.len(), ALL_ERROR_CODES.len());
    }

    #[test]
    fn registry_entries_have_consistent_subsystem_mapping() {
        for code in ALL_ERROR_CODES {
            let entry = code.to_registry_entry();
            assert_eq!(entry.numeric, code.numeric());
            assert_eq!(entry.subsystem, code.subsystem());
            assert_eq!(entry.severity, code.severity());
            assert_eq!(entry.code, code.stable_code());
        }
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    #[test]
    fn display_matches_stable_code() {
        for code in ALL_ERROR_CODES {
            assert_eq!(format!("{code}"), code.stable_code());
        }
    }

    // -----------------------------------------------------------------------
    // ErrorSeverity serde
    // -----------------------------------------------------------------------

    #[test]
    fn error_severity_round_trips_through_serde() {
        for severity in [
            ErrorSeverity::Critical,
            ErrorSeverity::Error,
            ErrorSeverity::Warning,
            ErrorSeverity::Info,
        ] {
            let json = serde_json::to_string(&severity).expect("serialize");
            let decoded: ErrorSeverity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, severity);
        }
    }

    // -----------------------------------------------------------------------
    // ErrorSubsystem serde
    // -----------------------------------------------------------------------

    #[test]
    fn error_subsystem_round_trips_through_serde() {
        for sub in [
            ErrorSubsystem::SerializationEncoding,
            ErrorSubsystem::IdentityAuthentication,
            ErrorSubsystem::CapabilityAuthorization,
            ErrorSubsystem::CheckpointPolicy,
            ErrorSubsystem::Revocation,
            ErrorSubsystem::SessionChannel,
            ErrorSubsystem::ZoneScope,
            ErrorSubsystem::AuditObservability,
            ErrorSubsystem::LifecycleMigration,
            ErrorSubsystem::Reserved,
        ] {
            let json = serde_json::to_string(&sub).expect("serialize");
            let decoded: ErrorSubsystem = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, sub);
        }
    }

    // -----------------------------------------------------------------------
    // Numeric uniqueness (explicit)
    // -----------------------------------------------------------------------

    #[test]
    fn all_numeric_codes_are_strictly_positive() {
        for code in ALL_ERROR_CODES {
            assert!(code.numeric() > 0, "{code:?} has zero numeric code");
        }
    }

    #[test]
    fn all_codes_belong_to_their_stated_subsystem() {
        for code in ALL_ERROR_CODES {
            let sub = code.subsystem();
            assert!(
                sub.includes(code.numeric()),
                "{code:?} (numeric={}) not in subsystem {sub:?}",
                code.numeric()
            );
        }
    }

    // -----------------------------------------------------------------------
    // FrankenErrorCode serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn franken_error_code_serde_round_trip_all() {
        for code in ALL_ERROR_CODES {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: FrankenErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, *code, "serde round-trip failed for {code:?}");
        }
    }

    // -----------------------------------------------------------------------
    // ErrorSubsystem includes() midpoint values
    // -----------------------------------------------------------------------

    #[test]
    fn error_subsystem_includes_midpoint_of_each_range() {
        let subsystems = [
            (ErrorSubsystem::SerializationEncoding, 500),
            (ErrorSubsystem::IdentityAuthentication, 1500),
            (ErrorSubsystem::CapabilityAuthorization, 2500),
            (ErrorSubsystem::CheckpointPolicy, 3500),
            (ErrorSubsystem::Revocation, 4500),
            (ErrorSubsystem::SessionChannel, 5500),
            (ErrorSubsystem::ZoneScope, 6500),
            (ErrorSubsystem::AuditObservability, 7500),
            (ErrorSubsystem::LifecycleMigration, 8500),
            (ErrorSubsystem::Reserved, 9500),
        ];
        for (sub, mid) in subsystems {
            assert!(sub.includes(mid), "{sub:?} should include midpoint {mid}");
        }
    }

    #[test]
    fn error_subsystem_excludes_cross_boundary_values() {
        // IdentityAuthentication range is 1000-1999; 999 and 2000 should not be included
        let sub = ErrorSubsystem::IdentityAuthentication;
        assert!(!sub.includes(999));
        assert!(sub.includes(1000));
        assert!(sub.includes(1999));
        assert!(!sub.includes(2000));
    }

    // -----------------------------------------------------------------------
    // Concrete HasErrorCode invocations
    // -----------------------------------------------------------------------

    #[test]
    fn has_error_code_non_canonical_error() {
        use crate::canonical_encoding::CanonicalViolation;
        use crate::engine_object_id::ObjectDomain;
        let err = NonCanonicalError {
            object_class: ObjectDomain::PolicyObject,
            input_hash: [0u8; 32],
            violation: CanonicalViolation::DuplicateKey {
                key: "k".to_string(),
            },
            trace_id: "t-1".to_string(),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::NonCanonicalEncodingError
        );
    }

    #[test]
    fn has_error_code_serde_error() {
        let err = SerdeError::BufferTooShort {
            expected: 8,
            actual: 2,
        };
        assert_eq!(err.error_code(), FrankenErrorCode::DeterministicSerdeError);
    }

    #[test]
    fn has_error_code_id_error() {
        let err = IdError::EmptyCanonicalBytes;
        assert_eq!(err.error_code(), FrankenErrorCode::EngineObjectIdError);
    }

    #[test]
    fn has_error_code_signature_error() {
        let err = SignatureError::InvalidSigningKey;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::SignatureVerificationError
        );
    }

    #[test]
    fn has_error_code_multi_sig_error() {
        let err = MultiSigError::EmptyArray;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::MultiSigVerificationError
        );
    }

    #[test]
    fn has_error_code_key_derivation_error() {
        let err = KeyDerivationError::EmptyMasterKey;
        assert_eq!(err.error_code(), FrankenErrorCode::KeyDerivationFailure);
    }

    #[test]
    fn has_error_code_capability_denied() {
        use crate::capability::{ProfileKind, RuntimeCapability};
        let err = CapabilityDenied {
            required: RuntimeCapability::VmDispatch,
            held_profile: ProfileKind::Policy,
            component: "test".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::CapabilityDeniedError);
    }

    #[test]
    fn has_error_code_token_error() {
        let err = TokenError::EmptyCapabilities;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::CapabilityTokenValidationError
        );
    }

    #[test]
    fn has_error_code_token_error_empty_audience() {
        let err = TokenError::EmptyAudience;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::CapabilityTokenValidationError
        );
    }

    #[test]
    fn has_error_code_mask_error() {
        let err = MaskError::NestingDenied;
        assert_eq!(err.error_code(), FrankenErrorCode::CancelMaskPolicyError);
    }

    #[test]
    fn has_error_code_mask_error_already_released() {
        let err = MaskError::AlreadyReleased;
        assert_eq!(err.error_code(), FrankenErrorCode::CancelMaskPolicyError);
    }

    #[test]
    fn has_error_code_checkpoint_error() {
        let err = CheckpointError::EmptyPolicyHeads;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::PolicyCheckpointValidationError
        );
    }

    #[test]
    fn has_error_code_fork_error() {
        let err = ForkError::PersistenceFailed {
            detail: "disk full".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::ForkDetectionError);
    }

    #[test]
    fn has_error_code_barrier_error() {
        let err = BarrierError::NoTransitionInProgress;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::EpochBarrierTransitionError
        );
    }

    #[test]
    fn has_error_code_policy_controller_error() {
        let err = PolicyControllerError::EmptyActionSet;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::PolicyControllerDecisionError
        );
    }

    #[test]
    fn has_error_code_reconcile_error() {
        let err = ReconcileError::EmptyObjectSet;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::AntiEntropyReconciliationError
        );
    }

    #[test]
    fn has_error_code_chain_integrity_error() {
        let err = ChainIntegrityError::EmptyStream;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::MarkerStreamIntegrityError
        );
    }

    #[test]
    fn has_error_code_lease_error() {
        let err = LeaseError::ZeroTtl;
        assert_eq!(err.error_code(), FrankenErrorCode::LeaseLifecycleError);
    }

    #[test]
    fn has_error_code_obligation_error() {
        let err = ObligationError::NotFound { obligation_id: 1 };
        assert_eq!(err.error_code(), FrankenErrorCode::ObligationChannelError);
    }

    #[test]
    fn has_error_code_lane_error() {
        let err = LaneError::EmptyTraceId;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::SchedulerLaneAdmissionError
        );
    }

    #[test]
    fn has_error_code_saga_error() {
        let err = SagaError::EmptySteps;
        assert_eq!(err.error_code(), FrankenErrorCode::SagaExecutionError);
    }

    #[test]
    fn has_error_code_alloc_domain_error() {
        let err = AllocDomainError::BudgetOverflow;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::AllocationDomainBudgetError
        );
    }

    #[test]
    fn has_error_code_phase_order_violation() {
        use crate::region_lifecycle::RegionState;
        let err = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "close".to_string(),
            region_id: "r-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::RegionPhaseOrderError);
    }

    #[test]
    fn has_error_code_gc_error() {
        let err = GcError::HeapNotFound {
            extension_id: "ext-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::GarbageCollectionError);
    }

    #[test]
    fn has_error_code_proof_error() {
        let err = ProofError::EmptyStream;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::MerkleProofVerificationError
        );
    }

    #[test]
    fn has_error_code_detector_error() {
        let err = DetectorError::UnknownMetricStream {
            stream: "s-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::RegimeDetectionError);
    }

    #[test]
    fn has_error_code_monotonicity_violation() {
        let err = MonotonicityViolation {
            current: crate::security_epoch::SecurityEpoch::from_raw(5),
            attempted: crate::security_epoch::SecurityEpoch::from_raw(3),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::EpochMonotonicityViolation
        );
    }

    #[test]
    fn has_error_code_eval_error_all_variants() {
        let codes = [
            EvalErrorCode::EmptySource,
            EvalErrorCode::ParseFailure,
            EvalErrorCode::ResolutionFailure,
            EvalErrorCode::PolicyDenied,
            EvalErrorCode::CapabilityDenied,
            EvalErrorCode::RuntimeFault,
            EvalErrorCode::HostcallFault,
            EvalErrorCode::InvariantViolation,
        ];
        for code in codes {
            let err = EvalError {
                code,
                message: "test".to_string(),
                correlation_ids: None,
                location: None,
                stack_frames: Vec::new(),
            };
            assert_eq!(err.error_code(), FrankenErrorCode::EvalRuntimeError);
        }
    }

    // -----------------------------------------------------------------------
    // from_numeric boundary values per subsystem
    // -----------------------------------------------------------------------

    #[test]
    fn from_numeric_first_code_in_each_subsystem() {
        assert_eq!(
            FrankenErrorCode::from_numeric(1),
            Some(FrankenErrorCode::NonCanonicalEncodingError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(1000),
            Some(FrankenErrorCode::EngineObjectIdError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(2000),
            Some(FrankenErrorCode::CapabilityDeniedError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(3000),
            Some(FrankenErrorCode::PolicyCheckpointValidationError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(4000),
            Some(FrankenErrorCode::RevocationChainIntegrityError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(5000),
            Some(FrankenErrorCode::LeaseLifecycleError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(6000),
            Some(FrankenErrorCode::AllocationDomainBudgetError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(7000),
            Some(FrankenErrorCode::EvidenceContractError)
        );
        assert_eq!(
            FrankenErrorCode::from_numeric(8000),
            Some(FrankenErrorCode::EpochMonotonicityViolation)
        );
    }

    #[test]
    fn from_numeric_gap_values_return_none() {
        // Values in between assigned codes
        assert_eq!(FrankenErrorCode::from_numeric(3), None);
        assert_eq!(FrankenErrorCode::from_numeric(500), None);
        assert_eq!(FrankenErrorCode::from_numeric(1500), None);
        assert_eq!(FrankenErrorCode::from_numeric(4001), None);
    }

    // -----------------------------------------------------------------------
    // to_registry_entry round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn to_registry_entry_preserves_all_fields() {
        for code in ALL_ERROR_CODES {
            let entry = code.to_registry_entry();
            assert_eq!(entry.code, code.stable_code());
            assert_eq!(entry.numeric, code.numeric());
            assert_eq!(entry.subsystem, code.subsystem());
            assert_eq!(entry.severity, code.severity());
            assert_eq!(entry.description, code.description());
            assert_eq!(entry.operator_action, code.operator_action());
            assert_eq!(entry.deprecated, code.deprecated());
        }
    }

    // -----------------------------------------------------------------------
    // ErrorCodeEntry serde
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_entry_serde_round_trip() {
        let entry = FrankenErrorCode::CapabilityDeniedError.to_registry_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let decoded: ErrorCodeEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, entry);
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_registry_version_is_one() {
        assert_eq!(ERROR_CODE_REGISTRY_VERSION, 1);
    }

    #[test]
    fn error_code_compatibility_policy_contains_append_only() {
        assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("append-only"));
    }

    // -----------------------------------------------------------------------
    // ALL_ERROR_CODES length matches variant count
    // -----------------------------------------------------------------------

    #[test]
    fn all_error_codes_has_42_entries() {
        assert_eq!(ALL_ERROR_CODES.len(), 42);
    }

    // -----------------------------------------------------------------------
    // Subsystem range returns correct values
    // -----------------------------------------------------------------------

    #[test]
    fn error_subsystem_serialization_encoding_range() {
        let (start, end) = ErrorSubsystem::SerializationEncoding.range();
        assert_eq!(start, 1);
        assert_eq!(end, 999);
    }

    #[test]
    fn error_subsystem_reserved_range() {
        let (start, end) = ErrorSubsystem::Reserved.range();
        assert_eq!(start, 9000);
        assert_eq!(end, 9999);
    }

    // -----------------------------------------------------------------------
    // Description and operator_action content verification
    // -----------------------------------------------------------------------

    #[test]
    fn description_is_distinct_per_code() {
        let descriptions: BTreeSet<_> = ALL_ERROR_CODES.iter().map(|c| c.description()).collect();
        assert_eq!(descriptions.len(), ALL_ERROR_CODES.len());
    }

    #[test]
    fn operator_action_is_distinct_per_code() {
        let actions: BTreeSet<_> = ALL_ERROR_CODES
            .iter()
            .map(|c| c.operator_action())
            .collect();
        assert_eq!(actions.len(), ALL_ERROR_CODES.len());
    }

    // -----------------------------------------------------------------------
    // Registry compatibility_policy field
    // -----------------------------------------------------------------------

    #[test]
    fn registry_compatibility_policy_matches_constant() {
        let registry = error_code_registry();
        assert_eq!(
            registry.compatibility_policy,
            ERROR_CODE_COMPATIBILITY_POLICY
        );
    }

    // ── enrichment: concrete HasErrorCode invocations for untested types ─

    #[test]
    fn has_error_code_remote_capability_denied() {
        use crate::capability::ProfileKind;
        use crate::remote_capability_gate::RemoteOperationType;
        let err = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::Policy,
            required_capabilities: vec![],
            trace_id: "t-1".to_string(),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::RemoteCapabilityDeniedError
        );
    }

    #[test]
    fn has_error_code_remote_transport_error() {
        let err = RemoteTransportError::Timeout {
            endpoint: "http://host".to_string(),
            duration_ms: 5000,
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::RemoteTransportExecutionError
        );
    }

    #[test]
    fn has_error_code_registry_error() {
        let err = RegistryError::InvalidComputationName {
            name: "".to_string(),
            reason: "empty".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::ComputationRegistryError);
    }

    #[test]
    fn has_error_code_frontier_error() {
        let err = FrontierError::UnknownZone {
            zone: "z-1".to_string(),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::CheckpointFrontierEnforcementError
        );
    }

    #[test]
    fn has_error_code_epoch_validation_error() {
        let err = EpochValidationError::InvertedWindow {
            valid_from: crate::security_epoch::SecurityEpoch::from_raw(5),
            valid_until: crate::security_epoch::SecurityEpoch::from_raw(3),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::EpochWindowValidationError
        );
    }

    #[test]
    fn has_error_code_idempotency_error() {
        let err = IdempotencyError::EntryNotFound {
            key_hex: "aabb".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::IdempotencyWorkflowError);
    }

    #[test]
    fn has_error_code_bulkhead_error() {
        let err = BulkheadError::BulkheadNotFound {
            bulkhead_id: "b-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::BulkheadIsolationError);
    }

    #[test]
    fn has_error_code_scheduler_error() {
        let err = SchedulerError::ProbeNotFound {
            probe_id: "p-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::MonitorSchedulerError);
    }

    #[test]
    fn has_error_code_slot_registry_error() {
        let err = SlotRegistryError::SlotNotFound {
            id: "s-1".to_string(),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::SlotRegistryAuthorityError
        );
    }

    #[test]
    fn has_error_code_contract_validation_error() {
        let err = ContractValidationError::EmptyRolloutStages;
        assert_eq!(err.error_code(), FrankenErrorCode::EvidenceContractError);
    }

    #[test]
    fn has_error_code_ledger_error() {
        let err = LedgerError::MissingChosenAction;
        assert_eq!(err.error_code(), FrankenErrorCode::EvidenceLedgerError);
    }

    #[test]
    fn has_error_code_verification_error() {
        let err = VerificationError::EmptyProofBundle;
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::RecoveryArtifactVerificationError
        );
    }

    #[test]
    fn has_error_code_proof_schema_error() {
        let err = ProofSchemaError::MissingField {
            field: "sig".to_string(),
        };
        assert_eq!(
            err.error_code(),
            FrankenErrorCode::ProofSchemaValidationError
        );
    }

    #[test]
    fn has_error_code_guardrail_error() {
        let err = GuardrailError::NotTriggered {
            guardrail_id: "g-1".to_string(),
        };
        assert_eq!(err.error_code(), FrankenErrorCode::EprocessGuardrailError);
    }

    #[test]
    fn has_error_code_ordering_violation() {
        let err = OrderingViolation::CandidatesNotSorted {
            first_unsorted_index: 1,
        };
        assert_eq!(err.error_code(), FrankenErrorCode::EvidenceOrderingError);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn error_severity_serde_exact_snake_case_strings() {
        assert_eq!(
            serde_json::to_string(&ErrorSeverity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorSeverity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorSeverity::Info).unwrap(),
            "\"info\""
        );
    }

    #[test]
    fn error_subsystem_serde_exact_snake_case_strings() {
        let expected = [
            (
                ErrorSubsystem::SerializationEncoding,
                "\"serialization_encoding\"",
            ),
            (
                ErrorSubsystem::IdentityAuthentication,
                "\"identity_authentication\"",
            ),
            (
                ErrorSubsystem::CapabilityAuthorization,
                "\"capability_authorization\"",
            ),
            (ErrorSubsystem::CheckpointPolicy, "\"checkpoint_policy\""),
            (ErrorSubsystem::Revocation, "\"revocation\""),
            (ErrorSubsystem::SessionChannel, "\"session_channel\""),
            (ErrorSubsystem::ZoneScope, "\"zone_scope\""),
            (
                ErrorSubsystem::AuditObservability,
                "\"audit_observability\"",
            ),
            (
                ErrorSubsystem::LifecycleMigration,
                "\"lifecycle_migration\"",
            ),
            (ErrorSubsystem::Reserved, "\"reserved\""),
        ];
        for (sub, json_str) in expected {
            assert_eq!(
                serde_json::to_string(&sub).unwrap(),
                json_str,
                "serde string mismatch for {sub:?}"
            );
        }
    }

    #[test]
    fn error_subsystem_range_exact_values_all_10() {
        let expected: [(ErrorSubsystem, u16, u16); 10] = [
            (ErrorSubsystem::SerializationEncoding, 1, 999),
            (ErrorSubsystem::IdentityAuthentication, 1000, 1999),
            (ErrorSubsystem::CapabilityAuthorization, 2000, 2999),
            (ErrorSubsystem::CheckpointPolicy, 3000, 3999),
            (ErrorSubsystem::Revocation, 4000, 4999),
            (ErrorSubsystem::SessionChannel, 5000, 5999),
            (ErrorSubsystem::ZoneScope, 6000, 6999),
            (ErrorSubsystem::AuditObservability, 7000, 7999),
            (ErrorSubsystem::LifecycleMigration, 8000, 8999),
            (ErrorSubsystem::Reserved, 9000, 9999),
        ];
        for (sub, exp_start, exp_end) in expected {
            let (start, end) = sub.range();
            assert_eq!(start, exp_start, "{sub:?} start");
            assert_eq!(end, exp_end, "{sub:?} end");
        }
    }

    #[test]
    fn all_error_codes_monotonically_sorted_by_numeric() {
        for pair in ALL_ERROR_CODES.windows(2) {
            assert!(
                pair[0].numeric() < pair[1].numeric(),
                "ALL_ERROR_CODES not monotonic: {} >= {}",
                pair[0].numeric(),
                pair[1].numeric()
            );
        }
    }

    #[test]
    fn stable_code_exact_strings_representative() {
        assert_eq!(
            FrankenErrorCode::NonCanonicalEncodingError.stable_code(),
            "FE-0001"
        );
        assert_eq!(
            FrankenErrorCode::EngineObjectIdError.stable_code(),
            "FE-1000"
        );
        assert_eq!(
            FrankenErrorCode::CapabilityDeniedError.stable_code(),
            "FE-2000"
        );
        assert_eq!(
            FrankenErrorCode::PolicyCheckpointValidationError.stable_code(),
            "FE-3000"
        );
        assert_eq!(
            FrankenErrorCode::RevocationChainIntegrityError.stable_code(),
            "FE-4000"
        );
        assert_eq!(
            FrankenErrorCode::LeaseLifecycleError.stable_code(),
            "FE-5000"
        );
        assert_eq!(
            FrankenErrorCode::AllocationDomainBudgetError.stable_code(),
            "FE-6000"
        );
        assert_eq!(
            FrankenErrorCode::EvidenceContractError.stable_code(),
            "FE-7000"
        );
        assert_eq!(
            FrankenErrorCode::EpochMonotonicityViolation.stable_code(),
            "FE-8000"
        );
    }

    #[test]
    fn description_exact_for_representative_codes() {
        assert_eq!(
            FrankenErrorCode::NonCanonicalEncodingError.description(),
            "Canonical encoding guard rejected non-canonical input."
        );
        assert_eq!(
            FrankenErrorCode::ForkDetectionError.description(),
            "Fork detection pipeline identified divergence or safe-mode policy violation."
        );
        assert_eq!(
            FrankenErrorCode::EpochMonotonicityViolation.description(),
            "Security epoch monotonicity violation detected (attempted regression)."
        );
    }

    #[test]
    fn has_error_code_gc_error_domain_error_variant() {
        let inner = AllocDomainError::BudgetOverflow;
        let err = GcError::DomainError(inner);
        assert_eq!(err.error_code(), FrankenErrorCode::GarbageCollectionError);
    }

    #[test]
    fn franken_error_code_hash_consistent_for_equal_values() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = FrankenErrorCode::CapabilityDeniedError;
        let b = FrankenErrorCode::CapabilityDeniedError;
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());

        // Different codes produce different hashes (probabilistic but deterministic)
        let c = FrankenErrorCode::EvalRuntimeError;
        let mut hc = DefaultHasher::new();
        c.hash(&mut hc);
        assert_ne!(ha.finish(), hc.finish());
    }

    #[test]
    fn error_code_entry_serde_json_keys_present() {
        let entry = FrankenErrorCode::DeterministicSerdeError.to_registry_entry();
        let json = serde_json::to_value(&entry).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("code"));
        assert!(obj.contains_key("numeric"));
        assert!(obj.contains_key("subsystem"));
        assert!(obj.contains_key("severity"));
        assert!(obj.contains_key("description"));
        assert!(obj.contains_key("operator_action"));
        assert!(obj.contains_key("deprecated"));
    }

    #[test]
    fn registry_entries_count_matches_all_error_codes() {
        let registry = error_code_registry();
        assert_eq!(registry.entries.len(), ALL_ERROR_CODES.len());
        for (entry, code) in registry.entries.iter().zip(ALL_ERROR_CODES.iter()) {
            assert_eq!(entry.numeric, code.numeric());
        }
    }

    #[test]
    fn operator_action_exact_for_representative_codes() {
        assert_eq!(
            FrankenErrorCode::NonCanonicalEncodingError.operator_action(),
            "Reject payload, log trace_id, and re-emit canonical bytes from trusted source."
        );
        assert_eq!(
            FrankenErrorCode::ForkDetectionError.operator_action(),
            "Keep safe mode active until incident is acknowledged and resolved with signed evidence."
        );
    }
}
