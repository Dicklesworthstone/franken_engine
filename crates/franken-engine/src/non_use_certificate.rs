//! E8.T3 certifier: assemble the non-use / use certificate bundle for a
//! data-contract run (bd-fqlfw.8.3).
//!
//! At completion of a `frankenctl run --data-contract` execution, the
//! certifier assembles six artifacts from the run's recorded evidence — the
//! data-contract IFC ingress, the flow edges the orchestrator recorded into
//! the provenance index, the capability-metered host-effect transcript, and
//! the staged declassification receipts — and signs the two certificates with
//! the engine's deterministic runtime evidence key (bd-k2bz7):
//!
//! 1. `non_use_certificate.json` — verdicts for the contract's negative
//!    claims (no flow label X → sink class Y, capability Z not used, no
//!    declassification outside route R), each scoped to the analyzed
//!    explicit-flow surface and evaluated fail-closed.
//! 2. `use_certificate.json` — the positive, conservatively over-approximated
//!    record of what the run *did* bind, hold, and potentially reach.
//! 3. `declassification_receipts.jsonl` — one signed receipt per line.
//! 4. `capability_trace.jsonl` — grants plus the host-effect transcript.
//! 5. `repro.lock` — house-canonical reproducibility lock binding every other
//!    file's digest plus the replay pointer (there is no separate
//!    `replay.lock` artifact in this repository; the `replay` section of the
//!    lock carries the trace linkage).
//! 6. `audit.md` — the deterministic human summary with the explicit scope
//!    statement and threat-model boundary.
//!
//! Soundness posture (the honesty boundary from bd-fqlfw.8, fail-closed
//! soundness from bd-fqlfw.8.4): positive "use" claims tolerate
//! over-approximation, so the use certificate may state them plainly.
//! Negative "non-use" claims do not — the certificate status is derived,
//! never asserted: it reaches `certified_within_analyzed_scope` only when the
//! E8 refusal ledger is an empty, scan-backed `certifiable_subset` receipt
//! (every construct in the run's source classified inside the analyzed
//! explicit-flow subset by `e8_analyzed_subset::scan_source`, evidence
//! complete, run-input hash bound) AND every requested claim holds within
//! that scope. Any unanalyzed construct downgrades the run to *uncertified —
//! unanalyzed flow at span X* via the refusal ledger; any claim whose
//! evidence lane is not analyzed fails closed to `unanalyzed_fail_closed`.
//! The threat model is EXPLICIT-FLOW ONLY (`explicit_flow_ifc_v1`); covert
//! channels, timing channels, and control-flow implicit channels are out of
//! scope (see `docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use frankenengine_extension_host::host_io::{HostIoCapability, HostIoOutcome, HostIoRequest};

use crate::capability::RuntimeCapability;
use crate::data_contract::{
    DataContract, DataContractError, DataContractIfcIngress, DataContractRunBinding,
    E8RefusalLedgerReceipt, RequestedOutputClaim,
};
use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::evidence_ledger::{shared_evidence_verification_key, sign_evidence_preimage};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{ClearanceClass, DeclassificationReceipt, Label};
use crate::ifc_provenance_index::{FlowDecision, FlowEventRecord};
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, VerificationKey, verify_signature,
};

pub const NON_USE_CERTIFICATE_SCHEMA_VERSION: &str = "franken-engine.non-use-certificate.v1";
pub const USE_CERTIFICATE_SCHEMA_VERSION: &str = "franken-engine.use-certificate.v1";
pub const E8_CERTIFICATE_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.e8-certificate-bundle.v1";
pub const E8_CERTIFICATE_REPRO_LOCK_SCHEMA_VERSION: &str = "franken-engine.repro-lock.v1";
pub const E8_CERTIFIER_PRODUCER_ID: &str = "franken-engine.e8-certifier";
pub const E8_CERTIFICATE_ANALYSIS_POSTURE: &str = "conservative_ingress_over_approximation_v1";

pub const NON_USE_CERTIFICATE_FILE: &str = "non_use_certificate.json";
pub const USE_CERTIFICATE_FILE: &str = "use_certificate.json";
pub const DECLASSIFICATION_RECEIPTS_FILE: &str = "declassification_receipts.jsonl";
pub const CAPABILITY_TRACE_FILE: &str = "capability_trace.jsonl";
pub const REPRO_LOCK_FILE: &str = "repro.lock";
pub const AUDIT_FILE: &str = "audit.md";

fn non_use_certificate_schema() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"e8_non_use_certificate_v1"));
    &HASH
}

fn use_certificate_schema() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(b"e8_use_certificate_v1"));
    &HASH
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifierError {
    ContractBinding(DataContractError),
    EvidenceExtensionMismatch {
        expected: String,
        actual: String,
        event_id: String,
    },
    EvidenceContractMismatch {
        event_id: String,
        flow_location: String,
        expected_prefix: String,
    },
    RefusalReceiptRunMismatch {
        expected_run_id: String,
        actual_run_id: String,
    },
    RefusalReceiptContractMismatch {
        expected_contract_id: String,
        actual_contract_id: String,
    },
    DeclassifiedEdgeWithoutReceipt {
        event_id: String,
    },
    UnreferencedDeclassificationReceipt {
        receipt_id: String,
    },
    SerializationFailed {
        target: String,
        detail: String,
    },
    SignatureInvalid {
        target: String,
        detail: String,
    },
}

impl fmt::Display for CertifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractBinding(error) => {
                write!(f, "certifier contract binding failed: {error}")
            }
            Self::EvidenceExtensionMismatch {
                expected,
                actual,
                event_id,
            } => write!(
                f,
                "flow event `{event_id}` belongs to extension `{actual}`, expected `{expected}`"
            ),
            Self::EvidenceContractMismatch {
                event_id,
                flow_location,
                expected_prefix,
            } => write!(
                f,
                "flow event `{event_id}` location `{flow_location}` was not produced by this \
                 contract (expected prefix `{expected_prefix}`)"
            ),
            Self::RefusalReceiptRunMismatch {
                expected_run_id,
                actual_run_id,
            } => write!(
                f,
                "refusal ledger receipt is for run `{actual_run_id}`, expected `{expected_run_id}`"
            ),
            Self::RefusalReceiptContractMismatch {
                expected_contract_id,
                actual_contract_id,
            } => write!(
                f,
                "refusal ledger receipt is for contract `{actual_contract_id}`, expected \
                 `{expected_contract_id}`"
            ),
            Self::DeclassifiedEdgeWithoutReceipt { event_id } => write!(
                f,
                "declassified flow event `{event_id}` carries no verified receipt reference"
            ),
            Self::UnreferencedDeclassificationReceipt { receipt_id } => write!(
                f,
                "declassification receipt `{receipt_id}` is not referenced by any recorded flow \
                 edge"
            ),
            Self::SerializationFailed { target, detail } => {
                write!(f, "failed to serialize {target}: {detail}")
            }
            Self::SignatureInvalid { target, detail } => {
                write!(f, "signature verification failed for {target}: {detail}")
            }
        }
    }
}

impl std::error::Error for CertifierError {}

impl From<DataContractError> for CertifierError {
    fn from(error: DataContractError) -> Self {
        Self::ContractBinding(error)
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// One declared sink in the certificate's host boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredSinkScope {
    pub sink_id: String,
    pub clearance: ClearanceClass,
    pub location: String,
    pub allowed_labels: Vec<Label>,
}

/// The precise scope every certificate claim is bound to: "under this engine
/// version, policy epoch, declared host boundary, input binding, and replay
/// artifact, these flows/capabilities were absent/present".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateScope {
    pub engine_version: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub parse_goal: String,
    pub contract_id: String,
    pub contract_hash_hex: String,
    pub extension_id: String,
    pub run_input_binding_id: String,
    pub run_input_object_ref: String,
    pub run_input_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_input_content_hash_hex: Option<String>,
    pub purpose: String,
    pub trace_id: String,
    pub decision_id: String,
    pub containment_action: String,
    /// Content hash of the run's finalized nondeterminism trace — the replay
    /// artifact every claim is anchored to.
    pub replay_trace_content_hash_hex: String,
    /// The declared host boundary: every sink the contract admits.
    pub declared_sinks: Vec<DeclaredSinkScope>,
    /// Capability envelope the contract declares.
    pub contract_capabilities: Vec<RuntimeCapability>,
    /// Capability profile the runtime actually granted the run.
    pub runtime_granted_capabilities: Vec<RuntimeCapability>,
    /// Declassification routes the contract requires for cross-label flows.
    pub declassification_route_ids: Vec<String>,
    /// Threat-model boundary: explicit flows only; covert/timing out of scope.
    pub threat_model_scope: String,
    /// v1 analysis posture: every declared sink is treated as a potential
    /// destination of the ingress label (no per-flow propagation proof yet).
    pub analysis_posture: String,
}

// ---------------------------------------------------------------------------
// Claim verdicts
// ---------------------------------------------------------------------------

/// Fail-closed evaluation of one requested output claim over the recorded
/// run evidence, within the analyzed explicit-flow scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEvaluation {
    /// No evidence of the claimed flow/use exists in the analyzed surface,
    /// and the surface is enforced fail-closed: the negative claim holds
    /// within the stated scope.
    HoldsWithinAnalyzedScope,
    /// Recorded evidence contradicts the negative claim (the flow or use
    /// demonstrably occurred).
    Contradicted,
    /// The conservative over-approximation cannot rule the flow/use out;
    /// asserting the negative would overclaim, so the certifier refuses to.
    NotAssertableConservative,
    /// The claim's evidence lane is not analyzed in v1 (per-flow label
    /// propagation is unproven; see bd-fqlfw.8.4). Fail-closed.
    UnanalyzedFailClosed,
}

impl fmt::Display for ClaimEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HoldsWithinAnalyzedScope => "holds_within_analyzed_scope",
            Self::Contradicted => "contradicted",
            Self::NotAssertableConservative => "not_assertable_conservative",
            Self::UnanalyzedFailClosed => "unanalyzed_fail_closed",
        };
        f.write_str(name)
    }
}

/// Verdict for one requested output claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonUseClaimVerdict {
    pub claim_id: String,
    pub claim: RequestedOutputClaim,
    pub evaluation: ClaimEvaluation,
    /// Flow-event ids / transcript indexes / enforcement facts backing the
    /// verdict.
    pub evidence_refs: Vec<String>,
    pub detail: String,
}

/// Top-level certificate status, derived mechanically from the E8 refusal
/// ledger receipt plus every per-claim verdict — never asserted directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    /// The refusal ledger blocks certification, or at least one requested
    /// claim did not hold within the analyzed scope.
    Uncertified,
    /// Every construct in the run's source sits inside the analyzed
    /// explicit-flow subset (bd-fqlfw.8.4 scan), all required evidence is
    /// linked, and every requested claim holds within that scope.
    CertifiedWithinAnalyzedScope,
}

impl fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uncertified => f.write_str("uncertified"),
            Self::CertifiedWithinAnalyzedScope => f.write_str("certified_within_analyzed_scope"),
        }
    }
}

/// Whether the E8 refusal ledger permits certification at all: an empty,
/// scan-backed `certifiable_subset` receipt. Any refusal code, any unanalyzed
/// surface, or a blocking flag fails closed.
///
/// `positive_non_use_claim_allowed` is deliberately NOT consulted here: the
/// v1 ledger schema pins it `false` unconditionally
/// (`docs/e8_refusal_ledger_schema_v1.json`) because the *receipt* is never
/// itself quotable as a non-use claim. The signed certificate is the only
/// artifact allowed to state non-use, and only within the analyzed scope.
fn refusal_ledger_certifiable(receipt: &E8RefusalLedgerReceipt) -> bool {
    !receipt.must_block_certificate
        && receipt.certifier_input_allowed
        && receipt.result_class == "certifiable_subset"
        && receipt.refusal_codes.is_empty()
        && receipt.unanalyzed_surface_count == 0
}

/// Derive the certificate status: certifiable ledger AND every requested
/// claim holds within the analyzed scope. Any weaker verdict on any claim —
/// contradicted, not-assertable, or unanalyzed — downgrades the whole
/// certificate to `uncertified` (the per-claim verdicts remain visible).
fn derive_certificate_status(
    receipt: &E8RefusalLedgerReceipt,
    claims: &[NonUseClaimVerdict],
) -> CertificateStatus {
    let every_claim_holds = claims
        .iter()
        .all(|claim| claim.evaluation == ClaimEvaluation::HoldsWithinAnalyzedScope);
    if refusal_ledger_certifiable(receipt) && every_claim_holds {
        CertificateStatus::CertifiedWithinAnalyzedScope
    } else {
        CertificateStatus::Uncertified
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// The signed negative-claims certificate (`non_use_certificate.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonUseCertificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub producer_id: String,
    pub scope: CertificateScope,
    pub certificate_status: CertificateStatus,
    /// Refusal-ledger linkage: the receipt that governs the status.
    pub refusal_ledger_id: String,
    pub refusal_ledger_result_class: String,
    pub refusal_ledger_content_hash_hex: String,
    pub claims: Vec<NonUseClaimVerdict>,
    /// The complete recorded flow-edge evidence (allowed AND blocked).
    pub flow_events: Vec<FlowEventRecord>,
    pub declassification_receipt_count: u64,
    pub signed_by: VerificationKey,
    pub signature: Signature,
}

impl SignaturePreimage for NonUseCertificate {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        non_use_certificate_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).expect("serialization should succeed"))
    }
}

impl NonUseCertificate {
    /// Sign with the engine's deterministic runtime evidence key (bd-k2bz7).
    fn sign_with_runtime_key(&mut self) {
        self.signed_by = shared_evidence_verification_key();
        self.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        let preimage = self.preimage_bytes();
        self.signature = sign_evidence_preimage(&preimage);
    }

    /// Verify the embedded signature against the embedded verification key.
    pub fn verify(&self) -> Result<(), CertifierError> {
        verify_signature(&self.signed_by, &self.preimage_bytes(), &self.signature).map_err(
            |error| CertifierError::SignatureInvalid {
                target: "non_use_certificate".to_string(),
                detail: error.to_string(),
            },
        )
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.preimage_bytes())
    }
}

/// One contract input binding and whether it actually entered the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundInputRecord {
    pub binding_id: String,
    pub object_ref: String,
    pub label: Label,
    pub role: String,
    /// Whether this binding was resolved as the run input (v1: exactly the
    /// run-input binding ingresses; other bindings never enter the runtime).
    pub ingressed: bool,
}

/// Summarized capability-use evidence in the use certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityUseRecord {
    pub capability: RuntimeCapability,
    pub evidence: String,
}

/// The signed positive-claims certificate (`use_certificate.json`).
///
/// Positive dependency/use claims are conservative over-approximations,
/// which is sound in this direction: over-stating what the run *may* have
/// used or reached never launders a hidden use into a non-use claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseCertificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub producer_id: String,
    pub scope: CertificateScope,
    pub inputs_bound: Vec<BoundInputRecord>,
    /// Whether the runtime-granted profile stayed inside the contract's
    /// declared capability envelope.
    pub contract_capability_envelope_respected: bool,
    /// Capabilities granted beyond the contract envelope (empty when the
    /// envelope was respected).
    pub capabilities_granted_beyond_contract: Vec<RuntimeCapability>,
    pub capability_use_evidence: Vec<CapabilityUseRecord>,
    /// Sinks with an `Allowed` ingress edge: under the v1 over-approximation
    /// the output may have reached any of these.
    pub sinks_potentially_reached: Vec<String>,
    pub declassification_route_ids_exercised: Vec<String>,
    /// Conservative posture statement for output dependencies.
    pub output_dependency_posture: String,
    pub console_entry_count: u64,
    pub instructions_executed: u64,
    pub execution_value_content_hash_hex: String,
    pub signed_by: VerificationKey,
    pub signature: Signature,
}

impl SignaturePreimage for UseCertificate {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        use_certificate_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).expect("serialization should succeed"))
    }
}

impl UseCertificate {
    fn sign_with_runtime_key(&mut self) {
        self.signed_by = shared_evidence_verification_key();
        self.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        let preimage = self.preimage_bytes();
        self.signature = sign_evidence_preimage(&preimage);
    }

    pub fn verify(&self) -> Result<(), CertifierError> {
        verify_signature(&self.signed_by, &self.preimage_bytes(), &self.signature).map_err(
            |error| CertifierError::SignatureInvalid {
                target: "use_certificate".to_string(),
                detail: error.to_string(),
            },
        )
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.preimage_bytes())
    }
}

// ---------------------------------------------------------------------------
// Capability trace records (capability_trace.jsonl)
// ---------------------------------------------------------------------------

/// One line of `capability_trace.jsonl`.
///
/// Host-effect lines deliberately record payload *lengths and hashes*, never
/// raw payload bytes: the trace is an audit artifact that leaves the trust
/// boundary, so embedding labeled payloads in it would itself be an
/// exfiltration channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilityTraceRecord {
    Grant {
        capability: RuntimeCapability,
        source: String,
    },
    HostEffect {
        index: u64,
        request_kind: String,
        required_capability: String,
        target: String,
        payload_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload_content_hash_hex: Option<String>,
        outcome: String,
    },
    ConsoleSummary {
        entries: u64,
    },
}

// ---------------------------------------------------------------------------
// repro.lock
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReproDeterminism {
    pub allow_network: bool,
    pub allow_wall_clock: bool,
    pub allow_randomness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReproReplay {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    /// Content hash of the finalized nondeterminism trace.
    pub replay_pointer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBundleFileDigest {
    pub name: String,
    pub sha256_hex: String,
    pub bytes: u64,
}

/// The bundle's reproducibility lock (`repro.lock`), house schema
/// `franken-engine.repro-lock.v1`. Carries no wall-clock so the bundle is
/// byte-identical across re-runs of the same fixed inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReproLock {
    pub schema_version: String,
    pub schema_hash: String,
    pub lock_id: String,
    pub bundle_schema_version: String,
    pub determinism: CertificateReproDeterminism,
    pub replay: CertificateReproReplay,
    /// Digests of every other file in the bundle.
    pub files: Vec<CertificateBundleFileDigest>,
    pub commands: Vec<String>,
}

// ---------------------------------------------------------------------------
// Certifier inputs and bundle
// ---------------------------------------------------------------------------

/// Everything the certifier consumes from a completed data-contract run.
#[derive(Debug)]
pub struct CertifierInputs<'a> {
    pub contract: &'a DataContract,
    pub binding: &'a DataContractRunBinding,
    /// Flow edges recorded by the data-contract ingress guard
    /// (`ExecutionOrchestrator::data_contract_flow_events`).
    pub flow_events: &'a [FlowEventRecord],
    /// The capability-metered host-effect transcript from the run.
    pub host_effects: &'a [(HostIoRequest, HostIoOutcome)],
    /// Signed declassification receipts consumed by the run (v1: typically
    /// empty; every receipt must be referenced by a recorded flow edge).
    pub declassification_receipts: &'a [DeclassificationReceipt],
    /// The uncertified-preflight refusal receipt for this run.
    pub refusal_receipt: &'a E8RefusalLedgerReceipt,
    /// Capability profile the runtime actually granted the run.
    pub runtime_granted_capabilities: &'a BTreeSet<RuntimeCapability>,
    pub policy_id: &'a str,
    pub policy_epoch: u64,
    pub parse_goal: &'a str,
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub engine_version: &'a str,
    pub containment_action: &'a str,
    pub instructions_executed: u64,
    pub console_entry_count: u64,
    pub execution_value: &'a str,
    /// Content hash of the run's finalized nondeterminism trace.
    pub replay_trace_content_hash_hex: &'a str,
}

/// One emitted bundle file with its deterministic byte content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBundleFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The assembled, signed certificate bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateBundle {
    pub non_use_certificate: NonUseCertificate,
    pub use_certificate: UseCertificate,
    pub repro_lock: CertificateReproLock,
    /// All six files in canonical emission order.
    pub files: Vec<CertificateBundleFile>,
    /// Length-prefixed content hash over every (name, bytes) pair.
    pub bundle_content_hash_hex: String,
}

impl CertificateBundle {
    pub fn file(&self, name: &str) -> Option<&CertificateBundleFile> {
        self.files.iter().find(|file| file.name == name)
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

fn append_seed_field(seed: &mut Vec<u8>, field: &str, value: &str) {
    seed.extend_from_slice(&(field.len() as u64).to_be_bytes());
    seed.extend_from_slice(field.as_bytes());
    seed.extend_from_slice(&(value.len() as u64).to_be_bytes());
    seed.extend_from_slice(value.as_bytes());
}

fn map_host_capability(capability: HostIoCapability) -> RuntimeCapability {
    match capability {
        HostIoCapability::FsRead => RuntimeCapability::FsRead,
        HostIoCapability::FsWrite => RuntimeCapability::FsWrite,
        // Both network directions gate on the runtime's network-egress
        // authority; receive-only sockets still cross the host boundary.
        HostIoCapability::NetworkSend | HostIoCapability::NetworkRecv => {
            RuntimeCapability::NetworkEgress
        }
    }
}

fn host_effect_target(request: &HostIoRequest) -> (String, u64, Option<String>) {
    match request {
        HostIoRequest::FsRead { path } => (path.clone(), 0, None),
        HostIoRequest::FsWrite { path, data } => (
            path.clone(),
            data.len() as u64,
            Some(ContentHash::compute(data).to_hex()),
        ),
        HostIoRequest::FsMeta {
            operation,
            path,
            arguments,
            data,
        } => (
            format!("{}:{path} [{}]", operation.as_str(), arguments.join(",")),
            data.len() as u64,
            (!data.is_empty()).then(|| ContentHash::compute(data).to_hex()),
        ),
        HostIoRequest::NetworkSend { endpoint, payload } => (
            endpoint.clone(),
            payload.len() as u64,
            Some(ContentHash::compute(payload).to_hex()),
        ),
        HostIoRequest::NetworkRecv { endpoint, max_len } => {
            (format!("{endpoint} (max_len {max_len})"), 0, None)
        }
        HostIoRequest::NetworkRequest {
            endpoint,
            payload,
            max_len,
            use_tls,
        } => (
            format!("{endpoint} (max_len {max_len}, tls {use_tls})"),
            payload.len() as u64,
            Some(ContentHash::compute(payload).to_hex()),
        ),
    }
}

fn host_effect_outcome(outcome: &HostIoOutcome) -> String {
    match outcome {
        Ok(_) => "performed".to_string(),
        Err(error) => format!("denied: {error}"),
    }
}

/// Whether the recorded evidence demonstrates actual use of `capability`.
fn capability_use_evidence(
    capability: RuntimeCapability,
    inputs: &CertifierInputs<'_>,
) -> Option<String> {
    if capability == RuntimeCapability::Console && inputs.console_entry_count > 0 {
        return Some(format!(
            "{} console entr{} recorded",
            inputs.console_entry_count,
            if inputs.console_entry_count == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    if capability == RuntimeCapability::VmDispatch && inputs.instructions_executed > 0 {
        return Some(format!(
            "{} instructions executed",
            inputs.instructions_executed
        ));
    }
    if capability == RuntimeCapability::Declassify
        && inputs
            .flow_events
            .iter()
            .any(|event| event.decision == FlowDecision::Declassified)
    {
        return Some("declassified flow edge recorded".to_string());
    }
    for (index, (request, outcome)) in inputs.host_effects.iter().enumerate() {
        if outcome.is_ok() && map_host_capability(request.required_capability()) == capability {
            return Some(format!(
                "host effect #{index} ({}) performed",
                request.kind()
            ));
        }
    }
    None
}

fn evaluate_no_flow(
    claim_id: &str,
    claim_source_label: &Label,
    claim_sink_clearance: ClearanceClass,
    ingress: &DataContractIfcIngress,
    flow_events: &[FlowEventRecord],
) -> (ClaimEvaluation, Vec<String>, String) {
    let matching_sinks: Vec<_> = ingress
        .sinks
        .iter()
        .filter(|sink| sink.clearance == claim_sink_clearance)
        .collect();
    if matching_sinks.is_empty() {
        return (
            ClaimEvaluation::HoldsWithinAnalyzedScope,
            vec!["host_boundary:no_matching_sink".to_string()],
            format!(
                "no declared sink of clearance {claim_sink_clearance:?} exists in the host \
                 boundary; undeclared sinks are fail-closed by the membrane"
            ),
        );
    }

    let mut evidence = Vec::new();
    let mut potential_flow = false;
    let mut incomplete_evidence = false;
    for sink in &matching_sinks {
        let event_id = format!(
            "dc-ingress-{}-{}-{}",
            ingress.contract_id, ingress.run_input_binding_id, sink.sink_id
        );
        match flow_events.iter().find(|event| event.event_id == event_id) {
            Some(event) => {
                evidence.push(format!("flow_event:{}", event.event_id));
                match event.decision {
                    FlowDecision::Blocked => {}
                    FlowDecision::Allowed | FlowDecision::Declassified => {
                        if ingress.source_label.level() >= claim_source_label.level() {
                            potential_flow = true;
                        }
                    }
                }
            }
            None => {
                evidence.push(format!("missing_flow_event:{event_id}"));
                incomplete_evidence = true;
            }
        }
    }

    if incomplete_evidence {
        return (
            ClaimEvaluation::NotAssertableConservative,
            evidence,
            format!(
                "claim `{claim_id}`: a declared sink of clearance {claim_sink_clearance:?} has \
                 no recorded flow edge; incomplete evidence cannot support a non-use assertion"
            ),
        );
    }
    if potential_flow {
        return (
            ClaimEvaluation::NotAssertableConservative,
            evidence,
            format!(
                "ingress label {:?} (level {}) may have reached a declared sink of clearance \
                 {claim_sink_clearance:?} via an allowed edge; under the v1 conservative \
                 over-approximation absence cannot be asserted",
                ingress.source_label,
                ingress.source_label.level()
            ),
        );
    }
    (
        ClaimEvaluation::HoldsWithinAnalyzedScope,
        evidence,
        format!(
            "no data at or above label {:?} (level {}) entered the run (ingress label {:?}, \
             level {}); every declared sink edge of clearance {claim_sink_clearance:?} is \
             accounted for",
            claim_source_label,
            claim_source_label.level(),
            ingress.source_label,
            ingress.source_label.level()
        ),
    )
}

/// Capabilities whose *use* is completely witnessed by the recorded run
/// evidence: console entries, the instruction counter, declassified flow
/// edges, and the capability-metered host-effect transcript. For these lanes,
/// absence of a witness on a scan-certified run is evidence of non-use within
/// the analyzed scope. All other capabilities stay not-assertable when
/// granted.
fn capability_use_is_witnessed(capability: RuntimeCapability) -> bool {
    matches!(
        capability,
        RuntimeCapability::Console
            | RuntimeCapability::VmDispatch
            | RuntimeCapability::Declassify
            | RuntimeCapability::FsRead
            | RuntimeCapability::FsWrite
            | RuntimeCapability::NetworkEgress
    )
}

fn evaluate_capability_not_used(
    capability: RuntimeCapability,
    inputs: &CertifierInputs<'_>,
) -> (ClaimEvaluation, Vec<String>, String) {
    let contract_grants = inputs.contract.allowed_capabilities.contains(&capability);
    let runtime_grants = inputs.runtime_granted_capabilities.contains(&capability);
    if let Some(use_evidence) = capability_use_evidence(capability, inputs) {
        return (
            ClaimEvaluation::Contradicted,
            vec![format!("capability_use:{capability:?}")],
            format!("capability {capability:?} was used: {use_evidence}"),
        );
    }
    if !contract_grants && !runtime_grants {
        return (
            ClaimEvaluation::HoldsWithinAnalyzedScope,
            vec![format!("enforcement:ungranted:{capability:?}")],
            format!(
                "capability {capability:?} was granted by neither the contract envelope nor the \
                 runtime profile; the hostcall membrane denies ungranted capabilities fail-closed"
            ),
        );
    }
    if refusal_ledger_certifiable(inputs.refusal_receipt) && capability_use_is_witnessed(capability)
    {
        return (
            ClaimEvaluation::HoldsWithinAnalyzedScope,
            vec![
                format!("grant:{capability:?}"),
                "witness:no_recorded_use".to_string(),
                format!(
                    "refusal_ledger:certifiable:{}",
                    inputs.refusal_receipt.ledger_id
                ),
            ],
            format!(
                "capability {capability:?} was granted (contract: {contract_grants}, runtime: \
                 {runtime_grants}) but its witnessed evidence lane recorded no use, and every \
                 construct in the run sits inside the analyzed explicit-flow subset \
                 (bd-fqlfw.8.4 scan); non-use holds within the analyzed scope"
            ),
        );
    }
    (
        ClaimEvaluation::NotAssertableConservative,
        vec![format!("grant:{capability:?}")],
        format!(
            "capability {capability:?} was granted (contract: {contract_grants}, runtime: \
             {runtime_grants}) and either the run is not scan-certified within the analyzed \
             subset or this capability has no complete use-witness lane; asserting non-use \
             would overclaim"
        ),
    )
}

fn evaluate_output_independent_of(
    binding_id: &str,
    ingress: &DataContractIfcIngress,
    inputs: &CertifierInputs<'_>,
) -> (ClaimEvaluation, Vec<String>, String) {
    if !refusal_ledger_certifiable(inputs.refusal_receipt) {
        return (
            ClaimEvaluation::UnanalyzedFailClosed,
            vec![format!("unanalyzed:output_independence:{binding_id}")],
            format!(
                "output independence from binding `{binding_id}` requires every construct in \
                 the run to sit inside the analyzed explicit-flow subset, but the E8 refusal \
                 ledger (`{}`, result class `{}`) blocks certification; fail-closed \
                 (bd-fqlfw.8.4). The historical IFC holes bd-0zybl (GetProperty) and \
                 bd-ooaka.1 (callback lanes) are closed with regression tests; remaining \
                 unanalyzed lanes are enumerated by the analyzed-subset scan.",
                inputs.refusal_receipt.ledger_id, inputs.refusal_receipt.result_class
            ),
        );
    }
    if binding_id == ingress.run_input_binding_id {
        return (
            ClaimEvaluation::NotAssertableConservative,
            vec![format!("ingress:run_input:{binding_id}")],
            format!(
                "binding `{binding_id}` is the run input and demonstrably entered the run; \
                 proving the output independent of the data that fed it requires a per-value \
                 output-label proof, which is outside the analyzed explicit-flow subset"
            ),
        );
    }
    (
        ClaimEvaluation::HoldsWithinAnalyzedScope,
        vec![
            format!(
                "ingress_model:only_run_input_binding:{}",
                ingress.run_input_binding_id
            ),
            format!(
                "refusal_ledger:certifiable:{}",
                inputs.refusal_receipt.ledger_id
            ),
        ],
        format!(
            "binding `{binding_id}` never entered the runtime: under the v1 ingress model \
             exactly the run-input binding (`{}`) ingresses, every construct in the run sits \
             inside the analyzed explicit-flow subset, and undeclared ingress paths are \
             denied fail-closed by the membrane",
            ingress.run_input_binding_id
        ),
    )
}

fn evaluate_claim(
    claim: &RequestedOutputClaim,
    ingress: &DataContractIfcIngress,
    inputs: &CertifierInputs<'_>,
) -> NonUseClaimVerdict {
    let (evaluation, evidence_refs, detail) = match claim {
        RequestedOutputClaim::NoFlow {
            claim_id,
            source_label,
            sink_clearance,
        } => evaluate_no_flow(
            claim_id,
            source_label,
            *sink_clearance,
            ingress,
            inputs.flow_events,
        ),
        RequestedOutputClaim::CapabilityNotUsed { capability, .. } => {
            evaluate_capability_not_used(*capability, inputs)
        }
        RequestedOutputClaim::OutputIndependentOf { binding_id, .. } => {
            evaluate_output_independent_of(binding_id, ingress, inputs)
        }
    };
    NonUseClaimVerdict {
        claim_id: claim.claim_id().to_string(),
        claim: claim.clone(),
        evaluation,
        evidence_refs,
        detail,
    }
}

fn validate_evidence(
    ingress: &DataContractIfcIngress,
    inputs: &CertifierInputs<'_>,
) -> Result<(), CertifierError> {
    if inputs.refusal_receipt.run_id != inputs.trace_id {
        return Err(CertifierError::RefusalReceiptRunMismatch {
            expected_run_id: inputs.trace_id.to_string(),
            actual_run_id: inputs.refusal_receipt.run_id.clone(),
        });
    }
    if inputs.refusal_receipt.contract_id != ingress.contract_id {
        return Err(CertifierError::RefusalReceiptContractMismatch {
            expected_contract_id: ingress.contract_id.clone(),
            actual_contract_id: inputs.refusal_receipt.contract_id.clone(),
        });
    }

    let expected_prefix = format!("data_contract:{}:", ingress.contract_id);
    let mut referenced_receipts = BTreeSet::new();
    for event in inputs.flow_events {
        if event.extension_id != ingress.extension_id {
            return Err(CertifierError::EvidenceExtensionMismatch {
                expected: ingress.extension_id.clone(),
                actual: event.extension_id.clone(),
                event_id: event.event_id.clone(),
            });
        }
        if !event.flow_location.starts_with(&expected_prefix) {
            return Err(CertifierError::EvidenceContractMismatch {
                event_id: event.event_id.clone(),
                flow_location: event.flow_location.clone(),
                expected_prefix,
            });
        }
        if event.decision == FlowDecision::Declassified {
            match event.receipt_ref.as_deref() {
                Some(receipt_ref)
                    if inputs
                        .declassification_receipts
                        .iter()
                        .any(|receipt| receipt.receipt_id == receipt_ref) =>
                {
                    referenced_receipts.insert(receipt_ref.to_string());
                }
                _ => {
                    return Err(CertifierError::DeclassifiedEdgeWithoutReceipt {
                        event_id: event.event_id.clone(),
                    });
                }
            }
        }
    }
    for receipt in inputs.declassification_receipts {
        if !referenced_receipts.contains(&receipt.receipt_id) {
            return Err(CertifierError::UnreferencedDeclassificationReceipt {
                receipt_id: receipt.receipt_id.clone(),
            });
        }
    }
    Ok(())
}

fn json_pretty_bytes<T: Serialize>(value: &T, target: &str) -> Result<Vec<u8>, CertifierError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| CertifierError::SerializationFailed {
            target: target.to_string(),
            detail: error.to_string(),
        })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn jsonl_bytes<T: Serialize>(records: &[T], target: &str) -> Result<Vec<u8>, CertifierError> {
    let mut bytes = Vec::new();
    for record in records {
        let line =
            serde_json::to_string(record).map_err(|error| CertifierError::SerializationFailed {
                target: target.to_string(),
                detail: error.to_string(),
            })?;
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn build_capability_trace(inputs: &CertifierInputs<'_>) -> Vec<CapabilityTraceRecord> {
    let mut records = Vec::new();
    for capability in inputs.contract.allowed_capabilities.iter().copied() {
        records.push(CapabilityTraceRecord::Grant {
            capability,
            source: "data_contract.allowed_capabilities".to_string(),
        });
    }
    for capability in inputs.runtime_granted_capabilities.iter().copied() {
        records.push(CapabilityTraceRecord::Grant {
            capability,
            source: "runtime_profile".to_string(),
        });
    }
    for (index, (request, outcome)) in inputs.host_effects.iter().enumerate() {
        let (target, payload_bytes, payload_content_hash_hex) = host_effect_target(request);
        records.push(CapabilityTraceRecord::HostEffect {
            index: index as u64,
            request_kind: request.kind().to_string(),
            required_capability: request.required_capability().as_str().to_string(),
            target,
            payload_bytes,
            payload_content_hash_hex,
            outcome: host_effect_outcome(outcome),
        });
    }
    if inputs.console_entry_count > 0 {
        records.push(CapabilityTraceRecord::ConsoleSummary {
            entries: inputs.console_entry_count,
        });
    }
    records
}

fn render_audit_markdown(
    non_use: &NonUseCertificate,
    use_certificate: &UseCertificate,
    receipt_count: usize,
    trace_record_count: usize,
) -> String {
    let scope = &non_use.scope;
    let mut out = String::new();
    out.push_str("# E8 Non-Use / Use Certificate Bundle — Audit Summary\n\n");
    out.push_str(&format!(
        "**Certificate status: {}** (refusal ledger `{}`, result class `{}`).\n\n",
        non_use.certificate_status, non_use.refusal_ledger_id, non_use.refusal_ledger_result_class
    ));
    out.push_str("## Scope\n\n");
    out.push_str(&format!(
        "Under engine version `{}`, policy `{}` at security epoch {}, the declared host \
         boundary ({} sink(s)), input binding `{}` of contract `{}` (contract hash `{}`), and \
         replay artifact `{}`, the flows and capability uses enumerated below were absent or \
         present as stated.\n\n",
        scope.engine_version,
        scope.policy_id,
        scope.policy_epoch,
        scope.declared_sinks.len(),
        scope.run_input_binding_id,
        scope.contract_id,
        scope.contract_hash_hex,
        scope.replay_trace_content_hash_hex,
    ));
    out.push_str(&format!(
        "Threat model: **EXPLICIT-FLOW ONLY** (`{}`); covert channels, timing channels, and \
         control-flow implicit channels are out of scope (see \
         `docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`). Analysis posture: `{}` — every \
         declared sink is treated as a potential destination of the ingress label; \
         certification additionally requires the bd-fqlfw.8.4 analyzed-subset scan to place \
         every construct of the run inside the analyzed explicit-flow subset.\n\n",
        scope.threat_model_scope, scope.analysis_posture,
    ));
    out.push_str("### Declared host boundary\n\n");
    out.push_str("| sink | clearance | location |\n|---|---|---|\n");
    for sink in &scope.declared_sinks {
        out.push_str(&format!(
            "| `{}` | {:?} | {} |\n",
            sink.sink_id, sink.clearance, sink.location
        ));
    }
    out.push_str("\n## Requested output claims\n\n");
    out.push_str("| claim id | evaluation | detail |\n|---|---|---|\n");
    for verdict in &non_use.claims {
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            verdict.claim_id, verdict.evaluation, verdict.detail
        ));
    }
    out.push_str("\n## Recorded flow edges\n\n");
    out.push_str("| event id | source label | sink ceiling | decision |\n|---|---|---|---|\n");
    for event in &non_use.flow_events {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            event.event_id, event.source_label, event.sink_clearance, event.decision
        ));
    }
    out.push_str(&format!(
        "\n## Capability and declassification evidence\n\n\
         - capability trace records: {trace_record_count} (see `capability_trace.jsonl`)\n\
         - declassification receipts consumed: {receipt_count} (see \
         `declassification_receipts.jsonl`)\n\
         - contract capability envelope respected by runtime profile: {}\n\
         - instructions executed: {}\n\
         - console entries: {}\n",
        use_certificate.contract_capability_envelope_respected,
        use_certificate.instructions_executed,
        use_certificate.console_entry_count,
    ));
    out.push_str(&format!(
        "\n## Verification\n\n\
         1. Verify both certificate signatures against the embedded engine verification key \
         (`signed_by`) over the domain-separated, schema-hash-prefixed preimage.\n\
         2. Replay the run: `frankenctl replay run --trace <nondeterminism-trace.json> --mode \
         strict` and confirm the trace content hash `{}`.\n\
         3. Re-emit the bundle from the same fixed inputs and confirm byte-identical files \
         (digests in `repro.lock`).\n",
        scope.replay_trace_content_hash_hex,
    ));
    out.push_str(&format!(
        "\n## Honesty boundary\n\n\
         This bundle never asserts a negative claim beyond its analyzed scope: verdicts are \
         limited to `holds_within_analyzed_scope`, `contradicted`, \
         `not_assertable_conservative`, and `unanalyzed_fail_closed`. The certificate status \
         (`{}`) is derived, never asserted — it requires an empty, scan-backed \
         `certifiable_subset` refusal ledger AND every requested claim to hold within the \
         analyzed explicit-flow subset; any unanalyzed construct keeps the run `uncertified` \
         (bd-fqlfw.8.4). Payload bytes never appear in the trace — only lengths and content \
         hashes.\n",
        non_use.certificate_status,
    ));
    out
}

/// Assemble, sign, and serialize the certificate bundle from a completed
/// data-contract run. Pure function of its inputs: identical inputs yield
/// byte-identical files.
pub fn emit_certificate_bundle(
    inputs: &CertifierInputs<'_>,
) -> Result<CertificateBundle, CertifierError> {
    let ingress = inputs.contract.ifc_ingress(inputs.binding)?;
    validate_evidence(&ingress, inputs)?;

    let mut declared_sinks: Vec<DeclaredSinkScope> = ingress
        .sinks
        .iter()
        .map(|sink| DeclaredSinkScope {
            sink_id: sink.sink_id.clone(),
            clearance: sink.clearance,
            location: sink.location.clone(),
            allowed_labels: sink.allowed_labels.iter().cloned().collect(),
        })
        .collect();
    declared_sinks.sort_by(|a, b| a.sink_id.cmp(&b.sink_id));

    let mut declassification_route_ids: Vec<String> = ingress
        .declassification_routes
        .iter()
        .map(|route| route.route_id.clone())
        .collect();
    declassification_route_ids.sort();

    let scope = CertificateScope {
        engine_version: inputs.engine_version.to_string(),
        policy_id: inputs.policy_id.to_string(),
        policy_epoch: inputs.policy_epoch,
        parse_goal: inputs.parse_goal.to_string(),
        contract_id: ingress.contract_id.clone(),
        contract_hash_hex: ingress.contract_hash_hex.clone(),
        extension_id: ingress.extension_id.clone(),
        run_input_binding_id: inputs.binding.run_input_binding_id.clone(),
        run_input_object_ref: inputs.binding.run_input_object_ref.clone(),
        run_input_path: inputs.binding.run_input_path.clone(),
        run_input_content_hash_hex: inputs.binding.run_input_content_hash_hex.clone(),
        purpose: ingress.purpose.clone(),
        trace_id: inputs.trace_id.to_string(),
        decision_id: inputs.decision_id.to_string(),
        containment_action: inputs.containment_action.to_string(),
        replay_trace_content_hash_hex: inputs.replay_trace_content_hash_hex.to_string(),
        declared_sinks,
        contract_capabilities: inputs
            .contract
            .allowed_capabilities
            .iter()
            .copied()
            .collect(),
        runtime_granted_capabilities: inputs
            .runtime_granted_capabilities
            .iter()
            .copied()
            .collect(),
        declassification_route_ids: declassification_route_ids.clone(),
        threat_model_scope: crate::data_contract::E8_REFUSAL_THREAT_MODEL_SCOPE.to_string(),
        analysis_posture: E8_CERTIFICATE_ANALYSIS_POSTURE.to_string(),
    };

    let claims: Vec<NonUseClaimVerdict> = inputs
        .contract
        .requested_output_claims
        .iter()
        .map(|claim| evaluate_claim(claim, &ingress, inputs))
        .collect();

    let refusal_ledger_content_hash_hex = ContentHash::compute(
        &serde_json::to_vec(inputs.refusal_receipt).map_err(|error| {
            CertifierError::SerializationFailed {
                target: "refusal ledger receipt".to_string(),
                detail: error.to_string(),
            }
        })?,
    )
    .to_hex();

    let mut certificate_seed = Vec::new();
    certificate_seed.extend_from_slice(b"e8-certificate-v1");
    append_seed_field(&mut certificate_seed, "trace_id", inputs.trace_id);
    append_seed_field(
        &mut certificate_seed,
        "contract_hash",
        &ingress.contract_hash_hex,
    );
    append_seed_field(
        &mut certificate_seed,
        "run_input_binding_id",
        &inputs.binding.run_input_binding_id,
    );
    append_seed_field(&mut certificate_seed, "purpose", &ingress.purpose);
    append_seed_field(
        &mut certificate_seed,
        "replay_trace_content_hash",
        inputs.replay_trace_content_hash_hex,
    );
    let certificate_seed_hash = ContentHash::compute(&certificate_seed).to_hex();

    let mut non_use = NonUseCertificate {
        schema_version: NON_USE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        certificate_id: format!("e8-nuc-{certificate_seed_hash}"),
        producer_id: E8_CERTIFIER_PRODUCER_ID.to_string(),
        scope: scope.clone(),
        certificate_status: derive_certificate_status(inputs.refusal_receipt, &claims),
        refusal_ledger_id: inputs.refusal_receipt.ledger_id.clone(),
        refusal_ledger_result_class: inputs.refusal_receipt.result_class.clone(),
        refusal_ledger_content_hash_hex,
        claims,
        flow_events: inputs.flow_events.to_vec(),
        declassification_receipt_count: inputs.declassification_receipts.len() as u64,
        signed_by: shared_evidence_verification_key(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    non_use.sign_with_runtime_key();

    let capabilities_granted_beyond_contract: Vec<RuntimeCapability> = inputs
        .runtime_granted_capabilities
        .difference(&inputs.contract.allowed_capabilities)
        .copied()
        .collect();
    let mut capability_use_records = Vec::new();
    for capability in inputs
        .contract
        .allowed_capabilities
        .union(inputs.runtime_granted_capabilities)
    {
        if let Some(evidence) = capability_use_evidence(*capability, inputs) {
            capability_use_records.push(CapabilityUseRecord {
                capability: *capability,
                evidence,
            });
        }
    }
    let mut sinks_potentially_reached: Vec<String> = ingress
        .sinks
        .iter()
        .filter(|sink| {
            let event_id = format!(
                "dc-ingress-{}-{}-{}",
                ingress.contract_id, ingress.run_input_binding_id, sink.sink_id
            );
            inputs.flow_events.iter().any(|event| {
                event.event_id == event_id
                    && matches!(
                        event.decision,
                        FlowDecision::Allowed | FlowDecision::Declassified
                    )
            })
        })
        .map(|sink| sink.sink_id.clone())
        .collect();
    sinks_potentially_reached.sort();

    let mut route_ids_exercised: Vec<String> = inputs
        .declassification_receipts
        .iter()
        .map(|receipt| receipt.declassification_route_ref.clone())
        .filter(|route_ref| !route_ref.is_empty())
        .collect();
    route_ids_exercised.sort();
    route_ids_exercised.dedup();

    let mut use_certificate = UseCertificate {
        schema_version: USE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        certificate_id: format!("e8-uc-{certificate_seed_hash}"),
        producer_id: E8_CERTIFIER_PRODUCER_ID.to_string(),
        scope,
        inputs_bound: inputs
            .contract
            .input_bindings
            .iter()
            .map(|binding| BoundInputRecord {
                binding_id: binding.binding_id.clone(),
                object_ref: binding.object_ref.clone(),
                label: binding.label.clone(),
                role: format!("{:?}", binding.role),
                ingressed: binding.binding_id == inputs.binding.run_input_binding_id,
            })
            .collect(),
        contract_capability_envelope_respected: capabilities_granted_beyond_contract.is_empty(),
        capabilities_granted_beyond_contract,
        capability_use_evidence: capability_use_records,
        sinks_potentially_reached,
        declassification_route_ids_exercised: route_ids_exercised,
        output_dependency_posture: format!(
            "conservative over-approximation: the output may depend on every ingressed input \
             binding and every capability with recorded use; independence claims are evaluated \
             fail-closed in {NON_USE_CERTIFICATE_FILE}"
        ),
        console_entry_count: inputs.console_entry_count,
        instructions_executed: inputs.instructions_executed,
        execution_value_content_hash_hex: ContentHash::compute(inputs.execution_value.as_bytes())
            .to_hex(),
        signed_by: shared_evidence_verification_key(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    use_certificate.sign_with_runtime_key();

    let mut sorted_receipts = inputs.declassification_receipts.to_vec();
    sorted_receipts.sort_by(|a, b| a.receipt_id.cmp(&b.receipt_id));
    let trace_records = build_capability_trace(inputs);

    let non_use_bytes = json_pretty_bytes(&non_use, NON_USE_CERTIFICATE_FILE)?;
    let use_bytes = json_pretty_bytes(&use_certificate, USE_CERTIFICATE_FILE)?;
    let receipts_bytes = jsonl_bytes(&sorted_receipts, DECLASSIFICATION_RECEIPTS_FILE)?;
    let trace_bytes = jsonl_bytes(&trace_records, CAPABILITY_TRACE_FILE)?;
    let audit_markdown = render_audit_markdown(
        &non_use,
        &use_certificate,
        sorted_receipts.len(),
        trace_records.len(),
    );
    let audit_bytes = audit_markdown.into_bytes();

    let digest_sources = [
        (NON_USE_CERTIFICATE_FILE, &non_use_bytes),
        (USE_CERTIFICATE_FILE, &use_bytes),
        (DECLASSIFICATION_RECEIPTS_FILE, &receipts_bytes),
        (CAPABILITY_TRACE_FILE, &trace_bytes),
        (AUDIT_FILE, &audit_bytes),
    ];
    let files_digests: Vec<CertificateBundleFileDigest> = digest_sources
        .iter()
        .map(|(name, bytes)| CertificateBundleFileDigest {
            name: (*name).to_string(),
            sha256_hex: ContentHash::compute(bytes).to_hex(),
            bytes: bytes.len() as u64,
        })
        .collect();

    let mut lock_seed = Vec::new();
    lock_seed.extend_from_slice(b"e8-cert-lock-v1");
    for digest in &files_digests {
        append_seed_field(&mut lock_seed, &digest.name, &digest.sha256_hex);
    }
    let repro_lock = CertificateReproLock {
        schema_version: E8_CERTIFICATE_REPRO_LOCK_SCHEMA_VERSION.to_string(),
        schema_hash: format!(
            "sha256:{}",
            ContentHash::compute(E8_CERTIFICATE_BUNDLE_SCHEMA_VERSION.as_bytes()).to_hex()
        ),
        lock_id: format!("e8-cert-lock-{}", ContentHash::compute(&lock_seed).to_hex()),
        bundle_schema_version: E8_CERTIFICATE_BUNDLE_SCHEMA_VERSION.to_string(),
        determinism: CertificateReproDeterminism {
            allow_network: false,
            allow_wall_clock: false,
            allow_randomness: false,
        },
        replay: CertificateReproReplay {
            trace_id: inputs.trace_id.to_string(),
            decision_id: inputs.decision_id.to_string(),
            policy_id: inputs.policy_id.to_string(),
            replay_pointer: inputs.replay_trace_content_hash_hex.to_string(),
        },
        files: files_digests,
        commands: vec![
            format!(
                "frankenctl run --input {} --extension-id {} --goal {} --data-contract \
                 <contract.json> --purpose {} --certificate-out <bundle-dir>",
                non_use.scope.run_input_path,
                non_use.scope.extension_id,
                non_use.scope.parse_goal,
                non_use.scope.purpose,
            ),
            "frankenctl replay run --trace <nondeterminism-trace.json> --mode strict".to_string(),
        ],
    };
    let lock_bytes = json_pretty_bytes(&repro_lock, REPRO_LOCK_FILE)?;

    let files = vec![
        CertificateBundleFile {
            name: NON_USE_CERTIFICATE_FILE.to_string(),
            bytes: non_use_bytes,
        },
        CertificateBundleFile {
            name: USE_CERTIFICATE_FILE.to_string(),
            bytes: use_bytes,
        },
        CertificateBundleFile {
            name: DECLASSIFICATION_RECEIPTS_FILE.to_string(),
            bytes: receipts_bytes,
        },
        CertificateBundleFile {
            name: CAPABILITY_TRACE_FILE.to_string(),
            bytes: trace_bytes,
        },
        CertificateBundleFile {
            name: REPRO_LOCK_FILE.to_string(),
            bytes: lock_bytes,
        },
        CertificateBundleFile {
            name: AUDIT_FILE.to_string(),
            bytes: audit_bytes,
        },
    ];

    let mut bundle_seed = Vec::new();
    bundle_seed.extend_from_slice(b"e8-cert-bundle-v1");
    for file in &files {
        bundle_seed.extend_from_slice(&(file.name.len() as u64).to_be_bytes());
        bundle_seed.extend_from_slice(file.name.as_bytes());
        bundle_seed.extend_from_slice(&(file.bytes.len() as u64).to_be_bytes());
        bundle_seed.extend_from_slice(&file.bytes);
    }

    Ok(CertificateBundle {
        non_use_certificate: non_use,
        use_certificate,
        repro_lock,
        files,
        bundle_content_hash_hex: ContentHash::compute(&bundle_seed).to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::data_contract::{
        DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
        RequiredDeclassificationRoute, SinkBinding,
    };
    use crate::ifc_artifacts::DeclassificationRoute;

    fn contract() -> DataContract {
        DataContract {
            schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
            contract_id: "contract-e8-cert".to_string(),
            extension_id: "ext-e8-cert".to_string(),
            input_bindings: vec![
                DataBinding {
                    binding_id: "source-js".to_string(),
                    object_ref: "object://source-js".to_string(),
                    path: Some("agent.js".to_string()),
                    label: Label::Public,
                    owner: "runtime-team".to_string(),
                    role: DataBindingRole::RunInput,
                    allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                    content_hash_hex: None,
                },
                DataBinding {
                    binding_id: "customer-pii".to_string(),
                    object_ref: "dataset://customer-pii".to_string(),
                    path: None,
                    label: Label::Secret,
                    owner: "data-owner".to_string(),
                    role: DataBindingRole::SensitiveInput,
                    allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                    content_hash_hex: None,
                },
            ],
            allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
            allowed_capabilities: BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]),
            allowed_sinks: vec![SinkBinding {
                sink_id: "stdout".to_string(),
                clearance: ClearanceClass::RestrictedSink,
                location: "console".to_string(),
                allowed_labels: BTreeSet::from([Label::Public, Label::Internal]),
            }],
            required_declassification_routes: vec![],
            requested_output_claims: vec![
                RequestedOutputClaim::NoFlow {
                    claim_id: "no-secret-open-sink".to_string(),
                    source_label: Label::Secret,
                    sink_clearance: ClearanceClass::OpenSink,
                },
                RequestedOutputClaim::CapabilityNotUsed {
                    claim_id: "no-process-spawn".to_string(),
                    capability: RuntimeCapability::ProcessSpawn,
                },
                RequestedOutputClaim::OutputIndependentOf {
                    claim_id: "output-independent-of-pii".to_string(),
                    binding_id: "customer-pii".to_string(),
                },
            ],
            metadata: BTreeMap::new(),
        }
    }

    struct Fixture {
        contract: DataContract,
        binding: DataContractRunBinding,
        flow_events: Vec<FlowEventRecord>,
        refusal_receipt: E8RefusalLedgerReceipt,
        runtime_granted: BTreeSet<RuntimeCapability>,
    }

    fn fixture() -> Fixture {
        fixture_with_contract(contract())
    }

    fn fixture_with_contract(contract: DataContract) -> Fixture {
        let binding = contract
            .bind_to_run(
                &contract.extension_id,
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                None,
            )
            .expect("contract binds");
        let ingress = contract.ifc_ingress(&binding).expect("ingress derives");
        let flow_events = ingress
            .sinks
            .iter()
            .map(|sink| {
                let receivable = sink.clearance.can_receive(&ingress.source_label)
                    && sink.allowed_labels.contains(&ingress.source_label);
                FlowEventRecord {
                    event_id: format!(
                        "dc-ingress-{}-{}-{}",
                        ingress.contract_id, ingress.run_input_binding_id, sink.sink_id
                    ),
                    extension_id: ingress.extension_id.clone(),
                    source_label: ingress.source_label.clone(),
                    sink_clearance: ingress.source_label.clone(),
                    flow_location: format!(
                        "data_contract:{}:sink:{}:purpose:{}",
                        ingress.contract_id, sink.sink_id, ingress.purpose
                    ),
                    decision: if receivable {
                        FlowDecision::Allowed
                    } else {
                        FlowDecision::Blocked
                    },
                    receipt_ref: None,
                    timestamp_ms: 7,
                }
            })
            .collect();
        let refusal_receipt = binding.uncertified_preflight_receipt("trace-e8-cert", None);
        Fixture {
            contract,
            binding,
            flow_events,
            refusal_receipt,
            runtime_granted: BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]),
        }
    }

    fn inputs<'a>(
        fixture: &'a Fixture,
        host_effects: &'a [(HostIoRequest, HostIoOutcome)],
        receipts: &'a [DeclassificationReceipt],
    ) -> CertifierInputs<'a> {
        CertifierInputs {
            contract: &fixture.contract,
            binding: &fixture.binding,
            flow_events: &fixture.flow_events,
            host_effects,
            declassification_receipts: receipts,
            refusal_receipt: &fixture.refusal_receipt,
            runtime_granted_capabilities: &fixture.runtime_granted,
            policy_id: "policy-e8",
            policy_epoch: 7,
            parse_goal: "script",
            trace_id: "trace-e8-cert",
            decision_id: "decision-e8-cert",
            engine_version: "0.1.0-test",
            containment_action: "allow",
            instructions_executed: 42,
            console_entry_count: 1,
            execution_value: "\"ok\"",
            replay_trace_content_hash_hex: "0000000000000000000000000000000000000000000000000000000000000042",
        }
    }

    fn emit(fixture: &Fixture) -> CertificateBundle {
        emit_certificate_bundle(&inputs(fixture, &[], &[])).expect("bundle emits")
    }

    #[test]
    fn bundle_contains_exactly_the_six_declared_files() {
        let bundle = emit(&fixture());
        let names: Vec<&str> = bundle.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                NON_USE_CERTIFICATE_FILE,
                USE_CERTIFICATE_FILE,
                DECLASSIFICATION_RECEIPTS_FILE,
                CAPABILITY_TRACE_FILE,
                REPRO_LOCK_FILE,
                AUDIT_FILE,
            ]
        );
    }

    #[test]
    fn bundle_is_byte_identical_across_reemission() {
        let fixture = fixture();
        let first = emit(&fixture);
        let second = emit(&fixture);
        assert_eq!(
            first.bundle_content_hash_hex,
            second.bundle_content_hash_hex
        );
        for (a, b) in first.files.iter().zip(second.files.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.bytes, b.bytes, "file `{}` must be byte-identical", a.name);
        }
    }

    #[test]
    fn no_flow_claim_holds_when_no_matching_sink_is_declared() {
        let bundle = emit(&fixture());
        let verdict = bundle
            .non_use_certificate
            .claims
            .iter()
            .find(|claim| claim.claim_id == "no-secret-open-sink")
            .expect("claim present");
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert!(verdict.detail.contains("no declared sink"));
    }

    #[test]
    fn no_flow_claim_is_not_assertable_when_allowed_edge_matches() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::NoFlow {
            claim_id: "no-public-restricted".to_string(),
            source_label: Label::Public,
            sink_clearance: ClearanceClass::RestrictedSink,
        }];
        let fixture = fixture_with_contract(contract);
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::NotAssertableConservative
        );
        assert!(
            verdict
                .evidence_refs
                .iter()
                .any(|evidence| evidence.starts_with("flow_event:dc-ingress-"))
        );
    }

    #[test]
    fn no_flow_claim_holds_when_ingress_label_is_below_claim_label() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::NoFlow {
            claim_id: "no-secret-restricted".to_string(),
            source_label: Label::Secret,
            sink_clearance: ClearanceClass::RestrictedSink,
        }];
        let fixture = fixture_with_contract(contract);
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert!(verdict.detail.contains("no data at or above label"));
    }

    #[test]
    fn no_flow_claim_treats_blocked_edges_as_non_flows() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::NoFlow {
            claim_id: "no-public-restricted".to_string(),
            source_label: Label::Public,
            sink_clearance: ClearanceClass::RestrictedSink,
        }];
        let mut fixture = fixture_with_contract(contract);
        for event in &mut fixture.flow_events {
            event.decision = FlowDecision::Blocked;
        }
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
    }

    #[test]
    fn no_flow_claim_fails_closed_when_a_declared_sink_has_no_edge() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::NoFlow {
            claim_id: "no-public-restricted".to_string(),
            source_label: Label::Public,
            sink_clearance: ClearanceClass::RestrictedSink,
        }];
        let mut fixture = fixture_with_contract(contract);
        fixture.flow_events.clear();
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::NotAssertableConservative
        );
        assert!(
            verdict
                .evidence_refs
                .iter()
                .any(|evidence| evidence.starts_with("missing_flow_event:"))
        );
    }

    #[test]
    fn capability_not_used_holds_for_ungranted_capability() {
        let bundle = emit(&fixture());
        let verdict = bundle
            .non_use_certificate
            .claims
            .iter()
            .find(|claim| claim.claim_id == "no-process-spawn")
            .expect("claim present");
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert!(verdict.detail.contains("fail-closed"));
    }

    #[test]
    fn capability_not_used_is_contradicted_by_console_evidence() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::CapabilityNotUsed {
            claim_id: "no-console".to_string(),
            capability: RuntimeCapability::Console,
        }];
        let fixture = fixture_with_contract(contract);
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(verdict.evaluation, ClaimEvaluation::Contradicted);
        assert!(verdict.detail.contains("console"));
    }

    #[test]
    fn capability_not_used_is_contradicted_by_host_effect_evidence() {
        let mut contract = contract();
        contract
            .allowed_capabilities
            .insert(RuntimeCapability::FsRead);
        contract.requested_output_claims = vec![RequestedOutputClaim::CapabilityNotUsed {
            claim_id: "no-fs-read".to_string(),
            capability: RuntimeCapability::FsRead,
        }];
        let fixture = fixture_with_contract(contract);
        let effects = vec![(
            HostIoRequest::FsRead {
                path: "/tmp/data.txt".to_string(),
            },
            Ok(frankenengine_extension_host::host_io::HostIoResponse::FsRead { bytes: vec![1] }),
        )];
        let bundle = emit_certificate_bundle(&inputs(&fixture, &effects, &[])).expect("emits");
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(verdict.evaluation, ClaimEvaluation::Contradicted);
    }

    #[test]
    fn capability_not_used_is_not_assertable_for_granted_unused_capability() {
        let mut contract = contract();
        contract
            .allowed_capabilities
            .insert(RuntimeCapability::NetworkEgress);
        contract.requested_output_claims = vec![RequestedOutputClaim::CapabilityNotUsed {
            claim_id: "no-network".to_string(),
            capability: RuntimeCapability::NetworkEgress,
        }];
        let fixture = fixture_with_contract(contract);
        let bundle = emit(&fixture);
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::NotAssertableConservative
        );
    }

    #[test]
    fn denied_host_effect_does_not_contradict_capability_claim() {
        let mut contract = contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::CapabilityNotUsed {
            claim_id: "no-fs-write".to_string(),
            capability: RuntimeCapability::FsWrite,
        }];
        let fixture = fixture_with_contract(contract);
        let effects = vec![(
            HostIoRequest::FsWrite {
                path: "/etc/passwd".to_string(),
                data: vec![0],
            },
            Err(
                frankenengine_extension_host::host_io::HostIoError::CapabilityMissing {
                    capability: HostIoCapability::FsWrite,
                },
            ),
        )];
        let bundle = emit_certificate_bundle(&inputs(&fixture, &effects, &[])).expect("emits");
        let verdict = &bundle.non_use_certificate.claims[0];
        assert_eq!(
            verdict.evaluation,
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
    }

    #[test]
    fn output_independence_claim_fails_closed_as_unanalyzed() {
        let bundle = emit(&fixture());
        let verdict = bundle
            .non_use_certificate
            .claims
            .iter()
            .find(|claim| claim.claim_id == "output-independent-of-pii")
            .expect("claim present");
        assert_eq!(verdict.evaluation, ClaimEvaluation::UnanalyzedFailClosed);
        assert!(verdict.detail.contains("bd-fqlfw.8.4"));
    }

    #[test]
    fn certificate_status_is_uncertified_under_v1_refusal_receipt() {
        let bundle = emit(&fixture());
        assert_eq!(
            bundle.non_use_certificate.certificate_status,
            CertificateStatus::Uncertified
        );
        assert_eq!(
            bundle.non_use_certificate.refusal_ledger_id,
            fixture().refusal_receipt.ledger_id
        );
    }

    #[test]
    fn both_certificate_signatures_verify() {
        let bundle = emit(&fixture());
        bundle
            .non_use_certificate
            .verify()
            .expect("non-use signature verifies");
        bundle
            .use_certificate
            .verify()
            .expect("use signature verifies");
    }

    #[test]
    fn tampered_certificate_fails_verification() {
        let bundle = emit(&fixture());
        let mut tampered = bundle.non_use_certificate.clone();
        tampered.certificate_status = CertificateStatus::CertifiedWithinAnalyzedScope;
        assert!(matches!(
            tampered.verify(),
            Err(CertifierError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn repro_lock_digests_match_emitted_file_bytes() {
        let bundle = emit(&fixture());
        assert_eq!(bundle.repro_lock.files.len(), 5);
        for digest in &bundle.repro_lock.files {
            let file = bundle.file(&digest.name).expect("digested file exists");
            assert_eq!(
                digest.sha256_hex,
                ContentHash::compute(&file.bytes).to_hex(),
                "digest mismatch for `{}`",
                digest.name
            );
            assert_eq!(digest.bytes, file.bytes.len() as u64);
        }
    }

    #[test]
    fn repro_lock_carries_replay_pointer_and_no_wall_clock() {
        let bundle = emit(&fixture());
        assert_eq!(
            bundle.repro_lock.replay.replay_pointer,
            "0000000000000000000000000000000000000000000000000000000000000042"
        );
        assert!(!bundle.repro_lock.determinism.allow_wall_clock);
        assert!(!bundle.repro_lock.determinism.allow_randomness);
        assert!(!bundle.repro_lock.determinism.allow_network);
    }

    #[test]
    fn capability_trace_records_grants_effects_and_console() {
        let fixture = fixture();
        let effects = vec![(
            HostIoRequest::NetworkSend {
                endpoint: "https://example.com".to_string(),
                payload: vec![1, 2, 3],
            },
            Err(
                frankenengine_extension_host::host_io::HostIoError::CapabilityMissing {
                    capability: HostIoCapability::NetworkSend,
                },
            ),
        )];
        let bundle = emit_certificate_bundle(&inputs(&fixture, &effects, &[])).expect("emits");
        let trace_file = bundle.file(CAPABILITY_TRACE_FILE).expect("trace file");
        let lines: Vec<CapabilityTraceRecord> = String::from_utf8(trace_file.bytes.clone())
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("trace line parses"))
            .collect();
        let grants = lines
            .iter()
            .filter(|record| matches!(record, CapabilityTraceRecord::Grant { .. }))
            .count();
        // 3 contract grants + 3 runtime grants.
        assert_eq!(grants, 6);
        assert!(lines.iter().any(|record| matches!(
            record,
            CapabilityTraceRecord::HostEffect { outcome, .. } if outcome.starts_with("denied:")
        )));
        assert!(
            lines
                .iter()
                .any(|record| matches!(record, CapabilityTraceRecord::ConsoleSummary { entries } if *entries == 1))
        );
    }

    #[test]
    fn capability_trace_never_embeds_payload_bytes() {
        let fixture = fixture();
        let secret_payload = b"api-key-hunter2".to_vec();
        let effects = vec![(
            HostIoRequest::NetworkSend {
                endpoint: "https://exfil.example".to_string(),
                payload: secret_payload.clone(),
            },
            Err(
                frankenengine_extension_host::host_io::HostIoError::CapabilityMissing {
                    capability: HostIoCapability::NetworkSend,
                },
            ),
        )];
        let bundle = emit_certificate_bundle(&inputs(&fixture, &effects, &[])).expect("emits");
        for file in &bundle.files {
            let haystack = String::from_utf8_lossy(&file.bytes);
            assert!(
                !haystack.contains("hunter2"),
                "payload bytes leaked into `{}`",
                file.name
            );
        }
    }

    #[test]
    fn declassification_receipts_file_is_empty_without_receipts() {
        let bundle = emit(&fixture());
        let file = bundle
            .file(DECLASSIFICATION_RECEIPTS_FILE)
            .expect("receipts file");
        assert!(file.bytes.is_empty());
        assert_eq!(bundle.non_use_certificate.declassification_receipt_count, 0);
    }

    #[test]
    fn audit_markdown_states_scope_and_threat_model() {
        let bundle = emit(&fixture());
        let audit = String::from_utf8(bundle.file(AUDIT_FILE).expect("audit").bytes.clone())
            .expect("audit is utf8");
        assert!(audit.contains("Under engine version `0.1.0-test`"));
        assert!(audit.contains("security epoch 7"));
        assert!(audit.contains("EXPLICIT-FLOW ONLY"));
        assert!(audit.contains("explicit_flow_ifc_v1"));
        assert!(audit.contains("uncertified"));
        assert!(audit.contains("0000000000000000000000000000000000000000000000000000000000000042"));
    }

    #[test]
    fn scope_carries_declared_host_boundary_and_capability_envelopes() {
        let bundle = emit(&fixture());
        let scope = &bundle.non_use_certificate.scope;
        assert_eq!(scope.declared_sinks.len(), 1);
        assert_eq!(scope.declared_sinks[0].sink_id, "stdout");
        assert_eq!(scope.contract_capabilities.len(), 3);
        assert_eq!(scope.runtime_granted_capabilities.len(), 3);
        assert_eq!(
            scope.threat_model_scope,
            crate::data_contract::E8_REFUSAL_THREAT_MODEL_SCOPE
        );
        assert_eq!(scope.analysis_posture, E8_CERTIFICATE_ANALYSIS_POSTURE);
    }

    #[test]
    fn use_certificate_reports_envelope_violation() {
        let mut fixture = fixture();
        fixture
            .runtime_granted
            .insert(RuntimeCapability::ProcessSpawn);
        let bundle = emit(&fixture);
        assert!(
            !bundle
                .use_certificate
                .contract_capability_envelope_respected
        );
        assert_eq!(
            bundle.use_certificate.capabilities_granted_beyond_contract,
            vec![RuntimeCapability::ProcessSpawn]
        );
    }

    #[test]
    fn use_certificate_lists_ingressed_binding_and_reached_sinks() {
        let bundle = emit(&fixture());
        let ingressed: Vec<_> = bundle
            .use_certificate
            .inputs_bound
            .iter()
            .filter(|record| record.ingressed)
            .collect();
        assert_eq!(ingressed.len(), 1);
        assert_eq!(ingressed[0].binding_id, "source-js");
        assert_eq!(
            bundle.use_certificate.sinks_potentially_reached,
            vec!["stdout".to_string()]
        );
    }

    #[test]
    fn foreign_extension_flow_event_fails_closed() {
        let mut fixture = fixture();
        fixture.flow_events[0].extension_id = "ext-other".to_string();
        let error = emit_certificate_bundle(&inputs(&fixture, &[], &[]))
            .expect_err("foreign extension must fail closed");
        assert!(matches!(
            error,
            CertifierError::EvidenceExtensionMismatch { .. }
        ));
    }

    #[test]
    fn foreign_contract_flow_event_fails_closed() {
        let mut fixture = fixture();
        fixture.flow_events[0].flow_location = "data_contract:other:sink:x:purpose:p".to_string();
        let error = emit_certificate_bundle(&inputs(&fixture, &[], &[]))
            .expect_err("foreign contract must fail closed");
        assert!(matches!(
            error,
            CertifierError::EvidenceContractMismatch { .. }
        ));
    }

    #[test]
    fn refusal_receipt_for_other_run_fails_closed() {
        let mut fixture = fixture();
        fixture.refusal_receipt = fixture
            .binding
            .uncertified_preflight_receipt("trace-other", None);
        let error = emit_certificate_bundle(&inputs(&fixture, &[], &[]))
            .expect_err("mismatched refusal receipt must fail closed");
        assert!(matches!(
            error,
            CertifierError::RefusalReceiptRunMismatch { .. }
        ));
    }

    #[test]
    fn declassified_edge_without_receipt_fails_closed() {
        let mut fixture = fixture();
        fixture.flow_events[0].decision = FlowDecision::Declassified;
        fixture.flow_events[0].receipt_ref = None;
        let error = emit_certificate_bundle(&inputs(&fixture, &[], &[]))
            .expect_err("declassified edge without receipt must fail closed");
        assert!(matches!(
            error,
            CertifierError::DeclassifiedEdgeWithoutReceipt { .. }
        ));
    }

    #[test]
    fn binding_from_another_contract_fails_closed() {
        let fixture = fixture();
        let mut other = contract();
        other.contract_id = "contract-other".to_string();
        let mut bad_inputs = inputs(&fixture, &[], &[]);
        bad_inputs.contract = &other;
        let error = emit_certificate_bundle(&bad_inputs)
            .expect_err("binding/contract mismatch must fail closed");
        assert!(matches!(error, CertifierError::ContractBinding(_)));
    }

    #[test]
    fn certificate_ids_are_content_derived_and_stable() {
        let fixture = fixture();
        let first = emit(&fixture);
        let second = emit(&fixture);
        assert_eq!(
            first.non_use_certificate.certificate_id,
            second.non_use_certificate.certificate_id
        );
        assert!(
            first
                .non_use_certificate
                .certificate_id
                .starts_with("e8-nuc-")
        );
        assert!(first.use_certificate.certificate_id.starts_with("e8-uc-"));
        let suffix = |id: &str| id.rsplit('-').next().unwrap().to_string();
        assert_eq!(
            suffix(&first.non_use_certificate.certificate_id),
            suffix(&first.use_certificate.certificate_id)
        );
    }

    #[test]
    fn certificate_ids_change_when_replay_artifact_changes() {
        let fixture = fixture();
        let baseline = emit(&fixture);
        let mut changed_inputs = inputs(&fixture, &[], &[]);
        changed_inputs.replay_trace_content_hash_hex =
            "1111111111111111111111111111111111111111111111111111111111111111";
        let changed = emit_certificate_bundle(&changed_inputs).expect("emits");
        assert_ne!(
            baseline.non_use_certificate.certificate_id,
            changed.non_use_certificate.certificate_id
        );
    }

    #[test]
    fn non_use_certificate_round_trips_through_serde() {
        let bundle = emit(&fixture());
        let file = bundle.file(NON_USE_CERTIFICATE_FILE).expect("file");
        let parsed: NonUseCertificate =
            serde_json::from_slice(&file.bytes).expect("certificate parses");
        assert_eq!(parsed, bundle.non_use_certificate);
        parsed.verify().expect("parsed certificate verifies");
    }

    #[test]
    fn use_certificate_round_trips_through_serde() {
        let bundle = emit(&fixture());
        let file = bundle.file(USE_CERTIFICATE_FILE).expect("file");
        let parsed: UseCertificate = serde_json::from_slice(&file.bytes).expect("parses");
        assert_eq!(parsed, bundle.use_certificate);
        parsed.verify().expect("parsed certificate verifies");
    }

    #[test]
    fn declassification_route_scope_is_sorted_and_complete() {
        let mut contract = contract();
        contract.required_declassification_routes = vec![
            RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-b".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Internal,
                    conditions: vec!["receipt_required".to_string()],
                },
                required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
            },
            RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-a".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Public,
                    conditions: vec!["owner_approval".to_string()],
                },
                required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
            },
        ];
        let fixture = fixture_with_contract(contract);
        let bundle = emit(&fixture);
        assert_eq!(
            bundle.non_use_certificate.scope.declassification_route_ids,
            vec!["route-a".to_string(), "route-b".to_string()]
        );
    }

    // -- bd-fqlfw.8.4: derived status + receipt-aware claim lanes ------------

    use crate::ast::ParseGoal;
    use crate::e8_analyzed_subset::scan_source;
    use crate::hash_tiers::ContentHash as TestContentHash;

    const CERTIFIABLE_SOURCE: &str = "const answer = 40 + 2;";

    /// A contract whose requested claims all hold on a clean run: no OpenSink
    /// is declared, ProcessSpawn is ungranted, NetworkEgress is witnessed and
    /// unused, and customer-pii never ingresses.
    fn certifiable_contract() -> DataContract {
        let mut contract = contract();
        contract.requested_output_claims = vec![
            RequestedOutputClaim::NoFlow {
                claim_id: "no-secret-open-sink".to_string(),
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::OpenSink,
            },
            RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-process-spawn".to_string(),
                capability: RuntimeCapability::ProcessSpawn,
            },
            RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-network-egress".to_string(),
                capability: RuntimeCapability::NetworkEgress,
            },
            RequestedOutputClaim::OutputIndependentOf {
                claim_id: "output-independent-of-pii".to_string(),
                binding_id: "customer-pii".to_string(),
            },
        ];
        contract
    }

    /// Fixture whose refusal ledger is a scan-backed `certifiable_subset`
    /// receipt: hash-bound scan of a fully-analyzed source plus a linked
    /// explain bundle.
    fn certifiable_fixture() -> Fixture {
        let contract = certifiable_contract();
        let binding = contract
            .bind_to_run(
                &contract.extension_id,
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                Some(&TestContentHash::compute(CERTIFIABLE_SOURCE.as_bytes())),
            )
            .expect("contract binds");
        let ingress = contract.ifc_ingress(&binding).expect("ingress derives");
        let flow_events = ingress
            .sinks
            .iter()
            .map(|sink| {
                let receivable = sink.clearance.can_receive(&ingress.source_label)
                    && sink.allowed_labels.contains(&ingress.source_label);
                FlowEventRecord {
                    event_id: format!(
                        "dc-ingress-{}-{}-{}",
                        ingress.contract_id, ingress.run_input_binding_id, sink.sink_id
                    ),
                    extension_id: ingress.extension_id.clone(),
                    source_label: ingress.source_label.clone(),
                    sink_clearance: ingress.source_label.clone(),
                    flow_location: format!(
                        "data_contract:{}:sink:{}:purpose:{}",
                        ingress.contract_id, sink.sink_id, ingress.purpose
                    ),
                    decision: if receivable {
                        FlowDecision::Allowed
                    } else {
                        FlowDecision::Blocked
                    },
                    receipt_ref: None,
                    timestamp_ms: 7,
                }
            })
            .collect();
        let scan = scan_source(CERTIFIABLE_SOURCE, "agent.js", ParseGoal::Script);
        assert!(scan.is_fully_analyzed(), "fixture source must scan clean");
        let refusal_receipt = binding.preflight_receipt(
            "trace-e8-cert",
            Some("agent.explain.json"),
            Some(&scan),
            &[],
        );
        Fixture {
            contract,
            binding,
            flow_events,
            refusal_receipt,
            runtime_granted: BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
                RuntimeCapability::NetworkEgress,
            ]),
        }
    }

    fn holds(bundle: &CertificateBundle, claim_id: &str) -> ClaimEvaluation {
        bundle
            .non_use_certificate
            .claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
            .unwrap_or_else(|| panic!("claim `{claim_id}` present"))
            .evaluation
    }

    #[test]
    fn refusal_ledger_certifiable_requires_every_gate() {
        let fixture = certifiable_fixture();
        let receipt = &fixture.refusal_receipt;
        assert!(refusal_ledger_certifiable(receipt));

        let mut blocked = receipt.clone();
        blocked.must_block_certificate = true;
        assert!(!refusal_ledger_certifiable(&blocked));

        let mut no_input = receipt.clone();
        no_input.certifier_input_allowed = false;
        assert!(!refusal_ledger_certifiable(&no_input));

        let mut wrong_class = receipt.clone();
        wrong_class.result_class = "uncertified".to_string();
        assert!(!refusal_ledger_certifiable(&wrong_class));

        let mut with_code = receipt.clone();
        with_code
            .refusal_codes
            .push(crate::data_contract::E8RefusalCode {
                code: "unproven_ifc_propagation".to_string(),
                class: "uncertified".to_string(),
                source_ref_id: "r".to_string(),
                remediation: "m".to_string(),
            });
        assert!(!refusal_ledger_certifiable(&with_code));

        let mut unanalyzed = receipt.clone();
        unanalyzed.unanalyzed_surface_count = 1;
        assert!(!refusal_ledger_certifiable(&unanalyzed));
    }

    #[test]
    fn derived_status_requires_certifiable_ledger_and_all_claims_holding() {
        let fixture = certifiable_fixture();
        let hold = NonUseClaimVerdict {
            claim_id: "c".to_string(),
            claim: RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "c".to_string(),
                capability: RuntimeCapability::ProcessSpawn,
            },
            evaluation: ClaimEvaluation::HoldsWithinAnalyzedScope,
            evidence_refs: vec![],
            detail: String::new(),
        };
        let mut weaker = hold.clone();
        weaker.evaluation = ClaimEvaluation::NotAssertableConservative;

        assert_eq!(
            derive_certificate_status(&fixture.refusal_receipt, std::slice::from_ref(&hold)),
            CertificateStatus::CertifiedWithinAnalyzedScope
        );
        assert_eq!(
            derive_certificate_status(&fixture.refusal_receipt, &[hold.clone(), weaker]),
            CertificateStatus::Uncertified
        );
        let legacy = fixture
            .binding
            .uncertified_preflight_receipt("trace-e8-cert", None);
        assert_eq!(
            derive_certificate_status(&legacy, &[hold]),
            CertificateStatus::Uncertified
        );
    }

    /// ACCEPTANCE (bd-fqlfw.8.4, positive direction): a fully-analyzed run
    /// with complete evidence and claims that all hold certifies within the
    /// analyzed scope.
    #[test]
    fn fully_analyzed_run_certifies_within_analyzed_scope() {
        let fixture = certifiable_fixture();
        let bundle = emit(&fixture);
        assert_eq!(
            bundle.non_use_certificate.certificate_status,
            CertificateStatus::CertifiedWithinAnalyzedScope
        );
        assert_eq!(
            holds(&bundle, "no-secret-open-sink"),
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert_eq!(
            holds(&bundle, "no-process-spawn"),
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert_eq!(
            holds(&bundle, "no-network-egress"),
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
        assert_eq!(
            holds(&bundle, "output-independent-of-pii"),
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );
    }

    #[test]
    fn certified_audit_states_the_derived_status() {
        let fixture = certifiable_fixture();
        let bundle = emit(&fixture);
        let audit = String::from_utf8(bundle.file(AUDIT_FILE).expect("audit").bytes.clone())
            .expect("audit is utf8");
        assert!(audit.contains("certified_within_analyzed_scope"));
        assert!(audit.contains("EXPLICIT-FLOW ONLY"));
        assert!(audit.contains("E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md"));
    }

    #[test]
    fn granted_unused_witnessed_capability_holds_only_under_certified_scan() {
        // Certifiable ledger: NetworkEgress is runtime-granted, witnessed,
        // and unused -> holds within the analyzed scope.
        let fixture = certifiable_fixture();
        let bundle = emit(&fixture);
        assert_eq!(
            holds(&bundle, "no-network-egress"),
            ClaimEvaluation::HoldsWithinAnalyzedScope
        );

        // Same claim under the legacy (blocked) ledger stays not-assertable.
        let mut legacy = certifiable_fixture();
        legacy.refusal_receipt = legacy
            .binding
            .uncertified_preflight_receipt("trace-e8-cert", None);
        let bundle = emit(&legacy);
        assert_eq!(
            holds(&bundle, "no-network-egress"),
            ClaimEvaluation::NotAssertableConservative
        );
        assert_eq!(
            bundle.non_use_certificate.certificate_status,
            CertificateStatus::Uncertified
        );
    }

    #[test]
    fn granted_unwitnessed_capability_stays_not_assertable_even_when_certified() {
        let mut contract = certifiable_contract();
        contract
            .requested_output_claims
            .push(RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-builtin".to_string(),
                capability: RuntimeCapability::Builtin,
            });
        let mut fixture = certifiable_fixture();
        // Rebind against the modified contract so ids and hashes line up.
        let binding = contract
            .bind_to_run(
                &contract.extension_id,
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                Some(&TestContentHash::compute(CERTIFIABLE_SOURCE.as_bytes())),
            )
            .expect("contract binds");
        let scan = scan_source(CERTIFIABLE_SOURCE, "agent.js", ParseGoal::Script);
        fixture.refusal_receipt = binding.preflight_receipt(
            "trace-e8-cert",
            Some("agent.explain.json"),
            Some(&scan),
            &[],
        );
        fixture.binding = binding;
        fixture.contract = contract;
        let bundle = emit(&fixture);
        // Builtin is granted but has no complete use-witness lane: asserting
        // non-use would overclaim, and the weaker verdict downgrades the
        // whole certificate.
        assert_eq!(
            holds(&bundle, "no-builtin"),
            ClaimEvaluation::NotAssertableConservative
        );
        assert_eq!(
            bundle.non_use_certificate.certificate_status,
            CertificateStatus::Uncertified
        );
    }

    #[test]
    fn output_independence_of_the_run_input_is_not_assertable() {
        let mut contract = certifiable_contract();
        contract.requested_output_claims = vec![RequestedOutputClaim::OutputIndependentOf {
            claim_id: "independent-of-run-input".to_string(),
            binding_id: "source-js".to_string(),
        }];
        let binding = contract
            .bind_to_run(
                &contract.extension_id,
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                Some(&TestContentHash::compute(CERTIFIABLE_SOURCE.as_bytes())),
            )
            .expect("contract binds");
        let scan = scan_source(CERTIFIABLE_SOURCE, "agent.js", ParseGoal::Script);
        let refusal_receipt = binding.preflight_receipt(
            "trace-e8-cert",
            Some("agent.explain.json"),
            Some(&scan),
            &[],
        );
        let mut fixture = certifiable_fixture();
        fixture.contract = contract;
        fixture.binding = binding;
        fixture.refusal_receipt = refusal_receipt;
        let bundle = emit(&fixture);
        assert_eq!(
            holds(&bundle, "independent-of-run-input"),
            ClaimEvaluation::NotAssertableConservative
        );
    }

    #[test]
    fn certifiable_bundle_is_byte_identical_across_reemission() {
        let fixture = certifiable_fixture();
        let first = emit(&fixture);
        let second = emit(&fixture);
        assert_eq!(
            first.bundle_content_hash_hex,
            second.bundle_content_hash_hex
        );
    }

    #[test]
    fn capability_witness_lane_membership_is_pinned() {
        for capability in [
            RuntimeCapability::Console,
            RuntimeCapability::VmDispatch,
            RuntimeCapability::Declassify,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
            RuntimeCapability::NetworkEgress,
        ] {
            assert!(capability_use_is_witnessed(capability), "{capability:?}");
        }
        for capability in [RuntimeCapability::Builtin, RuntimeCapability::ProcessSpawn] {
            assert!(!capability_use_is_witnessed(capability), "{capability:?}");
        }
    }
}
