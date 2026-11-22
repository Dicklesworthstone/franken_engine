//! Native shadow observations against an explicit, content-addressed corpus.
//!
//! This producer executes the real parser, lowering pipeline and baseline
//! interpreter. It never accepts caller-supplied success counts. Baseline /
//! candidate parity and final-envelope capability-necessity trials are separate
//! observations. The latter alone populate the witness's Wilson interval.
//! Corpus support is not independent production sampling, a completeness proof,
//! elapsed burn-in, or permission to activate an artifact.
//!
//! Host effects replay an exact input tape with no live provider fallback. The
//! initial profile excludes module loading, process spawning, declassification,
//! dynamic code generation and reference-valued completions; those require
//! additional authority or a semantic snapshot this producer cannot yet attest.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frankenengine_extension_host::host_io::{
    DenyAllHostIo, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoRecorder,
    HostIoRequest, InMemoryHostIoTranscript,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    CapabilityWitness, CapabilityWitnessTrustRoot, ConfidenceInterval, LifecycleState, ProofKind,
    ProofObligation, WitnessBuilder, WitnessSchemaVersion,
};
use crate::ast::ParseGoal;
use crate::baseline_interpreter::{
    ConsoleEntry, InterpreterConfig, InterpreterCore, InterpreterError, ModuleSourceIntegrity,
    Value,
};
use crate::capability::RuntimeCapability;
use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::Label;
use crate::ir_contract::{Ir0Module, Ir3Module};
use crate::lowering_pipeline::{
    AmbientAuthorityGrant, LoweringContext, lower_ir0_to_ir3, lowered_unit_flow_label_ceiling,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use crate::policy_theorem_compiler::Capability;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

pub const NATIVE_OBSERVATION_CORPUS_SCHEMA: &str = "frankenengine.native-observation-corpus.v1";
pub const NATIVE_OBSERVATION_MAX_SOURCE_BYTES: usize = 1_048_576;
pub const NATIVE_OBSERVATION_MAX_CORPUS_BYTES: usize = 16 * 1024 * 1024;
const TRANSCRIPT_SCHEMA: &str = "frankenengine.native-witness-observation.v1";
const SIGNATURE_DOMAIN: &[u8] = b"frankenengine.native-witness-observation.v1\0";
const MAX_CASES: usize = 256;
const MAX_EXECUTIONS: u64 = 4096;
const MAX_INSTRUCTIONS_PER_EXECUTION: u64 = 1_000_000;
const MAX_RESERVED_INSTRUCTIONS: u64 = 100_000_000;
const MAX_HOST_EFFECTS_PER_CASE: usize = 1024;
const MAX_ARGV_BYTES_PER_CASE: usize = 64 * 1024;
const MAX_RETAINED_HOST_BYTES_PER_EXECUTION: usize = 16 * 1024 * 1024;
const MAX_TRANSCRIPT_BYTES: usize = 64 * 1024 * 1024;

fn default_clock_epoch_ms() -> i64 {
    1_767_225_600_000
}

/// Only actual deterministic input contexts belong in a corpus. Case labels
/// are excluded from context deduplication, so relabeling a case adds no trials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationCase {
    pub case_id: String,
    #[serde(default)]
    pub process_argv: Vec<String>,
    #[serde(default = "default_clock_epoch_ms")]
    pub clock_epoch_ms: i64,
    #[serde(default)]
    pub host_effects: Vec<(HostIoRequest, HostIoOutcome)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationCorpus {
    pub schema_version: String,
    pub cases: Vec<NativeObservationCase>,
}

/// Bounded execution policy, included in the signed observation body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationConfig {
    pub expected_epoch: SecurityEpoch,
    pub instruction_budget: u64,
    pub max_executions: u64,
    /// Artifact metadata only. This is never interpreted as elapsed burn-in.
    pub timestamp_ns: u64,
    /// A nonempty selection from the authenticated envelope, or that envelope
    /// unchanged. Each selected runtime authority retains all its signed parent
    /// operation tags. No effective capability or raw tag is added to the parent.
    pub candidate_capabilities: Option<BTreeSet<Capability>>,
    /// Explicit embedder permission to read supplied invocation shape. No host
    /// environment, filesystem or process provider is installed by this grant.
    pub allow_process_shape_reads: bool,
}

impl Default for NativeObservationConfig {
    fn default() -> Self {
        Self {
            expected_epoch: SecurityEpoch::GENESIS,
            instruction_budget: 100_000,
            max_executions: 1024,
            timestamp_ns: 0,
            candidate_capabilities: None,
            allow_process_shape_reads: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeObservationFailureClass {
    CapabilityDenied,
    GuestFailure,
    ResourceLimit,
    UnsupportedCompletion,
    RuntimeFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeObservedCompletion {
    Completed {
        /// Only primitive values are accepted. Native Value serialization
        /// retains exact UTF-16 and floating-point bits, including negative zero.
        value: Value,
        label: Label,
        exit_code: Option<i32>,
    },
    Failed {
        class: NativeObservationFailureClass,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeExecutionObservation {
    pub completion: NativeObservedCompletion,
    /// None when the native error API does not expose a completed instruction
    /// count. No zero or estimated work is substituted for missing evidence.
    pub instructions_executed: Option<u64>,
    pub console_output: Vec<ConsoleEntry>,
    /// Requests actually attempted against the replay boundary, including a
    /// divergent request and its failure. This is not a copy of the input tape.
    pub host_effects: Vec<(HostIoRequest, HostIoOutcome)>,
    pub replay_error: Option<String>,
    /// A retention boundary failed. Retained effects are an explicitly bounded
    /// prefix, and this execution cannot count as conclusive ablation support.
    pub recording_error: Option<String>,
    pub nondeterminism_hash: ContentHash,
}

impl NativeExecutionObservation {
    fn completed(&self) -> bool {
        matches!(&self.completion, NativeObservedCompletion::Completed { value, .. } if primitive_completion(value))
            && self.replay_error.is_none()
            && self.recording_error.is_none()
    }

    fn inconclusive(&self) -> bool {
        self.recording_error.is_some()
            || matches!(
                self.completion,
                NativeObservedCompletion::Failed {
                    class: NativeObservationFailureClass::ResourceLimit
                        | NativeObservationFailureClass::UnsupportedCompletion
                        | NativeObservationFailureClass::RuntimeFailure,
                    ..
                }
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAblationObservation {
    /// Runtime authority removed. All raw aliases for this authority are
    /// removed together; aliases cannot inflate the number of actual trials.
    pub removed_runtime_capability: RuntimeCapability,
    pub removed_witness_capabilities: BTreeSet<Capability>,
    pub observation: NativeExecutionObservation,
    pub behavior_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeObservationCaseRecord {
    pub case_id: String,
    pub context_hash: ContentHash,
    pub baseline: NativeExecutionObservation,
    pub candidate: Option<NativeExecutionObservation>,
    pub ablations: Vec<NativeAblationObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeObservationTranscriptBody {
    pub schema_version: String,
    pub parent_witness_id: EngineObjectId,
    pub parent_witness_hash: ContentHash,
    pub extension_id: EngineObjectId,
    pub policy_id: EngineObjectId,
    pub epoch: SecurityEpoch,
    pub trust_root_hash: ContentHash,
    pub source_sha256: String,
    pub parse_goal: String,
    pub corpus_hash: ContentHash,
    pub corpus: NativeObservationCorpus,
    pub config: NativeObservationConfig,
    pub baseline_capabilities: BTreeSet<Capability>,
    pub candidate_capabilities: BTreeSet<Capability>,
    pub records: Vec<NativeObservationCaseRecord>,
    pub candidate_matches_baseline: bool,
    pub baseline_executions: u64,
    pub candidate_executions: u64,
    pub ablation_executions: u64,
    pub ablation_breakages: u64,
    pub confidence: ConfidenceInterval,
    pub failure: Option<String>,
    pub signer: VerificationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNativeObservationTranscript {
    pub body: NativeObservationTranscriptBody,
    pub content_hash: ContentHash,
    pub signature: Vec<u8>,
}

impl SignedNativeObservationTranscript {
    /// Verify against caller-pinned authority and epoch, never the embedded
    /// signer alone. The signature commits to all inputs, outcomes and counts.
    pub fn verify(
        &self,
        trust_root: &CapabilityWitnessTrustRoot,
        expected_epoch: SecurityEpoch,
    ) -> Result<(), NativeObservationError> {
        trust_root.validate().map_err(error)?;
        if self.body.epoch != expected_epoch || self.body.config.expected_epoch != expected_epoch {
            return Err(error(
                "observation epoch differs from the expected security epoch",
            ));
        }
        if !trust_root
            .synthesizer_verification_keys
            .contains(&self.body.signer)
        {
            return Err(error(
                "observation signer is not authorized by the external trust root",
            ));
        }
        if self.body.trust_root_hash != trust_root.canonical_digest().map_err(error)? {
            return Err(error(
                "observation trust root differs from the external policy pin",
            ));
        }
        let preimage = transcript_preimage(&self.body)?;
        if self.content_hash != ContentHash::compute(&preimage) {
            return Err(error("observation transcript content hash mismatch"));
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| error("observation signature must contain exactly 64 bytes"))?;
        verify_signature(
            &self.body.signer,
            &preimage,
            &Signature::from_bytes(signature),
        )
        .map_err(error)?;
        if self.body.schema_version != TRANSCRIPT_SCHEMA
            || self.body.corpus_hash != hash_json(&self.body.corpus)?
        {
            return Err(error("observation schema or corpus commitment mismatch"));
        }
        let baseline_count = self.body.records.len() as u64;
        let candidate_count = self
            .body
            .records
            .iter()
            .filter(|r| r.candidate.is_some())
            .count() as u64;
        let ablation_count = self
            .body
            .records
            .iter()
            .map(|r| r.ablations.len() as u64)
            .sum::<u64>();
        let breakages = self
            .body
            .records
            .iter()
            .flat_map(|r| &r.ablations)
            .filter(|trial| trial.behavior_changed)
            .count() as u64;
        if baseline_count != self.body.baseline_executions
            || candidate_count != self.body.candidate_executions
            || ablation_count != self.body.ablation_executions
            || breakages != self.body.ablation_breakages
            || ablation_count > u32::MAX as u64
            || self.body.confidence
                != ConfidenceInterval::from_trials(ablation_count as u32, breakages as u32)
        {
            return Err(error(
                "observation counts or confidence disagree with recorded executions",
            ));
        }
        verify_observation_structure(&self.body)?;
        Ok(())
    }

    /// Check that a fresh signed draft consumes this exact observation rather
    /// than borrowing a transcript from another source, envelope or epoch.
    pub fn verify_witness(
        &self,
        witness: &CapabilityWitness,
        trust_root: &CapabilityWitnessTrustRoot,
        expected_epoch: SecurityEpoch,
    ) -> Result<(), NativeObservationError> {
        self.verify(trust_root, expected_epoch)?;
        witness.verify_integrity().map_err(error)?;
        witness
            .verify_synthesizer_signature(&self.body.signer)
            .map_err(error)?;
        if !self.body.candidate_matches_baseline
            || self.body.failure.is_some()
            || witness.lifecycle_state != LifecycleState::Draft
            || !witness.promotion_signatures.is_empty()
            || witness.transcript_hash != self.content_hash
            || witness.epoch != expected_epoch
            || witness.timestamp_ns != self.body.config.timestamp_ns
            || witness.extension_id != self.body.extension_id
            || witness.policy_id != self.body.policy_id
            || witness.required_capabilities != self.body.candidate_capabilities
            || witness.confidence != self.body.confidence
            || witness.metadata.get("source_sha256") != Some(&self.body.source_sha256)
            || witness.metadata.get("parse_goal") != Some(&self.body.parse_goal)
        {
            return Err(error(
                "draft does not consume this successful native observation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeObservationResult {
    /// Absent on an observed baseline failure, parity failure or inconclusive
    /// trial. The failed signed transcript remains available to the caller.
    pub witness: Option<CapabilityWitness>,
    pub transcript: SignedNativeObservationTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeObservationError(pub String);

impl fmt::Display for NativeObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for NativeObservationError {}

fn error(detail: impl fmt::Display) -> NativeObservationError {
    NativeObservationError(detail.to_string())
}

fn hash_json(value: &impl Serialize) -> Result<ContentHash, NativeObservationError> {
    bounded_json_hash_and_size(value, usize::MAX).map(|(hash, _)| hash)
}

struct JsonDigestWriter {
    hasher: Sha256,
    written: usize,
    limit: usize,
}

impl Write for JsonDigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            return Err(io::Error::other(
                "native observation serialized byte limit exceeded",
            ));
        }
        self.hasher.update(bytes);
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hash/count directly into a bounded writer; a large guest request is never
/// cloned or serialized into a second large buffer merely to measure its size.
fn bounded_json_hash_and_size(
    value: &impl Serialize,
    limit: usize,
) -> Result<(ContentHash, usize), NativeObservationError> {
    let mut writer = JsonDigestWriter {
        hasher: Sha256::new(),
        written: 0,
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(error)?;
    Ok((
        ContentHash::from_bytes(writer.hasher.finalize().into()),
        writer.written,
    ))
}

fn transcript_preimage(
    body: &NativeObservationTranscriptBody,
) -> Result<Vec<u8>, NativeObservationError> {
    bounded_json_hash_and_size(body, MAX_TRANSCRIPT_BYTES)?;
    let mut bytes = SIGNATURE_DOMAIN.to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(body).map_err(error)?);
    Ok(bytes)
}

fn context_hash(case: &NativeObservationCase) -> Result<ContentHash, NativeObservationError> {
    hash_json(&(&case.process_argv, case.clock_epoch_ms, &case.host_effects))
}

fn runtime_capabilities(
    caps: &BTreeSet<Capability>,
) -> Result<BTreeMap<RuntimeCapability, BTreeSet<Capability>>, NativeObservationError> {
    let mut grouped = BTreeMap::<RuntimeCapability, BTreeSet<Capability>>::new();
    for cap in caps {
        let authority = RuntimeCapability::from_tag_str(cap.as_str())
            .ok_or_else(|| error(format!("unsupported native capability `{cap}`")))?;
        if matches!(
            authority,
            RuntimeCapability::ModuleLoad
                | RuntimeCapability::ProcessSpawn
                | RuntimeCapability::Declassify
        ) {
            return Err(error(format!(
                "native observation profile does not support `{authority}` authority"
            )));
        }
        grouped.entry(authority).or_default().insert(cap.clone());
    }
    Ok(grouped)
}

fn primitive_completion(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::BigInt(_)
            | Value::Str(_)
    )
}

fn verify_observation_structure(
    body: &NativeObservationTranscriptBody,
) -> Result<(), NativeObservationError> {
    if body.corpus.schema_version != NATIVE_OBSERVATION_CORPUS_SCHEMA
        || body.corpus.cases.is_empty()
        || body.corpus.cases.len() > MAX_CASES
        || bounded_json_hash_and_size(&body.corpus, NATIVE_OBSERVATION_MAX_CORPUS_BYTES).is_err()
        || body.records.is_empty()
        || body.records.len() > body.corpus.cases.len()
        || body.baseline_capabilities.is_empty()
        || body.candidate_capabilities.is_empty()
        || !body
            .candidate_capabilities
            .is_subset(&body.baseline_capabilities)
    {
        return Err(error(
            "observation corpus, envelope or record shape is inconsistent",
        ));
    }
    let baseline_groups = runtime_capabilities(&body.baseline_capabilities)?;
    let requested = body
        .config
        .candidate_capabilities
        .as_ref()
        .unwrap_or(&body.baseline_capabilities);
    if requested.is_empty() || !requested.is_subset(&body.baseline_capabilities) {
        return Err(error(
            "requested observation authorities are not a parent subset",
        ));
    }
    let selected = runtime_capabilities(requested)?;
    let expanded: BTreeSet<Capability> = baseline_groups
        .iter()
        .filter(|(authority, _)| selected.contains_key(*authority))
        .flat_map(|(_, aliases)| aliases.iter().cloned())
        .collect();
    if expanded != body.candidate_capabilities {
        return Err(error(
            "effective candidate does not retain all authenticated operation tags of its selected authorities",
        ));
    }
    let groups = runtime_capabilities(&body.candidate_capabilities)?;
    let planned_executions = body.corpus.cases.len() as u64 * (2 + groups.len() as u64);
    if body.config.instruction_budget == 0
        || body.config.instruction_budget > MAX_INSTRUCTIONS_PER_EXECUTION
        || body.config.max_executions == 0
        || body.config.max_executions > MAX_EXECUTIONS
        || planned_executions > body.config.max_executions
        || planned_executions.saturating_mul(body.config.instruction_budget)
            > MAX_RESERVED_INSTRUCTIONS
    {
        return Err(error("observation execution policy exceeds native bounds"));
    }
    let mut labels = BTreeSet::new();
    let mut contexts = BTreeSet::new();
    for case in &body.corpus.cases {
        if case.case_id.trim().is_empty()
            || case.case_id.len() > 256
            || !labels.insert(&case.case_id)
            || !contexts.insert(context_hash(case)?)
        {
            return Err(error(
                "observation corpus contains duplicate labels or input contexts",
            ));
        }
    }
    let all_parity = body.records.len() == body.corpus.cases.len()
        && body.records.iter().all(|record| {
            record.baseline.completed()
                && record
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.completed() && candidate == &record.baseline)
        });
    if all_parity != body.candidate_matches_baseline {
        return Err(error(
            "candidate parity summary disagrees with native execution records",
        ));
    }
    let mut inconclusive = false;
    let mut incomplete_ablations = false;
    for (index, record) in body.records.iter().enumerate() {
        let case = &body.corpus.cases[index];
        if record.case_id != case.case_id || record.context_hash != context_hash(case)? {
            return Err(error(
                "observation record does not match its ordered corpus context",
            ));
        }
        if record.baseline.completed() != record.candidate.is_some() {
            return Err(error(
                "candidate presence disagrees with baseline completion",
            ));
        }
        let parity = record.baseline.completed()
            && record
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.completed() && candidate == &record.baseline);
        if !parity && index + 1 != body.records.len() {
            return Err(error(
                "native observations continued after a failed parity case",
            ));
        }
        if record.ablations.len() > groups.len()
            || (!record.ablations.is_empty() && (!all_parity || incomplete_ablations))
        {
            return Err(error(
                "necessity trials do not form a bounded final-envelope execution prefix",
            ));
        }
        for (trial, (authority, aliases)) in record.ablations.iter().zip(&groups) {
            if inconclusive
                || trial.removed_runtime_capability != *authority
                || trial.removed_witness_capabilities != *aliases
            {
                return Err(error(
                    "necessity trial does not remove the exact next final-envelope authority",
                ));
            }
            let changed = !trial.observation.inconclusive()
                && record.candidate.as_ref() != Some(&trial.observation);
            if changed != trial.behavior_changed {
                return Err(error(
                    "necessity result disagrees with the recorded native completion and effects",
                ));
            }
            inconclusive |= trial.observation.inconclusive();
        }
        incomplete_ablations |= record.ablations.len() != groups.len();
    }
    let succeeded = all_parity && !incomplete_ablations && !inconclusive;
    if succeeded == body.failure.is_some()
        || (all_parity && body.failure.is_some() && !inconclusive)
    {
        return Err(error(
            "observation success/failure summary disagrees with completed trials",
        ));
    }
    Ok(())
}

/// Authenticate, execute and sign a bounded corpus against one exact source.
/// Preflight errors return before execution. Execution failures are retained in
/// a signed result with no new witness. Successful results are always Drafts.
pub fn observe_native_witness(
    draft: &CapabilityWitness,
    source: &str,
    corpus: &NativeObservationCorpus,
    config: &NativeObservationConfig,
    trust_root: &CapabilityWitnessTrustRoot,
    signing_key: &SigningKey,
) -> Result<NativeObservationResult, NativeObservationError> {
    trust_root.validate().map_err(error)?;
    let signer = signing_key.verification_key();
    if !trust_root.synthesizer_verification_keys.contains(&signer) {
        return Err(error(
            "observation signing key is not authorized by the external trust root",
        ));
    }
    draft.verify_integrity().map_err(error)?;
    draft.verify_synthesizer_signature(&signer).map_err(error)?;
    draft.verify_proof_coverage().map_err(error)?;
    if draft.lifecycle_state != LifecycleState::Draft || !draft.promotion_signatures.is_empty() {
        return Err(error(
            "native observation requires an unapproved Draft witness",
        ));
    }
    if !WitnessSchemaVersion::CURRENT.is_compatible_with(&draft.schema_version)
        || draft.epoch != config.expected_epoch
    {
        return Err(error(
            "draft schema or epoch differs from the observation policy",
        ));
    }
    if draft.required_capabilities.is_empty()
        || !draft
            .required_capabilities
            .is_disjoint(&draft.denied_capabilities)
    {
        return Err(error(
            "authenticated parent envelope is empty or contradictory",
        ));
    }
    if draft.required_capabilities.len() > 256
        || draft.denied_capabilities.len() > 256
        || draft
            .required_capabilities
            .iter()
            .chain(&draft.denied_capabilities)
            .any(|cap| cap.as_str().len() > 256)
    {
        return Err(error(
            "authenticated parent capability tags exceed native observation bounds",
        ));
    }
    if source.len() > NATIVE_OBSERVATION_MAX_SOURCE_BYTES {
        return Err(error("native observation source exceeds the 1 MiB bound"));
    }
    let source_sha256 = ContentHash::compute(source.as_bytes()).to_hex();
    if draft.metadata.get("source_sha256") != Some(&source_sha256) {
        return Err(error(
            "source SHA256 does not match the authenticated Draft",
        ));
    }
    let parse_goal = match draft.metadata.get("parse_goal").map(String::as_str) {
        Some("script") => ParseGoal::Script,
        Some("module") => ParseGoal::Module,
        _ => {
            return Err(error(
                "authenticated Draft must bind a supported parse_goal",
            ));
        }
    };
    if corpus.schema_version != NATIVE_OBSERVATION_CORPUS_SCHEMA
        || corpus.cases.is_empty()
        || corpus.cases.len() > MAX_CASES
    {
        return Err(error(
            "native corpus requires the supported schema and 1..=256 cases",
        ));
    }
    let (corpus_hash, _) = bounded_json_hash_and_size(corpus, NATIVE_OBSERVATION_MAX_CORPUS_BYTES)
        .map_err(|_| error("native observation corpus exceeds the 16 MiB bound"))?;
    let mut labels = BTreeSet::new();
    let mut contexts = BTreeSet::new();
    for case in &corpus.cases {
        if case.case_id.trim().is_empty()
            || case.case_id.len() > 256
            || !labels.insert(&case.case_id)
            || !contexts.insert(context_hash(case)?)
        {
            return Err(error(
                "native corpus contains an empty/duplicate case label or duplicate input context",
            ));
        }
        if case.host_effects.len() > MAX_HOST_EFFECTS_PER_CASE
            || case.process_argv.len() > 256
            || case.process_argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES_PER_CASE
        {
            return Err(error(
                "native corpus case exceeds host-effect or invocation-input bounds",
            ));
        }
    }
    let requested_candidate = config
        .candidate_capabilities
        .as_ref()
        .unwrap_or(&draft.required_capabilities);
    if requested_candidate.is_empty()
        || !requested_candidate.is_subset(&draft.required_capabilities)
        || !requested_candidate.is_disjoint(&draft.denied_capabilities)
    {
        return Err(error(
            "candidate capabilities must be a nonempty subset of the authenticated required envelope",
        ));
    }
    let baseline_groups = runtime_capabilities(&draft.required_capabilities)?;
    if draft
        .denied_capabilities
        .iter()
        .filter_map(|cap| RuntimeCapability::from_tag_str(cap.as_str()))
        .any(|cap| baseline_groups.contains_key(&cap))
    {
        return Err(error(
            "authenticated parent required and denied aliases name the same runtime authority",
        ));
    }
    let selected_groups = runtime_capabilities(requested_candidate)?;
    let candidate_groups: BTreeMap<_, _> = baseline_groups
        .iter()
        .filter(|(authority, _)| selected_groups.contains_key(*authority))
        .map(|(authority, aliases)| (*authority, aliases.clone()))
        .collect();
    let candidate: BTreeSet<Capability> = candidate_groups.values().flatten().cloned().collect();
    let planned_executions = (corpus.cases.len() as u64) * (2 + candidate_groups.len() as u64);
    if config.instruction_budget == 0
        || config.instruction_budget > MAX_INSTRUCTIONS_PER_EXECUTION
        || config.max_executions == 0
        || config.max_executions > MAX_EXECUTIONS
        || planned_executions > config.max_executions
        || planned_executions.saturating_mul(config.instruction_budget) > MAX_RESERVED_INSTRUCTIONS
    {
        return Err(error(
            "native observation execution or reserved-instruction budget exceeded before execution",
        ));
    }
    let mut body = NativeObservationTranscriptBody {
        schema_version: TRANSCRIPT_SCHEMA.to_string(),
        parent_witness_id: draft.witness_id.clone(),
        parent_witness_hash: draft.content_hash,
        extension_id: draft.extension_id.clone(),
        policy_id: draft.policy_id.clone(),
        epoch: draft.epoch,
        trust_root_hash: trust_root.canonical_digest().map_err(error)?,
        source_sha256,
        parse_goal: parse_goal.as_str().to_string(),
        corpus_hash,
        corpus: corpus.clone(),
        config: config.clone(),
        baseline_capabilities: draft.required_capabilities.clone(),
        candidate_capabilities: candidate.clone(),
        records: Vec::new(),
        candidate_matches_baseline: false,
        baseline_executions: 0,
        candidate_executions: 0,
        ablation_executions: 0,
        ablation_breakages: 0,
        confidence: ConfidenceInterval::from_trials(0, 0),
        failure: None,
        signer,
    };
    // Reserve exact corpus bytes plus conservative record/tag framing before
    // execution. Every native observation receives an equal finite share of
    // the remaining transcript budget, so all retained runs fit in aggregate.
    let (_, base_bytes) = bounded_json_hash_and_size(&body, MAX_TRANSCRIPT_BYTES)?;
    let mut per_case_framing = 1024usize;
    for aliases in candidate_groups.values() {
        per_case_framing = per_case_framing
            .saturating_add(256 + bounded_json_hash_and_size(aliases, MAX_TRANSCRIPT_BYTES)?.1);
    }
    let framing = base_bytes.saturating_add(corpus.cases.len().saturating_mul(per_case_framing));
    let observation_byte_budget =
        MAX_TRANSCRIPT_BYTES.saturating_sub(framing) / planned_executions as usize;
    if observation_byte_budget < 4096 {
        return Err(error(
            "native observation corpus and execution count exceed the aggregate transcript byte budget",
        ));
    }
    let (module, label_ceiling) = prepare_source(source, parse_goal, config)?;
    let baseline_grants = baseline_groups.keys().copied().collect::<BTreeSet<_>>();
    let candidate_grants = candidate_groups.keys().copied().collect::<BTreeSet<_>>();
    for case in &corpus.cases {
        let baseline = execute_case(
            &module,
            &label_ceiling,
            case,
            config,
            &baseline_grants,
            observation_byte_budget,
        )?;
        body.baseline_executions += 1;
        let baseline_completed = baseline.completed();
        let mut record = NativeObservationCaseRecord {
            case_id: case.case_id.clone(),
            context_hash: context_hash(case)?,
            baseline,
            candidate: None,
            ablations: Vec::new(),
        };
        if !baseline_completed {
            body.failure = Some(format!(
                "baseline did not complete with an exact host tape for case `{}`",
                case.case_id
            ));
            body.records.push(record);
            return finish(draft, body, signing_key);
        }
        let observed = execute_case(
            &module,
            &label_ceiling,
            case,
            config,
            &candidate_grants,
            observation_byte_budget,
        )?;
        body.candidate_executions += 1;
        let matches = observed.completed() && observed == record.baseline;
        record.candidate = Some(observed);
        body.records.push(record);
        if !matches {
            body.failure = Some(format!(
                "candidate behavior differs from baseline for case `{}`",
                case.case_id
            ));
            return finish(draft, body, signing_key);
        }
    }
    body.candidate_matches_baseline = true;
    // No search attempts or baseline matches are counted as necessity trials.
    // Every row below removes one distinct authority from the final candidate.
    for (case_index, case) in corpus.cases.iter().enumerate() {
        for (authority, aliases) in &candidate_groups {
            let mut grants = candidate_grants.clone();
            grants.remove(authority);
            let observed = execute_case(
                &module,
                &label_ceiling,
                case,
                config,
                &grants,
                observation_byte_budget,
            )?;
            let inconclusive = observed.inconclusive();
            let changed =
                !inconclusive && body.records[case_index].candidate.as_ref() != Some(&observed);
            body.ablation_executions += 1;
            body.ablation_breakages += u64::from(changed);
            body.records[case_index]
                .ablations
                .push(NativeAblationObservation {
                    removed_runtime_capability: *authority,
                    removed_witness_capabilities: aliases.clone(),
                    observation: observed,
                    behavior_changed: changed,
                });
            if inconclusive {
                body.failure = Some(format!(
                    "inconclusive native ablation of `{authority}` for case `{}`",
                    case.case_id
                ));
                return finish(draft, body, signing_key);
            }
        }
    }
    finish(draft, body, signing_key)
}

fn prepare_source(
    source: &str,
    goal: ParseGoal,
    config: &NativeObservationConfig,
) -> Result<(Ir3Module, Label), NativeObservationError> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "native-observation".to_string(),
                text: source.to_string(),
            },
            goal,
            &ParserOptions::default(),
        )
        .map_err(error)?;
    let mut ir0 = Ir0Module::from_syntax_tree(tree, "native-observation");
    ir0.script_strict = Some(
        goal == ParseGoal::Module || crate::parser::source_has_use_strict_directive(source, goal),
    );
    let mut context = LoweringContext::new(
        "native-observation",
        "native-observation",
        "native-observation",
    );
    context.forbid_dynamic_codegen = true;
    if config.allow_process_shape_reads {
        context.ambient_authority_grant = AmbientAuthorityGrant::TrustedProcessShape;
    }
    // A caller-supplied replay tape can contain host-derived exception text.
    // Keep its IFC provenance fail-high; never relabel replay as internal I/O.
    context.host_io_exception_provenance = HostIoExceptionProvenance::Unknown;
    let lowered = lower_ir0_to_ir3(&ir0, &context).map_err(error)?;
    let ceiling = lowered_unit_flow_label_ceiling(&lowered.ir2, HostIoExceptionProvenance::Unknown);
    Ok((lowered.ir3, ceiling))
}

#[derive(Debug)]
struct ObservedReplay {
    replay: InMemoryHostIoTranscript,
    expected_request_hashes: Vec<ContentHash>,
    retention_limit: usize,
    state: Mutex<ObservedReplayState>,
}

#[derive(Debug, Default)]
struct ObservedReplayState {
    attempted: Vec<(HostIoRequest, HostIoOutcome)>,
    retained_bytes: usize,
    diverged: bool,
    recording_error: Option<String>,
}

impl HostIoRecorder for ObservedReplay {
    fn begin_execution(&self) -> Result<(), HostIoError> {
        self.replay.begin_execution()
    }
    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
        let Ok(mut state) = self.state.lock() else {
            return Some(Err(HostIoError::Denied {
                reason: "native observation recorder is poisoned".to_string(),
            }));
        };
        // Retain the exact replay prefix plus at most its first divergent
        // request. Catching replay errors cannot create an unmetered cloning
        // loop outside the interpreter's own memory accounting.
        if state.diverged
            || state.recording_error.is_some()
            || state.attempted.len() > self.expected_request_hashes.len()
        {
            let reason = state
                .recording_error
                .get_or_insert_with(|| {
                    "native observation refused repeated host requests after replay divergence"
                        .to_string()
                })
                .clone();
            return Some(Err(HostIoError::Denied { reason }));
        }
        let remaining = self.retention_limit.saturating_sub(state.retained_bytes);
        let request_hash = match bounded_json_hash_and_size(request, remaining) {
            Ok((hash, _)) => hash,
            Err(_) => {
                let reason =
                    "native observation host request retention budget exceeded".to_string();
                state.recording_error = Some(reason.clone());
                return Some(Err(HostIoError::Denied { reason }));
            }
        };
        let outcome = self.replay.replay(request).unwrap_or_else(|| {
            Err(HostIoError::Denied {
                reason: "native observation has no live host fallback".to_string(),
            })
        });
        let retained_bytes = match bounded_json_hash_and_size(&(request, &outcome), remaining) {
            Ok((_, size)) => size,
            Err(_) => {
                let reason =
                    "native observation host outcome retention budget exceeded".to_string();
                state.recording_error = Some(reason.clone());
                return Some(Err(HostIoError::Denied { reason }));
            }
        };
        state.diverged =
            self.expected_request_hashes.get(state.attempted.len()) != Some(&request_hash);
        state.retained_bytes += retained_bytes;
        state.attempted.push((request.clone(), outcome.clone()));
        Some(outcome)
    }
    fn record(&self, _request: &HostIoRequest, _outcome: &HostIoOutcome) {}
    fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
        self.replay.finish_execution()
    }
}

fn execute_case(
    module: &Ir3Module,
    label_ceiling: &Label,
    case: &NativeObservationCase,
    policy: &NativeObservationConfig,
    grants: &BTreeSet<RuntimeCapability>,
    observation_byte_budget: usize,
) -> Result<NativeExecutionObservation, NativeObservationError> {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = policy.instruction_budget;
    config.max_total_memory_bytes = 64 * 1024 * 1024;
    config.max_heap_objects = 65_536;
    config.max_call_depth = 64;
    config.max_string_size = 1024 * 1024;
    config.max_console_entries = 256;
    config.max_console_bytes = 64 * 1024;
    config.granted_capabilities = grants.clone();
    config.process_argv = case.process_argv.clone();
    config.process_shape_read_allowed = policy.allow_process_shape_reads;
    config.disallow_dynamic_codegen = true;
    config.module_source_integrity = Some(ModuleSourceIntegrity::replaying(BTreeMap::new()));
    let replay = Arc::new(ObservedReplay {
        replay: InMemoryHostIoTranscript::replaying(case.host_effects.clone()),
        expected_request_hashes: case
            .host_effects
            .iter()
            .map(|(request, _)| hash_json(request))
            .collect::<Result<_, _>>()?,
        retention_limit: MAX_RETAINED_HOST_BYTES_PER_EXECUTION.min(observation_byte_budget / 2),
        state: Mutex::new(ObservedReplayState::default()),
    });
    replay.begin_execution().map_err(error)?;
    let mut core = InterpreterCore::new(
        config,
        format!("native-observation:{}", context_hash(case)?.to_hex()),
    );
    core.set_clock_epoch_ms(case.clock_epoch_ms);
    core.set_entry_flow_label_ceiling(label_ceiling.clone());
    core.set_host_io(Arc::new(DenyAllHostIo), Some(replay.clone()));
    let result = core.execute(module);
    let replay_error = replay.finish_execution().err().map(|e| e.to_string());
    let state = replay
        .state
        .lock()
        .map_err(|_| error("native observation recorder is poisoned"))?;
    let host_effects = state.attempted.clone();
    let recording_error = state.recording_error.clone();
    let mut console_output = core.console_output().to_vec();
    let nondeterminism_hash = hash_json(core.nondeterminism_trace_ref())?;
    let (mut completion, instructions_executed) = match result {
        Ok(result) => {
            // A successful execute drains console entries into its result;
            // failures leave their emitted prefix on the core.
            console_output = result.console_output;
            let completion = if primitive_completion(&result.value) {
                NativeObservedCompletion::Completed {
                    value: result.value,
                    label: result.completion_label,
                    exit_code: result.exit_code,
                }
            } else {
                NativeObservedCompletion::Failed { class: NativeObservationFailureClass::UnsupportedCompletion, detail: "native observation requires a primitive completion; heap-reference identity is not semantic equality".to_string() }
            };
            (completion, Some(result.instructions_executed))
        }
        Err(native_error) => {
            let class = match &native_error {
                InterpreterError::CapabilityDenied { .. } => {
                    NativeObservationFailureClass::CapabilityDenied
                }
                InterpreterError::BudgetExhausted { .. }
                | InterpreterError::MemoryBudgetExceeded { .. }
                | InterpreterError::StackOverflow { .. }
                | InterpreterError::StringLimitExceeded { .. }
                | InterpreterError::ScopeDepthExceeded { .. }
                | InterpreterError::ConsoleBudgetExceeded { .. }
                | InterpreterError::Cancelled => NativeObservationFailureClass::ResourceLimit,
                InterpreterError::UncaughtException { .. }
                | InterpreterError::TypeError { .. }
                | InterpreterError::RangeError { .. }
                | InterpreterError::DivisionByZero
                | InterpreterError::UninitializedBinding { .. }
                | InterpreterError::UndefinedBinding { .. }
                | InterpreterError::ConstAssignment { .. }
                | InterpreterError::HostFilesystem { .. } => {
                    NativeObservationFailureClass::GuestFailure
                }
                _ => NativeObservationFailureClass::RuntimeFailure,
            };
            (
                NativeObservedCompletion::Failed {
                    class,
                    detail: native_error.to_string(),
                },
                None,
            )
        }
    };
    if let Some(detail) = &recording_error {
        completion = NativeObservedCompletion::Failed {
            class: NativeObservationFailureClass::ResourceLimit,
            detail: detail.clone(),
        };
    }
    let observation = NativeExecutionObservation {
        completion,
        instructions_executed,
        console_output,
        host_effects,
        replay_error,
        recording_error,
        nondeterminism_hash,
    };
    if bounded_json_hash_and_size(&observation, observation_byte_budget).is_err() {
        // Never retain an oversized completion or console payload in the
        // aggregate transcript. The signed replacement explicitly reports the
        // omitted payload and is inconclusive, not an equivalent completion.
        let detail = format!(
            "native observation exceeded its {observation_byte_budget}-byte transcript share; omitted {} console entries and {} retained host requests",
            observation.console_output.len(),
            observation.host_effects.len()
        );
        return Ok(NativeExecutionObservation {
            completion: NativeObservedCompletion::Failed {
                class: NativeObservationFailureClass::ResourceLimit,
                detail: detail.clone(),
            },
            instructions_executed: observation.instructions_executed,
            console_output: Vec::new(),
            host_effects: Vec::new(),
            replay_error: observation.replay_error,
            recording_error: Some(detail),
            nondeterminism_hash,
        });
    }
    Ok(observation)
}

fn finish(
    draft: &CapabilityWitness,
    mut body: NativeObservationTranscriptBody,
    signing_key: &SigningKey,
) -> Result<NativeObservationResult, NativeObservationError> {
    body.confidence = ConfidenceInterval::from_trials(
        body.ablation_executions as u32,
        body.ablation_breakages as u32,
    );
    let preimage = transcript_preimage(&body)?;
    let content_hash = ContentHash::compute(&preimage);
    let signature = sign_preimage(signing_key, &preimage)
        .map_err(error)?
        .to_bytes()
        .to_vec();
    let transcript = SignedNativeObservationTranscript {
        body,
        content_hash,
        signature,
    };
    if !transcript.body.candidate_matches_baseline || transcript.body.failure.is_some() {
        return Ok(NativeObservationResult {
            witness: None,
            transcript,
        });
    }
    let artifact_id = derive_id(
        ObjectDomain::EvidenceRecord,
        "native-witness-observation",
        &SchemaId::from_definition(TRANSCRIPT_SCHEMA.as_bytes()),
        content_hash.as_bytes(),
    )
    .map_err(error)?;
    let mut builder = WitnessBuilder::new(
        draft.extension_id.clone(),
        draft.policy_id.clone(),
        draft.epoch,
        transcript.body.config.timestamp_ns,
        signing_key.clone(),
    )
    .require_all(transcript.body.candidate_capabilities.clone())
    .confidence(transcript.body.confidence)
    .replay_seed(draft.replay_seed)
    .transcript_hash(content_hash);
    if let Some(rollback) = &draft.rollback_token {
        builder = builder.rollback(rollback.clone());
    }
    for (key, value) in &draft.metadata {
        if !key.starts_with("promotion_theorem.") && !key.starts_with("native_observation.") {
            builder = builder.meta(key, value);
        }
    }
    builder = builder
        .meta("witness_purpose", "native_observed_draft")
        .meta(
            "trusted_synthesizer_verification_key",
            signing_key.verification_key().to_hex(),
        )
        .meta(
            "native_observation.parent_witness_id",
            draft.witness_id.to_string(),
        )
        .meta(
            "native_observation.parent_witness_hash",
            draft.content_hash.to_hex(),
        )
        .meta(
            "native_observation.corpus_hash",
            transcript.body.corpus_hash.to_hex(),
        )
        .meta(
            "native_observation.profile",
            "baseline_deterministic_exact_grants_v1",
        )
        .meta(
            "native_observation.scope",
            "bounded-corpus empirical support; no production burn-in or completeness claim",
        );
    for proof in &draft.proof_obligations {
        if transcript
            .body
            .candidate_capabilities
            .contains(&proof.capability)
            && proof.kind != ProofKind::PolicyTheoremCheck
        {
            builder = builder.proof(proof.clone());
        }
    }
    for capability in &transcript.body.candidate_capabilities {
        let trials = transcript
            .body
            .records
            .iter()
            .flat_map(|r| &r.ablations)
            .filter(|a| a.removed_witness_capabilities.contains(capability))
            .collect::<Vec<_>>();
        let breakages = trials.iter().filter(|a| a.behavior_changed).count();
        if breakages > 0 {
            builder = builder.proof(ProofObligation {
                capability: capability.clone(), kind: ProofKind::DynamicAblation,
                proof_artifact_id: artifact_id.clone(), artifact_hash: content_hash,
                justification: format!("Removing the exact runtime authority changed behavior in {breakages}/{} native corpus executions; see the signed transcript; this is bounded empirical evidence", trials.len()),
            });
        }
    }
    for capability in &draft.denied_capabilities {
        let reason = draft
            .denial_records
            .iter()
            .find(|d| &d.capability == capability)
            .map(|d| d.reason.as_str())
            .unwrap_or("excluded by the authenticated predecessor envelope");
        builder = builder.deny(capability.clone(), reason);
    }
    for capability in draft
        .required_capabilities
        .difference(&transcript.body.candidate_capabilities)
    {
        debug_assert!(
            !transcript
                .body
                .candidate_capabilities
                .iter()
                .any(
                    |retained| RuntimeCapability::from_tag_str(retained.as_str())
                        == RuntimeCapability::from_tag_str(capability.as_str())
                )
        );
        builder = builder.deny(capability.clone(), format!("Excluded by explicit candidate selection; baseline parity observed on corpus {} in signed transcript {}", transcript.body.corpus_hash.to_hex(), content_hash.to_hex()));
    }
    Ok(NativeObservationResult {
        witness: Some(builder.build().map_err(error)?),
        transcript,
    })
}
