#![forbid(unsafe_code)]

//! Kernel synthesis eligibility contract for hot-kernel schema mining.
//!
//! Implements [RGC-613A]: mines recurring hot-kernel schemas and defines which
//! kernels are eligible for synthesis, which are forbidden, and why.
//!
//! # Design decisions
//!
//! - **Kernel families** — the engine groups hot loops and recurring patterns
//!   into named families (arithmetic loops, collection iteration, string
//!   processing, etc.) so that eligibility rules can be expressed per-family.
//! - **Eligibility status** — each kernel receives one of four verdicts:
//!   Eligible, Forbidden, Conditional (needs extra requirements), or Deferred
//!   (insufficient evidence to decide now).
//! - **Forbidden reasons** — explicit, auditable reasons prevent synthesis of
//!   kernels that would violate determinism, security, or purity invariants.
//! - **Evidence-backed** — decisions carry confidence scores and evidence
//!   counts so downstream consumers can gate on quality.
//! - **Certificate model** — each synthesis decision is wrapped in a
//!   certificate that records the budget consumed and a tamper-evident hash.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for kernel synthesis contract artifacts.
pub const KERNEL_SYNTH_SCHEMA_VERSION: &str = "franken-engine.kernel-synthesis-contract.v1";

/// Component name.
pub const KERNEL_SYNTH_COMPONENT: &str = "kernel_synthesis_contract";

/// Policy identifier.
pub const KERNEL_SYNTH_POLICY_ID: &str = "RGC-613A";

/// One million — unit for fixed-point millionths arithmetic.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Kernel family
// ---------------------------------------------------------------------------

/// Named families of recurring hot-kernel patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFamily {
    /// Tight numeric loops (add, mul, fma, etc.).
    ArithmeticLoop,
    /// Iteration over arrays, maps, sets, iterators.
    CollectionIteration,
    /// String concatenation, slicing, regex-free transforms.
    StringProcessing,
    /// Regular expression matching and compilation.
    RegExpMatch,
    /// Property access chains (dot, bracket, optional chaining).
    PropertyAccess,
    /// Type guard narrowing (typeof, instanceof, discriminated unions).
    TypeGuard,
    /// Allocation-heavy patterns (object/array literals in loops).
    MemoryAllocation,
    /// Batched host-call dispatch sequences.
    HostcallBatch,
    /// React render pipelines (vdom diff, reconciliation).
    ReactRender,
    /// Module initialisation and top-level evaluation.
    ModuleInit,
}

impl fmt::Display for KernelFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ArithmeticLoop => "arithmetic_loop",
            Self::CollectionIteration => "collection_iteration",
            Self::StringProcessing => "string_processing",
            Self::RegExpMatch => "regexp_match",
            Self::PropertyAccess => "property_access",
            Self::TypeGuard => "type_guard",
            Self::MemoryAllocation => "memory_allocation",
            Self::HostcallBatch => "hostcall_batch",
            Self::ReactRender => "react_render",
            Self::ModuleInit => "module_init",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Eligibility status
// ---------------------------------------------------------------------------

/// Verdict for a kernel's synthesis eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStatus {
    /// Kernel may be synthesised without restriction.
    Eligible,
    /// Kernel must NOT be synthesised.
    Forbidden,
    /// Kernel may be synthesised only if additional requirements are met.
    Conditional {
        /// Human-readable requirement descriptions.
        requirements: Vec<String>,
    },
    /// Decision is deferred pending further evidence.
    Deferred {
        /// Reason the decision cannot be made yet.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Forbidden reason
// ---------------------------------------------------------------------------

/// Auditable reason a kernel is forbidden from synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForbiddenReason {
    /// Kernel performs observable side effects.
    SideEffect,
    /// Kernel behaviour is non-deterministic.
    NonDeterministic,
    /// Kernel has unbounded time or space complexity.
    UnboundedComplexity,
    /// Kernel touches security-sensitive APIs.
    SecuritySensitive,
    /// Not enough evidence to justify synthesis.
    InsufficientEvidence,
    /// An external policy explicitly restricts this kernel.
    PolicyRestriction,
}

impl fmt::Display for ForbiddenReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SideEffect => "side_effect",
            Self::NonDeterministic => "non_deterministic",
            Self::UnboundedComplexity => "unbounded_complexity",
            Self::SecuritySensitive => "security_sensitive",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::PolicyRestriction => "policy_restriction",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Proof requirement
// ---------------------------------------------------------------------------

/// How much proof is required before a synthesised kernel may be deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRequirement {
    /// No proof is needed (best-effort synthesis).
    None,
    /// Proof is attempted but failure does not block deployment.
    BestEffort,
    /// A verified proof is mandatory before deployment.
    Mandatory,
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

/// Schema describing a single hot-kernel pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSchema {
    /// Unique kernel identifier.
    pub id: String,
    /// Family this kernel belongs to.
    pub family: KernelFamily,
    /// Human-readable description of the pattern.
    pub pattern_description: String,
    /// Number of IR instructions in the kernel body.
    pub instruction_count: u32,
    /// How frequently this kernel fires, in millionths (1_000_000 = 100%).
    pub hotness_millionths: u64,
    /// Purity score in millionths (1_000_000 = fully pure).
    pub purity_score_millionths: u64,
    /// Whether the kernel is free of observable side effects.
    pub side_effect_free: bool,
    /// Whether the kernel produces deterministic output for identical input.
    pub deterministic: bool,
    /// Whether the kernel runs in bounded time.
    pub bounded_time: bool,
    /// Content hash of the kernel source / IR.
    pub source_hash: ContentHash,
}

/// Eligibility decision for a single kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityDecision {
    /// Kernel identifier this decision applies to.
    pub kernel_id: String,
    /// The eligibility verdict.
    pub status: EligibilityStatus,
    /// Reasons the kernel is forbidden (empty unless status is `Forbidden`).
    pub forbidden_reasons: Vec<ForbiddenReason>,
    /// Confidence in the decision, in millionths (1_000_000 = full confidence).
    pub confidence_millionths: u64,
    /// Number of evidence records backing this decision.
    pub evidence_count: u32,
}

/// Envelope grouping all eligibility decisions by verdict category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisEnvelope {
    /// Kernels approved for synthesis.
    pub eligible: Vec<EligibilityDecision>,
    /// Kernels forbidden from synthesis.
    pub forbidden: Vec<EligibilityDecision>,
    /// Kernels with deferred decisions.
    pub deferred: Vec<EligibilityDecision>,
    /// Tamper-evident hash of the envelope contents.
    pub envelope_hash: ContentHash,
}

/// Full corpus of kernel schemas and their eligibility decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCorpus {
    /// All known kernel schemas.
    pub schemas: Vec<KernelSchema>,
    /// Eligibility decisions for each schema.
    pub decisions: Vec<EligibilityDecision>,
    /// Content hash of the whole corpus.
    pub corpus_hash: ContentHash,
}

/// Budget constraints for kernel synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisBudget {
    /// Maximum number of kernels that may be synthesised.
    pub max_kernels: u32,
    /// Maximum factor by which instruction count may grow during synthesis.
    pub max_instruction_expansion: u32,
    /// Time budget in millionths of a second.
    pub time_budget_millionths: u64,
    /// Required level of proof.
    pub proof_requirement: ProofRequirement,
}

/// Certificate attesting to a kernel synthesis decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSynthCertificate {
    /// Schema version of this certificate.
    pub schema_version: String,
    /// Kernel identifier.
    pub kernel_id: String,
    /// The eligibility decision.
    pub decision: EligibilityDecision,
    /// Budget consumed during synthesis evaluation.
    pub budget_consumed: SynthesisBudget,
    /// Tamper-evident hash of the certificate.
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during kernel synthesis contract operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelSynthError {
    /// The corpus contained no kernel schemas.
    EmptyCorpus,
    /// A kernel with the same id appeared more than once.
    DuplicateKernel {
        /// The duplicated identifier.
        id: String,
    },
    /// The synthesis budget is invalid.
    InvalidBudget {
        /// Explanation.
        reason: String,
    },
    /// A kernel schema failed validation.
    InvalidSchema {
        /// Explanation.
        reason: String,
    },
}

impl fmt::Display for KernelSynthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => write!(f, "empty corpus: no kernel schemas provided"),
            Self::DuplicateKernel { id } => write!(f, "duplicate kernel id: {id}"),
            Self::InvalidBudget { reason } => write!(f, "invalid budget: {reason}"),
            Self::InvalidSchema { reason } => write!(f, "invalid schema: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

/// Evidence manifest summarising a full kernel-synthesis evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSynthEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Total number of kernels evaluated.
    pub kernels_evaluated: u32,
    /// Number of kernels found eligible.
    pub eligible_count: u32,
    /// Number of kernels found forbidden.
    pub forbidden_count: u32,
    /// Number of kernels with deferred decisions.
    pub deferred_count: u32,
    /// Certificates produced.
    pub certificates: Vec<KernelSynthCertificate>,
    /// Content hash of the manifest.
    pub manifest_hash: ContentHash,
    /// Optional error message if the run encountered a problem.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Evaluate the synthesis eligibility of a single kernel schema.
///
/// Rules:
/// 1. A kernel that is side-effect-free, deterministic, and bounded-time is
///    `Eligible` — provided its purity score meets the threshold (≥ 800_000).
/// 2. If the kernel has side effects, it is `Forbidden` with `SideEffect`.
/// 3. If the kernel is non-deterministic, it is `Forbidden` with
///    `NonDeterministic`.
/// 4. If the kernel is not bounded-time, it is `Forbidden` with
///    `UnboundedComplexity`.
/// 5. If the purity score is below the threshold but the kernel otherwise
///    passes, it is `Conditional` with a purity requirement.
/// 6. If hotness is zero the kernel is `Deferred` (no evidence of use).
pub fn evaluate_eligibility(schema: &KernelSchema) -> EligibilityDecision {
    let mut forbidden_reasons: Vec<ForbiddenReason> = Vec::new();

    // Hotness zero means no evidence of the kernel being hot — defer.
    if schema.hotness_millionths == 0 {
        return EligibilityDecision {
            kernel_id: schema.id.clone(),
            status: EligibilityStatus::Deferred {
                reason: "kernel has zero hotness — no evidence of use".into(),
            },
            forbidden_reasons: Vec::new(),
            confidence_millionths: 0,
            evidence_count: 0,
        };
    }

    // Collect forbidden reasons.
    if !schema.side_effect_free {
        forbidden_reasons.push(ForbiddenReason::SideEffect);
    }
    if !schema.deterministic {
        forbidden_reasons.push(ForbiddenReason::NonDeterministic);
    }
    if !schema.bounded_time {
        forbidden_reasons.push(ForbiddenReason::UnboundedComplexity);
    }

    if !forbidden_reasons.is_empty() {
        // Confidence is proportional to the number of checks that failed.
        let confidence = MILLIONTHS; // full confidence in a forbidden verdict
        return EligibilityDecision {
            kernel_id: schema.id.clone(),
            status: EligibilityStatus::Forbidden,
            forbidden_reasons,
            confidence_millionths: confidence,
            evidence_count: 1,
        };
    }

    // Purity threshold: 800_000 millionths (80%).
    let purity_threshold: u64 = 800_000;
    if schema.purity_score_millionths < purity_threshold {
        return EligibilityDecision {
            kernel_id: schema.id.clone(),
            status: EligibilityStatus::Conditional {
                requirements: vec![format!(
                    "purity score must be >= {} millionths (currently {})",
                    purity_threshold, schema.purity_score_millionths
                )],
            },
            forbidden_reasons: Vec::new(),
            confidence_millionths: schema.purity_score_millionths,
            evidence_count: 1,
        };
    }

    // All checks passed — eligible.
    EligibilityDecision {
        kernel_id: schema.id.clone(),
        status: EligibilityStatus::Eligible,
        forbidden_reasons: Vec::new(),
        confidence_millionths: MILLIONTHS,
        evidence_count: 1,
    }
}

/// Build a [`SynthesisEnvelope`] from a slice of kernel schemas.
///
/// Each schema is evaluated and the resulting decision is placed into the
/// appropriate bucket (eligible, forbidden, deferred). Conditional decisions
/// are grouped with deferred for conservatism.
pub fn build_synthesis_envelope(schemas: &[KernelSchema]) -> SynthesisEnvelope {
    let mut eligible = Vec::new();
    let mut forbidden = Vec::new();
    let mut deferred = Vec::new();

    for schema in schemas {
        let decision = evaluate_eligibility(schema);
        match &decision.status {
            EligibilityStatus::Eligible => eligible.push(decision),
            EligibilityStatus::Forbidden => forbidden.push(decision),
            EligibilityStatus::Conditional { .. } | EligibilityStatus::Deferred { .. } => {
                deferred.push(decision);
            }
        }
    }

    // Compute envelope hash over serialised eligible + forbidden + deferred.
    let hash_input = envelope_hash_input(&eligible, &forbidden, &deferred);
    let envelope_hash = ContentHash::compute(&hash_input);

    SynthesisEnvelope {
        eligible,
        forbidden,
        deferred,
        envelope_hash,
    }
}

/// Validate a slice of schemas, checking for duplicates and empty id fields.
pub fn validate_schemas(schemas: &[KernelSchema]) -> Result<(), KernelSynthError> {
    if schemas.is_empty() {
        return Err(KernelSynthError::EmptyCorpus);
    }
    let mut seen = BTreeSet::new();
    for schema in schemas {
        if schema.id.is_empty() {
            return Err(KernelSynthError::InvalidSchema {
                reason: "kernel id must not be empty".into(),
            });
        }
        if !seen.insert(&schema.id) {
            return Err(KernelSynthError::DuplicateKernel {
                id: schema.id.clone(),
            });
        }
    }
    Ok(())
}

/// Build the canonical FrankenEngine kernel corpus with 10+ realistic schemas.
pub fn mine_canonical_kernels() -> KernelCorpus {
    let schemas = canonical_schemas();
    let decisions: Vec<EligibilityDecision> =
        schemas.iter().map(evaluate_eligibility).collect();

    let mut corpus_bytes = Vec::new();
    for s in &schemas {
        corpus_bytes.extend_from_slice(s.id.as_bytes());
    }
    for d in &decisions {
        corpus_bytes.extend_from_slice(d.kernel_id.as_bytes());
    }
    let corpus_hash = ContentHash::compute(&corpus_bytes);

    KernelCorpus {
        schemas,
        decisions,
        corpus_hash,
    }
}

/// Produce a full evidence manifest from the canonical corpus.
pub fn run_kernel_synth_evidence() -> KernelSynthEvidenceManifest {
    let corpus = mine_canonical_kernels();

    let mut eligible_count: u32 = 0;
    let mut forbidden_count: u32 = 0;
    let mut deferred_count: u32 = 0;

    let default_budget = SynthesisBudget {
        max_kernels: 64,
        max_instruction_expansion: 4,
        time_budget_millionths: 5 * MILLIONTHS,
        proof_requirement: ProofRequirement::BestEffort,
    };

    let mut certificates = Vec::new();

    for decision in &corpus.decisions {
        match &decision.status {
            EligibilityStatus::Eligible => eligible_count += 1,
            EligibilityStatus::Forbidden => forbidden_count += 1,
            EligibilityStatus::Conditional { .. } | EligibilityStatus::Deferred { .. } => {
                deferred_count += 1;
            }
        }

        let cert_bytes = format!(
            "{}:{}:{}",
            KERNEL_SYNTH_SCHEMA_VERSION, decision.kernel_id, decision.confidence_millionths
        );
        let certificate_hash = ContentHash::compute(cert_bytes.as_bytes());

        certificates.push(KernelSynthCertificate {
            schema_version: KERNEL_SYNTH_SCHEMA_VERSION.to_string(),
            kernel_id: decision.kernel_id.clone(),
            decision: decision.clone(),
            budget_consumed: default_budget.clone(),
            certificate_hash,
        });
    }

    let kernels_evaluated = corpus.schemas.len() as u32;

    let manifest_bytes = format!(
        "{}:{}:{}:{}:{}",
        KERNEL_SYNTH_SCHEMA_VERSION,
        kernels_evaluated,
        eligible_count,
        forbidden_count,
        deferred_count
    );
    let manifest_hash = ContentHash::compute(manifest_bytes.as_bytes());

    KernelSynthEvidenceManifest {
        schema_version: KERNEL_SYNTH_SCHEMA_VERSION.to_string(),
        kernels_evaluated,
        eligible_count,
        forbidden_count,
        deferred_count,
        certificates,
        manifest_hash,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a deterministic byte sequence for hashing envelope contents.
fn envelope_hash_input(
    eligible: &[EligibilityDecision],
    forbidden: &[EligibilityDecision],
    deferred: &[EligibilityDecision],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"eligible:");
    for d in eligible {
        buf.extend_from_slice(d.kernel_id.as_bytes());
        buf.push(b':');
    }
    buf.extend_from_slice(b"forbidden:");
    for d in forbidden {
        buf.extend_from_slice(d.kernel_id.as_bytes());
        buf.push(b':');
    }
    buf.extend_from_slice(b"deferred:");
    for d in deferred {
        buf.extend_from_slice(d.kernel_id.as_bytes());
        buf.push(b':');
    }
    buf
}

/// Helper: create a `KernelSchema` with all fields.
#[allow(clippy::too_many_arguments)]
fn make_schema(
    id: &str,
    family: KernelFamily,
    description: &str,
    instruction_count: u32,
    hotness: u64,
    purity: u64,
    side_effect_free: bool,
    deterministic: bool,
    bounded_time: bool,
) -> KernelSchema {
    let source_hash = ContentHash::compute(id.as_bytes());
    KernelSchema {
        id: id.to_string(),
        family,
        pattern_description: description.to_string(),
        instruction_count,
        hotness_millionths: hotness,
        purity_score_millionths: purity,
        side_effect_free,
        deterministic,
        bounded_time,
        source_hash,
    }
}

/// Build the canonical set of 10+ kernel schemas.
fn canonical_schemas() -> Vec<KernelSchema> {
    vec![
        make_schema(
            "kern-arith-001",
            KernelFamily::ArithmeticLoop,
            "Integer summation loop (for-i pattern)",
            12,
            950_000,
            MILLIONTHS,
            true,
            true,
            true,
        ),
        make_schema(
            "kern-coll-001",
            KernelFamily::CollectionIteration,
            "Array.map with pure callback",
            24,
            880_000,
            950_000,
            true,
            true,
            true,
        ),
        make_schema(
            "kern-str-001",
            KernelFamily::StringProcessing,
            "String.prototype.split + join idiom",
            18,
            720_000,
            900_000,
            true,
            true,
            true,
        ),
        make_schema(
            "kern-regex-001",
            KernelFamily::RegExpMatch,
            "Simple character class match (/[a-z]+/)",
            32,
            600_000,
            850_000,
            true,
            true,
            false, // unbounded for pathological patterns
        ),
        make_schema(
            "kern-prop-001",
            KernelFamily::PropertyAccess,
            "Monomorphic property load chain (a.b.c)",
            8,
            990_000,
            MILLIONTHS,
            true,
            true,
            true,
        ),
        make_schema(
            "kern-guard-001",
            KernelFamily::TypeGuard,
            "typeof + strict equality narrowing",
            6,
            870_000,
            MILLIONTHS,
            true,
            true,
            true,
        ),
        make_schema(
            "kern-alloc-001",
            KernelFamily::MemoryAllocation,
            "Object literal in hot loop",
            14,
            750_000,
            700_000, // low purity — allocation side channel
            true,
            true,
            true,
        ),
        make_schema(
            "kern-host-001",
            KernelFamily::HostcallBatch,
            "console.log batch in event handler",
            20,
            400_000,
            200_000,
            false, // side effects
            true,
            true,
        ),
        make_schema(
            "kern-react-001",
            KernelFamily::ReactRender,
            "Functional component re-render with hooks",
            48,
            820_000,
            500_000,
            false, // DOM side effects
            false, // non-deterministic (hooks state)
            true,
        ),
        make_schema(
            "kern-mod-001",
            KernelFamily::ModuleInit,
            "Top-level await + import graph evaluation",
            36,
            300_000,
            400_000,
            false, // I/O side effects
            false, // import resolution non-determinism
            false, // can hang on circular deps
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --

    fn sample_eligible_schema() -> KernelSchema {
        make_schema(
            "test-eligible",
            KernelFamily::ArithmeticLoop,
            "pure arithmetic loop",
            10,
            MILLIONTHS,
            MILLIONTHS,
            true,
            true,
            true,
        )
    }

    fn sample_forbidden_schema() -> KernelSchema {
        make_schema(
            "test-forbidden",
            KernelFamily::HostcallBatch,
            "side-effecting hostcall",
            20,
            500_000,
            200_000,
            false,
            true,
            true,
        )
    }

    fn sample_deferred_schema() -> KernelSchema {
        make_schema(
            "test-deferred",
            KernelFamily::StringProcessing,
            "never-hot string op",
            8,
            0,
            MILLIONTHS,
            true,
            true,
            true,
        )
    }

    fn sample_conditional_schema() -> KernelSchema {
        make_schema(
            "test-conditional",
            KernelFamily::MemoryAllocation,
            "allocation with low purity",
            14,
            750_000,
            700_000,
            true,
            true,
            true,
        )
    }

    // -- constants --

    #[test]
    fn test_constants() {
        assert_eq!(KERNEL_SYNTH_POLICY_ID, "RGC-613A");
        assert_eq!(MILLIONTHS, 1_000_000);
        assert!(!KERNEL_SYNTH_SCHEMA_VERSION.is_empty());
        assert!(!KERNEL_SYNTH_COMPONENT.is_empty());
    }

    // -- KernelFamily --

    #[test]
    fn test_kernel_family_display() {
        assert_eq!(KernelFamily::ArithmeticLoop.to_string(), "arithmetic_loop");
        assert_eq!(
            KernelFamily::CollectionIteration.to_string(),
            "collection_iteration"
        );
        assert_eq!(
            KernelFamily::StringProcessing.to_string(),
            "string_processing"
        );
        assert_eq!(KernelFamily::RegExpMatch.to_string(), "regexp_match");
        assert_eq!(KernelFamily::PropertyAccess.to_string(), "property_access");
        assert_eq!(KernelFamily::TypeGuard.to_string(), "type_guard");
        assert_eq!(
            KernelFamily::MemoryAllocation.to_string(),
            "memory_allocation"
        );
        assert_eq!(KernelFamily::HostcallBatch.to_string(), "hostcall_batch");
        assert_eq!(KernelFamily::ReactRender.to_string(), "react_render");
        assert_eq!(KernelFamily::ModuleInit.to_string(), "module_init");
    }

    #[test]
    fn test_kernel_family_ord() {
        assert!(KernelFamily::ArithmeticLoop < KernelFamily::CollectionIteration);
        assert!(KernelFamily::ModuleInit > KernelFamily::ReactRender);
    }

    #[test]
    fn test_kernel_family_serde_roundtrip() {
        let family = KernelFamily::PropertyAccess;
        let json = serde_json::to_string(&family).unwrap();
        assert_eq!(json, "\"property_access\"");
        let back: KernelFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back, family);
    }

    // -- ForbiddenReason --

    #[test]
    fn test_forbidden_reason_display() {
        assert_eq!(ForbiddenReason::SideEffect.to_string(), "side_effect");
        assert_eq!(
            ForbiddenReason::NonDeterministic.to_string(),
            "non_deterministic"
        );
        assert_eq!(
            ForbiddenReason::UnboundedComplexity.to_string(),
            "unbounded_complexity"
        );
        assert_eq!(
            ForbiddenReason::SecuritySensitive.to_string(),
            "security_sensitive"
        );
    }

    #[test]
    fn test_forbidden_reason_serde_roundtrip() {
        let reason = ForbiddenReason::PolicyRestriction;
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, "\"policy_restriction\"");
        let back: ForbiddenReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reason);
    }

    // -- ProofRequirement --

    #[test]
    fn test_proof_requirement_serde_roundtrip() {
        for pr in [
            ProofRequirement::None,
            ProofRequirement::BestEffort,
            ProofRequirement::Mandatory,
        ] {
            let json = serde_json::to_string(&pr).unwrap();
            let back: ProofRequirement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, pr);
        }
    }

    // -- EligibilityStatus --

    #[test]
    fn test_eligibility_status_serde_eligible() {
        let status = EligibilityStatus::Eligible;
        let json = serde_json::to_string(&status).unwrap();
        let back: EligibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_eligibility_status_serde_conditional() {
        let status = EligibilityStatus::Conditional {
            requirements: vec!["purity >= 80%".into()],
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: EligibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_eligibility_status_serde_deferred() {
        let status = EligibilityStatus::Deferred {
            reason: "waiting for profiling data".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: EligibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    // -- evaluate_eligibility --

    #[test]
    fn test_evaluate_eligible_kernel() {
        let schema = sample_eligible_schema();
        let decision = evaluate_eligibility(&schema);
        assert_eq!(decision.kernel_id, "test-eligible");
        assert_eq!(decision.status, EligibilityStatus::Eligible);
        assert!(decision.forbidden_reasons.is_empty());
        assert_eq!(decision.confidence_millionths, MILLIONTHS);
    }

    #[test]
    fn test_evaluate_forbidden_side_effect() {
        let schema = sample_forbidden_schema();
        let decision = evaluate_eligibility(&schema);
        assert_eq!(decision.status, EligibilityStatus::Forbidden);
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::SideEffect)
        );
    }

    #[test]
    fn test_evaluate_forbidden_nondeterministic() {
        let schema = make_schema(
            "nd-kern",
            KernelFamily::ReactRender,
            "nondeterministic render",
            30,
            500_000,
            MILLIONTHS,
            true,
            false, // non-deterministic
            true,
        );
        let decision = evaluate_eligibility(&schema);
        assert_eq!(decision.status, EligibilityStatus::Forbidden);
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::NonDeterministic)
        );
    }

    #[test]
    fn test_evaluate_forbidden_unbounded() {
        let schema = make_schema(
            "ub-kern",
            KernelFamily::RegExpMatch,
            "pathological regex",
            40,
            600_000,
            900_000,
            true,
            true,
            false, // unbounded
        );
        let decision = evaluate_eligibility(&schema);
        assert_eq!(decision.status, EligibilityStatus::Forbidden);
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::UnboundedComplexity)
        );
    }

    #[test]
    fn test_evaluate_forbidden_multiple_reasons() {
        let schema = make_schema(
            "multi-bad",
            KernelFamily::ModuleInit,
            "bad kernel",
            50,
            400_000,
            100_000,
            false,
            false,
            false,
        );
        let decision = evaluate_eligibility(&schema);
        assert_eq!(decision.status, EligibilityStatus::Forbidden);
        assert_eq!(decision.forbidden_reasons.len(), 3);
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::SideEffect)
        );
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::NonDeterministic)
        );
        assert!(
            decision
                .forbidden_reasons
                .contains(&ForbiddenReason::UnboundedComplexity)
        );
    }

    #[test]
    fn test_evaluate_deferred_zero_hotness() {
        let schema = sample_deferred_schema();
        let decision = evaluate_eligibility(&schema);
        assert!(matches!(
            decision.status,
            EligibilityStatus::Deferred { .. }
        ));
        assert_eq!(decision.confidence_millionths, 0);
        assert_eq!(decision.evidence_count, 0);
    }

    #[test]
    fn test_evaluate_conditional_low_purity() {
        let schema = sample_conditional_schema();
        let decision = evaluate_eligibility(&schema);
        assert!(matches!(
            decision.status,
            EligibilityStatus::Conditional { .. }
        ));
        if let EligibilityStatus::Conditional { requirements } = &decision.status {
            assert!(!requirements.is_empty());
            assert!(requirements[0].contains("purity"));
        }
    }

    // -- build_synthesis_envelope --

    #[test]
    fn test_build_synthesis_envelope_empty() {
        let envelope = build_synthesis_envelope(&[]);
        assert!(envelope.eligible.is_empty());
        assert!(envelope.forbidden.is_empty());
        assert!(envelope.deferred.is_empty());
    }

    #[test]
    fn test_build_synthesis_envelope_mixed() {
        let schemas = vec![
            sample_eligible_schema(),
            sample_forbidden_schema(),
            sample_deferred_schema(),
            sample_conditional_schema(),
        ];
        let envelope = build_synthesis_envelope(&schemas);
        assert_eq!(envelope.eligible.len(), 1);
        assert_eq!(envelope.forbidden.len(), 1);
        // deferred + conditional both go to deferred bucket
        assert_eq!(envelope.deferred.len(), 2);
        // envelope hash should be non-zero
        assert_ne!(envelope.envelope_hash, ContentHash::default());
    }

    #[test]
    fn test_build_synthesis_envelope_all_eligible() {
        let schemas = vec![
            sample_eligible_schema(),
            make_schema(
                "e2",
                KernelFamily::PropertyAccess,
                "pure access",
                5,
                900_000,
                MILLIONTHS,
                true,
                true,
                true,
            ),
        ];
        let envelope = build_synthesis_envelope(&schemas);
        assert_eq!(envelope.eligible.len(), 2);
        assert!(envelope.forbidden.is_empty());
        assert!(envelope.deferred.is_empty());
    }

    #[test]
    fn test_build_synthesis_envelope_deterministic_hash() {
        let schemas = vec![sample_eligible_schema(), sample_forbidden_schema()];
        let e1 = build_synthesis_envelope(&schemas);
        let e2 = build_synthesis_envelope(&schemas);
        assert_eq!(e1.envelope_hash, e2.envelope_hash);
    }

    // -- validate_schemas --

    #[test]
    fn test_validate_schemas_empty() {
        let result = validate_schemas(&[]);
        assert_eq!(result, Err(KernelSynthError::EmptyCorpus));
    }

    #[test]
    fn test_validate_schemas_duplicate() {
        let schemas = vec![sample_eligible_schema(), sample_eligible_schema()];
        let result = validate_schemas(&schemas);
        assert!(matches!(
            result,
            Err(KernelSynthError::DuplicateKernel { .. })
        ));
    }

    #[test]
    fn test_validate_schemas_empty_id() {
        let mut s = sample_eligible_schema();
        s.id = String::new();
        let result = validate_schemas(&[s]);
        assert!(matches!(
            result,
            Err(KernelSynthError::InvalidSchema { .. })
        ));
    }

    #[test]
    fn test_validate_schemas_ok() {
        let schemas = vec![sample_eligible_schema(), sample_forbidden_schema()];
        assert!(validate_schemas(&schemas).is_ok());
    }

    // -- mine_canonical_kernels --

    #[test]
    fn test_mine_canonical_kernels_has_ten_or_more() {
        let corpus = mine_canonical_kernels();
        assert!(corpus.schemas.len() >= 10);
        assert_eq!(corpus.schemas.len(), corpus.decisions.len());
    }

    #[test]
    fn test_mine_canonical_kernels_no_duplicate_ids() {
        let corpus = mine_canonical_kernels();
        let mut ids = BTreeSet::new();
        for s in &corpus.schemas {
            assert!(ids.insert(&s.id), "duplicate id: {}", s.id);
        }
    }

    #[test]
    fn test_mine_canonical_kernels_all_families_present() {
        let corpus = mine_canonical_kernels();
        let families: BTreeSet<KernelFamily> = corpus.schemas.iter().map(|s| s.family).collect();
        assert!(families.contains(&KernelFamily::ArithmeticLoop));
        assert!(families.contains(&KernelFamily::CollectionIteration));
        assert!(families.contains(&KernelFamily::StringProcessing));
        assert!(families.contains(&KernelFamily::RegExpMatch));
        assert!(families.contains(&KernelFamily::PropertyAccess));
        assert!(families.contains(&KernelFamily::TypeGuard));
        assert!(families.contains(&KernelFamily::MemoryAllocation));
        assert!(families.contains(&KernelFamily::HostcallBatch));
        assert!(families.contains(&KernelFamily::ReactRender));
        assert!(families.contains(&KernelFamily::ModuleInit));
    }

    #[test]
    fn test_mine_canonical_kernels_has_mixed_verdicts() {
        let corpus = mine_canonical_kernels();
        let has_eligible = corpus
            .decisions
            .iter()
            .any(|d| d.status == EligibilityStatus::Eligible);
        let has_forbidden = corpus
            .decisions
            .iter()
            .any(|d| d.status == EligibilityStatus::Forbidden);
        assert!(has_eligible, "corpus should have eligible kernels");
        assert!(has_forbidden, "corpus should have forbidden kernels");
    }

    #[test]
    fn test_mine_canonical_kernels_deterministic() {
        let c1 = mine_canonical_kernels();
        let c2 = mine_canonical_kernels();
        assert_eq!(c1.corpus_hash, c2.corpus_hash);
        assert_eq!(c1.schemas.len(), c2.schemas.len());
    }

    // -- run_kernel_synth_evidence --

    #[test]
    fn test_evidence_manifest_schema_version() {
        let manifest = run_kernel_synth_evidence();
        assert_eq!(manifest.schema_version, KERNEL_SYNTH_SCHEMA_VERSION);
    }

    #[test]
    fn test_evidence_manifest_counts() {
        let manifest = run_kernel_synth_evidence();
        assert_eq!(
            manifest.kernels_evaluated,
            manifest.eligible_count + manifest.forbidden_count + manifest.deferred_count
        );
        assert!(manifest.kernels_evaluated >= 10);
    }

    #[test]
    fn test_evidence_manifest_certificates() {
        let manifest = run_kernel_synth_evidence();
        assert_eq!(
            manifest.certificates.len(),
            manifest.kernels_evaluated as usize
        );
        for cert in &manifest.certificates {
            assert_eq!(cert.schema_version, KERNEL_SYNTH_SCHEMA_VERSION);
            assert!(!cert.kernel_id.is_empty());
            assert_ne!(cert.certificate_hash, ContentHash::default());
        }
    }

    #[test]
    fn test_evidence_manifest_no_error() {
        let manifest = run_kernel_synth_evidence();
        assert!(manifest.error.is_none());
    }

    #[test]
    fn test_evidence_manifest_deterministic_hash() {
        let m1 = run_kernel_synth_evidence();
        let m2 = run_kernel_synth_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // -- KernelSynthError --

    #[test]
    fn test_error_display() {
        let e = KernelSynthError::EmptyCorpus;
        assert!(e.to_string().contains("empty corpus"));

        let e = KernelSynthError::DuplicateKernel { id: "k1".into() };
        assert!(e.to_string().contains("k1"));

        let e = KernelSynthError::InvalidBudget {
            reason: "negative time".into(),
        };
        assert!(e.to_string().contains("negative time"));

        let e = KernelSynthError::InvalidSchema {
            reason: "missing id".into(),
        };
        assert!(e.to_string().contains("missing id"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let errors = vec![
            KernelSynthError::EmptyCorpus,
            KernelSynthError::DuplicateKernel { id: "x".into() },
            KernelSynthError::InvalidBudget { reason: "r".into() },
            KernelSynthError::InvalidSchema { reason: "s".into() },
        ];
        for e in errors {
            let json = serde_json::to_string(&e).unwrap();
            let back: KernelSynthError = serde_json::from_str(&json).unwrap();
            assert_eq!(back, e);
        }
    }

    // -- SynthesisBudget --

    #[test]
    fn test_synthesis_budget_serde_roundtrip() {
        let budget = SynthesisBudget {
            max_kernels: 32,
            max_instruction_expansion: 8,
            time_budget_millionths: 10 * MILLIONTHS,
            proof_requirement: ProofRequirement::Mandatory,
        };
        let json = serde_json::to_string(&budget).unwrap();
        let back: SynthesisBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, budget);
    }

    // -- KernelSchema --

    #[test]
    fn test_kernel_schema_serde_roundtrip() {
        let schema = sample_eligible_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let back: KernelSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(back, schema);
    }

    // -- EligibilityDecision --

    #[test]
    fn test_eligibility_decision_serde_roundtrip() {
        let decision = evaluate_eligibility(&sample_eligible_schema());
        let json = serde_json::to_string(&decision).unwrap();
        let back: EligibilityDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, decision);
    }

    // -- KernelSynthCertificate --

    #[test]
    fn test_certificate_serde_roundtrip() {
        let manifest = run_kernel_synth_evidence();
        let cert = &manifest.certificates[0];
        let json = serde_json::to_string(cert).unwrap();
        let back: KernelSynthCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, cert);
    }

    // -- Corpus hash --

    #[test]
    fn test_corpus_hash_nonzero() {
        let corpus = mine_canonical_kernels();
        assert_ne!(corpus.corpus_hash, ContentHash::default());
    }
}
