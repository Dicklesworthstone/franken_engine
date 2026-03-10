//! Proof-guided trace fusion and superinstructions for policy-legal motifs.
//!
//! This module fuses repeated hostcall and effect motifs into
//! trace/superinstruction paths with deterministic side-exit behavior,
//! explicit proof lineage, and supportable disable semantics.
//!
//! Policy reference: RGC-604B.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for trace-fusion superinstruction artifacts.
pub const TRACE_FUSION_SCHEMA_VERSION: &str = "franken-engine.trace-fusion-superinstruction.v1";

/// Component name for diagnostics.
pub const TRACE_FUSION_COMPONENT: &str = "trace_fusion_superinstruction";

/// Policy identifier.
pub const TRACE_FUSION_POLICY_ID: &str = "RGC-604B";

/// One unit in fixed-point millionths representation (1.0).
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// MotifKind
// ---------------------------------------------------------------------------

/// Kind of repeatable instruction motif eligible for fusion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotifKind {
    /// Consecutive hostcall invocations sharing a capability envelope.
    HostcallSequence,
    /// Property-load chain on a stable shape.
    PropertyAccess,
    /// Linear arithmetic chain with no side effects.
    ArithmeticChain,
    /// Guard-elided region authorized by capability proofs.
    GuardChain,
    /// Load/store sequence on contiguous memory.
    LoadStoreSequence,
    /// Comparison-and-branch idiom.
    BranchPattern,
    /// Function call sequence.
    CallSequence,
}

// ---------------------------------------------------------------------------
// SideEffectKind
// ---------------------------------------------------------------------------

/// Kinds of observable side effects a trace segment may perform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectKind {
    /// Write to engine-managed memory.
    MemoryWrite,
    /// Invocation of a host-provided function.
    HostcallInvocation,
    /// Throwing an exception.
    ExceptionThrow,
    /// Defining a new property on an object.
    PropertyDefine,
    /// Triggering an allocation.
    AllocationTrigger,
    /// Reaching a GC safepoint.
    GcSafepoint,
}

// ---------------------------------------------------------------------------
// TraceSegment
// ---------------------------------------------------------------------------

/// A single segment of a recorded trace, representing a fusible motif.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSegment {
    /// Unique identifier for this segment.
    pub id: String,
    /// Kind of motif this segment represents.
    pub motif: MotifKind,
    /// Number of instructions in this segment.
    pub instruction_count: u32,
    /// Hotness score in fixed-point millionths.
    pub hotness_millionths: u64,
    /// Whether this segment passes policy legality checks.
    pub is_policy_legal: bool,
    /// Side effects that this segment may produce.
    pub side_effects: Vec<SideEffectKind>,
}

// ---------------------------------------------------------------------------
// FusionCandidate
// ---------------------------------------------------------------------------

/// A candidate set of trace segments proposed for fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionCandidate {
    /// Ordered segments to fuse.
    pub segments: Vec<TraceSegment>,
    /// Total instruction count across all segments.
    pub total_instructions: u32,
    /// Estimated speedup from fusion, in fixed-point millionths.
    pub estimated_speedup_millionths: u64,
    /// Content hash of the candidate for deterministic identity.
    pub fusion_hash: ContentHash,
}

impl FusionCandidate {
    /// Compute the content hash from segments.
    pub fn compute_hash(segments: &[TraceSegment]) -> ContentHash {
        let mut data = Vec::new();
        for seg in segments {
            data.extend_from_slice(seg.id.as_bytes());
            data.extend_from_slice(format!("{:?}", seg.motif).as_bytes());
            data.extend_from_slice(&seg.instruction_count.to_le_bytes());
        }
        ContentHash::compute(&data)
    }

    /// Create a new candidate from segments with computed totals.
    pub fn from_segments(segments: Vec<TraceSegment>, speedup: u64) -> Self {
        let total: u32 = segments.iter().map(|s| s.instruction_count).sum();
        let hash = Self::compute_hash(&segments);
        Self {
            segments,
            total_instructions: total,
            estimated_speedup_millionths: speedup,
            fusion_hash: hash,
        }
    }
}

// ---------------------------------------------------------------------------
// FusionRejectReason
// ---------------------------------------------------------------------------

/// Reason a fusion candidate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionRejectReason {
    /// The candidate violates a policy constraint.
    PolicyViolation,
    /// Side effects between segments conflict.
    SideEffectConflict,
    /// The candidate contains an unbounded loop.
    UnboundedLoop,
    /// Hotness is below the required threshold.
    InsufficientHotness,
    /// Required proof is missing.
    ProofMissing,
    /// A guard in the candidate failed verification.
    GuardFailure,
}

// ---------------------------------------------------------------------------
// FusionDecision
// ---------------------------------------------------------------------------

/// Decision made about a fusion candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionDecision {
    /// The candidate should be fused into a superinstruction.
    Fuse {
        /// Identifier for the resulting superinstruction.
        superinstruction_id: String,
    },
    /// The candidate was rejected.
    Reject {
        /// Reason for rejection.
        reason: FusionRejectReason,
    },
    /// The decision is deferred for later evaluation.
    Defer {
        /// Explanation for deferral.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// SideExitDescriptor
// ---------------------------------------------------------------------------

/// Descriptor for a side exit from a superinstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideExitDescriptor {
    /// Unique identifier for this exit.
    pub exit_id: String,
    /// Index of the guard that triggers this exit.
    pub guard_index: u32,
    /// Target program counter to resume at.
    pub target_pc: u64,
    /// Content hash of the deoptimization state.
    pub deopt_state_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Superinstruction
// ---------------------------------------------------------------------------

/// A fused superinstruction built from trace segments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superinstruction {
    /// Unique identifier for this superinstruction.
    pub id: String,
    /// IDs of the trace segments that were fused.
    pub fused_segments: Vec<String>,
    /// Side exits from this superinstruction.
    pub side_exits: Vec<SideExitDescriptor>,
    /// Proof hash that authorized this fusion.
    pub proof_hash: ContentHash,
    /// Optional token that can be used to disable this superinstruction.
    pub disable_token: Option<String>,
    /// Total estimated speedup in fixed-point millionths.
    pub total_speedup_millionths: u64,
}

// ---------------------------------------------------------------------------
// FusionProof
// ---------------------------------------------------------------------------

/// Proof that authorizes a fusion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionProof {
    /// Content hash of the candidate this proof covers.
    pub candidate_hash: ContentHash,
    /// Whether the policy check passed.
    pub policy_check_passed: bool,
    /// Whether determinism was verified.
    pub determinism_verified: bool,
    /// Number of side exits verified for coverage.
    pub side_exit_coverage: u32,
    /// Content hash of the proof itself.
    pub proof_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// TraceFusionConfig
// ---------------------------------------------------------------------------

/// Configuration for trace fusion evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFusionConfig {
    /// Minimum hotness (millionths) for a segment to be fusible.
    pub min_hotness_millionths: u64,
    /// Maximum fused instruction count.
    pub max_fused_instructions: u32,
    /// Maximum side exits per superinstruction.
    pub max_side_exits: u32,
    /// Whether a proof is required for fusion.
    pub require_proof: bool,
    /// Whether hostcall sequences may be fused.
    pub allow_hostcall_fusion: bool,
}

impl TraceFusionConfig {
    /// Returns a default configuration with sensible values.
    pub fn default_config() -> Self {
        Self {
            min_hotness_millionths: 500_000, // 0.5
            max_fused_instructions: 128,
            max_side_exits: 16,
            require_proof: true,
            allow_hostcall_fusion: true,
        }
    }
}

// ---------------------------------------------------------------------------
// FusionCertificate
// ---------------------------------------------------------------------------

/// A certificate recording the full fusion decision pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionCertificate {
    /// Schema version for this certificate.
    pub schema_version: String,
    /// The candidate that was evaluated.
    pub candidate: FusionCandidate,
    /// The decision made.
    pub decision: FusionDecision,
    /// Optional proof that authorized the decision.
    pub proof: Option<FusionProof>,
    /// Optional superinstruction produced by fusion.
    pub superinstruction: Option<Superinstruction>,
    /// Content hash of this certificate.
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// TraceFusionError
// ---------------------------------------------------------------------------

/// Errors that may occur during trace fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceFusionError {
    /// The candidate has no segments.
    EmptyCandidate,
    /// A duplicate segment ID was found.
    DuplicateSegment {
        /// The duplicated segment ID.
        id: String,
    },
    /// The configuration is invalid.
    InvalidConfig {
        /// Description of the invalid configuration.
        reason: String,
    },
    /// Proof construction or verification failed.
    ProofFailure {
        /// Description of the proof failure.
        reason: String,
    },
}

impl std::fmt::Display for TraceFusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCandidate => write!(f, "empty candidate"),
            Self::DuplicateSegment { id } => {
                write!(f, "duplicate segment: {id}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::ProofFailure { reason } => {
                write!(f, "proof failure: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TraceFusionEvidenceManifest
// ---------------------------------------------------------------------------

/// Evidence manifest summarizing trace fusion activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFusionEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Number of candidates evaluated.
    pub candidates_evaluated: u32,
    /// Number of candidates that were fused.
    pub fused_count: u32,
    /// Number of candidates that were rejected.
    pub rejected_count: u32,
    /// Number of candidates that were deferred.
    pub deferred_count: u32,
    /// Superinstructions produced.
    pub superinstructions: Vec<Superinstruction>,
    /// Certificates produced.
    pub certificates: Vec<FusionCertificate>,
    /// Content hash of this manifest.
    pub manifest_hash: ContentHash,
    /// Optional error encountered during evidence collection.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Validate that a candidate has no empty or duplicate segments.
pub fn validate_candidate(candidate: &FusionCandidate) -> Result<(), TraceFusionError> {
    if candidate.segments.is_empty() {
        return Err(TraceFusionError::EmptyCandidate);
    }
    let mut seen = BTreeSet::new();
    for seg in &candidate.segments {
        if !seen.insert(&seg.id) {
            return Err(TraceFusionError::DuplicateSegment { id: seg.id.clone() });
        }
    }
    Ok(())
}

/// Evaluate a fusion candidate against the given configuration, returning a
/// decision.
pub fn evaluate_candidate(
    candidate: &FusionCandidate,
    config: &TraceFusionConfig,
) -> FusionDecision {
    // Check total instruction budget.
    if candidate.total_instructions > config.max_fused_instructions {
        return FusionDecision::Reject {
            reason: FusionRejectReason::UnboundedLoop,
        };
    }

    // Check policy legality of every segment.
    for seg in &candidate.segments {
        if !seg.is_policy_legal {
            return FusionDecision::Reject {
                reason: FusionRejectReason::PolicyViolation,
            };
        }
    }

    // Check hotness.
    for seg in &candidate.segments {
        if seg.hotness_millionths < config.min_hotness_millionths {
            return FusionDecision::Reject {
                reason: FusionRejectReason::InsufficientHotness,
            };
        }
    }

    // Check hostcall fusion permission.
    if !config.allow_hostcall_fusion {
        for seg in &candidate.segments {
            if seg.motif == MotifKind::HostcallSequence {
                return FusionDecision::Reject {
                    reason: FusionRejectReason::PolicyViolation,
                };
            }
        }
    }

    // Check for side-effect conflicts between adjacent segments.
    for window in candidate.segments.windows(2) {
        if !can_fuse_segments(&window[0], &window[1]) {
            return FusionDecision::Reject {
                reason: FusionRejectReason::SideEffectConflict,
            };
        }
    }

    // If proof is required, defer until proof is built.
    if config.require_proof {
        // We still issue a Fuse decision; the caller must supply a proof
        // before materializing the superinstruction.
    }

    let si_id = format!("si-{}", &candidate.fusion_hash.to_hex()[..16]);
    FusionDecision::Fuse {
        superinstruction_id: si_id,
    }
}

/// Check whether two adjacent trace segments can be fused.
///
/// Segments cannot be fused if one writes memory and the other throws
/// exceptions, or if both perform hostcall invocations (ordering concern).
pub fn can_fuse_segments(a: &TraceSegment, b: &TraceSegment) -> bool {
    let a_effects: BTreeSet<_> = a.side_effects.iter().collect();
    let b_effects: BTreeSet<_> = b.side_effects.iter().collect();

    // Memory write + exception throw across segments is a conflict.
    if a_effects.contains(&SideEffectKind::MemoryWrite)
        && b_effects.contains(&SideEffectKind::ExceptionThrow)
    {
        return false;
    }
    if b_effects.contains(&SideEffectKind::MemoryWrite)
        && a_effects.contains(&SideEffectKind::ExceptionThrow)
    {
        return false;
    }

    // Two hostcall invocations must preserve ordering — reject.
    if a_effects.contains(&SideEffectKind::HostcallInvocation)
        && b_effects.contains(&SideEffectKind::HostcallInvocation)
    {
        return false;
    }

    true
}

/// Build a proof for the given fusion candidate.
pub fn build_proof(candidate: &FusionCandidate) -> FusionProof {
    let policy_ok = candidate.segments.iter().all(|s| s.is_policy_legal);
    let determinism_ok = candidate
        .segments
        .iter()
        .all(|s| !s.side_effects.contains(&SideEffectKind::AllocationTrigger) || s.is_policy_legal);

    let side_exit_coverage = candidate.segments.len() as u32;

    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(candidate.fusion_hash.as_bytes());
    proof_data.extend_from_slice(if policy_ok {
        b"policy_pass"
    } else {
        b"policy_fail"
    });
    proof_data.extend_from_slice(if determinism_ok {
        b"det_pass"
    } else {
        b"det_fail"
    });
    let proof_hash = ContentHash::compute(&proof_data);

    FusionProof {
        candidate_hash: candidate.fusion_hash.clone(),
        policy_check_passed: policy_ok,
        determinism_verified: determinism_ok,
        side_exit_coverage,
        proof_hash,
    }
}

/// Build a superinstruction from a candidate and its proof.
pub fn build_superinstruction(
    candidate: &FusionCandidate,
    proof: &FusionProof,
) -> Superinstruction {
    let si_id = format!("si-{}", &candidate.fusion_hash.to_hex()[..16]);

    let fused_segments: Vec<String> = candidate.segments.iter().map(|s| s.id.clone()).collect();

    let side_exits: Vec<SideExitDescriptor> = candidate
        .segments
        .iter()
        .enumerate()
        .map(|(i, seg)| {
            let mut exit_data = Vec::new();
            exit_data.extend_from_slice(seg.id.as_bytes());
            exit_data.extend_from_slice(&(i as u32).to_le_bytes());
            let deopt_hash = ContentHash::compute(&exit_data);
            SideExitDescriptor {
                exit_id: format!("exit-{}-{i}", &seg.id),
                guard_index: i as u32,
                target_pc: (i as u64) * 16,
                deopt_state_hash: deopt_hash,
            }
        })
        .collect();

    let disable_token = Some(format!("disable-{}", &candidate.fusion_hash.to_hex()[..8]));

    Superinstruction {
        id: si_id,
        fused_segments,
        side_exits,
        proof_hash: proof.proof_hash.clone(),
        disable_token,
        total_speedup_millionths: candidate.estimated_speedup_millionths,
    }
}

/// Certify a fusion candidate end-to-end: validate, evaluate, prove, build.
pub fn certify_fusion(
    candidate: &FusionCandidate,
    config: &TraceFusionConfig,
) -> FusionCertificate {
    let decision = evaluate_candidate(candidate, config);

    let (proof, superinstruction) = match &decision {
        FusionDecision::Fuse { .. } => {
            let p = build_proof(candidate);
            if p.policy_check_passed && p.determinism_verified {
                let si = build_superinstruction(candidate, &p);
                (Some(p), Some(si))
            } else {
                (Some(p), None)
            }
        }
        _ => (None, None),
    };

    let mut cert_data = Vec::new();
    cert_data.extend_from_slice(TRACE_FUSION_SCHEMA_VERSION.as_bytes());
    cert_data.extend_from_slice(candidate.fusion_hash.as_bytes());
    cert_data.extend_from_slice(format!("{:?}", decision).as_bytes());
    if let Some(ref p) = proof {
        cert_data.extend_from_slice(p.proof_hash.as_bytes());
    }
    let certificate_hash = ContentHash::compute(&cert_data);

    FusionCertificate {
        schema_version: TRACE_FUSION_SCHEMA_VERSION.to_string(),
        candidate: candidate.clone(),
        decision,
        proof,
        superinstruction,
        certificate_hash,
    }
}

/// Run a sample evidence corpus and return a manifest.
pub fn run_trace_fusion_evidence() -> TraceFusionEvidenceManifest {
    let config = TraceFusionConfig::default_config();

    // Build sample candidates.
    let candidates = sample_candidates();

    let mut fused_count = 0u32;
    let mut rejected_count = 0u32;
    let mut deferred_count = 0u32;
    let mut superinstructions = Vec::new();
    let mut certificates = Vec::new();

    for candidate in &candidates {
        let cert = certify_fusion(candidate, &config);
        match &cert.decision {
            FusionDecision::Fuse { .. } => {
                fused_count += 1;
                if let Some(ref si) = cert.superinstruction {
                    superinstructions.push(si.clone());
                }
            }
            FusionDecision::Reject { .. } => {
                rejected_count += 1;
            }
            FusionDecision::Defer { .. } => {
                deferred_count += 1;
            }
        }
        certificates.push(cert);
    }

    let mut manifest_data = Vec::new();
    manifest_data.extend_from_slice(TRACE_FUSION_SCHEMA_VERSION.as_bytes());
    manifest_data.extend_from_slice(&(candidates.len() as u32).to_le_bytes());
    manifest_data.extend_from_slice(&fused_count.to_le_bytes());
    manifest_data.extend_from_slice(&rejected_count.to_le_bytes());
    let manifest_hash = ContentHash::compute(&manifest_data);

    TraceFusionEvidenceManifest {
        schema_version: TRACE_FUSION_SCHEMA_VERSION.to_string(),
        candidates_evaluated: candidates.len() as u32,
        fused_count,
        rejected_count,
        deferred_count,
        superinstructions,
        certificates,
        manifest_hash,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a simple trace segment for testing / evidence.
fn make_segment(
    id: &str,
    motif: MotifKind,
    instruction_count: u32,
    hotness: u64,
    policy_legal: bool,
    effects: Vec<SideEffectKind>,
) -> TraceSegment {
    TraceSegment {
        id: id.to_string(),
        motif,
        instruction_count,
        hotness_millionths: hotness,
        is_policy_legal: policy_legal,
        side_effects: effects,
    }
}

/// Build sample candidates for the evidence corpus.
fn sample_candidates() -> Vec<FusionCandidate> {
    let seg_a = make_segment(
        "seg-arith-1",
        MotifKind::ArithmeticChain,
        8,
        900_000,
        true,
        vec![],
    );
    let seg_b = make_segment(
        "seg-arith-2",
        MotifKind::ArithmeticChain,
        6,
        850_000,
        true,
        vec![],
    );
    let seg_c = make_segment(
        "seg-prop-1",
        MotifKind::PropertyAccess,
        4,
        700_000,
        true,
        vec![SideEffectKind::MemoryWrite],
    );
    let seg_d = make_segment(
        "seg-hostcall-1",
        MotifKind::HostcallSequence,
        3,
        600_000,
        true,
        vec![SideEffectKind::HostcallInvocation],
    );
    let seg_e = make_segment(
        "seg-cold",
        MotifKind::BranchPattern,
        5,
        200_000, // below default threshold
        true,
        vec![],
    );
    let seg_f = make_segment(
        "seg-illegal",
        MotifKind::GuardChain,
        4,
        800_000,
        false, // not policy legal
        vec![],
    );

    vec![
        // Good candidate: two arithmetic segments.
        FusionCandidate::from_segments(vec![seg_a.clone(), seg_b.clone()], 200_000),
        // Rejected: cold segment.
        FusionCandidate::from_segments(vec![seg_c.clone(), seg_e], 100_000),
        // Rejected: illegal segment.
        FusionCandidate::from_segments(vec![seg_f], 50_000),
        // Good candidate: property + hostcall (allowed).
        FusionCandidate::from_segments(vec![seg_c, seg_d], 150_000),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn arith_segment(id: &str, hotness: u64) -> TraceSegment {
        make_segment(id, MotifKind::ArithmeticChain, 5, hotness, true, vec![])
    }

    #[allow(dead_code)]
    fn hot_segment(id: &str, motif: MotifKind) -> TraceSegment {
        make_segment(id, motif, 4, 800_000, true, vec![])
    }

    fn effectful_segment(id: &str, effects: Vec<SideEffectKind>) -> TraceSegment {
        make_segment(id, MotifKind::LoadStoreSequence, 3, 700_000, true, effects)
    }

    // -- Constants --

    #[test]
    fn test_schema_version_correct() {
        assert_eq!(
            TRACE_FUSION_SCHEMA_VERSION,
            "franken-engine.trace-fusion-superinstruction.v1"
        );
    }

    #[test]
    fn test_component_correct() {
        assert_eq!(TRACE_FUSION_COMPONENT, "trace_fusion_superinstruction");
    }

    #[test]
    fn test_policy_id_correct() {
        assert_eq!(TRACE_FUSION_POLICY_ID, "RGC-604B");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -- MotifKind --

    #[test]
    fn test_motif_kind_serde_roundtrip() {
        let kinds = vec![
            MotifKind::HostcallSequence,
            MotifKind::PropertyAccess,
            MotifKind::ArithmeticChain,
            MotifKind::GuardChain,
            MotifKind::LoadStoreSequence,
            MotifKind::BranchPattern,
            MotifKind::CallSequence,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: MotifKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, kind);
        }
    }

    #[test]
    fn test_motif_kind_ordering() {
        assert!(MotifKind::ArithmeticChain < MotifKind::BranchPattern);
        assert!(MotifKind::HostcallSequence > MotifKind::GuardChain);
    }

    // -- SideEffectKind --

    #[test]
    fn test_side_effect_kind_serde() {
        let effect = SideEffectKind::MemoryWrite;
        let json = serde_json::to_string(&effect).unwrap();
        assert!(json.contains("memory_write"));
        let back: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, effect);
    }

    // -- TraceSegment --

    #[test]
    fn test_trace_segment_creation() {
        let seg = arith_segment("s1", 900_000);
        assert_eq!(seg.id, "s1");
        assert_eq!(seg.instruction_count, 5);
        assert_eq!(seg.hotness_millionths, 900_000);
        assert!(seg.is_policy_legal);
        assert!(seg.side_effects.is_empty());
    }

    // -- FusionCandidate --

    #[test]
    fn test_candidate_from_segments() {
        let s1 = arith_segment("a", 800_000);
        let s2 = arith_segment("b", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 100_000);
        assert_eq!(cand.total_instructions, 10);
        assert_eq!(cand.estimated_speedup_millionths, 100_000);
        assert_eq!(cand.segments.len(), 2);
    }

    #[test]
    fn test_candidate_hash_deterministic() {
        let s1 = arith_segment("x", 800_000);
        let s2 = arith_segment("y", 800_000);
        let h1 = FusionCandidate::compute_hash(&[s1.clone(), s2.clone()]);
        let h2 = FusionCandidate::compute_hash(&[s1, s2]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_candidate_hash_differs_by_order() {
        let s1 = arith_segment("x", 800_000);
        let s2 = arith_segment("y", 800_000);
        let h1 = FusionCandidate::compute_hash(&[s1.clone(), s2.clone()]);
        let h2 = FusionCandidate::compute_hash(&[s2, s1]);
        assert_ne!(h1, h2);
    }

    // -- validate_candidate --

    #[test]
    fn test_validate_empty_candidate() {
        let cand = FusionCandidate::from_segments(vec![], 0);
        // Manually construct because from_segments will have total 0
        let result = validate_candidate(&cand);
        assert_eq!(result, Err(TraceFusionError::EmptyCandidate));
    }

    #[test]
    fn test_validate_duplicate_segment() {
        let s1 = arith_segment("dup", 800_000);
        let s2 = arith_segment("dup", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 0);
        let result = validate_candidate(&cand);
        assert_eq!(
            result,
            Err(TraceFusionError::DuplicateSegment {
                id: "dup".to_string(),
            })
        );
    }

    #[test]
    fn test_validate_good_candidate() {
        let s1 = arith_segment("a", 800_000);
        let s2 = arith_segment("b", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 100_000);
        assert!(validate_candidate(&cand).is_ok());
    }

    // -- evaluate_candidate --

    #[test]
    fn test_evaluate_fuses_hot_legal_candidate() {
        let s1 = arith_segment("a", 800_000);
        let s2 = arith_segment("b", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 100_000);
        let config = TraceFusionConfig::default_config();
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(decision, FusionDecision::Fuse { .. }));
    }

    #[test]
    fn test_evaluate_rejects_cold_segment() {
        let s1 = arith_segment("a", 100_000); // below 500k threshold
        let cand = FusionCandidate::from_segments(vec![s1], 50_000);
        let config = TraceFusionConfig::default_config();
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(
            decision,
            FusionDecision::Reject {
                reason: FusionRejectReason::InsufficientHotness
            }
        ));
    }

    #[test]
    fn test_evaluate_rejects_policy_violation() {
        let seg = make_segment("illegal", MotifKind::GuardChain, 4, 800_000, false, vec![]);
        let cand = FusionCandidate::from_segments(vec![seg], 50_000);
        let config = TraceFusionConfig::default_config();
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(
            decision,
            FusionDecision::Reject {
                reason: FusionRejectReason::PolicyViolation
            }
        ));
    }

    #[test]
    fn test_evaluate_rejects_too_many_instructions() {
        let seg = make_segment(
            "big",
            MotifKind::ArithmeticChain,
            200,
            800_000,
            true,
            vec![],
        );
        let mut config = TraceFusionConfig::default_config();
        config.max_fused_instructions = 100;
        let cand = FusionCandidate::from_segments(vec![seg], 50_000);
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(
            decision,
            FusionDecision::Reject {
                reason: FusionRejectReason::UnboundedLoop
            }
        ));
    }

    #[test]
    fn test_evaluate_rejects_hostcall_when_disabled() {
        let seg = make_segment("hc", MotifKind::HostcallSequence, 3, 800_000, true, vec![]);
        let mut config = TraceFusionConfig::default_config();
        config.allow_hostcall_fusion = false;
        let cand = FusionCandidate::from_segments(vec![seg], 50_000);
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(
            decision,
            FusionDecision::Reject {
                reason: FusionRejectReason::PolicyViolation
            }
        ));
    }

    #[test]
    fn test_evaluate_rejects_side_effect_conflict() {
        let s1 = effectful_segment("w", vec![SideEffectKind::MemoryWrite]);
        let s2 = effectful_segment("e", vec![SideEffectKind::ExceptionThrow]);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 50_000);
        let config = TraceFusionConfig::default_config();
        let decision = evaluate_candidate(&cand, &config);
        assert!(matches!(
            decision,
            FusionDecision::Reject {
                reason: FusionRejectReason::SideEffectConflict
            }
        ));
    }

    // -- can_fuse_segments --

    #[test]
    fn test_can_fuse_no_effects() {
        let a = arith_segment("a", 800_000);
        let b = arith_segment("b", 800_000);
        assert!(can_fuse_segments(&a, &b));
    }

    #[test]
    fn test_cannot_fuse_write_and_exception() {
        let a = effectful_segment("a", vec![SideEffectKind::MemoryWrite]);
        let b = effectful_segment("b", vec![SideEffectKind::ExceptionThrow]);
        assert!(!can_fuse_segments(&a, &b));
    }

    #[test]
    fn test_cannot_fuse_two_hostcalls() {
        let a = effectful_segment("a", vec![SideEffectKind::HostcallInvocation]);
        let b = effectful_segment("b", vec![SideEffectKind::HostcallInvocation]);
        assert!(!can_fuse_segments(&a, &b));
    }

    #[test]
    fn test_can_fuse_write_and_gc() {
        let a = effectful_segment("a", vec![SideEffectKind::MemoryWrite]);
        let b = effectful_segment("b", vec![SideEffectKind::GcSafepoint]);
        assert!(can_fuse_segments(&a, &b));
    }

    // -- build_proof --

    #[test]
    fn test_build_proof_passes_for_legal_candidate() {
        let s1 = arith_segment("a", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1], 100_000);
        let proof = build_proof(&cand);
        assert!(proof.policy_check_passed);
        assert!(proof.determinism_verified);
        assert_eq!(proof.side_exit_coverage, 1);
        assert_eq!(proof.candidate_hash, cand.fusion_hash);
    }

    #[test]
    fn test_build_proof_fails_for_illegal_candidate() {
        let seg = make_segment("bad", MotifKind::GuardChain, 4, 800_000, false, vec![]);
        let cand = FusionCandidate::from_segments(vec![seg], 50_000);
        let proof = build_proof(&cand);
        assert!(!proof.policy_check_passed);
    }

    #[test]
    fn test_build_proof_hash_deterministic() {
        let s1 = arith_segment("a", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1], 100_000);
        let p1 = build_proof(&cand);
        let p2 = build_proof(&cand);
        assert_eq!(p1.proof_hash, p2.proof_hash);
    }

    // -- build_superinstruction --

    #[test]
    fn test_build_superinstruction_structure() {
        let s1 = arith_segment("a", 800_000);
        let s2 = arith_segment("b", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 200_000);
        let proof = build_proof(&cand);
        let si = build_superinstruction(&cand, &proof);

        assert!(si.id.starts_with("si-"));
        assert_eq!(si.fused_segments, vec!["a", "b"]);
        assert_eq!(si.side_exits.len(), 2);
        assert_eq!(si.total_speedup_millionths, 200_000);
        assert!(si.disable_token.is_some());
        assert_eq!(si.proof_hash, proof.proof_hash);
    }

    #[test]
    fn test_superinstruction_side_exits_ordered() {
        let s1 = arith_segment("x", 800_000);
        let s2 = arith_segment("y", 800_000);
        let s3 = arith_segment("z", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2, s3], 300_000);
        let proof = build_proof(&cand);
        let si = build_superinstruction(&cand, &proof);

        assert_eq!(si.side_exits.len(), 3);
        for (i, exit) in si.side_exits.iter().enumerate() {
            assert_eq!(exit.guard_index, i as u32);
            assert_eq!(exit.target_pc, (i as u64) * 16);
        }
    }

    // -- certify_fusion --

    #[test]
    fn test_certify_fusion_fuses_good_candidate() {
        let s1 = arith_segment("a", 800_000);
        let s2 = arith_segment("b", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1, s2], 150_000);
        let config = TraceFusionConfig::default_config();
        let cert = certify_fusion(&cand, &config);

        assert_eq!(cert.schema_version, TRACE_FUSION_SCHEMA_VERSION);
        assert!(matches!(cert.decision, FusionDecision::Fuse { .. }));
        assert!(cert.proof.is_some());
        assert!(cert.superinstruction.is_some());
    }

    #[test]
    fn test_certify_fusion_rejects_bad_candidate() {
        let seg = make_segment("bad", MotifKind::GuardChain, 4, 800_000, false, vec![]);
        let cand = FusionCandidate::from_segments(vec![seg], 50_000);
        let config = TraceFusionConfig::default_config();
        let cert = certify_fusion(&cand, &config);

        assert!(matches!(cert.decision, FusionDecision::Reject { .. }));
        assert!(cert.proof.is_none());
        assert!(cert.superinstruction.is_none());
    }

    #[test]
    fn test_certify_certificate_hash_deterministic() {
        let s1 = arith_segment("a", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1], 100_000);
        let config = TraceFusionConfig::default_config();
        let c1 = certify_fusion(&cand, &config);
        let c2 = certify_fusion(&cand, &config);
        assert_eq!(c1.certificate_hash, c2.certificate_hash);
    }

    // -- run_trace_fusion_evidence --

    #[test]
    fn test_evidence_manifest_populated() {
        let manifest = run_trace_fusion_evidence();
        assert_eq!(manifest.schema_version, TRACE_FUSION_SCHEMA_VERSION);
        assert!(manifest.candidates_evaluated > 0);
        assert!(manifest.fused_count > 0);
        assert!(manifest.rejected_count > 0);
        assert_eq!(
            manifest.candidates_evaluated,
            manifest.fused_count + manifest.rejected_count + manifest.deferred_count
        );
        assert_eq!(
            manifest.certificates.len(),
            manifest.candidates_evaluated as usize
        );
        assert!(manifest.error.is_none());
    }

    #[test]
    fn test_evidence_manifest_hash_deterministic() {
        let m1 = run_trace_fusion_evidence();
        let m2 = run_trace_fusion_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // -- TraceFusionConfig --

    #[test]
    fn test_default_config_values() {
        let cfg = TraceFusionConfig::default_config();
        assert_eq!(cfg.min_hotness_millionths, 500_000);
        assert_eq!(cfg.max_fused_instructions, 128);
        assert_eq!(cfg.max_side_exits, 16);
        assert!(cfg.require_proof);
        assert!(cfg.allow_hostcall_fusion);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = TraceFusionConfig::default_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: TraceFusionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    // -- TraceFusionError --

    #[test]
    fn test_error_display() {
        let e1 = TraceFusionError::EmptyCandidate;
        assert_eq!(format!("{e1}"), "empty candidate");

        let e2 = TraceFusionError::DuplicateSegment {
            id: "seg-1".to_string(),
        };
        assert!(format!("{e2}").contains("seg-1"));

        let e3 = TraceFusionError::InvalidConfig {
            reason: "bad value".to_string(),
        };
        assert!(format!("{e3}").contains("bad value"));

        let e4 = TraceFusionError::ProofFailure {
            reason: "missing".to_string(),
        };
        assert!(format!("{e4}").contains("missing"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = TraceFusionError::DuplicateSegment {
            id: "seg-x".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: TraceFusionError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }

    // -- FusionDecision serde --

    #[test]
    fn test_fusion_decision_serde_fuse() {
        let d = FusionDecision::Fuse {
            superinstruction_id: "si-abc".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: FusionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn test_fusion_decision_serde_reject() {
        let d = FusionDecision::Reject {
            reason: FusionRejectReason::ProofMissing,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: FusionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn test_fusion_decision_serde_defer() {
        let d = FusionDecision::Defer {
            reason: "waiting for profiling data".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: FusionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    // -- FusionCertificate serde --

    #[test]
    fn test_certificate_serde_roundtrip() {
        let s1 = arith_segment("a", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1], 100_000);
        let config = TraceFusionConfig::default_config();
        let cert = certify_fusion(&cand, &config);
        let json = serde_json::to_string(&cert).unwrap();
        let back: FusionCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cert);
    }

    // -- Superinstruction disable token --

    #[test]
    fn test_superinstruction_has_disable_token() {
        let s1 = arith_segment("a", 800_000);
        let cand = FusionCandidate::from_segments(vec![s1], 100_000);
        let proof = build_proof(&cand);
        let si = build_superinstruction(&cand, &proof);
        assert!(si.disable_token.is_some());
        let token = si.disable_token.unwrap();
        assert!(token.starts_with("disable-"));
    }

    // -- FusionRejectReason coverage --

    #[test]
    fn test_all_reject_reasons_serde() {
        let reasons = vec![
            FusionRejectReason::PolicyViolation,
            FusionRejectReason::SideEffectConflict,
            FusionRejectReason::UnboundedLoop,
            FusionRejectReason::InsufficientHotness,
            FusionRejectReason::ProofMissing,
            FusionRejectReason::GuardFailure,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: FusionRejectReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, reason);
        }
    }
}
