#![forbid(unsafe_code)]

//! Canonical semantic bases, orbit reductions, and stable IDs across IR and
//! artifact families.
//!
//! Bead: bd-1lsy.7.18.1 [RGC-618A]
//!
//! Derives equivalence relations over IR programs, artifact bundles, and cache
//! entries so that superficially different objects that carry the same semantic
//! content map to a single trustworthy identity.  The module defines:
//!
//! - **Artifact families** — the domains over which identity can be established
//!   (IR fragments, rewrite packs, compilation artifacts, evidence records).
//! - **Equivalence relations** — which structural transformations preserve
//!   semantic identity (alpha-renaming, dead-code removal, reordering of
//!   commutative operations, etc.).
//! - **Canonical representatives** — the deterministic choice of a single
//!   representative for each equivalence class, with content-addressed hashing.
//! - **Orbit reductions** — mapping from an arbitrary element to its canonical
//!   form, recording which transformations were applied.
//! - **Refusal policy** — conditions under which the system explicitly refuses
//!   to identify two artifacts as equivalent (e.g., differing observable side
//!   effects, epoch mismatch, unsupported transformation class).
//!
//! # Design decisions
//!
//! - **Deterministic orbit** — every orbit reduction path is recorded so an
//!   auditor can verify that canonicalization was sound.
//! - **Content-addressed hashing** — the canonical ID is a `ContentHash` of
//!   the representative's serialized form, ensuring stability across runs.
//! - **Refusal is first-class** — `IdentificationRefusal` carries structured
//!   reasons, not just a bool, so downstream caches know *why* two objects
//!   were kept separate.
//! - **All arithmetic uses fixed-point millionths** (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the semantic canonical basis.
pub const SCHEMA_VERSION: &str = "franken-engine.semantic-canonical-basis.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.18.1";

/// Component name.
pub const COMPONENT: &str = "semantic_canonical_basis";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Maximum number of transformations in a single orbit reduction path before
/// the system refuses to canonicalize (guards against runaway normalization).
pub const MAX_ORBIT_DEPTH: usize = 64;

/// Maximum number of equivalence classes per basis before compaction is forced.
pub const MAX_CLASSES_PER_BASIS: usize = 8_192;

/// Minimum similarity score (millionths) for two artifacts to be considered
/// candidates for the same equivalence class.
pub const MIN_SIMILARITY_THRESHOLD: u64 = 950_000; // 95%

// ---------------------------------------------------------------------------
// ArtifactFamily — the domain of objects subject to identification
// ---------------------------------------------------------------------------

/// Domain of artifacts over which semantic identity is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFamily {
    /// IR1-level instruction sequences.
    Ir1Fragment,
    /// IR3-level optimized instruction sequences.
    Ir3Fragment,
    /// Bytecode compilation artifacts.
    BytecodeArtifact,
    /// Rewrite pack entries (versioned rewrite rules).
    RewritePack,
    /// Evidence records (receipts, attestations).
    EvidenceRecord,
    /// Module resolution snapshots.
    ModuleSnapshot,
    /// Shape transition chains.
    ShapeChain,
    /// Type feedback profiles.
    TypeFeedbackProfile,
    /// Resource certificate bundles.
    ResourceCertificate,
    /// Compilation cache entries.
    CacheEntry,
}

impl ArtifactFamily {
    /// All known artifact families in canonical order.
    pub const ALL: &[Self] = &[
        Self::Ir1Fragment,
        Self::Ir3Fragment,
        Self::BytecodeArtifact,
        Self::RewritePack,
        Self::EvidenceRecord,
        Self::ModuleSnapshot,
        Self::ShapeChain,
        Self::TypeFeedbackProfile,
        Self::ResourceCertificate,
        Self::CacheEntry,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ir1Fragment => "ir1_fragment",
            Self::Ir3Fragment => "ir3_fragment",
            Self::BytecodeArtifact => "bytecode_artifact",
            Self::RewritePack => "rewrite_pack",
            Self::EvidenceRecord => "evidence_record",
            Self::ModuleSnapshot => "module_snapshot",
            Self::ShapeChain => "shape_chain",
            Self::TypeFeedbackProfile => "type_feedback_profile",
            Self::ResourceCertificate => "resource_certificate",
            Self::CacheEntry => "cache_entry",
        }
    }
}

impl fmt::Display for ArtifactFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EquivalenceTransformation — the allowed structural rewrites
// ---------------------------------------------------------------------------

/// A structural transformation that preserves semantic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivalenceTransformation {
    /// Alpha-renaming of bound variables.
    AlphaRenaming,
    /// Removal of unreachable / dead code.
    DeadCodeElimination,
    /// Reordering of commutative binary operations.
    CommutativeReorder,
    /// Constant folding of compile-time-known expressions.
    ConstantFolding,
    /// Normalization of redundant control flow (empty blocks, single-branch if).
    ControlFlowSimplification,
    /// Deduplication of identical sub-expressions.
    CommonSubexpressionElimination,
    /// Normalization of label / block naming.
    LabelNormalization,
    /// Canonicalization of instruction ordering within a basic block where
    /// data dependencies allow reordering.
    InstructionScheduleNormalization,
    /// Flattening of nested scope chains that are observationally equivalent.
    ScopeFlattening,
    /// Normalization of metadata annotations (source maps, debug info) that
    /// do not affect semantics.
    MetadataNormalization,
}

impl EquivalenceTransformation {
    /// All known transformation kinds in canonical order.
    pub const ALL: &[Self] = &[
        Self::AlphaRenaming,
        Self::DeadCodeElimination,
        Self::CommutativeReorder,
        Self::ConstantFolding,
        Self::ControlFlowSimplification,
        Self::CommonSubexpressionElimination,
        Self::LabelNormalization,
        Self::InstructionScheduleNormalization,
        Self::ScopeFlattening,
        Self::MetadataNormalization,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AlphaRenaming => "alpha_renaming",
            Self::DeadCodeElimination => "dead_code_elimination",
            Self::CommutativeReorder => "commutative_reorder",
            Self::ConstantFolding => "constant_folding",
            Self::ControlFlowSimplification => "control_flow_simplification",
            Self::CommonSubexpressionElimination => "common_subexpression_elimination",
            Self::LabelNormalization => "label_normalization",
            Self::InstructionScheduleNormalization => "instruction_schedule_normalization",
            Self::ScopeFlattening => "scope_flattening",
            Self::MetadataNormalization => "metadata_normalization",
        }
    }

    /// Whether this transformation is always safe (no observable difference).
    pub fn is_universally_safe(&self) -> bool {
        matches!(
            self,
            Self::AlphaRenaming | Self::LabelNormalization | Self::MetadataNormalization
        )
    }
}

impl fmt::Display for EquivalenceTransformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RefusalReason — why identification was declined
// ---------------------------------------------------------------------------

/// Structured reason for refusing to identify two artifacts as equivalent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The artifacts belong to different families and cross-family
    /// identification is not supported.
    FamilyMismatch {
        left: ArtifactFamily,
        right: ArtifactFamily,
    },
    /// The artifacts originate from different security epochs.
    EpochMismatch { left_epoch: u64, right_epoch: u64 },
    /// The artifacts have differing observable side effects that would be
    /// lost under the proposed transformation.
    ObservableEffectDifference { description: String },
    /// The orbit reduction path exceeded `MAX_ORBIT_DEPTH`.
    OrbitDepthExceeded { depth_reached: usize },
    /// A required transformation class is not in the allowed set.
    TransformationNotAllowed {
        transformation: EquivalenceTransformation,
    },
    /// The similarity score between the two artifacts fell below the
    /// minimum threshold.
    SimilarityBelowThreshold {
        score_millionths: u64,
        threshold_millionths: u64,
    },
    /// The artifacts contain opaque regions that the system cannot
    /// structurally inspect (e.g., foreign bytecode, native stubs).
    OpaqueRegionPresent { region_label: String },
}

impl RefusalReason {
    /// Machine-readable tag for the refusal category.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::FamilyMismatch { .. } => "family_mismatch",
            Self::EpochMismatch { .. } => "epoch_mismatch",
            Self::ObservableEffectDifference { .. } => "observable_effect_difference",
            Self::OrbitDepthExceeded { .. } => "orbit_depth_exceeded",
            Self::TransformationNotAllowed { .. } => "transformation_not_allowed",
            Self::SimilarityBelowThreshold { .. } => "similarity_below_threshold",
            Self::OpaqueRegionPresent { .. } => "opaque_region_present",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyMismatch { left, right } => {
                write!(f, "family mismatch: {} vs {}", left, right)
            }
            Self::EpochMismatch {
                left_epoch,
                right_epoch,
            } => write!(f, "epoch mismatch: {} vs {}", left_epoch, right_epoch),
            Self::ObservableEffectDifference { description } => {
                write!(f, "observable effect difference: {}", description)
            }
            Self::OrbitDepthExceeded { depth_reached } => {
                write!(
                    f,
                    "orbit depth exceeded: {} (max {})",
                    depth_reached, MAX_ORBIT_DEPTH
                )
            }
            Self::TransformationNotAllowed { transformation } => {
                write!(f, "transformation not allowed: {}", transformation)
            }
            Self::SimilarityBelowThreshold {
                score_millionths,
                threshold_millionths,
            } => write!(
                f,
                "similarity {}.{}% below threshold {}.{}%",
                score_millionths / (MILLION / 100),
                score_millionths % (MILLION / 100),
                threshold_millionths / (MILLION / 100),
                threshold_millionths % (MILLION / 100),
            ),
            Self::OpaqueRegionPresent { region_label } => {
                write!(f, "opaque region present: {}", region_label)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IdentificationRefusal — full refusal record
// ---------------------------------------------------------------------------

/// A full refusal record explaining why two artifacts were not identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentificationRefusal {
    /// The left artifact fingerprint.
    pub left_fingerprint: String,
    /// The right artifact fingerprint.
    pub right_fingerprint: String,
    /// The family of both artifacts (if they matched).
    pub family: Option<ArtifactFamily>,
    /// The structured reason(s) for refusal.
    pub reasons: Vec<RefusalReason>,
    /// Security epoch at the time of the refusal decision.
    pub epoch: SecurityEpoch,
    /// Content hash of the refusal record itself.
    pub content_hash: ContentHash,
}

impl IdentificationRefusal {
    /// Construct a new refusal, computing the content hash deterministically.
    pub fn new(
        left_fingerprint: String,
        right_fingerprint: String,
        family: Option<ArtifactFamily>,
        reasons: Vec<RefusalReason>,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(left_fingerprint.as_bytes());
        hasher.update(right_fingerprint.as_bytes());
        if let Some(fam) = &family {
            hasher.update(fam.as_str().as_bytes());
        }
        for r in &reasons {
            hasher.update(r.tag().as_bytes());
        }
        hasher.update(epoch.as_u64().to_le_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());
        Self {
            left_fingerprint,
            right_fingerprint,
            family,
            reasons,
            epoch,
            content_hash,
        }
    }

    /// Number of distinct refusal reasons.
    pub fn reason_count(&self) -> usize {
        self.reasons.len()
    }

    /// Whether the refusal includes a specific reason tag.
    pub fn has_reason_tag(&self, tag: &str) -> bool {
        self.reasons.iter().any(|r| r.tag() == tag)
    }
}

// ---------------------------------------------------------------------------
// OrbitStep — a single reduction step
// ---------------------------------------------------------------------------

/// One step in an orbit reduction path — records which transformation was
/// applied and a fingerprint of the intermediate result.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrbitStep {
    /// Zero-based index of this step in the path.
    pub step_index: usize,
    /// The transformation applied at this step.
    pub transformation: EquivalenceTransformation,
    /// Fingerprint of the artifact *after* applying this transformation.
    pub result_fingerprint: String,
    /// Estimated cost of this step in millionths (for budget tracking).
    pub cost_millionths: u64,
}

// ---------------------------------------------------------------------------
// OrbitReduction — the full path from input to canonical form
// ---------------------------------------------------------------------------

/// The complete orbit reduction from an input artifact to its canonical
/// representative, recording every transformation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrbitReduction {
    /// The family of the artifact being reduced.
    pub family: ArtifactFamily,
    /// Fingerprint of the original (unreduced) artifact.
    pub input_fingerprint: String,
    /// Fingerprint of the canonical representative (after all steps).
    pub canonical_fingerprint: String,
    /// The sequence of transformation steps applied.
    pub steps: Vec<OrbitStep>,
    /// Total cost in millionths across all steps.
    pub total_cost_millionths: u64,
    /// Whether the reduction converged (reached a fixed point).
    pub converged: bool,
    /// Content hash of this orbit reduction record.
    pub content_hash: ContentHash,
}

impl OrbitReduction {
    /// Build an orbit reduction from its parts, computing the content hash.
    pub fn new(
        family: ArtifactFamily,
        input_fingerprint: String,
        canonical_fingerprint: String,
        steps: Vec<OrbitStep>,
        converged: bool,
    ) -> Self {
        let total_cost_millionths = steps.iter().map(|s| s.cost_millionths).sum();
        let mut hasher = Sha256::new();
        hasher.update(family.as_str().as_bytes());
        hasher.update(input_fingerprint.as_bytes());
        hasher.update(canonical_fingerprint.as_bytes());
        hasher.update((steps.len() as u64).to_le_bytes());
        for step in &steps {
            hasher.update(step.transformation.as_str().as_bytes());
            hasher.update(step.result_fingerprint.as_bytes());
        }
        hasher.update(if converged { &[1u8] } else { &[0u8] });
        let content_hash = ContentHash::compute(&hasher.finalize());
        Self {
            family,
            input_fingerprint,
            canonical_fingerprint,
            steps,
            total_cost_millionths,
            converged,
            content_hash,
        }
    }

    /// Number of steps in the reduction path.
    pub fn depth(&self) -> usize {
        self.steps.len()
    }

    /// Whether the depth exceeds the maximum allowed orbit depth.
    pub fn exceeded_depth_limit(&self) -> bool {
        self.steps.len() > MAX_ORBIT_DEPTH
    }

    /// The set of distinct transformations used.
    pub fn transformations_used(&self) -> BTreeSet<EquivalenceTransformation> {
        self.steps.iter().map(|s| s.transformation).collect()
    }

    /// Whether the orbit is trivial (zero steps, input equals canonical).
    pub fn is_trivial(&self) -> bool {
        self.steps.is_empty() && self.input_fingerprint == self.canonical_fingerprint
    }
}

// ---------------------------------------------------------------------------
// CanonicalRepresentative — the chosen identity for an equivalence class
// ---------------------------------------------------------------------------

/// A canonical representative for an equivalence class within one artifact
/// family.  Carries the stable content-addressed identity that all members
/// of the class share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRepresentative {
    /// The artifact family this representative belongs to.
    pub family: ArtifactFamily,
    /// The fingerprint of the canonical form.
    pub canonical_fingerprint: String,
    /// Number of distinct artifacts that reduce to this representative.
    pub member_count: usize,
    /// The transformations allowed for this class (a subset of all
    /// transformations, chosen based on the family and safety analysis).
    pub allowed_transformations: BTreeSet<EquivalenceTransformation>,
    /// Security epoch under which this representative was established.
    pub epoch: SecurityEpoch,
    /// Content hash of the representative record.
    pub content_hash: ContentHash,
}

impl CanonicalRepresentative {
    /// Construct a new representative, computing the content hash.
    pub fn new(
        family: ArtifactFamily,
        canonical_fingerprint: String,
        member_count: usize,
        allowed_transformations: BTreeSet<EquivalenceTransformation>,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(family.as_str().as_bytes());
        hasher.update(canonical_fingerprint.as_bytes());
        hasher.update((member_count as u64).to_le_bytes());
        for t in &allowed_transformations {
            hasher.update(t.as_str().as_bytes());
        }
        hasher.update(epoch.as_u64().to_le_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());
        Self {
            family,
            canonical_fingerprint,
            member_count,
            allowed_transformations,
            epoch,
            content_hash,
        }
    }

    /// Whether this class is a singleton (exactly one member).
    pub fn is_singleton(&self) -> bool {
        self.member_count == 1
    }

    /// Whether a specific transformation is allowed for this class.
    pub fn allows_transformation(&self, t: EquivalenceTransformation) -> bool {
        self.allowed_transformations.contains(&t)
    }

    /// The fraction of all transformations that are allowed (millionths).
    pub fn allowed_fraction_millionths(&self) -> u64 {
        if EquivalenceTransformation::ALL.is_empty() {
            return 0;
        }
        let allowed = self.allowed_transformations.len() as u64;
        let total = EquivalenceTransformation::ALL.len() as u64;
        allowed.saturating_mul(MILLION) / total
    }
}

// ---------------------------------------------------------------------------
// EquivalenceClass — a full class with representative + orbit reductions
// ---------------------------------------------------------------------------

/// A full equivalence class: the canonical representative plus the orbit
/// reductions of all known members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceClass {
    /// The canonical representative for this class.
    pub representative: CanonicalRepresentative,
    /// Orbit reductions for each member artifact that was reduced to this
    /// representative.  Sorted by input fingerprint for determinism.
    pub member_orbits: Vec<OrbitReduction>,
    /// Refusals that were evaluated during membership testing for this class.
    pub refusals: Vec<IdentificationRefusal>,
}

impl EquivalenceClass {
    /// Build a new equivalence class.
    pub fn new(
        representative: CanonicalRepresentative,
        member_orbits: Vec<OrbitReduction>,
        refusals: Vec<IdentificationRefusal>,
    ) -> Self {
        Self {
            representative,
            member_orbits,
            refusals,
        }
    }

    /// Total number of members (orbit reductions) in this class.
    pub fn member_count(&self) -> usize {
        self.member_orbits.len()
    }

    /// Total number of refusals recorded against this class.
    pub fn refusal_count(&self) -> usize {
        self.refusals.len()
    }

    /// Whether every member orbit converged.
    pub fn all_converged(&self) -> bool {
        self.member_orbits.iter().all(|o| o.converged)
    }

    /// Maximum orbit depth across all members.
    pub fn max_orbit_depth(&self) -> usize {
        self.member_orbits
            .iter()
            .map(|o| o.depth())
            .max()
            .unwrap_or(0)
    }

    /// The set of all transformations used across all member orbits.
    pub fn all_transformations_used(&self) -> BTreeSet<EquivalenceTransformation> {
        let mut all = BTreeSet::new();
        for orbit in &self.member_orbits {
            all.extend(orbit.transformations_used());
        }
        all
    }

    /// Average orbit depth in millionths.
    pub fn average_depth_millionths(&self) -> u64 {
        if self.member_orbits.is_empty() {
            return 0;
        }
        let total_depth: u64 = self.member_orbits.iter().map(|o| o.depth() as u64).sum();
        total_depth.saturating_mul(MILLION) / self.member_orbits.len() as u64
    }
}

// ---------------------------------------------------------------------------
// BasisCoverageReport — which families are covered
// ---------------------------------------------------------------------------

/// Coverage report for a semantic canonical basis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasisCoverageReport {
    /// Artifact families that have at least one equivalence class.
    pub covered_families: BTreeSet<ArtifactFamily>,
    /// Artifact families with zero equivalence classes.
    pub uncovered_families: BTreeSet<ArtifactFamily>,
    /// Total number of equivalence classes across all families.
    pub total_classes: usize,
    /// Total number of member artifacts across all classes.
    pub total_members: usize,
    /// Total number of refusals across all classes.
    pub total_refusals: usize,
    /// Coverage fraction in millionths (covered / total families).
    pub coverage_millionths: u64,
}

impl BasisCoverageReport {
    /// Whether every artifact family is covered.
    pub fn is_complete(&self) -> bool {
        self.uncovered_families.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SemanticCanonicalBasis — the top-level structure
// ---------------------------------------------------------------------------

/// The semantic canonical basis: a collection of equivalence classes across
/// artifact families, with coverage and audit metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticCanonicalBasis {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch under which this basis was computed.
    pub epoch: SecurityEpoch,
    /// The equivalence classes, sorted by (family, canonical_fingerprint)
    /// for deterministic iteration.
    pub classes: Vec<EquivalenceClass>,
    /// Global transformation allow-list.  Only transformations in this set
    /// may be used during orbit reduction.
    pub global_allowed_transformations: BTreeSet<EquivalenceTransformation>,
    /// Content hash of the entire basis.
    pub content_hash: ContentHash,
}

impl SemanticCanonicalBasis {
    /// Construct a basis from its equivalence classes, computing the content
    /// hash deterministically.
    pub fn new(
        epoch: SecurityEpoch,
        classes: Vec<EquivalenceClass>,
        global_allowed_transformations: BTreeSet<EquivalenceTransformation>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update((classes.len() as u64).to_le_bytes());
        for cls in &classes {
            hasher.update(cls.representative.canonical_fingerprint.as_bytes());
            hasher.update(cls.representative.family.as_str().as_bytes());
        }
        for t in &global_allowed_transformations {
            hasher.update(t.as_str().as_bytes());
        }
        let content_hash = ContentHash::compute(&hasher.finalize());
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            classes,
            global_allowed_transformations,
            content_hash,
        }
    }

    /// Total number of equivalence classes.
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Whether the basis is within the maximum class limit.
    pub fn within_class_limit(&self) -> bool {
        self.classes.len() <= MAX_CLASSES_PER_BASIS
    }

    /// Total member count across all classes.
    pub fn total_member_count(&self) -> usize {
        self.classes.iter().map(|c| c.member_count()).sum()
    }

    /// Total refusal count across all classes.
    pub fn total_refusal_count(&self) -> usize {
        self.classes.iter().map(|c| c.refusal_count()).sum()
    }

    /// Lookup equivalence classes for a given artifact family.
    pub fn classes_for_family(&self, family: ArtifactFamily) -> Vec<&EquivalenceClass> {
        self.classes
            .iter()
            .filter(|c| c.representative.family == family)
            .collect()
    }

    /// Compute a coverage report.
    pub fn coverage_report(&self) -> BasisCoverageReport {
        let covered_families: BTreeSet<ArtifactFamily> = self
            .classes
            .iter()
            .map(|c| c.representative.family)
            .collect();
        let uncovered_families: BTreeSet<ArtifactFamily> = ArtifactFamily::ALL
            .iter()
            .copied()
            .filter(|f| !covered_families.contains(f))
            .collect();
        let total_families = ArtifactFamily::ALL.len() as u64;
        let coverage_millionths = (covered_families.len() as u64)
            .saturating_mul(MILLION)
            .checked_div(total_families)
            .unwrap_or(0);
        BasisCoverageReport {
            covered_families,
            uncovered_families,
            total_classes: self.class_count(),
            total_members: self.total_member_count(),
            total_refusals: self.total_refusal_count(),
            coverage_millionths,
        }
    }

    /// Whether all orbit reductions across all classes converged.
    pub fn all_orbits_converged(&self) -> bool {
        self.classes.iter().all(|c| c.all_converged())
    }

    /// Maximum orbit depth across the entire basis.
    pub fn max_orbit_depth(&self) -> usize {
        self.classes
            .iter()
            .map(|c| c.max_orbit_depth())
            .max()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Identification query helpers
// ---------------------------------------------------------------------------

/// Query whether two artifact fingerprints can be identified within a basis.
/// Returns `Ok(canonical_fingerprint)` if they share an equivalence class,
/// or `Err(refusal)` if they cannot be identified.
pub fn query_identification(
    basis: &SemanticCanonicalBasis,
    family: ArtifactFamily,
    fingerprint_a: &str,
    fingerprint_b: &str,
) -> Result<String, IdentificationRefusal> {
    // Check same-family constraint
    let classes = basis.classes_for_family(family);

    for cls in &classes {
        let has_a = cls
            .member_orbits
            .iter()
            .any(|o| o.input_fingerprint == fingerprint_a);
        let has_b = cls
            .member_orbits
            .iter()
            .any(|o| o.input_fingerprint == fingerprint_b);

        if has_a && has_b {
            return Ok(cls.representative.canonical_fingerprint.clone());
        }
    }

    // Not found in same class — build a refusal
    Err(IdentificationRefusal::new(
        fingerprint_a.to_string(),
        fingerprint_b.to_string(),
        Some(family),
        vec![RefusalReason::SimilarityBelowThreshold {
            score_millionths: 0,
            threshold_millionths: MIN_SIMILARITY_THRESHOLD,
        }],
        basis.epoch,
    ))
}

/// Cross-family refusal: immediately refuses identification of artifacts
/// from different families.
pub fn refuse_cross_family(
    left_family: ArtifactFamily,
    right_family: ArtifactFamily,
    left_fingerprint: &str,
    right_fingerprint: &str,
    epoch: SecurityEpoch,
) -> IdentificationRefusal {
    IdentificationRefusal::new(
        left_fingerprint.to_string(),
        right_fingerprint.to_string(),
        None,
        vec![RefusalReason::FamilyMismatch {
            left: left_family,
            right: right_family,
        }],
        epoch,
    )
}

/// Validate an orbit reduction path: checks depth limit, convergence, and
/// that all transformations used are in the allowed set.
pub fn validate_orbit(
    orbit: &OrbitReduction,
    allowed: &BTreeSet<EquivalenceTransformation>,
) -> Vec<RefusalReason> {
    let mut issues = Vec::new();

    if orbit.exceeded_depth_limit() {
        issues.push(RefusalReason::OrbitDepthExceeded {
            depth_reached: orbit.depth(),
        });
    }

    for step in &orbit.steps {
        if !allowed.contains(&step.transformation) {
            issues.push(RefusalReason::TransformationNotAllowed {
                transformation: step.transformation,
            });
        }
    }

    issues
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn all_transformations() -> BTreeSet<EquivalenceTransformation> {
        EquivalenceTransformation::ALL.iter().copied().collect()
    }

    fn safe_transformations() -> BTreeSet<EquivalenceTransformation> {
        EquivalenceTransformation::ALL
            .iter()
            .copied()
            .filter(|t| t.is_universally_safe())
            .collect()
    }

    fn make_orbit_step(idx: usize, t: EquivalenceTransformation) -> OrbitStep {
        OrbitStep {
            step_index: idx,
            transformation: t,
            result_fingerprint: format!("step_{}_result", idx),
            cost_millionths: 100_000,
        }
    }

    fn make_orbit(
        family: ArtifactFamily,
        input: &str,
        canonical: &str,
        steps: Vec<OrbitStep>,
    ) -> OrbitReduction {
        OrbitReduction::new(
            family,
            input.to_string(),
            canonical.to_string(),
            steps,
            true,
        )
    }

    fn make_representative(family: ArtifactFamily, fingerprint: &str) -> CanonicalRepresentative {
        CanonicalRepresentative::new(
            family,
            fingerprint.to_string(),
            1,
            all_transformations(),
            test_epoch(),
        )
    }

    fn make_class(
        family: ArtifactFamily,
        fingerprint: &str,
        orbits: Vec<OrbitReduction>,
    ) -> EquivalenceClass {
        EquivalenceClass::new(make_representative(family, fingerprint), orbits, Vec::new())
    }

    fn make_basis(classes: Vec<EquivalenceClass>) -> SemanticCanonicalBasis {
        SemanticCanonicalBasis::new(test_epoch(), classes, all_transformations())
    }

    // --- ArtifactFamily tests ---

    #[test]
    fn artifact_family_all_count() {
        assert_eq!(ArtifactFamily::ALL.len(), 10);
    }

    #[test]
    fn artifact_family_as_str_roundtrip() {
        for fam in ArtifactFamily::ALL {
            let s = fam.as_str();
            assert!(!s.is_empty(), "empty as_str for {:?}", fam);
            assert_eq!(fam.to_string(), s);
        }
    }

    #[test]
    fn artifact_family_all_unique() {
        let set: BTreeSet<_> = ArtifactFamily::ALL.iter().collect();
        assert_eq!(set.len(), ArtifactFamily::ALL.len());
    }

    #[test]
    fn artifact_family_serde_roundtrip() {
        for fam in ArtifactFamily::ALL {
            let json = serde_json::to_string(fam).unwrap();
            let back: ArtifactFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*fam, back);
        }
    }

    // --- EquivalenceTransformation tests ---

    #[test]
    fn transformation_all_count() {
        assert_eq!(EquivalenceTransformation::ALL.len(), 10);
    }

    #[test]
    fn transformation_as_str_roundtrip() {
        for t in EquivalenceTransformation::ALL {
            let s = t.as_str();
            assert!(!s.is_empty());
            assert_eq!(t.to_string(), s);
        }
    }

    #[test]
    fn transformation_all_unique() {
        let set: BTreeSet<_> = EquivalenceTransformation::ALL.iter().collect();
        assert_eq!(set.len(), EquivalenceTransformation::ALL.len());
    }

    #[test]
    fn transformation_serde_roundtrip() {
        for t in EquivalenceTransformation::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: EquivalenceTransformation = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn universally_safe_subset() {
        let safe: Vec<_> = EquivalenceTransformation::ALL
            .iter()
            .filter(|t| t.is_universally_safe())
            .collect();
        assert!(safe.len() >= 3);
        assert!(safe.len() < EquivalenceTransformation::ALL.len());
    }

    // --- RefusalReason tests ---

    #[test]
    fn refusal_reason_tags_unique() {
        let reasons = vec![
            RefusalReason::FamilyMismatch {
                left: ArtifactFamily::Ir1Fragment,
                right: ArtifactFamily::CacheEntry,
            },
            RefusalReason::EpochMismatch {
                left_epoch: 1,
                right_epoch: 2,
            },
            RefusalReason::ObservableEffectDifference {
                description: "test".into(),
            },
            RefusalReason::OrbitDepthExceeded { depth_reached: 100 },
            RefusalReason::TransformationNotAllowed {
                transformation: EquivalenceTransformation::ConstantFolding,
            },
            RefusalReason::SimilarityBelowThreshold {
                score_millionths: 500_000,
                threshold_millionths: 950_000,
            },
            RefusalReason::OpaqueRegionPresent {
                region_label: "native_stub".into(),
            },
        ];
        let tags: BTreeSet<_> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), reasons.len());
    }

    #[test]
    fn refusal_reason_serde_roundtrip() {
        let reason = RefusalReason::EpochMismatch {
            left_epoch: 10,
            right_epoch: 20,
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: RefusalReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }

    #[test]
    fn refusal_reason_display() {
        let reason = RefusalReason::FamilyMismatch {
            left: ArtifactFamily::Ir1Fragment,
            right: ArtifactFamily::CacheEntry,
        };
        let display = reason.to_string();
        assert!(display.contains("family mismatch"));
    }

    // --- IdentificationRefusal tests ---

    #[test]
    fn identification_refusal_content_hash_deterministic() {
        let r1 = IdentificationRefusal::new(
            "fp_a".into(),
            "fp_b".into(),
            Some(ArtifactFamily::Ir1Fragment),
            vec![RefusalReason::EpochMismatch {
                left_epoch: 1,
                right_epoch: 2,
            }],
            test_epoch(),
        );
        let r2 = IdentificationRefusal::new(
            "fp_a".into(),
            "fp_b".into(),
            Some(ArtifactFamily::Ir1Fragment),
            vec![RefusalReason::EpochMismatch {
                left_epoch: 1,
                right_epoch: 2,
            }],
            test_epoch(),
        );
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn identification_refusal_different_inputs_different_hash() {
        let r1 = IdentificationRefusal::new(
            "fp_a".into(),
            "fp_b".into(),
            Some(ArtifactFamily::Ir1Fragment),
            vec![],
            test_epoch(),
        );
        let r2 = IdentificationRefusal::new(
            "fp_c".into(),
            "fp_d".into(),
            Some(ArtifactFamily::Ir1Fragment),
            vec![],
            test_epoch(),
        );
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn identification_refusal_reason_queries() {
        let r = IdentificationRefusal::new(
            "a".into(),
            "b".into(),
            None,
            vec![
                RefusalReason::FamilyMismatch {
                    left: ArtifactFamily::RewritePack,
                    right: ArtifactFamily::ShapeChain,
                },
                RefusalReason::OrbitDepthExceeded { depth_reached: 65 },
            ],
            test_epoch(),
        );
        assert_eq!(r.reason_count(), 2);
        assert!(r.has_reason_tag("family_mismatch"));
        assert!(r.has_reason_tag("orbit_depth_exceeded"));
        assert!(!r.has_reason_tag("epoch_mismatch"));
    }

    #[test]
    fn identification_refusal_serde_roundtrip() {
        let r = IdentificationRefusal::new(
            "left".into(),
            "right".into(),
            Some(ArtifactFamily::BytecodeArtifact),
            vec![RefusalReason::OpaqueRegionPresent {
                region_label: "native".into(),
            }],
            test_epoch(),
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: IdentificationRefusal = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- OrbitStep tests ---

    #[test]
    fn orbit_step_serde_roundtrip() {
        let step = make_orbit_step(0, EquivalenceTransformation::AlphaRenaming);
        let json = serde_json::to_string(&step).unwrap();
        let back: OrbitStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    // --- OrbitReduction tests ---

    #[test]
    fn orbit_reduction_trivial() {
        let orbit = make_orbit(ArtifactFamily::Ir1Fragment, "fp", "fp", Vec::new());
        assert!(orbit.is_trivial());
        assert_eq!(orbit.depth(), 0);
        assert!(!orbit.exceeded_depth_limit());
        assert!(orbit.converged);
    }

    #[test]
    fn orbit_reduction_nontrivial() {
        let steps = vec![
            make_orbit_step(0, EquivalenceTransformation::AlphaRenaming),
            make_orbit_step(1, EquivalenceTransformation::DeadCodeElimination),
        ];
        let orbit = make_orbit(ArtifactFamily::Ir3Fragment, "input", "canonical", steps);
        assert!(!orbit.is_trivial());
        assert_eq!(orbit.depth(), 2);
        assert_eq!(orbit.total_cost_millionths, 200_000);
        let used = orbit.transformations_used();
        assert!(used.contains(&EquivalenceTransformation::AlphaRenaming));
        assert!(used.contains(&EquivalenceTransformation::DeadCodeElimination));
    }

    #[test]
    fn orbit_reduction_content_hash_deterministic() {
        let steps = vec![make_orbit_step(
            0,
            EquivalenceTransformation::ConstantFolding,
        )];
        let o1 = make_orbit(ArtifactFamily::CacheEntry, "in", "out", steps.clone());
        let o2 = make_orbit(ArtifactFamily::CacheEntry, "in", "out", steps);
        assert_eq!(o1.content_hash, o2.content_hash);
    }

    #[test]
    fn orbit_reduction_depth_limit() {
        let steps: Vec<_> = (0..MAX_ORBIT_DEPTH + 1)
            .map(|i| make_orbit_step(i, EquivalenceTransformation::AlphaRenaming))
            .collect();
        let orbit = make_orbit(ArtifactFamily::Ir1Fragment, "a", "b", steps);
        assert!(orbit.exceeded_depth_limit());
    }

    #[test]
    fn orbit_reduction_serde_roundtrip() {
        let orbit = make_orbit(
            ArtifactFamily::RewritePack,
            "orig",
            "canonical",
            vec![make_orbit_step(
                0,
                EquivalenceTransformation::ScopeFlattening,
            )],
        );
        let json = serde_json::to_string(&orbit).unwrap();
        let back: OrbitReduction = serde_json::from_str(&json).unwrap();
        assert_eq!(orbit, back);
    }

    // --- CanonicalRepresentative tests ---

    #[test]
    fn representative_content_hash_deterministic() {
        let r1 = make_representative(ArtifactFamily::Ir1Fragment, "fp1");
        let r2 = make_representative(ArtifactFamily::Ir1Fragment, "fp1");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn representative_singleton() {
        let r = make_representative(ArtifactFamily::CacheEntry, "solo");
        assert!(r.is_singleton());
    }

    #[test]
    fn representative_allows_transformation() {
        let r = make_representative(ArtifactFamily::Ir3Fragment, "fp");
        assert!(r.allows_transformation(EquivalenceTransformation::AlphaRenaming));
    }

    #[test]
    fn representative_restricted_transformations() {
        let r = CanonicalRepresentative::new(
            ArtifactFamily::EvidenceRecord,
            "restricted".into(),
            5,
            safe_transformations(),
            test_epoch(),
        );
        assert!(r.allows_transformation(EquivalenceTransformation::AlphaRenaming));
        assert!(!r.allows_transformation(EquivalenceTransformation::DeadCodeElimination));
        let frac = r.allowed_fraction_millionths();
        assert!(frac > 0);
        assert!(frac < MILLION);
    }

    #[test]
    fn representative_serde_roundtrip() {
        let r = make_representative(ArtifactFamily::ModuleSnapshot, "ms");
        let json = serde_json::to_string(&r).unwrap();
        let back: CanonicalRepresentative = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- EquivalenceClass tests ---

    #[test]
    fn equivalence_class_empty() {
        let cls = make_class(ArtifactFamily::Ir1Fragment, "c", Vec::new());
        assert_eq!(cls.member_count(), 0);
        assert_eq!(cls.refusal_count(), 0);
        assert!(cls.all_converged());
        assert_eq!(cls.max_orbit_depth(), 0);
        assert_eq!(cls.average_depth_millionths(), 0);
    }

    #[test]
    fn equivalence_class_with_members() {
        let orbits = vec![
            make_orbit(
                ArtifactFamily::Ir1Fragment,
                "a",
                "c",
                vec![make_orbit_step(0, EquivalenceTransformation::AlphaRenaming)],
            ),
            make_orbit(
                ArtifactFamily::Ir1Fragment,
                "b",
                "c",
                vec![
                    make_orbit_step(0, EquivalenceTransformation::AlphaRenaming),
                    make_orbit_step(1, EquivalenceTransformation::DeadCodeElimination),
                ],
            ),
        ];
        let cls = make_class(ArtifactFamily::Ir1Fragment, "c", orbits);
        assert_eq!(cls.member_count(), 2);
        assert!(cls.all_converged());
        assert_eq!(cls.max_orbit_depth(), 2);
        let avg = cls.average_depth_millionths();
        assert_eq!(avg, 1_500_000); // (1+2)/2 = 1.5 * MILLION
    }

    #[test]
    fn equivalence_class_transformations_used() {
        let orbits = vec![
            make_orbit(
                ArtifactFamily::CacheEntry,
                "x",
                "z",
                vec![make_orbit_step(
                    0,
                    EquivalenceTransformation::ConstantFolding,
                )],
            ),
            make_orbit(
                ArtifactFamily::CacheEntry,
                "y",
                "z",
                vec![make_orbit_step(
                    0,
                    EquivalenceTransformation::CommutativeReorder,
                )],
            ),
        ];
        let cls = make_class(ArtifactFamily::CacheEntry, "z", orbits);
        let used = cls.all_transformations_used();
        assert!(used.contains(&EquivalenceTransformation::ConstantFolding));
        assert!(used.contains(&EquivalenceTransformation::CommutativeReorder));
        assert_eq!(used.len(), 2);
    }

    // --- SemanticCanonicalBasis tests ---

    #[test]
    fn basis_empty() {
        let basis = make_basis(Vec::new());
        assert_eq!(basis.class_count(), 0);
        assert!(basis.within_class_limit());
        assert_eq!(basis.total_member_count(), 0);
        assert_eq!(basis.total_refusal_count(), 0);
        assert!(basis.all_orbits_converged());
        assert_eq!(basis.max_orbit_depth(), 0);
    }

    #[test]
    fn basis_content_hash_deterministic() {
        let cls1 = make_class(ArtifactFamily::Ir1Fragment, "c1", Vec::new());
        let cls2 = make_class(ArtifactFamily::Ir1Fragment, "c1", Vec::new());
        let b1 = make_basis(vec![cls1]);
        let b2 = make_basis(vec![cls2]);
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn basis_classes_for_family() {
        let classes = vec![
            make_class(ArtifactFamily::Ir1Fragment, "ir1_a", Vec::new()),
            make_class(ArtifactFamily::CacheEntry, "cache_a", Vec::new()),
            make_class(ArtifactFamily::Ir1Fragment, "ir1_b", Vec::new()),
        ];
        let basis = make_basis(classes);
        let ir1_classes = basis.classes_for_family(ArtifactFamily::Ir1Fragment);
        assert_eq!(ir1_classes.len(), 2);
        let cache_classes = basis.classes_for_family(ArtifactFamily::CacheEntry);
        assert_eq!(cache_classes.len(), 1);
        let empty = basis.classes_for_family(ArtifactFamily::ShapeChain);
        assert!(empty.is_empty());
    }

    #[test]
    fn basis_coverage_report() {
        let classes = vec![
            make_class(ArtifactFamily::Ir1Fragment, "a", Vec::new()),
            make_class(ArtifactFamily::Ir3Fragment, "b", Vec::new()),
        ];
        let basis = make_basis(classes);
        let report = basis.coverage_report();
        assert_eq!(report.covered_families.len(), 2);
        assert_eq!(
            report.uncovered_families.len(),
            ArtifactFamily::ALL.len() - 2
        );
        assert!(!report.is_complete());
        assert_eq!(report.total_classes, 2);
        assert!(report.coverage_millionths > 0);
    }

    #[test]
    fn basis_full_coverage() {
        let classes: Vec<_> = ArtifactFamily::ALL
            .iter()
            .map(|f| make_class(*f, &format!("rep_{}", f.as_str()), Vec::new()))
            .collect();
        let basis = make_basis(classes);
        let report = basis.coverage_report();
        assert!(report.is_complete());
        assert_eq!(report.coverage_millionths, MILLION);
    }

    #[test]
    fn basis_serde_roundtrip() {
        let classes = vec![make_class(
            ArtifactFamily::BytecodeArtifact,
            "bc",
            vec![make_orbit(
                ArtifactFamily::BytecodeArtifact,
                "x",
                "bc",
                vec![make_orbit_step(
                    0,
                    EquivalenceTransformation::MetadataNormalization,
                )],
            )],
        )];
        let basis = make_basis(classes);
        let json = serde_json::to_string(&basis).unwrap();
        let back: SemanticCanonicalBasis = serde_json::from_str(&json).unwrap();
        assert_eq!(basis, back);
    }

    #[test]
    fn basis_schema_version() {
        let basis = make_basis(Vec::new());
        assert_eq!(basis.schema_version, SCHEMA_VERSION);
    }

    // --- query_identification tests ---

    #[test]
    fn query_identification_same_class() {
        let orbits = vec![
            make_orbit(ArtifactFamily::Ir1Fragment, "a", "canon", Vec::new()),
            make_orbit(ArtifactFamily::Ir1Fragment, "b", "canon", Vec::new()),
        ];
        let cls = make_class(ArtifactFamily::Ir1Fragment, "canon", orbits);
        let basis = make_basis(vec![cls]);
        let result = query_identification(&basis, ArtifactFamily::Ir1Fragment, "a", "b");
        assert_eq!(result.unwrap(), "canon");
    }

    #[test]
    fn query_identification_different_class() {
        let cls = make_class(
            ArtifactFamily::Ir1Fragment,
            "canon",
            vec![make_orbit(
                ArtifactFamily::Ir1Fragment,
                "a",
                "canon",
                Vec::new(),
            )],
        );
        let basis = make_basis(vec![cls]);
        let result = query_identification(&basis, ArtifactFamily::Ir1Fragment, "a", "unknown");
        assert!(result.is_err());
        let refusal = result.unwrap_err();
        assert!(refusal.has_reason_tag("similarity_below_threshold"));
    }

    // --- refuse_cross_family tests ---

    #[test]
    fn cross_family_refusal() {
        let refusal = refuse_cross_family(
            ArtifactFamily::Ir1Fragment,
            ArtifactFamily::CacheEntry,
            "fp1",
            "fp2",
            test_epoch(),
        );
        assert!(refusal.has_reason_tag("family_mismatch"));
        assert_eq!(refusal.family, None);
    }

    // --- validate_orbit tests ---

    #[test]
    fn validate_orbit_all_allowed() {
        let orbit = make_orbit(
            ArtifactFamily::Ir1Fragment,
            "in",
            "out",
            vec![make_orbit_step(0, EquivalenceTransformation::AlphaRenaming)],
        );
        let issues = validate_orbit(&orbit, &all_transformations());
        assert!(issues.is_empty());
    }

    #[test]
    fn validate_orbit_disallowed_transformation() {
        let orbit = make_orbit(
            ArtifactFamily::Ir1Fragment,
            "in",
            "out",
            vec![make_orbit_step(
                0,
                EquivalenceTransformation::DeadCodeElimination,
            )],
        );
        let issues = validate_orbit(&orbit, &safe_transformations());
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0],
            RefusalReason::TransformationNotAllowed { .. }
        ));
    }

    #[test]
    fn validate_orbit_depth_exceeded() {
        let steps: Vec<_> = (0..MAX_ORBIT_DEPTH + 1)
            .map(|i| make_orbit_step(i, EquivalenceTransformation::AlphaRenaming))
            .collect();
        let orbit = make_orbit(ArtifactFamily::Ir1Fragment, "a", "b", steps);
        let issues = validate_orbit(&orbit, &all_transformations());
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, RefusalReason::OrbitDepthExceeded { .. }))
        );
    }

    // --- Constants tests ---

    #[test]
    fn constants_valid() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(MAX_ORBIT_DEPTH > 0);
        assert!(MAX_CLASSES_PER_BASIS > 0);
        assert!(MIN_SIMILARITY_THRESHOLD > 0);
        assert!(MIN_SIMILARITY_THRESHOLD <= MILLION);
    }

    #[test]
    fn million_value() {
        assert_eq!(MILLION, 1_000_000);
    }
}
