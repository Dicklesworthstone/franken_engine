//! Obstruction Witness Emitter — RGC-808B
//!
//! Turns support fractures into explicit geometric objects: obstruction
//! witnesses, nongluable programs, and localized seam diagnoses that can be
//! replayed and owned.
//!
//! An **obstruction witness** proves that a particular program or workload
//! cannot be correctly handled across a specific support surface boundary.
//! A **nongluable program** demonstrates a concrete source text whose
//! interpretation diverges between two surfaces.  A **seam diagnosis**
//! aggregates obstruction data for a specific surface boundary and computes
//! severity scores.
//!
//! All types are deterministic and serializable.  Hashes use
//! `ContentHash::compute` from the three-tier hash strategy.  Numeric
//! severity scores use fixed-point millionths (1_000_000 = 1.0).
//!
//! Bead: bd-1lsy.9.8.2 / Policy: RGC-808B

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for obstruction witness artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.obstruction_witness_emitter.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.9.8.2";

/// Component name used in tracing / logging.
pub const COMPONENT: &str = "obstruction_witness_emitter";

/// Policy identifier for this module.
pub const POLICY_ID: &str = "RGC-808B";

/// Fixed-point scale factor: 1_000_000 millionths = 1.0.
pub const MILLIONTHS: u64 = 1_000_000;

/// Maximum witnesses allowed in a single report.
const MAX_WITNESSES: usize = 50_000;

/// Maximum nongluable programs per report.
const MAX_NONGLUABLE: usize = 10_000;

/// Maximum seam diagnoses per report.
const MAX_DIAGNOSES: usize = 5_000;

/// Minimization reduction ceiling (steps).
const MAX_REDUCTION_STEPS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// SupportSurface
// ---------------------------------------------------------------------------

/// A support surface is the abstraction layer at which a program is
/// interpreted.  Obstructions occur at the boundary between two surfaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SupportSurface {
    /// The parser surface — syntax to AST.
    Parser,
    /// The lowering surface — AST to IR.
    Lowering,
    /// The runtime surface — IR execution.
    Runtime,
    /// The module resolution surface.
    Module,
    /// The TypeScript type-checking surface.
    TypeScript,
    /// The React component model surface.
    React,
    /// The CLI integration surface.
    Cli,
    /// A cross-cutting surface that spans multiple layers.
    CrossSurface,
}

impl fmt::Display for SupportSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parser => write!(f, "parser"),
            Self::Lowering => write!(f, "lowering"),
            Self::Runtime => write!(f, "runtime"),
            Self::Module => write!(f, "module"),
            Self::TypeScript => write!(f, "typescript"),
            Self::React => write!(f, "react"),
            Self::Cli => write!(f, "cli"),
            Self::CrossSurface => write!(f, "cross-surface"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObstructionKind
// ---------------------------------------------------------------------------

/// The category of obstruction that prevents correct cross-surface handling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObstructionKind {
    /// A type mismatch between surfaces.
    TypeMismatch,
    /// A semantic gap — one surface understands a concept that the other lacks.
    SemanticGap,
    /// Incompatible boundary assumptions between surfaces.
    BoundaryIncompatibility,
    /// Resource usage violations (memory, handles, descriptors).
    ResourceViolation,
    /// Timing dependencies that break across surface boundaries.
    TimingDependence,
    /// Nondeterministic behavior divergence between surfaces.
    NondeterministicBehavior,
    /// A feature supported on one surface but not the other.
    UnsupportedFeature,
}

impl fmt::Display for ObstructionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch => write!(f, "type-mismatch"),
            Self::SemanticGap => write!(f, "semantic-gap"),
            Self::BoundaryIncompatibility => write!(f, "boundary-incompatibility"),
            Self::ResourceViolation => write!(f, "resource-violation"),
            Self::TimingDependence => write!(f, "timing-dependence"),
            Self::NondeterministicBehavior => write!(f, "nondeterministic-behavior"),
            Self::UnsupportedFeature => write!(f, "unsupported-feature"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObstructionWitness
// ---------------------------------------------------------------------------

/// A concrete proof that a program cannot be correctly handled across a
/// support surface boundary.
///
/// Each witness carries the source text that triggers the failure, the
/// surface on which it fails, and an optional minimality flag indicating
/// whether the witness has been reduced to a minimal reproducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObstructionWitness {
    /// Unique identifier for this witness.
    pub witness_id: String,
    /// The surface at which the obstruction was observed.
    pub surface: SupportSurface,
    /// The category of obstruction.
    pub kind: ObstructionKind,
    /// The program source text that triggers the obstruction.
    pub program_source: String,
    /// Human-readable description of the failure.
    pub failure_description: String,
    /// Whether this witness has been minimized to a shortest reproducer.
    pub minimal: bool,
    /// Number of reduction steps applied during minimization.
    pub reduction_steps: u64,
    /// Location of the seam (boundary identifier) where the failure occurs.
    pub seam_location: String,
    /// Content hash of the witness data for integrity verification.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// NongluableProgram
// ---------------------------------------------------------------------------

/// A program whose interpretation diverges between two support surfaces,
/// proving that the surfaces cannot be composed ("glued") transparently
/// for this workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NongluableProgram {
    /// Unique identifier for this nongluable program.
    pub program_id: String,
    /// The source text exhibiting divergent behavior.
    pub source_text: String,
    /// The left (input) surface.
    pub left_surface: SupportSurface,
    /// The right (output) surface.
    pub right_surface: SupportSurface,
    /// Interpretation on the left surface.
    pub left_interpretation: String,
    /// Interpretation on the right surface.
    pub right_interpretation: String,
    /// Description of how interpretations diverge.
    pub divergence_description: String,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// SeamDiagnosis
// ---------------------------------------------------------------------------

/// Aggregated diagnosis for a specific surface boundary (seam).
///
/// Collects obstruction witnesses and nongluable program counts,
/// computes a severity score, and provides a remediation hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamDiagnosis {
    /// Unique identifier for this seam diagnosis.
    pub seam_id: String,
    /// The left surface of the boundary.
    pub left_surface: SupportSurface,
    /// The right surface of the boundary.
    pub right_surface: SupportSurface,
    /// Number of obstruction witnesses affecting this seam.
    pub obstruction_count: u64,
    /// Number of nongluable programs found for this seam.
    pub nongluable_count: u64,
    /// Severity in fixed-point millionths (1_000_000 = 1.0).
    pub severity_millionths: u64,
    /// Human-readable remediation hint.
    pub remediation_hint: String,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ObstructionReport
// ---------------------------------------------------------------------------

/// Top-level report aggregating all obstruction evidence for a given epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObstructionReport {
    /// Unique identifier for this report.
    pub report_id: String,
    /// The security epoch under which this report was produced.
    pub epoch: SecurityEpoch,
    /// All obstruction witnesses.
    pub witnesses: Vec<ObstructionWitness>,
    /// All nongluable programs.
    pub nongluable_programs: Vec<NongluableProgram>,
    /// All seam diagnoses.
    pub seam_diagnoses: Vec<SeamDiagnosis>,
    /// Total number of obstructions (may differ from witnesses.len() if
    /// some witnesses were aggregated).
    pub total_obstructions: u64,
    /// Content hash for the entire report.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ObstructionEmitterError
// ---------------------------------------------------------------------------

/// Errors that can occur during obstruction witness emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObstructionError {
    /// The witness has no meaningful content (empty program or description).
    EmptyWitness,
    /// The surface pair is invalid (e.g. same surface on both sides).
    InvalidSurface,
    /// Minimization failed after exhausting reduction budget.
    MinimizationFailed,
    /// The referenced seam was not found.
    SeamNotFound,
    /// An internal error with a descriptive message.
    InternalError(String),
}

impl fmt::Display for ObstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWitness => write!(f, "empty witness: program source or description is empty"),
            Self::InvalidSurface => write!(f, "invalid surface configuration"),
            Self::MinimizationFailed => write!(f, "witness minimization failed: reduction budget exhausted"),
            Self::SeamNotFound => write!(f, "seam not found in current surface topology"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: content hash computation
// ---------------------------------------------------------------------------

/// Compute a content hash from a collection of byte slices.
fn compute_content_hash(parts: &[&[u8]]) -> ContentHash {
    let mut buf = Vec::new();
    for part in parts {
        buf.extend_from_slice(part);
    }
    ContentHash::compute(&buf)
}

/// Compute a witness content hash from its fields.
fn witness_content_hash(
    surface: &SupportSurface,
    kind: &ObstructionKind,
    program: &str,
    failure: &str,
    seam: &str,
) -> ContentHash {
    compute_content_hash(&[
        surface.to_string().as_bytes(),
        kind.to_string().as_bytes(),
        program.as_bytes(),
        failure.as_bytes(),
        seam.as_bytes(),
    ])
}

/// Compute a nongluable program content hash from its fields.
fn nongluable_content_hash(
    source: &str,
    left: &SupportSurface,
    right: &SupportSurface,
    left_interp: &str,
    right_interp: &str,
) -> ContentHash {
    compute_content_hash(&[
        source.as_bytes(),
        left.to_string().as_bytes(),
        right.to_string().as_bytes(),
        left_interp.as_bytes(),
        right_interp.as_bytes(),
    ])
}

/// Compute a seam diagnosis content hash.
fn seam_content_hash(
    left: &SupportSurface,
    right: &SupportSurface,
    obstruction_count: u64,
    nongluable_count: u64,
    severity: u64,
) -> ContentHash {
    compute_content_hash(&[
        left.to_string().as_bytes(),
        right.to_string().as_bytes(),
        &obstruction_count.to_le_bytes(),
        &nongluable_count.to_le_bytes(),
        &severity.to_le_bytes(),
    ])
}

/// Compute a report content hash from its constituent hashes.
fn report_content_hash(
    report_id: &str,
    epoch: SecurityEpoch,
    witness_hashes: &[ContentHash],
    program_hashes: &[ContentHash],
    diagnosis_hashes: &[ContentHash],
) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(report_id.as_bytes());
    buf.extend_from_slice(&epoch.as_u64().to_le_bytes());
    for h in witness_hashes {
        buf.extend_from_slice(h.as_bytes());
    }
    for h in program_hashes {
        buf.extend_from_slice(h.as_bytes());
    }
    for h in diagnosis_hashes {
        buf.extend_from_slice(h.as_bytes());
    }
    ContentHash::compute(&buf)
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Emit a new obstruction witness.
///
/// Validates that the program source and failure description are non-empty,
/// computes a content hash, and returns the witness.
pub fn emit_witness(
    surface: SupportSurface,
    kind: ObstructionKind,
    program: &str,
    failure: &str,
    seam: &str,
) -> Result<ObstructionWitness, ObstructionError> {
    if program.is_empty() || failure.is_empty() {
        return Err(ObstructionError::EmptyWitness);
    }
    if seam.is_empty() {
        return Err(ObstructionError::SeamNotFound);
    }

    let content_hash = witness_content_hash(&surface, &kind, program, failure, seam);
    let witness_id = format!(
        "ow-{}-{}-{}",
        surface,
        kind,
        &content_hash.to_hex()[..16]
    );

    Ok(ObstructionWitness {
        witness_id,
        surface,
        kind,
        program_source: program.to_string(),
        failure_description: failure.to_string(),
        minimal: false,
        reduction_steps: 0,
        seam_location: seam.to_string(),
        content_hash,
    })
}

/// Attempt to minimize a witness by reducing its program source to a
/// shorter reproducer.
///
/// This performs a deterministic delta-reduction: repeatedly halves the
/// source text, retaining the portion that still demonstrates the
/// obstruction (heuristically, the portion containing the seam keyword).
/// Returns a new witness marked as minimal.
pub fn minimize_witness(
    witness: &ObstructionWitness,
) -> Result<ObstructionWitness, ObstructionError> {
    if witness.program_source.is_empty() {
        return Err(ObstructionError::EmptyWitness);
    }

    let source = &witness.program_source;
    let mut reduced = source.clone();
    let mut steps: u64 = 0;

    // Deterministic reduction: repeatedly try to halve the source while
    // keeping the seam keyword present.
    loop {
        if reduced.len() <= 1 {
            break;
        }
        if steps >= MAX_REDUCTION_STEPS {
            return Err(ObstructionError::MinimizationFailed);
        }

        let mid = reduced.len() / 2;
        let left_half = &reduced[..mid];
        let right_half = &reduced[mid..];

        // Prefer the half that contains the seam location substring.
        let seam_key = &witness.seam_location;
        let candidate = if left_half.contains(seam_key.as_str()) {
            left_half.to_string()
        } else if right_half.contains(seam_key.as_str()) {
            right_half.to_string()
        } else {
            // Neither half contains the seam marker — stop reducing.
            break;
        };

        if candidate.is_empty() {
            break;
        }
        reduced = candidate;
        steps += 1;
    }

    let content_hash = witness_content_hash(
        &witness.surface,
        &witness.kind,
        &reduced,
        &witness.failure_description,
        &witness.seam_location,
    );

    let witness_id = format!(
        "ow-min-{}-{}-{}",
        witness.surface,
        witness.kind,
        &content_hash.to_hex()[..16]
    );

    Ok(ObstructionWitness {
        witness_id,
        surface: witness.surface.clone(),
        kind: witness.kind.clone(),
        program_source: reduced,
        failure_description: witness.failure_description.clone(),
        minimal: true,
        reduction_steps: steps,
        seam_location: witness.seam_location.clone(),
        content_hash,
    })
}

/// Detect a nongluable program — a source text whose interpretation
/// diverges between two surfaces.
///
/// Constructs the nongluable record with a deterministic content hash.
/// The caller supplies the interpretation strings from each surface.
pub fn detect_nongluable(
    source: &str,
    left: SupportSurface,
    right: SupportSurface,
    left_interp: &str,
    right_interp: &str,
) -> NongluableProgram {
    let content_hash = nongluable_content_hash(source, &left, &right, left_interp, right_interp);
    let program_id = format!(
        "ng-{}-{}-{}",
        left,
        right,
        &content_hash.to_hex()[..16]
    );

    let divergence_description = format!(
        "Left surface ({left}) interprets as: {left_interp}; \
         Right surface ({right}) interprets as: {right_interp}"
    );

    NongluableProgram {
        program_id,
        source_text: source.to_string(),
        left_surface: left,
        right_surface: right,
        left_interpretation: left_interp.to_string(),
        right_interpretation: right_interp.to_string(),
        divergence_description,
        content_hash,
    }
}

/// Diagnose a seam boundary given a set of obstruction witnesses.
///
/// Computes severity from the number and kinds of obstructions.
/// Severity is expressed in millionths: an obstruction count of 10 with
/// varied kinds yields a higher severity than 10 with a single kind.
pub fn diagnose_seam(
    witnesses: &[ObstructionWitness],
    left: SupportSurface,
    right: SupportSurface,
) -> SeamDiagnosis {
    let obstruction_count = witnesses.len() as u64;

    // Count distinct obstruction kinds for severity weighting.
    let mut kind_counts: BTreeMap<String, u64> = BTreeMap::new();
    for w in witnesses {
        *kind_counts.entry(w.kind.to_string()).or_insert(0) += 1;
    }
    let distinct_kinds = kind_counts.len() as u64;

    // Severity formula: base severity per obstruction + diversity bonus.
    // Each obstruction contributes 50_000 millionths (0.05).
    // Each distinct kind adds 100_000 millionths (0.1) bonus.
    // Capped at 1_000_000 (1.0).
    let base_severity = obstruction_count.saturating_mul(50_000);
    let diversity_bonus = distinct_kinds.saturating_mul(100_000);
    let severity_millionths = base_severity
        .saturating_add(diversity_bonus)
        .min(MILLIONTHS);

    // Count witnesses that appear to have nongluable characteristics
    // (different surface than the seam surfaces indicates cross-surface
    // leakage, contributing to nongluability).
    let nongluable_count = witnesses
        .iter()
        .filter(|w| w.surface != left && w.surface != right)
        .count() as u64;

    let remediation_hint = if severity_millionths >= 800_000 {
        format!(
            "Critical seam between {left} and {right}: consider splitting into isolated surfaces"
        )
    } else if severity_millionths >= 400_000 {
        format!(
            "Moderate seam between {left} and {right}: adapter injection recommended"
        )
    } else {
        format!(
            "Low-severity seam between {left} and {right}: monitor and document"
        )
    };

    let seam_id = format!("seam-{left}-{right}");
    let content_hash = seam_content_hash(
        &left,
        &right,
        obstruction_count,
        nongluable_count,
        severity_millionths,
    );

    SeamDiagnosis {
        seam_id,
        left_surface: left,
        right_surface: right,
        obstruction_count,
        nongluable_count,
        severity_millionths,
        remediation_hint,
        content_hash,
    }
}

/// Build a top-level obstruction report from constituent parts.
///
/// Validates budget limits and computes a top-level content hash that
/// covers all included witnesses, programs, and diagnoses.
pub fn build_report(
    epoch: SecurityEpoch,
    witnesses: Vec<ObstructionWitness>,
    programs: Vec<NongluableProgram>,
    diagnoses: Vec<SeamDiagnosis>,
) -> Result<ObstructionReport, ObstructionError> {
    if witnesses.len() > MAX_WITNESSES {
        return Err(ObstructionError::InternalError(format!(
            "witness count {} exceeds limit {MAX_WITNESSES}",
            witnesses.len()
        )));
    }
    if programs.len() > MAX_NONGLUABLE {
        return Err(ObstructionError::InternalError(format!(
            "nongluable program count {} exceeds limit {MAX_NONGLUABLE}",
            programs.len()
        )));
    }
    if diagnoses.len() > MAX_DIAGNOSES {
        return Err(ObstructionError::InternalError(format!(
            "diagnosis count {} exceeds limit {MAX_DIAGNOSES}",
            diagnoses.len()
        )));
    }

    let total_obstructions = witnesses.len() as u64;

    let report_id = format!(
        "report-{COMPONENT}-epoch-{}",
        epoch.as_u64()
    );

    let witness_hashes: Vec<ContentHash> = witnesses.iter().map(|w| w.content_hash.clone()).collect();
    let program_hashes: Vec<ContentHash> = programs.iter().map(|p| p.content_hash.clone()).collect();
    let diagnosis_hashes: Vec<ContentHash> = diagnoses.iter().map(|d| d.content_hash.clone()).collect();

    let content_hash = report_content_hash(
        &report_id,
        epoch,
        &witness_hashes,
        &program_hashes,
        &diagnosis_hashes,
    );

    Ok(ObstructionReport {
        report_id,
        epoch,
        witnesses,
        nongluable_programs: programs,
        seam_diagnoses: diagnoses,
        total_obstructions,
        content_hash,
    })
}

/// Build a canonical reference obstruction report that documents the
/// known obstruction landscape of the FrankenEngine.
///
/// This is the "manifest" function: it emits a fixed, deterministic
/// report covering canonical obstructions across all surface boundaries.
pub fn franken_engine_obstruction_manifest() -> ObstructionReport {
    let epoch = SecurityEpoch::from_raw(1);

    // Canonical witnesses covering each surface and kind combination.
    let w1 = emit_witness(
        SupportSurface::Parser,
        ObstructionKind::SemanticGap,
        "function* gen() { yield 1; }",
        "Generator function syntax accepted by parser but not supported by lowering",
        "parser-lowering-boundary",
    )
    .expect("canonical witness w1");

    let w2 = emit_witness(
        SupportSurface::Lowering,
        ObstructionKind::TypeMismatch,
        "let x: number = 'hello';",
        "Type annotation present in source but IR has no type narrowing",
        "lowering-runtime-boundary",
    )
    .expect("canonical witness w2");

    let w3 = emit_witness(
        SupportSurface::Runtime,
        ObstructionKind::TimingDependence,
        "setTimeout(() => {}, 0); Promise.resolve().then(() => {});",
        "Microtask vs macrotask ordering differs between runtime implementations",
        "runtime-event-loop-seam",
    )
    .expect("canonical witness w3");

    let w4 = emit_witness(
        SupportSurface::Module,
        ObstructionKind::BoundaryIncompatibility,
        "import { foo } from './bar.cjs';",
        "ESM importing CJS default export has divergent semantics",
        "module-interop-boundary",
    )
    .expect("canonical witness w4");

    let w5 = emit_witness(
        SupportSurface::TypeScript,
        ObstructionKind::UnsupportedFeature,
        "const enum Direction { Up, Down }",
        "const enum requires type erasure not available at runtime surface",
        "typescript-runtime-boundary",
    )
    .expect("canonical witness w5");

    let w6 = emit_witness(
        SupportSurface::React,
        ObstructionKind::NondeterministicBehavior,
        "useEffect(() => { /* side effect */ }, [dep]);",
        "Effect cleanup ordering is implementation-defined across React versions",
        "react-effect-boundary",
    )
    .expect("canonical witness w6");

    let w7 = emit_witness(
        SupportSurface::Cli,
        ObstructionKind::ResourceViolation,
        "frankenctl run --memory-limit 0",
        "Zero memory limit causes OOM before CLI argument validation completes",
        "cli-resource-boundary",
    )
    .expect("canonical witness w7");

    let witnesses = vec![
        w1.clone(),
        w2.clone(),
        w3.clone(),
        w4.clone(),
        w5.clone(),
        w6.clone(),
        w7.clone(),
    ];

    // Canonical nongluable programs.
    let ng1 = detect_nongluable(
        "export default class Foo {}",
        SupportSurface::Module,
        SupportSurface::Runtime,
        "default export is a class expression",
        "default export is an object with prototype chain",
    );

    let ng2 = detect_nongluable(
        "import type { Foo } from './bar';",
        SupportSurface::TypeScript,
        SupportSurface::Lowering,
        "type-only import, no runtime binding",
        "import statement generates runtime module request",
    );

    let programs = vec![ng1, ng2];

    // Canonical seam diagnoses.
    let d1 = diagnose_seam(
        &[w1, w2.clone()],
        SupportSurface::Parser,
        SupportSurface::Lowering,
    );
    let d2 = diagnose_seam(
        &[w2, w3],
        SupportSurface::Lowering,
        SupportSurface::Runtime,
    );
    let d3 = diagnose_seam(
        &[w5, w6],
        SupportSurface::TypeScript,
        SupportSurface::React,
    );

    let diagnoses = vec![d1, d2, d3];

    build_report(epoch, witnesses, programs, diagnoses)
        .expect("canonical manifest report should succeed")
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper ---------------------------------------------------------

    fn make_witness(
        surface: SupportSurface,
        kind: ObstructionKind,
    ) -> ObstructionWitness {
        emit_witness(
            surface,
            kind,
            "let x = 1;",
            "test failure",
            "test-seam",
        )
        .unwrap()
    }

    // -- Constants ------------------------------------------------------

    #[test]
    fn test_schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.ends_with(".v1"));
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.9.8.2");
    }

    #[test]
    fn test_component_name() {
        assert_eq!(COMPONENT, "obstruction_witness_emitter");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-808B");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -- SupportSurface Display -----------------------------------------

    #[test]
    fn test_support_surface_display_all_variants() {
        assert_eq!(SupportSurface::Parser.to_string(), "parser");
        assert_eq!(SupportSurface::Lowering.to_string(), "lowering");
        assert_eq!(SupportSurface::Runtime.to_string(), "runtime");
        assert_eq!(SupportSurface::Module.to_string(), "module");
        assert_eq!(SupportSurface::TypeScript.to_string(), "typescript");
        assert_eq!(SupportSurface::React.to_string(), "react");
        assert_eq!(SupportSurface::Cli.to_string(), "cli");
        assert_eq!(SupportSurface::CrossSurface.to_string(), "cross-surface");
    }

    // -- ObstructionKind Display ----------------------------------------

    #[test]
    fn test_obstruction_kind_display_all_variants() {
        assert_eq!(ObstructionKind::TypeMismatch.to_string(), "type-mismatch");
        assert_eq!(ObstructionKind::SemanticGap.to_string(), "semantic-gap");
        assert_eq!(
            ObstructionKind::BoundaryIncompatibility.to_string(),
            "boundary-incompatibility"
        );
        assert_eq!(ObstructionKind::ResourceViolation.to_string(), "resource-violation");
        assert_eq!(ObstructionKind::TimingDependence.to_string(), "timing-dependence");
        assert_eq!(
            ObstructionKind::NondeterministicBehavior.to_string(),
            "nondeterministic-behavior"
        );
        assert_eq!(ObstructionKind::UnsupportedFeature.to_string(), "unsupported-feature");
    }

    // -- ObstructionError Display ---------------------------------------

    #[test]
    fn test_error_empty_witness_display() {
        let e = ObstructionError::EmptyWitness;
        assert!(e.to_string().contains("empty witness"));
    }

    #[test]
    fn test_error_invalid_surface_display() {
        let e = ObstructionError::InvalidSurface;
        assert!(e.to_string().contains("invalid surface"));
    }

    #[test]
    fn test_error_minimization_failed_display() {
        let e = ObstructionError::MinimizationFailed;
        assert!(e.to_string().contains("minimization failed"));
    }

    #[test]
    fn test_error_seam_not_found_display() {
        let e = ObstructionError::SeamNotFound;
        assert!(e.to_string().contains("seam not found"));
    }

    #[test]
    fn test_error_internal_display() {
        let e = ObstructionError::InternalError("something broke".to_string());
        assert!(e.to_string().contains("something broke"));
    }

    // -- emit_witness ---------------------------------------------------

    #[test]
    fn test_emit_witness_basic() {
        let w = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::SemanticGap,
            "let x = 1;",
            "gap in parser",
            "parser-lowering",
        )
        .unwrap();

        assert!(w.witness_id.starts_with("ow-"));
        assert_eq!(w.surface, SupportSurface::Parser);
        assert_eq!(w.kind, ObstructionKind::SemanticGap);
        assert_eq!(w.program_source, "let x = 1;");
        assert!(!w.minimal);
        assert_eq!(w.reduction_steps, 0);
    }

    #[test]
    fn test_emit_witness_empty_program_rejected() {
        let result = emit_witness(
            SupportSurface::Runtime,
            ObstructionKind::TypeMismatch,
            "",
            "failure",
            "seam",
        );
        assert_eq!(result, Err(ObstructionError::EmptyWitness));
    }

    #[test]
    fn test_emit_witness_empty_failure_rejected() {
        let result = emit_witness(
            SupportSurface::Runtime,
            ObstructionKind::TypeMismatch,
            "code",
            "",
            "seam",
        );
        assert_eq!(result, Err(ObstructionError::EmptyWitness));
    }

    #[test]
    fn test_emit_witness_empty_seam_rejected() {
        let result = emit_witness(
            SupportSurface::Runtime,
            ObstructionKind::TypeMismatch,
            "code",
            "failure",
            "",
        );
        assert_eq!(result, Err(ObstructionError::SeamNotFound));
    }

    #[test]
    fn test_emit_witness_deterministic_hash() {
        let w1 = emit_witness(
            SupportSurface::Lowering,
            ObstructionKind::BoundaryIncompatibility,
            "import x from 'y';",
            "boundary issue",
            "lowering-runtime",
        )
        .unwrap();
        let w2 = emit_witness(
            SupportSurface::Lowering,
            ObstructionKind::BoundaryIncompatibility,
            "import x from 'y';",
            "boundary issue",
            "lowering-runtime",
        )
        .unwrap();

        assert_eq!(w1.content_hash, w2.content_hash);
        assert_eq!(w1.witness_id, w2.witness_id);
    }

    #[test]
    fn test_emit_witness_different_inputs_different_hash() {
        let w1 = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::TypeMismatch,
            "let a = 1;",
            "type error",
            "seam-a",
        )
        .unwrap();
        let w2 = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::TypeMismatch,
            "let b = 2;",
            "type error",
            "seam-a",
        )
        .unwrap();

        assert_ne!(w1.content_hash, w2.content_hash);
    }

    #[test]
    fn test_emit_witness_all_surfaces() {
        let surfaces = vec![
            SupportSurface::Parser,
            SupportSurface::Lowering,
            SupportSurface::Runtime,
            SupportSurface::Module,
            SupportSurface::TypeScript,
            SupportSurface::React,
            SupportSurface::Cli,
            SupportSurface::CrossSurface,
        ];
        for s in surfaces {
            let w = emit_witness(
                s.clone(),
                ObstructionKind::SemanticGap,
                "code",
                "fail",
                "seam",
            )
            .unwrap();
            assert_eq!(w.surface, s);
        }
    }

    #[test]
    fn test_emit_witness_all_kinds() {
        let kinds = vec![
            ObstructionKind::TypeMismatch,
            ObstructionKind::SemanticGap,
            ObstructionKind::BoundaryIncompatibility,
            ObstructionKind::ResourceViolation,
            ObstructionKind::TimingDependence,
            ObstructionKind::NondeterministicBehavior,
            ObstructionKind::UnsupportedFeature,
        ];
        for k in kinds {
            let w = emit_witness(
                SupportSurface::Runtime,
                k.clone(),
                "code",
                "fail",
                "seam",
            )
            .unwrap();
            assert_eq!(w.kind, k);
        }
    }

    // -- minimize_witness -----------------------------------------------

    #[test]
    fn test_minimize_witness_reduces_source() {
        let w = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::SemanticGap,
            "aaaa seam-location bbbb cccc dddd eeee",
            "test failure",
            "seam-location",
        )
        .unwrap();
        let minimized = minimize_witness(&w).unwrap();

        assert!(minimized.minimal);
        assert!(minimized.reduction_steps > 0);
        assert!(minimized.program_source.len() <= w.program_source.len());
    }

    #[test]
    fn test_minimize_witness_preserves_surface_and_kind() {
        let w = make_witness(SupportSurface::Lowering, ObstructionKind::TypeMismatch);
        let minimized = minimize_witness(&w).unwrap();

        assert_eq!(minimized.surface, SupportSurface::Lowering);
        assert_eq!(minimized.kind, ObstructionKind::TypeMismatch);
    }

    #[test]
    fn test_minimize_witness_empty_source_error() {
        let w = ObstructionWitness {
            witness_id: "test".to_string(),
            surface: SupportSurface::Parser,
            kind: ObstructionKind::SemanticGap,
            program_source: String::new(),
            failure_description: "fail".to_string(),
            minimal: false,
            reduction_steps: 0,
            seam_location: "seam".to_string(),
            content_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(minimize_witness(&w), Err(ObstructionError::EmptyWitness));
    }

    #[test]
    fn test_minimize_witness_single_char_stays() {
        let w = emit_witness(
            SupportSurface::Runtime,
            ObstructionKind::ResourceViolation,
            "x",
            "fail",
            "x",
        )
        .unwrap();
        let minimized = minimize_witness(&w).unwrap();
        assert!(minimized.minimal);
        assert_eq!(minimized.program_source, "x");
    }

    #[test]
    fn test_minimize_witness_id_has_min_prefix() {
        let w = make_witness(SupportSurface::Module, ObstructionKind::UnsupportedFeature);
        let minimized = minimize_witness(&w).unwrap();
        assert!(minimized.witness_id.starts_with("ow-min-"));
    }

    #[test]
    fn test_minimize_witness_deterministic() {
        let w = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::SemanticGap,
            "aaaa seam-x bbbb cccc dddd",
            "failure",
            "seam-x",
        )
        .unwrap();
        let m1 = minimize_witness(&w).unwrap();
        let m2 = minimize_witness(&w).unwrap();
        assert_eq!(m1.content_hash, m2.content_hash);
        assert_eq!(m1.program_source, m2.program_source);
    }

    // -- detect_nongluable ----------------------------------------------

    #[test]
    fn test_detect_nongluable_basic() {
        let ng = detect_nongluable(
            "export default 42;",
            SupportSurface::Module,
            SupportSurface::Runtime,
            "number literal export",
            "object wrapper around number",
        );

        assert!(ng.program_id.starts_with("ng-"));
        assert_eq!(ng.left_surface, SupportSurface::Module);
        assert_eq!(ng.right_surface, SupportSurface::Runtime);
        assert_eq!(ng.source_text, "export default 42;");
    }

    #[test]
    fn test_detect_nongluable_divergence_description() {
        let ng = detect_nongluable(
            "code",
            SupportSurface::Parser,
            SupportSurface::Lowering,
            "AST node",
            "IR block",
        );
        assert!(ng.divergence_description.contains("AST node"));
        assert!(ng.divergence_description.contains("IR block"));
    }

    #[test]
    fn test_detect_nongluable_deterministic() {
        let ng1 = detect_nongluable(
            "code",
            SupportSurface::TypeScript,
            SupportSurface::Runtime,
            "typed",
            "untyped",
        );
        let ng2 = detect_nongluable(
            "code",
            SupportSurface::TypeScript,
            SupportSurface::Runtime,
            "typed",
            "untyped",
        );
        assert_eq!(ng1.content_hash, ng2.content_hash);
        assert_eq!(ng1.program_id, ng2.program_id);
    }

    #[test]
    fn test_detect_nongluable_different_surfaces_different_hash() {
        let ng1 = detect_nongluable(
            "code",
            SupportSurface::Parser,
            SupportSurface::Lowering,
            "left",
            "right",
        );
        let ng2 = detect_nongluable(
            "code",
            SupportSurface::Lowering,
            SupportSurface::Runtime,
            "left",
            "right",
        );
        assert_ne!(ng1.content_hash, ng2.content_hash);
    }

    // -- diagnose_seam --------------------------------------------------

    #[test]
    fn test_diagnose_seam_empty_witnesses() {
        let d = diagnose_seam(&[], SupportSurface::Parser, SupportSurface::Lowering);
        assert_eq!(d.obstruction_count, 0);
        assert_eq!(d.severity_millionths, 0);
        assert!(d.seam_id.contains("parser"));
    }

    #[test]
    fn test_diagnose_seam_single_witness() {
        let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
        let d = diagnose_seam(&[w], SupportSurface::Parser, SupportSurface::Lowering);
        assert_eq!(d.obstruction_count, 1);
        // 1 * 50_000 + 1 * 100_000 = 150_000
        assert_eq!(d.severity_millionths, 150_000);
    }

    #[test]
    fn test_diagnose_seam_severity_capped_at_million() {
        let mut witnesses = Vec::new();
        for _ in 0..100 {
            witnesses.push(make_witness(SupportSurface::Runtime, ObstructionKind::TypeMismatch));
        }
        let d = diagnose_seam(&witnesses, SupportSurface::Runtime, SupportSurface::Module);
        assert_eq!(d.severity_millionths, MILLIONTHS);
    }

    #[test]
    fn test_diagnose_seam_diversity_increases_severity() {
        let w1 = make_witness(SupportSurface::Lowering, ObstructionKind::TypeMismatch);
        let w2 = make_witness(SupportSurface::Lowering, ObstructionKind::SemanticGap);

        let d_diverse = diagnose_seam(
            &[w1.clone(), w2],
            SupportSurface::Lowering,
            SupportSurface::Runtime,
        );

        let w3 = make_witness(SupportSurface::Lowering, ObstructionKind::TypeMismatch);
        let d_uniform = diagnose_seam(
            &[w1, w3],
            SupportSurface::Lowering,
            SupportSurface::Runtime,
        );

        // Same count but diverse has more distinct kinds -> higher severity.
        assert!(d_diverse.severity_millionths > d_uniform.severity_millionths);
    }

    #[test]
    fn test_diagnose_seam_remediation_hint_critical() {
        // Need severity >= 800_000.
        // 16 * 50_000 = 800_000 base + kind diversity.
        let mut witnesses = Vec::new();
        for _ in 0..16 {
            witnesses.push(make_witness(SupportSurface::Parser, ObstructionKind::TypeMismatch));
        }
        let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
        assert!(d.severity_millionths >= 800_000);
        assert!(d.remediation_hint.contains("Critical"));
    }

    #[test]
    fn test_diagnose_seam_remediation_hint_moderate() {
        // 6 * 50_000 + 1 * 100_000 = 400_000.
        let mut witnesses = Vec::new();
        for _ in 0..6 {
            witnesses.push(make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap));
        }
        let d = diagnose_seam(&witnesses, SupportSurface::Parser, SupportSurface::Lowering);
        assert!(d.severity_millionths >= 400_000);
        assert!(d.remediation_hint.contains("Moderate") || d.remediation_hint.contains("Critical"));
    }

    #[test]
    fn test_diagnose_seam_remediation_hint_low() {
        let d = diagnose_seam(&[], SupportSurface::Cli, SupportSurface::Runtime);
        assert!(d.remediation_hint.contains("Low-severity"));
    }

    #[test]
    fn test_diagnose_seam_deterministic() {
        let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
        let d1 = diagnose_seam(&[w.clone()], SupportSurface::Parser, SupportSurface::Lowering);
        let d2 = diagnose_seam(&[w], SupportSurface::Parser, SupportSurface::Lowering);
        assert_eq!(d1.content_hash, d2.content_hash);
    }

    // -- build_report ---------------------------------------------------

    #[test]
    fn test_build_report_empty() {
        let report = build_report(
            SecurityEpoch::from_raw(1),
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(report.total_obstructions, 0);
        assert!(report.report_id.contains("obstruction_witness_emitter"));
    }

    #[test]
    fn test_build_report_with_witnesses() {
        let w = make_witness(SupportSurface::Parser, ObstructionKind::TypeMismatch);
        let report = build_report(
            SecurityEpoch::from_raw(5),
            vec![w],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(report.total_obstructions, 1);
        assert_eq!(report.witnesses.len(), 1);
    }

    #[test]
    fn test_build_report_deterministic() {
        let w = make_witness(SupportSurface::Runtime, ObstructionKind::ResourceViolation);
        let r1 = build_report(
            SecurityEpoch::from_raw(2),
            vec![w.clone()],
            vec![],
            vec![],
        )
        .unwrap();
        let r2 = build_report(
            SecurityEpoch::from_raw(2),
            vec![w],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_build_report_epoch_preserved() {
        let epoch = SecurityEpoch::from_raw(42);
        let report = build_report(epoch, vec![], vec![], vec![]).unwrap();
        assert_eq!(report.epoch, epoch);
    }

    #[test]
    fn test_build_report_includes_programs_and_diagnoses() {
        let ng = detect_nongluable(
            "code",
            SupportSurface::Parser,
            SupportSurface::Lowering,
            "a",
            "b",
        );
        let d = diagnose_seam(&[], SupportSurface::Parser, SupportSurface::Lowering);
        let report = build_report(
            SecurityEpoch::from_raw(1),
            vec![],
            vec![ng],
            vec![d],
        )
        .unwrap();
        assert_eq!(report.nongluable_programs.len(), 1);
        assert_eq!(report.seam_diagnoses.len(), 1);
    }

    // -- franken_engine_obstruction_manifest -----------------------------

    #[test]
    fn test_manifest_is_nonempty() {
        let report = franken_engine_obstruction_manifest();
        assert!(!report.witnesses.is_empty());
        assert!(!report.nongluable_programs.is_empty());
        assert!(!report.seam_diagnoses.is_empty());
    }

    #[test]
    fn test_manifest_deterministic() {
        let r1 = franken_engine_obstruction_manifest();
        let r2 = franken_engine_obstruction_manifest();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_manifest_epoch_is_one() {
        let report = franken_engine_obstruction_manifest();
        assert_eq!(report.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn test_manifest_has_seven_witnesses() {
        let report = franken_engine_obstruction_manifest();
        assert_eq!(report.witnesses.len(), 7);
    }

    #[test]
    fn test_manifest_has_two_nongluable_programs() {
        let report = franken_engine_obstruction_manifest();
        assert_eq!(report.nongluable_programs.len(), 2);
    }

    #[test]
    fn test_manifest_has_three_diagnoses() {
        let report = franken_engine_obstruction_manifest();
        assert_eq!(report.seam_diagnoses.len(), 3);
    }

    #[test]
    fn test_manifest_total_obstructions() {
        let report = franken_engine_obstruction_manifest();
        assert_eq!(report.total_obstructions, 7);
    }

    // -- Serde roundtrip ------------------------------------------------

    #[test]
    fn test_serde_roundtrip_witness() {
        let w = make_witness(SupportSurface::Parser, ObstructionKind::SemanticGap);
        let json = serde_json::to_string(&w).unwrap();
        let deserialized: ObstructionWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_nongluable() {
        let ng = detect_nongluable(
            "source",
            SupportSurface::TypeScript,
            SupportSurface::Runtime,
            "typed",
            "untyped",
        );
        let json = serde_json::to_string(&ng).unwrap();
        let deserialized: NongluableProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(ng, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_seam_diagnosis() {
        let d = diagnose_seam(&[], SupportSurface::Parser, SupportSurface::Lowering);
        let json = serde_json::to_string(&d).unwrap();
        let deserialized: SeamDiagnosis = serde_json::from_str(&json).unwrap();
        assert_eq!(d, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let report = build_report(
            SecurityEpoch::from_raw(1),
            vec![make_witness(SupportSurface::Runtime, ObstructionKind::TypeMismatch)],
            vec![],
            vec![],
        )
        .unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: ObstructionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_error() {
        let errors = vec![
            ObstructionError::EmptyWitness,
            ObstructionError::InvalidSurface,
            ObstructionError::MinimizationFailed,
            ObstructionError::SeamNotFound,
            ObstructionError::InternalError("test".to_string()),
        ];
        for e in errors {
            let json = serde_json::to_string(&e).unwrap();
            let deserialized: ObstructionError = serde_json::from_str(&json).unwrap();
            assert_eq!(e, deserialized);
        }
    }

    // -- Edge cases -----------------------------------------------------

    #[test]
    fn test_witness_with_unicode_source() {
        let w = emit_witness(
            SupportSurface::Parser,
            ObstructionKind::UnsupportedFeature,
            "const \u{1F600} = '\u{2603}';",
            "unicode identifier not supported",
            "parser-unicode-seam",
        )
        .unwrap();
        assert!(w.program_source.contains('\u{1F600}'));
    }

    #[test]
    fn test_nongluable_with_long_source() {
        let source = "x".repeat(100_000);
        let ng = detect_nongluable(
            &source,
            SupportSurface::Runtime,
            SupportSurface::Module,
            "interp-a",
            "interp-b",
        );
        assert_eq!(ng.source_text.len(), 100_000);
    }

    #[test]
    fn test_diagnose_seam_with_cross_surface_witnesses() {
        // Witnesses whose surface is CrossSurface — neither matches
        // left nor right, so they count as nongluable.
        let w = make_witness(SupportSurface::CrossSurface, ObstructionKind::TimingDependence);
        let d = diagnose_seam(&[w], SupportSurface::Parser, SupportSurface::Lowering);
        assert_eq!(d.nongluable_count, 1);
    }

    #[test]
    fn test_report_id_contains_epoch() {
        let report = build_report(
            SecurityEpoch::from_raw(99),
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(report.report_id.contains("99"));
    }
}
