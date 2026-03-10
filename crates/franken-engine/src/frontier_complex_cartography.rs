#![forbid(unsafe_code)]

//! Frontier complex cartography: persistence diagrams, hole-significance
//! ledgers, and multi-scale coverage geometry over program/workload space.
//!
//! Bead: bd-1lsy.9.9.1 [RGC-809A]
//!
//! Computes frontier complexes (simplicial complexes built from coverage
//! samples), persistence diagrams that record the birth and death of
//! topological features across filtration values, and a hole-significance
//! ledger that distinguishes persistent unsupported basins from transient
//! sampling noise.
//!
//! # Design decisions
//!
//! - A `FrontierComplex` is a filtered simplicial complex: each simplex
//!   carries a filtration value in fixed-point millionths (1_000_000 = 1.0).
//!   Simplices must respect the sub-complex property: every face of a
//!   simplex must appear at a filtration value no greater than its parent.
//! - `compute_persistence` implements a simplified persistence algorithm
//!   that pairs birth/death events for each homological dimension.  The
//!   output is a `PersistenceDiagram` whose total persistence is the sum
//!   of individual pair lifetimes.
//! - `classify_hole` decides whether a topological hole is *persistent*
//!   (genuine unsupported basin), *transient* (short-lived feature above
//!   threshold but sample-dependent), *sampling noise* (below threshold
//!   relative to sample count), or *structural* (infinite persistence —
//!   never killed).
//! - The `HoleLedger` collects all classified holes for an epoch, with
//!   counts by significance class.  `filter_significant_holes` extracts
//!   only the holes that warrant investigation.
//! - All types are serde-serialisable with deterministic content hashes
//!   for audit trails.
//! - Fixed-point millionths throughout; no floating-point.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the frontier complex cartography module.
pub const SCHEMA_VERSION: &str = "franken-engine.frontier-complex-cartography.v1";

/// Bead identifier for traceability.
pub const BEAD_ID: &str = "bd-1lsy.9.9.1";

/// Component name.
pub const COMPONENT: &str = "frontier_complex_cartography";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-809A";

/// One million — the unit for fixed-point millionths arithmetic.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default significance threshold: 50_000 millionths (5% of unit scale).
/// Holes with persistence below this (relative to sample count) are
/// considered sampling noise.
const DEFAULT_SIGNIFICANCE_THRESHOLD: u64 = 50_000;

/// Minimum sample count below which all holes are classified as noise.
const MIN_MEANINGFUL_SAMPLES: u64 = 10;

// ---------------------------------------------------------------------------
// SimplexDimension
// ---------------------------------------------------------------------------

/// The combinatorial dimension of a simplex.
///
/// Vertex = 0-simplex, Edge = 1-simplex, Triangle = 2-simplex,
/// Tetrahedron = 3-simplex, HigherDim(k) for k >= 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimplexDimension {
    /// A 0-dimensional simplex (point).
    Vertex,
    /// A 1-dimensional simplex (line segment).
    Edge,
    /// A 2-dimensional simplex (filled triangle).
    Triangle,
    /// A 3-dimensional simplex (filled tetrahedron).
    Tetrahedron,
    /// A simplex of dimension >= 4.
    HigherDim(u32),
}

impl SimplexDimension {
    /// Return the numeric dimension.
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Vertex => 0,
            Self::Edge => 1,
            Self::Triangle => 2,
            Self::Tetrahedron => 3,
            Self::HigherDim(k) => *k,
        }
    }

    /// Construct from a numeric dimension.
    pub fn from_u32(dim: u32) -> Self {
        match dim {
            0 => Self::Vertex,
            1 => Self::Edge,
            2 => Self::Triangle,
            3 => Self::Tetrahedron,
            k => Self::HigherDim(k),
        }
    }

    /// Expected number of vertices for this dimension.
    pub fn expected_vertex_count(&self) -> u32 {
        self.as_u32() + 1
    }
}

impl fmt::Display for SimplexDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vertex => write!(f, "vertex"),
            Self::Edge => write!(f, "edge"),
            Self::Triangle => write!(f, "triangle"),
            Self::Tetrahedron => write!(f, "tetrahedron"),
            Self::HigherDim(k) => write!(f, "dim-{k}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Simplex
// ---------------------------------------------------------------------------

/// A simplex in the frontier complex.
///
/// Each simplex is identified by a unique ID, has a dimension, a set of
/// vertices (whose count must equal dimension + 1), and a filtration value
/// that records when the simplex "appears" in the filtered complex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Simplex {
    /// Unique identifier for this simplex.
    pub simplex_id: String,
    /// Combinatorial dimension.
    pub dimension: SimplexDimension,
    /// Vertex labels (must have exactly `dimension + 1` entries).
    pub vertices: Vec<String>,
    /// Filtration value in fixed-point millionths.
    pub filtration_value_millionths: u64,
}

impl Simplex {
    /// Validate that the vertex count matches the declared dimension.
    pub fn validate(&self) -> Result<(), CartographyError> {
        let expected = self.dimension.expected_vertex_count() as usize;
        if self.vertices.len() != expected {
            return Err(CartographyError::InvalidSimplex);
        }
        if self.simplex_id.is_empty() {
            return Err(CartographyError::InvalidSimplex);
        }
        // Check for duplicate vertices.
        let unique: BTreeSet<&String> = self.vertices.iter().collect();
        if unique.len() != self.vertices.len() {
            return Err(CartographyError::InvalidSimplex);
        }
        Ok(())
    }

    /// Compute a content hash over the simplex's defining data.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.simplex_id.as_bytes());
        buf.extend_from_slice(&self.dimension.as_u32().to_le_bytes());
        for v in &self.vertices {
            buf.extend_from_slice(v.as_bytes());
            buf.push(0xFF);
        }
        buf.extend_from_slice(&self.filtration_value_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for Simplex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "simplex[{}] dim={} filt={}",
            self.simplex_id, self.dimension, self.filtration_value_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// FrontierComplex
// ---------------------------------------------------------------------------

/// A filtered simplicial complex representing the frontier of coverage
/// geometry in program/workload space.
///
/// The complex is built from coverage samples: each program configuration
/// or workload point becomes a vertex, and higher-dimensional simplices
/// encode proximity relationships at various filtration scales.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierComplex {
    /// Unique identifier for this complex.
    pub complex_id: String,
    /// Security epoch at which the complex was computed.
    pub epoch: SecurityEpoch,
    /// All simplices in the complex, ordered by filtration value.
    pub simplices: Vec<Simplex>,
    /// Maximum simplex dimension in the complex.
    pub max_dimension: u32,
    /// Number of 0-dimensional simplices (vertices).
    pub vertex_count: u64,
    /// Content hash over the complex's canonical representation.
    pub content_hash: ContentHash,
}

impl FrontierComplex {
    /// Recompute the content hash from the complex's state.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.complex_id.as_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.max_dimension.to_le_bytes());
        buf.extend_from_slice(&self.vertex_count.to_le_bytes());
        for s in &self.simplices {
            buf.extend_from_slice(s.content_hash().as_bytes());
        }
        self.content_hash = ContentHash::compute(&buf);
    }

    /// Return the number of simplices at a given dimension.
    pub fn count_at_dimension(&self, dim: u32) -> usize {
        self.simplices
            .iter()
            .filter(|s| s.dimension.as_u32() == dim)
            .count()
    }

    /// Return the filtration range: (min, max) in millionths.
    /// Returns `None` if the complex is empty.
    pub fn filtration_range(&self) -> Option<(u64, u64)> {
        if self.simplices.is_empty() {
            return None;
        }
        let min = self
            .simplices
            .iter()
            .map(|s| s.filtration_value_millionths)
            .min()
            .unwrap_or(0);
        let max = self
            .simplices
            .iter()
            .map(|s| s.filtration_value_millionths)
            .max()
            .unwrap_or(0);
        Some((min, max))
    }
}

impl fmt::Display for FrontierComplex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FrontierComplex[{}] epoch={} simplices={} max_dim={} vertices={}",
            self.complex_id,
            self.epoch,
            self.simplices.len(),
            self.max_dimension,
            self.vertex_count,
        )
    }
}

// ---------------------------------------------------------------------------
// PersistencePair
// ---------------------------------------------------------------------------

/// A birth-death pair in a persistence diagram.
///
/// Records when a topological feature (cycle) is born at a certain
/// filtration value and when it is killed.  If `killer_simplex` is `None`,
/// the feature persists to infinity (essential cycle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistencePair {
    /// Filtration value at which the feature is born (millionths).
    pub birth_filtration_millionths: u64,
    /// Filtration value at which the feature dies (millionths).
    /// For essential cycles, this equals `u64::MAX`.
    pub death_filtration_millionths: u64,
    /// Homological dimension of the feature (0 = connected component,
    /// 1 = loop, 2 = void, ...).
    pub dimension: u32,
    /// ID of the simplex that generates the cycle.
    pub generator_simplex: String,
    /// ID of the simplex that kills the cycle (`None` for essential).
    pub killer_simplex: Option<String>,
    /// Persistence = death - birth (millionths).  For essential cycles
    /// this is `u64::MAX - birth`.
    pub persistence_millionths: u64,
}

impl PersistencePair {
    /// Is this an essential (never-killed) pair?
    pub fn is_essential(&self) -> bool {
        self.killer_simplex.is_none()
    }

    /// Compute content hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.birth_filtration_millionths.to_le_bytes());
        buf.extend_from_slice(&self.death_filtration_millionths.to_le_bytes());
        buf.extend_from_slice(&self.dimension.to_le_bytes());
        buf.extend_from_slice(self.generator_simplex.as_bytes());
        if let Some(k) = &self.killer_simplex {
            buf.extend_from_slice(k.as_bytes());
        }
        buf.extend_from_slice(&self.persistence_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for PersistencePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let death_str = if self.is_essential() {
            "inf".to_string()
        } else {
            self.death_filtration_millionths.to_string()
        };
        write!(
            f,
            "pair[dim={}] birth={} death={} pers={}",
            self.dimension,
            self.birth_filtration_millionths,
            death_str,
            self.persistence_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// PersistenceDiagram
// ---------------------------------------------------------------------------

/// A persistence diagram: the collection of all birth-death pairs
/// extracted from a filtered complex.
///
/// The diagram is the primary topological summary: short-lived pairs
/// correspond to noise, while long-lived pairs indicate genuine
/// structural features of the coverage geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceDiagram {
    /// Unique identifier for this diagram.
    pub diagram_id: String,
    /// All persistence pairs.
    pub pairs: Vec<PersistencePair>,
    /// Sum of all finite persistence values (millionths).
    pub total_persistence_millionths: u64,
    /// Content hash over the canonical diagram representation.
    pub content_hash: ContentHash,
}

impl PersistenceDiagram {
    /// Recompute the content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.diagram_id.as_bytes());
        buf.extend_from_slice(&self.total_persistence_millionths.to_le_bytes());
        for p in &self.pairs {
            buf.extend_from_slice(p.content_hash().as_bytes());
        }
        self.content_hash = ContentHash::compute(&buf);
    }

    /// Number of pairs at a specific homological dimension.
    pub fn count_at_dimension(&self, dim: u32) -> usize {
        self.pairs.iter().filter(|p| p.dimension == dim).count()
    }

    /// Number of essential (never-killed) pairs.
    pub fn essential_count(&self) -> usize {
        self.pairs.iter().filter(|p| p.is_essential()).count()
    }

    /// Maximum finite persistence across all pairs (millionths).
    pub fn max_persistence(&self) -> u64 {
        self.pairs
            .iter()
            .filter(|p| !p.is_essential())
            .map(|p| p.persistence_millionths)
            .max()
            .unwrap_or(0)
    }
}

impl fmt::Display for PersistenceDiagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PersistenceDiagram[{}] pairs={} total_pers={} essential={}",
            self.diagram_id,
            self.pairs.len(),
            self.total_persistence_millionths,
            self.essential_count(),
        )
    }
}

// ---------------------------------------------------------------------------
// HoleSignificance
// ---------------------------------------------------------------------------

/// Significance classification for a topological hole.
///
/// Determines whether a detected hole in the coverage frontier warrants
/// action (persistent unsupported basin) or can be ignored (sampling
/// artifact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoleSignificance {
    /// The hole persists across many filtration scales and is confirmed
    /// by sufficient samples: a genuine unsupported basin.
    Persistent,
    /// The hole has moderate persistence but may depend on specific
    /// sampling or configuration.
    Transient,
    /// The hole's persistence is below the noise threshold relative to
    /// sample count: likely an artifact of finite sampling.
    SamplingNoise,
    /// The hole is structural (essential / infinite persistence): it
    /// reflects a fundamental topological feature of the space.
    Structural,
}

impl HoleSignificance {
    /// Whether this significance level warrants investigation.
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Persistent | Self::Structural)
    }
}

impl fmt::Display for HoleSignificance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Persistent => "persistent",
            Self::Transient => "transient",
            Self::SamplingNoise => "sampling_noise",
            Self::Structural => "structural",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// FrontierHole
// ---------------------------------------------------------------------------

/// A topological hole detected in the coverage frontier, annotated with
/// significance, representative cycle, and affected programs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierHole {
    /// Unique identifier for this hole.
    pub hole_id: String,
    /// Homological dimension of the hole.
    pub dimension: u32,
    /// Significance classification.
    pub significance: HoleSignificance,
    /// Persistence in millionths (death - birth).
    pub persistence_millionths: u64,
    /// Representative cycle: list of simplex IDs forming the cycle.
    pub representative_cycle: Vec<String>,
    /// Programs or workloads affected by (adjacent to) this hole.
    pub affected_programs: Vec<String>,
    /// Content hash of the hole record.
    pub content_hash: ContentHash,
}

impl FrontierHole {
    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.hole_id.as_bytes());
        buf.extend_from_slice(&self.dimension.to_le_bytes());
        buf.extend_from_slice(&(self.significance as u32).to_le_bytes());
        buf.extend_from_slice(&self.persistence_millionths.to_le_bytes());
        for s in &self.representative_cycle {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0xFF);
        }
        for p in &self.affected_programs {
            buf.extend_from_slice(p.as_bytes());
            buf.push(0xFE);
        }
        self.content_hash = ContentHash::compute(&buf);
    }
}

impl fmt::Display for FrontierHole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FrontierHole[{}] dim={} sig={} pers={} programs={}",
            self.hole_id,
            self.dimension,
            self.significance,
            self.persistence_millionths,
            self.affected_programs.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// HoleLedger
// ---------------------------------------------------------------------------

/// A ledger of all frontier holes for a given security epoch, with
/// aggregate significance statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoleLedger {
    /// Unique identifier for this ledger.
    pub ledger_id: String,
    /// Security epoch at which the ledger was computed.
    pub epoch: SecurityEpoch,
    /// All detected holes.
    pub holes: Vec<FrontierHole>,
    /// Count of holes classified as `Persistent`.
    pub persistent_count: u64,
    /// Count of holes classified as `SamplingNoise`.
    pub noise_count: u64,
    /// Significance threshold used for classification (millionths).
    pub significance_threshold_millionths: u64,
    /// Content hash of the ledger.
    pub content_hash: ContentHash,
}

impl HoleLedger {
    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.ledger_id.as_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.persistent_count.to_le_bytes());
        buf.extend_from_slice(&self.noise_count.to_le_bytes());
        buf.extend_from_slice(&self.significance_threshold_millionths.to_le_bytes());
        for h in &self.holes {
            buf.extend_from_slice(h.content_hash.as_bytes());
        }
        self.content_hash = ContentHash::compute(&buf);
    }

    /// Count of holes classified as `Transient`.
    pub fn transient_count(&self) -> u64 {
        self.holes
            .iter()
            .filter(|h| h.significance == HoleSignificance::Transient)
            .count() as u64
    }

    /// Count of holes classified as `Structural`.
    pub fn structural_count(&self) -> u64 {
        self.holes
            .iter()
            .filter(|h| h.significance == HoleSignificance::Structural)
            .count() as u64
    }

    /// Total number of holes.
    pub fn total_holes(&self) -> usize {
        self.holes.len()
    }
}

impl fmt::Display for HoleLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HoleLedger[{}] epoch={} holes={} persistent={} noise={} threshold={}",
            self.ledger_id,
            self.epoch,
            self.holes.len(),
            self.persistent_count,
            self.noise_count,
            self.significance_threshold_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// CartographyError
// ---------------------------------------------------------------------------

/// Errors arising from frontier complex cartography operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CartographyError {
    /// The complex has no simplices.
    EmptyComplex,
    /// A simplex has invalid structure (wrong vertex count, empty ID, etc.).
    InvalidSimplex,
    /// A simplex appears at a filtration value before one of its faces.
    FiltrationViolation,
    /// The persistence diagram is inconsistent (e.g. birth > death).
    DiagramInconsistent,
    /// An internal error with a description.
    InternalError(String),
}

impl fmt::Display for CartographyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyComplex => write!(f, "complex contains no simplices"),
            Self::InvalidSimplex => write!(f, "simplex structure is invalid"),
            Self::FiltrationViolation => {
                write!(
                    f,
                    "filtration ordering violation: face appears after parent"
                )
            }
            Self::DiagramInconsistent => {
                write!(f, "persistence diagram is inconsistent")
            }
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for CartographyError {}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Build a `FrontierComplex` from a list of simplices.
///
/// Validates each simplex, checks filtration ordering (every face of a
/// simplex must have a filtration value <= the simplex's filtration value),
/// computes aggregate statistics, and seals the complex with a content
/// hash.
///
/// # Errors
///
/// - `EmptyComplex` if `simplices` is empty.
/// - `InvalidSimplex` if any simplex has mismatched vertex count or
///   empty ID.
/// - `FiltrationViolation` if a higher-dimensional simplex appears at a
///   filtration value strictly less than one of its faces.
pub fn build_complex(simplices: Vec<Simplex>) -> Result<FrontierComplex, CartographyError> {
    if simplices.is_empty() {
        return Err(CartographyError::EmptyComplex);
    }

    // Validate individual simplices.
    for s in &simplices {
        s.validate()?;
    }

    // Build a lookup: simplex vertices (sorted) -> filtration value.
    // This allows us to check the sub-complex property.
    let mut vertex_set_to_filt: std::collections::BTreeMap<Vec<String>, u64> =
        std::collections::BTreeMap::new();
    for s in &simplices {
        let mut sorted_verts = s.vertices.clone();
        sorted_verts.sort();
        vertex_set_to_filt.insert(sorted_verts, s.filtration_value_millionths);
    }

    // For each simplex of dimension >= 1, check that every face has a
    // filtration value <= the simplex's own.
    for s in &simplices {
        if s.dimension.as_u32() == 0 {
            continue;
        }
        let mut sorted_verts = s.vertices.clone();
        sorted_verts.sort();

        // Generate all faces (subsets of size `dim`).
        let faces = generate_faces(&sorted_verts);
        for face in &faces {
            if let Some(&face_filt) = vertex_set_to_filt.get(face)
                && face_filt > s.filtration_value_millionths
            {
                return Err(CartographyError::FiltrationViolation);
            }
            // If a face is not present, that is allowed: we do not require
            // a complete simplicial complex, only that present faces
            // satisfy the ordering.
        }
    }

    // Compute statistics.
    let max_dimension = simplices
        .iter()
        .map(|s| s.dimension.as_u32())
        .max()
        .unwrap_or(0);

    let vertex_count = simplices
        .iter()
        .filter(|s| s.dimension == SimplexDimension::Vertex)
        .count() as u64;

    // Sort simplices by filtration value (stable, deterministic).
    let mut sorted = simplices;
    sorted.sort_by(|a, b| {
        a.filtration_value_millionths
            .cmp(&b.filtration_value_millionths)
            .then_with(|| a.dimension.as_u32().cmp(&b.dimension.as_u32()))
            .then_with(|| a.simplex_id.cmp(&b.simplex_id))
    });

    let complex_id = format!("{BEAD_ID}-complex-{}", vertex_count);

    let mut complex = FrontierComplex {
        complex_id,
        epoch: SecurityEpoch::GENESIS,
        simplices: sorted,
        max_dimension,
        vertex_count,
        content_hash: ContentHash::compute(b""),
    };
    complex.seal();
    Ok(complex)
}

/// Generate all codimension-1 faces of a sorted vertex set.
///
/// For a simplex with vertices [v0, v1, ..., vk], the faces are all
/// subsets of size k obtained by removing one vertex.
fn generate_faces(sorted_verts: &[String]) -> Vec<Vec<String>> {
    let mut faces = Vec::new();
    for i in 0..sorted_verts.len() {
        let mut face = Vec::with_capacity(sorted_verts.len() - 1);
        for (j, v) in sorted_verts.iter().enumerate() {
            if j != i {
                face.push(v.clone());
            }
        }
        faces.push(face);
    }
    faces
}

/// Compute a persistence diagram from a frontier complex.
///
/// This is a simplified persistence computation suitable for the
/// cartography use case.  For each dimension d, we pair simplices that
/// create cycles (births) with simplices that fill them (deaths).
///
/// The algorithm sorts simplices by filtration value and dimension, then
/// greedily pairs births and deaths by dimension.  Unpaired births become
/// essential cycles.
///
/// # Errors
///
/// - `EmptyComplex` if the complex has no simplices.
pub fn compute_persistence(
    complex: &FrontierComplex,
) -> Result<PersistenceDiagram, CartographyError> {
    if complex.simplices.is_empty() {
        return Err(CartographyError::EmptyComplex);
    }

    let mut pairs: Vec<PersistencePair> = Vec::new();

    // Collect simplices by dimension.
    let max_dim = complex.max_dimension;

    // For dimension 0: each vertex is a birth of a connected component.
    // Edges can kill components by merging them (death).
    // For dimension d >= 1: a d-simplex can birth a d-cycle; a (d+1)-simplex
    // can kill it.

    // Simplified approach: for each dimension d, collect "births" from
    // d-simplices and "deaths" from (d+1)-simplices, pairing greedily by
    // filtration order.

    for dim in 0..=max_dim {
        let mut births: Vec<&Simplex> = complex
            .simplices
            .iter()
            .filter(|s| s.dimension.as_u32() == dim)
            .collect();
        births.sort_by_key(|s| (s.filtration_value_millionths, s.simplex_id.clone()));

        let mut deaths: Vec<&Simplex> = complex
            .simplices
            .iter()
            .filter(|s| s.dimension.as_u32() == dim + 1)
            .collect();
        deaths.sort_by_key(|s| (s.filtration_value_millionths, s.simplex_id.clone()));

        let paired_count = births.len().min(deaths.len());

        for i in 0..paired_count {
            let birth_filt = births[i].filtration_value_millionths;
            let death_filt = deaths[i].filtration_value_millionths;
            let pers = death_filt.saturating_sub(birth_filt);

            pairs.push(PersistencePair {
                birth_filtration_millionths: birth_filt,
                death_filtration_millionths: death_filt,
                dimension: dim,
                generator_simplex: births[i].simplex_id.clone(),
                killer_simplex: Some(deaths[i].simplex_id.clone()),
                persistence_millionths: pers,
            });
        }

        // Unpaired births become essential cycles.
        for birth in births.iter().skip(paired_count) {
            let birth_filt = birth.filtration_value_millionths;
            pairs.push(PersistencePair {
                birth_filtration_millionths: birth_filt,
                death_filtration_millionths: u64::MAX,
                dimension: dim,
                generator_simplex: birth.simplex_id.clone(),
                killer_simplex: None,
                persistence_millionths: u64::MAX.saturating_sub(birth_filt),
            });
        }
    }

    // Compute total persistence (only finite pairs).
    let total_persistence_millionths: u64 = pairs
        .iter()
        .filter(|p| !p.is_essential())
        .map(|p| p.persistence_millionths)
        .sum();

    let diagram_id = format!("{BEAD_ID}-diagram-{}", complex.complex_id);

    let mut diagram = PersistenceDiagram {
        diagram_id,
        pairs,
        total_persistence_millionths,
        content_hash: ContentHash::compute(b""),
    };
    diagram.seal();
    Ok(diagram)
}

/// Classify the significance of a hole based on its persistence pair.
///
/// Classification rules:
/// 1. If the pair is essential (no killer), classify as `Structural`.
/// 2. If `sample_count < MIN_MEANINGFUL_SAMPLES`, classify as
///    `SamplingNoise`.
/// 3. If persistence < threshold_millionths, classify as `SamplingNoise`.
/// 4. If persistence >= threshold_millionths * 2, classify as `Persistent`.
/// 5. Otherwise, classify as `Transient`.
pub fn classify_hole(
    pair: &PersistencePair,
    threshold_millionths: u64,
    sample_count: u64,
) -> HoleSignificance {
    // Essential cycles are structural.
    if pair.is_essential() {
        return HoleSignificance::Structural;
    }

    // Insufficient samples: everything is noise.
    if sample_count < MIN_MEANINGFUL_SAMPLES {
        return HoleSignificance::SamplingNoise;
    }

    let pers = pair.persistence_millionths;

    if pers < threshold_millionths {
        HoleSignificance::SamplingNoise
    } else if pers >= threshold_millionths.saturating_mul(2) {
        HoleSignificance::Persistent
    } else {
        HoleSignificance::Transient
    }
}

/// Build a hole ledger from a persistence diagram.
///
/// For each pair in the diagram, creates a `FrontierHole` with the
/// appropriate significance classification and representative cycle.
/// The ledger aggregates counts by significance class.
pub fn build_hole_ledger(
    epoch: SecurityEpoch,
    diagram: &PersistenceDiagram,
    threshold: u64,
    sample_count: u64,
) -> HoleLedger {
    let mut holes = Vec::new();
    let mut persistent_count: u64 = 0;
    let mut noise_count: u64 = 0;

    for (idx, pair) in diagram.pairs.iter().enumerate() {
        let significance = classify_hole(pair, threshold, sample_count);

        match significance {
            HoleSignificance::Persistent => persistent_count += 1,
            HoleSignificance::SamplingNoise => noise_count += 1,
            _ => {}
        }

        let cycle = vec![pair.generator_simplex.clone()];
        let affected = if let Some(killer) = &pair.killer_simplex {
            vec![pair.generator_simplex.clone(), killer.clone()]
        } else {
            vec![pair.generator_simplex.clone()]
        };

        let hole_id = format!("{BEAD_ID}-hole-{idx}");

        let mut hole = FrontierHole {
            hole_id,
            dimension: pair.dimension,
            significance,
            persistence_millionths: pair.persistence_millionths,
            representative_cycle: cycle,
            affected_programs: affected,
            content_hash: ContentHash::compute(b""),
        };
        hole.seal();
        holes.push(hole);
    }

    let ledger_id = format!("{BEAD_ID}-ledger-{}", diagram.diagram_id);

    let mut ledger = HoleLedger {
        ledger_id,
        epoch,
        holes,
        persistent_count,
        noise_count,
        significance_threshold_millionths: threshold,
        content_hash: ContentHash::compute(b""),
    };
    ledger.seal();
    ledger
}

/// Compute total persistence of a diagram (sum of finite pair lifetimes).
pub fn total_persistence(diagram: &PersistenceDiagram) -> u64 {
    diagram
        .pairs
        .iter()
        .filter(|p| !p.is_essential())
        .map(|p| p.persistence_millionths)
        .sum()
}

/// Filter a ledger to return only significant (actionable) holes.
///
/// Returns holes classified as `Persistent` or `Structural`.
pub fn filter_significant_holes(ledger: &HoleLedger) -> Vec<&FrontierHole> {
    ledger
        .holes
        .iter()
        .filter(|h| h.significance.is_actionable())
        .collect()
}

/// Produce a canonical reference `HoleLedger` (manifest).
///
/// This creates a representative ledger with one hole per significance
/// class, demonstrating the module's classification capabilities.
/// Useful for testing, schema validation, and integration verification.
pub fn franken_engine_frontier_manifest() -> HoleLedger {
    let epoch = SecurityEpoch::from_raw(1);

    // Build a small representative complex.
    let v_a = Simplex {
        simplex_id: "v-a".to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec!["a".to_string()],
        filtration_value_millionths: 0,
    };
    let v_b = Simplex {
        simplex_id: "v-b".to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec!["b".to_string()],
        filtration_value_millionths: 0,
    };
    let v_c = Simplex {
        simplex_id: "v-c".to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec!["c".to_string()],
        filtration_value_millionths: 100_000,
    };
    let v_d = Simplex {
        simplex_id: "v-d".to_string(),
        dimension: SimplexDimension::Vertex,
        vertices: vec!["d".to_string()],
        filtration_value_millionths: 200_000,
    };
    let e_ab = Simplex {
        simplex_id: "e-ab".to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec!["a".to_string(), "b".to_string()],
        filtration_value_millionths: 500_000,
    };
    let e_bc = Simplex {
        simplex_id: "e-bc".to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec!["b".to_string(), "c".to_string()],
        filtration_value_millionths: 600_000,
    };
    let e_ac = Simplex {
        simplex_id: "e-ac".to_string(),
        dimension: SimplexDimension::Edge,
        vertices: vec!["a".to_string(), "c".to_string()],
        filtration_value_millionths: 700_000,
    };
    let t_abc = Simplex {
        simplex_id: "t-abc".to_string(),
        dimension: SimplexDimension::Triangle,
        vertices: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        filtration_value_millionths: MILLIONTHS,
    };

    let simplices = vec![v_a, v_b, v_c, v_d, e_ab, e_bc, e_ac, t_abc];
    let mut complex = build_complex(simplices).expect("manifest complex should be valid");
    complex.epoch = epoch;
    complex.seal();

    let diagram = compute_persistence(&complex).expect("manifest persistence should succeed");

    build_hole_ledger(epoch, &diagram, DEFAULT_SIGNIFICANCE_THRESHOLD, 100)
}

// ---------------------------------------------------------------------------
// Helpers for complex analysis
// ---------------------------------------------------------------------------

/// Compute the Euler characteristic of a frontier complex.
///
/// chi = sum over dim d of (-1)^d * count(d-simplices)
pub fn euler_characteristic(complex: &FrontierComplex) -> i64 {
    let mut chi: i64 = 0;
    for s in &complex.simplices {
        let d = s.dimension.as_u32();
        if d.is_multiple_of(2) {
            chi += 1;
        } else {
            chi -= 1;
        }
    }
    chi
}

/// Compute the bottleneck distance between two persistence diagrams.
///
/// The bottleneck distance is the maximum over all matched pairs of
/// the L-infinity distance between birth-death coordinates.  This is
/// a simplified version that pairs by index (suitable for diagrams of
/// the same complex at different epochs).
///
/// Returns `None` if the diagrams have different numbers of pairs.
pub fn bottleneck_distance_approx(a: &PersistenceDiagram, b: &PersistenceDiagram) -> Option<u64> {
    if a.pairs.len() != b.pairs.len() {
        return None;
    }
    let mut max_dist: u64 = 0;
    for (pa, pb) in a.pairs.iter().zip(b.pairs.iter()) {
        let birth_diff = pa
            .birth_filtration_millionths
            .abs_diff(pb.birth_filtration_millionths);
        let death_diff = if pa.is_essential() || pb.is_essential() {
            // If either is essential, we use a large sentinel.
            if pa.is_essential() && pb.is_essential() {
                0
            } else {
                u64::MAX
            }
        } else {
            pa.death_filtration_millionths
                .abs_diff(pb.death_filtration_millionths)
        };
        let pair_dist = birth_diff.max(death_diff);
        if pair_dist > max_dist {
            max_dist = pair_dist;
        }
    }
    Some(max_dist)
}

/// Compute a stability score for a ledger.
///
/// The stability score is the ratio of persistent+structural holes to
/// total holes, expressed in millionths.  A high score means most
/// detected features are genuine.  Returns 0 if no holes.
pub fn stability_score(ledger: &HoleLedger) -> u64 {
    if ledger.holes.is_empty() {
        return 0;
    }
    let significant = ledger.persistent_count + ledger.structural_count();
    significant
        .saturating_mul(MILLIONTHS)
        .checked_div(ledger.holes.len() as u64)
        .unwrap_or(0)
}

/// Produce a summary report of a hole ledger for diagnostic display.
pub fn ledger_summary(ledger: &HoleLedger) -> LedgerSummary {
    let total = ledger.total_holes() as u64;
    let persistent = ledger.persistent_count;
    let transient = ledger.transient_count();
    let noise = ledger.noise_count;
    let structural = ledger.structural_count();
    let score = stability_score(ledger);

    LedgerSummary {
        ledger_id: ledger.ledger_id.clone(),
        epoch: ledger.epoch,
        total_holes: total,
        persistent_holes: persistent,
        transient_holes: transient,
        noise_holes: noise,
        structural_holes: structural,
        stability_score_millionths: score,
        threshold_millionths: ledger.significance_threshold_millionths,
        content_hash: ledger.content_hash.clone(),
    }
}

// ---------------------------------------------------------------------------
// LedgerSummary
// ---------------------------------------------------------------------------

/// Compact summary of a hole ledger for diagnostic reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSummary {
    /// Ledger ID.
    pub ledger_id: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Total number of holes.
    pub total_holes: u64,
    /// Persistent holes.
    pub persistent_holes: u64,
    /// Transient holes.
    pub transient_holes: u64,
    /// Noise holes.
    pub noise_holes: u64,
    /// Structural holes.
    pub structural_holes: u64,
    /// Stability score in millionths.
    pub stability_score_millionths: u64,
    /// Significance threshold used.
    pub threshold_millionths: u64,
    /// Content hash of the originating ledger.
    pub content_hash: ContentHash,
}

impl fmt::Display for LedgerSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LedgerSummary[{}] epoch={} total={} pers={} trans={} noise={} struct={} score={}",
            self.ledger_id,
            self.epoch,
            self.total_holes,
            self.persistent_holes,
            self.transient_holes,
            self.noise_holes,
            self.structural_holes,
            self.stability_score_millionths,
        )
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper: build a standard test simplex set
    // -----------------------------------------------------------------------

    fn make_vertex(id: &str, label: &str, filt: u64) -> Simplex {
        Simplex {
            simplex_id: id.to_string(),
            dimension: SimplexDimension::Vertex,
            vertices: vec![label.to_string()],
            filtration_value_millionths: filt,
        }
    }

    fn make_edge(id: &str, v0: &str, v1: &str, filt: u64) -> Simplex {
        Simplex {
            simplex_id: id.to_string(),
            dimension: SimplexDimension::Edge,
            vertices: vec![v0.to_string(), v1.to_string()],
            filtration_value_millionths: filt,
        }
    }

    fn make_triangle(id: &str, v0: &str, v1: &str, v2: &str, filt: u64) -> Simplex {
        Simplex {
            simplex_id: id.to_string(),
            dimension: SimplexDimension::Triangle,
            vertices: vec![v0.to_string(), v1.to_string(), v2.to_string()],
            filtration_value_millionths: filt,
        }
    }

    /// Standard 4-vertex, 3-edge, 1-triangle complex for tests.
    fn standard_complex_simplices() -> Vec<Simplex> {
        vec![
            make_vertex("v0", "a", 0),
            make_vertex("v1", "b", 0),
            make_vertex("v2", "c", 100_000),
            make_vertex("v3", "d", 200_000),
            make_edge("e01", "a", "b", 300_000),
            make_edge("e12", "b", "c", 400_000),
            make_edge("e02", "a", "c", 500_000),
            make_triangle("t012", "a", "b", "c", 600_000),
        ]
    }

    // -----------------------------------------------------------------------
    // SimplexDimension tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_simplex_dimension_as_u32() {
        assert_eq!(SimplexDimension::Vertex.as_u32(), 0);
        assert_eq!(SimplexDimension::Edge.as_u32(), 1);
        assert_eq!(SimplexDimension::Triangle.as_u32(), 2);
        assert_eq!(SimplexDimension::Tetrahedron.as_u32(), 3);
        assert_eq!(SimplexDimension::HigherDim(7).as_u32(), 7);
    }

    #[test]
    fn test_simplex_dimension_from_u32_roundtrip() {
        for d in 0..=5 {
            let dim = SimplexDimension::from_u32(d);
            assert_eq!(dim.as_u32(), d);
        }
    }

    #[test]
    fn test_simplex_dimension_expected_vertex_count() {
        assert_eq!(SimplexDimension::Vertex.expected_vertex_count(), 1);
        assert_eq!(SimplexDimension::Edge.expected_vertex_count(), 2);
        assert_eq!(SimplexDimension::Triangle.expected_vertex_count(), 3);
        assert_eq!(SimplexDimension::Tetrahedron.expected_vertex_count(), 4);
    }

    #[test]
    fn test_simplex_dimension_display() {
        assert_eq!(SimplexDimension::Vertex.to_string(), "vertex");
        assert_eq!(SimplexDimension::Edge.to_string(), "edge");
        assert_eq!(SimplexDimension::Triangle.to_string(), "triangle");
        assert_eq!(SimplexDimension::Tetrahedron.to_string(), "tetrahedron");
        assert_eq!(SimplexDimension::HigherDim(5).to_string(), "dim-5");
    }

    #[test]
    fn test_simplex_dimension_serde_roundtrip() {
        let dims = vec![
            SimplexDimension::Vertex,
            SimplexDimension::Edge,
            SimplexDimension::Triangle,
            SimplexDimension::Tetrahedron,
            SimplexDimension::HigherDim(10),
        ];
        for dim in &dims {
            let json = serde_json::to_string(dim).unwrap();
            let back: SimplexDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(*dim, back);
        }
    }

    // -----------------------------------------------------------------------
    // Simplex tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_simplex_validate_vertex_ok() {
        let s = make_vertex("v0", "a", 0);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_simplex_validate_edge_ok() {
        let s = make_edge("e01", "a", "b", 100);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_simplex_validate_wrong_vertex_count() {
        let s = Simplex {
            simplex_id: "bad".to_string(),
            dimension: SimplexDimension::Edge,
            vertices: vec!["a".to_string()], // Edge needs 2
            filtration_value_millionths: 0,
        };
        assert_eq!(s.validate(), Err(CartographyError::InvalidSimplex));
    }

    #[test]
    fn test_simplex_validate_empty_id() {
        let s = Simplex {
            simplex_id: String::new(),
            dimension: SimplexDimension::Vertex,
            vertices: vec!["a".to_string()],
            filtration_value_millionths: 0,
        };
        assert_eq!(s.validate(), Err(CartographyError::InvalidSimplex));
    }

    #[test]
    fn test_simplex_validate_duplicate_vertices() {
        let s = Simplex {
            simplex_id: "dup".to_string(),
            dimension: SimplexDimension::Edge,
            vertices: vec!["a".to_string(), "a".to_string()],
            filtration_value_millionths: 0,
        };
        assert_eq!(s.validate(), Err(CartographyError::InvalidSimplex));
    }

    #[test]
    fn test_simplex_content_hash_deterministic() {
        let s1 = make_vertex("v0", "a", 0);
        let s2 = make_vertex("v0", "a", 0);
        assert_eq!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn test_simplex_content_hash_differs_on_id() {
        let s1 = make_vertex("v0", "a", 0);
        let s2 = make_vertex("v1", "a", 0);
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn test_simplex_display() {
        let s = make_vertex("v0", "a", 42);
        let d = s.to_string();
        assert!(d.contains("v0"));
        assert!(d.contains("vertex"));
        assert!(d.contains("42"));
    }

    #[test]
    fn test_simplex_serde_roundtrip() {
        let s = make_edge("e01", "x", "y", 500_000);
        let json = serde_json::to_string(&s).unwrap();
        let back: Simplex = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // FrontierComplex / build_complex tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_complex_empty_returns_error() {
        let result = build_complex(vec![]);
        assert_eq!(result, Err(CartographyError::EmptyComplex));
    }

    #[test]
    fn test_build_complex_single_vertex() {
        let simplices = vec![make_vertex("v0", "a", 0)];
        let complex = build_complex(simplices).unwrap();
        assert_eq!(complex.vertex_count, 1);
        assert_eq!(complex.max_dimension, 0);
        assert_eq!(complex.simplices.len(), 1);
    }

    #[test]
    fn test_build_complex_standard() {
        let simplices = standard_complex_simplices();
        let complex = build_complex(simplices).unwrap();
        assert_eq!(complex.vertex_count, 4);
        assert_eq!(complex.max_dimension, 2);
        assert_eq!(complex.simplices.len(), 8);
    }

    #[test]
    fn test_build_complex_sorted_by_filtration() {
        let simplices = standard_complex_simplices();
        let complex = build_complex(simplices).unwrap();
        for w in complex.simplices.windows(2) {
            assert!(
                w[0].filtration_value_millionths <= w[1].filtration_value_millionths,
                "simplices not sorted by filtration"
            );
        }
    }

    #[test]
    fn test_build_complex_filtration_violation() {
        // Edge appears before its face vertex.
        let simplices = vec![
            make_vertex("v0", "a", 500_000),
            make_vertex("v1", "b", 0),
            make_edge("e01", "a", "b", 100_000), // 100k < 500k for vertex a
        ];
        let result = build_complex(simplices);
        assert_eq!(result, Err(CartographyError::FiltrationViolation));
    }

    #[test]
    fn test_build_complex_invalid_simplex() {
        let bad = Simplex {
            simplex_id: "bad".to_string(),
            dimension: SimplexDimension::Triangle,
            vertices: vec!["a".to_string(), "b".to_string()], // needs 3
            filtration_value_millionths: 0,
        };
        let result = build_complex(vec![bad]);
        assert_eq!(result, Err(CartographyError::InvalidSimplex));
    }

    #[test]
    fn test_build_complex_content_hash_deterministic() {
        let s1 = standard_complex_simplices();
        let s2 = standard_complex_simplices();
        let c1 = build_complex(s1).unwrap();
        let c2 = build_complex(s2).unwrap();
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn test_frontier_complex_count_at_dimension() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        assert_eq!(complex.count_at_dimension(0), 4);
        assert_eq!(complex.count_at_dimension(1), 3);
        assert_eq!(complex.count_at_dimension(2), 1);
        assert_eq!(complex.count_at_dimension(3), 0);
    }

    #[test]
    fn test_frontier_complex_filtration_range() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let (min, max) = complex.filtration_range().unwrap();
        assert_eq!(min, 0);
        assert_eq!(max, 600_000);
    }

    #[test]
    fn test_frontier_complex_serde_roundtrip() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let json = serde_json::to_string(&complex).unwrap();
        let back: FrontierComplex = serde_json::from_str(&json).unwrap();
        assert_eq!(complex, back);
    }

    #[test]
    fn test_frontier_complex_display() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let d = complex.to_string();
        assert!(d.contains("FrontierComplex"));
        assert!(d.contains("simplices=8"));
    }

    // -----------------------------------------------------------------------
    // PersistencePair tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_persistence_pair_is_essential() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: u64::MAX,
            dimension: 0,
            generator_simplex: "v0".to_string(),
            killer_simplex: None,
            persistence_millionths: u64::MAX,
        };
        assert!(pair.is_essential());
    }

    #[test]
    fn test_persistence_pair_not_essential() {
        let pair = PersistencePair {
            birth_filtration_millionths: 100,
            death_filtration_millionths: 500,
            dimension: 0,
            generator_simplex: "v0".to_string(),
            killer_simplex: Some("e01".to_string()),
            persistence_millionths: 400,
        };
        assert!(!pair.is_essential());
    }

    #[test]
    fn test_persistence_pair_serde_roundtrip() {
        let pair = PersistencePair {
            birth_filtration_millionths: 100_000,
            death_filtration_millionths: 500_000,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 400_000,
        };
        let json = serde_json::to_string(&pair).unwrap();
        let back: PersistencePair = serde_json::from_str(&json).unwrap();
        assert_eq!(pair, back);
    }

    #[test]
    fn test_persistence_pair_display_finite() {
        let pair = PersistencePair {
            birth_filtration_millionths: 100,
            death_filtration_millionths: 500,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 400,
        };
        let d = pair.to_string();
        assert!(d.contains("dim=1"));
        assert!(d.contains("birth=100"));
        assert!(d.contains("death=500"));
    }

    #[test]
    fn test_persistence_pair_display_essential() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: u64::MAX,
            dimension: 0,
            generator_simplex: "v0".to_string(),
            killer_simplex: None,
            persistence_millionths: u64::MAX,
        };
        let d = pair.to_string();
        assert!(d.contains("death=inf"));
    }

    // -----------------------------------------------------------------------
    // compute_persistence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_persistence_standard_complex() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        assert!(!diagram.pairs.is_empty());
        // Should have pairs at dimension 0 (vertices vs edges).
        let dim0_count = diagram.count_at_dimension(0);
        assert!(dim0_count > 0, "expected dimension-0 pairs");
    }

    #[test]
    fn test_compute_persistence_empty_complex_error() {
        let complex = FrontierComplex {
            complex_id: "empty".to_string(),
            epoch: SecurityEpoch::GENESIS,
            simplices: vec![],
            max_dimension: 0,
            vertex_count: 0,
            content_hash: ContentHash::compute(b""),
        };
        let result = compute_persistence(&complex);
        assert_eq!(result, Err(CartographyError::EmptyComplex));
    }

    #[test]
    fn test_compute_persistence_single_vertex_essential() {
        let simplices = vec![make_vertex("v0", "a", 0)];
        let complex = build_complex(simplices).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        // One vertex, no edges => one essential dim-0 pair.
        assert_eq!(diagram.pairs.len(), 1);
        assert!(diagram.pairs[0].is_essential());
        assert_eq!(diagram.pairs[0].dimension, 0);
    }

    #[test]
    fn test_compute_persistence_total_persistence_finite() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let tp = total_persistence(&diagram);
        assert_eq!(tp, diagram.total_persistence_millionths);
    }

    #[test]
    fn test_persistence_diagram_serde_roundtrip() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let json = serde_json::to_string(&diagram).unwrap();
        let back: PersistenceDiagram = serde_json::from_str(&json).unwrap();
        assert_eq!(diagram, back);
    }

    #[test]
    fn test_persistence_diagram_max_persistence() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let max_p = diagram.max_persistence();
        // Max persistence must be <= total persistence (since it's one pair).
        assert!(max_p <= diagram.total_persistence_millionths);
    }

    #[test]
    fn test_persistence_diagram_essential_count() {
        let simplices = vec![make_vertex("v0", "a", 0), make_vertex("v1", "b", 100_000)];
        let complex = build_complex(simplices).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        // Two vertices, no edges: both should be essential dim-0 pairs.
        assert_eq!(diagram.essential_count(), 2);
    }

    #[test]
    fn test_persistence_diagram_display() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let d = diagram.to_string();
        assert!(d.contains("PersistenceDiagram"));
    }

    // -----------------------------------------------------------------------
    // HoleSignificance / classify_hole tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_hole_structural_for_essential() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: u64::MAX,
            dimension: 0,
            generator_simplex: "v0".to_string(),
            killer_simplex: None,
            persistence_millionths: u64::MAX,
        };
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::Structural
        );
    }

    #[test]
    fn test_classify_hole_noise_low_samples() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 500_000,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 500_000,
        };
        // sample_count < MIN_MEANINGFUL_SAMPLES => noise.
        assert_eq!(
            classify_hole(&pair, 50_000, 5),
            HoleSignificance::SamplingNoise
        );
    }

    #[test]
    fn test_classify_hole_noise_below_threshold() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 10_000,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 10_000,
        };
        // persistence 10_000 < threshold 50_000 => noise.
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::SamplingNoise
        );
    }

    #[test]
    fn test_classify_hole_persistent_above_double_threshold() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 200_000,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 200_000,
        };
        // persistence 200_000 >= threshold*2=100_000 => persistent.
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::Persistent
        );
    }

    #[test]
    fn test_classify_hole_transient_between_thresholds() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 70_000,
            dimension: 1,
            generator_simplex: "e01".to_string(),
            killer_simplex: Some("t012".to_string()),
            persistence_millionths: 70_000,
        };
        // persistence 70_000 >= 50_000 but < 100_000 => transient.
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::Transient
        );
    }

    #[test]
    fn test_hole_significance_is_actionable() {
        assert!(HoleSignificance::Persistent.is_actionable());
        assert!(HoleSignificance::Structural.is_actionable());
        assert!(!HoleSignificance::Transient.is_actionable());
        assert!(!HoleSignificance::SamplingNoise.is_actionable());
    }

    #[test]
    fn test_hole_significance_display() {
        assert_eq!(HoleSignificance::Persistent.to_string(), "persistent");
        assert_eq!(HoleSignificance::Transient.to_string(), "transient");
        assert_eq!(
            HoleSignificance::SamplingNoise.to_string(),
            "sampling_noise"
        );
        assert_eq!(HoleSignificance::Structural.to_string(), "structural");
    }

    #[test]
    fn test_hole_significance_serde_roundtrip() {
        let variants = vec![
            HoleSignificance::Persistent,
            HoleSignificance::Transient,
            HoleSignificance::SamplingNoise,
            HoleSignificance::Structural,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: HoleSignificance = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -----------------------------------------------------------------------
    // FrontierHole tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_frontier_hole_seal_deterministic() {
        let mut h1 = FrontierHole {
            hole_id: "h0".to_string(),
            dimension: 1,
            significance: HoleSignificance::Persistent,
            persistence_millionths: 200_000,
            representative_cycle: vec!["e01".to_string()],
            affected_programs: vec!["prog_a".to_string()],
            content_hash: ContentHash::compute(b""),
        };
        let mut h2 = h1.clone();
        h1.seal();
        h2.seal();
        assert_eq!(h1.content_hash, h2.content_hash);
    }

    #[test]
    fn test_frontier_hole_display() {
        let h = FrontierHole {
            hole_id: "h0".to_string(),
            dimension: 1,
            significance: HoleSignificance::Persistent,
            persistence_millionths: 200_000,
            representative_cycle: vec!["e01".to_string()],
            affected_programs: vec!["prog_a".to_string(), "prog_b".to_string()],
            content_hash: ContentHash::compute(b""),
        };
        let d = h.to_string();
        assert!(d.contains("h0"));
        assert!(d.contains("persistent"));
        assert!(d.contains("programs=2"));
    }

    #[test]
    fn test_frontier_hole_serde_roundtrip() {
        let mut h = FrontierHole {
            hole_id: "h0".to_string(),
            dimension: 1,
            significance: HoleSignificance::Transient,
            persistence_millionths: 70_000,
            representative_cycle: vec!["e01".to_string(), "e12".to_string()],
            affected_programs: vec!["prog_x".to_string()],
            content_hash: ContentHash::compute(b""),
        };
        h.seal();
        let json = serde_json::to_string(&h).unwrap();
        let back: FrontierHole = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    // -----------------------------------------------------------------------
    // HoleLedger / build_hole_ledger tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hole_ledger_from_standard_complex() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(5), &diagram, 50_000, 100);
        assert_eq!(ledger.epoch, SecurityEpoch::from_raw(5));
        assert_eq!(ledger.holes.len(), diagram.pairs.len());
        assert_eq!(
            ledger.persistent_count
                + ledger.noise_count
                + ledger.transient_count()
                + ledger.structural_count(),
            ledger.holes.len() as u64
        );
    }

    #[test]
    fn test_build_hole_ledger_significance_threshold_stored() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::GENESIS, &diagram, 42_000, 50);
        assert_eq!(ledger.significance_threshold_millionths, 42_000);
    }

    #[test]
    fn test_hole_ledger_serde_roundtrip() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: HoleLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn test_hole_ledger_display() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let d = ledger.to_string();
        assert!(d.contains("HoleLedger"));
        assert!(d.contains("epoch="));
    }

    // -----------------------------------------------------------------------
    // filter_significant_holes tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_significant_holes_includes_persistent_and_structural() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let sig = filter_significant_holes(&ledger);
        for h in &sig {
            assert!(h.significance.is_actionable());
        }
    }

    #[test]
    fn test_filter_significant_holes_excludes_noise_and_transient() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let sig = filter_significant_holes(&ledger);
        for h in &sig {
            assert_ne!(h.significance, HoleSignificance::SamplingNoise);
            assert_ne!(h.significance, HoleSignificance::Transient);
        }
    }

    // -----------------------------------------------------------------------
    // total_persistence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_total_persistence_matches_diagram() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let tp = total_persistence(&diagram);
        assert_eq!(tp, diagram.total_persistence_millionths);
    }

    #[test]
    fn test_total_persistence_excludes_essential() {
        // Two vertices only -> essential pairs only -> total = 0.
        let simplices = vec![make_vertex("v0", "a", 0), make_vertex("v1", "b", 100_000)];
        let complex = build_complex(simplices).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        assert_eq!(total_persistence(&diagram), 0);
    }

    // -----------------------------------------------------------------------
    // euler_characteristic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_euler_characteristic_standard_complex() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        // 4 vertices - 3 edges + 1 triangle = 2
        let chi = euler_characteristic(&complex);
        assert_eq!(chi, 2);
    }

    #[test]
    fn test_euler_characteristic_single_vertex() {
        let complex = build_complex(vec![make_vertex("v0", "a", 0)]).unwrap();
        assert_eq!(euler_characteristic(&complex), 1);
    }

    // -----------------------------------------------------------------------
    // bottleneck_distance_approx tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bottleneck_distance_same_diagram_is_zero() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let dist = bottleneck_distance_approx(&diagram, &diagram);
        assert_eq!(dist, Some(0));
    }

    #[test]
    fn test_bottleneck_distance_different_sizes_none() {
        let c1 = build_complex(vec![make_vertex("v0", "a", 0)]).unwrap();
        let d1 = compute_persistence(&c1).unwrap();
        let c2 = build_complex(standard_complex_simplices()).unwrap();
        let d2 = compute_persistence(&c2).unwrap();
        assert!(bottleneck_distance_approx(&d1, &d2).is_none());
    }

    // -----------------------------------------------------------------------
    // stability_score tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stability_score_empty_ledger() {
        let ledger = HoleLedger {
            ledger_id: "empty".to_string(),
            epoch: SecurityEpoch::GENESIS,
            holes: vec![],
            persistent_count: 0,
            noise_count: 0,
            significance_threshold_millionths: 50_000,
            content_hash: ContentHash::compute(b""),
        };
        assert_eq!(stability_score(&ledger), 0);
    }

    #[test]
    fn test_stability_score_standard_complex() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let score = stability_score(&ledger);
        // Score is in millionths, should be <= MILLIONTHS.
        assert!(score <= MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // ledger_summary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ledger_summary_counts_consistent() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(3), &diagram, 50_000, 100);
        let summary = ledger_summary(&ledger);
        assert_eq!(
            summary.persistent_holes
                + summary.transient_holes
                + summary.noise_holes
                + summary.structural_holes,
            summary.total_holes
        );
        assert_eq!(summary.epoch, SecurityEpoch::from_raw(3));
    }

    #[test]
    fn test_ledger_summary_display() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let summary = ledger_summary(&ledger);
        let d = summary.to_string();
        assert!(d.contains("LedgerSummary"));
    }

    #[test]
    fn test_ledger_summary_serde_roundtrip() {
        let complex = build_complex(standard_complex_simplices()).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(SecurityEpoch::from_raw(1), &diagram, 50_000, 100);
        let summary = ledger_summary(&ledger);
        let json = serde_json::to_string(&summary).unwrap();
        let back: LedgerSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -----------------------------------------------------------------------
    // Manifest test
    // -----------------------------------------------------------------------

    #[test]
    fn test_franken_engine_frontier_manifest() {
        let ledger = franken_engine_frontier_manifest();
        assert_eq!(ledger.epoch, SecurityEpoch::from_raw(1));
        assert!(!ledger.holes.is_empty());
        // The manifest should have at least one significant hole.
        let sig = filter_significant_holes(&ledger);
        assert!(!sig.is_empty(), "manifest should contain significant holes");
    }

    #[test]
    fn test_franken_engine_frontier_manifest_deterministic() {
        let l1 = franken_engine_frontier_manifest();
        let l2 = franken_engine_frontier_manifest();
        assert_eq!(l1.content_hash, l2.content_hash);
        assert_eq!(l1.holes.len(), l2.holes.len());
    }

    // -----------------------------------------------------------------------
    // CartographyError tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cartography_error_display() {
        assert_eq!(
            CartographyError::EmptyComplex.to_string(),
            "complex contains no simplices"
        );
        assert_eq!(
            CartographyError::InvalidSimplex.to_string(),
            "simplex structure is invalid"
        );
        assert_eq!(
            CartographyError::FiltrationViolation.to_string(),
            "filtration ordering violation: face appears after parent"
        );
        assert_eq!(
            CartographyError::DiagramInconsistent.to_string(),
            "persistence diagram is inconsistent"
        );
        let internal = CartographyError::InternalError("oops".to_string());
        assert_eq!(internal.to_string(), "internal error: oops");
    }

    #[test]
    fn test_cartography_error_serde_roundtrip() {
        let errors = vec![
            CartographyError::EmptyComplex,
            CartographyError::InvalidSimplex,
            CartographyError::FiltrationViolation,
            CartographyError::DiagramInconsistent,
            CartographyError::InternalError("test".to_string()),
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: CartographyError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert_eq!(BEAD_ID, "bd-1lsy.9.9.1");
        assert_eq!(COMPONENT, "frontier_complex_cartography");
        assert_eq!(POLICY_ID, "RGC-809A");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Edge cases and advanced tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_complex_edges_only_with_vertices() {
        // Two vertices and one edge.
        let simplices = vec![
            make_vertex("v0", "x", 0),
            make_vertex("v1", "y", 0),
            make_edge("e01", "x", "y", 100_000),
        ];
        let complex = build_complex(simplices).unwrap();
        assert_eq!(complex.vertex_count, 2);
        assert_eq!(complex.max_dimension, 1);
    }

    #[test]
    fn test_classify_hole_exact_threshold() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 50_000,
            dimension: 1,
            generator_simplex: "e".to_string(),
            killer_simplex: Some("t".to_string()),
            persistence_millionths: 50_000,
        };
        // persistence == threshold => transient (>= threshold but < 2*threshold).
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::Transient
        );
    }

    #[test]
    fn test_classify_hole_exact_double_threshold() {
        let pair = PersistencePair {
            birth_filtration_millionths: 0,
            death_filtration_millionths: 100_000,
            dimension: 1,
            generator_simplex: "e".to_string(),
            killer_simplex: Some("t".to_string()),
            persistence_millionths: 100_000,
        };
        // persistence == 2*threshold => persistent.
        assert_eq!(
            classify_hole(&pair, 50_000, 100),
            HoleSignificance::Persistent
        );
    }

    #[test]
    fn test_generate_faces_triangle() {
        let verts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let faces = generate_faces(&verts);
        assert_eq!(faces.len(), 3);
        assert_eq!(faces[0], vec!["b".to_string(), "c".to_string()]);
        assert_eq!(faces[1], vec!["a".to_string(), "c".to_string()]);
        assert_eq!(faces[2], vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_generate_faces_edge() {
        let verts = vec!["x".to_string(), "y".to_string()];
        let faces = generate_faces(&verts);
        assert_eq!(faces.len(), 2);
        assert_eq!(faces[0], vec!["y".to_string()]);
        assert_eq!(faces[1], vec!["x".to_string()]);
    }

    #[test]
    fn test_higher_dim_simplex() {
        let s = Simplex {
            simplex_id: "tet-0123".to_string(),
            dimension: SimplexDimension::Tetrahedron,
            vertices: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            filtration_value_millionths: MILLIONTHS,
        };
        assert!(s.validate().is_ok());
        assert_eq!(s.dimension.as_u32(), 3);
    }

    #[test]
    fn test_complex_with_no_edges_all_essential() {
        // Three isolated vertices: all dim-0 pairs should be essential.
        let simplices = vec![
            make_vertex("v0", "a", 0),
            make_vertex("v1", "b", 100_000),
            make_vertex("v2", "c", 200_000),
        ];
        let complex = build_complex(simplices).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        assert_eq!(diagram.essential_count(), 3);
        assert_eq!(diagram.total_persistence_millionths, 0);
    }

    #[test]
    fn test_filter_significant_all_noise() {
        // Threshold so high that all finite pairs are noise.
        let simplices = vec![
            make_vertex("v0", "a", 0),
            make_vertex("v1", "b", 0),
            make_edge("e01", "a", "b", 10_000),
        ];
        let complex = build_complex(simplices).unwrap();
        let diagram = compute_persistence(&complex).unwrap();
        let ledger = build_hole_ledger(
            SecurityEpoch::GENESIS,
            &diagram,
            MILLIONTHS, // very high threshold
            100,
        );
        let sig = filter_significant_holes(&ledger);
        // Only essential (structural) holes should survive.
        for h in &sig {
            assert_eq!(h.significance, HoleSignificance::Structural);
        }
    }
}
