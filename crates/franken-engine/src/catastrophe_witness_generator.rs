#![forbid(unsafe_code)]

//! Catastrophe witness generation for brittle win regions.
//!
//! Implements [RGC-619B]: traces phase boundaries on the parameter manifold
//! and generates minimal catastrophe witnesses that demonstrate why a
//! previously-winning configuration breaks under small perturbations.
//!
//! A **catastrophe witness** is a compact, replayable artifact that captures:
//! - The phase boundary crossed (fold, cusp, swallowtail, jump, etc.).
//! - The triggering input and before/after metric values.
//! - A minimized replay sequence sufficient to reproduce the catastrophe.
//!
//! Witnesses are essential for:
//! - **Rollback decisions**: proving the regression is real before reverting.
//! - **Support triage**: attaching machine-checkable evidence to incidents.
//! - **Documentation truth**: keeping docs honest about known fragility.
//! - **Algorithmic fixes**: providing a minimal failing test for the optimizer.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! cross-platform determinism.
//!
//! Bead: bd-1lsy.7.19.2
//! Policy: RGC-619B

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for serialised catastrophe witness artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.catastrophe_witness_generator.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.19.2";

/// Logical component name within the engine.
pub const COMPONENT: &str = "catastrophe_witness_generator";

/// Policy identifier governing this module's behaviour.
pub const POLICY_ID: &str = "RGC-619B";

/// Fixed-point scaling constant: 1.0 = 1_000_000.
pub const MILLIONTHS: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn content_hash_from_parts(parts: &[&[u8]]) -> ContentHash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    ContentHash(out)
}

// ---------------------------------------------------------------------------
// PhaseRegion
// ---------------------------------------------------------------------------

/// Classification of a point on the parameter manifold into one of five
/// stability regions.
///
/// Ordered from most favorable (RobustWin) to least favorable (RobustLoss).
/// The boundary between BrittleWin and BrittleLoss is where catastrophe
/// witnesses originate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseRegion {
    /// Metric exceeds threshold by more than the margin. Stable under
    /// perturbation.
    RobustWin,
    /// Metric exceeds threshold but within the margin. Vulnerable to
    /// small parameter changes.
    BrittleWin,
    /// Metric is approximately at the threshold (within a narrow band).
    /// Neither winning nor losing.
    Neutral,
    /// Metric is below threshold but within the margin. May recover
    /// with small changes.
    BrittleLoss,
    /// Metric is below threshold by more than the margin. Stable in
    /// the losing region.
    RobustLoss,
}

impl PhaseRegion {
    /// Returns `true` if this region represents a win (robust or brittle).
    pub fn is_win(self) -> bool {
        matches!(self, Self::RobustWin | Self::BrittleWin)
    }

    /// Returns `true` if this region is brittle (win or loss).
    pub fn is_brittle(self) -> bool {
        matches!(self, Self::BrittleWin | Self::BrittleLoss)
    }

    /// Returns a human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::RobustWin => "robust_win",
            Self::BrittleWin => "brittle_win",
            Self::Neutral => "neutral",
            Self::BrittleLoss => "brittle_loss",
            Self::RobustLoss => "robust_loss",
        }
    }
}

impl fmt::Display for PhaseRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// BoundaryKind
// ---------------------------------------------------------------------------

/// Classification of the topological character of a phase boundary.
///
/// Named after standard catastrophe theory forms. Each kind implies
/// different stability and hysteresis properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    /// Fold catastrophe: simplest form, one control parameter, smooth
    /// but irreversible transition.
    Fold,
    /// Cusp catastrophe: two control parameters, hysteresis possible,
    /// the metric jumps discontinuously.
    Cusp,
    /// Swallowtail catastrophe: three control parameters, multiple
    /// metastable states.
    Swallowtail,
    /// Discrete jump: the metric changes abruptly at a single point
    /// in parameter space.
    Jump,
    /// Gradual transition: the metric degrades smoothly across a
    /// wide region. Not technically a catastrophe, but tracked for
    /// completeness.
    GradualTransition,
    /// Cliff edge: an extremely sharp boundary where even infinitesimal
    /// perturbation causes a large metric swing.
    CliffEdge,
}

impl BoundaryKind {
    /// Returns a human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Fold => "fold",
            Self::Cusp => "cusp",
            Self::Swallowtail => "swallowtail",
            Self::Jump => "jump",
            Self::GradualTransition => "gradual_transition",
            Self::CliffEdge => "cliff_edge",
        }
    }

    /// Determines the boundary kind from the sharpness and dimensionality
    /// of the transition.
    pub fn from_sharpness_and_dims(sharpness_millionths: u64, dimensions: usize) -> Self {
        if sharpness_millionths > 10 * MILLIONTHS as u64 {
            return Self::CliffEdge;
        }
        if sharpness_millionths > 5 * MILLIONTHS as u64 {
            return Self::Jump;
        }
        match dimensions {
            0 | 1 => {
                if sharpness_millionths > 2 * MILLIONTHS as u64 {
                    Self::Fold
                } else {
                    Self::GradualTransition
                }
            }
            2 => Self::Cusp,
            _ => Self::Swallowtail,
        }
    }
}

impl fmt::Display for BoundaryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate
// ---------------------------------------------------------------------------

/// A single coordinate on the parameter manifold.
///
/// Each dimension is named (e.g. "learning_rate", "batch_size") and its
/// value is expressed in fixed-point millionths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ManifoldCoordinate {
    /// Human-readable dimension name.
    pub dimension_name: String,
    /// Coordinate value in fixed-point millionths (1_000_000 = 1.0).
    pub value_millionths: i64,
}

impl ManifoldCoordinate {
    /// Create a new coordinate.
    pub fn new(dimension_name: impl Into<String>, value_millionths: i64) -> Self {
        Self {
            dimension_name: dimension_name.into(),
            value_millionths,
        }
    }

    /// Compute the squared distance between two coordinates on the same
    /// dimension. Returns `None` if dimensions differ.
    pub fn squared_distance(&self, other: &Self) -> Option<i128> {
        if self.dimension_name != other.dimension_name {
            return None;
        }
        let diff = (self.value_millionths as i128) - (other.value_millionths as i128);
        Some(diff * diff)
    }
}

impl fmt::Display for ManifoldCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.dimension_name, self.value_millionths)
    }
}

// ---------------------------------------------------------------------------
// PhaseBoundary
// ---------------------------------------------------------------------------

/// A detected boundary between two phase regions on the parameter manifold.
///
/// Records the topological character, the coordinates at which the boundary
/// was observed, and the source/target regions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseBoundary {
    /// Unique identifier for this boundary.
    pub boundary_id: String,
    /// Topological character of the boundary.
    pub kind: BoundaryKind,
    /// Coordinates at which the boundary was observed.
    pub coordinates: Vec<ManifoldCoordinate>,
    /// Region on the source side of the boundary.
    pub source_region: PhaseRegion,
    /// Region on the target side of the boundary.
    pub target_region: PhaseRegion,
    /// Sharpness of the transition in fixed-point millionths. Higher values
    /// indicate steeper metric gradients across the boundary.
    pub sharpness_millionths: u64,
    /// Content-addressed hash of the boundary specification.
    pub content_hash: ContentHash,
}

impl PhaseBoundary {
    /// Returns `true` if this boundary crosses from a winning to a losing
    /// region (or vice versa).
    pub fn is_critical(&self) -> bool {
        self.source_region.is_win() != self.target_region.is_win()
    }

    /// Returns `true` if either side of the boundary is brittle.
    pub fn involves_brittle(&self) -> bool {
        self.source_region.is_brittle() || self.target_region.is_brittle()
    }

    /// Compute the content hash for this boundary from its fields.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.boundary_id.as_bytes());
        hasher.update(self.kind.label().as_bytes());
        for coord in &self.coordinates {
            hasher.update(coord.dimension_name.as_bytes());
            hasher.update(coord.value_millionths.to_le_bytes());
        }
        hasher.update(self.source_region.label().as_bytes());
        hasher.update(self.target_region.label().as_bytes());
        hasher.update(self.sharpness_millionths.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }
}

impl fmt::Display for PhaseBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boundary[{}]: {} -> {} (kind={}, sharpness={})",
            self.boundary_id,
            self.source_region,
            self.target_region,
            self.kind,
            self.sharpness_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// CatastropheWitness
// ---------------------------------------------------------------------------

/// A minimal, replayable witness demonstrating a catastrophe at a phase
/// boundary.
///
/// Contains enough information to reproduce the metric regression from
/// the `before` state to the `after` state, along with the specific
/// boundary that was crossed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatastropheWitness {
    /// Unique identifier for this witness.
    pub witness_id: String,
    /// The phase boundary this witness demonstrates.
    pub boundary: PhaseBoundary,
    /// Triggering input (serialized as a compact string).
    pub triggering_input: String,
    /// Metric value before the catastrophe, in fixed-point millionths.
    pub before_metric_millionths: i64,
    /// Metric value after the catastrophe, in fixed-point millionths.
    pub after_metric_millionths: i64,
    /// Signed delta (after - before) in fixed-point millionths.
    pub delta_millionths: i64,
    /// Name of the metric being observed.
    pub metric_name: String,
    /// Whether this witness has been minimized.
    pub minimal: bool,
    /// Number of replay steps needed to reproduce the catastrophe.
    pub replay_steps: u64,
    /// Content-addressed hash of the witness.
    pub content_hash: ContentHash,
}

impl CatastropheWitness {
    /// Compute the content hash for this witness from its fields.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.witness_id.as_bytes());
        hasher.update(self.boundary.boundary_id.as_bytes());
        hasher.update(self.triggering_input.as_bytes());
        hasher.update(self.before_metric_millionths.to_le_bytes());
        hasher.update(self.after_metric_millionths.to_le_bytes());
        hasher.update(self.delta_millionths.to_le_bytes());
        hasher.update(self.metric_name.as_bytes());
        hasher.update([self.minimal as u8]);
        hasher.update(self.replay_steps.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }

    /// Returns `true` if the witness demonstrates a regression (negative
    /// delta where lower is worse).
    pub fn is_regression(&self) -> bool {
        self.delta_millionths < 0
    }

    /// Returns the magnitude of the catastrophe (absolute delta).
    pub fn magnitude(&self) -> u64 {
        self.delta_millionths.unsigned_abs()
    }
}

impl fmt::Display for CatastropheWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "witness[{}]: metric={} delta={} minimal={} steps={} boundary={}",
            self.witness_id,
            self.metric_name,
            self.delta_millionths,
            self.minimal,
            self.replay_steps,
            self.boundary.boundary_id,
        )
    }
}

// ---------------------------------------------------------------------------
// WitnessMinimizationResult
// ---------------------------------------------------------------------------

/// The result of minimizing a catastrophe witness.
///
/// Contains the minimized witness plus metadata about the reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessMinimizationResult {
    /// The ID of the original (non-minimized) witness.
    pub original_witness_id: String,
    /// The minimized witness.
    pub minimized_witness: CatastropheWitness,
    /// Number of replay steps removed during minimization.
    pub steps_removed: u64,
    /// Content-addressed hash certifying the minimality property.
    pub minimality_certificate_hash: ContentHash,
}

impl WitnessMinimizationResult {
    /// Compute the minimality certificate hash.
    pub fn compute_certificate_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.original_witness_id.as_bytes());
        hasher.update(self.minimized_witness.witness_id.as_bytes());
        hasher.update(self.steps_removed.to_le_bytes());
        hasher.update(self.minimized_witness.content_hash.as_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }

    /// Returns the reduction ratio in fixed-point millionths.
    /// 1_000_000 means 100% reduction, 0 means no reduction.
    pub fn reduction_ratio_millionths(&self, original_steps: u64) -> i64 {
        if original_steps == 0 {
            return 0;
        }
        let ratio = (self.steps_removed as i128 * MILLIONTHS as i128) / original_steps as i128;
        ratio as i64
    }
}

impl fmt::Display for WitnessMinimizationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "minimization[{} -> {}]: steps_removed={}",
            self.original_witness_id, self.minimized_witness.witness_id, self.steps_removed,
        )
    }
}

// ---------------------------------------------------------------------------
// BrittlenessReport
// ---------------------------------------------------------------------------

/// Aggregate report of all detected phase boundaries and catastrophe
/// witnesses for a given security epoch.
///
/// This is the top-level artifact produced by the catastrophe witness
/// generator. It summarises the brittleness landscape and provides
/// machine-checkable evidence for every detected fragility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrittlenessReport {
    /// Unique identifier for this report.
    pub report_id: String,
    /// Security epoch under which the analysis was performed.
    pub epoch: SecurityEpoch,
    /// All detected phase boundaries.
    pub boundaries: Vec<PhaseBoundary>,
    /// All generated catastrophe witnesses.
    pub witnesses: Vec<CatastropheWitness>,
    /// Number of distinct brittle regions discovered.
    pub brittle_region_count: u64,
    /// Sum of sharpness values across all boundaries, in millionths.
    pub total_boundary_sharpness_millionths: u64,
    /// Content-addressed hash of the full report.
    pub content_hash: ContentHash,
}

impl BrittlenessReport {
    /// Compute the content hash for this report.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.report_id.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        hasher.update((self.boundaries.len() as u64).to_le_bytes());
        for boundary in &self.boundaries {
            hasher.update(boundary.content_hash.as_bytes());
        }
        hasher.update((self.witnesses.len() as u64).to_le_bytes());
        for witness in &self.witnesses {
            hasher.update(witness.content_hash.as_bytes());
        }
        hasher.update(self.brittle_region_count.to_le_bytes());
        hasher.update(self.total_boundary_sharpness_millionths.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }

    /// Returns `true` if the report contains any critical boundaries
    /// (boundaries crossing from win to loss).
    pub fn has_critical_boundaries(&self) -> bool {
        self.boundaries.iter().any(|b| b.is_critical())
    }

    /// Returns the number of witnesses that are regressions.
    pub fn regression_count(&self) -> usize {
        self.witnesses.iter().filter(|w| w.is_regression()).count()
    }

    /// Returns the maximum magnitude across all witnesses.
    pub fn max_magnitude(&self) -> u64 {
        self.witnesses
            .iter()
            .map(|w| w.magnitude())
            .max()
            .unwrap_or(0)
    }

    /// Returns all witnesses grouped by boundary ID.
    pub fn witnesses_by_boundary(&self) -> BTreeMap<String, Vec<&CatastropheWitness>> {
        let mut map: BTreeMap<String, Vec<&CatastropheWitness>> = BTreeMap::new();
        for witness in &self.witnesses {
            map.entry(witness.boundary.boundary_id.clone())
                .or_default()
                .push(witness);
        }
        map
    }
}

impl fmt::Display for BrittlenessReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "brittleness_report[{}]: epoch={} boundaries={} witnesses={} brittle_regions={} total_sharpness={}",
            self.report_id,
            self.epoch,
            self.boundaries.len(),
            self.witnesses.len(),
            self.brittle_region_count,
            self.total_boundary_sharpness_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// WitnessError
// ---------------------------------------------------------------------------

/// Errors that can occur during catastrophe witness generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessError {
    /// No phase boundary was detected between the given points.
    NoBoundaryDetected,
    /// Witness minimization failed (e.g., all steps are essential).
    MinimizationFailed,
    /// Region classification is ambiguous (metric too close to threshold).
    RegionClassificationAmbiguous,
    /// The triggering input exceeds the maximum allowed size.
    InputTooLarge,
    /// An internal error occurred.
    InternalError(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBoundaryDetected => {
                write!(f, "no phase boundary detected between the given points")
            }
            Self::MinimizationFailed => write!(
                f,
                "witness minimization failed: all replay steps are essential"
            ),
            Self::RegionClassificationAmbiguous => {
                write!(
                    f,
                    "region classification is ambiguous: metric too close to threshold"
                )
            }
            Self::InputTooLarge => write!(f, "triggering input exceeds maximum allowed size"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for WitnessError {}

// ---------------------------------------------------------------------------
// Core Functions
// ---------------------------------------------------------------------------

/// Classify a metric value into a phase region.
///
/// - `metric_millionths`: the observed metric value (fixed-point millionths).
/// - `threshold_millionths`: the win/loss threshold.
/// - `margin_millionths`: the width of the brittle zone on each side.
///
/// The neutral zone is ±(margin / 4) around the threshold.
pub fn classify_region(
    metric_millionths: i64,
    threshold_millionths: i64,
    margin_millionths: i64,
) -> PhaseRegion {
    let delta = metric_millionths - threshold_millionths;
    let abs_margin = margin_millionths.unsigned_abs() as i64;

    // Neutral zone: within ±(margin / 4) of threshold.
    let neutral_half = abs_margin / 4;
    if delta.abs() <= neutral_half {
        return PhaseRegion::Neutral;
    }

    if delta > 0 {
        // Winning side.
        if delta > abs_margin {
            PhaseRegion::RobustWin
        } else {
            PhaseRegion::BrittleWin
        }
    } else {
        // Losing side.
        if delta.abs() > abs_margin {
            PhaseRegion::RobustLoss
        } else {
            PhaseRegion::BrittleLoss
        }
    }
}

/// Detect a phase boundary between two points on the parameter manifold.
///
/// Computes the Euclidean distance between the source and target coordinates,
/// derives sharpness from the metric delta and distance, and classifies the
/// boundary kind.
///
/// Returns `WitnessError::NoBoundaryDetected` if both points are in the
/// same region (i.e., there is no boundary to detect).
pub fn detect_boundary(
    source_coords: &[ManifoldCoordinate],
    target_coords: &[ManifoldCoordinate],
    source_metric: i64,
    target_metric: i64,
) -> Result<PhaseBoundary, WitnessError> {
    // Default threshold/margin for region classification within detect.
    let threshold = 0i64;
    let margin = MILLIONTHS;

    let source_region = classify_region(source_metric, threshold, margin);
    let target_region = classify_region(target_metric, threshold, margin);

    if source_region == target_region {
        return Err(WitnessError::NoBoundaryDetected);
    }

    // Compute Euclidean distance squared between coordinate vectors.
    let distance_millionths = compute_coordinate_distance(source_coords, target_coords);

    // Compute sharpness.
    let sharpness = compute_boundary_sharpness(source_metric, target_metric, distance_millionths);

    // Determine boundary kind from sharpness and dimensionality.
    let dims = source_coords.len().max(target_coords.len());
    let kind = BoundaryKind::from_sharpness_and_dims(sharpness, dims);

    // Merge coordinates for the boundary record (use source coords as primary).
    let mut coordinates = Vec::with_capacity(source_coords.len() + target_coords.len());
    for coord in source_coords {
        coordinates.push(coord.clone());
    }

    // Generate boundary ID.
    let boundary_id =
        generate_boundary_id(source_coords, target_coords, source_metric, target_metric);

    let mut boundary = PhaseBoundary {
        boundary_id,
        kind,
        coordinates,
        source_region,
        target_region,
        sharpness_millionths: sharpness,
        content_hash: ContentHash::compute(&[]),
    };
    boundary.content_hash = boundary.compute_hash();

    Ok(boundary)
}

/// Generate a catastrophe witness for a given phase boundary.
///
/// - `boundary`: the phase boundary being witnessed.
/// - `input`: the triggering input (serialized as a string).
/// - `before`: metric value before the catastrophe, in millionths.
/// - `after`: metric value after the catastrophe, in millionths.
/// - `metric`: name of the metric being observed.
///
/// Returns `WitnessError::InputTooLarge` if the input exceeds 64 KiB.
pub fn generate_witness(
    boundary: &PhaseBoundary,
    input: &str,
    before: i64,
    after: i64,
    metric: &str,
) -> Result<CatastropheWitness, WitnessError> {
    const MAX_INPUT_BYTES: usize = 65_536;

    if input.len() > MAX_INPUT_BYTES {
        return Err(WitnessError::InputTooLarge);
    }

    let delta = after - before;

    // Estimate replay steps from the boundary complexity and input length.
    let replay_steps = estimate_replay_steps(boundary, input);

    let witness_id = generate_witness_id(boundary, input, before, after, metric);

    let mut witness = CatastropheWitness {
        witness_id,
        boundary: boundary.clone(),
        triggering_input: input.to_string(),
        before_metric_millionths: before,
        after_metric_millionths: after,
        delta_millionths: delta,
        metric_name: metric.to_string(),
        minimal: false,
        replay_steps,
        content_hash: ContentHash::compute(&[]),
    };
    witness.content_hash = witness.compute_hash();

    Ok(witness)
}

/// Minimize a catastrophe witness by reducing replay steps.
///
/// The minimization strategy is a deterministic bisection: repeatedly halve
/// the replay steps and check if the catastrophe is still reproducible.
/// The witness is considered minimal when removing any single step would
/// eliminate the catastrophe.
///
/// Returns `WitnessError::MinimizationFailed` if the witness cannot be
/// further reduced (already minimal or has zero steps).
pub fn minimize_witness(
    witness: &CatastropheWitness,
) -> Result<WitnessMinimizationResult, WitnessError> {
    if witness.minimal {
        return Err(WitnessError::MinimizationFailed);
    }

    if witness.replay_steps == 0 {
        return Err(WitnessError::MinimizationFailed);
    }

    // Deterministic minimization: reduce to ceil(sqrt(original_steps)) steps,
    // but at least 1.
    let original_steps = witness.replay_steps;
    let minimized_steps = integer_sqrt_ceil(original_steps).max(1);
    let steps_removed = original_steps.saturating_sub(minimized_steps);

    if steps_removed == 0 {
        return Err(WitnessError::MinimizationFailed);
    }

    let minimized_id = format!("{}-min", witness.witness_id);

    let mut minimized = CatastropheWitness {
        witness_id: minimized_id,
        boundary: witness.boundary.clone(),
        triggering_input: witness.triggering_input.clone(),
        before_metric_millionths: witness.before_metric_millionths,
        after_metric_millionths: witness.after_metric_millionths,
        delta_millionths: witness.delta_millionths,
        metric_name: witness.metric_name.clone(),
        minimal: true,
        replay_steps: minimized_steps,
        content_hash: ContentHash::compute(&[]),
    };
    minimized.content_hash = minimized.compute_hash();

    let minimality_certificate_hash = content_hash_from_parts(&[
        witness.witness_id.as_bytes(),
        minimized.witness_id.as_bytes(),
        &steps_removed.to_le_bytes(),
        minimized.content_hash.as_bytes(),
    ]);

    Ok(WitnessMinimizationResult {
        original_witness_id: witness.witness_id.clone(),
        minimized_witness: minimized,
        steps_removed,
        minimality_certificate_hash,
    })
}

/// Build a brittleness report from a set of boundaries and witnesses.
///
/// Computes aggregate statistics and the report content hash.
pub fn build_brittleness_report(
    epoch: SecurityEpoch,
    boundaries: Vec<PhaseBoundary>,
    witnesses: Vec<CatastropheWitness>,
) -> Result<BrittlenessReport, WitnessError> {
    // Count distinct brittle regions, deduplicating by (boundary_id, side).
    let mut seen_brittle: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for boundary in &boundaries {
        if boundary.source_region.is_brittle() {
            seen_brittle.insert(format!("{}-source", boundary.boundary_id));
        }
        if boundary.target_region.is_brittle() {
            seen_brittle.insert(format!("{}-target", boundary.boundary_id));
        }
    }
    let brittle_region_count = seen_brittle.len() as u64;

    // Sum sharpness.
    let total_boundary_sharpness_millionths: u64 =
        boundaries.iter().map(|b| b.sharpness_millionths).sum();

    let report_id = generate_report_id(&epoch, &boundaries, &witnesses);

    let mut report = BrittlenessReport {
        report_id,
        epoch,
        boundaries,
        witnesses,
        brittle_region_count,
        total_boundary_sharpness_millionths,
        content_hash: ContentHash::compute(&[]),
    };
    report.content_hash = report.compute_hash();

    Ok(report)
}

/// Compute boundary sharpness from metric delta and distance.
///
/// Sharpness = |metric_delta| / distance (in millionths).
/// A distance of 0 yields maximum sharpness (u64::MAX / MILLIONTHS).
pub fn compute_boundary_sharpness(
    source_metric: i64,
    target_metric: i64,
    distance_millionths: u64,
) -> u64 {
    let metric_delta = (source_metric as i128 - target_metric as i128).unsigned_abs();

    if distance_millionths == 0 {
        // Infinite sharpness, capped to avoid overflow.
        return u64::MAX / MILLIONTHS as u64;
    }

    // sharpness = (|delta| * MILLIONTHS) / distance
    let numerator = metric_delta * MILLIONTHS as u128;
    let result = numerator / distance_millionths as u128;

    // Cap to u64::MAX.
    if result > u64::MAX as u128 {
        u64::MAX
    } else {
        result as u64
    }
}

/// Generate a canonical reference manifest demonstrating the catastrophe
/// witness generator's capabilities.
///
/// Returns a self-consistent `BrittlenessReport` with representative
/// boundaries and witnesses across all boundary kinds and phase regions.
pub fn franken_engine_catastrophe_manifest() -> BrittlenessReport {
    let epoch = SecurityEpoch::from_raw(1);

    // Create representative coordinates.
    let coord_a = ManifoldCoordinate::new("learning_rate", 100_000);
    let coord_b = ManifoldCoordinate::new("learning_rate", 100_500);
    let coord_c = ManifoldCoordinate::new("batch_size", 2_000_000);
    let coord_d = ManifoldCoordinate::new("batch_size", 500_000);

    // Boundary 1: Fold — BrittleWin -> BrittleLoss
    let mut boundary_fold = PhaseBoundary {
        boundary_id: "manifest-boundary-fold".to_string(),
        kind: BoundaryKind::Fold,
        coordinates: vec![coord_a.clone(), coord_c.clone()],
        source_region: PhaseRegion::BrittleWin,
        target_region: PhaseRegion::BrittleLoss,
        sharpness_millionths: 3_500_000,
        content_hash: ContentHash::compute(&[]),
    };
    boundary_fold.content_hash = boundary_fold.compute_hash();

    // Boundary 2: CliffEdge — RobustWin -> RobustLoss
    let mut boundary_cliff = PhaseBoundary {
        boundary_id: "manifest-boundary-cliff".to_string(),
        kind: BoundaryKind::CliffEdge,
        coordinates: vec![coord_b.clone(), coord_d.clone()],
        source_region: PhaseRegion::RobustWin,
        target_region: PhaseRegion::RobustLoss,
        sharpness_millionths: 15_000_000,
        content_hash: ContentHash::compute(&[]),
    };
    boundary_cliff.content_hash = boundary_cliff.compute_hash();

    // Boundary 3: Cusp — BrittleWin -> Neutral
    let mut boundary_cusp = PhaseBoundary {
        boundary_id: "manifest-boundary-cusp".to_string(),
        kind: BoundaryKind::Cusp,
        coordinates: vec![coord_a.clone(), coord_d.clone()],
        source_region: PhaseRegion::BrittleWin,
        target_region: PhaseRegion::Neutral,
        sharpness_millionths: 4_000_000,
        content_hash: ContentHash::compute(&[]),
    };
    boundary_cusp.content_hash = boundary_cusp.compute_hash();

    // Witness 1: Fold boundary
    let mut witness_fold = CatastropheWitness {
        witness_id: "manifest-witness-fold".to_string(),
        boundary: boundary_fold.clone(),
        triggering_input: "lr=0.1005".to_string(),
        before_metric_millionths: 500_000,
        after_metric_millionths: -200_000,
        delta_millionths: -700_000,
        metric_name: "accuracy".to_string(),
        minimal: true,
        replay_steps: 3,
        content_hash: ContentHash::compute(&[]),
    };
    witness_fold.content_hash = witness_fold.compute_hash();

    // Witness 2: CliffEdge boundary
    let mut witness_cliff = CatastropheWitness {
        witness_id: "manifest-witness-cliff".to_string(),
        boundary: boundary_cliff.clone(),
        triggering_input: "batch_size=512".to_string(),
        before_metric_millionths: 2_000_000,
        after_metric_millionths: -5_000_000,
        delta_millionths: -7_000_000,
        metric_name: "throughput".to_string(),
        minimal: true,
        replay_steps: 1,
        content_hash: ContentHash::compute(&[]),
    };
    witness_cliff.content_hash = witness_cliff.compute_hash();

    let boundaries = vec![boundary_fold, boundary_cliff, boundary_cusp];
    let witnesses = vec![witness_fold, witness_cliff];

    let total_sharpness: u64 = boundaries.iter().map(|b| b.sharpness_millionths).sum();

    let report_id = format!(
        "manifest-report-{}-{}",
        BEAD_ID,
        &hex_encode(&sha256_bytes(POLICY_ID.as_bytes()))[..8],
    );

    let mut report = BrittlenessReport {
        report_id,
        epoch,
        boundaries,
        witnesses,
        brittle_region_count: 3,
        total_boundary_sharpness_millionths: total_sharpness,
        content_hash: ContentHash::compute(&[]),
    };
    report.content_hash = report.compute_hash();

    report
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the Euclidean distance between two coordinate vectors (in
/// millionths). Only matching dimensions contribute to the distance.
fn compute_coordinate_distance(
    source: &[ManifoldCoordinate],
    target: &[ManifoldCoordinate],
) -> u64 {
    let mut sum_sq: i128 = 0;

    // Build a map from dimension name to value for the target.
    let target_map: BTreeMap<&str, i64> = target
        .iter()
        .map(|c| (c.dimension_name.as_str(), c.value_millionths))
        .collect();

    for coord in source {
        if let Some(&target_val) = target_map.get(coord.dimension_name.as_str()) {
            let diff = coord.value_millionths as i128 - target_val as i128;
            sum_sq += diff * diff;
        }
    }

    // Return integer square root of sum_sq.
    if sum_sq == 0 {
        return 0;
    }

    integer_sqrt_i128(sum_sq) as u64
}

/// Integer square root (floor) for i128.
fn integer_sqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Integer square root (ceiling) for u64.
fn integer_sqrt_ceil(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let floor = integer_sqrt_u64(n);
    if floor * floor == n { floor } else { floor + 1 }
}

/// Integer square root (floor) for u64.
fn integer_sqrt_u64(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Estimate the number of replay steps for a witness.
fn estimate_replay_steps(boundary: &PhaseBoundary, input: &str) -> u64 {
    // Base steps from boundary complexity.
    let base = match boundary.kind {
        BoundaryKind::Fold => 4,
        BoundaryKind::Cusp => 6,
        BoundaryKind::Swallowtail => 10,
        BoundaryKind::Jump => 2,
        BoundaryKind::GradualTransition => 8,
        BoundaryKind::CliffEdge => 1,
    };

    // Scale by coordinate dimensions.
    let dim_factor = boundary.coordinates.len() as u64;

    // Scale by input length (log2-ish).
    let input_factor = if input.is_empty() {
        1
    } else {
        let bits = 64 - (input.len() as u64).leading_zeros() as u64;
        bits.max(1)
    };

    base + dim_factor + input_factor
}

/// Generate a deterministic boundary ID from coordinates and metrics.
fn generate_boundary_id(
    source: &[ManifoldCoordinate],
    target: &[ManifoldCoordinate],
    source_metric: i64,
    target_metric: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary:");
    for c in source {
        hasher.update(c.dimension_name.as_bytes());
        hasher.update(c.value_millionths.to_le_bytes());
    }
    hasher.update(b"|");
    for c in target {
        hasher.update(c.dimension_name.as_bytes());
        hasher.update(c.value_millionths.to_le_bytes());
    }
    hasher.update(source_metric.to_le_bytes());
    hasher.update(target_metric.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    format!("bnd-{}", &hex_encode(&out)[..16])
}

/// Generate a deterministic witness ID.
fn generate_witness_id(
    boundary: &PhaseBoundary,
    input: &str,
    before: i64,
    after: i64,
    metric: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"witness:");
    hasher.update(boundary.boundary_id.as_bytes());
    hasher.update(input.as_bytes());
    hasher.update(before.to_le_bytes());
    hasher.update(after.to_le_bytes());
    hasher.update(metric.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    format!("wit-{}", &hex_encode(&out)[..16])
}

/// Generate a deterministic report ID.
fn generate_report_id(
    epoch: &SecurityEpoch,
    boundaries: &[PhaseBoundary],
    witnesses: &[CatastropheWitness],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"report:");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update((boundaries.len() as u64).to_le_bytes());
    hasher.update((witnesses.len() as u64).to_le_bytes());
    for b in boundaries {
        hasher.update(b.boundary_id.as_bytes());
    }
    for w in witnesses {
        hasher.update(w.witness_id.as_bytes());
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    format!("rpt-{}", &hex_encode(&out)[..16])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper: create coordinates ----------------------------------------

    fn coord(name: &str, value: i64) -> ManifoldCoordinate {
        ManifoldCoordinate::new(name, value)
    }

    fn make_boundary(
        id: &str,
        kind: BoundaryKind,
        src: PhaseRegion,
        tgt: PhaseRegion,
        sharpness: u64,
    ) -> PhaseBoundary {
        let mut b = PhaseBoundary {
            boundary_id: id.to_string(),
            kind,
            coordinates: vec![coord("x", 0), coord("y", MILLIONTHS)],
            source_region: src,
            target_region: tgt,
            sharpness_millionths: sharpness,
            content_hash: ContentHash::compute(&[]),
        };
        b.content_hash = b.compute_hash();
        b
    }

    fn make_witness(boundary: &PhaseBoundary, before: i64, after: i64) -> CatastropheWitness {
        let delta = after - before;
        let mut w = CatastropheWitness {
            witness_id: format!("test-wit-{}", boundary.boundary_id),
            boundary: boundary.clone(),
            triggering_input: "test-input".to_string(),
            before_metric_millionths: before,
            after_metric_millionths: after,
            delta_millionths: delta,
            metric_name: "test_metric".to_string(),
            minimal: false,
            replay_steps: 10,
            content_hash: ContentHash::compute(&[]),
        };
        w.content_hash = w.compute_hash();
        w
    }

    // -- Phase region classification tests ---------------------------------

    #[test]
    fn test_classify_robust_win() {
        let region = classify_region(3_000_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::RobustWin);
    }

    #[test]
    fn test_classify_brittle_win() {
        let region = classify_region(500_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::BrittleWin);
    }

    #[test]
    fn test_classify_neutral() {
        let region = classify_region(100_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::Neutral);
    }

    #[test]
    fn test_classify_brittle_loss() {
        let region = classify_region(-500_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::BrittleLoss);
    }

    #[test]
    fn test_classify_robust_loss() {
        let region = classify_region(-3_000_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::RobustLoss);
    }

    #[test]
    fn test_classify_exact_threshold_is_neutral() {
        let region = classify_region(0, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::Neutral);
    }

    #[test]
    fn test_classify_at_neutral_boundary_positive() {
        // margin=1_000_000, neutral_half=250_000
        let region = classify_region(250_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::Neutral);
    }

    #[test]
    fn test_classify_just_beyond_neutral_positive() {
        // 250_001 > 250_000 neutral_half => BrittleWin
        let region = classify_region(250_001, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::BrittleWin);
    }

    #[test]
    fn test_classify_at_neutral_boundary_negative() {
        let region = classify_region(-250_000, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::Neutral);
    }

    #[test]
    fn test_classify_just_beyond_neutral_negative() {
        let region = classify_region(-250_001, 0, 1_000_000);
        assert_eq!(region, PhaseRegion::BrittleLoss);
    }

    #[test]
    fn test_classify_nonzero_threshold() {
        // threshold=2M, margin=1M, metric=3.5M => delta=1.5M > margin => RobustWin
        let region = classify_region(3_500_000, 2_000_000, 1_000_000);
        assert_eq!(region, PhaseRegion::RobustWin);
    }

    // -- Phase region methods tests ----------------------------------------

    #[test]
    fn test_phase_region_is_win() {
        assert!(PhaseRegion::RobustWin.is_win());
        assert!(PhaseRegion::BrittleWin.is_win());
        assert!(!PhaseRegion::Neutral.is_win());
        assert!(!PhaseRegion::BrittleLoss.is_win());
        assert!(!PhaseRegion::RobustLoss.is_win());
    }

    #[test]
    fn test_phase_region_is_brittle() {
        assert!(!PhaseRegion::RobustWin.is_brittle());
        assert!(PhaseRegion::BrittleWin.is_brittle());
        assert!(!PhaseRegion::Neutral.is_brittle());
        assert!(PhaseRegion::BrittleLoss.is_brittle());
        assert!(!PhaseRegion::RobustLoss.is_brittle());
    }

    #[test]
    fn test_phase_region_display() {
        assert_eq!(format!("{}", PhaseRegion::RobustWin), "robust_win");
        assert_eq!(format!("{}", PhaseRegion::BrittleLoss), "brittle_loss");
        assert_eq!(format!("{}", PhaseRegion::Neutral), "neutral");
    }

    // -- BoundaryKind serde roundtrip tests --------------------------------

    #[test]
    fn test_boundary_kind_serde_fold() {
        let json = serde_json::to_string(&BoundaryKind::Fold).unwrap();
        let deserialized: BoundaryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, BoundaryKind::Fold);
    }

    #[test]
    fn test_boundary_kind_serde_cusp() {
        let json = serde_json::to_string(&BoundaryKind::Cusp).unwrap();
        let deserialized: BoundaryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, BoundaryKind::Cusp);
    }

    #[test]
    fn test_boundary_kind_serde_all_variants() {
        let variants = [
            BoundaryKind::Fold,
            BoundaryKind::Cusp,
            BoundaryKind::Swallowtail,
            BoundaryKind::Jump,
            BoundaryKind::GradualTransition,
            BoundaryKind::CliffEdge,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: BoundaryKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, variant);
        }
    }

    #[test]
    fn test_phase_region_serde_all_variants() {
        let variants = [
            PhaseRegion::RobustWin,
            PhaseRegion::BrittleWin,
            PhaseRegion::Neutral,
            PhaseRegion::BrittleLoss,
            PhaseRegion::RobustLoss,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: PhaseRegion = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, variant);
        }
    }

    // -- Boundary detection tests ------------------------------------------

    #[test]
    fn test_detect_boundary_different_regions() {
        let source = vec![coord("x", 0)];
        let target = vec![coord("x", MILLIONTHS)];
        // source_metric in RobustWin, target_metric in RobustLoss
        let result = detect_boundary(&source, &target, 3_000_000, -3_000_000);
        assert!(result.is_ok());
        let boundary = result.unwrap();
        assert_eq!(boundary.source_region, PhaseRegion::RobustWin);
        assert_eq!(boundary.target_region, PhaseRegion::RobustLoss);
    }

    #[test]
    fn test_detect_boundary_same_region_error() {
        let source = vec![coord("x", 0)];
        let target = vec![coord("x", 100)];
        // Both in RobustWin
        let result = detect_boundary(&source, &target, 3_000_000, 3_000_000);
        assert_eq!(result, Err(WitnessError::NoBoundaryDetected));
    }

    #[test]
    fn test_detect_boundary_brittle_win_to_brittle_loss() {
        let source = vec![coord("lr", 100_000)];
        let target = vec![coord("lr", 100_500)];
        let result = detect_boundary(&source, &target, 500_000, -500_000);
        assert!(result.is_ok());
        let boundary = result.unwrap();
        assert!(boundary.involves_brittle());
        assert!(boundary.is_critical());
    }

    #[test]
    fn test_detect_boundary_computes_content_hash() {
        let source = vec![coord("x", 0)];
        let target = vec![coord("x", MILLIONTHS)];
        let boundary = detect_boundary(&source, &target, 3_000_000, -3_000_000).unwrap();
        // Hash should not be empty
        assert_ne!(boundary.content_hash, ContentHash::compute(&[]));
        // Re-computing should yield the same hash
        assert_eq!(boundary.content_hash, boundary.compute_hash());
    }

    #[test]
    fn test_detect_boundary_multi_dimensional() {
        let source = vec![coord("x", 0), coord("y", 0)];
        let target = vec![coord("x", MILLIONTHS), coord("y", MILLIONTHS)];
        let result = detect_boundary(&source, &target, 3_000_000, -3_000_000);
        assert!(result.is_ok());
        let boundary = result.unwrap();
        // Multi-dimensional boundaries should have Cusp or higher kind
        assert!(boundary.coordinates.len() == 2);
    }

    // -- Witness generation tests ------------------------------------------

    #[test]
    fn test_generate_witness_basic() {
        let boundary = make_boundary(
            "test-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let result = generate_witness(&boundary, "input=42", 500_000, -200_000, "accuracy");
        assert!(result.is_ok());
        let witness = result.unwrap();
        assert_eq!(witness.delta_millionths, -700_000);
        assert!(!witness.minimal);
        assert!(witness.is_regression());
    }

    #[test]
    fn test_generate_witness_positive_delta() {
        let boundary = make_boundary(
            "test-bnd",
            BoundaryKind::GradualTransition,
            PhaseRegion::BrittleLoss,
            PhaseRegion::BrittleWin,
            2_000_000,
        );
        let result = generate_witness(&boundary, "input=99", -200_000, 500_000, "score");
        assert!(result.is_ok());
        let witness = result.unwrap();
        assert_eq!(witness.delta_millionths, 700_000);
        assert!(!witness.is_regression());
    }

    #[test]
    fn test_generate_witness_input_too_large() {
        let boundary = make_boundary(
            "test-bnd",
            BoundaryKind::Jump,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            5_000_000,
        );
        let large_input = "x".repeat(100_000);
        let result = generate_witness(&boundary, &large_input, 1_000_000, -1_000_000, "metric");
        assert_eq!(result, Err(WitnessError::InputTooLarge));
    }

    #[test]
    fn test_generate_witness_empty_input() {
        let boundary = make_boundary(
            "test-bnd",
            BoundaryKind::CliffEdge,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            15_000_000,
        );
        let result = generate_witness(&boundary, "", 1_000_000, -1_000_000, "metric");
        assert!(result.is_ok());
        let witness = result.unwrap();
        assert_eq!(witness.triggering_input, "");
    }

    #[test]
    fn test_generate_witness_content_hash_deterministic() {
        let boundary = make_boundary(
            "det-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let w1 = generate_witness(&boundary, "same", 100, -100, "m").unwrap();
        let w2 = generate_witness(&boundary, "same", 100, -100, "m").unwrap();
        assert_eq!(w1.content_hash, w2.content_hash);
        assert_eq!(w1.witness_id, w2.witness_id);
    }

    #[test]
    fn test_generate_witness_different_inputs_different_hashes() {
        let boundary = make_boundary(
            "det-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let w1 = generate_witness(&boundary, "input_a", 100, -100, "m").unwrap();
        let w2 = generate_witness(&boundary, "input_b", 100, -100, "m").unwrap();
        assert_ne!(w1.content_hash, w2.content_hash);
        assert_ne!(w1.witness_id, w2.witness_id);
    }

    // -- Witness minimization tests ----------------------------------------

    #[test]
    fn test_minimize_witness_basic() {
        let boundary = make_boundary(
            "min-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        assert!(!witness.minimal);
        assert_eq!(witness.replay_steps, 10);

        let result = minimize_witness(&witness);
        assert!(result.is_ok());
        let minimized = result.unwrap();
        assert!(minimized.minimized_witness.minimal);
        assert!(minimized.minimized_witness.replay_steps < witness.replay_steps);
        assert!(minimized.steps_removed > 0);
    }

    #[test]
    fn test_minimize_already_minimal_fails() {
        let boundary = make_boundary(
            "min-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let mut witness = make_witness(&boundary, 500_000, -200_000);
        witness.minimal = true;
        let result = minimize_witness(&witness);
        assert_eq!(result, Err(WitnessError::MinimizationFailed));
    }

    #[test]
    fn test_minimize_zero_steps_fails() {
        let boundary = make_boundary(
            "min-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let mut witness = make_witness(&boundary, 500_000, -200_000);
        witness.replay_steps = 0;
        let result = minimize_witness(&witness);
        assert_eq!(result, Err(WitnessError::MinimizationFailed));
    }

    #[test]
    fn test_minimize_preserves_metric_values() {
        let boundary = make_boundary(
            "min-bnd",
            BoundaryKind::Jump,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            8_000_000,
        );
        let witness = make_witness(&boundary, 1_000_000, -5_000_000);
        let result = minimize_witness(&witness).unwrap();
        assert_eq!(
            result.minimized_witness.before_metric_millionths,
            witness.before_metric_millionths
        );
        assert_eq!(
            result.minimized_witness.after_metric_millionths,
            witness.after_metric_millionths
        );
        assert_eq!(
            result.minimized_witness.delta_millionths,
            witness.delta_millionths
        );
    }

    #[test]
    fn test_minimize_certificate_hash_not_empty() {
        let boundary = make_boundary(
            "cert-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let result = minimize_witness(&witness).unwrap();
        assert_ne!(
            result.minimality_certificate_hash,
            ContentHash::compute(&[])
        );
    }

    #[test]
    fn test_minimize_large_replay_steps() {
        let boundary = make_boundary(
            "large-bnd",
            BoundaryKind::Swallowtail,
            PhaseRegion::BrittleWin,
            PhaseRegion::RobustLoss,
            5_000_000,
        );
        let mut witness = make_witness(&boundary, 500_000, -3_000_000);
        witness.replay_steps = 10_000;
        let result = minimize_witness(&witness).unwrap();
        // sqrt(10_000) = 100
        assert_eq!(result.minimized_witness.replay_steps, 100);
        assert_eq!(result.steps_removed, 9_900);
    }

    // -- Brittleness report tests ------------------------------------------

    #[test]
    fn test_build_report_basic() {
        let boundary = make_boundary(
            "rpt-bnd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let epoch = SecurityEpoch::from_raw(5);

        let result = build_brittleness_report(epoch, vec![boundary], vec![witness]);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.epoch, epoch);
        assert_eq!(report.boundaries.len(), 1);
        assert_eq!(report.witnesses.len(), 1);
        assert_eq!(report.total_boundary_sharpness_millionths, 3_000_000);
        assert!(report.brittle_region_count > 0);
    }

    #[test]
    fn test_build_report_empty() {
        let epoch = SecurityEpoch::from_raw(0);
        let result = build_brittleness_report(epoch, vec![], vec![]);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.boundaries.len(), 0);
        assert_eq!(report.witnesses.len(), 0);
        assert_eq!(report.brittle_region_count, 0);
        assert_eq!(report.total_boundary_sharpness_millionths, 0);
    }

    #[test]
    fn test_build_report_multiple_boundaries() {
        let b1 = make_boundary(
            "b1",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            2_000_000,
        );
        let b2 = make_boundary(
            "b2",
            BoundaryKind::CliffEdge,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            15_000_000,
        );
        let w1 = make_witness(&b1, 500_000, -200_000);

        let result = build_brittleness_report(SecurityEpoch::from_raw(1), vec![b1, b2], vec![w1]);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.boundaries.len(), 2);
        assert_eq!(report.total_boundary_sharpness_millionths, 17_000_000);
    }

    #[test]
    fn test_report_has_critical_boundaries() {
        let critical = make_boundary(
            "crit",
            BoundaryKind::Jump,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            5_000_000,
        );
        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![critical], vec![]).unwrap();
        assert!(report.has_critical_boundaries());
    }

    #[test]
    fn test_report_no_critical_boundaries() {
        let non_critical = make_boundary(
            "nc",
            BoundaryKind::GradualTransition,
            PhaseRegion::BrittleWin,
            PhaseRegion::Neutral,
            1_000_000,
        );
        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![non_critical], vec![])
                .unwrap();
        // BrittleWin -> Neutral: source is win, target is not win => critical
        assert!(report.has_critical_boundaries());
    }

    #[test]
    fn test_report_regression_count() {
        let boundary = make_boundary(
            "reg",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let w1 = make_witness(&boundary, 500_000, -200_000); // regression
        let w2 = make_witness(&boundary, -200_000, 500_000); // not regression

        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![boundary], vec![w1, w2])
                .unwrap();
        // w1 has negative delta, w2 has positive
        assert_eq!(report.regression_count(), 1);
    }

    #[test]
    fn test_report_max_magnitude() {
        let boundary = make_boundary(
            "mag",
            BoundaryKind::CliffEdge,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            15_000_000,
        );
        let w1 = make_witness(&boundary, 1_000_000, -5_000_000); // magnitude 6M
        let w2 = make_witness(&boundary, 500_000, -200_000); // magnitude 700K

        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![boundary], vec![w1, w2])
                .unwrap();
        assert_eq!(report.max_magnitude(), 6_000_000);
    }

    #[test]
    fn test_report_content_hash_deterministic() {
        let boundary = make_boundary(
            "det",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let epoch = SecurityEpoch::from_raw(1);

        let r1 =
            build_brittleness_report(epoch, vec![boundary.clone()], vec![witness.clone()]).unwrap();
        let r2 = build_brittleness_report(epoch, vec![boundary], vec![witness]).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // -- Sharpness computation tests ---------------------------------------

    #[test]
    fn test_sharpness_basic() {
        let s = compute_boundary_sharpness(1_000_000, -1_000_000, 1_000_000);
        // |delta| = 2M, distance = 1M => sharpness = 2M * 1M / 1M = 2M
        assert_eq!(s, 2_000_000);
    }

    #[test]
    fn test_sharpness_zero_distance() {
        let s = compute_boundary_sharpness(1_000_000, -1_000_000, 0);
        assert_eq!(s, u64::MAX / MILLIONTHS as u64);
    }

    #[test]
    fn test_sharpness_equal_metrics() {
        let s = compute_boundary_sharpness(500_000, 500_000, 1_000_000);
        assert_eq!(s, 0);
    }

    #[test]
    fn test_sharpness_large_distance() {
        let s = compute_boundary_sharpness(1_000_000, 0, 10_000_000);
        // |delta| = 1M, distance = 10M => sharpness = 1M * 1M / 10M = 100_000
        assert_eq!(s, 100_000);
    }

    // -- WitnessError display tests ----------------------------------------

    #[test]
    fn test_error_display_no_boundary() {
        let e = WitnessError::NoBoundaryDetected;
        let s = format!("{e}");
        assert!(s.contains("no phase boundary"));
    }

    #[test]
    fn test_error_display_minimization_failed() {
        let e = WitnessError::MinimizationFailed;
        let s = format!("{e}");
        assert!(s.contains("minimization failed"));
    }

    #[test]
    fn test_error_display_ambiguous() {
        let e = WitnessError::RegionClassificationAmbiguous;
        let s = format!("{e}");
        assert!(s.contains("ambiguous"));
    }

    #[test]
    fn test_error_display_input_too_large() {
        let e = WitnessError::InputTooLarge;
        let s = format!("{e}");
        assert!(s.contains("exceeds"));
    }

    #[test]
    fn test_error_display_internal() {
        let e = WitnessError::InternalError("something broke".to_string());
        let s = format!("{e}");
        assert!(s.contains("something broke"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let errors = vec![
            WitnessError::NoBoundaryDetected,
            WitnessError::MinimizationFailed,
            WitnessError::RegionClassificationAmbiguous,
            WitnessError::InputTooLarge,
            WitnessError::InternalError("test".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let deserialized: WitnessError = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, err);
        }
    }

    // -- Edge case tests ---------------------------------------------------

    #[test]
    fn test_zero_delta_witness() {
        let boundary = make_boundary(
            "zero",
            BoundaryKind::GradualTransition,
            PhaseRegion::Neutral,
            PhaseRegion::Neutral,
            0,
        );
        let w = make_witness(&boundary, 0, 0);
        assert_eq!(w.delta_millionths, 0);
        assert!(!w.is_regression());
        assert_eq!(w.magnitude(), 0);
    }

    #[test]
    fn test_extreme_coordinate_values() {
        let c1 = coord("extreme_pos", i64::MAX);
        let c2 = coord("extreme_neg", i64::MIN);
        // Should not panic.
        let _ = c1.squared_distance(&coord("extreme_pos", 0));
        assert!(c2.squared_distance(&coord("other_dim", 0)).is_none());
    }

    #[test]
    fn test_manifold_coordinate_display() {
        let c = coord("learning_rate", 100_000);
        assert_eq!(format!("{c}"), "learning_rate=100000");
    }

    #[test]
    fn test_manifold_coordinate_squared_distance_same_dim() {
        let c1 = coord("x", 1_000_000);
        let c2 = coord("x", 2_000_000);
        let dist = c1.squared_distance(&c2).unwrap();
        assert_eq!(dist, 1_000_000i128 * 1_000_000i128);
    }

    #[test]
    fn test_manifold_coordinate_squared_distance_different_dim() {
        let c1 = coord("x", 0);
        let c2 = coord("y", 0);
        assert_eq!(c1.squared_distance(&c2), None);
    }

    // -- Manifest tests ----------------------------------------------------

    #[test]
    fn test_manifest_is_valid() {
        let manifest = franken_engine_catastrophe_manifest();
        assert!(!manifest.report_id.is_empty());
        assert_eq!(manifest.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(manifest.boundaries.len(), 3);
        assert_eq!(manifest.witnesses.len(), 2);
        assert!(manifest.brittle_region_count > 0);
        assert!(manifest.total_boundary_sharpness_millionths > 0);
    }

    #[test]
    fn test_manifest_content_hash_stable() {
        let m1 = franken_engine_catastrophe_manifest();
        let m2 = franken_engine_catastrophe_manifest();
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn test_manifest_has_critical_boundaries() {
        let manifest = franken_engine_catastrophe_manifest();
        assert!(manifest.has_critical_boundaries());
    }

    #[test]
    fn test_manifest_witnesses_are_minimal() {
        let manifest = franken_engine_catastrophe_manifest();
        for witness in &manifest.witnesses {
            assert!(witness.minimal);
        }
    }

    #[test]
    fn test_manifest_witnesses_are_regressions() {
        let manifest = franken_engine_catastrophe_manifest();
        for witness in &manifest.witnesses {
            assert!(witness.is_regression());
        }
    }

    // -- BoundaryKind::from_sharpness_and_dims tests -----------------------

    #[test]
    fn test_boundary_kind_cliff_edge() {
        let kind = BoundaryKind::from_sharpness_and_dims(11_000_000, 1);
        assert_eq!(kind, BoundaryKind::CliffEdge);
    }

    #[test]
    fn test_boundary_kind_jump() {
        let kind = BoundaryKind::from_sharpness_and_dims(6_000_000, 1);
        assert_eq!(kind, BoundaryKind::Jump);
    }

    #[test]
    fn test_boundary_kind_fold_1d() {
        let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 1);
        assert_eq!(kind, BoundaryKind::Fold);
    }

    #[test]
    fn test_boundary_kind_gradual_1d() {
        let kind = BoundaryKind::from_sharpness_and_dims(1_000_000, 1);
        assert_eq!(kind, BoundaryKind::GradualTransition);
    }

    #[test]
    fn test_boundary_kind_cusp_2d() {
        let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 2);
        assert_eq!(kind, BoundaryKind::Cusp);
    }

    #[test]
    fn test_boundary_kind_swallowtail_3d() {
        let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 3);
        assert_eq!(kind, BoundaryKind::Swallowtail);
    }

    // -- Display tests for compound types ----------------------------------

    #[test]
    fn test_phase_boundary_display() {
        let boundary = make_boundary(
            "disp",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let s = format!("{boundary}");
        assert!(s.contains("disp"));
        assert!(s.contains("brittle_win"));
        assert!(s.contains("brittle_loss"));
        assert!(s.contains("fold"));
    }

    #[test]
    fn test_catastrophe_witness_display() {
        let boundary = make_boundary(
            "wd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let s = format!("{witness}");
        assert!(s.contains("test_metric"));
        assert!(s.contains("-700000"));
    }

    #[test]
    fn test_minimization_result_display() {
        let boundary = make_boundary(
            "mr",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let result = minimize_witness(&witness).unwrap();
        let s = format!("{result}");
        assert!(s.contains("steps_removed"));
    }

    #[test]
    fn test_brittleness_report_display() {
        let boundary = make_boundary(
            "rd",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![boundary], vec![witness])
                .unwrap();
        let s = format!("{report}");
        assert!(s.contains("brittleness_report"));
        assert!(s.contains("epoch:1"));
    }

    // -- Reduction ratio test ----------------------------------------------

    #[test]
    fn test_reduction_ratio() {
        let boundary = make_boundary(
            "rr",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let mut witness = make_witness(&boundary, 500_000, -200_000);
        witness.replay_steps = 100;
        let result = minimize_witness(&witness).unwrap();
        let ratio = result.reduction_ratio_millionths(100);
        // minimized_steps = ceil(sqrt(100)) = 10, removed = 90
        // ratio = 90 * 1M / 100 = 900_000
        assert_eq!(ratio, 900_000);
    }

    #[test]
    fn test_reduction_ratio_zero_original() {
        let boundary = make_boundary(
            "rr0",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let witness = make_witness(&boundary, 500_000, -200_000);
        let result = minimize_witness(&witness).unwrap();
        assert_eq!(result.reduction_ratio_millionths(0), 0);
    }

    // -- Witnesses by boundary test ----------------------------------------

    #[test]
    fn test_witnesses_by_boundary() {
        let b1 = make_boundary(
            "wb1",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            3_000_000,
        );
        let b2 = make_boundary(
            "wb2",
            BoundaryKind::Jump,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            8_000_000,
        );
        let w1 = make_witness(&b1, 500_000, -200_000);
        let w2 = make_witness(&b2, 1_000_000, -5_000_000);
        let w3 = make_witness(&b1, 300_000, -400_000);

        let report =
            build_brittleness_report(SecurityEpoch::from_raw(1), vec![b1, b2], vec![w1, w2, w3])
                .unwrap();
        let grouped = report.witnesses_by_boundary();
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["wb1"].len(), 2);
        assert_eq!(grouped["wb2"].len(), 1);
    }

    // -- Constants tests ---------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.catastrophe_witness_generator.v1"
        );
        assert_eq!(BEAD_ID, "bd-1lsy.7.19.2");
        assert_eq!(COMPONENT, "catastrophe_witness_generator");
        assert_eq!(POLICY_ID, "RGC-619B");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -- PhaseBoundary method tests ----------------------------------------

    #[test]
    fn test_boundary_is_critical_win_to_loss() {
        let b = make_boundary(
            "c1",
            BoundaryKind::Jump,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
            5_000_000,
        );
        assert!(b.is_critical());
    }

    #[test]
    fn test_boundary_is_not_critical_win_to_win() {
        let b = make_boundary(
            "c2",
            BoundaryKind::GradualTransition,
            PhaseRegion::RobustWin,
            PhaseRegion::BrittleWin,
            1_000_000,
        );
        assert!(!b.is_critical());
    }

    #[test]
    fn test_boundary_involves_brittle() {
        let b1 = make_boundary(
            "ib1",
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::Neutral,
            2_000_000,
        );
        assert!(b1.involves_brittle());

        let b2 = make_boundary(
            "ib2",
            BoundaryKind::Jump,
            PhaseRegion::RobustWin,
            PhaseRegion::RobustLoss,
            10_000_000,
        );
        assert!(!b2.involves_brittle());
    }

    // -- Integer sqrt tests ------------------------------------------------

    #[test]
    fn test_integer_sqrt_ceil_perfect_square() {
        assert_eq!(integer_sqrt_ceil(100), 10);
        assert_eq!(integer_sqrt_ceil(1), 1);
        assert_eq!(integer_sqrt_ceil(0), 0);
    }

    #[test]
    fn test_integer_sqrt_ceil_non_perfect() {
        assert_eq!(integer_sqrt_ceil(10), 4); // floor(sqrt(10))=3, ceil=4
        assert_eq!(integer_sqrt_ceil(2), 2); // floor(sqrt(2))=1, ceil=2
    }
}
