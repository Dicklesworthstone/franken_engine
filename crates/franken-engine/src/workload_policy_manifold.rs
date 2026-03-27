//! Workload-hardware-policy manifold and stable homotopy coordinates.
//!
//! Implements [RGC-619A]: defines the parameterized coordinate system for
//! workload, hardware, cache, and policy manifolds so that the cliff atlas
//! (RGC-619B) can trace nearby parameter motion, compare neighborhoods
//! across runs, and express distance to failure surfaces deterministically.
//!
//! # Design decisions
//!
//! - Each manifold axis is typed (workload, hardware, cache, policy) with
//!   a stable string key and fixed-point millionths value.
//! - Coordinates are bounded: the system abstains from placing a point when
//!   any axis value is missing or out of calibrated range.
//! - Distance is computed via L∞ (Chebyshev) in the normalized coordinate
//!   space — this is the most conservative metric for cliff detection.
//! - Neighborhood membership uses an explicit radius budget so comparisons
//!   across runs use the same tolerance.
//! - All state is serializable for deterministic replay.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::regime_signature_feature::RegimeLabel;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "workload_policy_manifold";
pub const MANIFOLD_SCHEMA_VERSION: &str = "franken-engine.workload-policy-manifold.v1";
pub const COORDINATE_SCHEMA_VERSION: &str = "franken-engine.manifold-coordinate.v1";
pub const NEIGHBORHOOD_SCHEMA_VERSION: &str = "franken-engine.manifold-neighborhood.v1";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

/// Maximum number of axes in any single manifold dimension.
pub const MAX_AXES_PER_DIMENSION: usize = 32;

/// Default neighborhood radius (millionths). 5% = 50_000.
pub const DEFAULT_NEIGHBORHOOD_RADIUS: i64 = 50_000;

// ---------------------------------------------------------------------------
// ManifoldDimension — axis classification
// ---------------------------------------------------------------------------

/// Classification of a manifold axis into one of the four dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldDimension {
    /// Workload characteristics: request rate, payload size, concurrency, etc.
    Workload,
    /// Hardware parameters: core count, cache size, memory bandwidth, etc.
    Hardware,
    /// Cache and storage parameters: eviction policy, capacity, hit rates, etc.
    Cache,
    /// Policy parameters: security level, resource budgets, tier thresholds, etc.
    Policy,
}

impl fmt::Display for ManifoldDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workload => write!(f, "workload"),
            Self::Hardware => write!(f, "hardware"),
            Self::Cache => write!(f, "cache"),
            Self::Policy => write!(f, "policy"),
        }
    }
}

// ---------------------------------------------------------------------------
// AxisDescriptor — metadata for a single axis
// ---------------------------------------------------------------------------

/// Descriptor for a single axis in the manifold coordinate space.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AxisDescriptor {
    /// Stable key for this axis (e.g., "request_rate", "l2_cache_kb").
    pub key: String,
    /// Which dimension this axis belongs to.
    pub dimension: ManifoldDimension,
    /// Human-readable description.
    pub description: String,
    /// Unit label (e.g., "ops/s", "KB", "millionths").
    pub unit: String,
    /// Minimum calibrated value (millionths). Below this, the axis abstains.
    pub min_calibrated_millionths: i64,
    /// Maximum calibrated value (millionths). Above this, the axis abstains.
    pub max_calibrated_millionths: i64,
    /// Whether this axis is required for a coordinate to be valid.
    pub required: bool,
}

impl AxisDescriptor {
    /// Check whether a raw value falls within the calibrated range.
    pub fn is_in_range(&self, value_millionths: i64) -> bool {
        value_millionths >= self.min_calibrated_millionths
            && value_millionths <= self.max_calibrated_millionths
    }

    /// Normalize a value to [0, MILLION] within the calibrated range.
    /// Returns None if out of range.
    pub fn normalize(&self, value_millionths: i64) -> Option<i64> {
        if !self.is_in_range(value_millionths) {
            return None;
        }
        let range = self.max_calibrated_millionths - self.min_calibrated_millionths;
        if range == 0 {
            return Some(MILLION / 2);
        }
        let offset = value_millionths - self.min_calibrated_millionths;
        Some(offset.checked_mul(MILLION)? / range)
    }

    /// Content hash for the axis descriptor (deterministic).
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.key.as_bytes());
        hasher.update([self.dimension as u8]);
        hasher.update(self.min_calibrated_millionths.to_le_bytes());
        hasher.update(self.max_calibrated_millionths.to_le_bytes());
        hasher.update([u8::from(self.required)]);
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// ManifoldSchema — defines the coordinate space
// ---------------------------------------------------------------------------

/// Schema defining the axes of the workload-hardware-policy manifold.
///
/// This is the contract: any coordinate in this manifold must supply values
/// for all required axes, and all values must fall within calibrated ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldSchema {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Schema identifier.
    pub schema_id: String,
    /// Axis descriptors, keyed by axis key.
    pub axes: BTreeMap<String, AxisDescriptor>,
    /// Security epoch at creation time.
    pub epoch: SecurityEpoch,
}

impl ManifoldSchema {
    /// Create a new schema with the given axes.
    pub fn new(schema_id: &str, axes: Vec<AxisDescriptor>, epoch: SecurityEpoch) -> Self {
        let mut axis_map = BTreeMap::new();
        for axis in axes {
            axis_map.insert(axis.key.clone(), axis);
        }
        Self {
            schema_version: MANIFOLD_SCHEMA_VERSION.into(),
            schema_id: schema_id.into(),
            axes: axis_map,
            epoch,
        }
    }

    /// Get all axes for a given dimension.
    pub fn axes_for_dimension(&self, dim: ManifoldDimension) -> Vec<&AxisDescriptor> {
        self.axes.values().filter(|a| a.dimension == dim).collect()
    }

    /// Get the set of required axis keys.
    pub fn required_keys(&self) -> BTreeSet<String> {
        self.axes
            .values()
            .filter(|a| a.required)
            .map(|a| a.key.clone())
            .collect()
    }

    /// Total number of axes.
    pub fn axis_count(&self) -> usize {
        self.axes.len()
    }

    /// Content hash of the schema (deterministic).
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.as_bytes());
        hasher.update(self.schema_id.as_bytes());
        for (key, axis) in &self.axes {
            hasher.update(key.as_bytes());
            hasher.update(axis.content_hash().as_bytes());
        }
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate — a point in the manifold
// ---------------------------------------------------------------------------

/// Placement validity for a coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementValidity {
    /// All required axes present and in range.
    Valid,
    /// One or more required axes missing.
    MissingRequired,
    /// One or more values out of calibrated range.
    OutOfRange,
    /// Both missing and out-of-range issues.
    MissingAndOutOfRange,
}

impl fmt::Display for PlacementValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::MissingRequired => write!(f, "missing_required"),
            Self::OutOfRange => write!(f, "out_of_range"),
            Self::MissingAndOutOfRange => write!(f, "missing_and_out_of_range"),
        }
    }
}

/// A point in the workload-hardware-policy manifold.
///
/// Contains raw axis values and their normalized representations.
/// Normalization is relative to the schema's calibrated ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldCoordinate {
    /// Schema version.
    pub schema_version: String,
    /// Reference to the schema this coordinate belongs to.
    pub schema_id: String,
    /// Coordinate identifier (unique within a session).
    pub coordinate_id: String,
    /// Raw axis values (millionths), keyed by axis key.
    pub raw_values: BTreeMap<String, i64>,
    /// Normalized axis values (millionths in [0, MILLION]), keyed by axis key.
    pub normalized_values: BTreeMap<String, i64>,
    /// Placement validity.
    pub validity: PlacementValidity,
    /// Axes that are missing or out-of-range.
    pub issues: Vec<CoordinateIssue>,
    /// Associated regime label, if available.
    pub regime_label: Option<RegimeLabel>,
    /// Timestamp (epoch-relative sequence number).
    pub sequence: u64,
}

/// Issue with a single axis in a coordinate placement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoordinateIssue {
    /// Which axis has the issue.
    pub axis_key: String,
    /// What kind of issue.
    pub kind: CoordinateIssueKind,
}

/// Kind of coordinate placement issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinateIssueKind {
    /// A required axis has no value.
    MissingRequired,
    /// Value is below calibrated minimum.
    BelowRange,
    /// Value is above calibrated maximum.
    AboveRange,
}

impl fmt::Display for CoordinateIssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequired => write!(f, "missing_required"),
            Self::BelowRange => write!(f, "below_range"),
            Self::AboveRange => write!(f, "above_range"),
        }
    }
}

// ---------------------------------------------------------------------------
// ManifoldPlacer — places raw observations into coordinates
// ---------------------------------------------------------------------------

/// Places raw axis observations into manifold coordinates with validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifoldPlacer {
    /// The schema this placer operates against.
    pub schema: ManifoldSchema,
    /// Counter for coordinate IDs.
    next_sequence: u64,
}

impl ManifoldPlacer {
    /// Create a placer for the given schema.
    pub fn new(schema: ManifoldSchema) -> Self {
        Self {
            schema,
            next_sequence: 0,
        }
    }

    /// Place a set of raw axis values into the manifold, producing a coordinate.
    pub fn place(
        &mut self,
        raw_values: &BTreeMap<String, i64>,
        regime_label: Option<RegimeLabel>,
    ) -> ManifoldCoordinate {
        let mut normalized = BTreeMap::new();
        let mut issues = Vec::new();
        let mut has_missing = false;
        let mut has_out_of_range = false;

        // Check all required axes and normalize provided values
        for (key, axis) in &self.schema.axes {
            match raw_values.get(key) {
                Some(&value) => {
                    if let Some(norm) = axis.normalize(value) {
                        normalized.insert(key.clone(), norm);
                    } else if value < axis.min_calibrated_millionths {
                        issues.push(CoordinateIssue {
                            axis_key: key.clone(),
                            kind: CoordinateIssueKind::BelowRange,
                        });
                        has_out_of_range = true;
                    } else {
                        issues.push(CoordinateIssue {
                            axis_key: key.clone(),
                            kind: CoordinateIssueKind::AboveRange,
                        });
                        has_out_of_range = true;
                    }
                }
                None if axis.required => {
                    issues.push(CoordinateIssue {
                        axis_key: key.clone(),
                        kind: CoordinateIssueKind::MissingRequired,
                    });
                    has_missing = true;
                }
                None => { /* optional axis, skip */ }
            }
        }

        let validity = match (has_missing, has_out_of_range) {
            (false, false) => PlacementValidity::Valid,
            (true, false) => PlacementValidity::MissingRequired,
            (false, true) => PlacementValidity::OutOfRange,
            (true, true) => PlacementValidity::MissingAndOutOfRange,
        };

        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        ManifoldCoordinate {
            schema_version: COORDINATE_SCHEMA_VERSION.into(),
            schema_id: self.schema.schema_id.clone(),
            coordinate_id: format!("coord-{}-{seq}", self.schema.schema_id),
            raw_values: raw_values.clone(),
            normalized_values: normalized,
            validity,
            issues,
            regime_label,
            sequence: seq,
        }
    }

    /// Number of coordinates placed so far.
    pub fn placed_count(&self) -> u64 {
        self.next_sequence
    }
}

// ---------------------------------------------------------------------------
// Neighborhood — local region around a coordinate
// ---------------------------------------------------------------------------

/// A neighborhood in the manifold: all coordinates within a given radius
/// of a center point, measured in L∞ (Chebyshev) distance on normalized axes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldNeighborhood {
    /// Schema version.
    pub schema_version: String,
    /// Center coordinate ID.
    pub center_id: String,
    /// Center's normalized values.
    pub center_normalized: BTreeMap<String, i64>,
    /// Radius (millionths) for L∞ membership.
    pub radius_millionths: i64,
    /// Member coordinate IDs within the neighborhood.
    pub member_ids: BTreeSet<String>,
    /// Number of members.
    pub member_count: usize,
}

/// Compute L∞ (Chebyshev) distance between two coordinate points
/// using only the shared normalized axes.
pub fn chebyshev_distance(a: &BTreeMap<String, i64>, b: &BTreeMap<String, i64>) -> Option<i64> {
    let mut max_diff: i64 = 0;
    let mut shared_axes = 0;

    for (key, &a_val) in a {
        if let Some(&b_val) = b.get(key) {
            let diff = (a_val - b_val).abs();
            if diff > max_diff {
                max_diff = diff;
            }
            shared_axes += 1;
        }
    }

    if shared_axes == 0 {
        None
    } else {
        Some(max_diff)
    }
}

/// Compute L1 (Manhattan) distance between two coordinate points
/// using only shared normalized axes.
pub fn manhattan_distance(a: &BTreeMap<String, i64>, b: &BTreeMap<String, i64>) -> Option<i64> {
    let mut total: i64 = 0;
    let mut shared_axes = 0;

    for (key, &a_val) in a {
        if let Some(&b_val) = b.get(key) {
            total = total.saturating_add((a_val - b_val).abs());
            shared_axes += 1;
        }
    }

    if shared_axes == 0 { None } else { Some(total) }
}

/// Compute L2² (squared Euclidean) distance between two coordinate points
/// using only shared normalized axes. Returns millionths².
pub fn squared_euclidean_distance(
    a: &BTreeMap<String, i64>,
    b: &BTreeMap<String, i64>,
) -> Option<i64> {
    let mut total: i64 = 0;
    let mut shared_axes = 0;

    for (key, &a_val) in a {
        if let Some(&b_val) = b.get(key) {
            let diff = a_val - b_val;
            total = total.saturating_add(diff.saturating_mul(diff));
            shared_axes += 1;
        }
    }

    if shared_axes == 0 { None } else { Some(total) }
}

// ---------------------------------------------------------------------------
// NeighborhoodBuilder — constructs neighborhoods from coordinate sets
// ---------------------------------------------------------------------------

/// Builds neighborhoods from a set of placed coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborhoodBuilder {
    /// Default radius for neighborhoods.
    pub default_radius: i64,
}

impl NeighborhoodBuilder {
    /// Create a builder with the given default radius.
    pub fn new(default_radius: i64) -> Self {
        Self { default_radius }
    }

    /// Build a neighborhood around a center coordinate.
    pub fn build(
        &self,
        center: &ManifoldCoordinate,
        candidates: &[ManifoldCoordinate],
        radius_override: Option<i64>,
    ) -> ManifoldNeighborhood {
        let radius = radius_override.unwrap_or(self.default_radius);
        let mut member_ids = BTreeSet::new();

        for candidate in candidates {
            if candidate.coordinate_id == center.coordinate_id {
                continue;
            }
            if candidate.validity != PlacementValidity::Valid {
                continue;
            }
            if let Some(dist) =
                chebyshev_distance(&center.normalized_values, &candidate.normalized_values)
                && dist <= radius
            {
                member_ids.insert(candidate.coordinate_id.clone());
            }
        }

        let member_count = member_ids.len();
        ManifoldNeighborhood {
            schema_version: NEIGHBORHOOD_SCHEMA_VERSION.into(),
            center_id: center.coordinate_id.clone(),
            center_normalized: center.normalized_values.clone(),
            radius_millionths: radius,
            member_ids,
            member_count,
        }
    }
}

// ---------------------------------------------------------------------------
// FailureSurfaceProximity — distance to failure
// ---------------------------------------------------------------------------

/// A failure surface in the manifold: a region where performance degrades
/// catastrophically or policy guarantees are violated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSurface {
    /// Unique identifier for this failure surface.
    pub surface_id: String,
    /// Human-readable description.
    pub description: String,
    /// Which axes are involved in defining this surface.
    pub relevant_axes: BTreeSet<String>,
    /// Boundary conditions: for each relevant axis, the threshold value
    /// (millionths, normalized) beyond which failure occurs.
    pub boundary_thresholds: BTreeMap<String, FailureBoundary>,
}

/// A boundary condition on a single axis for a failure surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FailureBoundary {
    /// Threshold value (normalized millionths).
    pub threshold_millionths: i64,
    /// Direction: does failure occur above or below this threshold?
    pub direction: BoundaryDirection,
}

/// Direction of a failure boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryDirection {
    /// Failure occurs when the value exceeds the threshold.
    Above,
    /// Failure occurs when the value falls below the threshold.
    Below,
}

impl fmt::Display for BoundaryDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Above => write!(f, "above"),
            Self::Below => write!(f, "below"),
        }
    }
}

/// Proximity of a coordinate to a failure surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureProximity {
    /// Which surface this measures proximity to.
    pub surface_id: String,
    /// The coordinate being measured.
    pub coordinate_id: String,
    /// Minimum distance across all relevant axes (normalized millionths).
    /// Positive means safe; negative means past the boundary.
    pub min_margin_millionths: i64,
    /// Per-axis margins.
    pub axis_margins: BTreeMap<String, i64>,
    /// Whether this coordinate is past the failure boundary.
    pub is_past_boundary: bool,
    /// The closest axis to the boundary.
    pub closest_axis: Option<String>,
}

impl FailureSurface {
    /// Compute the proximity of a coordinate to this failure surface.
    pub fn proximity(&self, coord: &ManifoldCoordinate) -> FailureProximity {
        let mut margins = BTreeMap::new();
        let mut min_margin = i64::MAX;
        let mut closest = None;

        for (axis_key, boundary) in &self.boundary_thresholds {
            if let Some(&norm_val) = coord.normalized_values.get(axis_key) {
                let margin = match boundary.direction {
                    BoundaryDirection::Above => boundary.threshold_millionths - norm_val,
                    BoundaryDirection::Below => norm_val - boundary.threshold_millionths,
                };
                margins.insert(axis_key.clone(), margin);
                if margin < min_margin {
                    min_margin = margin;
                    closest = Some(axis_key.clone());
                }
            }
        }

        if min_margin == i64::MAX {
            min_margin = 0;
        }

        FailureProximity {
            surface_id: self.surface_id.clone(),
            coordinate_id: coord.coordinate_id.clone(),
            min_margin_millionths: min_margin,
            axis_margins: margins,
            is_past_boundary: min_margin < 0,
            closest_axis: closest,
        }
    }
}

// ---------------------------------------------------------------------------
// ManifoldTrajectory — path through the manifold over time
// ---------------------------------------------------------------------------

/// A trajectory: a time-ordered sequence of coordinates in the manifold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldTrajectory {
    /// Trajectory identifier.
    pub trajectory_id: String,
    /// Schema ID this trajectory belongs to.
    pub schema_id: String,
    /// Ordered coordinate IDs.
    pub coordinate_ids: Vec<String>,
    /// Per-step velocity (L∞ distance between consecutive coordinates).
    pub step_velocities: Vec<i64>,
    /// Total path length (sum of step distances).
    pub total_path_length: i64,
}

impl ManifoldTrajectory {
    /// Build a trajectory from a sequence of coordinates.
    pub fn from_coordinates(trajectory_id: &str, coordinates: &[ManifoldCoordinate]) -> Self {
        let mut step_velocities = Vec::new();
        let mut total_path_length: i64 = 0;

        for window in coordinates.windows(2) {
            let dist =
                chebyshev_distance(&window[0].normalized_values, &window[1].normalized_values)
                    .unwrap_or(0);
            step_velocities.push(dist);
            total_path_length = total_path_length.saturating_add(dist);
        }

        let schema_id = coordinates
            .first()
            .map(|c| c.schema_id.clone())
            .unwrap_or_default();

        Self {
            trajectory_id: trajectory_id.into(),
            schema_id,
            coordinate_ids: coordinates
                .iter()
                .map(|c| c.coordinate_id.clone())
                .collect(),
            step_velocities,
            total_path_length,
        }
    }

    /// Maximum single-step velocity (largest jump between consecutive points).
    pub fn max_velocity(&self) -> i64 {
        self.step_velocities.iter().copied().max().unwrap_or(0)
    }

    /// Mean velocity (average step distance in millionths).
    pub fn mean_velocity_millionths(&self) -> i64 {
        if self.step_velocities.is_empty() {
            return 0;
        }
        let sum: i64 = self.step_velocities.iter().sum();
        sum.checked_mul(MILLION)
            .map(|s| s / self.step_velocities.len() as i64)
            .unwrap_or(0)
    }

    /// Number of steps.
    pub fn step_count(&self) -> usize {
        self.step_velocities.len()
    }
}

// ---------------------------------------------------------------------------
// ManifoldWitness — evidence record for auditable manifold operations
// ---------------------------------------------------------------------------

/// Witness record for a manifold operation (placement, neighborhood, proximity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldWitness {
    /// Witness identifier.
    pub witness_id: String,
    /// What operation this witnesses.
    pub operation: ManifoldOperation,
    /// Schema ID.
    pub schema_id: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Content hash of the witness (deterministic).
    pub content_hash: ContentHash,
    /// Detail string.
    pub detail: String,
}

/// Kind of manifold operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldOperation {
    /// Coordinate placement.
    Placement,
    /// Neighborhood construction.
    NeighborhoodBuild,
    /// Failure proximity computation.
    ProximityCheck,
    /// Trajectory construction.
    TrajectoryBuild,
    /// Schema creation.
    SchemaCreation,
}

impl fmt::Display for ManifoldOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Placement => write!(f, "placement"),
            Self::NeighborhoodBuild => write!(f, "neighborhood_build"),
            Self::ProximityCheck => write!(f, "proximity_check"),
            Self::TrajectoryBuild => write!(f, "trajectory_build"),
            Self::SchemaCreation => write!(f, "schema_creation"),
        }
    }
}

impl ManifoldWitness {
    /// Create a new witness for an operation.
    pub fn new(
        witness_id: &str,
        operation: ManifoldOperation,
        schema_id: &str,
        epoch: SecurityEpoch,
        detail: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(witness_id.as_bytes());
        hasher.update([operation as u8]);
        hasher.update(schema_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(detail.as_bytes());
        let hash = ContentHash::compute(&hasher.finalize());

        Self {
            witness_id: witness_id.into(),
            operation,
            schema_id: schema_id.into(),
            epoch,
            content_hash: hash,
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Default axis definitions — canonical set for FrankenEngine
// ---------------------------------------------------------------------------

/// Create the canonical set of workload axes.
pub fn default_workload_axes() -> Vec<AxisDescriptor> {
    vec![
        AxisDescriptor {
            key: "request_rate_ops".into(),
            dimension: ManifoldDimension::Workload,
            description: "Request rate in operations per second".into(),
            unit: "ops/s".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: 10_000 * MILLION,
            required: true,
        },
        AxisDescriptor {
            key: "payload_bytes".into(),
            dimension: ManifoldDimension::Workload,
            description: "Mean request payload size in bytes".into(),
            unit: "bytes".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: 100_000 * MILLION,
            required: false,
        },
        AxisDescriptor {
            key: "concurrency_level".into(),
            dimension: ManifoldDimension::Workload,
            description: "Number of concurrent execution contexts".into(),
            unit: "count".into(),
            min_calibrated_millionths: MILLION,
            max_calibrated_millionths: 10_000 * MILLION,
            required: true,
        },
        AxisDescriptor {
            key: "module_count".into(),
            dimension: ManifoldDimension::Workload,
            description: "Number of loaded modules".into(),
            unit: "count".into(),
            min_calibrated_millionths: MILLION,
            max_calibrated_millionths: 50_000 * MILLION,
            required: false,
        },
    ]
}

/// Create the canonical set of hardware axes.
pub fn default_hardware_axes() -> Vec<AxisDescriptor> {
    vec![
        AxisDescriptor {
            key: "core_count".into(),
            dimension: ManifoldDimension::Hardware,
            description: "Number of logical CPU cores".into(),
            unit: "count".into(),
            min_calibrated_millionths: MILLION,
            max_calibrated_millionths: 1024 * MILLION,
            required: true,
        },
        AxisDescriptor {
            key: "l2_cache_kb".into(),
            dimension: ManifoldDimension::Hardware,
            description: "L2 cache size in KB".into(),
            unit: "KB".into(),
            min_calibrated_millionths: 64 * MILLION,
            max_calibrated_millionths: 131_072 * MILLION,
            required: false,
        },
        AxisDescriptor {
            key: "memory_bandwidth_gbps".into(),
            dimension: ManifoldDimension::Hardware,
            description: "Memory bandwidth in GB/s".into(),
            unit: "GB/s".into(),
            min_calibrated_millionths: MILLION,
            max_calibrated_millionths: 1000 * MILLION,
            required: false,
        },
    ]
}

/// Create the canonical set of policy axes.
pub fn default_policy_axes() -> Vec<AxisDescriptor> {
    vec![
        AxisDescriptor {
            key: "security_level".into(),
            dimension: ManifoldDimension::Policy,
            description: "Security enforcement level (0=minimal, 1M=maximum)".into(),
            unit: "millionths".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: MILLION,
            required: true,
        },
        AxisDescriptor {
            key: "resource_budget_pct".into(),
            dimension: ManifoldDimension::Policy,
            description: "Resource budget allocation percentage".into(),
            unit: "millionths".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: MILLION,
            required: false,
        },
        AxisDescriptor {
            key: "tier_up_threshold".into(),
            dimension: ManifoldDimension::Policy,
            description: "Execution count threshold for tier-up".into(),
            unit: "count".into(),
            min_calibrated_millionths: 10 * MILLION,
            max_calibrated_millionths: 100_000 * MILLION,
            required: false,
        },
    ]
}

/// Create the canonical set of cache axes.
pub fn default_cache_axes() -> Vec<AxisDescriptor> {
    vec![
        AxisDescriptor {
            key: "code_cache_capacity_mb".into(),
            dimension: ManifoldDimension::Cache,
            description: "Code cache capacity in MB".into(),
            unit: "MB".into(),
            min_calibrated_millionths: MILLION,
            max_calibrated_millionths: 4096 * MILLION,
            required: false,
        },
        AxisDescriptor {
            key: "cache_hit_rate".into(),
            dimension: ManifoldDimension::Cache,
            description: "Cache hit rate (0=miss, 1M=perfect)".into(),
            unit: "millionths".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: MILLION,
            required: false,
        },
    ]
}

/// Create the full default schema with all canonical axes.
pub fn default_manifold_schema(epoch: SecurityEpoch) -> ManifoldSchema {
    let mut axes = default_workload_axes();
    axes.extend(default_hardware_axes());
    axes.extend(default_policy_axes());
    axes.extend(default_cache_axes());
    ManifoldSchema::new("franken-engine-default-manifold", axes, epoch)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regime_detector::Regime;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_schema() -> ManifoldSchema {
        ManifoldSchema::new(
            "test-schema",
            vec![
                AxisDescriptor {
                    key: "rate".into(),
                    dimension: ManifoldDimension::Workload,
                    description: "req rate".into(),
                    unit: "ops/s".into(),
                    min_calibrated_millionths: 0,
                    max_calibrated_millionths: 1_000 * MILLION,
                    required: true,
                },
                AxisDescriptor {
                    key: "cores".into(),
                    dimension: ManifoldDimension::Hardware,
                    description: "cpu cores".into(),
                    unit: "count".into(),
                    min_calibrated_millionths: MILLION,
                    max_calibrated_millionths: 128 * MILLION,
                    required: true,
                },
                AxisDescriptor {
                    key: "security".into(),
                    dimension: ManifoldDimension::Policy,
                    description: "sec level".into(),
                    unit: "millionths".into(),
                    min_calibrated_millionths: 0,
                    max_calibrated_millionths: MILLION,
                    required: false,
                },
            ],
            test_epoch(),
        )
    }

    // --- ManifoldDimension ---

    #[test]
    fn dimension_display() {
        assert_eq!(format!("{}", ManifoldDimension::Workload), "workload");
        assert_eq!(format!("{}", ManifoldDimension::Hardware), "hardware");
        assert_eq!(format!("{}", ManifoldDimension::Cache), "cache");
        assert_eq!(format!("{}", ManifoldDimension::Policy), "policy");
    }

    #[test]
    fn dimension_serde_roundtrip() {
        for dim in [
            ManifoldDimension::Workload,
            ManifoldDimension::Hardware,
            ManifoldDimension::Cache,
            ManifoldDimension::Policy,
        ] {
            let json = serde_json::to_string(&dim).unwrap();
            let back: ManifoldDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(dim, back);
        }
    }

    #[test]
    fn dimension_ordering() {
        assert!(ManifoldDimension::Workload < ManifoldDimension::Hardware);
        assert!(ManifoldDimension::Hardware < ManifoldDimension::Cache);
        assert!(ManifoldDimension::Cache < ManifoldDimension::Policy);
    }

    // --- AxisDescriptor ---

    #[test]
    fn axis_in_range() {
        let axis = AxisDescriptor {
            key: "test".into(),
            dimension: ManifoldDimension::Workload,
            description: "test".into(),
            unit: "x".into(),
            min_calibrated_millionths: 100,
            max_calibrated_millionths: 500,
            required: true,
        };
        assert!(axis.is_in_range(100));
        assert!(axis.is_in_range(300));
        assert!(axis.is_in_range(500));
        assert!(!axis.is_in_range(99));
        assert!(!axis.is_in_range(501));
    }

    #[test]
    fn axis_normalize() {
        let axis = AxisDescriptor {
            key: "t".into(),
            dimension: ManifoldDimension::Workload,
            description: "".into(),
            unit: "".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: MILLION,
            required: true,
        };
        assert_eq!(axis.normalize(0), Some(0));
        assert_eq!(axis.normalize(MILLION), Some(MILLION));
        assert_eq!(axis.normalize(500_000), Some(500_000));
        assert_eq!(axis.normalize(-1), None);
        assert_eq!(axis.normalize(MILLION + 1), None);
    }

    #[test]
    fn axis_normalize_zero_range() {
        let axis = AxisDescriptor {
            key: "t".into(),
            dimension: ManifoldDimension::Workload,
            description: "".into(),
            unit: "".into(),
            min_calibrated_millionths: 500,
            max_calibrated_millionths: 500,
            required: true,
        };
        assert_eq!(axis.normalize(500), Some(MILLION / 2));
    }

    #[test]
    fn axis_content_hash_deterministic() {
        let axis = AxisDescriptor {
            key: "test".into(),
            dimension: ManifoldDimension::Workload,
            description: "test".into(),
            unit: "x".into(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: MILLION,
            required: true,
        };
        assert_eq!(axis.content_hash(), axis.content_hash());
    }

    // --- ManifoldSchema ---

    #[test]
    fn schema_axes_for_dimension() {
        let schema = test_schema();
        assert_eq!(
            schema.axes_for_dimension(ManifoldDimension::Workload).len(),
            1
        );
        assert_eq!(
            schema.axes_for_dimension(ManifoldDimension::Hardware).len(),
            1
        );
        assert_eq!(
            schema.axes_for_dimension(ManifoldDimension::Policy).len(),
            1
        );
        assert_eq!(schema.axes_for_dimension(ManifoldDimension::Cache).len(), 0);
    }

    #[test]
    fn schema_required_keys() {
        let schema = test_schema();
        let required = schema.required_keys();
        assert!(required.contains("rate"));
        assert!(required.contains("cores"));
        assert!(!required.contains("security"));
    }

    #[test]
    fn schema_axis_count() {
        let schema = test_schema();
        assert_eq!(schema.axis_count(), 3);
    }

    #[test]
    fn schema_content_hash_deterministic() {
        let s1 = test_schema();
        let s2 = test_schema();
        assert_eq!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn schema_serde_roundtrip() {
        let schema = test_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, back);
    }

    // --- ManifoldPlacer ---

    #[test]
    fn placer_valid_coordinate() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), 500 * MILLION);
        values.insert("cores".into(), 8 * MILLION);
        let coord = placer.place(&values, None);
        assert_eq!(coord.validity, PlacementValidity::Valid);
        assert!(coord.issues.is_empty());
        assert_eq!(coord.sequence, 0);
        assert_eq!(placer.placed_count(), 1);
    }

    #[test]
    fn placer_missing_required() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), 500 * MILLION);
        // "cores" is required but missing
        let coord = placer.place(&values, None);
        assert_eq!(coord.validity, PlacementValidity::MissingRequired);
        assert_eq!(coord.issues.len(), 1);
        assert_eq!(coord.issues[0].axis_key, "cores");
        assert_eq!(coord.issues[0].kind, CoordinateIssueKind::MissingRequired);
    }

    #[test]
    fn placer_out_of_range() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), -1); // below 0
        values.insert("cores".into(), 8 * MILLION);
        let coord = placer.place(&values, None);
        assert_eq!(coord.validity, PlacementValidity::OutOfRange);
    }

    #[test]
    fn placer_optional_axis_omitted() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), 100 * MILLION);
        values.insert("cores".into(), 4 * MILLION);
        // "security" is optional, omitted
        let coord = placer.place(&values, None);
        assert_eq!(coord.validity, PlacementValidity::Valid);
        assert!(!coord.normalized_values.contains_key("security"));
    }

    #[test]
    fn placer_sequence_increments() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), 100 * MILLION);
        values.insert("cores".into(), 4 * MILLION);
        let c1 = placer.place(&values, None);
        let c2 = placer.place(&values, None);
        assert_eq!(c1.sequence, 0);
        assert_eq!(c2.sequence, 1);
        assert_ne!(c1.coordinate_id, c2.coordinate_id);
    }

    #[test]
    fn placer_with_regime_label() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut values = BTreeMap::new();
        values.insert("rate".into(), 100 * MILLION);
        values.insert("cores".into(), 4 * MILLION);
        let label = RegimeLabel::Classified(Regime::Normal);
        let coord = placer.place(&values, Some(label));
        assert_eq!(coord.regime_label, Some(label));
    }

    // --- Distance functions ---

    #[test]
    fn chebyshev_distance_same_point() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 500_000i64);
        a.insert("y".into(), 700_000i64);
        assert_eq!(chebyshev_distance(&a, &a), Some(0));
    }

    #[test]
    fn chebyshev_distance_different_points() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 100_000i64);
        a.insert("y".into(), 200_000i64);
        let mut b = BTreeMap::new();
        b.insert("x".into(), 400_000i64);
        b.insert("y".into(), 300_000i64);
        assert_eq!(chebyshev_distance(&a, &b), Some(300_000));
    }

    #[test]
    fn chebyshev_distance_no_shared_axes() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 100_000i64);
        let mut b = BTreeMap::new();
        b.insert("y".into(), 200_000i64);
        assert_eq!(chebyshev_distance(&a, &b), None);
    }

    #[test]
    fn manhattan_distance_basic() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 100_000i64);
        a.insert("y".into(), 200_000i64);
        let mut b = BTreeMap::new();
        b.insert("x".into(), 400_000i64);
        b.insert("y".into(), 300_000i64);
        assert_eq!(manhattan_distance(&a, &b), Some(400_000));
    }

    #[test]
    fn squared_euclidean_distance_basic() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), 0i64);
        let mut b = BTreeMap::new();
        b.insert("x".into(), 100i64);
        assert_eq!(squared_euclidean_distance(&a, &b), Some(10_000));
    }

    // --- NeighborhoodBuilder ---

    #[test]
    fn neighborhood_build_basic() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut v = BTreeMap::new();
        v.insert("rate".into(), 500 * MILLION);
        v.insert("cores".into(), 64 * MILLION);
        let center = placer.place(&v, None);

        v.insert("rate".into(), 510 * MILLION); // slightly different
        let near = placer.place(&v, None);

        v.insert("rate".into(), 999 * MILLION); // far away
        let far = placer.place(&v, None);

        let builder = NeighborhoodBuilder::new(100_000); // 10% radius
        let neighborhood = builder.build(&center, &[near.clone(), far.clone()], None);
        assert!(neighborhood.member_ids.contains(&near.coordinate_id));
        assert!(!neighborhood.member_ids.contains(&far.coordinate_id));
    }

    #[test]
    fn neighborhood_excludes_center() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut v = BTreeMap::new();
        v.insert("rate".into(), 500 * MILLION);
        v.insert("cores".into(), 64 * MILLION);
        let center = placer.place(&v, None);
        let builder = NeighborhoodBuilder::new(MILLION);
        let neighborhood = builder.build(&center, std::slice::from_ref(&center), None);
        assert!(!neighborhood.member_ids.contains(&center.coordinate_id));
    }

    // --- FailureSurface ---

    #[test]
    fn failure_surface_proximity_safe() {
        let surface = FailureSurface {
            surface_id: "test-cliff".into(),
            description: "Test failure surface".into(),
            relevant_axes: BTreeSet::from(["rate".into()]),
            boundary_thresholds: BTreeMap::from([(
                "rate".into(),
                FailureBoundary {
                    threshold_millionths: 800_000,
                    direction: BoundaryDirection::Above,
                },
            )]),
        };
        let coord = ManifoldCoordinate {
            schema_version: "v1".into(),
            schema_id: "test".into(),
            coordinate_id: "c0".into(),
            raw_values: BTreeMap::new(),
            normalized_values: BTreeMap::from([("rate".into(), 500_000i64)]),
            validity: PlacementValidity::Valid,
            issues: vec![],
            regime_label: None,
            sequence: 0,
        };
        let prox = surface.proximity(&coord);
        assert!(!prox.is_past_boundary);
        assert_eq!(prox.min_margin_millionths, 300_000);
        assert_eq!(prox.closest_axis, Some("rate".into()));
    }

    #[test]
    fn failure_surface_proximity_past_boundary() {
        let surface = FailureSurface {
            surface_id: "test-cliff".into(),
            description: "Test".into(),
            relevant_axes: BTreeSet::from(["rate".into()]),
            boundary_thresholds: BTreeMap::from([(
                "rate".into(),
                FailureBoundary {
                    threshold_millionths: 800_000,
                    direction: BoundaryDirection::Above,
                },
            )]),
        };
        let coord = ManifoldCoordinate {
            schema_version: "v1".into(),
            schema_id: "test".into(),
            coordinate_id: "c0".into(),
            raw_values: BTreeMap::new(),
            normalized_values: BTreeMap::from([("rate".into(), 900_000i64)]),
            validity: PlacementValidity::Valid,
            issues: vec![],
            regime_label: None,
            sequence: 0,
        };
        let prox = surface.proximity(&coord);
        assert!(prox.is_past_boundary);
        assert_eq!(prox.min_margin_millionths, -100_000);
    }

    #[test]
    fn failure_surface_below_direction() {
        let surface = FailureSurface {
            surface_id: "memory-oom".into(),
            description: "OOM threshold".into(),
            relevant_axes: BTreeSet::from(["memory".into()]),
            boundary_thresholds: BTreeMap::from([(
                "memory".into(),
                FailureBoundary {
                    threshold_millionths: 100_000,
                    direction: BoundaryDirection::Below,
                },
            )]),
        };
        let coord = ManifoldCoordinate {
            schema_version: "v1".into(),
            schema_id: "test".into(),
            coordinate_id: "c0".into(),
            raw_values: BTreeMap::new(),
            normalized_values: BTreeMap::from([("memory".into(), 50_000i64)]),
            validity: PlacementValidity::Valid,
            issues: vec![],
            regime_label: None,
            sequence: 0,
        };
        let prox = surface.proximity(&coord);
        assert!(prox.is_past_boundary);
        assert_eq!(prox.min_margin_millionths, -50_000);
    }

    // --- ManifoldTrajectory ---

    #[test]
    fn trajectory_from_coordinates() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let coords: Vec<ManifoldCoordinate> = (0..5)
            .map(|i| {
                let mut v = BTreeMap::new();
                v.insert("rate".into(), (100 + i * 100) * MILLION);
                v.insert("cores".into(), 8 * MILLION);
                placer.place(&v, None)
            })
            .collect();

        let traj = ManifoldTrajectory::from_coordinates("t1", &coords);
        assert_eq!(traj.step_count(), 4);
        assert!(traj.total_path_length > 0);
        assert!(traj.max_velocity() > 0);
    }

    #[test]
    fn trajectory_empty() {
        let traj = ManifoldTrajectory::from_coordinates("empty", &[]);
        assert_eq!(traj.step_count(), 0);
        assert_eq!(traj.total_path_length, 0);
        assert_eq!(traj.max_velocity(), 0);
        assert_eq!(traj.mean_velocity_millionths(), 0);
    }

    #[test]
    fn trajectory_single_point() {
        let schema = test_schema();
        let mut placer = ManifoldPlacer::new(schema);
        let mut v = BTreeMap::new();
        v.insert("rate".into(), 500 * MILLION);
        v.insert("cores".into(), 8 * MILLION);
        let coord = placer.place(&v, None);
        let traj = ManifoldTrajectory::from_coordinates("t1", &[coord]);
        assert_eq!(traj.step_count(), 0);
    }

    // --- ManifoldWitness ---

    #[test]
    fn witness_deterministic_hash() {
        let w1 = ManifoldWitness::new(
            "w1",
            ManifoldOperation::Placement,
            "s1",
            test_epoch(),
            "detail",
        );
        let w2 = ManifoldWitness::new(
            "w1",
            ManifoldOperation::Placement,
            "s1",
            test_epoch(),
            "detail",
        );
        assert_eq!(w1.content_hash, w2.content_hash);
    }

    #[test]
    fn witness_different_operations_different_hash() {
        let w1 = ManifoldWitness::new("w1", ManifoldOperation::Placement, "s1", test_epoch(), "d");
        let w2 = ManifoldWitness::new(
            "w1",
            ManifoldOperation::ProximityCheck,
            "s1",
            test_epoch(),
            "d",
        );
        assert_ne!(w1.content_hash, w2.content_hash);
    }

    #[test]
    fn witness_serde_roundtrip() {
        let w = ManifoldWitness::new(
            "w1",
            ManifoldOperation::TrajectoryBuild,
            "s1",
            test_epoch(),
            "test",
        );
        let json = serde_json::to_string(&w).unwrap();
        let back: ManifoldWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    // --- ManifoldOperation Display ---

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", ManifoldOperation::Placement), "placement");
        assert_eq!(
            format!("{}", ManifoldOperation::NeighborhoodBuild),
            "neighborhood_build"
        );
        assert_eq!(
            format!("{}", ManifoldOperation::ProximityCheck),
            "proximity_check"
        );
        assert_eq!(
            format!("{}", ManifoldOperation::TrajectoryBuild),
            "trajectory_build"
        );
        assert_eq!(
            format!("{}", ManifoldOperation::SchemaCreation),
            "schema_creation"
        );
    }

    #[test]
    fn operation_serde_roundtrip() {
        for op in [
            ManifoldOperation::Placement,
            ManifoldOperation::NeighborhoodBuild,
            ManifoldOperation::ProximityCheck,
            ManifoldOperation::TrajectoryBuild,
            ManifoldOperation::SchemaCreation,
        ] {
            let json = serde_json::to_string(&op).unwrap();
            let back: ManifoldOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    // --- Default axes ---

    #[test]
    fn default_workload_axes_non_empty() {
        assert!(!default_workload_axes().is_empty());
    }

    #[test]
    fn default_hardware_axes_non_empty() {
        assert!(!default_hardware_axes().is_empty());
    }

    #[test]
    fn default_policy_axes_non_empty() {
        assert!(!default_policy_axes().is_empty());
    }

    #[test]
    fn default_cache_axes_non_empty() {
        assert!(!default_cache_axes().is_empty());
    }

    #[test]
    fn default_schema_has_all_dimensions() {
        let schema = default_manifold_schema(test_epoch());
        assert!(
            !schema
                .axes_for_dimension(ManifoldDimension::Workload)
                .is_empty()
        );
        assert!(
            !schema
                .axes_for_dimension(ManifoldDimension::Hardware)
                .is_empty()
        );
        assert!(
            !schema
                .axes_for_dimension(ManifoldDimension::Policy)
                .is_empty()
        );
        assert!(
            !schema
                .axes_for_dimension(ManifoldDimension::Cache)
                .is_empty()
        );
    }

    #[test]
    fn default_schema_serde_roundtrip() {
        let schema = default_manifold_schema(test_epoch());
        let json = serde_json::to_string(&schema).unwrap();
        let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, back);
    }

    // --- PlacementValidity ---

    #[test]
    fn placement_validity_display() {
        assert_eq!(format!("{}", PlacementValidity::Valid), "valid");
        assert_eq!(
            format!("{}", PlacementValidity::MissingRequired),
            "missing_required"
        );
        assert_eq!(format!("{}", PlacementValidity::OutOfRange), "out_of_range");
        assert_eq!(
            format!("{}", PlacementValidity::MissingAndOutOfRange),
            "missing_and_out_of_range"
        );
    }

    #[test]
    fn placement_validity_serde_roundtrip() {
        for v in [
            PlacementValidity::Valid,
            PlacementValidity::MissingRequired,
            PlacementValidity::OutOfRange,
            PlacementValidity::MissingAndOutOfRange,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: PlacementValidity = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- CoordinateIssueKind ---

    #[test]
    fn issue_kind_display() {
        assert_eq!(
            format!("{}", CoordinateIssueKind::MissingRequired),
            "missing_required"
        );
        assert_eq!(
            format!("{}", CoordinateIssueKind::BelowRange),
            "below_range"
        );
        assert_eq!(
            format!("{}", CoordinateIssueKind::AboveRange),
            "above_range"
        );
    }

    // --- BoundaryDirection ---

    #[test]
    fn boundary_direction_display() {
        assert_eq!(format!("{}", BoundaryDirection::Above), "above");
        assert_eq!(format!("{}", BoundaryDirection::Below), "below");
    }

    #[test]
    fn boundary_direction_serde_roundtrip() {
        for d in [BoundaryDirection::Above, BoundaryDirection::Below] {
            let json = serde_json::to_string(&d).unwrap();
            let back: BoundaryDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }
}
