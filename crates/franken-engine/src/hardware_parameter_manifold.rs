//! Hardware parameter manifold, symmetry classes, and fixed-point obligation reduction.
//!
//! Implements [RGC-616A]: defines the hardware parameter space that captures
//! the axes actually relevant to FrankenEngine performance, groups hardware
//! configurations into symmetry classes where transport behavior is invariant,
//! and reduces proof obligations by reusing evidence across symmetric configs.
//!
//! # Design
//!
//! - Hardware axes are typed with stable string keys, calibrated ranges, and
//!   domain tags (Microarch, Memory, Simd, Io, Platform).
//! - Symmetry classes group hardware configurations that exhibit invariant
//!   behavior for a specific optimization question.
//! - Obligation graphs track which (hardware, optimization) pairs still need
//!   evidence and which can be discharged by symmetry transport.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-616A]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for hardware manifold artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.hardware-parameter-manifold.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "hardware_parameter_manifold";

/// Bead / policy reference.
pub const BEAD_ID: &str = "bd-1lsy.7.16.1";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-616A";

/// Fixed-point unit: 1.0 = 1_000_000.
const MILLION: u64 = 1_000_000;

/// Maximum number of axes in the hardware manifold.
pub const MAX_HARDWARE_AXES: usize = 32;

/// Maximum number of members in a single symmetry class.
pub const MAX_CLASS_SIZE: usize = 128;

/// Default similarity threshold for symmetry class membership (millionths).
/// Two hardware configs are symmetric if their normalized distance ≤ this.
pub const DEFAULT_SIMILARITY_THRESHOLD: u64 = 50_000; // 5%

// ---------------------------------------------------------------------------
// HardwareAxisDomain
// ---------------------------------------------------------------------------

/// Domain classification for hardware axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareAxisDomain {
    /// CPU microarchitecture: core count, frequency, cache hierarchy.
    Microarch,
    /// Memory subsystem: bandwidth, latency, capacity, channels.
    Memory,
    /// SIMD / vector unit: width, instruction set level.
    Simd,
    /// I/O subsystem: disk latency, network bandwidth.
    Io,
    /// Platform-level: OS, page size, NUMA topology.
    Platform,
}

impl HardwareAxisDomain {
    pub const ALL: &[Self] = &[
        Self::Microarch,
        Self::Memory,
        Self::Simd,
        Self::Io,
        Self::Platform,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Microarch => "microarch",
            Self::Memory => "memory",
            Self::Simd => "simd",
            Self::Io => "io",
            Self::Platform => "platform",
        }
    }
}

impl fmt::Display for HardwareAxisDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HardwareAxis
// ---------------------------------------------------------------------------

/// A single axis in the hardware parameter manifold.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HardwareAxis {
    /// Stable string key for this axis (e.g. "core_count", "l2_cache_kb").
    pub key: String,
    /// Domain classification.
    pub domain: HardwareAxisDomain,
    /// Minimum calibrated value (millionths).
    pub min_millionths: u64,
    /// Maximum calibrated value (millionths).
    pub max_millionths: u64,
    /// Whether this axis is required for any hardware fingerprint.
    pub required: bool,
    /// Human-readable description.
    pub description: String,
}

impl HardwareAxis {
    /// Create a new hardware axis.
    pub fn new(
        key: impl Into<String>,
        domain: HardwareAxisDomain,
        min_millionths: u64,
        max_millionths: u64,
        required: bool,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            domain,
            min_millionths,
            max_millionths,
            required,
            description: description.into(),
        }
    }

    /// Range span in millionths.
    pub fn range_span(&self) -> u64 {
        self.max_millionths.saturating_sub(self.min_millionths)
    }

    /// Normalize a raw value to [0, MILLION] within calibrated range.
    /// Returns None if the range is zero.
    pub fn normalize(&self, value_millionths: u64) -> Option<u64> {
        let span = self.range_span();
        if span == 0 {
            return None;
        }
        let clamped = value_millionths
            .max(self.min_millionths)
            .min(self.max_millionths);
        let offset = clamped.saturating_sub(self.min_millionths);
        Some(
            offset
                .saturating_mul(MILLION)
                .checked_div(span)
                .unwrap_or(0),
        )
    }

    /// Content hash for this axis definition.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.key.as_bytes());
        h.update(self.domain.as_str().as_bytes());
        h.update(self.min_millionths.to_le_bytes());
        h.update(self.max_millionths.to_le_bytes());
        h.update(if self.required { &[1u8] } else { &[0u8] });
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// HardwareFingerprint
// ---------------------------------------------------------------------------

/// A concrete hardware configuration expressed as axis values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    /// Unique identifier for this fingerprint.
    pub id: String,
    /// Human-readable label (e.g. "AWS c7g.xlarge").
    pub label: String,
    /// Axis key → observed value in millionths.
    pub values: BTreeMap<String, u64>,
    /// Content hash of the fingerprint.
    pub content_hash: ContentHash,
}

impl HardwareFingerprint {
    /// Create a new fingerprint with computed content hash.
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        values: BTreeMap<String, u64>,
    ) -> Self {
        let id = id.into();
        let label = label.into();
        let mut h = Sha256::new();
        h.update(id.as_bytes());
        h.update(label.as_bytes());
        for (k, v) in &values {
            h.update(k.as_bytes());
            h.update(v.to_le_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());
        Self {
            id,
            label,
            values,
            content_hash,
        }
    }

    /// Get a value for an axis key.
    pub fn get(&self, key: &str) -> Option<u64> {
        self.values.get(key).copied()
    }

    /// Number of axes with values.
    pub fn axis_count(&self) -> usize {
        self.values.len()
    }
}

// ---------------------------------------------------------------------------
// SymmetryReason
// ---------------------------------------------------------------------------

/// Justification for why two hardware configurations are symmetric.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymmetryReason {
    /// All relevant axes are within the similarity threshold.
    WithinThreshold {
        max_distance_millionths: u64,
        threshold_millionths: u64,
    },
    /// Expert annotation declares these configs equivalent.
    ExpertAnnotation { note: String },
    /// Empirical measurement confirms identical behavior.
    EmpiricallyVerified { measurement_hash: ContentHash },
}

impl SymmetryReason {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::WithinThreshold { .. } => "within_threshold",
            Self::ExpertAnnotation { .. } => "expert_annotation",
            Self::EmpiricallyVerified { .. } => "empirically_verified",
        }
    }
}

impl fmt::Display for SymmetryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinThreshold {
                max_distance_millionths,
                threshold_millionths,
            } => write!(
                f,
                "within threshold: distance {} ≤ {}",
                max_distance_millionths, threshold_millionths
            ),
            Self::ExpertAnnotation { note } => write!(f, "expert: {}", note),
            Self::EmpiricallyVerified { .. } => write!(f, "empirically verified"),
        }
    }
}

// ---------------------------------------------------------------------------
// SymmetryRefusal
// ---------------------------------------------------------------------------

/// Reason why two hardware configurations cannot be grouped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymmetryRefusal {
    /// Distance exceeds threshold on some axis.
    ExceedsThreshold {
        axis_key: String,
        distance_millionths: u64,
        threshold_millionths: u64,
    },
    /// Missing axis values prevent comparison.
    IncomparableAxes { missing_keys: BTreeSet<String> },
    /// Different SIMD capability level.
    SimdMismatch {
        left_level: String,
        right_level: String,
    },
    /// Different platform characteristics.
    PlatformMismatch { detail: String },
}

impl SymmetryRefusal {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ExceedsThreshold { .. } => "exceeds_threshold",
            Self::IncomparableAxes { .. } => "incomparable_axes",
            Self::SimdMismatch { .. } => "simd_mismatch",
            Self::PlatformMismatch { .. } => "platform_mismatch",
        }
    }
}

impl fmt::Display for SymmetryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsThreshold {
                axis_key,
                distance_millionths,
                threshold_millionths,
            } => write!(
                f,
                "axis '{}' distance {} > threshold {}",
                axis_key, distance_millionths, threshold_millionths
            ),
            Self::IncomparableAxes { missing_keys } => {
                write!(f, "missing axes: {:?}", missing_keys)
            }
            Self::SimdMismatch {
                left_level,
                right_level,
            } => write!(f, "SIMD mismatch: {} vs {}", left_level, right_level),
            Self::PlatformMismatch { detail } => write!(f, "platform mismatch: {}", detail),
        }
    }
}

// ---------------------------------------------------------------------------
// SymmetryClass
// ---------------------------------------------------------------------------

/// A group of hardware fingerprints that exhibit invariant behavior
/// for a specific set of optimization questions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymmetryClass {
    /// Unique class identifier.
    pub class_id: String,
    /// Representative fingerprint ID (the "canonical" member).
    pub representative_id: String,
    /// All member fingerprint IDs (including the representative).
    pub member_ids: BTreeSet<String>,
    /// Axes that are invariant within this class.
    pub invariant_axes: BTreeSet<String>,
    /// Reason for grouping.
    pub reason: SymmetryReason,
    /// Content hash of the class definition.
    pub content_hash: ContentHash,
}

impl SymmetryClass {
    /// Create a new symmetry class.
    pub fn new(
        class_id: impl Into<String>,
        representative_id: impl Into<String>,
        member_ids: BTreeSet<String>,
        invariant_axes: BTreeSet<String>,
        reason: SymmetryReason,
    ) -> Self {
        let class_id = class_id.into();
        let representative_id = representative_id.into();
        let mut h = Sha256::new();
        h.update(class_id.as_bytes());
        h.update(representative_id.as_bytes());
        for m in &member_ids {
            h.update(m.as_bytes());
        }
        for a in &invariant_axes {
            h.update(a.as_bytes());
        }
        h.update(reason.tag().as_bytes());
        let content_hash = ContentHash::compute(&h.finalize());
        Self {
            class_id,
            representative_id,
            member_ids,
            invariant_axes,
            reason,
            content_hash,
        }
    }

    /// Number of members in this class.
    pub fn size(&self) -> usize {
        self.member_ids.len()
    }

    /// Whether a fingerprint ID is a member of this class.
    pub fn contains(&self, fingerprint_id: &str) -> bool {
        self.member_ids.contains(fingerprint_id)
    }

    /// Whether this class is trivial (single member).
    pub fn is_trivial(&self) -> bool {
        self.member_ids.len() <= 1
    }
}

// ---------------------------------------------------------------------------
// ObligationStatus
// ---------------------------------------------------------------------------

/// Status of a proof/measurement obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    /// Obligation not yet addressed.
    Pending,
    /// Discharged by direct evidence.
    DischargedDirect,
    /// Discharged by symmetry transport from another config.
    DischargedByTransport,
    /// Obligation cannot be discharged (infeasible hardware).
    Infeasible,
    /// Obligation explicitly waived by policy.
    Waived,
}

impl ObligationStatus {
    pub const ALL: &[Self] = &[
        Self::Pending,
        Self::DischargedDirect,
        Self::DischargedByTransport,
        Self::Infeasible,
        Self::Waived,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::DischargedDirect => "discharged_direct",
            Self::DischargedByTransport => "discharged_by_transport",
            Self::Infeasible => "infeasible",
            Self::Waived => "waived",
        }
    }

    /// Whether this obligation is resolved (not pending).
    pub const fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Whether this was discharged (direct or transport).
    pub const fn is_discharged(self) -> bool {
        matches!(self, Self::DischargedDirect | Self::DischargedByTransport)
    }
}

impl fmt::Display for ObligationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// OptimizationQuestion
// ---------------------------------------------------------------------------

/// An optimization question that requires hardware-specific evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OptimizationQuestion {
    /// Stable identifier for this question.
    pub question_id: String,
    /// Human-readable description.
    pub description: String,
    /// Which hardware axes matter for this question.
    pub relevant_axes: BTreeSet<String>,
}

impl OptimizationQuestion {
    pub fn new(
        question_id: impl Into<String>,
        description: impl Into<String>,
        relevant_axes: BTreeSet<String>,
    ) -> Self {
        Self {
            question_id: question_id.into(),
            description: description.into(),
            relevant_axes,
        }
    }
}

// ---------------------------------------------------------------------------
// Obligation
// ---------------------------------------------------------------------------

/// A single proof/measurement obligation: (hardware_config, question).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Obligation {
    /// Fingerprint ID this obligation is for.
    pub fingerprint_id: String,
    /// Question ID this obligation addresses.
    pub question_id: String,
    /// Current status.
    pub status: ObligationStatus,
    /// If discharged by transport, the source fingerprint ID.
    pub transport_source: Option<String>,
    /// If discharged by transport, the symmetry class ID.
    pub transport_class_id: Option<String>,
}

impl Obligation {
    /// Create a pending obligation.
    pub fn pending(fingerprint_id: impl Into<String>, question_id: impl Into<String>) -> Self {
        Self {
            fingerprint_id: fingerprint_id.into(),
            question_id: question_id.into(),
            status: ObligationStatus::Pending,
            transport_source: None,
            transport_class_id: None,
        }
    }

    /// Discharge this obligation directly.
    pub fn discharge_direct(&mut self) {
        self.status = ObligationStatus::DischargedDirect;
    }

    /// Discharge this obligation by symmetry transport.
    pub fn discharge_by_transport(
        &mut self,
        source_id: impl Into<String>,
        class_id: impl Into<String>,
    ) {
        self.status = ObligationStatus::DischargedByTransport;
        self.transport_source = Some(source_id.into());
        self.transport_class_id = Some(class_id.into());
    }

    /// Mark as infeasible.
    pub fn mark_infeasible(&mut self) {
        self.status = ObligationStatus::Infeasible;
    }

    /// Waive this obligation.
    pub fn waive(&mut self) {
        self.status = ObligationStatus::Waived;
    }
}

// ---------------------------------------------------------------------------
// ObligationGraph
// ---------------------------------------------------------------------------

/// The full obligation graph: fingerprints × questions, with symmetry-based reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationGraph {
    /// All registered hardware axes.
    pub axes: BTreeMap<String, HardwareAxis>,
    /// All registered fingerprints.
    pub fingerprints: BTreeMap<String, HardwareFingerprint>,
    /// All registered questions.
    pub questions: BTreeMap<String, OptimizationQuestion>,
    /// All symmetry classes.
    pub symmetry_classes: Vec<SymmetryClass>,
    /// All obligations, keyed by (fingerprint_id, question_id).
    pub obligations: Vec<Obligation>,
    /// Similarity threshold for automatic symmetry detection.
    pub similarity_threshold: u64,
}

impl ObligationGraph {
    /// Create an empty obligation graph.
    pub fn new(similarity_threshold: u64) -> Self {
        Self {
            axes: BTreeMap::new(),
            fingerprints: BTreeMap::new(),
            questions: BTreeMap::new(),
            symmetry_classes: Vec::new(),
            obligations: Vec::new(),
            similarity_threshold,
        }
    }

    /// Create with default similarity threshold.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_SIMILARITY_THRESHOLD)
    }

    /// Register a hardware axis.
    pub fn add_axis(&mut self, axis: HardwareAxis) {
        self.axes.insert(axis.key.clone(), axis);
    }

    /// Register a hardware fingerprint.
    pub fn add_fingerprint(&mut self, fp: HardwareFingerprint) {
        self.fingerprints.insert(fp.id.clone(), fp);
    }

    /// Register an optimization question.
    pub fn add_question(&mut self, q: OptimizationQuestion) {
        self.questions.insert(q.question_id.clone(), q);
    }

    /// Register a symmetry class.
    pub fn add_symmetry_class(&mut self, class: SymmetryClass) {
        self.symmetry_classes.push(class);
    }

    /// Generate all pending obligations for registered fingerprints × questions.
    pub fn generate_obligations(&mut self) {
        self.obligations.clear();
        for fp_id in self.fingerprints.keys() {
            for q_id in self.questions.keys() {
                self.obligations
                    .push(Obligation::pending(fp_id.clone(), q_id.clone()));
            }
        }
    }

    /// Total number of obligations.
    pub fn obligation_count(&self) -> usize {
        self.obligations.len()
    }

    /// Number of pending obligations.
    pub fn pending_count(&self) -> usize {
        self.obligations
            .iter()
            .filter(|o| o.status == ObligationStatus::Pending)
            .count()
    }

    /// Number of discharged obligations (direct + transport).
    pub fn discharged_count(&self) -> usize {
        self.obligations
            .iter()
            .filter(|o| o.status.is_discharged())
            .count()
    }

    /// Number of obligations discharged by transport.
    pub fn transport_count(&self) -> usize {
        self.obligations
            .iter()
            .filter(|o| o.status == ObligationStatus::DischargedByTransport)
            .count()
    }

    /// Coverage: fraction of obligations resolved (millionths).
    pub fn coverage_millionths(&self) -> u64 {
        let total = self.obligations.len() as u64;
        let resolved = self
            .obligations
            .iter()
            .filter(|o| o.status.is_resolved())
            .count() as u64;
        resolved
            .saturating_mul(MILLION)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Reduction ratio: fraction of discharged obligations via transport (millionths).
    pub fn transport_reduction_millionths(&self) -> u64 {
        let discharged = self.discharged_count() as u64;
        let transport = self.transport_count() as u64;
        transport
            .saturating_mul(MILLION)
            .checked_div(discharged)
            .unwrap_or(0)
    }

    /// Apply symmetry-based obligation reduction.
    /// For each symmetry class, if the representative's obligation is discharged,
    /// transport that discharge to all other class members.
    pub fn reduce_by_symmetry(&mut self) {
        for class in &self.symmetry_classes {
            for q_id in self.questions.keys() {
                // Find the representative's obligation status
                let rep_discharged = self.obligations.iter().any(|o| {
                    o.fingerprint_id == class.representative_id
                        && o.question_id == *q_id
                        && o.status == ObligationStatus::DischargedDirect
                });
                if rep_discharged {
                    // Transport to all non-representative members
                    for member_id in &class.member_ids {
                        if *member_id != class.representative_id {
                            for o in &mut self.obligations {
                                if o.fingerprint_id == *member_id
                                    && o.question_id == *q_id
                                    && o.status == ObligationStatus::Pending
                                {
                                    o.discharge_by_transport(
                                        class.representative_id.clone(),
                                        class.class_id.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Look up obligation for a specific (fingerprint, question) pair.
    pub fn find_obligation(&self, fingerprint_id: &str, question_id: &str) -> Option<&Obligation> {
        self.obligations
            .iter()
            .find(|o| o.fingerprint_id == fingerprint_id && o.question_id == question_id)
    }

    /// Look up mutable obligation for a specific (fingerprint, question) pair.
    pub fn find_obligation_mut(
        &mut self,
        fingerprint_id: &str,
        question_id: &str,
    ) -> Option<&mut Obligation> {
        self.obligations
            .iter_mut()
            .find(|o| o.fingerprint_id == fingerprint_id && o.question_id == question_id)
    }

    /// Compute L∞ (Chebyshev) distance between two fingerprints over shared axes.
    /// Returns None if no shared axes exist.
    #[allow(clippy::collapsible_if)]
    pub fn chebyshev_distance(&self, fp_a: &str, fp_b: &str) -> Option<u64> {
        let a = self.fingerprints.get(fp_a)?;
        let b = self.fingerprints.get(fp_b)?;
        let mut max_dist: Option<u64> = None;
        for (key, axis) in &self.axes {
            if let (Some(va), Some(vb)) = (a.get(key), b.get(key)) {
                if let (Some(na), Some(nb)) = (axis.normalize(va), axis.normalize(vb)) {
                    let dist = na.abs_diff(nb);
                    max_dist = Some(max_dist.map_or(dist, |d: u64| d.max(dist)));
                }
            }
        }
        max_dist
    }

    /// Check whether two fingerprints are within the similarity threshold.
    #[allow(clippy::collapsible_if)]
    pub fn check_symmetry(
        &self,
        fp_a: &str,
        fp_b: &str,
    ) -> Result<SymmetryReason, SymmetryRefusal> {
        let a = match self.fingerprints.get(fp_a) {
            Some(fp) => fp,
            None => {
                let mut missing = BTreeSet::new();
                missing.insert(fp_a.to_string());
                return Err(SymmetryRefusal::IncomparableAxes {
                    missing_keys: missing,
                });
            }
        };
        let b = match self.fingerprints.get(fp_b) {
            Some(fp) => fp,
            None => {
                let mut missing = BTreeSet::new();
                missing.insert(fp_b.to_string());
                return Err(SymmetryRefusal::IncomparableAxes {
                    missing_keys: missing,
                });
            }
        };

        // Check for missing required axes
        let mut missing = BTreeSet::new();
        for (key, axis) in &self.axes {
            if axis.required && (a.get(key).is_none() || b.get(key).is_none()) {
                missing.insert(key.clone());
            }
        }
        if !missing.is_empty() {
            return Err(SymmetryRefusal::IncomparableAxes {
                missing_keys: missing,
            });
        }

        // Compute per-axis normalized distance, track max
        let mut max_distance: u64 = 0;
        let mut max_axis = String::new();
        for (key, axis) in &self.axes {
            if let (Some(va), Some(vb)) = (a.get(key), b.get(key)) {
                if let (Some(na), Some(nb)) = (axis.normalize(va), axis.normalize(vb)) {
                    let dist = na.abs_diff(nb);
                    if dist > max_distance {
                        max_distance = dist;
                        max_axis = key.clone();
                    }
                }
            }
        }

        if max_distance > self.similarity_threshold {
            Err(SymmetryRefusal::ExceedsThreshold {
                axis_key: max_axis,
                distance_millionths: max_distance,
                threshold_millionths: self.similarity_threshold,
            })
        } else {
            Ok(SymmetryReason::WithinThreshold {
                max_distance_millionths: max_distance,
                threshold_millionths: self.similarity_threshold,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationReport
// ---------------------------------------------------------------------------

/// Summary report of obligation graph coverage and reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total obligations.
    pub total_obligations: usize,
    /// Pending obligations.
    pub pending_obligations: usize,
    /// Discharged (direct).
    pub direct_discharges: usize,
    /// Discharged (transport).
    pub transport_discharges: usize,
    /// Infeasible.
    pub infeasible_count: usize,
    /// Waived.
    pub waived_count: usize,
    /// Coverage ratio (millionths).
    pub coverage_millionths: u64,
    /// Transport reduction ratio (millionths).
    pub transport_reduction_millionths: u64,
    /// Number of symmetry classes.
    pub symmetry_class_count: usize,
    /// Number of non-trivial symmetry classes (size > 1).
    pub nontrivial_class_count: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ObligationReport {
    /// Generate a report from an obligation graph.
    pub fn from_graph(graph: &ObligationGraph, epoch: SecurityEpoch) -> Self {
        let total_obligations = graph.obligation_count();
        let pending_obligations = graph.pending_count();
        let direct_discharges = graph
            .obligations
            .iter()
            .filter(|o| o.status == ObligationStatus::DischargedDirect)
            .count();
        let transport_discharges = graph.transport_count();
        let infeasible_count = graph
            .obligations
            .iter()
            .filter(|o| o.status == ObligationStatus::Infeasible)
            .count();
        let waived_count = graph
            .obligations
            .iter()
            .filter(|o| o.status == ObligationStatus::Waived)
            .count();
        let coverage_millionths = graph.coverage_millionths();
        let transport_reduction_millionths = graph.transport_reduction_millionths();
        let symmetry_class_count = graph.symmetry_classes.len();
        let nontrivial_class_count = graph
            .symmetry_classes
            .iter()
            .filter(|c| !c.is_trivial())
            .count();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update((total_obligations as u64).to_le_bytes());
        h.update((pending_obligations as u64).to_le_bytes());
        h.update((direct_discharges as u64).to_le_bytes());
        h.update((transport_discharges as u64).to_le_bytes());
        h.update(coverage_millionths.to_le_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            total_obligations,
            pending_obligations,
            direct_discharges,
            transport_discharges,
            infeasible_count,
            waived_count,
            coverage_millionths,
            transport_reduction_millionths,
            symmetry_class_count,
            nontrivial_class_count,
            content_hash,
        }
    }

    /// Whether all obligations are resolved.
    pub fn is_complete(&self) -> bool {
        self.pending_obligations == 0
    }
}

// ---------------------------------------------------------------------------
// Default axis factory
// ---------------------------------------------------------------------------

/// Create the canonical set of hardware axes for FrankenEngine.
pub fn default_hardware_axes() -> Vec<HardwareAxis> {
    vec![
        HardwareAxis::new(
            "core_count",
            HardwareAxisDomain::Microarch,
            1_000_000,   // 1 core
            128_000_000, // 128 cores
            true,
            "Physical core count",
        ),
        HardwareAxis::new(
            "base_freq_mhz",
            HardwareAxisDomain::Microarch,
            800_000_000,   // 800 MHz
            6_000_000_000, // 6 GHz
            false,
            "Base CPU frequency in MHz (millionths)",
        ),
        HardwareAxis::new(
            "l1d_cache_kb",
            HardwareAxisDomain::Microarch,
            16_000_000,  // 16 KB
            128_000_000, // 128 KB
            false,
            "L1 data cache size in KB (millionths)",
        ),
        HardwareAxis::new(
            "l2_cache_kb",
            HardwareAxisDomain::Microarch,
            128_000_000,   // 128 KB
            4_096_000_000, // 4096 KB
            false,
            "L2 cache size in KB (millionths)",
        ),
        HardwareAxis::new(
            "l3_cache_mb",
            HardwareAxisDomain::Microarch,
            0,           // 0 MB (some configs lack L3)
            512_000_000, // 512 MB
            false,
            "L3 cache size in MB (millionths)",
        ),
        HardwareAxis::new(
            "mem_bandwidth_gbps",
            HardwareAxisDomain::Memory,
            10_000_000,    // 10 GB/s
            1_000_000_000, // 1000 GB/s
            true,
            "Memory bandwidth in GB/s (millionths)",
        ),
        HardwareAxis::new(
            "mem_capacity_gb",
            HardwareAxisDomain::Memory,
            1_000_000,     // 1 GB
            4_096_000_000, // 4096 GB
            false,
            "Memory capacity in GB (millionths)",
        ),
        HardwareAxis::new(
            "mem_latency_ns",
            HardwareAxisDomain::Memory,
            30_000_000,  // 30 ns
            200_000_000, // 200 ns
            false,
            "Memory latency in ns (millionths)",
        ),
        HardwareAxis::new(
            "simd_width_bits",
            HardwareAxisDomain::Simd,
            0,           // no SIMD
            512_000_000, // 512-bit (AVX-512)
            false,
            "SIMD register width in bits (millionths)",
        ),
        HardwareAxis::new(
            "numa_nodes",
            HardwareAxisDomain::Platform,
            1_000_000, // 1 node
            8_000_000, // 8 nodes
            false,
            "NUMA node count (millionths)",
        ),
        HardwareAxis::new(
            "page_size_kb",
            HardwareAxisDomain::Platform,
            4_000_000,     // 4 KB
            2_048_000_000, // 2 MB (huge pages)
            false,
            "Default page size in KB (millionths)",
        ),
        HardwareAxis::new(
            "disk_iops",
            HardwareAxisDomain::Io,
            100_000_000,       // 100 IOPS
            1_000_000_000_000, // 1M IOPS (NVMe)
            false,
            "Disk IOPS (millionths)",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(500)
    }

    fn sample_axis() -> HardwareAxis {
        HardwareAxis::new(
            "core_count",
            HardwareAxisDomain::Microarch,
            1_000_000,
            128_000_000,
            true,
            "Core count",
        )
    }

    fn sample_fingerprint(id: &str, core_count: u64, mem_bw: u64) -> HardwareFingerprint {
        let mut values = BTreeMap::new();
        values.insert("core_count".to_string(), core_count);
        values.insert("mem_bandwidth_gbps".to_string(), mem_bw);
        HardwareFingerprint::new(id, format!("hw-{}", id), values)
    }

    fn sample_question(id: &str) -> OptimizationQuestion {
        OptimizationQuestion::new(
            id,
            format!("Does {} improve throughput?", id),
            BTreeSet::from(["core_count".to_string()]),
        )
    }

    fn sample_graph() -> ObligationGraph {
        let mut g = ObligationGraph::with_defaults();
        for axis in default_hardware_axes() {
            g.add_axis(axis);
        }
        g.add_fingerprint(sample_fingerprint("fp1", 8_000_000, 50_000_000));
        g.add_fingerprint(sample_fingerprint("fp2", 8_500_000, 52_000_000));
        g.add_fingerprint(sample_fingerprint("fp3", 64_000_000, 200_000_000));
        g.add_question(sample_question("q-tiering"));
        g.add_question(sample_question("q-gc"));
        g
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(!SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "hardware_parameter_manifold");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn max_axes_positive() {
        let mha = MAX_HARDWARE_AXES;
        assert!(mha > 0);
    }

    #[test]
    fn max_class_size_positive() {
        let mcs = MAX_CLASS_SIZE;
        assert!(mcs > 0);
    }

    #[test]
    fn default_threshold_range() {
        let dst = DEFAULT_SIMILARITY_THRESHOLD;
        assert!(dst > 0);
        assert!(dst < MILLION);
    }

    // --- HardwareAxisDomain ---

    #[test]
    fn domain_all_length() {
        assert_eq!(HardwareAxisDomain::ALL.len(), 5);
    }

    #[test]
    fn domain_names_unique() {
        let names: BTreeSet<&str> = HardwareAxisDomain::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(names.len(), HardwareAxisDomain::ALL.len());
    }

    #[test]
    fn domain_display_matches_as_str() {
        for d in HardwareAxisDomain::ALL {
            assert_eq!(d.to_string(), d.as_str());
        }
    }

    #[test]
    fn domain_serde_roundtrip() {
        for d in HardwareAxisDomain::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: HardwareAxisDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // --- HardwareAxis ---

    #[test]
    fn axis_range_span() {
        let a = sample_axis();
        assert_eq!(a.range_span(), 127_000_000);
    }

    #[test]
    fn axis_normalize_min() {
        let a = sample_axis();
        assert_eq!(a.normalize(1_000_000), Some(0));
    }

    #[test]
    fn axis_normalize_max() {
        let a = sample_axis();
        assert_eq!(a.normalize(128_000_000), Some(MILLION));
    }

    #[test]
    fn axis_normalize_mid() {
        let a = sample_axis();
        let mid = a.normalize(64_500_000).unwrap();
        assert!(mid > 0 && mid < MILLION);
    }

    #[test]
    fn axis_normalize_below_min_clamps() {
        let a = sample_axis();
        assert_eq!(a.normalize(0), Some(0));
    }

    #[test]
    fn axis_normalize_above_max_clamps() {
        let a = sample_axis();
        assert_eq!(a.normalize(999_000_000), Some(MILLION));
    }

    #[test]
    fn axis_normalize_zero_range() {
        let a = HardwareAxis::new("x", HardwareAxisDomain::Microarch, 10, 10, false, "");
        assert_eq!(a.normalize(10), None);
    }

    #[test]
    fn axis_content_hash_deterministic() {
        let a1 = sample_axis();
        let a2 = sample_axis();
        assert_eq!(a1.content_hash(), a2.content_hash());
    }

    #[test]
    fn axis_serde_roundtrip() {
        let a = sample_axis();
        let json = serde_json::to_string(&a).unwrap();
        let back: HardwareAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- HardwareFingerprint ---

    #[test]
    fn fingerprint_creation() {
        let fp = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        assert_eq!(fp.id, "fp1");
        assert_eq!(fp.axis_count(), 2);
        assert_eq!(fp.get("core_count"), Some(8_000_000));
    }

    #[test]
    fn fingerprint_missing_axis() {
        let fp = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        assert_eq!(fp.get("nonexistent"), None);
    }

    #[test]
    fn fingerprint_hash_deterministic() {
        let fp1 = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        let fp2 = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        assert_eq!(fp1.content_hash, fp2.content_hash);
    }

    #[test]
    fn fingerprint_different_values_different_hash() {
        let fp1 = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        let fp2 = sample_fingerprint("fp1", 16_000_000, 50_000_000);
        assert_ne!(fp1.content_hash, fp2.content_hash);
    }

    #[test]
    fn fingerprint_serde_roundtrip() {
        let fp = sample_fingerprint("fp1", 8_000_000, 50_000_000);
        let json = serde_json::to_string(&fp).unwrap();
        let back: HardwareFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }

    // --- SymmetryReason ---

    #[test]
    fn symmetry_reason_tags_unique() {
        let reasons = [
            SymmetryReason::WithinThreshold {
                max_distance_millionths: 1000,
                threshold_millionths: 50_000,
            },
            SymmetryReason::ExpertAnnotation {
                note: "same gen".into(),
            },
            SymmetryReason::EmpiricallyVerified {
                measurement_hash: ContentHash::compute(b"test"),
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn symmetry_reason_display() {
        let r = SymmetryReason::WithinThreshold {
            max_distance_millionths: 1000,
            threshold_millionths: 50_000,
        };
        let s = r.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("50000"));
    }

    #[test]
    fn symmetry_reason_serde() {
        let r = SymmetryReason::ExpertAnnotation {
            note: "same gen".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SymmetryReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- SymmetryRefusal ---

    #[test]
    fn symmetry_refusal_tags_unique() {
        let refusals: Vec<SymmetryRefusal> = vec![
            SymmetryRefusal::ExceedsThreshold {
                axis_key: "x".into(),
                distance_millionths: 100_000,
                threshold_millionths: 50_000,
            },
            SymmetryRefusal::IncomparableAxes {
                missing_keys: BTreeSet::new(),
            },
            SymmetryRefusal::SimdMismatch {
                left_level: "avx2".into(),
                right_level: "neon".into(),
            },
            SymmetryRefusal::PlatformMismatch { detail: "x".into() },
        ];
        let tags: BTreeSet<&str> = refusals.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 4);
    }

    #[test]
    fn symmetry_refusal_display() {
        let r = SymmetryRefusal::ExceedsThreshold {
            axis_key: "core_count".into(),
            distance_millionths: 100_000,
            threshold_millionths: 50_000,
        };
        let s = r.to_string();
        assert!(s.contains("core_count"));
    }

    #[test]
    fn symmetry_refusal_serde() {
        let r = SymmetryRefusal::SimdMismatch {
            left_level: "avx2".into(),
            right_level: "neon".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SymmetryRefusal = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- SymmetryClass ---

    #[test]
    fn symmetry_class_creation() {
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        let axes = BTreeSet::from(["core_count".to_string()]);
        let class = SymmetryClass::new(
            "class1",
            "fp1",
            members,
            axes,
            SymmetryReason::WithinThreshold {
                max_distance_millionths: 1000,
                threshold_millionths: 50_000,
            },
        );
        assert_eq!(class.size(), 2);
        assert!(class.contains("fp1"));
        assert!(class.contains("fp2"));
        assert!(!class.contains("fp3"));
        assert!(!class.is_trivial());
    }

    #[test]
    fn symmetry_class_trivial() {
        let members = BTreeSet::from(["fp1".to_string()]);
        let class = SymmetryClass::new(
            "c1",
            "fp1",
            members,
            BTreeSet::new(),
            SymmetryReason::ExpertAnnotation {
                note: "solo".into(),
            },
        );
        assert!(class.is_trivial());
    }

    #[test]
    fn symmetry_class_hash_deterministic() {
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        let axes = BTreeSet::from(["core_count".to_string()]);
        let c1 = SymmetryClass::new(
            "c1",
            "fp1",
            members.clone(),
            axes.clone(),
            SymmetryReason::WithinThreshold {
                max_distance_millionths: 1000,
                threshold_millionths: 50_000,
            },
        );
        let c2 = SymmetryClass::new(
            "c1",
            "fp1",
            members,
            axes,
            SymmetryReason::WithinThreshold {
                max_distance_millionths: 1000,
                threshold_millionths: 50_000,
            },
        );
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn symmetry_class_serde() {
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        let class = SymmetryClass::new(
            "c1",
            "fp1",
            members,
            BTreeSet::new(),
            SymmetryReason::ExpertAnnotation {
                note: "test".into(),
            },
        );
        let json = serde_json::to_string(&class).unwrap();
        let back: SymmetryClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }

    // --- ObligationStatus ---

    #[test]
    fn obligation_status_all_length() {
        assert_eq!(ObligationStatus::ALL.len(), 5);
    }

    #[test]
    fn obligation_status_names_unique() {
        let names: BTreeSet<&str> = ObligationStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), ObligationStatus::ALL.len());
    }

    #[test]
    fn obligation_status_pending_not_resolved() {
        assert!(!ObligationStatus::Pending.is_resolved());
    }

    #[test]
    fn obligation_status_discharged_resolved() {
        assert!(ObligationStatus::DischargedDirect.is_resolved());
        assert!(ObligationStatus::DischargedByTransport.is_resolved());
    }

    #[test]
    fn obligation_status_discharged_check() {
        assert!(ObligationStatus::DischargedDirect.is_discharged());
        assert!(ObligationStatus::DischargedByTransport.is_discharged());
        assert!(!ObligationStatus::Pending.is_discharged());
        assert!(!ObligationStatus::Infeasible.is_discharged());
        assert!(!ObligationStatus::Waived.is_discharged());
    }

    #[test]
    fn obligation_status_display() {
        for s in ObligationStatus::ALL {
            assert!(!s.to_string().is_empty());
        }
    }

    #[test]
    fn obligation_status_serde() {
        for s in ObligationStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: ObligationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- Obligation ---

    #[test]
    fn obligation_pending() {
        let o = Obligation::pending("fp1", "q1");
        assert_eq!(o.status, ObligationStatus::Pending);
        assert!(o.transport_source.is_none());
    }

    #[test]
    fn obligation_discharge_direct() {
        let mut o = Obligation::pending("fp1", "q1");
        o.discharge_direct();
        assert_eq!(o.status, ObligationStatus::DischargedDirect);
    }

    #[test]
    fn obligation_discharge_transport() {
        let mut o = Obligation::pending("fp2", "q1");
        o.discharge_by_transport("fp1", "class1");
        assert_eq!(o.status, ObligationStatus::DischargedByTransport);
        assert_eq!(o.transport_source.as_deref(), Some("fp1"));
        assert_eq!(o.transport_class_id.as_deref(), Some("class1"));
    }

    #[test]
    fn obligation_mark_infeasible() {
        let mut o = Obligation::pending("fp1", "q1");
        o.mark_infeasible();
        assert_eq!(o.status, ObligationStatus::Infeasible);
    }

    #[test]
    fn obligation_waive() {
        let mut o = Obligation::pending("fp1", "q1");
        o.waive();
        assert_eq!(o.status, ObligationStatus::Waived);
    }

    // --- ObligationGraph ---

    #[test]
    fn graph_empty() {
        let g = ObligationGraph::with_defaults();
        assert_eq!(g.obligation_count(), 0);
        assert_eq!(g.pending_count(), 0);
        assert_eq!(g.discharged_count(), 0);
        assert_eq!(g.coverage_millionths(), 0);
    }

    #[test]
    fn graph_generate_obligations() {
        let mut g = sample_graph();
        g.generate_obligations();
        // 3 fingerprints × 2 questions = 6
        assert_eq!(g.obligation_count(), 6);
        assert_eq!(g.pending_count(), 6);
    }

    #[test]
    fn graph_discharge_direct() {
        let mut g = sample_graph();
        g.generate_obligations();
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        assert_eq!(g.pending_count(), 5);
        assert_eq!(g.discharged_count(), 1);
    }

    #[test]
    fn graph_coverage_partial() {
        let mut g = sample_graph();
        g.generate_obligations();
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        g.find_obligation_mut("fp1", "q-gc")
            .unwrap()
            .discharge_direct();
        // 2 of 6 resolved = 333_333 (one-third)
        let cov = g.coverage_millionths();
        assert!(cov > 330_000 && cov < 340_000);
    }

    #[test]
    fn graph_coverage_full() {
        let mut g = sample_graph();
        g.generate_obligations();
        for o in &mut g.obligations {
            o.discharge_direct();
        }
        assert_eq!(g.coverage_millionths(), MILLION);
    }

    #[test]
    fn graph_symmetry_reduction() {
        let mut g = sample_graph();
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        g.add_symmetry_class(SymmetryClass::new(
            "class1",
            "fp1",
            members,
            BTreeSet::from(["core_count".to_string()]),
            SymmetryReason::WithinThreshold {
                max_distance_millionths: 1000,
                threshold_millionths: 50_000,
            },
        ));
        g.generate_obligations();
        // Discharge fp1's obligations directly
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        g.find_obligation_mut("fp1", "q-gc")
            .unwrap()
            .discharge_direct();
        // Now reduce by symmetry
        g.reduce_by_symmetry();
        // fp2's obligations should be discharged by transport
        let o_fp2_tier = g.find_obligation("fp2", "q-tiering").unwrap();
        assert_eq!(o_fp2_tier.status, ObligationStatus::DischargedByTransport);
        assert_eq!(o_fp2_tier.transport_source.as_deref(), Some("fp1"));
        let o_fp2_gc = g.find_obligation("fp2", "q-gc").unwrap();
        assert_eq!(o_fp2_gc.status, ObligationStatus::DischargedByTransport);
        // fp3 should still be pending (not in the class)
        assert_eq!(
            g.find_obligation("fp3", "q-tiering").unwrap().status,
            ObligationStatus::Pending
        );
    }

    #[test]
    fn graph_transport_reduction_ratio() {
        let mut g = sample_graph();
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        g.add_symmetry_class(SymmetryClass::new(
            "class1",
            "fp1",
            members,
            BTreeSet::new(),
            SymmetryReason::ExpertAnnotation {
                note: "test".into(),
            },
        ));
        g.generate_obligations();
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        g.find_obligation_mut("fp1", "q-gc")
            .unwrap()
            .discharge_direct();
        g.reduce_by_symmetry();
        // 4 discharged total: 2 direct + 2 transport → ratio = 500_000
        assert_eq!(g.transport_reduction_millionths(), 500_000);
    }

    #[test]
    fn graph_chebyshev_similar() {
        let g = sample_graph();
        let dist = g.chebyshev_distance("fp1", "fp2").unwrap();
        // fp1 and fp2 have similar values
        assert!(dist < 50_000);
    }

    #[test]
    fn graph_chebyshev_different() {
        let g = sample_graph();
        let dist = g.chebyshev_distance("fp1", "fp3").unwrap();
        // fp1 and fp3 have very different values
        assert!(dist > 100_000);
    }

    #[test]
    fn graph_chebyshev_unknown_fp() {
        let g = sample_graph();
        assert!(g.chebyshev_distance("fp1", "unknown").is_none());
    }

    #[test]
    fn graph_check_symmetry_within() {
        let g = sample_graph();
        let result = g.check_symmetry("fp1", "fp2");
        assert!(result.is_ok());
    }

    #[test]
    fn graph_check_symmetry_exceeds() {
        let g = sample_graph();
        let result = g.check_symmetry("fp1", "fp3");
        assert!(result.is_err());
    }

    #[test]
    fn graph_check_symmetry_unknown() {
        let g = sample_graph();
        let result = g.check_symmetry("fp1", "unknown");
        assert!(result.is_err());
    }

    #[test]
    fn graph_serde_roundtrip() {
        let mut g = sample_graph();
        g.generate_obligations();
        let json = serde_json::to_string(&g).unwrap();
        let back: ObligationGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    // --- ObligationReport ---

    #[test]
    fn report_empty_graph() {
        let g = ObligationGraph::with_defaults();
        let r = ObligationReport::from_graph(&g, epoch());
        assert_eq!(r.total_obligations, 0);
        assert!(r.is_complete());
        assert_eq!(r.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_partial() {
        let mut g = sample_graph();
        g.generate_obligations();
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        let r = ObligationReport::from_graph(&g, epoch());
        assert_eq!(r.total_obligations, 6);
        assert_eq!(r.pending_obligations, 5);
        assert_eq!(r.direct_discharges, 1);
        assert!(!r.is_complete());
    }

    #[test]
    fn report_with_transport() {
        let mut g = sample_graph();
        let members = BTreeSet::from(["fp1".to_string(), "fp2".to_string()]);
        g.add_symmetry_class(SymmetryClass::new(
            "class1",
            "fp1",
            members,
            BTreeSet::new(),
            SymmetryReason::ExpertAnnotation {
                note: "test".into(),
            },
        ));
        g.generate_obligations();
        g.find_obligation_mut("fp1", "q-tiering")
            .unwrap()
            .discharge_direct();
        g.find_obligation_mut("fp1", "q-gc")
            .unwrap()
            .discharge_direct();
        g.reduce_by_symmetry();
        let r = ObligationReport::from_graph(&g, epoch());
        assert_eq!(r.direct_discharges, 2);
        assert_eq!(r.transport_discharges, 2);
        assert_eq!(r.nontrivial_class_count, 1);
    }

    #[test]
    fn report_hash_deterministic() {
        let g = sample_graph();
        let r1 = ObligationReport::from_graph(&g, epoch());
        let r2 = ObligationReport::from_graph(&g, epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut g = sample_graph();
        g.generate_obligations();
        let r = ObligationReport::from_graph(&g, epoch());
        let json = serde_json::to_string(&r).unwrap();
        let back: ObligationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- default_hardware_axes ---

    #[test]
    fn default_axes_count() {
        let axes = default_hardware_axes();
        assert_eq!(axes.len(), 12);
    }

    #[test]
    fn default_axes_keys_unique() {
        let axes = default_hardware_axes();
        let keys: BTreeSet<&str> = axes.iter().map(|a| a.key.as_str()).collect();
        assert_eq!(keys.len(), axes.len());
    }

    #[test]
    fn default_axes_all_domains_present() {
        let axes = default_hardware_axes();
        let domains: BTreeSet<HardwareAxisDomain> = axes.iter().map(|a| a.domain).collect();
        assert_eq!(domains.len(), HardwareAxisDomain::ALL.len());
    }

    #[test]
    fn default_axes_at_least_two_required() {
        let axes = default_hardware_axes();
        let required_count = axes.iter().filter(|a| a.required).count();
        assert!(required_count >= 2);
    }

    #[test]
    fn default_axes_valid_ranges() {
        for axis in default_hardware_axes() {
            assert!(
                axis.max_millionths >= axis.min_millionths,
                "axis {} has inverted range",
                axis.key
            );
        }
    }
}
