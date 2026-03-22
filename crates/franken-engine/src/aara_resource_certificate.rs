//! AARA-backed resource certificates, effect summaries, and symbolic potentials.
//!
//! Bead: bd-1lsy.7.25.1 [RGC-625A]
//!
//! Derives symbolic potential functions, effect summaries, and resource
//! certificates over IR regions, builtin kernels, and hostcall graphs.
//! Every certificate carries explicit assumption and abstention surfaces
//! so downstream consumers know exactly what was proven and what was not.
//!
//! # Design decisions
//!
//! - **Symbolic potential** tracks amortized resource credit at each program
//!   point. If the potential stays non-negative across all paths, the
//!   resource bound is certified.
//! - **Effect summaries** enumerate side effects (allocations, hostcalls,
//!   mutations, I/O) per code region with monotone composition.
//! - **Resource certificates** are self-contained: they include the analysis
//!   inputs, derived bounds, assumption surface, and abstention surface.
//! - **Assumption surface** lists conditions the certificate depends on
//!   (e.g., bounded iteration, no eval, no dynamic dispatch).
//! - **Abstention surface** marks code points where analysis cannot produce
//!   a bound and explicitly abstains rather than risk unsoundness.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "aara_resource_certificate";
pub const BEAD_ID: &str = "bd-1lsy.7.25.1";
pub const CERTIFICATE_SCHEMA_VERSION: &str = "franken-engine.aara-resource-certificate.v1";
pub const EFFECT_SUMMARY_SCHEMA_VERSION: &str = "franken-engine.aara-effect-summary.v1";
pub const POTENTIAL_SCHEMA_VERSION: &str = "franken-engine.aara-symbolic-potential.v1";
pub const BUNDLE_SCHEMA_VERSION: &str = "franken-engine.aara-certificate-bundle.v1";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

/// Maximum number of assumptions per certificate before forced abstention.
pub const MAX_ASSUMPTIONS_PER_CERTIFICATE: usize = 64;

/// Maximum number of abstention points per region.
pub const MAX_ABSTENTION_POINTS_PER_REGION: usize = 128;

/// Minimum confidence (millionths) for a certificate to be granted.
pub const MIN_CERTIFICATE_CONFIDENCE: i64 = 900_000; // 90%

// ---------------------------------------------------------------------------
// ResourceDimension — what resource is being bounded
// ---------------------------------------------------------------------------

/// Dimension of resource consumption being tracked and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    /// Wall-clock time budget (nanoseconds as millionths).
    Time,
    /// Heap memory allocation budget (bytes as millionths).
    HeapMemory,
    /// Stack depth budget (frames as millionths).
    StackDepth,
    /// Hostcall invocation count budget.
    HostcallCount,
    /// GC pressure budget (allocation rate in bytes/s as millionths).
    GcPressure,
    /// Module load count budget.
    ModuleLoadCount,
    /// I/O operation count budget.
    IoOperationCount,
}

impl fmt::Display for ResourceDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Time => write!(f, "time"),
            Self::HeapMemory => write!(f, "heap_memory"),
            Self::StackDepth => write!(f, "stack_depth"),
            Self::HostcallCount => write!(f, "hostcall_count"),
            Self::GcPressure => write!(f, "gc_pressure"),
            Self::ModuleLoadCount => write!(f, "module_load_count"),
            Self::IoOperationCount => write!(f, "io_operation_count"),
        }
    }
}

impl ResourceDimension {
    pub const ALL: &[Self] = &[
        Self::Time,
        Self::HeapMemory,
        Self::StackDepth,
        Self::HostcallCount,
        Self::GcPressure,
        Self::ModuleLoadCount,
        Self::IoOperationCount,
    ];
}

// ---------------------------------------------------------------------------
// EffectKind — classification of side effects
// ---------------------------------------------------------------------------

/// Classification of a side effect in a code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    /// Heap allocation (object, array, closure, etc.).
    Allocation,
    /// Property mutation on an existing object.
    PropertyMutation,
    /// Global variable read.
    GlobalRead,
    /// Global variable write.
    GlobalWrite,
    /// Hostcall invocation (filesystem, network, etc.).
    Hostcall,
    /// Module import or dynamic import.
    ModuleImport,
    /// Exception throw or rejection.
    ExceptionThrow,
    /// Prototype chain traversal (hidden class transition).
    PrototypeTraversal,
    /// Closure capture (variable lifted into closure scope).
    ClosureCapture,
    /// Eval or Function() constructor (dynamic code generation).
    DynamicCodeGen,
}

impl fmt::Display for EffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => write!(f, "allocation"),
            Self::PropertyMutation => write!(f, "property_mutation"),
            Self::GlobalRead => write!(f, "global_read"),
            Self::GlobalWrite => write!(f, "global_write"),
            Self::Hostcall => write!(f, "hostcall"),
            Self::ModuleImport => write!(f, "module_import"),
            Self::ExceptionThrow => write!(f, "exception_throw"),
            Self::PrototypeTraversal => write!(f, "prototype_traversal"),
            Self::ClosureCapture => write!(f, "closure_capture"),
            Self::DynamicCodeGen => write!(f, "dynamic_code_gen"),
        }
    }
}

impl EffectKind {
    /// Whether this effect kind forces analysis abstention (cannot bound).
    pub fn forces_abstention(self) -> bool {
        matches!(self, Self::DynamicCodeGen)
    }
}

// ---------------------------------------------------------------------------
// EffectEntry — a single observed/inferred effect
// ---------------------------------------------------------------------------

/// A single effect entry within an effect summary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EffectEntry {
    /// What kind of effect.
    pub kind: EffectKind,
    /// Program point identifier (e.g., "fn:foo:line:42" or IR offset).
    pub program_point: String,
    /// Worst-case count (millionths). For loops, this is the iteration-bound
    /// multiplied count.
    pub worst_case_count_millionths: i64,
    /// Whether this count is exact or an over-approximation.
    pub is_exact: bool,
}

// ---------------------------------------------------------------------------
// EffectSummary — aggregate effects for a code region
// ---------------------------------------------------------------------------

/// Aggregate effect summary for a code region (function, loop, module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSummary {
    /// Schema version.
    pub schema_version: String,
    /// Region identifier (function name, module path, etc.).
    pub region_id: String,
    /// Individual effect entries.
    pub entries: Vec<EffectEntry>,
    /// Per-kind aggregate counts (worst case, millionths).
    pub kind_totals: BTreeMap<EffectKind, i64>,
    /// Whether this summary is complete (no abstentions within the region).
    pub is_complete: bool,
    /// Points where the analysis abstained.
    pub abstention_points: Vec<AbstentionPoint>,
    /// Content hash (deterministic).
    pub content_hash: ContentHash,
}

impl EffectSummary {
    /// Build an effect summary from a list of entries with optional abstentions.
    pub fn build(
        region_id: &str,
        entries: Vec<EffectEntry>,
        abstention_points: Vec<AbstentionPoint>,
    ) -> Self {
        let mut kind_totals = BTreeMap::new();
        for entry in &entries {
            *kind_totals.entry(entry.kind).or_insert(0i64) += entry.worst_case_count_millionths;
        }
        let is_complete = abstention_points.is_empty();

        let content_hash = Self::compute_hash(region_id, &entries, &abstention_points);

        Self {
            schema_version: EFFECT_SUMMARY_SCHEMA_VERSION.into(),
            region_id: region_id.into(),
            entries,
            kind_totals,
            is_complete,
            abstention_points,
            content_hash,
        }
    }

    /// Total effect count across all kinds (millionths).
    pub fn total_effect_count(&self) -> i64 {
        self.kind_totals.values().sum()
    }

    /// Whether the region has any dynamic code generation effects.
    pub fn has_dynamic_code_gen(&self) -> bool {
        self.kind_totals.contains_key(&EffectKind::DynamicCodeGen)
    }

    /// Whether the region is effect-free (pure).
    pub fn is_pure(&self) -> bool {
        self.entries.is_empty() && self.is_complete
    }

    /// Compose two summaries (sequential composition).
    pub fn compose(&self, other: &Self) -> Self {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.iter().cloned());

        let mut abstentions = self.abstention_points.clone();
        abstentions.extend(other.abstention_points.iter().cloned());
        abstentions.truncate(MAX_ABSTENTION_POINTS_PER_REGION);

        let region_id = format!("{}+{}", self.region_id, other.region_id);
        Self::build(&region_id, entries, abstentions)
    }

    fn compute_hash(
        region_id: &str,
        entries: &[EffectEntry],
        abstentions: &[AbstentionPoint],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(region_id.as_bytes());
        for entry in entries {
            hasher.update(format!("{}", entry.kind).as_bytes());
            hasher.update(entry.program_point.as_bytes());
            hasher.update(entry.worst_case_count_millionths.to_le_bytes());
            hasher.update([u8::from(entry.is_exact)]);
        }
        for abs in abstentions {
            hasher.update(abs.program_point.as_bytes());
            hasher.update(format!("{}", abs.reason).as_bytes());
            hasher.update(abs.detail.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// AbstentionPoint — where analysis gives up
// ---------------------------------------------------------------------------

/// A point where the resource analysis explicitly abstains.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AbstentionPoint {
    /// Program point identifier.
    pub program_point: String,
    /// Why analysis abstained.
    pub reason: AbstentionReason,
    /// Human-readable detail.
    pub detail: String,
}

/// Reason for analysis abstention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReason {
    /// Dynamic dispatch prevents static resolution.
    DynamicDispatch,
    /// Eval or Function() constructor.
    DynamicCodeGen,
    /// Unbounded loop (no provable iteration bound).
    UnboundedLoop,
    /// Recursive call cycle without provable depth bound.
    UnboundedRecursion,
    /// External hostcall with unknown resource profile.
    UnknownHostcall,
    /// Prototype mutation invalidates shape assumptions.
    PrototypeMutation,
    /// with-statement introduces dynamic scope.
    WithStatement,
    /// Proxy trap intercepts property access.
    ProxyTrap,
    /// Analysis budget exhausted before completion.
    BudgetExhausted,
}

impl fmt::Display for AbstentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DynamicDispatch => write!(f, "dynamic_dispatch"),
            Self::DynamicCodeGen => write!(f, "dynamic_code_gen"),
            Self::UnboundedLoop => write!(f, "unbounded_loop"),
            Self::UnboundedRecursion => write!(f, "unbounded_recursion"),
            Self::UnknownHostcall => write!(f, "unknown_hostcall"),
            Self::PrototypeMutation => write!(f, "prototype_mutation"),
            Self::WithStatement => write!(f, "with_statement"),
            Self::ProxyTrap => write!(f, "proxy_trap"),
            Self::BudgetExhausted => write!(f, "budget_exhausted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Assumption — conditions a certificate depends on
// ---------------------------------------------------------------------------

/// An assumption that a resource certificate depends on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CertificateAssumption {
    /// Unique key for this assumption.
    pub key: String,
    /// What kind of assumption.
    pub kind: AssumptionKind,
    /// Human-readable description.
    pub description: String,
    /// Whether violation of this assumption invalidates the entire certificate.
    pub is_critical: bool,
}

/// Kind of assumption underlying a resource certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionKind {
    /// Loop iteration is bounded by a constant or input-dependent expression.
    BoundedIteration,
    /// No eval/Function() in the analyzed region.
    NoEval,
    /// No dynamic dispatch (all call targets statically resolved).
    StaticDispatch,
    /// No prototype mutation after initialization.
    StablePrototypes,
    /// Hostcall resource profile matches declared upper bounds.
    HostcallBoundsDeclared,
    /// No with-statement in scope chain.
    NoWithStatement,
    /// No Proxy traps in property access paths.
    NoProxyTraps,
    /// Stack depth bounded by a known constant.
    BoundedStackDepth,
    /// Input size bounded by a declared maximum.
    BoundedInputSize,
}

impl fmt::Display for AssumptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundedIteration => write!(f, "bounded_iteration"),
            Self::NoEval => write!(f, "no_eval"),
            Self::StaticDispatch => write!(f, "static_dispatch"),
            Self::StablePrototypes => write!(f, "stable_prototypes"),
            Self::HostcallBoundsDeclared => write!(f, "hostcall_bounds_declared"),
            Self::NoWithStatement => write!(f, "no_with_statement"),
            Self::NoProxyTraps => write!(f, "no_proxy_traps"),
            Self::BoundedStackDepth => write!(f, "bounded_stack_depth"),
            Self::BoundedInputSize => write!(f, "bounded_input_size"),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolicPotential — amortized resource credit at program points
// ---------------------------------------------------------------------------

/// A symbolic potential function mapping program points to amortized resource
/// credits. The AARA invariant: if the potential stays non-negative on all
/// paths through the region, the resource bound holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicPotential {
    /// Schema version.
    pub schema_version: String,
    /// Region this potential covers.
    pub region_id: String,
    /// Which resource dimension this potential tracks.
    pub dimension: ResourceDimension,
    /// Initial potential at region entry (millionths).
    pub initial_potential_millionths: i64,
    /// Per-program-point potentials (millionths). Positive means credit
    /// remains; negative means the bound is violated on that path.
    pub point_potentials: BTreeMap<String, i64>,
    /// Minimum potential across all program points (millionths).
    pub min_potential_millionths: i64,
    /// Whether the potential is non-negative everywhere (bound holds).
    pub is_valid: bool,
    /// Content hash (deterministic).
    pub content_hash: ContentHash,
}

impl SymbolicPotential {
    /// Create a new symbolic potential from program-point credits.
    pub fn new(
        region_id: &str,
        dimension: ResourceDimension,
        initial_potential: i64,
        point_potentials: BTreeMap<String, i64>,
    ) -> Self {
        let min_potential = point_potentials
            .values()
            .copied()
            .min()
            .unwrap_or(initial_potential);
        let is_valid = min_potential >= 0;

        let content_hash =
            Self::compute_hash(region_id, dimension, initial_potential, &point_potentials);

        Self {
            schema_version: POTENTIAL_SCHEMA_VERSION.into(),
            region_id: region_id.into(),
            dimension,
            initial_potential_millionths: initial_potential,
            point_potentials,
            min_potential_millionths: min_potential,
            is_valid,
            content_hash,
        }
    }

    /// Terminal potential (potential at the last program point, or initial
    /// if no points).
    pub fn terminal_potential(&self) -> i64 {
        self.point_potentials
            .values()
            .last()
            .copied()
            .unwrap_or(self.initial_potential_millionths)
    }

    /// Number of program points tracked.
    pub fn point_count(&self) -> usize {
        self.point_potentials.len()
    }

    /// Fraction of points with non-negative potential (millionths).
    pub fn non_negative_fraction_millionths(&self) -> i64 {
        if self.point_potentials.is_empty() {
            return MILLION;
        }
        let non_neg = self.point_potentials.values().filter(|&&v| v >= 0).count() as i64;
        let total = self.point_potentials.len() as i64;
        non_neg.checked_mul(MILLION).unwrap_or(0) / total
    }

    fn compute_hash(
        region_id: &str,
        dimension: ResourceDimension,
        initial: i64,
        points: &BTreeMap<String, i64>,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(region_id.as_bytes());
        hasher.update([dimension as u8]);
        hasher.update(initial.to_le_bytes());
        for (key, &val) in points {
            hasher.update(key.as_bytes());
            hasher.update(val.to_le_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// ResourceBound — a concrete bound on resource usage
// ---------------------------------------------------------------------------

/// A concrete resource bound for a single dimension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceBound {
    /// Which resource dimension.
    pub dimension: ResourceDimension,
    /// Upper bound on resource consumption (millionths).
    pub upper_bound_millionths: i64,
    /// Whether this bound is tight (exact worst case) or an over-approximation.
    pub is_tight: bool,
    /// Confidence in the bound (millionths). 1_000_000 = fully proven.
    pub confidence_millionths: i64,
}

impl ResourceBound {
    /// Whether this bound meets the minimum confidence threshold.
    pub fn meets_confidence_threshold(&self) -> bool {
        self.confidence_millionths >= MIN_CERTIFICATE_CONFIDENCE
    }

    /// Compose two bounds (sequential composition: sum the upper bounds,
    /// take the minimum confidence).
    pub fn compose(&self, other: &Self) -> Option<Self> {
        if self.dimension != other.dimension {
            return None;
        }
        Some(Self {
            dimension: self.dimension,
            upper_bound_millionths: self
                .upper_bound_millionths
                .saturating_add(other.upper_bound_millionths),
            is_tight: self.is_tight && other.is_tight,
            confidence_millionths: self.confidence_millionths.min(other.confidence_millionths),
        })
    }
}

// ---------------------------------------------------------------------------
// CertificateVerdict — outcome of resource certification
// ---------------------------------------------------------------------------

/// Verdict of a resource certificate analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateVerdict {
    /// All resource bounds certified; potential non-negative everywhere.
    Certified,
    /// Bounds computed but at least one is below confidence threshold.
    Provisional,
    /// Analysis abstained on at least one critical path.
    Abstained,
    /// Analysis proved a bound violation exists.
    Violated,
}

impl fmt::Display for CertificateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certified => write!(f, "certified"),
            Self::Provisional => write!(f, "provisional"),
            Self::Abstained => write!(f, "abstained"),
            Self::Violated => write!(f, "violated"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceCertificate — the main certificate type
// ---------------------------------------------------------------------------

struct CertificateHashInput<'a> {
    bounds: &'a [ResourceBound],
    effect_summary: &'a EffectSummary,
    assumptions: &'a [CertificateAssumption],
    abstention_points: &'a [AbstentionPoint],
    potentials: &'a [SymbolicPotential],
}

/// A certified resource bound for a code region.
///
/// Self-contained: includes the analysis inputs, derived bounds, assumptions,
/// abstention points, and supporting potential functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCertificate {
    /// Schema version.
    pub schema_version: String,
    /// Certificate identifier.
    pub certificate_id: String,
    /// Region being certified.
    pub region_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Overall verdict.
    pub verdict: CertificateVerdict,
    /// Per-dimension resource bounds.
    pub bounds: Vec<ResourceBound>,
    /// Effect summary for the region.
    pub effect_summary: EffectSummary,
    /// Assumptions this certificate depends on.
    pub assumptions: Vec<CertificateAssumption>,
    /// Abstention points where analysis could not proceed.
    pub abstention_points: Vec<AbstentionPoint>,
    /// Supporting symbolic potentials (one per dimension that was analyzed).
    pub potentials: Vec<SymbolicPotential>,
    /// Content hash (deterministic).
    pub content_hash: ContentHash,
}

/// Input for constructing a [`ResourceCertificate`].
#[derive(Debug, Clone)]
pub struct CertificateInput {
    /// Certificate identifier.
    pub certificate_id: String,
    /// Region being certified.
    pub region_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Per-dimension resource bounds.
    pub bounds: Vec<ResourceBound>,
    /// Effect summary for the region.
    pub effect_summary: EffectSummary,
    /// Assumptions this certificate depends on.
    pub assumptions: Vec<CertificateAssumption>,
    /// Abstention points where analysis could not proceed.
    pub abstention_points: Vec<AbstentionPoint>,
    /// Supporting symbolic potentials (one per dimension that was analyzed).
    pub potentials: Vec<SymbolicPotential>,
}

impl ResourceCertificate {
    /// Create a new resource certificate from input.
    pub fn new(input: CertificateInput) -> Self {
        let CertificateInput {
            certificate_id,
            region_id,
            epoch,
            bounds,
            effect_summary,
            assumptions,
            abstention_points: input_abstention_points,
            potentials,
        } = input;
        let mut abstention_points = input_abstention_points;
        for abstention in &effect_summary.abstention_points {
            if !abstention_points.contains(abstention) {
                abstention_points.push(abstention.clone());
            }
        }

        let verdict = Self::compute_verdict(&bounds, &abstention_points, &potentials);

        let content_hash = Self::compute_hash(
            &certificate_id,
            &region_id,
            epoch,
            verdict,
            CertificateHashInput {
                bounds: &bounds,
                effect_summary: &effect_summary,
                assumptions: &assumptions,
                abstention_points: &abstention_points,
                potentials: &potentials,
            },
        );

        Self {
            schema_version: CERTIFICATE_SCHEMA_VERSION.into(),
            certificate_id,
            region_id,
            epoch,
            verdict,
            bounds,
            effect_summary,
            assumptions,
            abstention_points,
            potentials,
            content_hash,
        }
    }

    /// Number of dimensions with certified bounds.
    pub fn certified_dimension_count(&self) -> usize {
        self.bounds
            .iter()
            .filter(|b| b.meets_confidence_threshold())
            .count()
    }

    /// Whether all potentials are valid (non-negative everywhere).
    pub fn all_potentials_valid(&self) -> bool {
        self.potentials.iter().all(|p| p.is_valid)
    }

    /// Get the bound for a specific dimension.
    pub fn bound_for(&self, dim: ResourceDimension) -> Option<&ResourceBound> {
        self.bounds.iter().find(|b| b.dimension == dim)
    }

    /// Whether any critical assumption could be violated.
    pub fn has_critical_assumptions(&self) -> bool {
        self.assumptions.iter().any(|a| a.is_critical)
    }

    /// Set of resource dimensions covered by this certificate.
    pub fn covered_dimensions(&self) -> BTreeSet<ResourceDimension> {
        self.bounds.iter().map(|b| b.dimension).collect()
    }

    fn compute_verdict(
        bounds: &[ResourceBound],
        abstention_points: &[AbstentionPoint],
        potentials: &[SymbolicPotential],
    ) -> CertificateVerdict {
        // Negative bounds or invalid potentials indicate an inconsistent proof artifact.
        if bounds.iter().any(|b| b.upper_bound_millionths < 0)
            || potentials.iter().any(|p| !p.is_valid)
        {
            return CertificateVerdict::Violated;
        }

        // If there are abstention points, verdict is Abstained
        if !abstention_points.is_empty() {
            return CertificateVerdict::Abstained;
        }

        // A certificate with no derived bounds is incomplete and must not certify.
        if bounds.is_empty() {
            return CertificateVerdict::Provisional;
        }

        // If all bounds meet confidence, verdict is Certified
        if bounds.iter().all(|b| b.meets_confidence_threshold()) {
            return CertificateVerdict::Certified;
        }

        // Otherwise provisional
        CertificateVerdict::Provisional
    }

    fn compute_hash(
        certificate_id: &str,
        region_id: &str,
        epoch: SecurityEpoch,
        verdict: CertificateVerdict,
        input: CertificateHashInput<'_>,
    ) -> ContentHash {
        let CertificateHashInput {
            bounds,
            effect_summary,
            assumptions,
            abstention_points,
            potentials,
        } = input;
        let mut hasher = Sha256::new();
        hasher.update(certificate_id.as_bytes());
        hasher.update(region_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update([verdict as u8]);
        for bound in bounds {
            hasher.update([bound.dimension as u8]);
            hasher.update(bound.upper_bound_millionths.to_le_bytes());
            hasher.update([u8::from(bound.is_tight)]);
            hasher.update(bound.confidence_millionths.to_le_bytes());
        }
        hasher.update(effect_summary.content_hash.as_bytes());
        for assumption in assumptions {
            hasher.update(assumption.key.as_bytes());
            hasher.update(format!("{}", assumption.kind).as_bytes());
            hasher.update(assumption.description.as_bytes());
            hasher.update([u8::from(assumption.is_critical)]);
        }
        for abstention in abstention_points {
            hasher.update(abstention.program_point.as_bytes());
            hasher.update(format!("{}", abstention.reason).as_bytes());
            hasher.update(abstention.detail.as_bytes());
        }
        for potential in potentials {
            hasher.update(potential.content_hash.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// CertificateBundle — collection of certificates for a compilation unit
// ---------------------------------------------------------------------------

/// A bundle of resource certificates for a compilation unit (module, package).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBundle {
    /// Schema version.
    pub schema_version: String,
    /// Bundle identifier.
    pub bundle_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Individual certificates.
    pub certificates: Vec<ResourceCertificate>,
    /// Aggregate: how many regions are fully certified.
    pub certified_count: usize,
    /// Aggregate: how many regions have at least one abstention.
    pub abstained_count: usize,
    /// Aggregate: how many regions have a violated potential.
    pub violated_count: usize,
    /// Content hash of the bundle.
    pub content_hash: ContentHash,
}

impl CertificateBundle {
    /// Build a bundle from a set of certificates.
    pub fn build(
        bundle_id: &str,
        epoch: SecurityEpoch,
        certificates: Vec<ResourceCertificate>,
    ) -> Self {
        let certified_count = certificates
            .iter()
            .filter(|c| c.verdict == CertificateVerdict::Certified)
            .count();
        let abstained_count = certificates
            .iter()
            .filter(|c| c.verdict == CertificateVerdict::Abstained)
            .count();
        let violated_count = certificates
            .iter()
            .filter(|c| c.verdict == CertificateVerdict::Violated)
            .count();

        let content_hash = Self::compute_hash(bundle_id, epoch, &certificates);

        Self {
            schema_version: BUNDLE_SCHEMA_VERSION.into(),
            bundle_id: bundle_id.into(),
            epoch,
            certificates,
            certified_count,
            abstained_count,
            violated_count,
            content_hash,
        }
    }

    /// Total number of certificates in the bundle.
    pub fn total_count(&self) -> usize {
        self.certificates.len()
    }

    /// Certification rate (millionths). Certified / total.
    pub fn certification_rate_millionths(&self) -> i64 {
        if self.certificates.is_empty() {
            return 0;
        }
        let total = self.certificates.len() as i64;
        (self.certified_count as i64)
            .checked_mul(MILLION)
            .unwrap_or(0)
            / total
    }

    /// Whether the bundle passes (no violations and certification rate above threshold).
    pub fn passes(&self, min_rate_millionths: i64) -> bool {
        self.violated_count == 0 && self.certification_rate_millionths() >= min_rate_millionths
    }

    fn compute_hash(
        bundle_id: &str,
        epoch: SecurityEpoch,
        certificates: &[ResourceCertificate],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(bundle_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        for cert in certificates {
            hasher.update(cert.content_hash.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_effect_entry(kind: EffectKind, point: &str, count: i64) -> EffectEntry {
        EffectEntry {
            kind,
            program_point: point.into(),
            worst_case_count_millionths: count,
            is_exact: true,
        }
    }

    fn test_abstention(point: &str, reason: AbstentionReason) -> AbstentionPoint {
        AbstentionPoint {
            program_point: point.into(),
            reason,
            detail: format!("test abstention at {point}"),
        }
    }

    fn test_assumption(key: &str, kind: AssumptionKind) -> CertificateAssumption {
        CertificateAssumption {
            key: key.into(),
            kind,
            description: format!("test assumption: {key}"),
            is_critical: true,
        }
    }

    fn test_bound(dim: ResourceDimension, upper: i64, confidence: i64) -> ResourceBound {
        ResourceBound {
            dimension: dim,
            upper_bound_millionths: upper,
            is_tight: false,
            confidence_millionths: confidence,
        }
    }

    fn test_potential(
        region: &str,
        dim: ResourceDimension,
        initial: i64,
        points: Vec<(&str, i64)>,
    ) -> SymbolicPotential {
        let mut map = BTreeMap::new();
        for (k, v) in points {
            map.insert(k.into(), v);
        }
        SymbolicPotential::new(region, dim, initial, map)
    }

    fn make_cert(
        id: &str,
        region: &str,
        bounds: Vec<ResourceBound>,
        summary: EffectSummary,
        assumptions: Vec<CertificateAssumption>,
        abs: Vec<AbstentionPoint>,
        potentials: Vec<SymbolicPotential>,
    ) -> ResourceCertificate {
        ResourceCertificate::new(CertificateInput {
            certificate_id: id.into(),
            region_id: region.into(),
            epoch: test_epoch(),
            bounds,
            effect_summary: summary,
            assumptions,
            abstention_points: abs,
            potentials,
        })
    }

    // --- ResourceDimension ---

    #[test]
    fn dimension_display_all() {
        for dim in ResourceDimension::ALL {
            let s = format!("{dim}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn dimension_serde_roundtrip() {
        for dim in ResourceDimension::ALL {
            let json = serde_json::to_string(dim).unwrap();
            let back: ResourceDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(*dim, back);
        }
    }

    #[test]
    fn dimension_ordering() {
        assert!(ResourceDimension::Time < ResourceDimension::HeapMemory);
        assert!(ResourceDimension::HeapMemory < ResourceDimension::StackDepth);
    }

    // --- EffectKind ---

    #[test]
    fn effect_kind_display() {
        assert_eq!(format!("{}", EffectKind::Allocation), "allocation");
        assert_eq!(format!("{}", EffectKind::Hostcall), "hostcall");
        assert_eq!(
            format!("{}", EffectKind::DynamicCodeGen),
            "dynamic_code_gen"
        );
    }

    #[test]
    fn effect_kind_forces_abstention() {
        assert!(EffectKind::DynamicCodeGen.forces_abstention());
        assert!(!EffectKind::Allocation.forces_abstention());
        assert!(!EffectKind::Hostcall.forces_abstention());
    }

    // --- EffectSummary ---

    #[test]
    fn effect_summary_empty_is_pure() {
        let summary = EffectSummary::build("pure_fn", vec![], vec![]);
        assert!(summary.is_pure());
        assert!(summary.is_complete);
        assert_eq!(summary.total_effect_count(), 0);
    }

    #[test]
    fn effect_summary_with_entries() {
        let entries = vec![
            test_effect_entry(EffectKind::Allocation, "fn:foo:12", 3 * MILLION),
            test_effect_entry(EffectKind::Hostcall, "fn:foo:15", MILLION),
        ];
        let summary = EffectSummary::build("fn:foo", entries, vec![]);
        assert!(!summary.is_pure());
        assert!(summary.is_complete);
        assert_eq!(summary.total_effect_count(), 4 * MILLION);
        assert_eq!(
            *summary.kind_totals.get(&EffectKind::Allocation).unwrap(),
            3 * MILLION
        );
    }

    #[test]
    fn effect_summary_with_abstention() {
        let entries = vec![test_effect_entry(
            EffectKind::Allocation,
            "fn:bar:5",
            MILLION,
        )];
        let abs = vec![test_abstention(
            "fn:bar:10",
            AbstentionReason::DynamicCodeGen,
        )];
        let summary = EffectSummary::build("fn:bar", entries, abs);
        assert!(!summary.is_complete);
        assert!(!summary.is_pure());
    }

    #[test]
    fn effect_summary_has_dynamic_code_gen() {
        let entries = vec![test_effect_entry(
            EffectKind::DynamicCodeGen,
            "eval:1",
            MILLION,
        )];
        let summary = EffectSummary::build("eval_region", entries, vec![]);
        assert!(summary.has_dynamic_code_gen());
    }

    #[test]
    fn effect_summary_compose() {
        let s1 = EffectSummary::build(
            "a",
            vec![test_effect_entry(EffectKind::Allocation, "a:1", MILLION)],
            vec![],
        );
        let s2 = EffectSummary::build(
            "b",
            vec![test_effect_entry(
                EffectKind::Allocation,
                "b:1",
                2 * MILLION,
            )],
            vec![],
        );
        let composed = s1.compose(&s2);
        assert_eq!(composed.total_effect_count(), 3 * MILLION);
        assert_eq!(composed.region_id, "a+b");
    }

    #[test]
    fn effect_summary_serde_roundtrip() {
        let summary = EffectSummary::build(
            "test",
            vec![test_effect_entry(EffectKind::Hostcall, "p1", MILLION)],
            vec![],
        );
        let json = serde_json::to_string(&summary).unwrap();
        let back: EffectSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn effect_summary_deterministic_hash() {
        let s1 = EffectSummary::build(
            "det",
            vec![test_effect_entry(EffectKind::Allocation, "p1", MILLION)],
            vec![],
        );
        let s2 = EffectSummary::build(
            "det",
            vec![test_effect_entry(EffectKind::Allocation, "p1", MILLION)],
            vec![],
        );
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // --- AbstentionReason ---

    #[test]
    fn abstention_reason_display() {
        assert_eq!(
            format!("{}", AbstentionReason::DynamicDispatch),
            "dynamic_dispatch"
        );
        assert_eq!(
            format!("{}", AbstentionReason::UnboundedLoop),
            "unbounded_loop"
        );
        assert_eq!(
            format!("{}", AbstentionReason::BudgetExhausted),
            "budget_exhausted"
        );
    }

    #[test]
    fn abstention_reason_serde_roundtrip() {
        for reason in [
            AbstentionReason::DynamicDispatch,
            AbstentionReason::DynamicCodeGen,
            AbstentionReason::UnboundedLoop,
            AbstentionReason::UnboundedRecursion,
            AbstentionReason::UnknownHostcall,
            AbstentionReason::PrototypeMutation,
            AbstentionReason::WithStatement,
            AbstentionReason::ProxyTrap,
            AbstentionReason::BudgetExhausted,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: AbstentionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    // --- AssumptionKind ---

    #[test]
    fn assumption_kind_display() {
        assert_eq!(
            format!("{}", AssumptionKind::BoundedIteration),
            "bounded_iteration"
        );
        assert_eq!(format!("{}", AssumptionKind::NoEval), "no_eval");
        assert_eq!(
            format!("{}", AssumptionKind::NoProxyTraps),
            "no_proxy_traps"
        );
    }

    #[test]
    fn assumption_kind_serde_roundtrip() {
        for kind in [
            AssumptionKind::BoundedIteration,
            AssumptionKind::NoEval,
            AssumptionKind::StaticDispatch,
            AssumptionKind::StablePrototypes,
            AssumptionKind::HostcallBoundsDeclared,
            AssumptionKind::NoWithStatement,
            AssumptionKind::NoProxyTraps,
            AssumptionKind::BoundedStackDepth,
            AssumptionKind::BoundedInputSize,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: AssumptionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // --- SymbolicPotential ---

    #[test]
    fn potential_valid_when_all_non_negative() {
        let pot = test_potential(
            "fn:f",
            ResourceDimension::Time,
            10 * MILLION,
            vec![
                ("entry", 10 * MILLION),
                ("loop_head", 5 * MILLION),
                ("exit", 2 * MILLION),
            ],
        );
        assert!(pot.is_valid);
        assert_eq!(pot.min_potential_millionths, 2 * MILLION);
    }

    #[test]
    fn potential_invalid_when_negative() {
        let pot = test_potential(
            "fn:g",
            ResourceDimension::HeapMemory,
            5 * MILLION,
            vec![
                ("entry", 5 * MILLION),
                ("alloc_heavy", -MILLION),
                ("exit", 0),
            ],
        );
        assert!(!pot.is_valid);
        assert_eq!(pot.min_potential_millionths, -MILLION);
    }

    #[test]
    fn potential_empty_points() {
        let pot = SymbolicPotential::new(
            "empty",
            ResourceDimension::StackDepth,
            MILLION,
            BTreeMap::new(),
        );
        assert!(pot.is_valid);
        assert_eq!(pot.point_count(), 0);
        assert_eq!(pot.terminal_potential(), MILLION);
    }

    #[test]
    fn potential_non_negative_fraction() {
        let pot = test_potential(
            "fn:h",
            ResourceDimension::Time,
            10 * MILLION,
            vec![
                ("a", 10 * MILLION),
                ("b", -MILLION),
                ("c", 5 * MILLION),
                ("d", -2 * MILLION),
            ],
        );
        // 2 out of 4 are non-negative
        assert_eq!(pot.non_negative_fraction_millionths(), 500_000);
    }

    #[test]
    fn potential_serde_roundtrip() {
        let pot = test_potential(
            "fn:i",
            ResourceDimension::GcPressure,
            3 * MILLION,
            vec![("start", 3 * MILLION), ("end", MILLION)],
        );
        let json = serde_json::to_string(&pot).unwrap();
        let back: SymbolicPotential = serde_json::from_str(&json).unwrap();
        assert_eq!(pot, back);
    }

    #[test]
    fn potential_deterministic_hash() {
        let p1 = test_potential(
            "fn:j",
            ResourceDimension::Time,
            MILLION,
            vec![("a", 500_000)],
        );
        let p2 = test_potential(
            "fn:j",
            ResourceDimension::Time,
            MILLION,
            vec![("a", 500_000)],
        );
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    // --- ResourceBound ---

    #[test]
    fn bound_meets_threshold() {
        let bound = test_bound(ResourceDimension::Time, 10 * MILLION, MILLION);
        assert!(bound.meets_confidence_threshold());

        let weak = test_bound(ResourceDimension::Time, 10 * MILLION, 500_000);
        assert!(!weak.meets_confidence_threshold());
    }

    #[test]
    fn bound_compose_same_dimension() {
        let b1 = test_bound(ResourceDimension::HeapMemory, 5 * MILLION, 950_000);
        let b2 = test_bound(ResourceDimension::HeapMemory, 3 * MILLION, MILLION);
        let composed = b1.compose(&b2).unwrap();
        assert_eq!(composed.upper_bound_millionths, 8 * MILLION);
        assert_eq!(composed.confidence_millionths, 950_000);
    }

    #[test]
    fn bound_compose_different_dimension_none() {
        let b1 = test_bound(ResourceDimension::Time, MILLION, MILLION);
        let b2 = test_bound(ResourceDimension::HeapMemory, MILLION, MILLION);
        assert!(b1.compose(&b2).is_none());
    }

    #[test]
    fn bound_serde_roundtrip() {
        let bound = test_bound(ResourceDimension::HostcallCount, 100 * MILLION, 980_000);
        let json = serde_json::to_string(&bound).unwrap();
        let back: ResourceBound = serde_json::from_str(&json).unwrap();
        assert_eq!(bound, back);
    }

    // --- CertificateVerdict ---

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", CertificateVerdict::Certified), "certified");
        assert_eq!(
            format!("{}", CertificateVerdict::Provisional),
            "provisional"
        );
        assert_eq!(format!("{}", CertificateVerdict::Abstained), "abstained");
        assert_eq!(format!("{}", CertificateVerdict::Violated), "violated");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in [
            CertificateVerdict::Certified,
            CertificateVerdict::Provisional,
            CertificateVerdict::Abstained,
            CertificateVerdict::Violated,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- ResourceCertificate ---

    #[test]
    fn certificate_certified_verdict() {
        let summary = EffectSummary::build("fn:x", vec![], vec![]);
        let bounds = vec![test_bound(ResourceDimension::Time, 10 * MILLION, MILLION)];
        let potentials = vec![test_potential(
            "fn:x",
            ResourceDimension::Time,
            10 * MILLION,
            vec![("entry", 10 * MILLION), ("exit", 5 * MILLION)],
        )];
        let cert = make_cert(
            "cert-1",
            "fn:x",
            bounds,
            summary,
            vec![test_assumption("no_eval", AssumptionKind::NoEval)],
            vec![],
            potentials,
        );
        assert_eq!(cert.verdict, CertificateVerdict::Certified);
        assert!(cert.all_potentials_valid());
        assert_eq!(cert.certified_dimension_count(), 1);
    }

    #[test]
    fn certificate_abstained_verdict() {
        let summary = EffectSummary::build("fn:y", vec![], vec![]);
        let bounds = vec![test_bound(ResourceDimension::Time, 10 * MILLION, MILLION)];
        let abs = vec![test_abstention(
            "fn:y:eval",
            AbstentionReason::DynamicCodeGen,
        )];
        let cert = make_cert("cert-2", "fn:y", bounds, summary, vec![], abs, vec![]);
        assert_eq!(cert.verdict, CertificateVerdict::Abstained);
    }

    #[test]
    fn certificate_violated_verdict() {
        let summary = EffectSummary::build("fn:z", vec![], vec![]);
        let bounds = vec![test_bound(
            ResourceDimension::HeapMemory,
            100 * MILLION,
            MILLION,
        )];
        let potentials = vec![test_potential(
            "fn:z",
            ResourceDimension::HeapMemory,
            5 * MILLION,
            vec![("alloc_bomb", -10 * MILLION)],
        )];
        let cert = make_cert(
            "cert-3",
            "fn:z",
            bounds,
            summary,
            vec![],
            vec![],
            potentials,
        );
        assert_eq!(cert.verdict, CertificateVerdict::Violated);
    }

    #[test]
    fn certificate_provisional_verdict() {
        let summary = EffectSummary::build("fn:w", vec![], vec![]);
        let bounds = vec![test_bound(ResourceDimension::Time, 10 * MILLION, 500_000)];
        let potentials = vec![test_potential(
            "fn:w",
            ResourceDimension::Time,
            MILLION,
            vec![("a", 500_000)],
        )];
        let cert = make_cert(
            "cert-4",
            "fn:w",
            bounds,
            summary,
            vec![],
            vec![],
            potentials,
        );
        assert_eq!(cert.verdict, CertificateVerdict::Provisional);
    }

    #[test]
    fn certificate_covered_dimensions() {
        let summary = EffectSummary::build("fn:multi", vec![], vec![]);
        let bounds = vec![
            test_bound(ResourceDimension::Time, 10 * MILLION, MILLION),
            test_bound(ResourceDimension::HeapMemory, 50 * MILLION, MILLION),
        ];
        let cert = make_cert(
            "cert-5",
            "fn:multi",
            bounds,
            summary,
            vec![],
            vec![],
            vec![],
        );
        let dims = cert.covered_dimensions();
        assert!(dims.contains(&ResourceDimension::Time));
        assert!(dims.contains(&ResourceDimension::HeapMemory));
        assert!(!dims.contains(&ResourceDimension::StackDepth));
    }

    #[test]
    fn certificate_bound_for_dimension() {
        let summary = EffectSummary::build("fn:q", vec![], vec![]);
        let bounds = vec![
            test_bound(ResourceDimension::Time, 10 * MILLION, MILLION),
            test_bound(ResourceDimension::HostcallCount, 5 * MILLION, MILLION),
        ];
        let cert = make_cert("cert-6", "fn:q", bounds, summary, vec![], vec![], vec![]);
        assert!(cert.bound_for(ResourceDimension::Time).is_some());
        assert!(cert.bound_for(ResourceDimension::HostcallCount).is_some());
        assert!(cert.bound_for(ResourceDimension::GcPressure).is_none());
    }

    #[test]
    fn certificate_has_critical_assumptions() {
        let summary = EffectSummary::build("fn:r", vec![], vec![]);
        let cert_with = make_cert(
            "cert-7",
            "fn:r",
            vec![],
            summary.clone(),
            vec![test_assumption("eval_free", AssumptionKind::NoEval)],
            vec![],
            vec![],
        );
        assert!(cert_with.has_critical_assumptions());

        let cert_without = make_cert("cert-8", "fn:r", vec![], summary, vec![], vec![], vec![]);
        assert!(!cert_without.has_critical_assumptions());
    }

    #[test]
    fn certificate_serde_roundtrip() {
        let summary = EffectSummary::build("fn:serde", vec![], vec![]);
        let cert = make_cert(
            "cert-serde",
            "fn:serde",
            vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
            summary,
            vec![],
            vec![],
            vec![],
        );
        let json = serde_json::to_string(&cert).unwrap();
        let back: ResourceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    #[test]
    fn certificate_deterministic_hash() {
        let summary1 = EffectSummary::build("fn:det", vec![], vec![]);
        let summary2 = EffectSummary::build("fn:det", vec![], vec![]);
        let c1 = make_cert(
            "cert-det",
            "fn:det",
            vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
            summary1,
            vec![],
            vec![],
            vec![],
        );
        let c2 = make_cert(
            "cert-det",
            "fn:det",
            vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
            summary2,
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    // --- CertificateBundle ---

    #[test]
    fn bundle_empty() {
        let bundle = CertificateBundle::build("empty", test_epoch(), vec![]);
        assert_eq!(bundle.total_count(), 0);
        assert_eq!(bundle.certification_rate_millionths(), 0);
        assert!(!bundle.passes(500_000));
    }

    #[test]
    fn bundle_all_certified() {
        let certs = (0..3)
            .map(|i| {
                let summary = EffectSummary::build(&format!("fn:{i}"), vec![], vec![]);
                make_cert(
                    &format!("cert-{i}"),
                    &format!("fn:{i}"),
                    vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
                    summary,
                    vec![],
                    vec![],
                    vec![test_potential(
                        &format!("fn:{i}"),
                        ResourceDimension::Time,
                        MILLION,
                        vec![("exit", 500_000)],
                    )],
                )
            })
            .collect();
        let bundle = CertificateBundle::build("all-cert", test_epoch(), certs);
        assert_eq!(bundle.certified_count, 3);
        assert_eq!(bundle.certification_rate_millionths(), MILLION);
        assert!(bundle.passes(900_000));
    }

    #[test]
    fn bundle_mixed_verdicts() {
        let cert = make_cert(
            "c1",
            "fn:a",
            vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
            EffectSummary::build("fn:a", vec![], vec![]),
            vec![],
            vec![],
            vec![test_potential(
                "fn:a",
                ResourceDimension::Time,
                MILLION,
                vec![("x", 500_000)],
            )],
        );
        let abstained = make_cert(
            "c2",
            "fn:b",
            vec![],
            EffectSummary::build("fn:b", vec![], vec![]),
            vec![],
            vec![test_abstention(
                "fn:b:eval",
                AbstentionReason::DynamicCodeGen,
            )],
            vec![],
        );
        let bundle = CertificateBundle::build("mixed", test_epoch(), vec![cert, abstained]);
        assert_eq!(bundle.certified_count, 1);
        assert_eq!(bundle.abstained_count, 1);
        assert_eq!(bundle.violated_count, 0);
        assert_eq!(bundle.certification_rate_millionths(), 500_000);
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let bundle = CertificateBundle::build("serde", test_epoch(), vec![]);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: CertificateBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn bundle_deterministic_hash() {
        let b1 = CertificateBundle::build("det", test_epoch(), vec![]);
        let b2 = CertificateBundle::build("det", test_epoch(), vec![]);
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn bundle_passes_with_violations() {
        let violated = make_cert(
            "v1",
            "fn:v",
            vec![test_bound(ResourceDimension::Time, MILLION, MILLION)],
            EffectSummary::build("fn:v", vec![], vec![]),
            vec![],
            vec![],
            vec![test_potential(
                "fn:v",
                ResourceDimension::Time,
                MILLION,
                vec![("x", -1)],
            )],
        );
        let bundle = CertificateBundle::build("violated", test_epoch(), vec![violated]);
        assert_eq!(bundle.violated_count, 1);
        assert!(!bundle.passes(0));
    }

    // --- EffectEntry serde ---

    #[test]
    fn effect_entry_serde_roundtrip() {
        let entry = test_effect_entry(EffectKind::Allocation, "fn:test:1", 5 * MILLION);
        let json = serde_json::to_string(&entry).unwrap();
        let back: EffectEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- CertificateAssumption serde ---

    #[test]
    fn assumption_serde_roundtrip() {
        let a = test_assumption("no_eval", AssumptionKind::NoEval);
        let json = serde_json::to_string(&a).unwrap();
        let back: CertificateAssumption = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- AbstentionPoint serde ---

    #[test]
    fn abstention_point_serde_roundtrip() {
        let abs = test_abstention("fn:test:eval", AbstentionReason::DynamicCodeGen);
        let json = serde_json::to_string(&abs).unwrap();
        let back: AbstentionPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(abs, back);
    }
}
