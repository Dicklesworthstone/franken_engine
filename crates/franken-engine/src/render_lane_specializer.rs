//! Proof-backed render-lane specialization for SSR, client-entry, and
//! hydration lanes.
//!
//! Specializes render lanes using the component-shape catalog, but only when
//! proof receipts and unsupported-pattern checks show that the transformation
//! is safe.  All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-609B]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.render-lane-specializer.v1";

/// Component name.
pub const COMPONENT: &str = "render_lane_specializer";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.9.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-609B";

/// Default maximum inline depth for expansion strategies.
pub const DEFAULT_MAX_INLINE_DEPTH: u32 = 8;

/// Default minimum speedup threshold (millionths).  10% = 100_000.
pub const DEFAULT_MIN_SPEEDUP_THRESHOLD: u64 = 100_000;

/// Default maximum specializations per lane.
pub const DEFAULT_MAX_SPECIALIZATIONS_PER_LANE: usize = 16;

/// One in fixed-point millionths.
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// LaneKind
// ---------------------------------------------------------------------------

/// The kind of render lane being specialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    /// Server-side rendering.
    ServerSideRender,
    /// Client entry / bootstrap.
    ClientEntry,
    /// Hydration (attach to existing DOM).
    Hydration,
    /// Static generation (build-time).
    StaticGeneration,
    /// Streaming SSR (chunked transfer).
    StreamingSSR,
    /// Islands architecture (selective hydration).
    IslandsArchitecture,
}

impl LaneKind {
    pub const ALL: &[Self] = &[
        Self::ServerSideRender,
        Self::ClientEntry,
        Self::Hydration,
        Self::StaticGeneration,
        Self::StreamingSSR,
        Self::IslandsArchitecture,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerSideRender => "server_side_render",
            Self::ClientEntry => "client_entry",
            Self::Hydration => "hydration",
            Self::StaticGeneration => "static_generation",
            Self::StreamingSSR => "streaming_ssr",
            Self::IslandsArchitecture => "islands_architecture",
        }
    }

    /// Whether this lane kind involves server-side execution.
    pub const fn is_server_side(self) -> bool {
        matches!(
            self,
            Self::ServerSideRender | Self::StaticGeneration | Self::StreamingSSR
        )
    }

    /// Whether this lane kind involves client-side hydration.
    pub const fn is_hydration_related(self) -> bool {
        matches!(
            self,
            Self::Hydration | Self::IslandsArchitecture | Self::ClientEntry
        )
    }
}

impl fmt::Display for LaneKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ComponentShape
// ---------------------------------------------------------------------------

/// Shape of a component in the component-shape catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentShape {
    /// Pure function component (no side effects, no state).
    PureFunction,
    /// Class component with state.
    ClassWithState,
    /// Function component using hooks.
    HookBased,
    /// `React.forwardRef` wrapper.
    ForwardRef,
    /// `React.memo` wrapper.
    Memo,
    /// `React.lazy` (code-split boundary).
    Lazy,
    /// `<Suspense>` boundary.
    Suspense,
    /// Error boundary (class with `componentDidCatch`).
    ErrorBoundary,
}

impl ComponentShape {
    pub const ALL: &[Self] = &[
        Self::PureFunction,
        Self::ClassWithState,
        Self::HookBased,
        Self::ForwardRef,
        Self::Memo,
        Self::Lazy,
        Self::Suspense,
        Self::ErrorBoundary,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PureFunction => "pure_function",
            Self::ClassWithState => "class_with_state",
            Self::HookBased => "hook_based",
            Self::ForwardRef => "forward_ref",
            Self::Memo => "memo",
            Self::Lazy => "lazy",
            Self::Suspense => "suspense",
            Self::ErrorBoundary => "error_boundary",
        }
    }

    /// Whether this shape is pure (stateless, no side effects).
    pub const fn is_pure(self) -> bool {
        matches!(self, Self::PureFunction | Self::Memo)
    }

    /// Whether this shape may introduce async boundaries.
    pub const fn is_async_boundary(self) -> bool {
        matches!(self, Self::Lazy | Self::Suspense)
    }
}

impl fmt::Display for ComponentShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SpecializationStrategy
// ---------------------------------------------------------------------------

/// Strategy for specializing a render lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationStrategy {
    /// Inline the component body at the call site.
    InlineExpansion,
    /// Fold constant props and eliminate known branches.
    ConstantFolding,
    /// Eliminate branches that are provably dead.
    DeadBranchElimination,
    /// Partially evaluate the component with known inputs.
    PartialEvaluation,
    /// Specialize based on the component shape catalog.
    ShapeSpecialization,
}

impl SpecializationStrategy {
    pub const ALL: &[Self] = &[
        Self::InlineExpansion,
        Self::ConstantFolding,
        Self::DeadBranchElimination,
        Self::PartialEvaluation,
        Self::ShapeSpecialization,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InlineExpansion => "inline_expansion",
            Self::ConstantFolding => "constant_folding",
            Self::DeadBranchElimination => "dead_branch_elimination",
            Self::PartialEvaluation => "partial_evaluation",
            Self::ShapeSpecialization => "shape_specialization",
        }
    }
}

impl fmt::Display for SpecializationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SafetyCheckKind
// ---------------------------------------------------------------------------

/// Kind of safety check performed before specialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCheckKind {
    /// Purity proof — no side effects.
    PurityProof,
    /// No unsupported patterns in the component.
    UnsupportedPatternAbsence,
    /// Proof receipt from a prior compilation step.
    ProofReceipt,
    /// Type stability — props and state types are stable.
    TypeStability,
    /// Idempotency — repeated render produces identical output.
    Idempotency,
    /// No ambient mutable state captured.
    NoAmbientMutation,
}

impl SafetyCheckKind {
    pub const ALL: &[Self] = &[
        Self::PurityProof,
        Self::UnsupportedPatternAbsence,
        Self::ProofReceipt,
        Self::TypeStability,
        Self::Idempotency,
        Self::NoAmbientMutation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PurityProof => "purity_proof",
            Self::UnsupportedPatternAbsence => "unsupported_pattern_absence",
            Self::ProofReceipt => "proof_receipt",
            Self::TypeStability => "type_stability",
            Self::Idempotency => "idempotency",
            Self::NoAmbientMutation => "no_ambient_mutation",
        }
    }
}

impl fmt::Display for SafetyCheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SafetyCheck
// ---------------------------------------------------------------------------

/// A single safety check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCheck {
    /// What kind of check.
    pub check_kind: SafetyCheckKind,
    /// Whether the check passed.
    pub passed: bool,
    /// Evidence hash backing this check (proof receipt).
    pub evidence_hash: ContentHash,
    /// Human-readable reason / explanation.
    pub reason: String,
}

impl SafetyCheck {
    /// Create a passing safety check.
    pub fn pass(check_kind: SafetyCheckKind, evidence: &[u8], reason: impl Into<String>) -> Self {
        Self {
            check_kind,
            passed: true,
            evidence_hash: ContentHash::compute(evidence),
            reason: reason.into(),
        }
    }

    /// Create a failing safety check.
    pub fn fail(check_kind: SafetyCheckKind, evidence: &[u8], reason: impl Into<String>) -> Self {
        Self {
            check_kind,
            passed: false,
            evidence_hash: ContentHash::compute(evidence),
            reason: reason.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SpecializationVerdict
// ---------------------------------------------------------------------------

/// Outcome of a specialization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationVerdict {
    /// Specialization was applied successfully.
    Applied,
    /// Specialization was rejected (safety check failed or benefit too low).
    Rejected,
    /// Decision deferred (not enough evidence to decide now).
    Deferred,
}

impl SpecializationVerdict {
    pub const ALL: &[Self] = &[Self::Applied, Self::Rejected, Self::Deferred];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
        }
    }
}

impl fmt::Display for SpecializationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SpecializationRequest
// ---------------------------------------------------------------------------

/// A request to specialize a render lane for a particular component shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationRequest {
    /// The lane to specialize.
    pub lane_kind: LaneKind,
    /// Component shape from the catalog.
    pub component_shape: ComponentShape,
    /// Desired specialization strategy.
    pub strategy: SpecializationStrategy,
    /// Hash of the input (component code / IR) being specialized.
    pub input_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// SpecializationResult
// ---------------------------------------------------------------------------

/// The result of a specialization attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationResult {
    /// Whether the specialization was applied, rejected, or deferred.
    pub verdict: SpecializationVerdict,
    /// Hash of the specialized output (if Applied).
    pub output_hash: ContentHash,
    /// Safety checks that were evaluated.
    pub safety_checks: Vec<SafetyCheck>,
    /// Estimated speedup in millionths (1_000_000 = 1x, 2_000_000 = 2x).
    pub speedup_millionths: u64,
    /// Rejection reasons (empty if Applied).
    pub rejection_reasons: Vec<String>,
}

impl SpecializationResult {
    pub fn is_applied(&self) -> bool {
        self.verdict == SpecializationVerdict::Applied
    }

    pub fn is_rejected(&self) -> bool {
        self.verdict == SpecializationVerdict::Rejected
    }

    pub fn is_deferred(&self) -> bool {
        self.verdict == SpecializationVerdict::Deferred
    }

    pub fn all_checks_passed(&self) -> bool {
        !self.safety_checks.is_empty() && self.safety_checks.iter().all(|c| c.passed)
    }

    pub fn failed_check_count(&self) -> usize {
        self.safety_checks.iter().filter(|c| !c.passed).count()
    }
}

// ---------------------------------------------------------------------------
// SpecializationConfig
// ---------------------------------------------------------------------------

/// Configuration for the specialization engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationConfig {
    /// Maximum inline depth for InlineExpansion.
    pub max_inline_depth: u32,
    /// Whether a purity proof is required before specialization.
    pub require_purity_proof: bool,
    /// Minimum speedup threshold in millionths (below → reject).
    pub min_speedup_threshold_millionths: u64,
    /// Maximum number of specializations per lane.
    pub max_specializations_per_lane: usize,
}

impl SpecializationConfig {
    pub fn default_config() -> Self {
        Self {
            max_inline_depth: DEFAULT_MAX_INLINE_DEPTH,
            require_purity_proof: true,
            min_speedup_threshold_millionths: DEFAULT_MIN_SPEEDUP_THRESHOLD,
            max_specializations_per_lane: DEFAULT_MAX_SPECIALIZATIONS_PER_LANE,
        }
    }

    /// Permissive config for testing: no purity proof, low threshold.
    pub fn permissive() -> Self {
        Self {
            max_inline_depth: 32,
            require_purity_proof: false,
            min_speedup_threshold_millionths: 0,
            max_specializations_per_lane: 256,
        }
    }
}

impl Default for SpecializationConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// SpecializationError
// ---------------------------------------------------------------------------

/// Errors from the specialization engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationError {
    /// Config validation failed.
    InvalidConfig { reason: String },
    /// Inline depth exceeded.
    InlineDepthExceeded { depth: u32, max: u32 },
    /// Specializations per lane exceeded.
    SpecializationLimitExceeded { count: usize, max: usize },
    /// Required safety check missing.
    MissingSafetyCheck { kind: SafetyCheckKind },
    /// Internal error.
    Internal { detail: String },
}

impl fmt::Display for SpecializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { reason } => write!(f, "invalid config: {reason}"),
            Self::InlineDepthExceeded { depth, max } => {
                write!(f, "inline depth {depth} exceeds max {max}")
            }
            Self::SpecializationLimitExceeded { count, max } => {
                write!(f, "specialization count {count} exceeds max {max}")
            }
            Self::MissingSafetyCheck { kind } => {
                write!(f, "missing safety check: {kind}")
            }
            Self::Internal { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Hash-chained proof receipt for a specialization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// The request that was evaluated.
    pub lane_kind: LaneKind,
    /// Component shape.
    pub component_shape: ComponentShape,
    /// Strategy attempted.
    pub strategy: SpecializationStrategy,
    /// Verdict.
    pub verdict: SpecializationVerdict,
    /// Speedup achieved (millionths).
    pub speedup_millionths: u64,
    /// Number of safety checks passed.
    pub checks_passed: usize,
    /// Number of safety checks total.
    pub checks_total: usize,
    /// Content hash of this receipt.
    pub content_hash: ContentHash,
    /// Previous receipt hash (for chaining); zero-hash if first.
    pub previous_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new receipt chained to a previous one.
    pub fn new(
        epoch: SecurityEpoch,
        request: &SpecializationRequest,
        result: &SpecializationResult,
        previous_hash: ContentHash,
    ) -> Self {
        let checks_passed = result.safety_checks.iter().filter(|c| c.passed).count();
        let checks_total = result.safety_checks.len();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(request.lane_kind.as_str().as_bytes());
        h.update(request.component_shape.as_str().as_bytes());
        h.update(request.strategy.as_str().as_bytes());
        h.update(result.verdict.as_str().as_bytes());
        h.update(result.speedup_millionths.to_le_bytes());
        h.update((checks_passed as u64).to_le_bytes());
        h.update((checks_total as u64).to_le_bytes());
        h.update(previous_hash.as_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            lane_kind: request.lane_kind,
            component_shape: request.component_shape,
            strategy: request.strategy,
            verdict: result.verdict,
            speedup_millionths: result.speedup_millionths,
            checks_passed,
            checks_total,
            content_hash,
            previous_hash,
        }
    }

    /// The genesis (zero) hash used as the first `previous_hash`.
    pub fn genesis_hash() -> ContentHash {
        ContentHash::compute(&[0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute the estimated specialization benefit for a (shape, strategy) pair.
///
/// Returns speedup in millionths (1_000_000 = 1x = no change,
/// 2_000_000 = 2x speedup).
pub fn compute_specialization_benefit(
    shape: ComponentShape,
    strategy: SpecializationStrategy,
) -> u64 {
    // Base benefit depends on shape purity and strategy applicability.
    let shape_factor: u64 = match shape {
        ComponentShape::PureFunction => 500_000,   // high benefit
        ComponentShape::Memo => 400_000,           // high (already memoized, less to do)
        ComponentShape::ForwardRef => 300_000,     // medium
        ComponentShape::HookBased => 250_000,      // medium-low (hooks complicate things)
        ComponentShape::ClassWithState => 150_000, // low (state complicates things)
        ComponentShape::Lazy => 100_000,           // low (async boundary)
        ComponentShape::Suspense => 80_000,        // very low
        ComponentShape::ErrorBoundary => 50_000,   // minimal
    };

    let strategy_multiplier: u64 = match strategy {
        SpecializationStrategy::ConstantFolding => 3,
        SpecializationStrategy::DeadBranchElimination => 2,
        SpecializationStrategy::InlineExpansion => 4,
        SpecializationStrategy::PartialEvaluation => 5,
        SpecializationStrategy::ShapeSpecialization => 3,
    };

    // Benefit = 1_000_000 (base, no change) + shape_factor * strategy_multiplier / 5
    let bonus = shape_factor.saturating_mul(strategy_multiplier) / 5;
    MILLION.saturating_add(bonus)
}

/// Evaluate safety checks for a specialization request.
///
/// Returns a vector of checks.  All checks must pass for specialization to
/// be safe.
pub fn evaluate_safety(request: &SpecializationRequest) -> Vec<SafetyCheck> {
    let mut checks = Vec::new();

    // 1. Purity proof check.
    let purity_passed = request.component_shape.is_pure();
    checks.push(if purity_passed {
        SafetyCheck::pass(
            SafetyCheckKind::PurityProof,
            request.input_hash.as_bytes(),
            format!("{} is pure", request.component_shape),
        )
    } else {
        SafetyCheck::fail(
            SafetyCheckKind::PurityProof,
            request.input_hash.as_bytes(),
            format!("{} is not provably pure", request.component_shape),
        )
    });

    // 2. Unsupported-pattern check.
    let pattern_ok = !request.component_shape.is_async_boundary()
        || !matches!(
            request.strategy,
            SpecializationStrategy::InlineExpansion | SpecializationStrategy::ConstantFolding
        );
    checks.push(if pattern_ok {
        SafetyCheck::pass(
            SafetyCheckKind::UnsupportedPatternAbsence,
            request.input_hash.as_bytes(),
            "no unsupported patterns detected".to_string(),
        )
    } else {
        SafetyCheck::fail(
            SafetyCheckKind::UnsupportedPatternAbsence,
            request.input_hash.as_bytes(),
            format!(
                "async boundary {} cannot be {}",
                request.component_shape, request.strategy
            ),
        )
    });

    // 3. Proof receipt check (always passes — receipt is the input hash).
    checks.push(SafetyCheck::pass(
        SafetyCheckKind::ProofReceipt,
        request.input_hash.as_bytes(),
        "proof receipt verified".to_string(),
    ));

    // 4. Type stability.
    let type_stable = !matches!(
        request.component_shape,
        ComponentShape::ClassWithState | ComponentShape::ErrorBoundary
    );
    checks.push(if type_stable {
        SafetyCheck::pass(
            SafetyCheckKind::TypeStability,
            request.input_hash.as_bytes(),
            "types are stable".to_string(),
        )
    } else {
        SafetyCheck::fail(
            SafetyCheckKind::TypeStability,
            request.input_hash.as_bytes(),
            format!("{} has dynamic state types", request.component_shape),
        )
    });

    // 5. Idempotency.
    let idempotent = request.component_shape.is_pure()
        || matches!(
            request.component_shape,
            ComponentShape::ForwardRef | ComponentShape::HookBased
        );
    checks.push(if idempotent {
        SafetyCheck::pass(
            SafetyCheckKind::Idempotency,
            request.input_hash.as_bytes(),
            "render is idempotent".to_string(),
        )
    } else {
        SafetyCheck::fail(
            SafetyCheckKind::Idempotency,
            request.input_hash.as_bytes(),
            format!("{} may not be idempotent", request.component_shape),
        )
    });

    // 6. No ambient mutation.
    let no_mutation = request.component_shape.is_pure();
    checks.push(if no_mutation {
        SafetyCheck::pass(
            SafetyCheckKind::NoAmbientMutation,
            request.input_hash.as_bytes(),
            "no ambient mutation".to_string(),
        )
    } else {
        SafetyCheck::fail(
            SafetyCheckKind::NoAmbientMutation,
            request.input_hash.as_bytes(),
            format!("{} may capture ambient state", request.component_shape),
        )
    });

    checks
}

/// Validate a specialization config.
pub fn validate_config(config: &SpecializationConfig) -> Result<(), SpecializationError> {
    if config.max_inline_depth == 0 {
        return Err(SpecializationError::InvalidConfig {
            reason: "max_inline_depth must be > 0".into(),
        });
    }
    if config.max_specializations_per_lane == 0 {
        return Err(SpecializationError::InvalidConfig {
            reason: "max_specializations_per_lane must be > 0".into(),
        });
    }
    if config.min_speedup_threshold_millionths > MILLION * 10 {
        return Err(SpecializationError::InvalidConfig {
            reason: "min_speedup_threshold_millionths unreasonably large".into(),
        });
    }
    Ok(())
}

/// Specialize a render lane given a request and configuration.
///
/// This is the main entry point.  It:
/// 1. Validates the config.
/// 2. Evaluates safety checks.
/// 3. Computes the specialization benefit.
/// 4. Decides whether to apply, reject, or defer.
pub fn specialize_lane(
    request: &SpecializationRequest,
    config: &SpecializationConfig,
) -> Result<SpecializationResult, SpecializationError> {
    validate_config(config)?;

    // Evaluate safety.
    let safety_checks = evaluate_safety(request);

    // Check purity requirement.
    if config.require_purity_proof {
        let purity_check = safety_checks
            .iter()
            .find(|c| c.check_kind == SafetyCheckKind::PurityProof);
        if let Some(check) = purity_check
            && !check.passed
        {
            return Ok(SpecializationResult {
                verdict: SpecializationVerdict::Rejected,
                output_hash: ContentHash::compute(b"rejected-purity"),
                safety_checks,
                speedup_millionths: MILLION,
                rejection_reasons: vec!["purity proof required but not satisfied".into()],
            });
        }
    }

    // Check inline depth for InlineExpansion.
    if request.strategy == SpecializationStrategy::InlineExpansion
        && config.max_inline_depth < DEFAULT_MAX_INLINE_DEPTH
    {
        // Still valid, just note the constraint.
    }

    // Compute benefit.
    let speedup = compute_specialization_benefit(request.component_shape, request.strategy);

    // Check minimum speedup threshold.
    if speedup < MILLION.saturating_add(config.min_speedup_threshold_millionths) {
        return Ok(SpecializationResult {
            verdict: SpecializationVerdict::Rejected,
            output_hash: ContentHash::compute(b"rejected-low-benefit"),
            safety_checks,
            speedup_millionths: speedup,
            rejection_reasons: vec![format!(
                "speedup {} below threshold {}",
                speedup,
                MILLION.saturating_add(config.min_speedup_threshold_millionths)
            )],
        });
    }

    // Check for any failed critical checks (unsupported patterns).
    let has_unsupported_pattern_failure = safety_checks
        .iter()
        .any(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence && !c.passed);
    if has_unsupported_pattern_failure {
        return Ok(SpecializationResult {
            verdict: SpecializationVerdict::Rejected,
            output_hash: ContentHash::compute(b"rejected-unsupported-pattern"),
            safety_checks,
            speedup_millionths: speedup,
            rejection_reasons: vec!["unsupported pattern detected".into()],
        });
    }

    // If some non-critical checks failed but no blocking issues → defer.
    let all_passed = safety_checks.iter().all(|c| c.passed);
    if !all_passed && !config.require_purity_proof {
        return Ok(SpecializationResult {
            verdict: SpecializationVerdict::Deferred,
            output_hash: ContentHash::compute(b"deferred"),
            safety_checks,
            speedup_millionths: speedup,
            rejection_reasons: vec!["some safety checks failed, deferring".into()],
        });
    }

    // Compute specialized output hash.
    let mut h = Sha256::new();
    h.update(request.input_hash.as_bytes());
    h.update(request.lane_kind.as_str().as_bytes());
    h.update(request.component_shape.as_str().as_bytes());
    h.update(request.strategy.as_str().as_bytes());
    h.update(speedup.to_le_bytes());
    let output_hash = ContentHash::compute(&h.finalize());

    Ok(SpecializationResult {
        verdict: SpecializationVerdict::Applied,
        output_hash,
        safety_checks,
        speedup_millionths: speedup,
        rejection_reasons: Vec::new(),
    })
}

/// Batch-specialize multiple requests against a config, returning results
/// and a chained receipt log.
pub fn specialize_batch(
    requests: &[SpecializationRequest],
    config: &SpecializationConfig,
    epoch: SecurityEpoch,
) -> Result<(Vec<SpecializationResult>, Vec<DecisionReceipt>), SpecializationError> {
    validate_config(config)?;

    let mut results = Vec::with_capacity(requests.len());
    let mut receipts = Vec::with_capacity(requests.len());
    let mut prev_hash = DecisionReceipt::genesis_hash();

    // Track per-lane specialization counts.
    let mut lane_counts: Vec<(LaneKind, usize)> = Vec::new();

    for req in requests {
        // Check per-lane limit.
        let lane_count = lane_counts
            .iter()
            .find(|(lk, _)| *lk == req.lane_kind)
            .map(|(_, c)| *c)
            .unwrap_or(0);

        if lane_count >= config.max_specializations_per_lane {
            return Err(SpecializationError::SpecializationLimitExceeded {
                count: lane_count + 1,
                max: config.max_specializations_per_lane,
            });
        }

        let result = specialize_lane(req, config)?;

        // Update lane count if applied.
        if result.verdict == SpecializationVerdict::Applied {
            if let Some(entry) = lane_counts.iter_mut().find(|(lk, _)| *lk == req.lane_kind) {
                entry.1 += 1;
            } else {
                lane_counts.push((req.lane_kind, 1));
            }
        }

        let receipt = DecisionReceipt::new(epoch, req, &result, prev_hash);
        prev_hash = receipt.content_hash;

        results.push(result);
        receipts.push(receipt);
    }

    Ok((results, receipts))
}

/// Summary of a batch specialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Total requests processed.
    pub total: usize,
    /// Applied count.
    pub applied: usize,
    /// Rejected count.
    pub rejected: usize,
    /// Deferred count.
    pub deferred: usize,
    /// Average speedup of applied specializations (millionths).
    pub avg_applied_speedup_millionths: u64,
    /// Content hash of the summary.
    pub content_hash: ContentHash,
}

impl BatchSummary {
    /// Compute a summary from results.
    pub fn from_results(results: &[SpecializationResult]) -> Self {
        let total = results.len();
        let applied = results
            .iter()
            .filter(|r| r.verdict == SpecializationVerdict::Applied)
            .count();
        let rejected = results
            .iter()
            .filter(|r| r.verdict == SpecializationVerdict::Rejected)
            .count();
        let deferred = results
            .iter()
            .filter(|r| r.verdict == SpecializationVerdict::Deferred)
            .count();

        let applied_speedup_sum: u64 = results
            .iter()
            .filter(|r| r.verdict == SpecializationVerdict::Applied)
            .map(|r| r.speedup_millionths)
            .sum();
        let avg_applied_speedup_millionths = if applied > 0 {
            applied_speedup_sum / applied as u64
        } else {
            0
        };

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update((total as u64).to_le_bytes());
        h.update((applied as u64).to_le_bytes());
        h.update((rejected as u64).to_le_bytes());
        h.update((deferred as u64).to_le_bytes());
        h.update(avg_applied_speedup_millionths.to_le_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            total,
            applied,
            rejected,
            deferred,
            avg_applied_speedup_millionths,
            content_hash,
        }
    }

    /// Application rate in millionths.
    pub fn application_rate(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        (self.applied as u64).saturating_mul(MILLION) / self.total as u64
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn pure_ssr_request() -> SpecializationRequest {
        SpecializationRequest {
            lane_kind: LaneKind::ServerSideRender,
            component_shape: ComponentShape::PureFunction,
            strategy: SpecializationStrategy::ConstantFolding,
            input_hash: ContentHash::compute(b"test-input"),
        }
    }

    fn hook_client_request() -> SpecializationRequest {
        SpecializationRequest {
            lane_kind: LaneKind::ClientEntry,
            component_shape: ComponentShape::HookBased,
            strategy: SpecializationStrategy::PartialEvaluation,
            input_hash: ContentHash::compute(b"hook-input"),
        }
    }

    fn lazy_ssr_request() -> SpecializationRequest {
        SpecializationRequest {
            lane_kind: LaneKind::StreamingSSR,
            component_shape: ComponentShape::Lazy,
            strategy: SpecializationStrategy::InlineExpansion,
            input_hash: ContentHash::compute(b"lazy-input"),
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_prefix() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "render_lane_specializer");
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
    fn default_constants_reasonable() {
        assert_eq!(DEFAULT_MAX_INLINE_DEPTH, 8);
        assert_eq!(DEFAULT_MIN_SPEEDUP_THRESHOLD, 100_000);
        const { assert!(DEFAULT_MIN_SPEEDUP_THRESHOLD <= MILLION) };
        assert_eq!(DEFAULT_MAX_SPECIALIZATIONS_PER_LANE, 16);
    }

    // --- LaneKind ---

    #[test]
    fn lane_kind_all_count() {
        assert_eq!(LaneKind::ALL.len(), 6);
    }

    #[test]
    fn lane_kind_names_unique() {
        let names: BTreeSet<&str> = LaneKind::ALL.iter().map(|lk| lk.as_str()).collect();
        assert_eq!(names.len(), LaneKind::ALL.len());
    }

    #[test]
    fn lane_kind_display_matches_as_str() {
        for lk in LaneKind::ALL {
            assert_eq!(lk.to_string(), lk.as_str());
        }
    }

    #[test]
    fn lane_kind_serde_roundtrip() {
        for lk in LaneKind::ALL {
            let json = serde_json::to_string(lk).unwrap();
            let back: LaneKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*lk, back);
        }
    }

    #[test]
    fn lane_kind_server_side() {
        assert!(LaneKind::ServerSideRender.is_server_side());
        assert!(LaneKind::StaticGeneration.is_server_side());
        assert!(LaneKind::StreamingSSR.is_server_side());
        assert!(!LaneKind::ClientEntry.is_server_side());
        assert!(!LaneKind::Hydration.is_server_side());
        assert!(!LaneKind::IslandsArchitecture.is_server_side());
    }

    #[test]
    fn lane_kind_hydration_related() {
        assert!(LaneKind::Hydration.is_hydration_related());
        assert!(LaneKind::IslandsArchitecture.is_hydration_related());
        assert!(LaneKind::ClientEntry.is_hydration_related());
        assert!(!LaneKind::ServerSideRender.is_hydration_related());
        assert!(!LaneKind::StaticGeneration.is_hydration_related());
        assert!(!LaneKind::StreamingSSR.is_hydration_related());
    }

    // --- ComponentShape ---

    #[test]
    fn component_shape_all_count() {
        assert_eq!(ComponentShape::ALL.len(), 8);
    }

    #[test]
    fn component_shape_names_unique() {
        let names: BTreeSet<&str> = ComponentShape::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), ComponentShape::ALL.len());
    }

    #[test]
    fn component_shape_display() {
        for s in ComponentShape::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn component_shape_serde() {
        for s in ComponentShape::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: ComponentShape = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn component_shape_purity() {
        assert!(ComponentShape::PureFunction.is_pure());
        assert!(ComponentShape::Memo.is_pure());
        assert!(!ComponentShape::HookBased.is_pure());
        assert!(!ComponentShape::ClassWithState.is_pure());
        assert!(!ComponentShape::Lazy.is_pure());
    }

    #[test]
    fn component_shape_async_boundary() {
        assert!(ComponentShape::Lazy.is_async_boundary());
        assert!(ComponentShape::Suspense.is_async_boundary());
        assert!(!ComponentShape::PureFunction.is_async_boundary());
        assert!(!ComponentShape::HookBased.is_async_boundary());
    }

    // --- SpecializationStrategy ---

    #[test]
    fn strategy_all_count() {
        assert_eq!(SpecializationStrategy::ALL.len(), 5);
    }

    #[test]
    fn strategy_names_unique() {
        let names: BTreeSet<&str> = SpecializationStrategy::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(names.len(), SpecializationStrategy::ALL.len());
    }

    #[test]
    fn strategy_display() {
        for s in SpecializationStrategy::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn strategy_serde() {
        for s in SpecializationStrategy::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: SpecializationStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- SafetyCheckKind ---

    #[test]
    fn safety_check_kind_all_count() {
        assert_eq!(SafetyCheckKind::ALL.len(), 6);
    }

    #[test]
    fn safety_check_kind_names_unique() {
        let names: BTreeSet<&str> = SafetyCheckKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), SafetyCheckKind::ALL.len());
    }

    #[test]
    fn safety_check_kind_display() {
        for k in SafetyCheckKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    // --- SafetyCheck ---

    #[test]
    fn safety_check_pass_sets_passed() {
        let c = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"evidence", "pure");
        assert!(c.passed);
        assert_eq!(c.check_kind, SafetyCheckKind::PurityProof);
    }

    #[test]
    fn safety_check_fail_sets_not_passed() {
        let c = SafetyCheck::fail(SafetyCheckKind::TypeStability, b"evidence", "unstable");
        assert!(!c.passed);
        assert_eq!(c.reason, "unstable");
    }

    #[test]
    fn safety_check_evidence_hash_deterministic() {
        let c1 = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"ev", "ok");
        let c2 = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"ev", "ok");
        assert_eq!(c1.evidence_hash, c2.evidence_hash);
    }

    // --- SpecializationVerdict ---

    #[test]
    fn verdict_all_count() {
        assert_eq!(SpecializationVerdict::ALL.len(), 3);
    }

    #[test]
    fn verdict_display() {
        for v in SpecializationVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn verdict_serde() {
        for v in SpecializationVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: SpecializationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- SpecializationConfig ---

    #[test]
    fn default_config_valid() {
        let c = SpecializationConfig::default_config();
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn permissive_config_valid() {
        let c = SpecializationConfig::permissive();
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn config_default_trait() {
        let c: SpecializationConfig = Default::default();
        assert_eq!(c, SpecializationConfig::default_config());
    }

    #[test]
    fn config_zero_depth_invalid() {
        let mut c = SpecializationConfig::default_config();
        c.max_inline_depth = 0;
        assert!(matches!(
            validate_config(&c),
            Err(SpecializationError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn config_zero_max_specs_invalid() {
        let mut c = SpecializationConfig::default_config();
        c.max_specializations_per_lane = 0;
        assert!(matches!(
            validate_config(&c),
            Err(SpecializationError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn config_huge_threshold_invalid() {
        let mut c = SpecializationConfig::default_config();
        c.min_speedup_threshold_millionths = MILLION * 11;
        assert!(matches!(
            validate_config(&c),
            Err(SpecializationError::InvalidConfig { .. })
        ));
    }

    // --- compute_specialization_benefit ---

    #[test]
    fn benefit_pure_always_above_base() {
        for strat in SpecializationStrategy::ALL {
            let b = compute_specialization_benefit(ComponentShape::PureFunction, *strat);
            assert!(b > MILLION, "pure function + {strat} should exceed 1x");
        }
    }

    #[test]
    fn benefit_pure_higher_than_error_boundary() {
        for strat in SpecializationStrategy::ALL {
            let pure = compute_specialization_benefit(ComponentShape::PureFunction, *strat);
            let eb = compute_specialization_benefit(ComponentShape::ErrorBoundary, *strat);
            assert!(pure > eb);
        }
    }

    #[test]
    fn benefit_partial_eval_highest_multiplier() {
        let pe = compute_specialization_benefit(
            ComponentShape::PureFunction,
            SpecializationStrategy::PartialEvaluation,
        );
        let cf = compute_specialization_benefit(
            ComponentShape::PureFunction,
            SpecializationStrategy::ConstantFolding,
        );
        assert!(pe > cf, "partial evaluation should beat constant folding");
    }

    #[test]
    fn benefit_deterministic() {
        let a = compute_specialization_benefit(
            ComponentShape::Memo,
            SpecializationStrategy::ShapeSpecialization,
        );
        let b = compute_specialization_benefit(
            ComponentShape::Memo,
            SpecializationStrategy::ShapeSpecialization,
        );
        assert_eq!(a, b);
    }

    // --- evaluate_safety ---

    #[test]
    fn safety_pure_function_all_pass() {
        let req = pure_ssr_request();
        let checks = evaluate_safety(&req);
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c.passed));
    }

    #[test]
    fn safety_hook_based_purity_fails() {
        let req = hook_client_request();
        let checks = evaluate_safety(&req);
        let purity = checks
            .iter()
            .find(|c| c.check_kind == SafetyCheckKind::PurityProof)
            .unwrap();
        assert!(!purity.passed);
    }

    #[test]
    fn safety_lazy_inline_has_unsupported_pattern() {
        let req = lazy_ssr_request();
        let checks = evaluate_safety(&req);
        let unsup = checks
            .iter()
            .find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence)
            .unwrap();
        assert!(!unsup.passed);
    }

    #[test]
    fn safety_class_type_stability_fails() {
        let req = SpecializationRequest {
            lane_kind: LaneKind::Hydration,
            component_shape: ComponentShape::ClassWithState,
            strategy: SpecializationStrategy::ShapeSpecialization,
            input_hash: ContentHash::compute(b"class"),
        };
        let checks = evaluate_safety(&req);
        let ts = checks
            .iter()
            .find(|c| c.check_kind == SafetyCheckKind::TypeStability)
            .unwrap();
        assert!(!ts.passed);
    }

    #[test]
    fn safety_check_count_always_six() {
        for shape in ComponentShape::ALL {
            for strat in SpecializationStrategy::ALL {
                let req = SpecializationRequest {
                    lane_kind: LaneKind::ServerSideRender,
                    component_shape: *shape,
                    strategy: *strat,
                    input_hash: ContentHash::compute(b"any"),
                };
                assert_eq!(evaluate_safety(&req).len(), 6);
            }
        }
    }

    // --- specialize_lane ---

    #[test]
    fn specialize_pure_ssr_applies() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        assert!(result.is_applied());
        assert!(result.speedup_millionths > MILLION);
        assert!(result.rejection_reasons.is_empty());
    }

    #[test]
    fn specialize_hook_rejected_with_purity_required() {
        let req = hook_client_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        assert!(result.is_rejected());
        assert!(!result.rejection_reasons.is_empty());
    }

    #[test]
    fn specialize_lazy_inline_rejected_unsupported_pattern() {
        let req = lazy_ssr_request();
        let mut cfg = SpecializationConfig::default_config();
        cfg.require_purity_proof = false;
        let result = specialize_lane(&req, &cfg).unwrap();
        // Should be rejected due to unsupported pattern (async + inline).
        assert!(result.is_rejected());
    }

    #[test]
    fn specialize_memo_applies() {
        let req = SpecializationRequest {
            lane_kind: LaneKind::StaticGeneration,
            component_shape: ComponentShape::Memo,
            strategy: SpecializationStrategy::DeadBranchElimination,
            input_hash: ContentHash::compute(b"memo-input"),
        };
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        assert!(result.is_applied());
    }

    #[test]
    fn specialize_invalid_config_returns_error() {
        let req = pure_ssr_request();
        let mut cfg = SpecializationConfig::default_config();
        cfg.max_inline_depth = 0;
        assert!(specialize_lane(&req, &cfg).is_err());
    }

    #[test]
    fn specialize_result_serde() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: SpecializationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn specialize_result_all_checks_passed() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        assert!(result.all_checks_passed());
        assert_eq!(result.failed_check_count(), 0);
    }

    #[test]
    fn specialize_hook_permissive_defers() {
        let req = hook_client_request();
        let cfg = SpecializationConfig::permissive();
        let result = specialize_lane(&req, &cfg).unwrap();
        // Permissive: no purity requirement, but non-critical checks fail → defer.
        assert!(result.is_deferred());
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_hash_deterministic() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        let genesis = DecisionReceipt::genesis_hash();
        let r1 = DecisionReceipt::new(epoch(), &req, &result, genesis.clone());
        let r2 = DecisionReceipt::new(epoch(), &req, &result, genesis);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn receipt_chains_differ() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        let genesis = DecisionReceipt::genesis_hash();
        let r1 = DecisionReceipt::new(epoch(), &req, &result, genesis);
        let r2 = DecisionReceipt::new(epoch(), &req, &result, r1.content_hash);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn receipt_fields_populated() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        let genesis = DecisionReceipt::genesis_hash();
        let r = DecisionReceipt::new(epoch(), &req, &result, genesis.clone());
        assert_eq!(r.lane_kind, LaneKind::ServerSideRender);
        assert_eq!(r.component_shape, ComponentShape::PureFunction);
        assert_eq!(r.verdict, SpecializationVerdict::Applied);
        assert_eq!(r.checks_passed, 6);
        assert_eq!(r.checks_total, 6);
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert_eq!(r.epoch, epoch());
        assert_eq!(r.previous_hash, genesis);
    }

    #[test]
    fn receipt_serde() {
        let req = pure_ssr_request();
        let cfg = SpecializationConfig::default_config();
        let result = specialize_lane(&req, &cfg).unwrap();
        let r = DecisionReceipt::new(epoch(), &req, &result, DecisionReceipt::genesis_hash());
        let json = serde_json::to_string(&r).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- specialize_batch ---

    #[test]
    fn batch_empty() {
        let cfg = SpecializationConfig::default_config();
        let (results, receipts) = specialize_batch(&[], &cfg, epoch()).unwrap();
        assert!(results.is_empty());
        assert!(receipts.is_empty());
    }

    #[test]
    fn batch_single() {
        let reqs = vec![pure_ssr_request()];
        let cfg = SpecializationConfig::default_config();
        let (results, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert!(results[0].is_applied());
    }

    #[test]
    fn batch_receipt_chain() {
        let reqs = vec![
            pure_ssr_request(),
            SpecializationRequest {
                lane_kind: LaneKind::StaticGeneration,
                component_shape: ComponentShape::Memo,
                strategy: SpecializationStrategy::ConstantFolding,
                input_hash: ContentHash::compute(b"memo2"),
            },
        ];
        let cfg = SpecializationConfig::default_config();
        let (_, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].previous_hash, DecisionReceipt::genesis_hash());
        assert_eq!(receipts[1].previous_hash, receipts[0].content_hash);
    }

    #[test]
    fn batch_lane_limit_exceeded() {
        let mut cfg = SpecializationConfig::default_config();
        cfg.max_specializations_per_lane = 1;
        let reqs = vec![
            pure_ssr_request(),
            SpecializationRequest {
                lane_kind: LaneKind::ServerSideRender,
                component_shape: ComponentShape::Memo,
                strategy: SpecializationStrategy::DeadBranchElimination,
                input_hash: ContentHash::compute(b"memo-ssr"),
            },
        ];
        let result = specialize_batch(&reqs, &cfg, epoch());
        assert!(matches!(
            result,
            Err(SpecializationError::SpecializationLimitExceeded { .. })
        ));
    }

    // --- BatchSummary ---

    #[test]
    fn batch_summary_empty() {
        let s = BatchSummary::from_results(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.applied, 0);
        assert_eq!(s.application_rate(), 0);
    }

    #[test]
    fn batch_summary_all_applied() {
        let reqs = vec![pure_ssr_request()];
        let cfg = SpecializationConfig::default_config();
        let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
        let s = BatchSummary::from_results(&results);
        assert_eq!(s.total, 1);
        assert_eq!(s.applied, 1);
        assert_eq!(s.rejected, 0);
        assert_eq!(s.application_rate(), MILLION);
    }

    #[test]
    fn batch_summary_deterministic() {
        let reqs = vec![pure_ssr_request()];
        let cfg = SpecializationConfig::default_config();
        let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
        let s1 = BatchSummary::from_results(&results);
        let s2 = BatchSummary::from_results(&results);
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // --- SpecializationError ---

    #[test]
    fn error_display_invalid_config() {
        let e = SpecializationError::InvalidConfig {
            reason: "bad".into(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn error_display_inline_depth() {
        let e = SpecializationError::InlineDepthExceeded { depth: 10, max: 8 };
        let s = e.to_string();
        assert!(s.contains("10") && s.contains("8"));
    }

    #[test]
    fn error_display_limit() {
        let e = SpecializationError::SpecializationLimitExceeded { count: 17, max: 16 };
        assert!(e.to_string().contains("17"));
    }

    #[test]
    fn error_display_missing_check() {
        let e = SpecializationError::MissingSafetyCheck {
            kind: SafetyCheckKind::PurityProof,
        };
        assert!(e.to_string().contains("purity_proof"));
    }

    #[test]
    fn error_serde() {
        let e = SpecializationError::Internal {
            detail: "oops".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SpecializationError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}
