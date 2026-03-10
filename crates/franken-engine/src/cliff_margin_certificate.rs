#![forbid(unsafe_code)]

//! Cliff-margin certificates and escape plans for autotuning, AOT, and supremacy gates.
//!
//! Implements [RGC-619C]: gates autotuning, AOT compilation, and supremacy claims
//! on cliff-margin certificates and deterministic escape plans so that brittle
//! wins never masquerade as stable product capability.
//!
//! A **cliff-margin certificate** proves that a claimed win has sufficient margin
//! from the nearest relevant phase boundary (cliff). If the margin is too thin
//! or the escape plan is absent, the gate fails closed.
//!
//! # Design
//!
//! 1. Each certificate references a specific metric, the claimed win value,
//!    the nearest boundary distance, and a minimum margin budget.
//! 2. Escape plans describe deterministic rollback actions when margin erodes.
//! 3. The gate evaluates certificates against budgets and produces verdicts
//!    with structured blocking reasons.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Bead: bd-1lsy.7.19.3
//! Policy: RGC-619C

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::catastrophe_witness_generator::{BoundaryKind, PhaseRegion};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for serialised cliff-margin certificate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.cliff_margin_certificate.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.19.3";

/// Logical component name within the engine.
pub const COMPONENT: &str = "cliff_margin_certificate";

/// Policy identifier governing this module's behaviour.
pub const POLICY_ID: &str = "RGC-619C";

/// Fixed-point scaling constant: 1.0 = 1_000_000.
const MILLIONTHS: i64 = 1_000_000;

/// Default minimum margin (millionths). 10% = 100_000.
pub const DEFAULT_MIN_MARGIN_MILLIONTHS: i64 = 100_000;

/// Default escape plan deadline (ticks). 100 ticks to execute rollback.
pub const DEFAULT_ESCAPE_DEADLINE_TICKS: u64 = 100;

/// Maximum number of escape actions per plan.
pub const MAX_ESCAPE_ACTIONS: usize = 16;

/// Maximum number of certificates in a single gate evaluation.
pub const MAX_CERTIFICATES_PER_EVALUATION: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(dead_code)]
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
// GateDomain — which decision surface the certificate covers
// ---------------------------------------------------------------------------

/// Which decision surface requires cliff-margin proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDomain {
    /// Autotuning decisions (parameter adaptation, strategy selection).
    Autotuning,
    /// AOT compilation decisions (ahead-of-time artifact production).
    AotCompilation,
    /// Supremacy claims (published wins over baselines or competitors).
    Supremacy,
    /// Shipped path promotion (moving optimized paths to default).
    ShippedPath,
    /// Benchmark publication (publishing performance numbers).
    BenchmarkPublication,
}

impl fmt::Display for GateDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Autotuning => write!(f, "autotuning"),
            Self::AotCompilation => write!(f, "aot_compilation"),
            Self::Supremacy => write!(f, "supremacy"),
            Self::ShippedPath => write!(f, "shipped_path"),
            Self::BenchmarkPublication => write!(f, "benchmark_publication"),
        }
    }
}

// ---------------------------------------------------------------------------
// MetricClaim — what the certificate is asserting
// ---------------------------------------------------------------------------

/// A metric claim that a certificate backs with cliff-margin evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MetricClaim {
    /// Human-readable metric name (e.g., "p99_latency_ns", "throughput_ops_s").
    pub metric_name: String,
    /// Claimed metric value in millionths.
    pub claimed_value_millionths: i64,
    /// Threshold that defines "winning" in millionths.
    pub threshold_millionths: i64,
    /// Whether higher values are better (true) or lower (true = higher is win).
    pub higher_is_better: bool,
}

impl MetricClaim {
    /// Returns the margin between claimed value and threshold in millionths.
    /// Positive means winning, negative means losing.
    pub fn margin_millionths(&self) -> i64 {
        if self.higher_is_better {
            self.claimed_value_millionths
                .saturating_sub(self.threshold_millionths)
        } else {
            self.threshold_millionths
                .saturating_sub(self.claimed_value_millionths)
        }
    }

    /// Returns whether the claim is currently winning (margin > 0).
    pub fn is_winning(&self) -> bool {
        self.margin_millionths() > 0
    }
}

// ---------------------------------------------------------------------------
// CliffProximity — distance to the nearest phase boundary
// ---------------------------------------------------------------------------

/// Measured proximity to the nearest relevant cliff/phase boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CliffProximity {
    /// Distance to nearest boundary in millionths of the metric range.
    pub distance_millionths: i64,
    /// Kind of the nearest boundary.
    pub boundary_kind: BoundaryKind,
    /// Region the claim point is in.
    pub current_region: PhaseRegion,
    /// How many boundary probes contributed to this estimate.
    pub probe_count: u32,
    /// Confidence in the estimate (millionths, 0..=1_000_000).
    pub confidence_millionths: i64,
}

impl CliffProximity {
    /// Returns true if the claim point is in a brittle region.
    pub fn is_brittle(&self) -> bool {
        self.current_region.is_brittle()
    }

    /// Returns true if we have enough probes for a trustworthy estimate.
    pub fn is_well_probed(&self) -> bool {
        self.probe_count >= 5
    }
}

// ---------------------------------------------------------------------------
// EscapeAction — a single rollback step
// ---------------------------------------------------------------------------

/// A single deterministic rollback action in an escape plan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeAction {
    /// Revert autotuning parameter to a safe default value.
    RevertParameter {
        parameter_key: String,
        safe_value_millionths: i64,
    },
    /// Disable an AOT-compiled artifact and fall back to interpreter.
    DisableAotArtifact { artifact_id: String },
    /// Revert shipped path to previous known-good version.
    RevertShippedPath {
        path_id: String,
        rollback_version: u64,
    },
    /// Emit operator alert with structured context.
    EmitAlert {
        alert_class: String,
        context: String,
    },
    /// Quarantine a specific optimization so it can't re-engage.
    QuarantineOptimization {
        optimization_id: String,
        reason: String,
    },
}

impl EscapeAction {
    /// Returns a stable key for this action (for dedup and hashing).
    pub fn stable_key(&self) -> String {
        match self {
            Self::RevertParameter { parameter_key, .. } => {
                format!("revert_param:{parameter_key}")
            }
            Self::DisableAotArtifact { artifact_id } => {
                format!("disable_aot:{artifact_id}")
            }
            Self::RevertShippedPath { path_id, .. } => {
                format!("revert_path:{path_id}")
            }
            Self::EmitAlert { alert_class, .. } => {
                format!("alert:{alert_class}")
            }
            Self::QuarantineOptimization {
                optimization_id, ..
            } => {
                format!("quarantine:{optimization_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EscapePlan — deterministic rollback sequence
// ---------------------------------------------------------------------------

/// A deterministic escape plan that activates when cliff margin erodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapePlan {
    /// Unique plan identifier.
    pub plan_id: String,
    /// Ordered actions to execute on escape trigger.
    pub actions: Vec<EscapeAction>,
    /// Maximum ticks allowed to complete the escape.
    pub deadline_ticks: u64,
    /// Whether the plan has been validated (dry-run tested).
    pub validated: bool,
    /// Margin threshold (millionths) below which this plan triggers.
    pub trigger_margin_millionths: i64,
}

impl EscapePlan {
    /// Computes a content hash of the plan for auditing.
    pub fn compute_hash(&self) -> ContentHash {
        let plan_bytes = format!(
            "{}:{}:{}:{}",
            self.plan_id,
            self.actions.len(),
            self.deadline_ticks,
            self.trigger_margin_millionths,
        );
        let action_keys: Vec<String> = self.actions.iter().map(|a| a.stable_key()).collect();
        let action_str = action_keys.join("|");
        content_hash_from_parts(&[plan_bytes.as_bytes(), action_str.as_bytes()])
    }

    /// Returns true if the plan is executable (non-empty, within limits).
    pub fn is_executable(&self) -> bool {
        !self.actions.is_empty()
            && self.actions.len() <= MAX_ESCAPE_ACTIONS
            && self.deadline_ticks > 0
    }
}

// ---------------------------------------------------------------------------
// CliffMarginCertificate — the core certificate
// ---------------------------------------------------------------------------

/// A cliff-margin certificate proving sufficient distance from phase boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliffMarginCertificate {
    /// Unique certificate identifier.
    pub certificate_id: String,
    /// Which gate domain this certificate covers.
    pub domain: GateDomain,
    /// The metric claim being asserted.
    pub claim: MetricClaim,
    /// Measured proximity to the nearest cliff.
    pub proximity: CliffProximity,
    /// Required minimum margin for the domain (millionths).
    pub required_margin_millionths: i64,
    /// Escape plan if margin erodes.
    pub escape_plan: Option<EscapePlan>,
    /// Security epoch at time of issue.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds since epoch) of certificate creation.
    pub issued_at_ns: u64,
    /// Certificate hash (computed lazily).
    pub certificate_hash: ContentHash,
}

impl CliffMarginCertificate {
    /// Creates a new certificate and computes its hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_id: impl Into<String>,
        domain: GateDomain,
        claim: MetricClaim,
        proximity: CliffProximity,
        required_margin_millionths: i64,
        escape_plan: Option<EscapePlan>,
        epoch: SecurityEpoch,
        issued_at_ns: u64,
    ) -> Self {
        let cert_id = certificate_id.into();
        let hash = Self::compute_certificate_hash(
            &cert_id,
            &domain,
            &claim,
            &proximity,
            required_margin_millionths,
            &escape_plan,
            &epoch,
        );
        Self {
            certificate_id: cert_id,
            domain,
            claim,
            proximity,
            required_margin_millionths,
            escape_plan,
            epoch,
            issued_at_ns,
            certificate_hash: hash,
        }
    }

    fn compute_certificate_hash(
        cert_id: &str,
        domain: &GateDomain,
        claim: &MetricClaim,
        proximity: &CliffProximity,
        required_margin: i64,
        escape_plan: &Option<EscapePlan>,
        epoch: &SecurityEpoch,
    ) -> ContentHash {
        let data = format!(
            "cert:{}:{}:{}:{}:{}:{}:{}:{}",
            cert_id,
            domain,
            claim.metric_name,
            claim.claimed_value_millionths,
            proximity.distance_millionths,
            required_margin,
            escape_plan
                .as_ref()
                .map_or("none".to_string(), |p| p.plan_id.clone()),
            epoch.as_u64(),
        );
        content_hash_from_parts(&[data.as_bytes()])
    }

    /// Returns the actual margin: distance to cliff minus required margin.
    /// Positive means the claim has headroom. Negative means insufficient.
    pub fn headroom_millionths(&self) -> i64 {
        self.proximity
            .distance_millionths
            .saturating_sub(self.required_margin_millionths)
    }

    /// Returns true if the certificate has sufficient margin.
    pub fn has_sufficient_margin(&self) -> bool {
        self.headroom_millionths() >= 0
    }

    /// Returns true if an escape plan exists and is executable.
    pub fn has_executable_escape_plan(&self) -> bool {
        self.escape_plan
            .as_ref()
            .is_some_and(|p| p.is_executable() && p.validated)
    }
}

// ---------------------------------------------------------------------------
// CertificateVerdict — gate outcome
// ---------------------------------------------------------------------------

/// Verdict from evaluating a cliff-margin certificate against gate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateVerdict {
    /// Certificate approved: margin sufficient and (if needed) escape plan present.
    Approved,
    /// Approved with caveats: margin is thin but escape plan compensates.
    ApprovedWithCaveats,
    /// Blocked: insufficient margin and no adequate escape plan.
    Blocked,
    /// Insufficient evidence: not enough probes or confidence too low.
    InsufficientEvidence,
}

impl CertificateVerdict {
    /// Returns true if the verdict permits the gated action.
    pub fn permits_action(self) -> bool {
        matches!(self, Self::Approved | Self::ApprovedWithCaveats)
    }
}

impl fmt::Display for CertificateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::ApprovedWithCaveats => write!(f, "approved_with_caveats"),
            Self::Blocked => write!(f, "blocked"),
            Self::InsufficientEvidence => write!(f, "insufficient_evidence"),
        }
    }
}

// ---------------------------------------------------------------------------
// BlockingReason — why a certificate was blocked
// ---------------------------------------------------------------------------

/// Structured reason why a cliff-margin certificate was blocked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingReason {
    /// Margin is below the required minimum.
    InsufficientMargin {
        actual_millionths: i64,
        required_millionths: i64,
    },
    /// No escape plan provided for a domain that requires one.
    MissingEscapePlan,
    /// Escape plan exists but is not validated.
    UnvalidatedEscapePlan,
    /// Escape plan has too many actions.
    EscapePlanTooComplex { action_count: usize },
    /// Escape plan deadline is zero (non-executable).
    EscapePlanZeroDeadline,
    /// The claim is not currently winning.
    ClaimNotWinning { margin_millionths: i64 },
    /// Cliff proximity confidence is too low.
    LowConfidence {
        confidence_millionths: i64,
        min_required_millionths: i64,
    },
    /// Too few boundary probes for a reliable estimate.
    InsufficientProbes { probe_count: u32, min_required: u32 },
    /// The current region is robust loss — no amount of margin can help.
    InRobustLossRegion,
    /// Boundary kind is too severe for the claimed margin.
    BoundaryTooSevere {
        kind: BoundaryKind,
        distance_millionths: i64,
    },
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientMargin {
                actual_millionths,
                required_millionths,
            } => write!(
                f,
                "insufficient margin: {actual_millionths} < {required_millionths}"
            ),
            Self::MissingEscapePlan => write!(f, "missing escape plan"),
            Self::UnvalidatedEscapePlan => write!(f, "unvalidated escape plan"),
            Self::EscapePlanTooComplex { action_count } => {
                write!(f, "escape plan too complex: {action_count} actions")
            }
            Self::EscapePlanZeroDeadline => write!(f, "escape plan has zero deadline"),
            Self::ClaimNotWinning { margin_millionths } => {
                write!(f, "claim not winning: margin = {margin_millionths}")
            }
            Self::LowConfidence {
                confidence_millionths,
                min_required_millionths,
            } => write!(
                f,
                "low confidence: {confidence_millionths} < {min_required_millionths}"
            ),
            Self::InsufficientProbes {
                probe_count,
                min_required,
            } => write!(f, "insufficient probes: {probe_count} < {min_required}"),
            Self::InRobustLossRegion => write!(f, "in robust loss region"),
            Self::BoundaryTooSevere {
                kind,
                distance_millionths,
            } => write!(
                f,
                "boundary too severe: {kind:?} at distance {distance_millionths}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// GateConfig — configuration for the cliff-margin gate
// ---------------------------------------------------------------------------

/// Configuration for a cliff-margin gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum margin budget per domain (millionths).
    pub min_margin_by_domain: BTreeMap<String, i64>,
    /// Domains that require an escape plan.
    pub escape_plan_required_domains: Vec<GateDomain>,
    /// Minimum confidence for cliff proximity (millionths).
    pub min_confidence_millionths: i64,
    /// Minimum probe count for cliff proximity.
    pub min_probe_count: u32,
    /// Whether cliff-edge boundaries require extra margin multiplier.
    pub cliff_edge_margin_multiplier_millionths: i64,
    /// Whether to fail closed on any error.
    pub fail_closed: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        let mut min_margin = BTreeMap::new();
        min_margin.insert("autotuning".to_string(), 50_000); // 5%
        min_margin.insert("aot_compilation".to_string(), 100_000); // 10%
        min_margin.insert("supremacy".to_string(), 150_000); // 15%
        min_margin.insert("shipped_path".to_string(), 100_000); // 10%
        min_margin.insert("benchmark_publication".to_string(), 200_000); // 20%

        Self {
            min_margin_by_domain: min_margin,
            escape_plan_required_domains: vec![
                GateDomain::Supremacy,
                GateDomain::ShippedPath,
                GateDomain::BenchmarkPublication,
            ],
            min_confidence_millionths: 700_000, // 70%
            min_probe_count: 5,
            cliff_edge_margin_multiplier_millionths: 2_000_000, // 2x
            fail_closed: true,
        }
    }
}

impl GateConfig {
    /// Computes a content hash of the config for auditing.
    pub fn config_hash(&self) -> ContentHash {
        let domain_str: String = self
            .min_margin_by_domain
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        let data = format!(
            "config:{}:{}:{}:{}:{}",
            domain_str,
            self.min_confidence_millionths,
            self.min_probe_count,
            self.cliff_edge_margin_multiplier_millionths,
            self.fail_closed,
        );
        content_hash_from_parts(&[data.as_bytes()])
    }

    /// Returns the effective minimum margin for a domain.
    pub fn effective_min_margin(&self, domain: &GateDomain, boundary_kind: &BoundaryKind) -> i64 {
        let base = self
            .min_margin_by_domain
            .get(&domain.to_string())
            .copied()
            .unwrap_or(DEFAULT_MIN_MARGIN_MILLIONTHS);

        if matches!(boundary_kind, BoundaryKind::CliffEdge) {
            // Apply multiplier for cliff-edge boundaries.
            let multiplied = (base as i128)
                .saturating_mul(self.cliff_edge_margin_multiplier_millionths as i128)
                / MILLIONTHS as i128;
            multiplied.clamp(0, i64::MAX as i128) as i64
        } else {
            base
        }
    }

    /// Returns whether a domain requires an escape plan.
    pub fn requires_escape_plan(&self, domain: &GateDomain) -> bool {
        self.escape_plan_required_domains.contains(domain)
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt — auditable gate decision
// ---------------------------------------------------------------------------

/// Auditable receipt for a cliff-margin gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Certificate identifier that was evaluated.
    pub certificate_id: String,
    /// Gate domain.
    pub domain: GateDomain,
    /// Verdict.
    pub verdict: CertificateVerdict,
    /// Blocking reasons (empty if approved).
    pub blocking_reasons: Vec<BlockingReason>,
    /// Caveats (non-blocking observations).
    pub caveats: Vec<String>,
    /// Headroom in millionths.
    pub headroom_millionths: i64,
    /// Whether escape plan was present and valid.
    pub escape_plan_status: EscapePlanStatus,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Config hash at decision time.
    pub config_hash: ContentHash,
    /// Receipt hash.
    pub receipt_hash: ContentHash,
}

/// Status of the escape plan at evaluation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapePlanStatus {
    /// Present, validated, and executable.
    ValidAndExecutable,
    /// Present but not validated.
    PresentNotValidated,
    /// Present but not executable (empty or deadline 0).
    PresentNotExecutable,
    /// Not provided.
    Absent,
    /// Not required for this domain.
    NotRequired,
}

impl DecisionReceipt {
    fn compute_hash(
        receipt_id: &str,
        certificate_id: &str,
        domain: &GateDomain,
        verdict: &CertificateVerdict,
        blocking_reasons: &[BlockingReason],
        epoch: &SecurityEpoch,
    ) -> ContentHash {
        let blocking_str = blocking_reasons
            .iter()
            .map(|r| format!("{r}"))
            .collect::<Vec<_>>()
            .join("|");
        let data = format!(
            "receipt:{}:{}:{}:{}:{}:{}",
            receipt_id,
            certificate_id,
            domain,
            verdict,
            blocking_str,
            epoch.as_u64(),
        );
        content_hash_from_parts(&[data.as_bytes()])
    }
}

// ---------------------------------------------------------------------------
// CliffMarginGate — the main gate evaluator
// ---------------------------------------------------------------------------

/// The cliff-margin gate evaluator. Evaluates certificates against policy
/// and produces auditable decision receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliffMarginGate {
    /// Gate configuration.
    pub config: GateConfig,
    /// Decision receipts from evaluations.
    pub receipts: Vec<DecisionReceipt>,
    /// Running receipt counter for ID generation.
    receipt_counter: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
}

impl CliffMarginGate {
    /// Creates a new gate with the given config and epoch.
    pub fn new(config: GateConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            receipts: Vec::new(),
            receipt_counter: 0,
            epoch,
        }
    }

    /// Creates a gate with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GateConfig::default(), epoch)
    }

    /// Evaluates a cliff-margin certificate and returns the verdict.
    pub fn evaluate(&mut self, cert: &CliffMarginCertificate) -> CertificateVerdict {
        let mut blocking_reasons = Vec::new();
        let mut caveats = Vec::new();

        // 1. Check that the claim is currently winning.
        if !cert.claim.is_winning() {
            blocking_reasons.push(BlockingReason::ClaimNotWinning {
                margin_millionths: cert.claim.margin_millionths(),
            });
        }

        // 2. Check the current region — robust loss is always blocked.
        if cert.proximity.current_region == PhaseRegion::RobustLoss {
            blocking_reasons.push(BlockingReason::InRobustLossRegion);
        }

        // 3. Check probe count.
        if cert.proximity.probe_count < self.config.min_probe_count {
            blocking_reasons.push(BlockingReason::InsufficientProbes {
                probe_count: cert.proximity.probe_count,
                min_required: self.config.min_probe_count,
            });
        }

        // 4. Check confidence.
        if cert.proximity.confidence_millionths < self.config.min_confidence_millionths {
            blocking_reasons.push(BlockingReason::LowConfidence {
                confidence_millionths: cert.proximity.confidence_millionths,
                min_required_millionths: self.config.min_confidence_millionths,
            });
        }

        // 5. Check margin against effective minimum.
        let effective_min = self
            .config
            .effective_min_margin(&cert.domain, &cert.proximity.boundary_kind);
        if cert.proximity.distance_millionths < effective_min {
            blocking_reasons.push(BlockingReason::InsufficientMargin {
                actual_millionths: cert.proximity.distance_millionths,
                required_millionths: effective_min,
            });
        }

        // 6. Check for severe boundary types.
        if matches!(
            cert.proximity.boundary_kind,
            BoundaryKind::CliffEdge | BoundaryKind::Cusp
        ) && cert.proximity.distance_millionths < effective_min * 2
        {
            caveats.push(format!(
                "severe boundary ({:?}) with limited margin",
                cert.proximity.boundary_kind,
            ));
        }

        // 7. Check escape plan if required.
        let escape_plan_status = self.evaluate_escape_plan(cert, &mut blocking_reasons);

        // 8. Determine verdict.
        let verdict = if blocking_reasons.is_empty() {
            if caveats.is_empty() {
                CertificateVerdict::Approved
            } else {
                CertificateVerdict::ApprovedWithCaveats
            }
        } else if blocking_reasons.iter().any(|r| {
            matches!(
                r,
                BlockingReason::InsufficientProbes { .. } | BlockingReason::LowConfidence { .. }
            )
        }) && blocking_reasons.len() == 1
        {
            CertificateVerdict::InsufficientEvidence
        } else {
            CertificateVerdict::Blocked
        };

        // 9. Emit receipt.
        self.receipt_counter += 1;
        let receipt_id = format!("cmg-rcpt-{}", self.receipt_counter);
        let receipt_hash = DecisionReceipt::compute_hash(
            &receipt_id,
            &cert.certificate_id,
            &cert.domain,
            &verdict,
            &blocking_reasons,
            &self.epoch,
        );

        self.receipts.push(DecisionReceipt {
            receipt_id,
            certificate_id: cert.certificate_id.clone(),
            domain: cert.domain,
            verdict,
            blocking_reasons,
            caveats,
            headroom_millionths: cert.headroom_millionths(),
            escape_plan_status,
            epoch: self.epoch,
            config_hash: self.config.config_hash(),
            receipt_hash,
        });

        verdict
    }

    /// Evaluates the escape plan portion of a certificate.
    fn evaluate_escape_plan(
        &self,
        cert: &CliffMarginCertificate,
        blocking_reasons: &mut Vec<BlockingReason>,
    ) -> EscapePlanStatus {
        let requires_plan = self.config.requires_escape_plan(&cert.domain);

        match &cert.escape_plan {
            None => {
                if requires_plan {
                    blocking_reasons.push(BlockingReason::MissingEscapePlan);
                    EscapePlanStatus::Absent
                } else {
                    EscapePlanStatus::NotRequired
                }
            }
            Some(plan) => {
                if !plan.is_executable() {
                    if plan.actions.is_empty() || plan.deadline_ticks == 0 {
                        blocking_reasons.push(BlockingReason::EscapePlanZeroDeadline);
                    }
                    if plan.actions.len() > MAX_ESCAPE_ACTIONS {
                        blocking_reasons.push(BlockingReason::EscapePlanTooComplex {
                            action_count: plan.actions.len(),
                        });
                    }
                    EscapePlanStatus::PresentNotExecutable
                } else if !plan.validated {
                    if requires_plan {
                        blocking_reasons.push(BlockingReason::UnvalidatedEscapePlan);
                    }
                    EscapePlanStatus::PresentNotValidated
                } else {
                    EscapePlanStatus::ValidAndExecutable
                }
            }
        }
    }

    /// Returns all receipts.
    pub fn receipts(&self) -> &[DecisionReceipt] {
        &self.receipts
    }

    /// Returns the most recent receipt.
    pub fn last_receipt(&self) -> Option<&DecisionReceipt> {
        self.receipts.last()
    }

    /// Returns the count of approved certificates.
    pub fn approved_count(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| r.verdict.permits_action())
            .count()
    }

    /// Returns the count of blocked certificates.
    pub fn blocked_count(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| !r.verdict.permits_action())
            .count()
    }

    /// Generates a gate summary.
    pub fn summary(&self) -> GateSummary {
        let total = self.receipts.len() as u64;
        let approved = self.approved_count() as u64;
        let blocked = self.blocked_count() as u64;

        let blocking_reason_counts = {
            let mut counts = BTreeMap::new();
            for receipt in &self.receipts {
                for reason in &receipt.blocking_reasons {
                    let key = format!("{reason}");
                    *counts.entry(key).or_insert(0u64) += 1;
                }
            }
            counts
        };

        let avg_headroom = if total > 0 {
            let sum: i64 = self.receipts.iter().map(|r| r.headroom_millionths).sum();
            sum / total as i64
        } else {
            0
        };

        let min_headroom = self
            .receipts
            .iter()
            .map(|r| r.headroom_millionths)
            .min()
            .unwrap_or(0);

        let summary_hash = content_hash_from_parts(&[format!(
            "summary:{}:{}:{}:{}:{}",
            total, approved, blocked, avg_headroom, min_headroom,
        )
        .as_bytes()]);

        GateSummary {
            total_evaluations: total,
            approved_count: approved,
            blocked_count: blocked,
            blocking_reason_counts,
            avg_headroom_millionths: avg_headroom,
            min_headroom_millionths: min_headroom,
            config_hash: self.config.config_hash(),
            epoch: self.epoch,
            summary_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics for a cliff-margin gate evaluation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total certificates evaluated.
    pub total_evaluations: u64,
    /// Certificates approved (including with caveats).
    pub approved_count: u64,
    /// Certificates blocked.
    pub blocked_count: u64,
    /// Count of each blocking reason type.
    pub blocking_reason_counts: BTreeMap<String, u64>,
    /// Average headroom across all evaluations (millionths).
    pub avg_headroom_millionths: i64,
    /// Minimum headroom observed (millionths).
    pub min_headroom_millionths: i64,
    /// Config hash at summary time.
    pub config_hash: ContentHash,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Summary hash.
    pub summary_hash: ContentHash,
}

impl GateSummary {
    /// Returns the pass rate in millionths (e.g., 750_000 = 75%).
    pub fn pass_rate_millionths(&self) -> i64 {
        if self.total_evaluations == 0 {
            return 0;
        }
        (self.approved_count as i64).saturating_mul(MILLIONTHS) / self.total_evaluations as i64
    }
}

// ---------------------------------------------------------------------------
// Batch evaluation
// ---------------------------------------------------------------------------

/// Batch evaluation result for multiple certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEvaluationResult {
    /// Individual verdicts indexed by certificate ID.
    pub verdicts: BTreeMap<String, CertificateVerdict>,
    /// Whether all certificates were approved.
    pub all_approved: bool,
    /// Summary after batch.
    pub summary: GateSummary,
}

/// Evaluates a batch of certificates through the gate.
pub fn evaluate_batch(
    gate: &mut CliffMarginGate,
    certificates: &[CliffMarginCertificate],
) -> BatchEvaluationResult {
    let mut verdicts = BTreeMap::new();
    let mut all_approved = true;

    for cert in certificates.iter().take(MAX_CERTIFICATES_PER_EVALUATION) {
        let verdict = gate.evaluate(cert);
        if !verdict.permits_action() {
            all_approved = false;
        }
        verdicts.insert(cert.certificate_id.clone(), verdict);
    }

    let summary = gate.summary();

    BatchEvaluationResult {
        verdicts,
        all_approved,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Complete manifest for a cliff-margin gate session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliffMarginManifest {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Component name.
    pub component: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Gate summary.
    pub summary: GateSummary,
    /// All decision receipts.
    pub receipts: Vec<DecisionReceipt>,
    /// Manifest hash.
    pub manifest_hash: ContentHash,
}

impl CliffMarginManifest {
    /// Builds a manifest from a gate.
    pub fn from_gate(gate: &CliffMarginGate) -> Self {
        let summary = gate.summary();
        let receipts = gate.receipts().to_vec();

        let manifest_data = format!(
            "manifest:{}:{}:{}:{}",
            SCHEMA_VERSION,
            summary.total_evaluations,
            summary.approved_count,
            summary.blocked_count,
        );
        let manifest_hash = content_hash_from_parts(&[manifest_data.as_bytes()]);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            summary,
            receipts,
            manifest_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Creates a cliff-margin certificate for a latency metric claim.
#[allow(clippy::too_many_arguments)]
pub fn latency_certificate(
    cert_id: impl Into<String>,
    domain: GateDomain,
    metric_name: impl Into<String>,
    claimed_ns: i64,
    threshold_ns: i64,
    cliff_distance_millionths: i64,
    boundary_kind: BoundaryKind,
    region: PhaseRegion,
    probe_count: u32,
    confidence_millionths: i64,
    escape_plan: Option<EscapePlan>,
    epoch: SecurityEpoch,
) -> CliffMarginCertificate {
    CliffMarginCertificate::new(
        cert_id,
        domain,
        MetricClaim {
            metric_name: metric_name.into(),
            claimed_value_millionths: claimed_ns,
            threshold_millionths: threshold_ns,
            higher_is_better: false, // lower latency is better
        },
        CliffProximity {
            distance_millionths: cliff_distance_millionths,
            boundary_kind,
            current_region: region,
            probe_count,
            confidence_millionths,
        },
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        escape_plan,
        epoch,
        0,
    )
}

/// Creates a cliff-margin certificate for a throughput metric claim.
#[allow(clippy::too_many_arguments)]
pub fn throughput_certificate(
    cert_id: impl Into<String>,
    domain: GateDomain,
    metric_name: impl Into<String>,
    claimed_ops: i64,
    threshold_ops: i64,
    cliff_distance_millionths: i64,
    boundary_kind: BoundaryKind,
    region: PhaseRegion,
    probe_count: u32,
    confidence_millionths: i64,
    escape_plan: Option<EscapePlan>,
    epoch: SecurityEpoch,
) -> CliffMarginCertificate {
    CliffMarginCertificate::new(
        cert_id,
        domain,
        MetricClaim {
            metric_name: metric_name.into(),
            claimed_value_millionths: claimed_ops,
            threshold_millionths: threshold_ops,
            higher_is_better: true, // higher throughput is better
        },
        CliffProximity {
            distance_millionths: cliff_distance_millionths,
            boundary_kind,
            current_region: region,
            probe_count,
            confidence_millionths,
        },
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        escape_plan,
        epoch,
        0,
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers
    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn good_claim() -> MetricClaim {
        MetricClaim {
            metric_name: "p99_latency_ns".to_string(),
            claimed_value_millionths: 800_000,
            threshold_millionths: 1_000_000,
            higher_is_better: false,
        }
    }

    fn losing_claim() -> MetricClaim {
        MetricClaim {
            metric_name: "p99_latency_ns".to_string(),
            claimed_value_millionths: 1_200_000,
            threshold_millionths: 1_000_000,
            higher_is_better: false,
        }
    }

    fn good_proximity() -> CliffProximity {
        CliffProximity {
            distance_millionths: 300_000,
            boundary_kind: BoundaryKind::Fold,
            current_region: PhaseRegion::RobustWin,
            probe_count: 10,
            confidence_millionths: 900_000,
        }
    }

    fn thin_proximity() -> CliffProximity {
        CliffProximity {
            distance_millionths: 30_000,
            boundary_kind: BoundaryKind::CliffEdge,
            current_region: PhaseRegion::BrittleWin,
            probe_count: 10,
            confidence_millionths: 900_000,
        }
    }

    fn low_confidence_proximity() -> CliffProximity {
        CliffProximity {
            distance_millionths: 300_000,
            boundary_kind: BoundaryKind::Fold,
            current_region: PhaseRegion::RobustWin,
            probe_count: 2,
            confidence_millionths: 400_000,
        }
    }

    fn valid_escape_plan() -> EscapePlan {
        EscapePlan {
            plan_id: "escape-001".to_string(),
            actions: vec![
                EscapeAction::RevertParameter {
                    parameter_key: "concurrency".to_string(),
                    safe_value_millionths: 500_000,
                },
                EscapeAction::EmitAlert {
                    alert_class: "margin_erosion".to_string(),
                    context: "cliff margin below threshold".to_string(),
                },
            ],
            deadline_ticks: 50,
            validated: true,
            trigger_margin_millionths: 50_000,
        }
    }

    fn unvalidated_escape_plan() -> EscapePlan {
        let mut plan = valid_escape_plan();
        plan.validated = false;
        plan
    }

    fn make_cert(
        domain: GateDomain,
        claim: MetricClaim,
        proximity: CliffProximity,
        escape_plan: Option<EscapePlan>,
    ) -> CliffMarginCertificate {
        CliffMarginCertificate::new(
            "cert-test",
            domain,
            claim,
            proximity,
            DEFAULT_MIN_MARGIN_MILLIONTHS,
            escape_plan,
            epoch(),
            1_000_000,
        )
    }

    // -----------------------------------------------------------------------
    // MetricClaim tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_claim_margin_higher_is_better() {
        let claim = MetricClaim {
            metric_name: "throughput".to_string(),
            claimed_value_millionths: 1_500_000,
            threshold_millionths: 1_000_000,
            higher_is_better: true,
        };
        assert_eq!(claim.margin_millionths(), 500_000);
        assert!(claim.is_winning());
    }

    #[test]
    fn test_claim_margin_lower_is_better() {
        let claim = good_claim();
        assert_eq!(claim.margin_millionths(), 200_000);
        assert!(claim.is_winning());
    }

    #[test]
    fn test_losing_claim_margin() {
        let claim = losing_claim();
        assert_eq!(claim.margin_millionths(), -200_000);
        assert!(!claim.is_winning());
    }

    #[test]
    fn test_exact_threshold_claim() {
        let claim = MetricClaim {
            metric_name: "latency".to_string(),
            claimed_value_millionths: 1_000_000,
            threshold_millionths: 1_000_000,
            higher_is_better: false,
        };
        assert_eq!(claim.margin_millionths(), 0);
        assert!(!claim.is_winning());
    }

    // -----------------------------------------------------------------------
    // CliffProximity tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_proximity_is_brittle() {
        let p = thin_proximity();
        assert!(p.is_brittle());
        assert!(p.is_well_probed());
    }

    #[test]
    fn test_proximity_robust_not_brittle() {
        let p = good_proximity();
        assert!(!p.is_brittle());
    }

    #[test]
    fn test_proximity_low_probes() {
        let p = low_confidence_proximity();
        assert!(!p.is_well_probed());
    }

    // -----------------------------------------------------------------------
    // EscapePlan tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_escape_plan() {
        let plan = valid_escape_plan();
        assert!(plan.is_executable());
    }

    #[test]
    fn test_empty_escape_plan_not_executable() {
        let plan = EscapePlan {
            plan_id: "empty".to_string(),
            actions: vec![],
            deadline_ticks: 50,
            validated: true,
            trigger_margin_millionths: 50_000,
        };
        assert!(!plan.is_executable());
    }

    #[test]
    fn test_zero_deadline_not_executable() {
        let mut plan = valid_escape_plan();
        plan.deadline_ticks = 0;
        assert!(!plan.is_executable());
    }

    #[test]
    fn test_escape_plan_hash_deterministic() {
        let plan = valid_escape_plan();
        let h1 = plan.compute_hash();
        let h2 = plan.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_escape_action_stable_keys() {
        let a1 = EscapeAction::RevertParameter {
            parameter_key: "k".to_string(),
            safe_value_millionths: 0,
        };
        assert!(a1.stable_key().starts_with("revert_param:"));
        let a2 = EscapeAction::DisableAotArtifact {
            artifact_id: "a".to_string(),
        };
        assert!(a2.stable_key().starts_with("disable_aot:"));
        let a3 = EscapeAction::QuarantineOptimization {
            optimization_id: "o".to_string(),
            reason: "r".to_string(),
        };
        assert!(a3.stable_key().starts_with("quarantine:"));
    }

    // -----------------------------------------------------------------------
    // CliffMarginCertificate tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cert_headroom_sufficient() {
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        assert_eq!(cert.headroom_millionths(), 200_000); // 300k - 100k
        assert!(cert.has_sufficient_margin());
    }

    #[test]
    fn test_cert_headroom_insufficient() {
        let cert = make_cert(GateDomain::Supremacy, good_claim(), thin_proximity(), None);
        assert_eq!(cert.headroom_millionths(), -70_000); // 30k - 100k
        assert!(!cert.has_sufficient_margin());
    }

    #[test]
    fn test_cert_hash_deterministic() {
        let cert1 = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        let cert2 = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
    }

    #[test]
    fn test_cert_has_executable_escape_plan() {
        let cert = make_cert(
            GateDomain::Supremacy,
            good_claim(),
            good_proximity(),
            Some(valid_escape_plan()),
        );
        assert!(cert.has_executable_escape_plan());
    }

    #[test]
    fn test_cert_unvalidated_plan_not_executable() {
        let cert = make_cert(
            GateDomain::Supremacy,
            good_claim(),
            good_proximity(),
            Some(unvalidated_escape_plan()),
        );
        assert!(!cert.has_executable_escape_plan());
    }

    // -----------------------------------------------------------------------
    // GateDomain tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_domain_display() {
        assert_eq!(GateDomain::Autotuning.to_string(), "autotuning");
        assert_eq!(GateDomain::AotCompilation.to_string(), "aot_compilation");
        assert_eq!(GateDomain::Supremacy.to_string(), "supremacy");
        assert_eq!(GateDomain::ShippedPath.to_string(), "shipped_path");
        assert_eq!(
            GateDomain::BenchmarkPublication.to_string(),
            "benchmark_publication"
        );
    }

    // -----------------------------------------------------------------------
    // GateConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_margins() {
        let config = GateConfig::default();
        assert_eq!(config.min_margin_by_domain.get("autotuning"), Some(&50_000));
        assert_eq!(config.min_margin_by_domain.get("supremacy"), Some(&150_000));
    }

    #[test]
    fn test_effective_margin_cliff_edge_multiplier() {
        let config = GateConfig::default();
        let base = config.effective_min_margin(&GateDomain::Autotuning, &BoundaryKind::Fold);
        let cliff = config.effective_min_margin(&GateDomain::Autotuning, &BoundaryKind::CliffEdge);
        assert_eq!(base, 50_000);
        assert_eq!(cliff, 100_000); // 50k * 2.0
    }

    #[test]
    fn test_requires_escape_plan() {
        let config = GateConfig::default();
        assert!(!config.requires_escape_plan(&GateDomain::Autotuning));
        assert!(config.requires_escape_plan(&GateDomain::Supremacy));
        assert!(config.requires_escape_plan(&GateDomain::ShippedPath));
        assert!(config.requires_escape_plan(&GateDomain::BenchmarkPublication));
    }

    #[test]
    fn test_config_hash_deterministic() {
        let c1 = GateConfig::default();
        let c2 = GateConfig::default();
        assert_eq!(c1.config_hash(), c2.config_hash());
    }

    // -----------------------------------------------------------------------
    // Gate evaluation tests — approved
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_approves_good_autotuning_cert() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Approved);
        assert_eq!(gate.approved_count(), 1);
        assert_eq!(gate.blocked_count(), 0);
    }

    #[test]
    fn test_gate_approves_supremacy_with_escape_plan() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Supremacy,
            MetricClaim {
                metric_name: "throughput".to_string(),
                claimed_value_millionths: 2_000_000,
                threshold_millionths: 1_000_000,
                higher_is_better: true,
            },
            good_proximity(),
            Some(valid_escape_plan()),
        );
        let verdict = gate.evaluate(&cert);
        assert!(verdict.permits_action());
    }

    // -----------------------------------------------------------------------
    // Gate evaluation tests — blocked
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_blocks_losing_claim() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Autotuning,
            losing_claim(),
            good_proximity(),
            None,
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    #[test]
    fn test_gate_blocks_insufficient_margin() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), thin_proximity(), None);
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    #[test]
    fn test_gate_blocks_supremacy_without_escape_plan() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Supremacy,
            MetricClaim {
                metric_name: "throughput".to_string(),
                claimed_value_millionths: 2_000_000,
                threshold_millionths: 1_000_000,
                higher_is_better: true,
            },
            good_proximity(),
            None, // No escape plan
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    #[test]
    fn test_gate_blocks_unvalidated_escape_plan() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Supremacy,
            MetricClaim {
                metric_name: "throughput".to_string(),
                claimed_value_millionths: 2_000_000,
                threshold_millionths: 1_000_000,
                higher_is_better: true,
            },
            good_proximity(),
            Some(unvalidated_escape_plan()),
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    #[test]
    fn test_gate_blocks_robust_loss_region() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let prox = CliffProximity {
            distance_millionths: 500_000,
            boundary_kind: BoundaryKind::Fold,
            current_region: PhaseRegion::RobustLoss,
            probe_count: 10,
            confidence_millionths: 900_000,
        };
        let cert = make_cert(GateDomain::Autotuning, losing_claim(), prox, None);
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    // -----------------------------------------------------------------------
    // Gate evaluation tests — insufficient evidence
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_insufficient_evidence_low_probes() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let prox = CliffProximity {
            distance_millionths: 300_000,
            boundary_kind: BoundaryKind::Fold,
            current_region: PhaseRegion::RobustWin,
            probe_count: 2,
            confidence_millionths: 900_000,
        };
        let cert = make_cert(GateDomain::Autotuning, good_claim(), prox, None);
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::InsufficientEvidence);
    }

    #[test]
    fn test_gate_insufficient_evidence_low_confidence() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let prox = CliffProximity {
            distance_millionths: 300_000,
            boundary_kind: BoundaryKind::Fold,
            current_region: PhaseRegion::RobustWin,
            probe_count: 10,
            confidence_millionths: 400_000,
        };
        let cert = make_cert(GateDomain::Autotuning, good_claim(), prox, None);
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::InsufficientEvidence);
    }

    // -----------------------------------------------------------------------
    // DecisionReceipt tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_created_on_evaluation() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        gate.evaluate(&cert);
        assert_eq!(gate.receipts.len(), 1);
        let receipt = &gate.receipts[0];
        assert_eq!(receipt.domain, GateDomain::Autotuning);
        assert_eq!(receipt.verdict, CertificateVerdict::Approved);
        assert!(receipt.blocking_reasons.is_empty());
    }

    #[test]
    fn test_receipt_has_blocking_reasons() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Supremacy,
            losing_claim(),
            thin_proximity(),
            None,
        );
        gate.evaluate(&cert);
        let receipt = &gate.receipts[0];
        assert!(!receipt.blocking_reasons.is_empty());
    }

    #[test]
    fn test_receipt_escape_plan_status() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        // Autotuning doesn't require escape plan
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        gate.evaluate(&cert);
        assert_eq!(
            gate.receipts[0].escape_plan_status,
            EscapePlanStatus::NotRequired
        );
    }

    // -----------------------------------------------------------------------
    // GateSummary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_summary() {
        let gate = CliffMarginGate::with_defaults(epoch());
        let summary = gate.summary();
        assert_eq!(summary.total_evaluations, 0);
        assert_eq!(summary.pass_rate_millionths(), 0);
    }

    #[test]
    fn test_summary_after_evaluations() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert1 = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        let cert2 = make_cert(
            GateDomain::Autotuning,
            losing_claim(),
            good_proximity(),
            None,
        );
        gate.evaluate(&cert1);
        gate.evaluate(&cert2);

        let summary = gate.summary();
        assert_eq!(summary.total_evaluations, 2);
        assert_eq!(summary.approved_count, 1);
        assert_eq!(summary.blocked_count, 1);
        assert_eq!(summary.pass_rate_millionths(), 500_000);
    }

    #[test]
    fn test_summary_blocking_reason_counts() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Autotuning,
            losing_claim(),
            thin_proximity(),
            None,
        );
        gate.evaluate(&cert);

        let summary = gate.summary();
        assert!(!summary.blocking_reason_counts.is_empty());
    }

    // -----------------------------------------------------------------------
    // Batch evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_all_approved() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let certs = vec![
            make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None),
            make_cert(
                GateDomain::Autotuning,
                MetricClaim {
                    metric_name: "throughput".to_string(),
                    claimed_value_millionths: 2_000_000,
                    threshold_millionths: 1_000_000,
                    higher_is_better: true,
                },
                good_proximity(),
                None,
            ),
        ];
        let result = evaluate_batch(&mut gate, &certs);
        assert!(result.all_approved);
        assert_eq!(result.verdicts.len(), 2);
    }

    #[test]
    fn test_batch_not_all_approved() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let certs = vec![
            make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None),
            make_cert(
                GateDomain::Autotuning,
                losing_claim(),
                good_proximity(),
                None,
            ),
        ];
        let result = evaluate_batch(&mut gate, &certs);
        assert!(!result.all_approved);
    }

    #[test]
    fn test_batch_respects_max_limit() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let certs: Vec<CliffMarginCertificate> = (0..100)
            .map(|i| {
                let mut cert =
                    make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
                cert.certificate_id = format!("cert-{i}");
                cert
            })
            .collect();
        let result = evaluate_batch(&mut gate, &certs);
        assert_eq!(result.verdicts.len(), MAX_CERTIFICATES_PER_EVALUATION);
    }

    // -----------------------------------------------------------------------
    // Convenience constructor tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_latency_certificate() {
        let cert = latency_certificate(
            "lat-001",
            GateDomain::AotCompilation,
            "p99_latency_ns",
            800_000,
            1_000_000,
            200_000,
            BoundaryKind::Fold,
            PhaseRegion::RobustWin,
            10,
            900_000,
            None,
            epoch(),
        );
        assert!(!cert.claim.higher_is_better);
        assert!(cert.claim.is_winning());
    }

    #[test]
    fn test_throughput_certificate() {
        let cert = throughput_certificate(
            "tp-001",
            GateDomain::Supremacy,
            "ops_per_sec",
            2_000_000,
            1_000_000,
            300_000,
            BoundaryKind::Fold,
            PhaseRegion::RobustWin,
            10,
            900_000,
            Some(valid_escape_plan()),
            epoch(),
        );
        assert!(cert.claim.higher_is_better);
        assert!(cert.claim.is_winning());
    }

    // -----------------------------------------------------------------------
    // Manifest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_from_gate() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        gate.evaluate(&cert);

        let manifest = CliffMarginManifest::from_gate(&gate);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.bead_id, BEAD_ID);
        assert_eq!(manifest.receipts.len(), 1);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let mut g1 = CliffMarginGate::with_defaults(epoch());
        let mut g2 = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        g1.evaluate(&cert.clone());
        g2.evaluate(&cert);

        let m1 = CliffMarginManifest::from_gate(&g1);
        let m2 = CliffMarginManifest::from_gate(&g2);
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_domain_serde_roundtrip() {
        let domain = GateDomain::Supremacy;
        let json = serde_json::to_string(&domain).unwrap();
        let back: GateDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(domain, back);
    }

    #[test]
    fn test_certificate_serde_roundtrip() {
        let cert = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            good_proximity(),
            Some(valid_escape_plan()),
        );
        let json = serde_json::to_string(&cert).unwrap();
        let back: CliffMarginCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert.certificate_id, back.certificate_id);
        assert_eq!(cert.certificate_hash, back.certificate_hash);
    }

    #[test]
    fn test_escape_plan_serde_roundtrip() {
        let plan = valid_escape_plan();
        let json = serde_json::to_string(&plan).unwrap();
        let back: EscapePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan.plan_id, back.plan_id);
        assert_eq!(plan.actions.len(), back.actions.len());
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        for v in [
            CertificateVerdict::Approved,
            CertificateVerdict::ApprovedWithCaveats,
            CertificateVerdict::Blocked,
            CertificateVerdict::InsufficientEvidence,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_decision_receipt_serde_roundtrip() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        gate.evaluate(&cert);
        let receipt = &gate.receipts[0];
        let json = serde_json::to_string(receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.receipt_id, back.receipt_id);
        assert_eq!(receipt.verdict, back.verdict);
    }

    #[test]
    fn test_manifest_serde_roundtrip() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(GateDomain::Autotuning, good_claim(), good_proximity(), None);
        gate.evaluate(&cert);
        let manifest = CliffMarginManifest::from_gate(&gate);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: CliffMarginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.schema_version, back.schema_version);
        assert_eq!(manifest.manifest_hash, back.manifest_hash);
    }

    // -----------------------------------------------------------------------
    // Blocking reason Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blocking_reason_display() {
        let reasons = vec![
            BlockingReason::InsufficientMargin {
                actual_millionths: 30_000,
                required_millionths: 100_000,
            },
            BlockingReason::MissingEscapePlan,
            BlockingReason::UnvalidatedEscapePlan,
            BlockingReason::InRobustLossRegion,
        ];
        for reason in &reasons {
            let s = format!("{reason}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(CertificateVerdict::Approved.to_string(), "approved");
        assert_eq!(CertificateVerdict::Blocked.to_string(), "blocked");
    }

    // -----------------------------------------------------------------------
    // Edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_blocking_reasons_combined() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        // Losing claim + thin proximity + robust loss + low confidence + no escape plan for supremacy
        let cert = make_cert(
            GateDomain::Supremacy,
            losing_claim(),
            CliffProximity {
                distance_millionths: 10_000,
                boundary_kind: BoundaryKind::CliffEdge,
                current_region: PhaseRegion::RobustLoss,
                probe_count: 1,
                confidence_millionths: 100_000,
            },
            None,
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
        let receipt = gate.last_receipt().unwrap();
        // Should have multiple blocking reasons
        assert!(receipt.blocking_reasons.len() >= 3);
    }

    #[test]
    fn test_approved_with_caveats_severe_boundary() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        // Good claim, enough margin, but cliff-edge boundary type
        let cert = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            CliffProximity {
                distance_millionths: 150_000,
                boundary_kind: BoundaryKind::CliffEdge,
                current_region: PhaseRegion::RobustWin,
                probe_count: 10,
                confidence_millionths: 900_000,
            },
            None,
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::ApprovedWithCaveats);
    }

    #[test]
    fn test_gate_with_custom_config() {
        let mut config = GateConfig::default();
        config
            .min_margin_by_domain
            .insert("autotuning".to_string(), 500_000);
        let mut gate = CliffMarginGate::new(config, epoch());

        let cert = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            good_proximity(), // distance = 300k < required 500k
            None,
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Blocked);
    }

    #[test]
    fn test_summary_min_headroom_tracking() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert1 = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            good_proximity(), // distance=300k, required=50k, headroom=200k
            None,
        );
        let cert2 = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            CliffProximity {
                distance_millionths: 60_000,
                boundary_kind: BoundaryKind::Fold,
                current_region: PhaseRegion::RobustWin,
                probe_count: 10,
                confidence_millionths: 900_000,
            },
            None,
        );
        gate.evaluate(&cert1);
        gate.evaluate(&cert2);

        let summary = gate.summary();
        // cert2 headroom = 60k - 100k = -40k (default required margin)
        assert!(summary.min_headroom_millionths < 0);
    }

    #[test]
    fn test_escape_plan_too_many_actions() {
        let actions: Vec<EscapeAction> = (0..20)
            .map(|i| EscapeAction::EmitAlert {
                alert_class: format!("alert_{i}"),
                context: "test".to_string(),
            })
            .collect();
        let plan = EscapePlan {
            plan_id: "too-many".to_string(),
            actions,
            deadline_ticks: 50,
            validated: true,
            trigger_margin_millionths: 50_000,
        };
        assert!(!plan.is_executable()); // >16 actions
    }

    #[test]
    fn test_gate_autotuning_does_not_require_escape_plan() {
        let mut gate = CliffMarginGate::with_defaults(epoch());
        let cert = make_cert(
            GateDomain::Autotuning,
            good_claim(),
            good_proximity(),
            None, // No escape plan, but autotuning doesn't require one
        );
        let verdict = gate.evaluate(&cert);
        assert_eq!(verdict, CertificateVerdict::Approved);
        assert_eq!(
            gate.last_receipt().unwrap().escape_plan_status,
            EscapePlanStatus::NotRequired,
        );
    }
}
