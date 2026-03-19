#![forbid(unsafe_code)]

//! Stage-envelope certificates and runtime violation detectors for tail latency.
//!
//! Bead: bd-1lsy.7.11.1 [RGC-611A]
//!
//! Derives per-stage latency-envelope certificates so the runtime can prove
//! where p99/p999 budget is spent.  Violation detectors fire before tail
//! behavior silently drifts out of bounds.
//!
//! Each execution stage (parse, compile, GC, tier-up, module-load, etc.) has
//! a declared latency envelope: percentile thresholds that bound how much of
//! the overall tail budget that stage is allowed to consume.  The certificate
//! proves compliance; a violation witness proves a breach with minimal evidence.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const STAGE_ENVELOPE_SCHEMA_VERSION: &str = "franken-engine.stage-envelope-certificate.v1";
pub const STAGE_ENVELOPE_BEAD_ID: &str = "bd-1lsy.7.11.1";
pub const VIOLATION_REPORT_SCHEMA_VERSION: &str = "franken-engine.stage-violation-report.v1";
pub const ENVELOPE_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.stage-envelope-bundle.v1";

/// Default p99 budget per stage in nanoseconds (10 ms).
pub const DEFAULT_P99_BUDGET_NS: u64 = 10_000_000;
/// Default p999 budget per stage in nanoseconds (50 ms).
pub const DEFAULT_P999_BUDGET_NS: u64 = 50_000_000;
/// Minimum observation count for a statistically valid certificate.
pub const MIN_OBSERVATION_COUNT: u64 = 30;

// ---------------------------------------------------------------------------
// Execution stages
// ---------------------------------------------------------------------------

/// Execution stages whose latency is individually budgeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    /// Source → AST parsing.
    Parse,
    /// AST → IR lowering.
    Lower,
    /// Baseline bytecode compilation.
    CompileBaseline,
    /// Optimized (Cranelift) tier-up compilation.
    CompileOptimized,
    /// Garbage collection pause.
    GcPause,
    /// Module graph resolution and linking.
    ModuleLoad,
    /// Extension sandbox initialization.
    SandboxInit,
    /// Execution of a single dispatch quantum.
    ExecutionQuantum,
    /// Cache lookup and deserialization.
    CacheLookup,
    /// AOT artifact loading.
    AotLoad,
    /// Custom user-defined stage for extensibility.
    Custom,
}

impl fmt::Display for ExecutionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Parse => "parse",
            Self::Lower => "lower",
            Self::CompileBaseline => "compile_baseline",
            Self::CompileOptimized => "compile_optimized",
            Self::GcPause => "gc_pause",
            Self::ModuleLoad => "module_load",
            Self::SandboxInit => "sandbox_init",
            Self::ExecutionQuantum => "execution_quantum",
            Self::CacheLookup => "cache_lookup",
            Self::AotLoad => "aot_load",
            Self::Custom => "custom",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Latency percentile
// ---------------------------------------------------------------------------

/// Percentile tiers tracked for latency envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyPercentile {
    /// Median (50th percentile).
    P50,
    /// 95th percentile.
    P95,
    /// 99th percentile.
    P99,
    /// 99.9th percentile.
    P999,
}

impl LatencyPercentile {
    /// Return the percentile rank as a millionths value (e.g., P99 → 990_000).
    pub fn rank_millionths(self) -> u64 {
        match self {
            Self::P50 => 500_000,
            Self::P95 => 950_000,
            Self::P99 => 990_000,
            Self::P999 => 999_000,
        }
    }
}

impl fmt::Display for LatencyPercentile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::P50 => "p50",
            Self::P95 => "p95",
            Self::P99 => "p99",
            Self::P999 => "p999",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Stage latency envelope
// ---------------------------------------------------------------------------

/// Declared latency envelope for a single execution stage.
///
/// The envelope specifies the maximum acceptable latency at each
/// percentile tier.  Values are in nanoseconds for direct
/// comparison with runtime telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLatencyEnvelope {
    /// Which stage this envelope covers.
    pub stage: ExecutionStage,
    /// Optional label for custom stages.
    pub stage_label: Option<String>,
    /// p50 budget in nanoseconds.
    pub p50_budget_ns: u64,
    /// p95 budget in nanoseconds.
    pub p95_budget_ns: u64,
    /// p99 budget in nanoseconds.
    pub p99_budget_ns: u64,
    /// p999 budget in nanoseconds.
    pub p999_budget_ns: u64,
    /// Fraction of the global tail budget this stage may consume (millionths).
    /// 1_000_000 = 100% of the global budget.
    pub budget_share_millionths: u64,
}

impl StageLatencyEnvelope {
    /// Create a default envelope for a standard stage.
    pub fn default_for_stage(stage: ExecutionStage) -> Self {
        let (p50, p95, p99, p999, share) = match stage {
            ExecutionStage::Parse => (
                500_000,    // 500 µs
                2_000_000,  // 2 ms
                5_000_000,  // 5 ms
                15_000_000, // 15 ms
                150_000,    // 15%
            ),
            ExecutionStage::Lower => (
                200_000,    // 200 µs
                1_000_000,  // 1 ms
                3_000_000,  // 3 ms
                10_000_000, // 10 ms
                100_000,    // 10%
            ),
            ExecutionStage::CompileBaseline => (
                300_000, 1_500_000, 4_000_000, 12_000_000, 120_000, // 12%
            ),
            ExecutionStage::CompileOptimized => (
                1_000_000,  // 1 ms
                5_000_000,  // 5 ms
                15_000_000, // 15 ms
                50_000_000, // 50 ms
                200_000,    // 20%
            ),
            ExecutionStage::GcPause => (
                500_000, 2_000_000, 10_000_000, 30_000_000, 150_000, // 15%
            ),
            ExecutionStage::ModuleLoad => (
                100_000, 500_000, 2_000_000, 8_000_000, 80_000, // 8%
            ),
            ExecutionStage::SandboxInit => (
                200_000, 1_000_000, 3_000_000, 10_000_000, 80_000, // 8%
            ),
            ExecutionStage::ExecutionQuantum => (
                100_000, 500_000, 1_000_000, 5_000_000, 50_000, // 5%
            ),
            ExecutionStage::CacheLookup => (
                50_000, 200_000, 500_000, 2_000_000, 30_000, // 3%
            ),
            ExecutionStage::AotLoad => (
                100_000, 500_000, 2_000_000, 8_000_000, 70_000, // 7%
            ),
            ExecutionStage::Custom => (
                1_000_000,
                5_000_000,
                DEFAULT_P99_BUDGET_NS,
                DEFAULT_P999_BUDGET_NS,
                100_000, // 10%
            ),
        };

        Self {
            stage,
            stage_label: None,
            p50_budget_ns: p50,
            p95_budget_ns: p95,
            p99_budget_ns: p99,
            p999_budget_ns: p999,
            budget_share_millionths: share,
        }
    }
}

// ---------------------------------------------------------------------------
// Observed stage latency
// ---------------------------------------------------------------------------

/// Observed percentile latencies for a single stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLatencyObservation {
    /// Which stage was observed.
    pub stage: ExecutionStage,
    /// Optional label for custom stages.
    pub stage_label: Option<String>,
    /// Number of observations in this measurement window.
    pub observation_count: u64,
    /// Observed p50 in nanoseconds.
    pub p50_ns: u64,
    /// Observed p95 in nanoseconds.
    pub p95_ns: u64,
    /// Observed p99 in nanoseconds.
    pub p99_ns: u64,
    /// Observed p999 in nanoseconds.
    pub p999_ns: u64,
    /// Epoch at which these observations were collected.
    pub observed_epoch: u64,
}

// ---------------------------------------------------------------------------
// Envelope compliance verdict
// ---------------------------------------------------------------------------

/// Verdict on whether a stage's observed latency complies with its envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeVerdict {
    /// All percentiles are within their budgets.
    Compliant,
    /// One or more percentiles are within 20% of their budget (early warning).
    NearLimit,
    /// One or more percentiles exceed their budget.
    Violated,
    /// Insufficient observations for a valid determination.
    InsufficientData,
}

impl fmt::Display for EnvelopeVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Compliant => "compliant",
            Self::NearLimit => "near_limit",
            Self::Violated => "violated",
            Self::InsufficientData => "insufficient_data",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Stage-envelope certificate
// ---------------------------------------------------------------------------

/// A certificate proving that a stage's latency is (or is not) within its
/// declared envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageEnvelopeCertificate {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Unique certificate identifier.
    pub certificate_id: String,
    /// The stage being certified.
    pub stage: ExecutionStage,
    /// Optional custom stage label.
    pub stage_label: Option<String>,
    /// The declared envelope.
    pub envelope: StageLatencyEnvelope,
    /// The observed latency.
    pub observation: StageLatencyObservation,
    /// Compliance verdict.
    pub verdict: EnvelopeVerdict,
    /// Per-percentile violation details (empty if compliant).
    pub violations: Vec<PercentileViolation>,
    /// Epoch at which the certificate was issued.
    pub issued_epoch: u64,
    /// Evidence artifact IDs supporting this certificate.
    pub evidence_ids: Vec<String>,
}

/// A single percentile budget violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PercentileViolation {
    /// Which percentile was violated.
    pub percentile: LatencyPercentile,
    /// Observed value in nanoseconds.
    pub observed_ns: u64,
    /// Budget threshold in nanoseconds.
    pub budget_ns: u64,
    /// Overshoot in nanoseconds.
    pub overshoot_ns: u64,
    /// Overshoot as a fraction of budget (millionths).
    pub overshoot_fraction_millionths: u64,
}

// ---------------------------------------------------------------------------
// Envelope bundle (for a full pipeline)
// ---------------------------------------------------------------------------

/// Bundle of all stage-envelope certificates for a complete execution pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeBundle {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// All per-stage certificates.
    pub certificates: Vec<StageEnvelopeCertificate>,
    /// Overall verdict (worst-case across all stages).
    pub overall_verdict: EnvelopeVerdict,
    /// Epoch at which the bundle was computed.
    pub bundle_epoch: u64,
    /// Number of stages.
    pub stage_count: usize,
    /// Number of compliant stages.
    pub compliant_count: usize,
    /// Number of near-limit stages.
    pub near_limit_count: usize,
    /// Number of violated stages.
    pub violated_count: usize,
    /// Number with insufficient data.
    pub insufficient_data_count: usize,
    /// Total budget share consumed (millionths; should be ≤ 1_000_000).
    pub total_budget_share_millionths: u64,
}

// ---------------------------------------------------------------------------
// Violation report
// ---------------------------------------------------------------------------

/// Detailed violation report for a single stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Report identifier.
    pub report_id: String,
    /// The stage with the violation.
    pub stage: ExecutionStage,
    /// All percentile violations for this stage.
    pub violations: Vec<PercentileViolation>,
    /// Recommended remediation.
    pub remediation: RemediationAction,
    /// Severity of the worst violation.
    pub severity: ViolationSeverity,
    /// Epoch at which the report was generated.
    pub reported_epoch: u64,
}

/// Severity of a latency violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationSeverity {
    /// Less than 10% overshoot.
    Minor,
    /// 10–50% overshoot.
    Moderate,
    /// Over 50% overshoot.
    Severe,
    /// Over 200% overshoot — catastrophic tail.
    Catastrophic,
}

impl fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Minor => "minor",
            Self::Moderate => "moderate",
            Self::Severe => "severe",
            Self::Catastrophic => "catastrophic",
        };
        write!(f, "{label}")
    }
}

/// Recommended remediation for a latency violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    /// Continue monitoring; violation is minor.
    Monitor,
    /// Increase the budget allocation for this stage.
    IncreaseBudget,
    /// Reduce the workload or complexity hitting this stage.
    ReduceWorkload,
    /// Defer this stage to a background thread.
    DeferToBackground,
    /// Split this stage into smaller sub-stages.
    SplitStage,
    /// Fall back to a simpler/cheaper implementation.
    Downgrade,
}

impl fmt::Display for RemediationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Monitor => "monitor",
            Self::IncreaseBudget => "increase_budget",
            Self::ReduceWorkload => "reduce_workload",
            Self::DeferToBackground => "defer_to_background",
            Self::SplitStage => "split_stage",
            Self::Downgrade => "downgrade",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Check a single stage observation against its envelope and issue a certificate.
pub fn issue_stage_certificate(
    envelope: &StageLatencyEnvelope,
    observation: &StageLatencyObservation,
    certificate_id: &str,
    epoch: u64,
    evidence_ids: Vec<String>,
) -> StageEnvelopeCertificate {
    if observation.observation_count < MIN_OBSERVATION_COUNT {
        return StageEnvelopeCertificate {
            schema_version: STAGE_ENVELOPE_SCHEMA_VERSION.to_string(),
            bead_id: STAGE_ENVELOPE_BEAD_ID.to_string(),
            certificate_id: certificate_id.to_string(),
            stage: envelope.stage,
            stage_label: envelope.stage_label.clone(),
            envelope: envelope.clone(),
            observation: observation.clone(),
            verdict: EnvelopeVerdict::InsufficientData,
            violations: Vec::new(),
            issued_epoch: epoch,
            evidence_ids,
        };
    }

    let mut violations = Vec::new();

    check_percentile(
        LatencyPercentile::P50,
        observation.p50_ns,
        envelope.p50_budget_ns,
        &mut violations,
    );
    check_percentile(
        LatencyPercentile::P95,
        observation.p95_ns,
        envelope.p95_budget_ns,
        &mut violations,
    );
    check_percentile(
        LatencyPercentile::P99,
        observation.p99_ns,
        envelope.p99_budget_ns,
        &mut violations,
    );
    check_percentile(
        LatencyPercentile::P999,
        observation.p999_ns,
        envelope.p999_budget_ns,
        &mut violations,
    );

    let verdict = if !violations.is_empty() {
        EnvelopeVerdict::Violated
    } else if is_near_limit(observation, envelope) {
        EnvelopeVerdict::NearLimit
    } else {
        EnvelopeVerdict::Compliant
    };

    StageEnvelopeCertificate {
        schema_version: STAGE_ENVELOPE_SCHEMA_VERSION.to_string(),
        bead_id: STAGE_ENVELOPE_BEAD_ID.to_string(),
        certificate_id: certificate_id.to_string(),
        stage: envelope.stage,
        stage_label: envelope.stage_label.clone(),
        envelope: envelope.clone(),
        observation: observation.clone(),
        verdict,
        violations,
        issued_epoch: epoch,
        evidence_ids,
    }
}

/// Build an envelope bundle by certifying all stages in a pipeline.
pub fn build_envelope_bundle(
    envelopes: &[StageLatencyEnvelope],
    observations: &[StageLatencyObservation],
    epoch: u64,
) -> EnvelopeBundle {
    let mut certificates = Vec::new();
    let mut cert_seq = 0u64;

    // Match observations to envelopes by stage
    let obs_map: BTreeMap<ExecutionStage, &StageLatencyObservation> =
        observations.iter().map(|o| (o.stage, o)).collect();

    for envelope in envelopes {
        cert_seq += 1;
        let cert_id = format!("stage-cert-{cert_seq}");

        if let Some(obs) = obs_map.get(&envelope.stage) {
            let cert = issue_stage_certificate(envelope, obs, &cert_id, epoch, Vec::new());
            certificates.push(cert);
        }
        // If no observation for this envelope, skip (stage wasn't exercised)
    }

    let compliant_count = certificates
        .iter()
        .filter(|c| c.verdict == EnvelopeVerdict::Compliant)
        .count();
    let near_limit_count = certificates
        .iter()
        .filter(|c| c.verdict == EnvelopeVerdict::NearLimit)
        .count();
    let violated_count = certificates
        .iter()
        .filter(|c| c.verdict == EnvelopeVerdict::Violated)
        .count();
    let insufficient_data_count = certificates
        .iter()
        .filter(|c| c.verdict == EnvelopeVerdict::InsufficientData)
        .count();

    let overall_verdict = if violated_count > 0 {
        EnvelopeVerdict::Violated
    } else if near_limit_count > 0 {
        EnvelopeVerdict::NearLimit
    } else if insufficient_data_count > 0 && compliant_count == 0 {
        EnvelopeVerdict::InsufficientData
    } else {
        EnvelopeVerdict::Compliant
    };

    let total_budget_share_millionths: u64 =
        envelopes.iter().map(|e| e.budget_share_millionths).sum();

    EnvelopeBundle {
        schema_version: ENVELOPE_BUNDLE_SCHEMA_VERSION.to_string(),
        bead_id: STAGE_ENVELOPE_BEAD_ID.to_string(),
        certificates,
        overall_verdict,
        bundle_epoch: epoch,
        stage_count: cert_seq as usize,
        compliant_count,
        near_limit_count,
        violated_count,
        insufficient_data_count,
        total_budget_share_millionths,
    }
}

/// Generate a violation report for a stage that exceeded its envelope.
pub fn generate_violation_report(
    certificate: &StageEnvelopeCertificate,
    report_id: &str,
) -> Option<ViolationReport> {
    if certificate.violations.is_empty() {
        return None;
    }

    let worst_fraction = certificate
        .violations
        .iter()
        .map(|v| v.overshoot_fraction_millionths)
        .max()
        .unwrap_or(0);

    let severity = classify_severity(worst_fraction);
    let remediation = recommend_remediation(certificate.stage, &severity);

    Some(ViolationReport {
        schema_version: VIOLATION_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: STAGE_ENVELOPE_BEAD_ID.to_string(),
        report_id: report_id.to_string(),
        stage: certificate.stage,
        violations: certificate.violations.clone(),
        remediation,
        severity,
        reported_epoch: certificate.issued_epoch,
    })
}

/// Render a human-readable summary of an envelope bundle.
pub fn render_envelope_summary(bundle: &EnvelopeBundle) -> String {
    let mut lines = vec![
        format!("schema_version: {}", bundle.schema_version),
        format!("bundle_epoch: {}", bundle.bundle_epoch),
        format!("stage_count: {}", bundle.stage_count),
        format!("overall_verdict: {}", bundle.overall_verdict),
        format!("compliant: {}", bundle.compliant_count),
        format!("near_limit: {}", bundle.near_limit_count),
        format!("violated: {}", bundle.violated_count),
        format!("insufficient_data: {}", bundle.insufficient_data_count),
        format!(
            "total_budget_share: {}%",
            bundle.total_budget_share_millionths / 10_000
        ),
    ];

    if bundle.violated_count > 0 {
        lines.push("violated_stages:".to_string());
        for cert in &bundle.certificates {
            if cert.verdict == EnvelopeVerdict::Violated {
                lines.push(format!(
                    "  {}: {} violations",
                    cert.stage,
                    cert.violations.len()
                ));
            }
        }
    }

    lines.join("\n")
}

/// Render a human-readable summary of a violation report.
pub fn render_violation_summary(report: &ViolationReport) -> String {
    let mut lines = vec![
        format!("schema_version: {}", report.schema_version),
        format!("stage: {}", report.stage),
        format!("severity: {}", report.severity),
        format!("remediation: {}", report.remediation),
        format!("violations: {}", report.violations.len()),
    ];

    for v in &report.violations {
        lines.push(format!(
            "  {}: observed={} ns, budget={} ns, overshoot={}%",
            v.percentile,
            v.observed_ns,
            v.budget_ns,
            v.overshoot_fraction_millionths / 10_000,
        ));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn check_percentile(
    percentile: LatencyPercentile,
    observed_ns: u64,
    budget_ns: u64,
    violations: &mut Vec<PercentileViolation>,
) {
    if observed_ns > budget_ns {
        let overshoot_ns = observed_ns - budget_ns;
        let overshoot_fraction = (overshoot_ns * 1_000_000)
            .checked_div(budget_ns)
            .unwrap_or(1_000_000); // 100% overshoot if budget is zero
        violations.push(PercentileViolation {
            percentile,
            observed_ns,
            budget_ns,
            overshoot_ns,
            overshoot_fraction_millionths: overshoot_fraction,
        });
    }
}

fn is_near_limit(observation: &StageLatencyObservation, envelope: &StageLatencyEnvelope) -> bool {
    // "Near limit" = within 20% of budget (i.e., observed > 80% of budget)
    let threshold_fraction = 800_000u64; // 80% in millionths
    is_near(
        observation.p50_ns,
        envelope.p50_budget_ns,
        threshold_fraction,
    ) || is_near(
        observation.p95_ns,
        envelope.p95_budget_ns,
        threshold_fraction,
    ) || is_near(
        observation.p99_ns,
        envelope.p99_budget_ns,
        threshold_fraction,
    ) || is_near(
        observation.p999_ns,
        envelope.p999_budget_ns,
        threshold_fraction,
    )
}

fn is_near(observed: u64, budget: u64, threshold_fraction_millionths: u64) -> bool {
    if budget == 0 {
        return observed > 0;
    }
    let threshold = budget * threshold_fraction_millionths / 1_000_000;
    observed >= threshold && observed <= budget
}

fn classify_severity(overshoot_fraction_millionths: u64) -> ViolationSeverity {
    if overshoot_fraction_millionths > 2_000_000 {
        ViolationSeverity::Catastrophic // > 200%
    } else if overshoot_fraction_millionths > 500_000 {
        ViolationSeverity::Severe // > 50%
    } else if overshoot_fraction_millionths > 100_000 {
        ViolationSeverity::Moderate // > 10%
    } else {
        ViolationSeverity::Minor // ≤ 10%
    }
}

fn recommend_remediation(stage: ExecutionStage, severity: &ViolationSeverity) -> RemediationAction {
    match (stage, severity) {
        (_, ViolationSeverity::Catastrophic) => RemediationAction::Downgrade,
        (ExecutionStage::GcPause, ViolationSeverity::Severe) => RemediationAction::SplitStage,
        (ExecutionStage::CompileOptimized, _) => RemediationAction::DeferToBackground,
        (ExecutionStage::Parse | ExecutionStage::Lower, ViolationSeverity::Severe) => {
            RemediationAction::ReduceWorkload
        }
        (_, ViolationSeverity::Severe) => RemediationAction::IncreaseBudget,
        (_, ViolationSeverity::Moderate) => RemediationAction::IncreaseBudget,
        (_, ViolationSeverity::Minor) => RemediationAction::Monitor,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_envelope(stage: ExecutionStage) -> StageLatencyEnvelope {
        StageLatencyEnvelope::default_for_stage(stage)
    }

    fn compliant_observation(stage: ExecutionStage) -> StageLatencyObservation {
        let env = default_envelope(stage);
        StageLatencyObservation {
            stage,
            stage_label: None,
            observation_count: 100,
            p50_ns: env.p50_budget_ns / 2,
            p95_ns: env.p95_budget_ns / 2,
            p99_ns: env.p99_budget_ns / 2,
            p999_ns: env.p999_budget_ns / 2,
            observed_epoch: 0,
        }
    }

    fn violating_observation(stage: ExecutionStage) -> StageLatencyObservation {
        let env = default_envelope(stage);
        StageLatencyObservation {
            stage,
            stage_label: None,
            observation_count: 100,
            p50_ns: env.p50_budget_ns + 1,
            p95_ns: env.p95_budget_ns + 1,
            p99_ns: env.p99_budget_ns * 2,
            p999_ns: env.p999_budget_ns * 3,
            observed_epoch: 0,
        }
    }

    fn near_limit_observation(stage: ExecutionStage) -> StageLatencyObservation {
        let env = default_envelope(stage);
        StageLatencyObservation {
            stage,
            stage_label: None,
            observation_count: 100,
            p50_ns: env.p50_budget_ns * 85 / 100,
            p95_ns: env.p95_budget_ns * 85 / 100,
            p99_ns: env.p99_budget_ns * 85 / 100,
            p999_ns: env.p999_budget_ns * 85 / 100,
            observed_epoch: 0,
        }
    }

    // -- ExecutionStage --

    #[test]
    fn stage_display_all_variants() {
        let stages = [
            (ExecutionStage::Parse, "parse"),
            (ExecutionStage::Lower, "lower"),
            (ExecutionStage::CompileBaseline, "compile_baseline"),
            (ExecutionStage::CompileOptimized, "compile_optimized"),
            (ExecutionStage::GcPause, "gc_pause"),
            (ExecutionStage::ModuleLoad, "module_load"),
            (ExecutionStage::SandboxInit, "sandbox_init"),
            (ExecutionStage::ExecutionQuantum, "execution_quantum"),
            (ExecutionStage::CacheLookup, "cache_lookup"),
            (ExecutionStage::AotLoad, "aot_load"),
            (ExecutionStage::Custom, "custom"),
        ];
        for (stage, expected) in &stages {
            assert_eq!(stage.to_string(), *expected);
        }
    }

    #[test]
    fn stage_serde_round_trip_all() {
        let stages = [
            ExecutionStage::Parse,
            ExecutionStage::Lower,
            ExecutionStage::CompileBaseline,
            ExecutionStage::CompileOptimized,
            ExecutionStage::GcPause,
            ExecutionStage::ModuleLoad,
            ExecutionStage::SandboxInit,
            ExecutionStage::ExecutionQuantum,
            ExecutionStage::CacheLookup,
            ExecutionStage::AotLoad,
            ExecutionStage::Custom,
        ];
        for stage in &stages {
            let json = serde_json::to_string(stage).expect("serialize");
            let deser: ExecutionStage = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*stage, deser);
        }
    }

    // -- LatencyPercentile --

    #[test]
    fn percentile_display() {
        assert_eq!(LatencyPercentile::P50.to_string(), "p50");
        assert_eq!(LatencyPercentile::P95.to_string(), "p95");
        assert_eq!(LatencyPercentile::P99.to_string(), "p99");
        assert_eq!(LatencyPercentile::P999.to_string(), "p999");
    }

    #[test]
    fn percentile_rank_millionths() {
        assert_eq!(LatencyPercentile::P50.rank_millionths(), 500_000);
        assert_eq!(LatencyPercentile::P99.rank_millionths(), 990_000);
        assert_eq!(LatencyPercentile::P999.rank_millionths(), 999_000);
    }

    // -- EnvelopeVerdict --

    #[test]
    fn verdict_display() {
        assert_eq!(EnvelopeVerdict::Compliant.to_string(), "compliant");
        assert_eq!(EnvelopeVerdict::NearLimit.to_string(), "near_limit");
        assert_eq!(EnvelopeVerdict::Violated.to_string(), "violated");
        assert_eq!(
            EnvelopeVerdict::InsufficientData.to_string(),
            "insufficient_data"
        );
    }

    #[test]
    fn verdict_serde_round_trip() {
        for v in &[
            EnvelopeVerdict::Compliant,
            EnvelopeVerdict::NearLimit,
            EnvelopeVerdict::Violated,
            EnvelopeVerdict::InsufficientData,
        ] {
            let json = serde_json::to_string(v).expect("serialize");
            let deser: EnvelopeVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, deser);
        }
    }

    // -- ViolationSeverity --

    #[test]
    fn severity_display() {
        assert_eq!(ViolationSeverity::Minor.to_string(), "minor");
        assert_eq!(ViolationSeverity::Moderate.to_string(), "moderate");
        assert_eq!(ViolationSeverity::Severe.to_string(), "severe");
        assert_eq!(ViolationSeverity::Catastrophic.to_string(), "catastrophic");
    }

    #[test]
    fn severity_ordering() {
        assert!(ViolationSeverity::Minor < ViolationSeverity::Moderate);
        assert!(ViolationSeverity::Moderate < ViolationSeverity::Severe);
        assert!(ViolationSeverity::Severe < ViolationSeverity::Catastrophic);
    }

    // -- RemediationAction --

    #[test]
    fn remediation_display() {
        assert_eq!(RemediationAction::Monitor.to_string(), "monitor");
        assert_eq!(
            RemediationAction::DeferToBackground.to_string(),
            "defer_to_background"
        );
        assert_eq!(RemediationAction::Downgrade.to_string(), "downgrade");
    }

    // -- issue_stage_certificate --

    #[test]
    fn certificate_compliant() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = compliant_observation(ExecutionStage::Parse);
        let cert = issue_stage_certificate(&env, &obs, "cert-1", 0, vec![]);
        assert_eq!(cert.verdict, EnvelopeVerdict::Compliant);
        assert!(cert.violations.is_empty());
    }

    #[test]
    fn certificate_violated() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = violating_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "cert-v", 0, vec![]);
        assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
        assert!(!cert.violations.is_empty());
    }

    #[test]
    fn certificate_near_limit() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = near_limit_observation(ExecutionStage::Parse);
        let cert = issue_stage_certificate(&env, &obs, "cert-n", 0, vec![]);
        assert_eq!(cert.verdict, EnvelopeVerdict::NearLimit);
    }

    #[test]
    fn certificate_insufficient_data() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = StageLatencyObservation {
            stage: ExecutionStage::Parse,
            stage_label: None,
            observation_count: 5, // below MIN_OBSERVATION_COUNT
            p50_ns: 100_000,
            p95_ns: 200_000,
            p99_ns: 300_000,
            p999_ns: 400_000,
            observed_epoch: 0,
        };
        let cert = issue_stage_certificate(&env, &obs, "cert-id", 0, vec![]);
        assert_eq!(cert.verdict, EnvelopeVerdict::InsufficientData);
    }

    #[test]
    fn certificate_serde_round_trip() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = compliant_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "serde-cert", 42, vec!["ev-1".to_string()]);
        let json = serde_json::to_string(&cert).expect("serialize");
        let deser: StageEnvelopeCertificate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cert, deser);
    }

    // -- build_envelope_bundle --

    #[test]
    fn bundle_all_compliant() {
        let stages = [
            ExecutionStage::Parse,
            ExecutionStage::Lower,
            ExecutionStage::GcPause,
        ];
        let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
        let observations: Vec<_> = stages.iter().map(|s| compliant_observation(*s)).collect();
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
        assert_eq!(bundle.stage_count, 3);
        assert_eq!(bundle.compliant_count, 3);
        assert_eq!(bundle.violated_count, 0);
    }

    #[test]
    fn bundle_one_violated() {
        let envelopes = vec![
            default_envelope(ExecutionStage::Parse),
            default_envelope(ExecutionStage::GcPause),
        ];
        let observations = vec![
            compliant_observation(ExecutionStage::Parse),
            violating_observation(ExecutionStage::GcPause),
        ];
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Violated);
        assert_eq!(bundle.violated_count, 1);
    }

    #[test]
    fn bundle_empty() {
        let bundle = build_envelope_bundle(&[], &[], 0);
        assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
        assert_eq!(bundle.stage_count, 0);
    }

    #[test]
    fn bundle_serde_round_trip() {
        let envelopes = vec![default_envelope(ExecutionStage::Parse)];
        let observations = vec![compliant_observation(ExecutionStage::Parse)];
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let deser: EnvelopeBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(bundle, deser);
    }

    // -- generate_violation_report --

    #[test]
    fn violation_report_generated_for_violated_cert() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = violating_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "v-cert", 0, vec![]);
        let report = generate_violation_report(&cert, "rpt-1");
        assert!(report.is_some());
        let rpt = report.unwrap();
        assert!(!rpt.violations.is_empty());
        assert_eq!(rpt.stage, ExecutionStage::GcPause);
    }

    #[test]
    fn violation_report_none_for_compliant() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = compliant_observation(ExecutionStage::Parse);
        let cert = issue_stage_certificate(&env, &obs, "c-cert", 0, vec![]);
        assert!(generate_violation_report(&cert, "rpt-none").is_none());
    }

    #[test]
    fn violation_report_serde_round_trip() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = violating_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "v-cert", 0, vec![]);
        let report = generate_violation_report(&cert, "rpt-serde").unwrap();
        let json = serde_json::to_string(&report).expect("serialize");
        let deser: ViolationReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, deser);
    }

    // -- Summary rendering --

    #[test]
    fn envelope_summary_compliant() {
        let envelopes = vec![default_envelope(ExecutionStage::Parse)];
        let observations = vec![compliant_observation(ExecutionStage::Parse)];
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        let summary = render_envelope_summary(&bundle);
        assert!(summary.contains("overall_verdict: compliant"));
        assert!(summary.contains("stage_count: 1"));
    }

    #[test]
    fn violation_summary_shows_details() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = violating_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "v", 0, vec![]);
        let report = generate_violation_report(&cert, "rpt").unwrap();
        let summary = render_violation_summary(&report);
        assert!(summary.contains("stage: gc_pause"));
        assert!(summary.contains("severity:"));
        assert!(summary.contains("remediation:"));
    }

    // -- classify_severity --

    #[test]
    fn severity_classification() {
        assert_eq!(classify_severity(50_000), ViolationSeverity::Minor);
        assert_eq!(classify_severity(200_000), ViolationSeverity::Moderate);
        assert_eq!(classify_severity(800_000), ViolationSeverity::Severe);
        assert_eq!(
            classify_severity(3_000_000),
            ViolationSeverity::Catastrophic
        );
    }

    // -- Default envelopes --

    #[test]
    fn default_envelope_budget_monotonic() {
        // p50 < p95 < p99 < p999 for all stages
        let stages = [
            ExecutionStage::Parse,
            ExecutionStage::Lower,
            ExecutionStage::CompileBaseline,
            ExecutionStage::CompileOptimized,
            ExecutionStage::GcPause,
            ExecutionStage::ModuleLoad,
            ExecutionStage::SandboxInit,
            ExecutionStage::ExecutionQuantum,
            ExecutionStage::CacheLookup,
            ExecutionStage::AotLoad,
            ExecutionStage::Custom,
        ];
        for stage in &stages {
            let env = default_envelope(*stage);
            assert!(
                env.p50_budget_ns <= env.p95_budget_ns,
                "p50 > p95 for {stage}"
            );
            assert!(
                env.p95_budget_ns <= env.p99_budget_ns,
                "p95 > p99 for {stage}"
            );
            assert!(
                env.p99_budget_ns <= env.p999_budget_ns,
                "p99 > p999 for {stage}"
            );
        }
    }

    #[test]
    fn default_envelope_nonzero_budget() {
        for stage in &[
            ExecutionStage::Parse,
            ExecutionStage::GcPause,
            ExecutionStage::CompileOptimized,
        ] {
            let env = default_envelope(*stage);
            assert!(env.p50_budget_ns > 0);
            assert!(env.budget_share_millionths > 0);
        }
    }

    #[test]
    fn envelope_serde_round_trip() {
        let env = default_envelope(ExecutionStage::Parse);
        let json = serde_json::to_string(&env).expect("serialize");
        let deser: StageLatencyEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, deser);
    }

    // -- PercentileViolation --

    #[test]
    fn violation_overshoot_calculation() {
        let mut violations = Vec::new();
        check_percentile(
            LatencyPercentile::P99,
            20_000_000,
            10_000_000,
            &mut violations,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].overshoot_ns, 10_000_000);
        assert_eq!(violations[0].overshoot_fraction_millionths, 1_000_000); // 100%
    }

    #[test]
    fn no_violation_when_within_budget() {
        let mut violations = Vec::new();
        check_percentile(
            LatencyPercentile::P99,
            5_000_000,
            10_000_000,
            &mut violations,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn no_violation_at_exact_budget() {
        let mut violations = Vec::new();
        check_percentile(
            LatencyPercentile::P99,
            10_000_000,
            10_000_000,
            &mut violations,
        );
        assert!(violations.is_empty());
    }

    // -- Remediation recommendations --

    #[test]
    fn catastrophic_always_recommends_downgrade() {
        assert_eq!(
            recommend_remediation(ExecutionStage::Parse, &ViolationSeverity::Catastrophic),
            RemediationAction::Downgrade
        );
        assert_eq!(
            recommend_remediation(ExecutionStage::GcPause, &ViolationSeverity::Catastrophic),
            RemediationAction::Downgrade
        );
    }

    #[test]
    fn compile_optimized_recommends_defer() {
        assert_eq!(
            recommend_remediation(
                ExecutionStage::CompileOptimized,
                &ViolationSeverity::Moderate
            ),
            RemediationAction::DeferToBackground
        );
    }

    #[test]
    fn gc_severe_recommends_split() {
        assert_eq!(
            recommend_remediation(ExecutionStage::GcPause, &ViolationSeverity::Severe),
            RemediationAction::SplitStage
        );
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn percentile_serde_all() {
        for p in [
            LatencyPercentile::P50,
            LatencyPercentile::P95,
            LatencyPercentile::P99,
            LatencyPercentile::P999,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: LatencyPercentile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn percentile_rank_ordering() {
        assert!(
            LatencyPercentile::P50.rank_millionths() < LatencyPercentile::P95.rank_millionths()
        );
        assert!(
            LatencyPercentile::P95.rank_millionths() < LatencyPercentile::P99.rank_millionths()
        );
        assert!(
            LatencyPercentile::P99.rank_millionths() < LatencyPercentile::P999.rank_millionths()
        );
    }

    #[test]
    fn severity_serde_all() {
        for s in [
            ViolationSeverity::Minor,
            ViolationSeverity::Moderate,
            ViolationSeverity::Severe,
            ViolationSeverity::Catastrophic,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn remediation_serde_all() {
        for r in [
            RemediationAction::Monitor,
            RemediationAction::IncreaseBudget,
            RemediationAction::ReduceWorkload,
            RemediationAction::DeferToBackground,
            RemediationAction::SplitStage,
            RemediationAction::Downgrade,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: RemediationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn certificate_schema_version_correct() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = compliant_observation(ExecutionStage::Parse);
        let cert = issue_stage_certificate(&env, &obs, "cert-v", 0, vec![]);
        assert_eq!(cert.schema_version, STAGE_ENVELOPE_SCHEMA_VERSION);
        assert_eq!(cert.bead_id, STAGE_ENVELOPE_BEAD_ID);
    }

    #[test]
    fn certificate_preserves_evidence_ids() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = compliant_observation(ExecutionStage::Parse);
        let ids = vec!["ev-1".to_string(), "ev-2".to_string()];
        let cert = issue_stage_certificate(&env, &obs, "cert-ev", 0, ids.clone());
        assert_eq!(cert.evidence_ids, ids);
    }

    #[test]
    fn certificate_preserves_epoch() {
        let env = default_envelope(ExecutionStage::Parse);
        let obs = compliant_observation(ExecutionStage::Parse);
        let cert = issue_stage_certificate(&env, &obs, "cert-ep", 42, vec![]);
        assert_eq!(cert.issued_epoch, 42);
    }

    #[test]
    fn violation_overshoot_zero_budget() {
        let mut violations = Vec::new();
        check_percentile(LatencyPercentile::P99, 1000, 0, &mut violations);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].overshoot_ns, 1000);
    }

    #[test]
    fn bundle_near_limit_verdict() {
        let envelopes = vec![default_envelope(ExecutionStage::Parse)];
        let observations = vec![near_limit_observation(ExecutionStage::Parse)];
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        assert_eq!(bundle.overall_verdict, EnvelopeVerdict::NearLimit);
        assert_eq!(bundle.near_limit_count, 1);
    }

    #[test]
    fn bundle_budget_share_sums() {
        let stages = [
            ExecutionStage::Parse,
            ExecutionStage::Lower,
            ExecutionStage::GcPause,
        ];
        let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
        let observations: Vec<_> = stages.iter().map(|s| compliant_observation(*s)).collect();
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        let expected_sum: u64 = envelopes.iter().map(|e| e.budget_share_millionths).sum();
        assert_eq!(bundle.total_budget_share_millionths, expected_sum);
    }

    #[test]
    fn bundle_mixed_verdicts() {
        let envelopes = vec![
            default_envelope(ExecutionStage::Parse),
            default_envelope(ExecutionStage::Lower),
            default_envelope(ExecutionStage::GcPause),
        ];
        let observations = vec![
            compliant_observation(ExecutionStage::Parse),
            near_limit_observation(ExecutionStage::Lower),
            violating_observation(ExecutionStage::GcPause),
        ];
        let bundle = build_envelope_bundle(&envelopes, &observations, 0);
        assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Violated);
        assert_eq!(bundle.compliant_count, 1);
        assert_eq!(bundle.near_limit_count, 1);
        assert_eq!(bundle.violated_count, 1);
    }

    #[test]
    fn default_envelope_custom_stage_uses_default_constants() {
        let env = default_envelope(ExecutionStage::Custom);
        assert_eq!(env.p99_budget_ns, DEFAULT_P99_BUDGET_NS);
        assert_eq!(env.p999_budget_ns, DEFAULT_P999_BUDGET_NS);
    }

    #[test]
    fn default_envelope_stage_label_is_none() {
        for stage in [
            ExecutionStage::Parse,
            ExecutionStage::GcPause,
            ExecutionStage::Custom,
        ] {
            let env = default_envelope(stage);
            assert!(env.stage_label.is_none());
        }
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!STAGE_ENVELOPE_SCHEMA_VERSION.is_empty());
        assert!(!STAGE_ENVELOPE_BEAD_ID.is_empty());
        assert!(!VIOLATION_REPORT_SCHEMA_VERSION.is_empty());
        assert!(!ENVELOPE_BUNDLE_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn min_observation_count_positive() {
        let min_obs = MIN_OBSERVATION_COUNT;
        assert!(min_obs > 0);
    }

    #[test]
    fn default_budgets_positive() {
        let p99 = DEFAULT_P99_BUDGET_NS;
        let p999 = DEFAULT_P999_BUDGET_NS;
        assert!(p99 > 0);
        assert!(p999 > p99);
    }

    #[test]
    fn severity_boundary_values() {
        // Exact boundary: 100_000 = 10% -> Moderate (not Minor)
        assert_eq!(classify_severity(99_999), ViolationSeverity::Minor);
        assert_eq!(classify_severity(100_000), ViolationSeverity::Moderate);
        // Exact boundary: 500_000 = 50% -> Severe
        assert_eq!(classify_severity(499_999), ViolationSeverity::Moderate);
        assert_eq!(classify_severity(500_000), ViolationSeverity::Severe);
    }

    #[test]
    fn percentile_violation_serde() {
        let v = PercentileViolation {
            percentile: LatencyPercentile::P99,
            observed_ns: 20_000_000,
            budget_ns: 10_000_000,
            overshoot_ns: 10_000_000,
            overshoot_fraction_millionths: 1_000_000,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PercentileViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn observation_serde() {
        let obs = compliant_observation(ExecutionStage::Parse);
        let json = serde_json::to_string(&obs).unwrap();
        let back: StageLatencyObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    #[test]
    fn violation_report_schema_version() {
        let env = default_envelope(ExecutionStage::GcPause);
        let obs = violating_observation(ExecutionStage::GcPause);
        let cert = issue_stage_certificate(&env, &obs, "v-cert", 0, vec![]);
        let report = generate_violation_report(&cert, "rpt").unwrap();
        assert_eq!(report.schema_version, VIOLATION_REPORT_SCHEMA_VERSION);
        assert_eq!(report.bead_id, STAGE_ENVELOPE_BEAD_ID);
    }

    #[test]
    fn minor_recommends_monitor() {
        assert_eq!(
            recommend_remediation(ExecutionStage::Parse, &ViolationSeverity::Minor),
            RemediationAction::Monitor
        );
    }

    #[test]
    fn all_stages_default_envelopes_have_positive_share() {
        let stages = [
            ExecutionStage::Parse,
            ExecutionStage::Lower,
            ExecutionStage::CompileBaseline,
            ExecutionStage::CompileOptimized,
            ExecutionStage::GcPause,
            ExecutionStage::ModuleLoad,
            ExecutionStage::SandboxInit,
            ExecutionStage::ExecutionQuantum,
            ExecutionStage::CacheLookup,
            ExecutionStage::AotLoad,
            ExecutionStage::Custom,
        ];
        for stage in stages {
            let env = default_envelope(stage);
            assert!(
                env.budget_share_millionths > 0,
                "stage {stage} has zero budget share"
            );
        }
    }
}
