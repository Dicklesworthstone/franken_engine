//! Performance arm of the differential oracle (E2.T4, bd-fqlfw.2.4).
//!
//! Measures steady-state throughput of the same JS corpus the correctness arm
//! compares and emits raw Node/Bun diagnostic evidence. The report deliberately
//! keeps its denominators degraded while the engine and external lifecycle
//! contracts differ; a lifecycle-symmetric successor is required before
//! FE-CLAIM-010 can use these measurements for promotion.
//!
//! ## Measurement protocol (binding)
//!
//! * One subprocess per (case, external runtime). The subprocess runs a
//!   generated harness: the case source is compiled ONCE via `new Function`
//!   and invoked `warmup_iterations` times (discarded) then
//!   `measured_iterations` times, each timed with `process.hrtime.bigint()`.
//!   Process startup is therefore excluded by construction, and the external
//!   runtime gets full JIT warm-up — a deliberately *conservative* bias in
//!   favour of Node/Bun.
//! * The engine lane prepares immutable IR3 ONCE, then executes that handle on
//!   a fresh `HybridRouter` (and therefore a fresh interpreter core) for every
//!   warm-up and measured iteration. Preparation is timed separately. This
//!   matches the external compile-once boundary while retaining per-execution
//!   runtime isolation. Node/Bun retain a shared realm and JIT state, however,
//!   so this is not full lifecycle parity.
//! * Per-iteration nanosecond timings (warm-up and measured) are retained in
//!   the report and exported as `diffperf.iteration` events so a skeptic can
//!   re-derive every aggregate from raw data.
//!
//! ## Fairness rules (from PLAN sections 7.4–7.5)
//!
//! Identical hardware and corpus for all runtimes, pinned + recorded runtime
//! versions and resolved binary paths, a documented warm-up protocol, a full
//! environment manifest, and geometric-mean aggregation. V3 records the
//! fresh-engine/shared-realm asymmetry as a fairness violation, so its
//! denominators remain DEGRADED rather than publishing a ratio. One additional
//! trap this module checks explicitly: `node` on PATH may be Bun's `node` shim,
//! which would make the "Node" lane silently measure Bun (`node_genuine`).
//!
//! ## Honest outcome
//!
//! Cases are eligible for baseline-specific diagnostic aggregation only when
//! the correctness arm reports structured-value consensus between Node, Bun,
//! and FrankenEngine and the per-invocation observations are stable and equal.
//! The report retains raw samples and per-case ratios, but V3 exposes no
//! publishable aggregate or `meets_3x_floor` verdict while fairness is degraded.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::differential_oracle::{
    DifferentialBackend, DifferentialComparisonMode, DifferentialComparisonVerdict,
    DifferentialHostFacts, DifferentialOracleInput, ExternalRuntimeSpec, VersionProbe,
    capture_external_version, capture_host_facts, current_unix_ns, run_command_with_timeout,
    run_differential_oracle, sha256_hex,
};
use crate::{EngineKind, EvalOutcome, HybridRouter, PreparedTierDispatchPolicy, RouteReason};

pub const DIFFERENTIAL_PERF_SCHEMA_VERSION: &str = "franken-engine.differential-oracle-perf.v3";
pub const TIER_CONTROL_PERF_SCHEMA_VERSION: &str = "franken-engine.tier-control-perf.v1";

/// FE-CLAIM-010's requested ">= 3x throughput" floor in fixed-point
/// millionths (1_000_000 == 1.0x). V3 cannot publish a verdict against it
/// because its execution lifecycles are asymmetric.
pub const DENOMINATOR_FLOOR_MILLIONTHS: u64 = 3_000_000;

/// Sentinel prefix the external harness prints before its timing payload.
pub const PERF_HARNESS_SENTINEL: &str = "__FE_PERF__";

/// Default engine-lane instruction budget for perf measurement. The engine's
/// containment defaults (100K/1M instructions) cannot execute the benchmark
/// corpus (1M-iteration loops); measurement needs workloads to COMPLETE so
/// throughput — not the budget ceiling — is what gets measured. Recorded in
/// the environment manifest because a budget override is a
/// measurement-configuration fact.
pub const DEFAULT_PERF_ENGINE_INSTRUCTION_BUDGET: u64 = 2_000_000_000;

/// Predeclared minimum retained improvement for the compact Tier-I tranche.
/// `1_050_000` means the forced Tier-R control took at least 5% longer than
/// production Tier-I on the same prepared module and execution lifecycle.
pub const TIER_CONTROL_KEEP_FLOOR_MILLIONTHS: u64 = 1_050_000;

/// Predeclared mixed positive/negative denominator for the compact scalar
/// dispatch keep/kill experiment. Both the identifier and exact source bytes
/// are authoritative: a custom manifest cannot retain these names while
/// substituting more favorable programs.
pub const TIER_CONTROL_REQUIRED_CASE_SOURCES_SHA256: &[(&str, &str)] = &[
    (
        "micro-arithmetic-loop",
        "8a139b47d84ab89b5979b8a69bb6d57add4e43e0f44949aea778377d5c734d58",
    ),
    (
        "micro-function-calls",
        "0cf202d0e18b9341724ad658714b06d30d65b68b8c78c3400f4cc9369056134a",
    ),
    (
        "micro-object-property-access",
        "afbef1aaf21a136e50b641a1055ea6064edafffdc1720b104af49550ef227cb0",
    ),
    (
        "micro-array-indexing",
        "d9ea70c2ab86a4432a5cf030549f3d0c71e27bdfbf9ff57e57993e190cc2eda6",
    ),
    (
        "micro-bitwise-ops",
        "fdad184b299e2bba1667ce92dc1387489f2f714a90fcf99fd6da606b12b7b900",
    ),
    (
        "micro-modulo-ops",
        "2bc9ac8e95af7ef1855cc0ee2bfa532afd4b8798cf15b75f5c278e83bc1d96ce",
    ),
    (
        "micro-float-arithmetic",
        "b66c76ad769e54e6f12c98634c26595889577c221812f60aa69874653a3dd697",
    ),
];

/// Exact measurement policy for a decision-bearing Tier-I run. Runs with any
/// other policy remain useful diagnostic evidence but cannot emit keep/kill.
pub const TIER_CONTROL_DECISION_WARMUP_ITERATIONS: u32 = 3;
pub const TIER_CONTROL_DECISION_MEASURED_ITERATIONS: u32 = 30;
pub const TIER_CONTROL_DECISION_MAX_CV_MILLIONTHS: u32 = 150_000;

/// Conservative two-sided 95% Student-t critical value used for paired
/// log-ratio intervals. The diagnostic floor is ten measured pairs (9 degrees
/// of freedom), whose critical value is 2.262; retaining that value for larger
/// samples widens rather than overstates confidence.
pub const TIER_CONTROL_CI95_T_CRITICAL_MILLIONTHS: u64 = 2_262_000;

const MILLIONTHS: u64 = 1_000_000;
const CARGO_BUILD_PROFILE_CLASS: &str = env!("FRANKENENGINE_CARGO_PROFILE_CLASS");
const CARGO_BUILD_PROFILE_DIRECTORY: &str = env!("FRANKENENGINE_CARGO_PROFILE_DIRECTORY");
const CARGO_BUILD_OPT_LEVEL: &str = env!("FRANKENENGINE_CARGO_OPT_LEVEL");
const CARGO_BUILD_DEBUG_INFO: &str = env!("FRANKENENGINE_CARGO_DEBUG_INFO");

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One corpus case: an id plus the exact JS source every runtime evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfCorpusCase {
    pub case_id: String,
    pub source: String,
}

impl PerfCorpusCase {
    pub fn new(case_id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            source: source.into(),
        }
    }
}

/// Tunable measurement policy for this performance arm. Every selected value
/// is serialized into the report; the runtime-comparison manifest's separate
/// fairness policy is not implicitly loaded by this API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfArmConfig {
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    /// Budget for one whole harness subprocess (all iterations of one case).
    pub case_timeout_ms: u64,
    /// Per-case coefficient-of-variation admission bar, in millionths
    /// (150_000 == 15%). Cases noisier than this are excluded from the
    /// denominator and the exclusion is recorded.
    pub max_cv_millionths: u32,
    /// Engine-lane instruction budget (applies to the perf lane AND the
    /// correctness-arm consensus precondition).
    pub engine_instruction_budget: u64,
    pub node: ExternalRuntimeSpec,
    pub bun: ExternalRuntimeSpec,
}

impl Default for PerfArmConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 3,
            measured_iterations: 30,
            case_timeout_ms: 120_000,
            max_cv_millionths: 150_000,
            engine_instruction_budget: DEFAULT_PERF_ENGINE_INSTRUCTION_BUDGET,
            node: ExternalRuntimeSpec::node_default(),
            bun: ExternalRuntimeSpec::bun_default(),
        }
    }
}

/// Same-binary Tier-I treatment/control measurement policy. This deliberately
/// excludes Node and Bun: it answers only whether the current compact dispatch
/// earns its keep relative to the canonical Tier-R path under identical native
/// lifecycle and budget conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlConfig {
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    pub max_cv_millionths: u32,
    pub engine_instruction_budget: u64,
}

impl Default for TierControlConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: TIER_CONTROL_DECISION_WARMUP_ITERATIONS,
            measured_iterations: TIER_CONTROL_DECISION_MEASURED_ITERATIONS,
            max_cv_millionths: TIER_CONTROL_DECISION_MAX_CV_MILLIONTHS,
            engine_instruction_budget: DEFAULT_PERF_ENGINE_INSTRUCTION_BUDGET,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-iteration evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfPhase {
    Preparation,
    Warmup,
    Measured,
}

/// One raw timing observation; serialized verbatim into `events.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfIterationEvent {
    pub event: String,
    pub case_id: String,
    pub backend: DifferentialBackend,
    pub phase: PerfPhase,
    pub index: u32,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierControlArm {
    ProductionTierI,
    ForcedTierR,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierExecutionCounters {
    pub instructions_executed: u64,
    pub tier_i_instructions_executed: u64,
    pub tier_i_specialized_instructions_executed: u64,
}

impl From<&EvalOutcome> for TierExecutionCounters {
    fn from(outcome: &EvalOutcome) -> Self {
        Self {
            instructions_executed: outcome.instructions_executed,
            tier_i_instructions_executed: outcome.tier_i_instructions_executed,
            tier_i_specialized_instructions_executed: outcome
                .tier_i_specialized_instructions_executed,
        }
    }
}

/// Raw timing plus exact dispatch counters for one side of the matched native
/// experiment. Counter vectors are index-aligned with timing and observation
/// vectors; a mismatch excludes the case rather than being repaired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlArmResult {
    pub arm: TierControlArm,
    pub status: PerfMeasurementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_kind: Option<EngineKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_reason: Option<RouteReason>,
    pub warmup_ns: Vec<u64>,
    pub measured_ns: Vec<u64>,
    pub warmup_observation_sha256: Vec<String>,
    pub measured_observation_sha256: Vec<String>,
    pub warmup_execution_artifact_sha256: Vec<String>,
    pub measured_execution_artifact_sha256: Vec<String>,
    pub warmup_counters: Vec<TierExecutionCounters>,
    pub measured_counters: Vec<TierExecutionCounters>,
    pub observations_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<PerfSampleStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlIterationEvent {
    pub event: String,
    pub case_id: String,
    pub arm: TierControlArm,
    pub phase: PerfPhase,
    pub index: u32,
    /// Zero-based order across warm-up followed by measured pairs.
    pub pair_sequence: u32,
    /// Execution order within the pair: zero ran first, one ran second.
    pub order_in_pair: u8,
    pub duration_ns: u64,
    pub counters: TierExecutionCounters,
    pub execution_artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlCaseResult {
    pub case_id: String,
    pub source_sha256: String,
    pub preparation_ns: u64,
    pub production: TierControlArmResult,
    pub control: TierControlArmResult,
    pub equivalent: bool,
    pub equivalence_detail: String,
    /// forced Tier-R mean / production Tier-I mean, in millionths. Values
    /// above one million mean production Tier-I was faster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_i_speedup_over_tier_r_millionths: Option<u64>,
    /// Paired log-ratio estimate and conservative 95% confidence interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_speedup: Option<TierControlPairedSpeedup>,
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusion_reasons: Vec<String>,
}

/// One ordered identity in the predeclared Tier-I decision corpus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TierControlCaseIdentity {
    pub case_id: String,
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlPairedSpeedup {
    pub pair_count: usize,
    pub geomean_speedup_millionths: u64,
    pub ci95_lower_speedup_millionths: u64,
    pub ci95_upper_speedup_millionths: u64,
    pub confidence_method: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierControlDecision {
    Keep,
    Kill,
    Inconclusive,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlEnvironment {
    pub host: DifferentialHostFacts,
    /// Hash of the exact executable containing both treatment and control.
    /// Missing only when the platform cannot resolve or read its current
    /// executable; absence is retained rather than replaced by a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
    /// Kernel-reported CPU affinity for this process when `/proc` exposes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_affinity: Option<String>,
    /// Kernel-reported NUMA-memory affinity for this process when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_memory_affinity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_1m_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_governor: Option<String>,
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    pub max_cv_millionths: u32,
    pub engine_instruction_budget: u64,
    pub cargo_profile_class: String,
    pub cargo_profile_directory: String,
    pub cargo_opt_level: String,
    pub cargo_debug_info: String,
    pub debug_assertions_enabled: bool,
    pub decision_corpus_complete: bool,
    pub decision_policy_complete: bool,
    pub decision_build_complete: bool,
    pub decision_scope_complete: bool,
    pub required_case_ids: Vec<String>,
    pub selected_case_ids: Vec<String>,
    pub required_case_identities: Vec<TierControlCaseIdentity>,
    pub selected_case_identities: Vec<TierControlCaseIdentity>,
    pub lifecycle: String,
    pub pair_order: String,
    pub execution_artifact_projection: String,
    pub corpus_case_count: usize,
    pub corpus_sha256: String,
    pub generated_unix_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlSummary {
    pub admitted_cases: usize,
    pub excluded_cases: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geomean_speedup_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meets_keep_floor: Option<bool>,
    pub decision: TierControlDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_speedup: Option<TierControlPairedSpeedup>,
    pub keep_floor_millionths: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierControlPerfReport {
    pub schema_version: String,
    pub generated_unix_ns: u128,
    pub environment: TierControlEnvironment,
    pub cases: Vec<TierControlCaseResult>,
    pub iteration_event_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration_events_jsonl_sha256: Option<String>,
    pub summary: TierControlSummary,
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfSampleStats {
    pub sample_count: usize,
    pub mean_ns: u64,
    pub stddev_ns: u64,
    /// stddev / mean in millionths.
    pub cv_millionths: u32,
    pub ci95_lower_ns: u64,
    pub ci95_upper_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfMeasurementStatus {
    Measured,
    Failed,
    Unavailable,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfBackendCaseResult {
    pub backend: DifferentialBackend,
    pub status: PerfMeasurementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// One-time source preparation/compilation cost excluded from the warmup
    /// and steady-state samples below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_ns: Option<u64>,
    /// Concrete in-process lane selected by the prepared router. External
    /// backends leave this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_kind: Option<EngineKind>,
    /// Concrete source-routing reason selected by the prepared router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_reason: Option<RouteReason>,
    pub warmup_ns: Vec<u64>,
    pub measured_ns: Vec<u64>,
    /// SHA-256 of the captured console streams plus typed invocation-return
    /// projection for every warm-up invocation, in the same order as
    /// `warmup_ns`. For the external `new Function` lanes this is the function
    /// return, not arbitrary Script completion. V3 therefore marks the
    /// observation complete only for an `undefined` return, which is also the
    /// observed completion shape of the checked-in benchmark corpus; lifecycle
    /// asymmetry remains a publication-blocking fairness violation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warmup_observation_sha256: Vec<String>,
    /// SHA-256 of the captured console streams plus typed invocation-return
    /// projection for every measured invocation, in the same order as
    /// `measured_ns`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measured_observation_sha256: Vec<String>,
    /// True only when every invocation produced a structurally valid console
    /// observation and the v3-supported exact `undefined` invocation return,
    /// so the digest cannot be an empty or unsupported placeholder.
    #[serde(default)]
    pub observations_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<PerfSampleStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfCaseResult {
    pub case_id: String,
    pub source_sha256: String,
    /// Correctness-arm precondition: Node, Bun, and FrankenEngine produced
    /// the same canonical structured value for this source.
    pub behavior_equivalent: bool,
    pub equivalence_detail: String,
    /// Captured console streams and typed invocation-return projections were
    /// stable across warm-up/measured invocations within each backend and
    /// agreed across Node, Bun, and FrankenEngine.
    pub measured_lifecycle_equivalent: bool,
    pub measured_lifecycle_detail: String,
    pub engine: PerfBackendCaseResult,
    pub node: PerfBackendCaseResult,
    pub bun: PerfBackendCaseResult,
    /// node_mean / engine_mean in millionths (> 1_000_000 means the engine
    /// completed the workload faster than Node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_over_engine_speedup_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_over_engine_speedup_millionths: Option<u64>,
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusion_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Environment + fairness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfEnvironmentManifest {
    pub host: DifferentialHostFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_memory_kb: Option<u64>,
    /// 1-minute load average at run start, millionths (12_340_000 == 12.34).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_1m_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_governor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    /// False when the `node` binary is actually Bun's node shim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_genuine: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_version: Option<String>,
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    /// Maximum admitted coefficient of variation, in millionths. Persisting
    /// the threshold lets downstream bundle validation recompute each
    /// baseline's admission set from raw samples.
    pub max_cv_millionths: u32,
    /// Exact lifecycle used for the FrankenEngine timing denominator.
    pub engine_execution_lifecycle: String,
    /// Exact lifecycle used for the Node/Bun timing denominator.
    pub external_execution_lifecycle: String,
    /// Engine-lane instruction budget in force for this run (containment
    /// defaults are overridden for measurement; see `PerfArmConfig`).
    #[serde(default)]
    pub engine_instruction_budget: u64,
    pub corpus_case_count: usize,
    pub corpus_sha256: String,
    pub generated_unix_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfFairnessReport {
    pub compliant: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Denominator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfDenominatorStatus {
    /// Fairness rules met and enough cases admitted: the ratio is a number a
    /// skeptic can re-derive. Publication of CLAIM wording is still gated by
    /// the claim-to-proof matrix, not by this report.
    Published,
    /// Fairness rules unmet (or no admissible cases): the receipt documents
    /// why and carries no usable ratio.
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfDenominator {
    pub baseline: String,
    pub admitted_cases: usize,
    pub excluded_cases: usize,
    /// Unweighted geometric mean of per-case speedups, millionths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geomean_speedup_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meets_3x_floor: Option<bool>,
    pub status: PerfDenominatorStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialPerfReport {
    pub schema_version: String,
    pub generated_unix_ns: u128,
    pub environment: PerfEnvironmentManifest,
    pub fairness: PerfFairnessReport,
    pub cases: Vec<PerfCaseResult>,
    pub node_denominator: PerfDenominator,
    pub bun_denominator: PerfDenominator,
}

// ---------------------------------------------------------------------------
// Harness generation + parsing
// ---------------------------------------------------------------------------

/// Builds the JS harness an external runtime executes for one case.
///
/// The case source is embedded as a JSON string literal and compiled once via
/// `new Function`; console methods are replaced with accumulators during the
/// timed loops so I/O cost does not dominate the workload being measured. The
/// function-return projection is captured after the timer stops and joins the
/// console streams in the per-invocation observation. This is deliberately not
/// described as general Script completion: `new Function(source)()` returns
/// `undefined` unless the function body executes `return`.
pub fn build_external_perf_harness(source: &str, warmup: u32, measured: u32) -> String {
    let escaped = serde_json::to_string(source).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "const __feSrc = {escaped};\n\
         const __fePrepareStart = process.hrtime.bigint();\n\
         const __feFn = new Function(__feSrc);\n\
         const __fePreparationNs = Number(process.hrtime.bigint() - __fePrepareStart);\n\
         const __feConsole = console;\n\
         const __feRealLog = __feConsole.log;\n\
         const __feRealInfo = __feConsole.info;\n\
         const __feRealWarn = __feConsole.warn;\n\
         const __feRealError = __feConsole.error;\n\
         const __feNow = process.hrtime.bigint.bind(process.hrtime);\n\
         const __feString = String;\n\
         const __feNumber = Number;\n\
         const __feJsonStringify = JSON.stringify;\n\
         const __feArrayPush = Function.call.bind(Array.prototype.push);\n\
         const __feArrayJoin = Function.call.bind(Array.prototype.join);\n\
         let __feSink = 0;\n\
         let __feStdout = [];\n\
         let __feStderr = [];\n\
         function __feCapture(target, args) {{\n\
           const rendered = [];\n\
           for (let i = 0; i < args.length; i += 1) __feArrayPush(rendered, __feString(args[i]));\n\
           __feArrayPush(target, __feArrayJoin(rendered, ' ') + '\\n');\n\
           __feSink += args.length;\n\
         }}\n\
         function __feObservation(completion) {{\n\
           const completionType = typeof completion;\n\
           const completionValue = completionType === 'undefined' ? 'undefined' : '<unsupported>';\n\
           return __feJsonStringify([__feArrayJoin(__feStdout, ''), __feArrayJoin(__feStderr, ''), completionType, completionValue]);\n\
         }}\n\
         __feConsole.log = function () {{ __feCapture(__feStdout, arguments); }};\n\
         __feConsole.info = function () {{ __feCapture(__feStdout, arguments); }};\n\
         __feConsole.warn = function () {{ __feCapture(__feStderr, arguments); }};\n\
         __feConsole.error = function () {{ __feCapture(__feStderr, arguments); }};\n\
         const __feWarm = [];\n\
         const __feMeas = [];\n\
         const __feWarmObservations = [];\n\
         const __feMeasuredObservations = [];\n\
         for (let i = 0; i < {warmup}; i += 1) {{\n\
           __feStdout = []; __feStderr = [];\n\
           const t0 = __feNow();\n\
           const completion = __feFn();\n\
           const t1 = __feNow();\n\
           __feArrayPush(__feWarm, __feNumber(t1 - t0));\n\
           __feArrayPush(__feWarmObservations, __feObservation(completion));\n\
         }}\n\
         for (let i = 0; i < {measured}; i += 1) {{\n\
           __feStdout = []; __feStderr = [];\n\
           const t0 = __feNow();\n\
           const completion = __feFn();\n\
           const t1 = __feNow();\n\
           __feArrayPush(__feMeas, __feNumber(t1 - t0));\n\
           __feArrayPush(__feMeasuredObservations, __feObservation(completion));\n\
         }}\n\
         __feConsole.log = __feRealLog;\n\
         __feConsole.info = __feRealInfo; __feConsole.warn = __feRealWarn; __feConsole.error = __feRealError;\n\
         __feRealLog('{sentinel}' + __feJsonStringify({{ preparation_ns: __fePreparationNs, warmup_ns: __feWarm, measured_ns: __feMeas, warmup_observations: __feWarmObservations, measured_observations: __feMeasuredObservations, sink: __feSink }}));\n",
        sentinel = PERF_HARNESS_SENTINEL,
    )
}

#[derive(Debug, Deserialize)]
struct HarnessPayload {
    preparation_ns: u64,
    warmup_ns: Vec<u64>,
    measured_ns: Vec<u64>,
    warmup_observations: Vec<String>,
    measured_observations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPerfHarnessOutput {
    pub preparation_ns: u64,
    pub warmup_ns: Vec<u64>,
    pub measured_ns: Vec<u64>,
    pub warmup_observation_sha256: Vec<String>,
    pub measured_observation_sha256: Vec<String>,
    pub observations_complete: bool,
}

/// Extracts one-time preparation, per-invocation timing, and captured
/// console/completion-observation digests from harness stdout.
/// The LAST sentinel line wins so workload output cannot spoof the payload
/// unless it also runs after the harness completes.
pub fn parse_perf_harness_output(stdout: &str) -> Result<ParsedPerfHarnessOutput, String> {
    let payload_line = stdout
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(PERF_HARNESS_SENTINEL))
        .ok_or_else(|| format!("no `{PERF_HARNESS_SENTINEL}` sentinel line in harness stdout"))?;
    let payload: HarnessPayload = serde_json::from_str(payload_line)
        .map_err(|error| format!("malformed harness timing payload: {error}"))?;
    if payload.warmup_ns.len() != payload.warmup_observations.len()
        || payload.measured_ns.len() != payload.measured_observations.len()
    {
        return Err("harness timing/observation vector lengths differ".to_string());
    }
    let observation_count = payload
        .warmup_observations
        .len()
        .saturating_add(payload.measured_observations.len());
    let observations_complete = observation_count > 0
        && payload
            .warmup_observations
            .iter()
            .chain(&payload.measured_observations)
            .all(|observation| {
                serde_json::from_str::<[String; 4]>(observation)
                    .is_ok_and(|fields| fields[2] == "undefined" && fields[3] == "undefined")
            });
    Ok(ParsedPerfHarnessOutput {
        preparation_ns: payload.preparation_ns,
        warmup_ns: payload.warmup_ns,
        measured_ns: payload.measured_ns,
        warmup_observation_sha256: payload
            .warmup_observations
            .iter()
            .map(|observation| sha256_hex(observation.as_bytes()))
            .collect(),
        measured_observation_sha256: payload
            .measured_observations
            .iter()
            .map(|observation| sha256_hex(observation.as_bytes()))
            .collect(),
        observations_complete,
    })
}

fn validate_harness_sample_counts(
    parsed: &ParsedPerfHarnessOutput,
    expected_warmup: u32,
    expected_measured: u32,
) -> Result<(), String> {
    let expected_warmup = expected_warmup as usize;
    let expected_measured = expected_measured as usize;
    if parsed.warmup_ns.len() != expected_warmup
        || parsed.warmup_observation_sha256.len() != expected_warmup
        || parsed.measured_ns.len() != expected_measured
        || parsed.measured_observation_sha256.len() != expected_measured
    {
        return Err(format!(
            "harness sample counts differ from request: warmup timing/observation={}/{}, expected {}; measured timing/observation={}/{}, expected {}",
            parsed.warmup_ns.len(),
            parsed.warmup_observation_sha256.len(),
            expected_warmup,
            parsed.measured_ns.len(),
            parsed.measured_observation_sha256.len(),
            expected_measured,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Statistics (integer-only, deterministic)
// ---------------------------------------------------------------------------

/// Deterministic integer square root (Newton's method) over u128.
fn isqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = value;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

/// Computes deterministic sample statistics; `None` for empty input.
pub fn compute_sample_stats(samples: &[u64]) -> Option<PerfSampleStats> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len() as u128;
    let sum: u128 = samples.iter().map(|&s| u128::from(s)).sum();
    let mean = sum / n;
    let variance = if samples.len() < 2 {
        0
    } else {
        let sum_sq_dev: u128 = samples
            .iter()
            .map(|&s| {
                let d = u128::from(s).abs_diff(mean);
                d.saturating_mul(d)
            })
            .sum();
        sum_sq_dev / (n - 1)
    };
    let stddev = isqrt_u128(variance);
    let cv_millionths = stddev
        .saturating_mul(u128::from(MILLIONTHS))
        .checked_div(mean)
        .map(|value| u32::try_from(value).unwrap_or(u32::MAX))
        .unwrap_or(0);
    // ci95 half-width = 1.96 * stddev / sqrt(n), computed in millionths so
    // sqrt(n) keeps six fractional digits of precision.
    let sqrt_n_millionths = isqrt_u128(n.saturating_mul(1_000_000_000_000));
    let ci_half = stddev
        .saturating_mul(1_960_000)
        .checked_div(sqrt_n_millionths)
        .unwrap_or(0);
    let mean_u64 = u64::try_from(mean).unwrap_or(u64::MAX);
    let ci_half_u64 = u64::try_from(ci_half).unwrap_or(u64::MAX);
    Some(PerfSampleStats {
        sample_count: samples.len(),
        mean_ns: mean_u64,
        stddev_ns: u64::try_from(stddev).unwrap_or(u64::MAX),
        cv_millionths,
        ci95_lower_ns: mean_u64.saturating_sub(ci_half_u64),
        ci95_upper_ns: mean_u64.saturating_add(ci_half_u64),
        min_ns: samples.iter().copied().min().unwrap_or(0),
        max_ns: samples.iter().copied().max().unwrap_or(0),
    })
}

/// baseline_mean / engine_mean in millionths; `None` if the engine mean is zero.
pub fn speedup_millionths(engine_mean_ns: u64, baseline_mean_ns: u64) -> Option<u64> {
    if engine_mean_ns == 0 {
        return None;
    }
    let value = u128::from(baseline_mean_ns).saturating_mul(u128::from(MILLIONTHS))
        / u128::from(engine_mean_ns);
    Some(u64::try_from(value).unwrap_or(u64::MAX))
}

/// Unweighted geometric mean of millionths-scaled ratios, in millionths.
///
/// Internally uses `f64::ln`/`exp` on report-only values (never hashed) and
/// rounds back to exact millionths, matching the precision convention used by
/// `benchmark_denominator::weighted_geometric_mean`.
pub fn geometric_mean_millionths(ratios: &[u64]) -> Option<u64> {
    if ratios.is_empty() {
        return None;
    }
    if ratios.contains(&0) {
        return None;
    }
    let log_sum: f64 = ratios
        .iter()
        .map(|&r| (r as f64 / MILLIONTHS as f64).ln())
        .sum();
    let gm = (log_sum / ratios.len() as f64).exp();
    let scaled = gm * MILLIONTHS as f64;
    if !scaled.is_finite() || scaled < 0.0 {
        return None;
    }
    Some(scaled.round() as u64)
}

fn speedup_millionths_from_float(value: f64, round_up: bool) -> Option<u64> {
    let scaled = value * MILLIONTHS as f64;
    if !scaled.is_finite() || scaled <= 0.0 {
        return None;
    }
    const U64_UPPER_EXCLUSIVE_AS_F64: f64 = 18_446_744_073_709_551_616.0;
    let rounded = if round_up {
        scaled.ceil()
    } else {
        scaled.floor()
    };
    if rounded < 1.0 || rounded >= U64_UPPER_EXCLUSIVE_AS_F64 {
        return None;
    }
    Some(rounded as u64)
}

fn paired_speedup_from_log_ratios(
    log_ratios: &[f64],
    confidence_method: &str,
) -> Option<TierControlPairedSpeedup> {
    if log_ratios.len() < 2 || log_ratios.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let count = log_ratios.len() as f64;
    let mean = log_ratios.iter().sum::<f64>() / count;
    let sample_variance = log_ratios
        .iter()
        .map(|value| {
            let deviation = value - mean;
            deviation * deviation
        })
        .sum::<f64>()
        / (count - 1.0);
    let standard_error = sample_variance.sqrt() / count.sqrt();
    let critical = TIER_CONTROL_CI95_T_CRITICAL_MILLIONTHS as f64 / MILLIONTHS as f64;
    let margin = critical * standard_error;
    let center = speedup_millionths_from_float(mean.exp(), false)?;
    let lower = speedup_millionths_from_float((mean - margin).exp(), false)?;
    let upper = speedup_millionths_from_float((mean + margin).exp(), true)?;
    Some(TierControlPairedSpeedup {
        pair_count: log_ratios.len(),
        geomean_speedup_millionths: center,
        ci95_lower_speedup_millionths: lower,
        ci95_upper_speedup_millionths: upper,
        confidence_method: confidence_method.to_string(),
    })
}

fn paired_speedup(
    production_ns: &[u64],
    control_ns: &[u64],
    confidence_method: &str,
) -> Option<TierControlPairedSpeedup> {
    if production_ns.len() != control_ns.len()
        || production_ns
            .iter()
            .chain(control_ns)
            .any(|value| *value == 0)
    {
        return None;
    }
    let log_ratios = production_ns
        .iter()
        .zip(control_ns)
        .map(|(production, control)| (*control as f64 / *production as f64).ln())
        .collect::<Vec<_>>();
    paired_speedup_from_log_ratios(&log_ratios, confidence_method)
}

/// Parses a decimal string like "12.34" into millionths (12_340_000) without
/// floating point. Returns `None` on malformed input.
pub fn parse_decimal_millionths(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let (whole, frac) = match trimmed.split_once('.') {
        Some((w, f)) => (w, f),
        None => (trimmed, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    let whole_value: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut frac_value: u64 = 0;
    let mut scale: u64 = MILLIONTHS / 10;
    for ch in frac.chars().take(6) {
        let digit = ch.to_digit(10)? as u64;
        frac_value += digit * scale;
        scale /= 10;
    }
    whole_value
        .checked_mul(MILLIONTHS)
        .map(|w| w.saturating_add(frac_value))
}

// ---------------------------------------------------------------------------
// Environment capture + fairness evaluation
// ---------------------------------------------------------------------------

fn resolve_program_path(program: &str) -> Option<String> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        return fs::canonicalize(candidate)
            .ok()
            .map(|p| p.display().to_string());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full = dir.join(program);
        if full.is_file() {
            return fs::canonicalize(&full)
                .ok()
                .map(|p| p.display().to_string())
                .or_else(|| Some(full.display().to_string()));
        }
    }
    None
}

/// True when the configured node binary is real Node.js rather than Bun's
/// `node` compatibility shim (`typeof Bun` is `"undefined"` on real Node).
fn detect_node_genuine(spec: &ExternalRuntimeSpec, timeout: Duration) -> Option<bool> {
    let args: Vec<&str> = spec
        .eval_args
        .iter()
        .map(String::as_str)
        .chain(["console.log(typeof Bun);"])
        .collect();
    let output = run_command_with_timeout(spec.program.as_str(), args, timeout).ok()?;
    if !output.status.success() || output.timed_out {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.trim() == "undefined")
}

fn read_total_memory_kb() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(|line| {
        line.strip_prefix("MemTotal:").and_then(|rest| {
            rest.trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
    })
}

fn read_load_avg_1m_millionths() -> Option<u64> {
    let loadavg = fs::read_to_string("/proc/loadavg").ok()?;
    parse_decimal_millionths(loadavg.split_whitespace().next()?)
}

fn read_cpu_governor() -> Option<String> {
    fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn corpus_sha256(corpus: &[PerfCorpusCase]) -> String {
    // Length-prefix every variable-length field before mixing so distinct
    // corpora cannot collide on a shared byte stream.
    let mut bytes = Vec::new();
    for case in corpus {
        bytes.extend_from_slice(&(case.case_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.case_id.as_bytes());
        bytes.extend_from_slice(&(case.source.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.source.as_bytes());
    }
    sha256_hex(&bytes)
}

/// Captures the full environment manifest the fairness rules require.
pub fn capture_perf_environment(
    config: &PerfArmConfig,
    corpus: &[PerfCorpusCase],
) -> PerfEnvironmentManifest {
    let probe_timeout = Duration::from_millis(5_000);
    let node_version = match capture_external_version(&config.node, probe_timeout) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(_) => None,
    };
    let bun_version = match capture_external_version(&config.bun, probe_timeout) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(_) => None,
    };
    PerfEnvironmentManifest {
        host: capture_host_facts(),
        total_memory_kb: read_total_memory_kb(),
        load_avg_1m_millionths: read_load_avg_1m_millionths(),
        cpu_governor: read_cpu_governor(),
        node_resolved_program: resolve_program_path(config.node.program.as_str()),
        node_version,
        node_genuine: detect_node_genuine(&config.node, probe_timeout),
        bun_resolved_program: resolve_program_path(config.bun.program.as_str()),
        bun_version,
        warmup_iterations: config.warmup_iterations,
        measured_iterations: config.measured_iterations,
        max_cv_millionths: config.max_cv_millionths,
        engine_execution_lifecycle: "prepare_once_fresh_router_and_interpreter_core_per_iteration"
            .to_string(),
        external_execution_lifecycle: "new_function_once_single_process_shared_realm_and_jit_state"
            .to_string(),
        engine_instruction_budget: config.engine_instruction_budget,
        corpus_case_count: corpus.len(),
        corpus_sha256: corpus_sha256(corpus),
        generated_unix_ns: current_unix_ns(),
    }
}

/// Applies the binding fairness rules to a captured environment.
pub fn evaluate_fairness(
    environment: &PerfEnvironmentManifest,
    config: &PerfArmConfig,
) -> PerfFairnessReport {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    if config.warmup_iterations == 0 {
        violations.push("warmup protocol requires at least one warmup iteration".to_string());
    }
    if config.measured_iterations < 10 {
        violations.push(format!(
            "measured_iterations={} is below the minimum sample floor of 10",
            config.measured_iterations
        ));
    }
    if environment.node_version.is_none() {
        violations.push("node runtime version could not be recorded".to_string());
    }
    if environment.bun_version.is_none() {
        violations.push("bun runtime version could not be recorded".to_string());
    }
    match environment.node_genuine {
        Some(true) => {}
        Some(false) => violations.push(
            "configured `node` binary is Bun's node shim, not real Node.js — \
             point --node-bin at a genuine Node installation"
                .to_string(),
        ),
        None => violations.push("could not verify the node binary is genuine Node.js".to_string()),
    }
    match environment.cpu_governor.as_deref() {
        Some("performance") => {}
        Some(other) => notes.push(format!(
            "cpu governor is `{other}` (not `performance`); host does not allow pinning"
        )),
        None => notes.push("cpu governor not readable on this host".to_string()),
    }
    if let Some(load) = environment.load_avg_1m_millionths {
        let cores = environment.host.cpu_cores_logical as u64;
        if cores > 0 && load > cores.saturating_mul(MILLIONTHS) / 2 {
            notes.push(format!(
                "1m load average {load_whole}.{load_frac:06} exceeds half the {cores} logical cores; \
                 expect elevated variance",
                load_whole = load / MILLIONTHS,
                load_frac = load % MILLIONTHS,
            ));
        }
    }
    violations.push(
        "execution lifecycle is not symmetric: FrankenEngine uses a fresh router/interpreter \
         core per iteration while node/bun reuse one process, realm, and JIT state; this run is \
         diagnostic-only"
            .to_string(),
    );
    notes.push(format!(
        "engine instruction budget overridden to {} for measurement (containment defaults \
         cannot execute the corpus); node/bun have no analogous cap",
        environment.engine_instruction_budget
    ));

    PerfFairnessReport {
        compliant: violations.is_empty(),
        violations,
        notes,
    }
}

// ---------------------------------------------------------------------------
// Per-case measurement
// ---------------------------------------------------------------------------

fn run_external_perf_case(
    spec: &ExternalRuntimeSpec,
    source: &str,
    config: &PerfArmConfig,
) -> PerfBackendCaseResult {
    let timeout = Duration::from_millis(config.case_timeout_ms.max(1));
    let version = match capture_external_version(spec, Duration::from_millis(5_000)) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(message) => {
            return PerfBackendCaseResult {
                backend: spec.runtime_id,
                status: PerfMeasurementStatus::Unavailable,
                resolved_program: resolve_program_path(spec.program.as_str()),
                version: None,
                preparation_ns: None,
                engine_kind: None,
                route_reason: None,
                warmup_ns: Vec::new(),
                measured_ns: Vec::new(),
                warmup_observation_sha256: Vec::new(),
                measured_observation_sha256: Vec::new(),
                observations_complete: false,
                stats: None,
                diagnostics: vec![message],
            };
        }
    };
    let harness =
        build_external_perf_harness(source, config.warmup_iterations, config.measured_iterations);
    let args: Vec<&str> = spec
        .eval_args
        .iter()
        .map(String::as_str)
        .chain([harness.as_str()])
        .collect();
    match run_command_with_timeout(spec.program.as_str(), args, timeout) {
        Ok(output) if output.timed_out => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Timeout,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            preparation_ns: None,
            engine_kind: None,
            route_reason: None,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            warmup_observation_sha256: Vec::new(),
            measured_observation_sha256: Vec::new(),
            observations_complete: false,
            stats: None,
            diagnostics: vec![format!(
                "perf harness exceeded {}ms timeout",
                timeout.as_millis()
            )],
        },
        Ok(output) if !output.status.success() => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Failed,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            preparation_ns: None,
            engine_kind: None,
            route_reason: None,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            warmup_observation_sha256: Vec::new(),
            measured_observation_sha256: Vec::new(),
            observations_complete: false,
            stats: None,
            diagnostics: vec![format!(
                "perf harness exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(400)
                    .collect::<String>()
            )],
        },
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match parse_perf_harness_output(&stdout) {
                Ok(parsed) => {
                    if let Err(message) = validate_harness_sample_counts(
                        &parsed,
                        config.warmup_iterations,
                        config.measured_iterations,
                    ) {
                        return PerfBackendCaseResult {
                            backend: spec.runtime_id,
                            status: PerfMeasurementStatus::Failed,
                            resolved_program: resolve_program_path(spec.program.as_str()),
                            version,
                            preparation_ns: Some(parsed.preparation_ns),
                            engine_kind: None,
                            route_reason: None,
                            warmup_ns: Vec::new(),
                            measured_ns: Vec::new(),
                            warmup_observation_sha256: Vec::new(),
                            measured_observation_sha256: Vec::new(),
                            observations_complete: false,
                            stats: None,
                            diagnostics: vec![message],
                        };
                    }
                    let stats = compute_sample_stats(&parsed.measured_ns);
                    PerfBackendCaseResult {
                        backend: spec.runtime_id,
                        status: PerfMeasurementStatus::Measured,
                        resolved_program: resolve_program_path(spec.program.as_str()),
                        version,
                        preparation_ns: Some(parsed.preparation_ns),
                        engine_kind: None,
                        route_reason: None,
                        warmup_ns: parsed.warmup_ns,
                        measured_ns: parsed.measured_ns,
                        warmup_observation_sha256: parsed.warmup_observation_sha256,
                        measured_observation_sha256: parsed.measured_observation_sha256,
                        observations_complete: parsed.observations_complete,
                        stats,
                        diagnostics: Vec::new(),
                    }
                }
                Err(message) => PerfBackendCaseResult {
                    backend: spec.runtime_id,
                    status: PerfMeasurementStatus::Failed,
                    resolved_program: resolve_program_path(spec.program.as_str()),
                    version,
                    preparation_ns: None,
                    engine_kind: None,
                    route_reason: None,
                    warmup_ns: Vec::new(),
                    measured_ns: Vec::new(),
                    warmup_observation_sha256: Vec::new(),
                    measured_observation_sha256: Vec::new(),
                    observations_complete: false,
                    stats: None,
                    diagnostics: vec![message],
                },
            }
        }
        Err(error) => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Unavailable,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            preparation_ns: None,
            engine_kind: None,
            route_reason: None,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            warmup_observation_sha256: Vec::new(),
            measured_observation_sha256: Vec::new(),
            observations_complete: false,
            stats: None,
            diagnostics: vec![format!("failed to spawn perf harness: {error}")],
        },
    }
}

fn run_engine_perf_case(source: &str, config: &PerfArmConfig) -> PerfBackendCaseResult {
    let preparation_started = Instant::now();
    let prepared = HybridRouter::prepare_eval(source);
    let preparation_ns =
        u64::try_from(preparation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return PerfBackendCaseResult {
                backend: DifferentialBackend::FrankenEngine,
                status: PerfMeasurementStatus::Failed,
                resolved_program: None,
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                preparation_ns: Some(preparation_ns),
                engine_kind: None,
                route_reason: None,
                warmup_ns: Vec::new(),
                measured_ns: Vec::new(),
                warmup_observation_sha256: Vec::new(),
                measured_observation_sha256: Vec::new(),
                observations_complete: false,
                stats: None,
                diagnostics: vec![format!("engine preparation failed: {error}")],
            };
        }
    };
    let mut warmup_ns = Vec::with_capacity(config.warmup_iterations as usize);
    let mut measured_ns = Vec::with_capacity(config.measured_iterations as usize);
    let mut warmup_observation_sha256 = Vec::with_capacity(config.warmup_iterations as usize);
    let mut measured_observation_sha256 = Vec::with_capacity(config.measured_iterations as usize);
    let mut observations_complete = true;
    let mut engine_kind = None;
    let mut route_reason = None;
    let mut diagnostics = Vec::new();
    let mut failed = false;

    for phase_measured in [false, true] {
        let count = if phase_measured {
            config.measured_iterations
        } else {
            config.warmup_iterations
        };
        for _ in 0..count {
            let mut router = HybridRouter::default();
            let started = Instant::now();
            let outcome = router
                .eval_prepared_with_instruction_budget(&prepared, config.engine_instruction_budget);
            let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            match outcome {
                Ok(outcome) => {
                    if engine_kind.is_some_and(|kind| kind != outcome.engine)
                        || route_reason.is_some_and(|reason| reason != outcome.route_reason)
                    {
                        diagnostics.push(
                            "prepared engine kind or route reason changed between invocations"
                                .to_string(),
                        );
                        failed = true;
                        break;
                    }
                    engine_kind.get_or_insert(outcome.engine);
                    route_reason.get_or_insert(outcome.route_reason);
                    let (observation_sha256, observation_present) =
                        engine_observation_sha256(&outcome);
                    observations_complete &= observation_present;
                    if phase_measured {
                        measured_ns.push(elapsed);
                        measured_observation_sha256.push(observation_sha256);
                    } else {
                        warmup_ns.push(elapsed);
                        warmup_observation_sha256.push(observation_sha256);
                    }
                }
                Err(error) => {
                    diagnostics.push(format!("engine eval failed: {error}"));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            break;
        }
    }

    if failed {
        return PerfBackendCaseResult {
            backend: DifferentialBackend::FrankenEngine,
            status: PerfMeasurementStatus::Failed,
            resolved_program: None,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            preparation_ns: Some(preparation_ns),
            engine_kind,
            route_reason,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            warmup_observation_sha256: Vec::new(),
            measured_observation_sha256: Vec::new(),
            observations_complete: false,
            stats: None,
            diagnostics,
        };
    }
    observations_complete &=
        !warmup_observation_sha256.is_empty() || !measured_observation_sha256.is_empty();
    let stats = compute_sample_stats(&measured_ns);
    PerfBackendCaseResult {
        backend: DifferentialBackend::FrankenEngine,
        status: PerfMeasurementStatus::Measured,
        resolved_program: None,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        preparation_ns: Some(preparation_ns),
        engine_kind,
        route_reason,
        warmup_ns,
        measured_ns,
        warmup_observation_sha256,
        measured_observation_sha256,
        observations_complete,
        stats,
        diagnostics,
    }
}

fn engine_observation_sha256(outcome: &crate::EvalOutcome) -> (String, bool) {
    use crate::baseline_interpreter::ConsoleLevel;

    let mut stdout = String::new();
    let mut stderr = String::new();
    for entry in &outcome.console_output {
        let target = match entry.level {
            ConsoleLevel::Log | ConsoleLevel::Info => &mut stdout,
            ConsoleLevel::Warn | ConsoleLevel::Error => &mut stderr,
        };
        target.push_str(&entry.message);
        target.push('\n');
    }
    let Some(completion_type) = outcome.completion_type.as_deref() else {
        return (String::new(), false);
    };
    // The external v3 harness executes a Function body, whose return is not
    // general ECMAScript Script completion. Restrict evidence admission to the
    // one representation that is exact on both sides for the governed corpus.
    // A future richer canonical completion contract must bump the schema.
    let supported_completion = completion_type == "undefined" && outcome.value == "undefined";
    let observation = serde_json::to_string(&[
        stdout.as_str(),
        stderr.as_str(),
        completion_type,
        outcome.value.as_str(),
    ])
    .unwrap_or_default();
    let present = !observation.is_empty() && supported_completion;
    (sha256_hex(observation.as_bytes()), present)
}

fn measured_lifecycle_equivalence(
    engine: &PerfBackendCaseResult,
    node: &PerfBackendCaseResult,
    bun: &PerfBackendCaseResult,
) -> (bool, String) {
    fn stable_observation(label: &str, result: &PerfBackendCaseResult) -> Result<String, String> {
        if result.status != PerfMeasurementStatus::Measured {
            return Err(format!("{label} lifecycle was not measured"));
        }
        if !result.observations_complete {
            return Err(format!(
                "{label} lifecycle produced an invocation without a complete console/completion observation"
            ));
        }
        let mut observations = result
            .warmup_observation_sha256
            .iter()
            .chain(&result.measured_observation_sha256);
        let Some(first) = observations.next() else {
            return Err(format!("{label} lifecycle produced no observation digest"));
        };
        if observations.any(|observation| observation != first) {
            return Err(format!(
                "{label} observable output changed between warmup/measured invocations"
            ));
        }
        Ok(first.clone())
    }

    let engine_observation = match stable_observation("engine", engine) {
        Ok(observation) => observation,
        Err(message) => return (false, message),
    };
    let node_observation = match stable_observation("node", node) {
        Ok(observation) => observation,
        Err(message) => return (false, message),
    };
    let bun_observation = match stable_observation("bun", bun) {
        Ok(observation) => observation,
        Err(message) => return (false, message),
    };
    if engine_observation != node_observation || engine_observation != bun_observation {
        return (
            false,
            "engine/node/bun console/completion digests differ in the measured lifecycle"
                .to_string(),
        );
    }
    (
        true,
        format!(
            "engine/node/bun warmup and measured invocations share observable digest {engine_observation}"
        ),
    )
}

/// Output-equivalence precondition via the correctness arm: Node, Bun, and
/// FrankenEngine must share one canonical structured-value group. FrankenCore
/// membership is ignored — the denominator claim is about Node and Bun.
fn check_behavior_equivalence(case: &PerfCorpusCase, config: &PerfArmConfig) -> (bool, String) {
    let mut input = DifferentialOracleInput::new(case.case_id.clone(), case.source.clone())
        .with_timeout_ms(config.case_timeout_ms.max(1))
        .with_engine_instruction_budget(config.engine_instruction_budget)
        .with_selected_backends([
            DifferentialBackend::NodeLts,
            DifferentialBackend::BunStable,
            DifferentialBackend::FrankenEngine,
        ]);
    input.node = config.node.clone();
    input.bun = config.bun.clone();
    let report = run_differential_oracle(&input);
    let comparison = report
        .canonicalization
        .comparisons
        .iter()
        .find(|c| c.mode == DifferentialComparisonMode::StructuredValue);
    let Some(comparison) = comparison else {
        return (
            false,
            "correctness arm produced no structured-value comparison (fail-closed)".to_string(),
        );
    };
    if comparison.verdict == DifferentialComparisonVerdict::InsufficientData {
        return (
            false,
            "structured-value comparison had insufficient data (fail-closed)".to_string(),
        );
    }
    let required = [
        DifferentialBackend::NodeLts,
        DifferentialBackend::BunStable,
        DifferentialBackend::FrankenEngine,
    ];
    for group in &comparison.groups {
        if required.iter().all(|b| group.backends.contains(b)) {
            return (
                true,
                format!(
                    "node/bun/engine share structured-value group {}",
                    group.canonical_key_sha256
                ),
            );
        }
    }
    (
        false,
        "node/bun/engine did not share a structured-value group".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Denominator assembly
// ---------------------------------------------------------------------------

fn case_speedup(engine: &PerfBackendCaseResult, baseline: &PerfBackendCaseResult) -> Option<u64> {
    let engine_mean = engine.stats.as_ref()?.mean_ns;
    let baseline_mean = baseline.stats.as_ref()?.mean_ns;
    speedup_millionths(engine_mean, baseline_mean)
}

/// Builds one baseline's denominator from per-case results.
pub fn build_denominator(
    cases: &[PerfCaseResult],
    baseline: DifferentialBackend,
    fairness: &PerfFairnessReport,
    config: &PerfArmConfig,
) -> PerfDenominator {
    let baseline_label = match baseline {
        DifferentialBackend::NodeLts => "node",
        DifferentialBackend::BunStable => "bun",
        other => other.stable_label(),
    };
    let mut admitted_ratios = Vec::new();
    let mut excluded = 0usize;
    for case in cases {
        let baseline_result = match baseline {
            DifferentialBackend::NodeLts => &case.node,
            DifferentialBackend::BunStable => &case.bun,
            _ => &case.node,
        };
        let ratio = match baseline {
            DifferentialBackend::NodeLts => case.node_over_engine_speedup_millionths,
            DifferentialBackend::BunStable => case.bun_over_engine_speedup_millionths,
            _ => None,
        };
        let cv_ok = |result: &PerfBackendCaseResult| {
            result
                .stats
                .as_ref()
                .is_some_and(|s| s.cv_millionths <= config.max_cv_millionths)
        };
        if case.behavior_equivalent
            && case.measured_lifecycle_equivalent
            && case.engine.status == PerfMeasurementStatus::Measured
            && baseline_result.status == PerfMeasurementStatus::Measured
            && cv_ok(&case.engine)
            && cv_ok(baseline_result)
            && ratio.is_some()
        {
            admitted_ratios.push(ratio.unwrap_or(0));
        } else {
            excluded = excluded.saturating_add(1);
        }
    }

    let geomean = geometric_mean_millionths(&admitted_ratios);
    let mut degraded_reasons = Vec::new();
    if !fairness.compliant {
        degraded_reasons.push("fairness rules unmet (see fairness.violations)".to_string());
    }
    if admitted_ratios.is_empty() {
        degraded_reasons.push("no case satisfied the admission preconditions".to_string());
    }
    if !admitted_ratios.is_empty() && geomean.is_none() {
        degraded_reasons
            .push("admitted ratios did not yield a finite positive geometric mean".to_string());
    }
    let status = if degraded_reasons.is_empty() {
        PerfDenominatorStatus::Published
    } else {
        PerfDenominatorStatus::Degraded
    };
    let publishable = status == PerfDenominatorStatus::Published;
    PerfDenominator {
        baseline: baseline_label.to_string(),
        admitted_cases: admitted_ratios.len(),
        excluded_cases: excluded,
        geomean_speedup_millionths: if publishable { geomean } else { None },
        meets_3x_floor: if publishable {
            geomean.map(|g| g >= DENOMINATOR_FLOOR_MILLIONTHS)
        } else {
            None
        },
        status,
        degraded_reasons,
    }
}

fn empty_tier_control_arm(arm: TierControlArm) -> TierControlArmResult {
    TierControlArmResult {
        arm,
        status: PerfMeasurementStatus::Measured,
        engine_kind: None,
        route_reason: None,
        warmup_ns: Vec::new(),
        measured_ns: Vec::new(),
        warmup_observation_sha256: Vec::new(),
        measured_observation_sha256: Vec::new(),
        warmup_execution_artifact_sha256: Vec::new(),
        measured_execution_artifact_sha256: Vec::new(),
        warmup_counters: Vec::new(),
        measured_counters: Vec::new(),
        observations_complete: true,
        stats: None,
        diagnostics: Vec::new(),
    }
}

fn execute_tier_control_arm(
    prepared: &crate::PreparedHybridEval,
    instruction_budget: u64,
    policy: PreparedTierDispatchPolicy,
) -> (
    u64,
    crate::EvalResult<crate::PreparedTierDispatchObservation>,
) {
    let mut router = HybridRouter::default();
    let started = Instant::now();
    let outcome = router.eval_prepared_with_instruction_budget_and_dispatch_policy(
        prepared,
        instruction_budget,
        policy,
    );
    let outer_elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let elapsed = outcome.as_ref().map_or(outer_elapsed, |observation| {
        observation.execution_duration_ns
    });
    (elapsed, outcome)
}

fn tier_neutral_outcomes_equal(production: &EvalOutcome, control: &EvalOutcome) -> bool {
    let mut production = production.clone();
    let mut control = control.clone();
    production.tier_i_instructions_executed = 0;
    production.tier_i_specialized_instructions_executed = 0;
    control.tier_i_instructions_executed = 0;
    control.tier_i_specialized_instructions_executed = 0;
    production == control
}

fn tier_control_observation_sha256(outcome: &EvalOutcome) -> (String, bool) {
    let mut neutral = outcome.clone();
    neutral.tier_i_instructions_executed = 0;
    neutral.tier_i_specialized_instructions_executed = 0;
    match serde_json::to_vec(&neutral) {
        Ok(bytes) if !bytes.is_empty() => (sha256_hex(&bytes), true),
        _ => (String::new(), false),
    }
}

struct TierControlObservationRecord {
    phase: PerfPhase,
    duration_ns: u64,
    observation_sha256: String,
    execution_artifact_sha256: String,
    observation_complete: bool,
    counters: TierExecutionCounters,
    engine_kind: EngineKind,
    route_reason: RouteReason,
}

fn record_tier_control_observation(
    result: &mut TierControlArmResult,
    observation: TierControlObservationRecord,
) {
    let TierControlObservationRecord {
        phase,
        duration_ns,
        observation_sha256,
        execution_artifact_sha256,
        observation_complete,
        counters,
        engine_kind,
        route_reason,
    } = observation;
    if result
        .engine_kind
        .is_some_and(|existing| existing != engine_kind)
    {
        result
            .diagnostics
            .push("engine kind changed between matched invocations".to_string());
        result.status = PerfMeasurementStatus::Failed;
    }
    if result
        .route_reason
        .is_some_and(|existing| existing != route_reason)
    {
        result
            .diagnostics
            .push("route reason changed between matched invocations".to_string());
        result.status = PerfMeasurementStatus::Failed;
    }
    result.engine_kind.get_or_insert(engine_kind);
    result.route_reason.get_or_insert(route_reason);
    result.observations_complete &= observation_complete;
    match phase {
        PerfPhase::Warmup => {
            result.warmup_ns.push(duration_ns);
            result.warmup_observation_sha256.push(observation_sha256);
            result
                .warmup_execution_artifact_sha256
                .push(execution_artifact_sha256);
            result.warmup_counters.push(counters);
        }
        PerfPhase::Measured => {
            result.measured_ns.push(duration_ns);
            result.measured_observation_sha256.push(observation_sha256);
            result
                .measured_execution_artifact_sha256
                .push(execution_artifact_sha256);
            result.measured_counters.push(counters);
        }
        PerfPhase::Preparation => {}
    }
}

fn tier_control_vectors_complete(
    result: &TierControlArmResult,
    config: &TierControlConfig,
) -> bool {
    let expected_warmup = config.warmup_iterations as usize;
    let expected_measured = config.measured_iterations as usize;
    result.warmup_ns.len() == expected_warmup
        && result.warmup_observation_sha256.len() == expected_warmup
        && result.warmup_execution_artifact_sha256.len() == expected_warmup
        && result.warmup_counters.len() == expected_warmup
        && result.measured_ns.len() == expected_measured
        && result.measured_observation_sha256.len() == expected_measured
        && result.measured_execution_artifact_sha256.len() == expected_measured
        && result.measured_counters.len() == expected_measured
}

fn run_tier_control_case(
    case: &PerfCorpusCase,
    config: &TierControlConfig,
) -> (TierControlCaseResult, Vec<TierControlIterationEvent>) {
    let preparation_started = Instant::now();
    let prepared = HybridRouter::prepare_eval(case.source.as_str());
    let preparation_ns =
        u64::try_from(preparation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut production = empty_tier_control_arm(TierControlArm::ProductionTierI);
    let mut control = empty_tier_control_arm(TierControlArm::ForcedTierR);
    let mut equivalent = true;
    let mut equivalence_details = Vec::new();

    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let diagnostic = format!("engine preparation failed: {error}");
            production.status = PerfMeasurementStatus::Failed;
            control.status = PerfMeasurementStatus::Failed;
            production.diagnostics.push(diagnostic.clone());
            control.diagnostics.push(diagnostic.clone());
            return (
                TierControlCaseResult {
                    case_id: case.case_id.clone(),
                    source_sha256: sha256_hex(case.source.as_bytes()),
                    preparation_ns,
                    production,
                    control,
                    equivalent: false,
                    equivalence_detail: diagnostic.clone(),
                    tier_i_speedup_over_tier_r_millionths: None,
                    paired_speedup: None,
                    admitted: false,
                    exclusion_reasons: vec![diagnostic],
                },
                Vec::new(),
            );
        }
    };

    let mut pair_sequence = 0usize;
    let mut events = Vec::new();
    'phases: for (phase, count) in [
        (PerfPhase::Warmup, config.warmup_iterations),
        (PerfPhase::Measured, config.measured_iterations),
    ] {
        for index in 0..count {
            let current_pair_sequence = pair_sequence;
            let production_first = current_pair_sequence.is_multiple_of(2);
            pair_sequence = pair_sequence.saturating_add(1);
            let run_production = || {
                execute_tier_control_arm(
                    &prepared,
                    config.engine_instruction_budget,
                    PreparedTierDispatchPolicy::Production,
                )
            };
            let run_control = || {
                execute_tier_control_arm(
                    &prepared,
                    config.engine_instruction_budget,
                    PreparedTierDispatchPolicy::ForceTierR,
                )
            };
            let (production_run, control_run) = if production_first {
                (run_production(), run_control())
            } else {
                let control_run = run_control();
                let production_run = run_production();
                (production_run, control_run)
            };
            let (production_ns, production_observation) = production_run;
            let (control_ns, control_observation) = control_run;
            let (production_observation, control_observation) =
                match (production_observation, control_observation) {
                    (Ok(production_observation), Ok(control_observation)) => {
                        (production_observation, control_observation)
                    }
                    (production_observation, control_observation) => {
                        let detail = format!(
                            "matched pair {phase:?}/{index} failed: production={:?}; control={:?}",
                            production_observation.as_ref().err(),
                            control_observation.as_ref().err()
                        );
                        production.status = PerfMeasurementStatus::Failed;
                        control.status = PerfMeasurementStatus::Failed;
                        production.diagnostics.push(detail.clone());
                        control.diagnostics.push(detail.clone());
                        equivalent = false;
                        equivalence_details.push(detail);
                        break 'phases;
                    }
                };

            let production_artifact_sha256 =
                production_observation.tier_neutral_execution_artifact_sha256;
            let control_artifact_sha256 =
                control_observation.tier_neutral_execution_artifact_sha256;
            let production_outcome = production_observation.outcome;
            let control_outcome = control_observation.outcome;

            let production_counters = TierExecutionCounters::from(&production_outcome);
            let control_counters = TierExecutionCounters::from(&control_outcome);
            if production_counters.tier_i_specialized_instructions_executed
                > production_counters.tier_i_instructions_executed
                || production_counters.tier_i_instructions_executed
                    > production_counters.instructions_executed
                || production_counters.tier_i_instructions_executed == 0
            {
                equivalent = false;
                equivalence_details.push(format!(
                    "production pair {phase:?}/{index} did not execute valid Tier-I counters: {production_counters:?}"
                ));
            }
            if control_counters.tier_i_instructions_executed != 0
                || control_counters.tier_i_specialized_instructions_executed != 0
            {
                equivalent = false;
                equivalence_details.push(format!(
                    "forced Tier-R pair {phase:?}/{index} executed Tier-I counters: {control_counters:?}"
                ));
            }
            if production_counters.instructions_executed != control_counters.instructions_executed {
                equivalent = false;
                equivalence_details.push(format!(
                    "pair {phase:?}/{index} instruction totals differ: production={}, control={}",
                    production_counters.instructions_executed,
                    control_counters.instructions_executed
                ));
            }
            if !tier_neutral_outcomes_equal(&production_outcome, &control_outcome) {
                equivalent = false;
                equivalence_details.push(format!(
                    "pair {phase:?}/{index} outcomes differ after removing Tier-I counters"
                ));
            }
            let (production_observation, production_observation_complete) =
                tier_control_observation_sha256(&production_outcome);
            let (control_observation, control_observation_complete) =
                tier_control_observation_sha256(&control_outcome);
            if production_observation != control_observation {
                equivalent = false;
                equivalence_details
                    .push(format!("pair {phase:?}/{index} observation digests differ"));
            }
            if production_artifact_sha256 != control_artifact_sha256 {
                equivalent = false;
                equivalence_details.push(format!(
                    "pair {phase:?}/{index} replay/security artifact digests differ"
                ));
            }

            let event_index = index;
            let pair_sequence_u32 = u32::try_from(current_pair_sequence).unwrap_or(u32::MAX);
            let production_event = TierControlIterationEvent {
                event: "tier-control.iteration".to_string(),
                case_id: case.case_id.clone(),
                arm: TierControlArm::ProductionTierI,
                phase,
                index: event_index,
                pair_sequence: pair_sequence_u32,
                order_in_pair: if production_first { 0 } else { 1 },
                duration_ns: production_ns,
                counters: production_counters,
                execution_artifact_sha256: production_artifact_sha256.clone(),
            };
            let control_event = TierControlIterationEvent {
                event: "tier-control.iteration".to_string(),
                case_id: case.case_id.clone(),
                arm: TierControlArm::ForcedTierR,
                phase,
                index: event_index,
                pair_sequence: pair_sequence_u32,
                order_in_pair: if production_first { 1 } else { 0 },
                duration_ns: control_ns,
                counters: control_counters,
                execution_artifact_sha256: control_artifact_sha256.clone(),
            };
            if production_first {
                events.extend([production_event, control_event]);
            } else {
                events.extend([control_event, production_event]);
            }
            record_tier_control_observation(
                &mut production,
                TierControlObservationRecord {
                    phase,
                    duration_ns: production_ns,
                    observation_sha256: production_observation,
                    execution_artifact_sha256: production_artifact_sha256,
                    observation_complete: production_observation_complete,
                    counters: production_counters,
                    engine_kind: production_outcome.engine,
                    route_reason: production_outcome.route_reason,
                },
            );
            record_tier_control_observation(
                &mut control,
                TierControlObservationRecord {
                    phase,
                    duration_ns: control_ns,
                    observation_sha256: control_observation,
                    execution_artifact_sha256: control_artifact_sha256,
                    observation_complete: control_observation_complete,
                    counters: control_counters,
                    engine_kind: control_outcome.engine,
                    route_reason: control_outcome.route_reason,
                },
            );
        }
    }

    production.stats = compute_sample_stats(&production.measured_ns);
    control.stats = compute_sample_stats(&control.measured_ns);
    let mut exclusion_reasons = equivalence_details.clone();
    if config.warmup_iterations == 0 {
        exclusion_reasons.push("warmup protocol requires at least one iteration".to_string());
    }
    if config.measured_iterations < 10 {
        exclusion_reasons.push(format!(
            "measured_iterations={} is below the minimum sample floor of 10",
            config.measured_iterations
        ));
    }
    for (label, result) in [("production", &production), ("control", &control)] {
        if result.status != PerfMeasurementStatus::Measured {
            exclusion_reasons.push(format!("{label} arm did not complete"));
        }
        if !tier_control_vectors_complete(result, config) {
            exclusion_reasons.push(format!(
                "{label} timing, observation, or counter vectors are incomplete"
            ));
        }
        if !result.observations_complete {
            exclusion_reasons.push(format!("{label} observations are incomplete"));
        }
        if result
            .stats
            .as_ref()
            .is_none_or(|stats| stats.cv_millionths > config.max_cv_millionths)
        {
            exclusion_reasons.push(format!(
                "{label} CV is unavailable or exceeds {} millionths",
                config.max_cv_millionths
            ));
        }
    }
    if production.engine_kind != control.engine_kind
        || production.route_reason != control.route_reason
    {
        exclusion_reasons.push("engine kind or route reason differs between arms".to_string());
    }
    let speedup = match (production.stats.as_ref(), control.stats.as_ref()) {
        (Some(production_stats), Some(control_stats))
            if production_stats.mean_ns > 0 && control_stats.mean_ns > 0 =>
        {
            speedup_millionths(production_stats.mean_ns, control_stats.mean_ns)
        }
        _ => None,
    };
    if speedup.is_none() {
        exclusion_reasons.push("matched means did not yield a positive finite ratio".to_string());
    }
    let paired_stats = paired_speedup(
        &production.measured_ns,
        &control.measured_ns,
        "per_case_paired_log_ratio_conservative_student_t_95pct_t_2_262",
    );
    if paired_stats.is_none() {
        exclusion_reasons.push(
            "matched samples did not yield a finite positive paired log-ratio interval".to_string(),
        );
    }
    exclusion_reasons.sort();
    exclusion_reasons.dedup();
    let admitted = equivalent && exclusion_reasons.is_empty();
    let equivalence_detail = if equivalence_details.is_empty() {
        "every paired Tier-I/Tier-R outcome, replay/security artifact, instruction total, route, and observation matched".to_string()
    } else {
        equivalence_details.join("; ")
    };

    (
        TierControlCaseResult {
            case_id: case.case_id.clone(),
            source_sha256: sha256_hex(case.source.as_bytes()),
            preparation_ns,
            production,
            control,
            equivalent,
            equivalence_detail,
            tier_i_speedup_over_tier_r_millionths: if admitted { speedup } else { None },
            paired_speedup: if admitted { paired_stats } else { None },
            admitted,
            exclusion_reasons,
        },
        events,
    )
}

fn current_executable_sha256() -> Option<String> {
    #[cfg(target_os = "linux")]
    let bytes = fs::read("/proc/self/exe").ok()?;
    #[cfg(not(target_os = "linux"))]
    let bytes = {
        let executable = std::env::current_exe().ok()?;
        fs::read(executable).ok()?
    };
    Some(sha256_hex(&bytes))
}

fn linux_process_status_field(field: &str) -> Option<String> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix(field)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn affinity_is_exactly_one_cpu(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(',')
        && !value.contains('-')
        && value.parse::<u32>().is_ok()
}

fn required_tier_control_case_identities() -> Vec<TierControlCaseIdentity> {
    TIER_CONTROL_REQUIRED_CASE_SOURCES_SHA256
        .iter()
        .map(|(case_id, source_sha256)| TierControlCaseIdentity {
            case_id: (*case_id).to_string(),
            source_sha256: (*source_sha256).to_string(),
        })
        .collect()
}

fn tier_control_case_identities(corpus: &[PerfCorpusCase]) -> Vec<TierControlCaseIdentity> {
    corpus
        .iter()
        .map(|case| TierControlCaseIdentity {
            case_id: case.case_id.clone(),
            source_sha256: sha256_hex(case.source.as_bytes()),
        })
        .collect()
}

fn tier_control_decision_policy_complete(config: &TierControlConfig) -> bool {
    config.warmup_iterations == TIER_CONTROL_DECISION_WARMUP_ITERATIONS
        && config.measured_iterations == TIER_CONTROL_DECISION_MEASURED_ITERATIONS
        && config.max_cv_millionths == TIER_CONTROL_DECISION_MAX_CV_MILLIONTHS
        && config.engine_instruction_budget == DEFAULT_PERF_ENGINE_INSTRUCTION_BUDGET
}

fn tier_control_decision_build_complete() -> bool {
    CARGO_BUILD_PROFILE_CLASS == "release"
        && CARGO_BUILD_PROFILE_DIRECTORY == "release-perf"
        && CARGO_BUILD_OPT_LEVEL == "3"
        && !cfg!(debug_assertions)
}

fn aggregate_tier_control_paired_speedup(
    cases: &[TierControlCaseResult],
) -> Option<TierControlPairedSpeedup> {
    let pair_count = cases.first()?.paired_speedup.as_ref()?.pair_count;
    if pair_count < 2
        || cases.iter().any(|case| {
            !case.admitted
                || case
                    .paired_speedup
                    .as_ref()
                    .is_none_or(|speedup| speedup.pair_count != pair_count)
        })
    {
        return None;
    }

    let mut aggregate_log_ratios = Vec::with_capacity(pair_count);
    for index in 0..pair_count {
        let mut equal_case_log_sum = 0.0_f64;
        for case in cases {
            let production = *case.production.measured_ns.get(index)?;
            let control = *case.control.measured_ns.get(index)?;
            if production == 0 || control == 0 {
                return None;
            }
            equal_case_log_sum += (control as f64 / production as f64).ln();
        }
        aggregate_log_ratios.push(equal_case_log_sum / cases.len() as f64);
    }
    paired_speedup_from_log_ratios(
        &aggregate_log_ratios,
        "equal_case_geomean_of_paired_log_ratios_conservative_student_t_95pct_t_2_262",
    )
}

fn classify_tier_control_decision(
    publishable: bool,
    paired_speedup: Option<&TierControlPairedSpeedup>,
) -> TierControlDecision {
    if !publishable {
        return TierControlDecision::Degraded;
    }
    let Some(paired_speedup) = paired_speedup else {
        return TierControlDecision::Degraded;
    };
    if paired_speedup.ci95_lower_speedup_millionths >= TIER_CONTROL_KEEP_FLOOR_MILLIONTHS {
        TierControlDecision::Keep
    } else if paired_speedup.ci95_upper_speedup_millionths < TIER_CONTROL_KEEP_FLOOR_MILLIONTHS {
        TierControlDecision::Kill
    } else {
        TierControlDecision::Inconclusive
    }
}

fn tier_control_iteration_events_jsonl_sha256(
    events: &[TierControlIterationEvent],
) -> Option<String> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend_from_slice(&serde_json::to_vec(event).ok()?);
        bytes.push(b'\n');
    }
    Some(sha256_hex(&bytes))
}

/// Run the purpose-specific same-binary Tier-I treatment/control experiment.
/// This is independent of the Node/Bun v3 report and cannot promote
/// FE-CLAIM-010; it exists solely to decide whether the compact interpreter
/// tranche clears its predeclared 5% native keep floor.
pub fn run_tier_control_perf(
    corpus: &[PerfCorpusCase],
    config: &TierControlConfig,
) -> (TierControlPerfReport, Vec<TierControlIterationEvent>) {
    let generated_unix_ns = current_unix_ns();
    let required_case_identities = required_tier_control_case_identities();
    let selected_case_identities = tier_control_case_identities(corpus);
    let required_case_ids = required_case_identities
        .iter()
        .map(|identity| identity.case_id.clone())
        .collect::<Vec<_>>();
    let selected_case_ids = selected_case_identities
        .iter()
        .map(|identity| identity.case_id.clone())
        .collect::<Vec<_>>();
    let decision_corpus_complete = selected_case_identities == required_case_identities;
    let decision_policy_complete = tier_control_decision_policy_complete(config);
    let decision_build_complete = tier_control_decision_build_complete();
    let decision_scope_complete =
        decision_corpus_complete && decision_policy_complete && decision_build_complete;
    let environment = TierControlEnvironment {
        host: capture_host_facts(),
        executable_sha256: current_executable_sha256(),
        cpu_affinity: linux_process_status_field("Cpus_allowed_list:"),
        numa_memory_affinity: linux_process_status_field("Mems_allowed_list:"),
        load_avg_1m_millionths: read_load_avg_1m_millionths(),
        cpu_governor: read_cpu_governor(),
        warmup_iterations: config.warmup_iterations,
        measured_iterations: config.measured_iterations,
        max_cv_millionths: config.max_cv_millionths,
        engine_instruction_budget: config.engine_instruction_budget,
        cargo_profile_class: CARGO_BUILD_PROFILE_CLASS.to_string(),
        cargo_profile_directory: CARGO_BUILD_PROFILE_DIRECTORY.to_string(),
        cargo_opt_level: CARGO_BUILD_OPT_LEVEL.to_string(),
        cargo_debug_info: CARGO_BUILD_DEBUG_INFO.to_string(),
        debug_assertions_enabled: cfg!(debug_assertions),
        decision_corpus_complete,
        decision_policy_complete,
        decision_build_complete,
        decision_scope_complete,
        required_case_ids,
        selected_case_ids,
        required_case_identities,
        selected_case_identities,
        lifecycle: "prepare_once_fresh_router_and_interpreter_core_per_arm_invocation".to_string(),
        pair_order: "alternating_production_first_then_control_first_by_pair_sequence".to_string(),
        execution_artifact_projection: "tier-neutral positional projection of every ExecutionResult field except tier_i_instructions_executed and tier_i_specialized_instructions_executed".to_string(),
        corpus_case_count: corpus.len(),
        corpus_sha256: corpus_sha256(corpus),
        generated_unix_ns,
    };
    let mut cases = Vec::with_capacity(corpus.len());
    let mut events = Vec::new();
    for case in corpus {
        let (result, mut case_events) = run_tier_control_case(case, config);
        cases.push(result);
        events.append(&mut case_events);
    }
    let iteration_events_jsonl_sha256 = tier_control_iteration_events_jsonl_sha256(&events);
    let ratios = cases
        .iter()
        .filter(|case| case.admitted)
        .filter_map(|case| case.tier_i_speedup_over_tier_r_millionths)
        .collect::<Vec<_>>();
    let paired_speedup = aggregate_tier_control_paired_speedup(&cases);
    let mut degraded_reasons = Vec::new();
    if ratios.is_empty() {
        degraded_reasons.push("no case satisfied the matched-control admission rules".to_string());
    }
    if ratios.len() != cases.len() {
        degraded_reasons.push(format!(
            "only {}/{} selected cases satisfied every admission rule",
            ratios.len(),
            cases.len()
        ));
    }
    if !ratios.is_empty() && paired_speedup.is_none() {
        degraded_reasons.push(
            "admitted paired samples did not yield an aggregate log-ratio confidence interval"
                .to_string(),
        );
    }
    if !environment.decision_corpus_complete {
        degraded_reasons.push(
            "selected case IDs and source hashes do not exactly match the predeclared Tier-control decision denominator"
                .to_string(),
        );
    }
    if !environment.decision_policy_complete {
        degraded_reasons.push(
            "measurement policy does not exactly match the predeclared Tier-control decision protocol"
                .to_string(),
        );
    }
    if !environment.decision_build_complete {
        degraded_reasons.push(
            "executable was not built by Cargo profile release-perf at effective opt-level 3 with debug assertions disabled"
                .to_string(),
        );
    }
    if environment.executable_sha256.is_none() {
        degraded_reasons.push("exact current executable SHA-256 could not be captured".to_string());
    }
    if iteration_events_jsonl_sha256.is_none() {
        degraded_reasons.push("iteration event stream could not be encoded and hashed".to_string());
    }
    if environment.host.os != "linux" {
        degraded_reasons
            .push("the decision-bearing Tier-control protocol is currently Linux-only".to_string());
    } else {
        if environment
            .cpu_affinity
            .as_deref()
            .is_none_or(|affinity| !affinity_is_exactly_one_cpu(affinity))
        {
            degraded_reasons.push(
                "Linux decision runs require affinity to exactly one recorded logical CPU"
                    .to_string(),
            );
        }
        if environment.numa_memory_affinity.is_none() {
            degraded_reasons.push(
                "Linux NUMA-memory affinity could not be captured from /proc/self/status"
                    .to_string(),
            );
        }
    }
    let publishable = !cases.is_empty()
        && ratios.len() == cases.len()
        && paired_speedup.is_some()
        && iteration_events_jsonl_sha256.is_some()
        && degraded_reasons.is_empty();
    let decision = classify_tier_control_decision(publishable, paired_speedup.as_ref());
    let summary = TierControlSummary {
        admitted_cases: ratios.len(),
        excluded_cases: cases.len().saturating_sub(ratios.len()),
        geomean_speedup_millionths: if publishable {
            paired_speedup
                .as_ref()
                .map(|speedup| speedup.geomean_speedup_millionths)
        } else {
            None
        },
        meets_keep_floor: match decision {
            TierControlDecision::Keep => Some(true),
            TierControlDecision::Kill => Some(false),
            TierControlDecision::Inconclusive | TierControlDecision::Degraded => None,
        },
        decision,
        paired_speedup: if publishable { paired_speedup } else { None },
        keep_floor_millionths: TIER_CONTROL_KEEP_FLOOR_MILLIONTHS,
        degraded_reasons,
    };
    (
        TierControlPerfReport {
            schema_version: TIER_CONTROL_PERF_SCHEMA_VERSION.to_string(),
            generated_unix_ns,
            environment,
            cases,
            iteration_event_count: events.len(),
            iteration_events_jsonl_sha256,
            summary,
        },
        events,
    )
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Runs the full performance arm over a corpus. Returns the report plus the
/// raw per-iteration event stream for `events.jsonl`.
pub fn run_differential_perf(
    corpus: &[PerfCorpusCase],
    config: &PerfArmConfig,
) -> (DifferentialPerfReport, Vec<PerfIterationEvent>) {
    let environment = capture_perf_environment(config, corpus);
    let fairness = evaluate_fairness(&environment, config);

    let mut events = Vec::new();
    let mut case_results = Vec::new();
    for case in corpus {
        let (behavior_equivalent, equivalence_detail) = check_behavior_equivalence(case, config);
        let engine = run_engine_perf_case(case.source.as_str(), config);
        let node = run_external_perf_case(&config.node, case.source.as_str(), config);
        let bun = run_external_perf_case(&config.bun, case.source.as_str(), config);
        let (measured_lifecycle_equivalent, measured_lifecycle_detail) =
            measured_lifecycle_equivalence(&engine, &node, &bun);

        for (backend_result, backend) in [
            (&engine, DifferentialBackend::FrankenEngine),
            (&node, DifferentialBackend::NodeLts),
            (&bun, DifferentialBackend::BunStable),
        ] {
            if let Some(duration_ns) = backend_result.preparation_ns {
                events.push(PerfIterationEvent {
                    event: "diffperf.iteration".to_string(),
                    case_id: case.case_id.clone(),
                    backend,
                    phase: PerfPhase::Preparation,
                    index: 0,
                    duration_ns,
                });
            }
            for (phase, samples) in [
                (PerfPhase::Warmup, &backend_result.warmup_ns),
                (PerfPhase::Measured, &backend_result.measured_ns),
            ] {
                for (index, &duration_ns) in samples.iter().enumerate() {
                    events.push(PerfIterationEvent {
                        event: "diffperf.iteration".to_string(),
                        case_id: case.case_id.clone(),
                        backend,
                        phase,
                        index: u32::try_from(index).unwrap_or(u32::MAX),
                        duration_ns,
                    });
                }
            }
        }

        let node_ratio = case_speedup(&engine, &node);
        let bun_ratio = case_speedup(&engine, &bun);
        let mut exclusion_reasons = Vec::new();
        if !behavior_equivalent {
            exclusion_reasons.push(equivalence_detail.clone());
        }
        if !measured_lifecycle_equivalent {
            exclusion_reasons.push(measured_lifecycle_detail.clone());
        }
        for (label, result) in [("engine", &engine), ("node", &node), ("bun", &bun)] {
            if result.status != PerfMeasurementStatus::Measured {
                exclusion_reasons.push(format!(
                    "{label} lane status {:?} prevented measurement",
                    result.status
                ));
            } else if let Some(stats) = result.stats.as_ref()
                && stats.cv_millionths > config.max_cv_millionths
            {
                exclusion_reasons.push(format!(
                    "{label} lane cv {} millionths exceeds the {} millionths bar",
                    stats.cv_millionths, config.max_cv_millionths
                ));
            }
        }
        let admitted = exclusion_reasons.is_empty();
        case_results.push(PerfCaseResult {
            case_id: case.case_id.clone(),
            source_sha256: sha256_hex(case.source.as_bytes()),
            behavior_equivalent,
            equivalence_detail,
            measured_lifecycle_equivalent,
            measured_lifecycle_detail,
            engine,
            node,
            bun,
            node_over_engine_speedup_millionths: node_ratio,
            bun_over_engine_speedup_millionths: bun_ratio,
            admitted,
            exclusion_reasons,
        });
    }

    let node_denominator = build_denominator(
        &case_results,
        DifferentialBackend::NodeLts,
        &fairness,
        config,
    );
    let bun_denominator = build_denominator(
        &case_results,
        DifferentialBackend::BunStable,
        &fairness,
        config,
    );

    (
        DifferentialPerfReport {
            schema_version: DIFFERENTIAL_PERF_SCHEMA_VERSION.to_string(),
            generated_unix_ns: current_unix_ns(),
            environment,
            fairness,
            cases: case_results,
            node_denominator,
            bun_denominator,
        },
        events,
    )
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ComparisonManifestCase {
    benchmark_id: String,
    program_path: String,
}

#[derive(Debug, Deserialize)]
struct ComparisonManifest {
    cases: Vec<ComparisonManifestCase>,
}

/// Loads the `benchmarks/runtime_comparison/manifest.json` corpus: each case's
/// program file is read relative to the manifest's directory. Case ids are
/// returned in manifest order; duplicates are rejected.
pub fn load_runtime_comparison_corpus(manifest_path: &Path) -> Result<Vec<PerfCorpusCase>, String> {
    let manifest_text = fs::read_to_string(manifest_path).map_err(|error| {
        format!(
            "failed to read manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: ComparisonManifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("malformed manifest {}: {error}", manifest_path.display()))?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut seen = BTreeMap::new();
    let mut corpus = Vec::with_capacity(manifest.cases.len());
    for case in manifest.cases {
        if seen.insert(case.benchmark_id.clone(), ()).is_some() {
            return Err(format!("duplicate benchmark_id `{}`", case.benchmark_id));
        }
        let program = base.join(&case.program_path);
        let source = fs::read_to_string(&program)
            .map_err(|error| format!("failed to read {}: {error}", program.display()))?;
        corpus.push(PerfCorpusCase::new(case.benchmark_id, source));
    }
    Ok(corpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured_result(backend: DifferentialBackend, samples: &[u64]) -> PerfBackendCaseResult {
        PerfBackendCaseResult {
            backend,
            status: PerfMeasurementStatus::Measured,
            resolved_program: None,
            version: Some("test".to_string()),
            preparation_ns: Some(1),
            engine_kind: (backend == DifferentialBackend::FrankenEngine)
                .then_some(EngineKind::QuickJsInspiredNative),
            route_reason: (backend == DifferentialBackend::FrankenEngine)
                .then_some(RouteReason::DefaultQuickJsPath),
            warmup_ns: Vec::new(),
            measured_ns: samples.to_vec(),
            warmup_observation_sha256: Vec::new(),
            measured_observation_sha256: vec!["digest".to_string(); samples.len()],
            observations_complete: true,
            stats: compute_sample_stats(samples),
            diagnostics: Vec::new(),
        }
    }

    fn equivalent_case(
        case_id: &str,
        engine_ns: &[u64],
        node_ns: &[u64],
        bun_ns: &[u64],
    ) -> PerfCaseResult {
        let engine = measured_result(DifferentialBackend::FrankenEngine, engine_ns);
        let node = measured_result(DifferentialBackend::NodeLts, node_ns);
        let bun = measured_result(DifferentialBackend::BunStable, bun_ns);
        let node_ratio = case_speedup(&engine, &node);
        let bun_ratio = case_speedup(&engine, &bun);
        PerfCaseResult {
            case_id: case_id.to_string(),
            source_sha256: sha256_hex(case_id.as_bytes()),
            behavior_equivalent: true,
            equivalence_detail: "test".to_string(),
            measured_lifecycle_equivalent: true,
            measured_lifecycle_detail: "test".to_string(),
            engine,
            node,
            bun,
            node_over_engine_speedup_millionths: node_ratio,
            bun_over_engine_speedup_millionths: bun_ratio,
            admitted: true,
            exclusion_reasons: Vec::new(),
        }
    }

    fn compliant_fairness() -> PerfFairnessReport {
        PerfFairnessReport {
            compliant: true,
            violations: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn harness_contains_sentinel_and_iteration_counts() {
        let harness = build_external_perf_harness("console.log(1);", 2, 7);
        assert!(harness.contains(PERF_HARNESS_SENTINEL));
        assert!(harness.contains("i < 2"));
        assert!(harness.contains("i < 7"));
        assert!(harness.contains("const completion = __feFn()"));
        assert!(harness.contains("__feObservation(completion)"));
    }

    #[test]
    fn harness_json_escapes_source() {
        let harness = build_external_perf_harness("var s = \"quoted\";\nconsole.log(s);", 1, 1);
        assert!(harness.contains("\\\"quoted\\\""));
        assert!(harness.contains("\\n"));
    }

    #[test]
    fn harness_compiles_source_once() {
        let harness = build_external_perf_harness("1 + 1;", 1, 1);
        assert_eq!(harness.matches("new Function").count(), 1);
        assert!(harness.contains("__fePreparationNs"));
    }

    #[test]
    fn parse_harness_output_happy_path() {
        let warmup_observation =
            serde_json::to_string(&["5\n", "", "undefined", "undefined"]).expect("observation");
        let measured_observation =
            serde_json::to_string(&["10\n", "", "undefined", "undefined"]).expect("observation");
        let stdout = format!(
            "workload noise\n{PERF_HARNESS_SENTINEL}{}\n",
            serde_json::json!({
                "preparation_ns": 3,
                "warmup_ns": [5],
                "measured_ns": [10, 11],
                "warmup_observations": [warmup_observation],
                "measured_observations": [measured_observation.clone(), measured_observation],
                "sink": 3,
            })
        );
        let parsed = parse_perf_harness_output(&stdout).expect("parse");
        assert_eq!(parsed.preparation_ns, 3);
        assert_eq!(parsed.warmup_ns, vec![5]);
        assert_eq!(parsed.measured_ns, vec![10, 11]);
        assert!(parsed.observations_complete);
        assert_eq!(parsed.warmup_observation_sha256.len(), 1);
        assert_eq!(parsed.measured_observation_sha256.len(), 2);
    }

    #[test]
    fn parse_harness_output_requires_sentinel() {
        let error = parse_perf_harness_output("no sentinel here").unwrap_err();
        assert!(error.contains("sentinel"));
    }

    #[test]
    fn parse_harness_output_rejects_malformed_json() {
        let stdout = format!("{PERF_HARNESS_SENTINEL}{{not json");
        let error = parse_perf_harness_output(&stdout).unwrap_err();
        assert!(error.contains("malformed"));
    }

    #[test]
    fn parse_harness_output_rejects_timing_observation_length_mismatch() {
        let stdout = format!(
            "{PERF_HARNESS_SENTINEL}{{\"preparation_ns\":1,\"warmup_ns\":[1],\"measured_ns\":[2],\"warmup_observations\":[],\"measured_observations\":[\"2\\u0000\"]}}"
        );
        let error = parse_perf_harness_output(&stdout).unwrap_err();
        assert!(error.contains("lengths differ"));
    }

    #[test]
    fn parse_harness_output_marks_malformed_observation_incomplete() {
        let stdout = format!(
            "{PERF_HARNESS_SENTINEL}{{\"preparation_ns\":1,\"warmup_ns\":[],\"measured_ns\":[2],\"warmup_observations\":[],\"measured_observations\":[\"console-only\"]}}"
        );
        let parsed = parse_perf_harness_output(&stdout).expect("parse shape");
        assert!(!parsed.observations_complete);
    }

    #[test]
    fn parse_harness_output_rejects_non_undefined_function_return() {
        let observation = serde_json::to_string(&["", "", "number", "1"]).expect("observation");
        let stdout = format!(
            "{PERF_HARNESS_SENTINEL}{}",
            serde_json::json!({
                "preparation_ns": 1,
                "warmup_ns": [],
                "measured_ns": [2],
                "warmup_observations": [],
                "measured_observations": [observation],
            })
        );
        let parsed = parse_perf_harness_output(&stdout).expect("parse shape");
        assert!(!parsed.observations_complete);
    }

    #[test]
    fn requested_sample_counts_are_exact() {
        let parsed = ParsedPerfHarnessOutput {
            preparation_ns: 1,
            warmup_ns: vec![1],
            measured_ns: vec![2, 3],
            warmup_observation_sha256: vec!["a".repeat(64)],
            measured_observation_sha256: vec!["b".repeat(64), "c".repeat(64)],
            observations_complete: true,
        };
        validate_harness_sample_counts(&parsed, 1, 2).expect("exact counts");
        let error = validate_harness_sample_counts(&parsed, 2, 2).unwrap_err();
        assert!(error.contains("differ from request"));
        let error = validate_harness_sample_counts(&parsed, 1, 3).unwrap_err();
        assert!(error.contains("differ from request"));
    }

    #[test]
    fn parse_harness_output_uses_last_sentinel_line() {
        let observation =
            serde_json::to_string(&["1\n", "", "undefined", "undefined"]).expect("observation");
        let stdout = format!(
            "{PERF_HARNESS_SENTINEL}{}\n{PERF_HARNESS_SENTINEL}{}\n",
            serde_json::json!({
                "preparation_ns": 1,
                "warmup_ns": [1],
                "measured_ns": [1],
                "warmup_observations": [observation.clone()],
                "measured_observations": [observation.clone()],
                "sink": 0,
            }),
            serde_json::json!({
                "preparation_ns": 2,
                "warmup_ns": [2],
                "measured_ns": [9],
                "warmup_observations": [observation.clone()],
                "measured_observations": [observation],
                "sink": 0,
            })
        );
        let parsed = parse_perf_harness_output(&stdout).expect("parse");
        assert_eq!(parsed.preparation_ns, 2);
        assert_eq!(parsed.warmup_ns, vec![2]);
        assert_eq!(parsed.measured_ns, vec![9]);
    }

    #[test]
    fn stats_empty_input_is_none() {
        assert!(compute_sample_stats(&[]).is_none());
    }

    #[test]
    fn stats_single_sample_has_zero_spread() {
        let stats = compute_sample_stats(&[1_000]).expect("stats");
        assert_eq!(stats.mean_ns, 1_000);
        assert_eq!(stats.stddev_ns, 0);
        assert_eq!(stats.cv_millionths, 0);
        assert_eq!(stats.ci95_lower_ns, 1_000);
        assert_eq!(stats.ci95_upper_ns, 1_000);
    }

    #[test]
    fn measured_lifecycle_equivalence_requires_stable_cross_runtime_observations() {
        let engine = measured_result(DifferentialBackend::FrankenEngine, &[10, 11]);
        let node = measured_result(DifferentialBackend::NodeLts, &[5, 6]);
        let bun = measured_result(DifferentialBackend::BunStable, &[4, 5]);
        let (equivalent, detail) = measured_lifecycle_equivalence(&engine, &node, &bun);
        assert!(equivalent, "{detail}");

        let mut changing_node = node.clone();
        changing_node.measured_observation_sha256[1] = "changed".to_string();
        let (equivalent, detail) = measured_lifecycle_equivalence(&engine, &changing_node, &bun);
        assert!(!equivalent);
        assert!(detail.contains("changed between"));

        let mut missing_bun = bun;
        missing_bun.observations_complete = false;
        let (equivalent, detail) = measured_lifecycle_equivalence(&engine, &node, &missing_bun);
        assert!(!equivalent);
        assert!(detail.contains("without a complete console/completion observation"));
    }

    #[test]
    fn engine_observation_fails_closed_for_non_undefined_completion() {
        let mut router = HybridRouter::default();
        let number = router.eval("1;").expect("number completion");
        let string = router.eval("'1';").expect("string completion");
        assert!(number.console_output.is_empty());
        assert!(string.console_output.is_empty());
        let (number_digest, number_complete) = engine_observation_sha256(&number);
        let (string_digest, string_complete) = engine_observation_sha256(&string);
        assert!(!number_complete);
        assert!(!string_complete);
        assert_eq!(number_digest.len(), 64);
        assert_eq!(string_digest.len(), 64);

        let undefined = router.eval("undefined;").expect("undefined completion");
        let (undefined_digest, undefined_complete) = engine_observation_sha256(&undefined);
        assert!(undefined_complete);
        assert_eq!(undefined_digest.len(), 64);
    }

    #[test]
    fn stats_known_values() {
        // mean 200, sample variance ((100)^2 + 0 + (100)^2) / 2 = 10000 -> stddev 100.
        let stats = compute_sample_stats(&[100, 200, 300]).expect("stats");
        assert_eq!(stats.mean_ns, 200);
        assert_eq!(stats.stddev_ns, 100);
        assert_eq!(stats.cv_millionths, 500_000);
        assert_eq!(stats.min_ns, 100);
        assert_eq!(stats.max_ns, 300);
    }

    #[test]
    fn stats_ci_brackets_mean() {
        let stats = compute_sample_stats(&[90, 100, 110, 95, 105]).expect("stats");
        assert!(stats.ci95_lower_ns <= stats.mean_ns);
        assert!(stats.ci95_upper_ns >= stats.mean_ns);
        assert!(stats.ci95_lower_ns > 0);
    }

    #[test]
    fn isqrt_edge_cases() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(15), 3);
        assert_eq!(isqrt_u128(16), 4);
        assert_eq!(isqrt_u128(1_000_000_000_000), 1_000_000);
    }

    #[test]
    fn speedup_exact_two_x() {
        assert_eq!(speedup_millionths(100, 200), Some(2_000_000));
    }

    #[test]
    fn speedup_engine_slower_is_below_one() {
        assert_eq!(speedup_millionths(200, 100), Some(500_000));
    }

    #[test]
    fn speedup_zero_engine_mean_is_none() {
        assert_eq!(speedup_millionths(0, 100), None);
    }

    #[test]
    fn geomean_of_two_and_eight_is_four() {
        let gm = geometric_mean_millionths(&[2_000_000, 8_000_000]).expect("gm");
        assert!((gm as i64 - 4_000_000).abs() <= 1, "gm={gm}");
    }

    #[test]
    fn geomean_empty_is_none() {
        assert!(geometric_mean_millionths(&[]).is_none());
    }

    #[test]
    fn geomean_zero_ratio_is_none() {
        assert!(geometric_mean_millionths(&[0, 2_000_000]).is_none());
    }

    #[test]
    fn parse_decimal_millionths_variants() {
        assert_eq!(parse_decimal_millionths("12.34"), Some(12_340_000));
        assert_eq!(parse_decimal_millionths("0.5"), Some(500_000));
        assert_eq!(parse_decimal_millionths("7"), Some(7_000_000));
        assert_eq!(parse_decimal_millionths(""), None);
        assert_eq!(parse_decimal_millionths("not-a-number"), None);
    }

    #[test]
    fn denominator_publishes_and_checks_floor() {
        let cases = vec![
            equivalent_case("a", &[100; 12], &[400; 12], &[200; 12]),
            equivalent_case("b", &[100; 12], &[900; 12], &[400; 12]),
        ];
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &cases,
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.status, PerfDenominatorStatus::Published);
        assert_eq!(node.admitted_cases, 2);
        // geomean(4x, 9x) = 6x.
        assert_eq!(node.geomean_speedup_millionths, Some(6_000_000));
        assert_eq!(node.meets_3x_floor, Some(true));
    }

    #[test]
    fn denominator_honest_below_floor() {
        let cases = vec![equivalent_case("a", &[400; 12], &[200; 12], &[100; 12])];
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &cases,
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.status, PerfDenominatorStatus::Published);
        assert_eq!(node.geomean_speedup_millionths, Some(500_000));
        assert_eq!(node.meets_3x_floor, Some(false));
    }

    #[test]
    fn denominator_degrades_when_positive_geomean_is_undefined() {
        let cases = vec![equivalent_case("a", &[u64::MAX; 12], &[0; 12], &[0; 12])];
        let node = build_denominator(
            &cases,
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &PerfArmConfig::default(),
        );
        assert_eq!(node.admitted_cases, 1);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
        assert_eq!(node.geomean_speedup_millionths, None);
        assert_eq!(node.meets_3x_floor, None);
    }

    #[test]
    fn denominator_excludes_non_equivalent_case() {
        let mut case = equivalent_case("a", &[100; 12], &[400; 12], &[200; 12]);
        case.behavior_equivalent = false;
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &[case],
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.admitted_cases, 0);
        assert_eq!(node.excluded_cases, 1);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
    }

    #[test]
    fn denominator_excludes_high_cv_case() {
        // Wildly bimodal engine samples blow through the 15% CV bar.
        let case = equivalent_case(
            "a",
            &[
                100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000,
            ],
            &[400; 12],
            &[200; 12],
        );
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &[case],
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.admitted_cases, 0);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
    }

    #[test]
    fn denominator_degraded_when_fairness_violated() {
        let cases = vec![equivalent_case("a", &[100; 12], &[400; 12], &[200; 12])];
        let fairness = PerfFairnessReport {
            compliant: false,
            violations: vec!["node binary is bun shim".to_string()],
            notes: Vec::new(),
        };
        let config = PerfArmConfig::default();
        let node = build_denominator(&cases, DifferentialBackend::NodeLts, &fairness, &config);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
        assert_eq!(node.geomean_speedup_millionths, None);
        assert_eq!(node.meets_3x_floor, None);
    }

    #[test]
    fn fairness_flags_zero_warmup() {
        let config = PerfArmConfig {
            warmup_iterations: 0,
            ..PerfArmConfig::default()
        };
        let environment = test_environment();
        let report = evaluate_fairness(&environment, &config);
        assert!(!report.compliant);
        assert!(report.violations.iter().any(|v| v.contains("warmup")));
    }

    #[test]
    fn fairness_flags_bun_shim_node() {
        let config = PerfArmConfig::default();
        let mut environment = test_environment();
        environment.node_genuine = Some(false);
        let report = evaluate_fairness(&environment, &config);
        assert!(!report.compliant);
        assert!(report.violations.iter().any(|v| v.contains("shim")));
    }

    #[test]
    fn fairness_rejects_asymmetric_runtime_lifecycle() {
        let config = PerfArmConfig::default();
        let environment = test_environment();
        let report = evaluate_fairness(&environment, &config);
        assert!(!report.compliant);
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("not symmetric"))
        );
    }

    #[test]
    fn fairness_flags_engine_lifecycle_asymmetry() {
        let report = evaluate_fairness(&test_environment(), &PerfArmConfig::default());
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("fresh router/interpreter"))
        );
    }

    #[test]
    fn fairness_notes_record_budget_override() {
        let report = evaluate_fairness(&test_environment(), &PerfArmConfig::default());
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("instruction budget overridden to 2000000000"))
        );
    }

    #[test]
    fn default_engine_budget_executes_million_iteration_loop() {
        // The containment default (100K instructions) refuses this workload;
        // the perf default must let it complete so throughput is measurable.
        let config = PerfArmConfig {
            warmup_iterations: 0,
            measured_iterations: 1,
            ..PerfArmConfig::default()
        };
        let source = "var i = 0; var sum = 0;\n\
                      while (i < 1000000) { sum = sum + i; i = i + 1; }\n\
                      sum;";
        let result = run_engine_perf_case(source, &config);
        assert_eq!(
            result.status,
            PerfMeasurementStatus::Measured,
            "diagnostics: {:?}",
            result.diagnostics
        );
    }

    #[test]
    fn corpus_sha_is_length_prefixed() {
        // ("ab","c") and ("a","bc") must hash differently.
        let one = corpus_sha256(&[PerfCorpusCase::new("ab", "c")]);
        let two = corpus_sha256(&[PerfCorpusCase::new("a", "bc")]);
        assert_ne!(one, two);
    }

    #[test]
    fn engine_perf_case_measures_simple_source() {
        let config = PerfArmConfig {
            warmup_iterations: 1,
            measured_iterations: 3,
            ..PerfArmConfig::default()
        };
        let result = run_engine_perf_case("1 + 1;", &config);
        assert_eq!(result.status, PerfMeasurementStatus::Measured);
        assert_eq!(result.warmup_ns.len(), 1);
        assert_eq!(result.measured_ns.len(), 3);
        assert!(result.preparation_ns.is_some());
        assert!(result.stats.is_some());
    }

    #[test]
    fn engine_perf_case_reports_failure() {
        let config = PerfArmConfig {
            warmup_iterations: 1,
            measured_iterations: 2,
            ..PerfArmConfig::default()
        };
        let result = run_engine_perf_case("syntax error here (", &config);
        assert_eq!(result.status, PerfMeasurementStatus::Failed);
        assert!(result.preparation_ns.is_some());
        assert!(result.stats.is_none());
        assert!(!result.diagnostics.is_empty());
    }

    #[test]
    fn corpus_loader_reads_manifest_relative_programs() {
        let dir =
            std::env::temp_dir().join(format!("fe_diffperf_corpus_test_{}", std::process::id()));
        let programs = dir.join("programs");
        fs::create_dir_all(&programs).expect("mkdir");
        fs::write(programs.join("one.js"), "console.log(1);").expect("write program");
        let manifest = dir.join("manifest.json");
        fs::write(
            &manifest,
            "{\"cases\":[{\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"}]}",
        )
        .expect("write manifest");
        let corpus = load_runtime_comparison_corpus(&manifest).expect("load");
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus[0].case_id, "one");
        assert_eq!(corpus[0].source, "console.log(1);");
    }

    #[test]
    fn corpus_loader_rejects_duplicate_ids() {
        let dir = std::env::temp_dir().join(format!(
            "fe_diffperf_corpus_dup_test_{}",
            std::process::id()
        ));
        let programs = dir.join("programs");
        fs::create_dir_all(&programs).expect("mkdir");
        fs::write(programs.join("one.js"), "1;").expect("write program");
        let manifest = dir.join("manifest.json");
        fs::write(
            &manifest,
            "{\"cases\":[\
             {\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"},\
             {\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"}]}",
        )
        .expect("write manifest");
        let error = load_runtime_comparison_corpus(&manifest).unwrap_err();
        assert!(error.contains("duplicate"));
    }

    #[test]
    fn report_serde_round_trip() {
        let cases = vec![equivalent_case("a", &[100; 12], &[400; 12], &[200; 12])];
        let config = PerfArmConfig::default();
        let fairness = compliant_fairness();
        let node = build_denominator(&cases, DifferentialBackend::NodeLts, &fairness, &config);
        let bun = build_denominator(&cases, DifferentialBackend::BunStable, &fairness, &config);
        let report = DifferentialPerfReport {
            schema_version: DIFFERENTIAL_PERF_SCHEMA_VERSION.to_string(),
            generated_unix_ns: 42,
            environment: test_environment(),
            fairness,
            cases,
            node_denominator: node,
            bun_denominator: bun,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: DifferentialPerfReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn iteration_event_serializes_snake_case_phase() {
        let event = PerfIterationEvent {
            event: "diffperf.iteration".to_string(),
            case_id: "a".to_string(),
            backend: DifferentialBackend::NodeLts,
            phase: PerfPhase::Measured,
            index: 0,
            duration_ns: 5,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"measured\""));
        assert!(json.contains("node_lts"));
    }

    fn canonical_tier_control_corpus() -> Vec<PerfCorpusCase> {
        vec![
            PerfCorpusCase::new(
                "micro-arithmetic-loop",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_arithmetic_loop.js"
                ),
            ),
            PerfCorpusCase::new(
                "micro-function-calls",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_function_calls.js"
                ),
            ),
            PerfCorpusCase::new(
                "micro-object-property-access",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_object_property_access.js"
                ),
            ),
            PerfCorpusCase::new(
                "micro-array-indexing",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_array_indexing.js"
                ),
            ),
            PerfCorpusCase::new(
                "micro-bitwise-ops",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_bitwise_ops.js"
                ),
            ),
            PerfCorpusCase::new(
                "micro-modulo-ops",
                include_str!("../../../benchmarks/runtime_comparison/programs/micro_modulo_ops.js"),
            ),
            PerfCorpusCase::new(
                "micro-float-arithmetic",
                include_str!(
                    "../../../benchmarks/runtime_comparison/programs/micro_float_arithmetic.js"
                ),
            ),
        ]
    }

    #[test]
    fn tier_control_decision_scope_binds_exact_sources_and_protocol() {
        let corpus = canonical_tier_control_corpus();
        assert_eq!(
            tier_control_case_identities(&corpus),
            required_tier_control_case_identities()
        );
        assert!(tier_control_decision_policy_complete(
            &TierControlConfig::default()
        ));

        let mut substituted = corpus.clone();
        substituted[0].source = substituted[1].source.clone();
        assert_ne!(
            tier_control_case_identities(&substituted),
            required_tier_control_case_identities()
        );

        let mut reordered = corpus.clone();
        reordered.swap(0, 1);
        assert_ne!(
            tier_control_case_identities(&reordered),
            required_tier_control_case_identities()
        );

        let diagnostic_policy = TierControlConfig {
            measured_iterations: TIER_CONTROL_DECISION_MEASURED_ITERATIONS - 1,
            ..TierControlConfig::default()
        };
        assert!(!tier_control_decision_policy_complete(&diagnostic_policy));
    }

    #[test]
    fn tier_control_paired_interval_drives_three_state_decision() {
        let exact_keep = paired_speedup(
            &[100; 30],
            &[106; 30],
            "deterministic_test_paired_log_ratio",
        )
        .expect("constant positive paired ratio");
        assert!(exact_keep.geomean_speedup_millionths.abs_diff(1_060_000) <= 1);
        assert!(exact_keep.ci95_lower_speedup_millionths.abs_diff(1_060_000) <= 1);
        assert!(exact_keep.ci95_upper_speedup_millionths.abs_diff(1_060_000) <= 1);
        assert_eq!(
            classify_tier_control_decision(true, Some(&exact_keep)),
            TierControlDecision::Keep
        );

        let exact_kill = paired_speedup(
            &[100; 30],
            &[104; 30],
            "deterministic_test_paired_log_ratio",
        )
        .expect("constant sub-floor paired ratio");
        assert_eq!(
            classify_tier_control_decision(true, Some(&exact_kill)),
            TierControlDecision::Kill
        );

        let straddling = TierControlPairedSpeedup {
            pair_count: 30,
            geomean_speedup_millionths: TIER_CONTROL_KEEP_FLOOR_MILLIONTHS,
            ci95_lower_speedup_millionths: TIER_CONTROL_KEEP_FLOOR_MILLIONTHS - 1,
            ci95_upper_speedup_millionths: TIER_CONTROL_KEEP_FLOOR_MILLIONTHS + 1,
            confidence_method: "deterministic_test".to_string(),
        };
        assert_eq!(
            classify_tier_control_decision(true, Some(&straddling)),
            TierControlDecision::Inconclusive
        );
        assert_eq!(
            classify_tier_control_decision(false, Some(&exact_keep)),
            TierControlDecision::Degraded
        );
    }

    #[test]
    fn tier_control_float_speedup_conversion_is_positive_and_representable() {
        assert_eq!(speedup_millionths_from_float(f64::NAN, false), None);
        assert_eq!(speedup_millionths_from_float(f64::INFINITY, false), None);
        assert_eq!(speedup_millionths_from_float(0.0, false), None);
        assert_eq!(speedup_millionths_from_float(-1.0, false), None);
        assert_eq!(speedup_millionths_from_float(0.000_000_1, false), None);
        assert_eq!(speedup_millionths_from_float(0.000_001, false), Some(1));
        assert_eq!(speedup_millionths_from_float(f64::MAX, true), None);
        assert_eq!(
            speedup_millionths_from_float(u64::MAX as f64 / MILLIONTHS as f64, true),
            None
        );
    }

    #[test]
    fn tier_control_build_profile_contract_is_fail_closed() {
        let exact_contract = CARGO_BUILD_PROFILE_CLASS == "release"
            && CARGO_BUILD_PROFILE_DIRECTORY == "release-perf"
            && CARGO_BUILD_OPT_LEVEL == "3"
            && !cfg!(debug_assertions);
        assert_eq!(tier_control_decision_build_complete(), exact_contract);
    }

    #[test]
    fn tier_control_scalar_case_is_exact_and_counter_bound() {
        let corpus = vec![PerfCorpusCase::new(
            "scalar-add",
            "var answer = 1 + 1; answer;",
        )];
        let config = TierControlConfig {
            warmup_iterations: 1,
            measured_iterations: 10,
            max_cv_millionths: u32::MAX,
            engine_instruction_budget: 1_000_000,
        };
        let (report, events) = run_tier_control_perf(&corpus, &config);
        assert_eq!(report.schema_version, TIER_CONTROL_PERF_SCHEMA_VERSION);
        assert_eq!(
            report
                .environment
                .executable_sha256
                .as_deref()
                .map(str::len),
            Some(64)
        );
        #[cfg(target_os = "linux")]
        {
            assert!(report.environment.cpu_affinity.is_some());
            assert!(report.environment.numa_memory_affinity.is_some());
        }
        assert_eq!(report.cases.len(), 1);
        let case = &report.cases[0];
        assert!(case.equivalent, "{}", case.equivalence_detail);
        assert!(case.admitted, "{:?}", case.exclusion_reasons);
        assert!(!report.environment.decision_scope_complete);
        assert!(report.summary.meets_keep_floor.is_none());
        assert_eq!(report.summary.decision, TierControlDecision::Degraded);
        assert!(case.tier_i_speedup_over_tier_r_millionths.is_some());
        assert_eq!(case.production.warmup_ns.len(), 1);
        assert_eq!(case.production.measured_ns.len(), 10);
        assert_eq!(case.control.warmup_ns.len(), 1);
        assert_eq!(case.control.measured_ns.len(), 10);
        assert_eq!(
            case.production.warmup_execution_artifact_sha256,
            case.control.warmup_execution_artifact_sha256
        );
        assert_eq!(
            case.production.measured_execution_artifact_sha256,
            case.control.measured_execution_artifact_sha256
        );
        assert!(
            case.production
                .warmup_counters
                .iter()
                .chain(&case.production.measured_counters)
                .all(|counters| counters.tier_i_instructions_executed > 0
                    && counters.tier_i_specialized_instructions_executed
                        <= counters.tier_i_instructions_executed
                    && counters.tier_i_instructions_executed <= counters.instructions_executed)
        );
        assert!(
            case.control
                .warmup_counters
                .iter()
                .chain(&case.control.measured_counters)
                .all(|counters| counters.tier_i_instructions_executed == 0
                    && counters.tier_i_specialized_instructions_executed == 0)
        );
        assert_eq!(events.len(), 22);
        let (event_pairs, event_remainder) = events.as_chunks::<2>();
        assert!(event_remainder.is_empty());
        assert!(
            event_pairs
                .iter()
                .all(|pair| pair[0].order_in_pair == 0 && pair[1].order_in_pair == 1)
        );
        assert!(
            events
                .iter()
                .all(|event| event.execution_artifact_sha256.len() == 64)
        );
        for pair_sequence in 0..11_u32 {
            let pair = events
                .iter()
                .filter(|event| event.pair_sequence == pair_sequence)
                .collect::<Vec<_>>();
            assert_eq!(pair.len(), 2);
            assert!(pair.iter().any(|event| event.order_in_pair == 0));
            assert!(pair.iter().any(|event| event.order_in_pair == 1));
            let production = pair
                .iter()
                .find(|event| event.arm == TierControlArm::ProductionTierI)
                .expect("production event");
            assert_eq!(
                production.order_in_pair,
                if pair_sequence.is_multiple_of(2) {
                    0
                } else {
                    1
                }
            );
        }
        let json = serde_json::to_string(&report).expect("serialize tier-control report");
        let parsed: TierControlPerfReport =
            serde_json::from_str(&json).expect("deserialize tier-control report");
        assert_eq!(parsed, report);
    }

    #[test]
    fn tier_control_preparation_failure_cannot_emit_a_ratio() {
        let corpus = vec![PerfCorpusCase::new("invalid", "syntax error here (")];
        let config = TierControlConfig {
            warmup_iterations: 1,
            measured_iterations: 10,
            max_cv_millionths: u32::MAX,
            engine_instruction_budget: 1_000_000,
        };
        let (report, events) = run_tier_control_perf(&corpus, &config);
        assert!(events.is_empty());
        assert!(!report.cases[0].admitted);
        assert!(!report.cases[0].equivalent);
        assert!(
            report.cases[0]
                .tier_i_speedup_over_tier_r_millionths
                .is_none()
        );
        assert_eq!(report.summary.admitted_cases, 0);
        assert!(report.summary.geomean_speedup_millionths.is_none());
        assert!(report.summary.meets_keep_floor.is_none());
    }

    #[test]
    fn tier_control_excluded_survivor_cannot_emit_a_keep_verdict() {
        let mut corpus = TIER_CONTROL_REQUIRED_CASE_SOURCES_SHA256
            .iter()
            .map(|(case_id, _)| PerfCorpusCase::new(*case_id, "var answer = 1 + 1; answer;"))
            .collect::<Vec<_>>();
        corpus[0].source = "syntax error here (".to_string();
        let config = TierControlConfig {
            warmup_iterations: 1,
            measured_iterations: 10,
            max_cv_millionths: u32::MAX,
            engine_instruction_budget: 1_000_000,
        };

        let (report, _) = run_tier_control_perf(&corpus, &config);
        assert!(!report.environment.decision_corpus_complete);
        assert!(!report.environment.decision_policy_complete);
        assert!(!report.environment.decision_scope_complete);
        assert_eq!(report.summary.excluded_cases, 1);
        assert_eq!(report.summary.admitted_cases, corpus.len() - 1);
        assert!(report.summary.geomean_speedup_millionths.is_none());
        assert!(report.summary.meets_keep_floor.is_none());
        assert!(
            report
                .summary
                .degraded_reasons
                .iter()
                .any(|reason| { reason.contains("selected cases satisfied every admission rule") })
        );
    }

    fn test_environment() -> PerfEnvironmentManifest {
        PerfEnvironmentManifest {
            host: DifferentialHostFacts {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel: "test".to_string(),
                cpu_model: "test".to_string(),
                cpu_cores_logical: 8,
                franken_engine_version: "0.1.0".to_string(),
            },
            total_memory_kb: Some(1),
            load_avg_1m_millionths: Some(100_000),
            cpu_governor: Some("performance".to_string()),
            node_resolved_program: Some("/usr/bin/node".to_string()),
            node_version: Some("v22.2.0".to_string()),
            node_genuine: Some(true),
            bun_resolved_program: Some("/home/test/.bun/bin/bun".to_string()),
            bun_version: Some("1.3.14".to_string()),
            warmup_iterations: 3,
            measured_iterations: 30,
            max_cv_millionths: 150_000,
            engine_execution_lifecycle:
                "prepare_once_fresh_router_and_interpreter_core_per_iteration".to_string(),
            external_execution_lifecycle:
                "new_function_once_single_process_shared_realm_and_jit_state".to_string(),
            engine_instruction_budget: DEFAULT_PERF_ENGINE_INSTRUCTION_BUDGET,
            corpus_case_count: 1,
            corpus_sha256: "0".repeat(64),
            generated_unix_ns: 42,
        }
    }
}
