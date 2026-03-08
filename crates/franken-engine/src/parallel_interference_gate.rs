//! Parallel parsing interference + determinism gate.
//!
//! Proves that the parallel parser (bd-1vfi) produces deterministic results
//! across seeds, schedules, and worker counts. Detects nondeterminism early
//! and enforces serial fallback on any parity violation.
//!
//! ## Gate guarantee
//!
//! Parallel mode cannot be promoted to production unless this gate passes with
//! zero unresolved nondeterminism incidents across the configured stress suite.
//!
//! ## Related beads
//!
//! - bd-3rjg (this module)
//! - bd-1vfi (parallel parser — upstream)
//! - bd-1gfn (error recovery — downstream)

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
#[cfg(test)]
use crate::parallel_parser::ScheduleDispatch;
use crate::parallel_parser::{
    self, MergeWitness, ParallelConfig, ParseInput, ParseOutput, ParserMode, RollbackControl,
    ScheduleTranscript,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "parallel_interference_gate";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.parallel-interference-gate.v1";

/// Default number of seeds to test in the perturbation suite.
pub const DEFAULT_SEED_COUNT: u32 = 10;

/// Default number of repeat runs per seed for flake detection.
pub const DEFAULT_REPEATS_PER_SEED: u32 = 3;

/// Default flake-rate threshold (millionths, 0 = zero tolerance).
pub const DEFAULT_FLAKE_THRESHOLD_MILLIONTHS: u64 = 0;

/// Default maximum worker count variations to test.
pub const DEFAULT_MAX_WORKER_VARIATIONS: u32 = 4;

// ---------------------------------------------------------------------------
// Interference taxonomy
// ---------------------------------------------------------------------------

/// Class of nondeterminism detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InterferenceClass {
    /// Merge ordering differs across runs.
    MergeOrder,
    /// Scheduler produced different execution order.
    Scheduler,
    /// Data structure iteration order varied.
    DataStructureIteration,
    /// Artifact pipeline produced different outputs.
    ArtifactPipeline,
    /// Timeout/cancellation race condition.
    TimeoutRace,
    /// Backpressure caused ordering drift.
    BackpressureDrift,
}

impl fmt::Display for InterferenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MergeOrder => write!(f, "merge-order"),
            Self::Scheduler => write!(f, "scheduler"),
            Self::DataStructureIteration => write!(f, "data-structure-iteration"),
            Self::ArtifactPipeline => write!(f, "artifact-pipeline"),
            Self::TimeoutRace => write!(f, "timeout-race"),
            Self::BackpressureDrift => write!(f, "backpressure-drift"),
        }
    }
}

/// Severity of an interference incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InterferenceSeverity {
    /// Informational — no semantic impact.
    Info,
    /// Warning — potential semantic impact.
    Warning,
    /// Critical — confirmed semantic divergence.
    Critical,
}

impl fmt::Display for InterferenceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Interference incident
// ---------------------------------------------------------------------------

/// A single detected interference incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceIncident {
    /// Classification of the nondeterminism.
    pub class: InterferenceClass,
    /// Severity assessment.
    pub severity: InterferenceSeverity,
    /// Seed that triggered the incident.
    pub seed: u64,
    /// Worker count configuration.
    pub worker_count: u32,
    /// Run index within the repetition.
    pub run_index: u32,
    /// Hash of the expected output.
    pub expected_hash: ContentHash,
    /// Hash of the actual output.
    pub actual_hash: ContentHash,
    /// Mismatch position (token index) if applicable.
    pub mismatch_token_index: Option<u64>,
    /// Human-readable triage hint.
    pub triage_hint: String,
    /// Remediation playbook reference.
    pub remediation_playbook_id: String,
    /// One-command reproduction instruction.
    pub replay_command: String,
}

// ---------------------------------------------------------------------------
// Witness comparison
// ---------------------------------------------------------------------------

/// Result of comparing two merge witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessDiff {
    /// Whether witnesses match.
    pub matches: bool,
    /// Differences found.
    pub diffs: Vec<WitnessDiffEntry>,
}

/// A single difference between merge witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessDiffEntry {
    /// Field that differs.
    pub field: String,
    /// Expected value (as string).
    pub expected: String,
    /// Actual value (as string).
    pub actual: String,
}

/// Compare two merge witnesses and produce a structured diff.
pub fn compare_witnesses(expected: &MergeWitness, actual: &MergeWitness) -> WitnessDiff {
    let mut diffs = Vec::new();

    if expected.merged_hash != actual.merged_hash {
        diffs.push(WitnessDiffEntry {
            field: "merged_hash".to_string(),
            expected: format!("{:?}", expected.merged_hash),
            actual: format!("{:?}", actual.merged_hash),
        });
    }
    if expected.witness_hash != actual.witness_hash {
        diffs.push(WitnessDiffEntry {
            field: "witness_hash".to_string(),
            expected: format!("{:?}", expected.witness_hash),
            actual: format!("{:?}", actual.witness_hash),
        });
    }
    if expected.chunk_count != actual.chunk_count {
        diffs.push(WitnessDiffEntry {
            field: "chunk_count".to_string(),
            expected: expected.chunk_count.to_string(),
            actual: actual.chunk_count.to_string(),
        });
    }
    if expected.boundary_repairs != actual.boundary_repairs {
        diffs.push(WitnessDiffEntry {
            field: "boundary_repairs".to_string(),
            expected: expected.boundary_repairs.to_string(),
            actual: actual.boundary_repairs.to_string(),
        });
    }
    if expected.total_tokens != actual.total_tokens {
        diffs.push(WitnessDiffEntry {
            field: "total_tokens".to_string(),
            expected: expected.total_tokens.to_string(),
            actual: actual.total_tokens.to_string(),
        });
    }

    WitnessDiff {
        matches: diffs.is_empty(),
        diffs,
    }
}

/// Compare two schedule transcripts.
pub fn compare_transcripts(
    expected: &ScheduleTranscript,
    actual: &ScheduleTranscript,
) -> WitnessDiff {
    let mut diffs = Vec::new();

    if expected.seed != actual.seed {
        diffs.push(WitnessDiffEntry {
            field: "seed".to_string(),
            expected: expected.seed.to_string(),
            actual: actual.seed.to_string(),
        });
    }
    if expected.worker_count != actual.worker_count {
        diffs.push(WitnessDiffEntry {
            field: "worker_count".to_string(),
            expected: expected.worker_count.to_string(),
            actual: actual.worker_count.to_string(),
        });
    }
    if expected.plan_hash != actual.plan_hash {
        diffs.push(WitnessDiffEntry {
            field: "plan_hash".to_string(),
            expected: format!("{:?}", expected.plan_hash),
            actual: format!("{:?}", actual.plan_hash),
        });
    }
    if expected.execution_order != actual.execution_order {
        diffs.push(WitnessDiffEntry {
            field: "execution_order".to_string(),
            expected: format!("{:?}", expected.execution_order),
            actual: format!("{:?}", actual.execution_order),
        });
    }
    if expected.dispatches != actual.dispatches {
        diffs.push(WitnessDiffEntry {
            field: "dispatches".to_string(),
            expected: format!("{:?}", expected.dispatches),
            actual: format!("{:?}", actual.dispatches),
        });
    }
    if expected.transcript_hash != actual.transcript_hash {
        diffs.push(WitnessDiffEntry {
            field: "transcript_hash".to_string(),
            expected: format!("{:?}", expected.transcript_hash),
            actual: format!("{:?}", actual.transcript_hash),
        });
    }

    WitnessDiff {
        matches: diffs.is_empty(),
        diffs,
    }
}

// ---------------------------------------------------------------------------
// Flake-rate measurement
// ---------------------------------------------------------------------------

/// Flake-rate measurement over a moving window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeRate {
    /// Total runs executed.
    pub total_runs: u64,
    /// Runs that produced different output from the reference.
    pub mismatched_runs: u64,
    /// Flake rate in millionths (1_000_000 = 100%).
    pub rate_millionths: u64,
    /// Configured threshold (millionths).
    pub threshold_millionths: u64,
    /// Whether the flake rate is within threshold.
    pub within_threshold: bool,
}

impl FlakeRate {
    /// Compute flake rate from raw counts.
    pub fn compute(total_runs: u64, mismatched_runs: u64, threshold_millionths: u64) -> Self {
        let mismatched_runs = mismatched_runs.min(total_runs);
        let rate_millionths = if total_runs > 0 {
            mismatched_runs
                .checked_mul(1_000_000)
                .and_then(|n| n.checked_div(total_runs))
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            total_runs,
            mismatched_runs,
            rate_millionths,
            threshold_millionths,
            within_threshold: rate_millionths <= threshold_millionths,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the interference gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Number of different seeds to test.
    pub seed_count: u32,
    /// Number of repeat runs per seed (for flake detection).
    pub repeats_per_seed: u32,
    /// Flake-rate threshold (millionths).
    pub flake_threshold_millionths: u64,
    /// Worker count variations to test (e.g., [2, 4, 8]).
    pub worker_variations: Vec<u32>,
    /// Base parallel config to use.
    pub base_config: ParallelConfig,
    /// Whether to require serial parity check on every run.
    pub require_serial_parity: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            seed_count: DEFAULT_SEED_COUNT,
            repeats_per_seed: DEFAULT_REPEATS_PER_SEED,
            flake_threshold_millionths: DEFAULT_FLAKE_THRESHOLD_MILLIONTHS,
            worker_variations: vec![2, 4, 8],
            base_config: ParallelConfig {
                min_parallel_bytes: 10,
                always_check_parity: true,
                ..ParallelConfig::default()
            },
            require_serial_parity: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate decision
// ---------------------------------------------------------------------------

/// Gate promotion decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateDecision {
    /// Parallel mode is approved for promotion.
    Promote,
    /// Parallel mode is held pending further investigation.
    Hold,
    /// Parallel mode is rejected; serial fallback enforced.
    Reject,
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promote => write!(f, "promote"),
            Self::Hold => write!(f, "hold"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

// ---------------------------------------------------------------------------
// Run record
// ---------------------------------------------------------------------------

/// Record of a single gate evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// Seed used.
    pub seed: u64,
    /// Worker count.
    pub worker_count: u32,
    /// Run index (repetition number).
    pub run_index: u32,
    /// Output hash.
    pub output_hash: ContentHash,
    /// Token count.
    pub token_count: u64,
    /// Parser mode actually used.
    pub mode: ParserMode,
    /// Parity result (if checked).
    pub parity_ok: Option<bool>,
    /// Merge witness hash (if parallel).
    pub merge_witness_hash: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// Gate evaluation result
// ---------------------------------------------------------------------------

/// Full result of running the interference gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Schema version.
    pub schema_version: String,
    /// Gate decision.
    pub decision: GateDecision,
    /// Human-readable rationale.
    pub rationale: String,
    /// All run records.
    pub runs: Vec<RunRecord>,
    /// Detected interference incidents.
    pub incidents: Vec<InterferenceIncident>,
    /// Flake rate measurement.
    pub flake_rate: FlakeRate,
    /// Reference output hash (from first run).
    pub reference_hash: ContentHash,
    /// Seeds tested.
    pub seeds_tested: Vec<u64>,
    /// Worker counts tested.
    pub workers_tested: Vec<u32>,
    /// Total runs executed.
    pub total_runs: u64,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Input size in bytes.
    pub input_bytes: u64,
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

/// Run the interference gate on a given source input.
///
/// Executes the parallel parser across multiple seeds, worker counts, and
/// repetitions, checking that all runs produce identical output.
pub fn evaluate_gate(source: &str, config: &GateConfig) -> GateResult {
    let input_hash = ContentHash::compute(source.as_bytes());
    let input_bytes = source.len() as u64;
    let mut runs = Vec::new();
    let mut incidents = Vec::new();
    let mut reference_hash: Option<ContentHash> = None;
    let mut mismatched_runs = 0u64;
    let mut seeds_tested = BTreeSet::new();
    let mut workers_tested = BTreeSet::new();

    for worker_count in &config.worker_variations {
        for seed_idx in 0..config.seed_count {
            let seed = seed_idx as u64;
            seeds_tested.insert(seed);
            workers_tested.insert(*worker_count);

            for repeat in 0..config.repeats_per_seed {
                let mut parallel_config = config.base_config.clone();
                parallel_config.max_workers = *worker_count;
                parallel_config.schedule_seed = seed;
                parallel_config.always_check_parity = config.require_serial_parity;

                let parse_input = ParseInput {
                    source,
                    trace_id: "interference-gate",
                    run_id: &format!("w{}-s{}-r{}", worker_count, seed, repeat),
                    epoch: SecurityEpoch::from_raw(1),
                    config: &parallel_config,
                };

                match parallel_parser::parse(&parse_input) {
                    Ok(output) => {
                        let parity_ok = output.parity_result.as_ref().map(|p| p.parity_ok);
                        let merge_witness_hash =
                            output.merge_witness.as_ref().map(|w| w.merged_hash.clone());

                        let record = RunRecord {
                            seed,
                            worker_count: *worker_count,
                            run_index: repeat,
                            output_hash: output.output_hash.clone(),
                            token_count: output.token_count,
                            mode: output.mode,
                            parity_ok,
                            merge_witness_hash,
                        };

                        // Check against reference.
                        if let Some(ref ref_hash) = reference_hash {
                            if output.output_hash != *ref_hash {
                                mismatched_runs += 1;
                                let class = classify_interference(&output, parity_ok);
                                let severity = if parity_ok == Some(false) {
                                    InterferenceSeverity::Critical
                                } else {
                                    InterferenceSeverity::Warning
                                };

                                incidents.push(InterferenceIncident {
                                    class,
                                    severity,
                                    seed,
                                    worker_count: *worker_count,
                                    run_index: repeat,
                                    expected_hash: ref_hash.clone(),
                                    actual_hash: output.output_hash.clone(),
                                    mismatch_token_index: output
                                        .parity_result
                                        .as_ref()
                                        .and_then(|p| p.mismatch_index),
                                    triage_hint: format!(
                                        "Output hash mismatch: workers={}, seed={}, run={}",
                                        worker_count, seed, repeat
                                    ),
                                    remediation_playbook_id: format!(
                                        "playbook.interference.{}",
                                        class
                                    ),
                                    replay_command: format!(
                                        "franken-engine parallel-parse --workers {} --seed {} --trace-id interference-gate",
                                        worker_count, seed
                                    ),
                                });
                            }
                        } else {
                            reference_hash = Some(output.output_hash.clone());
                        }

                        runs.push(record);
                    }
                    Err(_e) => {
                        // Parse error counts as a mismatch.
                        mismatched_runs += 1;
                        let record = RunRecord {
                            seed,
                            worker_count: *worker_count,
                            run_index: repeat,
                            output_hash: ContentHash::compute(b"error"),
                            token_count: 0,
                            mode: ParserMode::Serial,
                            parity_ok: None,
                            merge_witness_hash: None,
                        };
                        runs.push(record);
                    }
                }
            }
        }
    }

    let total_runs = runs.len() as u64;
    let flake_rate = FlakeRate::compute(
        total_runs,
        mismatched_runs,
        config.flake_threshold_millionths,
    );

    let decision = if incidents
        .iter()
        .any(|i| i.severity == InterferenceSeverity::Critical)
    {
        GateDecision::Reject
    } else if !flake_rate.within_threshold {
        GateDecision::Hold
    } else if incidents.is_empty() {
        GateDecision::Promote
    } else {
        GateDecision::Hold
    };

    let rationale = match decision {
        GateDecision::Promote => format!(
            "All {} runs deterministic across {} seeds and {} worker configs",
            total_runs,
            seeds_tested.len(),
            workers_tested.len()
        ),
        GateDecision::Hold => format!(
            "{} incidents detected, flake rate {}/1M (threshold {}/1M)",
            incidents.len(),
            flake_rate.rate_millionths,
            flake_rate.threshold_millionths
        ),
        GateDecision::Reject => format!(
            "Critical nondeterminism: {} incidents across {} runs",
            incidents
                .iter()
                .filter(|i| i.severity == InterferenceSeverity::Critical)
                .count(),
            total_runs
        ),
    };

    GateResult {
        schema_version: SCHEMA_VERSION.to_string(),
        decision,
        rationale,
        runs,
        incidents,
        flake_rate,
        reference_hash: reference_hash.unwrap_or_else(|| ContentHash::compute(b"empty")),
        seeds_tested: seeds_tested.into_iter().collect(),
        workers_tested: workers_tested.into_iter().collect(),
        total_runs,
        input_hash,
        input_bytes,
    }
}

/// Classify an interference incident from a parse output.
fn classify_interference(output: &ParseOutput, parity_ok: Option<bool>) -> InterferenceClass {
    if parity_ok == Some(false) {
        // Parity failure means merge ordering is wrong.
        return InterferenceClass::MergeOrder;
    }
    if output.mode == ParserMode::Serial {
        // Fell back to serial — could be timeout or budget.
        if output.fallback_cause.is_some() {
            return InterferenceClass::TimeoutRace;
        }
    }
    // Default to scheduler class.
    InterferenceClass::Scheduler
}

// ---------------------------------------------------------------------------
// Operator summary
// ---------------------------------------------------------------------------

/// Operator-facing summary with ranked root-cause hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummary {
    /// Gate decision.
    pub decision: GateDecision,
    /// Number of runs.
    pub total_runs: u64,
    /// Number of incidents.
    pub incident_count: u64,
    /// Ranked root-cause hints (most likely first).
    pub root_cause_hints: Vec<RootCauseHint>,
    /// Flake rate display.
    pub flake_rate_display: String,
    /// Recommended action.
    pub recommended_action: String,
}

/// A root-cause hint for an interference class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCauseHint {
    /// Interference class.
    pub class: InterferenceClass,
    /// Number of incidents in this class.
    pub count: u64,
    /// Severity.
    pub severity: InterferenceSeverity,
    /// Remediation suggestion.
    pub remediation: String,
}

/// Generate an operator summary from gate results.
pub fn generate_operator_summary(result: &GateResult) -> OperatorSummary {
    let mut class_counts: Vec<(InterferenceClass, u64, InterferenceSeverity)> = Vec::new();

    for incident in &result.incidents {
        if let Some(entry) = class_counts
            .iter_mut()
            .find(|(c, _, _)| *c == incident.class)
        {
            entry.1 += 1;
            if incident.severity > entry.2 {
                entry.2 = incident.severity;
            }
        } else {
            class_counts.push((incident.class, 1, incident.severity));
        }
    }

    // Sort by count descending.
    class_counts.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    let root_cause_hints: Vec<RootCauseHint> = class_counts
        .iter()
        .map(|(class, count, severity)| RootCauseHint {
            class: *class,
            count: *count,
            severity: *severity,
            remediation: remediation_for_class(*class),
        })
        .collect();

    let recommended_action = match result.decision {
        GateDecision::Promote => "Parallel mode is safe to promote.".to_string(),
        GateDecision::Hold => {
            "Investigate incidents before promotion. Run with --verbose for details.".to_string()
        }
        GateDecision::Reject => {
            "Force serial fallback immediately. Critical nondeterminism detected.".to_string()
        }
    };

    OperatorSummary {
        decision: result.decision,
        total_runs: result.total_runs,
        incident_count: result.incidents.len() as u64,
        root_cause_hints,
        flake_rate_display: format!(
            "{}/1M (threshold {}/1M)",
            result.flake_rate.rate_millionths, result.flake_rate.threshold_millionths
        ),
        recommended_action,
    }
}

fn remediation_for_class(class: InterferenceClass) -> String {
    match class {
        InterferenceClass::MergeOrder => {
            "Check merge-key sort stability and boundary repair logic.".to_string()
        }
        InterferenceClass::Scheduler => {
            "Verify schedule transcript determinism for given seed.".to_string()
        }
        InterferenceClass::DataStructureIteration => {
            "Replace HashMap with BTreeMap in merge path.".to_string()
        }
        InterferenceClass::ArtifactPipeline => {
            "Check artifact hash computation for timestamp leaks.".to_string()
        }
        InterferenceClass::TimeoutRace => {
            "Increase timeout budget or add deterministic timeout resolution.".to_string()
        }
        InterferenceClass::BackpressureDrift => {
            "Add stable ordering tiebreaker in backpressure queue.".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Replay bundle
// ---------------------------------------------------------------------------

/// Replay bundle for a failing interference run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    /// Schema version.
    pub schema_version: String,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Input size.
    pub input_bytes: u64,
    /// Failing incidents.
    pub incidents: Vec<InterferenceIncident>,
    /// Seed catalog that triggered failures.
    pub failing_seeds: Vec<u64>,
    /// Worker configs that triggered failures.
    pub failing_workers: Vec<u32>,
    /// Replay commands (one per incident).
    pub replay_commands: Vec<String>,
    /// Reference output hash.
    pub reference_hash: ContentHash,
}

/// Build a replay bundle from gate results (only if there are incidents).
pub fn build_replay_bundle(result: &GateResult) -> Option<ReplayBundle> {
    if result.incidents.is_empty() {
        return None;
    }

    let failing_seeds: BTreeSet<u64> = result.incidents.iter().map(|i| i.seed).collect();
    let failing_workers: BTreeSet<u32> = result.incidents.iter().map(|i| i.worker_count).collect();
    let replay_commands: Vec<String> = result
        .incidents
        .iter()
        .map(|i| i.replay_command.clone())
        .collect();

    Some(ReplayBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: result.input_hash.clone(),
        input_bytes: result.input_bytes,
        incidents: result.incidents.clone(),
        failing_seeds: failing_seeds.into_iter().collect(),
        failing_workers: failing_workers.into_iter().collect(),
        replay_commands,
        reference_hash: result.reference_hash.clone(),
    })
}

// ---------------------------------------------------------------------------
// Rollback integration
// ---------------------------------------------------------------------------

/// Apply gate results to a rollback control.
/// Returns true if rollback was triggered.
pub fn apply_gate_to_rollback(result: &GateResult, rollback: &mut RollbackControl) -> bool {
    match result.decision {
        GateDecision::Promote => {
            rollback.record_success();
            false
        }
        GateDecision::Hold | GateDecision::Reject => rollback.record_failure("interference-gate"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_source() -> String {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        source
    }

    fn small_gate_config() -> GateConfig {
        GateConfig {
            seed_count: 3,
            repeats_per_seed: 2,
            flake_threshold_millionths: 0,
            worker_variations: vec![2, 4],
            base_config: ParallelConfig {
                min_parallel_bytes: 10,
                always_check_parity: true,
                ..ParallelConfig::default()
            },
            require_serial_parity: true,
        }
    }

    // --- Interference taxonomy tests ---

    #[test]
    fn interference_class_display() {
        assert_eq!(InterferenceClass::MergeOrder.to_string(), "merge-order");
        assert_eq!(InterferenceClass::Scheduler.to_string(), "scheduler");
        assert_eq!(
            InterferenceClass::DataStructureIteration.to_string(),
            "data-structure-iteration"
        );
        assert_eq!(
            InterferenceClass::ArtifactPipeline.to_string(),
            "artifact-pipeline"
        );
        assert_eq!(InterferenceClass::TimeoutRace.to_string(), "timeout-race");
        assert_eq!(
            InterferenceClass::BackpressureDrift.to_string(),
            "backpressure-drift"
        );
    }

    #[test]
    fn interference_class_ordering() {
        assert!(InterferenceClass::MergeOrder < InterferenceClass::Scheduler);
        assert!(InterferenceClass::Scheduler < InterferenceClass::DataStructureIteration);
    }

    #[test]
    fn interference_severity_ordering() {
        assert!(InterferenceSeverity::Info < InterferenceSeverity::Warning);
        assert!(InterferenceSeverity::Warning < InterferenceSeverity::Critical);
    }

    #[test]
    fn interference_severity_display() {
        assert_eq!(InterferenceSeverity::Info.to_string(), "info");
        assert_eq!(InterferenceSeverity::Warning.to_string(), "warning");
        assert_eq!(InterferenceSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn interference_incident_serde_roundtrip() {
        let incident = InterferenceIncident {
            class: InterferenceClass::MergeOrder,
            severity: InterferenceSeverity::Critical,
            seed: 42,
            worker_count: 4,
            run_index: 1,
            expected_hash: ContentHash::compute(b"expected"),
            actual_hash: ContentHash::compute(b"actual"),
            mismatch_token_index: Some(5),
            triage_hint: "test hint".to_string(),
            remediation_playbook_id: "playbook.interference.merge-order".to_string(),
            replay_command: "franken-engine parallel-parse --workers 4 --seed 42".to_string(),
        };
        let json = serde_json::to_string(&incident).unwrap();
        let back: InterferenceIncident = serde_json::from_str(&json).unwrap();
        assert_eq!(incident, back);
    }

    // --- Witness comparison tests ---

    #[test]
    fn witness_diff_identical() {
        let witness = MergeWitness {
            merged_hash: ContentHash::compute(b"test"),
            witness_hash: ContentHash::compute(b"witness"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let diff = compare_witnesses(&witness, &witness);
        assert!(diff.matches);
        assert!(diff.diffs.is_empty());
    }

    #[test]
    fn witness_diff_hash_mismatch() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"a"),
            witness_hash: ContentHash::compute(b"shared"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            merged_hash: ContentHash::compute(b"b"),
            witness_hash: ContentHash::compute(b"shared"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 1);
        assert_eq!(diff.diffs[0].field, "merged_hash");
    }

    #[test]
    fn witness_diff_multiple_fields() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"a"),
            witness_hash: ContentHash::compute(b"shared"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            merged_hash: ContentHash::compute(b"b"),
            witness_hash: ContentHash::compute(b"shared"),
            chunk_count: 4,
            boundary_repairs: 2,
            total_tokens: 60,
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 4);
    }

    #[test]
    fn witness_diff_serde_roundtrip() {
        let diff = WitnessDiff {
            matches: false,
            diffs: vec![WitnessDiffEntry {
                field: "total_tokens".to_string(),
                expected: "50".to_string(),
                actual: "60".to_string(),
            }],
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: WitnessDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, back);
    }

    // --- Transcript comparison tests ---

    #[test]
    fn transcript_diff_identical() {
        let dispatches = vec![
            ScheduleDispatch {
                step_index: 0,
                chunk_index: 0,
                worker_slot: 0,
            },
            ScheduleDispatch {
                step_index: 1,
                chunk_index: 1,
                worker_slot: 1,
            },
            ScheduleDispatch {
                step_index: 2,
                chunk_index: 2,
                worker_slot: 2,
            },
            ScheduleDispatch {
                step_index: 3,
                chunk_index: 3,
                worker_slot: 3,
            },
        ];
        let t = ScheduleTranscript {
            seed: 42,
            worker_count: 4,
            plan_hash: ContentHash::compute(b"plan"),
            execution_order: vec![0, 1, 2, 3],
            dispatches: dispatches.clone(),
            transcript_hash: ContentHash::compute(b"transcript-a"),
        };
        let diff = compare_transcripts(&t, &t);
        assert!(diff.matches);
    }

    #[test]
    fn transcript_diff_seed_mismatch() {
        let dispatches = vec![
            ScheduleDispatch {
                step_index: 0,
                chunk_index: 0,
                worker_slot: 0,
            },
            ScheduleDispatch {
                step_index: 1,
                chunk_index: 1,
                worker_slot: 1,
            },
            ScheduleDispatch {
                step_index: 2,
                chunk_index: 2,
                worker_slot: 2,
            },
            ScheduleDispatch {
                step_index: 3,
                chunk_index: 3,
                worker_slot: 3,
            },
        ];
        let t1 = ScheduleTranscript {
            seed: 42,
            worker_count: 4,
            plan_hash: ContentHash::compute(b"plan"),
            execution_order: vec![0, 1, 2, 3],
            dispatches,
            transcript_hash: ContentHash::compute(b"transcript-a"),
        };
        let t2 = ScheduleTranscript {
            seed: 99,
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "seed"));
    }

    // --- Flake-rate tests ---

    #[test]
    fn flake_rate_zero_runs() {
        let fr = FlakeRate::compute(0, 0, 0);
        assert_eq!(fr.rate_millionths, 0);
        assert!(fr.within_threshold);
    }

    #[test]
    fn flake_rate_no_mismatches() {
        let fr = FlakeRate::compute(100, 0, 0);
        assert_eq!(fr.rate_millionths, 0);
        assert!(fr.within_threshold);
    }

    #[test]
    fn flake_rate_all_mismatched() {
        let fr = FlakeRate::compute(100, 100, 0);
        assert_eq!(fr.rate_millionths, 1_000_000);
        assert!(!fr.within_threshold);
    }

    #[test]
    fn flake_rate_partial() {
        let fr = FlakeRate::compute(100, 10, 100_000);
        assert_eq!(fr.rate_millionths, 100_000); // 10%
        assert!(fr.within_threshold);
    }

    #[test]
    fn flake_rate_above_threshold() {
        let fr = FlakeRate::compute(100, 20, 100_000);
        assert_eq!(fr.rate_millionths, 200_000); // 20%
        assert!(!fr.within_threshold);
    }

    #[test]
    fn flake_rate_serde_roundtrip() {
        let fr = FlakeRate::compute(50, 5, 100_000);
        let json = serde_json::to_string(&fr).unwrap();
        let back: FlakeRate = serde_json::from_str(&json).unwrap();
        assert_eq!(fr, back);
    }

    // --- Gate config tests ---

    #[test]
    fn gate_config_default() {
        let config = GateConfig::default();
        assert_eq!(config.seed_count, DEFAULT_SEED_COUNT);
        assert_eq!(config.repeats_per_seed, DEFAULT_REPEATS_PER_SEED);
        assert_eq!(
            config.flake_threshold_millionths,
            DEFAULT_FLAKE_THRESHOLD_MILLIONTHS
        );
        assert_eq!(config.worker_variations, vec![2, 4, 8]);
    }

    #[test]
    fn gate_config_serde_roundtrip() {
        let config = small_gate_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Gate decision tests ---

    #[test]
    fn gate_decision_display() {
        assert_eq!(GateDecision::Promote.to_string(), "promote");
        assert_eq!(GateDecision::Hold.to_string(), "hold");
        assert_eq!(GateDecision::Reject.to_string(), "reject");
    }

    #[test]
    fn gate_decision_ordering() {
        assert!(GateDecision::Promote < GateDecision::Hold);
        assert!(GateDecision::Hold < GateDecision::Reject);
    }

    // --- Gate evaluation tests ---

    #[test]
    fn gate_promotes_deterministic_input() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.decision, GateDecision::Promote);
        assert!(result.incidents.is_empty());
        assert_eq!(result.flake_rate.mismatched_runs, 0);
        assert!(result.total_runs > 0);
    }

    #[test]
    fn gate_result_has_correct_run_count() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let expected_runs = config.worker_variations.len() as u64
            * config.seed_count as u64
            * config.repeats_per_seed as u64;
        assert_eq!(result.total_runs, expected_runs);
    }

    #[test]
    fn gate_result_seeds_and_workers_tracked() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.seeds_tested.len(), config.seed_count as usize);
        assert_eq!(result.workers_tested.len(), config.worker_variations.len());
    }

    #[test]
    fn gate_result_serde_roundtrip() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let json = serde_json::to_string(&result).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn gate_result_schema_version() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn gate_result_input_hash_deterministic() {
        let source = test_source();
        let config = small_gate_config();
        let r1 = evaluate_gate(&source, &config);
        let r2 = evaluate_gate(&source, &config);
        assert_eq!(r1.input_hash, r2.input_hash);
    }

    #[test]
    fn gate_small_input_still_runs() {
        // Below parallel threshold — routes to serial for all runs.
        let config = GateConfig {
            seed_count: 2,
            repeats_per_seed: 2,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let result = evaluate_gate("x = 1;", &config);
        // All runs should be deterministic even if serial.
        assert_eq!(result.decision, GateDecision::Promote);
    }

    #[test]
    fn gate_single_seed_single_repeat() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![4],
            ..small_gate_config()
        };
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.total_runs, 1);
        // Single run — always promotes (no comparison possible).
        assert_eq!(result.decision, GateDecision::Promote);
    }

    // --- Operator summary tests ---

    #[test]
    fn operator_summary_promote() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let summary = generate_operator_summary(&result);
        assert_eq!(summary.decision, GateDecision::Promote);
        assert_eq!(summary.incident_count, 0);
        assert!(summary.root_cause_hints.is_empty());
        assert!(summary.recommended_action.contains("safe to promote"));
    }

    #[test]
    fn operator_summary_serde_roundtrip() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let summary = generate_operator_summary(&result);
        let json = serde_json::to_string(&summary).unwrap();
        let back: OperatorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // --- Replay bundle tests ---

    #[test]
    fn replay_bundle_none_on_clean_run() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let bundle = build_replay_bundle(&result);
        assert!(bundle.is_none());
    }

    #[test]
    fn replay_bundle_serde_roundtrip() {
        // Create a synthetic replay bundle.
        let bundle = ReplayBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash: ContentHash::compute(b"test"),
            input_bytes: 100,
            incidents: vec![InterferenceIncident {
                class: InterferenceClass::MergeOrder,
                severity: InterferenceSeverity::Warning,
                seed: 5,
                worker_count: 4,
                run_index: 0,
                expected_hash: ContentHash::compute(b"a"),
                actual_hash: ContentHash::compute(b"b"),
                mismatch_token_index: None,
                triage_hint: "test".to_string(),
                remediation_playbook_id: "playbook.merge".to_string(),
                replay_command: "replay cmd".to_string(),
            }],
            failing_seeds: vec![5],
            failing_workers: vec![4],
            replay_commands: vec!["replay cmd".to_string()],
            reference_hash: ContentHash::compute(b"ref"),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let back: ReplayBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    // --- Rollback integration tests ---

    #[test]
    fn rollback_integration_promote() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let mut rollback = RollbackControl::default();
        let triggered = apply_gate_to_rollback(&result, &mut rollback);
        assert!(!triggered);
        assert!(!rollback.parallel_disabled);
    }

    #[test]
    fn rollback_integration_multiple_promotes_reset() {
        let source = test_source();
        let config = small_gate_config();
        let mut rollback = RollbackControl::default();
        rollback.record_failure("prev-fail");
        assert_eq!(rollback.consecutive_failures, 1);

        let result = evaluate_gate(&source, &config);
        apply_gate_to_rollback(&result, &mut rollback);
        assert_eq!(rollback.consecutive_failures, 0);
    }

    // --- Remediation tests ---

    #[test]
    fn remediation_covers_all_classes() {
        let classes = [
            InterferenceClass::MergeOrder,
            InterferenceClass::Scheduler,
            InterferenceClass::DataStructureIteration,
            InterferenceClass::ArtifactPipeline,
            InterferenceClass::TimeoutRace,
            InterferenceClass::BackpressureDrift,
        ];
        for class in classes {
            let rem = remediation_for_class(class);
            assert!(!rem.is_empty(), "No remediation for {:?}", class);
        }
    }

    // --- Run record tests ---

    #[test]
    fn run_record_serde_roundtrip() {
        let rr = RunRecord {
            seed: 7,
            worker_count: 4,
            run_index: 2,
            output_hash: ContentHash::compute(b"test"),
            token_count: 100,
            mode: ParserMode::Parallel,
            parity_ok: Some(true),
            merge_witness_hash: Some(ContentHash::compute(b"witness")),
        };
        let json = serde_json::to_string(&rr).unwrap();
        let back: RunRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, back);
    }

    // --- Determinism stress tests ---

    #[test]
    fn gate_determinism_repeated_evaluations() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 2,
            repeats_per_seed: 2,
            worker_variations: vec![2],
            ..small_gate_config()
        };
        let r1 = evaluate_gate(&source, &config);
        let r2 = evaluate_gate(&source, &config);
        assert_eq!(r1.decision, r2.decision);
        assert_eq!(r1.reference_hash, r2.reference_hash);
        assert_eq!(r1.total_runs, r2.total_runs);
    }

    #[test]
    fn gate_with_eight_workers() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 2,
            repeats_per_seed: 2,
            worker_variations: vec![8],
            ..small_gate_config()
        };
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.decision, GateDecision::Promote);
    }

    #[test]
    fn gate_with_operators_and_strings() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!(
                "var s{} = \"hello\"; x{} == {} && y{} != z{};\n",
                i, i, i, i, i
            ));
        }
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.decision, GateDecision::Promote);
    }

    #[test]
    fn gate_empty_input() {
        let config = small_gate_config();
        let result = evaluate_gate("", &config);
        assert_eq!(result.decision, GateDecision::Promote);
        assert_eq!(result.input_bytes, 0);
    }

    #[test]
    fn gate_only_newlines() {
        let source = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
        let config = small_gate_config();
        let result = evaluate_gate(source, &config);
        assert_eq!(result.decision, GateDecision::Promote);
    }

    // --- Enrichment tests ---

    #[test]
    fn interference_class_display_uniqueness_btreeset() {
        let classes = [
            InterferenceClass::MergeOrder,
            InterferenceClass::Scheduler,
            InterferenceClass::DataStructureIteration,
            InterferenceClass::ArtifactPipeline,
            InterferenceClass::TimeoutRace,
            InterferenceClass::BackpressureDrift,
        ];
        let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            displays.len(),
            6,
            "all 6 classes should have unique Display"
        );
    }

    #[test]
    fn interference_severity_display_uniqueness_btreeset() {
        let severities = [
            InterferenceSeverity::Info,
            InterferenceSeverity::Warning,
            InterferenceSeverity::Critical,
        ];
        let displays: BTreeSet<String> = severities.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 severities should have unique Display"
        );
    }

    #[test]
    fn gate_decision_display_uniqueness_btreeset() {
        let decisions = [
            GateDecision::Promote,
            GateDecision::Hold,
            GateDecision::Reject,
        ];
        let displays: BTreeSet<String> = decisions.iter().map(|d| d.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn interference_class_serde_roundtrip_all_variants() {
        let classes = [
            InterferenceClass::MergeOrder,
            InterferenceClass::Scheduler,
            InterferenceClass::DataStructureIteration,
            InterferenceClass::ArtifactPipeline,
            InterferenceClass::TimeoutRace,
            InterferenceClass::BackpressureDrift,
        ];
        for class in classes {
            let json = serde_json::to_string(&class).unwrap();
            let back: InterferenceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn gate_decision_serde_roundtrip_all_variants() {
        for dec in [
            GateDecision::Promote,
            GateDecision::Hold,
            GateDecision::Reject,
        ] {
            let json = serde_json::to_string(&dec).unwrap();
            let back: GateDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(dec, back);
        }
    }

    #[test]
    fn flake_rate_boundary_single_run_single_mismatch() {
        let fr = FlakeRate::compute(1, 1, 0);
        assert_eq!(fr.rate_millionths, 1_000_000);
        assert!(!fr.within_threshold);
    }

    #[test]
    fn flake_rate_at_exact_threshold_boundary() {
        // 10 runs, 1 mismatch, threshold 100_000 (10%)
        let fr = FlakeRate::compute(10, 1, 100_000);
        assert_eq!(fr.rate_millionths, 100_000);
        assert!(fr.within_threshold);
    }

    #[test]
    fn witness_diff_only_witness_hash_differs() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"same"),
            witness_hash: ContentHash::compute(b"w1"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            merged_hash: ContentHash::compute(b"same"),
            witness_hash: ContentHash::compute(b"w2"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 1);
        assert_eq!(diff.diffs[0].field, "witness_hash");
    }

    // --- Enrichment: clone equality ---

    #[test]
    fn enrichment_interference_incident_clone_equality() {
        let incident = InterferenceIncident {
            class: InterferenceClass::ArtifactPipeline,
            severity: InterferenceSeverity::Warning,
            seed: 99,
            worker_count: 8,
            run_index: 3,
            expected_hash: ContentHash::compute(b"exp"),
            actual_hash: ContentHash::compute(b"act"),
            mismatch_token_index: Some(42),
            triage_hint: "artifact divergence".to_string(),
            remediation_playbook_id: "playbook.artifact".to_string(),
            replay_command: "replay --seed 99".to_string(),
        };
        let cloned = incident.clone();
        assert_eq!(incident, cloned);
    }

    #[test]
    fn enrichment_witness_diff_entry_clone_equality() {
        let entry = WitnessDiffEntry {
            field: "chunk_count".to_string(),
            expected: "3".to_string(),
            actual: "5".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn enrichment_witness_diff_clone_equality() {
        let diff = WitnessDiff {
            matches: false,
            diffs: vec![
                WitnessDiffEntry {
                    field: "merged_hash".to_string(),
                    expected: "aaa".to_string(),
                    actual: "bbb".to_string(),
                },
                WitnessDiffEntry {
                    field: "total_tokens".to_string(),
                    expected: "10".to_string(),
                    actual: "20".to_string(),
                },
            ],
        };
        let cloned = diff.clone();
        assert_eq!(diff, cloned);
    }

    #[test]
    fn enrichment_run_record_clone_equality() {
        let rr = RunRecord {
            seed: 55,
            worker_count: 2,
            run_index: 0,
            output_hash: ContentHash::compute(b"output"),
            token_count: 250,
            mode: ParserMode::Parallel,
            parity_ok: Some(true),
            merge_witness_hash: Some(ContentHash::compute(b"mw")),
        };
        let cloned = rr.clone();
        assert_eq!(rr, cloned);
    }

    #[test]
    fn enrichment_root_cause_hint_clone_equality() {
        let hint = RootCauseHint {
            class: InterferenceClass::BackpressureDrift,
            count: 7,
            severity: InterferenceSeverity::Critical,
            remediation: "add stable ordering tiebreaker".to_string(),
        };
        let cloned = hint.clone();
        assert_eq!(hint, cloned);
    }

    // --- Enrichment: JSON field presence ---

    #[test]
    fn enrichment_interference_incident_json_field_presence() {
        let incident = InterferenceIncident {
            class: InterferenceClass::TimeoutRace,
            severity: InterferenceSeverity::Info,
            seed: 1,
            worker_count: 2,
            run_index: 0,
            expected_hash: ContentHash::compute(b"e"),
            actual_hash: ContentHash::compute(b"a"),
            mismatch_token_index: None,
            triage_hint: "hint".to_string(),
            remediation_playbook_id: "pb".to_string(),
            replay_command: "cmd".to_string(),
        };
        let json = serde_json::to_string(&incident).unwrap();
        assert!(json.contains("\"class\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"worker_count\""));
        assert!(json.contains("\"run_index\""));
        assert!(json.contains("\"expected_hash\""));
        assert!(json.contains("\"actual_hash\""));
        assert!(json.contains("\"mismatch_token_index\""));
        assert!(json.contains("\"triage_hint\""));
        assert!(json.contains("\"remediation_playbook_id\""));
        assert!(json.contains("\"replay_command\""));
    }

    #[test]
    fn enrichment_flake_rate_json_field_presence() {
        let fr = FlakeRate::compute(50, 5, 200_000);
        let json = serde_json::to_string(&fr).unwrap();
        assert!(json.contains("\"total_runs\""));
        assert!(json.contains("\"mismatched_runs\""));
        assert!(json.contains("\"rate_millionths\""));
        assert!(json.contains("\"threshold_millionths\""));
        assert!(json.contains("\"within_threshold\""));
    }

    #[test]
    fn enrichment_operator_summary_json_field_presence() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let summary = generate_operator_summary(&result);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"decision\""));
        assert!(json.contains("\"total_runs\""));
        assert!(json.contains("\"incident_count\""));
        assert!(json.contains("\"root_cause_hints\""));
        assert!(json.contains("\"flake_rate_display\""));
        assert!(json.contains("\"recommended_action\""));
    }

    // --- Enrichment: serde roundtrip ---

    #[test]
    fn enrichment_root_cause_hint_serde_roundtrip() {
        let hint = RootCauseHint {
            class: InterferenceClass::DataStructureIteration,
            count: 3,
            severity: InterferenceSeverity::Warning,
            remediation: "Replace HashMap with BTreeMap in merge path.".to_string(),
        };
        let json = serde_json::to_string(&hint).unwrap();
        let back: RootCauseHint = serde_json::from_str(&json).unwrap();
        assert_eq!(hint, back);
    }

    // --- Enrichment: Display uniqueness ---

    #[test]
    fn enrichment_remediation_strings_all_unique() {
        let classes = [
            InterferenceClass::MergeOrder,
            InterferenceClass::Scheduler,
            InterferenceClass::DataStructureIteration,
            InterferenceClass::ArtifactPipeline,
            InterferenceClass::TimeoutRace,
            InterferenceClass::BackpressureDrift,
        ];
        let remediations: BTreeSet<String> =
            classes.iter().map(|c| remediation_for_class(*c)).collect();
        assert_eq!(
            remediations.len(),
            6,
            "all 6 classes should have unique remediation strings"
        );
    }

    // --- Enrichment: boundary condition ---

    #[test]
    fn enrichment_flake_rate_large_values_no_overflow() {
        // Near u64::MAX values -- checked_mul/checked_div should handle gracefully
        let fr = FlakeRate::compute(u64::MAX, 1, 0);
        // 1 * 1_000_000 / u64::MAX rounds to 0
        assert_eq!(fr.rate_millionths, 0);
        assert!(fr.within_threshold);
    }

    // --- Enrichment: Ord transitivity ---

    #[test]
    fn enrichment_interference_class_ord_full_transitivity() {
        let ordered = [
            InterferenceClass::MergeOrder,
            InterferenceClass::Scheduler,
            InterferenceClass::DataStructureIteration,
            InterferenceClass::ArtifactPipeline,
            InterferenceClass::TimeoutRace,
            InterferenceClass::BackpressureDrift,
        ];
        for i in 0..ordered.len() {
            for j in (i + 1)..ordered.len() {
                assert!(
                    ordered[i] < ordered[j],
                    "{:?} should be < {:?}",
                    ordered[i],
                    ordered[j]
                );
            }
        }
    }

    // --- Witness comparison: isolated field mismatches ----------------------

    #[test]
    fn witness_diff_chunk_count_only() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"same"),
            witness_hash: ContentHash::compute(b"same"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            chunk_count: 5,
            ..w1.clone()
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 1);
        assert_eq!(diff.diffs[0].field, "chunk_count");
    }

    #[test]
    fn witness_diff_boundary_repairs_only() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"same"),
            witness_hash: ContentHash::compute(b"same"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            boundary_repairs: 7,
            ..w1.clone()
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 1);
        assert_eq!(diff.diffs[0].field, "boundary_repairs");
    }

    #[test]
    fn witness_diff_total_tokens_only() {
        let w1 = MergeWitness {
            merged_hash: ContentHash::compute(b"same"),
            witness_hash: ContentHash::compute(b"same"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 50,
        };
        let w2 = MergeWitness {
            total_tokens: 99,
            ..w1.clone()
        };
        let diff = compare_witnesses(&w1, &w2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 1);
        assert_eq!(diff.diffs[0].field, "total_tokens");
    }

    // --- Transcript comparison: isolated field mismatches -------------------

    fn make_transcript(seed: u64) -> ScheduleTranscript {
        ScheduleTranscript {
            seed,
            worker_count: 2,
            plan_hash: ContentHash::compute(b"plan"),
            execution_order: vec![0, 1],
            dispatches: vec![
                ScheduleDispatch {
                    step_index: 0,
                    chunk_index: 0,
                    worker_slot: 0,
                },
                ScheduleDispatch {
                    step_index: 1,
                    chunk_index: 1,
                    worker_slot: 1,
                },
            ],
            transcript_hash: ContentHash::compute(b"transcript"),
        }
    }

    #[test]
    fn transcript_diff_worker_count_only() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            worker_count: 8,
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "worker_count"));
    }

    #[test]
    fn transcript_diff_plan_hash_only() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            plan_hash: ContentHash::compute(b"different-plan"),
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "plan_hash"));
    }

    #[test]
    fn transcript_diff_execution_order_only() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            execution_order: vec![1, 0],
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "execution_order"));
    }

    #[test]
    fn transcript_diff_dispatches_only() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            dispatches: vec![ScheduleDispatch {
                step_index: 0,
                chunk_index: 1,
                worker_slot: 0,
            }],
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "dispatches"));
    }

    #[test]
    fn transcript_diff_transcript_hash_only() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            transcript_hash: ContentHash::compute(b"other-hash"),
            ..t1.clone()
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert!(diff.diffs.iter().any(|d| d.field == "transcript_hash"));
    }

    #[test]
    fn transcript_diff_all_fields_differ() {
        let t1 = make_transcript(42);
        let t2 = ScheduleTranscript {
            seed: 99,
            worker_count: 8,
            plan_hash: ContentHash::compute(b"other"),
            execution_order: vec![1, 0],
            dispatches: vec![],
            transcript_hash: ContentHash::compute(b"other-hash"),
        };
        let diff = compare_transcripts(&t1, &t2);
        assert!(!diff.matches);
        assert_eq!(diff.diffs.len(), 6, "all 6 transcript fields should differ");
    }

    // --- Gate config variations --------------------------------------------

    #[test]
    fn gate_single_worker_variation() {
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let result = evaluate_gate(&test_source(), &config);
        assert_eq!(result.workers_tested, vec![2]);
        assert_eq!(result.total_runs, 1);
    }

    #[test]
    fn gate_no_serial_parity() {
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![2],
            require_serial_parity: false,
            ..GateConfig::default()
        };
        let result = evaluate_gate(&test_source(), &config);
        assert_eq!(result.decision, GateDecision::Promote);
    }

    #[test]
    fn gate_utf8_source() {
        let source = "var résumé = 'café';\nvar π = 3;\n".repeat(10);
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let result = evaluate_gate(&source, &config);
        assert!(result.total_runs >= 1);
    }

    #[test]
    fn gate_input_bytes_matches_source() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.input_bytes, source.len() as u64);
    }

    // --- Flake-rate edge cases ---------------------------------------------

    #[test]
    fn flake_rate_one_run_one_mismatch() {
        let fr = FlakeRate::compute(1, 1, 0);
        assert_eq!(fr.rate_millionths, 1_000_000);
        assert!(!fr.within_threshold);
    }

    #[test]
    fn flake_rate_mismatched_exceeds_total_clamped() {
        // If mismatched > total, clamp to 100%.
        let fr = FlakeRate::compute(5, 10, 0);
        assert_eq!(fr.mismatched_runs, 5);
        assert_eq!(fr.rate_millionths, 1_000_000);
        assert!(!fr.within_threshold);
    }

    #[test]
    fn flake_rate_within_threshold_boundary() {
        // Exactly at threshold should be within.
        let fr = FlakeRate::compute(100, 5, 50_000);
        assert_eq!(fr.rate_millionths, 50_000);
        assert!(fr.within_threshold);
    }

    #[test]
    fn flake_rate_just_above_threshold() {
        // 100 runs, 6 mismatches = 60_000, threshold 50_000.
        let fr = FlakeRate::compute(100, 6, 50_000);
        assert_eq!(fr.rate_millionths, 60_000);
        assert!(!fr.within_threshold);
    }

    // --- Operator summary edge cases ---------------------------------------

    #[test]
    fn operator_summary_fields_present() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let summary = generate_operator_summary(&result);
        assert!(!summary.flake_rate_display.is_empty());
        assert!(!summary.recommended_action.is_empty());
    }

    #[test]
    fn operator_summary_zero_incidents_no_hints() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let summary = generate_operator_summary(&result);
        assert_eq!(summary.incident_count, 0);
        assert!(summary.root_cause_hints.is_empty());
    }

    // --- Replay bundle edge cases ------------------------------------------

    #[test]
    fn replay_bundle_empty_on_promote() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert_eq!(result.decision, GateDecision::Promote);
        assert!(build_replay_bundle(&result).is_none());
    }

    #[test]
    fn replay_bundle_schema_version() {
        // Build a bundle with synthetic incidents.
        let bundle = ReplayBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash: ContentHash::compute(b"test"),
            input_bytes: 100,
            incidents: vec![],
            failing_seeds: vec![42],
            failing_workers: vec![2],
            replay_commands: vec!["franken-engine parse --seed 42".to_string()],
            reference_hash: ContentHash::compute(b"ref"),
        };
        assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn replay_bundle_serde_fields() {
        let bundle = ReplayBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            input_hash: ContentHash::compute(b"test"),
            input_bytes: 100,
            incidents: vec![],
            failing_seeds: vec![42, 99],
            failing_workers: vec![2, 4],
            replay_commands: vec!["cmd1".to_string(), "cmd2".to_string()],
            reference_hash: ContentHash::compute(b"ref"),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let back: ReplayBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
        assert_eq!(back.failing_seeds.len(), 2);
        assert_eq!(back.replay_commands.len(), 2);
    }

    // --- Rollback integration edge cases -----------------------------------

    #[test]
    fn rollback_not_triggered_on_promote() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        let mut rollback = RollbackControl::default();
        let triggered = apply_gate_to_rollback(&result, &mut rollback);
        assert!(!triggered);
    }

    // --- Gate result determinism with varied configs -----------------------

    #[test]
    fn gate_result_reference_hash_stable() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 2,
            repeats_per_seed: 2,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let r1 = evaluate_gate(&source, &config);
        let r2 = evaluate_gate(&source, &config);
        assert_eq!(r1.reference_hash, r2.reference_hash);
        assert_eq!(r1.input_hash, r2.input_hash);
    }

    // --- Run record coverage -----------------------------------------------

    #[test]
    fn run_record_fields_from_gate() {
        let source = test_source();
        let config = GateConfig {
            seed_count: 1,
            repeats_per_seed: 1,
            worker_variations: vec![2],
            ..GateConfig::default()
        };
        let result = evaluate_gate(&source, &config);
        assert!(!result.runs.is_empty());
        let run = &result.runs[0];
        assert!(run.token_count > 0);
        assert_eq!(run.run_index, 0);
    }

    // --- GateResult accessors & constants ----------------------------------

    #[test]
    fn component_constant() {
        assert_eq!(COMPONENT, "parallel_interference_gate");
    }

    #[test]
    fn default_constants() {
        assert_eq!(DEFAULT_SEED_COUNT, 10);
        assert_eq!(DEFAULT_REPEATS_PER_SEED, 3);
        assert_eq!(DEFAULT_FLAKE_THRESHOLD_MILLIONTHS, 0);
        assert_eq!(DEFAULT_MAX_WORKER_VARIATIONS, 4);
    }

    #[test]
    fn gate_result_no_incidents_means_promote() {
        let source = test_source();
        let config = small_gate_config();
        let result = evaluate_gate(&source, &config);
        assert!(result.incidents.is_empty());
        assert_eq!(result.decision, GateDecision::Promote);
    }

    // --- WitnessDiffEntry clone & equality ----------------------------------

    #[test]
    fn witness_diff_entry_fields() {
        let entry = WitnessDiffEntry {
            field: "merged_hash".to_string(),
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        let clone = entry.clone();
        assert_eq!(entry, clone);
        assert_eq!(entry.field, "merged_hash");
    }
}
