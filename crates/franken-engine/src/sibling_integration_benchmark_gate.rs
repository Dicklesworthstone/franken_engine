//! Deterministic benchmark gate for sibling-repo integration overhead.
//!
//! Plan reference: Section 10.14 item 13 (`bd-1coe`).
//!
//! This gate validates that control-plane latency SLOs remain within budget
//! when sibling integrations are enabled (`frankentui`, `frankensqlite`,
//! `sqlmodel_rust`, `fastapi_rust`) and that integration overhead is bounded
//! relative to a no-integration control run.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const SIBLING_BENCHMARK_GATE_DOMAIN: &[u8] = b"FrankenEngine.SiblingIntegrationBenchmarkGate.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Canonical sibling integrations covered by this gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SiblingIntegration {
    Frankentui,
    Frankensqlite,
    SqlmodelRust,
    FastapiRust,
}

impl SiblingIntegration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Frankentui => "frankentui",
            Self::Frankensqlite => "frankensqlite",
            Self::SqlmodelRust => "sqlmodel_rust",
            Self::FastapiRust => "fastapi_rust",
        }
    }

    fn all_required() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::Frankentui,
            Self::Frankensqlite,
            Self::SqlmodelRust,
            Self::FastapiRust,
        ])
    }
}

impl fmt::Display for SiblingIntegration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Control-plane operations with explicit p95/p99 SLOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ControlPlaneOperation {
    EvidenceWrite,
    PolicyQuery,
    TelemetryIngestion,
    TuiDataUpdate,
}

impl ControlPlaneOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceWrite => "evidence_write",
            Self::PolicyQuery => "policy_query",
            Self::TelemetryIngestion => "telemetry_ingestion",
            Self::TuiDataUpdate => "tui_data_update",
        }
    }
}

impl fmt::Display for ControlPlaneOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Latency samples in nanoseconds for an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationLatencySamples {
    /// Control run with sibling integrations disabled.
    pub without_integrations_ns: Vec<u64>,
    /// Integrated run with sibling integrations enabled.
    pub with_integrations_ns: Vec<u64>,
}

impl OperationLatencySamples {
    fn sorted_without(&self) -> Vec<u64> {
        let mut sorted = self.without_integrations_ns.clone();
        sorted.sort_unstable();
        sorted
    }

    fn sorted_with(&self) -> Vec<u64> {
        let mut sorted = self.with_integrations_ns.clone();
        sorted.sort_unstable();
        sorted
    }
}

/// Benchmark snapshot for one run ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSnapshot {
    pub snapshot_id: String,
    pub benchmark_run_id: String,
    pub integrations: BTreeSet<SiblingIntegration>,
    pub operation_samples: BTreeMap<ControlPlaneOperation, OperationLatencySamples>,
}

impl BenchmarkSnapshot {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "benchmark_run_id".to_string(),
            CanonicalValue::String(self.benchmark_run_id.clone()),
        );
        map.insert(
            "integrations".to_string(),
            CanonicalValue::Array(
                self.integrations
                    .iter()
                    .copied()
                    .map(|integration| CanonicalValue::String(integration.as_str().to_string()))
                    .collect(),
            ),
        );

        let mut operations_map = BTreeMap::new();
        for (operation, samples) in &self.operation_samples {
            let mut operation_map = BTreeMap::new();
            operation_map.insert(
                "with_integrations_ns".to_string(),
                CanonicalValue::Array(
                    samples
                        .sorted_with()
                        .into_iter()
                        .map(CanonicalValue::U64)
                        .collect(),
                ),
            );
            operation_map.insert(
                "without_integrations_ns".to_string(),
                CanonicalValue::Array(
                    samples
                        .sorted_without()
                        .into_iter()
                        .map(CanonicalValue::U64)
                        .collect(),
                ),
            );
            operations_map.insert(
                operation.as_str().to_string(),
                CanonicalValue::Map(operation_map),
            );
        }
        map.insert(
            "operation_samples".to_string(),
            CanonicalValue::Map(operations_map),
        );
        map.insert(
            "snapshot_id".to_string(),
            CanonicalValue::String(self.snapshot_id.clone()),
        );
        CanonicalValue::Map(map)
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineLedgerEntry {
    pub epoch: u64,
    pub snapshot_hash: [u8; 32],
    pub snapshot: BenchmarkSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BaselineLedger {
    pub entries: Vec<BaselineLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineLedgerError {
    NonMonotonicEpoch {
        previous_epoch: u64,
        next_epoch: u64,
    },
    DuplicateSnapshotHash {
        snapshot_hash: [u8; 32],
    },
}

impl fmt::Display for BaselineLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicEpoch {
                previous_epoch,
                next_epoch,
            } => write!(
                f,
                "baseline epoch must be strictly increasing: previous={previous_epoch} next={next_epoch}"
            ),
            Self::DuplicateSnapshotHash { snapshot_hash } => write!(
                f,
                "baseline snapshot hash already recorded: {}",
                to_hex(snapshot_hash)
            ),
        }
    }
}

impl std::error::Error for BaselineLedgerError {}

impl BaselineLedger {
    pub fn record(
        &mut self,
        epoch: u64,
        snapshot: BenchmarkSnapshot,
    ) -> Result<[u8; 32], BaselineLedgerError> {
        if let Some(last) = self.entries.last()
            && epoch <= last.epoch
        {
            return Err(BaselineLedgerError::NonMonotonicEpoch {
                previous_epoch: last.epoch,
                next_epoch: epoch,
            });
        }

        let snapshot_hash = snapshot.snapshot_hash();
        if self
            .entries
            .iter()
            .any(|entry| entry.snapshot_hash == snapshot_hash)
        {
            return Err(BaselineLedgerError::DuplicateSnapshotHash { snapshot_hash });
        }

        self.entries.push(BaselineLedgerEntry {
            epoch,
            snapshot_hash,
            snapshot,
        });
        Ok(snapshot_hash)
    }

    pub fn latest(&self) -> Option<&BaselineLedgerEntry> {
        self.entries.last()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub baseline: BenchmarkSnapshot,
    pub candidate: BenchmarkSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSloThreshold {
    pub p95_ns: u64,
    pub p99_ns: u64,
    /// Max tolerated increase vs baseline, in millionths (1_000_000 = 1.0x).
    pub max_regression_millionths: u64,
    /// Max tolerated overhead for integrated run vs no-integration run.
    pub max_integration_overhead_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateThresholds {
    pub required_integrations: BTreeSet<SiblingIntegration>,
    pub per_operation: BTreeMap<ControlPlaneOperation, OperationSloThreshold>,
}

impl Default for BenchmarkGateThresholds {
    fn default() -> Self {
        let mut per_operation = BTreeMap::new();
        per_operation.insert(
            ControlPlaneOperation::EvidenceWrite,
            OperationSloThreshold {
                p95_ns: 5_000_000,
                p99_ns: 10_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::PolicyQuery,
            OperationSloThreshold {
                p95_ns: 3_000_000,
                p99_ns: 6_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::TelemetryIngestion,
            OperationSloThreshold {
                p95_ns: 4_000_000,
                p99_ns: 8_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::TuiDataUpdate,
            OperationSloThreshold {
                p95_ns: 7_000_000,
                p99_ns: 12_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        Self {
            required_integrations: SiblingIntegration::all_required(),
            per_operation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkGateFailureCode {
    MissingRequiredIntegration,
    MissingOperationSamples,
    EmptySamples,
    SloThresholdExceeded,
    RegressionThresholdExceeded,
    IntegrationOverheadExceeded,
}

impl fmt::Display for BenchmarkGateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredIntegration => f.write_str("missing_required_integration"),
            Self::MissingOperationSamples => f.write_str("missing_operation_samples"),
            Self::EmptySamples => f.write_str("empty_samples"),
            Self::SloThresholdExceeded => f.write_str("slo_threshold_exceeded"),
            Self::RegressionThresholdExceeded => f.write_str("regression_threshold_exceeded"),
            Self::IntegrationOverheadExceeded => f.write_str("integration_overhead_exceeded"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateFinding {
    pub code: BenchmarkGateFailureCode,
    pub operation: Option<ControlPlaneOperation>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationBenchmarkEvaluation {
    pub operation: ControlPlaneOperation,
    pub baseline_p95_ns: u64,
    pub baseline_p99_ns: u64,
    pub candidate_p95_ns: u64,
    pub candidate_p99_ns: u64,
    pub candidate_without_integrations_p95_ns: u64,
    pub candidate_without_integrations_p99_ns: u64,
    pub regression_p95_millionths: u64,
    pub regression_p99_millionths: u64,
    pub integration_overhead_p95_millionths: u64,
    pub integration_overhead_p99_millionths: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub operation: Option<String>,
    pub candidate_p95_ns: Option<u64>,
    pub candidate_p99_ns: Option<u64>,
    pub baseline_p95_ns: Option<u64>,
    pub baseline_p99_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateDecision {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub baseline_snapshot_hash: [u8; 32],
    pub candidate_snapshot_hash: [u8; 32],
    pub evaluations: Vec<OperationBenchmarkEvaluation>,
    pub findings: Vec<BenchmarkGateFinding>,
    pub logs: Vec<BenchmarkGateLogEvent>,
}

fn percentile(sorted_samples: &[u64], percentile: usize) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let rank = percentile
        .saturating_mul(sorted_samples.len())
        .div_ceil(100);
    let index = rank.saturating_sub(1).min(sorted_samples.len() - 1);
    sorted_samples[index]
}

fn ratio_millionths(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let m = (numerator as u128 * 1_000_000) / (denominator as u128);
    if m > u64::MAX as u128 {
        u64::MAX
    } else {
        m as u64
    }
}

fn overhead_millionths(with_integrations_ns: u64, without_integrations_ns: u64) -> u64 {
    if without_integrations_ns == 0 {
        return u64::MAX;
    }
    if with_integrations_ns <= without_integrations_ns {
        return 0;
    }
    let diff = with_integrations_ns.saturating_sub(without_integrations_ns);
    let m = (diff as u128 * 1_000_000) / (without_integrations_ns as u128);
    if m > u64::MAX as u128 {
        u64::MAX
    } else {
        m as u64
    }
}

fn decision_canonical_value(
    input: &BenchmarkGateInput,
    baseline_hash: [u8; 32],
    candidate_hash: [u8; 32],
    pass: bool,
    evaluations: &[OperationBenchmarkEvaluation],
    findings: &[BenchmarkGateFinding],
) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "baseline_snapshot_hash".to_string(),
        CanonicalValue::Bytes(baseline_hash.to_vec()),
    );
    map.insert(
        "candidate_snapshot_hash".to_string(),
        CanonicalValue::Bytes(candidate_hash.to_vec()),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );

    map.insert(
        "evaluations".to_string(),
        CanonicalValue::Array(
            evaluations
                .iter()
                .map(|evaluation| {
                    let mut evaluation_map = BTreeMap::new();
                    evaluation_map.insert(
                        "baseline_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.baseline_p95_ns),
                    );
                    evaluation_map.insert(
                        "baseline_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.baseline_p99_ns),
                    );
                    evaluation_map.insert(
                        "candidate_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_p95_ns),
                    );
                    evaluation_map.insert(
                        "candidate_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_p99_ns),
                    );
                    evaluation_map.insert(
                        "candidate_without_integrations_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_without_integrations_p95_ns),
                    );
                    evaluation_map.insert(
                        "candidate_without_integrations_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_without_integrations_p99_ns),
                    );
                    evaluation_map.insert(
                        "integration_overhead_p95_millionths".to_string(),
                        CanonicalValue::U64(evaluation.integration_overhead_p95_millionths),
                    );
                    evaluation_map.insert(
                        "integration_overhead_p99_millionths".to_string(),
                        CanonicalValue::U64(evaluation.integration_overhead_p99_millionths),
                    );
                    evaluation_map.insert(
                        "operation".to_string(),
                        CanonicalValue::String(evaluation.operation.as_str().to_string()),
                    );
                    evaluation_map
                        .insert("pass".to_string(), CanonicalValue::Bool(evaluation.pass));
                    evaluation_map.insert(
                        "regression_p95_millionths".to_string(),
                        CanonicalValue::U64(evaluation.regression_p95_millionths),
                    );
                    evaluation_map.insert(
                        "regression_p99_millionths".to_string(),
                        CanonicalValue::U64(evaluation.regression_p99_millionths),
                    );
                    CanonicalValue::Map(evaluation_map)
                })
                .collect(),
        ),
    );

    map.insert(
        "findings".to_string(),
        CanonicalValue::Array(
            findings
                .iter()
                .map(|finding| {
                    let mut finding_map = BTreeMap::new();
                    finding_map.insert(
                        "code".to_string(),
                        CanonicalValue::String(finding.code.to_string()),
                    );
                    finding_map.insert(
                        "detail".to_string(),
                        CanonicalValue::String(finding.detail.clone()),
                    );
                    finding_map.insert(
                        "operation".to_string(),
                        match finding.operation {
                            Some(operation) => {
                                CanonicalValue::String(operation.as_str().to_string())
                            }
                            None => CanonicalValue::Null,
                        },
                    );
                    CanonicalValue::Map(finding_map)
                })
                .collect(),
        ),
    );

    CanonicalValue::Map(map)
}

/// Evaluate sibling integration benchmark results against deterministic SLO gates.
pub fn evaluate_sibling_integration_benchmark(
    input: &BenchmarkGateInput,
    thresholds: &BenchmarkGateThresholds,
) -> BenchmarkGateDecision {
    let baseline_hash = input.baseline.snapshot_hash();
    let candidate_hash = input.candidate.snapshot_hash();

    let mut findings = Vec::new();
    let mut evaluations = Vec::new();

    for required in &thresholds.required_integrations {
        if !input.baseline.integrations.contains(required) {
            findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingRequiredIntegration,
                operation: None,
                detail: format!("baseline snapshot missing required integration `{required}`"),
            });
        }
        if !input.candidate.integrations.contains(required) {
            findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingRequiredIntegration,
                operation: None,
                detail: format!("candidate snapshot missing required integration `{required}`"),
            });
        }
    }

    for (operation, operation_slo) in &thresholds.per_operation {
        let baseline_samples = input.baseline.operation_samples.get(operation);
        let candidate_samples = input.candidate.operation_samples.get(operation);
        match (baseline_samples, candidate_samples) {
            (Some(baseline_samples), Some(candidate_samples)) => {
                if baseline_samples.with_integrations_ns.is_empty()
                    || baseline_samples.without_integrations_ns.is_empty()
                    || candidate_samples.with_integrations_ns.is_empty()
                    || candidate_samples.without_integrations_ns.is_empty()
                {
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::EmptySamples,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` must include non-empty with/without sample vectors for baseline and candidate"
                        ),
                    });
                    continue;
                }

                let baseline_with_sorted = baseline_samples.sorted_with();
                let candidate_with_sorted = candidate_samples.sorted_with();
                let candidate_without_sorted = candidate_samples.sorted_without();

                let baseline_p95 = percentile(&baseline_with_sorted, 95);
                let baseline_p99 = percentile(&baseline_with_sorted, 99);
                let candidate_p95 = percentile(&candidate_with_sorted, 95);
                let candidate_p99 = percentile(&candidate_with_sorted, 99);
                let candidate_without_p95 = percentile(&candidate_without_sorted, 95);
                let candidate_without_p99 = percentile(&candidate_without_sorted, 99);

                let regression_p95 = ratio_millionths(candidate_p95, baseline_p95);
                let regression_p99 = ratio_millionths(candidate_p99, baseline_p99);
                let overhead_p95 =
                    overhead_millionths(candidate_p95, candidate_without_p95);
                let overhead_p99 =
                    overhead_millionths(candidate_p99, candidate_without_p99);

                let mut operation_pass = true;

                if candidate_p95 > operation_slo.p95_ns || candidate_p99 > operation_slo.p99_ns {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::SloThresholdExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` candidate p95/p99 exceeded SLO (p95 {} ns <= {} ns, p99 {} ns <= {} ns required)",
                            candidate_p95, operation_slo.p95_ns, candidate_p99, operation_slo.p99_ns
                        ),
                    });
                }

                let max_regression_ratio =
                    1_000_000u64.saturating_add(operation_slo.max_regression_millionths);
                if regression_p95 > max_regression_ratio || regression_p99 > max_regression_ratio {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::RegressionThresholdExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` regressed beyond threshold (p95 ratio {} ppm, p99 ratio {} ppm, max {} ppm)",
                            regression_p95, regression_p99, max_regression_ratio
                        ),
                    });
                }

                if overhead_p95 > operation_slo.max_integration_overhead_millionths
                    || overhead_p99 > operation_slo.max_integration_overhead_millionths
                {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::IntegrationOverheadExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` integration overhead exceeded threshold (p95 {} ppm, p99 {} ppm, max {} ppm)",
                            overhead_p95,
                            overhead_p99,
                            operation_slo.max_integration_overhead_millionths
                        ),
                    });
                }

                evaluations.push(OperationBenchmarkEvaluation {
                    operation: *operation,
                    baseline_p95_ns: baseline_p95,
                    baseline_p99_ns: baseline_p99,
                    candidate_p95_ns: candidate_p95,
                    candidate_p99_ns: candidate_p99,
                    candidate_without_integrations_p95_ns: candidate_without_p95,
                    candidate_without_integrations_p99_ns: candidate_without_p99,
                    regression_p95_millionths: regression_p95,
                    regression_p99_millionths: regression_p99,
                    integration_overhead_p95_millionths: overhead_p95,
                    integration_overhead_p99_millionths: overhead_p99,
                    pass: operation_pass,
                });
            }
            _ => findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingOperationSamples,
                operation: Some(*operation),
                detail: format!(
                    "operation `{operation}` missing from baseline and/or candidate benchmark snapshot"
                ),
            }),
        }
    }

    let pass = findings.is_empty() && evaluations.iter().all(|evaluation| evaluation.pass);
    let decision_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(SIBLING_BENCHMARK_GATE_DOMAIN.to_vec()),
            decision_canonical_value(
                input,
                baseline_hash,
                candidate_hash,
                pass,
                &evaluations,
                &findings,
            ),
        ],
    )));
    let decision_id = format!("sib-bench-gate-{}", to_hex(&decision_hash[..16]));

    let mut logs = Vec::new();
    for evaluation in &evaluations {
        let maybe_failure = findings.iter().find_map(|finding| {
            if finding.operation == Some(evaluation.operation) {
                Some(finding.code.to_string())
            } else {
                None
            }
        });
        logs.push(BenchmarkGateLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "sibling_integration_benchmark_gate".to_string(),
            event: "operation_slo_check".to_string(),
            outcome: if evaluation.pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: maybe_failure,
            operation: Some(evaluation.operation.as_str().to_string()),
            candidate_p95_ns: Some(evaluation.candidate_p95_ns),
            candidate_p99_ns: Some(evaluation.candidate_p99_ns),
            baseline_p95_ns: Some(evaluation.baseline_p95_ns),
            baseline_p99_ns: Some(evaluation.baseline_p99_ns),
        });
    }
    logs.push(BenchmarkGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "sibling_integration_benchmark_gate".to_string(),
        event: "benchmark_gate_decision".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("benchmark_gate_failed".to_string())
        },
        operation: None,
        candidate_p95_ns: None,
        candidate_p99_ns: None,
        baseline_p95_ns: None,
        baseline_p99_ns: None,
    });

    BenchmarkGateDecision {
        decision_id,
        pass,
        rollback_required: !pass,
        baseline_snapshot_hash: baseline_hash,
        candidate_snapshot_hash: candidate_hash,
        evaluations,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_integrations() -> BTreeSet<SiblingIntegration> {
        SiblingIntegration::all_required()
    }

    fn make_samples(without: &[u64], with: &[u64]) -> OperationLatencySamples {
        OperationLatencySamples {
            without_integrations_ns: without.to_vec(),
            with_integrations_ns: with.to_vec(),
        }
    }

    fn base_snapshot() -> BenchmarkSnapshot {
        let mut operation_samples = BTreeMap::new();
        operation_samples.insert(
            ControlPlaneOperation::EvidenceWrite,
            make_samples(
                &[1_000_000, 1_020_000, 1_010_000, 1_050_000, 1_040_000],
                &[1_200_000, 1_220_000, 1_210_000, 1_260_000, 1_240_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[800_000, 820_000, 810_000, 830_000, 840_000],
                &[950_000, 960_000, 955_000, 980_000, 990_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[900_000, 910_000, 920_000, 930_000, 940_000],
                &[1_080_000, 1_090_000, 1_100_000, 1_120_000, 1_130_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TuiDataUpdate,
            make_samples(
                &[1_200_000, 1_220_000, 1_230_000, 1_240_000, 1_250_000],
                &[1_420_000, 1_430_000, 1_440_000, 1_460_000, 1_470_000],
            ),
        );
        BenchmarkSnapshot {
            snapshot_id: "baseline-snapshot-1".to_string(),
            benchmark_run_id: "baseline-run-1".to_string(),
            integrations: full_integrations(),
            operation_samples,
        }
    }

    fn candidate_snapshot_pass() -> BenchmarkSnapshot {
        let mut operation_samples = BTreeMap::new();
        operation_samples.insert(
            ControlPlaneOperation::EvidenceWrite,
            make_samples(
                &[1_010_000, 1_020_000, 1_030_000, 1_040_000, 1_050_000],
                &[1_220_000, 1_230_000, 1_240_000, 1_250_000, 1_260_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 825_000, 830_000, 835_000],
                &[970_000, 975_000, 980_000, 985_000, 990_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[910_000, 920_000, 930_000, 935_000, 940_000],
                &[1_090_000, 1_100_000, 1_110_000, 1_115_000, 1_120_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TuiDataUpdate,
            make_samples(
                &[1_210_000, 1_220_000, 1_230_000, 1_235_000, 1_240_000],
                &[1_430_000, 1_435_000, 1_440_000, 1_445_000, 1_450_000],
            ),
        );
        BenchmarkSnapshot {
            snapshot_id: "candidate-snapshot-pass".to_string(),
            benchmark_run_id: "candidate-run-pass".to_string(),
            integrations: full_integrations(),
            operation_samples,
        }
    }

    #[test]
    fn gate_passes_for_valid_candidate_and_emits_logs() {
        let input = BenchmarkGateInput {
            trace_id: "trace-bench-pass".to_string(),
            policy_id: "policy-bench-pass".to_string(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };

        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(decision.pass);
        assert!(!decision.rollback_required);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.evaluations.len(), 4);
        assert_eq!(decision.logs.len(), 5);
        assert_eq!(
            decision.logs.last().map(|log| log.event.as_str()),
            Some("benchmark_gate_decision")
        );
    }

    #[test]
    fn gate_fails_when_candidate_missing_required_integration() {
        let mut candidate = candidate_snapshot_pass();
        candidate
            .integrations
            .remove(&SiblingIntegration::FastapiRust);

        let input = BenchmarkGateInput {
            trace_id: "trace-missing-integration".to_string(),
            policy_id: "policy-missing-integration".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(
            decision
                .findings
                .iter()
                .any(|finding| finding.code == BenchmarkGateFailureCode::MissingRequiredIntegration)
        );
    }

    #[test]
    fn gate_fails_when_regression_exceeds_threshold() {
        let mut candidate = candidate_snapshot_pass();
        candidate.operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 830_000, 840_000, 850_000],
                &[1_250_000, 1_260_000, 1_270_000, 1_280_000, 1_300_000],
            ),
        );

        let input = BenchmarkGateInput {
            trace_id: "trace-regression".to_string(),
            policy_id: "policy-regression".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkGateFailureCode::RegressionThresholdExceeded
                && finding.operation == Some(ControlPlaneOperation::PolicyQuery)
        }));
    }

    #[test]
    fn gate_fails_when_integration_overhead_exceeds_threshold() {
        let mut candidate = candidate_snapshot_pass();
        candidate.operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[900_000, 910_000, 920_000, 930_000, 940_000],
                &[1_600_000, 1_650_000, 1_700_000, 1_750_000, 1_800_000],
            ),
        );
        let input = BenchmarkGateInput {
            trace_id: "trace-overhead".to_string(),
            policy_id: "policy-overhead".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkGateFailureCode::IntegrationOverheadExceeded
                && finding.operation == Some(ControlPlaneOperation::TelemetryIngestion)
        }));
    }

    #[test]
    fn decision_id_is_deterministic_across_sample_ordering() {
        let baseline = base_snapshot();
        let candidate = candidate_snapshot_pass();
        let input_a = BenchmarkGateInput {
            trace_id: "trace-deterministic".to_string(),
            policy_id: "policy-deterministic".to_string(),
            baseline: baseline.clone(),
            candidate: candidate.clone(),
        };

        let mut shuffled_candidate = candidate.clone();
        let telemetry = shuffled_candidate
            .operation_samples
            .get_mut(&ControlPlaneOperation::TelemetryIngestion)
            .expect("telemetry sample must exist");
        telemetry.with_integrations_ns.reverse();
        telemetry.without_integrations_ns.reverse();
        let input_b = BenchmarkGateInput {
            trace_id: "trace-deterministic".to_string(),
            policy_id: "policy-deterministic".to_string(),
            baseline,
            candidate: shuffled_candidate,
        };

        let decision_a =
            evaluate_sibling_integration_benchmark(&input_a, &BenchmarkGateThresholds::default());
        let decision_b =
            evaluate_sibling_integration_benchmark(&input_b, &BenchmarkGateThresholds::default());

        assert_eq!(decision_a.decision_id, decision_b.decision_id);
        assert_eq!(decision_a.pass, decision_b.pass);
        assert_eq!(decision_a.findings, decision_b.findings);
    }

    #[test]
    fn baseline_ledger_tracks_monotonic_epochs_and_rejects_duplicate_snapshots() {
        let mut ledger = BaselineLedger::default();
        let baseline = base_snapshot();
        let hash = ledger
            .record(1, baseline.clone())
            .expect("first baseline should record");
        assert_eq!(ledger.latest().expect("latest").snapshot_hash, hash);

        let non_monotonic = ledger.record(1, candidate_snapshot_pass());
        assert!(matches!(
            non_monotonic,
            Err(BaselineLedgerError::NonMonotonicEpoch { .. })
        ));

        let duplicate_hash = ledger.record(2, baseline);
        assert!(matches!(
            duplicate_hash,
            Err(BaselineLedgerError::DuplicateSnapshotHash { .. })
        ));
    }

    // ── SiblingIntegration ───────────────────────────────────────────

    #[test]
    fn sibling_integration_as_str() {
        assert_eq!(SiblingIntegration::Frankentui.as_str(), "frankentui");
        assert_eq!(SiblingIntegration::Frankensqlite.as_str(), "frankensqlite");
        assert_eq!(SiblingIntegration::SqlmodelRust.as_str(), "sqlmodel_rust");
        assert_eq!(SiblingIntegration::FastapiRust.as_str(), "fastapi_rust");
    }

    #[test]
    fn sibling_integration_display() {
        assert_eq!(SiblingIntegration::Frankentui.to_string(), "frankentui");
    }

    #[test]
    fn sibling_integration_ordering() {
        assert!(SiblingIntegration::Frankentui < SiblingIntegration::SqlmodelRust);
    }

    #[test]
    fn sibling_integration_serde_roundtrip() {
        for integration in [
            SiblingIntegration::Frankentui,
            SiblingIntegration::Frankensqlite,
            SiblingIntegration::SqlmodelRust,
            SiblingIntegration::FastapiRust,
        ] {
            // SAFETY: SiblingIntegration derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&integration).unwrap();
            // SAFETY: JSON was just produced by to_string of a valid SiblingIntegration,
            // so from_str back to SiblingIntegration cannot fail (valid format + matching schema).
            let back: SiblingIntegration = serde_json::from_str(&json).unwrap();
            assert_eq!(back, integration);
        }
    }

    // ── ControlPlaneOperation ────────────────────────────────────────

    #[test]
    fn control_plane_operation_as_str() {
        assert_eq!(
            ControlPlaneOperation::EvidenceWrite.as_str(),
            "evidence_write"
        );
        assert_eq!(ControlPlaneOperation::PolicyQuery.as_str(), "policy_query");
        assert_eq!(
            ControlPlaneOperation::TelemetryIngestion.as_str(),
            "telemetry_ingestion"
        );
        assert_eq!(
            ControlPlaneOperation::TuiDataUpdate.as_str(),
            "tui_data_update"
        );
    }

    #[test]
    fn control_plane_operation_display() {
        assert_eq!(
            ControlPlaneOperation::TuiDataUpdate.to_string(),
            "tui_data_update"
        );
    }

    #[test]
    fn control_plane_operation_serde_roundtrip() {
        for op in [
            ControlPlaneOperation::EvidenceWrite,
            ControlPlaneOperation::PolicyQuery,
            ControlPlaneOperation::TelemetryIngestion,
            ControlPlaneOperation::TuiDataUpdate,
        ] {
            // SAFETY: ControlPlaneOperation derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&op).unwrap();
            // SAFETY: JSON was just produced by to_string of a valid ControlPlaneOperation,
            // so from_str back to ControlPlaneOperation cannot fail (valid format + matching schema).
            let back: ControlPlaneOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(back, op);
        }
    }

    // ── BenchmarkGateFailureCode ─────────────────────────────────────

    #[test]
    fn failure_code_display_all_variants() {
        assert_eq!(
            BenchmarkGateFailureCode::MissingRequiredIntegration.to_string(),
            "missing_required_integration"
        );
        assert_eq!(
            BenchmarkGateFailureCode::MissingOperationSamples.to_string(),
            "missing_operation_samples"
        );
        assert_eq!(
            BenchmarkGateFailureCode::EmptySamples.to_string(),
            "empty_samples"
        );
        assert_eq!(
            BenchmarkGateFailureCode::SloThresholdExceeded.to_string(),
            "slo_threshold_exceeded"
        );
        assert_eq!(
            BenchmarkGateFailureCode::RegressionThresholdExceeded.to_string(),
            "regression_threshold_exceeded"
        );
        assert_eq!(
            BenchmarkGateFailureCode::IntegrationOverheadExceeded.to_string(),
            "integration_overhead_exceeded"
        );
    }

    #[test]
    fn failure_code_ordering() {
        assert!(
            BenchmarkGateFailureCode::MissingRequiredIntegration
                < BenchmarkGateFailureCode::IntegrationOverheadExceeded
        );
    }

    #[test]
    fn failure_code_serde_roundtrip() {
        for code in [
            BenchmarkGateFailureCode::MissingRequiredIntegration,
            BenchmarkGateFailureCode::MissingOperationSamples,
            BenchmarkGateFailureCode::EmptySamples,
            BenchmarkGateFailureCode::SloThresholdExceeded,
            BenchmarkGateFailureCode::RegressionThresholdExceeded,
            BenchmarkGateFailureCode::IntegrationOverheadExceeded,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: BenchmarkGateFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    // ── BenchmarkGateThresholds default ──────────────────────────────

    #[test]
    fn thresholds_default_has_all_integrations() {
        let t = BenchmarkGateThresholds::default();
        assert_eq!(t.required_integrations.len(), 4);
        assert!(
            t.required_integrations
                .contains(&SiblingIntegration::Frankentui)
        );
        assert!(
            t.required_integrations
                .contains(&SiblingIntegration::FastapiRust)
        );
    }

    #[test]
    fn thresholds_default_has_all_operations() {
        let t = BenchmarkGateThresholds::default();
        assert_eq!(t.per_operation.len(), 4);
        assert!(
            t.per_operation
                .contains_key(&ControlPlaneOperation::EvidenceWrite)
        );
        assert!(
            t.per_operation
                .contains_key(&ControlPlaneOperation::TuiDataUpdate)
        );
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = BenchmarkGateThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: BenchmarkGateThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ── Empty samples finding ────────────────────────────────────────

    #[test]
    fn gate_fails_on_empty_samples() {
        let mut candidate = candidate_snapshot_pass();
        candidate.operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(&[], &[1_000_000]),
        );
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkGateFailureCode::EmptySamples
                && f.operation == Some(ControlPlaneOperation::PolicyQuery)
        }));
    }

    // ── Missing operation samples ────────────────────────────────────

    #[test]
    fn gate_fails_on_missing_operation_samples() {
        let mut candidate = candidate_snapshot_pass();
        candidate
            .operation_samples
            .remove(&ControlPlaneOperation::EvidenceWrite);
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkGateFailureCode::MissingOperationSamples
                && f.operation == Some(ControlPlaneOperation::EvidenceWrite)
        }));
    }

    // ── SLO threshold exceeded ───────────────────────────────────────

    #[test]
    fn gate_fails_when_slo_exceeded() {
        let mut candidate = candidate_snapshot_pass();
        // Set p95 above SLO of 3_000_000 for PolicyQuery
        candidate.operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 830_000, 840_000, 850_000],
                &[3_100_000, 3_200_000, 3_300_000, 3_400_000, 3_500_000],
            ),
        );
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkGateFailureCode::SloThresholdExceeded
                && f.operation == Some(ControlPlaneOperation::PolicyQuery)
        }));
    }

    // ── BaselineLedgerError display ──────────────────────────────────

    #[test]
    fn baseline_ledger_error_display_non_monotonic() {
        let err = BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch: 5,
            next_epoch: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("strictly increasing"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn baseline_ledger_error_display_duplicate_hash() {
        let err = BaselineLedgerError::DuplicateSnapshotHash {
            snapshot_hash: [0xab; 32],
        };
        let msg = err.to_string();
        assert!(msg.contains("abababab"));
    }

    #[test]
    fn baseline_ledger_error_serde_roundtrip() {
        let err = BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch: 10,
            next_epoch: 5,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: BaselineLedgerError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }

    // ── BaselineLedger ───────────────────────────────────────────────

    #[test]
    fn baseline_ledger_latest_empty_returns_none() {
        let ledger = BaselineLedger::default();
        assert!(ledger.latest().is_none());
    }

    #[test]
    fn baseline_ledger_multiple_entries() {
        let mut ledger = BaselineLedger::default();
        ledger.record(1, base_snapshot()).unwrap();
        ledger.record(2, candidate_snapshot_pass()).unwrap();
        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.latest().unwrap().epoch, 2);
    }

    // ── Snapshot hash ────────────────────────────────────────────────

    #[test]
    fn snapshot_hash_deterministic() {
        let snap = base_snapshot();
        assert_eq!(snap.snapshot_hash(), snap.snapshot_hash());
    }

    #[test]
    fn snapshot_hash_changes_with_data() {
        let a = base_snapshot();
        let b = candidate_snapshot_pass();
        assert_ne!(a.snapshot_hash(), b.snapshot_hash());
    }

    // ── pass/rollback symmetry ───────────────────────────────────────

    #[test]
    fn pass_and_rollback_are_inverse() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert_eq!(d.pass, !d.rollback_required);
    }

    // ── Logs ─────────────────────────────────────────────────────────

    #[test]
    fn logs_carry_trace_and_policy_ids() {
        let input = BenchmarkGateInput {
            trace_id: "my-trace".into(),
            policy_id: "my-policy".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        for log in &d.logs {
            assert_eq!(log.trace_id, "my-trace");
            assert_eq!(log.policy_id, "my-policy");
            assert_eq!(log.component, "sibling_integration_benchmark_gate");
        }
    }

    #[test]
    fn logs_final_event_is_benchmark_gate_decision() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        let last = d.logs.last().unwrap();
        assert_eq!(last.event, "benchmark_gate_decision");
        assert_eq!(last.outcome, "pass");
        assert!(last.error_code.is_none());
    }

    #[test]
    fn logs_final_event_fail_on_failure() {
        let mut candidate = candidate_snapshot_pass();
        candidate
            .integrations
            .remove(&SiblingIntegration::Frankensqlite);
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        let last = d.logs.last().unwrap();
        assert_eq!(last.outcome, "fail");
        assert_eq!(last.error_code.as_deref(), Some("benchmark_gate_failed"));
    }

    // ── Helper functions ─────────────────────────────────────────────

    #[test]
    fn percentile_edge_cases() {
        assert_eq!(percentile(&[], 95), 0);
        assert_eq!(percentile(&[42], 95), 42);
        assert_eq!(percentile(&[42], 99), 42);
        let sorted = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert!(percentile(&sorted, 95) >= 90);
    }

    #[test]
    fn ratio_millionths_zero_denominator() {
        assert_eq!(ratio_millionths(100, 0), u64::MAX);
    }

    #[test]
    fn ratio_millionths_normal() {
        assert_eq!(ratio_millionths(200, 100), 2_000_000);
    }

    #[test]
    fn overhead_millionths_zero_denominator() {
        assert_eq!(overhead_millionths(100, 0), u64::MAX);
    }

    #[test]
    fn overhead_millionths_no_overhead() {
        assert_eq!(overhead_millionths(100, 200), 0);
    }

    #[test]
    fn overhead_millionths_normal() {
        // 200 vs 100 = 100% overhead = 1_000_000 ppm
        assert_eq!(overhead_millionths(200, 100), 1_000_000);
    }

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn benchmark_snapshot_serde_roundtrip() {
        let snap = base_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: BenchmarkSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        let json = serde_json::to_string(&d).unwrap();
        let back: BenchmarkGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision_id, d.decision_id);
        assert_eq!(back.pass, d.pass);
        assert_eq!(back.evaluations, d.evaluations);
        assert_eq!(back.findings, d.findings);
    }

    #[test]
    fn finding_serde_roundtrip() {
        let finding = BenchmarkGateFinding {
            code: BenchmarkGateFailureCode::SloThresholdExceeded,
            operation: Some(ControlPlaneOperation::PolicyQuery),
            detail: "test".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: BenchmarkGateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn log_event_serde_roundtrip() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        for log in &d.logs {
            let json = serde_json::to_string(log).unwrap();
            let back: BenchmarkGateLogEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, log);
        }
    }

    #[test]
    fn operation_evaluation_serde_roundtrip() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        for eval in &d.evaluations {
            let json = serde_json::to_string(eval).unwrap();
            let back: OperationBenchmarkEvaluation = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, eval);
        }
    }

    // ── Baseline missing integration ─────────────────────────────────

    #[test]
    fn gate_fails_when_baseline_missing_integration() {
        let mut baseline = base_snapshot();
        baseline
            .integrations
            .remove(&SiblingIntegration::Frankentui);
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline,
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkGateFailureCode::MissingRequiredIntegration
                && f.detail.contains("baseline")
        }));
    }

    // ── Decision ID changes with input ───────────────────────────────

    #[test]
    fn decision_id_changes_with_different_trace() {
        let d1 = evaluate_sibling_integration_benchmark(
            &BenchmarkGateInput {
                trace_id: "trace-1".into(),
                policy_id: "p".into(),
                baseline: base_snapshot(),
                candidate: candidate_snapshot_pass(),
            },
            &BenchmarkGateThresholds::default(),
        );
        let d2 = evaluate_sibling_integration_benchmark(
            &BenchmarkGateInput {
                trace_id: "trace-2".into(),
                policy_id: "p".into(),
                baseline: base_snapshot(),
                candidate: candidate_snapshot_pass(),
            },
            &BenchmarkGateThresholds::default(),
        );
        assert_ne!(d1.decision_id, d2.decision_id);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn sibling_integration_display_uniqueness_btreeset() {
        let integrations = [
            SiblingIntegration::Frankentui,
            SiblingIntegration::Frankensqlite,
            SiblingIntegration::SqlmodelRust,
            SiblingIntegration::FastapiRust,
        ];
        let mut displays = BTreeSet::new();
        for i in &integrations {
            displays.insert(i.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all SiblingIntegration variants produce distinct Display strings"
        );
    }

    #[test]
    fn control_plane_operation_display_uniqueness_btreeset() {
        let ops = [
            ControlPlaneOperation::EvidenceWrite,
            ControlPlaneOperation::PolicyQuery,
            ControlPlaneOperation::TelemetryIngestion,
            ControlPlaneOperation::TuiDataUpdate,
        ];
        let mut displays = BTreeSet::new();
        for op in &ops {
            displays.insert(op.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all ControlPlaneOperation variants produce distinct Display strings"
        );
    }

    #[test]
    fn operation_latency_samples_serde_roundtrip() {
        let samples = make_samples(&[100, 200, 300], &[150, 250, 350]);
        let json = serde_json::to_string(&samples).unwrap();
        let back: OperationLatencySamples = serde_json::from_str(&json).unwrap();
        assert_eq!(samples, back);
    }

    #[test]
    fn enrichment_thresholds_default_has_required_integrations() {
        let t = BenchmarkGateThresholds::default();
        assert_eq!(
            t.required_integrations.len(),
            4,
            "default thresholds must require all 4 integrations"
        );
        assert!(!t.per_operation.is_empty(), "must have per-operation SLOs");
    }

    #[test]
    fn enrichment_sibling_integration_as_str_matches_display() {
        for i in [
            SiblingIntegration::Frankentui,
            SiblingIntegration::Frankensqlite,
            SiblingIntegration::SqlmodelRust,
            SiblingIntegration::FastapiRust,
        ] {
            assert_eq!(i.as_str(), &i.to_string());
        }
    }

    #[test]
    fn enrichment_benchmark_snapshot_base_serde() {
        let snap = base_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: BenchmarkSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn operation_latency_sorted_preserves_length() {
        let samples = make_samples(&[300, 100, 200], &[350, 150, 250]);
        let sorted_w = samples.sorted_without();
        let sorted_wi = samples.sorted_with();
        assert_eq!(sorted_w.len(), 3);
        assert_eq!(sorted_wi.len(), 3);
        assert_eq!(sorted_w[0], 100);
        assert_eq!(sorted_wi[2], 350);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-28
    // -----------------------------------------------------------------------

    #[test]
    fn operation_slo_threshold_serde_roundtrip() {
        let slo = OperationSloThreshold {
            p95_ns: 5_000_000,
            p99_ns: 10_000_000,
            max_regression_millionths: 150_000,
            max_integration_overhead_millionths: 200_000,
        };
        let json = serde_json::to_string(&slo).unwrap();
        let back: OperationSloThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(slo, back);
    }

    #[test]
    fn benchmark_gate_input_serde_roundtrip() {
        let input = BenchmarkGateInput {
            trace_id: "trace-serde".into(),
            policy_id: "policy-serde".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: BenchmarkGateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn baseline_ledger_entry_serde_roundtrip() {
        let snap = base_snapshot();
        let hash = snap.snapshot_hash();
        let entry = BaselineLedgerEntry {
            epoch: 42,
            snapshot_hash: hash,
            snapshot: snap,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: BaselineLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn baseline_ledger_serde_roundtrip() {
        let mut ledger = BaselineLedger::default();
        ledger.record(1, base_snapshot()).unwrap();
        ledger.record(2, candidate_snapshot_pass()).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: BaselineLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn ratio_millionths_equal_values() {
        assert_eq!(ratio_millionths(100, 100), 1_000_000);
    }

    #[test]
    fn overhead_millionths_equal_values() {
        assert_eq!(overhead_millionths(100, 100), 0);
    }

    #[test]
    fn percentile_two_elements() {
        let sorted = [10, 20];
        assert_eq!(percentile(&sorted, 50), 10);
        assert_eq!(percentile(&sorted, 95), 20);
        assert_eq!(percentile(&sorted, 99), 20);
    }

    #[test]
    fn percentile_100_returns_max() {
        let sorted = [10, 20, 30, 40, 50];
        assert_eq!(percentile(&sorted, 100), 50);
    }

    #[test]
    fn snapshot_hash_changes_with_run_id() {
        let mut a = base_snapshot();
        let mut b = base_snapshot();
        b.benchmark_run_id = "different-run-id".to_string();
        assert_ne!(a.snapshot_hash(), b.snapshot_hash());
        // But same data produces same hash.
        a.benchmark_run_id = "same".to_string();
        b.benchmark_run_id = "same".to_string();
        // Still differ because snapshot_id differs
        a.snapshot_id = "snap-1".to_string();
        b.snapshot_id = "snap-1".to_string();
        assert_eq!(a.snapshot_hash(), b.snapshot_hash());
    }

    #[test]
    fn baseline_ledger_error_implements_std_error() {
        let errs: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BaselineLedgerError::NonMonotonicEpoch {
                previous_epoch: 5,
                next_epoch: 3,
            }),
            Box::new(BaselineLedgerError::DuplicateSnapshotHash {
                snapshot_hash: [0; 32],
            }),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn multiple_failures_accumulate_in_gate() {
        let mut candidate = candidate_snapshot_pass();
        // Remove an integration AND set SLO-exceeding latency
        candidate
            .integrations
            .remove(&SiblingIntegration::FastapiRust);
        candidate.operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 830_000, 840_000, 850_000],
                &[3_200_000, 3_300_000, 3_400_000, 3_500_000, 3_600_000],
            ),
        );
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        // Should have at least two different failure codes.
        let codes: BTreeSet<_> = d.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&BenchmarkGateFailureCode::MissingRequiredIntegration));
        assert!(codes.contains(&BenchmarkGateFailureCode::SloThresholdExceeded));
    }

    #[test]
    fn decision_id_has_correct_prefix() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(
            d.decision_id.starts_with("sib-bench-gate-"),
            "decision_id should start with 'sib-bench-gate-', got: {}",
            d.decision_id,
        );
    }

    #[test]
    fn all_evaluations_pass_in_passing_decision() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(d.pass);
        for eval in &d.evaluations {
            assert!(eval.pass, "evaluation for {:?} should pass", eval.operation);
        }
    }

    #[test]
    fn evaluations_cover_all_four_operations() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        let ops: BTreeSet<_> = d.evaluations.iter().map(|e| e.operation).collect();
        assert!(ops.contains(&ControlPlaneOperation::EvidenceWrite));
        assert!(ops.contains(&ControlPlaneOperation::PolicyQuery));
        assert!(ops.contains(&ControlPlaneOperation::TelemetryIngestion));
        assert!(ops.contains(&ControlPlaneOperation::TuiDataUpdate));
    }

    #[test]
    fn regression_millionths_in_evaluation_reasonable() {
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        for eval in &d.evaluations {
            // Regression ratio should be around 1.0 (= 1_000_000 millionths) since
            // candidate values are close to baseline.
            assert!(
                eval.regression_p95_millionths >= 900_000
                    && eval.regression_p95_millionths <= 1_200_000,
                "p95 regression ratio for {:?} = {} should be near 1.0",
                eval.operation,
                eval.regression_p95_millionths,
            );
        }
    }

    #[test]
    fn finding_without_operation() {
        let finding = BenchmarkGateFinding {
            code: BenchmarkGateFailureCode::MissingRequiredIntegration,
            operation: None,
            detail: "no specific operation".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: BenchmarkGateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
        assert!(back.operation.is_none());
    }

    #[test]
    fn gate_both_baseline_and_candidate_missing_integration() {
        let mut baseline = base_snapshot();
        let mut candidate = candidate_snapshot_pass();
        baseline
            .integrations
            .remove(&SiblingIntegration::SqlmodelRust);
        candidate
            .integrations
            .remove(&SiblingIntegration::SqlmodelRust);
        let input = BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "p".into(),
            baseline,
            candidate,
        };
        let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!d.pass);
        // Should have at least 2 findings for missing integration (one baseline, one candidate).
        let missing_findings: Vec<_> = d
            .findings
            .iter()
            .filter(|f| f.code == BenchmarkGateFailureCode::MissingRequiredIntegration)
            .collect();
        assert!(
            missing_findings.len() >= 2,
            "should report missing integration for both baseline and candidate"
        );
    }

    #[test]
    fn baseline_ledger_error_serde_roundtrip_duplicate() {
        let err = BaselineLedgerError::DuplicateSnapshotHash {
            snapshot_hash: [0x42; 32],
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: BaselineLedgerError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn failure_code_display_uniqueness() {
        let codes = [
            BenchmarkGateFailureCode::MissingRequiredIntegration,
            BenchmarkGateFailureCode::MissingOperationSamples,
            BenchmarkGateFailureCode::EmptySamples,
            BenchmarkGateFailureCode::SloThresholdExceeded,
            BenchmarkGateFailureCode::RegressionThresholdExceeded,
            BenchmarkGateFailureCode::IntegrationOverheadExceeded,
        ];
        let displays: BTreeSet<_> = codes.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            displays.len(),
            6,
            "all 6 failure codes must have unique Display"
        );
    }
}
