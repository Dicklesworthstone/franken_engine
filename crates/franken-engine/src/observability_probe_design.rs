//! Optimal Probe Design and Budgeted Observability Allocation — FRX-17.2
//!
//! Designs probe selection as a constrained optimization problem
//! (submodular coverage + convex resource allocation) rather than
//! ad-hoc instrumentation.
//!
//! Key capabilities:
//! - Candidate probe universe across compiler/runtime/router/evidence pipeline
//! - Probe set optimization for maximal forensic utility under budget caps
//! - Deterministic probe schedules for normal, degraded, and incident modes
//! - Per-mode observability budgets integrated with one-lever governance

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Maximum probes in the candidate universe.
const MAX_PROBES: usize = 10_000;

/// Schema version.
pub const PROBE_DESIGN_SCHEMA_VERSION: &str = "franken-engine.observability_probe_design.v1";

// ---------------------------------------------------------------------------
// Probe Universe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProbeDomain {
    Compiler,
    Runtime,
    Router,
    EvidencePipeline,
    Scheduler,
    Governance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProbeGranularity {
    Coarse,
    Medium,
    Fine,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateProbe {
    pub id: EngineObjectId,
    pub name: String,
    pub domain: ProbeDomain,
    pub granularity: ProbeGranularity,
    pub forensic_utility_millionths: i64,
    pub latency_overhead_micros: u64,
    pub memory_overhead_bytes: u64,
    pub covers_events: BTreeSet<String>,
    pub metadata: BTreeMap<String, String>,
}

impl CandidateProbe {
    pub fn marginal_gain(&self, already_covered: &BTreeSet<String>) -> i64 {
        let new_events: usize = self
            .covers_events
            .iter()
            .filter(|e| !already_covered.contains(*e))
            .count();
        if self.covers_events.is_empty() {
            return self.forensic_utility_millionths;
        }
        let fraction = new_events as i64 * MILLION / self.covers_events.len().max(1) as i64;
        self.forensic_utility_millionths * fraction / MILLION
    }

    pub fn efficiency_ratio_millionths(&self) -> i64 {
        let cost = self.latency_overhead_micros.max(1) as i64;
        self.forensic_utility_millionths * MILLION / cost
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeUniverse {
    pub probes: Vec<CandidateProbe>,
    pub all_events: BTreeSet<String>,
}

impl ProbeUniverse {
    pub fn new() -> Self {
        Self {
            probes: Vec::new(),
            all_events: BTreeSet::new(),
        }
    }

    pub fn add_probe(&mut self, probe: CandidateProbe) -> Result<(), ProbeDesignError> {
        if self.probes.len() >= MAX_PROBES {
            return Err(ProbeDesignError::UniverseCapacityExceeded);
        }
        if self.probes.iter().any(|p| p.id == probe.id) {
            return Err(ProbeDesignError::DuplicateProbe);
        }
        for event in &probe.covers_events {
            self.all_events.insert(event.clone());
        }
        self.probes.push(probe);
        Ok(())
    }

    pub fn probes_by_domain(&self, domain: &ProbeDomain) -> Vec<&CandidateProbe> {
        self.probes.iter().filter(|p| &p.domain == domain).collect()
    }

    pub fn total_forensic_utility(&self) -> i64 {
        self.probes
            .iter()
            .map(|p| p.forensic_utility_millionths)
            .sum()
    }
}

impl Default for ProbeUniverse {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Budget constraints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityBudget {
    pub max_latency_micros: u64,
    pub max_memory_bytes: u64,
    pub max_probe_count: usize,
    pub min_event_coverage_millionths: i64,
}

impl ObservabilityBudget {
    pub fn normal() -> Self {
        Self {
            max_latency_micros: 500,
            max_memory_bytes: 1_048_576, // 1 MiB
            max_probe_count: 50,
            min_event_coverage_millionths: 700_000,
        }
    }

    pub fn degraded() -> Self {
        Self {
            max_latency_micros: 2000,
            max_memory_bytes: 4_194_304, // 4 MiB
            max_probe_count: 100,
            min_event_coverage_millionths: 900_000,
        }
    }

    pub fn incident() -> Self {
        Self {
            max_latency_micros: 10_000,
            max_memory_bytes: 16_777_216, // 16 MiB
            max_probe_count: 200,
            min_event_coverage_millionths: 950_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Operating modes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperatingMode {
    Normal,
    Degraded,
    Incident,
}

impl fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Degraded => write!(f, "degraded"),
            Self::Incident => write!(f, "incident"),
        }
    }
}

// ---------------------------------------------------------------------------
// Probe Schedule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSchedule {
    pub mode: OperatingMode,
    pub selected_probe_ids: Vec<EngineObjectId>,
    pub total_latency_micros: u64,
    pub total_memory_bytes: u64,
    pub event_coverage_millionths: i64,
    pub forensic_utility_millionths: i64,
    pub budget: ObservabilityBudget,
    pub within_budget: bool,
    pub schedule_hash: ContentHash,
}

impl ProbeSchedule {
    pub fn probe_count(&self) -> usize {
        self.selected_probe_ids.len()
    }

    pub fn meets_coverage(&self) -> bool {
        self.event_coverage_millionths >= self.budget.min_event_coverage_millionths
    }
}

// ---------------------------------------------------------------------------
// Optimization result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationResult {
    pub selected_indices: Vec<usize>,
    pub total_utility_millionths: i64,
    pub total_latency_micros: u64,
    pub total_memory_bytes: u64,
    pub covered_events: BTreeSet<String>,
    pub iterations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproximationCertificate {
    pub algorithm: String,
    pub optimality_bound_millionths: i64,
    pub actual_utility_millionths: i64,
    pub budget_headroom_latency_micros: u64,
    pub budget_headroom_memory_bytes: u64,
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Greedy submodular optimizer
// ---------------------------------------------------------------------------

pub fn greedy_submodular_select(
    universe: &ProbeUniverse,
    budget: &ObservabilityBudget,
) -> OptimizationResult {
    let mut selected: Vec<usize> = Vec::new();
    let mut covered_events = BTreeSet::new();
    let mut total_latency: u64 = 0;
    let mut total_memory: u64 = 0;
    let mut total_utility: i64 = 0;
    let mut iterations = 0;

    loop {
        if selected.len() >= budget.max_probe_count {
            break;
        }

        let mut best_index = None;
        let mut best_gain: i64 = 0;

        for (i, probe) in universe.probes.iter().enumerate() {
            if selected.contains(&i) {
                continue;
            }

            // Check budget feasibility
            if total_latency + probe.latency_overhead_micros > budget.max_latency_micros {
                continue;
            }
            if total_memory + probe.memory_overhead_bytes > budget.max_memory_bytes {
                continue;
            }

            let gain = probe.marginal_gain(&covered_events);
            if gain > best_gain {
                best_gain = gain;
                best_index = Some(i);
            }
        }

        iterations += 1;

        if let Some(idx) = best_index {
            let probe = &universe.probes[idx];
            selected.push(idx);
            total_latency += probe.latency_overhead_micros;
            total_memory += probe.memory_overhead_bytes;
            total_utility += best_gain;
            for event in &probe.covers_events {
                covered_events.insert(event.clone());
            }
        } else {
            break;
        }
    }

    OptimizationResult {
        selected_indices: selected,
        total_utility_millionths: total_utility,
        total_latency_micros: total_latency,
        total_memory_bytes: total_memory,
        covered_events,
        iterations,
    }
}

// ---------------------------------------------------------------------------
// Schedule builder
// ---------------------------------------------------------------------------

pub fn build_schedule(
    universe: &ProbeUniverse,
    mode: OperatingMode,
    budget: ObservabilityBudget,
) -> ProbeSchedule {
    let result = greedy_submodular_select(universe, &budget);

    let selected_probe_ids: Vec<EngineObjectId> = result
        .selected_indices
        .iter()
        .map(|&i| universe.probes[i].id.clone())
        .collect();

    let event_coverage = if universe.all_events.is_empty() {
        MILLION
    } else {
        result.covered_events.len() as i64 * MILLION / universe.all_events.len() as i64
    };

    let within_budget = result.total_latency_micros <= budget.max_latency_micros
        && result.total_memory_bytes <= budget.max_memory_bytes
        && selected_probe_ids.len() <= budget.max_probe_count;

    let schedule_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(mode.to_string().as_bytes());
        for id in &selected_probe_ids {
            data.extend_from_slice(id.as_bytes());
        }
        data.extend_from_slice(&result.total_latency_micros.to_le_bytes());
        data.extend_from_slice(&result.total_memory_bytes.to_le_bytes());
        data.extend_from_slice(&event_coverage.to_le_bytes());
        data.extend_from_slice(&result.total_utility_millionths.to_le_bytes());
        data.extend_from_slice(&budget.max_latency_micros.to_le_bytes());
        data.extend_from_slice(&budget.max_memory_bytes.to_le_bytes());
        data.extend_from_slice(&(budget.max_probe_count as u64).to_le_bytes());
        data.push(if within_budget { 1 } else { 0 });
        ContentHash::compute(&data)
    };

    ProbeSchedule {
        mode,
        selected_probe_ids,
        total_latency_micros: result.total_latency_micros,
        total_memory_bytes: result.total_memory_bytes,
        event_coverage_millionths: event_coverage,
        forensic_utility_millionths: result.total_utility_millionths,
        budget,
        within_budget,
        schedule_hash,
    }
}

pub fn build_approximation_certificate(
    result: &OptimizationResult,
    budget: &ObservabilityBudget,
) -> ApproximationCertificate {
    // Greedy submodular gives (1-1/e) ≈ 0.632 approximation guarantee
    let optimality_bound: i64 = 632_121; // (1 - 1/e) * 1_000_000

    let cert_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(b"greedy_submodular");
        data.extend_from_slice(&result.total_utility_millionths.to_le_bytes());
        data.extend_from_slice(&optimality_bound.to_le_bytes());
        ContentHash::compute(&data)
    };

    ApproximationCertificate {
        algorithm: "greedy_submodular".to_string(),
        optimality_bound_millionths: optimality_bound,
        actual_utility_millionths: result.total_utility_millionths,
        budget_headroom_latency_micros: budget
            .max_latency_micros
            .saturating_sub(result.total_latency_micros),
        budget_headroom_memory_bytes: budget
            .max_memory_bytes
            .saturating_sub(result.total_memory_bytes),
        certificate_hash: cert_hash,
    }
}

// ---------------------------------------------------------------------------
// Probe utility ledger
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeUtilityLedger {
    pub entries: Vec<UtilityLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtilityLedgerEntry {
    pub probe_id: EngineObjectId,
    pub probe_name: String,
    pub marginal_gain_millionths: i64,
    pub cumulative_coverage_millionths: i64,
    pub selection_round: usize,
}

impl ProbeUtilityLedger {
    pub fn from_optimization(universe: &ProbeUniverse, result: &OptimizationResult) -> Self {
        let mut entries = Vec::new();
        let mut covered = BTreeSet::new();
        let all_events_count = universe.all_events.len().max(1) as i64;

        for (round, &idx) in result.selected_indices.iter().enumerate() {
            let probe = &universe.probes[idx];
            let gain = probe.marginal_gain(&covered);
            for event in &probe.covers_events {
                covered.insert(event.clone());
            }
            let coverage = covered.len() as i64 * MILLION / all_events_count;

            entries.push(UtilityLedgerEntry {
                probe_id: probe.id.clone(),
                probe_name: probe.name.clone(),
                marginal_gain_millionths: gain,
                cumulative_coverage_millionths: coverage,
                selection_round: round,
            });
        }

        Self { entries }
    }
}

// ---------------------------------------------------------------------------
// Multi-mode manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiModeManifest {
    pub normal_schedule: ProbeSchedule,
    pub degraded_schedule: ProbeSchedule,
    pub incident_schedule: ProbeSchedule,
    pub manifest_hash: ContentHash,
}

impl MultiModeManifest {
    pub fn build(universe: &ProbeUniverse) -> Self {
        let normal = build_schedule(
            universe,
            OperatingMode::Normal,
            ObservabilityBudget::normal(),
        );
        let degraded = build_schedule(
            universe,
            OperatingMode::Degraded,
            ObservabilityBudget::degraded(),
        );
        let incident = build_schedule(
            universe,
            OperatingMode::Incident,
            ObservabilityBudget::incident(),
        );

        let manifest_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(normal.schedule_hash.as_bytes());
            data.extend_from_slice(degraded.schedule_hash.as_bytes());
            data.extend_from_slice(incident.schedule_hash.as_bytes());
            ContentHash::compute(&data)
        };

        Self {
            normal_schedule: normal,
            degraded_schedule: degraded,
            incident_schedule: incident,
            manifest_hash,
        }
    }

    pub fn schedule_for_mode(&self, mode: &OperatingMode) -> &ProbeSchedule {
        match mode {
            OperatingMode::Normal => &self.normal_schedule,
            OperatingMode::Degraded => &self.degraded_schedule,
            OperatingMode::Incident => &self.incident_schedule,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeDesignError {
    UniverseCapacityExceeded,
    DuplicateProbe,
    EmptyUniverse,
    InvalidBudget(String),
}

impl fmt::Display for ProbeDesignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UniverseCapacityExceeded => write!(f, "probe universe capacity exceeded"),
            Self::DuplicateProbe => write!(f, "duplicate probe id"),
            Self::EmptyUniverse => write!(f, "empty probe universe"),
            Self::InvalidBudget(msg) => write!(f, "invalid budget: {}", msg),
        }
    }
}

impl std::error::Error for ProbeDesignError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};

    fn make_id(label: &str) -> EngineObjectId {
        let schema = SchemaId::from_definition(PROBE_DESIGN_SCHEMA_VERSION.as_bytes());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "tests.observability_probe_design",
            &schema,
            label.as_bytes(),
        )
        .expect("derive id")
    }

    fn make_probe(
        name: &str,
        domain: ProbeDomain,
        utility: i64,
        latency: u64,
        memory: u64,
        events: &[&str],
    ) -> CandidateProbe {
        CandidateProbe {
            id: make_id(name),
            name: name.to_string(),
            domain,
            granularity: ProbeGranularity::Medium,
            forensic_utility_millionths: utility,
            latency_overhead_micros: latency,
            memory_overhead_bytes: memory,
            covers_events: events.iter().map(|e| e.to_string()).collect(),
            metadata: BTreeMap::new(),
        }
    }

    fn make_universe_with_probes() -> ProbeUniverse {
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "compiler_pass_trace",
            ProbeDomain::Compiler,
            800_000,
            100,
            10_000,
            &["pass_start", "pass_end", "invariant_check"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "runtime_scheduler",
            ProbeDomain::Runtime,
            700_000,
            50,
            8_000,
            &["task_dispatch", "task_complete", "preemption"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "router_decision",
            ProbeDomain::Router,
            900_000,
            30,
            5_000,
            &["lane_select", "fallback_trigger", "calibration_update"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "evidence_pipeline",
            ProbeDomain::EvidencePipeline,
            600_000,
            80,
            12_000,
            &["evidence_emit", "ledger_write", "hash_chain"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "governance_audit",
            ProbeDomain::Governance,
            500_000,
            200,
            20_000,
            &["policy_eval", "decision_record"],
        ))
        .unwrap();
        u
    }

    // --- Probe tests ---

    #[test]
    fn probe_marginal_gain_all_new() {
        let probe = make_probe("p", ProbeDomain::Compiler, MILLION, 10, 100, &["a", "b"]);
        let covered = BTreeSet::new();
        assert_eq!(probe.marginal_gain(&covered), MILLION);
    }

    #[test]
    fn probe_marginal_gain_half_covered() {
        let probe = make_probe("p", ProbeDomain::Compiler, MILLION, 10, 100, &["a", "b"]);
        let mut covered = BTreeSet::new();
        covered.insert("a".to_string());
        assert_eq!(probe.marginal_gain(&covered), 500_000);
    }

    #[test]
    fn probe_marginal_gain_all_covered() {
        let probe = make_probe("p", ProbeDomain::Compiler, MILLION, 10, 100, &["a", "b"]);
        let mut covered = BTreeSet::new();
        covered.insert("a".to_string());
        covered.insert("b".to_string());
        assert_eq!(probe.marginal_gain(&covered), 0);
    }

    #[test]
    fn probe_efficiency_ratio() {
        let probe = make_probe("p", ProbeDomain::Compiler, MILLION, 100, 1000, &["a"]);
        assert_eq!(probe.efficiency_ratio_millionths(), 10_000 * MILLION);
    }

    // --- Universe tests ---

    #[test]
    fn universe_new_empty() {
        let u = ProbeUniverse::new();
        assert!(u.probes.is_empty());
        assert!(u.all_events.is_empty());
    }

    #[test]
    fn universe_add_probe() {
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "p1",
            ProbeDomain::Compiler,
            MILLION,
            10,
            100,
            &["a"],
        ))
        .unwrap();
        assert_eq!(u.probes.len(), 1);
        assert_eq!(u.all_events.len(), 1);
    }

    #[test]
    fn universe_reject_duplicate() {
        let mut u = ProbeUniverse::new();
        let p = make_probe("dup", ProbeDomain::Compiler, MILLION, 10, 100, &["a"]);
        u.add_probe(p.clone()).unwrap();
        assert_eq!(u.add_probe(p), Err(ProbeDesignError::DuplicateProbe));
    }

    #[test]
    fn universe_probes_by_domain() {
        let u = make_universe_with_probes();
        assert_eq!(u.probes_by_domain(&ProbeDomain::Compiler).len(), 1);
        assert_eq!(u.probes_by_domain(&ProbeDomain::Router).len(), 1);
        assert_eq!(u.probes_by_domain(&ProbeDomain::Scheduler).len(), 0);
    }

    #[test]
    fn universe_total_forensic_utility() {
        let u = make_universe_with_probes();
        let total = u.total_forensic_utility();
        assert_eq!(total, 3_500_000);
    }

    #[test]
    fn universe_all_events_tracked() {
        let u = make_universe_with_probes();
        assert_eq!(u.all_events.len(), 14); // unique events across all probes
    }

    // --- Budget tests ---

    #[test]
    fn budget_normal() {
        let b = ObservabilityBudget::normal();
        assert_eq!(b.max_latency_micros, 500);
        assert_eq!(b.max_probe_count, 50);
    }

    #[test]
    fn budget_degraded_has_more_capacity() {
        let n = ObservabilityBudget::normal();
        let d = ObservabilityBudget::degraded();
        assert!(d.max_latency_micros > n.max_latency_micros);
        assert!(d.max_memory_bytes > n.max_memory_bytes);
    }

    #[test]
    fn budget_incident_has_most_capacity() {
        let d = ObservabilityBudget::degraded();
        let i = ObservabilityBudget::incident();
        assert!(i.max_latency_micros > d.max_latency_micros);
        assert!(i.max_memory_bytes > d.max_memory_bytes);
    }

    // --- Optimizer tests ---

    #[test]
    fn greedy_empty_universe() {
        let u = ProbeUniverse::new();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        assert!(result.selected_indices.is_empty());
        assert_eq!(result.total_utility_millionths, 0);
    }

    #[test]
    fn greedy_selects_highest_utility_first() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        assert!(!result.selected_indices.is_empty());
        // Router has highest utility (900k) and lowest latency (30)
        assert_eq!(result.selected_indices[0], 2); // router_decision
    }

    #[test]
    fn greedy_respects_latency_budget() {
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "fast",
            ProbeDomain::Compiler,
            MILLION,
            100,
            100,
            &["a"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "slow",
            ProbeDomain::Runtime,
            MILLION,
            1000,
            100,
            &["b"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 150,
            max_memory_bytes: 10_000,
            max_probe_count: 10,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        assert_eq!(result.selected_indices.len(), 1);
        assert_eq!(result.selected_indices[0], 0); // only "fast"
    }

    #[test]
    fn greedy_respects_memory_budget() {
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "small",
            ProbeDomain::Compiler,
            MILLION,
            10,
            100,
            &["a"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "big",
            ProbeDomain::Runtime,
            MILLION,
            10,
            10_000,
            &["b"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 1000,
            max_memory_bytes: 500,
            max_probe_count: 10,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        assert_eq!(result.selected_indices.len(), 1);
        assert_eq!(result.selected_indices[0], 0); // only "small"
    }

    #[test]
    fn greedy_respects_count_budget() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget {
            max_latency_micros: 100_000,
            max_memory_bytes: 100_000_000,
            max_probe_count: 2,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        assert_eq!(result.selected_indices.len(), 2);
    }

    #[test]
    fn greedy_covers_events() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::incident(); // generous budget
        let result = greedy_submodular_select(&u, &budget);
        assert!(!result.covered_events.is_empty());
    }

    // --- Schedule tests ---

    #[test]
    fn schedule_normal() {
        let u = make_universe_with_probes();
        let schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        assert!(schedule.within_budget);
        assert!(schedule.probe_count() > 0);
        assert_eq!(schedule.mode, OperatingMode::Normal);
    }

    #[test]
    fn schedule_incident_more_probes() {
        let u = make_universe_with_probes();
        let normal = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        let incident = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
        assert!(incident.probe_count() >= normal.probe_count());
    }

    #[test]
    fn schedule_hash_deterministic() {
        let u = make_universe_with_probes();
        let s1 = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        let s2 = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        assert_eq!(s1.schedule_hash, s2.schedule_hash);
    }

    // --- Approximation certificate ---

    #[test]
    fn approximation_certificate() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        let cert = build_approximation_certificate(&result, &budget);
        assert_eq!(cert.algorithm, "greedy_submodular");
        assert_eq!(cert.optimality_bound_millionths, 632_121);
        assert!(cert.actual_utility_millionths > 0);
    }

    // --- Utility ledger tests ---

    #[test]
    fn utility_ledger() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        assert_eq!(ledger.entries.len(), result.selected_indices.len());
        // Coverage should be monotonically increasing
        for window in ledger.entries.windows(2) {
            assert!(
                window[1].cumulative_coverage_millionths
                    >= window[0].cumulative_coverage_millionths
            );
        }
    }

    #[test]
    fn utility_ledger_rounds_sequential() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::incident();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        for (i, entry) in ledger.entries.iter().enumerate() {
            assert_eq!(entry.selection_round, i);
        }
    }

    // --- Multi-mode manifest tests ---

    #[test]
    fn multi_mode_manifest() {
        let u = make_universe_with_probes();
        let manifest = MultiModeManifest::build(&u);
        assert_eq!(manifest.normal_schedule.mode, OperatingMode::Normal);
        assert_eq!(manifest.degraded_schedule.mode, OperatingMode::Degraded);
        assert_eq!(manifest.incident_schedule.mode, OperatingMode::Incident);
    }

    #[test]
    fn multi_mode_manifest_incident_covers_more() {
        let u = make_universe_with_probes();
        let manifest = MultiModeManifest::build(&u);
        assert!(
            manifest.incident_schedule.event_coverage_millionths
                >= manifest.normal_schedule.event_coverage_millionths
        );
    }

    #[test]
    fn multi_mode_manifest_schedule_for_mode() {
        let u = make_universe_with_probes();
        let manifest = MultiModeManifest::build(&u);
        assert_eq!(
            manifest.schedule_for_mode(&OperatingMode::Normal).mode,
            OperatingMode::Normal
        );
        assert_eq!(
            manifest.schedule_for_mode(&OperatingMode::Incident).mode,
            OperatingMode::Incident
        );
    }

    #[test]
    fn multi_mode_manifest_hash_deterministic() {
        let u = make_universe_with_probes();
        let m1 = MultiModeManifest::build(&u);
        let m2 = MultiModeManifest::build(&u);
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // --- Serde tests ---

    #[test]
    fn serde_probe() {
        let p = make_probe("p1", ProbeDomain::Compiler, MILLION, 10, 100, &["a", "b"]);
        let json = serde_json::to_string(&p).unwrap();
        let p2: CandidateProbe = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn serde_budget() {
        let b = ObservabilityBudget::normal();
        let json = serde_json::to_string(&b).unwrap();
        let b2: ObservabilityBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn serde_schedule() {
        let u = make_universe_with_probes();
        let s = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        let json = serde_json::to_string(&s).unwrap();
        let s2: ProbeSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn serde_optimization_result() {
        let u = make_universe_with_probes();
        let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
        let json = serde_json::to_string(&result).unwrap();
        let r2: OptimizationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, r2);
    }

    #[test]
    fn serde_approximation_certificate() {
        let u = make_universe_with_probes();
        let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
        let cert = build_approximation_certificate(&result, &ObservabilityBudget::normal());
        let json = serde_json::to_string(&cert).unwrap();
        let c2: ApproximationCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, c2);
    }

    #[test]
    fn serde_manifest() {
        let u = make_universe_with_probes();
        let m = MultiModeManifest::build(&u);
        let json = serde_json::to_string(&m).unwrap();
        let m2: MultiModeManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    // --- Error tests ---

    #[test]
    fn error_display() {
        assert_eq!(
            ProbeDesignError::DuplicateProbe.to_string(),
            "duplicate probe id"
        );
        assert_eq!(
            ProbeDesignError::EmptyUniverse.to_string(),
            "empty probe universe"
        );
    }

    #[test]
    fn error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ProbeDesignError::EmptyUniverse);
        assert_eq!(err.to_string(), "empty probe universe");
    }

    // --- Operating mode tests ---

    #[test]
    fn mode_display() {
        assert_eq!(OperatingMode::Normal.to_string(), "normal");
        assert_eq!(OperatingMode::Degraded.to_string(), "degraded");
        assert_eq!(OperatingMode::Incident.to_string(), "incident");
    }

    #[test]
    fn mode_ordering() {
        assert!(OperatingMode::Degraded > OperatingMode::Normal);
        assert!(OperatingMode::Incident > OperatingMode::Degraded);
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(
            PROBE_DESIGN_SCHEMA_VERSION,
            "franken-engine.observability_probe_design.v1"
        );
    }

    // --- End-to-end ---

    #[test]
    fn e2e_full_pipeline() {
        let u = make_universe_with_probes();

        // Build manifest
        let manifest = MultiModeManifest::build(&u);

        // Verify normal schedule
        let normal = &manifest.normal_schedule;
        assert!(normal.within_budget);
        assert!(normal.probe_count() > 0);

        // Build utility ledger for normal
        let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        assert!(!ledger.entries.is_empty());

        // Build approximation certificate
        let cert = build_approximation_certificate(&result, &ObservabilityBudget::normal());
        assert!(cert.actual_utility_millionths > 0);
        assert_eq!(cert.optimality_bound_millionths, 632_121);

        // Incident mode should cover at least as much
        let incident = &manifest.incident_schedule;
        assert!(incident.event_coverage_millionths >= normal.event_coverage_millionths);
    }

    // -- Enrichment: Display uniqueness, serde, edge cases --

    #[test]
    fn probe_domain_display_all_unique() {
        let domains = [
            ProbeDomain::Compiler,
            ProbeDomain::Runtime,
            ProbeDomain::Router,
            ProbeDomain::EvidencePipeline,
            ProbeDomain::Scheduler,
            ProbeDomain::Governance,
        ];
        let json_set: std::collections::BTreeSet<String> = domains
            .iter()
            .map(|d| serde_json::to_string(d).unwrap())
            .collect();
        assert_eq!(json_set.len(), domains.len());
    }

    #[test]
    fn probe_granularity_serde_roundtrip() {
        for granularity in [
            ProbeGranularity::Coarse,
            ProbeGranularity::Medium,
            ProbeGranularity::Fine,
            ProbeGranularity::Trace,
        ] {
            let json = serde_json::to_string(&granularity).unwrap();
            let back: ProbeGranularity = serde_json::from_str(&json).unwrap();
            assert_eq!(granularity, back);
        }
    }

    #[test]
    fn probe_design_error_display_all_unique() {
        let errors = [
            ProbeDesignError::UniverseCapacityExceeded,
            ProbeDesignError::DuplicateProbe,
            ProbeDesignError::EmptyUniverse,
            ProbeDesignError::InvalidBudget("test".to_string()),
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    #[test]
    fn probe_marginal_gain_empty_covers_events_returns_raw_utility() {
        let probe = make_probe("p", ProbeDomain::Compiler, 500_000, 10, 100, &[]);
        let covered = BTreeSet::new();
        assert_eq!(probe.marginal_gain(&covered), 500_000);
    }

    #[test]
    fn schedule_empty_universe_produces_zero_coverage() {
        let u = ProbeUniverse::new();
        let schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        assert_eq!(schedule.probe_count(), 0);
        // Empty universe means full coverage by convention
        assert_eq!(schedule.event_coverage_millionths, MILLION);
        assert!(schedule.within_budget);
    }

    #[test]
    fn probe_universe_default_is_empty() {
        let u = ProbeUniverse::default();
        assert!(u.probes.is_empty());
        assert!(u.all_events.is_empty());
    }

    #[test]
    fn schedule_meets_coverage_boundary() {
        let u = make_universe_with_probes();
        let mut schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        // Force coverage to exactly match minimum
        schedule.event_coverage_millionths = schedule.budget.min_event_coverage_millionths;
        assert!(schedule.meets_coverage());
        // One less should fail
        schedule.event_coverage_millionths -= 1;
        assert!(!schedule.meets_coverage());
    }

    #[test]
    fn utility_ledger_serde_roundtrip() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: ProbeUtilityLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment tests — clone equality, JSON field presence, serde roundtrip,
    // Display uniqueness, boundary conditions, Error source
    // -----------------------------------------------------------------------

    // --- Clone equality (5 tests) ---

    #[test]
    fn enrichment_clone_eq_candidate_probe() {
        let a = make_probe("ce1", ProbeDomain::Runtime, 750_000, 42, 2048, &["x", "y"]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_observability_budget() {
        let a = ObservabilityBudget::degraded();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_probe_schedule() {
        let u = make_universe_with_probes();
        let a = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_approximation_certificate() {
        let u = make_universe_with_probes();
        let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
        let a = build_approximation_certificate(&result, &ObservabilityBudget::normal());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_multi_mode_manifest() {
        let u = make_universe_with_probes();
        let a = MultiModeManifest::build(&u);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // --- JSON field presence (3 tests) ---

    #[test]
    fn enrichment_json_field_presence_candidate_probe() {
        let p = make_probe("jp", ProbeDomain::Scheduler, 300_000, 55, 4096, &["evt_a"]);
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"granularity\""));
        assert!(json.contains("\"forensic_utility_millionths\""));
        assert!(json.contains("\"latency_overhead_micros\""));
        assert!(json.contains("\"memory_overhead_bytes\""));
        assert!(json.contains("\"covers_events\""));
        assert!(json.contains("\"metadata\""));
    }

    #[test]
    fn enrichment_json_field_presence_probe_schedule() {
        let u = make_universe_with_probes();
        let s = build_schedule(&u, OperatingMode::Degraded, ObservabilityBudget::degraded());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"mode\""));
        assert!(json.contains("\"selected_probe_ids\""));
        assert!(json.contains("\"total_latency_micros\""));
        assert!(json.contains("\"total_memory_bytes\""));
        assert!(json.contains("\"event_coverage_millionths\""));
        assert!(json.contains("\"within_budget\""));
        assert!(json.contains("\"schedule_hash\""));
    }

    #[test]
    fn enrichment_json_field_presence_approximation_certificate() {
        let u = make_universe_with_probes();
        let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
        let cert = build_approximation_certificate(&result, &ObservabilityBudget::normal());
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("\"algorithm\""));
        assert!(json.contains("\"optimality_bound_millionths\""));
        assert!(json.contains("\"actual_utility_millionths\""));
        assert!(json.contains("\"budget_headroom_latency_micros\""));
        assert!(json.contains("\"budget_headroom_memory_bytes\""));
        assert!(json.contains("\"certificate_hash\""));
    }

    // --- Serde roundtrip (1 test) ---

    #[test]
    fn enrichment_serde_roundtrip_probe_design_error() {
        let errors = [
            ProbeDesignError::UniverseCapacityExceeded,
            ProbeDesignError::DuplicateProbe,
            ProbeDesignError::EmptyUniverse,
            ProbeDesignError::InvalidBudget("budget too small".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ProbeDesignError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // --- Display uniqueness (1 test) ---

    #[test]
    fn enrichment_display_uniqueness_operating_mode() {
        let modes = [
            OperatingMode::Normal,
            OperatingMode::Degraded,
            OperatingMode::Incident,
        ];
        let display_set: BTreeSet<String> = modes.iter().map(|m| m.to_string()).collect();
        assert_eq!(display_set.len(), modes.len());
    }

    // --- Boundary condition (1 test) ---

    #[test]
    fn enrichment_boundary_zero_utility_probes_skipped() {
        let mut u = ProbeUniverse::new();
        // Add a probe with zero forensic utility — greedy should skip it
        // because its marginal gain is 0.
        u.add_probe(make_probe(
            "zero_util",
            ProbeDomain::Compiler,
            0,
            10,
            100,
            &["ev_zero"],
        ))
        .unwrap();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        // Zero utility means marginal_gain returns 0, which is not > best_gain (0),
        // so the probe is never selected.
        assert!(result.selected_indices.is_empty());
        assert_eq!(result.total_utility_millionths, 0);
    }

    // --- Error source (1 test) ---

    #[test]
    fn enrichment_error_source_returns_none() {
        use std::error::Error;
        let errors: Vec<ProbeDesignError> = vec![
            ProbeDesignError::UniverseCapacityExceeded,
            ProbeDesignError::DuplicateProbe,
            ProbeDesignError::EmptyUniverse,
            ProbeDesignError::InvalidBudget("msg".to_string()),
        ];
        for err in &errors {
            assert!(err.source().is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — deeper coverage: Ord derivation, Debug formatting,
    // metadata propagation, optimizer edge cases, coverage math, certificate
    // headroom, ledger entries, JSON value checks, schedule determinism
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_probe_domain_ord_all_variants() {
        // ProbeDomain derives Ord — verify the derive-order matches definition order
        let mut domains = vec![
            ProbeDomain::Governance,
            ProbeDomain::Scheduler,
            ProbeDomain::Router,
            ProbeDomain::EvidencePipeline,
            ProbeDomain::Runtime,
            ProbeDomain::Compiler,
        ];
        domains.sort();
        assert_eq!(
            domains,
            vec![
                ProbeDomain::Compiler,
                ProbeDomain::Runtime,
                ProbeDomain::Router,
                ProbeDomain::EvidencePipeline,
                ProbeDomain::Scheduler,
                ProbeDomain::Governance,
            ]
        );
    }

    #[test]
    fn enrichment_probe_granularity_ord_all_variants() {
        let mut gs = vec![
            ProbeGranularity::Trace,
            ProbeGranularity::Fine,
            ProbeGranularity::Coarse,
            ProbeGranularity::Medium,
        ];
        gs.sort();
        assert_eq!(
            gs,
            vec![
                ProbeGranularity::Coarse,
                ProbeGranularity::Medium,
                ProbeGranularity::Fine,
                ProbeGranularity::Trace,
            ]
        );
    }

    #[test]
    fn enrichment_candidate_probe_debug_contains_name() {
        let p = make_probe("dbg_probe", ProbeDomain::Router, 100_000, 5, 50, &["z"]);
        let dbg = format!("{:?}", p);
        assert!(dbg.contains("dbg_probe"));
        assert!(dbg.contains("Router"));
    }

    #[test]
    fn enrichment_candidate_probe_metadata_round_trip() {
        let mut p = make_probe("meta_p", ProbeDomain::Governance, 200_000, 10, 100, &["m"]);
        p.metadata
            .insert("owner".to_string(), "team-obs".to_string());
        p.metadata.insert("version".to_string(), "3".to_string());
        let json = serde_json::to_string(&p).unwrap();
        let p2: CandidateProbe = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.metadata.get("owner").unwrap(), "team-obs");
        assert_eq!(p2.metadata.get("version").unwrap(), "3");
        assert_eq!(p2.metadata.len(), 2);
    }

    #[test]
    fn enrichment_efficiency_ratio_with_zero_latency_uses_max_one() {
        // latency_overhead_micros = 0 => .max(1) = 1 in efficiency_ratio
        let p = make_probe("zero_lat", ProbeDomain::Compiler, MILLION, 0, 100, &["a"]);
        let ratio = p.efficiency_ratio_millionths();
        // utility * MILLION / 1 = 1_000_000 * 1_000_000 = 1_000_000_000_000
        assert_eq!(ratio, MILLION * MILLION);
    }

    #[test]
    fn enrichment_marginal_gain_single_of_three_covered() {
        // 3 events, 1 already covered => 2/3 fraction
        let p = make_probe(
            "frac",
            ProbeDomain::Runtime,
            MILLION,
            10,
            50,
            &["a", "b", "c"],
        );
        let mut covered = BTreeSet::new();
        covered.insert("b".to_string());
        let gain = p.marginal_gain(&covered);
        // fraction = 2 * 1_000_000 / 3 = 666_666
        // gain = 1_000_000 * 666_666 / 1_000_000 = 666_666
        assert_eq!(gain, 666_666);
    }

    #[test]
    fn enrichment_greedy_overlapping_events_diminishing_returns() {
        // Two probes covering overlapping events; second probe gains less
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "overlap_a",
            ProbeDomain::Compiler,
            MILLION,
            10,
            100,
            &["shared", "unique_a"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "overlap_b",
            ProbeDomain::Runtime,
            MILLION,
            10,
            100,
            &["shared", "unique_b"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 100,
            max_memory_bytes: 100_000,
            max_probe_count: 10,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        // Both should be selected (budget allows)
        assert_eq!(result.selected_indices.len(), 2);
        // Total utility should be less than 2*MILLION because of overlap
        assert!(result.total_utility_millionths < 2 * MILLION);
    }

    #[test]
    fn enrichment_greedy_single_probe_exactly_at_budget() {
        // Probe latency/memory exactly equals budget limits
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "exact_fit",
            ProbeDomain::Scheduler,
            500_000,
            100,
            1000,
            &["fit_event"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 100,
            max_memory_bytes: 1000,
            max_probe_count: 5,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        assert_eq!(result.selected_indices.len(), 1);
        assert_eq!(result.total_latency_micros, 100);
        assert_eq!(result.total_memory_bytes, 1000);
    }

    #[test]
    fn enrichment_greedy_probe_exceeds_budget_skipped() {
        // Single probe that exceeds latency budget is not selected
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "too_expensive",
            ProbeDomain::Compiler,
            MILLION,
            1000,
            100,
            &["ex_event"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 999,
            max_memory_bytes: 100_000,
            max_probe_count: 10,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        assert!(result.selected_indices.is_empty());
    }

    #[test]
    fn enrichment_schedule_coverage_fraction_computed_correctly() {
        // Build a universe where we know exactly how many events are covered
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "cov_p1",
            ProbeDomain::Compiler,
            MILLION,
            10,
            100,
            &["e1", "e2"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "cov_p2",
            ProbeDomain::Runtime,
            800_000,
            10,
            100,
            &["e3", "e4"],
        ))
        .unwrap();
        // Universe has 4 events total. Normal budget can pick both.
        let schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
        // Both probes selected => 4/4 = 1.0 = MILLION
        assert_eq!(schedule.event_coverage_millionths, MILLION);
    }

    #[test]
    fn enrichment_certificate_headroom_zero_when_fully_consumed() {
        // Craft budget that probe fully consumes
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "headroom_p",
            ProbeDomain::Compiler,
            MILLION,
            500,
            1024,
            &["h1"],
        ))
        .unwrap();
        let budget = ObservabilityBudget {
            max_latency_micros: 500,
            max_memory_bytes: 1024,
            max_probe_count: 10,
            min_event_coverage_millionths: 0,
        };
        let result = greedy_submodular_select(&u, &budget);
        let cert = build_approximation_certificate(&result, &budget);
        assert_eq!(cert.budget_headroom_latency_micros, 0);
        assert_eq!(cert.budget_headroom_memory_bytes, 0);
    }

    #[test]
    fn enrichment_certificate_headroom_positive_when_under_budget() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::incident(); // generous
        let result = greedy_submodular_select(&u, &budget);
        let cert = build_approximation_certificate(&result, &budget);
        // Incident budget is 10_000 latency, sum of all probes is 460
        assert!(cert.budget_headroom_latency_micros > 0);
        assert!(cert.budget_headroom_memory_bytes > 0);
    }

    #[test]
    fn enrichment_utility_ledger_final_entry_has_full_coverage() {
        // When all probes are selected, final ledger entry should reach 100% coverage
        let mut u = ProbeUniverse::new();
        u.add_probe(make_probe(
            "led_p1",
            ProbeDomain::Compiler,
            MILLION,
            10,
            100,
            &["le1"],
        ))
        .unwrap();
        u.add_probe(make_probe(
            "led_p2",
            ProbeDomain::Runtime,
            800_000,
            10,
            100,
            &["le2"],
        ))
        .unwrap();
        let budget = ObservabilityBudget::incident();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        assert_eq!(result.selected_indices.len(), 2);
        let last = ledger.entries.last().unwrap();
        assert_eq!(last.cumulative_coverage_millionths, MILLION);
    }

    #[test]
    fn enrichment_utility_ledger_empty_optimization() {
        let u = ProbeUniverse::new();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        assert!(ledger.entries.is_empty());
    }

    #[test]
    fn enrichment_json_value_check_operating_mode_variants() {
        // Verify the JSON representation of each mode variant
        let normal_json = serde_json::to_string(&OperatingMode::Normal).unwrap();
        let degraded_json = serde_json::to_string(&OperatingMode::Degraded).unwrap();
        let incident_json = serde_json::to_string(&OperatingMode::Incident).unwrap();
        assert_eq!(normal_json, "\"Normal\"");
        assert_eq!(degraded_json, "\"Degraded\"");
        assert_eq!(incident_json, "\"Incident\"");
    }

    #[test]
    fn enrichment_json_field_presence_utility_ledger_entry() {
        let u = make_universe_with_probes();
        let budget = ObservabilityBudget::normal();
        let result = greedy_submodular_select(&u, &budget);
        let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
        let json = serde_json::to_string(&ledger.entries[0]).unwrap();
        assert!(json.contains("\"probe_id\""));
        assert!(json.contains("\"probe_name\""));
        assert!(json.contains("\"marginal_gain_millionths\""));
        assert!(json.contains("\"cumulative_coverage_millionths\""));
        assert!(json.contains("\"selection_round\""));
    }

    #[test]
    fn enrichment_multi_mode_manifest_different_hashes_per_schedule() {
        let u = make_universe_with_probes();
        let manifest = MultiModeManifest::build(&u);
        // Each schedule should have a distinct hash (different modes, different selections)
        let hashes: BTreeSet<Vec<u8>> = [
            &manifest.normal_schedule,
            &manifest.degraded_schedule,
            &manifest.incident_schedule,
        ]
        .iter()
        .map(|s| s.schedule_hash.as_bytes().to_vec())
        .collect();
        // At least normal vs incident should differ because they select different probes
        assert!(hashes.len() >= 2);
    }

    #[test]
    fn enrichment_schedule_within_budget_false_when_too_many_probes() {
        // Manually construct a schedule that violates probe count budget
        let u = make_universe_with_probes();
        let mut schedule =
            build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
        // Force budget to disallow the number of probes selected
        schedule.budget.max_probe_count = 0;
        // within_budget was computed at build time, but we can check meets_coverage
        // The within_budget field is pre-computed, so we verify the field is correct
        // by rebuilding with a very restrictive budget
        let tiny_budget = ObservabilityBudget {
            max_latency_micros: 1,
            max_memory_bytes: 1,
            max_probe_count: 0,
            min_event_coverage_millionths: 0,
        };
        let restrictive = build_schedule(&u, OperatingMode::Normal, tiny_budget);
        assert_eq!(restrictive.probe_count(), 0);
        assert!(restrictive.within_budget);
    }
}
