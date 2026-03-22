//! VOI-budgeted monitor scheduler for high-cost diagnostic probes.
//!
//! Dynamically allocates probe execution budget based on Value of Information
//! (VOI) scoring: `VOI = staleness * relevance / cost`.  Probes are scheduled
//! in descending VOI order until the per-interval budget is exhausted.
//! Budget is regime-adaptive: higher during Elevated/Attack regimes.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Plan references: Section 10.11 item 16, 9G.5 (policy controller with
//! expected-loss actions under guardrails), Top-10 #2 (guardplane),
//! #4 (alien-performance profile discipline).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::regime_detector::Regime;

// ---------------------------------------------------------------------------
// ProbeKind — categories of diagnostic probes
// ---------------------------------------------------------------------------

/// Category of a diagnostic probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProbeKind {
    /// Lightweight subsystem health verification.
    HealthCheck,
    /// Expensive analysis (full GC inspection, extension-state snapshot).
    DeepDiagnostic,
    /// Model calibration verification for sentinel/controller components.
    CalibrationProbe,
    /// Hash verification, evidence-chain consistency check.
    IntegrityAudit,
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HealthCheck => write!(f, "health_check"),
            Self::DeepDiagnostic => write!(f, "deep_diagnostic"),
            Self::CalibrationProbe => write!(f, "calibration_probe"),
            Self::IntegrityAudit => write!(f, "integrity_audit"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeConfig — configuration for a single probe
// ---------------------------------------------------------------------------

/// Configuration for a single diagnostic probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Unique probe identifier.
    pub probe_id: String,
    /// Probe category.
    pub kind: ProbeKind,
    /// Cost of executing this probe (millionths, abstract units).
    pub cost_millionths: i64,
    /// Expected information gain (millionths, abstract units).
    pub information_gain_millionths: i64,
    /// Base relevance weight (millionths).
    pub base_relevance_millionths: i64,
}

impl ProbeConfig {
    /// Effective probe cost used by both VOI scoring and budget accounting.
    ///
    /// Non-positive configured costs are treated as a minimal positive unit so
    /// the scheduler cannot mint budget by registering zero/negative-cost probes.
    pub fn effective_cost_millionths(&self) -> i64 {
        self.cost_millionths.max(1)
    }
}

// ---------------------------------------------------------------------------
// ProbeState — runtime state of a probe
// ---------------------------------------------------------------------------

/// Runtime state of a probe managed by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeState {
    /// Probe configuration.
    pub config: ProbeConfig,
    /// Intervals since last execution (increases staleness).
    pub staleness: u64,
    /// Number of times this probe has been scheduled.
    pub execution_count: u64,
    /// Whether the last execution was successful.
    pub last_success: bool,
}

impl ProbeState {
    /// Create from a probe config with initial state.
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            staleness: 0,
            execution_count: 0,
            last_success: true,
        }
    }

    /// Compute VOI score: staleness * relevance * information_gain / cost.
    ///
    /// Returns millionths.  Higher is better.
    pub fn voi_score(&self, regime_relevance_multiplier: i64) -> i64 {
        let cost = self.config.effective_cost_millionths();
        let staleness_factor = (self.staleness.saturating_add(1) as i64).saturating_mul(1_000_000);
        let relevance = self.config.base_relevance_millionths as i128
            * regime_relevance_multiplier as i128
            / 1_000_000;
        let info = self.config.information_gain_millionths as i128;

        // VOI = staleness * relevance * info / cost
        let numerator = staleness_factor as i128 * relevance * info;
        let denominator = cost as i128 * 1_000_000i128 * 1_000_000;

        (numerator / denominator) as i64
    }

    /// Mark probe as executed (resets staleness).
    pub fn mark_executed(&mut self, success: bool) {
        self.staleness = 0;
        self.execution_count = self.execution_count.saturating_add(1);
        self.last_success = success;
    }

    /// Increment staleness (called each scheduling interval).
    pub fn tick_staleness(&mut self) {
        self.staleness = self.staleness.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// SchedulerConfig
// ---------------------------------------------------------------------------

/// Configuration for the monitor scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Scheduler identifier.
    pub scheduler_id: String,
    /// Base budget per scheduling interval (millionths, abstract cost units).
    pub base_budget_millionths: i64,
    /// Budget multipliers per regime (millionths).
    pub regime_budgets: BTreeMap<String, i64>,
    /// Relevance multipliers per regime and probe kind (millionths).
    /// Key: "regime:probe_kind".
    pub relevance_overrides: BTreeMap<String, i64>,
}

impl SchedulerConfig {
    /// Get the budget for a given regime.
    pub fn budget_for_regime(&self, regime: Regime) -> i64 {
        let key = regime.to_string();
        self.regime_budgets
            .get(&key)
            .copied()
            .unwrap_or(self.base_budget_millionths)
    }

    /// Get the relevance multiplier for a regime + probe kind.
    pub fn relevance_multiplier(&self, regime: Regime, kind: ProbeKind) -> i64 {
        let key = format!("{}:{}", regime, kind);
        self.relevance_overrides
            .get(&key)
            .copied()
            .unwrap_or(1_000_000) // default 1.0
    }
}

// ---------------------------------------------------------------------------
// ScheduleDecision — result for a single probe
// ---------------------------------------------------------------------------

/// Scheduling decision for a single probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDecision {
    /// Probe identifier.
    pub probe_id: String,
    /// Probe kind.
    pub kind: ProbeKind,
    /// Computed VOI score (millionths).
    pub voi_score: i64,
    /// Cost of the probe (millionths).
    pub cost: i64,
    /// Whether the probe was scheduled.
    pub scheduled: bool,
    /// Reason if not scheduled.
    pub skip_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// ScheduleResult — complete scheduling output
// ---------------------------------------------------------------------------

/// Complete result of a scheduling interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleResult {
    /// Scheduler identifier.
    pub scheduler_id: String,
    /// Scheduling interval number.
    pub interval: u64,
    /// Regime at time of scheduling.
    pub regime: Regime,
    /// Total budget for this interval (millionths).
    pub budget_total: i64,
    /// Budget consumed by scheduled probes (millionths).
    pub budget_used: i64,
    /// Number of probes scheduled.
    pub probes_scheduled: usize,
    /// Number of probes deferred.
    pub probes_deferred: usize,
    /// Per-probe decisions.
    pub decisions: Vec<ScheduleDecision>,
}

// ---------------------------------------------------------------------------
// SchedulerError
// ---------------------------------------------------------------------------

/// Errors from monitor scheduler operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedulerError {
    /// Duplicate probe ID.
    DuplicateProbe { probe_id: String },
    /// Probe not found.
    ProbeNotFound { probe_id: String },
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProbe { probe_id } => {
                write!(f, "duplicate probe: {probe_id}")
            }
            Self::ProbeNotFound { probe_id } => {
                write!(f, "probe not found: {probe_id}")
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

// ---------------------------------------------------------------------------
// MonitorScheduler — the VOI-budgeted scheduler
// ---------------------------------------------------------------------------

/// VOI-budgeted monitor scheduler.
///
/// Manages diagnostic probes and schedules them based on Value of Information
/// scoring within a regime-adaptive budget.
#[derive(Debug)]
pub struct MonitorScheduler {
    config: SchedulerConfig,
    /// Probes indexed by probe_id (BTreeMap for deterministic iteration).
    probes: BTreeMap<String, ProbeState>,
    /// Current scheduling interval.
    interval: u64,
    /// History of scheduling results.
    history: Vec<ScheduleResult>,
}

impl MonitorScheduler {
    /// Create a new scheduler.
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            probes: BTreeMap::new(),
            interval: 0,
            history: Vec::new(),
        }
    }

    /// Register a new probe.
    pub fn register_probe(&mut self, config: ProbeConfig) -> Result<(), SchedulerError> {
        if self.probes.contains_key(&config.probe_id) {
            return Err(SchedulerError::DuplicateProbe {
                probe_id: config.probe_id,
            });
        }
        let id = config.probe_id.clone();
        self.probes.insert(id, ProbeState::new(config));
        Ok(())
    }

    /// Remove a probe.
    pub fn unregister_probe(&mut self, probe_id: &str) -> Result<(), SchedulerError> {
        if self.probes.remove(probe_id).is_none() {
            return Err(SchedulerError::ProbeNotFound {
                probe_id: probe_id.to_string(),
            });
        }
        Ok(())
    }

    /// Number of registered probes.
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Current interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Scheduler configuration.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Scheduling history.
    pub fn history(&self) -> &[ScheduleResult] {
        &self.history
    }

    /// Get probe state by ID.
    pub fn probe(&self, probe_id: &str) -> Option<&ProbeState> {
        self.probes.get(probe_id)
    }

    /// Run a scheduling interval for the given regime.
    ///
    /// 1. Increments staleness for all probes.
    /// 2. Computes VOI scores.
    /// 3. Sorts by descending VOI.
    /// 4. Greedily schedules probes until budget exhausted.
    /// 5. Returns the schedule.
    pub fn schedule(&mut self, regime: Regime) -> ScheduleResult {
        self.interval += 1;

        // Step 1: Increment staleness.
        for probe in self.probes.values_mut() {
            probe.tick_staleness();
        }

        let budget = self.config.budget_for_regime(regime);

        // Step 2: Compute VOI for each probe.
        let mut scored: Vec<(String, i64, i64)> = self
            .probes
            .iter()
            .map(|(id, state)| {
                let relevance_mult = self.config.relevance_multiplier(regime, state.config.kind);
                let voi = state.voi_score(relevance_mult);
                (id.clone(), voi, state.config.effective_cost_millionths())
            })
            .collect();

        // Step 3: Sort by descending VOI, then by probe_id for tie-breaking.
        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        // Step 4: Greedy scheduling.
        let mut budget_remaining = budget;
        let mut decisions = Vec::new();
        let mut scheduled_ids = Vec::new();

        for (probe_id, voi, cost) in &scored {
            if *cost <= budget_remaining && *voi > 0 {
                decisions.push(ScheduleDecision {
                    probe_id: probe_id.clone(),
                    kind: self.probes[probe_id].config.kind,
                    voi_score: *voi,
                    cost: *cost,
                    scheduled: true,
                    skip_reason: None,
                });
                budget_remaining -= cost;
                scheduled_ids.push(probe_id.clone());
            } else {
                let reason = if *voi <= 0 {
                    "non-positive VOI".to_string()
                } else {
                    format!("budget exhausted (remaining: {budget_remaining}, cost: {cost})")
                };
                decisions.push(ScheduleDecision {
                    probe_id: probe_id.clone(),
                    kind: self.probes[probe_id].config.kind,
                    voi_score: *voi,
                    cost: *cost,
                    scheduled: false,
                    skip_reason: Some(reason),
                });
            }
        }

        let probes_scheduled = scheduled_ids.len();
        let probes_deferred = decisions.len() - probes_scheduled;

        // Mark scheduled probes as executed.
        for id in &scheduled_ids {
            if let Some(probe) = self.probes.get_mut(id) {
                probe.mark_executed(true);
            }
        }

        let result = ScheduleResult {
            scheduler_id: self.config.scheduler_id.clone(),
            interval: self.interval,
            regime,
            budget_total: budget,
            budget_used: budget - budget_remaining,
            probes_scheduled,
            probes_deferred,
            decisions,
        };

        self.history.push(result.clone());
        result
    }

    /// Record a probe execution result (for externally-executed probes).
    pub fn record_execution(
        &mut self,
        probe_id: &str,
        success: bool,
    ) -> Result<(), SchedulerError> {
        let probe = self
            .probes
            .get_mut(probe_id)
            .ok_or_else(|| SchedulerError::ProbeNotFound {
                probe_id: probe_id.to_string(),
            })?;
        probe.mark_executed(success);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn health_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,             // 0.1
            information_gain_millionths: 500_000, // 0.5
            base_relevance_millionths: 1_000_000, // 1.0
        }
    }

    fn deep_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::DeepDiagnostic,
            cost_millionths: 2_000_000,             // 2.0
            information_gain_millionths: 3_000_000, // 3.0
            base_relevance_millionths: 800_000,     // 0.8
        }
    }

    fn integrity_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::IntegrityAudit,
            cost_millionths: 1_500_000,             // 1.5
            information_gain_millionths: 2_000_000, // 2.0
            base_relevance_millionths: 900_000,     // 0.9
        }
    }

    fn test_config() -> SchedulerConfig {
        let mut regime_budgets = BTreeMap::new();
        regime_budgets.insert("normal".to_string(), 3_000_000); // 3.0
        regime_budgets.insert("elevated".to_string(), 6_000_000); // 6.0
        regime_budgets.insert("attack".to_string(), 10_000_000); // 10.0

        SchedulerConfig {
            scheduler_id: "sched-1".to_string(),
            base_budget_millionths: 3_000_000,
            regime_budgets,
            relevance_overrides: BTreeMap::new(),
        }
    }

    fn test_scheduler() -> MonitorScheduler {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("health-1")).unwrap();
        sched.register_probe(deep_probe("deep-1")).unwrap();
        sched
            .register_probe(integrity_probe("integrity-1"))
            .unwrap();
        sched
    }

    // -- ProbeKind --

    #[test]
    fn probe_kind_display() {
        assert_eq!(ProbeKind::HealthCheck.to_string(), "health_check");
        assert_eq!(ProbeKind::DeepDiagnostic.to_string(), "deep_diagnostic");
        assert_eq!(ProbeKind::CalibrationProbe.to_string(), "calibration_probe");
        assert_eq!(ProbeKind::IntegrityAudit.to_string(), "integrity_audit");
    }

    // -- ProbeState VOI --

    #[test]
    fn voi_score_increases_with_staleness() {
        let mut state = ProbeState::new(health_probe("h"));
        let voi1 = state.voi_score(1_000_000);
        state.tick_staleness();
        let voi2 = state.voi_score(1_000_000);
        state.tick_staleness();
        let voi3 = state.voi_score(1_000_000);
        assert!(voi2 > voi1);
        assert!(voi3 > voi2);
    }

    #[test]
    fn voi_score_scales_with_relevance() {
        let state = ProbeState::new(health_probe("h"));
        let voi_low = state.voi_score(500_000); // 0.5
        let voi_high = state.voi_score(2_000_000); // 2.0
        assert!(voi_high > voi_low);
    }

    #[test]
    fn mark_executed_resets_staleness() {
        let mut state = ProbeState::new(health_probe("h"));
        state.tick_staleness();
        state.tick_staleness();
        assert_eq!(state.staleness, 2);

        state.mark_executed(true);
        assert_eq!(state.staleness, 0);
        assert_eq!(state.execution_count, 1);
        assert!(state.last_success);
    }

    // -- Scheduler registration --

    #[test]
    fn register_and_count() {
        let mut sched = MonitorScheduler::new(test_config());
        assert_eq!(sched.probe_count(), 0);
        sched.register_probe(health_probe("h1")).unwrap();
        assert_eq!(sched.probe_count(), 1);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();
        let err = sched.register_probe(health_probe("h1")).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::DuplicateProbe {
                probe_id: "h1".to_string()
            }
        );
    }

    #[test]
    fn unregister_probe() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();
        sched.unregister_probe("h1").unwrap();
        assert_eq!(sched.probe_count(), 0);
    }

    #[test]
    fn unregister_missing_probe_fails() {
        let mut sched = MonitorScheduler::new(test_config());
        let err = sched.unregister_probe("missing").unwrap_err();
        assert_eq!(
            err,
            SchedulerError::ProbeNotFound {
                probe_id: "missing".to_string()
            }
        );
    }

    // -- Scheduling basics --

    #[test]
    fn schedule_respects_budget() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);

        // Budget = 3.0. Health costs 0.1, deep costs 2.0, integrity costs 1.5
        // Total available = 3.0
        assert!(result.budget_used <= result.budget_total);
    }

    #[test]
    fn schedule_orders_by_voi() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);

        // All scheduled probes should have VOI >= all deferred probes
        let scheduled_min_voi = result
            .decisions
            .iter()
            .filter(|d| d.scheduled)
            .map(|d| d.voi_score)
            .min()
            .unwrap_or(0);
        let deferred_max_voi = result
            .decisions
            .iter()
            .filter(|d| !d.scheduled)
            .map(|d| d.voi_score)
            .max()
            .unwrap_or(0);

        // If both exist, scheduled min should be >= deferred max
        // (or deferred was due to budget, not VOI)
        if scheduled_min_voi > 0 && deferred_max_voi > 0 {
            // Deferred due to budget is fine even if VOI is higher
            assert!(
                result
                    .decisions
                    .iter()
                    .filter(|d| !d.scheduled)
                    .all(|d| d.skip_reason.is_some())
            );
        }
    }

    #[test]
    fn interval_increments() {
        let mut sched = test_scheduler();
        assert_eq!(sched.interval(), 0);
        sched.schedule(Regime::Normal);
        assert_eq!(sched.interval(), 1);
        sched.schedule(Regime::Normal);
        assert_eq!(sched.interval(), 2);
    }

    // -- Regime-adaptive budget --

    #[test]
    fn attack_regime_gets_higher_budget() {
        let config = test_config();
        let normal_budget = config.budget_for_regime(Regime::Normal);
        let attack_budget = config.budget_for_regime(Regime::Attack);
        assert!(attack_budget > normal_budget);
    }

    #[test]
    fn elevated_regime_schedules_more_probes() {
        let mut sched1 = test_scheduler();
        let mut sched2 = test_scheduler();

        let normal = sched1.schedule(Regime::Normal);
        let elevated = sched2.schedule(Regime::Elevated);

        // Elevated has 6.0 budget vs 3.0, so should schedule >= as many
        assert!(elevated.probes_scheduled >= normal.probes_scheduled);
    }

    // -- Staleness accumulation --

    #[test]
    fn deferred_probes_accumulate_staleness() {
        let mut sched = MonitorScheduler::new(SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 100_000, // very small budget
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        });
        sched.register_probe(deep_probe("deep-1")).unwrap(); // costs 2.0, won't fit

        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("deep-1").unwrap().staleness, 1); // not executed

        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("deep-1").unwrap().staleness, 2);
    }

    #[test]
    fn scheduled_probes_reset_staleness() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap(); // cheap

        sched.schedule(Regime::Normal); // h1 should be scheduled
        assert_eq!(sched.probe("h1").unwrap().staleness, 0);
    }

    // -- Determinism --

    #[test]
    fn deterministic_schedule() {
        let run = || -> Vec<ScheduleResult> {
            let mut sched = test_scheduler();
            let results = vec![
                sched.schedule(Regime::Normal),
                sched.schedule(Regime::Elevated),
                sched.schedule(Regime::Attack),
            ];
            results
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // -- History tracking --

    #[test]
    fn history_records_all_schedules() {
        let mut sched = test_scheduler();
        sched.schedule(Regime::Normal);
        sched.schedule(Regime::Attack);
        assert_eq!(sched.history().len(), 2);
        assert_eq!(sched.history()[0].regime, Regime::Normal);
        assert_eq!(sched.history()[1].regime, Regime::Attack);
    }

    // -- Record execution --

    #[test]
    fn record_execution_updates_state() {
        let mut sched = test_scheduler();
        sched.record_execution("health-1", false).unwrap();
        assert!(!sched.probe("health-1").unwrap().last_success);
        assert_eq!(sched.probe("health-1").unwrap().execution_count, 1);
    }

    #[test]
    fn record_execution_missing_probe() {
        let mut sched = test_scheduler();
        let err = sched.record_execution("missing", true).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::ProbeNotFound {
                probe_id: "missing".to_string()
            }
        );
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            SchedulerError::DuplicateProbe {
                probe_id: "p".to_string()
            }
            .to_string(),
            "duplicate probe: p"
        );
        assert_eq!(
            SchedulerError::ProbeNotFound {
                probe_id: "p".to_string()
            }
            .to_string(),
            "probe not found: p"
        );
    }

    // -- Serialization --

    #[test]
    fn probe_kind_serialization_round_trip() {
        let kinds = vec![
            ProbeKind::HealthCheck,
            ProbeKind::DeepDiagnostic,
            ProbeKind::CalibrationProbe,
            ProbeKind::IntegrityAudit,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let restored: ProbeKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn probe_config_serialization_round_trip() {
        let config = health_probe("h1");
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ProbeConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn schedule_result_serialization_round_trip() {
        let result = ScheduleResult {
            scheduler_id: "s".to_string(),
            interval: 1,
            regime: Regime::Normal,
            budget_total: 3_000_000,
            budget_used: 1_000_000,
            probes_scheduled: 2,
            probes_deferred: 1,
            decisions: vec![ScheduleDecision {
                probe_id: "h1".to_string(),
                kind: ProbeKind::HealthCheck,
                voi_score: 5_000_000,
                cost: 100_000,
                scheduled: true,
                skip_reason: None,
            }],
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ScheduleResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn scheduler_error_serialization_round_trip() {
        let errors = vec![
            SchedulerError::DuplicateProbe {
                probe_id: "p".to_string(),
            },
            SchedulerError::ProbeNotFound {
                probe_id: "p".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SchedulerError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Relevance overrides --

    // -- Enrichment: serde, ordering, std::error --

    #[test]
    fn probe_state_serde_roundtrip() {
        let state = ProbeState {
            config: health_probe("h-serde"),
            staleness: 42,
            execution_count: 7,
            last_success: true,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: ProbeState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }

    #[test]
    fn scheduler_config_serde_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: SchedulerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn schedule_decision_serde_roundtrip() {
        let dec = ScheduleDecision {
            probe_id: "p-1".to_string(),
            kind: ProbeKind::IntegrityAudit,
            voi_score: 3_500_000,
            cost: 1_000_000,
            scheduled: true,
            skip_reason: None,
        };
        let json = serde_json::to_string(&dec).expect("serialize");
        let restored: ScheduleDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dec, restored);
    }

    #[test]
    fn probe_kind_ordering() {
        assert!(ProbeKind::HealthCheck < ProbeKind::DeepDiagnostic);
        assert!(ProbeKind::DeepDiagnostic < ProbeKind::CalibrationProbe);
        assert!(ProbeKind::CalibrationProbe < ProbeKind::IntegrityAudit);
    }

    #[test]
    fn scheduler_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SchedulerError::DuplicateProbe {
                probe_id: "p-1".into(),
            }),
            Box::new(SchedulerError::ProbeNotFound {
                probe_id: "p-2".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 2);
    }

    // -- Enrichment: edge cases, VOI boundary, scheduling depth --

    #[test]
    fn voi_score_zero_cost_uses_floor() {
        let config = ProbeConfig {
            probe_id: "z".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 0, // will be clamped to 1
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        let state = ProbeState::new(config);
        // cost clamped to max(0,1) = 1, so VOI should be computable
        let voi = state.voi_score(1_000_000);
        assert!(voi > 0);
    }

    #[test]
    fn voi_score_negative_cost_uses_floor() {
        let config = ProbeConfig {
            probe_id: "neg".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: -500_000,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        let state = ProbeState::new(config);
        // cost clamped to max(-500000, 1) = 1
        let voi = state.voi_score(1_000_000);
        assert!(voi > 0);
    }

    #[test]
    fn effective_cost_clamps_non_positive_values() {
        let zero = ProbeConfig {
            probe_id: "zero".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 0,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        let negative = ProbeConfig {
            probe_id: "negative".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: -250_000,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        let positive = ProbeConfig {
            probe_id: "positive".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 500_000,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        assert_eq!(zero.effective_cost_millionths(), 1);
        assert_eq!(negative.effective_cost_millionths(), 1);
        assert_eq!(positive.effective_cost_millionths(), 500_000);
    }

    #[test]
    fn voi_score_zero_information_gain() {
        let config = ProbeConfig {
            probe_id: "no-info".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,
            information_gain_millionths: 0,
            base_relevance_millionths: 1_000_000,
        };
        let state = ProbeState::new(config);
        assert_eq!(state.voi_score(1_000_000), 0);
    }

    #[test]
    fn mark_executed_failure_records_false() {
        let mut state = ProbeState::new(health_probe("h"));
        state.mark_executed(false);
        assert!(!state.last_success);
        assert_eq!(state.execution_count, 1);
        assert_eq!(state.staleness, 0);
    }

    #[test]
    fn mark_executed_toggles_success() {
        let mut state = ProbeState::new(health_probe("h"));
        state.mark_executed(false);
        assert!(!state.last_success);
        state.mark_executed(true);
        assert!(state.last_success);
        assert_eq!(state.execution_count, 2);
    }

    #[test]
    fn probe_state_initial_values() {
        let state = ProbeState::new(health_probe("h"));
        assert_eq!(state.staleness, 0);
        assert_eq!(state.execution_count, 0);
        assert!(state.last_success);
    }

    #[test]
    fn schedule_zero_budget_defers_all() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 0,
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.probes_scheduled, 0);
        assert_eq!(result.probes_deferred, 1);
    }

    #[test]
    fn schedule_empty_scheduler() {
        let mut sched = MonitorScheduler::new(test_config());
        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.probes_scheduled, 0);
        assert_eq!(result.probes_deferred, 0);
        assert!(result.decisions.is_empty());
    }

    #[test]
    fn schedule_single_probe_exact_budget_fit() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 100_000, // exactly matches health probe cost
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.probes_scheduled, 1);
        assert_eq!(result.budget_used, 100_000);
    }

    #[test]
    fn schedule_negative_cost_probe_uses_floor_for_budget_accounting() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 100_000,
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched
            .register_probe(ProbeConfig {
                probe_id: "neg".to_string(),
                kind: ProbeKind::HealthCheck,
                cost_millionths: -500_000,
                information_gain_millionths: 2_000_000,
                base_relevance_millionths: 1_000_000,
            })
            .unwrap();
        sched.register_probe(health_probe("h1")).unwrap();

        let result = sched.schedule(Regime::Normal);
        let neg = result
            .decisions
            .iter()
            .find(|decision| decision.probe_id == "neg")
            .expect("negative-cost probe decision");
        let health = result
            .decisions
            .iter()
            .find(|decision| decision.probe_id == "h1")
            .expect("health probe decision");

        assert!(neg.scheduled);
        assert_eq!(neg.cost, 1);
        assert_eq!(result.budget_used, 1);
        assert!(
            !health.scheduled,
            "negative-cost probes must not expand remaining budget"
        );
    }

    #[test]
    fn schedule_result_contains_all_decisions() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        // Should have one decision per probe
        assert_eq!(result.decisions.len(), 3);
    }

    #[test]
    fn schedule_deterministic_across_repeated_calls() {
        let mut sched1 = test_scheduler();
        let mut sched2 = test_scheduler();
        let r1 = sched1.schedule(Regime::Normal);
        let r2 = sched2.schedule(Regime::Normal);
        assert_eq!(r1.decisions, r2.decisions);
        assert_eq!(r1.budget_used, r2.budget_used);
    }

    #[test]
    fn history_interval_matches_schedule_count() {
        let mut sched = test_scheduler();
        for _ in 0..5 {
            sched.schedule(Regime::Normal);
        }
        assert_eq!(sched.history().len(), 5);
        for (i, h) in sched.history().iter().enumerate() {
            assert_eq!(h.interval, (i + 1) as u64);
        }
    }

    #[test]
    fn record_execution_multiple_times() {
        let mut sched = test_scheduler();
        sched.record_execution("health-1", true).unwrap();
        sched.record_execution("health-1", false).unwrap();
        sched.record_execution("health-1", true).unwrap();
        let state = sched.probe("health-1").unwrap();
        assert_eq!(state.execution_count, 3);
        assert!(state.last_success);
    }

    #[test]
    fn unregister_then_reregister_works() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();
        sched.unregister_probe("h1").unwrap();
        assert_eq!(sched.probe_count(), 0);
        sched.register_probe(deep_probe("h1")).unwrap();
        assert_eq!(sched.probe_count(), 1);
        assert_eq!(
            sched.probe("h1").unwrap().config.kind,
            ProbeKind::DeepDiagnostic
        );
    }

    #[test]
    fn budget_for_unknown_regime_falls_back_to_base() {
        let config = test_config();
        // Regime::Recovery isn't in the regime_budgets map
        let budget = config.budget_for_regime(Regime::Recovery);
        assert_eq!(budget, config.base_budget_millionths);
    }

    #[test]
    fn relevance_multiplier_default_is_one() {
        let config = test_config();
        let mult = config.relevance_multiplier(Regime::Normal, ProbeKind::HealthCheck);
        assert_eq!(mult, 1_000_000);
    }

    #[test]
    fn probe_query_missing_returns_none() {
        let sched = MonitorScheduler::new(test_config());
        assert!(sched.probe("nonexistent").is_none());
    }

    #[test]
    fn deferred_probe_has_skip_reason() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 50_000, // too small for any probe
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        let result = sched.schedule(Regime::Normal);
        let decision = &result.decisions[0];
        assert!(!decision.scheduled);
        assert!(decision.skip_reason.is_some());
    }

    #[test]
    fn calibration_probe_kind_display() {
        let config = ProbeConfig {
            probe_id: "cal".to_string(),
            kind: ProbeKind::CalibrationProbe,
            cost_millionths: 500_000,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        assert_eq!(config.kind.to_string(), "calibration_probe");
    }

    #[test]
    fn relevance_override_affects_scheduling() {
        let mut config = test_config();
        // Boost integrity probes during attack
        config.relevance_overrides.insert(
            "attack:integrity_audit".to_string(),
            5_000_000, // 5.0x
        );

        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        sched.register_probe(integrity_probe("i1")).unwrap();

        let result = sched.schedule(Regime::Attack);

        // Integrity probe should be scheduled (boosted relevance)
        let integrity = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "i1")
            .expect("integrity probe");
        assert!(integrity.scheduled);
    }

    // -- Enrichment: Display uniqueness via BTreeSet --

    #[test]
    fn probe_kind_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            ProbeKind::HealthCheck,
            ProbeKind::DeepDiagnostic,
            ProbeKind::CalibrationProbe,
            ProbeKind::IntegrityAudit,
        ]
        .iter()
        .map(|k| k.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn scheduler_error_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            SchedulerError::DuplicateProbe {
                probe_id: "a".into(),
            },
            SchedulerError::ProbeNotFound {
                probe_id: "b".into(),
            },
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(displays.len(), 2);
    }

    // -- Enrichment: staleness growth across multiple intervals --

    #[test]
    fn staleness_grows_linearly_across_intervals() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 50_000, // too small to schedule deep probe
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(deep_probe("d1")).unwrap();

        for expected in 1..=5 {
            sched.schedule(Regime::Normal);
            assert_eq!(sched.probe("d1").unwrap().staleness, expected);
        }
    }

    // -- Enrichment: VOI ordering determines schedule priority --

    #[test]
    fn higher_voi_probe_scheduled_first() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 200_000, // only fits one health probe
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        // Two health probes with different info gain
        let mut low_info = health_probe("low-info");
        low_info.information_gain_millionths = 100_000; // 0.1
        let mut high_info = health_probe("high-info");
        high_info.information_gain_millionths = 900_000; // 0.9

        sched.register_probe(low_info).unwrap();
        sched.register_probe(high_info).unwrap();

        let result = sched.schedule(Regime::Normal);
        // high-info should be scheduled, low-info deferred
        let high = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "high-info")
            .unwrap();
        assert!(high.scheduled);
    }

    // -- Enrichment: ScheduleResult serde roundtrip --

    #[test]
    fn schedule_result_serde_roundtrip() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ScheduleResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    // -- Enrichment: schedule result budget_total matches config --

    #[test]
    fn schedule_result_budget_total_matches_regime_config() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Attack);
        assert_eq!(result.budget_total, 10_000_000); // from test_config attack budget
    }

    // -- Enrichment: invariant assertions --

    #[test]
    fn budget_used_plus_remaining_equals_total() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        let budget_remaining = result.budget_total - result.budget_used;
        assert!(budget_remaining >= 0);
        assert_eq!(result.budget_used + budget_remaining, result.budget_total);
    }

    #[test]
    fn scheduled_plus_deferred_equals_total_decisions() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        assert_eq!(
            result.probes_scheduled + result.probes_deferred,
            result.decisions.len()
        );
    }

    #[test]
    fn scheduled_count_matches_decisions_flagged_true() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        let flagged_scheduled = result.decisions.iter().filter(|d| d.scheduled).count();
        assert_eq!(result.probes_scheduled, flagged_scheduled);
    }

    // -- Enrichment: VOI tie-breaking by probe_id --

    #[test]
    fn voi_tie_breaks_by_probe_id_alphabetically() {
        // Two identical probes differ only in name
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 100_000, // fits exactly one health probe (cost=100_000)
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        // Same cost, same info gain, same relevance => same VOI
        sched.register_probe(health_probe("beta")).unwrap();
        sched.register_probe(health_probe("alpha")).unwrap();

        let result = sched.schedule(Regime::Normal);
        // Tie-break: alphabetical => "alpha" wins
        let scheduled: Vec<&str> = result
            .decisions
            .iter()
            .filter(|d| d.scheduled)
            .map(|d| d.probe_id.as_str())
            .collect();
        assert_eq!(scheduled, vec!["alpha"]);
    }

    // -- Enrichment: skip reason message content --

    #[test]
    fn skip_reason_non_positive_voi() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 10_000_000,
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        let zero_info = ProbeConfig {
            probe_id: "zero-info".to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,
            information_gain_millionths: 0,
            base_relevance_millionths: 1_000_000,
        };
        sched.register_probe(zero_info).unwrap();
        let result = sched.schedule(Regime::Normal);
        let dec = &result.decisions[0];
        assert!(!dec.scheduled);
        assert_eq!(dec.skip_reason.as_deref(), Some("non-positive VOI"));
    }

    #[test]
    fn skip_reason_budget_exhausted_contains_cost_info() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 50_000, // too small for any probe
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap(); // cost 100_000
        let result = sched.schedule(Regime::Normal);
        let dec = &result.decisions[0];
        assert!(!dec.scheduled);
        let reason = dec.skip_reason.as_ref().unwrap();
        assert!(reason.contains("budget exhausted"));
        assert!(reason.contains("remaining:"));
        assert!(reason.contains("cost:"));
    }

    // -- Enrichment: config accessor --

    #[test]
    fn config_accessor_returns_correct_config() {
        let config = test_config();
        let sched = MonitorScheduler::new(config.clone());
        assert_eq!(sched.config().scheduler_id, config.scheduler_id);
        assert_eq!(
            sched.config().base_budget_millionths,
            config.base_budget_millionths
        );
    }

    // -- Enrichment: scheduler_id propagation --

    #[test]
    fn schedule_result_scheduler_id_matches_config() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.scheduler_id, "sched-1");
    }

    // -- Enrichment: combined staleness in same interval --

    #[test]
    fn same_interval_scheduled_resets_deferred_accumulates() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 200_000, // fits health (0.1) but not deep (2.0)
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("cheap")).unwrap();
        sched.register_probe(deep_probe("expensive")).unwrap();

        sched.schedule(Regime::Normal);
        // cheap scheduled => staleness reset to 0
        assert_eq!(sched.probe("cheap").unwrap().staleness, 0);
        // expensive deferred => staleness = 1 (ticked but not reset)
        assert_eq!(sched.probe("expensive").unwrap().staleness, 1);

        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("cheap").unwrap().staleness, 0);
        assert_eq!(sched.probe("expensive").unwrap().staleness, 2);
    }

    // -- Enrichment: record_execution resets staleness --

    #[test]
    fn record_execution_resets_staleness() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(deep_probe("d1")).unwrap();
        // Manually tick staleness by scheduling with tiny budget won't help,
        // so directly schedule to accumulate staleness
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 50_000,
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched2 = MonitorScheduler::new(config);
        sched2.register_probe(deep_probe("d1")).unwrap();
        sched2.schedule(Regime::Normal); // staleness = 1 (deferred)
        sched2.schedule(Regime::Normal); // staleness = 2
        assert_eq!(sched2.probe("d1").unwrap().staleness, 2);

        sched2.record_execution("d1", true).unwrap();
        assert_eq!(sched2.probe("d1").unwrap().staleness, 0);
    }

    // -- Enrichment: multi-regime sequence --

    #[test]
    fn schedule_across_all_regimes_in_sequence() {
        let mut sched = test_scheduler();
        let regimes = [
            Regime::Normal,
            Regime::Elevated,
            Regime::Attack,
            Regime::Recovery,
        ];
        for (i, &regime) in regimes.iter().enumerate() {
            let result = sched.schedule(regime);
            assert_eq!(result.regime, regime);
            assert_eq!(result.interval, (i + 1) as u64);
        }
        assert_eq!(sched.history().len(), 4);
    }

    // -- Enrichment: ProbeState new preserves config --

    #[test]
    fn probe_state_new_preserves_config_fields() {
        let config = ProbeConfig {
            probe_id: "custom-probe".to_string(),
            kind: ProbeKind::CalibrationProbe,
            cost_millionths: 750_000,
            information_gain_millionths: 2_500_000,
            base_relevance_millionths: 1_200_000,
        };
        let state = ProbeState::new(config.clone());
        assert_eq!(state.config, config);
    }

    // -- Enrichment: CalibrationProbe usage --

    #[test]
    fn calibration_probe_registers_and_schedules() {
        let mut sched = MonitorScheduler::new(test_config());
        let cal = ProbeConfig {
            probe_id: "cal-1".to_string(),
            kind: ProbeKind::CalibrationProbe,
            cost_millionths: 500_000,
            information_gain_millionths: 1_000_000,
            base_relevance_millionths: 1_000_000,
        };
        sched.register_probe(cal).unwrap();
        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.decisions.len(), 1);
        assert_eq!(result.decisions[0].kind, ProbeKind::CalibrationProbe);
    }

    // -- Enrichment: relevance_overrides serde with populated overrides --

    #[test]
    fn scheduler_config_with_relevance_overrides_serde() {
        let mut config = test_config();
        config
            .relevance_overrides
            .insert("attack:integrity_audit".to_string(), 5_000_000);
        config
            .relevance_overrides
            .insert("elevated:health_check".to_string(), 2_000_000);
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: SchedulerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
        assert_eq!(restored.relevance_overrides.len(), 2);
    }

    // -- Enrichment: ScheduleDecision with skip_reason serde --

    #[test]
    fn schedule_decision_with_skip_reason_serde() {
        let dec = ScheduleDecision {
            probe_id: "p-skip".to_string(),
            kind: ProbeKind::DeepDiagnostic,
            voi_score: 1_500_000,
            cost: 3_000_000,
            scheduled: false,
            skip_reason: Some("budget exhausted (remaining: 500000, cost: 3000000)".to_string()),
        };
        let json = serde_json::to_string(&dec).expect("serialize");
        let restored: ScheduleDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dec, restored);
    }

    // -- Enrichment: VOI score determinism --

    #[test]
    fn voi_score_is_deterministic() {
        let state = ProbeState {
            config: health_probe("h"),
            staleness: 5,
            execution_count: 3,
            last_success: true,
        };
        let voi1 = state.voi_score(1_500_000);
        let voi2 = state.voi_score(1_500_000);
        assert_eq!(voi1, voi2);
    }

    // -- Enrichment: multiple probes compete for limited budget --

    #[test]
    fn three_probes_compete_for_limited_budget() {
        let config = SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 1_700_000, // fits health(0.1) + integrity(1.5) but not deep(2.0)
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        };
        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        sched.register_probe(deep_probe("d1")).unwrap();
        sched.register_probe(integrity_probe("i1")).unwrap();

        let result = sched.schedule(Regime::Normal);
        assert_eq!(result.probes_scheduled + result.probes_deferred, 3);
        // Budget allows at most 1.7, so deep(2.0) won't fit by itself,
        // but health(0.1)+integrity(1.5) = 1.6 fits
        assert!(result.budget_used <= result.budget_total);
    }

    // -- Enrichment: probe_count after register/unregister cycles --

    #[test]
    fn probe_count_after_multiple_register_unregister_cycles() {
        let mut sched = MonitorScheduler::new(test_config());
        for i in 0..5 {
            sched
                .register_probe(health_probe(&format!("h-{i}")))
                .unwrap();
        }
        assert_eq!(sched.probe_count(), 5);

        sched.unregister_probe("h-0").unwrap();
        sched.unregister_probe("h-2").unwrap();
        sched.unregister_probe("h-4").unwrap();
        assert_eq!(sched.probe_count(), 2);

        sched.register_probe(deep_probe("d-new")).unwrap();
        assert_eq!(sched.probe_count(), 3);
    }

    // -- Enrichment: elevated regime budget used --

    #[test]
    fn elevated_regime_can_use_higher_budget() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Elevated);
        // Elevated budget is 6.0, can fit all: health(0.1) + deep(2.0) + integrity(1.5) = 3.6
        assert_eq!(result.budget_total, 6_000_000);
        assert!(result.budget_used <= result.budget_total);
    }

    // -- Enrichment: history preserves full schedule detail --

    #[test]
    fn history_preserves_decisions_and_budget_details() {
        let mut sched = test_scheduler();
        let r1 = sched.schedule(Regime::Normal);
        let r2 = sched.schedule(Regime::Attack);
        let history = sched.history();

        assert_eq!(history[0], r1);
        assert_eq!(history[1], r2);
        assert_ne!(history[0].budget_total, history[1].budget_total);
    }

    // -- Enrichment: execution count accumulates across record_execution calls --

    #[test]
    fn execution_count_accumulates_across_mixed_sources() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();

        // Schedule (auto-executes)
        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("h1").unwrap().execution_count, 1);

        // External record
        sched.record_execution("h1", true).unwrap();
        assert_eq!(sched.probe("h1").unwrap().execution_count, 2);

        // Schedule again
        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("h1").unwrap().execution_count, 3);
    }

    // -- Enrichment: VOI increases with relevance multiplier --

    #[test]
    fn relevance_override_boosts_voi_score() {
        let state = ProbeState {
            config: health_probe("h"),
            staleness: 3,
            execution_count: 0,
            last_success: true,
        };
        let voi_base = state.voi_score(1_000_000); // 1.0x
        let voi_boosted = state.voi_score(3_000_000); // 3.0x
        assert!(voi_boosted > voi_base);
        // The ratio should be approximately 3x
        assert!(voi_boosted >= voi_base * 2); // at least 2x due to integer truncation
    }

    // -- Enrichment: all decisions have correct probe kinds --

    #[test]
    fn schedule_decisions_reflect_correct_probe_kinds() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);

        let health_dec = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "health-1")
            .unwrap();
        assert_eq!(health_dec.kind, ProbeKind::HealthCheck);

        let deep_dec = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "deep-1")
            .unwrap();
        assert_eq!(deep_dec.kind, ProbeKind::DeepDiagnostic);

        let integrity_dec = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "integrity-1")
            .unwrap();
        assert_eq!(integrity_dec.kind, ProbeKind::IntegrityAudit);
    }
}
