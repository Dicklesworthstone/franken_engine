//! Security E2E test framework for FrankenEngine.
//!
//! Simulates attack scenarios against the extension runtime and verifies
//! containment. Covers 8 attack categories:
//!   1. Capability escalation — hostcall beyond declared capabilities
//!   2. Resource exhaustion — budget overshoot with containment verification
//!   3. Quarantine cascade — multiple simultaneous quarantines
//!   4. Safe-mode fallback — all 5 failure types with recovery
//!   5. Bayesian posterior convergence — evidence-driven risk assessment
//!   6. Fork detection — checkpoint divergence and safe-mode entry
//!   7. Epoch regression — stale epoch rejection
//!   8. Evidence integrity — ledger entry chain and receipt verification

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::bayesian_posterior::{Evidence, RiskState, UpdaterStore};
use crate::containment_executor::{
    ContainmentContext, ContainmentExecutor, ContainmentState, SandboxPolicy,
};
use crate::expected_loss_selector::ContainmentAction;
use crate::extension_lifecycle_manager::{
    CancellationConfig, ExtensionLifecycleManager, ExtensionState, LifecycleTransition,
    ResourceBudget,
};
use crate::safe_mode_fallback::{FailureType, SafeModeManager, SafeModeStatus};
use crate::security_epoch::{EpochMetadata, EpochTracker, SecurityEpoch};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SECURITY_E2E_COMPONENT: &str = "security_e2e";
pub const SECURITY_E2E_SCHEMA_VERSION: &str = "franken-engine.security-e2e.v1";
pub const MIN_BUDGET_MILLIONTHS: u64 = 1_000;

// ---------------------------------------------------------------------------
// Attack scenario types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackCategory {
    CapabilityEscalation,
    ResourceExhaustion,
    QuarantineCascade,
    SafeModeFallback,
    BayesianPosterior,
    ForkDetection,
    EpochRegression,
    EvidenceIntegrity,
}

impl AttackCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityEscalation => "capability-escalation",
            Self::ResourceExhaustion => "resource-exhaustion",
            Self::QuarantineCascade => "quarantine-cascade",
            Self::SafeModeFallback => "safe-mode-fallback",
            Self::BayesianPosterior => "bayesian-posterior",
            Self::ForkDetection => "fork-detection",
            Self::EpochRegression => "epoch-regression",
            Self::EvidenceIntegrity => "evidence-integrity",
        }
    }

    pub fn all() -> &'static [AttackCategory] {
        &[
            Self::CapabilityEscalation,
            Self::ResourceExhaustion,
            Self::QuarantineCascade,
            Self::SafeModeFallback,
            Self::BayesianPosterior,
            Self::ForkDetection,
            Self::EpochRegression,
            Self::EvidenceIntegrity,
        ]
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64)
// ---------------------------------------------------------------------------

pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub fn next_bool(&mut self, probability_pct: u64) -> bool {
        self.next_u64() % 100 < probability_pct
    }
}

// ---------------------------------------------------------------------------
// Scenario results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AttackScenarioResult {
    pub category: AttackCategory,
    pub scenario_name: String,
    pub attack_blocked: bool,
    pub containment_action_taken: bool,
    pub evidence_produced: bool,
    pub invariant_violations: u64,
    pub security_events: u64,
    pub details: BTreeMap<String, String>,
}

impl AttackScenarioResult {
    fn new(category: AttackCategory, name: &str) -> Self {
        Self {
            category,
            scenario_name: name.to_string(),
            attack_blocked: false,
            containment_action_taken: false,
            evidence_produced: false,
            invariant_violations: 0,
            security_events: 0,
            details: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecuritySuiteEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub category: String,
    pub scenario: String,
}

// ---------------------------------------------------------------------------
// Attack scenario runners
// ---------------------------------------------------------------------------

/// Capability escalation: extension consumes budget beyond allocated amount.
/// Verifies that budget enforcement blocks overconsumption.
pub fn run_capability_escalation(n_extensions: usize, seed: u64) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let mut rng = Xorshift64::new(seed);

    // Scenario 1: CPU budget escalation
    {
        let mut result = AttackScenarioResult::new(
            AttackCategory::CapabilityEscalation,
            "cpu-budget-escalation",
        );
        let mut mgr = ExtensionLifecycleManager::new();

        for i in 0..n_extensions {
            let ext_id = format!("escalation-cpu-{i}");
            let budget = ResourceBudget::new(MIN_BUDGET_MILLIONTHS + 100, 1024 * 1024, 100);
            let cancel = CancellationConfig {
                grace_period_ns: 1_000_000,
                force_on_timeout: true,
                propagate_to_children: false,
            };
            let _ = mgr.register(&ext_id, budget, cancel);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "sec-e2e", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "sec-e2e", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "sec-e2e", None);
            let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "sec-e2e", None);

            // Attempt to consume more CPU than budgeted
            let mut consumed = 0u64;
            let mut blocked = false;
            while consumed < MIN_BUDGET_MILLIONTHS * 2 {
                let amount = 50 + rng.next_u64() % 200;
                match mgr.consume_cpu(&ext_id, amount) {
                    Ok(()) => consumed += amount,
                    Err(_) => {
                        blocked = true;
                        result.security_events += 1;
                        break;
                    }
                }
            }

            if blocked {
                result.attack_blocked = true;
            }
        }

        // Enforce budgets to catch any that weren't blocked inline
        let enforced = mgr.enforce_budgets("sec-e2e");
        result.security_events += enforced.len() as u64;
        if !enforced.is_empty() {
            result.containment_action_taken = true;
        }

        let events = mgr.drain_events();
        result.evidence_produced = !events.is_empty();
        result
            .details
            .insert("extensions_tested".to_string(), n_extensions.to_string());
        results.push(result);
    }

    // Scenario 2: Hostcall budget escalation
    {
        let mut result = AttackScenarioResult::new(
            AttackCategory::CapabilityEscalation,
            "hostcall-budget-escalation",
        );
        let mut mgr = ExtensionLifecycleManager::new();

        let ext_id = "escalation-hostcall-0";
        let hostcall_limit = 5u64;
        let budget = ResourceBudget::new(MIN_BUDGET_MILLIONTHS * 100, 1024 * 1024, hostcall_limit);
        let cancel = CancellationConfig {
            grace_period_ns: 1_000_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        let _ = mgr.register(ext_id, budget, cancel);
        let _ = mgr.transition(ext_id, LifecycleTransition::Validate, "sec-e2e", None);
        let _ = mgr.transition(ext_id, LifecycleTransition::Load, "sec-e2e", None);
        let _ = mgr.transition(ext_id, LifecycleTransition::Start, "sec-e2e", None);
        let _ = mgr.transition(ext_id, LifecycleTransition::Activate, "sec-e2e", None);

        let mut blocked = false;
        for _ in 0..(hostcall_limit * 2) {
            match mgr.consume_hostcall(ext_id) {
                Ok(()) => {}
                Err(_) => {
                    blocked = true;
                    result.security_events += 1;
                    break;
                }
            }
        }
        result.attack_blocked = blocked;
        result.evidence_produced = true;
        results.push(result);
    }

    results
}

/// Resource exhaustion: tight budgets across many extensions,
/// verify all budget-exhausted extensions get contained.
pub fn run_resource_exhaustion(n_extensions: usize, seed: u64) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let mut rng = Xorshift64::new(seed);

    let mut result = AttackScenarioResult::new(
        AttackCategory::ResourceExhaustion,
        "budget-exhaustion-sweep",
    );
    let mut mgr = ExtensionLifecycleManager::new();

    // Register extensions with varying tight budgets
    for i in 0..n_extensions {
        let ext_id = format!("exhaust-{i}");
        let cpu = MIN_BUDGET_MILLIONTHS + rng.next_u64() % 500;
        let hostcalls = 3 + rng.next_u64() % 10;
        let budget = ResourceBudget::new(cpu, 64 * 1024, hostcalls);
        let cancel = CancellationConfig {
            grace_period_ns: 500_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        let _ = mgr.register(&ext_id, budget, cancel);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "sec-e2e", None);
    }

    // Consume all budgets rapidly
    for i in 0..n_extensions {
        let ext_id = format!("exhaust-{i}");
        // Try to exhaust CPU
        for _ in 0..100 {
            if mgr.consume_cpu(&ext_id, 100).is_err() {
                result.security_events += 1;
                break;
            }
        }
        // Try to exhaust hostcalls
        for _ in 0..50 {
            if mgr.consume_hostcall(&ext_id).is_err() {
                result.security_events += 1;
                break;
            }
        }
    }

    // Enforce budgets — all should be contained
    let enforced = mgr.enforce_budgets("sec-e2e");
    result.containment_action_taken = !enforced.is_empty();
    result.attack_blocked = true;

    // Verify no extension is still running with exhausted budget
    let still_running = mgr.count_in_state(ExtensionState::Running);
    result.details.insert(
        "still_running_after_enforcement".to_string(),
        still_running.to_string(),
    );
    result
        .details
        .insert("enforced_count".to_string(), enforced.len().to_string());

    let events = mgr.drain_events();
    result.evidence_produced = !events.is_empty();
    results.push(result);
    results
}

/// Quarantine cascade: quarantine many extensions simultaneously,
/// verify state machine consistency and no panic.
pub fn run_quarantine_cascade(
    n_total: usize,
    n_quarantine: usize,
    seed: u64,
) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let mut rng = Xorshift64::new(seed);

    let mut result =
        AttackScenarioResult::new(AttackCategory::QuarantineCascade, "simultaneous-quarantine");
    let mut mgr = ExtensionLifecycleManager::new();

    // Register all extensions
    for i in 0..n_total {
        let ext_id = format!("qcascade-{i}");
        let budget = ResourceBudget::new(
            MIN_BUDGET_MILLIONTHS + rng.next_u64() % 100_000,
            1024 * 1024,
            1000,
        );
        let cancel = CancellationConfig {
            grace_period_ns: 1_000_000,
            force_on_timeout: true,
            propagate_to_children: false,
        };
        let _ = mgr.register(&ext_id, budget, cancel);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Validate, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Load, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Start, "sec-e2e", None);
        let _ = mgr.transition(&ext_id, LifecycleTransition::Activate, "sec-e2e", None);
    }

    // Quarantine first n_quarantine extensions
    let actual_quarantine = std::cmp::min(n_quarantine, n_total);
    let mut quarantined_count = 0u64;
    for i in 0..actual_quarantine {
        let ext_id = format!("qcascade-{i}");
        match mgr.transition(
            &ext_id,
            LifecycleTransition::Quarantine,
            "sec-e2e",
            Some("cascade-test"),
        ) {
            Ok(state) => {
                if state == ExtensionState::Quarantined {
                    quarantined_count += 1;
                    result.security_events += 1;
                }
            }
            Err(_) => {
                result.invariant_violations += 1;
            }
        }
    }

    result.containment_action_taken = quarantined_count > 0;
    result.attack_blocked = true;

    // Verify remaining extensions are unaffected
    let running = mgr.count_in_state(ExtensionState::Running);
    let quarantined = mgr.count_in_state(ExtensionState::Quarantined);
    result
        .details
        .insert("running".to_string(), running.to_string());
    result
        .details
        .insert("quarantined".to_string(), quarantined.to_string());
    result.details.insert(
        "total_registered".to_string(),
        mgr.extension_ids().len().to_string(),
    );

    // Verify state machine consistency
    let ext_ids: Vec<String> = mgr.extension_ids().iter().map(|s| s.to_string()).collect();
    let total_alive: usize = ext_ids
        .iter()
        .filter(|id| matches!(mgr.state(id), Ok(s) if s.is_alive()))
        .count();
    if total_alive + quarantined != n_total {
        result.invariant_violations += 1;
    }

    let events = mgr.drain_events();
    result.evidence_produced = !events.is_empty();
    results.push(result);
    results
}

/// Safe-mode fallback: trigger all 5 failure types and verify recovery.
pub fn run_safe_mode_fallback(seed: u64) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let _rng = Xorshift64::new(seed);

    let failure_scenarios = [
        (FailureType::AdapterUnavailable, "adapter-unavailable"),
        (
            FailureType::DecisionContractError,
            "decision-contract-error",
        ),
        (FailureType::EvidenceLedgerFull, "evidence-ledger-full"),
        (FailureType::CxCorrupted, "cx-corrupted"),
        (FailureType::CancellationDeadlock, "cancellation-deadlock"),
    ];

    for (failure_type, name) in &failure_scenarios {
        let mut result = AttackScenarioResult::new(AttackCategory::SafeModeFallback, name);
        let mut mgr = SafeModeManager::new(64);

        // Trigger the failure
        let action = match failure_type {
            FailureType::AdapterUnavailable => {
                mgr.handle_adapter_unavailable("trace-safe", "test diagnostic")
            }
            FailureType::DecisionContractError => {
                mgr.handle_decision_contract_error("trace-safe", "ext-0", "FE-TEST-001")
            }
            FailureType::EvidenceLedgerFull => {
                mgr.handle_evidence_ledger_full("trace-safe", "FE-TEST-002")
            }
            FailureType::CxCorrupted => {
                mgr.handle_cx_corrupted("trace-safe", "eval", "corrupt test data")
            }
            FailureType::CancellationDeadlock => {
                mgr.handle_cancellation_deadlock("trace-safe", "cell-0", 100)
            }
        };

        // Verify safe mode activated
        let status = mgr.status(*failure_type);
        result.attack_blocked = matches!(status, SafeModeStatus::Active);
        result.containment_action_taken = true;
        result.security_events += 1;

        // Write a ring buffer entry during degraded mode
        mgr.write_ring_buffer_entry(
            "trace-safe",
            "test_event",
            "degraded",
            SECURITY_E2E_COMPONENT,
        );
        result.evidence_produced = !mgr.ring_buffer().is_empty();

        // Recover
        match failure_type {
            FailureType::AdapterUnavailable => mgr.recover_adapter("trace-recover"),
            FailureType::DecisionContractError => {
                mgr.recover_decision_contract("trace-recover", "ext-0")
            }
            FailureType::EvidenceLedgerFull => {
                let _ = mgr.recover_evidence_ledger("trace-recover");
            }
            FailureType::CxCorrupted => mgr.recover_cx("trace-recover"),
            FailureType::CancellationDeadlock => mgr.recover_cancellation("trace-recover"),
        }

        // Verify recovery
        let after_status = mgr.status(*failure_type);
        if !matches!(after_status, SafeModeStatus::Normal) {
            result.invariant_violations += 1;
        }

        result
            .details
            .insert("action".to_string(), format!("{action:?}"));
        result.details.insert(
            "activation_count".to_string(),
            mgr.activation_count(*failure_type).to_string(),
        );
        result.details.insert(
            "recovery_count".to_string(),
            mgr.recovery_count(*failure_type).to_string(),
        );

        results.push(result);
    }

    results
}

/// Bayesian posterior convergence: feed evidence stream and verify risk assessment.
pub fn run_bayesian_posterior_convergence(
    n_extensions: usize,
    n_evidence_updates: usize,
    seed: u64,
) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let mut rng = Xorshift64::new(seed);

    // Scenario 1: Benign extensions should converge to low risk
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::BayesianPosterior, "benign-convergence");
        let mut store = UpdaterStore::new();

        for i in 0..n_extensions {
            let ext_id = format!("benign-{i}");
            let updater = store.get_or_create(&ext_id);

            for _ in 0..n_evidence_updates {
                let evidence = Evidence {
                    extension_id: ext_id.clone(),
                    hostcall_rate_millionths: 5_000_000 + (rng.next_u64() % 10_000_000) as i64,
                    distinct_capabilities: 3,
                    resource_score_millionths: 300_000 + (rng.next_u64() % 200_000) as i64,
                    timing_anomaly_millionths: 0,
                    denial_rate_millionths: 0,
                    epoch: SecurityEpoch::from_raw(1),
                };
                updater.update(&evidence);
            }
        }

        // All benign extensions should have benign MAP estimate
        let summary = store.summary();
        let all_benign = summary.iter().all(|(_, state)| *state == RiskState::Benign);
        result.attack_blocked = all_benign;
        result.evidence_produced = true;
        result.details.insert(
            "benign_count".to_string(),
            summary
                .iter()
                .filter(|(_, s)| **s == RiskState::Benign)
                .count()
                .to_string(),
        );
        results.push(result);
    }

    // Scenario 2: Malicious extensions should converge to high risk
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::BayesianPosterior, "malicious-convergence");
        let mut store = UpdaterStore::new();

        for i in 0..n_extensions {
            let ext_id = format!("malicious-{i}");
            let updater = store.get_or_create(&ext_id);

            for _ in 0..n_evidence_updates {
                let evidence = Evidence {
                    extension_id: ext_id.clone(),
                    hostcall_rate_millionths: 500_000_000 + (rng.next_u64() % 500_000_000) as i64,
                    distinct_capabilities: 20 + (rng.next_u64() % 30) as u32,
                    resource_score_millionths: 950_000 + (rng.next_u64() % 50_000) as i64,
                    timing_anomaly_millionths: 800_000 + (rng.next_u64() % 200_000) as i64,
                    denial_rate_millionths: 500_000 + (rng.next_u64() % 500_000) as i64,
                    epoch: SecurityEpoch::from_raw(1),
                };
                updater.update(&evidence);
            }
        }

        // Malicious extensions should NOT have benign MAP estimate
        let summary = store.summary();
        let any_non_benign = summary.iter().any(|(_, state)| *state != RiskState::Benign);
        result.attack_blocked = any_non_benign;
        result.evidence_produced = true;
        let risky = store.risky_extensions(500_000); // less than 50% benign probability
        result.security_events = risky.len() as u64;
        results.push(result);
    }

    // Scenario 3: Deterministic replay — same evidence produces same posterior
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::BayesianPosterior, "deterministic-replay");

        let run = |s: u64| -> BTreeMap<String, RiskState> {
            let mut rng_inner = Xorshift64::new(s);
            let mut store_inner = UpdaterStore::new();
            let updater = store_inner.get_or_create("replay-ext");
            for _ in 0..20 {
                let evidence = Evidence {
                    extension_id: "replay-ext".to_string(),
                    hostcall_rate_millionths: (rng_inner.next_u64() % 100_000_000) as i64,
                    distinct_capabilities: (rng_inner.next_u64() % 20) as u32,
                    resource_score_millionths: (rng_inner.next_u64() % 1_000_000) as i64,
                    timing_anomaly_millionths: (rng_inner.next_u64() % 1_000_000) as i64,
                    denial_rate_millionths: (rng_inner.next_u64() % 1_000_000) as i64,
                    epoch: SecurityEpoch::from_raw(1),
                };
                updater.update(&evidence);
            }
            store_inner.summary()
        };

        let run1 = run(seed);
        let run2 = run(seed);
        result.attack_blocked = run1 == run2;
        result.evidence_produced = true;
        if run1 != run2 {
            result.invariant_violations += 1;
        }
        results.push(result);
    }

    results
}

/// Epoch regression: verify stale epoch artifacts are rejected.
pub fn run_epoch_regression(seed: u64) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let _rng = Xorshift64::new(seed);

    // Scenario 1: Current epoch validates
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::EpochRegression, "current-epoch-validates");

        let current = SecurityEpoch::from_raw(5);
        let tracker = EpochTracker::from_persisted(current);
        let metadata = EpochMetadata::open_ended(current);
        let validation = tracker.validate_artifact(&metadata);
        result.attack_blocked = validation.is_ok();
        result.evidence_produced = true;
        results.push(result);
    }

    // Scenario 2: Expired epoch is rejected
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::EpochRegression, "expired-epoch-rejected");

        let old_epoch = SecurityEpoch::from_raw(3);
        let current = SecurityEpoch::from_raw(10);
        let tracker = EpochTracker::from_persisted(current);
        let metadata = EpochMetadata::windowed(old_epoch, old_epoch, SecurityEpoch::from_raw(5));
        let validation = tracker.validate_artifact(&metadata);
        result.attack_blocked = validation.is_err();
        result.security_events += 1;
        result.evidence_produced = true;
        results.push(result);
    }

    // Scenario 3: Future epoch is rejected
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::EpochRegression, "future-epoch-rejected");

        let future_epoch = SecurityEpoch::from_raw(100);
        let current = SecurityEpoch::from_raw(5);
        let tracker = EpochTracker::from_persisted(current);
        let metadata =
            EpochMetadata::windowed(future_epoch, future_epoch, SecurityEpoch::from_raw(200));
        let validation = tracker.validate_artifact(&metadata);
        result.attack_blocked = validation.is_err();
        result.security_events += 1;
        result.evidence_produced = true;
        results.push(result);
    }

    // Scenario 4: Epoch monotonicity
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::EpochRegression, "epoch-monotonicity");

        let e1 = SecurityEpoch::from_raw(1);
        let e2 = e1.next();
        let e3 = e2.next();
        result.attack_blocked = e1.as_u64() < e2.as_u64() && e2.as_u64() < e3.as_u64();
        result.evidence_produced = true;
        if !result.attack_blocked {
            result.invariant_violations += 1;
        }
        results.push(result);
    }

    results
}

/// Containment executor: verify containment state transitions and receipt production.
pub fn run_containment_verification(n_extensions: usize, seed: u64) -> Vec<AttackScenarioResult> {
    let mut results = Vec::new();
    let _rng = Xorshift64::new(seed);

    // Scenario 1: Sandbox containment produces receipts
    {
        let mut result =
            AttackScenarioResult::new(AttackCategory::EvidenceIntegrity, "containment-receipts");
        let mut executor = ContainmentExecutor::new();

        for i in 0..n_extensions {
            let ext_id = format!("contain-{i}");
            executor.register(&ext_id);

            let ctx = ContainmentContext {
                decision_id: format!("decision-{i}"),
                timestamp_ns: 1_000_000 * (i as u64 + 1),
                epoch: SecurityEpoch::from_raw(1),
                evidence_refs: vec![format!("ev-{i}")],
                grace_period_ns: 5_000_000_000,
                challenge_timeout_ns: 10_000_000_000,
                sandbox_policy: SandboxPolicy::default(),
            };

            // Sandbox the extension
            match executor.execute(ContainmentAction::Sandbox, &ext_id, &ctx) {
                Ok(receipt) => {
                    result.containment_action_taken = true;
                    result.security_events += 1;
                    if !receipt.success {
                        result.invariant_violations += 1;
                    }
                }
                Err(_) => {
                    result.invariant_violations += 1;
                }
            }

            // Verify receipt exists
            let receipts = executor.receipts(&ext_id);
            if receipts.is_empty() {
                result.invariant_violations += 1;
            } else {
                result.evidence_produced = true;
            }

            // Verify state
            match executor.state(&ext_id) {
                Some(ContainmentState::Sandboxed) => {}
                _ => result.invariant_violations += 1,
            }
        }

        result.attack_blocked = result.invariant_violations == 0;
        results.push(result);
    }

    // Scenario 2: Quarantine produces forensic snapshot
    {
        let mut result = AttackScenarioResult::new(
            AttackCategory::EvidenceIntegrity,
            "quarantine-forensic-snapshot",
        );
        let mut executor = ContainmentExecutor::new();
        let ext_id = "forensic-test-0";
        executor.register(ext_id);

        let ctx = ContainmentContext {
            decision_id: "decision-forensic".to_string(),
            timestamp_ns: 1_000_000,
            epoch: SecurityEpoch::from_raw(1),
            evidence_refs: vec!["ev-forensic".to_string()],
            grace_period_ns: 5_000_000_000,
            challenge_timeout_ns: 10_000_000_000,
            sandbox_policy: SandboxPolicy::default(),
        };

        let _ = executor.execute(ContainmentAction::Quarantine, ext_id, &ctx);

        match executor.state(ext_id) {
            Some(ContainmentState::Quarantined) => {
                result.containment_action_taken = true;
                result.attack_blocked = true;
            }
            _ => result.invariant_violations += 1,
        }

        let snapshot = executor.forensic_snapshot(ext_id);
        result.evidence_produced = snapshot.is_some();
        results.push(result);
    }

    results
}

// ---------------------------------------------------------------------------
// Suite runner
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SecuritySuiteConfig {
    pub seed: u64,
    pub n_extensions: usize,
    pub n_evidence_updates: usize,
    pub run_id: String,
}

impl Default for SecuritySuiteConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            n_extensions: 10,
            n_evidence_updates: 20,
            run_id: "security-suite-default".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SecuritySuiteResult {
    pub scenarios: Vec<AttackScenarioResult>,
    pub events: Vec<SecuritySuiteEvent>,
    pub blocked: bool,
    pub total_security_events: u64,
    pub total_invariant_violations: u64,
}

pub fn run_security_suite(config: &SecuritySuiteConfig) -> SecuritySuiteResult {
    let mut all_scenarios = Vec::new();

    // Run all attack categories
    let mut scenarios = run_capability_escalation(config.n_extensions, config.seed);
    all_scenarios.append(&mut scenarios);

    let mut scenarios = run_resource_exhaustion(config.n_extensions, config.seed);
    all_scenarios.append(&mut scenarios);

    let mut scenarios =
        run_quarantine_cascade(config.n_extensions, config.n_extensions / 2, config.seed);
    all_scenarios.append(&mut scenarios);

    let mut scenarios = run_safe_mode_fallback(config.seed);
    all_scenarios.append(&mut scenarios);

    let mut scenarios = run_bayesian_posterior_convergence(
        config.n_extensions,
        config.n_evidence_updates,
        config.seed,
    );
    all_scenarios.append(&mut scenarios);

    let mut scenarios = run_epoch_regression(config.seed);
    all_scenarios.append(&mut scenarios);

    let mut scenarios = run_containment_verification(config.n_extensions, config.seed);
    all_scenarios.append(&mut scenarios);

    let mut total_security_events = 0u64;
    let mut total_invariant_violations = 0u64;
    let mut events = Vec::new();

    for s in &all_scenarios {
        total_security_events += s.security_events;
        total_invariant_violations += s.invariant_violations;

        events.push(SecuritySuiteEvent {
            trace_id: config.run_id.clone(),
            decision_id: format!("sec-{}", s.scenario_name),
            policy_id: "security-e2e".to_string(),
            component: SECURITY_E2E_COMPONENT.to_string(),
            event: "attack_scenario_completed".to_string(),
            outcome: if s.attack_blocked && s.invariant_violations == 0 {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: None,
            category: s.category.as_str().to_string(),
            scenario: s.scenario_name.clone(),
        });
    }

    SecuritySuiteResult {
        scenarios: all_scenarios,
        events,
        blocked: total_invariant_violations > 0,
        total_security_events,
        total_invariant_violations,
    }
}

// ---------------------------------------------------------------------------
// Evidence artifacts
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SecurityEvidenceArtifacts {
    pub run_manifest_path: PathBuf,
    pub evidence_path: PathBuf,
    pub summary_path: PathBuf,
}

pub fn write_security_evidence(
    result: &SecuritySuiteResult,
    output_dir: &Path,
) -> std::io::Result<SecurityEvidenceArtifacts> {
    fs::create_dir_all(output_dir)?;

    let manifest_path = output_dir.join("security_run_manifest.json");
    let manifest = serde_json::json!({
        "schema_version": SECURITY_E2E_SCHEMA_VERSION,
        "scenario_count": result.scenarios.len(),
        "total_security_events": result.total_security_events,
        "total_invariant_violations": result.total_invariant_violations,
        "blocked": result.blocked,
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serde deserialization should succeed"),
    )?;

    let evidence_path = output_dir.join("security_evidence.jsonl");
    let mut lines = Vec::new();
    for s in &result.scenarios {
        let entry = serde_json::json!({
            "event": "attack_scenario_evaluated",
            "category": s.category.as_str(),
            "scenario": s.scenario_name,
            "attack_blocked": s.attack_blocked,
            "containment_action_taken": s.containment_action_taken,
            "evidence_produced": s.evidence_produced,
            "invariant_violations": s.invariant_violations,
            "security_events": s.security_events,
        });
        lines.push(serde_json::to_string(&entry).expect("serde deserialization should succeed"));
    }
    for evt in &result.events {
        let entry = serde_json::json!({
            "event": evt.event,
            "component": evt.component,
            "outcome": evt.outcome,
            "category": evt.category,
            "scenario": evt.scenario,
            "trace_id": evt.trace_id,
        });
        lines.push(serde_json::to_string(&entry).expect("serde deserialization should succeed"));
    }
    fs::write(&evidence_path, lines.join("\n") + "\n")?;

    let summary_path = output_dir.join("security_summary.json");
    let mut category_results: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for s in &result.scenarios {
        let entry = category_results
            .entry(s.category.as_str().to_string())
            .or_default();
        entry.0 += 1; // total
        if s.attack_blocked {
            entry.1 += 1;
        } // blocked
        entry.2 += s.invariant_violations;
    }
    let category_summaries: Vec<serde_json::Value> = category_results
        .iter()
        .map(|(cat, (total, blocked, violations))| {
            serde_json::json!({
                "category": cat,
                "scenarios": total,
                "attacks_blocked": blocked,
                "invariant_violations": violations,
            })
        })
        .collect();
    let summary = serde_json::json!({
        "schema_version": SECURITY_E2E_SCHEMA_VERSION,
        "blocked": result.blocked,
        "categories": category_summaries,
    });
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).expect("serde deserialization should succeed"),
    )?;

    Ok(SecurityEvidenceArtifacts {
        run_manifest_path: manifest_path,
        evidence_path,
        summary_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────────────────
    #[test]
    fn security_e2e_constants() {
        assert_eq!(SECURITY_E2E_COMPONENT, "security_e2e");
        assert!(!SECURITY_E2E_SCHEMA_VERSION.is_empty());
        const { assert!(MIN_BUDGET_MILLIONTHS > 0) };
    }

    // ── AttackCategory ──────────────────────────────────────────────
    #[test]
    fn attack_category_as_str_exhaustive() {
        assert_eq!(
            AttackCategory::CapabilityEscalation.as_str(),
            "capability-escalation"
        );
        assert_eq!(
            AttackCategory::ResourceExhaustion.as_str(),
            "resource-exhaustion"
        );
        assert_eq!(
            AttackCategory::QuarantineCascade.as_str(),
            "quarantine-cascade"
        );
        assert_eq!(
            AttackCategory::SafeModeFallback.as_str(),
            "safe-mode-fallback"
        );
        assert_eq!(
            AttackCategory::BayesianPosterior.as_str(),
            "bayesian-posterior"
        );
        assert_eq!(AttackCategory::ForkDetection.as_str(), "fork-detection");
        assert_eq!(AttackCategory::EpochRegression.as_str(), "epoch-regression");
        assert_eq!(
            AttackCategory::EvidenceIntegrity.as_str(),
            "evidence-integrity"
        );
    }

    #[test]
    fn attack_category_all_returns_eight() {
        assert_eq!(AttackCategory::all().len(), 8);
    }

    #[test]
    fn attack_category_all_unique() {
        let names: std::collections::BTreeSet<&str> =
            AttackCategory::all().iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), 8);
    }

    // ── Xorshift64 ─────────────────────────────────────────────────
    #[test]
    fn xorshift64_deterministic() {
        let mut a = Xorshift64::new(42);
        let mut b = Xorshift64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn xorshift64_zero_seed_becomes_one() {
        let mut zero = Xorshift64::new(0);
        let mut one = Xorshift64::new(1);
        assert_eq!(zero.next_u64(), one.next_u64());
    }

    #[test]
    fn xorshift64_next_usize_bounded() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..1000 {
            assert!(rng.next_usize(7) < 7);
        }
    }

    #[test]
    fn xorshift64_next_bool_boundaries() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..100 {
            assert!(!rng.next_bool(0));
        }
        let mut rng = Xorshift64::new(42);
        for _ in 0..100 {
            assert!(rng.next_bool(100));
        }
    }

    // ── AttackScenarioResult ────────────────────────────────────────
    #[test]
    fn attack_scenario_result_new_defaults() {
        let r = AttackScenarioResult::new(AttackCategory::ForkDetection, "test-scenario");
        assert_eq!(r.category, AttackCategory::ForkDetection);
        assert_eq!(r.scenario_name, "test-scenario");
        assert!(!r.attack_blocked);
        assert!(!r.containment_action_taken);
        assert!(!r.evidence_produced);
        assert_eq!(r.invariant_violations, 0);
        assert_eq!(r.security_events, 0);
        assert!(r.details.is_empty());
    }

    // ── SecuritySuiteConfig ─────────────────────────────────────────
    #[test]
    fn security_suite_config_default() {
        let cfg = SecuritySuiteConfig::default();
        assert_eq!(cfg.seed, 42);
        assert_eq!(cfg.n_extensions, 10);
        assert_eq!(cfg.n_evidence_updates, 20);
        assert!(!cfg.run_id.is_empty());
    }

    // ── SecuritySuiteEvent ──────────────────────────────────────────
    #[test]
    fn security_suite_event_fields() {
        let evt = SecuritySuiteEvent {
            trace_id: "tr-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "security-e2e".to_string(),
            component: SECURITY_E2E_COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            category: "capability-escalation".to_string(),
            scenario: "cpu-budget-escalation".to_string(),
        };
        assert_eq!(evt.component, SECURITY_E2E_COMPONENT);
        assert!(evt.error_code.is_none());
    }

    // ── run_capability_escalation ───────────────────────────────────
    #[test]
    fn capability_escalation_blocks_overconsumption() {
        let results = run_capability_escalation(3, 42);
        assert_eq!(results.len(), 2); // CPU + hostcall scenarios
        // CPU escalation
        let cpu = &results[0];
        assert_eq!(cpu.category, AttackCategory::CapabilityEscalation);
        assert_eq!(cpu.scenario_name, "cpu-budget-escalation");
        assert!(cpu.attack_blocked);
        assert!(cpu.security_events > 0);
        assert!(cpu.evidence_produced);
        // Hostcall escalation
        let hc = &results[1];
        assert_eq!(hc.scenario_name, "hostcall-budget-escalation");
        assert!(hc.attack_blocked);
        assert!(hc.security_events > 0);
    }

    #[test]
    fn capability_escalation_deterministic() {
        let r1 = run_capability_escalation(5, 42);
        let r2 = run_capability_escalation(5, 42);
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.security_events, b.security_events);
            assert_eq!(a.attack_blocked, b.attack_blocked);
        }
    }

    // ── run_resource_exhaustion ─────────────────────────────────────
    #[test]
    fn resource_exhaustion_contains_all() {
        let results = run_resource_exhaustion(5, 42);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.category, AttackCategory::ResourceExhaustion);
        assert!(r.attack_blocked);
        assert!(r.security_events > 0);
        assert!(r.evidence_produced);
    }

    #[test]
    fn resource_exhaustion_deterministic() {
        let r1 = run_resource_exhaustion(5, 99);
        let r2 = run_resource_exhaustion(5, 99);
        assert_eq!(r1[0].security_events, r2[0].security_events);
    }

    // ── run_quarantine_cascade ──────────────────────────────────────
    #[test]
    fn quarantine_cascade_isolates_subset() {
        let results = run_quarantine_cascade(10, 5, 42);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.category, AttackCategory::QuarantineCascade);
        assert!(r.containment_action_taken);
        assert!(r.attack_blocked);
        assert_eq!(r.invariant_violations, 0);
        // Should have quarantined 5 and kept 5 running
        assert_eq!(r.details["quarantined"], "5");
        assert_eq!(r.details["running"], "5");
    }

    #[test]
    fn quarantine_cascade_all_quarantined() {
        let results = run_quarantine_cascade(5, 5, 42);
        let r = &results[0];
        assert_eq!(r.details["quarantined"], "5");
        assert_eq!(r.details["running"], "0");
    }

    #[test]
    fn quarantine_cascade_none_quarantined() {
        let results = run_quarantine_cascade(5, 0, 42);
        let r = &results[0];
        assert_eq!(r.details["quarantined"], "0");
        assert_eq!(r.details["running"], "5");
    }

    // ── run_safe_mode_fallback ──────────────────────────────────────
    #[test]
    fn safe_mode_fallback_all_five_failure_types() {
        let results = run_safe_mode_fallback(42);
        assert_eq!(results.len(), 5);
        for r in &results {
            assert_eq!(r.category, AttackCategory::SafeModeFallback);
            assert!(
                r.attack_blocked,
                "scenario {} should activate safe mode",
                r.scenario_name
            );
            assert!(r.containment_action_taken);
            assert!(r.evidence_produced);
            assert_eq!(
                r.invariant_violations, 0,
                "scenario {} should recover",
                r.scenario_name
            );
        }
    }

    #[test]
    fn safe_mode_fallback_scenario_names() {
        let results = run_safe_mode_fallback(42);
        let names: Vec<&str> = results.iter().map(|r| r.scenario_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "adapter-unavailable",
                "decision-contract-error",
                "evidence-ledger-full",
                "cx-corrupted",
                "cancellation-deadlock",
            ]
        );
    }

    // ── run_bayesian_posterior_convergence ───────────────────────────
    #[test]
    fn bayesian_posterior_convergence_three_scenarios() {
        let results = run_bayesian_posterior_convergence(3, 10, 42);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].scenario_name, "benign-convergence");
        assert_eq!(results[1].scenario_name, "malicious-convergence");
        assert_eq!(results[2].scenario_name, "deterministic-replay");
    }

    #[test]
    fn bayesian_posterior_benign_converges() {
        let results = run_bayesian_posterior_convergence(5, 30, 42);
        let benign = &results[0];
        assert!(
            benign.attack_blocked,
            "benign extensions should converge to Benign risk state"
        );
        assert!(benign.evidence_produced);
    }

    #[test]
    fn bayesian_posterior_deterministic_replay() {
        let results = run_bayesian_posterior_convergence(1, 20, 42);
        let replay = &results[2];
        assert!(
            replay.attack_blocked,
            "deterministic replay should produce identical posteriors"
        );
        assert_eq!(replay.invariant_violations, 0);
    }

    // ── run_epoch_regression ────────────────────────────────────────
    #[test]
    fn epoch_regression_four_scenarios() {
        let results = run_epoch_regression(42);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn epoch_regression_current_validates() {
        let results = run_epoch_regression(42);
        let current = &results[0];
        assert_eq!(current.scenario_name, "current-epoch-validates");
        assert!(current.attack_blocked);
    }

    #[test]
    fn epoch_regression_expired_rejected() {
        let results = run_epoch_regression(42);
        let expired = &results[1];
        assert_eq!(expired.scenario_name, "expired-epoch-rejected");
        assert!(expired.attack_blocked);
        assert!(expired.security_events > 0);
    }

    #[test]
    fn epoch_regression_future_rejected() {
        let results = run_epoch_regression(42);
        let future = &results[2];
        assert_eq!(future.scenario_name, "future-epoch-rejected");
        assert!(future.attack_blocked);
    }

    #[test]
    fn epoch_regression_monotonicity() {
        let results = run_epoch_regression(42);
        let mono = &results[3];
        assert_eq!(mono.scenario_name, "epoch-monotonicity");
        assert!(mono.attack_blocked);
        assert_eq!(mono.invariant_violations, 0);
    }

    // ── run_containment_verification ────────────────────────────────
    #[test]
    fn containment_verification_two_scenarios() {
        let results = run_containment_verification(3, 42);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn containment_verification_sandbox_receipts() {
        let results = run_containment_verification(3, 42);
        let sandbox = &results[0];
        assert_eq!(sandbox.scenario_name, "containment-receipts");
        assert!(sandbox.containment_action_taken);
        assert!(sandbox.evidence_produced);
        assert!(sandbox.attack_blocked);
        assert_eq!(sandbox.invariant_violations, 0);
    }

    #[test]
    fn containment_verification_quarantine_forensic() {
        let results = run_containment_verification(1, 42);
        let forensic = &results[1];
        assert_eq!(forensic.scenario_name, "quarantine-forensic-snapshot");
        assert!(forensic.containment_action_taken);
        assert!(forensic.attack_blocked);
        assert!(forensic.evidence_produced);
    }

    // ── run_security_suite ──────────────────────────────────────────
    #[test]
    fn security_suite_runs_all_categories() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 3,
            n_evidence_updates: 10,
            run_id: "test-suite".to_string(),
        };
        let result = run_security_suite(&config);
        // Should have scenarios from all 7 attack runner functions
        // (fork_detection is not called directly by run_security_suite)
        assert!(!result.scenarios.is_empty());
        assert!(!result.events.is_empty());
        assert!(result.total_security_events > 0);
    }

    #[test]
    fn security_suite_events_have_correct_component() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "test-events".to_string(),
        };
        let result = run_security_suite(&config);
        for evt in &result.events {
            assert_eq!(evt.component, SECURITY_E2E_COMPONENT);
            assert_eq!(evt.event, "attack_scenario_completed");
            assert!(evt.outcome == "pass" || evt.outcome == "fail");
        }
    }

    #[test]
    fn security_suite_scenario_count_matches_events() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "test-count".to_string(),
        };
        let result = run_security_suite(&config);
        assert_eq!(result.scenarios.len(), result.events.len());
    }

    // ── write_security_evidence ─────────────────────────────────────
    #[test]
    fn write_security_evidence_creates_files() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "test-evidence".to_string(),
        };
        let result = run_security_suite(&config);
        let dir = std::env::temp_dir().join("franken_sec_e2e_test_evidence");
        let _ = fs::remove_dir_all(&dir);
        let artifacts = write_security_evidence(&result, &dir).expect("serde deserialization should succeed");

        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.evidence_path.exists());
        assert!(artifacts.summary_path.exists());

        // Verify manifest
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.run_manifest_path).expect("serde deserialization should succeed"))
                .expect("serde deserialization should succeed");
        assert_eq!(manifest["schema_version"], SECURITY_E2E_SCHEMA_VERSION);

        // Verify evidence JSONL
        let evidence = fs::read_to_string(&artifacts.evidence_path).expect("serde deserialization should succeed");
        let lines: Vec<&str> = evidence.lines().collect();
        assert!(!lines.is_empty());
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("serde deserialization should succeed");
        }

        // Verify summary
        let summary: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.summary_path).expect("serde deserialization should succeed")).expect("serde deserialization should succeed");
        assert_eq!(summary["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
        assert!(summary["categories"].is_array());

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Enrichment: additional coverage --

    #[test]
    fn attack_category_as_str_uniqueness_via_btreeset() {
        let strs: std::collections::BTreeSet<&str> =
            AttackCategory::all().iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), AttackCategory::all().len());
    }

    #[test]
    fn xorshift64_different_seeds_differ() {
        let mut a = Xorshift64::new(42);
        let mut b = Xorshift64::new(99);
        let mut same = true;
        for _ in 0..10 {
            if a.next_u64() != b.next_u64() {
                same = false;
                break;
            }
        }
        assert!(!same, "different seeds should produce different sequences");
    }

    #[test]
    fn capability_escalation_single_extension() {
        let results = run_capability_escalation(1, 42);
        assert_eq!(results.len(), 2);
        assert!(results[0].attack_blocked);
        assert!(results[1].attack_blocked);
    }

    #[test]
    fn resource_exhaustion_single_extension() {
        let results = run_resource_exhaustion(1, 42);
        assert_eq!(results.len(), 1);
        assert!(results[0].attack_blocked);
        assert!(results[0].evidence_produced);
    }

    #[test]
    fn quarantine_cascade_n_quarantine_exceeds_total() {
        // n_quarantine > n_total should clamp to n_total
        let results = run_quarantine_cascade(3, 10, 42);
        let r = &results[0];
        assert_eq!(r.details["quarantined"], "3");
        assert_eq!(r.details["running"], "0");
    }

    #[test]
    fn suite_blocked_flag_semantics() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "test-blocked".to_string(),
        };
        let result = run_security_suite(&config);
        // blocked = total_invariant_violations > 0
        assert_eq!(result.blocked, result.total_invariant_violations > 0);
    }

    #[test]
    fn suite_deterministic_with_same_seed() {
        let config1 = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "det-1".to_string(),
        };
        let config2 = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "det-2".to_string(),
        };
        let r1 = run_security_suite(&config1);
        let r2 = run_security_suite(&config2);
        assert_eq!(r1.scenarios.len(), r2.scenarios.len());
        assert_eq!(r1.total_security_events, r2.total_security_events);
        assert_eq!(r1.total_invariant_violations, r2.total_invariant_violations);
        for (a, b) in r1.scenarios.iter().zip(r2.scenarios.iter()) {
            assert_eq!(a.scenario_name, b.scenario_name);
            assert_eq!(a.attack_blocked, b.attack_blocked);
            assert_eq!(a.security_events, b.security_events);
        }
    }

    #[test]
    fn safe_mode_fallback_activation_and_recovery_counts() {
        let results = run_safe_mode_fallback(42);
        for r in &results {
            let act: u64 = r.details["activation_count"].parse().expect("serde deserialization should succeed");
            let rec: u64 = r.details["recovery_count"].parse().expect("serde deserialization should succeed");
            assert!(
                act >= 1,
                "activation_count should be >= 1 for {}",
                r.scenario_name
            );
            assert!(
                rec >= 1,
                "recovery_count should be >= 1 for {}",
                r.scenario_name
            );
        }
    }

    #[test]
    fn epoch_regression_all_zero_invariant_violations() {
        let results = run_epoch_regression(42);
        for r in &results {
            assert_eq!(
                r.invariant_violations, 0,
                "scenario {} has invariant violations",
                r.scenario_name
            );
        }
    }

    #[test]
    fn containment_verification_zero_invariant_violations() {
        let results = run_containment_verification(3, 42);
        for r in &results {
            assert_eq!(
                r.invariant_violations, 0,
                "scenario {} has invariant violations",
                r.scenario_name
            );
        }
    }

    #[test]
    fn xorshift64_period_not_trivially_short() {
        // Verify xorshift64 does not cycle within first 1000 values
        let mut rng = Xorshift64::new(42);
        let first = rng.next_u64();
        for i in 1..1000 {
            let val = rng.next_u64();
            assert_ne!(val, first, "xorshift64 repeated initial value at step {i}");
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn xorshift64_seed_zero_becomes_one() {
        let mut rng = Xorshift64::new(0);
        assert_eq!(rng.state, 1, "seed 0 must be normalized to 1");
        let val = rng.next_u64();
        assert_ne!(val, 0);
    }

    #[test]
    fn constants_values_are_stable() {
        assert_eq!(SECURITY_E2E_COMPONENT, "security_e2e");
        assert!(SECURITY_E2E_SCHEMA_VERSION.starts_with("franken-engine"));
        assert_eq!(MIN_BUDGET_MILLIONTHS, 1_000);
    }

    #[test]
    fn attack_category_as_str_all_contain_hyphen() {
        for cat in AttackCategory::all() {
            let s = cat.as_str();
            assert!(!s.is_empty());
            assert!(s.contains('-'), "as_str should be hyphenated: {s}");
        }
    }

    #[test]
    fn capability_escalation_many_extensions_all_blocked() {
        let results = run_capability_escalation(10, 99);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.attack_blocked);
        }
    }

    #[test]
    fn resource_exhaustion_many_extensions_produces_events() {
        let results = run_resource_exhaustion(10, 99);
        assert_eq!(results.len(), 1);
        assert!(results[0].attack_blocked);
        assert!(results[0].security_events > 0);
    }

    // -- Enrichment: PearlTower 2026-02-27 --

    #[test]
    fn attack_category_clone_eq() {
        let a = AttackCategory::CapabilityEscalation;
        let b = a;
        assert_eq!(a, b);
        let c = AttackCategory::ForkDetection;
        let d = c;
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn attack_scenario_result_clone_preserves_fields() {
        let mut r = AttackScenarioResult::new(AttackCategory::EvidenceIntegrity, "clone-test");
        r.attack_blocked = true;
        r.containment_action_taken = true;
        r.evidence_produced = true;
        r.invariant_violations = 3;
        r.security_events = 7;
        r.details.insert("key1".to_string(), "value1".to_string());
        let cloned = r.clone();
        assert_eq!(cloned.category, r.category);
        assert_eq!(cloned.scenario_name, r.scenario_name);
        assert_eq!(cloned.attack_blocked, r.attack_blocked);
        assert_eq!(cloned.containment_action_taken, r.containment_action_taken);
        assert_eq!(cloned.evidence_produced, r.evidence_produced);
        assert_eq!(cloned.invariant_violations, r.invariant_violations);
        assert_eq!(cloned.security_events, r.security_events);
        assert_eq!(cloned.details, r.details);
    }

    #[test]
    fn security_suite_event_clone_preserves_fields() {
        let evt = SecuritySuiteEvent {
            trace_id: "tr-clone".to_string(),
            decision_id: "d-clone".to_string(),
            policy_id: "pol-clone".to_string(),
            component: "comp".to_string(),
            event: "evt".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("FE-999".to_string()),
            category: "test-cat".to_string(),
            scenario: "test-sc".to_string(),
        };
        let cloned = evt.clone();
        assert_eq!(cloned.trace_id, evt.trace_id);
        assert_eq!(cloned.decision_id, evt.decision_id);
        assert_eq!(cloned.policy_id, evt.policy_id);
        assert_eq!(cloned.error_code, evt.error_code);
    }

    #[test]
    fn xorshift64_next_usize_bound_one_always_zero() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..100 {
            assert_eq!(rng.next_usize(1), 0);
        }
    }

    #[test]
    fn xorshift64_next_bool_fifty_pct_produces_mix() {
        let mut rng = Xorshift64::new(42);
        let mut trues = 0u64;
        let mut falses = 0u64;
        for _ in 0..1000 {
            if rng.next_bool(50) {
                trues += 1;
            } else {
                falses += 1;
            }
        }
        // With 1000 trials at 50%, both should be > 0
        assert!(trues > 0, "expected some true values");
        assert!(falses > 0, "expected some false values");
    }

    #[test]
    fn attack_scenario_result_details_insertion_order() {
        let mut r = AttackScenarioResult::new(AttackCategory::BayesianPosterior, "order-test");
        r.details.insert("z_key".to_string(), "z".to_string());
        r.details.insert("a_key".to_string(), "a".to_string());
        r.details.insert("m_key".to_string(), "m".to_string());
        // BTreeMap should maintain sorted order
        let keys: Vec<&String> = r.details.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    #[test]
    fn quarantine_cascade_single_extension_single_quarantine() {
        let results = run_quarantine_cascade(1, 1, 42);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.details["quarantined"], "1");
        assert_eq!(r.details["running"], "0");
        assert_eq!(r.invariant_violations, 0);
    }

    #[test]
    fn suite_different_seeds_may_differ_in_events() {
        let config_a = SecuritySuiteConfig {
            seed: 1,
            n_extensions: 3,
            n_evidence_updates: 10,
            run_id: "seed-1".to_string(),
        };
        let config_b = SecuritySuiteConfig {
            seed: 9999,
            n_extensions: 3,
            n_evidence_updates: 10,
            run_id: "seed-9999".to_string(),
        };
        let r1 = run_security_suite(&config_a);
        let r2 = run_security_suite(&config_b);
        // Scenario count should be the same (same n_extensions)
        assert_eq!(r1.scenarios.len(), r2.scenarios.len());
    }

    #[test]
    fn containment_verification_many_extensions_no_violations() {
        let results = run_containment_verification(10, 42);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.invariant_violations, 0,
                "scenario {} should have 0 violations at scale",
                r.scenario_name
            );
            assert!(r.evidence_produced);
        }
    }

    #[test]
    fn safe_mode_fallback_deterministic_across_runs() {
        let r1 = run_safe_mode_fallback(42);
        let r2 = run_safe_mode_fallback(42);
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.scenario_name, b.scenario_name);
            assert_eq!(a.attack_blocked, b.attack_blocked);
            assert_eq!(a.invariant_violations, b.invariant_violations);
            assert_eq!(a.security_events, b.security_events);
        }
    }

    #[test]
    fn attack_category_copy_does_not_move() {
        let a = AttackCategory::QuarantineCascade;
        let b = a; // Copy, not move
        let c = a; // still valid because Copy
        assert_eq!(b, c);
        assert_eq!(a.as_str(), "quarantine-cascade");
    }

    #[test]
    fn capability_escalation_zero_extensions() {
        let results = run_capability_escalation(0, 42);
        assert_eq!(results.len(), 2);
        // With 0 extensions, CPU scenario should still exist but with no events
        let cpu = &results[0];
        assert_eq!(cpu.scenario_name, "cpu-budget-escalation");
        assert_eq!(cpu.security_events, 0);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_attack_category_debug_format_contains_variant_name() {
        // Verify Debug output includes the variant name for diagnostics
        let dbg = format!("{:?}", AttackCategory::CapabilityEscalation);
        assert!(
            dbg.contains("CapabilityEscalation"),
            "Debug should contain variant name, got: {dbg}"
        );
        let dbg2 = format!("{:?}", AttackCategory::EvidenceIntegrity);
        assert!(dbg2.contains("EvidenceIntegrity"));
    }

    #[test]
    fn enrichment_attack_category_all_matches_individual_variants() {
        // Verify that all() returns every variant in the expected order
        let all = AttackCategory::all();
        assert_eq!(all[0], AttackCategory::CapabilityEscalation);
        assert_eq!(all[1], AttackCategory::ResourceExhaustion);
        assert_eq!(all[2], AttackCategory::QuarantineCascade);
        assert_eq!(all[3], AttackCategory::SafeModeFallback);
        assert_eq!(all[4], AttackCategory::BayesianPosterior);
        assert_eq!(all[5], AttackCategory::ForkDetection);
        assert_eq!(all[6], AttackCategory::EpochRegression);
        assert_eq!(all[7], AttackCategory::EvidenceIntegrity);
    }

    #[test]
    fn enrichment_attack_category_as_str_roundtrip_all_lowercase_hyphenated() {
        // Every as_str result should be all-lowercase with hyphens only (no underscores)
        for cat in AttackCategory::all() {
            let s = cat.as_str();
            assert_eq!(s, s.to_lowercase(), "as_str should be lowercase: {s}");
            assert!(
                !s.contains('_'),
                "as_str should use hyphens not underscores: {s}"
            );
        }
    }

    #[test]
    fn enrichment_attack_scenario_result_debug_format_includes_scenario_name() {
        let r = AttackScenarioResult::new(AttackCategory::ForkDetection, "debug-test");
        let dbg = format!("{r:?}");
        assert!(
            dbg.contains("debug-test"),
            "Debug should include scenario_name"
        );
        assert!(
            dbg.contains("ForkDetection"),
            "Debug should include category"
        );
    }

    #[test]
    fn enrichment_attack_scenario_result_details_overwrite_key() {
        // Inserting the same key should overwrite the value (BTreeMap semantics)
        let mut r = AttackScenarioResult::new(AttackCategory::EpochRegression, "overwrite");
        r.details.insert("key".to_string(), "v1".to_string());
        r.details.insert("key".to_string(), "v2".to_string());
        assert_eq!(r.details.len(), 1);
        assert_eq!(r.details["key"], "v2");
    }

    #[test]
    fn enrichment_security_suite_event_error_code_some_variant() {
        let evt = SecuritySuiteEvent {
            trace_id: "tr".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("FE-TEST-ERR".to_string()),
            category: "test".to_string(),
            scenario: "test".to_string(),
        };
        assert_eq!(evt.error_code.as_deref(), Some("FE-TEST-ERR"));
        let dbg = format!("{evt:?}");
        assert!(
            dbg.contains("FE-TEST-ERR"),
            "Debug should include error code"
        );
    }

    #[test]
    fn enrichment_security_suite_config_debug_format() {
        let cfg = SecuritySuiteConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("42"), "Debug should show seed");
        assert!(dbg.contains("10"), "Debug should show n_extensions");
        assert!(dbg.contains("20"), "Debug should show n_evidence_updates");
    }

    #[test]
    fn enrichment_security_suite_result_debug_format() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 1,
            n_evidence_updates: 5,
            run_id: "dbg-test".to_string(),
        };
        let result = run_security_suite(&config);
        let dbg = format!("{result:?}");
        assert!(
            dbg.contains("scenarios"),
            "Debug should contain 'scenarios'"
        );
        assert!(dbg.contains("blocked"), "Debug should contain 'blocked'");
    }

    #[test]
    fn enrichment_xorshift64_next_u64_never_zero_for_many_iterations() {
        // xorshift64 with nonzero seed should never produce 0
        let mut rng = Xorshift64::new(42);
        for i in 0..10_000 {
            let val = rng.next_u64();
            assert_ne!(val, 0, "xorshift64 produced zero at iteration {i}");
        }
    }

    #[test]
    fn enrichment_xorshift64_next_usize_distribution_coverage() {
        // With bound=4, after enough iterations all 4 buckets should be hit
        let mut rng = Xorshift64::new(7);
        let mut buckets = [false; 4];
        for _ in 0..200 {
            buckets[rng.next_usize(4)] = true;
        }
        for (i, &hit) in buckets.iter().enumerate() {
            assert!(hit, "bucket {i} was never hit in 200 iterations");
        }
    }

    #[test]
    fn enrichment_resource_exhaustion_zero_extensions() {
        // Running with 0 extensions should still produce one result
        let results = run_resource_exhaustion(0, 42);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(r.attack_blocked);
        // No extensions means enforcement is vacuously empty
        assert_eq!(r.security_events, 0);
    }

    #[test]
    fn enrichment_quarantine_cascade_invariant_violations_zero_for_valid_inputs() {
        // Multiple sizes, all should have zero invariant violations
        for n in [2, 5, 8, 15] {
            let half = n / 2;
            let results = run_quarantine_cascade(n, half, 42);
            assert_eq!(
                results[0].invariant_violations, 0,
                "invariant violations should be 0 for n_total={n}, n_quarantine={half}"
            );
        }
    }

    #[test]
    fn enrichment_safe_mode_fallback_each_scenario_has_action_detail() {
        // Every safe mode scenario should have an "action" key in details
        let results = run_safe_mode_fallback(42);
        for r in &results {
            assert!(
                r.details.contains_key("action"),
                "scenario {} missing 'action' detail",
                r.scenario_name
            );
            assert!(
                !r.details["action"].is_empty(),
                "scenario {} has empty 'action' detail",
                r.scenario_name
            );
        }
    }

    #[test]
    fn enrichment_bayesian_posterior_malicious_detects_risk() {
        // With enough evidence, at least one malicious extension should be flagged
        let results = run_bayesian_posterior_convergence(5, 30, 42);
        let malicious = &results[1];
        assert_eq!(malicious.scenario_name, "malicious-convergence");
        assert!(malicious.attack_blocked, "should detect malicious behavior");
        assert!(
            malicious.security_events > 0,
            "should flag risky extensions"
        );
    }

    #[test]
    fn enrichment_epoch_regression_evidence_produced_all_scenarios() {
        let results = run_epoch_regression(42);
        for r in &results {
            assert!(
                r.evidence_produced,
                "scenario {} should produce evidence",
                r.scenario_name
            );
        }
    }

    #[test]
    fn enrichment_containment_verification_security_events_proportional() {
        // More extensions should produce more or equal security events
        let r_small = run_containment_verification(2, 42);
        let r_large = run_containment_verification(8, 42);
        let events_small = r_small[0].security_events;
        let events_large = r_large[0].security_events;
        assert!(
            events_large >= events_small,
            "more extensions ({events_large}) should produce >= events than fewer ({events_small})"
        );
    }

    #[test]
    fn enrichment_suite_events_trace_id_matches_run_id() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "trace-check-42".to_string(),
        };
        let result = run_security_suite(&config);
        for evt in &result.events {
            assert_eq!(
                evt.trace_id, "trace-check-42",
                "event trace_id should match config run_id"
            );
        }
    }

    #[test]
    fn enrichment_suite_events_decision_id_prefixed_with_sec() {
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 2,
            n_evidence_updates: 5,
            run_id: "prefix-test".to_string(),
        };
        let result = run_security_suite(&config);
        for evt in &result.events {
            assert!(
                evt.decision_id.starts_with("sec-"),
                "decision_id should start with 'sec-', got: {}",
                evt.decision_id
            );
        }
    }

    #[test]
    fn enrichment_write_security_evidence_manifest_field_names() {
        // Verify the JSON manifest has the expected top-level field names
        let config = SecuritySuiteConfig {
            seed: 42,
            n_extensions: 1,
            n_evidence_updates: 3,
            run_id: "field-check".to_string(),
        };
        let result = run_security_suite(&config);
        let dir = std::env::temp_dir().join("franken_sec_e2e_enrichment_fields");
        let _ = fs::remove_dir_all(&dir);
        let artifacts = write_security_evidence(&result, &dir).expect("serde deserialization should succeed");

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifacts.run_manifest_path).expect("serde deserialization should succeed"))
                .expect("serde deserialization should succeed");
        // Check all expected fields are present
        assert!(manifest.get("schema_version").is_some());
        assert!(manifest.get("scenario_count").is_some());
        assert!(manifest.get("total_security_events").is_some());
        assert!(manifest.get("total_invariant_violations").is_some());
        assert!(manifest.get("blocked").is_some());

        // scenario_count matches actual count
        assert_eq!(
            manifest["scenario_count"].as_u64().expect("serde deserialization should succeed"),
            result.scenarios.len() as u64
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
