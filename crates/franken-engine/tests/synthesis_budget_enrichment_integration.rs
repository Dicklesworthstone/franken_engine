//! Enrichment integration tests for `synthesis_budget` module.
//!
//! Tests advanced budget monitor scenarios, history tracking, registry
//! operations, fallback quality, and edge cases in consumption tracking.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::synthesis_budget::{
    BudgetDimension, BudgetError, BudgetHistory, BudgetHistoryEntry, BudgetMonitor, BudgetOverride,
    BudgetRegistry, ExhaustionReason, FallbackQuality, FallbackResult, PhaseBudget,
    PhaseConsumption, SynthesisBudgetContract, SynthesisPhase,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tight_contract() -> SynthesisBudgetContract {
    SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000,
        global_compute_cap: 100,
        global_depth_cap: 10,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn contract_with_phase_budgets() -> SynthesisBudgetContract {
    let mut pb = BTreeMap::new();
    pb.insert(
        SynthesisPhase::StaticAnalysis,
        PhaseBudget { time_cap_ns: 500, compute_cap: 50, depth_cap: 5 },
    );
    pb.insert(
        SynthesisPhase::Ablation,
        PhaseBudget { time_cap_ns: 300, compute_cap: 40, depth_cap: 8 },
    );
    SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000,
        global_compute_cap: 100,
        global_depth_cap: 20,
        phase_budgets: pb,
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn make_history_entry(ext: &str, exhausted: bool, time_ns: u64) -> BudgetHistoryEntry {
    BudgetHistoryEntry {
        extension_id: ext.to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption { time_ns, compute: 50, depth: 5 },
        exhausted,
        timestamp_ns: 1_000_000,
        epoch: SecurityEpoch::from_raw(0),
    }
}

// ---------------------------------------------------------------------------
// 1. SynthesisPhase ordering
// ---------------------------------------------------------------------------

#[test]
fn enrich_phase_ordering_matches_pipeline() {
    assert!(SynthesisPhase::StaticAnalysis < SynthesisPhase::Ablation);
    assert!(SynthesisPhase::Ablation < SynthesisPhase::TheoremChecking);
    assert!(SynthesisPhase::TheoremChecking < SynthesisPhase::ResultAssembly);
}

// ---------------------------------------------------------------------------
// 2. BudgetDimension ordering
// ---------------------------------------------------------------------------

#[test]
fn enrich_dimension_ordering() {
    assert!(BudgetDimension::Time < BudgetDimension::Compute);
    assert!(BudgetDimension::Compute < BudgetDimension::Depth);
}

// ---------------------------------------------------------------------------
// 3. PhaseBudget edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_phase_budget_exact_limit_not_exceeded() {
    let budget = PhaseBudget { time_cap_ns: 100, compute_cap: 50, depth_cap: 10 };
    let consumed = PhaseConsumption { time_ns: 100, compute: 50, depth: 10 };
    assert!(!budget.is_exceeded(&consumed));
}

#[test]
fn enrich_phase_budget_all_three_exceeded() {
    let budget = PhaseBudget { time_cap_ns: 100, compute_cap: 50, depth_cap: 10 };
    let consumed = PhaseConsumption { time_ns: 200, compute: 100, depth: 20 };
    assert!(budget.is_exceeded(&consumed));
    assert_eq!(budget.exceeded_dimensions(&consumed).len(), 3);
}

#[test]
fn enrich_phase_budget_zero_caps() {
    let budget = PhaseBudget { time_cap_ns: 0, compute_cap: 0, depth_cap: 0 };
    let consumed = PhaseConsumption { time_ns: 1, compute: 1, depth: 1 };
    assert!(budget.is_exceeded(&consumed));
}

// ---------------------------------------------------------------------------
// 4. PhaseConsumption::zero
// ---------------------------------------------------------------------------

#[test]
fn enrich_phase_consumption_zero_is_all_zero() {
    let c = PhaseConsumption::zero();
    assert_eq!(c.time_ns, 0);
    assert_eq!(c.compute, 0);
    assert_eq!(c.depth, 0);
}

// ---------------------------------------------------------------------------
// 5. Contract global exceeded
// ---------------------------------------------------------------------------

#[test]
fn enrich_contract_global_not_exceeded_within() {
    let c = tight_contract();
    let total = PhaseConsumption { time_ns: 500, compute: 50, depth: 5 };
    assert!(!c.is_globally_exceeded(&total));
}

#[test]
fn enrich_contract_global_exceeded_time_only() {
    let c = tight_contract();
    let total = PhaseConsumption { time_ns: 1001, compute: 0, depth: 0 };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrich_contract_global_exceeded_depth_only() {
    let c = tight_contract();
    let total = PhaseConsumption { time_ns: 0, compute: 0, depth: 11 };
    assert!(c.is_globally_exceeded(&total));
}

// ---------------------------------------------------------------------------
// 6. Monitor multi-phase tracking
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_multi_phase_total_accumulates() {
    let c = SynthesisBudgetContract::default();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(100, 10, 1).unwrap();
    monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
    monitor.record_consumption(200, 20, 2).unwrap();
    let total = monitor.total_consumption();
    assert_eq!(total.time_ns, 300);
    assert_eq!(total.compute, 30);
}

#[test]
fn enrich_monitor_phase_consumption_isolated() {
    let c = SynthesisBudgetContract::default();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(100, 10, 1).unwrap();
    monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
    monitor.record_consumption(200, 20, 2).unwrap();

    let sa = monitor.phase_consumption(SynthesisPhase::StaticAnalysis).unwrap();
    assert_eq!(sa.time_ns, 100);
    let ab = monitor.phase_consumption(SynthesisPhase::Ablation).unwrap();
    assert_eq!(ab.time_ns, 200);
}

// ---------------------------------------------------------------------------
// 7. Monitor remaining budget
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_remaining_global_tracks_correctly() {
    let c = tight_contract();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(400, 30, 3).unwrap();
    let remaining = monitor.remaining_global();
    assert_eq!(remaining.time_ns, 600);
    assert_eq!(remaining.compute, 70);
}

#[test]
fn enrich_monitor_remaining_current_phase() {
    let c = contract_with_phase_budgets();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(200, 20, 2).unwrap();
    let remaining = monitor.remaining_for_current_phase().unwrap();
    assert_eq!(remaining.time_ns, 300);
    assert_eq!(remaining.compute, 30);
}

// ---------------------------------------------------------------------------
// 8. Monitor utilization
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_utilization_zero_when_unused() {
    let c = tight_contract();
    let monitor = BudgetMonitor::new(c);
    let util = monitor.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap_or(&0), 0);
}

#[test]
fn enrich_monitor_utilization_100_percent() {
    let c = tight_contract();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(1_000, 100, 10).unwrap();
    let util = monitor.utilization();
    assert_eq!(util[&BudgetDimension::Time], 1_000_000);
}

// ---------------------------------------------------------------------------
// 9. Monitor current phase
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_current_phase_none_initially() {
    let monitor = BudgetMonitor::new(SynthesisBudgetContract::default());
    assert_eq!(monitor.current_phase(), None);
}

#[test]
fn enrich_monitor_current_phase_after_begin() {
    let mut monitor = BudgetMonitor::new(SynthesisBudgetContract::default());
    monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
    assert_eq!(monitor.current_phase(), Some(SynthesisPhase::Ablation));
}

// ---------------------------------------------------------------------------
// 10. BudgetError display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_budget_error_display_all_variants() {
    let errors = vec![
        BudgetError::AlreadyExhausted,
        BudgetError::NoActivePhase,
        BudgetError::Exhausted(ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Compute],
            phase: SynthesisPhase::TheoremChecking,
            global_limit_hit: true,
            consumption: PhaseConsumption { time_ns: 0, compute: 200, depth: 0 },
            limit_value: 100,
        }),
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn enrich_budget_error_serde_roundtrip() {
    let errors = vec![BudgetError::AlreadyExhausted, BudgetError::NoActivePhase];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: BudgetError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// 11. ExhaustionReason display
// ---------------------------------------------------------------------------

#[test]
fn enrich_exhaustion_reason_display_format() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Depth],
        phase: SynthesisPhase::Ablation,
        global_limit_hit: false,
        consumption: PhaseConsumption { time_ns: 2000, compute: 10, depth: 20 },
        limit_value: 1000,
    };
    let s = reason.to_string();
    assert!(s.contains("ablation"));
    assert!(s.contains("time"));
}

// ---------------------------------------------------------------------------
// 12. FallbackQuality display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_quality_display_all() {
    assert_eq!(FallbackQuality::StaticBound.to_string(), "static-bound");
    assert_eq!(FallbackQuality::PartialAblation.to_string(), "partial-ablation");
    assert_eq!(FallbackQuality::UnverifiedFull.to_string(), "unverified-full");
}

#[test]
fn enrich_fallback_quality_serde_roundtrip() {
    for q in [FallbackQuality::StaticBound, FallbackQuality::PartialAblation, FallbackQuality::UnverifiedFull] {
        let json = serde_json::to_string(&q).unwrap();
        let back: FallbackQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }
}

// ---------------------------------------------------------------------------
// 13. FallbackResult serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_result_serde_roundtrip() {
    let result = FallbackResult {
        quality: FallbackQuality::PartialAblation,
        result_digest: "abc123".into(),
        exhaustion_reason: ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time],
            phase: SynthesisPhase::Ablation,
            global_limit_hit: false,
            consumption: PhaseConsumption { time_ns: 500, compute: 10, depth: 1 },
            limit_value: 300,
        },
        increase_likely_helpful: true,
        recommended_multiplier: Some(2_000_000),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// 14. BudgetOverride serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_budget_override_serde_roundtrip() {
    let ovr = BudgetOverride {
        extension_id: "ext-special".into(),
        contract: tight_contract(),
        justification: "needs tight limits".into(),
    };
    let json = serde_json::to_string(&ovr).unwrap();
    let back: BudgetOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(ovr, back);
}

// ---------------------------------------------------------------------------
// 15. Registry multiple overrides
// ---------------------------------------------------------------------------

#[test]
fn enrich_registry_multiple_overrides() {
    let mut reg = BudgetRegistry::default();
    for i in 0..5 {
        reg.add_override(BudgetOverride {
            extension_id: format!("ext-{i}"),
            contract: tight_contract(),
            justification: format!("reason {i}"),
        });
    }
    assert_eq!(reg.override_count(), 5);
}

#[test]
fn enrich_registry_default_contract_accessible() {
    let reg = BudgetRegistry::default();
    let def = reg.default_contract();
    assert_eq!(def.global_time_cap_ns, 30_000_000_000);
}

// ---------------------------------------------------------------------------
// 16. BudgetHistory exhaustion rate
// ---------------------------------------------------------------------------

#[test]
fn enrich_history_exhaustion_rate_zero_when_empty() {
    let history = BudgetHistory::new(10);
    assert_eq!(history.exhaustion_rate("ext-1"), 0);
}

#[test]
fn enrich_history_exhaustion_rate_all_exhausted() {
    let mut history = BudgetHistory::new(10);
    for _ in 0..5 {
        history.record(make_history_entry("ext-1", true, 1000));
    }
    assert_eq!(history.exhaustion_rate("ext-1"), 1_000_000);
}

#[test]
fn enrich_history_exhaustion_rate_half() {
    let mut history = BudgetHistory::new(10);
    history.record(make_history_entry("ext-1", true, 1000));
    history.record(make_history_entry("ext-1", false, 500));
    assert_eq!(history.exhaustion_rate("ext-1"), 500_000);
}

// ---------------------------------------------------------------------------
// 17. BudgetHistory average utilization
// ---------------------------------------------------------------------------

#[test]
fn enrich_history_average_utilization_single_entry() {
    let contract = tight_contract();
    let mut history = BudgetHistory::new(10);
    history.record(make_history_entry("ext-1", false, 500));
    let avg = history.average_utilization("ext-1", &contract);
    assert_eq!(avg[&BudgetDimension::Time], 500_000);
}

#[test]
fn enrich_history_average_utilization_empty() {
    let contract = tight_contract();
    let history = BudgetHistory::new(10);
    let avg = history.average_utilization("ext-1", &contract);
    assert!(avg.is_empty());
}

// ---------------------------------------------------------------------------
// 18. BudgetHistory default
// ---------------------------------------------------------------------------

#[test]
fn enrich_history_default_max_entries() {
    let history = BudgetHistory::default();
    assert!(history.is_empty());
}

// ---------------------------------------------------------------------------
// 19. Monitor phase-level exhaustion detail
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_phase_exhaustion_records_phase() {
    let c = contract_with_phase_budgets();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let _ = monitor.record_consumption(600, 0, 0);
    let reason = monitor.exhaustion_reason().unwrap();
    assert_eq!(reason.phase, SynthesisPhase::StaticAnalysis);
    assert!(!reason.global_limit_hit);
}

// ---------------------------------------------------------------------------
// 20. Monitor global exhaustion across phases
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_global_exhaustion_across_phases() {
    let c = tight_contract();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(400, 0, 0).unwrap();
    monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
    monitor.record_consumption(400, 0, 0).unwrap();
    monitor.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    let result = monitor.record_consumption(300, 0, 0);
    assert!(matches!(result, Err(BudgetError::Exhausted(_))));
    let reason = monitor.exhaustion_reason().unwrap();
    assert!(reason.global_limit_hit);
}

// ---------------------------------------------------------------------------
// 21. Contract default values
// ---------------------------------------------------------------------------

#[test]
fn enrich_contract_default_has_sensible_values() {
    let c = SynthesisBudgetContract::default();
    assert_eq!(c.version, 1);
    assert_eq!(c.global_time_cap_ns, 30_000_000_000);
    assert_eq!(c.global_compute_cap, 100_000);
    assert_eq!(c.global_depth_cap, 1000);
}

// ---------------------------------------------------------------------------
// 22. Contract budget_for_phase fallback
// ---------------------------------------------------------------------------

#[test]
fn enrich_contract_budget_for_phase_fallback_to_global() {
    let c = tight_contract();
    let budget = c.budget_for_phase(SynthesisPhase::ResultAssembly);
    assert_eq!(budget.time_cap_ns, c.global_time_cap_ns);
}

// ---------------------------------------------------------------------------
// 23. BudgetHistoryEntry serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_budget_history_entry_serde_roundtrip() {
    let entry = make_history_entry("ext-test", false, 750);
    let json = serde_json::to_string(&entry).unwrap();
    let back: BudgetHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// 24. History eviction order
// ---------------------------------------------------------------------------

#[test]
fn enrich_history_eviction_removes_oldest() {
    let mut history = BudgetHistory::new(2);
    history.record(BudgetHistoryEntry {
        extension_id: "first".into(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption::zero(),
        exhausted: false,
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(0),
    });
    history.record(BudgetHistoryEntry {
        extension_id: "second".into(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption::zero(),
        exhausted: false,
        timestamp_ns: 200,
        epoch: SecurityEpoch::from_raw(0),
    });
    history.record(BudgetHistoryEntry {
        extension_id: "third".into(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption::zero(),
        exhausted: false,
        timestamp_ns: 300,
        epoch: SecurityEpoch::from_raw(0),
    });
    assert_eq!(history.len(), 2);
    assert_eq!(history.entries()[0].extension_id, "second");
}

// ---------------------------------------------------------------------------
// 25. Monitor remaining_for_current_phase None
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_remaining_current_phase_none_when_no_phase() {
    let monitor = BudgetMonitor::new(SynthesisBudgetContract::default());
    assert!(monitor.remaining_for_current_phase().is_none());
}

// ---------------------------------------------------------------------------
// 26. Registry replace override
// ---------------------------------------------------------------------------

#[test]
fn enrich_registry_replace_existing_override() {
    let mut reg = BudgetRegistry::default();
    reg.add_override(BudgetOverride {
        extension_id: "ext-1".into(),
        contract: tight_contract(),
        justification: "first".into(),
    });
    let mut updated = tight_contract();
    updated.global_time_cap_ns = 2000;
    reg.add_override(BudgetOverride {
        extension_id: "ext-1".into(),
        contract: updated,
        justification: "second".into(),
    });
    assert_eq!(reg.override_count(), 1);
    assert_eq!(reg.effective_contract("ext-1").global_time_cap_ns, 2000);
}

// ---------------------------------------------------------------------------
// 27. Monitor serde with multiple phases
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_serde_roundtrip_with_multiple_phases() {
    let c = SynthesisBudgetContract::default();
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(100, 10, 1).unwrap();
    monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
    monitor.record_consumption(200, 20, 2).unwrap();

    let json = serde_json::to_string(&monitor).unwrap();
    let back: BudgetMonitor = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_consumption().time_ns, 300);
}

// ---------------------------------------------------------------------------
// 28. ExhaustionReason serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_exhaustion_reason_serde_roundtrip() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Compute],
        phase: SynthesisPhase::TheoremChecking,
        global_limit_hit: true,
        consumption: PhaseConsumption { time_ns: 5000, compute: 200, depth: 15 },
        limit_value: 1000,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: ExhaustionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}

// ---------------------------------------------------------------------------
// 29. Full synthesis within budget
// ---------------------------------------------------------------------------

#[test]
fn enrich_full_synthesis_four_phases_within_budget() {
    let c = tight_contract();
    let mut m = BudgetMonitor::new(c);
    m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    m.record_consumption(200, 20, 2).unwrap();
    m.begin_phase(SynthesisPhase::Ablation).unwrap();
    m.record_consumption(300, 30, 3).unwrap();
    m.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    m.record_consumption(200, 20, 2).unwrap();
    m.begin_phase(SynthesisPhase::ResultAssembly).unwrap();
    m.record_consumption(100, 10, 1).unwrap();
    assert!(!m.is_exhausted());
    assert_eq!(m.total_consumption().time_ns, 800);
}

// ---------------------------------------------------------------------------
// 30. Monitor saturating addition
// ---------------------------------------------------------------------------

#[test]
fn enrich_monitor_saturating_add_no_overflow() {
    let c = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: u64::MAX,
        global_compute_cap: u64::MAX,
        global_depth_cap: u64::MAX,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mut monitor = BudgetMonitor::new(c);
    monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    monitor.record_consumption(u64::MAX / 2, 0, 0).unwrap();
    monitor.record_consumption(u64::MAX / 2, 0, 0).unwrap();
    let total = monitor.total_consumption();
    assert!(total.time_ns >= u64::MAX / 2);
}
