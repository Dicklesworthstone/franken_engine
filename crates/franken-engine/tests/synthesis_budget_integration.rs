#![forbid(unsafe_code)]

//! Integration tests for `franken_engine::synthesis_budget`.
//!
//! Covers the full public API surface: enums, structs, budget monitor,
//! budget registry, budget history, error types, and serde roundtrips.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
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

fn default_contract() -> SynthesisBudgetContract {
    SynthesisBudgetContract::default()
}

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
        PhaseBudget {
            time_cap_ns: 500,
            compute_cap: 50,
            depth_cap: 5,
        },
    );
    pb.insert(
        SynthesisPhase::Ablation,
        PhaseBudget {
            time_cap_ns: 300,
            compute_cap: 40,
            depth_cap: 8,
        },
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

fn sample_exhaustion_reason() -> ExhaustionReason {
    ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time],
        phase: SynthesisPhase::Ablation,
        global_limit_hit: false,
        consumption: PhaseConsumption {
            time_ns: 2_000,
            compute: 10,
            depth: 1,
        },
        limit_value: 1_000,
    }
}

fn make_history_entry(ext: &str, exhausted: bool, time_ns: u64) -> BudgetHistoryEntry {
    BudgetHistoryEntry {
        extension_id: ext.to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption {
            time_ns,
            compute: 50,
            depth: 5,
        },
        exhausted,
        timestamp_ns: 1_000_000,
        epoch: SecurityEpoch::from_raw(0),
    }
}

// ---------------------------------------------------------------------------
// 1. SynthesisPhase
// ---------------------------------------------------------------------------

#[test]
fn phase_all_has_four_elements_in_order() {
    let all = SynthesisPhase::ALL;
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], SynthesisPhase::StaticAnalysis);
    assert_eq!(all[1], SynthesisPhase::Ablation);
    assert_eq!(all[2], SynthesisPhase::TheoremChecking);
    assert_eq!(all[3], SynthesisPhase::ResultAssembly);
}

#[test]
fn phase_display_each_variant() {
    assert_eq!(
        SynthesisPhase::StaticAnalysis.to_string(),
        "static-analysis"
    );
    assert_eq!(SynthesisPhase::Ablation.to_string(), "ablation");
    assert_eq!(
        SynthesisPhase::TheoremChecking.to_string(),
        "theorem-checking"
    );
    assert_eq!(
        SynthesisPhase::ResultAssembly.to_string(),
        "result-assembly"
    );
}

#[test]
fn phase_serde_roundtrip() {
    for phase in &SynthesisPhase::ALL {
        let json = serde_json::to_string(phase).unwrap();
        let back: SynthesisPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(*phase, back);
    }
}

// ---------------------------------------------------------------------------
// 2. BudgetDimension
// ---------------------------------------------------------------------------

#[test]
fn dimension_display_each_variant() {
    assert_eq!(BudgetDimension::Time.to_string(), "time");
    assert_eq!(BudgetDimension::Compute.to_string(), "compute");
    assert_eq!(BudgetDimension::Depth.to_string(), "depth");
}

#[test]
fn dimension_serde_roundtrip() {
    for dim in &[
        BudgetDimension::Time,
        BudgetDimension::Compute,
        BudgetDimension::Depth,
    ] {
        let json = serde_json::to_string(dim).unwrap();
        let back: BudgetDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

// ---------------------------------------------------------------------------
// 3. PhaseBudget
// ---------------------------------------------------------------------------

#[test]
fn phase_budget_not_exceeded_within_limits() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000,
        compute_cap: 100,
        depth_cap: 10,
    };
    let consumed = PhaseConsumption {
        time_ns: 500,
        compute: 50,
        depth: 5,
    };
    assert!(!budget.is_exceeded(&consumed));
    assert!(budget.exceeded_dimensions(&consumed).is_empty());
}

#[test]
fn phase_budget_time_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000,
        compute_cap: 100,
        depth_cap: 10,
    };
    let consumed = PhaseConsumption {
        time_ns: 1_001,
        compute: 50,
        depth: 5,
    };
    assert!(budget.is_exceeded(&consumed));
    let dims = budget.exceeded_dimensions(&consumed);
    assert_eq!(dims, vec![BudgetDimension::Time]);
}

#[test]
fn phase_budget_multiple_dimensions_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000,
        compute_cap: 100,
        depth_cap: 10,
    };
    let consumed = PhaseConsumption {
        time_ns: 2_000,
        compute: 200,
        depth: 20,
    };
    assert!(budget.is_exceeded(&consumed));
    let dims = budget.exceeded_dimensions(&consumed);
    assert_eq!(dims.len(), 3);
    assert!(dims.contains(&BudgetDimension::Time));
    assert!(dims.contains(&BudgetDimension::Compute));
    assert!(dims.contains(&BudgetDimension::Depth));
}

#[test]
fn phase_budget_serde_roundtrip() {
    let budget = PhaseBudget {
        time_cap_ns: 42,
        compute_cap: 99,
        depth_cap: 7,
    };
    let json = serde_json::to_string(&budget).unwrap();
    let back: PhaseBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

// ---------------------------------------------------------------------------
// 4. PhaseConsumption
// ---------------------------------------------------------------------------

#[test]
fn phase_consumption_zero_all_fields() {
    let z = PhaseConsumption::zero();
    assert_eq!(z.time_ns, 0);
    assert_eq!(z.compute, 0);
    assert_eq!(z.depth, 0);
}

#[test]
fn phase_consumption_serde_roundtrip() {
    let pc = PhaseConsumption {
        time_ns: 123,
        compute: 456,
        depth: 789,
    };
    let json = serde_json::to_string(&pc).unwrap();
    let back: PhaseConsumption = serde_json::from_str(&json).unwrap();
    assert_eq!(pc, back);
}

// ---------------------------------------------------------------------------
// 5. SynthesisBudgetContract
// ---------------------------------------------------------------------------

#[test]
fn contract_default_values() {
    let c = SynthesisBudgetContract::default();
    assert_eq!(c.version, 1);
    assert_eq!(c.global_time_cap_ns, 30_000_000_000);
    assert_eq!(c.global_compute_cap, 100_000);
    assert_eq!(c.global_depth_cap, 1_000);
    assert!(c.phase_budgets.is_empty());
    assert_eq!(c.epoch, SecurityEpoch::from_raw(0));
}

#[test]
fn contract_budget_for_phase_without_override_derives_from_global() {
    let c = default_contract();
    let pb = c.budget_for_phase(SynthesisPhase::Ablation);
    assert_eq!(pb.time_cap_ns, c.global_time_cap_ns);
    assert_eq!(pb.compute_cap, c.global_compute_cap);
    assert_eq!(pb.depth_cap, c.global_depth_cap);
}

#[test]
fn contract_budget_for_phase_with_override_returns_specific() {
    let c = contract_with_phase_budgets();
    let pb = c.budget_for_phase(SynthesisPhase::StaticAnalysis);
    assert_eq!(pb.time_cap_ns, 500);
    assert_eq!(pb.compute_cap, 50);
    assert_eq!(pb.depth_cap, 5);

    // Phase without override still derives from global.
    let pb2 = c.budget_for_phase(SynthesisPhase::ResultAssembly);
    assert_eq!(pb2.time_cap_ns, c.global_time_cap_ns);
}

#[test]
fn contract_is_globally_exceeded_true() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 2_000,
        compute: 10,
        depth: 1,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn contract_is_globally_exceeded_false() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 500,
        compute: 50,
        depth: 5,
    };
    assert!(!c.is_globally_exceeded(&total));
}

#[test]
fn contract_serde_roundtrip() {
    let c = contract_with_phase_budgets();
    let json = serde_json::to_string(&c).unwrap();
    let back: SynthesisBudgetContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// 6. BudgetRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_new_uses_given_default() {
    let c = tight_contract();
    let reg = BudgetRegistry::new(c.clone());
    assert_eq!(*reg.default_contract(), c);
    assert_eq!(reg.override_count(), 0);
}

#[test]
fn registry_default_uses_default_contract() {
    let reg = BudgetRegistry::default();
    assert_eq!(*reg.default_contract(), SynthesisBudgetContract::default());
}

#[test]
fn registry_add_and_effective_contract() {
    let mut reg = BudgetRegistry::new(default_contract());
    let ovr = BudgetOverride {
        extension_id: "ext-a".to_string(),
        contract: tight_contract(),
        justification: "test".to_string(),
    };
    reg.add_override(ovr);
    assert_eq!(reg.override_count(), 1);

    let eff = reg.effective_contract("ext-a");
    assert_eq!(eff.global_time_cap_ns, 1_000);
}

#[test]
fn registry_effective_without_override_returns_default() {
    let reg = BudgetRegistry::new(default_contract());
    let eff = reg.effective_contract("no-such-ext");
    assert_eq!(*eff, default_contract());
}

#[test]
fn registry_remove_override() {
    let mut reg = BudgetRegistry::new(default_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-b".to_string(),
        contract: tight_contract(),
        justification: "test".to_string(),
    });
    assert!(reg.remove_override("ext-b"));
    assert!(!reg.remove_override("ext-b")); // already gone
    assert_eq!(reg.override_count(), 0);
}

// ---------------------------------------------------------------------------
// 7. BudgetMonitor
// ---------------------------------------------------------------------------

#[test]
fn monitor_begin_and_record_within_limits() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(100, 10, 1).unwrap();

    assert!(!mon.is_exhausted());
    assert_eq!(mon.current_phase(), Some(SynthesisPhase::StaticAnalysis));

    let pc = mon
        .phase_consumption(SynthesisPhase::StaticAnalysis)
        .unwrap();
    assert_eq!(pc.time_ns, 100);
    assert_eq!(pc.compute, 10);
    assert_eq!(pc.depth, 1);
}

#[test]
fn monitor_phase_level_time_exhaustion() {
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    // Phase budget for StaticAnalysis: time=500, compute=50, depth=5
    let err = mon.record_consumption(501, 10, 1).unwrap_err();
    assert!(mon.is_exhausted());
    match &err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Time));
            assert!(!reason.global_limit_hit);
            assert_eq!(reason.phase, SynthesisPhase::StaticAnalysis);
            assert_eq!(reason.limit_value, 500);
        }
        other => panic!("expected Exhausted, got: {other:?}"),
    }
}

#[test]
fn monitor_phase_level_compute_exhaustion() {
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    // Phase budget for Ablation: time=300, compute=40, depth=8
    let err = mon.record_consumption(100, 41, 1).unwrap_err();
    assert!(mon.is_exhausted());
    match &err {
        BudgetError::Exhausted(reason) => {
            assert!(
                reason
                    .exceeded_dimensions
                    .contains(&BudgetDimension::Compute)
            );
            assert_eq!(reason.limit_value, 40);
        }
        other => panic!("expected Exhausted, got: {other:?}"),
    }
}

#[test]
fn monitor_phase_level_depth_exhaustion() {
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    // Phase budget for StaticAnalysis: depth_cap=5
    let err = mon.record_consumption(10, 5, 6).unwrap_err();
    assert!(mon.is_exhausted());
    match &err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Depth));
            assert_eq!(reason.limit_value, 5);
        }
        other => panic!("expected Exhausted, got: {other:?}"),
    }
}

#[test]
fn monitor_global_exhaustion_across_phases() {
    // Global: time=1000, compute=100, depth=20
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);

    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(400, 40, 4).unwrap(); // within phase & global

    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(200, 30, 5).unwrap(); // within phase & global

    // Now switch to a phase without specific budget -> uses global (1000, 100, 20)
    mon.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    // Total would become: time=400+200+500=1100 > 1000 global
    let err = mon.record_consumption(500, 10, 1).unwrap_err();
    assert!(mon.is_exhausted());
    match &err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.global_limit_hit);
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Time));
        }
        other => panic!("expected Exhausted, got: {other:?}"),
    }
}

#[test]
fn monitor_begin_phase_after_exhaustion_fails() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let _ = mon.record_consumption(2_000, 10, 1); // exhaust
    assert!(mon.is_exhausted());

    let err = mon.begin_phase(SynthesisPhase::Ablation).unwrap_err();
    assert_eq!(err, BudgetError::AlreadyExhausted);
}

#[test]
fn monitor_record_after_exhaustion_fails() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let _ = mon.record_consumption(2_000, 10, 1);
    assert!(mon.is_exhausted());

    let err = mon.record_consumption(1, 1, 1).unwrap_err();
    assert_eq!(err, BudgetError::AlreadyExhausted);
}

#[test]
fn monitor_no_active_phase_error() {
    let mut mon = BudgetMonitor::new(tight_contract());
    let err = mon.record_consumption(1, 1, 1).unwrap_err();
    assert_eq!(err, BudgetError::NoActivePhase);
}

#[test]
fn monitor_utilization_calculation() {
    // Global: time=1000, compute=100, depth=10
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(500, 50, 5).unwrap(); // 50% each

    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 500_000);
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 500_000);
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 500_000);
}

#[test]
fn monitor_remaining_for_current_phase() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(300, 20, 3).unwrap();

    let rem = mon.remaining_for_current_phase().unwrap();
    assert_eq!(rem.time_ns, 700);
    assert_eq!(rem.compute, 80);
    assert_eq!(rem.depth, 7);
}

#[test]
fn monitor_remaining_global() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(300, 20, 3).unwrap();

    let rem = mon.remaining_global();
    assert_eq!(rem.time_ns, 700);
    assert_eq!(rem.compute, 80);
    assert_eq!(rem.depth, 7);
}

#[test]
fn monitor_multi_phase_pipeline() {
    let mut mon = BudgetMonitor::new(default_contract());

    for phase in &SynthesisPhase::ALL {
        mon.begin_phase(*phase).unwrap();
        mon.record_consumption(100, 10, 1).unwrap();
    }
    assert!(!mon.is_exhausted());
    assert_eq!(mon.total_consumption().time_ns, 400);
    assert_eq!(mon.total_consumption().compute, 40);
    assert_eq!(mon.total_consumption().depth, 4);

    for phase in &SynthesisPhase::ALL {
        let pc = mon.phase_consumption(*phase).unwrap();
        assert_eq!(pc.time_ns, 100);
    }
}

#[test]
fn monitor_exhaustion_reason_accessors() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let _ = mon.record_consumption(2_000, 10, 1);

    assert!(mon.is_exhausted());
    let reason = mon.exhaustion_reason().unwrap();
    assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Time));
    assert_eq!(reason.phase, SynthesisPhase::StaticAnalysis);
}

#[test]
fn monitor_no_exhaustion_reason_when_not_exhausted() {
    let mon = BudgetMonitor::new(tight_contract());
    assert!(mon.exhaustion_reason().is_none());
    assert!(!mon.is_exhausted());
}

#[test]
fn monitor_remaining_none_before_begin_phase() {
    let mon = BudgetMonitor::new(tight_contract());
    assert!(mon.remaining_for_current_phase().is_none());
    assert!(mon.current_phase().is_none());
}

// ---------------------------------------------------------------------------
// 8. BudgetHistory
// ---------------------------------------------------------------------------

#[test]
fn history_record_and_entries() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-b", true, 200));

    assert_eq!(hist.len(), 2);
    assert!(!hist.is_empty());
    assert_eq!(hist.entries()[0].extension_id, "ext-a");
    assert_eq!(hist.entries()[1].extension_id, "ext-b");
}

#[test]
fn history_eviction_when_full() {
    let mut hist = BudgetHistory::new(3);
    for i in 0..5 {
        hist.record(make_history_entry(&format!("ext-{i}"), false, i * 100));
    }
    assert_eq!(hist.len(), 3);
    // Oldest two should have been evicted.
    assert_eq!(hist.entries()[0].extension_id, "ext-2");
    assert_eq!(hist.entries()[1].extension_id, "ext-3");
    assert_eq!(hist.entries()[2].extension_id, "ext-4");
}

#[test]
fn history_entries_for_extension() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-b", true, 200));
    hist.record(make_history_entry("ext-a", true, 300));

    let a_entries = hist.entries_for_extension("ext-a");
    assert_eq!(a_entries.len(), 2);
    assert_eq!(a_entries[0].total_consumption.time_ns, 100);
    assert_eq!(a_entries[1].total_consumption.time_ns, 300);
}

#[test]
fn history_average_utilization() {
    let c = tight_contract(); // global: time=1000, compute=100, depth=10
    let mut hist = BudgetHistory::new(10);

    // Two entries for "ext-a" with time 500 and 300 -> avg 400 -> 400/1000 = 400_000 millionths
    hist.record(make_history_entry("ext-a", false, 500));
    hist.record(make_history_entry("ext-a", false, 300));

    let util = hist.average_utilization("ext-a", &c);
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 400_000);
    // compute: both 50, avg 50/100 = 500_000
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 500_000);
    // depth: both 5, avg 5/10 = 500_000
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 500_000);
}

#[test]
fn history_average_utilization_empty() {
    let hist = BudgetHistory::new(10);
    let c = tight_contract();
    let util = hist.average_utilization("nonexistent", &c);
    assert!(util.is_empty());
}

#[test]
fn history_exhaustion_rate() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", true, 100));
    hist.record(make_history_entry("ext-a", false, 200));
    hist.record(make_history_entry("ext-a", true, 300));
    hist.record(make_history_entry("ext-a", false, 400));

    // 2 out of 4 exhausted => 500_000 millionths
    assert_eq!(hist.exhaustion_rate("ext-a"), 500_000);
}

#[test]
fn history_exhaustion_rate_none_exhausted() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-a", false, 200));
    assert_eq!(hist.exhaustion_rate("ext-a"), 0);
}

#[test]
fn history_exhaustion_rate_all_exhausted() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", true, 100));
    hist.record(make_history_entry("ext-a", true, 200));
    assert_eq!(hist.exhaustion_rate("ext-a"), 1_000_000);
}

#[test]
fn history_exhaustion_rate_empty() {
    let hist = BudgetHistory::new(10);
    assert_eq!(hist.exhaustion_rate("nonexistent"), 0);
}

#[test]
fn history_default_max_entries() {
    let hist = BudgetHistory::default();
    assert!(hist.is_empty());
    assert_eq!(hist.len(), 0);
    // Default should support 1000 entries without eviction.
    // We won't insert 1000 here, just verify it's constructed.
}

// ---------------------------------------------------------------------------
// 9. FallbackQuality
// ---------------------------------------------------------------------------

#[test]
fn fallback_quality_display() {
    assert_eq!(FallbackQuality::StaticBound.to_string(), "static-bound");
    assert_eq!(
        FallbackQuality::PartialAblation.to_string(),
        "partial-ablation"
    );
    assert_eq!(
        FallbackQuality::UnverifiedFull.to_string(),
        "unverified-full"
    );
}

#[test]
fn fallback_quality_serde_roundtrip() {
    for q in &[
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
        FallbackQuality::UnverifiedFull,
    ] {
        let json = serde_json::to_string(q).unwrap();
        let back: FallbackQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(*q, back);
    }
}

// ---------------------------------------------------------------------------
// 10. ExhaustionReason
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_reason_display_format() {
    let r = sample_exhaustion_reason();
    let s = r.to_string();
    assert!(s.contains("ablation"));
    assert!(s.contains("time"));
    assert!(s.contains("global=false"));
}

#[test]
fn exhaustion_reason_display_multiple_dimensions() {
    let r = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Compute, BudgetDimension::Depth],
        phase: SynthesisPhase::TheoremChecking,
        global_limit_hit: true,
        consumption: PhaseConsumption::zero(),
        limit_value: 42,
    };
    let s = r.to_string();
    assert!(s.contains("theorem-checking"));
    assert!(s.contains("compute"));
    assert!(s.contains("depth"));
    assert!(s.contains("global=true"));
}

#[test]
fn exhaustion_reason_serde_roundtrip() {
    let r = sample_exhaustion_reason();
    let json = serde_json::to_string(&r).unwrap();
    let back: ExhaustionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// 11. BudgetError
// ---------------------------------------------------------------------------

#[test]
fn budget_error_display_already_exhausted() {
    let e = BudgetError::AlreadyExhausted;
    assert_eq!(e.to_string(), "budget already exhausted");
}

#[test]
fn budget_error_display_no_active_phase() {
    let e = BudgetError::NoActivePhase;
    assert_eq!(e.to_string(), "no active synthesis phase");
}

#[test]
fn budget_error_display_exhausted_variant() {
    let reason = sample_exhaustion_reason();
    let e = BudgetError::Exhausted(reason.clone());
    assert_eq!(e.to_string(), reason.to_string());
}

#[test]
fn budget_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(BudgetError::NoActivePhase);
    // Verify it can be used as a trait object.
    assert_eq!(e.to_string(), "no active synthesis phase");
}

#[test]
fn budget_error_serde_roundtrip() {
    let variants = vec![
        BudgetError::AlreadyExhausted,
        BudgetError::NoActivePhase,
        BudgetError::Exhausted(sample_exhaustion_reason()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BudgetError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// 12. FallbackResult
// ---------------------------------------------------------------------------

#[test]
fn fallback_result_serde_roundtrip() {
    let fr = FallbackResult {
        quality: FallbackQuality::PartialAblation,
        result_digest: "abc123".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: true,
        recommended_multiplier: Some(2_000_000),
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fr, back);
}

#[test]
fn fallback_result_serde_roundtrip_no_multiplier() {
    let fr = FallbackResult {
        quality: FallbackQuality::StaticBound,
        result_digest: "deadbeef".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: false,
        recommended_multiplier: None,
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fr, back);
    assert!(back.recommended_multiplier.is_none());
}

// ---------------------------------------------------------------------------
// 13. BudgetOverride
// ---------------------------------------------------------------------------

#[test]
fn budget_override_serde_roundtrip() {
    let ovr = BudgetOverride {
        extension_id: "my-ext".to_string(),
        contract: tight_contract(),
        justification: "performance-critical extension".to_string(),
    };
    let json = serde_json::to_string(&ovr).unwrap();
    let back: BudgetOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(ovr, back);
}

// ---------------------------------------------------------------------------
// 14. BudgetHistoryEntry serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn budget_history_entry_serde_roundtrip() {
    let mut pc_map = BTreeMap::new();
    pc_map.insert(
        SynthesisPhase::StaticAnalysis,
        PhaseConsumption {
            time_ns: 100,
            compute: 10,
            depth: 1,
        },
    );
    let entry = BudgetHistoryEntry {
        extension_id: "ext-z".to_string(),
        contract_version: 3,
        phase_consumption: pc_map,
        total_consumption: PhaseConsumption {
            time_ns: 100,
            compute: 10,
            depth: 1,
        },
        exhausted: false,
        timestamp_ns: 999_999,
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BudgetHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Enrichment tests — PearlTower 2026-03-12
// ---------------------------------------------------------------------------

// --- SynthesisPhase enrichment ---

#[test]
fn enrichment_phase_all_length_matches_variant_count() {
    // ALL constant must expose exactly the number of enum variants.
    assert_eq!(SynthesisPhase::ALL.len(), 4);
}

#[test]
fn enrichment_phase_all_has_no_duplicates() {
    let mut seen = std::collections::BTreeSet::new();
    for p in &SynthesisPhase::ALL {
        assert!(seen.insert(p), "duplicate phase in ALL: {p}");
    }
}

#[test]
fn enrichment_phase_debug_contains_variant_name() {
    let dbg = format!("{:?}", SynthesisPhase::StaticAnalysis);
    assert!(dbg.contains("StaticAnalysis"));
    let dbg2 = format!("{:?}", SynthesisPhase::TheoremChecking);
    assert!(dbg2.contains("TheoremChecking"));
}

#[test]
fn enrichment_phase_clone_preserves_identity() {
    for p in &SynthesisPhase::ALL {
        let cloned = *p;
        assert_eq!(*p, cloned);
    }
}

#[test]
fn enrichment_phase_copy_semantics() {
    let a = SynthesisPhase::Ablation;
    let b = a; // copy
    assert_eq!(a, b);
}

#[test]
fn enrichment_phase_ord_all_sorted() {
    let mut sorted = SynthesisPhase::ALL;
    sorted.sort();
    assert_eq!(sorted, SynthesisPhase::ALL);
}

// --- BudgetDimension enrichment ---

#[test]
fn enrichment_dimension_debug_contains_variant_name() {
    assert!(format!("{:?}", BudgetDimension::Time).contains("Time"));
    assert!(format!("{:?}", BudgetDimension::Compute).contains("Compute"));
    assert!(format!("{:?}", BudgetDimension::Depth).contains("Depth"));
}

#[test]
fn enrichment_dimension_clone_copy() {
    let a = BudgetDimension::Compute;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_dimension_ord_stable() {
    let mut dims = vec![
        BudgetDimension::Depth,
        BudgetDimension::Time,
        BudgetDimension::Compute,
    ];
    dims.sort();
    assert_eq!(dims[0], BudgetDimension::Time);
    assert_eq!(dims[1], BudgetDimension::Compute);
    assert_eq!(dims[2], BudgetDimension::Depth);
}

// --- PhaseBudget enrichment ---

#[test]
fn enrichment_phase_budget_zero_caps_never_exceeded() {
    // A budget with zero caps is exceeded by any non-zero consumption.
    let budget = PhaseBudget {
        time_cap_ns: 0,
        compute_cap: 0,
        depth_cap: 0,
    };
    let consumed = PhaseConsumption {
        time_ns: 1,
        compute: 0,
        depth: 0,
    };
    assert!(budget.is_exceeded(&consumed));
}

#[test]
fn enrichment_phase_budget_zero_consumption_never_exceeds() {
    let budget = PhaseBudget {
        time_cap_ns: 0,
        compute_cap: 0,
        depth_cap: 0,
    };
    let consumed = PhaseConsumption::zero();
    assert!(!budget.is_exceeded(&consumed));
}

#[test]
fn enrichment_phase_budget_only_depth_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000_000,
        compute_cap: 1_000_000,
        depth_cap: 5,
    };
    let consumed = PhaseConsumption {
        time_ns: 100,
        compute: 100,
        depth: 6,
    };
    assert!(budget.is_exceeded(&consumed));
    let dims = budget.exceeded_dimensions(&consumed);
    assert_eq!(dims, vec![BudgetDimension::Depth]);
}

#[test]
fn enrichment_phase_budget_only_compute_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000_000,
        compute_cap: 10,
        depth_cap: 1_000,
    };
    let consumed = PhaseConsumption {
        time_ns: 100,
        compute: 11,
        depth: 1,
    };
    let dims = budget.exceeded_dimensions(&consumed);
    assert_eq!(dims, vec![BudgetDimension::Compute]);
}

#[test]
fn enrichment_phase_budget_exceeded_dimensions_order_is_time_compute_depth() {
    let budget = PhaseBudget {
        time_cap_ns: 10,
        compute_cap: 10,
        depth_cap: 10,
    };
    let consumed = PhaseConsumption {
        time_ns: 11,
        compute: 11,
        depth: 11,
    };
    let dims = budget.exceeded_dimensions(&consumed);
    assert_eq!(
        dims,
        vec![
            BudgetDimension::Time,
            BudgetDimension::Compute,
            BudgetDimension::Depth,
        ]
    );
}

#[test]
fn enrichment_phase_budget_large_values() {
    let budget = PhaseBudget {
        time_cap_ns: u64::MAX,
        compute_cap: u64::MAX,
        depth_cap: u64::MAX,
    };
    let consumed = PhaseConsumption {
        time_ns: u64::MAX,
        compute: u64::MAX,
        depth: u64::MAX,
    };
    // At exact boundary -> not exceeded.
    assert!(!budget.is_exceeded(&consumed));
}

#[test]
fn enrichment_phase_budget_debug_format() {
    let budget = PhaseBudget {
        time_cap_ns: 42,
        compute_cap: 99,
        depth_cap: 7,
    };
    let dbg = format!("{budget:?}");
    assert!(dbg.contains("42"));
    assert!(dbg.contains("99"));
    assert!(dbg.contains("7"));
}

// --- PhaseConsumption enrichment ---

#[test]
fn enrichment_phase_consumption_debug_format() {
    let pc = PhaseConsumption {
        time_ns: 111,
        compute: 222,
        depth: 333,
    };
    let dbg = format!("{pc:?}");
    assert!(dbg.contains("111"));
    assert!(dbg.contains("222"));
    assert!(dbg.contains("333"));
}

#[test]
fn enrichment_phase_consumption_equality_reflexive() {
    let pc = PhaseConsumption {
        time_ns: 50,
        compute: 60,
        depth: 70,
    };
    assert_eq!(pc, pc.clone());
}

#[test]
fn enrichment_phase_consumption_inequality() {
    let a = PhaseConsumption {
        time_ns: 50,
        compute: 60,
        depth: 70,
    };
    let b = PhaseConsumption {
        time_ns: 51,
        compute: 60,
        depth: 70,
    };
    assert_ne!(a, b);
}

// --- SynthesisBudgetContract enrichment ---

#[test]
fn enrichment_contract_budget_for_all_phases_without_overrides() {
    let c = default_contract();
    for phase in &SynthesisPhase::ALL {
        let pb = c.budget_for_phase(*phase);
        assert_eq!(pb.time_cap_ns, c.global_time_cap_ns);
        assert_eq!(pb.compute_cap, c.global_compute_cap);
        assert_eq!(pb.depth_cap, c.global_depth_cap);
    }
}

#[test]
fn enrichment_contract_global_not_exceeded_at_exact_boundary() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: c.global_time_cap_ns,
        compute: c.global_compute_cap,
        depth: c.global_depth_cap,
    };
    assert!(!c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_global_exceeded_by_one_time() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: c.global_time_cap_ns + 1,
        compute: 0,
        depth: 0,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_global_exceeded_by_one_compute() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 0,
        compute: c.global_compute_cap + 1,
        depth: 0,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_global_exceeded_by_one_depth() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 0,
        compute: 0,
        depth: c.global_depth_cap + 1,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_zero_consumption_not_exceeded() {
    let c = tight_contract();
    let total = PhaseConsumption::zero();
    assert!(!c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_phase_budgets_btree_ordering() {
    let c = contract_with_phase_budgets();
    let keys: Vec<_> = c.phase_budgets.keys().collect();
    // BTreeMap should be sorted.
    for i in 1..keys.len() {
        assert!(keys[i - 1] < keys[i]);
    }
}

#[test]
fn enrichment_contract_default_epoch_is_zero() {
    let c = default_contract();
    assert_eq!(c.epoch, SecurityEpoch::from_raw(0));
}

#[test]
fn enrichment_contract_custom_epoch_preserved() {
    let c = SynthesisBudgetContract {
        epoch: SecurityEpoch::from_raw(42),
        ..Default::default()
    };
    assert_eq!(c.epoch.as_u64(), 42);
}

#[test]
fn enrichment_contract_serialization_deterministic() {
    let c1 = contract_with_phase_budgets();
    let c2 = contract_with_phase_budgets();
    let json1 = serde_json::to_string(&c1).unwrap();
    let json2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_contract_debug_format() {
    let c = tight_contract();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("SynthesisBudgetContract"));
}

// --- BudgetRegistry enrichment ---

#[test]
fn enrichment_registry_multiple_overrides() {
    let mut reg = BudgetRegistry::new(default_contract());
    for i in 0..5 {
        reg.add_override(BudgetOverride {
            extension_id: format!("ext-{i}"),
            contract: SynthesisBudgetContract {
                global_time_cap_ns: (i + 1) as u64 * 1_000,
                ..Default::default()
            },
            justification: format!("reason-{i}"),
        });
    }
    assert_eq!(reg.override_count(), 5);
    for i in 0..5 {
        let eff = reg.effective_contract(&format!("ext-{i}"));
        assert_eq!(eff.global_time_cap_ns, (i + 1) as u64 * 1_000);
    }
}

#[test]
fn enrichment_registry_override_replacement() {
    let mut reg = BudgetRegistry::new(default_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-a".to_string(),
        contract: SynthesisBudgetContract {
            global_time_cap_ns: 1_000,
            ..Default::default()
        },
        justification: "first".to_string(),
    });
    // Replace with different contract.
    reg.add_override(BudgetOverride {
        extension_id: "ext-a".to_string(),
        contract: SynthesisBudgetContract {
            global_time_cap_ns: 2_000,
            ..Default::default()
        },
        justification: "second".to_string(),
    });
    assert_eq!(reg.override_count(), 1);
    assert_eq!(
        reg.effective_contract("ext-a").global_time_cap_ns,
        2_000
    );
}

#[test]
fn enrichment_registry_remove_nonexistent_returns_false() {
    let mut reg = BudgetRegistry::new(default_contract());
    assert!(!reg.remove_override("does-not-exist"));
}

#[test]
fn enrichment_registry_serde_roundtrip_with_overrides() {
    let mut reg = BudgetRegistry::new(tight_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-x".to_string(),
        contract: contract_with_phase_budgets(),
        justification: "roundtrip-test".to_string(),
    });
    let json = serde_json::to_string(&reg).unwrap();
    let back: BudgetRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.override_count(), 1);
    assert_eq!(
        back.effective_contract("ext-x").global_time_cap_ns,
        1_000
    );
}

#[test]
fn enrichment_registry_default_contract_accessor() {
    let custom = tight_contract();
    let reg = BudgetRegistry::new(custom.clone());
    assert_eq!(*reg.default_contract(), custom);
}

// --- BudgetMonitor enrichment ---

#[test]
fn enrichment_monitor_fresh_is_not_exhausted() {
    let mon = BudgetMonitor::new(tight_contract());
    assert!(!mon.is_exhausted());
    assert!(mon.exhaustion_reason().is_none());
    assert!(mon.current_phase().is_none());
}

#[test]
fn enrichment_monitor_total_consumption_starts_at_zero() {
    let mon = BudgetMonitor::new(default_contract());
    let tc = mon.total_consumption();
    assert_eq!(tc.time_ns, 0);
    assert_eq!(tc.compute, 0);
    assert_eq!(tc.depth, 0);
}

#[test]
fn enrichment_monitor_phase_consumption_none_before_begin() {
    let mon = BudgetMonitor::new(default_contract());
    assert!(mon.phase_consumption(SynthesisPhase::Ablation).is_none());
}

#[test]
fn enrichment_monitor_begin_phase_sets_zero_consumption() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    let pc = mon.phase_consumption(SynthesisPhase::Ablation).unwrap();
    assert_eq!(pc.time_ns, 0);
    assert_eq!(pc.compute, 0);
    assert_eq!(pc.depth, 0);
}

#[test]
fn enrichment_monitor_accumulates_within_phase() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    for _ in 0..10 {
        mon.record_consumption(10, 5, 1).unwrap();
    }
    let pc = mon
        .phase_consumption(SynthesisPhase::StaticAnalysis)
        .unwrap();
    assert_eq!(pc.time_ns, 100);
    assert_eq!(pc.compute, 50);
    assert_eq!(pc.depth, 10);
}

#[test]
fn enrichment_monitor_resuming_same_phase_accumulates() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(100, 10, 1).unwrap();

    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(200, 20, 2).unwrap();

    // Re-enter StaticAnalysis -- consumption should accumulate.
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(50, 5, 1).unwrap();

    let pc = mon
        .phase_consumption(SynthesisPhase::StaticAnalysis)
        .unwrap();
    assert_eq!(pc.time_ns, 150);
    assert_eq!(pc.compute, 15);
    assert_eq!(pc.depth, 2);
}

#[test]
fn enrichment_monitor_global_exceeds_before_phase_specific() {
    // Phase budget is generous, global is tight.
    let mut pb = BTreeMap::new();
    pb.insert(
        SynthesisPhase::StaticAnalysis,
        PhaseBudget {
            time_cap_ns: 100_000,
            compute_cap: 100_000,
            depth_cap: 100_000,
        },
    );
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 100,
        global_compute_cap: 100_000,
        global_depth_cap: 100_000,
        phase_budgets: pb,
        epoch: SecurityEpoch::from_raw(1),
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let err = mon.record_consumption(101, 1, 1).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.global_limit_hit);
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Time));
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_phase_budget_stricter_than_global() {
    // Phase budget is tight, global is generous.
    let mut pb = BTreeMap::new();
    pb.insert(
        SynthesisPhase::Ablation,
        PhaseBudget {
            time_cap_ns: 50,
            compute_cap: 100_000,
            depth_cap: 100_000,
        },
    );
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000_000,
        global_compute_cap: 1_000_000,
        global_depth_cap: 1_000_000,
        phase_budgets: pb,
        epoch: SecurityEpoch::from_raw(1),
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    let err = mon.record_consumption(51, 1, 1).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(!reason.global_limit_hit);
            assert_eq!(reason.phase, SynthesisPhase::Ablation);
            assert_eq!(reason.limit_value, 50);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_remaining_global_saturates_at_zero() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(999, 99, 9).unwrap();

    let rem = mon.remaining_global();
    assert_eq!(rem.time_ns, 1);
    assert_eq!(rem.compute, 1);
    assert_eq!(rem.depth, 1);
}

#[test]
fn enrichment_monitor_utilization_zero_consumption() {
    let mon = BudgetMonitor::new(tight_contract());
    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 0);
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 0);
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 0);
}

#[test]
fn enrichment_monitor_utilization_full() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(1_000, 100, 10).unwrap();

    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 1_000_000);
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 1_000_000);
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 1_000_000);
}

#[test]
fn enrichment_monitor_utilization_quarter() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(250, 25, 2).unwrap();

    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 250_000);
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 250_000);
    // 2/10 = 200_000
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 200_000);
}

#[test]
fn enrichment_monitor_serde_roundtrip_preserves_state() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(300, 30, 3).unwrap();

    let json = serde_json::to_string(&mon).unwrap();
    let back: BudgetMonitor = serde_json::from_str(&json).unwrap();

    assert_eq!(back.total_consumption().time_ns, 300);
    assert_eq!(back.total_consumption().compute, 30);
    assert_eq!(back.total_consumption().depth, 3);
    assert_eq!(back.current_phase(), Some(SynthesisPhase::StaticAnalysis));
    assert!(!back.is_exhausted());
}

#[test]
fn enrichment_monitor_serde_roundtrip_exhausted_state() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let _ = mon.record_consumption(2_000, 0, 0);
    assert!(mon.is_exhausted());

    let json = serde_json::to_string(&mon).unwrap();
    let back: BudgetMonitor = serde_json::from_str(&json).unwrap();
    assert!(back.is_exhausted());
    assert!(back.exhaustion_reason().is_some());
}

#[test]
fn enrichment_monitor_saturating_add_compute() {
    let contract = SynthesisBudgetContract {
        global_time_cap_ns: u64::MAX,
        global_compute_cap: u64::MAX,
        global_depth_cap: u64::MAX,
        ..Default::default()
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(0, u64::MAX - 1, 0).unwrap();
    mon.record_consumption(0, 10, 0).unwrap();
    assert_eq!(mon.total_consumption().compute, u64::MAX);
}

#[test]
fn enrichment_monitor_saturating_add_depth() {
    let contract = SynthesisBudgetContract {
        global_time_cap_ns: u64::MAX,
        global_compute_cap: u64::MAX,
        global_depth_cap: u64::MAX,
        ..Default::default()
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(0, 0, u64::MAX - 1).unwrap();
    mon.record_consumption(0, 0, 10).unwrap();
    assert_eq!(mon.total_consumption().depth, u64::MAX);
}

// --- BudgetHistory enrichment ---

#[test]
fn enrichment_history_capacity_one() {
    let mut hist = BudgetHistory::new(1);
    hist.record(make_history_entry("a", false, 100));
    hist.record(make_history_entry("b", false, 200));
    assert_eq!(hist.len(), 1);
    assert_eq!(hist.entries()[0].extension_id, "b");
}

#[test]
fn enrichment_history_entries_for_nonexistent_extension() {
    let hist = BudgetHistory::new(10);
    let entries = hist.entries_for_extension("does-not-exist");
    assert!(entries.is_empty());
}

#[test]
fn enrichment_history_multiple_extensions_isolated() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-b", true, 200));
    hist.record(make_history_entry("ext-a", true, 300));
    hist.record(make_history_entry("ext-c", false, 400));

    assert_eq!(hist.entries_for_extension("ext-a").len(), 2);
    assert_eq!(hist.entries_for_extension("ext-b").len(), 1);
    assert_eq!(hist.entries_for_extension("ext-c").len(), 1);
    assert_eq!(hist.entries_for_extension("ext-d").len(), 0);
}

#[test]
fn enrichment_history_exhaustion_rate_one_third() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", true, 100));
    hist.record(make_history_entry("ext-a", false, 200));
    hist.record(make_history_entry("ext-a", false, 300));
    // 1 out of 3 = 333_333 millionths
    assert_eq!(hist.exhaustion_rate("ext-a"), 333_333);
}

#[test]
fn enrichment_history_average_utilization_single_entry() {
    let c = tight_contract(); // time=1000, compute=100, depth=10
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 250)); // compute=50, depth=5

    let util = hist.average_utilization("ext-a", &c);
    // time: 250/1000 = 250_000
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 250_000);
    // compute: 50/100 = 500_000
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 500_000);
    // depth: 5/10 = 500_000
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 500_000);
}

#[test]
fn enrichment_history_average_utilization_ignores_other_extensions() {
    let c = tight_contract();
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 500));
    hist.record(make_history_entry("ext-b", false, 900)); // should not affect ext-a

    let util = hist.average_utilization("ext-a", &c);
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 500_000);
}

#[test]
fn enrichment_history_default_is_empty() {
    let hist = BudgetHistory::default();
    assert!(hist.is_empty());
    assert_eq!(hist.len(), 0);
}

#[test]
fn enrichment_history_serde_roundtrip_with_entries() {
    let mut hist = BudgetHistory::new(5);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-b", true, 200));

    let json = serde_json::to_string(&hist).unwrap();
    let back: BudgetHistory = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back.entries()[0].extension_id, "ext-a");
    assert_eq!(back.entries()[1].extension_id, "ext-b");
}

#[test]
fn enrichment_history_eviction_preserves_newest() {
    let mut hist = BudgetHistory::new(2);
    for i in 0..10 {
        hist.record(make_history_entry(&format!("ext-{i}"), false, i * 100));
    }
    assert_eq!(hist.len(), 2);
    assert_eq!(hist.entries()[0].extension_id, "ext-8");
    assert_eq!(hist.entries()[1].extension_id, "ext-9");
}

// --- ExhaustionReason enrichment ---

#[test]
fn enrichment_exhaustion_reason_display_no_dimensions() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![],
        phase: SynthesisPhase::ResultAssembly,
        global_limit_hit: false,
        consumption: PhaseConsumption::zero(),
        limit_value: 0,
    };
    let s = reason.to_string();
    assert!(s.contains("result-assembly"));
    assert!(s.contains("global=false"));
}

#[test]
fn enrichment_exhaustion_reason_serde_all_phases() {
    for phase in &SynthesisPhase::ALL {
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time],
            phase: *phase,
            global_limit_hit: false,
            consumption: PhaseConsumption::zero(),
            limit_value: 100,
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: ExhaustionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }
}

#[test]
fn enrichment_exhaustion_reason_debug_format() {
    let reason = sample_exhaustion_reason();
    let dbg = format!("{reason:?}");
    assert!(dbg.contains("ExhaustionReason"));
    assert!(dbg.contains("Time"));
}

// --- FallbackQuality enrichment ---

#[test]
fn enrichment_fallback_quality_copy_semantics() {
    let a = FallbackQuality::PartialAblation;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_fallback_quality_debug_format() {
    let dbg = format!("{:?}", FallbackQuality::StaticBound);
    assert!(dbg.contains("StaticBound"));
}

#[test]
fn enrichment_fallback_quality_hash_consistency() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(FallbackQuality::StaticBound);
    set.insert(FallbackQuality::PartialAblation);
    set.insert(FallbackQuality::UnverifiedFull);
    set.insert(FallbackQuality::StaticBound); // duplicate
    assert_eq!(set.len(), 3);
}

// --- FallbackResult enrichment ---

#[test]
fn enrichment_fallback_result_with_all_qualities() {
    for quality in &[
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
        FallbackQuality::UnverifiedFull,
    ] {
        let fr = FallbackResult {
            quality: *quality,
            result_digest: format!("digest-{quality}"),
            exhaustion_reason: sample_exhaustion_reason(),
            increase_likely_helpful: false,
            recommended_multiplier: None,
        };
        let json = serde_json::to_string(&fr).unwrap();
        let back: FallbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(fr, back);
    }
}

#[test]
fn enrichment_fallback_result_multiplier_values() {
    let multipliers = vec![
        Some(1_000_000),  // 1x
        Some(2_000_000),  // 2x
        Some(10_000_000), // 10x
        None,
    ];
    for mult in &multipliers {
        let fr = FallbackResult {
            quality: FallbackQuality::StaticBound,
            result_digest: "test".to_string(),
            exhaustion_reason: sample_exhaustion_reason(),
            increase_likely_helpful: mult.is_some(),
            recommended_multiplier: *mult,
        };
        let json = serde_json::to_string(&fr).unwrap();
        let back: FallbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.recommended_multiplier, *mult);
    }
}

#[test]
fn enrichment_fallback_result_debug_format() {
    let fr = FallbackResult {
        quality: FallbackQuality::UnverifiedFull,
        result_digest: "abc".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: true,
        recommended_multiplier: Some(5_000_000),
    };
    let dbg = format!("{fr:?}");
    assert!(dbg.contains("UnverifiedFull"));
    assert!(dbg.contains("abc"));
}

// --- BudgetOverride enrichment ---

#[test]
fn enrichment_budget_override_debug_format() {
    let ovr = BudgetOverride {
        extension_id: "ext-debug".to_string(),
        contract: tight_contract(),
        justification: "debugging".to_string(),
    };
    let dbg = format!("{ovr:?}");
    assert!(dbg.contains("ext-debug"));
    assert!(dbg.contains("debugging"));
}

#[test]
fn enrichment_budget_override_clone_equality() {
    let ovr = BudgetOverride {
        extension_id: "ext-clone".to_string(),
        contract: tight_contract(),
        justification: "clone-test".to_string(),
    };
    let cloned = ovr.clone();
    assert_eq!(ovr, cloned);
}

// --- BudgetError enrichment ---

#[test]
fn enrichment_budget_error_clone_equality() {
    let err = BudgetError::Exhausted(sample_exhaustion_reason());
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_budget_error_debug_format() {
    let err = BudgetError::AlreadyExhausted;
    let dbg = format!("{err:?}");
    assert!(dbg.contains("AlreadyExhausted"));
}

#[test]
fn enrichment_budget_error_display_exhausted_includes_phase() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Compute],
        phase: SynthesisPhase::TheoremChecking,
        global_limit_hit: false,
        consumption: PhaseConsumption::zero(),
        limit_value: 100,
    };
    let err = BudgetError::Exhausted(reason);
    let s = err.to_string();
    assert!(s.contains("theorem-checking"));
    assert!(s.contains("compute"));
}

#[test]
fn enrichment_budget_error_source_is_none() {
    use std::error::Error;
    let errs = vec![
        BudgetError::AlreadyExhausted,
        BudgetError::NoActivePhase,
        BudgetError::Exhausted(sample_exhaustion_reason()),
    ];
    for e in &errs {
        assert!(e.source().is_none());
    }
}

// --- BudgetHistoryEntry enrichment ---

#[test]
fn enrichment_history_entry_with_all_phases() {
    let mut pc_map = BTreeMap::new();
    for phase in &SynthesisPhase::ALL {
        pc_map.insert(
            *phase,
            PhaseConsumption {
                time_ns: 100,
                compute: 10,
                depth: 1,
            },
        );
    }
    let entry = BudgetHistoryEntry {
        extension_id: "ext-full".to_string(),
        contract_version: 1,
        phase_consumption: pc_map.clone(),
        total_consumption: PhaseConsumption {
            time_ns: 400,
            compute: 40,
            depth: 4,
        },
        exhausted: false,
        timestamp_ns: 999_999,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BudgetHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert_eq!(back.phase_consumption.len(), 4);
}

#[test]
fn enrichment_history_entry_debug_format() {
    let entry = make_history_entry("ext-debug", false, 42);
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("ext-debug"));
    assert!(dbg.contains("42"));
}

// --- Integration: multi-phase pipeline edge cases ---

#[test]
fn enrichment_full_pipeline_exact_budget_boundary() {
    // Consume exactly the full global budget across phases.
    let c = tight_contract(); // time=1000, compute=100, depth=10
    let mut mon = BudgetMonitor::new(c);

    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(250, 25, 2).unwrap();

    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(250, 25, 3).unwrap();

    mon.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    mon.record_consumption(250, 25, 2).unwrap();

    mon.begin_phase(SynthesisPhase::ResultAssembly).unwrap();
    mon.record_consumption(250, 25, 3).unwrap();

    // Exactly at global limits -- not exhausted.
    assert!(!mon.is_exhausted());
    assert_eq!(mon.total_consumption().time_ns, 1_000);
    assert_eq!(mon.total_consumption().compute, 100);
    assert_eq!(mon.total_consumption().depth, 10);

    let rem = mon.remaining_global();
    assert_eq!(rem.time_ns, 0);
    assert_eq!(rem.compute, 0);
    assert_eq!(rem.depth, 0);
}

#[test]
fn enrichment_single_record_exceeds_all_three_dimensions() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let err = mon.record_consumption(2_000, 200, 20).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert_eq!(reason.exceeded_dimensions.len(), 3);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_remaining_phase_after_switching() {
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);

    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(200, 20, 2).unwrap();

    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(100, 10, 3).unwrap();

    // Remaining is relative to current phase (Ablation: time=300, compute=40, depth=8).
    let rem = mon.remaining_for_current_phase().unwrap();
    assert_eq!(rem.time_ns, 200);
    assert_eq!(rem.compute, 30);
    assert_eq!(rem.depth, 5);
}

#[test]
fn enrichment_monitor_zero_consumption_record() {
    let mut mon = BudgetMonitor::new(tight_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    // Recording zero should succeed.
    mon.record_consumption(0, 0, 0).unwrap();
    assert_eq!(mon.total_consumption().time_ns, 0);
    assert!(!mon.is_exhausted());
}

#[test]
fn enrichment_monitor_many_small_records() {
    let mut mon = BudgetMonitor::new(tight_contract()); // time=1000
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    for _ in 0..100 {
        mon.record_consumption(10, 1, 0).unwrap();
    }
    assert_eq!(mon.total_consumption().time_ns, 1_000);
    assert!(!mon.is_exhausted());
}

#[test]
fn enrichment_monitor_exhaustion_reason_limit_value_matches_first_dim() {
    let c = contract_with_phase_budgets();
    // Ablation budget: time=300, compute=40, depth=8
    let mut mon = BudgetMonitor::new(c);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    // Exceed compute (41 > 40) and depth (9 > 8), time OK (100 < 300).
    let err = mon.record_consumption(100, 41, 9).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            // First exceeded dimension is Compute -> limit_value should be 40.
            assert_eq!(reason.exceeded_dimensions[0], BudgetDimension::Compute);
            assert_eq!(reason.limit_value, 40);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

// --- Cross-cutting: determinism and serialization ---

#[test]
fn enrichment_registry_serialization_deterministic() {
    let build = || {
        let mut reg = BudgetRegistry::new(tight_contract());
        for i in 0..3 {
            reg.add_override(BudgetOverride {
                extension_id: format!("ext-{i}"),
                contract: default_contract(),
                justification: format!("j-{i}"),
            });
        }
        reg
    };
    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_history_serialization_deterministic() {
    let build = || {
        let mut hist = BudgetHistory::new(10);
        hist.record(make_history_entry("ext-a", false, 100));
        hist.record(make_history_entry("ext-b", true, 200));
        hist
    };
    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_monitor_serialization_deterministic() {
    let build = || {
        let mut mon = BudgetMonitor::new(tight_contract());
        mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        mon.record_consumption(100, 10, 1).unwrap();
        mon.begin_phase(SynthesisPhase::Ablation).unwrap();
        mon.record_consumption(200, 20, 2).unwrap();
        mon
    };
    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_fallback_result_serialization_deterministic() {
    let build = || FallbackResult {
        quality: FallbackQuality::PartialAblation,
        result_digest: "fixed-digest".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: true,
        recommended_multiplier: Some(3_000_000),
    };
    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_exhaustion_reason_consumption_preserved_in_serde() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Compute],
        phase: SynthesisPhase::Ablation,
        global_limit_hit: true,
        consumption: PhaseConsumption {
            time_ns: 12345,
            compute: 6789,
            depth: 42,
        },
        limit_value: 10_000,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: ExhaustionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back.consumption.time_ns, 12345);
    assert_eq!(back.consumption.compute, 6789);
    assert_eq!(back.consumption.depth, 42);
    assert_eq!(back.limit_value, 10_000);
}

#[test]
fn enrichment_history_entry_phase_consumption_map_roundtrip() {
    let mut pc_map = BTreeMap::new();
    pc_map.insert(
        SynthesisPhase::StaticAnalysis,
        PhaseConsumption {
            time_ns: 100,
            compute: 10,
            depth: 1,
        },
    );
    pc_map.insert(
        SynthesisPhase::Ablation,
        PhaseConsumption {
            time_ns: 200,
            compute: 20,
            depth: 2,
        },
    );
    pc_map.insert(
        SynthesisPhase::TheoremChecking,
        PhaseConsumption {
            time_ns: 300,
            compute: 30,
            depth: 3,
        },
    );
    pc_map.insert(
        SynthesisPhase::ResultAssembly,
        PhaseConsumption {
            time_ns: 400,
            compute: 40,
            depth: 4,
        },
    );
    let entry = BudgetHistoryEntry {
        extension_id: "ext-full-map".to_string(),
        contract_version: 2,
        phase_consumption: pc_map,
        total_consumption: PhaseConsumption {
            time_ns: 1000,
            compute: 100,
            depth: 10,
        },
        exhausted: false,
        timestamp_ns: 42_000,
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BudgetHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.phase_consumption.len(), 4);
    assert_eq!(
        back.phase_consumption
            .get(&SynthesisPhase::TheoremChecking)
            .unwrap()
            .time_ns,
        300
    );
}
