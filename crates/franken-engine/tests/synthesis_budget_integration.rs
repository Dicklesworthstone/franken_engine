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
    assert_eq!(reg.effective_contract("ext-a").global_time_cap_ns, 2_000);
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
    assert_eq!(back.effective_contract("ext-x").global_time_cap_ns, 1_000);
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

// ---------------------------------------------------------------------------
// Enrichment tests — PearlTower 2026-03-13 batch
// ---------------------------------------------------------------------------

// --- SynthesisPhase deeper property tests ---

#[test]
fn enrichment_phase_partial_eq_reflexive_all_variants() {
    for phase in &SynthesisPhase::ALL {
        assert_eq!(*phase, *phase);
    }
}

#[test]
fn enrichment_phase_ne_across_variants() {
    let phases = SynthesisPhase::ALL;
    for i in 0..phases.len() {
        for j in (i + 1)..phases.len() {
            assert_ne!(phases[i], phases[j]);
        }
    }
}

#[test]
fn enrichment_phase_display_no_empty_strings() {
    for phase in &SynthesisPhase::ALL {
        let disp = phase.to_string();
        assert!(!disp.is_empty());
        assert!(disp.len() > 3);
    }
}

#[test]
fn enrichment_phase_serde_json_strings_are_quoted() {
    for phase in &SynthesisPhase::ALL {
        let json = serde_json::to_string(phase).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }
}

#[test]
fn enrichment_phase_hash_in_btreeset_preserves_all() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for phase in &SynthesisPhase::ALL {
        set.insert(*phase);
    }
    assert_eq!(set.len(), 4);
}

// --- BudgetDimension deeper property tests ---

#[test]
fn enrichment_dimension_ne_across_variants() {
    assert_ne!(BudgetDimension::Time, BudgetDimension::Compute);
    assert_ne!(BudgetDimension::Compute, BudgetDimension::Depth);
    assert_ne!(BudgetDimension::Time, BudgetDimension::Depth);
}

#[test]
fn enrichment_dimension_serde_json_strings_are_quoted() {
    for dim in &[
        BudgetDimension::Time,
        BudgetDimension::Compute,
        BudgetDimension::Depth,
    ] {
        let json = serde_json::to_string(dim).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }
}

#[test]
fn enrichment_dimension_display_distinct_strings() {
    let time_s = BudgetDimension::Time.to_string();
    let compute_s = BudgetDimension::Compute.to_string();
    let depth_s = BudgetDimension::Depth.to_string();
    assert_ne!(time_s, compute_s);
    assert_ne!(compute_s, depth_s);
    assert_ne!(time_s, depth_s);
}

#[test]
fn enrichment_dimension_in_btreemap_key() {
    let mut map = BTreeMap::new();
    map.insert(BudgetDimension::Time, 1);
    map.insert(BudgetDimension::Compute, 2);
    map.insert(BudgetDimension::Depth, 3);
    assert_eq!(map.len(), 3);
    assert_eq!(*map.get(&BudgetDimension::Compute).unwrap(), 2);
}

// --- PhaseBudget boundary tests ---

#[test]
fn enrichment_phase_budget_exact_boundary_not_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: 1_000,
        compute_cap: 100,
        depth_cap: 10,
    };
    let consumed = PhaseConsumption {
        time_ns: 1_000,
        compute: 100,
        depth: 10,
    };
    assert!(!budget.is_exceeded(&consumed));
    assert!(budget.exceeded_dimensions(&consumed).is_empty());
}

#[test]
fn enrichment_phase_budget_one_over_each_dimension_individually() {
    let budget = PhaseBudget {
        time_cap_ns: 100,
        compute_cap: 200,
        depth_cap: 300,
    };
    // Time+1 only
    let c1 = PhaseConsumption {
        time_ns: 101,
        compute: 0,
        depth: 0,
    };
    assert_eq!(budget.exceeded_dimensions(&c1), vec![BudgetDimension::Time]);
    // Compute+1 only
    let c2 = PhaseConsumption {
        time_ns: 0,
        compute: 201,
        depth: 0,
    };
    assert_eq!(
        budget.exceeded_dimensions(&c2),
        vec![BudgetDimension::Compute]
    );
    // Depth+1 only
    let c3 = PhaseConsumption {
        time_ns: 0,
        compute: 0,
        depth: 301,
    };
    assert_eq!(
        budget.exceeded_dimensions(&c3),
        vec![BudgetDimension::Depth]
    );
}

#[test]
fn enrichment_phase_budget_clone_equals_original() {
    let budget = PhaseBudget {
        time_cap_ns: 500,
        compute_cap: 250,
        depth_cap: 42,
    };
    let cloned = budget.clone();
    assert_eq!(budget, cloned);
}

#[test]
fn enrichment_phase_budget_u64_max_minus_one_not_exceeded() {
    let budget = PhaseBudget {
        time_cap_ns: u64::MAX,
        compute_cap: u64::MAX,
        depth_cap: u64::MAX,
    };
    let consumed = PhaseConsumption {
        time_ns: u64::MAX - 1,
        compute: u64::MAX - 1,
        depth: u64::MAX - 1,
    };
    assert!(!budget.is_exceeded(&consumed));
}

// --- PhaseConsumption property tests ---

#[test]
fn enrichment_phase_consumption_zero_equals_self() {
    let a = PhaseConsumption::zero();
    let b = PhaseConsumption::zero();
    assert_eq!(a, b);
}

#[test]
fn enrichment_phase_consumption_clone_deep() {
    let pc = PhaseConsumption {
        time_ns: 1_000_000,
        compute: 999,
        depth: 77,
    };
    let cloned = pc.clone();
    assert_eq!(pc.time_ns, cloned.time_ns);
    assert_eq!(pc.compute, cloned.compute);
    assert_eq!(pc.depth, cloned.depth);
}

#[test]
fn enrichment_phase_consumption_large_values_serde() {
    let pc = PhaseConsumption {
        time_ns: u64::MAX,
        compute: u64::MAX,
        depth: u64::MAX,
    };
    let json = serde_json::to_string(&pc).unwrap();
    let back: PhaseConsumption = serde_json::from_str(&json).unwrap();
    assert_eq!(pc, back);
}

// --- SynthesisBudgetContract deeper tests ---

#[test]
fn enrichment_contract_version_default_is_one() {
    let c = default_contract();
    assert_eq!(c.version, 1);
}

#[test]
fn enrichment_contract_budget_for_all_four_phases_with_partial_overrides() {
    let c = contract_with_phase_budgets();
    // StaticAnalysis has override
    let sa = c.budget_for_phase(SynthesisPhase::StaticAnalysis);
    assert_eq!(sa.time_cap_ns, 500);
    // Ablation has override
    let ab = c.budget_for_phase(SynthesisPhase::Ablation);
    assert_eq!(ab.time_cap_ns, 300);
    // TheoremChecking inherits global
    let tc = c.budget_for_phase(SynthesisPhase::TheoremChecking);
    assert_eq!(tc.time_cap_ns, c.global_time_cap_ns);
    // ResultAssembly inherits global
    let ra = c.budget_for_phase(SynthesisPhase::ResultAssembly);
    assert_eq!(ra.time_cap_ns, c.global_time_cap_ns);
}

#[test]
fn enrichment_contract_globally_exceeded_compute_only() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 0,
        compute: c.global_compute_cap + 1,
        depth: 0,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_globally_exceeded_depth_only() {
    let c = tight_contract();
    let total = PhaseConsumption {
        time_ns: 0,
        compute: 0,
        depth: c.global_depth_cap + 1,
    };
    assert!(c.is_globally_exceeded(&total));
}

#[test]
fn enrichment_contract_clone_preserves_all_fields() {
    let c = contract_with_phase_budgets();
    let cloned = c.clone();
    assert_eq!(c.version, cloned.version);
    assert_eq!(c.global_time_cap_ns, cloned.global_time_cap_ns);
    assert_eq!(c.global_compute_cap, cloned.global_compute_cap);
    assert_eq!(c.global_depth_cap, cloned.global_depth_cap);
    assert_eq!(c.phase_budgets.len(), cloned.phase_budgets.len());
    assert_eq!(c.epoch, cloned.epoch);
}

#[test]
fn enrichment_contract_inequality_on_different_epochs() {
    let mut c1 = default_contract();
    let mut c2 = default_contract();
    c1.epoch = SecurityEpoch::from_raw(1);
    c2.epoch = SecurityEpoch::from_raw(2);
    assert_ne!(c1, c2);
}

#[test]
fn enrichment_contract_inequality_on_different_versions() {
    let mut c1 = default_contract();
    let mut c2 = default_contract();
    c1.version = 1;
    c2.version = 2;
    assert_ne!(c1, c2);
}

// --- BudgetRegistry deeper tests ---

#[test]
fn enrichment_registry_effective_contract_returns_ref_to_default() {
    let reg = BudgetRegistry::new(tight_contract());
    let eff1 = reg.effective_contract("no-override-1");
    let eff2 = reg.effective_contract("no-override-2");
    assert_eq!(eff1, eff2);
    assert_eq!(eff1.global_time_cap_ns, 1_000);
}

#[test]
fn enrichment_registry_add_override_increments_count() {
    let mut reg = BudgetRegistry::new(default_contract());
    for i in 0..10 {
        reg.add_override(BudgetOverride {
            extension_id: format!("ext-{i}"),
            contract: tight_contract(),
            justification: "test".to_string(),
        });
        assert_eq!(reg.override_count(), i + 1);
    }
}

#[test]
fn enrichment_registry_remove_restores_default() {
    let mut reg = BudgetRegistry::new(default_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-temp".to_string(),
        contract: tight_contract(),
        justification: "temp".to_string(),
    });
    assert_eq!(reg.effective_contract("ext-temp").global_time_cap_ns, 1_000);
    reg.remove_override("ext-temp");
    assert_eq!(
        reg.effective_contract("ext-temp").global_time_cap_ns,
        default_contract().global_time_cap_ns
    );
}

#[test]
fn enrichment_registry_debug_format() {
    let reg = BudgetRegistry::new(tight_contract());
    let dbg = format!("{reg:?}");
    assert!(dbg.contains("BudgetRegistry"));
}

#[test]
fn enrichment_registry_clone_preserves_overrides() {
    let mut reg = BudgetRegistry::new(default_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-clone".to_string(),
        contract: tight_contract(),
        justification: "clone".to_string(),
    });
    let cloned = reg.clone();
    assert_eq!(cloned.override_count(), 1);
    assert_eq!(
        cloned.effective_contract("ext-clone").global_time_cap_ns,
        1_000
    );
}

// --- BudgetMonitor phase lifecycle edge cases ---

#[test]
fn enrichment_monitor_begin_same_phase_twice_no_error() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(10, 1, 1).unwrap();
    // Re-beginning the same phase should succeed.
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(20, 2, 1).unwrap();
    let pc = mon.phase_consumption(SynthesisPhase::Ablation).unwrap();
    assert_eq!(pc.time_ns, 30);
}

#[test]
fn enrichment_monitor_current_phase_updates_on_begin() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    assert_eq!(mon.current_phase(), Some(SynthesisPhase::StaticAnalysis));
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    assert_eq!(mon.current_phase(), Some(SynthesisPhase::Ablation));
    mon.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    assert_eq!(mon.current_phase(), Some(SynthesisPhase::TheoremChecking));
    mon.begin_phase(SynthesisPhase::ResultAssembly).unwrap();
    assert_eq!(mon.current_phase(), Some(SynthesisPhase::ResultAssembly));
}

#[test]
fn enrichment_monitor_remaining_global_after_multi_phase() {
    let mut mon = BudgetMonitor::new(tight_contract()); // time=1000, compute=100, depth=10
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(200, 20, 2).unwrap();
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(300, 30, 3).unwrap();

    let rem = mon.remaining_global();
    assert_eq!(rem.time_ns, 500);
    assert_eq!(rem.compute, 50);
    assert_eq!(rem.depth, 5);
}

#[test]
fn enrichment_monitor_phase_consumption_returns_none_for_unvisited() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(10, 1, 1).unwrap();
    // Ablation never started
    assert!(mon.phase_consumption(SynthesisPhase::Ablation).is_none());
    assert!(
        mon.phase_consumption(SynthesisPhase::TheoremChecking)
            .is_none()
    );
    assert!(
        mon.phase_consumption(SynthesisPhase::ResultAssembly)
            .is_none()
    );
}

#[test]
fn enrichment_monitor_total_consumption_accumulates_across_phases() {
    let mut mon = BudgetMonitor::new(default_contract());
    for (i, phase) in SynthesisPhase::ALL.iter().enumerate() {
        mon.begin_phase(*phase).unwrap();
        mon.record_consumption((i as u64 + 1) * 100, (i as u64 + 1) * 10, i as u64 + 1)
            .unwrap();
    }
    // Total: time=100+200+300+400=1000, compute=10+20+30+40=100, depth=1+2+3+4=10
    assert_eq!(mon.total_consumption().time_ns, 1_000);
    assert_eq!(mon.total_consumption().compute, 100);
    assert_eq!(mon.total_consumption().depth, 10);
}

#[test]
fn enrichment_monitor_remaining_phase_with_override_budget() {
    let c = contract_with_phase_budgets();
    let mut mon = BudgetMonitor::new(c);
    // StaticAnalysis budget: time=500, compute=50, depth=5
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(100, 10, 1).unwrap();

    let rem = mon.remaining_for_current_phase().unwrap();
    assert_eq!(rem.time_ns, 400);
    assert_eq!(rem.compute, 40);
    assert_eq!(rem.depth, 4);
}

#[test]
fn enrichment_monitor_utilization_with_zero_global_caps() {
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 0,
        global_compute_cap: 0,
        global_depth_cap: 0,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mon = BudgetMonitor::new(contract);
    let util = mon.utilization();
    // Zero caps should result in empty utilization map (avoids division by zero).
    assert!(util.is_empty());
}

#[test]
fn enrichment_monitor_utilization_partial_zero_caps() {
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000,
        global_compute_cap: 0,
        global_depth_cap: 500,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(250, 0, 100).unwrap();

    let util = mon.utilization();
    // time: 250/1000 = 250_000
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 250_000);
    // compute: zero cap, no entry
    assert!(util.get(&BudgetDimension::Compute).is_none());
    // depth: 100/500 = 200_000
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 200_000);
}

#[test]
fn enrichment_monitor_exhaustion_compute_dimension_sets_limit_value() {
    let mut mon = BudgetMonitor::new(tight_contract()); // compute=100
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let err = mon.record_consumption(0, 101, 0).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(
                reason
                    .exceeded_dimensions
                    .contains(&BudgetDimension::Compute)
            );
            assert_eq!(reason.limit_value, 100);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_exhaustion_depth_dimension_sets_limit_value() {
    let mut mon = BudgetMonitor::new(tight_contract()); // depth=10
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    let err = mon.record_consumption(0, 0, 11).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Depth));
            assert_eq!(reason.limit_value, 10);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_global_compute_exhaustion_across_phases() {
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: u64::MAX,
        global_compute_cap: 100,
        global_depth_cap: u64::MAX,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(0, 50, 0).unwrap();
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(0, 40, 0).unwrap();
    mon.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    let err = mon.record_consumption(0, 11, 0).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.global_limit_hit);
            assert!(
                reason
                    .exceeded_dimensions
                    .contains(&BudgetDimension::Compute)
            );
            assert_eq!(reason.phase, SynthesisPhase::TheoremChecking);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_global_depth_exhaustion_across_phases() {
    let contract = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: u64::MAX,
        global_compute_cap: u64::MAX,
        global_depth_cap: 10,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(0, 0, 5).unwrap();
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    let err = mon.record_consumption(0, 0, 6).unwrap_err();
    match err {
        BudgetError::Exhausted(reason) => {
            assert!(reason.global_limit_hit);
            assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Depth));
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
}

#[test]
fn enrichment_monitor_saturating_add_time() {
    let contract = SynthesisBudgetContract {
        global_time_cap_ns: u64::MAX,
        global_compute_cap: u64::MAX,
        global_depth_cap: u64::MAX,
        ..Default::default()
    };
    let mut mon = BudgetMonitor::new(contract);
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(u64::MAX - 1, 0, 0).unwrap();
    mon.record_consumption(10, 0, 0).unwrap();
    assert_eq!(mon.total_consumption().time_ns, u64::MAX);
}

#[test]
fn enrichment_monitor_debug_format() {
    let mon = BudgetMonitor::new(tight_contract());
    let dbg = format!("{mon:?}");
    assert!(dbg.contains("BudgetMonitor"));
}

#[test]
fn enrichment_monitor_clone_is_independent() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(100, 10, 1).unwrap();

    let cloned = mon.clone();
    // Mutating original should not affect clone.
    mon.record_consumption(200, 20, 2).unwrap();
    assert_eq!(cloned.total_consumption().time_ns, 100);
    assert_eq!(mon.total_consumption().time_ns, 300);
}

// --- BudgetHistory deeper tests ---

#[test]
fn enrichment_history_record_order_preserved() {
    let mut hist = BudgetHistory::new(100);
    for i in 0..20 {
        hist.record(make_history_entry(&format!("ext-{i}"), i % 3 == 0, i * 50));
    }
    assert_eq!(hist.len(), 20);
    for (idx, entry) in hist.entries().iter().enumerate() {
        assert_eq!(entry.extension_id, format!("ext-{idx}"));
    }
}

#[test]
fn enrichment_history_capacity_exact() {
    let mut hist = BudgetHistory::new(5);
    for i in 0..5 {
        hist.record(make_history_entry(&format!("ext-{i}"), false, i * 10));
    }
    assert_eq!(hist.len(), 5);
    // Adding one more should evict the oldest.
    hist.record(make_history_entry("ext-5", false, 50));
    assert_eq!(hist.len(), 5);
    assert_eq!(hist.entries()[0].extension_id, "ext-1");
}

#[test]
fn enrichment_history_exhaustion_rate_all_different_extensions() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", true, 100));
    hist.record(make_history_entry("ext-b", false, 200));
    // ext-a: 1/1 = 1_000_000
    assert_eq!(hist.exhaustion_rate("ext-a"), 1_000_000);
    // ext-b: 0/1 = 0
    assert_eq!(hist.exhaustion_rate("ext-b"), 0);
}

#[test]
fn enrichment_history_average_utilization_multiple_entries() {
    let c = tight_contract(); // time=1000, compute=100, depth=10
    let mut hist = BudgetHistory::new(10);
    // Three entries: time 100, 200, 300 -> avg 200 -> 200/1000 = 200_000
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-a", false, 200));
    hist.record(make_history_entry("ext-a", false, 300));

    let util = hist.average_utilization("ext-a", &c);
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 200_000);
}

#[test]
fn enrichment_history_entries_for_extension_returns_references() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    hist.record(make_history_entry("ext-a", true, 200));

    let entries = hist.entries_for_extension("ext-a");
    assert_eq!(entries.len(), 2);
    assert!(!entries[0].exhausted);
    assert!(entries[1].exhausted);
}

#[test]
fn enrichment_history_large_capacity_no_eviction() {
    let mut hist = BudgetHistory::new(1000);
    for i in 0..500 {
        hist.record(make_history_entry(&format!("ext-{i}"), false, i));
    }
    assert_eq!(hist.len(), 500);
    assert_eq!(hist.entries()[0].extension_id, "ext-0");
    assert_eq!(hist.entries()[499].extension_id, "ext-499");
}

#[test]
fn enrichment_history_clone_is_independent() {
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 100));
    let cloned = hist.clone();
    hist.record(make_history_entry("ext-b", false, 200));
    assert_eq!(cloned.len(), 1);
    assert_eq!(hist.len(), 2);
}

// --- ExhaustionReason deeper tests ---

#[test]
fn enrichment_exhaustion_reason_display_single_dimension_time() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time],
        phase: SynthesisPhase::StaticAnalysis,
        global_limit_hit: false,
        consumption: PhaseConsumption {
            time_ns: 500,
            compute: 10,
            depth: 1,
        },
        limit_value: 400,
    };
    let s = reason.to_string();
    assert!(s.contains("static-analysis"));
    assert!(s.contains("time"));
    assert!(!s.contains("compute"));
    assert!(!s.contains("depth"));
}

#[test]
fn enrichment_exhaustion_reason_display_all_three_dimensions() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![
            BudgetDimension::Time,
            BudgetDimension::Compute,
            BudgetDimension::Depth,
        ],
        phase: SynthesisPhase::ResultAssembly,
        global_limit_hit: true,
        consumption: PhaseConsumption::zero(),
        limit_value: 0,
    };
    let s = reason.to_string();
    assert!(s.contains("time"));
    assert!(s.contains("compute"));
    assert!(s.contains("depth"));
    assert!(s.contains("global=true"));
}

#[test]
fn enrichment_exhaustion_reason_clone_preserves_all() {
    let reason = sample_exhaustion_reason();
    let cloned = reason.clone();
    assert_eq!(reason.exceeded_dimensions, cloned.exceeded_dimensions);
    assert_eq!(reason.phase, cloned.phase);
    assert_eq!(reason.global_limit_hit, cloned.global_limit_hit);
    assert_eq!(reason.consumption, cloned.consumption);
    assert_eq!(reason.limit_value, cloned.limit_value);
}

#[test]
fn enrichment_exhaustion_reason_ne_different_phases() {
    let r1 = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time],
        phase: SynthesisPhase::Ablation,
        global_limit_hit: false,
        consumption: PhaseConsumption::zero(),
        limit_value: 100,
    };
    let r2 = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time],
        phase: SynthesisPhase::TheoremChecking,
        global_limit_hit: false,
        consumption: PhaseConsumption::zero(),
        limit_value: 100,
    };
    assert_ne!(r1, r2);
}

// --- FallbackQuality ordering tests ---

#[test]
fn enrichment_fallback_quality_ord_static_bound_is_least() {
    assert!(FallbackQuality::StaticBound < FallbackQuality::PartialAblation);
    assert!(FallbackQuality::PartialAblation < FallbackQuality::UnverifiedFull);
    assert!(FallbackQuality::StaticBound < FallbackQuality::UnverifiedFull);
}

#[test]
fn enrichment_fallback_quality_all_variants_serde_json_strings() {
    for q in &[
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
        FallbackQuality::UnverifiedFull,
    ] {
        let json = serde_json::to_string(q).unwrap();
        assert!(json.starts_with('"'));
        let back: FallbackQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(*q, back);
    }
}

// --- FallbackResult deeper tests ---

#[test]
fn enrichment_fallback_result_negative_multiplier() {
    let fr = FallbackResult {
        quality: FallbackQuality::StaticBound,
        result_digest: "neg".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: false,
        recommended_multiplier: Some(-500_000),
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.recommended_multiplier, Some(-500_000));
}

#[test]
fn enrichment_fallback_result_empty_digest() {
    let fr = FallbackResult {
        quality: FallbackQuality::UnverifiedFull,
        result_digest: String::new(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: false,
        recommended_multiplier: None,
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert!(back.result_digest.is_empty());
}

#[test]
fn enrichment_fallback_result_clone_deep() {
    let fr = FallbackResult {
        quality: FallbackQuality::PartialAblation,
        result_digest: "deep-clone".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: true,
        recommended_multiplier: Some(2_000_000),
    };
    let cloned = fr.clone();
    assert_eq!(fr, cloned);
}

#[test]
fn enrichment_fallback_result_ne_different_quality() {
    let fr1 = FallbackResult {
        quality: FallbackQuality::StaticBound,
        result_digest: "same".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: false,
        recommended_multiplier: None,
    };
    let fr2 = FallbackResult {
        quality: FallbackQuality::UnverifiedFull,
        result_digest: "same".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: false,
        recommended_multiplier: None,
    };
    assert_ne!(fr1, fr2);
}

// --- BudgetOverride deeper tests ---

#[test]
fn enrichment_budget_override_inequality_different_extensions() {
    let ovr1 = BudgetOverride {
        extension_id: "ext-1".to_string(),
        contract: tight_contract(),
        justification: "same".to_string(),
    };
    let ovr2 = BudgetOverride {
        extension_id: "ext-2".to_string(),
        contract: tight_contract(),
        justification: "same".to_string(),
    };
    assert_ne!(ovr1, ovr2);
}

#[test]
fn enrichment_budget_override_empty_justification() {
    let ovr = BudgetOverride {
        extension_id: "ext-empty".to_string(),
        contract: default_contract(),
        justification: String::new(),
    };
    let json = serde_json::to_string(&ovr).unwrap();
    let back: BudgetOverride = serde_json::from_str(&json).unwrap();
    assert!(back.justification.is_empty());
}

// --- BudgetError deeper tests ---

#[test]
fn enrichment_budget_error_exhausted_display_delegates_to_reason() {
    let reason = ExhaustionReason {
        exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Depth],
        phase: SynthesisPhase::Ablation,
        global_limit_hit: true,
        consumption: PhaseConsumption {
            time_ns: 999,
            compute: 50,
            depth: 20,
        },
        limit_value: 500,
    };
    let err = BudgetError::Exhausted(reason.clone());
    // Error display should match the reason display.
    assert_eq!(err.to_string(), reason.to_string());
}

#[test]
fn enrichment_budget_error_ne_across_variants() {
    assert_ne!(BudgetError::AlreadyExhausted, BudgetError::NoActivePhase);
    assert_ne!(
        BudgetError::AlreadyExhausted,
        BudgetError::Exhausted(sample_exhaustion_reason())
    );
    assert_ne!(
        BudgetError::NoActivePhase,
        BudgetError::Exhausted(sample_exhaustion_reason())
    );
}

#[test]
fn enrichment_budget_error_serde_already_exhausted_roundtrip() {
    let e = BudgetError::AlreadyExhausted;
    let json = serde_json::to_string(&e).unwrap();
    let back: BudgetError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_budget_error_serde_no_active_phase_roundtrip() {
    let e = BudgetError::NoActivePhase;
    let json = serde_json::to_string(&e).unwrap();
    let back: BudgetError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// --- BudgetHistoryEntry deeper tests ---

#[test]
fn enrichment_history_entry_clone_equality() {
    let entry = make_history_entry("ext-clone", true, 999);
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_history_entry_inequality_different_extension_id() {
    let e1 = make_history_entry("ext-a", false, 100);
    let e2 = make_history_entry("ext-b", false, 100);
    assert_ne!(e1, e2);
}

#[test]
fn enrichment_history_entry_inequality_different_exhausted() {
    let e1 = make_history_entry("ext-a", false, 100);
    let e2 = make_history_entry("ext-a", true, 100);
    assert_ne!(e1, e2);
}

// --- Integration: end-to-end pipeline with registry and history ---

#[test]
fn enrichment_full_pipeline_registry_to_monitor_to_history() {
    // Build a registry with an override for a specific extension.
    let mut reg = BudgetRegistry::new(default_contract());
    reg.add_override(BudgetOverride {
        extension_id: "ext-special".to_string(),
        contract: tight_contract(),
        justification: "needs tight limits".to_string(),
    });

    // Create a monitor from the effective contract.
    let contract = reg.effective_contract("ext-special").clone();
    let mut mon = BudgetMonitor::new(contract.clone());

    // Run through phases.
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(300, 30, 3).unwrap();
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    mon.record_consumption(200, 20, 2).unwrap();

    // Build a history entry from the monitor state.
    let mut pc_map = BTreeMap::new();
    for phase in &SynthesisPhase::ALL {
        if let Some(pc) = mon.phase_consumption(*phase) {
            pc_map.insert(*phase, pc.clone());
        }
    }
    let entry = BudgetHistoryEntry {
        extension_id: "ext-special".to_string(),
        contract_version: contract.version,
        phase_consumption: pc_map,
        total_consumption: mon.total_consumption().clone(),
        exhausted: mon.is_exhausted(),
        timestamp_ns: 42_000_000,
        epoch: contract.epoch,
    };

    // Record in history and compute metrics.
    let mut hist = BudgetHistory::new(100);
    hist.record(entry);

    let util = hist.average_utilization("ext-special", &contract);
    // time: 500/1000 = 500_000
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 500_000);
    assert_eq!(hist.exhaustion_rate("ext-special"), 0);
}

#[test]
fn enrichment_full_pipeline_exhaustion_recorded_in_history() {
    let contract = tight_contract();
    let mut mon = BudgetMonitor::new(contract.clone());
    mon.begin_phase(SynthesisPhase::Ablation).unwrap();
    let _ = mon.record_consumption(2_000, 0, 0); // Exhaust time

    assert!(mon.is_exhausted());

    let entry = BudgetHistoryEntry {
        extension_id: "ext-exhaust".to_string(),
        contract_version: contract.version,
        phase_consumption: BTreeMap::new(),
        total_consumption: mon.total_consumption().clone(),
        exhausted: true,
        timestamp_ns: 1_000_000,
        epoch: contract.epoch,
    };

    let mut hist = BudgetHistory::new(10);
    hist.record(entry);
    assert_eq!(hist.exhaustion_rate("ext-exhaust"), 1_000_000);
}

#[test]
fn enrichment_pipeline_multiple_runs_mixed_exhaustion() {
    let contract = tight_contract(); // time=1000
    let mut hist = BudgetHistory::new(100);

    // Run 1: successful (500 time)
    hist.record(BudgetHistoryEntry {
        extension_id: "ext-mix".to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption {
            time_ns: 500,
            compute: 50,
            depth: 5,
        },
        exhausted: false,
        timestamp_ns: 1_000,
        epoch: SecurityEpoch::from_raw(0),
    });

    // Run 2: exhausted (2000 time)
    hist.record(BudgetHistoryEntry {
        extension_id: "ext-mix".to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption {
            time_ns: 2_000,
            compute: 50,
            depth: 5,
        },
        exhausted: true,
        timestamp_ns: 2_000,
        epoch: SecurityEpoch::from_raw(0),
    });

    // Run 3: successful (800 time)
    hist.record(BudgetHistoryEntry {
        extension_id: "ext-mix".to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption {
            time_ns: 800,
            compute: 50,
            depth: 5,
        },
        exhausted: false,
        timestamp_ns: 3_000,
        epoch: SecurityEpoch::from_raw(0),
    });

    // 1/3 exhausted = 333_333
    assert_eq!(hist.exhaustion_rate("ext-mix"), 333_333);

    // Average time: (500+2000+800)/3 = 1100, utilization: 1100/1000 = 1_100_000
    let util = hist.average_utilization("ext-mix", &contract);
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 1_100_000);
}

#[test]
fn enrichment_monitor_multiple_records_per_phase_summing() {
    let mut mon = BudgetMonitor::new(default_contract());
    mon.begin_phase(SynthesisPhase::TheoremChecking).unwrap();
    mon.record_consumption(1, 1, 1).unwrap();
    mon.record_consumption(2, 2, 2).unwrap();
    mon.record_consumption(3, 3, 3).unwrap();

    let pc = mon
        .phase_consumption(SynthesisPhase::TheoremChecking)
        .unwrap();
    assert_eq!(pc.time_ns, 6);
    assert_eq!(pc.compute, 6);
    assert_eq!(pc.depth, 6);
}

#[test]
fn enrichment_contract_phase_budget_for_result_assembly_inherits() {
    let c = contract_with_phase_budgets(); // Only StaticAnalysis and Ablation have overrides
    let pb = c.budget_for_phase(SynthesisPhase::ResultAssembly);
    assert_eq!(pb.time_cap_ns, c.global_time_cap_ns);
    assert_eq!(pb.compute_cap, c.global_compute_cap);
    assert_eq!(pb.depth_cap, c.global_depth_cap);
}

#[test]
fn enrichment_fallback_result_large_multiplier() {
    let fr = FallbackResult {
        quality: FallbackQuality::PartialAblation,
        result_digest: "large-mult".to_string(),
        exhaustion_reason: sample_exhaustion_reason(),
        increase_likely_helpful: true,
        recommended_multiplier: Some(i64::MAX),
    };
    let json = serde_json::to_string(&fr).unwrap();
    let back: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.recommended_multiplier, Some(i64::MAX));
}

#[test]
fn enrichment_monitor_full_pipeline_all_phases_remain_at_boundary() {
    // Each phase uses 1/4 of global budget.
    let c = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 400,
        global_compute_cap: 40,
        global_depth_cap: 8,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
    };
    let mut mon = BudgetMonitor::new(c);

    for phase in &SynthesisPhase::ALL {
        mon.begin_phase(*phase).unwrap();
        mon.record_consumption(100, 10, 2).unwrap();
    }

    assert!(!mon.is_exhausted());
    let rem = mon.remaining_global();
    assert_eq!(rem.time_ns, 0);
    assert_eq!(rem.compute, 0);
    assert_eq!(rem.depth, 0);

    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 1_000_000);
}

#[test]
fn enrichment_registry_override_with_phase_budgets() {
    let mut reg = BudgetRegistry::new(default_contract());
    let override_contract = contract_with_phase_budgets();
    reg.add_override(BudgetOverride {
        extension_id: "ext-phased".to_string(),
        contract: override_contract.clone(),
        justification: "needs phase budgets".to_string(),
    });

    let eff = reg.effective_contract("ext-phased");
    assert_eq!(eff.phase_budgets.len(), 2);
    let sa = eff.budget_for_phase(SynthesisPhase::StaticAnalysis);
    assert_eq!(sa.time_cap_ns, 500);
}

#[test]
fn enrichment_history_average_utilization_zero_time_cap() {
    let c = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 0,
        global_compute_cap: 100,
        global_depth_cap: 10,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(0),
    };
    let mut hist = BudgetHistory::new(10);
    hist.record(make_history_entry("ext-a", false, 0));

    let util = hist.average_utilization("ext-a", &c);
    // Time cap is zero, so Time dimension should not be present.
    assert!(util.get(&BudgetDimension::Time).is_none());
    // Compute and Depth should be present.
    assert!(util.get(&BudgetDimension::Compute).is_some());
    assert!(util.get(&BudgetDimension::Depth).is_some());
}

#[test]
fn enrichment_monitor_utilization_tenth() {
    let mut mon = BudgetMonitor::new(tight_contract()); // time=1000, compute=100, depth=10
    mon.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
    mon.record_consumption(100, 10, 1).unwrap(); // 10% each

    let util = mon.utilization();
    assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 100_000);
    assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 100_000);
    assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 100_000);
}

#[test]
fn enrichment_history_entry_empty_phase_consumption_serde() {
    let entry = BudgetHistoryEntry {
        extension_id: "ext-empty-pc".to_string(),
        contract_version: 1,
        phase_consumption: BTreeMap::new(),
        total_consumption: PhaseConsumption::zero(),
        exhausted: false,
        timestamp_ns: 0,
        epoch: SecurityEpoch::from_raw(0),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BudgetHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.phase_consumption.is_empty());
}
