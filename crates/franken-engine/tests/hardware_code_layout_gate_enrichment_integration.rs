//! Enrichment integration tests for `hardware_code_layout_gate`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default coverage, JSON field-name stability,
//! AlignmentStrategy computation, StallBudget tracking, LayoutPolicy operations,
//! RollbackGate, LayoutDecisionReceipt, CodeRegion builders, PlatformRule.

use std::collections::BTreeSet;

use frankenengine_engine::hardware_code_layout_gate::{
    AlignmentStrategy, AlignmentTarget, BEAD_ID, COMPONENT, CodeRegion, DEFAULT_CACHE_LINE_BYTES,
    DEFAULT_ICACHE_MISS_THRESHOLD, DEFAULT_PAGE_SIZE_BYTES, DEFAULT_REGRESSION_THRESHOLD,
    DEFAULT_STALL_BUDGET_CYCLES, LayoutDecisionKind, LayoutDecisionReceipt, LayoutPolicy,
    LayoutPolicyState, MAX_ALIGNMENT_BUDGET_BYTES, POLICY_ID, PlatformId, PlatformRule, RegionHeat,
    RegionId, RollbackGate, RollbackReason, RollbackRecord, SCHEMA_VERSION, StallBudget,
    StallEvent, StallKind,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ──────────────────────────────────────────────────────────

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

// -----------------------------------------------------------------------
// 1. Copy semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_target_copy() {
    let a = AlignmentTarget::CacheLine;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_region_heat_copy() {
    let a = RegionHeat::Hot;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_stall_kind_copy() {
    let a = StallKind::ICacheMiss;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_layout_policy_state_copy() {
    let a = LayoutPolicyState::Active;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_layout_decision_kind_copy() {
    let a = LayoutDecisionKind::AlignCacheLine;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_reason_copy() {
    // RollbackReason is Clone but not Copy (has Hash derive but String-like?)
    // Actually it derives Hash + Eq + Clone, check...
    let a = RollbackReason::PerformanceRegression;
    let b = a.clone();
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// 2. Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_strategy_clone_independence() {
    let a = AlignmentStrategy::cache_line(64);
    let mut b = a.clone();
    b.alignment_bytes = 128;
    assert_eq!(a.alignment_bytes, 64);
    assert_eq!(b.alignment_bytes, 128);
}

#[test]
fn enrichment_code_region_clone_independence() {
    let a = CodeRegion::new("r1", RegionHeat::Hot, 256);
    let mut b = a.clone();
    b.size_bytes = 512;
    assert_eq!(a.size_bytes, 256);
    assert_eq!(b.size_bytes, 512);
}

#[test]
fn enrichment_stall_budget_clone_independence() {
    let a = StallBudget::default();
    let mut b = a.clone();
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
    assert_eq!(a.event_count(), 0);
    assert_eq!(b.event_count(), 1);
}

#[test]
fn enrichment_platform_rule_clone_independence() {
    let a = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    let mut b = a.clone();
    b.pin("test pin");
    assert!(!a.pinned);
    assert!(b.pinned);
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_target_btreeset() {
    let mut set = BTreeSet::new();
    for t in AlignmentTarget::ALL {
        set.insert(*t);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_region_heat_btreeset() {
    let mut set = BTreeSet::new();
    for h in RegionHeat::ALL {
        set.insert(*h);
    }
    set.insert(RegionHeat::Hot); // duplicate
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_stall_kind_btreeset() {
    let mut set = BTreeSet::new();
    for k in StallKind::ALL {
        set.insert(*k);
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_layout_policy_state_btreeset() {
    let mut set = BTreeSet::new();
    for s in LayoutPolicyState::ALL {
        set.insert(*s);
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_layout_decision_kind_btreeset() {
    let mut set = BTreeSet::new();
    for k in LayoutDecisionKind::ALL {
        set.insert(*k);
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_rollback_reason_btreeset() {
    let mut set = BTreeSet::new();
    for r in RollbackReason::ALL {
        set.insert(r.clone());
    }
    assert_eq!(set.len(), 6);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_target_serde_roundtrip() {
    for t in AlignmentTarget::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: AlignmentTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *t);
    }
}

#[test]
fn enrichment_alignment_strategy_serde_roundtrip() {
    let strats = [
        AlignmentStrategy::natural(),
        AlignmentStrategy::cache_line(64),
        AlignmentStrategy::page_boundary(4096),
        AlignmentStrategy::explicit(32, 16),
    ];
    for s in &strats {
        let json = serde_json::to_string(s).unwrap();
        let back: AlignmentStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

#[test]
fn enrichment_region_heat_serde_roundtrip() {
    for h in RegionHeat::ALL {
        let json = serde_json::to_string(h).unwrap();
        let back: RegionHeat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *h);
    }
}

#[test]
fn enrichment_stall_kind_serde_roundtrip() {
    for k in StallKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: StallKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

#[test]
fn enrichment_layout_policy_state_serde_roundtrip() {
    for s in LayoutPolicyState::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: LayoutPolicyState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *s);
    }
}

#[test]
fn enrichment_layout_decision_kind_serde_roundtrip() {
    for k in LayoutDecisionKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: LayoutDecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

#[test]
fn enrichment_rollback_reason_serde_roundtrip() {
    for r in RollbackReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: RollbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
    }
}

#[test]
fn enrichment_code_region_serde_roundtrip() {
    let r = CodeRegion::new("r1", RegionHeat::Hot, 256)
        .with_base_address(0x1000)
        .with_execution_count(42)
        .with_loop_header(true)
        .with_function_entry(true);
    let json = serde_json::to_string(&r).unwrap();
    let back: CodeRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn enrichment_stall_event_serde_roundtrip() {
    let e = StallEvent::new(StallKind::ICacheMiss, "r1", 10).with_offset(64);
    let json = serde_json::to_string(&e).unwrap();
    let back: StallEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn enrichment_stall_budget_serde_roundtrip() {
    let mut sb = StallBudget::default();
    sb.record(StallEvent::new(StallKind::InstructionFetch, "r1", 5));
    let json = serde_json::to_string(&sb).unwrap();
    let back: StallBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sb);
}

#[test]
fn enrichment_platform_rule_serde_roundtrip() {
    let pr = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    let json = serde_json::to_string(&pr).unwrap();
    let back: PlatformRule = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pr);
}

#[test]
fn enrichment_layout_policy_serde_roundtrip() {
    let lp = LayoutPolicy::new("policy-1", epoch());
    let json = serde_json::to_string(&lp).unwrap();
    let back: LayoutPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lp);
}

#[test]
fn enrichment_layout_decision_receipt_serde_roundtrip() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot loop header",
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: LayoutDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn enrichment_rollback_record_serde_roundtrip() {
    let rr = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "policy-1",
        epoch(),
        1_000_000,
        900_000,
    );
    let json = serde_json::to_string(&rr).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rr);
}

#[test]
fn enrichment_rollback_gate_serde_roundtrip() {
    let rg = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let json = serde_json::to_string(&rg).unwrap();
    let back: RollbackGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rg);
}

#[test]
fn enrichment_platform_id_serde_roundtrip() {
    let pid = PlatformId::new("arm64");
    let json = serde_json::to_string(&pid).unwrap();
    let back: PlatformId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pid);
}

#[test]
fn enrichment_region_id_serde_roundtrip() {
    let rid = RegionId::new("my_region");
    let json = serde_json::to_string(&rid).unwrap();
    let back: RegionId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rid);
}

// -----------------------------------------------------------------------
// 5. Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_target_display() {
    for t in AlignmentTarget::ALL {
        let s = t.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, t.as_str());
    }
}

#[test]
fn enrichment_region_heat_display() {
    for h in RegionHeat::ALL {
        let s = h.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, h.as_str());
    }
}

#[test]
fn enrichment_stall_kind_display() {
    for k in StallKind::ALL {
        let s = k.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, k.as_str());
    }
}

#[test]
fn enrichment_layout_policy_state_display() {
    for s in LayoutPolicyState::ALL {
        let d = s.to_string();
        assert!(!d.is_empty());
        assert_eq!(d, s.as_str());
    }
}

#[test]
fn enrichment_layout_decision_kind_display() {
    for k in LayoutDecisionKind::ALL {
        let s = k.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, k.as_str());
    }
}

#[test]
fn enrichment_rollback_reason_display() {
    for r in RollbackReason::ALL {
        let s = r.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, r.as_str());
    }
}

#[test]
fn enrichment_alignment_strategy_display() {
    let s = AlignmentStrategy::cache_line(64);
    let d = s.to_string();
    assert!(d.contains("align("));
    assert!(d.contains("64B"));
}

#[test]
fn enrichment_platform_id_display() {
    let pid = PlatformId::new("x86_64");
    assert!(pid.to_string().contains("x86_64"));
}

#[test]
fn enrichment_region_id_display() {
    let rid = RegionId::new("loop_header");
    assert!(rid.to_string().contains("loop_header"));
}

#[test]
fn enrichment_code_region_display() {
    let r = CodeRegion::new("r1", RegionHeat::Hot, 256);
    let d = r.to_string();
    assert!(d.contains("r1"));
    assert!(d.contains("256B"));
}

#[test]
fn enrichment_stall_event_display() {
    let e = StallEvent::new(StallKind::ICacheMiss, "r1", 10);
    let d = e.to_string();
    assert!(d.contains("icache_miss"));
}

#[test]
fn enrichment_stall_budget_display() {
    let sb = StallBudget::default();
    let d = sb.to_string();
    assert!(d.contains("stall_budget"));
}

#[test]
fn enrichment_platform_rule_display() {
    let pr = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    let d = pr.to_string();
    assert!(d.contains("x86_64"));
    assert!(d.contains("active"));
}

#[test]
fn enrichment_layout_policy_display() {
    let lp = LayoutPolicy::new("policy-1", epoch());
    let d = lp.to_string();
    assert!(d.contains("policy-1"));
}

#[test]
fn enrichment_layout_decision_receipt_display() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot",
    );
    let d = r.to_string();
    assert!(d.contains("receipt"));
}

#[test]
fn enrichment_rollback_record_display() {
    let rr = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "p1",
        epoch(),
        1_000_000,
        900_000,
    );
    let d = rr.to_string();
    assert!(d.contains("rollback"));
}

// -----------------------------------------------------------------------
// 6. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_target_debug() {
    for t in AlignmentTarget::ALL {
        assert!(!format!("{t:?}").is_empty());
    }
}

#[test]
fn enrichment_region_heat_debug() {
    for h in RegionHeat::ALL {
        assert!(!format!("{h:?}").is_empty());
    }
}

#[test]
fn enrichment_stall_kind_debug() {
    for k in StallKind::ALL {
        assert!(!format!("{k:?}").is_empty());
    }
}

#[test]
fn enrichment_layout_policy_debug() {
    let lp = LayoutPolicy::new("p1", epoch());
    assert!(!format!("{lp:?}").is_empty());
}

// -----------------------------------------------------------------------
// 7. Default coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_strategy_default() {
    let d = AlignmentStrategy::default();
    assert_eq!(d.target, AlignmentTarget::Natural);
    assert_eq!(d.alignment_bytes, 1);
    assert_eq!(d.max_padding_bytes, 0);
    assert!(!d.allow_nop_padding);
}

#[test]
fn enrichment_stall_budget_default() {
    let sb = StallBudget::default();
    assert_eq!(sb.max_stall_cycles, DEFAULT_STALL_BUDGET_CYCLES);
    assert_eq!(sb.max_icache_misses, DEFAULT_ICACHE_MISS_THRESHOLD);
    assert_eq!(sb.accumulated_cycles, 0);
    assert_eq!(sb.accumulated_icache_misses, 0);
}

// -----------------------------------------------------------------------
// 8. Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    const {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
    }
}

#[test]
fn enrichment_default_constants_reasonable() {
    const {
        assert!(DEFAULT_CACHE_LINE_BYTES == 64);
        assert!(DEFAULT_PAGE_SIZE_BYTES == 4096);
        assert!(MAX_ALIGNMENT_BUDGET_BYTES > 0);
        assert!(DEFAULT_STALL_BUDGET_CYCLES > 0);
        assert!(DEFAULT_ICACHE_MISS_THRESHOLD > 0);
        assert!(DEFAULT_REGRESSION_THRESHOLD > 0);
    }
}

// -----------------------------------------------------------------------
// 9. AlignmentStrategy computation
// -----------------------------------------------------------------------

#[test]
fn enrichment_alignment_strategy_constructors() {
    let natural = AlignmentStrategy::natural();
    assert_eq!(natural.target, AlignmentTarget::Natural);
    assert_eq!(natural.alignment_bytes, 1);

    let cl = AlignmentStrategy::cache_line(64);
    assert_eq!(cl.target, AlignmentTarget::CacheLine);
    assert_eq!(cl.alignment_bytes, 64);
    assert_eq!(cl.max_padding_bytes, 63);
    assert!(cl.allow_nop_padding);

    let pb = AlignmentStrategy::page_boundary(4096);
    assert_eq!(pb.target, AlignmentTarget::PageBoundary);
    assert_eq!(pb.alignment_bytes, 4096);

    let ex = AlignmentStrategy::explicit(32, 16);
    assert_eq!(ex.target, AlignmentTarget::ExplicitBytes);
    assert_eq!(ex.alignment_bytes, 32);
    assert_eq!(ex.max_padding_bytes, 16);
}

#[test]
fn enrichment_alignment_is_power_of_two() {
    assert!(AlignmentStrategy::cache_line(64).is_power_of_two());
    assert!(AlignmentStrategy::page_boundary(4096).is_power_of_two());
    assert!(AlignmentStrategy::natural().is_power_of_two());
    assert!(!AlignmentStrategy::explicit(48, 10).is_power_of_two());
}

#[test]
fn enrichment_alignment_padding_for() {
    let cl = AlignmentStrategy::cache_line(64);
    assert_eq!(cl.padding_for(0), Some(0));
    assert_eq!(cl.padding_for(64), Some(0));
    assert_eq!(cl.padding_for(65), Some(63));
    assert_eq!(cl.padding_for(100), Some(28)); // 128 - 100

    // Zero alignment returns None
    let zero = AlignmentStrategy::explicit(0, 0);
    assert_eq!(zero.padding_for(42), None);
}

#[test]
fn enrichment_alignment_exceeds_budget() {
    let cl = AlignmentStrategy::cache_line(64);
    assert!(!cl.exceeds_budget(63)); // max_padding = 63
    assert!(cl.exceeds_budget(64));
}

// -----------------------------------------------------------------------
// 10. RegionHeat rank
// -----------------------------------------------------------------------

#[test]
fn enrichment_region_heat_rank_ordering() {
    assert!(RegionHeat::Cold.rank() < RegionHeat::Warm.rank());
    assert!(RegionHeat::Warm.rank() < RegionHeat::Hot.rank());
    assert!(RegionHeat::Hot.rank() < RegionHeat::Traced.rank());
}

// -----------------------------------------------------------------------
// 11. CodeRegion builders
// -----------------------------------------------------------------------

#[test]
fn enrichment_code_region_builders() {
    let r = CodeRegion::new("r1", RegionHeat::Hot, 256)
        .with_base_address(0x1000)
        .with_execution_count(42)
        .with_loop_header(true)
        .with_function_entry(true);
    assert_eq!(r.id.as_str(), "r1");
    assert_eq!(r.heat, RegionHeat::Hot);
    assert_eq!(r.size_bytes, 256);
    assert_eq!(r.base_address, 0x1000);
    assert_eq!(r.execution_count, 42);
    assert!(r.is_loop_header);
    assert!(r.is_function_entry);
}

#[test]
fn enrichment_code_region_defaults() {
    let r = CodeRegion::new("r1", RegionHeat::Cold, 100);
    assert_eq!(r.base_address, 0);
    assert_eq!(r.execution_count, 0);
    assert!(!r.is_loop_header);
    assert!(!r.is_function_entry);
}

// -----------------------------------------------------------------------
// 12. StallBudget tracking
// -----------------------------------------------------------------------

#[test]
fn enrichment_stall_budget_record_and_query() {
    let mut sb = StallBudget::new(100, 10);
    assert!(!sb.gate_fires());
    assert!(!sb.cycles_exhausted());
    assert!(!sb.icache_exhausted());
    assert_eq!(sb.remaining_cycles(), 100);
    assert_eq!(sb.remaining_icache_misses(), 10);

    sb.record(StallEvent::new(StallKind::ICacheMiss, "r1", 50));
    assert_eq!(sb.accumulated_cycles, 50);
    assert_eq!(sb.accumulated_icache_misses, 1);
    assert_eq!(sb.event_count(), 1);
    assert_eq!(sb.remaining_cycles(), 50);
}

#[test]
fn enrichment_stall_budget_gate_fires_cycles() {
    let mut sb = StallBudget::new(100, 1000);
    sb.record(StallEvent::new(StallKind::InstructionFetch, "r1", 100));
    assert!(sb.cycles_exhausted());
    assert!(sb.gate_fires());
}

#[test]
fn enrichment_stall_budget_gate_fires_icache() {
    let mut sb = StallBudget::new(1000, 2);
    sb.record(StallEvent::new(StallKind::ICacheMiss, "r1", 1));
    sb.record(StallEvent::new(StallKind::ICacheMiss, "r2", 1));
    assert!(sb.icache_exhausted());
    assert!(sb.gate_fires());
}

#[test]
fn enrichment_stall_budget_utilisation() {
    let mut sb = StallBudget::new(1_000_000, 100);
    sb.record(StallEvent::new(StallKind::InstructionFetch, "r1", 500_000));
    assert_eq!(sb.cycle_utilisation_millionths(), 500_000);
}

#[test]
fn enrichment_stall_budget_utilisation_zero_max() {
    let sb = StallBudget::new(0, 0);
    assert_eq!(sb.cycle_utilisation_millionths(), 1_000_000);
}

#[test]
fn enrichment_stall_budget_reset() {
    let mut sb = StallBudget::new(100, 10);
    sb.record(StallEvent::new(StallKind::ICacheMiss, "r1", 50));
    sb.reset();
    assert_eq!(sb.accumulated_cycles, 0);
    assert_eq!(sb.accumulated_icache_misses, 0);
    assert_eq!(sb.event_count(), 0);
    assert!(sb.counters.is_empty());
}

#[test]
fn enrichment_stall_budget_content_hash_deterministic() {
    let a = StallBudget::new(100, 10);
    let b = StallBudget::new(100, 10);
    assert_eq!(a.content_hash(), b.content_hash());
}

// -----------------------------------------------------------------------
// 13. PlatformRule operations
// -----------------------------------------------------------------------

#[test]
fn enrichment_platform_rule_pin_and_rollback() {
    let mut rule = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    assert!(!rule.pinned);
    assert!(!rule.rolled_back);
    assert!(rule.is_generalisable());

    rule.pin("benchmark shows 10% improvement");
    assert!(rule.pinned);
    assert!(!rule.is_generalisable());

    rule.generalise();
    assert!(!rule.pinned);
    assert!(rule.is_generalisable());

    rule.rollback("regression detected");
    assert!(rule.rolled_back);
    assert_eq!(rule.alignment.target, AlignmentTarget::Natural);
    assert!(!rule.is_generalisable());
}

#[test]
fn enrichment_platform_rule_display_states() {
    let mut rule = PlatformRule::new("arm64", AlignmentStrategy::cache_line(64));
    assert!(rule.to_string().contains("active"));
    rule.pin("test");
    assert!(rule.to_string().contains("pinned"));
}

// -----------------------------------------------------------------------
// 14. LayoutPolicy operations
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_policy_new_defaults() {
    let lp = LayoutPolicy::new("p1", epoch());
    assert_eq!(lp.policy_id, "p1");
    assert_eq!(lp.state, LayoutPolicyState::Draft);
    assert_eq!(lp.alignment_budget_bytes, MAX_ALIGNMENT_BUDGET_BYTES);
    assert_eq!(lp.padding_spent_bytes, 0);
    assert!(!lp.budget_exhausted());
    assert_eq!(lp.remaining_budget(), MAX_ALIGNMENT_BUDGET_BYTES);
    assert_eq!(lp.regions.len(), 0);
    assert_eq!(lp.hot_region_count(), 0);
    assert_eq!(lp.total_code_bytes(), 0);
}

#[test]
fn enrichment_layout_policy_activate() {
    let mut lp = LayoutPolicy::new("p1", epoch());
    lp.activate();
    assert_eq!(lp.state, LayoutPolicyState::Active);
}

#[test]
fn enrichment_layout_policy_spend_padding() {
    let mut lp = LayoutPolicy::new("p1", epoch());
    lp.alignment_budget_bytes = 100;
    assert!(lp.spend_padding(50));
    assert_eq!(lp.padding_spent_bytes, 50);
    assert_eq!(lp.remaining_budget(), 50);
    assert!(!lp.budget_exhausted());
    assert!(!lp.spend_padding(50)); // exactly at budget
    assert!(lp.budget_exhausted());
}

#[test]
fn enrichment_layout_policy_budget_utilisation() {
    let mut lp = LayoutPolicy::new("p1", epoch());
    lp.alignment_budget_bytes = 1_000_000;
    lp.padding_spent_bytes = 500_000;
    assert_eq!(lp.budget_utilisation_millionths(), 500_000);
}

#[test]
fn enrichment_layout_policy_add_region() {
    let mut lp = LayoutPolicy::new("p1", epoch());
    lp.add_region(CodeRegion::new("r1", RegionHeat::Hot, 256));
    lp.add_region(CodeRegion::new("r2", RegionHeat::Cold, 128));
    assert_eq!(lp.regions.len(), 2);
    assert_eq!(lp.hot_region_count(), 1);
    assert_eq!(lp.total_code_bytes(), 384);
}

#[test]
fn enrichment_layout_policy_effective_alignment_default() {
    let lp = LayoutPolicy::new("p1", epoch());
    let align = lp.effective_alignment("unknown_platform");
    assert_eq!(align.target, AlignmentTarget::CacheLine);
}

#[test]
fn enrichment_layout_policy_effective_alignment_platform_override() {
    let mut lp = LayoutPolicy::new("p1", epoch());
    lp.add_platform_rule(PlatformRule::new(
        "arm64",
        AlignmentStrategy::page_boundary(16384),
    ));
    let align = lp.effective_alignment("arm64");
    assert_eq!(align.target, AlignmentTarget::PageBoundary);
    assert_eq!(align.alignment_bytes, 16384);
}

#[test]
fn enrichment_layout_policy_content_hash_deterministic() {
    let a = LayoutPolicy::new("p1", epoch());
    let b = LayoutPolicy::new("p1", epoch());
    assert_eq!(a.content_hash(), b.content_hash());
}

// -----------------------------------------------------------------------
// 15. LayoutPolicyState is_operational
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_policy_state_is_operational() {
    assert!(LayoutPolicyState::Draft.is_operational());
    assert!(LayoutPolicyState::Active.is_operational());
    assert!(!LayoutPolicyState::RolledBack.is_operational());
    assert!(!LayoutPolicyState::Superseded.is_operational());
    assert!(!LayoutPolicyState::Archived.is_operational());
}

// -----------------------------------------------------------------------
// 16. LayoutDecisionReceipt
// -----------------------------------------------------------------------

#[test]
fn enrichment_layout_decision_receipt_fields() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot loop header",
    );
    assert_eq!(r.region_id.as_str(), "r1");
    assert_eq!(r.kind, LayoutDecisionKind::AlignCacheLine);
    assert_eq!(r.padding_bytes, 12);
    assert_eq!(r.platform_id.as_str(), "x86_64");
}

#[test]
fn enrichment_layout_decision_receipt_hash_deterministic() {
    let a = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot",
    );
    let b = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot",
    );
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn enrichment_layout_decision_receipt_hash_hex() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::KeepNatural,
        AlignmentStrategy::natural(),
        0,
        "generic",
        epoch(),
        "cold",
    );
    let hex = r.receipt_hash_hex();
    assert!(!hex.is_empty());
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// -----------------------------------------------------------------------
// 17. RollbackRecord
// -----------------------------------------------------------------------

#[test]
fn enrichment_rollback_record_perf_delta() {
    let rr = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "p1",
        epoch(),
        1_000_000,
        900_000,
    );
    assert_eq!(rr.perf_delta_millionths(), -100_000);
    assert!(rr.is_regression());
}

#[test]
fn enrichment_rollback_record_no_regression() {
    let rr = RollbackRecord::new(
        RollbackReason::OperatorOverride,
        "p1",
        epoch(),
        1_000_000,
        1_050_000,
    );
    assert_eq!(rr.perf_delta_millionths(), 50_000);
    assert!(!rr.is_regression());
}

#[test]
fn enrichment_rollback_record_zero_baseline() {
    let rr = RollbackRecord::new(
        RollbackReason::StallBudgetExhausted,
        "p1",
        epoch(),
        0,
        500_000,
    );
    assert_eq!(rr.perf_delta_millionths(), 0);
}

// -----------------------------------------------------------------------
// 18. RollbackGate
// -----------------------------------------------------------------------

#[test]
fn enrichment_rollback_gate_no_regression() {
    let mut rg = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let result = rg.evaluate("p1", epoch(), 1_000_000, 960_000);
    // 4% drop, threshold is 5% => no rollback
    assert!(result.is_none());
    assert!(!rg.fired);
}

#[test]
fn enrichment_rollback_gate_regression_fires() {
    let mut rg = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let result = rg.evaluate("p1", epoch(), 1_000_000, 940_000);
    // 6% drop > 5% threshold => rollback
    assert!(result.is_some());
    assert!(rg.fired);
    assert_eq!(rg.records.len(), 1);
}

#[test]
fn enrichment_rollback_gate_zero_baseline() {
    let mut rg = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let result = rg.evaluate("p1", epoch(), 0, 500_000);
    assert!(result.is_none());
}

// -----------------------------------------------------------------------
// 19. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_code_region_json_fields() {
    let r = CodeRegion::new("r1", RegionHeat::Hot, 256);
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"heat\""));
    assert!(json.contains("\"size_bytes\""));
    assert!(json.contains("\"base_address\""));
    assert!(json.contains("\"execution_count\""));
    assert!(json.contains("\"is_loop_header\""));
}

#[test]
fn enrichment_stall_budget_json_fields() {
    let sb = StallBudget::default();
    let json = serde_json::to_string(&sb).unwrap();
    assert!(json.contains("\"max_stall_cycles\""));
    assert!(json.contains("\"max_icache_misses\""));
    assert!(json.contains("\"accumulated_cycles\""));
}

#[test]
fn enrichment_layout_policy_json_fields() {
    let lp = LayoutPolicy::new("p1", epoch());
    let json = serde_json::to_string(&lp).unwrap();
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"state\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"default_alignment\""));
    assert!(json.contains("\"alignment_budget_bytes\""));
    assert!(json.contains("\"regression_threshold_millionths\""));
}

#[test]
fn enrichment_layout_decision_receipt_json_fields() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        12,
        "x86_64",
        epoch(),
        "hot",
    );
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"region_id\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"alignment\""));
    assert!(json.contains("\"padding_bytes\""));
    assert!(json.contains("\"receipt_hash\""));
}
