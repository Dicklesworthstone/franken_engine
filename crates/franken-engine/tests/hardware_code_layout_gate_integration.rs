//! Integration tests for hardware_code_layout_gate module: alignment strategies,
//! stall budgets, layout policies, rollback gates, parity checking, diagnostic
//! reports, and full layout evaluation pipelines.

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

use frankenengine_engine::hardware_code_layout_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: u64 = 1_000_000;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_policy(id: &str) -> LayoutPolicy {
    LayoutPolicy::new(id, test_epoch())
}

fn make_active_policy(id: &str) -> LayoutPolicy {
    let mut p = make_policy(id);
    p.activate();
    p
}

fn make_region(id: &str, heat: RegionHeat, size: u64, addr: u64) -> CodeRegion {
    CodeRegion::new(id, heat, size).with_base_address(addr)
}

fn hash_of(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn make_test_evaluator_policy() -> LayoutPolicy {
    let mut p = make_active_policy("eval_policy");
    p.add_region(make_region("cold_fn", RegionHeat::Cold, 64, 0x100));
    p.add_region(make_region("warm_fn", RegionHeat::Warm, 128, 0x300));
    p.add_region(make_region("hot_loop", RegionHeat::Hot, 256, 0x200));
    p.add_region(make_region("traced_fn", RegionHeat::Traced, 512, 0x400));
    p
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("hardware-code-layout-gate"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "hardware_code_layout_gate");
}

#[test]
fn test_bead_id_format() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.23.3");
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_policy_id_format() {
    assert_eq!(POLICY_ID, "RGC-623C");
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn test_default_constants_sensible() {
    assert_eq!(DEFAULT_CACHE_LINE_BYTES, 64);
    assert_eq!(DEFAULT_PAGE_SIZE_BYTES, 4096);
    assert_eq!(MAX_ALIGNMENT_BUDGET_BYTES, 1_048_576);
    assert_eq!(DEFAULT_STALL_BUDGET_CYCLES, 256);
    assert_eq!(DEFAULT_ICACHE_MISS_THRESHOLD, 64);
    assert_eq!(DEFAULT_REGRESSION_THRESHOLD, 50_000);
    assert_eq!(MAX_LAYOUT_REGIONS, 4096);
    assert_eq!(MAX_DIAGNOSTIC_ENTRIES, 512);
}

// ---------------------------------------------------------------------------
// AlignmentTarget
// ---------------------------------------------------------------------------

#[test]
fn test_alignment_target_all_variants_complete() {
    let all = AlignmentTarget::ALL;
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], AlignmentTarget::Natural);
    assert_eq!(all[1], AlignmentTarget::CacheLine);
    assert_eq!(all[2], AlignmentTarget::PageBoundary);
    assert_eq!(all[3], AlignmentTarget::ExplicitBytes);
}

#[test]
fn test_alignment_target_as_str_and_display() {
    let expected = [
        (AlignmentTarget::Natural, "natural"),
        (AlignmentTarget::CacheLine, "cache_line"),
        (AlignmentTarget::PageBoundary, "page_boundary"),
        (AlignmentTarget::ExplicitBytes, "explicit_bytes"),
    ];
    for (target, s) in &expected {
        assert_eq!(target.as_str(), *s);
        assert_eq!(target.to_string(), *s);
    }
}

#[test]
fn test_alignment_target_serde_round_trip() {
    for target in AlignmentTarget::ALL {
        let json = serde_json::to_string(target).unwrap();
        let back: AlignmentTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*target, back);
    }
}

#[test]
fn test_alignment_target_ordering() {
    assert!(AlignmentTarget::Natural < AlignmentTarget::CacheLine);
    assert!(AlignmentTarget::CacheLine < AlignmentTarget::PageBoundary);
    assert!(AlignmentTarget::PageBoundary < AlignmentTarget::ExplicitBytes);
}

// ---------------------------------------------------------------------------
// AlignmentStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_alignment_strategy_natural_constructor() {
    let a = AlignmentStrategy::natural();
    assert_eq!(a.target, AlignmentTarget::Natural);
    assert_eq!(a.alignment_bytes, 1);
    assert_eq!(a.max_padding_bytes, 0);
    assert!(!a.allow_nop_padding);
}

#[test]
fn test_alignment_strategy_cache_line_constructor() {
    let a = AlignmentStrategy::cache_line(64);
    assert_eq!(a.target, AlignmentTarget::CacheLine);
    assert_eq!(a.alignment_bytes, 64);
    assert_eq!(a.max_padding_bytes, 63);
    assert!(a.allow_nop_padding);
}

#[test]
fn test_alignment_strategy_page_boundary_constructor() {
    let a = AlignmentStrategy::page_boundary(4096);
    assert_eq!(a.target, AlignmentTarget::PageBoundary);
    assert_eq!(a.alignment_bytes, 4096);
    assert_eq!(a.max_padding_bytes, 4095);
    assert!(a.allow_nop_padding);
}

#[test]
fn test_alignment_strategy_explicit_constructor() {
    let a = AlignmentStrategy::explicit(32, 16);
    assert_eq!(a.target, AlignmentTarget::ExplicitBytes);
    assert_eq!(a.alignment_bytes, 32);
    assert_eq!(a.max_padding_bytes, 16);
    assert!(a.allow_nop_padding);
}

#[test]
fn test_alignment_strategy_is_power_of_two() {
    assert!(AlignmentStrategy::natural().is_power_of_two());
    assert!(AlignmentStrategy::cache_line(64).is_power_of_two());
    assert!(AlignmentStrategy::page_boundary(4096).is_power_of_two());
    assert!(!AlignmentStrategy::explicit(48, 16).is_power_of_two());
    assert!(!AlignmentStrategy::explicit(0, 0).is_power_of_two());
}

#[test]
fn test_alignment_strategy_padding_for_aligned() {
    let a = AlignmentStrategy::cache_line(64);
    assert_eq!(a.padding_for(0), Some(0));
    assert_eq!(a.padding_for(64), Some(0));
    assert_eq!(a.padding_for(128), Some(0));
    assert_eq!(a.padding_for(256), Some(0));
}

#[test]
fn test_alignment_strategy_padding_for_misaligned() {
    let a = AlignmentStrategy::cache_line(64);
    assert_eq!(a.padding_for(1), Some(63));
    assert_eq!(a.padding_for(100), Some(28)); // 128 - 100
    assert_eq!(a.padding_for(63), Some(1));
    assert_eq!(a.padding_for(65), Some(63)); // next is 128
}

#[test]
fn test_alignment_strategy_padding_for_zero_alignment() {
    let a = AlignmentStrategy::explicit(0, 0);
    assert_eq!(a.padding_for(42), None);
    assert_eq!(a.padding_for(0), None);
}

#[test]
fn test_alignment_strategy_exceeds_budget() {
    let a = AlignmentStrategy::cache_line(64);
    assert!(!a.exceeds_budget(0));
    assert!(!a.exceeds_budget(63));
    assert!(a.exceeds_budget(64));
    assert!(a.exceeds_budget(100));
}

#[test]
fn test_alignment_strategy_default_is_natural() {
    let a = AlignmentStrategy::default();
    assert_eq!(a, AlignmentStrategy::natural());
}

#[test]
fn test_alignment_strategy_display() {
    let a = AlignmentStrategy::cache_line(64);
    let s = a.to_string();
    assert!(s.contains("cache_line"));
    assert!(s.contains("64B"));
    assert!(s.contains("max_pad=63B"));
}

#[test]
fn test_alignment_strategy_serde_round_trip() {
    let strategies = vec![
        AlignmentStrategy::natural(),
        AlignmentStrategy::cache_line(64),
        AlignmentStrategy::page_boundary(4096),
        AlignmentStrategy::explicit(128, 64),
    ];
    for strategy in &strategies {
        let json = serde_json::to_string(strategy).unwrap();
        let back: AlignmentStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strategy, back);
    }
}

// ---------------------------------------------------------------------------
// PlatformId
// ---------------------------------------------------------------------------

#[test]
fn test_platform_id_new_and_as_str() {
    let p = PlatformId::new("x86_64_v3");
    assert_eq!(p.as_str(), "x86_64_v3");
}

#[test]
fn test_platform_id_display() {
    let p = PlatformId::new("aarch64");
    assert_eq!(p.to_string(), "platform:aarch64");
}

#[test]
fn test_platform_id_serde_round_trip() {
    let p = PlatformId::new("riscv64");
    let json = serde_json::to_string(&p).unwrap();
    let back: PlatformId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// RegionId
// ---------------------------------------------------------------------------

#[test]
fn test_region_id_new_and_as_str() {
    let r = RegionId::new("main_loop");
    assert_eq!(r.as_str(), "main_loop");
}

#[test]
fn test_region_id_display() {
    let r = RegionId::new("hot_path");
    assert_eq!(r.to_string(), "region:hot_path");
}

#[test]
fn test_region_id_serde_round_trip() {
    let r = RegionId::new("cold_code");
    let json = serde_json::to_string(&r).unwrap();
    let back: RegionId = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// RegionHeat
// ---------------------------------------------------------------------------

#[test]
fn test_region_heat_all_variants_complete() {
    assert_eq!(RegionHeat::ALL.len(), 4);
    assert_eq!(RegionHeat::ALL[0], RegionHeat::Cold);
    assert_eq!(RegionHeat::ALL[3], RegionHeat::Traced);
}

#[test]
fn test_region_heat_as_str_and_display() {
    let expected = [
        (RegionHeat::Cold, "cold"),
        (RegionHeat::Warm, "warm"),
        (RegionHeat::Hot, "hot"),
        (RegionHeat::Traced, "traced"),
    ];
    for (heat, s) in &expected {
        assert_eq!(heat.as_str(), *s);
        assert_eq!(heat.to_string(), *s);
    }
}

#[test]
fn test_region_heat_rank_monotonically_increasing() {
    let ranks: Vec<u32> = RegionHeat::ALL.iter().map(|h| h.rank()).collect();
    for w in ranks.windows(2) {
        assert!(w[0] < w[1], "rank should be strictly increasing");
    }
}

#[test]
fn test_region_heat_serde_round_trip() {
    for heat in RegionHeat::ALL {
        let json = serde_json::to_string(heat).unwrap();
        let back: RegionHeat = serde_json::from_str(&json).unwrap();
        assert_eq!(*heat, back);
    }
}

// ---------------------------------------------------------------------------
// CodeRegion
// ---------------------------------------------------------------------------

#[test]
fn test_code_region_new_defaults() {
    let r = CodeRegion::new("r1", RegionHeat::Cold, 128);
    assert_eq!(r.id.as_str(), "r1");
    assert_eq!(r.heat, RegionHeat::Cold);
    assert_eq!(r.size_bytes, 128);
    assert_eq!(r.base_address, 0);
    assert_eq!(r.execution_count, 0);
    assert!(!r.is_loop_header);
    assert!(!r.is_function_entry);
}

#[test]
fn test_code_region_builder_chain() {
    let r = CodeRegion::new("loop1", RegionHeat::Hot, 256)
        .with_base_address(0x2000)
        .with_execution_count(50_000)
        .with_loop_header(true)
        .with_function_entry(true);
    assert_eq!(r.base_address, 0x2000);
    assert_eq!(r.execution_count, 50_000);
    assert!(r.is_loop_header);
    assert!(r.is_function_entry);
}

#[test]
fn test_code_region_display() {
    let r = CodeRegion::new("fn_entry", RegionHeat::Hot, 512).with_execution_count(1000);
    let s = r.to_string();
    assert!(s.contains("fn_entry"));
    assert!(s.contains("hot"));
    assert!(s.contains("512B"));
    assert!(s.contains("exec=1000"));
}

#[test]
fn test_code_region_serde_round_trip() {
    let r = CodeRegion::new("test_region", RegionHeat::Traced, 1024)
        .with_base_address(0x4000)
        .with_execution_count(999)
        .with_loop_header(true)
        .with_function_entry(false);
    let json = serde_json::to_string(&r).unwrap();
    let back: CodeRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// StallKind
// ---------------------------------------------------------------------------

#[test]
fn test_stall_kind_all_variants() {
    assert_eq!(StallKind::ALL.len(), 5);
    let expected_strs = [
        "instruction_fetch",
        "icache_miss",
        "itlb_miss",
        "btb_miss",
        "decode_stall",
    ];
    for (kind, s) in StallKind::ALL.iter().zip(expected_strs.iter()) {
        assert_eq!(kind.as_str(), *s);
        assert_eq!(kind.to_string(), *s);
    }
}

#[test]
fn test_stall_kind_serde_round_trip() {
    for kind in StallKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: StallKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// StallEvent
// ---------------------------------------------------------------------------

#[test]
fn test_stall_event_new_defaults() {
    let e = StallEvent::new(StallKind::ICacheMiss, "loop1", 12);
    assert_eq!(e.kind, StallKind::ICacheMiss);
    assert_eq!(e.region_id.as_str(), "loop1");
    assert_eq!(e.cost_cycles, 12);
    assert_eq!(e.offset, 0);
}

#[test]
fn test_stall_event_with_offset() {
    let e = StallEvent::new(StallKind::BtbMiss, "fn1", 5).with_offset(42);
    assert_eq!(e.offset, 42);
    assert_eq!(e.cost_cycles, 5);
}

#[test]
fn test_stall_event_display() {
    let e = StallEvent::new(StallKind::DecodeStall, "r1", 8);
    let s = e.to_string();
    assert!(s.contains("decode_stall"));
    assert!(s.contains("r1"));
    assert!(s.contains("8cyc"));
}

#[test]
fn test_stall_event_serde_round_trip() {
    let e = StallEvent::new(StallKind::ITlbMiss, "region_a", 100).with_offset(64);
    let json = serde_json::to_string(&e).unwrap();
    let back: StallEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// StallBudget
// ---------------------------------------------------------------------------

#[test]
fn test_stall_budget_new_initial_state() {
    let b = StallBudget::new(200, 50);
    assert_eq!(b.max_stall_cycles, 200);
    assert_eq!(b.max_icache_misses, 50);
    assert_eq!(b.accumulated_cycles, 0);
    assert_eq!(b.accumulated_icache_misses, 0);
    assert!(b.counters.is_empty());
    assert!(b.events.is_empty());
    assert!(!b.gate_fires());
}

#[test]
fn test_stall_budget_default_values() {
    let b = StallBudget::default();
    assert_eq!(b.max_stall_cycles, DEFAULT_STALL_BUDGET_CYCLES);
    assert_eq!(b.max_icache_misses, DEFAULT_ICACHE_MISS_THRESHOLD);
}

#[test]
fn test_stall_budget_record_non_icache_event() {
    let mut b = StallBudget::new(100, 10);
    b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 20));
    assert_eq!(b.accumulated_cycles, 20);
    assert_eq!(b.accumulated_icache_misses, 0);
    assert_eq!(b.event_count(), 1);
    assert_eq!(b.counters.get("instruction_fetch"), Some(&1));
}

#[test]
fn test_stall_budget_record_icache_event_increments_counter() {
    let mut b = StallBudget::new(100, 10);
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 15));
    assert_eq!(b.accumulated_icache_misses, 1);
    assert_eq!(b.accumulated_cycles, 15);
}

#[test]
fn test_stall_budget_cycles_exhausted() {
    let mut b = StallBudget::new(50, 100);
    b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 30));
    assert!(!b.cycles_exhausted());
    b.record(StallEvent::new(StallKind::InstructionFetch, "r2", 20));
    assert!(b.cycles_exhausted());
    assert!(b.gate_fires());
}

#[test]
fn test_stall_budget_icache_exhausted() {
    let mut b = StallBudget::new(1000, 3);
    for i in 0..3 {
        b.record(StallEvent::new(StallKind::ICacheMiss, format!("r{i}"), 5));
    }
    assert!(b.icache_exhausted());
    assert!(b.gate_fires());
}

#[test]
fn test_stall_budget_remaining() {
    let mut b = StallBudget::new(100, 20);
    b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 30));
    b.record(StallEvent::new(StallKind::ICacheMiss, "r2", 10));
    assert_eq!(b.remaining_cycles(), 60);
    assert_eq!(b.remaining_icache_misses(), 19);
}

#[test]
fn test_stall_budget_cycle_utilisation_millionths() {
    let mut b = StallBudget::new(200, 10);
    b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 100));
    assert_eq!(b.cycle_utilisation_millionths(), 500_000);
}

#[test]
fn test_stall_budget_cycle_utilisation_zero_budget() {
    let b = StallBudget::new(0, 10);
    assert_eq!(b.cycle_utilisation_millionths(), MILLION);
}

#[test]
fn test_stall_budget_reset_clears_all() {
    let mut b = StallBudget::new(100, 10);
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 50));
    b.record(StallEvent::new(StallKind::BtbMiss, "r2", 20));
    b.reset();
    assert_eq!(b.accumulated_cycles, 0);
    assert_eq!(b.accumulated_icache_misses, 0);
    assert_eq!(b.event_count(), 0);
    assert!(b.counters.is_empty());
    assert!(!b.gate_fires());
}

#[test]
fn test_stall_budget_content_hash_deterministic() {
    let b1 = StallBudget::new(100, 10);
    let b2 = StallBudget::new(100, 10);
    assert_eq!(b1.content_hash(), b2.content_hash());

    let b3 = StallBudget::new(200, 10);
    assert_ne!(b1.content_hash(), b3.content_hash());
}

#[test]
fn test_stall_budget_display() {
    let mut b = StallBudget::new(100, 10);
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 30));
    let s = b.to_string();
    assert!(s.contains("stall_budget"));
    assert!(s.contains("30/100"));
    assert!(s.contains("1/10"));
}

#[test]
fn test_stall_budget_serde_round_trip() {
    let mut b = StallBudget::new(256, 64);
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 20));
    let json = serde_json::to_string(&b).unwrap();
    let back: StallBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// PlatformRule
// ---------------------------------------------------------------------------

#[test]
fn test_platform_rule_new_defaults() {
    let r = PlatformRule::new("aarch64_v8", AlignmentStrategy::cache_line(64));
    assert_eq!(r.platform_id.as_str(), "aarch64_v8");
    assert_eq!(r.alignment.target, AlignmentTarget::CacheLine);
    assert_eq!(r.cache_line_bytes, DEFAULT_CACHE_LINE_BYTES);
    assert_eq!(r.page_size_bytes, DEFAULT_PAGE_SIZE_BYTES);
    assert!(!r.pinned);
    assert!(!r.rolled_back);
    assert!(r.rationale.is_empty());
    assert!(r.is_generalisable());
}

#[test]
fn test_platform_rule_pin_and_unpin() {
    let mut r = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    r.pin("Performance critical");
    assert!(r.pinned);
    assert!(!r.is_generalisable());
    assert_eq!(r.rationale, "Performance critical");

    r.generalise();
    assert!(!r.pinned);
    // rationale persists
    assert_eq!(r.rationale, "Performance critical");
}

#[test]
fn test_platform_rule_rollback() {
    let mut r = PlatformRule::new("x86_64", AlignmentStrategy::page_boundary(4096));
    r.rollback("Regression detected");
    assert!(r.rolled_back);
    assert_eq!(r.alignment.target, AlignmentTarget::Natural);
    assert!(!r.is_generalisable());
    assert_eq!(r.rationale, "Regression detected");
}

#[test]
fn test_platform_rule_display_pinned() {
    let mut r = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    r.pin("test");
    let s = r.to_string();
    assert!(s.contains("x86_64"));
    assert!(s.contains("pinned"));
}

#[test]
fn test_platform_rule_display_rolled_back() {
    let mut r = PlatformRule::new("arm64", AlignmentStrategy::cache_line(64));
    r.rollback("regressed");
    let s = r.to_string();
    assert!(s.contains("rolled_back"));
}

#[test]
fn test_platform_rule_display_active() {
    let r = PlatformRule::new("riscv64", AlignmentStrategy::natural());
    let s = r.to_string();
    assert!(s.contains("active"));
}

#[test]
fn test_platform_rule_serde_round_trip() {
    let mut r = PlatformRule::new("x86_64", AlignmentStrategy::page_boundary(4096));
    r.pin("pinned for perf");
    let json = serde_json::to_string(&r).unwrap();
    let back: PlatformRule = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// LayoutPolicyState
// ---------------------------------------------------------------------------

#[test]
fn test_layout_policy_state_all_variants() {
    assert_eq!(LayoutPolicyState::ALL.len(), 5);
    let expected = ["draft", "active", "rolled_back", "superseded", "archived"];
    for (state, s) in LayoutPolicyState::ALL.iter().zip(expected.iter()) {
        assert_eq!(state.as_str(), *s);
        assert_eq!(state.to_string(), *s);
    }
}

#[test]
fn test_layout_policy_state_is_operational() {
    assert!(LayoutPolicyState::Draft.is_operational());
    assert!(LayoutPolicyState::Active.is_operational());
    assert!(!LayoutPolicyState::RolledBack.is_operational());
    assert!(!LayoutPolicyState::Superseded.is_operational());
    assert!(!LayoutPolicyState::Archived.is_operational());
}

#[test]
fn test_layout_policy_state_serde_round_trip() {
    for state in LayoutPolicyState::ALL {
        let json = serde_json::to_string(state).unwrap();
        let back: LayoutPolicyState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ---------------------------------------------------------------------------
// LayoutPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_layout_policy_new_defaults() {
    let p = make_policy("test_pol");
    assert_eq!(p.policy_id, "test_pol");
    assert_eq!(p.state, LayoutPolicyState::Draft);
    assert_eq!(p.epoch, test_epoch());
    assert_eq!(p.default_alignment.target, AlignmentTarget::CacheLine);
    assert!(p.platform_rules.is_empty());
    assert_eq!(p.alignment_budget_bytes, MAX_ALIGNMENT_BUDGET_BYTES);
    assert_eq!(p.padding_spent_bytes, 0);
    assert_eq!(
        p.regression_threshold_millionths,
        DEFAULT_REGRESSION_THRESHOLD
    );
    assert!(p.regions.is_empty());
    assert!(p.tags.is_empty());
}

#[test]
fn test_layout_policy_activate() {
    let mut p = make_policy("p1");
    assert_eq!(p.state, LayoutPolicyState::Draft);
    p.activate();
    assert_eq!(p.state, LayoutPolicyState::Active);
}

#[test]
fn test_layout_policy_add_platform_rule() {
    let mut p = make_policy("p1");
    p.add_platform_rule(PlatformRule::new(
        "arm64",
        AlignmentStrategy::page_boundary(4096),
    ));
    assert_eq!(p.platform_rules.len(), 1);
    p.add_platform_rule(PlatformRule::new(
        "x86_64",
        AlignmentStrategy::cache_line(64),
    ));
    assert_eq!(p.platform_rules.len(), 2);
}

#[test]
fn test_layout_policy_add_region_respects_max() {
    let mut p = make_policy("p1");
    for i in 0..10 {
        p.add_region(CodeRegion::new(format!("r{i}"), RegionHeat::Cold, 64));
    }
    assert_eq!(p.regions.len(), 10);
}

#[test]
fn test_layout_policy_effective_alignment_default_fallback() {
    let p = make_policy("p1");
    let a = p.effective_alignment("unknown_platform");
    assert_eq!(a.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_layout_policy_effective_alignment_platform_override() {
    let mut p = make_policy("p1");
    p.add_platform_rule(PlatformRule::new(
        "arm64",
        AlignmentStrategy::page_boundary(4096),
    ));
    let a = p.effective_alignment("arm64");
    assert_eq!(a.target, AlignmentTarget::PageBoundary);
}

#[test]
fn test_layout_policy_effective_alignment_skips_rolled_back_rule() {
    let mut p = make_policy("p1");
    let mut rule = PlatformRule::new("arm64", AlignmentStrategy::page_boundary(4096));
    rule.rollback("regressed");
    p.add_platform_rule(rule);
    // Falls back to default since the rule is rolled back
    let a = p.effective_alignment("arm64");
    assert_eq!(a.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_layout_policy_budget_exhausted() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 100;
    assert!(!p.budget_exhausted());
    p.padding_spent_bytes = 100;
    assert!(p.budget_exhausted());
    p.padding_spent_bytes = 200;
    assert!(p.budget_exhausted());
}

#[test]
fn test_layout_policy_remaining_budget() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 100;
    p.padding_spent_bytes = 40;
    assert_eq!(p.remaining_budget(), 60);
}

#[test]
fn test_layout_policy_spend_padding() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 100;
    assert!(p.spend_padding(50));
    assert_eq!(p.padding_spent_bytes, 50);
    assert!(!p.spend_padding(60)); // total 110 > 100
    assert!(p.budget_exhausted());
}

#[test]
fn test_layout_policy_budget_utilisation_millionths() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 200;
    p.padding_spent_bytes = 100;
    assert_eq!(p.budget_utilisation_millionths(), 500_000);
}

#[test]
fn test_layout_policy_budget_utilisation_zero_budget() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 0;
    assert_eq!(p.budget_utilisation_millionths(), MILLION);
}

#[test]
fn test_layout_policy_hot_region_count() {
    let mut p = make_policy("p1");
    p.add_region(CodeRegion::new("r1", RegionHeat::Cold, 64));
    p.add_region(CodeRegion::new("r2", RegionHeat::Warm, 64));
    p.add_region(CodeRegion::new("r3", RegionHeat::Hot, 64));
    p.add_region(CodeRegion::new("r4", RegionHeat::Traced, 64));
    assert_eq!(p.hot_region_count(), 2); // Hot + Traced
}

#[test]
fn test_layout_policy_total_code_bytes() {
    let mut p = make_policy("p1");
    p.add_region(CodeRegion::new("r1", RegionHeat::Cold, 64));
    p.add_region(CodeRegion::new("r2", RegionHeat::Hot, 128));
    p.add_region(CodeRegion::new("r3", RegionHeat::Traced, 256));
    assert_eq!(p.total_code_bytes(), 448);
}

#[test]
fn test_layout_policy_content_hash_deterministic() {
    let p1 = make_policy("p1");
    let p2 = make_policy("p1");
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn test_layout_policy_content_hash_differs_for_different_ids() {
    let p1 = make_policy("p1");
    let p2 = make_policy("p2");
    assert_ne!(p1.content_hash(), p2.content_hash());
}

#[test]
fn test_layout_policy_display() {
    let p = make_policy("pol_42");
    let s = p.to_string();
    assert!(s.contains("pol_42"));
    assert!(s.contains("draft"));
    assert!(s.contains("regions=0"));
}

#[test]
fn test_layout_policy_serde_round_trip() {
    let mut p = make_active_policy("serde_test");
    p.add_platform_rule(PlatformRule::new(
        "x86_64",
        AlignmentStrategy::cache_line(64),
    ));
    p.add_region(CodeRegion::new("r1", RegionHeat::Hot, 256));
    p.tags.insert("hot_path".to_string());
    let json = serde_json::to_string(&p).unwrap();
    let back: LayoutPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// LayoutDecisionKind
// ---------------------------------------------------------------------------

#[test]
fn test_layout_decision_kind_all_variants() {
    assert_eq!(LayoutDecisionKind::ALL.len(), 7);
    let expected = [
        "align_cache_line",
        "align_page_boundary",
        "keep_natural",
        "cold_pack",
        "split_boundary",
        "budget_exhausted",
        "rolled_back",
    ];
    for (kind, s) in LayoutDecisionKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.as_str(), *s);
        assert_eq!(kind.to_string(), *s);
    }
}

#[test]
fn test_layout_decision_kind_serde_round_trip() {
    for kind in LayoutDecisionKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: LayoutDecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// LayoutDecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_new_populates_all_fields() {
    let r = LayoutDecisionReceipt::new(
        "loop1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        28,
        "x86_64",
        test_epoch(),
        "hot loop aligned",
    );
    assert_eq!(r.region_id.as_str(), "loop1");
    assert_eq!(r.kind, LayoutDecisionKind::AlignCacheLine);
    assert_eq!(r.alignment.target, AlignmentTarget::CacheLine);
    assert_eq!(r.padding_bytes, 28);
    assert_eq!(r.platform_id.as_str(), "x86_64");
    assert_eq!(r.epoch, test_epoch());
    assert_eq!(r.rationale, "hot loop aligned");
}

#[test]
fn test_receipt_hash_is_deterministic() {
    let r1 = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::KeepNatural,
        AlignmentStrategy::natural(),
        0,
        "p",
        SecurityEpoch::GENESIS,
        "test",
    );
    let r2 = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::KeepNatural,
        AlignmentStrategy::natural(),
        0,
        "p",
        SecurityEpoch::GENESIS,
        "test",
    );
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_for_different_inputs() {
    let r1 = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::KeepNatural,
        AlignmentStrategy::natural(),
        0,
        "p",
        SecurityEpoch::GENESIS,
        "test",
    );
    let r2 = LayoutDecisionReceipt::new(
        "r2",
        LayoutDecisionKind::KeepNatural,
        AlignmentStrategy::natural(),
        0,
        "p",
        SecurityEpoch::GENESIS,
        "test",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_hex_is_valid_hex() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::ColdPack,
        AlignmentStrategy::natural(),
        0,
        "arm64",
        SecurityEpoch::GENESIS,
        "cold",
    );
    let hex = r.receipt_hash_hex();
    assert!(!hex.is_empty());
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_receipt_display() {
    let r = LayoutDecisionReceipt::new(
        "r1",
        LayoutDecisionKind::ColdPack,
        AlignmentStrategy::natural(),
        0,
        "arm64",
        SecurityEpoch::GENESIS,
        "cold",
    );
    let s = r.to_string();
    assert!(s.contains("r1"));
    assert!(s.contains("cold_pack"));
    assert!(s.contains("pad=0B"));
    assert!(s.contains("hash="));
}

#[test]
fn test_receipt_serde_round_trip() {
    let r = LayoutDecisionReceipt::new(
        "loop1",
        LayoutDecisionKind::AlignCacheLine,
        AlignmentStrategy::cache_line(64),
        28,
        "x86_64",
        test_epoch(),
        "aligned",
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: LayoutDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// RollbackReason
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_reason_all_variants() {
    assert_eq!(RollbackReason::ALL.len(), 6);
    let expected = [
        "performance_regression",
        "stall_budget_exhausted",
        "alignment_budget_overflow",
        "parity_failure",
        "operator_override",
        "platform_rule_invalidated",
    ];
    for (reason, s) in RollbackReason::ALL.iter().zip(expected.iter()) {
        assert_eq!(reason.as_str(), *s);
        assert_eq!(reason.to_string(), *s);
    }
}

#[test]
fn test_rollback_reason_serde_round_trip() {
    for reason in RollbackReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: RollbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_record_regression_case() {
    let r = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "pol1",
        test_epoch(),
        MILLION,
        900_000,
    );
    assert!(r.is_regression());
    assert_eq!(r.perf_delta_millionths(), -100_000);
    assert_eq!(r.policy_id, "pol1");
}

#[test]
fn test_rollback_record_improvement_case() {
    let r = RollbackRecord::new(
        RollbackReason::OperatorOverride,
        "pol1",
        test_epoch(),
        MILLION,
        MILLION + 100,
    );
    assert!(!r.is_regression());
    assert_eq!(r.perf_delta_millionths(), 100);
}

#[test]
fn test_rollback_record_zero_baseline() {
    let r = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "pol1",
        test_epoch(),
        0,
        500_000,
    );
    assert_eq!(r.perf_delta_millionths(), 0);
}

#[test]
fn test_rollback_record_equal_perf() {
    let r = RollbackRecord::new(
        RollbackReason::PerformanceRegression,
        "pol1",
        test_epoch(),
        MILLION,
        MILLION,
    );
    assert!(!r.is_regression());
    assert_eq!(r.perf_delta_millionths(), 0);
}

#[test]
fn test_rollback_record_hash_deterministic() {
    let r1 = RollbackRecord::new(RollbackReason::ParityFailure, "p", test_epoch(), 100, 50);
    let r2 = RollbackRecord::new(RollbackReason::ParityFailure, "p", test_epoch(), 100, 50);
    assert_eq!(r1.record_hash, r2.record_hash);
}

#[test]
fn test_rollback_record_display() {
    let r = RollbackRecord::new(
        RollbackReason::StallBudgetExhausted,
        "pol1",
        test_epoch(),
        MILLION,
        0,
    );
    let s = r.to_string();
    assert!(s.contains("stall_budget_exhausted"));
    assert!(s.contains("pol1"));
}

#[test]
fn test_rollback_record_serde_round_trip() {
    let r = RollbackRecord::new(
        RollbackReason::AlignmentBudgetOverflow,
        "test_pol",
        SecurityEpoch::from_raw(5),
        800_000,
        700_000,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// RollbackGate
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_gate_default() {
    let g = RollbackGate::default();
    assert_eq!(g.threshold_millionths, DEFAULT_REGRESSION_THRESHOLD);
    assert!(!g.fired);
    assert_eq!(g.rollback_count(), 0);
}

#[test]
fn test_rollback_gate_custom_threshold() {
    let g = RollbackGate::new(100_000);
    assert_eq!(g.threshold_millionths, 100_000);
}

#[test]
fn test_rollback_gate_threshold_clamped_to_million() {
    let g = RollbackGate::new(2_000_000);
    assert_eq!(g.threshold_millionths, MILLION);
}

#[test]
fn test_rollback_gate_no_regression() {
    let mut g = RollbackGate::new(50_000);
    let result = g.evaluate("p1", test_epoch(), MILLION, MILLION);
    assert!(result.is_none());
    assert!(!g.fired);
}

#[test]
fn test_rollback_gate_within_threshold() {
    let mut g = RollbackGate::new(50_000); // 5%
    let result = g.evaluate("p1", test_epoch(), MILLION, 960_000); // 4% drop
    assert!(result.is_none());
    assert!(!g.fired);
}

#[test]
fn test_rollback_gate_detects_regression() {
    let mut g = RollbackGate::new(50_000); // 5%
    let result = g.evaluate("p1", test_epoch(), MILLION, 900_000); // 10% drop
    assert!(result.is_some());
    assert!(g.fired);
    assert_eq!(g.rollback_count(), 1);
    let rec = result.unwrap();
    assert_eq!(rec.reason, RollbackReason::PerformanceRegression);
}

#[test]
fn test_rollback_gate_zero_baseline_no_regression() {
    let mut g = RollbackGate::new(50_000);
    let result = g.evaluate("p1", test_epoch(), 0, 100);
    assert!(result.is_none());
}

#[test]
fn test_rollback_gate_record_non_perf_rollback() {
    let mut g = RollbackGate::new(50_000);
    let record = RollbackRecord::new(
        RollbackReason::ParityFailure,
        "p1",
        test_epoch(),
        MILLION,
        0,
    );
    g.record_rollback(record);
    assert!(g.fired);
    assert_eq!(g.rollback_count(), 1);
}

#[test]
fn test_rollback_gate_multiple_rollbacks() {
    let mut g = RollbackGate::new(50_000);
    g.evaluate("p1", test_epoch(), MILLION, 800_000);
    g.evaluate("p1", test_epoch(), MILLION, 700_000);
    assert_eq!(g.rollback_count(), 2);
}

#[test]
fn test_rollback_gate_reset() {
    let mut g = RollbackGate::new(50_000);
    g.record_rollback(RollbackRecord::new(
        RollbackReason::OperatorOverride,
        "p1",
        test_epoch(),
        MILLION,
        0,
    ));
    g.reset();
    assert!(!g.fired);
    assert_eq!(g.rollback_count(), 0);
}

#[test]
fn test_rollback_gate_display() {
    let g = RollbackGate::new(50_000);
    let s = g.to_string();
    assert!(s.contains("rollback_gate"));
    assert!(s.contains("50000"));
    assert!(s.contains("fired=false"));
}

#[test]
fn test_rollback_gate_serde_round_trip() {
    let mut g = RollbackGate::new(75_000);
    g.record_rollback(RollbackRecord::new(
        RollbackReason::OperatorOverride,
        "p1",
        test_epoch(),
        MILLION,
        500_000,
    ));
    let json = serde_json::to_string(&g).unwrap();
    let back: RollbackGate = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_all_variants() {
    assert_eq!(ParityVerdict::ALL.len(), 4);
    let expected = [
        "equivalent",
        "within_tolerance",
        "divergent",
        "inconclusive",
    ];
    for (v, s) in ParityVerdict::ALL.iter().zip(expected.iter()) {
        assert_eq!(v.as_str(), *s);
        assert_eq!(v.to_string(), *s);
    }
}

#[test]
fn test_parity_verdict_allows_layout() {
    assert!(ParityVerdict::Equivalent.allows_layout());
    assert!(ParityVerdict::WithinTolerance.allows_layout());
    assert!(!ParityVerdict::Divergent.allows_layout());
    assert!(!ParityVerdict::Inconclusive.allows_layout());
}

#[test]
fn test_parity_verdict_serde_round_trip() {
    for v in ParityVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// ParityCheckResult
// ---------------------------------------------------------------------------

#[test]
fn test_parity_check_result_new() {
    let h1 = hash_of(b"ref");
    let h2 = hash_of(b"candidate");
    let r = ParityCheckResult::new(
        "r1",
        ParityVerdict::Divergent,
        h1.clone(),
        h2.clone(),
        10_000,
    );
    assert_eq!(r.region_id.as_str(), "r1");
    assert_eq!(r.verdict, ParityVerdict::Divergent);
    assert_eq!(r.reference_hash, h1);
    assert_eq!(r.candidate_hash, h2);
    assert_eq!(r.tolerance_millionths, 10_000);
    assert!(r.notes.is_empty());
}

#[test]
fn test_parity_check_result_with_notes() {
    let h = hash_of(b"data");
    let r = ParityCheckResult::new("r1", ParityVerdict::Equivalent, h.clone(), h, 0)
        .with_notes("Exact match");
    assert_eq!(r.notes, "Exact match");
}

#[test]
fn test_parity_check_result_display() {
    let h = hash_of(b"data");
    let r = ParityCheckResult::new(
        "region_a",
        ParityVerdict::WithinTolerance,
        h.clone(),
        h,
        5000,
    );
    let s = r.to_string();
    assert!(s.contains("region_a"));
    assert!(s.contains("within_tolerance"));
}

#[test]
fn test_parity_check_result_serde_round_trip() {
    let h1 = hash_of(b"ref_data");
    let h2 = hash_of(b"cand_data");
    let r = ParityCheckResult::new("r1", ParityVerdict::Divergent, h1, h2, 10_000)
        .with_notes("mismatch in output");
    let json = serde_json::to_string(&r).unwrap();
    let back: ParityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ParityChecker
// ---------------------------------------------------------------------------

#[test]
fn test_parity_checker_default() {
    let pc = ParityChecker::default();
    assert_eq!(pc.tolerance_millionths, 10_000);
    assert_eq!(pc.check_count(), 0);
    assert!(pc.all_passed());
    assert_eq!(pc.divergent_count(), 0);
}

#[test]
fn test_parity_checker_custom_tolerance() {
    let pc = ParityChecker::new(50_000);
    assert_eq!(pc.tolerance_millionths, 50_000);
}

#[test]
fn test_parity_checker_tolerance_clamped() {
    let pc = ParityChecker::new(2_000_000);
    assert_eq!(pc.tolerance_millionths, MILLION);
}

#[test]
fn test_parity_checker_check_equivalent() {
    let mut pc = ParityChecker::default();
    let h = hash_of(b"same_output");
    let verdict = pc.check("r1", h.clone(), h);
    assert_eq!(verdict, ParityVerdict::Equivalent);
    assert!(pc.all_passed());
    assert_eq!(pc.check_count(), 1);
    assert_eq!(pc.divergent_count(), 0);
}

#[test]
fn test_parity_checker_check_divergent() {
    let mut pc = ParityChecker::default();
    let h1 = hash_of(b"output_a");
    let h2 = hash_of(b"output_b");
    let verdict = pc.check("r1", h1, h2);
    assert_eq!(verdict, ParityVerdict::Divergent);
    assert!(!pc.all_passed());
    assert_eq!(pc.divergent_count(), 1);
}

#[test]
fn test_parity_checker_record_explicit_verdict() {
    let mut pc = ParityChecker::default();
    let h = hash_of(b"data");
    pc.record("r1", ParityVerdict::WithinTolerance, h.clone(), h);
    assert!(pc.all_passed());
    assert_eq!(pc.check_count(), 1);
}

#[test]
fn test_parity_checker_record_inconclusive() {
    let mut pc = ParityChecker::default();
    let h = hash_of(b"data");
    pc.record("r1", ParityVerdict::Inconclusive, h.clone(), h);
    // Inconclusive does not allow layout
    assert!(!pc.all_passed());
    assert_eq!(pc.divergent_count(), 0); // but not counted as divergent
}

#[test]
fn test_parity_checker_mixed_results() {
    let mut pc = ParityChecker::default();
    let h = hash_of(b"same");
    let h2 = hash_of(b"different");
    pc.check("r1", h.clone(), h.clone());
    pc.check("r2", h.clone(), h2);
    assert!(!pc.all_passed());
    assert_eq!(pc.check_count(), 2);
    assert_eq!(pc.divergent_count(), 1);
}

#[test]
fn test_parity_checker_reset() {
    let mut pc = ParityChecker::default();
    let h = hash_of(b"data");
    pc.check("r1", h.clone(), h);
    pc.reset();
    assert_eq!(pc.check_count(), 0);
    assert!(pc.all_passed());
}

#[test]
fn test_parity_checker_display() {
    let pc = ParityChecker::new(20_000);
    let s = pc.to_string();
    assert!(s.contains("parity_checker"));
    assert!(s.contains("20000"));
    assert!(s.contains("checks=0"));
    assert!(s.contains("divergent=0"));
}

#[test]
fn test_parity_checker_serde_round_trip() {
    let mut pc = ParityChecker::new(15_000);
    let h = hash_of(b"test");
    pc.check("r1", h.clone(), h);
    let json = serde_json::to_string(&pc).unwrap();
    let back: ParityChecker = serde_json::from_str(&json).unwrap();
    assert_eq!(pc, back);
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_severity_all_variants() {
    assert_eq!(DiagnosticSeverity::ALL.len(), 4);
    let expected = ["info", "warning", "error", "critical"];
    for (sev, s) in DiagnosticSeverity::ALL.iter().zip(expected.iter()) {
        assert_eq!(sev.as_str(), *s);
        assert_eq!(sev.to_string(), *s);
    }
}

#[test]
fn test_diagnostic_severity_ordering() {
    assert!(DiagnosticSeverity::Info < DiagnosticSeverity::Warning);
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Critical);
}

#[test]
fn test_diagnostic_severity_serde_round_trip() {
    for sev in DiagnosticSeverity::ALL {
        let json = serde_json::to_string(sev).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

// ---------------------------------------------------------------------------
// LayoutDiagnostic
// ---------------------------------------------------------------------------

#[test]
fn test_layout_diagnostic_new_defaults() {
    let d = LayoutDiagnostic::new(DiagnosticSeverity::Warning, "Budget low", "Only 10% left");
    assert_eq!(d.severity, DiagnosticSeverity::Warning);
    assert_eq!(d.summary, "Budget low");
    assert_eq!(d.detail, "Only 10% left");
    assert!(d.region_id.is_none());
    assert!(d.platform_id.is_none());
    assert!(d.suggested_action.is_empty());
}

#[test]
fn test_layout_diagnostic_builders() {
    let d = LayoutDiagnostic::new(DiagnosticSeverity::Error, "fail", "detail")
        .with_region("hot_loop")
        .with_platform("arm64")
        .with_action("Investigate alignment");
    assert_eq!(d.region_id.as_ref().unwrap().as_str(), "hot_loop");
    assert_eq!(d.platform_id.as_ref().unwrap().as_str(), "arm64");
    assert_eq!(d.suggested_action, "Investigate alignment");
}

#[test]
fn test_layout_diagnostic_display() {
    let d = LayoutDiagnostic::new(DiagnosticSeverity::Critical, "Crash imminent", "");
    let s = d.to_string();
    assert!(s.contains("[critical]"));
    assert!(s.contains("Crash imminent"));
}

#[test]
fn test_layout_diagnostic_serde_round_trip() {
    let d = LayoutDiagnostic::new(DiagnosticSeverity::Info, "All good", "No issues found")
        .with_region("r1")
        .with_platform("x86_64")
        .with_action("None needed");
    let json = serde_json::to_string(&d).unwrap();
    let back: LayoutDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_report_empty() {
    let r = DiagnosticReport::new("p1", test_epoch());
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(!r.has_errors());
    assert!(!r.has_critical());
    assert_eq!(r.policy_id, "p1");
    assert_eq!(r.epoch, test_epoch());
}

#[test]
fn test_diagnostic_report_add_and_count() {
    let mut r = DiagnosticReport::new("p1", test_epoch());
    r.add(LayoutDiagnostic::new(DiagnosticSeverity::Info, "ok", ""));
    r.add(LayoutDiagnostic::new(
        DiagnosticSeverity::Warning,
        "hmm",
        "",
    ));
    r.add(LayoutDiagnostic::new(DiagnosticSeverity::Error, "bad", ""));
    r.add(LayoutDiagnostic::new(
        DiagnosticSeverity::Critical,
        "crash",
        "",
    ));
    assert_eq!(r.len(), 4);
    assert_eq!(r.count_at_or_above(DiagnosticSeverity::Info), 4);
    assert_eq!(r.count_at_or_above(DiagnosticSeverity::Warning), 3);
    assert_eq!(r.count_at_or_above(DiagnosticSeverity::Error), 2);
    assert_eq!(r.count_at_or_above(DiagnosticSeverity::Critical), 1);
    assert!(r.has_errors());
    assert!(r.has_critical());
}

#[test]
fn test_diagnostic_report_no_errors_only_warnings() {
    let mut r = DiagnosticReport::new("p1", test_epoch());
    r.add(LayoutDiagnostic::new(DiagnosticSeverity::Warning, "w1", ""));
    r.add(LayoutDiagnostic::new(DiagnosticSeverity::Warning, "w2", ""));
    assert!(!r.has_errors());
    assert!(!r.has_critical());
}

#[test]
fn test_diagnostic_report_display() {
    let mut r = DiagnosticReport::new("policy_42", test_epoch());
    r.add(LayoutDiagnostic::new(DiagnosticSeverity::Error, "e", ""));
    let s = r.to_string();
    assert!(s.contains("policy_42"));
    assert!(s.contains("entries=1"));
    assert!(s.contains("errors=1"));
}

#[test]
fn test_diagnostic_report_serde_round_trip() {
    let mut r = DiagnosticReport::new("p1", test_epoch());
    r.add(LayoutDiagnostic::new(
        DiagnosticSeverity::Info,
        "ok",
        "detail",
    ));
    let json = serde_json::to_string(&r).unwrap();
    let back: DiagnosticReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// LayoutEvaluator — construction and selection
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_creation() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    assert_eq!(e.policy.state, LayoutPolicyState::Active);
    assert!(e.receipts.is_empty());
    assert!(!e.rollback_gate.fired);
    assert_eq!(e.parity_checker.check_count(), 0);
    assert!(e.diagnostics.is_empty());
}

#[test]
fn test_evaluator_select_alignment_cold_region() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("c1", RegionHeat::Cold, 64);
    let (align, kind) = e.select_alignment(&region, "x86_64");
    assert_eq!(kind, LayoutDecisionKind::ColdPack);
    assert_eq!(align.target, AlignmentTarget::Natural);
}

#[test]
fn test_evaluator_select_alignment_warm_region() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("w1", RegionHeat::Warm, 64);
    let (align, kind) = e.select_alignment(&region, "x86_64");
    assert_eq!(kind, LayoutDecisionKind::KeepNatural);
    assert_eq!(align.target, AlignmentTarget::Natural);
}

#[test]
fn test_evaluator_select_alignment_hot_region() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("h1", RegionHeat::Hot, 256);
    let (align, kind) = e.select_alignment(&region, "x86_64");
    assert_eq!(kind, LayoutDecisionKind::AlignCacheLine);
    assert_eq!(align.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_evaluator_select_alignment_traced_region() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("t1", RegionHeat::Traced, 512);
    let (_, kind) = e.select_alignment(&region, "x86_64");
    // Default policy uses cache-line alignment; traced should get page-boundary or cache-line
    assert!(
        kind == LayoutDecisionKind::AlignPageBoundary || kind == LayoutDecisionKind::AlignCacheLine
    );
}

#[test]
fn test_evaluator_select_alignment_budget_exhausted() {
    let mut policy = make_test_evaluator_policy();
    policy.alignment_budget_bytes = 0;
    let e = LayoutEvaluator::new(policy);
    let region = CodeRegion::new("h1", RegionHeat::Hot, 256);
    let (_, kind) = e.select_alignment(&region, "x86_64");
    assert_eq!(kind, LayoutDecisionKind::BudgetExhausted);
}

#[test]
fn test_evaluator_select_alignment_hot_with_page_boundary_platform() {
    let mut policy = make_test_evaluator_policy();
    policy.add_platform_rule(PlatformRule::new(
        "arm64",
        AlignmentStrategy::page_boundary(4096),
    ));
    let e = LayoutEvaluator::new(policy);
    let region = CodeRegion::new("h1", RegionHeat::Hot, 256);
    let (align, kind) = e.select_alignment(&region, "arm64");
    // Hot region with page-boundary platform gets downgraded to cache-line
    assert_eq!(kind, LayoutDecisionKind::AlignCacheLine);
    assert_eq!(align.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_evaluator_select_alignment_traced_with_page_boundary_platform() {
    let mut policy = make_test_evaluator_policy();
    policy.add_platform_rule(PlatformRule::new(
        "arm64",
        AlignmentStrategy::page_boundary(4096),
    ));
    let e = LayoutEvaluator::new(policy);
    let region = CodeRegion::new("t1", RegionHeat::Traced, 512);
    let (align, kind) = e.select_alignment(&region, "arm64");
    assert_eq!(kind, LayoutDecisionKind::AlignPageBoundary);
    assert_eq!(align.target, AlignmentTarget::PageBoundary);
}

// ---------------------------------------------------------------------------
// LayoutEvaluator — evaluate_region and evaluate_all
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_evaluate_region_produces_receipt() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("r1", RegionHeat::Hot, 128).with_base_address(0x100);
    let receipt = e.evaluate_region(&region, "x86_64");
    assert_eq!(receipt.kind, LayoutDecisionKind::AlignCacheLine);
    assert_eq!(e.receipts.len(), 1);
}

#[test]
fn test_evaluator_evaluate_region_spends_padding() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("r1", RegionHeat::Hot, 128).with_base_address(1); // 1 is misaligned
    let receipt = e.evaluate_region(&region, "x86_64");
    // Padding for address 1 with 64-byte alignment = 63 bytes
    assert_eq!(receipt.padding_bytes, 63);
    assert_eq!(e.policy.padding_spent_bytes, 63);
}

#[test]
fn test_evaluator_evaluate_region_aligned_address_zero_padding() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let region = CodeRegion::new("r1", RegionHeat::Hot, 128).with_base_address(0x100); // 256 is aligned to 64
    let receipt = e.evaluate_region(&region, "x86_64");
    assert_eq!(receipt.padding_bytes, 0);
}

#[test]
fn test_evaluator_evaluate_all_produces_receipts_for_all_regions() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let receipts = e.evaluate_all("x86_64");
    assert_eq!(receipts.len(), 4);
    assert_eq!(e.receipts.len(), 4);
}

#[test]
fn test_evaluator_evaluate_all_budget_exhausted_emits_diagnostic() {
    let mut policy = make_test_evaluator_policy();
    policy.alignment_budget_bytes = 0;
    let mut e = LayoutEvaluator::new(policy);
    e.evaluate_all("x86_64");
    // Hot and traced regions should trigger budget-exhausted diagnostics
    assert!(!e.diagnostics.is_empty());
}

// ---------------------------------------------------------------------------
// LayoutEvaluator — regression, stall, and parity
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_check_regression_no_regression() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let result = e.check_regression(MILLION, MILLION);
    assert!(result.is_none());
    assert_eq!(e.policy.state, LayoutPolicyState::Active);
}

#[test]
fn test_evaluator_check_regression_fires() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let result = e.check_regression(MILLION, 800_000); // 20% drop
    assert!(result.is_some());
    assert_eq!(e.policy.state, LayoutPolicyState::RolledBack);
    assert!(e.rollback_gate.fired);
    assert!(e.diagnostics.has_errors());
}

#[test]
fn test_evaluator_check_regression_marginal() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    // Default threshold is 50_000 (5%). A 4% drop should not fire.
    let result = e.check_regression(MILLION, 960_000);
    assert!(result.is_none());
    assert_eq!(e.policy.state, LayoutPolicyState::Active);
}

#[test]
fn test_evaluator_record_stall() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
    assert_eq!(e.policy.stall_budget.accumulated_cycles, 10);
    assert_eq!(e.policy.stall_budget.accumulated_icache_misses, 1);
}

#[test]
fn test_evaluator_record_stall_triggers_rollback_on_exhaustion() {
    let mut policy = make_test_evaluator_policy();
    policy.stall_budget = StallBudget::new(20, 2);
    let mut e = LayoutEvaluator::new(policy);
    e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
    e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r2", 15));
    assert!(e.rollback_gate.fired);
    assert!(e.diagnostics.has_critical());
}

#[test]
fn test_evaluator_check_parity_equivalent() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let h = hash_of(b"same_output");
    let v = e.check_parity("r1", h.clone(), h);
    assert_eq!(v, ParityVerdict::Equivalent);
    assert!(!e.rollback_gate.fired);
    assert!(!e.diagnostics.has_critical());
}

#[test]
fn test_evaluator_check_parity_divergent_triggers_rollback() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    let h1 = hash_of(b"reference");
    let h2 = hash_of(b"candidate");
    let v = e.check_parity("r1", h1, h2);
    assert_eq!(v, ParityVerdict::Divergent);
    assert!(e.rollback_gate.fired);
    assert!(e.diagnostics.has_critical());
    assert_eq!(e.rollback_gate.rollback_count(), 1);
}

// ---------------------------------------------------------------------------
// LayoutEvaluator — summary and hash
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_receipt_summary() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    e.evaluate_all("x86_64");
    let summary = e.receipt_summary();
    assert!(!summary.is_empty());
    // Should have entries for cold_pack, keep_natural, align_cache_line, etc.
    let total: usize = summary.values().sum();
    assert_eq!(total, 4);
}

#[test]
fn test_evaluator_total_padding_bytes() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    e.evaluate_all("x86_64");
    // Just verify it is a valid non-negative number
    let _ = e.total_padding_bytes();
}

#[test]
fn test_evaluator_evaluation_hash_deterministic() {
    let e1 = LayoutEvaluator::new(make_test_evaluator_policy());
    let e2 = LayoutEvaluator::new(make_test_evaluator_policy());
    assert_eq!(e1.evaluation_hash(), e2.evaluation_hash());
}

#[test]
fn test_evaluator_evaluation_hash_changes_after_evaluation() {
    let mut e1 = LayoutEvaluator::new(make_test_evaluator_policy());
    let hash_before = e1.evaluation_hash();
    e1.evaluate_all("x86_64");
    let hash_after = e1.evaluation_hash();
    assert_ne!(hash_before, hash_after);
}

#[test]
fn test_evaluator_display() {
    let e = LayoutEvaluator::new(make_test_evaluator_policy());
    let s = e.to_string();
    assert!(s.contains("eval_policy"));
    assert!(s.contains("receipts=0"));
    assert!(s.contains("rollbacks=0"));
}

#[test]
fn test_evaluator_serde_round_trip() {
    let mut e = LayoutEvaluator::new(make_test_evaluator_policy());
    e.evaluate_all("x86_64");
    let json = serde_json::to_string(&e).unwrap();
    let back: LayoutEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// End-to-end lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle_evaluate_regions_and_check_regression() {
    // 1. Create a policy with regions
    let mut policy = make_active_policy("lifecycle_1");
    policy.add_region(make_region("cold_fn", RegionHeat::Cold, 64, 0x1000));
    policy.add_region(make_region("hot_loop", RegionHeat::Hot, 256, 0x2000));
    policy.add_region(make_region("traced_fn", RegionHeat::Traced, 512, 0x3000));

    // 2. Evaluate all regions
    let mut evaluator = LayoutEvaluator::new(policy);
    let receipts = evaluator.evaluate_all("x86_64");
    assert_eq!(receipts.len(), 3);

    // 3. No regression
    assert!(evaluator.check_regression(MILLION, MILLION).is_none());
    assert_eq!(evaluator.policy.state, LayoutPolicyState::Active);

    // 4. Check parity (passes)
    let h = hash_of(b"correct_output");
    let v = evaluator.check_parity("hot_loop", h.clone(), h);
    assert_eq!(v, ParityVerdict::Equivalent);

    // 5. Verify receipt summary
    let summary = evaluator.receipt_summary();
    assert!(summary.values().sum::<usize>() == 3);
}

#[test]
fn test_full_lifecycle_regression_triggers_rollback() {
    let mut policy = make_active_policy("lifecycle_2");
    policy.add_region(make_region("hot_loop", RegionHeat::Hot, 256, 0x1000));

    let mut evaluator = LayoutEvaluator::new(policy);
    evaluator.evaluate_all("x86_64");

    // Severe regression (20% drop)
    let record = evaluator.check_regression(MILLION, 800_000);
    assert!(record.is_some());
    assert_eq!(evaluator.policy.state, LayoutPolicyState::RolledBack);
    assert!(evaluator.diagnostics.has_errors());
}

#[test]
fn test_full_lifecycle_stall_budget_exhaustion_triggers_critical() {
    let mut policy = make_active_policy("lifecycle_3");
    policy.stall_budget = StallBudget::new(50, 3);
    policy.add_region(make_region("hot_loop", RegionHeat::Hot, 256, 0x1000));

    let mut evaluator = LayoutEvaluator::new(policy);
    evaluator.evaluate_all("x86_64");

    // Record stalls until I-cache budget exhausted
    evaluator.record_stall(StallEvent::new(StallKind::ICacheMiss, "hot_loop", 10));
    evaluator.record_stall(StallEvent::new(StallKind::ICacheMiss, "hot_loop", 10));
    evaluator.record_stall(StallEvent::new(StallKind::ICacheMiss, "hot_loop", 10));
    assert!(evaluator.policy.stall_budget.gate_fires());
    assert!(evaluator.rollback_gate.fired);
    assert!(evaluator.diagnostics.has_critical());
}

#[test]
fn test_full_lifecycle_parity_failure_triggers_critical() {
    let mut policy = make_active_policy("lifecycle_4");
    policy.add_region(make_region("hot_loop", RegionHeat::Hot, 256, 0x1000));

    let mut evaluator = LayoutEvaluator::new(policy);
    evaluator.evaluate_all("x86_64");

    let h1 = hash_of(b"reference_output");
    let h2 = hash_of(b"divergent_output");
    let v = evaluator.check_parity("hot_loop", h1, h2);
    assert_eq!(v, ParityVerdict::Divergent);
    assert!(evaluator.rollback_gate.fired);
    assert!(evaluator.diagnostics.has_critical());
}

#[test]
fn test_batch_evaluate_many_regions() {
    let mut policy = make_active_policy("batch_test");
    for i in 0..20 {
        let heat = match i % 4 {
            0 => RegionHeat::Cold,
            1 => RegionHeat::Warm,
            2 => RegionHeat::Hot,
            _ => RegionHeat::Traced,
        };
        policy.add_region(make_region(
            &format!("r{i}"),
            heat,
            64 * (i as u64 + 1),
            (i as u64) * 0x100,
        ));
    }
    assert_eq!(policy.regions.len(), 20);
    assert_eq!(policy.hot_region_count(), 10); // 5 Hot + 5 Traced

    let mut evaluator = LayoutEvaluator::new(policy);
    let receipts = evaluator.evaluate_all("x86_64");
    assert_eq!(receipts.len(), 20);

    let summary = evaluator.receipt_summary();
    let total: usize = summary.values().sum();
    assert_eq!(total, 20);
}

#[test]
fn test_platform_rule_pinned_prevents_generalisation_in_policy() {
    let mut policy = make_active_policy("pin_test");
    let mut rule = PlatformRule::new("arm64", AlignmentStrategy::page_boundary(4096));
    rule.pin("ARM64 needs page alignment for performance");
    policy.add_platform_rule(rule);

    let a = policy.effective_alignment("arm64");
    assert_eq!(a.target, AlignmentTarget::PageBoundary);

    // Verify the rule is not generalisable
    assert!(!policy.platform_rules[0].is_generalisable());
}

#[test]
fn test_multiple_platform_rules_first_matching_wins() {
    let mut policy = make_active_policy("multi_rule");
    policy.add_platform_rule(PlatformRule::new(
        "x86_64",
        AlignmentStrategy::cache_line(64),
    ));
    policy.add_platform_rule(PlatformRule::new(
        "x86_64",
        AlignmentStrategy::page_boundary(4096),
    ));

    // First non-rolled-back rule wins
    let a = policy.effective_alignment("x86_64");
    assert_eq!(a.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_alignment_strategy_cache_line_saturating_sub() {
    // Edge case: cache_line(0) should not underflow
    let a = AlignmentStrategy::cache_line(0);
    assert_eq!(a.alignment_bytes, 0);
    assert_eq!(a.max_padding_bytes, 0); // 0.saturating_sub(1) = 0
}

#[test]
fn test_stall_budget_saturating_add_no_overflow() {
    let mut b = StallBudget::new(u64::MAX, u64::MAX);
    b.record(StallEvent::new(StallKind::ICacheMiss, "r1", u64::MAX));
    b.record(StallEvent::new(StallKind::ICacheMiss, "r2", u64::MAX));
    // Should saturate, not overflow
    assert_eq!(b.accumulated_cycles, u64::MAX);
    assert_eq!(b.accumulated_icache_misses, 2);
}

#[test]
fn test_layout_policy_spend_padding_saturating() {
    let mut p = make_policy("p1");
    p.alignment_budget_bytes = 100;
    p.spend_padding(u64::MAX);
    // Should saturate
    assert!(p.budget_exhausted());
}
