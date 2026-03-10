//! Integration tests for `hardware_code_layout_gate` module.
//!
//! Validates alignment strategies, stall budgets, layout policies, rollback
//! gates, parity checkers, diagnostic reports, layout evaluators, decision
//! receipts, serde contracts, and determinism.

use frankenengine_engine::hardware_code_layout_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample_region(id: &str, heat: RegionHeat, size: u64) -> CodeRegion {
    CodeRegion::new(id, heat, size)
}

fn default_policy() -> LayoutPolicy {
    let mut p = LayoutPolicy::new("test-policy", epoch(1));
    p.activate();
    p
}

fn default_evaluator() -> LayoutEvaluator {
    let policy = default_policy();
    LayoutEvaluator::new(policy)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_present() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.starts_with("franken-engine"));
}

#[test]
fn test_bead_id_present() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_policy_id_present() {
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn test_default_constants() {
    assert!(DEFAULT_CACHE_LINE_BYTES > 0);
    assert!(DEFAULT_PAGE_SIZE_BYTES > 0);
    assert!(MAX_ALIGNMENT_BUDGET_BYTES > 0);
    assert!(DEFAULT_STALL_BUDGET_CYCLES > 0);
    assert!(DEFAULT_ICACHE_MISS_THRESHOLD > 0);
    assert!(DEFAULT_REGRESSION_THRESHOLD > 0);
}

// ---------------------------------------------------------------------------
// AlignmentTarget
// ---------------------------------------------------------------------------

#[test]
fn test_alignment_target_variants() {
    let targets = [
        AlignmentTarget::Natural,
        AlignmentTarget::CacheLine,
        AlignmentTarget::PageBoundary,
        AlignmentTarget::Explicit,
    ];
    for t in &targets {
        let s = t.as_str();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_alignment_target_serde() {
    for t in [
        AlignmentTarget::Natural,
        AlignmentTarget::CacheLine,
        AlignmentTarget::PageBoundary,
        AlignmentTarget::Explicit,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: AlignmentTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ---------------------------------------------------------------------------
// AlignmentStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_natural_alignment() {
    let strat = AlignmentStrategy::natural();
    assert!(strat.is_power_of_two());
}

#[test]
fn test_cache_line_alignment() {
    let strat = AlignmentStrategy::cache_line(64);
    assert!(strat.is_power_of_two());
}

#[test]
fn test_page_boundary_alignment() {
    let strat = AlignmentStrategy::page_boundary(4096);
    assert!(strat.is_power_of_two());
}

#[test]
fn test_explicit_alignment() {
    let strat = AlignmentStrategy::explicit(16, 32);
    assert!(strat.is_power_of_two());
}

#[test]
fn test_padding_for_aligned() {
    let strat = AlignmentStrategy::cache_line(64);
    let pad = strat.padding_for(0);
    // Address 0 is already aligned to 64
    assert!(pad.is_some());
    assert_eq!(pad.unwrap(), 0);
}

#[test]
fn test_padding_for_unaligned() {
    let strat = AlignmentStrategy::cache_line(64);
    let pad = strat.padding_for(1);
    assert!(pad.is_some());
    assert!(pad.unwrap() > 0);
}

#[test]
fn test_exceeds_budget() {
    let strat = AlignmentStrategy::explicit(16, 8);
    assert!(strat.exceeds_budget(16));
    assert!(!strat.exceeds_budget(4));
}

#[test]
fn test_alignment_strategy_serde() {
    let strat = AlignmentStrategy::cache_line(64);
    let json = serde_json::to_string(&strat).unwrap();
    let back: AlignmentStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(strat, back);
}

// ---------------------------------------------------------------------------
// PlatformId / RegionId
// ---------------------------------------------------------------------------

#[test]
fn test_platform_id() {
    let pid = PlatformId::new("x86_64");
    assert_eq!(pid.as_str(), "x86_64");
}

#[test]
fn test_region_id() {
    let rid = RegionId::new("hot-loop-1");
    assert_eq!(rid.as_str(), "hot-loop-1");
}

// ---------------------------------------------------------------------------
// RegionHeat
// ---------------------------------------------------------------------------

#[test]
fn test_region_heat_variants() {
    let heats = [RegionHeat::Cold, RegionHeat::Warm, RegionHeat::Hot, RegionHeat::Critical];
    for h in &heats {
        let s = h.as_str();
        assert!(!s.is_empty());
        assert!(h.rank() <= 3);
    }
}

#[test]
fn test_region_heat_ordering() {
    assert!(RegionHeat::Cold.rank() < RegionHeat::Critical.rank());
}

#[test]
fn test_region_heat_serde() {
    for h in [RegionHeat::Cold, RegionHeat::Warm, RegionHeat::Hot, RegionHeat::Critical] {
        let json = serde_json::to_string(&h).unwrap();
        let back: RegionHeat = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }
}

// ---------------------------------------------------------------------------
// CodeRegion
// ---------------------------------------------------------------------------

#[test]
fn test_code_region_construction() {
    let r = sample_region("r1", RegionHeat::Hot, 1024);
    assert_eq!(r.heat, RegionHeat::Hot);
    assert_eq!(r.size_bytes, 1024);
}

#[test]
fn test_code_region_builder_methods() {
    let r = CodeRegion::new("r2", RegionHeat::Warm, 512)
        .with_base_address(0x1000)
        .with_execution_count(5000)
        .with_loop_header(true)
        .with_function_entry(false);
    assert_eq!(r.base_address, Some(0x1000));
    assert_eq!(r.execution_count, 5000);
    assert!(r.is_loop_header);
    assert!(!r.is_function_entry);
}

#[test]
fn test_code_region_serde() {
    let r = sample_region("serde-r", RegionHeat::Cold, 256);
    let json = serde_json::to_string(&r).unwrap();
    let back: CodeRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// StallBudget
// ---------------------------------------------------------------------------

#[test]
fn test_stall_budget_new() {
    let budget = StallBudget::new(256, 64);
    assert!(!budget.cycles_exhausted());
    assert!(!budget.icache_exhausted());
    assert!(!budget.gate_fires());
}

#[test]
fn test_stall_budget_record_events() {
    let mut budget = StallBudget::new(100, 10);
    let event = StallEvent::new(StallKind::IcacheMiss, "r1", 50);
    budget.record(event);
    assert_eq!(budget.event_count(), 1);
    assert!(budget.remaining_cycles() <= 100);
}

#[test]
fn test_stall_budget_exhaustion() {
    let mut budget = StallBudget::new(10, 2);
    for i in 0..5 {
        budget.record(StallEvent::new(StallKind::IcacheMiss, &format!("r{i}"), 5));
    }
    assert!(budget.cycles_exhausted() || budget.icache_exhausted());
    assert!(budget.gate_fires());
}

#[test]
fn test_stall_budget_reset() {
    let mut budget = StallBudget::new(100, 10);
    budget.record(StallEvent::new(StallKind::IcacheMiss, "r1", 50));
    budget.reset();
    assert_eq!(budget.event_count(), 0);
    assert!(!budget.gate_fires());
}

#[test]
fn test_stall_budget_utilisation() {
    let mut budget = StallBudget::new(100, 10);
    budget.record(StallEvent::new(StallKind::IcacheMiss, "r1", 50));
    let util = budget.cycle_utilisation_millionths();
    assert!(util > 0);
    assert!(util <= 1_000_000);
}

#[test]
fn test_stall_budget_content_hash() {
    let budget = StallBudget::new(100, 10);
    let hash = budget.content_hash();
    let json = serde_json::to_string(&hash).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// StallEvent
// ---------------------------------------------------------------------------

#[test]
fn test_stall_event_construction() {
    let event = StallEvent::new(StallKind::IcacheMiss, "region-a", 42);
    assert_eq!(event.kind, StallKind::IcacheMiss);
    assert_eq!(event.cost_cycles, 42);
}

#[test]
fn test_stall_event_with_offset() {
    let event = StallEvent::new(StallKind::BranchMispredict, "r1", 10).with_offset(0x100);
    assert_eq!(event.offset, Some(0x100));
}

#[test]
fn test_stall_kind_serde() {
    for k in [
        StallKind::IcacheMiss,
        StallKind::BranchMispredict,
        StallKind::AlignmentPenalty,
        StallKind::FrontendBubble,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: StallKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// LayoutPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_layout_policy_construction() {
    let p = LayoutPolicy::new("pol-1", epoch(1));
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_layout_policy_activate() {
    let mut p = LayoutPolicy::new("pol-2", epoch(1));
    p.activate();
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_layout_policy_add_region() {
    let mut p = default_policy();
    p.add_region(sample_region("r1", RegionHeat::Hot, 512));
    assert_eq!(p.hot_region_count(), 1);
}

#[test]
fn test_layout_policy_add_platform_rule() {
    let mut p = default_policy();
    let rule = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    p.add_platform_rule(rule);
    let eff = p.effective_alignment("x86_64");
    assert_eq!(eff.target, AlignmentTarget::CacheLine);
}

#[test]
fn test_layout_policy_budget() {
    let mut p = default_policy();
    assert!(!p.budget_exhausted());
    let remaining = p.remaining_budget();
    assert!(remaining > 0);
    p.spend_padding(100);
    assert!(p.remaining_budget() < remaining);
}

#[test]
fn test_layout_policy_total_code_bytes() {
    let mut p = default_policy();
    p.add_region(sample_region("r1", RegionHeat::Hot, 512));
    p.add_region(sample_region("r2", RegionHeat::Warm, 256));
    assert_eq!(p.total_code_bytes(), 768);
}

#[test]
fn test_layout_policy_content_hash() {
    let p = default_policy();
    let hash = p.content_hash();
    let json = serde_json::to_string(&hash).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_layout_policy_pin_rollback() {
    let mut p = default_policy();
    p.pin("performance-critical");
    p.rollback("regression detected");
}

#[test]
fn test_layout_policy_generalise() {
    let mut p = default_policy();
    p.generalise();
    assert!(p.is_generalisable());
}

// ---------------------------------------------------------------------------
// LayoutPolicyState
// ---------------------------------------------------------------------------

#[test]
fn test_layout_policy_state_variants() {
    let states = [
        LayoutPolicyState::Draft,
        LayoutPolicyState::Active,
        LayoutPolicyState::Pinned,
        LayoutPolicyState::RolledBack,
    ];
    for s in &states {
        let name = s.as_str();
        assert!(!name.is_empty());
    }
}

#[test]
fn test_layout_policy_state_is_operational() {
    assert!(LayoutPolicyState::Active.is_operational());
    assert!(LayoutPolicyState::Pinned.is_operational());
    assert!(!LayoutPolicyState::Draft.is_operational());
    assert!(!LayoutPolicyState::RolledBack.is_operational());
}

// ---------------------------------------------------------------------------
// RollbackGate
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_gate_new() {
    let gate = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    assert_eq!(gate.rollback_count(), 0);
}

#[test]
fn test_rollback_gate_evaluate_no_regression() {
    let gate = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let result = gate.evaluate(500_000, 510_000); // improvement
    assert!(!result.is_regression());
}

#[test]
fn test_rollback_gate_evaluate_regression() {
    let gate = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let result = gate.evaluate(500_000, 400_000); // 20% regression
    assert!(result.is_regression());
}

#[test]
fn test_rollback_gate_record() {
    let mut gate = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let record = RollbackRecord::new(
        "pol-1",
        epoch(1),
        RollbackReason::PerformanceRegression,
    );
    gate.record_rollback(record);
    assert_eq!(gate.rollback_count(), 1);
}

#[test]
fn test_rollback_gate_reset() {
    let mut gate = RollbackGate::new(DEFAULT_REGRESSION_THRESHOLD);
    let record = RollbackRecord::new("pol-1", epoch(1), RollbackReason::PerformanceRegression);
    gate.record_rollback(record);
    gate.reset();
    assert_eq!(gate.rollback_count(), 0);
}

// ---------------------------------------------------------------------------
// ParityChecker
// ---------------------------------------------------------------------------

#[test]
fn test_parity_checker_new() {
    let checker = ParityChecker::new(50_000);
    assert!(checker.all_passed());
    assert_eq!(checker.check_count(), 0);
}

#[test]
fn test_parity_checker_pass() {
    let mut checker = ParityChecker::new(50_000);
    let result = checker.check("r1", 500_000, 510_000);
    assert_eq!(result.verdict, ParityVerdict::Pass);
}

#[test]
fn test_parity_checker_fail() {
    let mut checker = ParityChecker::new(50_000);
    let result = checker.check("r1", 500_000, 400_000);
    assert_eq!(result.verdict, ParityVerdict::Divergent);
}

#[test]
fn test_parity_checker_record() {
    let mut checker = ParityChecker::new(50_000);
    checker.record("r1", 500_000, 500_000);
    checker.record("r2", 500_000, 300_000);
    assert_eq!(checker.check_count(), 2);
    assert!(!checker.all_passed());
}

#[test]
fn test_parity_checker_divergent_count() {
    let mut checker = ParityChecker::new(50_000);
    checker.record("r1", 500_000, 500_000);
    checker.record("r2", 500_000, 300_000);
    assert_eq!(checker.divergent_count(), 1);
}

#[test]
fn test_parity_checker_reset() {
    let mut checker = ParityChecker::new(50_000);
    checker.record("r1", 500_000, 300_000);
    checker.reset();
    assert_eq!(checker.check_count(), 0);
    assert!(checker.all_passed());
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_serde() {
    for v in [ParityVerdict::Pass, ParityVerdict::Divergent, ParityVerdict::Inconclusive] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_parity_verdict_allows_layout() {
    assert!(ParityVerdict::Pass.allows_layout());
    assert!(!ParityVerdict::Divergent.allows_layout());
}

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_report_empty() {
    let report = DiagnosticReport::new("pol-1", epoch(1));
    assert!(report.is_empty());
    assert_eq!(report.len(), 0);
    assert!(!report.has_errors());
    assert!(!report.has_critical());
}

#[test]
fn test_diagnostic_report_add() {
    let mut report = DiagnosticReport::new("pol-1", epoch(1));
    report.add(LayoutDiagnostic::new(
        DiagnosticSeverity::Warning,
        "alignment exceeds budget",
    ));
    assert_eq!(report.len(), 1);
    assert!(!report.has_errors());
}

#[test]
fn test_diagnostic_report_severity_count() {
    let mut report = DiagnosticReport::new("pol-1", epoch(1));
    report.add(LayoutDiagnostic::new(DiagnosticSeverity::Info, "info msg"));
    report.add(LayoutDiagnostic::new(DiagnosticSeverity::Warning, "warn msg"));
    report.add(LayoutDiagnostic::new(DiagnosticSeverity::Error, "err msg"));
    assert!(report.has_errors());
    assert_eq!(report.count_at_or_above(DiagnosticSeverity::Warning), 2);
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_severity_serde() {
    for s in [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// LayoutDiagnostic
// ---------------------------------------------------------------------------

#[test]
fn test_layout_diagnostic_builder() {
    let diag = LayoutDiagnostic::new(DiagnosticSeverity::Warning, "stall budget exceeded")
        .with_region("hot-loop-1")
        .with_platform("aarch64")
        .with_action("rollback to natural alignment");
    let json = serde_json::to_string(&diag).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// LayoutEvaluator
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_construction() {
    let evaluator = default_evaluator();
    assert_eq!(evaluator.total_padding_bytes(), 0);
}

#[test]
fn test_evaluator_select_alignment() {
    let mut evaluator = default_evaluator();
    let region = sample_region("r1", RegionHeat::Hot, 512);
    let strat = evaluator.select_alignment(&region, "x86_64");
    let json = serde_json::to_string(&strat).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_evaluator_evaluate_region() {
    let mut evaluator = default_evaluator();
    let region = sample_region("r1", RegionHeat::Hot, 512)
        .with_base_address(0x1001);
    let receipt = evaluator.evaluate_region(&region, "x86_64");
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_evaluator_evaluate_all() {
    let mut policy = default_policy();
    policy.add_region(sample_region("r1", RegionHeat::Hot, 512));
    policy.add_region(sample_region("r2", RegionHeat::Warm, 256));
    let mut evaluator = LayoutEvaluator::new(policy);
    let receipts = evaluator.evaluate_all("x86_64");
    assert_eq!(receipts.len(), 2);
}

#[test]
fn test_evaluator_check_regression() {
    let mut evaluator = default_evaluator();
    let result = evaluator.check_regression(500_000, 510_000);
    assert!(!result.is_regression());
}

#[test]
fn test_evaluator_record_stall() {
    let mut evaluator = default_evaluator();
    evaluator.record_stall(StallEvent::new(StallKind::IcacheMiss, "r1", 10));
    // Should be recorded without panic
}

#[test]
fn test_evaluator_check_parity() {
    let mut evaluator = default_evaluator();
    let result = evaluator.check_parity("r1", 500_000, 500_000);
    assert_eq!(result.verdict, ParityVerdict::Pass);
}

#[test]
fn test_evaluator_receipt_summary() {
    let mut policy = default_policy();
    policy.add_region(sample_region("r1", RegionHeat::Hot, 512));
    let mut evaluator = LayoutEvaluator::new(policy);
    evaluator.evaluate_all("x86_64");
    let summary = evaluator.receipt_summary();
    assert!(!summary.is_empty());
}

#[test]
fn test_evaluator_evaluation_hash() {
    let evaluator = default_evaluator();
    let hash = evaluator.evaluation_hash();
    let json = serde_json::to_string(&hash).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// LayoutDecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_layout_decision_receipt_hash() {
    let mut evaluator = default_evaluator();
    let region = sample_region("r1", RegionHeat::Hot, 512).with_base_address(0x1000);
    let receipt = evaluator.evaluate_region(&region, "x86_64");
    let hex = receipt.receipt_hash_hex();
    assert!(!hex.is_empty());
}

#[test]
fn test_layout_decision_receipt_serde() {
    let mut evaluator = default_evaluator();
    let region = sample_region("r1", RegionHeat::Hot, 512);
    let receipt = evaluator.evaluate_region(&region, "x86_64");
    let json = serde_json::to_string(&receipt).unwrap();
    let back: LayoutDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// RollbackReason
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_reason_serde() {
    for r in [
        RollbackReason::PerformanceRegression,
        RollbackReason::StallBudgetExhausted,
        RollbackReason::ParityFailure,
        RollbackReason::OperatorOverride,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: RollbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_record_serde() {
    let record = RollbackRecord::new("pol-1", epoch(1), RollbackReason::PerformanceRegression);
    let json = serde_json::to_string(&record).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_evaluation() {
    let mut e1 = default_evaluator();
    let mut e2 = default_evaluator();
    let region = sample_region("r1", RegionHeat::Hot, 512).with_base_address(0x1000);
    let r1 = e1.evaluate_region(&region, "x86_64");
    let r2 = e2.evaluate_region(&region, "x86_64");
    assert_eq!(r1, r2);
}

#[test]
fn test_deterministic_parity_check() {
    let mut c1 = ParityChecker::new(50_000);
    let mut c2 = ParityChecker::new(50_000);
    c1.record("r1", 500_000, 450_000);
    c2.record("r1", 500_000, 450_000);
    assert_eq!(c1.all_passed(), c2.all_passed());
    assert_eq!(c1.divergent_count(), c2.divergent_count());
}

// ---------------------------------------------------------------------------
// Full workflow
// ---------------------------------------------------------------------------

#[test]
fn test_full_layout_workflow() {
    // 1. Create policy with regions
    let mut policy = LayoutPolicy::new("workflow-pol", epoch(1));
    policy.activate();
    policy.add_region(
        CodeRegion::new("hot-1", RegionHeat::Hot, 1024)
            .with_base_address(0x1000)
            .with_execution_count(50000)
            .with_loop_header(true),
    );
    policy.add_region(
        CodeRegion::new("warm-1", RegionHeat::Warm, 512)
            .with_base_address(0x2000),
    );
    let rule = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
    policy.add_platform_rule(rule);

    // 2. Evaluate
    let mut evaluator = LayoutEvaluator::new(policy);
    let receipts = evaluator.evaluate_all("x86_64");
    assert_eq!(receipts.len(), 2);

    // 3. Check parity
    let parity = evaluator.check_parity("hot-1", 500_000, 510_000);
    assert_eq!(parity.verdict, ParityVerdict::Pass);

    // 4. Record stall events
    evaluator.record_stall(StallEvent::new(StallKind::IcacheMiss, "hot-1", 10));

    // 5. Check regression
    let regression = evaluator.check_regression(500_000, 520_000);
    assert!(!regression.is_regression());

    // 6. Summary
    let summary = evaluator.receipt_summary();
    assert!(!summary.is_empty());

    // 7. Hash is deterministic
    let hash = evaluator.evaluation_hash();
    let json = serde_json::to_string(&hash).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// LayoutDecisionKind
// ---------------------------------------------------------------------------

#[test]
fn test_layout_decision_kind_serde() {
    for k in [
        LayoutDecisionKind::Aligned,
        LayoutDecisionKind::Padded,
        LayoutDecisionKind::Skipped,
        LayoutDecisionKind::FallbackNatural,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: LayoutDecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// PlatformRule
// ---------------------------------------------------------------------------

#[test]
fn test_platform_rule_serde() {
    let rule = PlatformRule::new("aarch64", AlignmentStrategy::page_boundary(4096));
    let json = serde_json::to_string(&rule).unwrap();
    let back: PlatformRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ---------------------------------------------------------------------------
// ParityCheckResult
// ---------------------------------------------------------------------------

#[test]
fn test_parity_check_result_serde() {
    let mut checker = ParityChecker::new(50_000);
    let result = checker.check("r1", 500_000, 500_000);
    let json = serde_json::to_string(&result).unwrap();
    let back: ParityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn test_parity_check_result_with_notes() {
    let mut checker = ParityChecker::new(50_000);
    let result = checker.check("r1", 500_000, 500_000);
    let noted = result.with_notes("verified on x86_64");
    assert!(noted.notes.is_some());
}
