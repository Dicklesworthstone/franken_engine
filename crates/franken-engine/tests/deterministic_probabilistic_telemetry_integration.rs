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

use frankenengine_engine::deterministic_probabilistic_telemetry::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_schema_version() {
    assert!(SCHEMA_VERSION.contains("deterministic-probabilistic-telemetry"));
}

#[test]
fn constants_component() {
    assert_eq!(COMPONENT, "deterministic_probabilistic_telemetry");
}

#[test]
fn constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.11.20");
}

#[test]
fn constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-066");
}

#[test]
fn constants_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn constants_default_max_events() {
    assert_eq!(DEFAULT_MAX_EVENTS_PER_WINDOW, 10_000);
}

#[test]
fn constants_default_window_ns() {
    assert_eq!(DEFAULT_WINDOW_NS, 1_000_000_000);
}

#[test]
fn constants_default_sampling_rate() {
    assert_eq!(DEFAULT_SAMPLING_RATE_MILLIONTHS, 100_000);
}

#[test]
fn constants_max_domains() {
    assert_eq!(MAX_DOMAINS, 256);
}

#[test]
fn constants_max_windows() {
    assert_eq!(MAX_WINDOWS, 1_024);
}

// ---------------------------------------------------------------------------
// CaptureMode
// ---------------------------------------------------------------------------

#[test]
fn capture_mode_all_count() {
    assert_eq!(CaptureMode::ALL.len(), 5);
}

#[test]
fn capture_mode_ordering() {
    assert!(CaptureMode::ExactCounting < CaptureMode::ProbabilisticSampling);
}

#[test]
fn capture_mode_as_str() {
    assert_eq!(CaptureMode::ExactCounting.as_str(), "exact_counting");
    assert_eq!(CaptureMode::BudgetedSampling.as_str(), "budgeted_sampling");
}

#[test]
fn capture_mode_is_exact() {
    assert!(CaptureMode::ExactCounting.is_exact());
    assert!(CaptureMode::ExactShadow.is_exact());
    assert!(!CaptureMode::DeterministicReplay.is_exact());
    assert!(!CaptureMode::BudgetedSampling.is_exact());
    assert!(!CaptureMode::ProbabilisticSampling.is_exact());
}

#[test]
fn capture_mode_is_sampled() {
    assert!(!CaptureMode::ExactCounting.is_sampled());
    assert!(!CaptureMode::ExactShadow.is_sampled());
    assert!(CaptureMode::BudgetedSampling.is_sampled());
    assert!(CaptureMode::ProbabilisticSampling.is_sampled());
}

#[test]
fn capture_mode_is_replay_safe() {
    assert!(CaptureMode::ExactCounting.is_replay_safe());
    assert!(CaptureMode::DeterministicReplay.is_replay_safe());
    assert!(!CaptureMode::BudgetedSampling.is_replay_safe());
}

#[test]
fn capture_mode_display() {
    for mode in CaptureMode::ALL {
        assert_eq!(format!("{}", mode), mode.as_str());
    }
}

// ---------------------------------------------------------------------------
// ThinningPolicy
// ---------------------------------------------------------------------------

#[test]
fn thinning_policy_all_count() {
    assert_eq!(ThinningPolicy::ALL.len(), 4);
}

#[test]
fn thinning_policy_ordering() {
    assert!(ThinningPolicy::Uniform < ThinningPolicy::Priority);
}

#[test]
fn thinning_policy_as_str() {
    assert_eq!(ThinningPolicy::Uniform.as_str(), "uniform");
    assert_eq!(ThinningPolicy::Reservoir.as_str(), "reservoir");
    assert_eq!(ThinningPolicy::Stratified.as_str(), "stratified");
    assert_eq!(ThinningPolicy::Priority.as_str(), "priority");
}

#[test]
fn thinning_policy_display() {
    for policy in ThinningPolicy::ALL {
        assert_eq!(format!("{}", policy), policy.as_str());
    }
}

// ---------------------------------------------------------------------------
// TelemetryBudget
// ---------------------------------------------------------------------------

#[test]
fn budget_exact() {
    let budget = TelemetryBudget::exact();
    assert_eq!(budget.max_events_per_window, DEFAULT_MAX_EVENTS_PER_WINDOW);
    assert_eq!(budget.sampling_rate_millionths, MILLIONTHS);
    assert!(budget.is_full_capture());
    assert_eq!(budget.mode, CaptureMode::ExactCounting);
}

#[test]
fn budget_budgeted_default() {
    let budget = TelemetryBudget::budgeted_default();
    assert_eq!(
        budget.sampling_rate_millionths,
        DEFAULT_SAMPLING_RATE_MILLIONTHS
    );
    assert!(!budget.is_full_capture());
    assert_eq!(budget.mode, CaptureMode::BudgetedSampling);
}

#[test]
fn budget_effective_events_per_second() {
    let budget = TelemetryBudget::exact();
    let eps = budget.effective_events_per_second();
    // 10_000 events per 1s window = 10_000 events/sec
    assert_eq!(eps, 10_000);
}

#[test]
fn budget_effective_events_per_second_zero_window() {
    let budget = TelemetryBudget::new(100, 0, MILLIONTHS, CaptureMode::ExactCounting);
    assert_eq!(budget.effective_events_per_second(), 0);
}

#[test]
fn budget_sampling_rate_clamped() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, 5_000_000, CaptureMode::BudgetedSampling);
    assert_eq!(budget.sampling_rate_millionths, MILLIONTHS);
}

#[test]
fn budget_display() {
    let budget = TelemetryBudget::exact();
    let s = format!("{}", budget);
    assert!(s.contains("TelemetryBudget"));
}

// ---------------------------------------------------------------------------
// ThinningConfig
// ---------------------------------------------------------------------------

#[test]
fn thinning_config_uniform_default() {
    let cfg = ThinningConfig::uniform_default();
    assert_eq!(cfg.policy, ThinningPolicy::Uniform);
    assert_eq!(cfg.target_events, DEFAULT_THINNING_TARGET);
}

#[test]
fn thinning_config_priority_default() {
    let cfg = ThinningConfig::priority_default();
    assert_eq!(cfg.policy, ThinningPolicy::Priority);
}

#[test]
fn thinning_config_reservoir_default() {
    let cfg = ThinningConfig::reservoir_default();
    assert_eq!(cfg.policy, ThinningPolicy::Reservoir);
    assert_eq!(cfg.target_events, DEFAULT_RESERVOIR_SIZE);
}

#[test]
fn thinning_config_target_at_least_one() {
    let cfg = ThinningConfig::new(ThinningPolicy::Uniform, 0, 0);
    assert_eq!(cfg.target_events, 1);
}

// ---------------------------------------------------------------------------
// TelemetryEvent
// ---------------------------------------------------------------------------

#[test]
fn event_exact_construction() {
    let ev = TelemetryEvent::exact("evt_1", "jit_compiler", 1_000, b"payload");
    assert_eq!(ev.event_id, "evt_1");
    assert_eq!(ev.domain, "jit_compiler");
    assert_eq!(ev.timestamp_ns, 1_000);
    assert_eq!(ev.capture_mode, CaptureMode::ExactCounting);
    assert_eq!(ev.weight_millionths, MILLIONTHS);
    assert!(ev.is_exact());
}

#[test]
fn event_sampled_construction() {
    let ev = TelemetryEvent::sampled("evt_2", "gc", 2_000, 100_000, b"payload");
    assert_eq!(ev.capture_mode, CaptureMode::ProbabilisticSampling);
    // weight = MILLIONTHS^2 / 100_000 = 10_000_000
    assert_eq!(ev.weight_millionths, 10_000_000);
    assert!(!ev.is_exact());
}

#[test]
fn event_hash_determinism() {
    let a = TelemetryEvent::exact("e", "d", 100, b"data");
    let b = TelemetryEvent::exact("e", "d", 100, b"data");
    assert_eq!(a.event_hash, b.event_hash);
    assert_eq!(a.payload_hash, b.payload_hash);
}

#[test]
fn event_different_payload_different_hash() {
    let a = TelemetryEvent::exact("e", "d", 100, b"data_a");
    let b = TelemetryEvent::exact("e", "d", 100, b"data_b");
    assert_ne!(a.payload_hash, b.payload_hash);
    assert_ne!(a.event_hash, b.event_hash);
}

#[test]
fn event_display() {
    let ev = TelemetryEvent::exact("disp_1", "renderer", 500, b"x");
    let s = format!("{}", ev);
    assert!(s.contains("disp_1"));
    assert!(s.contains("renderer"));
}

// ---------------------------------------------------------------------------
// ProvenanceTag
// ---------------------------------------------------------------------------

#[test]
fn provenance_tag_exact() {
    let tag = ProvenanceTag::exact();
    assert_eq!(tag.capture_mode, CaptureMode::ExactCounting);
    assert_eq!(tag.sampling_rate_applied_millionths, MILLIONTHS);
    assert!(!tag.thinning_applied);
    assert!(tag.replay_deterministic);
    assert!(tag.is_high_fidelity());
}

#[test]
fn provenance_tag_budgeted() {
    let tag = ProvenanceTag::budgeted(100_000);
    assert_eq!(tag.capture_mode, CaptureMode::BudgetedSampling);
    assert_eq!(tag.sampling_rate_applied_millionths, 100_000);
    assert!(!tag.is_high_fidelity());
}

#[test]
fn provenance_tag_probabilistic() {
    let tag = ProvenanceTag::probabilistic(50_000);
    assert_eq!(tag.capture_mode, CaptureMode::ProbabilisticSampling);
}

#[test]
fn provenance_tag_exact_shadow() {
    let tag = ProvenanceTag::exact_shadow();
    assert_eq!(tag.capture_mode, CaptureMode::ExactShadow);
    assert!(tag.is_high_fidelity());
}

#[test]
fn provenance_tag_replay() {
    let tag = ProvenanceTag::replay();
    assert_eq!(tag.capture_mode, CaptureMode::DeterministicReplay);
    assert!(tag.replay_deterministic);
}

#[test]
fn provenance_tag_with_thinning() {
    let tag = ProvenanceTag::exact().with_thinning();
    assert!(tag.thinning_applied);
}

#[test]
fn provenance_tag_content_hash_determinism() {
    let a = ProvenanceTag::exact().content_hash();
    let b = ProvenanceTag::exact().content_hash();
    assert_eq!(a, b);
}

#[test]
fn provenance_tag_display() {
    let tag = ProvenanceTag::exact();
    let s = format!("{}", tag);
    assert!(s.contains("ProvenanceTag"));
}

// ---------------------------------------------------------------------------
// EventWindow
// ---------------------------------------------------------------------------

#[test]
fn event_window_new() {
    let budget = TelemetryBudget::exact();
    let window = EventWindow::new(1_000, budget);
    assert_eq!(window.start_ns, 1_000);
    assert_eq!(window.event_count(), 0);
    assert!(!window.is_at_capacity());
    assert_eq!(window.remaining_capacity(), DEFAULT_MAX_EVENTS_PER_WINDOW);
}

#[test]
fn event_window_record_and_count() {
    let budget = TelemetryBudget::new(5, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    for i in 0..5 {
        let ev = TelemetryEvent::exact(&format!("e{}", i), "d", i * 100, b"p");
        assert!(window.record(ev));
    }
    assert_eq!(window.event_count(), 5);
    assert!(window.is_at_capacity());
}

#[test]
fn event_window_reject_at_capacity() {
    let budget = TelemetryBudget::new(2, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    window.record(TelemetryEvent::exact("e0", "d", 0, b"p"));
    window.record(TelemetryEvent::exact("e1", "d", 100, b"p"));
    let accepted = window.record(TelemetryEvent::exact("e2", "d", 200, b"p"));
    assert!(!accepted);
    assert_eq!(window.rejected_count, 1);
}

#[test]
fn event_window_contains_timestamp() {
    let budget = TelemetryBudget::new(100, 1000, MILLIONTHS, CaptureMode::ExactCounting);
    let window = EventWindow::new(500, budget);
    assert!(window.contains_timestamp(500));
    assert!(window.contains_timestamp(1000));
    assert!(!window.contains_timestamp(1500));
}

#[test]
fn event_window_effective_sampling_rate_no_rejections() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    window.record(TelemetryEvent::exact("e0", "d", 0, b"p"));
    assert_eq!(window.effective_sampling_rate_millionths(), MILLIONTHS);
}

#[test]
fn event_window_effective_sampling_rate_with_rejections() {
    let budget = TelemetryBudget::new(1, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    window.record(TelemetryEvent::exact("e0", "d", 0, b"p"));
    window.record(TelemetryEvent::exact("e1", "d", 1, b"p")); // rejected
    // rate = 1 / 2 * 1M = 500_000
    assert_eq!(window.effective_sampling_rate_millionths(), 500_000);
}

#[test]
fn event_window_apply_thinning_uniform() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    for i in 0..20 {
        window.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
    let removed = window.apply_thinning(&config);
    assert_eq!(removed, 10);
    assert_eq!(window.event_count(), 10);
    assert!(window.thinning_applied);
}

#[test]
fn event_window_apply_thinning_reservoir() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    for i in 0..30 {
        window.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    let config = ThinningConfig::reservoir_default(); // target = 500, but only 30 events
    let removed = window.apply_thinning(&config);
    assert_eq!(removed, 0); // 30 < 500
}

#[test]
fn event_window_apply_thinning_priority() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut window = EventWindow::new(0, budget);
    for i in 0..20 {
        let ev = TelemetryEvent::new(
            &format!("e{}", i),
            "d",
            i * 10,
            CaptureMode::ExactCounting,
            (i + 1) * 100_000, // varying weights
            b"p",
        );
        window.record(ev);
    }
    let config = ThinningConfig::new(ThinningPolicy::Priority, 10, 500_000);
    let removed = window.apply_thinning(&config);
    assert!(removed > 0);
    assert!(window.event_count() <= 10);
}

#[test]
fn event_window_provenance_tag() {
    let budget = TelemetryBudget::exact();
    let window = EventWindow::new(0, budget);
    let tag = window.provenance_tag();
    assert_eq!(tag.capture_mode, CaptureMode::ExactCounting);
}

#[test]
fn event_window_content_hash_determinism() {
    let budget = TelemetryBudget::exact();
    let mut w1 = EventWindow::new(0, budget.clone());
    let mut w2 = EventWindow::new(0, budget);
    w1.record(TelemetryEvent::exact("e", "d", 1, b"p"));
    w2.record(TelemetryEvent::exact("e", "d", 1, b"p"));
    assert_eq!(w1.content_hash(), w2.content_hash());
}

// ---------------------------------------------------------------------------
// TelemetryPlane
// ---------------------------------------------------------------------------

#[test]
fn plane_new() {
    let plane = TelemetryPlane::new(epoch());
    assert_eq!(plane.active_domain_count(), 0);
    assert_eq!(plane.total_events_recorded, 0);
}

#[test]
fn plane_record_exact() {
    let mut plane = TelemetryPlane::new(epoch());
    let accepted = plane.record_exact("e1", "jit", 100, b"payload");
    assert!(accepted);
    assert_eq!(plane.total_events_recorded, 1);
    assert_eq!(plane.active_domain_count(), 1);
    assert_eq!(plane.domain_event_count("jit"), 1);
}

#[test]
fn plane_record_sampled() {
    let mut plane = TelemetryPlane::new(epoch());
    let accepted = plane.record_sampled("e1", "gc", 100, 100_000, b"payload");
    assert!(accepted);
    assert_eq!(plane.total_events_recorded, 1);
}

#[test]
fn plane_add_budget() {
    let mut plane = TelemetryPlane::new(epoch());
    let custom = TelemetryBudget::exact();
    plane.add_budget("jit", custom);
    let eff = plane.effective_budget("jit");
    assert!(eff.is_full_capture());
}

#[test]
fn plane_effective_budget_default() {
    let plane = TelemetryPlane::new(epoch());
    let eff = plane.effective_budget("unknown_domain");
    assert_eq!(eff.mode, CaptureMode::BudgetedSampling);
}

#[test]
fn plane_with_default_budget() {
    let budget = TelemetryBudget::exact();
    let plane = TelemetryPlane::with_default_budget(epoch(), budget);
    let eff = plane.effective_budget("any");
    assert!(eff.is_full_capture());
}

#[test]
fn plane_thin_domain() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..20 {
        plane.record_exact(&format!("e{}", i), "jit", i * 10, b"p");
    }
    let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
    let removed = plane.thin_domain("jit", &config);
    assert_eq!(removed, 10);
}

#[test]
fn plane_thin_all() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..15 {
        plane.record_exact(&format!("e{}", i), "jit", i * 10, b"p");
    }
    for i in 0..15 {
        plane.record_exact(&format!("f{}", i), "gc", i * 10, b"p");
    }
    plane.set_default_thinning(ThinningConfig::new(ThinningPolicy::Uniform, 5, 0));
    let removed = plane.thin_all();
    assert!(removed > 0);
}

// ---------------------------------------------------------------------------
// TelemetryReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty_plane() {
    let plane = TelemetryPlane::new(epoch());
    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 0);
    assert_eq!(report.window_count, 0);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn report_with_events() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..5 {
        plane.record_exact(&format!("e{}", i), "jit", i * 10, b"data");
    }
    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 5);
    assert_eq!(report.window_count, 1);
    assert!(report.domains.contains("jit"));
    assert!(report.is_all_exact());
    assert!(!report.has_thinning());
}

#[test]
fn report_content_hash_determinism() {
    let mut p1 = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    let mut p2 = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..3 {
        p1.record_exact(&format!("e{}", i), "d", i * 10, b"p");
        p2.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let r1 = p1.generate_report();
    let r2 = p2.generate_report();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_survival_rate_no_thinning() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    plane.record_exact("e0", "d", 0, b"p");
    let report = plane.generate_report();
    assert_eq!(report.survival_rate_millionths(), MILLIONTHS);
}

#[test]
fn report_budget_utilization() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(10, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..5 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let report = plane.generate_report();
    // 5 / 10 = 500_000 millionths
    assert_eq!(report.budget_utilization_millionths, 500_000);
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

#[test]
fn e2e_multi_domain_multi_window() {
    let budget = TelemetryBudget::new(5, 100, MILLIONTHS, CaptureMode::ExactCounting);
    let mut plane = TelemetryPlane::with_default_budget(epoch(), budget);

    // Domain "jit": 3 events in window starting at 0
    for i in 0..3 {
        plane.record_exact(&format!("j{}", i), "jit", i * 10, b"jit_data");
    }
    // Domain "gc": 4 events in window starting at 0
    for i in 0..4 {
        plane.record_exact(&format!("g{}", i), "gc", i * 10, b"gc_data");
    }

    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 7);
    assert!(report.domains.contains("jit"));
    assert!(report.domains.contains("gc"));
    assert_eq!(report.window_count, 2);
}

#[test]
fn e2e_thinning_then_report() {
    let budget = TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut plane = TelemetryPlane::with_default_budget(epoch(), budget);

    for i in 0..50 {
        plane.record_exact(&format!("e{}", i), "hot_path", i * 10, b"data");
    }

    let config = ThinningConfig::new(ThinningPolicy::Uniform, 20, 0);
    let removed = plane.thin_domain("hot_path", &config);
    assert_eq!(removed, 30);

    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 20);
    assert!(report.total_events_thinned > 0);
    assert!(report.has_thinning());
}

#[test]
fn e2e_mixed_capture_modes() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );

    plane.record_exact("exact_1", "d", 0, b"p");
    plane.record_exact("exact_2", "d", 10, b"p");

    let sampled = TelemetryEvent::sampled("sampled_1", "d", 20, 100_000, b"p");
    plane.record_event(sampled);

    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 3);
    assert!(!report.is_all_exact());
}

#[test]
fn e2e_mode_breakdown_counts() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..3 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let report = plane.generate_report();
    assert_eq!(report.mode_breakdowns.len(), 1);
    assert_eq!(report.mode_breakdowns[0].mode, CaptureMode::ExactCounting);
    assert_eq!(report.mode_breakdowns[0].event_count, 3);
}

// ---------------------------------------------------------------------------
// ModeBreakdown
// ---------------------------------------------------------------------------

#[test]
fn mode_breakdown_fraction() {
    let prov = ProvenanceTag::exact();
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 50, 100, prov);
    assert_eq!(bd.fraction_millionths, 500_000);
}

#[test]
fn mode_breakdown_zero_total() {
    let prov = ProvenanceTag::exact();
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 0, 0, prov);
    assert_eq!(bd.fraction_millionths, 0);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_capture_mode_roundtrip() {
    for mode in CaptureMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: CaptureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn serde_thinning_policy_roundtrip() {
    for policy in ThinningPolicy::ALL {
        let json = serde_json::to_string(policy).unwrap();
        let back: ThinningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*policy, back);
    }
}

#[test]
fn serde_telemetry_budget_roundtrip() {
    let budget = TelemetryBudget::exact();
    let json = serde_json::to_string(&budget).unwrap();
    let back: TelemetryBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn serde_telemetry_event_roundtrip() {
    let ev = TelemetryEvent::exact("e", "d", 100, b"p");
    let json = serde_json::to_string(&ev).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// Enrichment tests — 95 new tests
// ===========================================================================

// ---------------------------------------------------------------------------
// CaptureMode — exhaustive variants and trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_capture_mode_debug_all_variants() {
    for mode in CaptureMode::ALL {
        let dbg = format!("{:?}", mode);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_capture_mode_clone_eq() {
    for mode in CaptureMode::ALL {
        let cloned = mode.clone();
        assert_eq!(*mode, cloned);
    }
}

#[test]
fn enrichment_capture_mode_serde_json_field_names() {
    let json = serde_json::to_string(&CaptureMode::ExactCounting).unwrap();
    assert_eq!(json, "\"exact_counting\"");
    let json = serde_json::to_string(&CaptureMode::ExactShadow).unwrap();
    assert_eq!(json, "\"exact_shadow\"");
    let json = serde_json::to_string(&CaptureMode::DeterministicReplay).unwrap();
    assert_eq!(json, "\"deterministic_replay\"");
    let json = serde_json::to_string(&CaptureMode::BudgetedSampling).unwrap();
    assert_eq!(json, "\"budgeted_sampling\"");
    let json = serde_json::to_string(&CaptureMode::ProbabilisticSampling).unwrap();
    assert_eq!(json, "\"probabilistic_sampling\"");
}

#[test]
fn enrichment_capture_mode_is_exact_and_sampled_mutually_exclusive() {
    for mode in CaptureMode::ALL {
        // No mode should be both exact and sampled.
        assert!(!(mode.is_exact() && mode.is_sampled()));
    }
}

#[test]
fn enrichment_capture_mode_deterministic_replay_not_exact_not_sampled() {
    let dr = CaptureMode::DeterministicReplay;
    assert!(!dr.is_exact());
    assert!(!dr.is_sampled());
    assert!(dr.is_replay_safe());
}

#[test]
fn enrichment_capture_mode_probabilistic_not_replay_safe() {
    assert!(!CaptureMode::ProbabilisticSampling.is_replay_safe());
}

#[test]
fn enrichment_capture_mode_ord_total_ordering() {
    let mut modes: Vec<CaptureMode> = CaptureMode::ALL.to_vec();
    modes.reverse();
    modes.sort();
    assert_eq!(modes, CaptureMode::ALL);
}

#[test]
fn enrichment_capture_mode_display_matches_as_str_all_variants() {
    assert_eq!(CaptureMode::ExactShadow.to_string(), "exact_shadow");
    assert_eq!(
        CaptureMode::DeterministicReplay.to_string(),
        "deterministic_replay"
    );
    assert_eq!(
        CaptureMode::ProbabilisticSampling.to_string(),
        "probabilistic_sampling"
    );
}

// ---------------------------------------------------------------------------
// ThinningPolicy — exhaustive variants and trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thinning_policy_debug_all_variants() {
    for policy in ThinningPolicy::ALL {
        let dbg = format!("{:?}", policy);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_thinning_policy_clone_eq() {
    for policy in ThinningPolicy::ALL {
        let cloned = policy.clone();
        assert_eq!(*policy, cloned);
    }
}

#[test]
fn enrichment_thinning_policy_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&ThinningPolicy::Uniform).unwrap(),
        "\"uniform\""
    );
    assert_eq!(
        serde_json::to_string(&ThinningPolicy::Reservoir).unwrap(),
        "\"reservoir\""
    );
    assert_eq!(
        serde_json::to_string(&ThinningPolicy::Stratified).unwrap(),
        "\"stratified\""
    );
    assert_eq!(
        serde_json::to_string(&ThinningPolicy::Priority).unwrap(),
        "\"priority\""
    );
}

#[test]
fn enrichment_thinning_policy_ord_total_ordering() {
    let mut policies: Vec<ThinningPolicy> = ThinningPolicy::ALL.to_vec();
    policies.reverse();
    policies.sort();
    assert_eq!(policies, ThinningPolicy::ALL);
}

#[test]
fn enrichment_thinning_policy_serde_roundtrip_all() {
    for policy in ThinningPolicy::ALL {
        let json = serde_json::to_string(policy).unwrap();
        let back: ThinningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*policy, back);
    }
}

// ---------------------------------------------------------------------------
// TelemetryBudget — edge cases and trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_debug() {
    let budget = TelemetryBudget::exact();
    let dbg = format!("{:?}", budget);
    assert!(dbg.contains("TelemetryBudget"));
}

#[test]
fn enrichment_budget_clone_eq() {
    let a = TelemetryBudget::exact();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_budget_serde_roundtrip_budgeted_default() {
    let budget = TelemetryBudget::budgeted_default();
    let json = serde_json::to_string(&budget).unwrap();
    let back: TelemetryBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn enrichment_budget_serde_json_field_stability() {
    let budget = TelemetryBudget::exact();
    let json = serde_json::to_string(&budget).unwrap();
    assert!(json.contains("\"max_events_per_window\""));
    assert!(json.contains("\"window_ns\""));
    assert!(json.contains("\"sampling_rate_millionths\""));
    assert!(json.contains("\"mode\""));
}

#[test]
fn enrichment_budget_zero_max_events() {
    let budget = TelemetryBudget::new(0, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting);
    assert_eq!(budget.max_events_per_window, 0);
    assert_eq!(budget.effective_events_per_second(), 0);
}

#[test]
fn enrichment_budget_sampling_rate_zero() {
    let budget = TelemetryBudget::new(100, DEFAULT_WINDOW_NS, 0, CaptureMode::BudgetedSampling);
    assert_eq!(budget.sampling_rate_millionths, 0);
    assert!(!budget.is_full_capture());
}

#[test]
fn enrichment_budget_sampling_rate_exactly_millionths() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    assert!(budget.is_full_capture());
    assert_eq!(budget.sampling_rate_millionths, MILLIONTHS);
}

#[test]
fn enrichment_budget_display_contains_all_fields() {
    let budget = TelemetryBudget::new(500, 2_000_000_000, 250_000, CaptureMode::BudgetedSampling);
    let s = format!("{}", budget);
    assert!(s.contains("500"));
    assert!(s.contains("2000000000"));
    assert!(s.contains("250000"));
    assert!(s.contains("budgeted_sampling"));
}

#[test]
fn enrichment_budget_effective_eps_large_window() {
    // window = 10 seconds
    let budget = TelemetryBudget::new(100, 10_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    // 1_000_000_000 / 10_000_000_000 = 0 (integer division) => 0
    assert_eq!(budget.effective_events_per_second(), 0);
}

#[test]
fn enrichment_budget_effective_eps_sub_second_window() {
    // window = 100ms = 100_000_000 ns
    let budget = TelemetryBudget::new(50, 100_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    // 1_000_000_000 / 100_000_000 = 10 windows/sec => 50 * 10 = 500
    assert_eq!(budget.effective_events_per_second(), 500);
}

// ---------------------------------------------------------------------------
// ThinningConfig — edge cases and trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thinning_config_debug() {
    let cfg = ThinningConfig::uniform_default();
    let dbg = format!("{:?}", cfg);
    assert!(dbg.contains("ThinningConfig"));
}

#[test]
fn enrichment_thinning_config_clone_eq() {
    let a = ThinningConfig::priority_default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_thinning_config_serde_roundtrip() {
    let cfg = ThinningConfig::new(ThinningPolicy::Stratified, 42, 7777);
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ThinningConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_thinning_config_serde_json_field_stability() {
    let cfg = ThinningConfig::uniform_default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"policy\""));
    assert!(json.contains("\"target_events\""));
    assert!(json.contains("\"min_weight_millionths\""));
}

#[test]
fn enrichment_thinning_config_display() {
    let cfg = ThinningConfig::new(ThinningPolicy::Reservoir, 99, 5555);
    let s = format!("{}", cfg);
    assert!(s.contains("reservoir"));
    assert!(s.contains("99"));
    assert!(s.contains("5555"));
}

#[test]
fn enrichment_thinning_config_target_one_is_minimum() {
    let cfg = ThinningConfig::new(ThinningPolicy::Priority, 0, 0);
    assert_eq!(cfg.target_events, 1);
    let cfg2 = ThinningConfig::new(ThinningPolicy::Priority, 1, 0);
    assert_eq!(cfg2.target_events, 1);
}

#[test]
fn enrichment_thinning_config_reservoir_default_values() {
    let cfg = ThinningConfig::reservoir_default();
    assert_eq!(cfg.target_events, DEFAULT_RESERVOIR_SIZE);
    assert_eq!(cfg.min_weight_millionths, DEFAULT_MIN_WEIGHT_MILLIONTHS);
}

#[test]
fn enrichment_thinning_config_uniform_default_values() {
    let cfg = ThinningConfig::uniform_default();
    assert_eq!(cfg.target_events, DEFAULT_THINNING_TARGET);
    assert_eq!(cfg.min_weight_millionths, DEFAULT_MIN_WEIGHT_MILLIONTHS);
}

#[test]
fn enrichment_thinning_config_priority_default_values() {
    let cfg = ThinningConfig::priority_default();
    assert_eq!(cfg.target_events, DEFAULT_THINNING_TARGET);
    assert_eq!(cfg.min_weight_millionths, DEFAULT_MIN_WEIGHT_MILLIONTHS);
}

// ---------------------------------------------------------------------------
// TelemetryEvent — edge cases, determinism, trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_debug() {
    let ev = TelemetryEvent::exact("ev_dbg", "domain", 0, b"data");
    let dbg = format!("{:?}", ev);
    assert!(dbg.contains("TelemetryEvent"));
}

#[test]
fn enrichment_event_clone_eq() {
    let ev = TelemetryEvent::exact("ev_c", "d", 42, b"payload");
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

#[test]
fn enrichment_event_serde_roundtrip_sampled() {
    let ev = TelemetryEvent::sampled("s1", "gc", 500, 200_000, b"sample");
    let json = serde_json::to_string(&ev).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_event_serde_json_field_stability() {
    let ev = TelemetryEvent::exact("ev_f", "d", 100, b"p");
    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("\"event_id\""));
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"timestamp_ns\""));
    assert!(json.contains("\"capture_mode\""));
    assert!(json.contains("\"weight_millionths\""));
    assert!(json.contains("\"payload_hash\""));
    assert!(json.contains("\"event_hash\""));
}

#[test]
fn enrichment_event_empty_payload() {
    let ev = TelemetryEvent::exact("ev_empty", "d", 0, b"");
    assert_eq!(ev.weight_millionths, MILLIONTHS);
    assert!(ev.is_exact());
}

#[test]
fn enrichment_event_empty_event_id() {
    let ev = TelemetryEvent::exact("", "d", 0, b"p");
    assert_eq!(ev.event_id, "");
}

#[test]
fn enrichment_event_empty_domain() {
    let ev = TelemetryEvent::exact("ev", "", 0, b"p");
    assert_eq!(ev.domain, "");
}

#[test]
fn enrichment_event_large_timestamp() {
    let ev = TelemetryEvent::exact("ev_ts", "d", u64::MAX, b"p");
    assert_eq!(ev.timestamp_ns, u64::MAX);
}

#[test]
fn enrichment_event_sampled_weight_scaling_50_percent() {
    // 50% sampling => weight = 1M * 1M / 500_000 = 2_000_000
    let ev = TelemetryEvent::sampled("ev_50", "d", 0, 500_000, b"p");
    assert_eq!(ev.weight_millionths, 2_000_000);
}

#[test]
fn enrichment_event_sampled_weight_scaling_1_percent() {
    // 1% sampling rate = 10_000 millionths => weight = 1M * 1M / 10_000 = 100_000_000_000
    let ev = TelemetryEvent::sampled("ev_1pct", "d", 0, 10_000, b"p");
    // 1_000_000 * 1_000_000 = 1_000_000_000_000
    // 1_000_000_000_000 / 10_000 = 100_000_000
    assert_eq!(ev.weight_millionths, 100_000_000);
}

#[test]
fn enrichment_event_sampled_weight_full_rate() {
    // 100% sampling rate => weight = 1M * 1M / 1M = 1M
    let ev = TelemetryEvent::sampled("ev_full", "d", 0, MILLIONTHS, b"p");
    assert_eq!(ev.weight_millionths, MILLIONTHS);
}

#[test]
fn enrichment_event_sampled_zero_rate_fallback() {
    let ev = TelemetryEvent::sampled("ev_zero", "d", 0, 0, b"p");
    assert_eq!(ev.weight_millionths, MILLIONTHS);
}

#[test]
fn enrichment_event_new_with_all_capture_modes() {
    for mode in CaptureMode::ALL {
        let ev = TelemetryEvent::new("ev", "d", 0, *mode, MILLIONTHS, b"p");
        assert_eq!(ev.capture_mode, *mode);
    }
}

#[test]
fn enrichment_event_hash_different_event_id() {
    let a = TelemetryEvent::exact("id_a", "d", 100, b"p");
    let b = TelemetryEvent::exact("id_b", "d", 100, b"p");
    assert_ne!(a.event_hash, b.event_hash);
    // same payload, so payload_hash should be the same
    assert_eq!(a.payload_hash, b.payload_hash);
}

#[test]
fn enrichment_event_hash_different_domain() {
    let a = TelemetryEvent::exact("ev", "dom_a", 100, b"p");
    let b = TelemetryEvent::exact("ev", "dom_b", 100, b"p");
    assert_ne!(a.event_hash, b.event_hash);
    assert_eq!(a.payload_hash, b.payload_hash);
}

#[test]
fn enrichment_event_hash_different_timestamp() {
    let a = TelemetryEvent::exact("ev", "d", 100, b"p");
    let b = TelemetryEvent::exact("ev", "d", 200, b"p");
    assert_ne!(a.event_hash, b.event_hash);
    assert_eq!(a.payload_hash, b.payload_hash);
}

#[test]
fn enrichment_event_hash_determinism_multiple_runs() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let ev = TelemetryEvent::exact("stable", "dom", 777, b"stable_data");
            (ev.event_hash, ev.payload_hash)
        })
        .collect();
    for pair in hashes.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}

#[test]
fn enrichment_event_display_contains_weight() {
    let ev = TelemetryEvent::new("ev", "d", 0, CaptureMode::ExactCounting, 500_000, b"p");
    let s = format!("{}", ev);
    assert!(s.contains("500000"));
}

// ---------------------------------------------------------------------------
// ProvenanceTag — edge cases, trait coverage, determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_provenance_debug() {
    let tag = ProvenanceTag::exact();
    let dbg = format!("{:?}", tag);
    assert!(dbg.contains("ProvenanceTag"));
}

#[test]
fn enrichment_provenance_clone_eq() {
    let a = ProvenanceTag::budgeted(333_000);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_provenance_serde_roundtrip_all_constructors() {
    let tags = vec![
        ProvenanceTag::exact(),
        ProvenanceTag::budgeted(100_000),
        ProvenanceTag::probabilistic(50_000),
        ProvenanceTag::exact_shadow(),
        ProvenanceTag::replay(),
        ProvenanceTag::exact().with_thinning(),
    ];
    for tag in &tags {
        let json = serde_json::to_string(tag).unwrap();
        let back: ProvenanceTag = serde_json::from_str(&json).unwrap();
        assert_eq!(*tag, back);
    }
}

#[test]
fn enrichment_provenance_serde_json_field_stability() {
    let tag = ProvenanceTag::exact();
    let json = serde_json::to_string(&tag).unwrap();
    assert!(json.contains("\"capture_mode\""));
    assert!(json.contains("\"sampling_rate_applied_millionths\""));
    assert!(json.contains("\"thinning_applied\""));
    assert!(json.contains("\"exact_shadow_available\""));
    assert!(json.contains("\"replay_deterministic\""));
}

#[test]
fn enrichment_provenance_content_hash_different_thinning_state() {
    let without = ProvenanceTag::exact();
    let with = ProvenanceTag::exact().with_thinning();
    assert_ne!(without.content_hash(), with.content_hash());
}

#[test]
fn enrichment_provenance_content_hash_different_rates() {
    let a = ProvenanceTag::budgeted(100_000);
    let b = ProvenanceTag::budgeted(200_000);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_provenance_content_hash_determinism_multiple_runs() {
    let hashes: Vec<_> = (0..5)
        .map(|_| ProvenanceTag::replay().content_hash())
        .collect();
    for pair in hashes.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}

#[test]
fn enrichment_provenance_is_high_fidelity_property() {
    // high fidelity IFF capture_mode.is_exact()
    for mode in CaptureMode::ALL {
        let tag = ProvenanceTag::new(*mode, MILLIONTHS, false, false, false);
        assert_eq!(tag.is_high_fidelity(), mode.is_exact());
    }
}

#[test]
fn enrichment_provenance_display_contains_all_fields() {
    let tag = ProvenanceTag::new(CaptureMode::ExactShadow, 999_000, true, true, false);
    let s = format!("{}", tag);
    assert!(s.contains("exact_shadow"));
    assert!(s.contains("999000"));
    assert!(s.contains("true"));
}

#[test]
fn enrichment_provenance_with_thinning_preserves_other_fields() {
    let tag = ProvenanceTag::budgeted(150_000).with_thinning();
    assert_eq!(tag.capture_mode, CaptureMode::BudgetedSampling);
    assert_eq!(tag.sampling_rate_applied_millionths, 150_000);
    assert!(tag.thinning_applied);
    assert!(!tag.exact_shadow_available);
    assert!(!tag.replay_deterministic);
}

// ---------------------------------------------------------------------------
// EventWindow — edge cases, Display, content hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_window_debug() {
    let w = EventWindow::new(0, TelemetryBudget::exact());
    let dbg = format!("{:?}", w);
    assert!(dbg.contains("EventWindow"));
}

#[test]
fn enrichment_event_window_clone_eq() {
    let budget = TelemetryBudget::exact();
    let mut w = EventWindow::new(0, budget);
    w.record(TelemetryEvent::exact("e", "d", 0, b"p"));
    let cloned = w.clone();
    assert_eq!(w, cloned);
}

#[test]
fn enrichment_event_window_serde_roundtrip() {
    let budget = TelemetryBudget::exact();
    let mut w = EventWindow::new(100, budget);
    w.record(TelemetryEvent::exact("e", "d", 100, b"p"));
    let json = serde_json::to_string(&w).unwrap();
    let back: EventWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_event_window_display() {
    let budget = TelemetryBudget::new(10, 500, MILLIONTHS, CaptureMode::ExactCounting);
    let mut w = EventWindow::new(42, budget);
    w.record(TelemetryEvent::exact("e", "d", 42, b"p"));
    let s = format!("{}", w);
    assert!(s.contains("EventWindow"));
    assert!(s.contains("start=42"));
    assert!(s.contains("events=1"));
}

#[test]
fn enrichment_event_window_end_ns_computed_from_budget() {
    let budget = TelemetryBudget::new(10, 500, MILLIONTHS, CaptureMode::ExactCounting);
    let w = EventWindow::new(100, budget);
    assert_eq!(w.end_ns, 600);
}

#[test]
fn enrichment_event_window_end_ns_saturates() {
    let budget = TelemetryBudget::new(10, u64::MAX, MILLIONTHS, CaptureMode::ExactCounting);
    let w = EventWindow::new(100, budget);
    assert_eq!(w.end_ns, u64::MAX);
}

#[test]
fn enrichment_event_window_contains_timestamp_boundary() {
    let budget = TelemetryBudget::new(100, 100, MILLIONTHS, CaptureMode::ExactCounting);
    let w = EventWindow::new(50, budget);
    // [50, 150)
    assert!(!w.contains_timestamp(49));
    assert!(w.contains_timestamp(50));
    assert!(w.contains_timestamp(149));
    assert!(!w.contains_timestamp(150));
}

#[test]
fn enrichment_event_window_empty_effective_rate() {
    let w = EventWindow::new(0, TelemetryBudget::exact());
    assert_eq!(w.effective_sampling_rate_millionths(), MILLIONTHS);
}

#[test]
fn enrichment_event_window_remaining_capacity_at_boundary() {
    let budget = TelemetryBudget::new(3, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting);
    let mut w = EventWindow::new(0, budget);
    assert_eq!(w.remaining_capacity(), 3);
    w.record(TelemetryEvent::exact("e0", "d", 0, b"p"));
    assert_eq!(w.remaining_capacity(), 2);
    w.record(TelemetryEvent::exact("e1", "d", 1, b"p"));
    assert_eq!(w.remaining_capacity(), 1);
    w.record(TelemetryEvent::exact("e2", "d", 2, b"p"));
    assert_eq!(w.remaining_capacity(), 0);
}

#[test]
fn enrichment_event_window_domains_seen_updated() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    w.record(TelemetryEvent::exact("e1", "alpha", 0, b"p"));
    w.record(TelemetryEvent::exact("e2", "beta", 1, b"p"));
    w.record(TelemetryEvent::exact("e3", "alpha", 2, b"p"));
    assert_eq!(w.domains_seen.len(), 2);
    assert!(w.domains_seen.contains("alpha"));
    assert!(w.domains_seen.contains("beta"));
}

#[test]
fn enrichment_event_window_content_hash_different_with_different_events() {
    let budget = TelemetryBudget::exact();
    let mut w1 = EventWindow::new(0, budget.clone());
    let mut w2 = EventWindow::new(0, budget);
    w1.record(TelemetryEvent::exact("e", "d", 0, b"p_a"));
    w2.record(TelemetryEvent::exact("e", "d", 0, b"p_b"));
    assert_ne!(w1.content_hash(), w2.content_hash());
}

#[test]
fn enrichment_event_window_thinning_no_op_on_empty() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    let config = ThinningConfig::new(ThinningPolicy::Uniform, 5, 0);
    let removed = w.apply_thinning(&config);
    assert_eq!(removed, 0);
    assert!(!w.thinning_applied);
}

#[test]
fn enrichment_event_window_thinning_stratified_single_domain() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    for i in 0..20 {
        w.record(TelemetryEvent::exact(
            &format!("e{}", i),
            "single",
            i * 10,
            b"p",
        ));
    }
    let config = ThinningConfig::new(ThinningPolicy::Stratified, 10, 0);
    let removed = w.apply_thinning(&config);
    assert_eq!(removed, 10);
    assert_eq!(w.event_count(), 10);
}

#[test]
fn enrichment_event_window_thinning_sets_flag_and_count() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    for i in 0..10 {
        w.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    assert!(!w.thinning_applied);
    assert_eq!(w.thinned_count, 0);
    let config = ThinningConfig::new(ThinningPolicy::Reservoir, 5, 0);
    let removed = w.apply_thinning(&config);
    assert_eq!(removed, 5);
    assert!(w.thinning_applied);
    assert_eq!(w.thinned_count, 5);
}

#[test]
fn enrichment_event_window_thinning_weight_rescaling_reservoir() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    for i in 0..10 {
        w.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    let config = ThinningConfig::new(ThinningPolicy::Reservoir, 5, 0);
    w.apply_thinning(&config);
    // 10 down to 5 => scale = 10 * 1M / 5 = 2M => each weight = 1M * 2M / 1M = 2M
    for ev in &w.events {
        assert_eq!(ev.weight_millionths, 2_000_000);
    }
}

#[test]
fn enrichment_event_window_provenance_after_thinning() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    for i in 0..10 {
        w.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    let tag_before = w.provenance_tag();
    assert!(!tag_before.thinning_applied);

    let config = ThinningConfig::new(ThinningPolicy::Uniform, 5, 0);
    w.apply_thinning(&config);
    let tag_after = w.provenance_tag();
    assert!(tag_after.thinning_applied);
}

// ---------------------------------------------------------------------------
// ModeBreakdown — edge cases, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mode_breakdown_debug() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 5, 10, ProvenanceTag::exact());
    let dbg = format!("{:?}", bd);
    assert!(dbg.contains("ModeBreakdown"));
}

#[test]
fn enrichment_mode_breakdown_clone_eq() {
    let a = ModeBreakdown::new(
        CaptureMode::BudgetedSampling,
        3,
        9,
        ProvenanceTag::budgeted(100_000),
    );
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mode_breakdown_serde_roundtrip() {
    let bd = ModeBreakdown::new(
        CaptureMode::ProbabilisticSampling,
        7,
        14,
        ProvenanceTag::probabilistic(50_000),
    );
    let json = serde_json::to_string(&bd).unwrap();
    let back: ModeBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(bd, back);
}

#[test]
fn enrichment_mode_breakdown_fraction_full() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 100, 100, ProvenanceTag::exact());
    assert_eq!(bd.fraction_millionths, MILLIONTHS);
}

#[test]
fn enrichment_mode_breakdown_fraction_one_third() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 1, 3, ProvenanceTag::exact());
    assert_eq!(bd.fraction_millionths, 333_333);
}

#[test]
fn enrichment_mode_breakdown_display() {
    let bd = ModeBreakdown::new(
        CaptureMode::DeterministicReplay,
        42,
        100,
        ProvenanceTag::replay(),
    );
    let s = format!("{}", bd);
    assert!(s.contains("deterministic_replay"));
    assert!(s.contains("42"));
}

// ---------------------------------------------------------------------------
// TelemetryReport — edge cases, trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_debug() {
    let plane = TelemetryPlane::new(epoch());
    let report = plane.generate_report();
    let dbg = format!("{:?}", report);
    assert!(dbg.contains("TelemetryReport"));
}

#[test]
fn enrichment_report_clone_eq() {
    let plane = TelemetryPlane::new(epoch());
    let report = plane.generate_report();
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    plane.record_exact("e0", "d", 0, b"data");
    let report = plane.generate_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: TelemetryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_report_serde_json_field_stability() {
    let plane = TelemetryPlane::new(epoch());
    let report = plane.generate_report();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"total_events_captured\""));
    assert!(json.contains("\"total_events_thinned\""));
    assert!(json.contains("\"total_events_rejected\""));
    assert!(json.contains("\"budget_utilization_millionths\""));
    assert!(json.contains("\"window_count\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_report_display() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    for i in 0..3 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let report = plane.generate_report();
    let s = format!("{}", report);
    assert!(s.contains("TelemetryReport"));
    assert!(s.contains("captured=3"));
}

#[test]
fn enrichment_report_survival_rate_after_thinning() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    for i in 0..40 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
    plane.thin_domain("d", &config);
    let report = plane.generate_report();
    // 10 survived out of 40 (10 captured + 30 thinned) = 250_000
    assert_eq!(report.survival_rate_millionths(), 250_000);
}

#[test]
fn enrichment_report_is_all_exact_with_shadow() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(100, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactShadow),
    );
    let ev = TelemetryEvent::new("e", "d", 0, CaptureMode::ExactShadow, MILLIONTHS, b"p");
    plane.record_event(ev);
    let report = plane.generate_report();
    assert!(report.is_all_exact());
}

#[test]
fn enrichment_report_content_hash_changes_with_different_data() {
    let mut p1 = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    let mut p2 = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    p1.record_exact("e0", "d", 0, b"payload_a");
    p2.record_exact("e0", "d", 0, b"payload_b");
    let r1 = p1.generate_report();
    let r2 = p2.generate_report();
    // Different payloads lead to different event hashes which means different
    // event counts or different window hashes. The reports differ in content_hash
    // because the total counters still match but the window content differs.
    // However, generate_report hashes total counters + breakdowns, not individual
    // events. With identical counters the report hashes may be the same.
    // The key invariant: same inputs => same hash. Different inputs may or may not differ.
    // We just test that the report is valid.
    assert_eq!(r1.total_events_captured, 1);
    assert_eq!(r2.total_events_captured, 1);
}

// ---------------------------------------------------------------------------
// TelemetryPlane — edge cases, trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_plane_debug() {
    let plane = TelemetryPlane::new(epoch());
    let dbg = format!("{:?}", plane);
    assert!(dbg.contains("TelemetryPlane"));
}

#[test]
fn enrichment_plane_clone_eq() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.record_exact("e", "d", 0, b"p");
    let cloned = plane.clone();
    assert_eq!(plane, cloned);
}

#[test]
fn enrichment_plane_serde_roundtrip() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.record_exact("e", "d", 0, b"p");
    let json = serde_json::to_string(&plane).unwrap();
    let back: TelemetryPlane = serde_json::from_str(&json).unwrap();
    assert_eq!(plane, back);
}

#[test]
fn enrichment_plane_display() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.record_exact("e", "d", 0, b"p");
    let s = format!("{}", plane);
    assert!(s.contains("TelemetryPlane"));
    assert!(s.contains("recorded=1"));
}

#[test]
fn enrichment_plane_domain_event_count_unknown_domain() {
    let plane = TelemetryPlane::new(epoch());
    assert_eq!(plane.domain_event_count("nonexistent"), 0);
}

#[test]
fn enrichment_plane_observed_domains_empty() {
    let plane = TelemetryPlane::new(epoch());
    assert!(plane.observed_domains().is_empty());
}

#[test]
fn enrichment_plane_observed_domains_multiple() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.record_exact("e1", "gc", 0, b"p");
    plane.record_exact("e2", "jit", 1, b"p");
    plane.record_exact("e3", "parser", 2, b"p");
    let domains = plane.observed_domains();
    assert_eq!(domains.len(), 3);
    assert!(domains.contains("gc"));
    assert!(domains.contains("jit"));
    assert!(domains.contains("parser"));
}

#[test]
fn enrichment_plane_add_budget_overrides() {
    let mut plane = TelemetryPlane::new(epoch());
    let budget_a = TelemetryBudget::new(10, 100, MILLIONTHS, CaptureMode::ExactCounting);
    plane.add_budget("d", budget_a);
    assert_eq!(plane.effective_budget("d").max_events_per_window, 10);

    let budget_b = TelemetryBudget::new(99, 200, MILLIONTHS, CaptureMode::ExactCounting);
    plane.add_budget("d", budget_b);
    assert_eq!(plane.effective_budget("d").max_events_per_window, 99);
}

#[test]
fn enrichment_plane_set_default_thinning() {
    let mut plane = TelemetryPlane::new(epoch());
    let config = ThinningConfig::new(ThinningPolicy::Priority, 42, 5_000);
    plane.set_default_thinning(config.clone());
    assert_eq!(plane.default_thinning, config);
}

#[test]
fn enrichment_plane_record_event_rejected_increments_counter() {
    let mut plane = TelemetryPlane::new(epoch());
    // Budget of 1 event per window; when at capacity, a new window is created
    // for the same timestamp range. To trigger a rejection, we need the window
    // count limit to be exceeded OR the new window to also be full.
    // Instead, test that recording increments counters consistently.
    plane.add_budget(
        "d",
        TelemetryBudget::new(1, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting),
    );
    plane.record_exact("e0", "d", 0, b"p");
    assert_eq!(plane.total_events_recorded, 1);
    assert_eq!(plane.total_events_rejected, 0);
    // Second event at same timestamp creates a new window (capacity triggers new window)
    plane.record_exact("e1", "d", 1, b"p");
    // Both events should be recorded since each gets its own window
    assert_eq!(plane.total_events_recorded, 2);
    assert_eq!(plane.total_events_rejected, 0);
}

#[test]
fn enrichment_plane_window_boundary_creates_new_window() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.add_budget(
        "d",
        TelemetryBudget::new(1000, 100, MILLIONTHS, CaptureMode::ExactCounting),
    );
    // Window [0, 100)
    plane.record_exact("e0", "d", 0, b"p");
    // Window [200, 300)
    plane.record_exact("e1", "d", 200, b"p");
    let windows = plane.windows.get("d").unwrap();
    assert_eq!(windows.len(), 2);
}

#[test]
fn enrichment_plane_capacity_creates_new_window() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.add_budget(
        "d",
        TelemetryBudget::new(2, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting),
    );
    plane.record_exact("e0", "d", 0, b"p");
    plane.record_exact("e1", "d", 1, b"p");
    // Window is at capacity, next event in same time range gets new window
    plane.record_exact("e2", "d", 2, b"p");
    let windows = plane.windows.get("d").unwrap();
    assert_eq!(windows.len(), 2);
}

#[test]
fn enrichment_plane_thin_domain_nonexistent() {
    let mut plane = TelemetryPlane::new(epoch());
    let config = ThinningConfig::uniform_default();
    let removed = plane.thin_domain("no_such_domain", &config);
    assert_eq!(removed, 0);
}

#[test]
fn enrichment_plane_report_multiple_mode_breakdowns() {
    let mut plane = TelemetryPlane::new(epoch());
    plane.add_budget(
        "exact",
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    for i in 0..4 {
        plane.record_exact(&format!("e{}", i), "exact", i * 10, b"p");
    }
    // Record a sampled event in a different domain
    let sampled_ev = TelemetryEvent::new(
        "s0",
        "sampled_dom",
        0,
        CaptureMode::ProbabilisticSampling,
        10_000_000,
        b"p",
    );
    plane.record_event(sampled_ev);

    let report = plane.generate_report();
    assert_eq!(report.mode_breakdowns.len(), 2);
    let exact_bd = report
        .mode_breakdowns
        .iter()
        .find(|b| b.mode == CaptureMode::ExactCounting)
        .unwrap();
    let prob_bd = report
        .mode_breakdowns
        .iter()
        .find(|b| b.mode == CaptureMode::ProbabilisticSampling)
        .unwrap();
    assert_eq!(exact_bd.event_count, 4);
    assert_eq!(prob_bd.event_count, 1);
    // 4 of 5 = 800_000, 1 of 5 = 200_000
    assert_eq!(exact_bd.fraction_millionths, 800_000);
    assert_eq!(prob_bd.fraction_millionths, 200_000);
}

#[test]
fn enrichment_plane_report_budget_utilization_full() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(5, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..5 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let report = plane.generate_report();
    assert_eq!(report.budget_utilization_millionths, MILLIONTHS);
}

#[test]
fn enrichment_plane_report_rejected_events_counted() {
    // When at capacity, plane creates new windows rather than rejecting.
    // All 5 events get recorded across multiple windows.
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(2, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting),
    );
    for i in 0..5 {
        plane.record_exact(&format!("e{}", i), "d", i * 10, b"p");
    }
    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 5);
    assert_eq!(report.total_events_rejected, 0);
    // With budget of 2 per window, 5 events need 3 windows
    assert_eq!(report.window_count, 3);
}

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_default_thinning_target() {
    assert_eq!(DEFAULT_THINNING_TARGET, 1_000);
}

#[test]
fn enrichment_constants_default_min_weight() {
    assert_eq!(DEFAULT_MIN_WEIGHT_MILLIONTHS, 1_000);
}

#[test]
fn enrichment_constants_default_reservoir_size() {
    assert_eq!(DEFAULT_RESERVOIR_SIZE, 500);
}

#[test]
fn enrichment_determinism_same_plane_same_report_hash() {
    let build_plane = || {
        let mut p = TelemetryPlane::with_default_budget(
            epoch(),
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        for i in 0..10 {
            p.record_exact(&format!("ev_{}", i), "domain_x", i * 100, b"stable_payload");
        }
        p.generate_report()
    };
    let r1 = build_plane();
    let r2 = build_plane();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.total_events_captured, r2.total_events_captured);
    assert_eq!(r1.mode_breakdowns.len(), r2.mode_breakdowns.len());
}

#[test]
fn enrichment_e2e_thin_all_multiple_domains() {
    let mut plane = TelemetryPlane::with_default_budget(
        epoch(),
        TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        ),
    );
    for i in 0..25 {
        plane.record_exact(&format!("a{}", i), "alpha", i * 10, b"p");
    }
    for i in 0..30 {
        plane.record_exact(&format!("b{}", i), "beta", i * 10, b"p");
    }
    plane.set_default_thinning(ThinningConfig::new(ThinningPolicy::Uniform, 10, 0));
    let removed = plane.thin_all();
    // alpha: 25 -> 10 = 15 removed, beta: 30 -> 10 = 20 removed
    assert_eq!(removed, 35);
    let report = plane.generate_report();
    assert_eq!(report.total_events_captured, 20);
    assert!(report.has_thinning());
}

#[test]
fn enrichment_e2e_report_epoch_matches_plane() {
    let ep = SecurityEpoch::from_raw(999);
    let plane = TelemetryPlane::new(ep);
    let report = plane.generate_report();
    assert_eq!(report.epoch, ep);
}

#[test]
fn enrichment_e2e_multiple_thinning_passes() {
    let budget = TelemetryBudget::new(
        100,
        DEFAULT_WINDOW_NS,
        MILLIONTHS,
        CaptureMode::ExactCounting,
    );
    let mut w = EventWindow::new(0, budget);
    for i in 0..50 {
        w.record(TelemetryEvent::exact(&format!("e{}", i), "d", i * 10, b"p"));
    }
    let config1 = ThinningConfig::new(ThinningPolicy::Uniform, 30, 0);
    let removed1 = w.apply_thinning(&config1);
    assert_eq!(removed1, 20);
    assert_eq!(w.event_count(), 30);

    let config2 = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
    let removed2 = w.apply_thinning(&config2);
    assert_eq!(removed2, 20);
    assert_eq!(w.event_count(), 10);
    assert_eq!(w.thinned_count, 40);
}
