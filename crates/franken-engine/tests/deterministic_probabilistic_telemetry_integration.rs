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
