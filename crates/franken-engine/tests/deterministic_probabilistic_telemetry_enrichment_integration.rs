//! Enrichment integration tests for `deterministic_probabilistic_telemetry` module.
//!
//! Tests additional scenarios: budget lifecycle, window operations, thinning,
//! plane orchestration, report generation, provenance tags, Display/serde coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::deterministic_probabilistic_telemetry::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// CaptureMode enrichment
// ---------------------------------------------------------------------------

#[test]
fn capture_mode_is_exact_true_for_exact_modes() {
    assert!(CaptureMode::ExactCounting.is_exact());
    assert!(CaptureMode::ExactShadow.is_exact());
}

#[test]
fn capture_mode_is_exact_false_for_non_exact() {
    assert!(!CaptureMode::DeterministicReplay.is_exact());
    assert!(!CaptureMode::BudgetedSampling.is_exact());
    assert!(!CaptureMode::ProbabilisticSampling.is_exact());
}

#[test]
fn capture_mode_is_sampled() {
    assert!(CaptureMode::BudgetedSampling.is_sampled());
    assert!(CaptureMode::ProbabilisticSampling.is_sampled());
    assert!(!CaptureMode::ExactCounting.is_sampled());
}

#[test]
fn capture_mode_is_replay_safe() {
    assert!(CaptureMode::ExactCounting.is_replay_safe());
    assert!(CaptureMode::DeterministicReplay.is_replay_safe());
    assert!(!CaptureMode::BudgetedSampling.is_replay_safe());
}

#[test]
fn capture_mode_serde_roundtrip_all() {
    for m in CaptureMode::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: CaptureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

#[test]
fn capture_mode_display_distinctness() {
    let displays: BTreeSet<String> = CaptureMode::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// ThinningPolicy enrichment
// ---------------------------------------------------------------------------

#[test]
fn thinning_policy_all_count() {
    assert_eq!(ThinningPolicy::ALL.len(), 4);
}

#[test]
fn thinning_policy_display_distinctness() {
    let displays: BTreeSet<String> = ThinningPolicy::ALL.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn thinning_policy_serde_roundtrip_all() {
    for p in ThinningPolicy::ALL {
        let json = serde_json::to_string(p).unwrap();
        let back: ThinningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

// ---------------------------------------------------------------------------
// TelemetryBudget enrichment
// ---------------------------------------------------------------------------

#[test]
fn budget_exact_defaults() {
    let b = TelemetryBudget::exact();
    assert_eq!(b.max_events_per_window, DEFAULT_MAX_EVENTS_PER_WINDOW);
    assert_eq!(b.window_ns, DEFAULT_WINDOW_NS);
    assert_eq!(b.sampling_rate_millionths, MILLIONTHS);
    assert_eq!(b.mode, CaptureMode::ExactCounting);
    assert!(b.is_full_capture());
}

#[test]
fn budget_budgeted_default() {
    let b = TelemetryBudget::budgeted_default();
    assert_eq!(b.sampling_rate_millionths, DEFAULT_SAMPLING_RATE_MILLIONTHS);
    assert_eq!(b.mode, CaptureMode::BudgetedSampling);
    assert!(!b.is_full_capture());
}

#[test]
fn budget_sampling_rate_clamped() {
    let b = TelemetryBudget::new(
        100,
        1_000_000_000,
        2_000_000,
        CaptureMode::ProbabilisticSampling,
    );
    assert_eq!(b.sampling_rate_millionths, MILLIONTHS);
}

#[test]
fn budget_effective_events_per_second() {
    let b = TelemetryBudget::exact();
    let eps = b.effective_events_per_second();
    // 10_000 events * (1_000_000_000 / 1_000_000_000) = 10_000
    assert_eq!(eps, 10_000);
}

#[test]
fn budget_effective_events_per_second_zero_window() {
    let b = TelemetryBudget::new(100, 0, MILLIONTHS, CaptureMode::ExactCounting);
    assert_eq!(b.effective_events_per_second(), 0);
}

#[test]
fn budget_display_nonempty() {
    let b = TelemetryBudget::exact();
    let s = b.to_string();
    assert!(s.contains("TelemetryBudget"));
    assert!(s.contains("mode="));
}

#[test]
fn budget_serde_roundtrip() {
    let b = TelemetryBudget::budgeted_default();
    let json = serde_json::to_string(&b).unwrap();
    let back: TelemetryBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// ThinningConfig enrichment
// ---------------------------------------------------------------------------

#[test]
fn thinning_config_uniform_defaults() {
    let c = ThinningConfig::uniform_default();
    assert_eq!(c.policy, ThinningPolicy::Uniform);
    assert_eq!(c.target_events, DEFAULT_THINNING_TARGET);
    assert_eq!(c.min_weight_millionths, DEFAULT_MIN_WEIGHT_MILLIONTHS);
}

#[test]
fn thinning_config_priority_defaults() {
    let c = ThinningConfig::priority_default();
    assert_eq!(c.policy, ThinningPolicy::Priority);
}

#[test]
fn thinning_config_reservoir_defaults() {
    let c = ThinningConfig::reservoir_default();
    assert_eq!(c.policy, ThinningPolicy::Reservoir);
    assert_eq!(c.target_events, DEFAULT_RESERVOIR_SIZE);
}

#[test]
fn thinning_config_target_clamped_to_one() {
    let c = ThinningConfig::new(ThinningPolicy::Uniform, 0, 0);
    assert_eq!(c.target_events, 1);
}

#[test]
fn thinning_config_display_nonempty() {
    let c = ThinningConfig::uniform_default();
    assert!(c.to_string().contains("ThinningConfig"));
}

#[test]
fn thinning_config_serde_roundtrip() {
    let c = ThinningConfig::priority_default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ThinningConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// TelemetryEvent enrichment
// ---------------------------------------------------------------------------

#[test]
fn event_new_hash_deterministic() {
    let e1 = TelemetryEvent::new(
        "ev-1",
        "dom",
        1000,
        CaptureMode::ExactCounting,
        MILLIONTHS,
        b"data",
    );
    let e2 = TelemetryEvent::new(
        "ev-1",
        "dom",
        1000,
        CaptureMode::ExactCounting,
        MILLIONTHS,
        b"data",
    );
    assert_eq!(e1.event_hash, e2.event_hash);
    assert_eq!(e1.payload_hash, e2.payload_hash);
}

#[test]
fn event_new_hash_differs_on_payload() {
    let e1 = TelemetryEvent::new(
        "ev-1",
        "dom",
        1000,
        CaptureMode::ExactCounting,
        MILLIONTHS,
        b"data-a",
    );
    let e2 = TelemetryEvent::new(
        "ev-1",
        "dom",
        1000,
        CaptureMode::ExactCounting,
        MILLIONTHS,
        b"data-b",
    );
    assert_ne!(e1.payload_hash, e2.payload_hash);
}

#[test]
fn event_exact_mode_and_weight() {
    let e = TelemetryEvent::exact("ev-1", "dom", 500, b"payload");
    assert_eq!(e.capture_mode, CaptureMode::ExactCounting);
    assert_eq!(e.weight_millionths, MILLIONTHS);
    assert!(e.is_exact());
}

#[test]
fn event_sampled_weight_scaled() {
    let e = TelemetryEvent::sampled("ev-1", "dom", 500, 100_000, b"payload");
    assert_eq!(e.capture_mode, CaptureMode::ProbabilisticSampling);
    // weight = MILLIONTHS * MILLIONTHS / 100_000 = 10_000_000_000
    assert!(e.weight_millionths > MILLIONTHS);
    assert!(!e.is_exact());
}

#[test]
fn event_display_nonempty() {
    let e = TelemetryEvent::exact("ev-1", "dom", 500, b"payload");
    let s = e.to_string();
    assert!(s.contains("TelemetryEvent"));
    assert!(s.contains("ev-1"));
}

#[test]
fn event_serde_roundtrip() {
    let e = TelemetryEvent::exact("ev-1", "dom", 1000, b"test");
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// ProvenanceTag enrichment
// ---------------------------------------------------------------------------

#[test]
fn provenance_exact_tag() {
    let t = ProvenanceTag::exact();
    assert_eq!(t.capture_mode, CaptureMode::ExactCounting);
    assert_eq!(t.sampling_rate_applied_millionths, MILLIONTHS);
    assert!(!t.thinning_applied);
    assert!(t.replay_deterministic);
    assert!(t.is_high_fidelity());
}

#[test]
fn provenance_budgeted_tag() {
    let t = ProvenanceTag::budgeted(100_000);
    assert_eq!(t.capture_mode, CaptureMode::BudgetedSampling);
    assert_eq!(t.sampling_rate_applied_millionths, 100_000);
    assert!(!t.is_high_fidelity());
}

#[test]
fn provenance_probabilistic_tag() {
    let t = ProvenanceTag::probabilistic(50_000);
    assert_eq!(t.capture_mode, CaptureMode::ProbabilisticSampling);
}

#[test]
fn provenance_exact_shadow_tag() {
    let t = ProvenanceTag::exact_shadow();
    assert_eq!(t.capture_mode, CaptureMode::ExactShadow);
    assert!(t.exact_shadow_available);
    assert!(t.is_high_fidelity());
}

#[test]
fn provenance_replay_tag() {
    let t = ProvenanceTag::replay();
    assert_eq!(t.capture_mode, CaptureMode::DeterministicReplay);
    assert!(t.replay_deterministic);
}

#[test]
fn provenance_with_thinning() {
    let t = ProvenanceTag::exact().with_thinning();
    assert!(t.thinning_applied);
}

#[test]
fn provenance_content_hash_deterministic() {
    let t1 = ProvenanceTag::exact();
    let t2 = ProvenanceTag::exact();
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn provenance_content_hash_differs_on_mode() {
    let t1 = ProvenanceTag::exact();
    let t2 = ProvenanceTag::budgeted(MILLIONTHS);
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn provenance_display_nonempty() {
    let t = ProvenanceTag::exact();
    assert!(t.to_string().contains("ProvenanceTag"));
}

#[test]
fn provenance_serde_roundtrip() {
    let t = ProvenanceTag::exact_shadow().with_thinning();
    let json = serde_json::to_string(&t).unwrap();
    let back: ProvenanceTag = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ---------------------------------------------------------------------------
// EventWindow enrichment
// ---------------------------------------------------------------------------

#[test]
fn window_new_initial_state() {
    let w = EventWindow::new(1000, TelemetryBudget::exact());
    assert_eq!(w.start_ns, 1000);
    assert_eq!(w.end_ns, 1000 + DEFAULT_WINDOW_NS);
    assert_eq!(w.event_count(), 0);
    assert_eq!(w.rejected_count, 0);
    assert_eq!(w.thinned_count, 0);
    assert!(!w.thinning_applied);
    assert_eq!(w.remaining_capacity(), DEFAULT_MAX_EVENTS_PER_WINDOW);
    assert!(!w.is_at_capacity());
}

#[test]
fn window_record_accepts_within_budget() {
    let mut w = EventWindow::new(
        0,
        TelemetryBudget::new(3, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    let e1 = TelemetryEvent::exact("e1", "dom", 10, b"a");
    let e2 = TelemetryEvent::exact("e2", "dom", 20, b"b");
    let e3 = TelemetryEvent::exact("e3", "dom", 30, b"c");
    assert!(w.record(e1));
    assert!(w.record(e2));
    assert!(w.record(e3));
    assert_eq!(w.event_count(), 3);
    assert!(w.is_at_capacity());
}

#[test]
fn window_record_rejects_at_capacity() {
    let mut w = EventWindow::new(
        0,
        TelemetryBudget::new(1, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    let e1 = TelemetryEvent::exact("e1", "dom", 10, b"a");
    let e2 = TelemetryEvent::exact("e2", "dom", 20, b"b");
    assert!(w.record(e1));
    assert!(!w.record(e2));
    assert_eq!(w.rejected_count, 1);
}

#[test]
fn window_contains_timestamp() {
    let w = EventWindow::new(
        100,
        TelemetryBudget::new(10, 500, MILLIONTHS, CaptureMode::ExactCounting),
    );
    assert!(w.contains_timestamp(100));
    assert!(w.contains_timestamp(599));
    assert!(!w.contains_timestamp(600));
    assert!(!w.contains_timestamp(99));
}

#[test]
fn window_effective_sampling_rate_full() {
    let w = EventWindow::new(0, TelemetryBudget::exact());
    assert_eq!(w.effective_sampling_rate_millionths(), MILLIONTHS);
}

#[test]
fn window_effective_sampling_rate_with_rejections() {
    let mut w = EventWindow::new(
        0,
        TelemetryBudget::new(2, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    w.record(TelemetryEvent::exact("e1", "d", 10, b"a"));
    w.record(TelemetryEvent::exact("e2", "d", 20, b"b"));
    w.record(TelemetryEvent::exact("e3", "d", 30, b"c")); // rejected
    // 2 accepted / 3 total = 666_666
    assert_eq!(w.effective_sampling_rate_millionths(), 666_666);
}

#[test]
fn window_provenance_tag_mode() {
    let w = EventWindow::new(0, TelemetryBudget::exact());
    let tag = w.provenance_tag();
    assert_eq!(tag.capture_mode, CaptureMode::ExactCounting);
}

#[test]
fn window_content_hash_deterministic() {
    let w1 = EventWindow::new(0, TelemetryBudget::exact());
    let w2 = EventWindow::new(0, TelemetryBudget::exact());
    assert_eq!(w1.content_hash(), w2.content_hash());
}

#[test]
fn window_display_nonempty() {
    let w = EventWindow::new(0, TelemetryBudget::exact());
    assert!(w.to_string().contains("EventWindow"));
}

#[test]
fn window_serde_roundtrip() {
    let mut w = EventWindow::new(100, TelemetryBudget::exact());
    w.record(TelemetryEvent::exact("e1", "d", 200, b"data"));
    let json = serde_json::to_string(&w).unwrap();
    let back: EventWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// EventWindow — Thinning
// ---------------------------------------------------------------------------

#[test]
fn window_thinning_noop_below_target() {
    let mut w = EventWindow::new(
        0,
        TelemetryBudget::new(100, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting),
    );
    w.record(TelemetryEvent::exact("e1", "d", 10, b"a"));
    let removed = w.apply_thinning(&ThinningConfig::uniform_default());
    assert_eq!(removed, 0);
    assert!(!w.thinning_applied);
}

// ---------------------------------------------------------------------------
// ModeBreakdown enrichment
// ---------------------------------------------------------------------------

#[test]
fn mode_breakdown_fraction_calculation() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 50, 100, ProvenanceTag::exact());
    assert_eq!(bd.fraction_millionths, 500_000);
}

#[test]
fn mode_breakdown_zero_total() {
    let bd = ModeBreakdown::new(
        CaptureMode::BudgetedSampling,
        0,
        0,
        ProvenanceTag::budgeted(100_000),
    );
    assert_eq!(bd.fraction_millionths, 0);
}

#[test]
fn mode_breakdown_display_nonempty() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 10, 100, ProvenanceTag::exact());
    assert!(bd.to_string().contains("ModeBreakdown"));
}

#[test]
fn mode_breakdown_serde_roundtrip() {
    let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 25, 50, ProvenanceTag::exact());
    let json = serde_json::to_string(&bd).unwrap();
    let back: ModeBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(bd, back);
}

// ---------------------------------------------------------------------------
// TelemetryPlane enrichment
// ---------------------------------------------------------------------------

#[test]
fn plane_new_initial_state() {
    let p = TelemetryPlane::new(epoch(1));
    assert_eq!(p.epoch, epoch(1));
    assert_eq!(p.total_events_recorded, 0);
    assert_eq!(p.total_events_rejected, 0);
    assert_eq!(p.active_domain_count(), 0);
}

#[test]
fn plane_record_exact_event() {
    let mut p = TelemetryPlane::new(epoch(1));
    assert!(p.record_exact("ev-1", "test_domain", 100, b"payload"));
    assert_eq!(p.total_events_recorded, 1);
    assert_eq!(p.active_domain_count(), 1);
    assert_eq!(p.domain_event_count("test_domain"), 1);
}

#[test]
fn plane_record_sampled_event() {
    let mut p = TelemetryPlane::new(epoch(1));
    assert!(p.record_sampled("ev-1", "dom", 100, 100_000, b"payload"));
    assert_eq!(p.total_events_recorded, 1);
}

#[test]
fn plane_record_event_creates_new_window_at_capacity() {
    // When a window is at capacity, the plane creates a new window for subsequent events
    let budget = TelemetryBudget::new(2, 1_000_000_000, MILLIONTHS, CaptureMode::ExactCounting);
    let mut p = TelemetryPlane::with_default_budget(epoch(1), budget);
    assert!(p.record_exact("ev-1", "dom", 100, b"a"));
    assert!(p.record_exact("ev-2", "dom", 200, b"b"));
    // Third event goes into a new window
    assert!(p.record_exact("ev-3", "dom", 300, b"c"));
    assert_eq!(p.total_events_recorded, 3);
    assert_eq!(p.domain_event_count("dom"), 3);
}

#[test]
fn plane_add_budget_for_domain() {
    let mut p = TelemetryPlane::new(epoch(1));
    let custom = TelemetryBudget::new(5, 500_000_000, MILLIONTHS, CaptureMode::ExactShadow);
    p.add_budget("special_domain", custom.clone());
    let eff = p.effective_budget("special_domain");
    assert_eq!(*eff, custom);
}

#[test]
fn plane_effective_budget_falls_back() {
    let p = TelemetryPlane::new(epoch(1));
    let eff = p.effective_budget("unknown_domain");
    assert_eq!(*eff, p.default_budget);
}

#[test]
fn plane_observed_domains() {
    let mut p = TelemetryPlane::new(epoch(1));
    p.record_exact("e1", "dom-a", 100, b"a");
    p.record_exact("e2", "dom-b", 200, b"b");
    let domains = p.observed_domains();
    assert!(domains.contains("dom-a"));
    assert!(domains.contains("dom-b"));
}

#[test]
fn plane_generate_report_empty() {
    let p = TelemetryPlane::new(epoch(1));
    let r = p.generate_report();
    assert_eq!(r.total_events_captured, 0);
    assert_eq!(r.total_events_thinned, 0);
    assert_eq!(r.total_events_rejected, 0);
    assert_eq!(r.window_count, 0);
    assert_eq!(r.schema_version, SCHEMA_VERSION);
    assert_eq!(r.component, COMPONENT);
}

#[test]
fn plane_generate_report_with_events() {
    let mut p = TelemetryPlane::new(epoch(1));
    p.record_exact("e1", "dom", 100, b"a");
    p.record_exact("e2", "dom", 200, b"b");
    let r = p.generate_report();
    assert_eq!(r.total_events_captured, 2);
    assert_eq!(r.window_count, 1);
    assert!(!r.domains.is_empty());
}

#[test]
fn plane_display_nonempty() {
    let p = TelemetryPlane::new(epoch(1));
    assert!(p.to_string().contains("TelemetryPlane"));
}

#[test]
fn plane_serde_roundtrip() {
    let mut p = TelemetryPlane::new(epoch(1));
    p.record_exact("e1", "dom", 100, b"a");
    let json = serde_json::to_string(&p).unwrap();
    let back: TelemetryPlane = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// TelemetryReport enrichment
// ---------------------------------------------------------------------------

#[test]
fn report_is_all_exact_when_only_exact_events() {
    let mut p = TelemetryPlane::with_default_budget(epoch(1), TelemetryBudget::exact());
    p.record_exact("e1", "dom", 100, b"a");
    let r = p.generate_report();
    assert!(r.is_all_exact());
}

#[test]
fn report_has_thinning_false_initially() {
    let p = TelemetryPlane::new(epoch(1));
    let r = p.generate_report();
    assert!(!r.has_thinning());
}

#[test]
fn report_survival_rate_full_when_no_thinning() {
    let mut p = TelemetryPlane::with_default_budget(epoch(1), TelemetryBudget::exact());
    p.record_exact("e1", "dom", 100, b"a");
    let r = p.generate_report();
    assert_eq!(r.survival_rate_millionths(), MILLIONTHS);
}

#[test]
fn report_display_nonempty() {
    let p = TelemetryPlane::new(epoch(1));
    let r = p.generate_report();
    assert!(r.to_string().contains("TelemetryReport"));
}

#[test]
fn report_serde_roundtrip() {
    let mut p = TelemetryPlane::with_default_budget(epoch(1), TelemetryBudget::exact());
    p.record_exact("e1", "dom", 100, b"a");
    let r = p.generate_report();
    let json = serde_json::to_string(&r).unwrap();
    let back: TelemetryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn report_content_hash_deterministic() {
    let mut p1 = TelemetryPlane::with_default_budget(epoch(1), TelemetryBudget::exact());
    p1.record_exact("e1", "dom", 100, b"a");
    let r1 = p1.generate_report();

    let mut p2 = TelemetryPlane::with_default_budget(epoch(1), TelemetryBudget::exact());
    p2.record_exact("e1", "dom", 100, b"a");
    let r2 = p2.generate_report();

    assert_eq!(r1.content_hash, r2.content_hash);
}
