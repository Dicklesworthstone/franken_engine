//! Enrichment integration tests for `observability_probe_design`.
//!
//! Focuses on: optimizer edge cases, multi-mode manifest invariants,
//! coverage math, certificate headroom, ledger entry ordering,
//! probe universe capacity, serde for all types, deterministic hashing,
//! and Display uniqueness.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::observability_probe_design::{
    CandidateProbe, MultiModeManifest, ObservabilityBudget, OperatingMode,
    PROBE_DESIGN_SCHEMA_VERSION, ProbeDesignError, ProbeDomain, ProbeGranularity, ProbeUniverse,
    ProbeUtilityLedger, build_approximation_certificate, build_schedule, greedy_submodular_select,
};

// ===========================================================================
// Constants / Helpers
// ===========================================================================

const MILLION: i64 = 1_000_000;

fn make_id(label: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    let schema = SchemaId::from_definition(PROBE_DESIGN_SCHEMA_VERSION.as_bytes());
    derive_id(
        ObjectDomain::EvidenceRecord,
        "tests.observability_probe_design_enrichment",
        &schema,
        label.as_bytes(),
    )
    .expect("derive id")
}

fn simple_probe(
    name: &str,
    utility: i64,
    latency: u64,
    memory: u64,
    events: &[&str],
) -> CandidateProbe {
    CandidateProbe {
        id: make_id(name),
        name: name.to_string(),
        domain: ProbeDomain::Compiler,
        granularity: ProbeGranularity::Medium,
        forensic_utility_millionths: utility,
        latency_overhead_micros: latency,
        memory_overhead_bytes: memory,
        covers_events: events.iter().map(|e| e.to_string()).collect(),
        metadata: BTreeMap::new(),
    }
}

fn domain_probe(
    name: &str,
    domain: ProbeDomain,
    utility: i64,
    latency: u64,
    memory: u64,
    events: &[&str],
) -> CandidateProbe {
    CandidateProbe {
        id: make_id(name),
        name: name.to_string(),
        domain,
        granularity: ProbeGranularity::Fine,
        forensic_utility_millionths: utility,
        latency_overhead_micros: latency,
        memory_overhead_bytes: memory,
        covers_events: events.iter().map(|e| e.to_string()).collect(),
        metadata: BTreeMap::new(),
    }
}

fn small_universe() -> ProbeUniverse {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe("p1", 800_000, 50, 5_000, &["e1", "e2"]))
        .unwrap();
    u.add_probe(simple_probe("p2", 600_000, 30, 3_000, &["e3"]))
        .unwrap();
    u.add_probe(simple_probe("p3", 400_000, 20, 2_000, &["e4", "e5"]))
        .unwrap();
    u
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn enrichment_greedy_selects_all_when_budget_generous() {
    let u = small_universe();
    let budget = ObservabilityBudget {
        max_latency_micros: 1_000_000,
        max_memory_bytes: 1_000_000_000,
        max_probe_count: 100,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 3);
    assert_eq!(result.covered_events.len(), 5);
}

#[test]
fn enrichment_greedy_empty_universe_returns_zero_everything() {
    let u = ProbeUniverse::new();
    let budget = ObservabilityBudget::incident();
    let result = greedy_submodular_select(&u, &budget);
    assert!(result.selected_indices.is_empty());
    assert_eq!(result.total_utility_millionths, 0);
    assert_eq!(result.total_latency_micros, 0);
    assert_eq!(result.total_memory_bytes, 0);
    assert!(result.covered_events.is_empty());
}

#[test]
fn enrichment_greedy_single_probe_exactly_at_latency_budget() {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe("exact", 500_000, 200, 100, &["ev"]))
        .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 200,
        max_memory_bytes: 100_000,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 1);
    assert_eq!(result.total_latency_micros, 200);
}

#[test]
fn enrichment_greedy_probe_exceeding_memory_skipped() {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe("big", MILLION, 10, 50_000, &["ev"]))
        .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 1_000,
        max_memory_bytes: 49_999,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert!(result.selected_indices.is_empty());
}

#[test]
fn enrichment_schedule_coverage_full_when_all_selected() {
    let u = small_universe();
    let schedule = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
    assert_eq!(schedule.probe_count(), 3);
    assert_eq!(schedule.event_coverage_millionths, MILLION);
}

#[test]
fn enrichment_schedule_empty_universe_coverage_is_full() {
    let u = ProbeUniverse::new();
    let schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    assert_eq!(schedule.event_coverage_millionths, MILLION);
    assert!(schedule.within_budget);
    assert_eq!(schedule.probe_count(), 0);
}

#[test]
fn enrichment_schedule_hash_changes_with_mode() {
    let u = small_universe();
    let s_normal = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let s_incident = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
    assert_ne!(s_normal.schedule_hash, s_incident.schedule_hash);
}

#[test]
fn enrichment_schedule_deterministic_across_runs() {
    let u = small_universe();
    let s1 = build_schedule(&u, OperatingMode::Degraded, ObservabilityBudget::degraded());
    let s2 = build_schedule(&u, OperatingMode::Degraded, ObservabilityBudget::degraded());
    assert_eq!(s1, s2);
    assert_eq!(s1.schedule_hash, s2.schedule_hash);
}

#[test]
fn enrichment_certificate_headroom_computed_correctly() {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe("h1", MILLION, 100, 500, &["x"]))
        .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 300,
        max_memory_bytes: 2_000,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    assert_eq!(cert.budget_headroom_latency_micros, 200);
    assert_eq!(cert.budget_headroom_memory_bytes, 1_500);
    assert_eq!(cert.algorithm, "greedy_submodular");
    assert_eq!(cert.optimality_bound_millionths, 632_121);
}

#[test]
fn enrichment_certificate_headroom_zero_when_exact_fit() {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe("exact_fit", MILLION, 100, 200, &["e"]))
        .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 100,
        max_memory_bytes: 200,
        max_probe_count: 1,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    assert_eq!(cert.budget_headroom_latency_micros, 0);
    assert_eq!(cert.budget_headroom_memory_bytes, 0);
}

#[test]
fn enrichment_ledger_monotone_coverage() {
    let u = small_universe();
    let budget = ObservabilityBudget::incident();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    for window in ledger.entries.windows(2) {
        assert!(
            window[1].cumulative_coverage_millionths >= window[0].cumulative_coverage_millionths
        );
    }
}

#[test]
fn enrichment_ledger_rounds_sequential() {
    let u = small_universe();
    let budget = ObservabilityBudget::incident();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    for (i, entry) in ledger.entries.iter().enumerate() {
        assert_eq!(entry.selection_round, i);
    }
}

#[test]
fn enrichment_ledger_empty_when_no_selection() {
    let u = ProbeUniverse::new();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    assert!(ledger.entries.is_empty());
}

#[test]
fn enrichment_multi_mode_manifest_all_modes_present() {
    let u = small_universe();
    let manifest = MultiModeManifest::build(&u);
    assert_eq!(manifest.normal_schedule.mode, OperatingMode::Normal);
    assert_eq!(manifest.degraded_schedule.mode, OperatingMode::Degraded);
    assert_eq!(manifest.incident_schedule.mode, OperatingMode::Incident);
}

#[test]
fn enrichment_multi_mode_manifest_incident_coverage_gte_normal() {
    let u = small_universe();
    let manifest = MultiModeManifest::build(&u);
    assert!(
        manifest.incident_schedule.event_coverage_millionths
            >= manifest.normal_schedule.event_coverage_millionths
    );
}

#[test]
fn enrichment_multi_mode_manifest_schedule_for_mode_accessor() {
    let u = small_universe();
    let manifest = MultiModeManifest::build(&u);
    for mode in [
        OperatingMode::Normal,
        OperatingMode::Degraded,
        OperatingMode::Incident,
    ] {
        let schedule = manifest.schedule_for_mode(&mode);
        assert_eq!(schedule.mode, mode);
    }
}

#[test]
fn enrichment_multi_mode_manifest_deterministic_hash() {
    let u = small_universe();
    let m1 = MultiModeManifest::build(&u);
    let m2 = MultiModeManifest::build(&u);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn enrichment_universe_duplicate_probe_rejected() {
    let mut u = ProbeUniverse::new();
    let p = simple_probe("dup", MILLION, 10, 100, &["e"]);
    u.add_probe(p.clone()).unwrap();
    let err = u.add_probe(p).unwrap_err();
    assert_eq!(err, ProbeDesignError::DuplicateProbe);
}

#[test]
fn enrichment_universe_probes_by_domain_filters_correctly() {
    let mut u = ProbeUniverse::new();
    u.add_probe(domain_probe(
        "a",
        ProbeDomain::Compiler,
        100_000,
        10,
        100,
        &["e1"],
    ))
    .unwrap();
    u.add_probe(domain_probe(
        "b",
        ProbeDomain::Runtime,
        200_000,
        20,
        200,
        &["e2"],
    ))
    .unwrap();
    u.add_probe(domain_probe(
        "c",
        ProbeDomain::Compiler,
        300_000,
        30,
        300,
        &["e3"],
    ))
    .unwrap();
    assert_eq!(u.probes_by_domain(&ProbeDomain::Compiler).len(), 2);
    assert_eq!(u.probes_by_domain(&ProbeDomain::Runtime).len(), 1);
    assert_eq!(u.probes_by_domain(&ProbeDomain::Governance).len(), 0);
}

#[test]
fn enrichment_probe_marginal_gain_with_partial_overlap() {
    let p = simple_probe("overlap", MILLION, 10, 100, &["a", "b", "c", "d"]);
    let mut covered = BTreeSet::new();
    covered.insert("a".to_string());
    covered.insert("c".to_string());
    let gain = p.marginal_gain(&covered);
    assert_eq!(gain, 500_000);
}

#[test]
fn enrichment_probe_efficiency_ratio_with_unit_latency() {
    let p = simple_probe("eff", MILLION, 1, 100, &["e"]);
    let ratio = p.efficiency_ratio_millionths();
    assert_eq!(ratio, MILLION * MILLION);
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors = [
        ProbeDesignError::UniverseCapacityExceeded,
        ProbeDesignError::DuplicateProbe,
        ProbeDesignError::EmptyUniverse,
        ProbeDesignError::InvalidBudget("test".to_string()),
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ProbeDesignError::EmptyUniverse);
    assert_eq!(err.to_string(), "empty probe universe");
}

#[test]
fn enrichment_operating_mode_display_unique() {
    let modes = [
        OperatingMode::Normal,
        OperatingMode::Degraded,
        OperatingMode::Incident,
    ];
    let set: BTreeSet<String> = modes.iter().map(|m| m.to_string()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_operating_mode_ord() {
    assert!(OperatingMode::Normal < OperatingMode::Degraded);
    assert!(OperatingMode::Degraded < OperatingMode::Incident);
    assert!(OperatingMode::Normal < OperatingMode::Incident);
}

#[test]
fn enrichment_probe_domain_ord_definition_order() {
    let mut domains = vec![
        ProbeDomain::Governance,
        ProbeDomain::Scheduler,
        ProbeDomain::Router,
        ProbeDomain::EvidencePipeline,
        ProbeDomain::Runtime,
        ProbeDomain::Compiler,
    ];
    domains.sort();
    assert_eq!(domains[0], ProbeDomain::Compiler);
    assert_eq!(domains[5], ProbeDomain::Governance);
}

#[test]
fn enrichment_serde_roundtrip_probe_universe() {
    let u = small_universe();
    let json = serde_json::to_string(&u).unwrap();
    let back: ProbeUniverse = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

#[test]
fn enrichment_serde_roundtrip_multi_mode_manifest() {
    let u = small_universe();
    let m = MultiModeManifest::build(&u);
    let json = serde_json::to_string(&m).unwrap();
    let back: MultiModeManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_serde_roundtrip_all_error_variants() {
    let errors = [
        ProbeDesignError::UniverseCapacityExceeded,
        ProbeDesignError::DuplicateProbe,
        ProbeDesignError::EmptyUniverse,
        ProbeDesignError::InvalidBudget("msg".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ProbeDesignError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_budget_escalation_invariants() {
    let normal = ObservabilityBudget::normal();
    let degraded = ObservabilityBudget::degraded();
    let incident = ObservabilityBudget::incident();
    assert!(degraded.max_latency_micros > normal.max_latency_micros);
    assert!(incident.max_latency_micros > degraded.max_latency_micros);
    assert!(degraded.max_memory_bytes > normal.max_memory_bytes);
    assert!(incident.max_memory_bytes > degraded.max_memory_bytes);
    assert!(degraded.max_probe_count > normal.max_probe_count);
    assert!(incident.max_probe_count > degraded.max_probe_count);
    assert!(degraded.min_event_coverage_millionths > normal.min_event_coverage_millionths);
    assert!(incident.min_event_coverage_millionths > degraded.min_event_coverage_millionths);
}

#[test]
fn enrichment_probe_with_metadata_serde_roundtrip() {
    let mut p = simple_probe("meta", 500_000, 10, 100, &["e"]);
    p.metadata.insert("owner".to_string(), "team-a".to_string());
    p.metadata
        .insert("priority".to_string(), "high".to_string());
    let json = serde_json::to_string(&p).unwrap();
    let back: CandidateProbe = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert_eq!(back.metadata.len(), 2);
}

#[test]
fn enrichment_schedule_meets_coverage_boundary() {
    let u = small_universe();
    let mut schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    schedule.event_coverage_millionths = schedule.budget.min_event_coverage_millionths;
    assert!(schedule.meets_coverage());
    schedule.event_coverage_millionths -= 1;
    assert!(!schedule.meets_coverage());
}

#[test]
fn enrichment_overlapping_events_diminishing_returns() {
    let mut u = ProbeUniverse::new();
    u.add_probe(simple_probe(
        "ov_a",
        MILLION,
        10,
        100,
        &["shared", "unique_a"],
    ))
    .unwrap();
    u.add_probe(simple_probe(
        "ov_b",
        MILLION,
        10,
        100,
        &["shared", "unique_b"],
    ))
    .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 100,
        max_memory_bytes: 100_000,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 2);
    assert!(result.total_utility_millionths < 2 * MILLION);
}
