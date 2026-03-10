//! Integration tests for the `observability_probe_design` module.
#![forbid(unsafe_code)]
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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::observability_probe_design::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn make_id(label: &str) -> EngineObjectId {
    let schema = SchemaId::from_definition(PROBE_DESIGN_SCHEMA_VERSION.as_bytes());
    derive_id(
        ObjectDomain::EvidenceRecord,
        "tests.observability_probe_design_integration",
        &schema,
        label.as_bytes(),
    )
    .expect("derive id")
}

fn make_probe(
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
        granularity: ProbeGranularity::Medium,
        forensic_utility_millionths: utility,
        latency_overhead_micros: latency,
        memory_overhead_bytes: memory,
        covers_events: events.iter().map(|e| e.to_string()).collect(),
        metadata: BTreeMap::new(),
    }
}

fn make_probe_with_granularity(
    name: &str,
    domain: ProbeDomain,
    granularity: ProbeGranularity,
    utility: i64,
    latency: u64,
    memory: u64,
    events: &[&str],
) -> CandidateProbe {
    CandidateProbe {
        id: make_id(name),
        name: name.to_string(),
        domain,
        granularity,
        forensic_utility_millionths: utility,
        latency_overhead_micros: latency,
        memory_overhead_bytes: memory,
        covers_events: events.iter().map(|e| e.to_string()).collect(),
        metadata: BTreeMap::new(),
    }
}

fn standard_universe() -> ProbeUniverse {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "compiler_pass_trace",
        ProbeDomain::Compiler,
        800_000,
        100,
        10_000,
        &["pass_start", "pass_end", "invariant_check"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "runtime_scheduler",
        ProbeDomain::Runtime,
        700_000,
        50,
        8_000,
        &["task_dispatch", "task_complete", "preemption"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "router_decision",
        ProbeDomain::Router,
        900_000,
        30,
        5_000,
        &["lane_select", "fallback_trigger", "calibration_update"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "evidence_pipeline",
        ProbeDomain::EvidencePipeline,
        600_000,
        80,
        12_000,
        &["evidence_emit", "ledger_write", "hash_chain"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "governance_audit",
        ProbeDomain::Governance,
        500_000,
        200,
        20_000,
        &["policy_eval", "decision_record"],
    ))
    .unwrap();
    u
}

// ===========================================================================
// Section 1: Public constants
// ===========================================================================

#[test]
fn schema_version_non_empty() {
    assert!(!PROBE_DESIGN_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_version_value() {
    assert_eq!(
        PROBE_DESIGN_SCHEMA_VERSION,
        "franken-engine.observability_probe_design.v1"
    );
}

// ===========================================================================
// Section 2: ProbeDomain enum
// ===========================================================================

#[test]
fn probe_domain_serde_roundtrip_all_variants() {
    let variants = [
        ProbeDomain::Compiler,
        ProbeDomain::Runtime,
        ProbeDomain::Router,
        ProbeDomain::EvidencePipeline,
        ProbeDomain::Scheduler,
        ProbeDomain::Governance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ProbeDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn probe_domain_ord_consistent() {
    assert!(ProbeDomain::Compiler < ProbeDomain::Runtime);
    assert!(ProbeDomain::Runtime < ProbeDomain::Router);
    assert!(ProbeDomain::Router < ProbeDomain::EvidencePipeline);
    assert!(ProbeDomain::EvidencePipeline < ProbeDomain::Scheduler);
    assert!(ProbeDomain::Scheduler < ProbeDomain::Governance);
}

#[test]
fn probe_domain_debug_non_empty() {
    for d in [
        ProbeDomain::Compiler,
        ProbeDomain::Runtime,
        ProbeDomain::Router,
        ProbeDomain::EvidencePipeline,
        ProbeDomain::Scheduler,
        ProbeDomain::Governance,
    ] {
        assert!(!format!("{d:?}").is_empty());
    }
}

#[test]
fn probe_domain_serde_json_unique() {
    let variants = [
        ProbeDomain::Compiler,
        ProbeDomain::Runtime,
        ProbeDomain::Router,
        ProbeDomain::EvidencePipeline,
        ProbeDomain::Scheduler,
        ProbeDomain::Governance,
    ];
    let set: BTreeSet<String> = variants
        .iter()
        .map(|d| serde_json::to_string(d).unwrap())
        .collect();
    assert_eq!(set.len(), variants.len());
}

// ===========================================================================
// Section 3: ProbeGranularity enum
// ===========================================================================

#[test]
fn probe_granularity_serde_roundtrip() {
    for g in [
        ProbeGranularity::Coarse,
        ProbeGranularity::Medium,
        ProbeGranularity::Fine,
        ProbeGranularity::Trace,
    ] {
        let json = serde_json::to_string(&g).unwrap();
        let back: ProbeGranularity = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }
}

#[test]
fn probe_granularity_ord_consistent() {
    assert!(ProbeGranularity::Coarse < ProbeGranularity::Medium);
    assert!(ProbeGranularity::Medium < ProbeGranularity::Fine);
    assert!(ProbeGranularity::Fine < ProbeGranularity::Trace);
}

// ===========================================================================
// Section 4: OperatingMode enum
// ===========================================================================

#[test]
fn operating_mode_display_values() {
    assert_eq!(OperatingMode::Normal.to_string(), "normal");
    assert_eq!(OperatingMode::Degraded.to_string(), "degraded");
    assert_eq!(OperatingMode::Incident.to_string(), "incident");
}

#[test]
fn operating_mode_display_uniqueness() {
    let modes = [
        OperatingMode::Normal,
        OperatingMode::Degraded,
        OperatingMode::Incident,
    ];
    let set: BTreeSet<String> = modes.iter().map(|m| m.to_string()).collect();
    assert_eq!(set.len(), modes.len());
}

#[test]
fn operating_mode_ord() {
    assert!(OperatingMode::Normal < OperatingMode::Degraded);
    assert!(OperatingMode::Degraded < OperatingMode::Incident);
}

#[test]
fn operating_mode_serde_roundtrip() {
    for m in [
        OperatingMode::Normal,
        OperatingMode::Degraded,
        OperatingMode::Incident,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: OperatingMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

// ===========================================================================
// Section 5: ProbeDesignError enum
// ===========================================================================

#[test]
fn error_display_all_variants() {
    assert_eq!(
        ProbeDesignError::UniverseCapacityExceeded.to_string(),
        "probe universe capacity exceeded"
    );
    assert_eq!(
        ProbeDesignError::DuplicateProbe.to_string(),
        "duplicate probe id"
    );
    assert_eq!(
        ProbeDesignError::EmptyUniverse.to_string(),
        "empty probe universe"
    );
    assert_eq!(
        ProbeDesignError::InvalidBudget("too small".to_string()).to_string(),
        "invalid budget: too small"
    );
}

#[test]
fn error_display_uniqueness() {
    let errors = [
        ProbeDesignError::UniverseCapacityExceeded,
        ProbeDesignError::DuplicateProbe,
        ProbeDesignError::EmptyUniverse,
        ProbeDesignError::InvalidBudget("x".to_string()),
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn error_serde_roundtrip() {
    let errors = [
        ProbeDesignError::UniverseCapacityExceeded,
        ProbeDesignError::DuplicateProbe,
        ProbeDesignError::EmptyUniverse,
        ProbeDesignError::InvalidBudget("budget msg".to_string()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ProbeDesignError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ProbeDesignError::UniverseCapacityExceeded);
    assert_eq!(err.to_string(), "probe universe capacity exceeded");
}

#[test]
fn error_source_is_none() {
    use std::error::Error;
    for e in [
        ProbeDesignError::UniverseCapacityExceeded,
        ProbeDesignError::DuplicateProbe,
        ProbeDesignError::EmptyUniverse,
        ProbeDesignError::InvalidBudget("m".to_string()),
    ] {
        assert!(e.source().is_none());
    }
}

// ===========================================================================
// Section 6: CandidateProbe struct + methods
// ===========================================================================

#[test]
fn candidate_probe_construction_and_fields() {
    let p = make_probe("cp1", ProbeDomain::Compiler, 800_000, 50, 4096, &["a", "b"]);
    assert_eq!(p.name, "cp1");
    assert_eq!(p.domain, ProbeDomain::Compiler);
    assert_eq!(p.granularity, ProbeGranularity::Medium);
    assert_eq!(p.forensic_utility_millionths, 800_000);
    assert_eq!(p.latency_overhead_micros, 50);
    assert_eq!(p.memory_overhead_bytes, 4096);
    assert_eq!(p.covers_events.len(), 2);
    assert!(p.covers_events.contains("a"));
    assert!(p.covers_events.contains("b"));
    assert!(p.metadata.is_empty());
}

#[test]
fn candidate_probe_serde_roundtrip() {
    let mut p = make_probe("sr1", ProbeDomain::Router, 500_000, 20, 1024, &["x"]);
    p.metadata.insert("key1".to_string(), "val1".to_string());
    let json = serde_json::to_string(&p).unwrap();
    let back: CandidateProbe = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn candidate_probe_json_field_presence() {
    let p = make_probe("fp1", ProbeDomain::Scheduler, 300_000, 55, 4096, &["evt"]);
    let json = serde_json::to_string(&p).unwrap();
    for field in [
        "\"id\"",
        "\"name\"",
        "\"domain\"",
        "\"granularity\"",
        "\"forensic_utility_millionths\"",
        "\"latency_overhead_micros\"",
        "\"memory_overhead_bytes\"",
        "\"covers_events\"",
        "\"metadata\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn marginal_gain_all_new_events() {
    let p = make_probe(
        "mg1",
        ProbeDomain::Compiler,
        MILLION,
        10,
        100,
        &["a", "b", "c"],
    );
    let covered = BTreeSet::new();
    assert_eq!(p.marginal_gain(&covered), MILLION);
}

#[test]
fn marginal_gain_partial_overlap() {
    let p = make_probe(
        "mg2",
        ProbeDomain::Runtime,
        MILLION,
        10,
        100,
        &["a", "b", "c"],
    );
    let mut covered = BTreeSet::new();
    covered.insert("a".to_string());
    // 2 out of 3 new => fraction = 2/3 * MILLION
    let expected = MILLION * (2 * MILLION / 3) / MILLION;
    assert_eq!(p.marginal_gain(&covered), expected);
}

#[test]
fn marginal_gain_all_covered() {
    let p = make_probe("mg3", ProbeDomain::Router, MILLION, 10, 100, &["a", "b"]);
    let mut covered = BTreeSet::new();
    covered.insert("a".to_string());
    covered.insert("b".to_string());
    assert_eq!(p.marginal_gain(&covered), 0);
}

#[test]
fn marginal_gain_empty_events_returns_raw_utility() {
    let p = make_probe("mg4", ProbeDomain::Compiler, 750_000, 10, 100, &[]);
    let covered = BTreeSet::new();
    assert_eq!(p.marginal_gain(&covered), 750_000);
}

#[test]
fn marginal_gain_single_event_half_covered() {
    // With 1 event, if it is already covered, gain = 0; if not, gain = full utility
    let p = make_probe("mg5", ProbeDomain::Compiler, 600_000, 10, 100, &["only"]);
    let mut covered = BTreeSet::new();
    assert_eq!(p.marginal_gain(&covered), 600_000);
    covered.insert("only".to_string());
    assert_eq!(p.marginal_gain(&covered), 0);
}

#[test]
fn efficiency_ratio_basic() {
    let p = make_probe("er1", ProbeDomain::Compiler, MILLION, 100, 1000, &["a"]);
    // utility * MILLION / max(latency, 1) = 1_000_000 * 1_000_000 / 100 = 10_000_000_000
    assert_eq!(p.efficiency_ratio_millionths(), 10_000 * MILLION);
}

#[test]
fn efficiency_ratio_zero_latency_uses_one() {
    let p = make_probe("er2", ProbeDomain::Runtime, 500_000, 0, 100, &["a"]);
    // latency.max(1) = 1 => 500_000 * 1_000_000 / 1 = 500_000_000_000
    assert_eq!(p.efficiency_ratio_millionths(), 500_000 * MILLION);
}

#[test]
fn candidate_probe_clone_equality() {
    let a = make_probe(
        "cl1",
        ProbeDomain::EvidencePipeline,
        800_000,
        42,
        2048,
        &["x", "y"],
    );
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Section 7: ProbeUniverse struct + methods
// ===========================================================================

#[test]
fn universe_new_is_empty() {
    let u = ProbeUniverse::new();
    assert!(u.probes.is_empty());
    assert!(u.all_events.is_empty());
}

#[test]
fn universe_default_is_empty() {
    let u = ProbeUniverse::default();
    assert!(u.probes.is_empty());
    assert!(u.all_events.is_empty());
}

#[test]
fn universe_add_probe_success() {
    let mut u = ProbeUniverse::new();
    let p = make_probe(
        "ap1",
        ProbeDomain::Compiler,
        MILLION,
        10,
        100,
        &["ev1", "ev2"],
    );
    u.add_probe(p).unwrap();
    assert_eq!(u.probes.len(), 1);
    assert_eq!(u.all_events.len(), 2);
    assert!(u.all_events.contains("ev1"));
    assert!(u.all_events.contains("ev2"));
}

#[test]
fn universe_add_probe_duplicate_rejected() {
    let mut u = ProbeUniverse::new();
    let p = make_probe("dup1", ProbeDomain::Compiler, MILLION, 10, 100, &["a"]);
    u.add_probe(p.clone()).unwrap();
    assert_eq!(u.add_probe(p), Err(ProbeDesignError::DuplicateProbe));
}

#[test]
fn universe_events_merged_from_multiple_probes() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "m1",
        ProbeDomain::Compiler,
        MILLION,
        10,
        100,
        &["a", "b"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "m2",
        ProbeDomain::Runtime,
        MILLION,
        10,
        100,
        &["b", "c"],
    ))
    .unwrap();
    // "a", "b", "c" — "b" deduplicated
    assert_eq!(u.all_events.len(), 3);
}

#[test]
fn universe_probes_by_domain() {
    let u = standard_universe();
    assert_eq!(u.probes_by_domain(&ProbeDomain::Compiler).len(), 1);
    assert_eq!(u.probes_by_domain(&ProbeDomain::Router).len(), 1);
    assert_eq!(u.probes_by_domain(&ProbeDomain::Scheduler).len(), 0);
}

#[test]
fn universe_probes_by_domain_multiple_same_domain() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "c1",
        ProbeDomain::Compiler,
        100_000,
        10,
        100,
        &["a"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "c2",
        ProbeDomain::Compiler,
        200_000,
        20,
        200,
        &["b"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "r1",
        ProbeDomain::Runtime,
        300_000,
        30,
        300,
        &["c"],
    ))
    .unwrap();
    assert_eq!(u.probes_by_domain(&ProbeDomain::Compiler).len(), 2);
    assert_eq!(u.probes_by_domain(&ProbeDomain::Runtime).len(), 1);
}

#[test]
fn universe_total_forensic_utility() {
    let u = standard_universe();
    // 800k + 700k + 900k + 600k + 500k = 3_500_000
    assert_eq!(u.total_forensic_utility(), 3_500_000);
}

#[test]
fn universe_total_forensic_utility_empty() {
    let u = ProbeUniverse::new();
    assert_eq!(u.total_forensic_utility(), 0);
}

#[test]
fn universe_serde_roundtrip() {
    let u = standard_universe();
    let json = serde_json::to_string(&u).unwrap();
    let back: ProbeUniverse = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

// ===========================================================================
// Section 8: ObservabilityBudget
// ===========================================================================

#[test]
fn budget_normal_values() {
    let b = ObservabilityBudget::normal();
    assert_eq!(b.max_latency_micros, 500);
    assert_eq!(b.max_memory_bytes, 1_048_576);
    assert_eq!(b.max_probe_count, 50);
    assert_eq!(b.min_event_coverage_millionths, 700_000);
}

#[test]
fn budget_degraded_values() {
    let b = ObservabilityBudget::degraded();
    assert_eq!(b.max_latency_micros, 2000);
    assert_eq!(b.max_memory_bytes, 4_194_304);
    assert_eq!(b.max_probe_count, 100);
    assert_eq!(b.min_event_coverage_millionths, 900_000);
}

#[test]
fn budget_incident_values() {
    let b = ObservabilityBudget::incident();
    assert_eq!(b.max_latency_micros, 10_000);
    assert_eq!(b.max_memory_bytes, 16_777_216);
    assert_eq!(b.max_probe_count, 200);
    assert_eq!(b.min_event_coverage_millionths, 950_000);
}

#[test]
fn budget_monotonic_escalation() {
    let n = ObservabilityBudget::normal();
    let d = ObservabilityBudget::degraded();
    let i = ObservabilityBudget::incident();
    assert!(d.max_latency_micros > n.max_latency_micros);
    assert!(d.max_memory_bytes > n.max_memory_bytes);
    assert!(d.max_probe_count > n.max_probe_count);
    assert!(i.max_latency_micros > d.max_latency_micros);
    assert!(i.max_memory_bytes > d.max_memory_bytes);
    assert!(i.max_probe_count > d.max_probe_count);
}

#[test]
fn budget_serde_roundtrip() {
    for b in [
        ObservabilityBudget::normal(),
        ObservabilityBudget::degraded(),
        ObservabilityBudget::incident(),
    ] {
        let json = serde_json::to_string(&b).unwrap();
        let back: ObservabilityBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }
}

// ===========================================================================
// Section 9: greedy_submodular_select
// ===========================================================================

#[test]
fn greedy_empty_universe_selects_nothing() {
    let u = ProbeUniverse::new();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    assert!(result.selected_indices.is_empty());
    assert_eq!(result.total_utility_millionths, 0);
    assert_eq!(result.total_latency_micros, 0);
    assert_eq!(result.total_memory_bytes, 0);
    assert!(result.covered_events.is_empty());
}

#[test]
fn greedy_selects_highest_marginal_gain_first() {
    let u = standard_universe();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    // Router has highest utility (900k) and lowest latency — selected first
    assert!(!result.selected_indices.is_empty());
    assert_eq!(result.selected_indices[0], 2); // router_decision index
}

#[test]
fn greedy_respects_latency_budget() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "fast",
        ProbeDomain::Compiler,
        MILLION,
        100,
        100,
        &["a"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "slow",
        ProbeDomain::Runtime,
        MILLION,
        1000,
        100,
        &["b"],
    ))
    .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 150,
        max_memory_bytes: 1_000_000,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 1);
    assert_eq!(result.selected_indices[0], 0);
    assert!(result.total_latency_micros <= 150);
}

#[test]
fn greedy_respects_memory_budget() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "small",
        ProbeDomain::Compiler,
        MILLION,
        10,
        100,
        &["a"],
    ))
    .unwrap();
    u.add_probe(make_probe(
        "big",
        ProbeDomain::Runtime,
        MILLION,
        10,
        50_000,
        &["b"],
    ))
    .unwrap();
    let budget = ObservabilityBudget {
        max_latency_micros: 10_000,
        max_memory_bytes: 500,
        max_probe_count: 10,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 1);
    assert_eq!(result.selected_indices[0], 0);
    assert!(result.total_memory_bytes <= 500);
}

#[test]
fn greedy_respects_count_budget() {
    let u = standard_universe();
    let budget = ObservabilityBudget {
        max_latency_micros: 100_000,
        max_memory_bytes: 100_000_000,
        max_probe_count: 2,
        min_event_coverage_millionths: 0,
    };
    let result = greedy_submodular_select(&u, &budget);
    assert_eq!(result.selected_indices.len(), 2);
}

#[test]
fn greedy_covers_events_accumulated() {
    let u = standard_universe();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::incident());
    // With generous budget, should cover many events
    assert!(!result.covered_events.is_empty());
}

#[test]
fn greedy_zero_utility_probes_not_selected() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "zero_u",
        ProbeDomain::Compiler,
        0,
        10,
        100,
        &["ev"],
    ))
    .unwrap();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    assert!(result.selected_indices.is_empty());
}

#[test]
fn greedy_single_probe_selected() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe(
        "only",
        ProbeDomain::Compiler,
        500_000,
        10,
        100,
        &["a"],
    ))
    .unwrap();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    assert_eq!(result.selected_indices, vec![0]);
    assert_eq!(result.total_utility_millionths, 500_000);
    assert_eq!(result.total_latency_micros, 10);
    assert_eq!(result.total_memory_bytes, 100);
    assert!(result.covered_events.contains("a"));
}

#[test]
fn greedy_serde_roundtrip() {
    let u = standard_universe();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    let json = serde_json::to_string(&result).unwrap();
    let back: OptimizationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn greedy_deterministic() {
    let u = standard_universe();
    let b = ObservabilityBudget::normal();
    let r1 = greedy_submodular_select(&u, &b);
    let r2 = greedy_submodular_select(&u, &b);
    assert_eq!(r1, r2);
}

// ===========================================================================
// Section 10: build_schedule
// ===========================================================================

#[test]
fn schedule_normal_mode() {
    let u = standard_universe();
    let s = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    assert_eq!(s.mode, OperatingMode::Normal);
    assert!(s.within_budget);
    assert!(s.probe_count() > 0);
}

#[test]
fn schedule_empty_universe_full_coverage() {
    let u = ProbeUniverse::new();
    let s = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    assert_eq!(s.probe_count(), 0);
    assert_eq!(s.event_coverage_millionths, MILLION);
    assert!(s.within_budget);
}

#[test]
fn schedule_incident_has_at_least_as_many_probes_as_normal() {
    let u = standard_universe();
    let normal = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let incident = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
    assert!(incident.probe_count() >= normal.probe_count());
}

#[test]
fn schedule_hash_is_deterministic() {
    let u = standard_universe();
    let s1 = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let s2 = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    assert_eq!(s1.schedule_hash, s2.schedule_hash);
}

#[test]
fn schedule_different_modes_different_hashes() {
    let u = standard_universe();
    let s_normal = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let s_incident = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
    // Different modes should produce different schedule hashes
    assert_ne!(s_normal.schedule_hash, s_incident.schedule_hash);
}

#[test]
fn schedule_probe_count_method() {
    let u = standard_universe();
    let s = build_schedule(&u, OperatingMode::Incident, ObservabilityBudget::incident());
    assert_eq!(s.probe_count(), s.selected_probe_ids.len());
}

#[test]
fn schedule_meets_coverage_boundary() {
    let u = standard_universe();
    let mut s = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    s.event_coverage_millionths = s.budget.min_event_coverage_millionths;
    assert!(s.meets_coverage());
    s.event_coverage_millionths -= 1;
    assert!(!s.meets_coverage());
}

#[test]
fn schedule_serde_roundtrip() {
    let u = standard_universe();
    let s = build_schedule(&u, OperatingMode::Degraded, ObservabilityBudget::degraded());
    let json = serde_json::to_string(&s).unwrap();
    let back: ProbeSchedule = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn schedule_json_field_presence() {
    let u = standard_universe();
    let s = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let json = serde_json::to_string(&s).unwrap();
    for field in [
        "\"mode\"",
        "\"selected_probe_ids\"",
        "\"total_latency_micros\"",
        "\"total_memory_bytes\"",
        "\"event_coverage_millionths\"",
        "\"forensic_utility_millionths\"",
        "\"within_budget\"",
        "\"schedule_hash\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Section 11: build_approximation_certificate
// ===========================================================================

#[test]
fn cert_algorithm_name() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    assert_eq!(cert.algorithm, "greedy_submodular");
}

#[test]
fn cert_optimality_bound() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    assert_eq!(cert.optimality_bound_millionths, 632_121);
}

#[test]
fn cert_headroom_computed_correctly() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    assert_eq!(
        cert.budget_headroom_latency_micros,
        budget
            .max_latency_micros
            .saturating_sub(result.total_latency_micros)
    );
    assert_eq!(
        cert.budget_headroom_memory_bytes,
        budget
            .max_memory_bytes
            .saturating_sub(result.total_memory_bytes)
    );
}

#[test]
fn cert_serde_roundtrip() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    let json = serde_json::to_string(&cert).unwrap();
    let back: ApproximationCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn cert_hash_deterministic() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let c1 = build_approximation_certificate(&result, &budget);
    let c2 = build_approximation_certificate(&result, &budget);
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn cert_json_field_presence() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let cert = build_approximation_certificate(&result, &budget);
    let json = serde_json::to_string(&cert).unwrap();
    for field in [
        "\"algorithm\"",
        "\"optimality_bound_millionths\"",
        "\"actual_utility_millionths\"",
        "\"budget_headroom_latency_micros\"",
        "\"budget_headroom_memory_bytes\"",
        "\"certificate_hash\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Section 12: ProbeUtilityLedger
// ===========================================================================

#[test]
fn ledger_entries_match_selected_count() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    assert_eq!(ledger.entries.len(), result.selected_indices.len());
}

#[test]
fn ledger_coverage_monotonically_increasing() {
    let u = standard_universe();
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
fn ledger_rounds_sequential() {
    let u = standard_universe();
    let budget = ObservabilityBudget::incident();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    for (i, entry) in ledger.entries.iter().enumerate() {
        assert_eq!(entry.selection_round, i);
    }
}

#[test]
fn ledger_serde_roundtrip() {
    let u = standard_universe();
    let budget = ObservabilityBudget::normal();
    let result = greedy_submodular_select(&u, &budget);
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ProbeUtilityLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn ledger_empty_universe_empty_entries() {
    let u = ProbeUniverse::new();
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    assert!(ledger.entries.is_empty());
}

// ===========================================================================
// Section 13: MultiModeManifest
// ===========================================================================

#[test]
fn manifest_build_all_modes() {
    let u = standard_universe();
    let m = MultiModeManifest::build(&u);
    assert_eq!(m.normal_schedule.mode, OperatingMode::Normal);
    assert_eq!(m.degraded_schedule.mode, OperatingMode::Degraded);
    assert_eq!(m.incident_schedule.mode, OperatingMode::Incident);
}

#[test]
fn manifest_schedule_for_mode() {
    let u = standard_universe();
    let m = MultiModeManifest::build(&u);
    assert_eq!(
        m.schedule_for_mode(&OperatingMode::Normal).mode,
        OperatingMode::Normal
    );
    assert_eq!(
        m.schedule_for_mode(&OperatingMode::Degraded).mode,
        OperatingMode::Degraded
    );
    assert_eq!(
        m.schedule_for_mode(&OperatingMode::Incident).mode,
        OperatingMode::Incident
    );
}

#[test]
fn manifest_incident_covers_at_least_as_much_as_normal() {
    let u = standard_universe();
    let m = MultiModeManifest::build(&u);
    assert!(
        m.incident_schedule.event_coverage_millionths
            >= m.normal_schedule.event_coverage_millionths
    );
}

#[test]
fn manifest_hash_deterministic() {
    let u = standard_universe();
    let m1 = MultiModeManifest::build(&u);
    let m2 = MultiModeManifest::build(&u);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn manifest_serde_roundtrip() {
    let u = standard_universe();
    let m = MultiModeManifest::build(&u);
    let json = serde_json::to_string(&m).unwrap();
    let back: MultiModeManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn manifest_clone_equality() {
    let u = standard_universe();
    let a = MultiModeManifest::build(&u);
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Section 14: End-to-end lifecycle tests
// ===========================================================================

#[test]
fn e2e_full_pipeline() {
    let u = standard_universe();

    // Build multi-mode manifest
    let manifest = MultiModeManifest::build(&u);
    assert!(manifest.normal_schedule.within_budget);

    // Get the optimization result for normal mode
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());

    // Build utility ledger
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    assert!(!ledger.entries.is_empty());

    // Build approximation certificate
    let cert = build_approximation_certificate(&result, &ObservabilityBudget::normal());
    assert!(cert.actual_utility_millionths > 0);
    assert_eq!(cert.optimality_bound_millionths, 632_121);

    // Incident mode should cover >= normal
    assert!(
        manifest.incident_schedule.event_coverage_millionths
            >= manifest.normal_schedule.event_coverage_millionths
    );
}

#[test]
fn e2e_mixed_granularity_universe() {
    let mut u = ProbeUniverse::new();
    u.add_probe(make_probe_with_granularity(
        "coarse_p",
        ProbeDomain::Compiler,
        ProbeGranularity::Coarse,
        300_000,
        10,
        100,
        &["compile_start"],
    ))
    .unwrap();
    u.add_probe(make_probe_with_granularity(
        "fine_p",
        ProbeDomain::Compiler,
        ProbeGranularity::Fine,
        600_000,
        50,
        500,
        &["compile_start", "compile_pass", "compile_end"],
    ))
    .unwrap();
    u.add_probe(make_probe_with_granularity(
        "trace_p",
        ProbeDomain::Runtime,
        ProbeGranularity::Trace,
        800_000,
        200,
        2000,
        &["runtime_init", "runtime_exec"],
    ))
    .unwrap();

    let manifest = MultiModeManifest::build(&u);

    // Normal budget might exclude trace probe due to latency
    // Incident budget should include everything
    let incident = &manifest.incident_schedule;
    assert!(incident.probe_count() > 0);
    assert!(incident.within_budget);
}

#[test]
fn e2e_all_serde_roundtrip_in_pipeline() {
    let u = standard_universe();

    // Universe
    let u_json = serde_json::to_string(&u).unwrap();
    let u_back: ProbeUniverse = serde_json::from_str(&u_json).unwrap();
    assert_eq!(u, u_back);

    // Optimization result
    let result = greedy_submodular_select(&u, &ObservabilityBudget::normal());
    let r_json = serde_json::to_string(&result).unwrap();
    let r_back: OptimizationResult = serde_json::from_str(&r_json).unwrap();
    assert_eq!(result, r_back);

    // Schedule
    let schedule = build_schedule(&u, OperatingMode::Normal, ObservabilityBudget::normal());
    let s_json = serde_json::to_string(&schedule).unwrap();
    let s_back: ProbeSchedule = serde_json::from_str(&s_json).unwrap();
    assert_eq!(schedule, s_back);

    // Certificate
    let cert = build_approximation_certificate(&result, &ObservabilityBudget::normal());
    let c_json = serde_json::to_string(&cert).unwrap();
    let c_back: ApproximationCertificate = serde_json::from_str(&c_json).unwrap();
    assert_eq!(cert, c_back);

    // Ledger
    let ledger = ProbeUtilityLedger::from_optimization(&u, &result);
    let l_json = serde_json::to_string(&ledger).unwrap();
    let l_back: ProbeUtilityLedger = serde_json::from_str(&l_json).unwrap();
    assert_eq!(ledger, l_back);

    // Manifest
    let manifest = MultiModeManifest::build(&u);
    let m_json = serde_json::to_string(&manifest).unwrap();
    let m_back: MultiModeManifest = serde_json::from_str(&m_json).unwrap();
    assert_eq!(manifest, m_back);
}

#[test]
fn e2e_probe_metadata_preserved() {
    let mut p = make_probe(
        "meta_p",
        ProbeDomain::Governance,
        400_000,
        30,
        200,
        &["gov_evt"],
    );
    p.metadata
        .insert("owner".to_string(), "security-team".to_string());
    p.metadata
        .insert("priority".to_string(), "high".to_string());

    let mut u = ProbeUniverse::new();
    u.add_probe(p).unwrap();

    let json = serde_json::to_string(&u).unwrap();
    let back: ProbeUniverse = serde_json::from_str(&json).unwrap();
    assert_eq!(back.probes[0].metadata.len(), 2);
    assert_eq!(
        back.probes[0].metadata.get("owner").unwrap(),
        "security-team"
    );
}
