#![forbid(unsafe_code)]

//! Enrichment integration tests for the `adversarial_supremacy_synthesis` module.

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

use std::collections::BTreeSet;

use frankenengine_engine::adversarial_supremacy_synthesis::{
    ARCHETYPE_COUNT, BEAD_ID, COMPONENT, CRITICAL_GAP_THRESHOLD, CounterexampleSeverity,
    DEFAULT_MAX_GENERATIONS, DEFAULT_MAX_SEARCH_BUDGET, DEFAULT_MIN_COVERAGE,
    DEFAULT_MUTATION_RATE, DEFAULT_SEVERITY_THRESHOLD, DEFAULT_WORKLOADS_PER_GENERATION,
    DecisionReceipt, FalsificationResult, FalsificationVerdict, MAJOR_GAP_THRESHOLD,
    MINOR_GAP_THRESHOLD, MiningConfig, POLICY_ID, SCHEMA_VERSION, STRATEGY_COUNT, SynthesisReport,
    SynthesisStrategy, WorkloadArchetype, classify_severity, evaluate_counterexample,
    generate_workload, summarize, synthesize_batch,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ===========================================================================
// SynthesisStrategy — Copy, BTreeSet, Debug/Display unique, as_str matches Display
// ===========================================================================

#[test]
fn enrichment_synthesis_strategy_copy_semantics() {
    let a = SynthesisStrategy::GradientGuided;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_synthesis_strategy_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    for v in SynthesisStrategy::ALL {
        set.insert(*v);
    }
    set.insert(SynthesisStrategy::GradientGuided);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_synthesis_strategy_debug_all_unique() {
    let strs: BTreeSet<String> = SynthesisStrategy::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), STRATEGY_COUNT);
}

#[test]
fn enrichment_synthesis_strategy_display_all_unique() {
    let strs: BTreeSet<String> = SynthesisStrategy::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), STRATEGY_COUNT);
}

#[test]
fn enrichment_synthesis_strategy_as_str_matches_display() {
    for v in SynthesisStrategy::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_synthesis_strategy_clone_independence() {
    let a = SynthesisStrategy::BoundaryProbe;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_synthesis_strategy_effectiveness_all_positive() {
    for v in SynthesisStrategy::ALL {
        assert!(v.effectiveness_multiplier() > 0);
        assert!(v.effectiveness_multiplier() <= 1_000_000);
    }
}

// ===========================================================================
// CounterexampleSeverity — Copy, BTreeSet, Debug/Display unique, as_str, ordering
// ===========================================================================

#[test]
fn enrichment_counterexample_severity_copy_semantics() {
    let a = CounterexampleSeverity::Critical;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_counterexample_severity_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in CounterexampleSeverity::ALL {
        set.insert(*v);
    }
    set.insert(CounterexampleSeverity::Informational);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_counterexample_severity_debug_all_unique() {
    let strs: BTreeSet<String> = CounterexampleSeverity::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_counterexample_severity_display_all_unique() {
    let strs: BTreeSet<String> = CounterexampleSeverity::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_counterexample_severity_as_str_matches_display() {
    for v in CounterexampleSeverity::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_counterexample_severity_meets_threshold_reflexive() {
    for v in CounterexampleSeverity::ALL {
        assert!(v.meets_threshold(*v));
    }
}

#[test]
fn enrichment_counterexample_severity_ordering_ascending() {
    let sev = CounterexampleSeverity::ALL;
    for i in 1..sev.len() {
        assert!(sev[i] > sev[i - 1], "ALL should be ascending");
    }
}

#[test]
fn enrichment_counterexample_severity_critical_meets_all() {
    let crit = CounterexampleSeverity::Critical;
    for v in CounterexampleSeverity::ALL {
        assert!(crit.meets_threshold(*v));
    }
}

#[test]
fn enrichment_counterexample_severity_informational_only_meets_self() {
    let info = CounterexampleSeverity::Informational;
    assert!(info.meets_threshold(CounterexampleSeverity::Informational));
    assert!(!info.meets_threshold(CounterexampleSeverity::Minor));
}

// ===========================================================================
// FalsificationVerdict — Copy, BTreeSet, Debug/Display unique, as_str, methods
// ===========================================================================

#[test]
fn enrichment_falsification_verdict_copy_semantics() {
    let a = FalsificationVerdict::Falsified;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_falsification_verdict_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in FalsificationVerdict::ALL {
        set.insert(*v);
    }
    set.insert(FalsificationVerdict::Survived);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_falsification_verdict_debug_all_unique() {
    let strs: BTreeSet<String> = FalsificationVerdict::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_falsification_verdict_display_all_unique() {
    let strs: BTreeSet<String> = FalsificationVerdict::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_falsification_verdict_as_str_matches_display() {
    for v in FalsificationVerdict::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_falsification_verdict_exactly_one_valid() {
    let valid_count = FalsificationVerdict::ALL
        .iter()
        .filter(|v| v.is_valid())
        .count();
    assert_eq!(valid_count, 1);
    assert!(FalsificationVerdict::Survived.is_valid());
}

#[test]
fn enrichment_falsification_verdict_compromised_two() {
    let compromised: Vec<_> = FalsificationVerdict::ALL
        .iter()
        .filter(|v| v.is_compromised())
        .collect();
    assert_eq!(compromised.len(), 2);
    assert!(FalsificationVerdict::Falsified.is_compromised());
    assert!(FalsificationVerdict::Weakened.is_compromised());
}

#[test]
fn enrichment_falsification_verdict_serde_all() {
    for v in FalsificationVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: FalsificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// WorkloadArchetype — Copy, BTreeSet, Debug/Display unique, as_str, complexity
// ===========================================================================

#[test]
fn enrichment_workload_archetype_copy_semantics() {
    let a = WorkloadArchetype::CpuBound;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_archetype_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    for v in WorkloadArchetype::ALL {
        set.insert(*v);
    }
    set.insert(WorkloadArchetype::MixedProfile);
    assert_eq!(set.len(), ARCHETYPE_COUNT);
}

#[test]
fn enrichment_workload_archetype_debug_all_unique() {
    let strs: BTreeSet<String> = WorkloadArchetype::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), ARCHETYPE_COUNT);
}

#[test]
fn enrichment_workload_archetype_display_all_unique() {
    let strs: BTreeSet<String> = WorkloadArchetype::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), ARCHETYPE_COUNT);
}

#[test]
fn enrichment_workload_archetype_as_str_matches_display() {
    for v in WorkloadArchetype::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_workload_archetype_base_complexity_all_positive() {
    for v in WorkloadArchetype::ALL {
        let c = v.base_complexity();
        assert!(c > 0, "{v:?} has zero base_complexity");
        assert!(c <= 1_000_000, "{v:?} exceeds 1.0");
    }
}

// ===========================================================================
// SyntheticWorkload — Clone, Debug, Display, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_synthetic_workload_clone_independence() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"seed-1",
        epoch(),
    );
    let mut cloned = wl.clone();
    cloned.size_bytes = 999_999;
    assert_ne!(wl.size_bytes, cloned.size_bytes);
}

#[test]
fn enrichment_synthetic_workload_debug_nonempty() {
    let wl = generate_workload(
        WorkloadArchetype::MemoryBound,
        SynthesisStrategy::RandomMutation,
        1,
        b"seed-2",
        epoch(),
    );
    let dbg = format!("{wl:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SyntheticWorkload"));
}

#[test]
fn enrichment_synthetic_workload_display_contains_parts() {
    let wl = generate_workload(
        WorkloadArchetype::IoBound,
        SynthesisStrategy::CoverageDirected,
        2,
        b"seed-3",
        epoch(),
    );
    let disp = format!("{wl}");
    assert!(disp.contains("workload["));
    assert!(disp.contains("arch="));
    assert!(disp.contains("strat="));
    assert!(disp.contains("gen="));
}

#[test]
fn enrichment_synthetic_workload_json_field_names() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"seed-4",
        epoch(),
    );
    let json = serde_json::to_string(&wl).unwrap();
    for field in &[
        "workload_id",
        "archetype",
        "strategy",
        "program_hash",
        "size_bytes",
        "complexity_score",
        "generation",
        "epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_synthetic_workload_serde_roundtrip() {
    let wl = generate_workload(
        WorkloadArchetype::LatencySensitive,
        SynthesisStrategy::PatternRecombination,
        5,
        b"seed-5",
        epoch(),
    );
    let json = serde_json::to_string(&wl).unwrap();
    let back = serde_json::from_str(&json).unwrap();
    assert_eq!(wl, back);
}

#[test]
fn enrichment_synthetic_workload_id_starts_with_wl() {
    let wl = generate_workload(
        WorkloadArchetype::BranchHeavy,
        SynthesisStrategy::BoundaryProbe,
        0,
        b"seed-6",
        epoch(),
    );
    assert!(wl.workload_id.starts_with("wl-"));
}

#[test]
fn enrichment_synthetic_workload_different_seeds_different_hashes() {
    let wl1 = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"alpha",
        epoch(),
    );
    let wl2 = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"beta",
        epoch(),
    );
    assert_ne!(wl1.program_hash, wl2.program_hash);
}

#[test]
fn enrichment_synthetic_workload_complexity_in_range() {
    for arch in WorkloadArchetype::ALL {
        for strat in SynthesisStrategy::ALL {
            let wl = generate_workload(*arch, *strat, 0, b"x", epoch());
            assert!(
                wl.complexity_score <= 1_000_000,
                "{arch:?}+{strat:?} complexity={} exceeds 1.0",
                wl.complexity_score
            );
        }
    }
}

// ===========================================================================
// classify_severity — boundary tests
// ===========================================================================

#[test]
fn enrichment_classify_severity_exact_critical_boundary() {
    assert_eq!(
        classify_severity(CRITICAL_GAP_THRESHOLD),
        CounterexampleSeverity::Critical
    );
    assert_ne!(
        classify_severity(CRITICAL_GAP_THRESHOLD - 1),
        CounterexampleSeverity::Critical
    );
}

#[test]
fn enrichment_classify_severity_exact_major_boundary() {
    assert_eq!(
        classify_severity(MAJOR_GAP_THRESHOLD),
        CounterexampleSeverity::Major
    );
    assert_ne!(
        classify_severity(MAJOR_GAP_THRESHOLD - 1),
        CounterexampleSeverity::Major
    );
}

#[test]
fn enrichment_classify_severity_exact_minor_boundary() {
    assert_eq!(
        classify_severity(MINOR_GAP_THRESHOLD),
        CounterexampleSeverity::Minor
    );
    assert_ne!(
        classify_severity(MINOR_GAP_THRESHOLD - 1),
        CounterexampleSeverity::Minor
    );
}

#[test]
fn enrichment_classify_severity_zero_is_informational() {
    assert_eq!(classify_severity(0), CounterexampleSeverity::Informational);
}

#[test]
fn enrichment_classify_severity_max_is_critical() {
    assert_eq!(
        classify_severity(1_000_000),
        CounterexampleSeverity::Critical
    );
}

// ===========================================================================
// evaluate_counterexample — boundary and property tests
// ===========================================================================

#[test]
fn enrichment_evaluate_counterexample_none_when_equal() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"eq",
        epoch(),
    );
    let result = evaluate_counterexample(&wl, "claim-1", 500_000, 500_000);
    assert!(result.is_none());
}

#[test]
fn enrichment_evaluate_counterexample_none_when_observed_exceeds() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"ex",
        epoch(),
    );
    let result = evaluate_counterexample(&wl, "claim-2", 500_000, 600_000);
    assert!(result.is_none());
}

#[test]
fn enrichment_evaluate_counterexample_some_when_gap() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"gap",
        epoch(),
    );
    let result = evaluate_counterexample(&wl, "claim-3", 1_000_000, 400_000);
    assert!(result.is_some());
    let cx = result.unwrap();
    assert_eq!(cx.claim_id, "claim-3");
    assert_eq!(cx.expected_millionths, 1_000_000);
    assert_eq!(cx.observed_millionths, 400_000);
    assert!(cx.gap_fraction > 0);
}

#[test]
fn enrichment_evaluate_counterexample_gap_fraction_correct() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"frac",
        epoch(),
    );
    // gap = 1_000_000 - 500_000 = 500_000
    // gap_fraction = (500_000 * 1_000_000) / 1_000_000 = 500_000
    let cx = evaluate_counterexample(&wl, "claim-4", 1_000_000, 500_000).unwrap();
    assert_eq!(cx.gap_fraction, 500_000);
    assert_eq!(cx.severity, CounterexampleSeverity::Critical);
}

#[test]
fn enrichment_counterexample_clone_independence() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"cl",
        epoch(),
    );
    let cx = evaluate_counterexample(&wl, "claim-5", 1_000_000, 100_000).unwrap();
    let mut cloned = cx.clone();
    cloned.explanation = "changed".to_string();
    assert_ne!(cx.explanation, cloned.explanation);
}

#[test]
fn enrichment_counterexample_debug_nonempty() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"dbg",
        epoch(),
    );
    let cx = evaluate_counterexample(&wl, "claim-6", 1_000_000, 100_000).unwrap();
    let dbg = format!("{cx:?}");
    assert!(dbg.contains("Counterexample"));
}

#[test]
fn enrichment_counterexample_display_contains_parts() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"disp",
        epoch(),
    );
    let cx = evaluate_counterexample(&wl, "claim-7", 1_000_000, 100_000).unwrap();
    let disp = format!("{cx}");
    assert!(disp.contains("counterexample["));
    assert!(disp.contains("claim="));
    assert!(disp.contains("severity="));
}

#[test]
fn enrichment_counterexample_json_field_names() {
    let wl = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"json",
        epoch(),
    );
    let cx = evaluate_counterexample(&wl, "claim-8", 1_000_000, 100_000).unwrap();
    let json = serde_json::to_string(&cx).unwrap();
    for field in &[
        "workload",
        "severity",
        "claim_id",
        "expected_millionths",
        "observed_millionths",
        "gap_fraction",
        "explanation",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

// ===========================================================================
// MiningConfig — Clone, Debug, JSON fields, default, methods
// ===========================================================================

#[test]
fn enrichment_mining_config_clone_independence() {
    let mut a = MiningConfig::default();
    let b = a.clone();
    a.max_generations = 999;
    assert_ne!(a.max_generations, b.max_generations);
}

#[test]
fn enrichment_mining_config_debug_nonempty() {
    let cfg = MiningConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("MiningConfig"));
}

#[test]
fn enrichment_mining_config_json_field_names() {
    let cfg = MiningConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "max_generations",
        "workloads_per_generation",
        "mutation_rate",
        "min_coverage_fraction",
        "severity_threshold",
        "max_search_budget",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_mining_config_default_matches_constants() {
    let cfg = MiningConfig::default();
    assert_eq!(cfg.max_generations, DEFAULT_MAX_GENERATIONS);
    assert_eq!(
        cfg.workloads_per_generation,
        DEFAULT_WORKLOADS_PER_GENERATION
    );
    assert_eq!(cfg.mutation_rate, DEFAULT_MUTATION_RATE);
    assert_eq!(cfg.min_coverage_fraction, DEFAULT_MIN_COVERAGE);
    assert_eq!(cfg.severity_threshold, DEFAULT_SEVERITY_THRESHOLD);
    assert_eq!(cfg.max_search_budget, DEFAULT_MAX_SEARCH_BUDGET);
}

#[test]
fn enrichment_mining_config_coverage_sufficient_boundary() {
    let cfg = MiningConfig::default();
    assert!(cfg.coverage_sufficient(cfg.min_coverage_fraction));
    assert!(cfg.coverage_sufficient(cfg.min_coverage_fraction + 1));
    assert!(!cfg.coverage_sufficient(cfg.min_coverage_fraction - 1));
}

#[test]
fn enrichment_mining_config_budget_exhausted_boundary() {
    let cfg = MiningConfig::default();
    assert!(cfg.budget_exhausted(cfg.max_search_budget));
    assert!(cfg.budget_exhausted(cfg.max_search_budget + 1));
    assert!(!cfg.budget_exhausted(cfg.max_search_budget - 1));
}

#[test]
fn enrichment_mining_config_serde_roundtrip() {
    let cfg = MiningConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MiningConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// FalsificationResult — Clone, Debug, Display, JSON fields, methods
// ===========================================================================

#[test]
fn enrichment_falsification_result_clone_independence() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-fr1",
        &MiningConfig::default(),
        epoch(),
    );
    let mut cloned = result.clone();
    cloned.workloads_tested = 999_999;
    assert_ne!(result.workloads_tested, cloned.workloads_tested);
}

#[test]
fn enrichment_falsification_result_debug_nonempty() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-fr2",
        &MiningConfig::default(),
        epoch(),
    );
    let dbg = format!("{result:?}");
    assert!(dbg.contains("FalsificationResult"));
}

#[test]
fn enrichment_falsification_result_display_contains_parts() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-fr3",
        &MiningConfig::default(),
        epoch(),
    );
    let disp = format!("{result}");
    assert!(disp.contains("falsification["));
    assert!(disp.contains("verdict="));
    assert!(disp.contains("tested="));
}

#[test]
fn enrichment_falsification_result_json_field_names() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-fr4",
        &MiningConfig::default(),
        epoch(),
    );
    let json = serde_json::to_string(&result).unwrap();
    for field in &[
        "claim_id",
        "verdict",
        "counterexamples",
        "workloads_tested",
        "coverage_fraction",
        "search_budget_used",
        "epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_falsification_result_serde_roundtrip() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-fr5",
        &MiningConfig::default(),
        epoch(),
    );
    let json = serde_json::to_string(&result).unwrap();
    let back: FalsificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_falsification_result_count_at_severity_monotonic() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-sev",
        &MiningConfig::default(),
        epoch(),
    );
    let info = result.count_at_severity(CounterexampleSeverity::Informational);
    let minor = result.count_at_severity(CounterexampleSeverity::Minor);
    let major = result.count_at_severity(CounterexampleSeverity::Major);
    let crit = result.count_at_severity(CounterexampleSeverity::Critical);
    assert!(info >= minor);
    assert!(minor >= major);
    assert!(major >= crit);
}

// ===========================================================================
// SynthesisReport — Clone, Debug, Display, JSON fields, methods
// ===========================================================================

#[test]
fn enrichment_synthesis_report_clone_independence() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-sr1",
        &MiningConfig::default(),
        epoch(),
    );
    let report = summarize(&[result]);
    let mut cloned = report.clone();
    cloned.total_workloads = 999_999;
    assert_ne!(report.total_workloads, cloned.total_workloads);
}

#[test]
fn enrichment_synthesis_report_debug_nonempty() {
    let report = summarize(&[]);
    let dbg = format!("{report:?}");
    assert!(dbg.contains("SynthesisReport"));
}

#[test]
fn enrichment_synthesis_report_display_contains_parts() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-sr2",
        &MiningConfig::default(),
        epoch(),
    );
    let report = summarize(&[result]);
    let disp = format!("{report}");
    assert!(disp.contains("report:"));
    assert!(disp.contains("workloads="));
}

#[test]
fn enrichment_synthesis_report_json_field_names() {
    let report = summarize(&[]);
    let json = serde_json::to_string(&report).unwrap();
    for field in &[
        "total_workloads",
        "total_counterexamples",
        "falsified_claims",
        "weakened_claims",
        "survived_claims",
        "strongest_counterexample",
        "receipt_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_synthesis_report_serde_roundtrip() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-sr3",
        &MiningConfig::default(),
        epoch(),
    );
    let report = summarize(&[result]);
    let json = serde_json::to_string(&report).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_synthesis_report_empty_results_all_zero() {
    let report = summarize(&[]);
    assert_eq!(report.total_workloads, 0);
    assert_eq!(report.total_counterexamples, 0);
    assert_eq!(report.falsified_claims, 0);
    assert_eq!(report.weakened_claims, 0);
    assert_eq!(report.survived_claims, 0);
    assert!(report.strongest_counterexample.is_none());
}

#[test]
fn enrichment_synthesis_report_total_claims_sum() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-tc",
        &MiningConfig::default(),
        epoch(),
    );
    let report = summarize(&[result]);
    assert_eq!(
        report.total_claims(),
        report.falsified_claims + report.weakened_claims + report.survived_claims
    );
}

#[test]
fn enrichment_synthesis_report_all_survived_consistency() {
    let report = summarize(&[]);
    // No results → no survived
    assert!(!report.all_survived());
}

// ===========================================================================
// DecisionReceipt — Clone, Debug, Display, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_decision_receipt_clone_independence() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr1",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    let mut cloned = receipt.clone();
    cloned.component = "changed".to_string();
    assert_ne!(receipt.component, cloned.component);
}

#[test]
fn enrichment_decision_receipt_debug_nonempty() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr2",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("DecisionReceipt"));
}

#[test]
fn enrichment_decision_receipt_display_contains_parts() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr3",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    let disp = format!("{receipt}");
    assert!(disp.contains("receipt["));
    assert!(disp.contains("verdict="));
    assert!(disp.contains("epoch="));
}

#[test]
fn enrichment_decision_receipt_json_field_names() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr4",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    let json = serde_json::to_string(&receipt).unwrap();
    for field in &[
        "receipt_hash",
        "component",
        "epoch",
        "verdict",
        "evidence_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr5",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_decision_receipt_component_is_module() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr6",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_decision_receipt_verdict_matches_result() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-dr7",
        &MiningConfig::default(),
        epoch(),
    );
    let receipt = DecisionReceipt::from_result(&result);
    assert_eq!(receipt.verdict, result.verdict);
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_generate_workload() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let wl = generate_workload(
                WorkloadArchetype::CpuBound,
                SynthesisStrategy::GradientGuided,
                0,
                b"det-seed",
                epoch(),
            );
            wl.program_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_synthesize_batch() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let result = synthesize_batch(
                &[WorkloadArchetype::CpuBound],
                &[SynthesisStrategy::GradientGuided],
                "det-claim",
                &MiningConfig::default(),
                epoch(),
            );
            let json = serde_json::to_string(&result).unwrap();
            ContentHash::compute(json.as_bytes())
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_summarize() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let result = synthesize_batch(
                &[WorkloadArchetype::CpuBound],
                &[SynthesisStrategy::GradientGuided],
                "det-sum",
                &MiningConfig::default(),
                epoch(),
            );
            let report = summarize(&[result]);
            report.receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_decision_receipt() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let result = synthesize_batch(
                &[WorkloadArchetype::CpuBound],
                &[SynthesisStrategy::GradientGuided],
                "det-rcpt",
                &MiningConfig::default(),
                epoch(),
            );
            DecisionReceipt::from_result(&result).receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.adversarial-supremacy-synthesis.v1"
    );
    assert_eq!(COMPONENT, "adversarial_supremacy_synthesis");
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.4");
    assert_eq!(POLICY_ID, "RGC-705D");
    assert_eq!(STRATEGY_COUNT, 6);
    assert_eq!(ARCHETYPE_COUNT, 8);
}

#[test]
fn enrichment_gap_thresholds_ordered() {
    assert!(CRITICAL_GAP_THRESHOLD > MAJOR_GAP_THRESHOLD);
    assert!(MAJOR_GAP_THRESHOLD > MINOR_GAP_THRESHOLD);
    assert!(MINOR_GAP_THRESHOLD > 0);
}

#[test]
fn enrichment_all_array_lengths_match_counts() {
    assert_eq!(SynthesisStrategy::ALL.len(), STRATEGY_COUNT);
    assert_eq!(WorkloadArchetype::ALL.len(), ARCHETYPE_COUNT);
    assert_eq!(CounterexampleSeverity::ALL.len(), 4);
    assert_eq!(FalsificationVerdict::ALL.len(), 4);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_cross_cutting_different_claims_different_receipts() {
    let r1 = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-A",
        &MiningConfig::default(),
        epoch(),
    );
    let r2 = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-B",
        &MiningConfig::default(),
        epoch(),
    );
    let rcpt1 = DecisionReceipt::from_result(&r1);
    let rcpt2 = DecisionReceipt::from_result(&r2);
    assert_ne!(rcpt1.receipt_hash, rcpt2.receipt_hash);
}

#[test]
fn enrichment_cross_cutting_multi_archetype_multi_strategy() {
    let result = synthesize_batch(
        WorkloadArchetype::ALL,
        SynthesisStrategy::ALL,
        "claim-multi",
        &MiningConfig::default(),
        epoch(),
    );
    // Should have tested at least ARCHETYPE_COUNT * STRATEGY_COUNT workloads
    assert!(result.workloads_tested >= (ARCHETYPE_COUNT * STRATEGY_COUNT) as u64);
}

#[test]
fn enrichment_cross_cutting_strongest_cx_is_max_gap() {
    let result = synthesize_batch(
        WorkloadArchetype::ALL,
        SynthesisStrategy::ALL,
        "claim-strongest",
        &MiningConfig::default(),
        epoch(),
    );
    if let Some(strongest) = result.strongest_counterexample() {
        for cx in &result.counterexamples {
            assert!(strongest.gap_fraction >= cx.gap_fraction);
        }
    }
}

#[test]
fn enrichment_cross_cutting_empty_archetypes_zero_tested() {
    let result = synthesize_batch(
        &[],
        &[SynthesisStrategy::GradientGuided],
        "claim-empty",
        &MiningConfig::default(),
        epoch(),
    );
    assert_eq!(result.workloads_tested, 0);
}

#[test]
fn enrichment_cross_cutting_empty_strategies_zero_tested() {
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[],
        "claim-empty-strat",
        &MiningConfig::default(),
        epoch(),
    );
    assert_eq!(result.workloads_tested, 0);
}
