#![forbid(unsafe_code)]

//! Integration tests for the adversarial_supremacy_synthesis module.

use frankenengine_engine::adversarial_supremacy_synthesis::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(500)
}

fn make_workload(
    archetype: WorkloadArchetype,
    strategy: SynthesisStrategy,
    generation: u64,
) -> SyntheticWorkload {
    generate_workload(archetype, strategy, generation, b"integration-seed", epoch())
}

fn small_config() -> MiningConfig {
    MiningConfig {
        max_generations: 3,
        workloads_per_generation: 4,
        mutation_rate: 100_000,
        min_coverage_fraction: 800_000,
        severity_threshold: CounterexampleSeverity::Minor,
        max_search_budget: 1_000_000,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.adversarial-supremacy-synthesis.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "adversarial_supremacy_synthesis");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.4");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-705D");
}

#[test]
fn test_default_max_generations() {
    assert_eq!(DEFAULT_MAX_GENERATIONS, 100);
}

#[test]
fn test_default_workloads_per_generation() {
    assert_eq!(DEFAULT_WORKLOADS_PER_GENERATION, 64);
}

#[test]
fn test_default_mutation_rate() {
    assert_eq!(DEFAULT_MUTATION_RATE, 100_000);
}

#[test]
fn test_default_min_coverage() {
    assert_eq!(DEFAULT_MIN_COVERAGE, 800_000);
}

#[test]
fn test_default_max_search_budget() {
    assert_eq!(DEFAULT_MAX_SEARCH_BUDGET, 1_000_000);
}

#[test]
fn test_gap_thresholds_ordering() {
    assert!(CRITICAL_GAP_THRESHOLD > MAJOR_GAP_THRESHOLD);
    assert!(MAJOR_GAP_THRESHOLD > MINOR_GAP_THRESHOLD);
}

#[test]
fn test_strategy_count() {
    assert_eq!(STRATEGY_COUNT, SynthesisStrategy::ALL.len());
}

#[test]
fn test_archetype_count() {
    assert_eq!(ARCHETYPE_COUNT, WorkloadArchetype::ALL.len());
}

// ---------------------------------------------------------------------------
// SynthesisStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_synthesis_strategy_all_variants() {
    assert_eq!(SynthesisStrategy::ALL.len(), 6);
}

#[test]
fn test_synthesis_strategy_as_str_roundtrip() {
    for variant in SynthesisStrategy::ALL {
        let s = variant.as_str();
        assert!(!s.is_empty());
        assert_eq!(variant.to_string(), s);
    }
}

#[test]
fn test_synthesis_strategy_serde_roundtrip() {
    for variant in SynthesisStrategy::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: SynthesisStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_synthesis_strategy_effectiveness_multiplier_range() {
    for variant in SynthesisStrategy::ALL {
        let m = variant.effectiveness_multiplier();
        assert!(m > 0 && m <= 1_000_000);
    }
}

#[test]
fn test_synthesis_strategy_display() {
    assert_eq!(SynthesisStrategy::GradientGuided.to_string(), "gradient_guided");
    assert_eq!(SynthesisStrategy::RandomMutation.to_string(), "random_mutation");
    assert_eq!(SynthesisStrategy::ArchetypeInversion.to_string(), "archetype_inversion");
}

// ---------------------------------------------------------------------------
// CounterexampleSeverity
// ---------------------------------------------------------------------------

#[test]
fn test_severity_all_variants() {
    assert_eq!(CounterexampleSeverity::ALL.len(), 4);
}

#[test]
fn test_severity_serde_roundtrip() {
    for variant in CounterexampleSeverity::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: CounterexampleSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_severity_ordering() {
    assert!(CounterexampleSeverity::Informational < CounterexampleSeverity::Minor);
    assert!(CounterexampleSeverity::Minor < CounterexampleSeverity::Major);
    assert!(CounterexampleSeverity::Major < CounterexampleSeverity::Critical);
}

#[test]
fn test_severity_meets_threshold() {
    assert!(CounterexampleSeverity::Critical.meets_threshold(CounterexampleSeverity::Minor));
    assert!(CounterexampleSeverity::Minor.meets_threshold(CounterexampleSeverity::Minor));
    assert!(!CounterexampleSeverity::Informational.meets_threshold(CounterexampleSeverity::Minor));
}

#[test]
fn test_severity_display() {
    assert_eq!(CounterexampleSeverity::Critical.to_string(), "critical");
    assert_eq!(CounterexampleSeverity::Informational.to_string(), "informational");
}

// ---------------------------------------------------------------------------
// FalsificationVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_all_variants() {
    assert_eq!(FalsificationVerdict::ALL.len(), 4);
}

#[test]
fn test_verdict_serde_roundtrip() {
    for variant in FalsificationVerdict::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: FalsificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_verdict_is_valid() {
    assert!(FalsificationVerdict::Survived.is_valid());
    assert!(!FalsificationVerdict::Falsified.is_valid());
    assert!(!FalsificationVerdict::Weakened.is_valid());
    assert!(!FalsificationVerdict::InsufficientSearch.is_valid());
}

#[test]
fn test_verdict_is_compromised() {
    assert!(FalsificationVerdict::Falsified.is_compromised());
    assert!(FalsificationVerdict::Weakened.is_compromised());
    assert!(!FalsificationVerdict::Survived.is_compromised());
    assert!(!FalsificationVerdict::InsufficientSearch.is_compromised());
}

#[test]
fn test_verdict_display() {
    assert_eq!(FalsificationVerdict::Survived.to_string(), "survived");
    assert_eq!(FalsificationVerdict::Falsified.to_string(), "falsified");
}

// ---------------------------------------------------------------------------
// WorkloadArchetype
// ---------------------------------------------------------------------------

#[test]
fn test_archetype_all_variants() {
    assert_eq!(WorkloadArchetype::ALL.len(), 8);
}

#[test]
fn test_archetype_serde_roundtrip() {
    for variant in WorkloadArchetype::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: WorkloadArchetype = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_archetype_base_complexity_range() {
    for variant in WorkloadArchetype::ALL {
        let c = variant.base_complexity();
        assert!(c > 0 && c <= 1_000_000);
    }
}

#[test]
fn test_archetype_display() {
    assert_eq!(WorkloadArchetype::CpuBound.to_string(), "cpu_bound");
    assert_eq!(WorkloadArchetype::GcPressure.to_string(), "gc_pressure");
    assert_eq!(WorkloadArchetype::MixedProfile.to_string(), "mixed_profile");
}

// ---------------------------------------------------------------------------
// SyntheticWorkload
// ---------------------------------------------------------------------------

#[test]
fn test_generate_workload_basic() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    assert!(w.workload_id.starts_with("wl-"));
    assert_eq!(w.archetype, WorkloadArchetype::CpuBound);
    assert_eq!(w.strategy, SynthesisStrategy::GradientGuided);
    assert_eq!(w.generation, 0);
    assert_eq!(w.epoch, epoch());
}

#[test]
fn test_generate_workload_deterministic() {
    let a = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let b = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    assert_eq!(a.workload_id, b.workload_id);
    assert_eq!(a.program_hash, b.program_hash);
    assert_eq!(a.complexity_score, b.complexity_score);
}

#[test]
fn test_generate_workload_different_archetypes_differ() {
    let a = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let b = make_workload(WorkloadArchetype::IoBound, SynthesisStrategy::GradientGuided, 0);
    assert_ne!(a.workload_id, b.workload_id);
    assert_ne!(a.program_hash, b.program_hash);
}

#[test]
fn test_generate_workload_different_strategies_differ() {
    let a = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let b = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::RandomMutation, 0);
    assert_ne!(a.workload_id, b.workload_id);
}

#[test]
fn test_generate_workload_size_increases_with_generation() {
    let a = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let b = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 10);
    assert!(b.size_bytes > a.size_bytes);
}

#[test]
fn test_workload_display_contains_fields() {
    let w = make_workload(WorkloadArchetype::MemoryBound, SynthesisStrategy::BoundaryProbe, 5);
    let s = w.to_string();
    assert!(s.contains("memory_bound"));
    assert!(s.contains("boundary_probe"));
    assert!(s.contains("gen=5"));
}

#[test]
fn test_workload_serde_roundtrip() {
    let w = make_workload(WorkloadArchetype::BranchHeavy, SynthesisStrategy::CoverageDirected, 3);
    let json = serde_json::to_string(&w).unwrap();
    let back: SyntheticWorkload = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// classify_severity
// ---------------------------------------------------------------------------

#[test]
fn test_classify_severity_critical() {
    assert_eq!(classify_severity(500_000), CounterexampleSeverity::Critical);
    assert_eq!(classify_severity(999_999), CounterexampleSeverity::Critical);
}

#[test]
fn test_classify_severity_major() {
    assert_eq!(classify_severity(200_000), CounterexampleSeverity::Major);
    assert_eq!(classify_severity(499_999), CounterexampleSeverity::Major);
}

#[test]
fn test_classify_severity_minor() {
    assert_eq!(classify_severity(50_000), CounterexampleSeverity::Minor);
    assert_eq!(classify_severity(199_999), CounterexampleSeverity::Minor);
}

#[test]
fn test_classify_severity_informational() {
    assert_eq!(classify_severity(0), CounterexampleSeverity::Informational);
    assert_eq!(classify_severity(49_999), CounterexampleSeverity::Informational);
}

// ---------------------------------------------------------------------------
// evaluate_counterexample
// ---------------------------------------------------------------------------

#[test]
fn test_counterexample_when_observed_exceeds_expected() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let result = evaluate_counterexample(&w, "claim-1", 100_000, 200_000);
    assert!(result.is_none());
}

#[test]
fn test_counterexample_when_observed_equals_expected() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let result = evaluate_counterexample(&w, "claim-1", 100_000, 100_000);
    assert!(result.is_none());
}

#[test]
fn test_counterexample_when_observed_below_expected() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let result = evaluate_counterexample(&w, "claim-1", 1_000_000, 400_000);
    assert!(result.is_some());
    let ce = result.unwrap();
    assert_eq!(ce.claim_id, "claim-1");
    assert_eq!(ce.severity, CounterexampleSeverity::Critical);
    assert_eq!(ce.expected_millionths, 1_000_000);
    assert_eq!(ce.observed_millionths, 400_000);
}

#[test]
fn test_counterexample_gap_fraction_computed() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    // gap = 1_000_000 - 800_000 = 200_000
    // gap_fraction = 200_000 * 1_000_000 / 1_000_000 = 200_000
    let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 800_000).unwrap();
    assert_eq!(ce.gap_fraction, 200_000);
    assert_eq!(ce.severity, CounterexampleSeverity::Major);
}

#[test]
fn test_counterexample_exceeds_threshold() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let ce = evaluate_counterexample(&w, "c", 1_000_000, 300_000).unwrap();
    assert!(ce.exceeds_threshold(CounterexampleSeverity::Critical));
    assert!(ce.exceeds_threshold(CounterexampleSeverity::Minor));
}

#[test]
fn test_counterexample_display() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let ce = evaluate_counterexample(&w, "claim-x", 1_000_000, 300_000).unwrap();
    let s = ce.to_string();
    assert!(s.contains("claim=claim-x"));
    assert!(s.contains("severity="));
}

// ---------------------------------------------------------------------------
// Counterexample serde
// ---------------------------------------------------------------------------

#[test]
fn test_counterexample_serde_roundtrip() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 400_000).unwrap();
    let json = serde_json::to_string(&ce).unwrap();
    let back: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, back);
}

// ---------------------------------------------------------------------------
// FalsificationResult
// ---------------------------------------------------------------------------

#[test]
fn test_falsification_result_no_counterexamples() {
    let result = FalsificationResult {
        claim_id: "c-1".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 100,
        coverage_fraction: 900_000,
        search_budget_used: 500_000,
        epoch: epoch(),
    };
    assert!(!result.has_critical());
    assert!(!result.has_major_or_worse());
    assert_eq!(result.count_at_severity(CounterexampleSeverity::Minor), 0);
    assert!(result.strongest_counterexample().is_none());
}

#[test]
fn test_falsification_result_with_critical() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let ce = evaluate_counterexample(&w, "c-1", 1_000_000, 300_000).unwrap();
    let result = FalsificationResult {
        claim_id: "c-1".into(),
        verdict: FalsificationVerdict::Falsified,
        counterexamples: vec![ce],
        workloads_tested: 50,
        coverage_fraction: 500_000,
        search_budget_used: 250_000,
        epoch: epoch(),
    };
    assert!(result.has_critical());
    assert!(result.has_major_or_worse());
    assert_eq!(result.count_at_severity(CounterexampleSeverity::Critical), 1);
    assert!(result.strongest_counterexample().is_some());
}

#[test]
fn test_falsification_result_display() {
    let result = FalsificationResult {
        claim_id: "c-2".into(),
        verdict: FalsificationVerdict::Weakened,
        counterexamples: vec![],
        workloads_tested: 200,
        coverage_fraction: 700_000,
        search_budget_used: 600_000,
        epoch: epoch(),
    };
    let s = result.to_string();
    assert!(s.contains("c-2"));
    assert!(s.contains("weakened"));
}

#[test]
fn test_falsification_result_serde_roundtrip() {
    let result = FalsificationResult {
        claim_id: "c-3".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 900_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FalsificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// MiningConfig
// ---------------------------------------------------------------------------

#[test]
fn test_mining_config_default() {
    let cfg = MiningConfig::default();
    assert_eq!(cfg.max_generations, DEFAULT_MAX_GENERATIONS);
    assert_eq!(cfg.workloads_per_generation, DEFAULT_WORKLOADS_PER_GENERATION);
    assert_eq!(cfg.mutation_rate, DEFAULT_MUTATION_RATE);
    assert_eq!(cfg.min_coverage_fraction, DEFAULT_MIN_COVERAGE);
    assert_eq!(cfg.severity_threshold, DEFAULT_SEVERITY_THRESHOLD);
    assert_eq!(cfg.max_search_budget, DEFAULT_MAX_SEARCH_BUDGET);
}

#[test]
fn test_mining_config_max_total_workloads() {
    let cfg = small_config();
    assert_eq!(cfg.max_total_workloads(), 12);
}

#[test]
fn test_mining_config_coverage_sufficient() {
    let cfg = small_config();
    assert!(cfg.coverage_sufficient(800_000));
    assert!(cfg.coverage_sufficient(900_000));
    assert!(!cfg.coverage_sufficient(799_999));
}

#[test]
fn test_mining_config_budget_exhausted() {
    let cfg = small_config();
    assert!(cfg.budget_exhausted(1_000_000));
    assert!(!cfg.budget_exhausted(999_999));
}

#[test]
fn test_mining_config_serde_roundtrip() {
    let cfg = small_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MiningConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// synthesize_batch
// ---------------------------------------------------------------------------

#[test]
fn test_synthesize_batch_produces_results() {
    let cfg = small_config();
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-batch-1",
        &cfg,
        epoch(),
    );
    assert_eq!(result.claim_id, "claim-batch-1");
    assert!(result.workloads_tested > 0);
}

#[test]
fn test_synthesize_batch_deterministic() {
    let cfg = small_config();
    let a = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-det",
        &cfg,
        epoch(),
    );
    let b = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "claim-det",
        &cfg,
        epoch(),
    );
    assert_eq!(a.workloads_tested, b.workloads_tested);
    assert_eq!(a.counterexamples.len(), b.counterexamples.len());
    assert_eq!(a.verdict, b.verdict);
}

#[test]
fn test_synthesize_batch_multiple_archetypes_strategies() {
    let cfg = MiningConfig {
        max_generations: 2,
        workloads_per_generation: 100,
        ..small_config()
    };
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound, WorkloadArchetype::IoBound],
        &[SynthesisStrategy::GradientGuided, SynthesisStrategy::RandomMutation],
        "claim-multi",
        &cfg,
        epoch(),
    );
    assert!(result.workloads_tested > 1);
}

#[test]
fn test_synthesize_batch_verdict_with_high_generation_pressure() {
    let cfg = MiningConfig {
        max_generations: 10,
        workloads_per_generation: 100,
        min_coverage_fraction: 0,
        severity_threshold: CounterexampleSeverity::Informational,
        ..MiningConfig::default()
    };
    let result = synthesize_batch(
        &[WorkloadArchetype::BranchHeavy],
        &[SynthesisStrategy::CoverageDirected],
        "claim-pressure",
        &cfg,
        epoch(),
    );
    // With high generation pressure, counterexamples should appear
    assert!(result.workloads_tested > 0);
}

// ---------------------------------------------------------------------------
// SynthesisReport / summarize
// ---------------------------------------------------------------------------

#[test]
fn test_summarize_empty() {
    let report = summarize(&[]);
    assert_eq!(report.total_workloads, 0);
    assert_eq!(report.total_counterexamples, 0);
    assert_eq!(report.total_claims(), 0);
    assert_eq!(report.falsification_rate(), 0);
    assert!(!report.has_compromised_claims());
    assert!(!report.all_survived());
}

#[test]
fn test_summarize_all_survived() {
    let r = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 100,
        coverage_fraction: 900_000,
        search_budget_used: 500_000,
        epoch: epoch(),
    };
    let report = summarize(&[r]);
    assert_eq!(report.survived_claims, 1);
    assert_eq!(report.falsified_claims, 0);
    assert!(report.all_survived());
    assert!(!report.has_compromised_claims());
    assert_eq!(report.strongest_counterexample, None);
}

#[test]
fn test_summarize_with_falsified() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    let ce = evaluate_counterexample(&w, "c", 1_000_000, 300_000).unwrap();
    let r = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Falsified,
        counterexamples: vec![ce],
        workloads_tested: 50,
        coverage_fraction: 500_000,
        search_budget_used: 250_000,
        epoch: epoch(),
    };
    let report = summarize(&[r]);
    assert_eq!(report.falsified_claims, 1);
    assert!(report.has_compromised_claims());
    assert!(!report.all_survived());
    assert!(report.strongest_counterexample.is_some());
    assert_eq!(report.falsification_rate(), 1_000_000);
}

#[test]
fn test_summarize_report_display() {
    let report = summarize(&[]);
    let s = report.to_string();
    assert!(s.contains("report:"));
    assert!(s.contains("workloads="));
}

#[test]
fn test_synthesis_report_receipt_hash_determinism() {
    let cfg = small_config();
    let result = synthesize_batch(
        &[WorkloadArchetype::CpuBound],
        &[SynthesisStrategy::GradientGuided],
        "det-hash",
        &cfg,
        epoch(),
    );
    let a = summarize(&[result.clone()]);
    let b = summarize(&[result]);
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_synthesis_report_serde_roundtrip() {
    let report = summarize(&[]);
    let json = serde_json::to_string(&report).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_from_result() {
    let result = FalsificationResult {
        claim_id: "c-1".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 100,
        coverage_fraction: 900_000,
        search_budget_used: 500_000,
        epoch: epoch(),
    };
    let receipt = DecisionReceipt::from_result(&result);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.verdict, FalsificationVerdict::Survived);
}

#[test]
fn test_decision_receipt_hash_deterministic() {
    let result = FalsificationResult {
        claim_id: "c-det".into(),
        verdict: FalsificationVerdict::Weakened,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 300_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let a = DecisionReceipt::from_result(&result);
    let b = DecisionReceipt::from_result(&result);
    assert_eq!(a.receipt_hash, b.receipt_hash);
    assert_eq!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_decision_receipt_different_verdicts_differ() {
    let r1 = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 900_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let r2 = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Falsified,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 900_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let a = DecisionReceipt::from_result(&r1);
    let b = DecisionReceipt::from_result(&r2);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_receipt_display() {
    let result = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 900_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let receipt = DecisionReceipt::from_result(&result);
    let s = receipt.to_string();
    assert!(s.contains("receipt["));
    assert!(s.contains("survived"));
    assert!(s.contains("epoch=500"));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let result = FalsificationResult {
        claim_id: "c".into(),
        verdict: FalsificationVerdict::Survived,
        counterexamples: vec![],
        workloads_tested: 10,
        coverage_fraction: 900_000,
        search_budget_used: 100_000,
        epoch: epoch(),
    };
    let receipt = DecisionReceipt::from_result(&result);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_zero_generation_workload() {
    let w = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        0,
        b"",
        epoch(),
    );
    assert_eq!(w.generation, 0);
    assert!(w.size_bytes >= 256);
}

#[test]
fn test_empty_seed_workload() {
    let w = generate_workload(
        WorkloadArchetype::CpuBound,
        SynthesisStrategy::GradientGuided,
        5,
        b"",
        epoch(),
    );
    assert!(!w.workload_id.is_empty());
}

#[test]
fn test_counterexample_zero_expected() {
    let w = make_workload(WorkloadArchetype::CpuBound, SynthesisStrategy::GradientGuided, 0);
    // expected=0, observed=0 => observed >= expected => None
    let result = evaluate_counterexample(&w, "c", 0, 0);
    assert!(result.is_none());
}

#[test]
fn test_config_max_total_workloads_overflow() {
    let cfg = MiningConfig {
        max_generations: u64::MAX,
        workloads_per_generation: u64::MAX,
        ..MiningConfig::default()
    };
    assert_eq!(cfg.max_total_workloads(), u64::MAX);
}
