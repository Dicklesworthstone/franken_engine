// Enrichment integration tests for adversarial_workload_synthesis module.
//
// Covers: domain × strategy matrix, engine lifecycle, error paths, campaign
// verdict transitions, report integrity, coverage fraction edge cases,
// multi-campaign aggregation, worst-regression tracking, serde round-trips.
//
// Bead: bd-1lsy.8.5.4 [RGC-705D]

use std::collections::BTreeSet;

use frankenengine_engine::adversarial_workload_synthesis::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_input(seed_id: &str, domain: WorkloadDomain) -> SynthesisInput {
    SynthesisInput::new(
        seed_id,
        domain,
        ContentHash::compute(seed_id.as_bytes()),
        100,
    )
}

fn add_all_domain_inputs(engine: &mut SynthesisEngine) {
    for domain in WorkloadDomain::ALL {
        engine
            .add_input(make_input(&format!("seed_{}", domain.as_str()), *domain))
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Domain enumeration completeness
// ---------------------------------------------------------------------------

#[test]
fn test_workload_domain_count_is_twelve() {
    assert_eq!(WorkloadDomain::count(), 12);
    assert_eq!(WorkloadDomain::ALL.len(), 12);
}

#[test]
fn test_workload_domain_all_unique() {
    let set: BTreeSet<WorkloadDomain> = WorkloadDomain::ALL.iter().copied().collect();
    assert_eq!(set.len(), 12);
}

#[test]
fn test_workload_domain_display_all_twelve() {
    let expected = [
        "branch_heavy",
        "vectorizable",
        "proof_specialized",
        "native_addon",
        "hostcall_boundary",
        "startup_image",
        "metadata_locality",
        "observability_sensitive",
        "resource_bounded",
        "string_regexp",
        "react_lifecycle",
        "async_iterator",
    ];
    for (domain, name) in WorkloadDomain::ALL.iter().zip(expected.iter()) {
        assert_eq!(domain.to_string(), *name);
        assert_eq!(domain.as_str(), *name);
    }
}

// ---------------------------------------------------------------------------
// Strategy enumeration completeness
// ---------------------------------------------------------------------------

#[test]
fn test_falsification_strategy_count_is_six() {
    assert_eq!(FalsificationStrategy::count(), 6);
    assert_eq!(FalsificationStrategy::ALL.len(), 6);
}

#[test]
fn test_falsification_strategy_all_unique() {
    let set: BTreeSet<FalsificationStrategy> = FalsificationStrategy::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn test_falsification_strategy_display_all_six() {
    let expected = [
        "random_mutation",
        "guided_gradient",
        "coverage_directed",
        "symbolic_execution",
        "property_fuzzing",
        "domain_specific",
    ];
    for (strategy, name) in FalsificationStrategy::ALL.iter().zip(expected.iter()) {
        assert_eq!(strategy.to_string(), *name);
        assert_eq!(strategy.as_str(), *name);
    }
}

// ---------------------------------------------------------------------------
// SynthesisVerdict semantics
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_only_fortified_survives() {
    assert!(SynthesisVerdict::Fortified.claim_survives());
    assert!(!SynthesisVerdict::Falsified.claim_survives());
    assert!(!SynthesisVerdict::Incomplete.claim_survives());
    assert!(!SynthesisVerdict::InfrastructureFailure.claim_survives());
}

#[test]
fn test_verdict_only_falsified_blocks() {
    assert!(!SynthesisVerdict::Fortified.claim_blocked());
    assert!(SynthesisVerdict::Falsified.claim_blocked());
    assert!(!SynthesisVerdict::Incomplete.claim_blocked());
    assert!(!SynthesisVerdict::InfrastructureFailure.claim_blocked());
}

#[test]
fn test_verdict_all_variants_count() {
    assert_eq!(SynthesisVerdict::ALL.len(), 4);
}

#[test]
fn test_verdict_display_all() {
    let expected = [
        "fortified",
        "falsified",
        "incomplete",
        "infrastructure_failure",
    ];
    for (v, name) in SynthesisVerdict::ALL.iter().zip(expected.iter()) {
        assert_eq!(v.to_string(), *name);
    }
}

// ---------------------------------------------------------------------------
// SynthesisInput construction and hashing
// ---------------------------------------------------------------------------

#[test]
fn test_input_hash_deterministic() {
    let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
    let b = make_input("seed_a", WorkloadDomain::BranchHeavy);
    assert_eq!(a.input_hash, b.input_hash);
}

#[test]
fn test_input_hash_differs_by_domain() {
    let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
    let b = make_input("seed_a", WorkloadDomain::Vectorizable);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn test_input_hash_differs_by_seed_id() {
    let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
    let b = make_input("seed_b", WorkloadDomain::BranchHeavy);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn test_input_display_contains_domain() {
    let input = make_input("test_seed", WorkloadDomain::ReactLifecycle);
    let display = format!("{input}");
    assert!(display.contains("react_lifecycle"));
    assert!(display.contains("test_seed"));
}

// ---------------------------------------------------------------------------
// Counterexample construction
// ---------------------------------------------------------------------------

#[test]
fn test_counterexample_hash_deterministic() {
    let seed_hash = ContentHash::compute(b"seed");
    let a = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        1_000_000,
    );
    let b = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        1_000_000,
    );
    assert_eq!(a.counterexample_hash, b.counterexample_hash);
}

#[test]
fn test_counterexample_hash_differs_by_strategy() {
    let seed_hash = ContentHash::compute(b"seed");
    let a = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        1_000_000,
    );
    let b = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::GuidedGradient,
        seed_hash,
        1_000_000,
    );
    assert_ne!(a.counterexample_hash, b.counterexample_hash);
}

#[test]
fn test_counterexample_exceeds_threshold() {
    let seed_hash = ContentHash::compute(b"seed");
    let cx = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        1_000_000,
    );
    assert!(cx.exceeds_threshold(50_000));
    assert!(cx.exceeds_threshold(100_000));
    assert!(!cx.exceeds_threshold(100_001));
}

// ---------------------------------------------------------------------------
// SynthesisConfig
// ---------------------------------------------------------------------------

#[test]
fn test_default_config_covers_all_domains() {
    let config = SynthesisConfig::default_config(epoch());
    assert!(config.covers_all_domains());
    assert_eq!(config.domain_count(), 12);
    assert_eq!(config.strategy_count(), 6);
}

#[test]
fn test_minimal_config_covers_single_domain() {
    let config = SynthesisConfig::minimal(epoch());
    assert!(!config.covers_all_domains());
    assert_eq!(config.domain_count(), 1);
    assert_eq!(config.strategy_count(), 1);
}

#[test]
fn test_config_hash_deterministic() {
    let a = SynthesisConfig::default_config(epoch());
    let b = SynthesisConfig::default_config(epoch());
    assert_eq!(a.compute_hash(), b.compute_hash());
}

#[test]
fn test_config_hash_differs_by_epoch() {
    let a = SynthesisConfig::default_config(SecurityEpoch::from_raw(1));
    let b = SynthesisConfig::default_config(SecurityEpoch::from_raw(2));
    assert_ne!(a.compute_hash(), b.compute_hash());
}

// ---------------------------------------------------------------------------
// DomainCoverage
// ---------------------------------------------------------------------------

#[test]
fn test_domain_coverage_starts_zero() {
    let cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    assert_eq!(cov.iterations, 0);
    assert_eq!(cov.counterexamples_found, 0);
    assert_eq!(cov.worst_regression_millionths, 0);
    assert_eq!(cov.seeds_used, 0);
}

#[test]
fn test_domain_coverage_record_no_counterexample() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    cov.record_iteration(None);
    assert_eq!(cov.iterations, 1);
    assert_eq!(cov.counterexamples_found, 0);
}

#[test]
fn test_domain_coverage_record_with_counterexample() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    let cx = Counterexample::new(
        75_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        ContentHash::compute(b"seed"),
        1_000,
    );
    cov.record_iteration(Some(&cx));
    assert_eq!(cov.iterations, 1);
    assert_eq!(cov.counterexamples_found, 1);
    assert_eq!(cov.worst_regression_millionths, 75_000);
}

#[test]
fn test_domain_coverage_worst_regression_tracks_max() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    let seed_hash = ContentHash::compute(b"seed");
    let cx1 = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        1_000,
    );
    let cx2 = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        2_000,
    );
    let cx3 = Counterexample::new(
        75_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        3_000,
    );
    cov.record_iteration(Some(&cx1));
    cov.record_iteration(Some(&cx2));
    cov.record_iteration(Some(&cx3));
    assert_eq!(cov.worst_regression_millionths, 100_000);
}

#[test]
fn test_domain_coverage_meets_threshold() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    assert!(!cov.meets_threshold(10));
    for _ in 0..10 {
        cov.record_iteration(None);
    }
    assert!(cov.meets_threshold(10));
}

#[test]
fn test_coverage_fraction_zero_threshold() {
    let cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    assert_eq!(cov.coverage_fraction_millionths(0), 1_000_000);
}

#[test]
fn test_coverage_fraction_caps_at_one() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    for _ in 0..200 {
        cov.record_iteration(None);
    }
    assert_eq!(cov.coverage_fraction_millionths(100), 1_000_000);
}

#[test]
fn test_coverage_fraction_partial() {
    let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    for _ in 0..50 {
        cov.record_iteration(None);
    }
    assert_eq!(cov.coverage_fraction_millionths(100), 500_000);
}

// ---------------------------------------------------------------------------
// SynthesisCampaign verdict transitions
// ---------------------------------------------------------------------------

#[test]
fn test_campaign_empty_incomplete() {
    let config = SynthesisConfig::default_config(epoch());
    let campaign = SynthesisCampaign::new("c1", config);
    assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
}

#[test]
fn test_campaign_infra_failure_overrides() {
    let config = SynthesisConfig::default_config(epoch());
    let mut campaign = SynthesisCampaign::new("c1", config);
    campaign.record_infra_failure("disk full");
    assert_eq!(campaign.verdict(), SynthesisVerdict::InfrastructureFailure);
}

#[test]
fn test_campaign_falsified_on_counterexample() {
    let config = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("c1", config);
    let cx = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        ContentHash::compute(b"seed"),
        1_000,
    );
    campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 500);
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
}

#[test]
fn test_campaign_uncovered_domains_empty_when_all_met() {
    let config = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("c1", config.clone());
    for _ in 0..config.min_iterations_per_domain {
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
    }
    assert!(campaign.uncovered_domains().is_empty());
}

#[test]
fn test_campaign_worst_regression_zero_without_counterexamples() {
    let config = SynthesisConfig::minimal(epoch());
    let campaign = SynthesisCampaign::new("c1", config);
    assert_eq!(campaign.worst_regression_millionths(), 0);
}

#[test]
fn test_campaign_budget_exhausted() {
    let mut config = SynthesisConfig::minimal(epoch());
    config.budget_ns = 1000;
    let mut campaign = SynthesisCampaign::new("c1", config);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 500);
    assert!(!campaign.budget_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 600);
    assert!(campaign.budget_exhausted());
}

#[test]
fn test_campaign_iterations_exhausted() {
    let mut config = SynthesisConfig::minimal(epoch());
    config.max_iterations = 3;
    let mut campaign = SynthesisCampaign::new("c1", config);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
    assert!(!campaign.iterations_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
    assert!(campaign.iterations_exhausted());
}

// ---------------------------------------------------------------------------
// SynthesisEngine error paths
// ---------------------------------------------------------------------------

#[test]
fn test_engine_no_inputs_error() {
    let engine = SynthesisEngine::new(epoch());
    let config = SynthesisConfig::minimal(epoch());
    let result = engine.validate_config(&config);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.tag(), "no_inputs");
}

#[test]
fn test_engine_empty_domains_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.domains.clear();
    let result = engine.validate_config(&config);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().tag(), "empty_domains");
}

#[test]
fn test_engine_empty_strategies_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.strategies.clear();
    let result = engine.validate_config(&config);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().tag(), "empty_strategies");
}

#[test]
fn test_engine_missing_domain_inputs_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let config = SynthesisConfig::default_config(epoch());
    let result = engine.validate_config(&config);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().tag(), "missing_domain_inputs");
}

#[test]
fn test_engine_duplicate_campaign_id_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let config = SynthesisConfig::minimal(epoch());
    engine
        .run_campaign("c1", config.clone(), |_, _, _| None)
        .unwrap();
    let result = engine.run_campaign("c1", config, |_, _, _| None);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().tag(), "duplicate_campaign_id");
}

#[test]
fn test_engine_no_campaigns_evaluate_error() {
    let engine = SynthesisEngine::new(epoch());
    let result = engine.evaluate("r1");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().tag(), "no_campaigns");
}

// ---------------------------------------------------------------------------
// SynthesisEngine lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_engine_add_input_increments_count() {
    let mut engine = SynthesisEngine::new(epoch());
    assert_eq!(engine.input_count(), 0);
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    assert_eq!(engine.input_count(), 1);
}

#[test]
fn test_engine_covered_input_domains() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    engine
        .add_input(make_input("s2", WorkloadDomain::Vectorizable))
        .unwrap();
    let covered = engine.covered_input_domains();
    assert_eq!(covered.len(), 2);
    assert!(covered.contains(&WorkloadDomain::BranchHeavy));
    assert!(covered.contains(&WorkloadDomain::Vectorizable));
}

#[test]
fn test_engine_run_campaign_no_counterexamples_fortified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    let campaign = engine.run_campaign("c1", config, |_, _, _| None).unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
}

#[test]
fn test_engine_run_campaign_with_counterexample_falsified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let config = SynthesisConfig::minimal(epoch());
    let campaign = engine
        .run_campaign("c1", config, |_, _, _| Some(100_000))
        .unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    assert!(campaign.counterexample_count() > 0);
}

#[test]
fn test_engine_campaign_count_increments() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let config = SynthesisConfig::minimal(epoch());
    assert_eq!(engine.campaign_count(), 0);
    engine
        .run_campaign("c1", config.clone(), |_, _, _| None)
        .unwrap();
    assert_eq!(engine.campaign_count(), 1);
    engine.run_campaign("c2", config, |_, _, _| None).unwrap();
    assert_eq!(engine.campaign_count(), 2);
}

// ---------------------------------------------------------------------------
// Full-domain campaign E2E
// ---------------------------------------------------------------------------

#[test]
fn test_full_domain_campaign_fortified() {
    let mut engine = SynthesisEngine::new(epoch());
    add_all_domain_inputs(&mut engine);
    let mut config = SynthesisConfig::default_config(epoch());
    config.min_iterations_per_domain = 1;
    config.max_iterations = 10_000;
    let campaign = engine.run_campaign("full", config, |_, _, _| None).unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
    assert!(campaign.all_domains_covered());
    assert!(campaign.uncovered_domains().is_empty());
}

#[test]
fn test_full_domain_campaign_falsified_single_domain() {
    let mut engine = SynthesisEngine::new(epoch());
    add_all_domain_inputs(&mut engine);
    let mut config = SynthesisConfig::default_config(epoch());
    config.min_iterations_per_domain = 1;
    config.max_iterations = 10_000;
    let campaign = engine
        .run_campaign("targeted", config, |_, domain, _| {
            if domain == WorkloadDomain::ReactLifecycle {
                Some(200_000)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    assert!(campaign.counterexample_count() > 0);
}

// ---------------------------------------------------------------------------
// Report evaluation and aggregation
// ---------------------------------------------------------------------------

#[test]
fn test_report_single_fortified_campaign() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    engine.run_campaign("c1", config, |_, _, _| None).unwrap();
    let report = engine.evaluate("r1").unwrap();
    assert_eq!(report.verdict, SynthesisVerdict::Fortified);
    assert!(report.claim_survives());
    assert!(!report.has_counterexamples());
    assert_eq!(report.total_counterexamples, 0);
    assert_eq!(report.worst_regression_millionths, 0);
}

#[test]
fn test_report_falsified_overrides_fortified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    engine
        .run_campaign("c1", config.clone(), |_, _, _| None)
        .unwrap();
    engine
        .run_campaign("c2", config, |_, _, _| Some(80_000))
        .unwrap();
    let report = engine.evaluate("r1").unwrap();
    assert_eq!(report.verdict, SynthesisVerdict::Falsified);
    assert!(!report.claim_survives());
    assert!(report.has_counterexamples());
}

#[test]
fn test_report_worst_regression_tracks_max_across_campaigns() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    // Campaign 1: mild regression
    engine
        .run_campaign("c1", config.clone(), |_, _, _| Some(60_000))
        .unwrap();
    // Campaign 2: worse regression
    engine
        .run_campaign("c2", config, |_, _, _| Some(150_000))
        .unwrap();
    let report = engine.evaluate("r1").unwrap();
    assert_eq!(report.worst_regression_millionths, 150_000);
}

#[test]
fn test_report_total_iterations() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    engine
        .run_campaign("c1", config.clone(), |_, _, _| None)
        .unwrap();
    engine.run_campaign("c2", config, |_, _, _| None).unwrap();
    let report = engine.evaluate("r1").unwrap();
    assert!(report.total_iterations() > 0);
}

#[test]
fn test_report_verify_integrity() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let mut config = SynthesisConfig::minimal(epoch());
    config.min_iterations_per_domain = 1;
    engine.run_campaign("c1", config, |_, _, _| None).unwrap();
    let report = engine.evaluate("r1").unwrap();
    assert!(report.verify_integrity());
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_workload_domain_serde_roundtrip() {
    for domain in WorkloadDomain::ALL {
        let json = serde_json::to_string(domain).unwrap();
        let back: WorkloadDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, back);
    }
}

#[test]
fn test_falsification_strategy_serde_roundtrip() {
    for strategy in FalsificationStrategy::ALL {
        let json = serde_json::to_string(strategy).unwrap();
        let back: FalsificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strategy, back);
    }
}

#[test]
fn test_synthesis_verdict_serde_roundtrip() {
    for v in SynthesisVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: SynthesisVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_synthesis_input_serde_roundtrip() {
    let input = make_input("serde_test", WorkloadDomain::AsyncIterator);
    let json = serde_json::to_string(&input).unwrap();
    let back: SynthesisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn test_counterexample_serde_roundtrip() {
    let cx = Counterexample::new(
        100_000,
        WorkloadDomain::StringRegexp,
        FalsificationStrategy::PropertyFuzzing,
        ContentHash::compute(b"seed"),
        5_000_000,
    );
    let json = serde_json::to_string(&cx).unwrap();
    let back: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx, back);
}

#[test]
fn test_synthesis_config_serde_roundtrip() {
    let config = SynthesisConfig::default_config(epoch());
    let json = serde_json::to_string(&config).unwrap();
    let back: SynthesisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// SynthesisError display and tags
// ---------------------------------------------------------------------------

#[test]
fn test_synthesis_error_tags_unique() {
    let errors = [
        SynthesisError::NoInputs,
        SynthesisError::TooManyInputs {
            count: 5000,
            max: 4096,
        },
        SynthesisError::TooManyCampaigns { count: 65, max: 64 },
        SynthesisError::DuplicateCampaignId {
            campaign_id: "c1".to_string(),
        },
        SynthesisError::NoCampaigns,
        SynthesisError::EmptyDomains,
        SynthesisError::EmptyStrategies,
        SynthesisError::MissingDomainInputs {
            domain: "branch_heavy".to_string(),
        },
    ];
    let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), errors.len());
}

#[test]
fn test_synthesis_error_display_contains_details() {
    let err = SynthesisError::TooManyInputs {
        count: 5000,
        max: 4096,
    };
    let display = format!("{err}");
    assert!(display.contains("5000"));
    assert!(display.contains("4096"));
}

#[test]
fn test_synthesis_error_display_duplicate_campaign() {
    let err = SynthesisError::DuplicateCampaignId {
        campaign_id: "my_campaign".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("my_campaign"));
}

// ---------------------------------------------------------------------------
// Campaign hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_campaign_hash_deterministic() {
    let config = SynthesisConfig::minimal(epoch());
    let c1 = SynthesisCampaign::new("c1", config.clone());
    let c2 = SynthesisCampaign::new("c1", config);
    assert_eq!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn test_campaign_hash_differs_by_id() {
    let config = SynthesisConfig::minimal(epoch());
    let c1 = SynthesisCampaign::new("c1", config.clone());
    let c2 = SynthesisCampaign::new("c2", config);
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

// ---------------------------------------------------------------------------
// Engine display
// ---------------------------------------------------------------------------

#[test]
fn test_engine_display_contains_counts() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
        .unwrap();
    let display = format!("{engine}");
    assert!(display.contains("inputs=1"));
    assert!(display.contains("campaigns=0"));
}
