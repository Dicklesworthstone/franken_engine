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

use frankenengine_engine::adversarial_workload_synthesis::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_input(seed_id: &str, domain: WorkloadDomain, complexity: u64) -> SynthesisInput {
    let ir_hash = ContentHash::compute(seed_id.as_bytes());
    SynthesisInput::new(seed_id, domain, ir_hash, complexity)
}

fn seed_engine_all_domains() -> SynthesisEngine {
    let mut engine = SynthesisEngine::new(epoch());
    for domain in WorkloadDomain::ALL {
        let id = format!("seed_{}", domain.as_str());
        engine.add_input(make_input(&id, *domain, 100)).unwrap();
    }
    engine
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_schema_version() {
    assert!(SCHEMA_VERSION.contains("adversarial-workload-synthesis"));
}

#[test]
fn constants_component() {
    assert_eq!(COMPONENT, "adversarial_workload_synthesis");
}

#[test]
fn constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.4");
}

#[test]
fn constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-705D");
}

#[test]
fn constants_default_min_iterations() {
    assert_eq!(DEFAULT_MIN_ITERATIONS_PER_DOMAIN, 100);
}

#[test]
fn constants_default_regression_threshold() {
    assert_eq!(DEFAULT_MIN_REGRESSION_THRESHOLD, 50_000);
}

#[test]
fn constants_default_budget_ns() {
    assert_eq!(DEFAULT_BUDGET_NS, 10_000_000_000);
}

#[test]
fn constants_max_counterexamples() {
    assert_eq!(MAX_COUNTEREXAMPLES_PER_CAMPAIGN, 1024);
}

// ---------------------------------------------------------------------------
// WorkloadDomain ordering and coverage
// ---------------------------------------------------------------------------

#[test]
fn workload_domain_all_count() {
    assert_eq!(WorkloadDomain::ALL.len(), 12);
    assert_eq!(WorkloadDomain::count(), 12);
}

#[test]
fn workload_domain_ordering() {
    let a = WorkloadDomain::BranchHeavy;
    let b = WorkloadDomain::AsyncIterator;
    assert!(a < b);
}

#[test]
fn workload_domain_as_str_roundtrip() {
    for domain in WorkloadDomain::ALL {
        let s = domain.as_str();
        assert!(!s.is_empty());
        assert_eq!(format!("{}", domain), s);
    }
}

// ---------------------------------------------------------------------------
// FalsificationStrategy
// ---------------------------------------------------------------------------

#[test]
fn falsification_strategy_all_count() {
    assert_eq!(FalsificationStrategy::ALL.len(), 6);
    assert_eq!(FalsificationStrategy::count(), 6);
}

#[test]
fn falsification_strategy_ordering() {
    let a = FalsificationStrategy::RandomMutation;
    let b = FalsificationStrategy::DomainSpecific;
    assert!(a < b);
}

#[test]
fn falsification_strategy_as_str() {
    assert_eq!(FalsificationStrategy::GuidedGradient.as_str(), "guided_gradient");
    assert_eq!(FalsificationStrategy::SymbolicExecution.as_str(), "symbolic_execution");
}

// ---------------------------------------------------------------------------
// SynthesisInput
// ---------------------------------------------------------------------------

#[test]
fn synthesis_input_hash_determinism() {
    let ir = ContentHash::compute(b"ir_payload");
    let a = SynthesisInput::new("seed_a", WorkloadDomain::BranchHeavy, ir.clone(), 50);
    let b = SynthesisInput::new("seed_a", WorkloadDomain::BranchHeavy, ir, 50);
    assert_eq!(a.input_hash, b.input_hash);
}

#[test]
fn synthesis_input_different_seeds_different_hash() {
    let ir = ContentHash::compute(b"ir");
    let a = SynthesisInput::new("s1", WorkloadDomain::BranchHeavy, ir.clone(), 50);
    let b = SynthesisInput::new("s2", WorkloadDomain::BranchHeavy, ir, 50);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn synthesis_input_display() {
    let input = make_input("test_seed", WorkloadDomain::Vectorizable, 42);
    let s = format!("{}", input);
    assert!(s.contains("test_seed"));
    assert!(s.contains("vectorizable"));
}

// ---------------------------------------------------------------------------
// Counterexample
// ---------------------------------------------------------------------------

#[test]
fn counterexample_construction() {
    let seed_hash = ContentHash::compute(b"seed");
    let cx = Counterexample::new(
        75_000,
        WorkloadDomain::StringRegexp,
        FalsificationStrategy::PropertyFuzzing,
        seed_hash,
        1_000_000,
    );
    assert_eq!(cx.regression_magnitude_millionths, 75_000);
    assert_eq!(cx.domain, WorkloadDomain::StringRegexp);
}

#[test]
fn counterexample_exceeds_threshold() {
    let seed_hash = ContentHash::compute(b"s");
    let cx = Counterexample::new(
        60_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed_hash,
        100,
    );
    assert!(cx.exceeds_threshold(50_000));
    assert!(!cx.exceeds_threshold(70_000));
}

#[test]
fn counterexample_hash_determinism() {
    let seed = ContentHash::compute(b"seed");
    let a = Counterexample::new(50_000, WorkloadDomain::Vectorizable, FalsificationStrategy::GuidedGradient, seed.clone(), 999);
    let b = Counterexample::new(50_000, WorkloadDomain::Vectorizable, FalsificationStrategy::GuidedGradient, seed, 999);
    assert_eq!(a.counterexample_hash, b.counterexample_hash);
}

// ---------------------------------------------------------------------------
// SynthesisConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_covers_all_domains() {
    let cfg = SynthesisConfig::default_config(epoch());
    assert!(cfg.covers_all_domains());
    assert_eq!(cfg.domain_count(), 12);
    assert_eq!(cfg.strategy_count(), 6);
}

#[test]
fn config_minimal_single_domain() {
    let cfg = SynthesisConfig::minimal(epoch());
    assert!(!cfg.covers_all_domains());
    assert_eq!(cfg.domain_count(), 1);
    assert_eq!(cfg.strategy_count(), 1);
}

#[test]
fn config_hash_determinism() {
    let a = SynthesisConfig::default_config(epoch());
    let b = SynthesisConfig::default_config(epoch());
    assert_eq!(a.compute_hash(), b.compute_hash());
}

#[test]
fn config_different_epochs_different_hash() {
    let a = SynthesisConfig::default_config(SecurityEpoch::from_raw(1));
    let b = SynthesisConfig::default_config(SecurityEpoch::from_raw(2));
    assert_ne!(a.compute_hash(), b.compute_hash());
}

// ---------------------------------------------------------------------------
// DomainCoverage
// ---------------------------------------------------------------------------

#[test]
fn domain_coverage_new_is_zero() {
    let dc = DomainCoverage::new(WorkloadDomain::ReactLifecycle);
    assert_eq!(dc.iterations, 0);
    assert_eq!(dc.counterexamples_found, 0);
    assert_eq!(dc.worst_regression_millionths, 0);
}

#[test]
fn domain_coverage_record_iteration_no_cx() {
    let mut dc = DomainCoverage::new(WorkloadDomain::NativeAddon);
    dc.record_iteration(None);
    assert_eq!(dc.iterations, 1);
    assert_eq!(dc.counterexamples_found, 0);
}

#[test]
fn domain_coverage_record_iteration_with_cx() {
    let mut dc = DomainCoverage::new(WorkloadDomain::NativeAddon);
    let seed = ContentHash::compute(b"s");
    let cx = Counterexample::new(80_000, WorkloadDomain::NativeAddon, FalsificationStrategy::RandomMutation, seed, 1);
    dc.record_iteration(Some(&cx));
    assert_eq!(dc.iterations, 1);
    assert_eq!(dc.counterexamples_found, 1);
    assert_eq!(dc.worst_regression_millionths, 80_000);
}

#[test]
fn domain_coverage_meets_threshold() {
    let mut dc = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    for _ in 0..10 {
        dc.record_iteration(None);
    }
    assert!(dc.meets_threshold(10));
    assert!(!dc.meets_threshold(11));
}

#[test]
fn domain_coverage_fraction_millionths() {
    let mut dc = DomainCoverage::new(WorkloadDomain::Vectorizable);
    for _ in 0..50 {
        dc.record_iteration(None);
    }
    let frac = dc.coverage_fraction_millionths(100);
    assert_eq!(frac, 500_000);
}

// ---------------------------------------------------------------------------
// SynthesisCampaign
// ---------------------------------------------------------------------------

#[test]
fn campaign_new_empty() {
    let cfg = SynthesisConfig::minimal(epoch());
    let campaign = SynthesisCampaign::new("camp_1", cfg);
    assert_eq!(campaign.iterations_completed, 0);
    assert_eq!(campaign.counterexample_count(), 0);
    assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
}

#[test]
fn campaign_record_iteration_increments() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("camp_2", cfg);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
    assert_eq!(campaign.iterations_completed, 1);
    assert_eq!(campaign.budget_spent_ns, 100);
}

#[test]
fn campaign_infra_failure_verdict() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("camp_3", cfg);
    campaign.record_infra_failure("disk full");
    assert_eq!(campaign.verdict(), SynthesisVerdict::InfrastructureFailure);
    assert!(campaign.infra_failure);
}

#[test]
fn campaign_falsified_verdict_on_counterexample() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("camp_4", cfg);
    let seed = ContentHash::compute(b"s");
    let cx = Counterexample::new(
        100_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
    campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 100);
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    assert_eq!(campaign.worst_regression_millionths(), 100_000);
}

#[test]
fn campaign_hash_determinism() {
    let cfg = SynthesisConfig::minimal(epoch());
    let a = SynthesisCampaign::new("camp_h", cfg.clone());
    let b = SynthesisCampaign::new("camp_h", cfg);
    assert_eq!(a.compute_hash(), b.compute_hash());
}

// ---------------------------------------------------------------------------
// SynthesisVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_all_count() {
    assert_eq!(SynthesisVerdict::ALL.len(), 4);
}

#[test]
fn verdict_ordering() {
    assert!(SynthesisVerdict::Fortified < SynthesisVerdict::Falsified);
    assert!(SynthesisVerdict::Falsified < SynthesisVerdict::Incomplete);
}

#[test]
fn verdict_claim_survives() {
    assert!(SynthesisVerdict::Fortified.claim_survives());
    assert!(!SynthesisVerdict::Falsified.claim_survives());
    assert!(!SynthesisVerdict::Incomplete.claim_survives());
    assert!(!SynthesisVerdict::InfrastructureFailure.claim_survives());
}

#[test]
fn verdict_claim_blocked() {
    assert!(SynthesisVerdict::Falsified.claim_blocked());
    assert!(!SynthesisVerdict::Fortified.claim_blocked());
}

#[test]
fn verdict_display() {
    assert_eq!(format!("{}", SynthesisVerdict::InfrastructureFailure), "infrastructure_failure");
}

// ---------------------------------------------------------------------------
// SynthesisEngine lifecycle
// ---------------------------------------------------------------------------

#[test]
fn engine_add_input() {
    let mut engine = SynthesisEngine::new(epoch());
    let input = make_input("s1", WorkloadDomain::BranchHeavy, 10);
    assert!(engine.add_input(input).is_ok());
    assert_eq!(engine.input_count(), 1);
}

#[test]
fn engine_covered_input_domains() {
    let mut engine = SynthesisEngine::new(epoch());
    engine.add_input(make_input("a", WorkloadDomain::BranchHeavy, 1)).unwrap();
    engine.add_input(make_input("b", WorkloadDomain::Vectorizable, 2)).unwrap();
    let covered = engine.covered_input_domains();
    assert!(covered.contains(&WorkloadDomain::BranchHeavy));
    assert!(covered.contains(&WorkloadDomain::Vectorizable));
    assert_eq!(covered.len(), 2);
}

#[test]
fn engine_validate_config_no_inputs() {
    let engine = SynthesisEngine::new(epoch());
    let cfg = SynthesisConfig::minimal(epoch());
    assert!(engine.validate_config(&cfg).is_err());
}

#[test]
fn engine_validate_config_missing_domain() {
    let mut engine = SynthesisEngine::new(epoch());
    engine.add_input(make_input("a", WorkloadDomain::Vectorizable, 1)).unwrap();
    let cfg = SynthesisConfig::minimal(epoch()); // requires BranchHeavy
    assert!(engine.validate_config(&cfg).is_err());
}

#[test]
fn engine_run_campaign_no_counterexamples() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    let campaign = engine.run_campaign("camp_fort", cfg, |_, _, _| None).unwrap();
    let v = campaign.verdict();
    // With 12 domains x 6 strategies x 1 seed = 72 iters; need 100/domain -> Incomplete
    assert!(v == SynthesisVerdict::Incomplete || v == SynthesisVerdict::Fortified);
}

#[test]
fn engine_run_campaign_falsified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine.add_input(make_input("s", WorkloadDomain::BranchHeavy, 10)).unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    let campaign = engine.run_campaign("camp_f", cfg, |_, _, _| Some(100_000)).unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    assert!(campaign.counterexample_count() > 0);
}

#[test]
fn engine_duplicate_campaign_id_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine.add_input(make_input("s", WorkloadDomain::BranchHeavy, 10)).unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    engine.run_campaign("dup", cfg.clone(), |_, _, _| None).unwrap();
    let result = engine.run_campaign("dup", cfg, |_, _, _| None);
    assert!(result.is_err());
}

#[test]
fn engine_evaluate_no_campaigns_error() {
    let engine = SynthesisEngine::new(epoch());
    assert!(engine.evaluate("report_1").is_err());
}

// ---------------------------------------------------------------------------
// SynthesisReport and E2E
// ---------------------------------------------------------------------------

#[test]
fn e2e_report_no_counterexamples() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("e2e_1", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("report_e2e_1").unwrap();
    assert_eq!(report.total_counterexamples, 0);
    assert!(!report.has_counterexamples());
}

#[test]
fn e2e_report_with_counterexamples() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("e2e_2", cfg, |_, d, _| {
        if d == WorkloadDomain::ReactLifecycle {
            Some(200_000)
        } else {
            None
        }
    }).unwrap();
    let report = engine.evaluate("report_e2e_2").unwrap();
    assert!(report.has_counterexamples());
    assert_eq!(report.verdict, SynthesisVerdict::Falsified);
    assert!(report.worst_regression_millionths >= 200_000);
}

#[test]
fn e2e_report_content_hash_determinism() {
    let mut engine_a = seed_engine_all_domains();
    let mut engine_b = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine_a.run_campaign("det", cfg.clone(), |_, _, _| None).unwrap();
    engine_b.run_campaign("det", cfg, |_, _, _| None).unwrap();
    let ra = engine_a.evaluate("rep_det").unwrap();
    let rb = engine_b.evaluate("rep_det").unwrap();
    assert_eq!(ra.content_hash, rb.content_hash);
}

#[test]
fn e2e_report_verify_integrity() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("vi", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_vi").unwrap();
    assert!(report.verify_integrity());
}

#[test]
fn e2e_report_total_iterations() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("ti", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_ti").unwrap();
    assert!(report.total_iterations() > 0);
}

// ---------------------------------------------------------------------------
// SynthesisError variants
// ---------------------------------------------------------------------------

#[test]
fn error_no_inputs_tag() {
    let e = SynthesisError::NoInputs;
    assert_eq!(e.tag(), "no_inputs");
    assert!(!format!("{}", e).is_empty());
}

#[test]
fn error_too_many_inputs_tag() {
    let e = SynthesisError::TooManyInputs { count: 5, max: 4 };
    assert_eq!(e.tag(), "too_many_inputs");
}

#[test]
fn error_empty_domains_tag() {
    let e = SynthesisError::EmptyDomains;
    assert_eq!(e.tag(), "empty_domains");
}

#[test]
fn error_missing_domain_inputs() {
    let e = SynthesisError::MissingDomainInputs { domain: "foo".into() };
    assert_eq!(e.tag(), "missing_domain_inputs");
    let s = format!("{}", e);
    assert!(s.contains("foo"));
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_workload_domain_roundtrip() {
    for domain in WorkloadDomain::ALL {
        let json = serde_json::to_string(domain).unwrap();
        let back: WorkloadDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, back);
    }
}

#[test]
fn serde_falsification_strategy_roundtrip() {
    for s in FalsificationStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: FalsificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn serde_verdict_roundtrip() {
    for v in SynthesisVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: SynthesisVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}
