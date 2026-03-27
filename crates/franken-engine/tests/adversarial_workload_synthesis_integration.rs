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
    assert_eq!(
        FalsificationStrategy::GuidedGradient.as_str(),
        "guided_gradient"
    );
    assert_eq!(
        FalsificationStrategy::SymbolicExecution.as_str(),
        "symbolic_execution"
    );
}

// ---------------------------------------------------------------------------
// SynthesisInput
// ---------------------------------------------------------------------------

#[test]
fn synthesis_input_hash_determinism() {
    let ir = ContentHash::compute(b"ir_payload");
    let a = SynthesisInput::new("seed_a", WorkloadDomain::BranchHeavy, ir, 50);
    let b = SynthesisInput::new("seed_a", WorkloadDomain::BranchHeavy, ir, 50);
    assert_eq!(a.input_hash, b.input_hash);
}

#[test]
fn synthesis_input_different_seeds_different_hash() {
    let ir = ContentHash::compute(b"ir");
    let a = SynthesisInput::new("s1", WorkloadDomain::BranchHeavy, ir, 50);
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
    let a = Counterexample::new(
        50_000,
        WorkloadDomain::Vectorizable,
        FalsificationStrategy::GuidedGradient,
        seed,
        999,
    );
    let b = Counterexample::new(
        50_000,
        WorkloadDomain::Vectorizable,
        FalsificationStrategy::GuidedGradient,
        seed,
        999,
    );
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
    let cx = Counterexample::new(
        80_000,
        WorkloadDomain::NativeAddon,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
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
    assert_eq!(
        format!("{}", SynthesisVerdict::InfrastructureFailure),
        "infrastructure_failure"
    );
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
    engine
        .add_input(make_input("a", WorkloadDomain::BranchHeavy, 1))
        .unwrap();
    engine
        .add_input(make_input("b", WorkloadDomain::Vectorizable, 2))
        .unwrap();
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
    engine
        .add_input(make_input("a", WorkloadDomain::Vectorizable, 1))
        .unwrap();
    let cfg = SynthesisConfig::minimal(epoch()); // requires BranchHeavy
    assert!(engine.validate_config(&cfg).is_err());
}

#[test]
fn engine_run_campaign_no_counterexamples() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    let campaign = engine
        .run_campaign("camp_fort", cfg, |_, _, _| None)
        .unwrap();
    let v = campaign.verdict();
    // With 12 domains x 6 strategies x 1 seed = 72 iters; need 100/domain -> Incomplete
    assert!(v == SynthesisVerdict::Incomplete || v == SynthesisVerdict::Fortified);
}

#[test]
fn engine_run_campaign_falsified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    let campaign = engine
        .run_campaign("camp_f", cfg, |_, _, _| Some(100_000))
        .unwrap();
    assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    assert!(campaign.counterexample_count() > 0);
}

#[test]
fn engine_duplicate_campaign_id_error() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    engine
        .run_campaign("dup", cfg.clone(), |_, _, _| None)
        .unwrap();
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
    engine
        .run_campaign("e2e_2", cfg, |_, d, _| {
            if d == WorkloadDomain::ReactLifecycle {
                Some(200_000)
            } else {
                None
            }
        })
        .unwrap();
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
    engine_a
        .run_campaign("det", cfg.clone(), |_, _, _| None)
        .unwrap();
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
    let e = SynthesisError::MissingDomainInputs {
        domain: "foo".into(),
    };
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

// ===========================================================================
// Enrichment: additional integration tests (50–70 new tests)
// ===========================================================================

// ---------------------------------------------------------------------------
// Constants (additional)
// ---------------------------------------------------------------------------

#[test]
fn constants_max_campaigns_per_engine() {
    assert_eq!(MAX_CAMPAIGNS_PER_ENGINE, 64);
}

#[test]
fn constants_max_inputs_per_engine() {
    assert_eq!(MAX_INPUTS_PER_ENGINE, 4096);
}

#[test]
fn constants_schema_version_starts_with_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// WorkloadDomain (additional)
// ---------------------------------------------------------------------------

#[test]
fn workload_domain_display_all_variants() {
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
    for (domain, exp) in WorkloadDomain::ALL.iter().zip(expected.iter()) {
        assert_eq!(format!("{}", domain), *exp);
    }
}

#[test]
fn workload_domain_as_str_all_unique() {
    let strs: std::collections::BTreeSet<&str> =
        WorkloadDomain::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(strs.len(), 12);
}

#[test]
fn workload_domain_serde_snake_case_format() {
    let json = serde_json::to_string(&WorkloadDomain::BranchHeavy).unwrap();
    assert_eq!(json, "\"branch_heavy\"");
    let json = serde_json::to_string(&WorkloadDomain::ProofSpecialized).unwrap();
    assert_eq!(json, "\"proof_specialized\"");
}

#[test]
fn workload_domain_count_matches_all_len() {
    assert_eq!(WorkloadDomain::count(), WorkloadDomain::ALL.len());
}

// ---------------------------------------------------------------------------
// FalsificationStrategy (additional)
// ---------------------------------------------------------------------------

#[test]
fn falsification_strategy_display_all_variants() {
    let expected = [
        "random_mutation",
        "guided_gradient",
        "coverage_directed",
        "symbolic_execution",
        "property_fuzzing",
        "domain_specific",
    ];
    for (strat, exp) in FalsificationStrategy::ALL.iter().zip(expected.iter()) {
        assert_eq!(format!("{}", strat), *exp);
    }
}

#[test]
fn falsification_strategy_as_str_all_unique() {
    let strs: std::collections::BTreeSet<&str> = FalsificationStrategy::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn falsification_strategy_serde_snake_case_format() {
    let json = serde_json::to_string(&FalsificationStrategy::CoverageDirected).unwrap();
    assert_eq!(json, "\"coverage_directed\"");
    let json = serde_json::to_string(&FalsificationStrategy::PropertyFuzzing).unwrap();
    assert_eq!(json, "\"property_fuzzing\"");
}

#[test]
fn falsification_strategy_count_matches_all_len() {
    assert_eq!(
        FalsificationStrategy::count(),
        FalsificationStrategy::ALL.len()
    );
}

// ---------------------------------------------------------------------------
// SynthesisInput (additional)
// ---------------------------------------------------------------------------

#[test]
fn synthesis_input_serde_roundtrip() {
    let input = make_input("serde_seed", WorkloadDomain::AsyncIterator, 77);
    let json = serde_json::to_string(&input).unwrap();
    let back: SynthesisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn synthesis_input_different_domain_different_hash() {
    let ir = ContentHash::compute(b"ir_same");
    let a = SynthesisInput::new("same_seed", WorkloadDomain::BranchHeavy, ir, 50);
    let b = SynthesisInput::new("same_seed", WorkloadDomain::Vectorizable, ir, 50);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn synthesis_input_different_complexity_different_hash() {
    let ir = ContentHash::compute(b"ir_same");
    let a = SynthesisInput::new("same_seed", WorkloadDomain::BranchHeavy, ir, 1);
    let b = SynthesisInput::new("same_seed", WorkloadDomain::BranchHeavy, ir, 999);
    assert_ne!(a.input_hash, b.input_hash);
}

#[test]
fn synthesis_input_display_contains_complexity() {
    let input = make_input("cx_seed", WorkloadDomain::ResourceBounded, 1234);
    let s = format!("{}", input);
    assert!(s.contains("1234"));
    assert!(s.contains("resource_bounded"));
}

#[test]
fn synthesis_input_fields_accessible() {
    let ir = ContentHash::compute(b"ir_check");
    let input = SynthesisInput::new("f_seed", WorkloadDomain::StartupImage, ir, 42);
    assert_eq!(input.seed_id, "f_seed");
    assert_eq!(input.domain, WorkloadDomain::StartupImage);
    assert_eq!(input.ir_hash, ir);
    assert_eq!(input.complexity_score, 42);
}

// ---------------------------------------------------------------------------
// Counterexample (additional)
// ---------------------------------------------------------------------------

#[test]
fn counterexample_serde_roundtrip() {
    let seed = ContentHash::compute(b"cx_serde");
    let cx = Counterexample::new(
        120_000,
        WorkloadDomain::MetadataLocality,
        FalsificationStrategy::CoverageDirected,
        seed,
        9999,
    );
    let json = serde_json::to_string(&cx).unwrap();
    let back: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx, back);
}

#[test]
fn counterexample_display_contains_strategy() {
    let seed = ContentHash::compute(b"disp");
    let cx = Counterexample::new(
        55_000,
        WorkloadDomain::HostcallBoundary,
        FalsificationStrategy::SymbolicExecution,
        seed,
        1,
    );
    let s = format!("{}", cx);
    assert!(s.contains("hostcall_boundary"));
    assert!(s.contains("symbolic_execution"));
    assert!(s.contains("55000"));
}

#[test]
fn counterexample_exceeds_threshold_exact_boundary() {
    let seed = ContentHash::compute(b"boundary");
    let cx = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
    assert!(cx.exceeds_threshold(50_000), "equal should exceed");
    assert!(!cx.exceeds_threshold(50_001), "above should not exceed");
}

#[test]
fn counterexample_exceeds_threshold_zero() {
    let seed = ContentHash::compute(b"zero_thresh");
    let cx = Counterexample::new(
        0,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
    assert!(cx.exceeds_threshold(0));
    assert!(!cx.exceeds_threshold(1));
}

#[test]
fn counterexample_different_strategy_different_hash() {
    let seed = ContentHash::compute(b"strat_diff");
    let a = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        100,
    );
    let b = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::GuidedGradient,
        seed,
        100,
    );
    assert_ne!(a.counterexample_hash, b.counterexample_hash);
}

#[test]
fn counterexample_different_timestamp_different_hash() {
    let seed = ContentHash::compute(b"ts_diff");
    let a = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        100,
    );
    let b = Counterexample::new(
        50_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        200,
    );
    assert_ne!(a.counterexample_hash, b.counterexample_hash);
}

// ---------------------------------------------------------------------------
// SynthesisConfig (additional)
// ---------------------------------------------------------------------------

#[test]
fn config_serde_roundtrip() {
    let cfg = SynthesisConfig::default_config(epoch());
    let json = serde_json::to_string(&cfg).unwrap();
    let back: SynthesisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_minimal_serde_roundtrip() {
    let cfg = SynthesisConfig::minimal(epoch());
    let json = serde_json::to_string(&cfg).unwrap();
    let back: SynthesisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_display_format() {
    let cfg = SynthesisConfig::default_config(epoch());
    let s = format!("{}", cfg);
    assert!(s.contains("domains=12"));
    assert!(s.contains("strategies=6"));
    assert!(s.contains("max_iter="));
    assert!(s.contains("budget_ns="));
}

#[test]
fn config_minimal_display() {
    let cfg = SynthesisConfig::minimal(epoch());
    let s = format!("{}", cfg);
    assert!(s.contains("domains=1"));
    assert!(s.contains("strategies=1"));
}

#[test]
fn config_hash_varies_with_domain_set() {
    let a = SynthesisConfig::default_config(epoch());
    let b = SynthesisConfig::minimal(epoch());
    assert_ne!(a.compute_hash(), b.compute_hash());
}

#[test]
fn config_default_values() {
    let cfg = SynthesisConfig::default_config(epoch());
    assert_eq!(cfg.max_iterations, 10_000);
    assert_eq!(
        cfg.min_regression_threshold_millionths,
        DEFAULT_MIN_REGRESSION_THRESHOLD
    );
    assert_eq!(cfg.budget_ns, DEFAULT_BUDGET_NS);
    assert_eq!(
        cfg.min_iterations_per_domain,
        DEFAULT_MIN_ITERATIONS_PER_DOMAIN
    );
}

#[test]
fn config_minimal_values() {
    let cfg = SynthesisConfig::minimal(epoch());
    assert_eq!(cfg.max_iterations, 100);
    assert_eq!(cfg.domain_count(), 1);
    assert_eq!(cfg.strategy_count(), 1);
    assert!(cfg.domains.contains(&WorkloadDomain::BranchHeavy));
    assert!(
        cfg.strategies
            .contains(&FalsificationStrategy::RandomMutation)
    );
}

// ---------------------------------------------------------------------------
// DomainCoverage (additional)
// ---------------------------------------------------------------------------

#[test]
fn domain_coverage_serde_roundtrip() {
    let mut dc = DomainCoverage::new(WorkloadDomain::ObservabilitySensitive);
    dc.record_iteration(None);
    dc.record_iteration(None);
    let json = serde_json::to_string(&dc).unwrap();
    let back: DomainCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

#[test]
fn domain_coverage_display_format() {
    let mut dc = DomainCoverage::new(WorkloadDomain::StringRegexp);
    dc.record_iteration(None);
    let s = format!("{}", dc);
    assert!(s.contains("string_regexp"));
    assert!(s.contains("iter=1"));
    assert!(s.contains("cx=0"));
}

#[test]
fn domain_coverage_fraction_zero_min_iterations() {
    let dc = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    let frac = dc.coverage_fraction_millionths(0);
    assert_eq!(frac, 1_000_000, "zero min_iterations returns MILLIONTHS");
}

#[test]
fn domain_coverage_fraction_caps_at_millionths() {
    let mut dc = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    for _ in 0..200 {
        dc.record_iteration(None);
    }
    let frac = dc.coverage_fraction_millionths(100);
    assert_eq!(frac, 1_000_000);
}

#[test]
fn domain_coverage_worst_regression_tracks_max() {
    let mut dc = DomainCoverage::new(WorkloadDomain::Vectorizable);
    let seed = ContentHash::compute(b"s");
    let cx1 = Counterexample::new(
        30_000,
        WorkloadDomain::Vectorizable,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
    let cx2 = Counterexample::new(
        90_000,
        WorkloadDomain::Vectorizable,
        FalsificationStrategy::RandomMutation,
        seed,
        2,
    );
    let cx3 = Counterexample::new(
        60_000,
        WorkloadDomain::Vectorizable,
        FalsificationStrategy::RandomMutation,
        seed,
        3,
    );
    dc.record_iteration(Some(&cx1));
    dc.record_iteration(Some(&cx2));
    dc.record_iteration(Some(&cx3));
    assert_eq!(dc.worst_regression_millionths, 90_000);
    assert_eq!(dc.counterexamples_found, 3);
}

#[test]
fn domain_coverage_meets_threshold_zero() {
    let dc = DomainCoverage::new(WorkloadDomain::BranchHeavy);
    assert!(dc.meets_threshold(0), "zero threshold always met");
}

#[test]
fn domain_coverage_seeds_used_field() {
    let dc = DomainCoverage::new(WorkloadDomain::ReactLifecycle);
    assert_eq!(dc.seeds_used, 0);
}

// ---------------------------------------------------------------------------
// SynthesisCampaign (additional)
// ---------------------------------------------------------------------------

#[test]
fn campaign_serde_roundtrip() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("serde_camp", cfg);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 500);
    let json = serde_json::to_string(&campaign).unwrap();
    let back: SynthesisCampaign = serde_json::from_str(&json).unwrap();
    assert_eq!(campaign, back);
}

#[test]
fn campaign_display_format() {
    let cfg = SynthesisConfig::minimal(epoch());
    let campaign = SynthesisCampaign::new("disp_camp", cfg);
    let s = format!("{}", campaign);
    assert!(s.contains("disp_camp"));
    assert!(s.contains("incomplete"));
    assert!(s.contains("iter=0"));
}

#[test]
fn campaign_uncovered_domains_all_initially() {
    let cfg = SynthesisConfig::default_config(epoch());
    let campaign = SynthesisCampaign::new("uncov", cfg);
    assert_eq!(campaign.uncovered_domains().len(), 12);
}

#[test]
fn campaign_uncovered_domains_shrinks_after_coverage() {
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    let mut campaign = SynthesisCampaign::new("uncov2", cfg);
    assert_eq!(campaign.uncovered_domains().len(), 1);
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 10);
    assert_eq!(campaign.uncovered_domains().len(), 0);
}

#[test]
fn campaign_budget_exhausted_tracking() {
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.budget_ns = 1000;
    let mut campaign = SynthesisCampaign::new("budget_test", cfg);
    assert!(!campaign.budget_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 500);
    assert!(!campaign.budget_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 600);
    assert!(campaign.budget_exhausted());
}

#[test]
fn campaign_iterations_exhausted_tracking() {
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.max_iterations = 2;
    let mut campaign = SynthesisCampaign::new("iter_test", cfg);
    assert!(!campaign.iterations_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
    assert!(!campaign.iterations_exhausted());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
    assert!(campaign.iterations_exhausted());
}

#[test]
fn campaign_all_domains_covered_single_domain() {
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 2;
    let mut campaign = SynthesisCampaign::new("all_cov", cfg);
    assert!(!campaign.all_domains_covered());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
    assert!(!campaign.all_domains_covered());
    campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
    assert!(campaign.all_domains_covered());
}

#[test]
fn campaign_worst_regression_no_counterexamples() {
    let cfg = SynthesisConfig::minimal(epoch());
    let campaign = SynthesisCampaign::new("no_cx", cfg);
    assert_eq!(campaign.worst_regression_millionths(), 0);
}

#[test]
fn campaign_infra_failure_detail_stored() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("infra_detail", cfg);
    campaign.record_infra_failure("OOM killed");
    assert!(campaign.infra_failure);
    assert_eq!(campaign.infra_failure_detail.as_deref(), Some("OOM killed"));
}

#[test]
fn campaign_verdict_infra_overrides_counterexamples() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("infra_vs_cx", cfg);
    let seed = ContentHash::compute(b"s");
    let cx = Counterexample::new(
        200_000,
        WorkloadDomain::BranchHeavy,
        FalsificationStrategy::RandomMutation,
        seed,
        1,
    );
    campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 10);
    campaign.record_infra_failure("timeout");
    // Infra failure takes priority over falsified in verdict.
    assert_eq!(campaign.verdict(), SynthesisVerdict::InfrastructureFailure);
}

#[test]
fn campaign_counterexample_count_matches_vec() {
    let cfg = SynthesisConfig::minimal(epoch());
    let mut campaign = SynthesisCampaign::new("cx_count", cfg);
    let seed = ContentHash::compute(b"s");
    for i in 0..5 {
        let cx = Counterexample::new(
            100_000 + i * 10_000,
            WorkloadDomain::BranchHeavy,
            FalsificationStrategy::RandomMutation,
            seed,
            i,
        );
        campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 10);
    }
    assert_eq!(campaign.counterexample_count(), 5);
    assert_eq!(campaign.counterexamples.len(), 5);
}

// ---------------------------------------------------------------------------
// SynthesisVerdict (additional)
// ---------------------------------------------------------------------------

#[test]
fn verdict_as_str_all_variants() {
    assert_eq!(SynthesisVerdict::Fortified.as_str(), "fortified");
    assert_eq!(SynthesisVerdict::Falsified.as_str(), "falsified");
    assert_eq!(SynthesisVerdict::Incomplete.as_str(), "incomplete");
    assert_eq!(
        SynthesisVerdict::InfrastructureFailure.as_str(),
        "infrastructure_failure"
    );
}

#[test]
fn verdict_claim_survives_only_fortified() {
    for v in SynthesisVerdict::ALL {
        if *v == SynthesisVerdict::Fortified {
            assert!(v.claim_survives());
        } else {
            assert!(!v.claim_survives());
        }
    }
}

#[test]
fn verdict_claim_blocked_only_falsified() {
    for v in SynthesisVerdict::ALL {
        if *v == SynthesisVerdict::Falsified {
            assert!(v.claim_blocked());
        } else {
            assert!(!v.claim_blocked());
        }
    }
}

#[test]
fn verdict_ordering_complete() {
    assert!(SynthesisVerdict::Fortified < SynthesisVerdict::Falsified);
    assert!(SynthesisVerdict::Falsified < SynthesisVerdict::Incomplete);
    assert!(SynthesisVerdict::Incomplete < SynthesisVerdict::InfrastructureFailure);
}

// ---------------------------------------------------------------------------
// SynthesisError (additional)
// ---------------------------------------------------------------------------

#[test]
fn error_too_many_campaigns_tag_and_display() {
    let e = SynthesisError::TooManyCampaigns { count: 65, max: 64 };
    assert_eq!(e.tag(), "too_many_campaigns");
    let s = format!("{}", e);
    assert!(s.contains("65"));
    assert!(s.contains("64"));
}

#[test]
fn error_duplicate_campaign_id_tag_and_display() {
    let e = SynthesisError::DuplicateCampaignId {
        campaign_id: "dup_camp".into(),
    };
    assert_eq!(e.tag(), "duplicate_campaign_id");
    let s = format!("{}", e);
    assert!(s.contains("dup_camp"));
}

#[test]
fn error_no_campaigns_tag_and_display() {
    let e = SynthesisError::NoCampaigns;
    assert_eq!(e.tag(), "no_campaigns");
    let s = format!("{}", e);
    assert!(!s.is_empty());
}

#[test]
fn error_empty_strategies_tag_and_display() {
    let e = SynthesisError::EmptyStrategies;
    assert_eq!(e.tag(), "empty_strategies");
    let s = format!("{}", e);
    assert!(!s.is_empty());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors: Vec<SynthesisError> = vec![
        SynthesisError::NoInputs,
        SynthesisError::TooManyInputs {
            count: 5000,
            max: 4096,
        },
        SynthesisError::TooManyCampaigns {
            count: 100,
            max: 64,
        },
        SynthesisError::DuplicateCampaignId {
            campaign_id: "dup".into(),
        },
        SynthesisError::NoCampaigns,
        SynthesisError::EmptyDomains,
        SynthesisError::EmptyStrategies,
        SynthesisError::MissingDomainInputs {
            domain: "branch_heavy".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn error_tags_all_unique() {
    let errors: Vec<SynthesisError> = vec![
        SynthesisError::NoInputs,
        SynthesisError::TooManyInputs { count: 1, max: 1 },
        SynthesisError::TooManyCampaigns { count: 1, max: 1 },
        SynthesisError::DuplicateCampaignId {
            campaign_id: "x".into(),
        },
        SynthesisError::NoCampaigns,
        SynthesisError::EmptyDomains,
        SynthesisError::EmptyStrategies,
        SynthesisError::MissingDomainInputs { domain: "x".into() },
    ];
    let tags: std::collections::BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), 8);
}

// ---------------------------------------------------------------------------
// SynthesisEngine (additional)
// ---------------------------------------------------------------------------

#[test]
fn engine_serde_roundtrip() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("sr_seed", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let json = serde_json::to_string(&engine).unwrap();
    let back: SynthesisEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, back);
}

#[test]
fn engine_campaign_count() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    assert_eq!(engine.campaign_count(), 0);
    let cfg = SynthesisConfig::minimal(epoch());
    engine.run_campaign("c1", cfg, |_, _, _| None).unwrap();
    assert_eq!(engine.campaign_count(), 1);
}

#[test]
fn engine_display_format() {
    let engine = SynthesisEngine::new(epoch());
    let s = format!("{}", engine);
    assert!(s.contains("SynthesisEngine"));
    assert!(s.contains("inputs=0"));
    assert!(s.contains("campaigns=0"));
    assert!(s.contains("epoch=42"));
}

#[test]
fn engine_validate_config_empty_domains() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.domains.clear();
    let err = engine.validate_config(&cfg).unwrap_err();
    assert_eq!(err.tag(), "empty_domains");
}

#[test]
fn engine_validate_config_empty_strategies() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.strategies.clear();
    let err = engine.validate_config(&cfg).unwrap_err();
    assert_eq!(err.tag(), "empty_strategies");
}

#[test]
fn engine_multiple_seeds_per_domain() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    engine
        .add_input(make_input("s2", WorkloadDomain::BranchHeavy, 20))
        .unwrap();
    assert_eq!(engine.input_count(), 2);
    let covered = engine.covered_input_domains();
    assert_eq!(covered.len(), 1);
    assert!(covered.contains(&WorkloadDomain::BranchHeavy));
}

#[test]
fn engine_run_campaign_multiple_seeds_more_iterations() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s1", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    engine
        .add_input(make_input("s2", WorkloadDomain::BranchHeavy, 20))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    let campaign = engine
        .run_campaign("multi_seed", cfg, |_, _, _| None)
        .unwrap();
    // 2 seeds x 1 strategy x 1 domain = 2 iterations
    assert_eq!(campaign.iterations_completed, 2);
}

#[test]
fn engine_run_campaign_below_threshold_not_counterexample() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_regression_threshold_millionths = 100_000;
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    let campaign = engine
        .run_campaign("below_thresh", cfg, |_, _, _| Some(50_000))
        .unwrap();
    assert_eq!(campaign.counterexample_count(), 0);
}

// ---------------------------------------------------------------------------
// SynthesisReport (additional)
// ---------------------------------------------------------------------------

#[test]
fn report_serde_roundtrip() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("rsr", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_serde").unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn report_display_format() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("rd", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_disp").unwrap();
    let s = format!("{}", report);
    assert!(s.contains("rep_disp"));
    assert!(s.contains("campaigns=1"));
}

#[test]
fn report_schema_version_set() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine.run_campaign("rsv", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_sv").unwrap();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_claim_survives_fortified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    engine.run_campaign("fort", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_fort").unwrap();
    assert!(report.claim_survives());
}

#[test]
fn report_claim_does_not_survive_falsified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    engine
        .run_campaign("fals", cfg, |_, _, _| Some(200_000))
        .unwrap();
    let report = engine.evaluate("rep_fals").unwrap();
    assert!(!report.claim_survives());
    assert!(report.has_counterexamples());
}

// ---------------------------------------------------------------------------
// E2E aggregation scenarios
// ---------------------------------------------------------------------------

#[test]
fn e2e_infra_failure_overrides_incomplete() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    // Run a normal campaign (will be Incomplete due to iteration threshold).
    engine
        .run_campaign("inc", cfg.clone(), |_, _, _| None)
        .unwrap();
    // Manually add an infra-failed campaign.
    let mut failed = SynthesisCampaign::new("infra", cfg);
    failed.record_infra_failure("network error");
    engine.campaigns.push(failed);
    let report = engine.evaluate("rep_infra").unwrap();
    assert_eq!(report.verdict, SynthesisVerdict::InfrastructureFailure);
}

#[test]
fn e2e_falsified_overrides_infra_and_fortified() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;

    // Fortified campaign.
    engine
        .run_campaign("fort", cfg.clone(), |_, _, _| None)
        .unwrap();

    // Infra failure campaign.
    let mut infra = SynthesisCampaign::new("infra", cfg.clone());
    infra.record_infra_failure("disk");
    engine.campaigns.push(infra);

    // Falsified campaign.
    engine
        .run_campaign("fals", cfg, |_, _, _| Some(150_000))
        .unwrap();

    let report = engine.evaluate("rep_all").unwrap();
    assert_eq!(report.verdict, SynthesisVerdict::Falsified);
}

#[test]
fn e2e_multiple_campaigns_total_iterations() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    engine
        .run_campaign("c1", cfg.clone(), |_, _, _| None)
        .unwrap();
    engine.run_campaign("c2", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_mi").unwrap();
    assert_eq!(report.total_iterations(), 2);
    assert_eq!(report.all_campaigns.len(), 2);
}

#[test]
fn e2e_domain_coverage_aggregated_across_campaigns() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    engine
        .run_campaign("a1", cfg.clone(), |_, _, _| None)
        .unwrap();
    engine.run_campaign("a2", cfg, |_, _, _| None).unwrap();
    let report = engine.evaluate("rep_agg").unwrap();
    let cov = report.domain_coverage.get("branch_heavy").unwrap();
    assert_eq!(cov.iterations, 2);
}

#[test]
fn e2e_worst_regression_across_campaigns() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let mut cfg = SynthesisConfig::minimal(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 100;
    engine
        .run_campaign("w1", cfg.clone(), |_, _, _| Some(60_000))
        .unwrap();
    engine
        .run_campaign("w2", cfg, |_, _, _| Some(300_000))
        .unwrap();
    let report = engine.evaluate("rep_worst").unwrap();
    assert_eq!(report.worst_regression_millionths, 300_000);
}

#[test]
fn e2e_report_verify_integrity_after_falsification() {
    let mut engine = seed_engine_all_domains();
    let cfg = SynthesisConfig::default_config(epoch());
    engine
        .run_campaign("vi_fals", cfg, |_, d, _| {
            if d == WorkloadDomain::StringRegexp {
                Some(100_000)
            } else {
                None
            }
        })
        .unwrap();
    let report = engine.evaluate("rep_vi_fals").unwrap();
    assert!(report.verify_integrity());
    assert_eq!(report.verdict, SynthesisVerdict::Falsified);
}

#[test]
fn e2e_engine_with_all_domains_and_strategies() {
    let mut engine = seed_engine_all_domains();
    let mut cfg = SynthesisConfig::default_config(epoch());
    cfg.min_iterations_per_domain = 1;
    cfg.max_iterations = 10_000;
    let campaign = engine
        .run_campaign("full_run", cfg, |_, _, _| None)
        .unwrap();
    // 12 domains x 6 strategies x 1 seed each = 72 iterations
    assert_eq!(campaign.iterations_completed, 72);
    assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
}

#[test]
fn e2e_fortified_verdict_requires_all_domains_covered() {
    let mut engine = seed_engine_all_domains();
    // Add many extra seeds per domain so we exceed min_iterations_per_domain
    for domain in WorkloadDomain::ALL {
        for i in 0..20 {
            let id = format!("extra_{}_{}", domain.as_str(), i);
            engine.add_input(make_input(&id, *domain, 10 + i)).unwrap();
        }
    }
    let mut cfg = SynthesisConfig::default_config(epoch());
    cfg.min_iterations_per_domain = 100;
    cfg.max_iterations = 100_000;
    let campaign = engine
        .run_campaign("fort_all", cfg, |_, _, _| None)
        .unwrap();
    // 12 domains x 6 strategies x 21 seeds = 1512 iterations
    // 1512 / 12 = 126 per domain => >= 100 threshold
    assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
}

#[test]
fn e2e_engine_serde_roundtrip_with_campaigns() {
    let mut engine = SynthesisEngine::new(epoch());
    engine
        .add_input(make_input("s", WorkloadDomain::BranchHeavy, 10))
        .unwrap();
    let cfg = SynthesisConfig::minimal(epoch());
    engine.run_campaign("c", cfg, |_, _, _| None).unwrap();
    let json = serde_json::to_string(&engine).unwrap();
    let back: SynthesisEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, back);
    assert_eq!(back.campaign_count(), 1);
}
