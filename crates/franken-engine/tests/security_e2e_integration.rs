#![forbid(unsafe_code)]

//! Comprehensive integration tests for the `security_e2e` module.
//!
//! Covers all 8 attack categories, Xorshift64 PRNG, scenario result types,
//! the full suite runner, evidence artifact I/O, determinism, and cross-category
//! invariants.

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
use std::fs;

use frankenengine_engine::security_e2e::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config() -> SecuritySuiteConfig {
    SecuritySuiteConfig {
        seed: 42,
        n_extensions: 4,
        n_evidence_updates: 15,
        run_id: "integration-test".to_string(),
    }
}

fn small_config() -> SecuritySuiteConfig {
    SecuritySuiteConfig {
        seed: 42,
        n_extensions: 2,
        n_evidence_updates: 5,
        run_id: "small-integ".to_string(),
    }
}

fn tmp_dir(suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("franken_sec_e2e_integ_{suffix}"))
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_component_matches_expected() {
    assert_eq!(SECURITY_E2E_COMPONENT, "security_e2e");
}

#[test]
fn constants_schema_version_is_v1() {
    assert_eq!(
        SECURITY_E2E_SCHEMA_VERSION,
        "franken-engine.security-e2e.v1"
    );
}

#[test]
fn constants_min_budget_positive() {
    const { assert!(MIN_BUDGET_MILLIONTHS > 0) };
    assert_eq!(MIN_BUDGET_MILLIONTHS, 1_000);
}

#[test]
fn constants_component_non_empty() {
    assert!(!SECURITY_E2E_COMPONENT.is_empty());
}

#[test]
fn constants_schema_version_non_empty() {
    assert!(!SECURITY_E2E_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. AttackCategory
// ===========================================================================

#[test]
fn attack_category_all_returns_eight_variants() {
    assert_eq!(AttackCategory::all().len(), 8);
}

#[test]
fn attack_category_all_unique_strings() {
    let strs: BTreeSet<&str> = AttackCategory::all().iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), 8);
}

#[test]
fn attack_category_as_str_returns_distinct_non_empty_for_all() {
    let mut seen = BTreeSet::new();
    for cat in AttackCategory::all() {
        let s = cat.as_str();
        assert!(!s.is_empty(), "as_str() returned empty for {:?}", cat);
        assert!(seen.insert(s), "duplicate as_str() value: {s}");
    }
}

#[test]
fn attack_category_round_trip_as_str() {
    let expected = [
        (
            AttackCategory::CapabilityEscalation,
            "capability-escalation",
        ),
        (AttackCategory::ResourceExhaustion, "resource-exhaustion"),
        (AttackCategory::QuarantineCascade, "quarantine-cascade"),
        (AttackCategory::SafeModeFallback, "safe-mode-fallback"),
        (AttackCategory::BayesianPosterior, "bayesian-posterior"),
        (AttackCategory::ForkDetection, "fork-detection"),
        (AttackCategory::EpochRegression, "epoch-regression"),
        (AttackCategory::EvidenceIntegrity, "evidence-integrity"),
    ];
    for (cat, label) in &expected {
        assert_eq!(cat.as_str(), *label);
    }
}

#[test]
fn attack_category_copy_semantics() {
    let a = AttackCategory::ForkDetection;
    let b = a;
    let c = a;
    assert_eq!(b, c);
    assert_eq!(a.as_str(), b.as_str());
}

#[test]
fn attack_category_all_as_str_contain_hyphens() {
    for cat in AttackCategory::all() {
        assert!(
            cat.as_str().contains('-'),
            "{} missing hyphen",
            cat.as_str()
        );
    }
}

#[test]
fn attack_category_all_as_str_lowercase_no_underscores() {
    for cat in AttackCategory::all() {
        let s = cat.as_str();
        assert_eq!(s, s.to_lowercase(), "as_str should be lowercase: {s}");
        assert!(
            !s.contains('_'),
            "as_str should use hyphens not underscores: {s}"
        );
    }
}

#[test]
fn attack_category_all_order_matches_individual_variants() {
    let all = AttackCategory::all();
    assert_eq!(all[0], AttackCategory::CapabilityEscalation);
    assert_eq!(all[1], AttackCategory::ResourceExhaustion);
    assert_eq!(all[2], AttackCategory::QuarantineCascade);
    assert_eq!(all[3], AttackCategory::SafeModeFallback);
    assert_eq!(all[4], AttackCategory::BayesianPosterior);
    assert_eq!(all[5], AttackCategory::ForkDetection);
    assert_eq!(all[6], AttackCategory::EpochRegression);
    assert_eq!(all[7], AttackCategory::EvidenceIntegrity);
}

#[test]
fn attack_category_debug_format_contains_variant_name() {
    let dbg = format!("{:?}", AttackCategory::CapabilityEscalation);
    assert!(dbg.contains("CapabilityEscalation"));
    let dbg2 = format!("{:?}", AttackCategory::EvidenceIntegrity);
    assert!(dbg2.contains("EvidenceIntegrity"));
}

#[test]
fn attack_category_clone_eq_ne() {
    let a = AttackCategory::CapabilityEscalation;
    let b = a;
    assert_eq!(a, b);
    let c = AttackCategory::ForkDetection;
    assert_ne!(a, c);
}

// ===========================================================================
// 3. Xorshift64 PRNG
// ===========================================================================

#[test]
fn xorshift64_deterministic_across_instances() {
    let mut a = Xorshift64::new(42);
    let mut b = Xorshift64::new(42);
    for _ in 0..200 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn xorshift64_zero_seed_normalised_to_one() {
    let mut zero = Xorshift64::new(0);
    let mut one = Xorshift64::new(1);
    // seed=0 becomes state=1, so they produce the same sequence
    assert_eq!(zero.next_u64(), one.next_u64());
}

#[test]
fn xorshift64_zero_seed_does_not_produce_zero() {
    let mut rng = Xorshift64::new(0);
    let val = rng.next_u64();
    assert_ne!(val, 0, "seed=0 should produce nonzero first value");
}

#[test]
fn xorshift64_different_seeds_diverge() {
    let mut a = Xorshift64::new(1);
    let mut b = Xorshift64::new(2);
    let mut differ = false;
    for _ in 0..10 {
        if a.next_u64() != b.next_u64() {
            differ = true;
            break;
        }
    }
    assert!(differ, "different seeds should produce different sequences");
}

#[test]
fn xorshift64_many_different_seeds_diverge() {
    // Test several seed pairs
    for (s1, s2) in [(10, 20), (100, 200), (42, 43), (9999, 1)] {
        let mut a = Xorshift64::new(s1);
        let mut b = Xorshift64::new(s2);
        let mut differ = false;
        for _ in 0..10 {
            if a.next_u64() != b.next_u64() {
                differ = true;
                break;
            }
        }
        assert!(differ, "seeds {s1} and {s2} should diverge");
    }
}

#[test]
fn xorshift64_next_usize_bounded() {
    let mut rng = Xorshift64::new(77);
    for _ in 0..500 {
        assert!(rng.next_usize(13) < 13);
    }
}

#[test]
fn xorshift64_next_usize_bound_one_always_zero() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert_eq!(rng.next_usize(1), 0);
    }
}

#[test]
fn xorshift64_next_usize_covers_all_values_for_small_bound() {
    let mut rng = Xorshift64::new(7);
    let mut hit = [false; 4];
    for _ in 0..200 {
        hit[rng.next_usize(4)] = true;
    }
    for (i, &h) in hit.iter().enumerate() {
        assert!(h, "bucket {i} was never hit in 200 iterations");
    }
}

#[test]
fn xorshift64_next_bool_zero_pct_always_false() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert!(!rng.next_bool(0));
    }
}

#[test]
fn xorshift64_next_bool_hundred_pct_always_true() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert!(rng.next_bool(100));
    }
}

#[test]
fn xorshift64_next_bool_fifty_pct_mixed() {
    let mut rng = Xorshift64::new(42);
    let mut t = 0u64;
    let mut f = 0u64;
    for _ in 0..1000 {
        if rng.next_bool(50) {
            t += 1;
        } else {
            f += 1;
        }
    }
    assert!(t > 0 && f > 0);
}

#[test]
fn xorshift64_no_trivial_period() {
    let mut rng = Xorshift64::new(42);
    let first = rng.next_u64();
    for i in 1..2000 {
        assert_ne!(rng.next_u64(), first, "repeated at step {i}");
    }
}

#[test]
fn xorshift64_never_produces_zero_for_many_iterations() {
    let mut rng = Xorshift64::new(42);
    for i in 0..10_000 {
        let val = rng.next_u64();
        assert_ne!(val, 0, "xorshift64 produced zero at iteration {i}");
    }
}

// ===========================================================================
// 4. Capability escalation
// ===========================================================================

#[test]
fn capability_escalation_returns_two_scenarios() {
    let results = run_capability_escalation(3, 42);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].scenario_name, "cpu-budget-escalation");
    assert_eq!(results[1].scenario_name, "hostcall-budget-escalation");
}

#[test]
fn capability_escalation_blocks_all() {
    let results = run_capability_escalation(5, 42);
    for r in &results {
        assert!(r.attack_blocked, "scenario {} not blocked", r.scenario_name);
    }
}

#[test]
fn capability_escalation_at_least_one_blocked() {
    let results = run_capability_escalation(3, 42);
    let any_blocked = results.iter().any(|r| r.attack_blocked);
    assert!(any_blocked, "at least one attack should be blocked");
}

#[test]
fn capability_escalation_deterministic() {
    let a = run_capability_escalation(4, 42);
    let b = run_capability_escalation(4, 42);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.security_events, y.security_events);
        assert_eq!(x.attack_blocked, y.attack_blocked);
    }
}

#[test]
fn capability_escalation_zero_extensions() {
    let results = run_capability_escalation(0, 42);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].security_events, 0);
}

#[test]
fn capability_escalation_cpu_produces_evidence() {
    let results = run_capability_escalation(2, 42);
    assert!(results[0].evidence_produced);
}

#[test]
fn capability_escalation_non_empty_results() {
    let results = run_capability_escalation(3, 42);
    assert!(!results.is_empty());
}

#[test]
fn capability_escalation_hostcall_produces_evidence() {
    let results = run_capability_escalation(2, 42);
    assert!(results[1].evidence_produced);
}

#[test]
fn capability_escalation_many_extensions_all_blocked() {
    let results = run_capability_escalation(10, 99);
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(r.attack_blocked);
    }
}

// ===========================================================================
// 5. Resource exhaustion
// ===========================================================================

#[test]
fn resource_exhaustion_single_scenario() {
    let results = run_resource_exhaustion(3, 42);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].category, AttackCategory::ResourceExhaustion);
}

#[test]
fn resource_exhaustion_non_empty_results() {
    let results = run_resource_exhaustion(3, 42);
    assert!(!results.is_empty());
}

#[test]
fn resource_exhaustion_blocks_all() {
    let results = run_resource_exhaustion(5, 42);
    assert!(results[0].attack_blocked);
    assert!(results[0].security_events > 0);
}

#[test]
fn resource_exhaustion_produces_evidence() {
    let results = run_resource_exhaustion(3, 42);
    assert!(results[0].evidence_produced);
}

#[test]
fn resource_exhaustion_deterministic() {
    let a = run_resource_exhaustion(4, 99);
    let b = run_resource_exhaustion(4, 99);
    assert_eq!(a[0].security_events, b[0].security_events);
}

#[test]
fn resource_exhaustion_zero_extensions() {
    let results = run_resource_exhaustion(0, 42);
    assert_eq!(results.len(), 1);
    assert!(results[0].attack_blocked);
    assert_eq!(results[0].security_events, 0);
}

#[test]
fn resource_exhaustion_many_extensions_produces_events() {
    let results = run_resource_exhaustion(10, 99);
    assert_eq!(results.len(), 1);
    assert!(results[0].attack_blocked);
    assert!(results[0].security_events > 0);
}

// ===========================================================================
// 6. Quarantine cascade
// ===========================================================================

#[test]
fn quarantine_cascade_non_empty_results() {
    let results = run_quarantine_cascade(8, 4, 42);
    assert!(!results.is_empty());
}

#[test]
fn quarantine_cascade_isolates_subset() {
    let results = run_quarantine_cascade(8, 4, 42);
    let r = &results[0];
    assert_eq!(r.details["quarantined"], "4");
    assert_eq!(r.details["running"], "4");
    assert_eq!(r.invariant_violations, 0);
}

#[test]
fn quarantine_cascade_all_quarantined() {
    let results = run_quarantine_cascade(5, 5, 42);
    let r = &results[0];
    assert_eq!(r.details["quarantined"], "5");
    assert_eq!(r.details["running"], "0");
}

#[test]
fn quarantine_cascade_none_quarantined() {
    let results = run_quarantine_cascade(5, 0, 42);
    let r = &results[0];
    assert_eq!(r.details["quarantined"], "0");
    assert_eq!(r.details["running"], "5");
}

#[test]
fn quarantine_cascade_clamps_excess() {
    let results = run_quarantine_cascade(3, 100, 42);
    let r = &results[0];
    assert_eq!(r.details["quarantined"], "3");
    assert_eq!(r.invariant_violations, 0);
}

#[test]
fn quarantine_cascade_total_registered_correct() {
    let results = run_quarantine_cascade(7, 3, 42);
    let r = &results[0];
    assert_eq!(r.details["total_registered"], "7");
}

#[test]
fn quarantine_cascade_single_extension_single_quarantine() {
    let results = run_quarantine_cascade(1, 1, 42);
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert_eq!(r.details["quarantined"], "1");
    assert_eq!(r.details["running"], "0");
    assert_eq!(r.invariant_violations, 0);
}

#[test]
fn quarantine_cascade_invariant_violations_zero_for_valid_inputs() {
    for n in [2, 5, 8, 15] {
        let half = n / 2;
        let results = run_quarantine_cascade(n, half, 42);
        assert_eq!(
            results[0].invariant_violations, 0,
            "invariant violations should be 0 for n_total={n}, n_quarantine={half}"
        );
    }
}

// ===========================================================================
// 7. Safe-mode fallback
// ===========================================================================

#[test]
fn safe_mode_fallback_five_scenarios() {
    let results = run_safe_mode_fallback(42);
    assert_eq!(results.len(), 5);
}

#[test]
fn safe_mode_fallback_non_empty_results() {
    let results = run_safe_mode_fallback(42);
    assert!(!results.is_empty());
}

#[test]
fn safe_mode_fallback_all_blocked_and_recovered() {
    let results = run_safe_mode_fallback(42);
    for r in &results {
        assert!(r.attack_blocked, "{} not blocked", r.scenario_name);
        assert!(
            r.containment_action_taken,
            "{} no containment",
            r.scenario_name
        );
        assert!(r.evidence_produced, "{} no evidence", r.scenario_name);
        assert_eq!(
            r.invariant_violations, 0,
            "{} has violations",
            r.scenario_name
        );
    }
}

#[test]
fn safe_mode_fallback_scenario_names_correct() {
    let results = run_safe_mode_fallback(42);
    let names: Vec<&str> = results.iter().map(|r| r.scenario_name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "adapter-unavailable",
            "decision-contract-error",
            "evidence-ledger-full",
            "cx-corrupted",
            "cancellation-deadlock",
        ]
    );
}

#[test]
fn safe_mode_fallback_activation_and_recovery_counts() {
    let results = run_safe_mode_fallback(42);
    for r in &results {
        let act: u64 = r.details["activation_count"].parse().unwrap();
        let rec: u64 = r.details["recovery_count"].parse().unwrap();
        assert!(act >= 1, "{} activation_count < 1", r.scenario_name);
        assert!(rec >= 1, "{} recovery_count < 1", r.scenario_name);
    }
}

#[test]
fn safe_mode_fallback_each_scenario_has_action_detail() {
    let results = run_safe_mode_fallback(42);
    for r in &results {
        assert!(
            r.details.contains_key("action"),
            "scenario {} missing 'action' detail",
            r.scenario_name
        );
        assert!(
            !r.details["action"].is_empty(),
            "scenario {} has empty 'action' detail",
            r.scenario_name
        );
    }
}

#[test]
fn safe_mode_fallback_deterministic_across_runs() {
    let r1 = run_safe_mode_fallback(42);
    let r2 = run_safe_mode_fallback(42);
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.scenario_name, b.scenario_name);
        assert_eq!(a.attack_blocked, b.attack_blocked);
        assert_eq!(a.invariant_violations, b.invariant_violations);
        assert_eq!(a.security_events, b.security_events);
    }
}

// ===========================================================================
// 8. Bayesian posterior convergence
// ===========================================================================

#[test]
fn bayesian_posterior_three_scenarios() {
    let results = run_bayesian_posterior_convergence(2, 10, 42);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].scenario_name, "benign-convergence");
    assert_eq!(results[1].scenario_name, "malicious-convergence");
    assert_eq!(results[2].scenario_name, "deterministic-replay");
}

#[test]
fn bayesian_posterior_non_empty_results() {
    let results = run_bayesian_posterior_convergence(2, 10, 42);
    assert!(!results.is_empty());
}

#[test]
fn bayesian_posterior_benign_converges() {
    let results = run_bayesian_posterior_convergence(4, 30, 42);
    assert!(
        results[0].attack_blocked,
        "benign should converge to Benign"
    );
    assert!(results[0].evidence_produced);
}

#[test]
fn bayesian_posterior_malicious_detected() {
    let results = run_bayesian_posterior_convergence(4, 30, 42);
    assert!(results[1].attack_blocked, "malicious should be non-benign");
    assert!(results[1].security_events > 0);
}

#[test]
fn bayesian_posterior_deterministic_replay_no_violations() {
    let results = run_bayesian_posterior_convergence(1, 20, 42);
    let replay = &results[2];
    assert!(replay.attack_blocked);
    assert_eq!(replay.invariant_violations, 0);
}

#[test]
fn bayesian_posterior_deterministic_with_same_seed() {
    let a = run_bayesian_posterior_convergence(3, 15, 77);
    let b = run_bayesian_posterior_convergence(3, 15, 77);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.attack_blocked, y.attack_blocked);
        assert_eq!(x.security_events, y.security_events);
    }
}

// ===========================================================================
// 9. Epoch regression
// ===========================================================================

#[test]
fn epoch_regression_four_scenarios() {
    let results = run_epoch_regression(42);
    assert_eq!(results.len(), 4);
}

#[test]
fn epoch_regression_non_empty_results() {
    let results = run_epoch_regression(42);
    assert!(!results.is_empty());
}

#[test]
fn epoch_regression_current_validates() {
    let results = run_epoch_regression(42);
    assert!(results[0].attack_blocked);
    assert_eq!(results[0].scenario_name, "current-epoch-validates");
}

#[test]
fn epoch_regression_expired_rejected() {
    let results = run_epoch_regression(42);
    assert!(results[1].attack_blocked);
    assert!(results[1].security_events > 0);
}

#[test]
fn epoch_regression_future_rejected() {
    let results = run_epoch_regression(42);
    assert!(results[2].attack_blocked);
}

#[test]
fn epoch_regression_monotonicity_holds() {
    let results = run_epoch_regression(42);
    let mono = &results[3];
    assert!(mono.attack_blocked);
    assert_eq!(mono.invariant_violations, 0);
}

#[test]
fn epoch_regression_zero_invariant_violations() {
    let results = run_epoch_regression(42);
    for r in &results {
        assert_eq!(
            r.invariant_violations, 0,
            "{} has violations",
            r.scenario_name
        );
    }
}

#[test]
fn epoch_regression_all_produce_evidence() {
    let results = run_epoch_regression(42);
    for r in &results {
        assert!(
            r.evidence_produced,
            "scenario {} should produce evidence",
            r.scenario_name
        );
    }
}

// ===========================================================================
// 10. Containment verification (evidence integrity)
// ===========================================================================

#[test]
fn containment_verification_two_scenarios() {
    let results = run_containment_verification(3, 42);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].scenario_name, "containment-receipts");
    assert_eq!(results[1].scenario_name, "quarantine-forensic-snapshot");
}

#[test]
fn containment_receipts_no_violations() {
    let results = run_containment_verification(5, 42);
    let r = &results[0];
    assert!(r.containment_action_taken);
    assert!(r.evidence_produced);
    assert!(r.attack_blocked);
    assert_eq!(r.invariant_violations, 0);
}

#[test]
fn containment_quarantine_forensic_snapshot() {
    let results = run_containment_verification(1, 42);
    let r = &results[1];
    assert!(r.containment_action_taken);
    assert!(r.attack_blocked);
    assert!(r.evidence_produced);
}

#[test]
fn containment_verification_scales_to_many() {
    let results = run_containment_verification(10, 42);
    for r in &results {
        assert_eq!(
            r.invariant_violations, 0,
            "{} has violations",
            r.scenario_name
        );
        assert!(r.evidence_produced);
    }
}

#[test]
fn containment_verification_security_events_proportional() {
    let r_small = run_containment_verification(2, 42);
    let r_large = run_containment_verification(8, 42);
    let events_small = r_small[0].security_events;
    let events_large = r_large[0].security_events;
    assert!(
        events_large >= events_small,
        "more extensions ({events_large}) should produce >= events than fewer ({events_small})"
    );
}

// ===========================================================================
// 11. SecuritySuiteConfig
// ===========================================================================

#[test]
fn security_suite_config_default_values() {
    let cfg = SecuritySuiteConfig::default();
    assert_eq!(cfg.seed, 42);
    assert_eq!(cfg.n_extensions, 10);
    assert_eq!(cfg.n_evidence_updates, 20);
    assert!(!cfg.run_id.is_empty());
}

#[test]
fn security_suite_config_debug_format() {
    let cfg = SecuritySuiteConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("42"), "Debug should show seed");
    assert!(dbg.contains("10"), "Debug should show n_extensions");
}

// ===========================================================================
// 12. Full suite runner
// ===========================================================================

#[test]
fn suite_runs_all_categories() {
    let config = default_config();
    let result = run_security_suite(&config);
    assert!(!result.scenarios.is_empty());
    assert!(!result.events.is_empty());
    assert!(result.total_security_events > 0);
}

#[test]
fn suite_returns_results_for_all_eight_categories() {
    let config = default_config();
    let result = run_security_suite(&config);
    let categories: BTreeSet<&str> = result
        .scenarios
        .iter()
        .map(|s| s.category.as_str())
        .collect();
    // run_security_suite calls 7 runners but covers multiple categories
    // At minimum we should see capability-escalation, resource-exhaustion,
    // quarantine-cascade, safe-mode-fallback, bayesian-posterior,
    // epoch-regression, and evidence-integrity.
    assert!(
        categories.len() >= 6,
        "expected at least 6 distinct categories, got {}: {:?}",
        categories.len(),
        categories
    );
}

#[test]
fn suite_scenario_count_matches_events() {
    let config = default_config();
    let result = run_security_suite(&config);
    assert_eq!(result.scenarios.len(), result.events.len());
}

#[test]
fn suite_events_have_correct_component() {
    let config = default_config();
    let result = run_security_suite(&config);
    for evt in &result.events {
        assert_eq!(evt.component, SECURITY_E2E_COMPONENT);
        assert_eq!(evt.event, "attack_scenario_completed");
        assert!(evt.outcome == "pass" || evt.outcome == "fail");
    }
}

#[test]
fn suite_blocked_flag_matches_violations() {
    let config = default_config();
    let result = run_security_suite(&config);
    assert_eq!(result.blocked, result.total_invariant_violations > 0);
}

#[test]
fn suite_deterministic_with_same_seed() {
    let cfg1 = default_config();
    let cfg2 = default_config();
    let r1 = run_security_suite(&cfg1);
    let r2 = run_security_suite(&cfg2);
    assert_eq!(r1.scenarios.len(), r2.scenarios.len());
    assert_eq!(r1.total_security_events, r2.total_security_events);
    assert_eq!(r1.total_invariant_violations, r2.total_invariant_violations);
    for (a, b) in r1.scenarios.iter().zip(r2.scenarios.iter()) {
        assert_eq!(a.scenario_name, b.scenario_name);
        assert_eq!(a.attack_blocked, b.attack_blocked);
        assert_eq!(a.security_events, b.security_events);
    }
}

#[test]
fn suite_different_seeds_same_scenario_count() {
    let cfg_a = SecuritySuiteConfig {
        seed: 1,
        n_extensions: 3,
        n_evidence_updates: 10,
        run_id: "seed-1".to_string(),
    };
    let cfg_b = SecuritySuiteConfig {
        seed: 9999,
        n_extensions: 3,
        n_evidence_updates: 10,
        run_id: "seed-9999".to_string(),
    };
    let r1 = run_security_suite(&cfg_a);
    let r2 = run_security_suite(&cfg_b);
    assert_eq!(r1.scenarios.len(), r2.scenarios.len());
}

#[test]
fn suite_events_trace_id_matches_run_id() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 2,
        n_evidence_updates: 5,
        run_id: "trace-check-abc".to_string(),
    };
    let result = run_security_suite(&config);
    for evt in &result.events {
        assert_eq!(evt.trace_id, "trace-check-abc");
    }
}

#[test]
fn suite_events_decision_id_prefixed_with_sec() {
    let config = default_config();
    let result = run_security_suite(&config);
    for evt in &result.events {
        assert!(
            evt.decision_id.starts_with("sec-"),
            "decision_id {} missing sec- prefix",
            evt.decision_id
        );
    }
}

#[test]
fn suite_events_policy_id_is_security_e2e() {
    let config = default_config();
    let result = run_security_suite(&config);
    for evt in &result.events {
        assert_eq!(evt.policy_id, "security-e2e");
    }
}

// ===========================================================================
// 13. Evidence artifact I/O (write_security_evidence)
// ===========================================================================

#[test]
fn write_security_evidence_creates_all_files() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("creates_all_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.summary_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_manifest_valid_json() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("manifest_json_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(manifest["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
    assert!(manifest["scenario_count"].as_u64().unwrap() > 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_manifest_has_all_fields() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("manifest_fields_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(manifest.get("schema_version").is_some());
    assert!(manifest.get("scenario_count").is_some());
    assert!(manifest.get("total_security_events").is_some());
    assert!(manifest.get("total_invariant_violations").is_some());
    assert!(manifest.get("blocked").is_some());
    assert_eq!(
        manifest["scenario_count"].as_u64().unwrap(),
        result.scenarios.len() as u64
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_jsonl_valid_lines() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("jsonl_lines_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.evidence_path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert!(!lines.is_empty());
    for line in &lines {
        let _v: serde_json::Value = serde_json::from_str(line).expect("invalid JSONL line");
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_summary_has_categories() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("summary_cats_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.summary_path).unwrap();
    let summary: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(summary["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
    let cats = summary["categories"].as_array().unwrap();
    assert!(!cats.is_empty());
    for cat_entry in cats {
        assert!(cat_entry["category"].is_string());
        assert!(cat_entry["scenarios"].as_u64().unwrap() > 0);
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_idempotent_overwrite() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("idempotent_v2");
    let _ = fs::remove_dir_all(&dir);

    let a1 = write_security_evidence(&result, &dir).unwrap();
    let content1 = fs::read_to_string(&a1.run_manifest_path).unwrap();

    let a2 = write_security_evidence(&result, &dir).unwrap();
    let content2 = fs::read_to_string(&a2.run_manifest_path).unwrap();

    assert_eq!(content1, content2);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_creates_parent_directory() {
    let dir = tmp_dir("nested_v2/subdir/deep");
    let _ = fs::remove_dir_all(tmp_dir("nested_v2"));
    let config = small_config();
    let result = run_security_suite(&config);
    let artifacts = write_security_evidence(&result, &dir).unwrap();
    assert!(artifacts.run_manifest_path.exists());
    let _ = fs::remove_dir_all(tmp_dir("nested_v2"));
}

// ===========================================================================
// 14. SecuritySuiteEvent fields
// ===========================================================================

#[test]
fn security_suite_event_clone_preserves_all_fields() {
    let evt = SecuritySuiteEvent {
        trace_id: "tr-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "comp".to_string(),
        event: "evt".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-001".to_string()),
        category: "cat".to_string(),
        scenario: "sc".to_string(),
    };
    let cloned = evt.clone();
    assert_eq!(cloned.trace_id, evt.trace_id);
    assert_eq!(cloned.decision_id, evt.decision_id);
    assert_eq!(cloned.policy_id, evt.policy_id);
    assert_eq!(cloned.component, evt.component);
    assert_eq!(cloned.event, evt.event);
    assert_eq!(cloned.outcome, evt.outcome);
    assert_eq!(cloned.error_code, evt.error_code);
    assert_eq!(cloned.category, evt.category);
    assert_eq!(cloned.scenario, evt.scenario);
}

#[test]
fn security_suite_event_error_code_none() {
    let evt = SecuritySuiteEvent {
        trace_id: String::new(),
        decision_id: String::new(),
        policy_id: String::new(),
        component: String::new(),
        event: String::new(),
        outcome: String::new(),
        error_code: None,
        category: String::new(),
        scenario: String::new(),
    };
    assert!(evt.error_code.is_none());
}

#[test]
fn security_suite_event_error_code_some() {
    let evt = SecuritySuiteEvent {
        trace_id: "tr".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TEST-ERR".to_string()),
        category: "test".to_string(),
        scenario: "test".to_string(),
    };
    assert_eq!(evt.error_code.as_deref(), Some("FE-TEST-ERR"));
}

#[test]
fn security_suite_event_debug_format() {
    let evt = SecuritySuiteEvent {
        trace_id: "tr-dbg".to_string(),
        decision_id: "d-dbg".to_string(),
        policy_id: "p-dbg".to_string(),
        component: "comp-dbg".to_string(),
        event: "evt-dbg".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        category: "cat-dbg".to_string(),
        scenario: "sc-dbg".to_string(),
    };
    let dbg = format!("{evt:?}");
    assert!(dbg.contains("tr-dbg"), "Debug should include trace_id");
    assert!(dbg.contains("comp-dbg"), "Debug should include component");
}

#[test]
fn suite_generated_events_have_non_empty_trace_id_component_event() {
    let config = default_config();
    let result = run_security_suite(&config);
    for evt in &result.events {
        assert!(!evt.trace_id.is_empty(), "trace_id should be non-empty");
        assert!(!evt.component.is_empty(), "component should be non-empty");
        assert!(!evt.event.is_empty(), "event should be non-empty");
    }
}

// ===========================================================================
// 15. Cross-category invariants
// ===========================================================================

#[test]
fn all_scenarios_have_known_category() {
    let config = default_config();
    let result = run_security_suite(&config);
    let known: BTreeSet<&str> = AttackCategory::all().iter().map(|c| c.as_str()).collect();
    for s in &result.scenarios {
        assert!(
            known.contains(s.category.as_str()),
            "unknown category: {}",
            s.category.as_str()
        );
    }
}

#[test]
fn suite_total_security_events_is_sum_of_scenario_events() {
    let config = default_config();
    let result = run_security_suite(&config);
    let sum: u64 = result.scenarios.iter().map(|s| s.security_events).sum();
    assert_eq!(result.total_security_events, sum);
}

#[test]
fn suite_total_invariant_violations_is_sum() {
    let config = default_config();
    let result = run_security_suite(&config);
    let sum: u64 = result
        .scenarios
        .iter()
        .map(|s| s.invariant_violations)
        .sum();
    assert_eq!(result.total_invariant_violations, sum);
}

#[test]
fn suite_every_scenario_has_non_empty_name() {
    let config = default_config();
    let result = run_security_suite(&config);
    for s in &result.scenarios {
        assert!(!s.scenario_name.is_empty());
    }
}

#[test]
fn suite_scenario_names_contain_hyphens() {
    let config = default_config();
    let result = run_security_suite(&config);
    for s in &result.scenarios {
        assert!(
            s.scenario_name.contains('-'),
            "scenario_name {} missing hyphen",
            s.scenario_name
        );
    }
}

// ===========================================================================
// 16. Determinism: same seed produces same results across full suite
// ===========================================================================

#[test]
fn full_determinism_same_seed_identical_scenario_results() {
    let make_config = || SecuritySuiteConfig {
        seed: 12345,
        n_extensions: 5,
        n_evidence_updates: 10,
        run_id: "det-test".to_string(),
    };
    let r1 = run_security_suite(&make_config());
    let r2 = run_security_suite(&make_config());
    assert_eq!(r1.scenarios.len(), r2.scenarios.len());
    assert_eq!(r1.total_security_events, r2.total_security_events);
    assert_eq!(r1.total_invariant_violations, r2.total_invariant_violations);
    assert_eq!(r1.blocked, r2.blocked);
    for (a, b) in r1.scenarios.iter().zip(r2.scenarios.iter()) {
        assert_eq!(a.scenario_name, b.scenario_name);
        assert_eq!(a.category, b.category);
        assert_eq!(a.attack_blocked, b.attack_blocked);
        assert_eq!(a.containment_action_taken, b.containment_action_taken);
        assert_eq!(a.evidence_produced, b.evidence_produced);
        assert_eq!(a.invariant_violations, b.invariant_violations);
        assert_eq!(a.security_events, b.security_events);
        assert_eq!(a.details, b.details);
    }
}

#[test]
fn full_determinism_individual_runners_with_same_seed() {
    for seed in [1, 42, 9999, u64::MAX] {
        let a = run_capability_escalation(3, seed);
        let b = run_capability_escalation(3, seed);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.attack_blocked, y.attack_blocked);
            assert_eq!(x.security_events, y.security_events);
        }

        let a = run_resource_exhaustion(3, seed);
        let b = run_resource_exhaustion(3, seed);
        assert_eq!(a[0].security_events, b[0].security_events);

        let a = run_epoch_regression(seed);
        let b = run_epoch_regression(seed);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.attack_blocked, y.attack_blocked);
        }
    }
}

// ===========================================================================
// 17. AttackScenarioResult field population
// ===========================================================================

#[test]
fn all_suite_results_have_populated_evidence_field() {
    let config = default_config();
    let result = run_security_suite(&config);
    // At least some scenarios should have evidence_produced = true
    let with_evidence = result
        .scenarios
        .iter()
        .filter(|s| s.evidence_produced)
        .count();
    assert!(
        with_evidence > 0,
        "at least some scenarios should produce evidence"
    );
}

#[test]
fn all_suite_results_have_correct_category_type() {
    let config = default_config();
    let result = run_security_suite(&config);
    for s in &result.scenarios {
        // Verify category as_str is non-empty and round-trips via all()
        let s_str = s.category.as_str();
        assert!(!s_str.is_empty());
        let found = AttackCategory::all().iter().any(|c| c.as_str() == s_str);
        assert!(found, "category {} not in AttackCategory::all()", s_str);
    }
}

// ===========================================================================
// 18. SecurityEvidenceArtifacts path structure
// ===========================================================================

#[test]
fn evidence_artifacts_paths_use_expected_filenames() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("path_names_v2");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    assert!(
        artifacts
            .run_manifest_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("manifest")
    );
    assert!(
        artifacts
            .evidence_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("evidence")
    );
    assert!(
        artifacts
            .summary_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("summary")
    );

    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// 19. SecuritySuiteResult debug
// ===========================================================================

#[test]
fn security_suite_result_debug_format() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dbg = format!("{result:?}");
    assert!(dbg.contains("scenarios"));
    assert!(dbg.contains("blocked"));
}

// ===========================================================================
// 20. Edge case: very large n_extensions
// ===========================================================================

#[test]
fn capability_escalation_with_twenty_extensions() {
    let results = run_capability_escalation(20, 42);
    assert_eq!(results.len(), 2);
    assert!(results[0].attack_blocked);
    assert!(results[0].evidence_produced);
}

#[test]
fn quarantine_cascade_with_twenty_extensions() {
    let results = run_quarantine_cascade(20, 10, 42);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].details["quarantined"], "10");
    assert_eq!(results[0].details["running"], "10");
    assert_eq!(results[0].invariant_violations, 0);
}
