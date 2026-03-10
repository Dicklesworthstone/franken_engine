#![forbid(unsafe_code)]

//! Integration tests for the `security_e2e` module.
//!
//! Covers all 8 attack categories, Xorshift64 PRNG, scenario result types,
//! the full suite runner, evidence artifact I/O, and cross-category invariants.

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
    assert_eq!(zero.next_u64(), one.next_u64());
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
    assert!(differ);
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

// ===========================================================================
// 6. Quarantine cascade
// ===========================================================================

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

// ===========================================================================
// 7. Safe-mode fallback
// ===========================================================================

#[test]
fn safe_mode_fallback_five_scenarios() {
    let results = run_safe_mode_fallback(42);
    assert_eq!(results.len(), 5);
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

// ===========================================================================
// 10. Containment verification
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
// 13. Evidence artifact I/O
// ===========================================================================

#[test]
fn write_security_evidence_creates_all_files() {
    let config = default_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("creates_all");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.summary_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_manifest_valid_json() {
    let config = default_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("manifest_json");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(manifest["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
    assert!(manifest["scenario_count"].as_u64().unwrap() > 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_security_evidence_jsonl_valid_lines() {
    let config = default_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("jsonl_lines");
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
    let config = default_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("summary_cats");
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
    let config = default_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("idempotent");
    let _ = fs::remove_dir_all(&dir);

    let a1 = write_security_evidence(&result, &dir).unwrap();
    let content1 = fs::read_to_string(&a1.run_manifest_path).unwrap();

    let a2 = write_security_evidence(&result, &dir).unwrap();
    let content2 = fs::read_to_string(&a2.run_manifest_path).unwrap();

    assert_eq!(content1, content2);

    let _ = fs::remove_dir_all(&dir);
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
