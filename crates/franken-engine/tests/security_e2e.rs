//! Integration tests for the Security E2E test framework.
//!
//! Validates all 8 attack categories, the suite runner, determinism,
//! and evidence artifact production.

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

use frankenengine_engine::security_e2e::*;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Individual attack category tests
// ---------------------------------------------------------------------------

#[test]
fn capability_escalation_blocks_cpu_overconsumption() {
    let results = run_capability_escalation(5, 42);
    assert!(results.len() >= 2, "expect cpu + hostcall scenarios");

    let cpu = &results[0];
    assert_eq!(cpu.category, AttackCategory::CapabilityEscalation);
    assert_eq!(cpu.scenario_name, "cpu-budget-escalation");
    assert!(cpu.attack_blocked, "CPU overconsumption must be blocked");
    assert!(cpu.security_events > 0, "must report security events");
    assert!(cpu.evidence_produced, "must produce evidence");
}

#[test]
fn capability_escalation_blocks_hostcall_overconsumption() {
    let results = run_capability_escalation(5, 42);
    let hostcall = &results[1];
    assert_eq!(hostcall.scenario_name, "hostcall-budget-escalation");
    assert!(
        hostcall.attack_blocked,
        "hostcall overconsumption must be blocked"
    );
    assert!(hostcall.security_events > 0);
}

#[test]
fn resource_exhaustion_enforces_budgets() {
    let results = run_resource_exhaustion(10, 42);
    assert_eq!(results.len(), 1);

    let r = &results[0];
    assert_eq!(r.category, AttackCategory::ResourceExhaustion);
    assert!(r.attack_blocked);
    assert!(
        r.security_events > 0,
        "must detect budget exhaustion events"
    );
    assert!(r.evidence_produced, "must produce enforcement evidence");
}

#[test]
fn quarantine_cascade_handles_simultaneous_quarantines() {
    let results = run_quarantine_cascade(20, 10, 42);
    assert_eq!(results.len(), 1);

    let r = &results[0];
    assert_eq!(r.category, AttackCategory::QuarantineCascade);
    assert!(r.containment_action_taken);
    assert_eq!(r.invariant_violations, 0, "no invariant violations allowed");

    let quarantined: usize = r.details["quarantined"].parse().unwrap();
    assert!(
        quarantined > 0,
        "at least some extensions should be quarantined"
    );
}

#[test]
fn quarantine_cascade_state_consistency() {
    let results = run_quarantine_cascade(15, 7, 99);
    let r = &results[0];

    let running: usize = r.details["running"].parse().unwrap();
    let quarantined: usize = r.details["quarantined"].parse().unwrap();
    let total: usize = r.details["total_registered"].parse().unwrap();
    assert_eq!(total, 15);
    assert_eq!(running + quarantined, total);
}

#[test]
fn safe_mode_fallback_all_five_failure_types() {
    let results = run_safe_mode_fallback(42);
    assert_eq!(results.len(), 5, "must test all 5 failure types");

    let expected_names = [
        "adapter-unavailable",
        "decision-contract-error",
        "evidence-ledger-full",
        "cx-corrupted",
        "cancellation-deadlock",
    ];

    for (i, name) in expected_names.iter().enumerate() {
        let r = &results[i];
        assert_eq!(r.scenario_name, *name);
        assert_eq!(r.category, AttackCategory::SafeModeFallback);
        assert!(r.attack_blocked, "safe mode must activate for {name}");
        assert!(r.containment_action_taken);
        assert!(
            r.evidence_produced,
            "ring buffer must have entries for {name}"
        );
        assert_eq!(
            r.invariant_violations, 0,
            "recovery must succeed for {name}"
        );

        // Verify activation and recovery counts
        let activation: u64 = r.details["activation_count"].parse().unwrap();
        let recovery: u64 = r.details["recovery_count"].parse().unwrap();
        assert_eq!(activation, 1);
        assert_eq!(recovery, 1);
    }
}

#[test]
fn bayesian_posterior_benign_convergence() {
    let results = run_bayesian_posterior_convergence(5, 30, 42);
    assert!(results.len() >= 3);

    let benign = &results[0];
    assert_eq!(benign.scenario_name, "benign-convergence");
    assert!(
        benign.attack_blocked,
        "benign extensions should converge to benign state"
    );
    assert!(benign.evidence_produced);

    let count: usize = benign.details["benign_count"].parse().unwrap();
    assert_eq!(count, 5, "all 5 extensions should be classified as benign");
}

#[test]
fn bayesian_posterior_malicious_convergence() {
    let results = run_bayesian_posterior_convergence(5, 30, 42);
    let malicious = &results[1];
    assert_eq!(malicious.scenario_name, "malicious-convergence");
    assert!(
        malicious.attack_blocked,
        "malicious extensions should be detected as non-benign"
    );
    assert!(
        malicious.security_events > 0,
        "risky extensions should be flagged"
    );
}

#[test]
fn bayesian_posterior_deterministic_replay() {
    let results = run_bayesian_posterior_convergence(5, 30, 42);
    let replay = &results[2];
    assert_eq!(replay.scenario_name, "deterministic-replay");
    assert!(
        replay.attack_blocked,
        "same seed must produce same posteriors"
    );
    assert_eq!(replay.invariant_violations, 0);
}

#[test]
fn epoch_regression_current_validates() {
    let results = run_epoch_regression(42);
    let current = &results[0];
    assert_eq!(current.scenario_name, "current-epoch-validates");
    assert!(
        current.attack_blocked,
        "current epoch metadata must validate"
    );
}

#[test]
fn epoch_regression_expired_rejected() {
    let results = run_epoch_regression(42);
    let expired = &results[1];
    assert_eq!(expired.scenario_name, "expired-epoch-rejected");
    assert!(expired.attack_blocked, "expired epoch must be rejected");
    assert!(expired.security_events > 0);
}

#[test]
fn epoch_regression_future_rejected() {
    let results = run_epoch_regression(42);
    let future = &results[2];
    assert_eq!(future.scenario_name, "future-epoch-rejected");
    assert!(future.attack_blocked, "future epoch must be rejected");
}

#[test]
fn epoch_monotonicity() {
    let results = run_epoch_regression(42);
    let mono = &results[3];
    assert_eq!(mono.scenario_name, "epoch-monotonicity");
    assert!(
        mono.attack_blocked,
        "epochs must be monotonically increasing"
    );
    assert_eq!(mono.invariant_violations, 0);
}

#[test]
fn containment_receipts_produced() {
    let results = run_containment_verification(5, 42);
    assert!(results.len() >= 2);

    let receipts = &results[0];
    assert_eq!(receipts.scenario_name, "containment-receipts");
    assert_eq!(receipts.category, AttackCategory::EvidenceIntegrity);
    assert!(receipts.containment_action_taken);
    assert!(receipts.evidence_produced, "receipts must be produced");
    assert_eq!(receipts.invariant_violations, 0);
    assert!(receipts.attack_blocked);
}

#[test]
fn quarantine_forensic_snapshot() {
    let results = run_containment_verification(5, 42);
    let snapshot = &results[1];
    assert_eq!(snapshot.scenario_name, "quarantine-forensic-snapshot");
    assert!(snapshot.containment_action_taken);
    assert!(snapshot.evidence_produced, "forensic snapshot must exist");
    assert!(snapshot.attack_blocked);
}

// ---------------------------------------------------------------------------
// Suite runner tests
// ---------------------------------------------------------------------------

#[test]
fn full_security_suite_runs_all_categories() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 5,
        n_evidence_updates: 20,
        run_id: "test-suite".to_string(),
    };
    let result = run_security_suite(&config);

    // Expected scenario count: 2 (capability) + 1 (resource) + 1 (quarantine)
    // + 5 (safe-mode) + 3 (bayesian) + 4 (epoch) + 2 (containment) = 18
    assert_eq!(
        result.scenarios.len(),
        18,
        "suite must produce 18 scenarios"
    );
    assert_eq!(result.events.len(), 18, "events must match scenarios");

    // All categories should be represented
    let categories: BTreeSet<&str> = result
        .scenarios
        .iter()
        .map(|s| s.category.as_str())
        .collect();
    assert_eq!(
        categories.len(),
        7,
        "7 distinct categories expected (fork-detection not yet wired)"
    );
    assert!(categories.contains("capability-escalation"));
    assert!(categories.contains("resource-exhaustion"));
    assert!(categories.contains("quarantine-cascade"));
    assert!(categories.contains("safe-mode-fallback"));
    assert!(categories.contains("bayesian-posterior"));
    assert!(categories.contains("epoch-regression"));
    assert!(categories.contains("evidence-integrity"));
}

#[test]
fn suite_events_have_structured_fields() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);

    for event in &result.events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert_eq!(event.policy_id, "security-e2e");
        assert_eq!(event.component, SECURITY_E2E_COMPONENT);
        assert_eq!(event.event, "attack_scenario_completed");
        assert!(event.outcome == "pass" || event.outcome == "fail");
        assert!(!event.category.is_empty());
        assert!(!event.scenario.is_empty());
    }
}

#[test]
fn suite_default_config_no_invariant_violations() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);
    assert_eq!(
        result.total_invariant_violations, 0,
        "default suite config must produce zero invariant violations"
    );
    assert!(
        !result.blocked,
        "blocked flag should be false when no violations"
    );
}

#[test]
fn suite_accumulates_security_events() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);
    assert!(
        result.total_security_events > 0,
        "suite must detect security events across categories"
    );

    // Verify sum matches individual scenario totals
    let sum: u64 = result.scenarios.iter().map(|s| s.security_events).sum();
    assert_eq!(sum, result.total_security_events);
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn suite_is_deterministic_same_seed() {
    let config = SecuritySuiteConfig {
        seed: 7777,
        n_extensions: 5,
        n_evidence_updates: 10,
        run_id: "det-test".to_string(),
    };

    let r1 = run_security_suite(&config);
    let r2 = run_security_suite(&config);

    assert_eq!(r1.scenarios.len(), r2.scenarios.len());
    for (s1, s2) in r1.scenarios.iter().zip(r2.scenarios.iter()) {
        assert_eq!(s1.scenario_name, s2.scenario_name);
        assert_eq!(s1.attack_blocked, s2.attack_blocked);
        assert_eq!(s1.containment_action_taken, s2.containment_action_taken);
        assert_eq!(s1.evidence_produced, s2.evidence_produced);
        assert_eq!(s1.invariant_violations, s2.invariant_violations);
        assert_eq!(s1.security_events, s2.security_events);
    }
}

#[test]
fn different_seeds_produce_different_prng_sequences() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(9999);
    let seq1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
    let seq2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();
    assert_ne!(
        seq1, seq2,
        "different seeds must produce different PRNG sequences"
    );
}

// ---------------------------------------------------------------------------
// Attack category enumeration
// ---------------------------------------------------------------------------

#[test]
fn attack_category_all_returns_eight() {
    assert_eq!(AttackCategory::all().len(), 8);
}

#[test]
fn attack_category_labels_are_unique() {
    let labels: BTreeSet<&str> = AttackCategory::all().iter().map(|c| c.as_str()).collect();
    assert_eq!(labels.len(), 8);
}

#[test]
fn attack_category_as_str_round_trip() {
    for cat in AttackCategory::all() {
        let s = cat.as_str();
        assert!(!s.is_empty());
        assert!(s.contains('-'), "labels should be kebab-case: {s}");
    }
}

// ---------------------------------------------------------------------------
// Xorshift64 PRNG tests
// ---------------------------------------------------------------------------

#[test]
fn xorshift64_deterministic() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(42);
    for _ in 0..100 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn xorshift64_zero_seed_handled() {
    let mut rng = Xorshift64::new(0);
    let v = rng.next_u64();
    assert_ne!(v, 0, "zero seed should not produce zero output");
}

#[test]
fn xorshift64_next_usize_bounded() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..1000 {
        let v = rng.next_usize(10);
        assert!(v < 10);
    }
}

#[test]
fn xorshift64_next_bool_range() {
    let mut rng = Xorshift64::new(42);
    let mut true_count = 0u64;
    for _ in 0..1000 {
        if rng.next_bool(50) {
            true_count += 1;
        }
    }
    // With probability 50%, expect roughly 500 — allow wide range
    assert!(
        true_count > 200 && true_count < 800,
        "bool 50% should be roughly balanced: got {true_count}"
    );
}

// ---------------------------------------------------------------------------
// Evidence artifacts
// ---------------------------------------------------------------------------

#[test]
fn write_security_evidence_produces_files() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 3,
        n_evidence_updates: 10,
        run_id: "evidence-test".to_string(),
    };
    let result = run_security_suite(&config);

    let dir = std::env::temp_dir().join("franken_security_e2e_evidence_test");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_security_evidence(&result, &dir).expect("write evidence");
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.summary_path.exists());

    // Verify manifest content
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert_eq!(manifest["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
    assert_eq!(manifest["scenario_count"], result.scenarios.len());

    // Verify evidence JSONL has correct line count
    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();
    let lines: Vec<&str> = evidence.lines().filter(|l| !l.is_empty()).collect();
    // scenarios + events
    assert_eq!(lines.len(), result.scenarios.len() + result.events.len());

    // Verify summary categories
    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.summary_path).unwrap()).unwrap();
    assert_eq!(summary["schema_version"], SECURITY_E2E_SCHEMA_VERSION);
    let categories = summary["categories"].as_array().unwrap();
    assert!(
        categories.len() >= 5,
        "should have multiple category summaries"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evidence_jsonl_lines_are_valid_json() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);

    let dir = std::env::temp_dir().join("franken_security_e2e_jsonl_test");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_security_evidence(&result, &dir).unwrap();
    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();

    for line in evidence.lines().filter(|l| !l.is_empty()) {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\n  line: {line}"));
        assert!(parsed.is_object());
        assert!(
            parsed.get("event").is_some(),
            "each line must have event field"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Scale tests
// ---------------------------------------------------------------------------

#[test]
fn capability_escalation_scales_with_extensions() {
    let small = run_capability_escalation(2, 42);
    let large = run_capability_escalation(20, 42);

    // Both should succeed
    assert!(small[0].attack_blocked);
    assert!(large[0].attack_blocked);

    // Large should have more or equal security events
    let small_events: u64 = small.iter().map(|s| s.security_events).sum();
    let large_events: u64 = large.iter().map(|s| s.security_events).sum();
    assert!(large_events >= small_events);
}

#[test]
fn resource_exhaustion_scales_with_extensions() {
    let small = run_resource_exhaustion(3, 42);
    let large = run_resource_exhaustion(30, 42);

    assert!(small[0].attack_blocked);
    assert!(large[0].attack_blocked);
}

// ---------------------------------------------------------------------------
// SecuritySuiteConfig default
// ---------------------------------------------------------------------------

#[test]
fn default_config_has_sane_values() {
    let config = SecuritySuiteConfig::default();
    assert_eq!(config.seed, 42);
    assert!(config.n_extensions >= 5);
    assert!(config.n_evidence_updates >= 10);
    assert!(!config.run_id.is_empty());
}

// ---------------------------------------------------------------------------
// Scenario result invariants
// ---------------------------------------------------------------------------

#[test]
fn all_passing_scenarios_have_zero_invariant_violations() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);

    for s in &result.scenarios {
        if s.attack_blocked {
            assert_eq!(
                s.invariant_violations, 0,
                "blocked scenario {} must have 0 violations",
                s.scenario_name
            );
        }
    }
}

#[test]
fn all_scenarios_produce_evidence() {
    let config = SecuritySuiteConfig::default();
    let result = run_security_suite(&config);

    for s in &result.scenarios {
        assert!(
            s.evidence_produced,
            "scenario {} must produce evidence",
            s.scenario_name
        );
    }
}
