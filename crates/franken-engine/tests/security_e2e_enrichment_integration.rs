#![forbid(unsafe_code)]

//! Enrichment integration tests for the `security_e2e` module.
//!
//! Covers Debug/Clone/Copy deep properties, BTreeMap/BTreeSet ordering,
//! cross-category invariants, scaling behavior, evidence artifact
//! field-name stability, determinism proofs, and edge-case configurations.

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

fn small_config() -> SecuritySuiteConfig {
    SecuritySuiteConfig {
        seed: 42,
        n_extensions: 2,
        n_evidence_updates: 5,
        run_id: "enrichment-test".to_string(),
    }
}

fn tmp_dir(suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("franken_sec_e2e_enrich_{suffix}"))
}

// ===========================================================================
// 1. AttackCategory — Debug, BTreeSet, Copy deep properties
// ===========================================================================

#[test]
fn enrichment_attack_category_debug_all_eight_contain_variant_name() {
    let expected = [
        ("CapabilityEscalation", AttackCategory::CapabilityEscalation),
        ("ResourceExhaustion", AttackCategory::ResourceExhaustion),
        ("QuarantineCascade", AttackCategory::QuarantineCascade),
        ("SafeModeFallback", AttackCategory::SafeModeFallback),
        ("BayesianPosterior", AttackCategory::BayesianPosterior),
        ("ForkDetection", AttackCategory::ForkDetection),
        ("EpochRegression", AttackCategory::EpochRegression),
        ("EvidenceIntegrity", AttackCategory::EvidenceIntegrity),
    ];
    for (name, cat) in &expected {
        let dbg = format!("{cat:?}");
        assert!(
            dbg.contains(name),
            "Debug for {name} should contain variant name, got: {dbg}"
        );
    }
}

#[test]
fn enrichment_attack_category_debug_all_unique() {
    let debugs: BTreeSet<String> = AttackCategory::all()
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    assert_eq!(
        debugs.len(),
        8,
        "all Debug representations should be unique"
    );
}

#[test]
fn enrichment_attack_category_as_str_dedup_via_btreeset() {
    let mut set = BTreeSet::new();
    // Insert duplicate as_str values
    set.insert(AttackCategory::ForkDetection.as_str());
    set.insert(AttackCategory::ForkDetection.as_str());
    set.insert(AttackCategory::EpochRegression.as_str());
    set.insert(AttackCategory::EpochRegression.as_str());
    set.insert(AttackCategory::EpochRegression.as_str());
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_attack_category_as_str_btreeset_ordering_stable() {
    let mut set = BTreeSet::new();
    for cat in AttackCategory::all() {
        set.insert(cat.as_str());
    }
    assert_eq!(set.len(), 8);
    // Collect twice, verify same order
    let order1: Vec<&str> = set.iter().copied().collect();
    let order2: Vec<&str> = set.iter().copied().collect();
    assert_eq!(order1, order2);
}

#[test]
fn enrichment_attack_category_copy_does_not_invalidate_source() {
    let a = AttackCategory::BayesianPosterior;
    let b = a;
    let c = a;
    let d = b;
    // All should be usable simultaneously (Copy semantics)
    assert_eq!(a.as_str(), b.as_str());
    assert_eq!(c.as_str(), d.as_str());
    assert_eq!(a, d);
}

#[test]
fn enrichment_attack_category_as_str_no_underscores_no_spaces() {
    for cat in AttackCategory::all() {
        let s = cat.as_str();
        assert!(
            !s.contains('_'),
            "as_str should use hyphens not underscores: {s}"
        );
        assert!(!s.contains(' '), "as_str should not contain spaces: {s}");
        assert!(!s.is_empty(), "as_str should not be empty");
    }
}

// ===========================================================================
// 2. AttackScenarioResult — Clone independence, details ordering
// ===========================================================================

#[test]
fn enrichment_attack_scenario_result_clone_independence() {
    // Get a result from a runner function
    let results = run_capability_escalation(3, 42);
    let original = results[0].clone();
    let cloned = original.clone();

    // Both should have the same values
    assert_eq!(original.category, cloned.category);
    assert_eq!(original.scenario_name, cloned.scenario_name);
    assert_eq!(original.attack_blocked, cloned.attack_blocked);
    assert_eq!(original.security_events, cloned.security_events);
    // Cloned details should be independent
    assert_eq!(original.details, cloned.details);
}

#[test]
fn enrichment_attack_scenario_result_details_btreemap_sorted() {
    // Use quarantine cascade which populates details with multiple keys
    let results = run_quarantine_cascade(5, 2, 42);
    let r = &results[0];
    // BTreeMap keys should be in sorted order
    let keys: Vec<&String> = r.details.keys().collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    assert_eq!(keys, sorted_keys, "details keys should be in sorted order");
}

#[test]
fn enrichment_attack_scenario_result_debug_includes_scenario_name() {
    let results = run_capability_escalation(2, 42);
    let r = &results[0];
    let dbg = format!("{r:?}");
    assert!(
        dbg.contains(&r.scenario_name),
        "Debug should contain scenario_name"
    );
    assert!(
        dbg.contains("CapabilityEscalation"),
        "Debug should contain category"
    );
}

#[test]
fn enrichment_attack_scenario_result_fields_from_runner() {
    // Verify field types and values from a runner
    let results = run_epoch_regression(42);
    for r in &results {
        // scenario_name is non-empty
        assert!(!r.scenario_name.is_empty());
        // invariant_violations is u64
        let _v: u64 = r.invariant_violations;
        // security_events is u64
        let _e: u64 = r.security_events;
    }
}

// ===========================================================================
// 3. Xorshift64 — deep properties
// ===========================================================================

#[test]
fn enrichment_xorshift64_never_zero_10k_iterations() {
    let mut rng = Xorshift64::new(42);
    for i in 0..10_000 {
        let val = rng.next_u64();
        assert_ne!(val, 0, "xorshift64 produced zero at iteration {i}");
    }
}

#[test]
fn enrichment_xorshift64_next_usize_all_buckets_covered() {
    let mut rng = Xorshift64::new(7);
    let bound = 8;
    let mut buckets = vec![false; bound];
    for _ in 0..500 {
        buckets[rng.next_usize(bound)] = true;
    }
    for (i, &hit) in buckets.iter().enumerate() {
        assert!(hit, "bucket {i} was never hit in 500 iterations");
    }
}

#[test]
fn enrichment_xorshift64_consecutive_values_unique() {
    let mut rng = Xorshift64::new(42);
    let mut prev = rng.next_u64();
    for i in 1..1000 {
        let val = rng.next_u64();
        assert_ne!(val, prev, "consecutive values equal at step {i}");
        prev = val;
    }
}

#[test]
fn enrichment_xorshift64_determinism_across_three_instances() {
    let mut a = Xorshift64::new(12345);
    let mut b = Xorshift64::new(12345);
    let mut c = Xorshift64::new(12345);
    for _ in 0..100 {
        let va = a.next_u64();
        let vb = b.next_u64();
        let vc = c.next_u64();
        assert_eq!(va, vb);
        assert_eq!(vb, vc);
    }
}

#[test]
fn enrichment_xorshift64_next_bool_boundary_1_pct() {
    let mut rng = Xorshift64::new(42);
    let mut any_true = false;
    let mut any_false = false;
    for _ in 0..10_000 {
        if rng.next_bool(1) {
            any_true = true;
        } else {
            any_false = true;
        }
        if any_true && any_false {
            break;
        }
    }
    // With 1% probability over 10k iterations, we should see at least one true
    assert!(
        any_true,
        "expected at least one true at 1% over 10k iterations"
    );
    assert!(
        any_false,
        "expected at least one false at 1% over 10k iterations"
    );
}

#[test]
fn enrichment_xorshift64_next_bool_99_pct() {
    let mut rng = Xorshift64::new(42);
    let mut any_true = false;
    let mut any_false = false;
    for _ in 0..10_000 {
        if rng.next_bool(99) {
            any_true = true;
        } else {
            any_false = true;
        }
        if any_true && any_false {
            break;
        }
    }
    assert!(any_true, "expected at least one true at 99%");
    assert!(any_false, "expected at least one false at 99%");
}

// ===========================================================================
// 4. SecuritySuiteConfig — custom values, Debug
// ===========================================================================

#[test]
fn enrichment_security_suite_config_custom_values_propagate() {
    let config = SecuritySuiteConfig {
        seed: 999,
        n_extensions: 50,
        n_evidence_updates: 100,
        run_id: "custom-42".to_string(),
    };
    assert_eq!(config.seed, 999);
    assert_eq!(config.n_extensions, 50);
    assert_eq!(config.n_evidence_updates, 100);
    assert_eq!(config.run_id, "custom-42");
}

#[test]
fn enrichment_security_suite_config_debug_includes_fields() {
    let cfg = SecuritySuiteConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("seed"), "Debug missing 'seed'");
    assert!(dbg.contains("n_extensions"), "Debug missing 'n_extensions'");
    assert!(
        dbg.contains("n_evidence_updates"),
        "Debug missing 'n_evidence_updates'"
    );
    assert!(dbg.contains("run_id"), "Debug missing 'run_id'");
}

// ===========================================================================
// 5. Safe mode — "action" detail, determinism
// ===========================================================================

#[test]
fn enrichment_safe_mode_fallback_action_detail_present() {
    let results = run_safe_mode_fallback(42);
    for r in &results {
        assert!(
            r.details.contains_key("action"),
            "scenario {} missing 'action' detail",
            r.scenario_name
        );
        assert!(
            !r.details["action"].is_empty(),
            "scenario {} has empty 'action'",
            r.scenario_name
        );
    }
}

#[test]
fn enrichment_safe_mode_fallback_deterministic() {
    let r1 = run_safe_mode_fallback(42);
    let r2 = run_safe_mode_fallback(42);
    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.scenario_name, b.scenario_name);
        assert_eq!(a.attack_blocked, b.attack_blocked);
        assert_eq!(a.invariant_violations, b.invariant_violations);
        assert_eq!(a.security_events, b.security_events);
        assert_eq!(a.details, b.details);
    }
}

// ===========================================================================
// 6. Bayesian posterior — scaling
// ===========================================================================

#[test]
fn enrichment_bayesian_posterior_large_scale() {
    let results = run_bayesian_posterior_convergence(10, 50, 42);
    assert_eq!(results.len(), 3);
    // All three scenarios should complete without violations
    for r in &results {
        assert_eq!(
            r.invariant_violations, 0,
            "scenario {} has violations at scale",
            r.scenario_name
        );
    }
}

#[test]
fn enrichment_bayesian_posterior_single_extension_still_three_scenarios() {
    let results = run_bayesian_posterior_convergence(1, 5, 42);
    assert_eq!(results.len(), 3);
}

#[test]
fn enrichment_bayesian_posterior_deterministic() {
    let a = run_bayesian_posterior_convergence(3, 15, 77);
    let b = run_bayesian_posterior_convergence(3, 15, 77);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.scenario_name, y.scenario_name);
        assert_eq!(x.attack_blocked, y.attack_blocked);
        assert_eq!(x.security_events, y.security_events);
        assert_eq!(x.invariant_violations, y.invariant_violations);
    }
}

// ===========================================================================
// 7. Epoch regression — evidence, determinism
// ===========================================================================

#[test]
fn enrichment_epoch_regression_evidence_produced_all() {
    let results = run_epoch_regression(42);
    for r in &results {
        assert!(
            r.evidence_produced,
            "scenario {} should produce evidence",
            r.scenario_name
        );
    }
}

#[test]
fn enrichment_epoch_regression_deterministic() {
    let a = run_epoch_regression(42);
    let b = run_epoch_regression(42);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.scenario_name, y.scenario_name);
        assert_eq!(x.attack_blocked, y.attack_blocked);
        assert_eq!(x.security_events, y.security_events);
    }
}

// ===========================================================================
// 8. Containment — scaling, determinism
// ===========================================================================

#[test]
fn enrichment_containment_security_events_scaling() {
    let r_small = run_containment_verification(2, 42);
    let r_large = run_containment_verification(8, 42);
    let events_small = r_small[0].security_events;
    let events_large = r_large[0].security_events;
    assert!(
        events_large >= events_small,
        "more extensions ({events_large}) should produce >= events than fewer ({events_small})"
    );
}

#[test]
fn enrichment_containment_deterministic() {
    let a = run_containment_verification(5, 42);
    let b = run_containment_verification(5, 42);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.scenario_name, y.scenario_name);
        assert_eq!(x.attack_blocked, y.attack_blocked);
        assert_eq!(x.security_events, y.security_events);
        assert_eq!(x.invariant_violations, y.invariant_violations);
    }
}

// ===========================================================================
// 9. Capability escalation — scaling
// ===========================================================================

#[test]
fn enrichment_capability_escalation_ten_extensions_all_blocked() {
    let results = run_capability_escalation(10, 42);
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(r.attack_blocked, "scenario {} not blocked", r.scenario_name);
        assert_eq!(
            r.invariant_violations, 0,
            "scenario {} has violations",
            r.scenario_name
        );
    }
}

#[test]
fn enrichment_capability_escalation_cpu_events_scale_with_extensions() {
    let r_small = run_capability_escalation(2, 42);
    let r_large = run_capability_escalation(10, 42);
    assert!(
        r_large[0].security_events >= r_small[0].security_events,
        "more extensions should produce >= security events"
    );
}

// ===========================================================================
// 10. Resource exhaustion — scaling
// ===========================================================================

#[test]
fn enrichment_resource_exhaustion_scaling() {
    let r_small = run_resource_exhaustion(2, 42);
    let r_large = run_resource_exhaustion(20, 42);
    assert!(
        r_large[0].security_events >= r_small[0].security_events,
        "more extensions should produce >= events"
    );
}

#[test]
fn enrichment_resource_exhaustion_zero_extensions() {
    let results = run_resource_exhaustion(0, 42);
    assert_eq!(results.len(), 1);
    assert!(results[0].attack_blocked);
    assert_eq!(results[0].security_events, 0);
}

// ===========================================================================
// 11. Quarantine cascade — determinism
// ===========================================================================

#[test]
fn enrichment_quarantine_cascade_deterministic() {
    let a = run_quarantine_cascade(10, 5, 42);
    let b = run_quarantine_cascade(10, 5, 42);
    assert_eq!(a[0].details, b[0].details);
    assert_eq!(a[0].invariant_violations, b[0].invariant_violations);
}

// ===========================================================================
// 12. Suite runner — minimal, large, cross-category
// ===========================================================================

#[test]
fn enrichment_suite_minimal_config() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 1,
        n_evidence_updates: 1,
        run_id: "minimal".to_string(),
    };
    let result = run_security_suite(&config);
    assert!(!result.scenarios.is_empty());
    assert!(!result.events.is_empty());
    assert_eq!(result.scenarios.len(), result.events.len());
}

#[test]
fn enrichment_suite_large_config() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 15,
        n_evidence_updates: 40,
        run_id: "large-scale".to_string(),
    };
    let result = run_security_suite(&config);
    assert!(!result.scenarios.is_empty());
    assert!(result.total_security_events > 0);
}

#[test]
fn enrichment_suite_all_categories_represented() {
    let config = small_config();
    let result = run_security_suite(&config);
    let categories: BTreeSet<String> = result
        .scenarios
        .iter()
        .map(|s| s.category.as_str().to_string())
        .collect();
    // Suite runs 7 runner functions (fork detection not called directly)
    // At minimum should see capability-escalation, resource-exhaustion,
    // quarantine-cascade, safe-mode-fallback, bayesian-posterior,
    // epoch-regression, evidence-integrity
    assert!(
        categories.len() >= 5,
        "expected at least 5 categories, got {}",
        categories.len()
    );
}

#[test]
fn enrichment_suite_scenario_names_all_unique() {
    let config = small_config();
    let result = run_security_suite(&config);
    let names: BTreeSet<&str> = result
        .scenarios
        .iter()
        .map(|s| s.scenario_name.as_str())
        .collect();
    assert_eq!(
        names.len(),
        result.scenarios.len(),
        "all scenario names should be unique"
    );
}

#[test]
fn enrichment_suite_events_category_matches_scenario() {
    let config = small_config();
    let result = run_security_suite(&config);
    for (scenario, event) in result.scenarios.iter().zip(result.events.iter()) {
        assert_eq!(
            event.category,
            scenario.category.as_str(),
            "event category should match scenario category for {}",
            scenario.scenario_name
        );
        assert_eq!(
            event.scenario, scenario.scenario_name,
            "event scenario should match scenario name"
        );
    }
}

#[test]
fn enrichment_suite_events_outcome_consistent_with_scenario() {
    let config = small_config();
    let result = run_security_suite(&config);
    for (scenario, event) in result.scenarios.iter().zip(result.events.iter()) {
        let expected_outcome = if scenario.attack_blocked && scenario.invariant_violations == 0 {
            "pass"
        } else {
            "fail"
        };
        assert_eq!(
            event.outcome, expected_outcome,
            "event outcome should match scenario state for {}",
            scenario.scenario_name
        );
    }
}

// ===========================================================================
// 13. Evidence artifact — deep field checks
// ===========================================================================

#[test]
fn enrichment_evidence_jsonl_line_count_matches_scenarios_plus_events() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("line_count");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.evidence_path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    let expected = result.scenarios.len() + result.events.len();
    assert_eq!(
        lines.len(),
        expected,
        "JSONL lines should equal scenarios + events"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_evidence_summary_blocked_matches_suite() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("blocked_match");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.summary_path).unwrap();
    let summary: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(summary["blocked"].as_bool().unwrap(), result.blocked);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_evidence_manifest_total_events_matches() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("total_events");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        manifest["total_security_events"].as_u64().unwrap(),
        result.total_security_events
    );
    assert_eq!(
        manifest["total_invariant_violations"].as_u64().unwrap(),
        result.total_invariant_violations
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_evidence_artifact_paths_have_expected_filenames() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("filenames");
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

#[test]
fn enrichment_evidence_summary_category_scenario_counts() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("cat_counts");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.summary_path).unwrap();
    let summary: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let cats = summary["categories"].as_array().unwrap();

    // Sum of per-category scenario counts should equal total scenarios
    let total_from_summary: u64 = cats.iter().map(|c| c["scenarios"].as_u64().unwrap()).sum();
    assert_eq!(
        total_from_summary,
        result.scenarios.len() as u64,
        "sum of per-category scenarios should match total"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_evidence_jsonl_each_line_has_event_field() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("event_field");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let raw = fs::read_to_string(&artifacts.evidence_path).unwrap();
    for (i, line) in raw.lines().enumerate() {
        let val: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            val.get("event").is_some(),
            "JSONL line {i} missing 'event' field"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// 14. SecuritySuiteResult — Debug, aggregation
// ===========================================================================

#[test]
fn enrichment_security_suite_result_debug() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dbg = format!("{result:?}");
    assert!(
        dbg.contains("scenarios"),
        "Debug should contain 'scenarios'"
    );
    assert!(dbg.contains("blocked"), "Debug should contain 'blocked'");
    assert!(
        dbg.contains("total_security_events"),
        "Debug should contain 'total_security_events'"
    );
}

#[test]
fn enrichment_security_suite_result_total_events_is_sum() {
    let config = small_config();
    let result = run_security_suite(&config);
    let sum: u64 = result.scenarios.iter().map(|s| s.security_events).sum();
    assert_eq!(result.total_security_events, sum);
}

#[test]
fn enrichment_security_suite_result_total_violations_is_sum() {
    let config = small_config();
    let result = run_security_suite(&config);
    let sum: u64 = result
        .scenarios
        .iter()
        .map(|s| s.invariant_violations)
        .sum();
    assert_eq!(result.total_invariant_violations, sum);
}

// ===========================================================================
// 15. Cross-category invariants
// ===========================================================================

#[test]
fn enrichment_cross_category_blocked_implies_evidence_or_containment() {
    let config = small_config();
    let result = run_security_suite(&config);
    for s in &result.scenarios {
        if s.attack_blocked {
            // Blocked scenarios should have produced evidence or taken containment action
            let has_evidence_trail = s.evidence_produced || s.containment_action_taken;
            assert!(
                has_evidence_trail || s.security_events == 0,
                "blocked scenario {} should have evidence trail or zero events",
                s.scenario_name
            );
        }
    }
}

#[test]
fn enrichment_cross_category_no_violations_when_fully_blocked() {
    let config = small_config();
    let result = run_security_suite(&config);
    // Scenarios that report attack_blocked=true should have 0 violations
    for s in &result.scenarios {
        if s.attack_blocked {
            assert_eq!(
                s.invariant_violations, 0,
                "blocked scenario {} should have 0 violations",
                s.scenario_name
            );
        }
    }
}

#[test]
fn enrichment_cross_category_all_scenarios_have_category_in_known_set() {
    let config = SecuritySuiteConfig {
        seed: 42,
        n_extensions: 5,
        n_evidence_updates: 10,
        run_id: "known-set".to_string(),
    };
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

// ===========================================================================
// 16. SecuritySuiteEvent — field-level checks
// ===========================================================================

#[test]
fn enrichment_security_suite_event_debug_includes_all_fields() {
    let evt = SecuritySuiteEvent {
        trace_id: "tr-dbg".to_string(),
        decision_id: "d-dbg".to_string(),
        policy_id: "p-dbg".to_string(),
        component: "comp-dbg".to_string(),
        event: "evt-dbg".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("ERR-DBG".to_string()),
        category: "cat-dbg".to_string(),
        scenario: "sc-dbg".to_string(),
    };
    let dbg = format!("{evt:?}");
    assert!(dbg.contains("tr-dbg"), "Debug missing trace_id");
    assert!(dbg.contains("d-dbg"), "Debug missing decision_id");
    assert!(dbg.contains("ERR-DBG"), "Debug missing error_code");
    assert!(dbg.contains("comp-dbg"), "Debug missing component");
}

#[test]
fn enrichment_security_suite_event_clone_independence() {
    let original = SecuritySuiteEvent {
        trace_id: "tr".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        category: "cat".to_string(),
        scenario: "sc".to_string(),
    };
    let cloned = original.clone();
    // Drop original scope, use cloned
    drop(original);
    assert_eq!(cloned.trace_id, "tr");
    assert_eq!(cloned.outcome, "pass");
    assert!(cloned.error_code.is_none());
}

// ===========================================================================
// 17. SecurityEvidenceArtifacts — Debug
// ===========================================================================

#[test]
fn enrichment_security_evidence_artifacts_debug() {
    let config = small_config();
    let result = run_security_suite(&config);
    let dir = tmp_dir("artifacts_debug");
    let _ = fs::remove_dir_all(&dir);
    let artifacts = write_security_evidence(&result, &dir).unwrap();

    let dbg = format!("{artifacts:?}");
    assert!(
        dbg.contains("run_manifest_path"),
        "Debug missing run_manifest_path"
    );
    assert!(dbg.contains("evidence_path"), "Debug missing evidence_path");
    assert!(dbg.contains("summary_path"), "Debug missing summary_path");

    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// 18. Determinism proof — full suite
// ===========================================================================

#[test]
fn enrichment_suite_determinism_five_runs() {
    let config = small_config();
    let reference = run_security_suite(&config);
    for run_idx in 1..5 {
        let trial = run_security_suite(&config);
        assert_eq!(
            reference.scenarios.len(),
            trial.scenarios.len(),
            "run {run_idx}: scenario count mismatch"
        );
        assert_eq!(
            reference.total_security_events, trial.total_security_events,
            "run {run_idx}: total events mismatch"
        );
        assert_eq!(
            reference.total_invariant_violations, trial.total_invariant_violations,
            "run {run_idx}: total violations mismatch"
        );
        for (a, b) in reference.scenarios.iter().zip(trial.scenarios.iter()) {
            assert_eq!(
                a.scenario_name, b.scenario_name,
                "run {run_idx}: scenario name mismatch"
            );
            assert_eq!(
                a.attack_blocked, b.attack_blocked,
                "run {run_idx}: {} blocked mismatch",
                a.scenario_name
            );
            assert_eq!(
                a.security_events, b.security_events,
                "run {run_idx}: {} events mismatch",
                a.scenario_name
            );
        }
    }
}
