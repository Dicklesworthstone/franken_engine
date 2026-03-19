#![forbid(unsafe_code)]
//! Enrichment integration tests for `frankenlab_extension_lifecycle`.
//!
//! Tests ScenarioKind Display uniqueness, serde roundtrips for all types,
//! ScenarioAssertion serde, ScenarioResult serde with various fields,
//! Display ordering, and structural invariants.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::frankenlab_extension_lifecycle::{
    ScenarioAssertion, ScenarioKind, ScenarioResult, ScenarioSuiteResult, run_all_scenarios,
    run_scenario,
};
use frankenengine_engine::lab_runtime::Verdict;

// ===========================================================================
// helpers
// ===========================================================================

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(42), MockBudget::new(budget_ms))
}

const ALL_KINDS: [ScenarioKind; 7] = [
    ScenarioKind::Startup,
    ScenarioKind::NormalShutdown,
    ScenarioKind::ForcedCancel,
    ScenarioKind::Quarantine,
    ScenarioKind::Revocation,
    ScenarioKind::DegradedMode,
    ScenarioKind::MultiExtension,
];

fn make_assertion(desc: &str, passed: bool) -> ScenarioAssertion {
    ScenarioAssertion {
        description: desc.to_string(),
        passed,
        detail: if passed {
            String::new()
        } else {
            format!("failed: {desc}")
        },
    }
}

fn make_scenario_result_via_serde(kind: ScenarioKind, seed: u64) -> ScenarioResult {
    let json = serde_json::json!({
        "kind": kind,
        "seed": seed,
        "passed": true,
        "assertions": [],
        "lifecycle_events": [],
        "extensions_loaded": [],
        "final_states": {},
        "total_events_emitted": 0
    });
    serde_json::from_value(json).expect("deserialize ScenarioResult")
}

// ===========================================================================
// ScenarioKind Display uniqueness
// ===========================================================================

#[test]
fn enrichment_scenario_kind_display_all_seven_unique() {
    let set: BTreeSet<String> = ALL_KINDS.iter().map(|k| k.to_string()).collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_scenario_kind_display_exact_values() {
    assert_eq!(ScenarioKind::Startup.to_string(), "startup");
    assert_eq!(ScenarioKind::NormalShutdown.to_string(), "normal_shutdown");
    assert_eq!(ScenarioKind::ForcedCancel.to_string(), "forced_cancel");
    assert_eq!(ScenarioKind::Quarantine.to_string(), "quarantine");
    assert_eq!(ScenarioKind::Revocation.to_string(), "revocation");
    assert_eq!(ScenarioKind::DegradedMode.to_string(), "degraded_mode");
    assert_eq!(ScenarioKind::MultiExtension.to_string(), "multi_extension");
}

#[test]
fn enrichment_scenario_kind_display_all_lowercase_snake() {
    for kind in &ALL_KINDS {
        let s = kind.to_string();
        assert!(
            s.chars().all(|c| c.is_lowercase() || c == '_'),
            "Display for {kind:?} should be lowercase snake_case, got '{s}'"
        );
    }
}

#[test]
fn enrichment_scenario_kind_display_no_whitespace() {
    for kind in &ALL_KINDS {
        let s = kind.to_string();
        assert!(!s.contains(' '), "Display for {kind:?} contains whitespace");
    }
}

// ===========================================================================
// ScenarioKind serde roundtrips
// ===========================================================================

#[test]
fn enrichment_scenario_kind_serde_roundtrip_all_variants() {
    for kind in &ALL_KINDS {
        let json = serde_json::to_string(kind).unwrap();
        let back: ScenarioKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_scenario_kind_serde_tags_all_distinct() {
    let tags: BTreeSet<String> = ALL_KINDS
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn enrichment_scenario_kind_serde_startup_tag() {
    let json = serde_json::to_string(&ScenarioKind::Startup).unwrap();
    assert!(json.contains("Startup"));
}

#[test]
fn enrichment_scenario_kind_serde_forced_cancel_tag() {
    let json = serde_json::to_string(&ScenarioKind::ForcedCancel).unwrap();
    assert!(json.contains("ForcedCancel"));
}

// ===========================================================================
// ScenarioKind ordering
// ===========================================================================

#[test]
fn enrichment_scenario_kind_ord_follows_declaration() {
    for pair in ALL_KINDS.windows(2) {
        assert!(pair[0] < pair[1], "{:?} should be < {:?}", pair[0], pair[1]);
    }
}

#[test]
fn enrichment_scenario_kind_sort_deterministic() {
    let mut shuffled = [
        ScenarioKind::MultiExtension,
        ScenarioKind::Startup,
        ScenarioKind::DegradedMode,
        ScenarioKind::Quarantine,
        ScenarioKind::Revocation,
        ScenarioKind::ForcedCancel,
        ScenarioKind::NormalShutdown,
    ];
    shuffled.sort();
    assert_eq!(shuffled, ALL_KINDS);
}

#[test]
fn enrichment_scenario_kind_btreemap_key_all_variants() {
    let mut map: BTreeMap<ScenarioKind, usize> = BTreeMap::new();
    for (i, kind) in ALL_KINDS.iter().enumerate() {
        map.insert(*kind, i);
    }
    assert_eq!(map.len(), 7);
    assert_eq!(map[&ScenarioKind::Startup], 0);
    assert_eq!(map[&ScenarioKind::MultiExtension], 6);
}

// ===========================================================================
// ScenarioAssertion serde
// ===========================================================================

#[test]
fn enrichment_assertion_serde_roundtrip_passed() {
    let a = make_assertion("check ok", true);
    let json = serde_json::to_string(&a).unwrap();
    let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
    assert!(back.detail.is_empty());
}

#[test]
fn enrichment_assertion_serde_roundtrip_failed() {
    let a = make_assertion("check fail", false);
    let json = serde_json::to_string(&a).unwrap();
    let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
    assert!(!back.detail.is_empty());
}

#[test]
fn enrichment_assertion_json_field_names() {
    let a = make_assertion("test", true);
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"passed\""));
    assert!(json.contains("\"detail\""));
}

#[test]
fn enrichment_assertion_clone_independence() {
    let a = make_assertion("original", true);
    let mut b = a.clone();
    b.description = "modified".to_string();
    b.passed = false;
    assert_eq!(a.description, "original");
    assert!(a.passed);
}

#[test]
fn enrichment_assertion_empty_description_roundtrip() {
    let a = ScenarioAssertion {
        description: String::new(),
        passed: true,
        detail: String::new(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ===========================================================================
// ScenarioResult serde (via serde since new is private)
// ===========================================================================

#[test]
fn enrichment_result_serde_roundtrip_empty() {
    let r = make_scenario_result_via_serde(ScenarioKind::Startup, 42);
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_result_serde_with_assertions() {
    let json = serde_json::json!({
        "kind": "Startup",
        "seed": 99,
        "passed": false,
        "assertions": [
            {"description": "check-1", "passed": true, "detail": ""},
            {"description": "check-2", "passed": false, "detail": "expected X"}
        ],
        "lifecycle_events": [],
        "extensions_loaded": ["ext-a"],
        "final_states": {"ext-a": true},
        "total_events_emitted": 5
    });
    let r: ScenarioResult = serde_json::from_value(json).unwrap();
    assert_eq!(r.kind, ScenarioKind::Startup);
    assert_eq!(r.seed, 99);
    assert!(!r.passed);
    assert_eq!(r.assertions.len(), 2);
    assert_eq!(r.extensions_loaded, vec!["ext-a"]);
    assert_eq!(r.final_states.get("ext-a"), Some(&true));
    assert_eq!(r.total_events_emitted, 5);

    let roundtrip_json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&roundtrip_json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_result_json_field_names_stable() {
    let r = make_scenario_result_via_serde(ScenarioKind::Quarantine, 1);
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"seed\""));
    assert!(json.contains("\"passed\""));
    assert!(json.contains("\"assertions\""));
    assert!(json.contains("\"lifecycle_events\""));
    assert!(json.contains("\"extensions_loaded\""));
    assert!(json.contains("\"final_states\""));
    assert!(json.contains("\"total_events_emitted\""));
}

#[test]
fn enrichment_result_all_kinds_serde() {
    for kind in &ALL_KINDS {
        let r = make_scenario_result_via_serde(*kind, 7);
        let json = serde_json::to_string(&r).unwrap();
        let back: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, *kind);
    }
}

#[test]
fn enrichment_result_serde_seed_zero() {
    let r = make_scenario_result_via_serde(ScenarioKind::Revocation, 0);
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.seed, 0);
}

#[test]
fn enrichment_result_serde_seed_max() {
    let r = make_scenario_result_via_serde(ScenarioKind::DegradedMode, u64::MAX);
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.seed, u64::MAX);
}

#[test]
fn enrichment_result_final_states_btreemap_sorted() {
    let json = serde_json::json!({
        "kind": "MultiExtension",
        "seed": 10,
        "passed": true,
        "assertions": [],
        "lifecycle_events": [],
        "extensions_loaded": ["ext-0", "ext-1", "ext-2"],
        "final_states": {"ext-2": false, "ext-0": true, "ext-1": false},
        "total_events_emitted": 0
    });
    let r: ScenarioResult = serde_json::from_value(json).unwrap();
    let keys: Vec<&String> = r.final_states.keys().collect();
    assert_eq!(keys, vec!["ext-0", "ext-1", "ext-2"]);
}

// ===========================================================================
// ScenarioSuiteResult serde
// ===========================================================================

#[test]
fn enrichment_suite_result_serde_roundtrip() {
    let mut cx = mock_cx(100_000);
    let suite = run_all_scenarios(42, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    let back: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
    assert_eq!(suite, back);
}

#[test]
fn enrichment_suite_result_json_field_names() {
    let mut cx = mock_cx(100_000);
    let suite = run_all_scenarios(1, &mut cx);
    let json = serde_json::to_string(&suite).unwrap();
    assert!(json.contains("\"seed\""));
    assert!(json.contains("\"scenarios\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"total_assertions\""));
    assert!(json.contains("\"passed_assertions\""));
}

// ===========================================================================
// Debug distinctness
// ===========================================================================

#[test]
fn enrichment_scenario_kind_debug_all_distinct() {
    let debugs: BTreeSet<String> = ALL_KINDS.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 7);
}

#[test]
fn enrichment_scenario_kind_debug_contains_variant() {
    assert!(format!("{:?}", ScenarioKind::Startup).contains("Startup"));
    assert!(format!("{:?}", ScenarioKind::NormalShutdown).contains("NormalShutdown"));
    assert!(format!("{:?}", ScenarioKind::MultiExtension).contains("MultiExtension"));
}

#[test]
fn enrichment_assertion_debug_nonempty() {
    let a = make_assertion("check", true);
    assert!(!format!("{a:?}").is_empty());
}

// ===========================================================================
// Copy / Clone semantics
// ===========================================================================

#[test]
fn enrichment_scenario_kind_copy_semantics() {
    let a = ScenarioKind::Quarantine;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.to_string(), b.to_string());
}

#[test]
fn enrichment_result_clone_equality() {
    let r = make_scenario_result_via_serde(ScenarioKind::ForcedCancel, 55);
    let c = r.clone();
    assert_eq!(r, c);
}

// ===========================================================================
// Hash uniqueness
// ===========================================================================

#[test]
fn enrichment_scenario_kind_hash_all_unique() {
    use std::hash::{Hash, Hasher};
    let hashes: BTreeSet<u64> = ALL_KINDS
        .iter()
        .map(|k| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(hashes.len(), 7);
}

#[test]
fn enrichment_scenario_kind_hash_consistent() {
    use std::hash::{Hash, Hasher};
    let k = ScenarioKind::Revocation;
    let h1 = {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut h);
        h.finish()
    };
    let h2 = {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut h);
        h.finish()
    };
    assert_eq!(h1, h2);
}

// ===========================================================================
// Run-scenario integration
// ===========================================================================

#[test]
fn enrichment_run_all_scenarios_seven_results() {
    let mut cx = mock_cx(100_000);
    let suite = run_all_scenarios(42, &mut cx);
    assert_eq!(suite.scenarios.len(), 7);
    assert_eq!(suite.verdict, Verdict::Pass);
}

#[test]
fn enrichment_run_all_deterministic() {
    let mut cx1 = mock_cx(100_000);
    let mut cx2 = mock_cx(100_000);
    let s1 = run_all_scenarios(99, &mut cx1);
    let s2 = run_all_scenarios(99, &mut cx2);
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_each_scenario_emits_events() {
    let mut cx = mock_cx(100_000);
    for kind in ALL_KINDS {
        let r = run_scenario(kind, 1, &mut cx);
        assert!(r.total_events_emitted > 0, "{kind} should emit events");
    }
}

#[test]
fn enrichment_each_scenario_loads_extensions() {
    let mut cx = mock_cx(100_000);
    for kind in ALL_KINDS {
        let r = run_scenario(kind, 1, &mut cx);
        assert!(!r.extensions_loaded.is_empty(), "{kind} should load extensions");
    }
}

#[test]
fn enrichment_multi_extension_has_most_extensions() {
    let mut cx = mock_cx(100_000);
    let multi = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
    let startup = run_scenario(ScenarioKind::Startup, 1, &mut cx);
    assert!(multi.extensions_loaded.len() >= startup.extensions_loaded.len());
}

#[test]
fn enrichment_suite_total_assertions_matches_sum() {
    let mut cx = mock_cx(100_000);
    let suite = run_all_scenarios(42, &mut cx);
    let sum: usize = suite.scenarios.iter().map(|s| s.assertions.len()).sum();
    assert_eq!(suite.total_assertions, sum);
}
