#![forbid(unsafe_code)]
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

use serde::Deserialize;
use serde_json::Value;

// --- Seqlock Candidate Inventory ---
const CANDIDATE_INV_JSON: &str =
    include_str!("../../../docs/rgc_seqlock_candidate_inventory_v1.json");

// --- Seqlock Rollout Guard ---
const ROLLOUT_GUARD_JSON: &str = include_str!("../../../docs/rgc_seqlock_rollout_guard_v1.json");

// --- Persistent Cache Contract ---
const CACHE_JSON: &str = include_str!("../../../docs/rgc_persistent_cache_contract_v1.json");

// ===== Seqlock Candidate Inventory =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SeqlockCandidateInventory {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    candidate_expectations: Vec<CandidateExpectation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CandidateExpectation {
    candidate_id: String,
    disposition: String,
}

fn parse_candidate_inv() -> SeqlockCandidateInventory {
    serde_json::from_str(CANDIDATE_INV_JSON).expect("seqlock candidate inventory must parse")
}

#[test]
fn candidate_inv_parses_with_expected_schema() {
    let c = parse_candidate_inv();
    assert_eq!(
        c.schema_version,
        "franken-engine.rgc-seqlock-reader-writer-bundle.v1"
    );
}

#[test]
fn candidate_inv_bead_id_is_valid() {
    let c = parse_candidate_inv();
    assert!(c.bead_id.starts_with("bd-"));
}

#[test]
fn candidate_inv_required_artifacts_include_standard_set() {
    let c = parse_candidate_inv();
    let artifacts: BTreeSet<&str> = c.required_artifacts.iter().map(String::as_str).collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn candidate_inv_required_artifacts_are_unique() {
    let c = parse_candidate_inv();
    let mut seen = BTreeSet::new();
    for a in &c.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn candidate_inv_has_9_candidates() {
    let c = parse_candidate_inv();
    assert_eq!(
        c.candidate_expectations.len(),
        9,
        "must have exactly 9 candidate expectations"
    );
}

#[test]
fn candidate_inv_ids_are_unique() {
    let c = parse_candidate_inv();
    let mut seen = BTreeSet::new();
    for exp in &c.candidate_expectations {
        assert!(
            seen.insert(exp.candidate_id.clone()),
            "duplicate candidate_id: {}",
            exp.candidate_id
        );
    }
}

#[test]
fn candidate_inv_ids_are_kebab_case() {
    let c = parse_candidate_inv();
    for exp in &c.candidate_expectations {
        assert!(
            exp.candidate_id
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '-' || ch.is_ascii_digit()),
            "candidate_id must be kebab-case: {}",
            exp.candidate_id
        );
    }
}

#[test]
fn candidate_inv_dispositions_from_known_set() {
    let c = parse_candidate_inv();
    let known: BTreeSet<&str> = ["accept", "reject", "conditional"].into_iter().collect();
    for exp in &c.candidate_expectations {
        assert!(
            known.contains(exp.disposition.as_str()),
            "unknown disposition '{}' for {}",
            exp.disposition,
            exp.candidate_id
        );
    }
}

#[test]
fn candidate_inv_has_all_three_dispositions() {
    let c = parse_candidate_inv();
    let dispositions: BTreeSet<&str> = c
        .candidate_expectations
        .iter()
        .map(|e| e.disposition.as_str())
        .collect();
    for d in ["accept", "reject", "conditional"] {
        assert!(
            dispositions.contains(d),
            "missing disposition category: {d}"
        );
    }
}

#[test]
fn candidate_inv_sorted_by_id() {
    let c = parse_candidate_inv();
    for window in c.candidate_expectations.windows(2) {
        assert!(
            window[0].candidate_id < window[1].candidate_id,
            "candidates must be sorted: {} should come before {}",
            window[0].candidate_id,
            window[1].candidate_id
        );
    }
}

// ===== Seqlock Rollout Guard =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SeqlockRolloutGuard {
    schema_version: String,
    bead_id: String,
    default_disabled_candidates: Vec<String>,
    required_artifacts: Vec<String>,
}

fn parse_rollout_guard() -> SeqlockRolloutGuard {
    serde_json::from_str(ROLLOUT_GUARD_JSON).expect("seqlock rollout guard must parse")
}

#[test]
fn rollout_guard_parses_with_expected_schema() {
    let g = parse_rollout_guard();
    assert_eq!(
        g.schema_version,
        "franken-engine.rgc-seqlock-rollout-guard-docs.v1"
    );
}

#[test]
fn rollout_guard_bead_id_is_valid() {
    let g = parse_rollout_guard();
    assert!(g.bead_id.starts_with("bd-"));
}

#[test]
fn rollout_guard_disabled_candidates_are_unique_and_kebab_case() {
    let g = parse_rollout_guard();
    let mut seen = BTreeSet::new();
    for c in &g.default_disabled_candidates {
        assert!(
            c.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '-' || ch.is_ascii_digit()),
            "disabled candidate must be kebab-case: {c}"
        );
        assert!(seen.insert(c.clone()), "duplicate disabled candidate: {c}");
    }
}

#[test]
fn rollout_guard_disabled_candidates_are_subset_of_inventory_accepts() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let accepted: BTreeSet<&str> = inv
        .candidate_expectations
        .iter()
        .filter(|e| e.disposition == "accept")
        .map(|e| e.candidate_id.as_str())
        .collect();
    for disabled in &guard.default_disabled_candidates {
        assert!(
            accepted.contains(disabled.as_str()),
            "disabled candidate '{}' must be an accepted candidate in the inventory",
            disabled
        );
    }
}

#[test]
fn rollout_guard_required_artifacts_include_standard_set() {
    let g = parse_rollout_guard();
    let artifacts: BTreeSet<&str> = g.required_artifacts.iter().map(String::as_str).collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn rollout_guard_required_artifacts_are_unique() {
    let g = parse_rollout_guard();
    let mut seen = BTreeSet::new();
    for a in &g.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

// ===== Persistent Cache Contract =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PersistentCacheContract {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    key_fields: Vec<String>,
    consumers: Vec<String>,
    scenario_ids: Vec<String>,
}

fn parse_cache() -> PersistentCacheContract {
    serde_json::from_str(CACHE_JSON).expect("persistent cache contract must parse")
}

#[test]
fn cache_parses_with_expected_schema() {
    let c = parse_cache();
    assert_eq!(
        c.schema_version,
        "franken-engine.rgc-persistent-cache-docs.v1"
    );
}

#[test]
fn cache_bead_id_is_valid() {
    let c = parse_cache();
    assert!(c.bead_id.starts_with("bd-"));
}

#[test]
fn cache_required_artifacts_include_standard_set() {
    let c = parse_cache();
    let artifacts: BTreeSet<&str> = c.required_artifacts.iter().map(String::as_str).collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn cache_required_artifacts_are_unique() {
    let c = parse_cache();
    let mut seen = BTreeSet::new();
    for a in &c.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn cache_key_fields_are_unique_and_snake_case() {
    let c = parse_cache();
    let mut seen = BTreeSet::new();
    for field in &c.key_fields {
        assert!(
            field
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit()),
            "key field must be snake_case: {field}"
        );
        assert!(seen.insert(field.clone()), "duplicate key field: {field}");
    }
}

#[test]
fn cache_key_fields_include_critical_identity_fields() {
    let c = parse_cache();
    let fields: BTreeSet<&str> = c.key_fields.iter().map(String::as_str).collect();
    for required in ["module_id", "source_hash", "policy_version"] {
        assert!(
            fields.contains(required),
            "missing critical key field: {required}"
        );
    }
}

#[test]
fn cache_consumers_are_unique_and_nonempty() {
    let c = parse_cache();
    assert!(!c.consumers.is_empty(), "consumers must not be empty");
    let mut seen = BTreeSet::new();
    for consumer in &c.consumers {
        assert!(!consumer.trim().is_empty(), "consumer must not be empty");
        assert!(
            seen.insert(consumer.clone()),
            "duplicate consumer: {consumer}"
        );
    }
}

#[test]
fn cache_scenario_ids_are_unique_and_snake_case() {
    let c = parse_cache();
    let mut seen = BTreeSet::new();
    for scenario in &c.scenario_ids {
        assert!(
            scenario
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit()),
            "scenario_id must be snake_case: {scenario}"
        );
        assert!(
            seen.insert(scenario.clone()),
            "duplicate scenario_id: {scenario}"
        );
    }
}

#[test]
fn cache_scenarios_include_hit_and_miss() {
    let c = parse_cache();
    let scenarios: BTreeSet<&str> = c.scenario_ids.iter().map(String::as_str).collect();
    assert!(
        scenarios.contains("cache_hit"),
        "must include cache_hit scenario"
    );
    assert!(
        scenarios.contains("cache_miss"),
        "must include cache_miss scenario"
    );
}

#[test]
fn cache_top_level_keys_match_expected() {
    let raw: Value = serde_json::from_str(CACHE_JSON).unwrap();
    let keys: BTreeSet<&str> = raw
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "bead_id",
            "required_artifacts",
            "key_fields",
            "consumers",
            "scenario_ids"
        ])
    );
}

#[test]
fn deterministic_double_parse_all_three() {
    assert_eq!(parse_candidate_inv(), parse_candidate_inv());
    assert_eq!(parse_rollout_guard(), parse_rollout_guard());
    assert_eq!(parse_cache(), parse_cache());
}
