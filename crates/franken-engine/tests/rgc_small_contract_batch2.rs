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

// ===== Cross-schema and structural enrichment =====

#[test]
fn cross_schema_all_three_bead_ids_are_distinct() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    let ids: BTreeSet<&str> = [
        inv.bead_id.as_str(),
        guard.bead_id.as_str(),
        cache.bead_id.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(ids.len(), 3, "all three bead_ids must be distinct");
}

#[test]
fn cross_schema_all_three_schema_versions_are_distinct() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    let versions: BTreeSet<&str> = [
        inv.schema_version.as_str(),
        guard.schema_version.as_str(),
        cache.schema_version.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        versions.len(),
        3,
        "all three schema_versions must be distinct"
    );
}

#[test]
fn candidate_inv_top_level_keys_match_expected() {
    let raw: Value = serde_json::from_str(CANDIDATE_INV_JSON).unwrap();
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
            "candidate_expectations"
        ])
    );
}

#[test]
fn rollout_guard_top_level_keys_match_expected() {
    let raw: Value = serde_json::from_str(ROLLOUT_GUARD_JSON).unwrap();
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
            "default_disabled_candidates",
            "required_artifacts"
        ])
    );
}

#[test]
fn rollout_guard_has_at_least_one_disabled_candidate() {
    let g = parse_rollout_guard();
    assert!(
        !g.default_disabled_candidates.is_empty(),
        "rollout guard must disable at least one candidate"
    );
}

#[test]
fn cache_consumers_follow_snake_case_convention() {
    let c = parse_cache();
    for consumer in &c.consumers {
        assert!(
            consumer
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit()),
            "consumer must be snake_case: {consumer}"
        );
    }
}

#[test]
fn cache_scenario_ids_include_at_least_three_scenarios() {
    let c = parse_cache();
    assert!(
        c.scenario_ids.len() >= 3,
        "must have at least 3 scenario_ids, found {}",
        c.scenario_ids.len()
    );
}

// ===== Additional enrichment tests =====

// --- Seqlock Candidate Inventory extra ---

#[test]
fn candidate_inv_clone_equals_original() {
    let c = parse_candidate_inv();
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn candidate_inv_debug_contains_schema_version() {
    let c = parse_candidate_inv();
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains("franken-engine.rgc-seqlock-reader-writer-bundle.v1"),
        "Debug output must contain schema_version"
    );
}

#[test]
fn candidate_inv_debug_contains_bead_id() {
    let c = parse_candidate_inv();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("bd-"), "Debug output must contain bead_id");
}

#[test]
fn candidate_inv_bead_id_contains_dot_separated_segments() {
    let c = parse_candidate_inv();
    // Valid hierarchical bead IDs like "bd-1lsy.7.21.2" have multiple segments
    let suffix = c.bead_id.trim_start_matches("bd-");
    assert!(
        !suffix.is_empty(),
        "bead_id must have content after 'bd-' prefix"
    );
}

#[test]
fn candidate_inv_required_artifacts_nonempty_strings() {
    let c = parse_candidate_inv();
    for a in &c.required_artifacts {
        assert!(!a.trim().is_empty(), "artifact name must not be blank");
    }
}

#[test]
fn candidate_inv_required_artifacts_are_dot_separated_filenames() {
    let c = parse_candidate_inv();
    for a in &c.required_artifacts {
        assert!(
            a.contains('.'),
            "artifact '{a}' must have a file extension (dot separator)"
        );
    }
}

#[test]
fn candidate_inv_reject_candidates_exist() {
    let c = parse_candidate_inv();
    let reject_count = c
        .candidate_expectations
        .iter()
        .filter(|e| e.disposition == "reject")
        .count();
    assert!(
        reject_count >= 1,
        "must have at least one 'reject' candidate, found {reject_count}"
    );
}

#[test]
fn candidate_inv_accept_candidates_exist() {
    let c = parse_candidate_inv();
    let accept_count = c
        .candidate_expectations
        .iter()
        .filter(|e| e.disposition == "accept")
        .count();
    assert!(
        accept_count >= 1,
        "must have at least one 'accept' candidate, found {accept_count}"
    );
}

#[test]
fn candidate_inv_candidate_ids_are_nonempty() {
    let c = parse_candidate_inv();
    for exp in &c.candidate_expectations {
        assert!(
            !exp.candidate_id.trim().is_empty(),
            "candidate_id must not be blank"
        );
    }
}

// --- Seqlock Rollout Guard extra ---

#[test]
fn rollout_guard_clone_equals_original() {
    let g = parse_rollout_guard();
    let cloned = g.clone();
    assert_eq!(g, cloned);
}

#[test]
fn rollout_guard_debug_contains_schema_version() {
    let g = parse_rollout_guard();
    let dbg = format!("{g:?}");
    assert!(
        dbg.contains("franken-engine.rgc-seqlock-rollout-guard-docs.v1"),
        "Debug output must contain schema_version"
    );
}

#[test]
fn rollout_guard_disabled_candidates_are_subset_of_all_candidates() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let all_ids: BTreeSet<&str> = inv
        .candidate_expectations
        .iter()
        .map(|e| e.candidate_id.as_str())
        .collect();
    for disabled in &guard.default_disabled_candidates {
        assert!(
            all_ids.contains(disabled.as_str()),
            "disabled candidate '{disabled}' must appear in candidate inventory"
        );
    }
}

#[test]
fn rollout_guard_required_artifacts_are_dot_separated_filenames() {
    let g = parse_rollout_guard();
    for a in &g.required_artifacts {
        assert!(
            a.contains('.'),
            "artifact '{a}' must have a file extension (dot separator)"
        );
    }
}

#[test]
fn rollout_guard_required_artifacts_nonempty_strings() {
    let g = parse_rollout_guard();
    for a in &g.required_artifacts {
        assert!(!a.trim().is_empty(), "artifact name must not be blank");
    }
}

#[test]
fn rollout_guard_disabled_count_does_not_exceed_accepted_count() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let accepted_count = inv
        .candidate_expectations
        .iter()
        .filter(|e| e.disposition == "accept")
        .count();
    assert!(
        guard.default_disabled_candidates.len() <= accepted_count,
        "disabled candidates ({}) must not exceed accepted candidates ({})",
        guard.default_disabled_candidates.len(),
        accepted_count
    );
}

// --- Persistent Cache Contract extra ---

#[test]
fn cache_clone_equals_original() {
    let c = parse_cache();
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn cache_debug_contains_schema_version() {
    let c = parse_cache();
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains("franken-engine.rgc-persistent-cache-docs.v1"),
        "Debug output must contain schema_version"
    );
}

#[test]
fn cache_key_fields_are_nonempty() {
    let c = parse_cache();
    assert!(!c.key_fields.is_empty(), "key_fields must not be empty");
}

#[test]
fn cache_required_artifacts_nonempty_strings() {
    let c = parse_cache();
    for a in &c.required_artifacts {
        assert!(!a.trim().is_empty(), "artifact name must not be blank");
    }
}

#[test]
fn cache_required_artifacts_are_dot_separated_filenames() {
    let c = parse_cache();
    for a in &c.required_artifacts {
        assert!(
            a.contains('.'),
            "artifact '{a}' must have a file extension (dot separator)"
        );
    }
}

#[test]
fn cache_scenario_ids_are_sorted() {
    let c = parse_cache();
    for window in c.scenario_ids.windows(2) {
        assert!(
            window[0] <= window[1],
            "scenario_ids should be sorted: '{}' should not come after '{}'",
            window[0],
            window[1]
        );
    }
}

#[test]
fn cache_key_fields_include_engine_version_marker() {
    let c = parse_cache();
    let fields: BTreeSet<&str> = c.key_fields.iter().map(String::as_str).collect();
    assert!(
        fields.contains("engine_version_marker"),
        "key_fields must include engine_version_marker"
    );
}

#[test]
fn cache_consumers_include_product_and_benchmark() {
    let c = parse_cache();
    let consumers: BTreeSet<&str> = c.consumers.iter().map(String::as_str).collect();
    assert!(
        consumers.contains("product"),
        "consumers must include 'product'"
    );
    assert!(
        consumers.contains("benchmark"),
        "consumers must include 'benchmark'"
    );
}

// --- Cross-schema invariants ---

#[test]
fn cross_schema_all_bead_ids_start_with_bd_prefix() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    for bead_id in [&inv.bead_id, &guard.bead_id, &cache.bead_id] {
        assert!(
            bead_id.starts_with("bd-"),
            "bead_id must start with 'bd-': {bead_id}"
        );
    }
}

#[test]
fn cross_schema_all_schema_versions_start_with_franken_engine() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    for sv in [
        &inv.schema_version,
        &guard.schema_version,
        &cache.schema_version,
    ] {
        assert!(
            sv.starts_with("franken-engine."),
            "schema_version must start with 'franken-engine.': {sv}"
        );
    }
}

#[test]
fn cross_schema_all_schema_versions_end_with_versioned_suffix() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    for sv in [
        &inv.schema_version,
        &guard.schema_version,
        &cache.schema_version,
    ] {
        // All schema_version strings must end with ".v1" or similar ".vN" suffix
        assert!(
            sv.contains(".v"),
            "schema_version must contain a versioned suffix (.vN): {sv}"
        );
    }
}

#[test]
fn cross_schema_shared_standard_artifacts_appear_in_all_three() {
    let inv = parse_candidate_inv();
    let guard = parse_rollout_guard();
    let cache = parse_cache();
    let inv_set: BTreeSet<&str> = inv.required_artifacts.iter().map(String::as_str).collect();
    let guard_set: BTreeSet<&str> = guard
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    let cache_set: BTreeSet<&str> = cache
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(inv_set.contains(standard), "inv missing: {standard}");
        assert!(guard_set.contains(standard), "guard missing: {standard}");
        assert!(cache_set.contains(standard), "cache missing: {standard}");
    }
}

#[test]
fn cross_schema_raw_json_all_values_are_strings_or_arrays() {
    for (label, raw) in [
        ("candidate_inv", CANDIDATE_INV_JSON),
        ("rollout_guard", ROLLOUT_GUARD_JSON),
        ("cache", CACHE_JSON),
    ] {
        let v: Value = serde_json::from_str(raw).unwrap();
        let obj = v.as_object().unwrap();
        for (key, val) in obj {
            assert!(
                val.is_string() || val.is_array(),
                "{label}: field '{key}' must be string or array, got: {val:?}"
            );
        }
    }
}
