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

use serde::{Deserialize, Serialize};
use serde_json::Value;

const FORBIDDEN_REGRESSIONS_JSON: &str =
    include_str!("../../../docs/frx_forbidden_regressions_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForbiddenRegressions {
    schema_version: String,
    generated_by: String,
    entries: Vec<ForbiddenRegressionEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForbiddenRegressionEntry {
    id: String,
    invariant: String,
    description: String,
    severity: String,
    detection: String,
    fixture_ref: String,
}

fn parse_regressions() -> ForbiddenRegressions {
    serde_json::from_str(FORBIDDEN_REGRESSIONS_JSON)
        .expect("forbidden regressions manifest must parse")
}

#[test]
fn manifest_parses_with_expected_schema_version() {
    let regressions = parse_regressions();
    assert_eq!(regressions.schema_version, "frx.forbidden-regressions.v1");
}

#[test]
fn manifest_has_expected_generated_by() {
    let regressions = parse_regressions();
    assert!(
        regressions.generated_by.starts_with("bd-"),
        "generated_by must reference a bead: {}",
        regressions.generated_by
    );
}

#[test]
fn manifest_has_expected_entry_count() {
    let regressions = parse_regressions();
    assert_eq!(
        regressions.entries.len(),
        8,
        "must have exactly 8 forbidden regression entries"
    );
}

#[test]
fn entry_ids_are_unique() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        assert!(
            seen.insert(entry.id.clone()),
            "duplicate entry id: {}",
            entry.id
        );
    }
}

#[test]
fn entry_ids_follow_fr_ci_prefix_format() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            entry.id.starts_with("FR-CI-"),
            "entry id must start with FR-CI-: {}",
            entry.id
        );
        let suffix = &entry.id[6..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit()),
            "entry id suffix must be numeric: {}",
            entry.id
        );
    }
}

#[test]
fn invariant_ids_are_unique() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        assert!(
            seen.insert(entry.invariant.clone()),
            "duplicate invariant id: {}",
            entry.invariant
        );
    }
}

#[test]
fn invariant_ids_follow_ci_prefix_format() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            entry.invariant.starts_with("CI-"),
            "invariant must start with CI-: {}",
            entry.invariant
        );
    }
}

#[test]
fn severity_values_are_from_allowed_set() {
    let regressions = parse_regressions();
    let allowed: BTreeSet<&str> = ["critical", "high"].into_iter().collect();
    for entry in &regressions.entries {
        assert!(
            allowed.contains(entry.severity.as_str()),
            "invalid severity '{}' for {}: forbidden regressions should be critical or high",
            entry.severity,
            entry.id
        );
    }
}

#[test]
fn critical_entries_exist() {
    let regressions = parse_regressions();
    let critical_count = regressions
        .entries
        .iter()
        .filter(|e| e.severity == "critical")
        .count();
    assert!(
        critical_count >= 3,
        "must have at least 3 critical regressions, got {}",
        critical_count
    );
}

#[test]
fn descriptions_are_nonempty_and_unique() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        assert!(
            !entry.description.trim().is_empty(),
            "description must be non-empty for {}",
            entry.id
        );
        assert!(
            seen.insert(entry.description.clone()),
            "duplicate description for {}",
            entry.id
        );
    }
}

#[test]
fn detection_methods_are_nonempty() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            !entry.detection.trim().is_empty(),
            "detection method must be non-empty for {}",
            entry.id
        );
    }
}

#[test]
fn detection_methods_end_with_oracle_or_diff() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            entry.detection.ends_with("_oracle") || entry.detection.ends_with("_diff"),
            "detection method must end with _oracle or _diff: {} for {}",
            entry.detection,
            entry.id
        );
    }
}

#[test]
fn fixture_refs_follow_compat_namespace_pattern() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            entry.fixture_ref.starts_with("compat."),
            "fixture_ref must start with compat. namespace: {} for {}",
            entry.fixture_ref,
            entry.id
        );
        assert!(
            entry.fixture_ref.ends_with(".*"),
            "fixture_ref must use glob pattern (end with .*): {} for {}",
            entry.fixture_ref,
            entry.id
        );
    }
}

#[test]
fn fixture_refs_are_unique() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        assert!(
            seen.insert(entry.fixture_ref.clone()),
            "duplicate fixture_ref: {}",
            entry.fixture_ref
        );
    }
}

#[test]
fn entries_are_sorted_by_id() {
    let regressions = parse_regressions();
    for window in regressions.entries.windows(2) {
        assert!(
            window[0].id < window[1].id,
            "entries must be sorted by id: {} should come before {}",
            window[0].id,
            window[1].id
        );
    }
}

#[test]
fn top_level_keys_match_expected_schema() {
    let raw: Value = serde_json::from_str(FORBIDDEN_REGRESSIONS_JSON).expect("must parse as Value");
    let obj = raw.as_object().expect("must be a JSON object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from(["schema_version", "generated_by", "entries"])
    );
}

#[test]
fn deterministic_double_parse() {
    let a = parse_regressions();
    let b = parse_regressions();
    assert_eq!(a, b);
}

#[test]
fn fixture_ref_namespace_covers_expected_categories() {
    let regressions = parse_regressions();
    let categories: BTreeSet<&str> = regressions
        .entries
        .iter()
        .map(|e| {
            let parts: Vec<&str> = e.fixture_ref.splitn(3, '.').collect();
            parts[1]
        })
        .collect();

    for expected in [
        "render",
        "hooks",
        "effects",
        "errors",
        "suspense",
        "hydration",
        "state",
        "events",
    ] {
        assert!(
            categories.contains(expected),
            "missing fixture category: {}",
            expected
        );
    }
}

// ---------------------------------------------------------------------------
// Enrichment: serde, structure, and entry-level invariants
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_preserves_manifest() {
    let original = parse_regressions();
    let serialized = serde_json::to_string(&original).expect("serialize must succeed");
    let deserialized: ForbiddenRegressions =
        serde_json::from_str(&serialized).expect("roundtrip deserialize must succeed");
    assert_eq!(original, deserialized);
}

#[test]
fn entry_ids_are_sequential_from_001_through_008() {
    let regressions = parse_regressions();
    for (i, entry) in regressions.entries.iter().enumerate() {
        let expected = format!("FR-CI-{:03}", i + 1);
        assert_eq!(
            entry.id, expected,
            "entry at index {} should be {} but was {}",
            i, expected, entry.id
        );
    }
}

#[test]
fn each_raw_entry_has_exactly_six_fields() {
    let raw: Value = serde_json::from_str(FORBIDDEN_REGRESSIONS_JSON).expect("must parse");
    let entries = raw["entries"].as_array().expect("entries must be array");
    for (i, entry) in entries.iter().enumerate() {
        let obj = entry.as_object().expect("entry must be object");
        assert_eq!(
            obj.len(),
            6,
            "entry at index {} has {} fields, expected 6",
            i,
            obj.len()
        );
    }
}

#[test]
fn generated_by_is_hierarchical_bead_reference() {
    let regressions = parse_regressions();
    assert!(
        regressions.generated_by.contains('.'),
        "generated_by should be a hierarchical bead reference (contain '.'): {}",
        regressions.generated_by
    );
}

#[test]
fn schema_version_follows_frx_prefix() {
    let regressions = parse_regressions();
    assert!(
        regressions.schema_version.starts_with("frx."),
        "schema_version must start with frx. prefix: {}",
        regressions.schema_version
    );
}

#[test]
fn high_severity_entries_exist() {
    let regressions = parse_regressions();
    let high_count = regressions
        .entries
        .iter()
        .filter(|e| e.severity == "high")
        .count();
    assert!(
        high_count >= 1,
        "must have at least 1 high-severity entry, got {}",
        high_count
    );
}

#[test]
fn detection_methods_are_unique() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        assert!(
            seen.insert(entry.detection.clone()),
            "duplicate detection method: {} (entry {})",
            entry.detection,
            entry.id
        );
    }
}

#[test]
fn detection_methods_follow_snake_case() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            !entry.detection.is_empty(),
            "detection must not be empty for {}",
            entry.id
        );
        for ch in entry.detection.chars() {
            assert!(
                ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit(),
                "detection '{}' for {} contains non-snake_case char '{}'",
                entry.detection,
                entry.id,
                ch
            );
        }
    }
}

#[test]
fn invariant_ids_contain_subsystem_segment() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        let after_ci = entry.invariant.strip_prefix("CI-").unwrap_or("");
        assert!(
            after_ci.contains('-'),
            "invariant '{}' for {} should reference a subsystem (contain '-' after CI-)",
            entry.invariant,
            entry.id
        );
    }
}

#[test]
fn descriptions_have_minimum_meaningful_length() {
    let regressions = parse_regressions();
    let min_len = 20;
    for entry in &regressions.entries {
        assert!(
            entry.description.len() >= min_len,
            "description for {} is too short ({} chars, minimum {}): '{}'",
            entry.id,
            entry.description.len(),
            min_len,
            entry.description
        );
    }
}

#[test]
fn clone_and_debug_derive_verification() {
    let regressions = parse_regressions();
    let cloned = regressions.clone();
    assert_eq!(regressions, cloned);
    let debug_str = format!("{:?}", regressions);
    assert!(
        debug_str.contains("ForbiddenRegressions"),
        "Debug output must contain struct name"
    );
    assert!(
        debug_str.contains("FR-CI-001"),
        "Debug output must contain entry data"
    );
}

#[test]
fn entry_count_matches_raw_json_array_length() {
    let regressions = parse_regressions();
    let raw: Value = serde_json::from_str(FORBIDDEN_REGRESSIONS_JSON).expect("must parse");
    let raw_entries = raw["entries"].as_array().expect("entries must be array");
    assert_eq!(
        regressions.entries.len(),
        raw_entries.len(),
        "typed entry count must match raw JSON array length"
    );
}

// ---------------------------------------------------------------------------
// Enrichment batch 2: deeper structural and semantic invariants
// ---------------------------------------------------------------------------

#[test]
fn all_invariant_values_are_nonempty() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            !entry.invariant.trim().is_empty(),
            "invariant must be non-empty for entry {}",
            entry.id
        );
    }
}

#[test]
fn individual_entry_serde_roundtrip() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        let serialized = serde_json::to_string(entry).expect("entry must serialize");
        let deserialized: ForbiddenRegressionEntry =
            serde_json::from_str(&serialized).expect("entry must deserialize");
        assert_eq!(*entry, deserialized, "roundtrip mismatch for {}", entry.id);
    }
}

#[test]
fn fixture_ref_contains_exactly_two_dots() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        let dot_count = entry.fixture_ref.chars().filter(|c| *c == '.').count();
        assert_eq!(
            dot_count, 2,
            "fixture_ref '{}' for {} must contain exactly 2 dots (compat.X.*)",
            entry.fixture_ref, entry.id
        );
    }
}

#[test]
fn severity_distribution_is_not_uniform() {
    let regressions = parse_regressions();
    let critical = regressions
        .entries
        .iter()
        .filter(|e| e.severity == "critical")
        .count();
    let high = regressions
        .entries
        .iter()
        .filter(|e| e.severity == "high")
        .count();
    assert!(
        critical != high || regressions.entries.len() <= 2,
        "severity distribution should vary: critical={}, high={}",
        critical,
        high
    );
}

#[test]
fn schema_version_ends_with_v1() {
    let regressions = parse_regressions();
    assert!(
        regressions.schema_version.ends_with(".v1"),
        "schema_version must end with .v1: {}",
        regressions.schema_version
    );
}

#[test]
fn raw_json_entry_values_are_all_strings() {
    let raw: Value = serde_json::from_str(FORBIDDEN_REGRESSIONS_JSON).expect("must parse");
    let entries = raw["entries"].as_array().expect("entries must be array");
    for (i, entry) in entries.iter().enumerate() {
        let obj = entry.as_object().expect("entry must be object");
        for (key, val) in obj {
            assert!(
                val.is_string(),
                "entry {} field '{}' must be a string, got {:?}",
                i,
                key,
                val
            );
        }
    }
}

#[test]
fn entry_description_word_count_minimum() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        let word_count = entry.description.split_whitespace().count();
        assert!(
            word_count >= 3,
            "description for {} has only {} words, need at least 3: '{}'",
            entry.id,
            word_count,
            entry.description
        );
    }
}

#[test]
fn invariant_ids_are_sorted_ascending() {
    let regressions = parse_regressions();
    let invariants: Vec<&str> = regressions
        .entries
        .iter()
        .map(|e| e.invariant.as_str())
        .collect();
    for window in invariants.windows(2) {
        assert!(
            window[0] <= window[1],
            "invariants must be sorted: '{}' should come before '{}'",
            window[0],
            window[1]
        );
    }
}

#[test]
fn clone_independence_on_entries() {
    let regressions = parse_regressions();
    let mut cloned = regressions.clone();
    cloned.entries[0].id = "FR-CI-999".to_string();
    assert_ne!(
        regressions.entries[0].id, cloned.entries[0].id,
        "clone must be independent of original"
    );
}

#[test]
fn all_string_fields_are_trimmed() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert_eq!(entry.id, entry.id.trim(), "id not trimmed for {}", entry.id);
        assert_eq!(
            entry.invariant,
            entry.invariant.trim(),
            "invariant not trimmed for {}",
            entry.id
        );
        assert_eq!(
            entry.description,
            entry.description.trim(),
            "description not trimmed for {}",
            entry.id
        );
        assert_eq!(
            entry.severity,
            entry.severity.trim(),
            "severity not trimmed for {}",
            entry.id
        );
        assert_eq!(
            entry.detection,
            entry.detection.trim(),
            "detection not trimmed for {}",
            entry.id
        );
        assert_eq!(
            entry.fixture_ref,
            entry.fixture_ref.trim(),
            "fixture_ref not trimmed for {}",
            entry.id
        );
    }
}

#[test]
fn entry_fields_contain_no_control_characters() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        for (field_name, val) in [
            ("id", &entry.id),
            ("invariant", &entry.invariant),
            ("description", &entry.description),
            ("severity", &entry.severity),
            ("detection", &entry.detection),
            ("fixture_ref", &entry.fixture_ref),
        ] {
            assert!(
                !val.chars().any(|c| c.is_control()),
                "{} for {} contains control characters",
                field_name,
                entry.id
            );
        }
    }
}

#[test]
fn fixture_ref_middle_segment_is_lowercase_alpha() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        let parts: Vec<&str> = entry.fixture_ref.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "fixture_ref must have 3 dot-segments");
        let middle = parts[1];
        assert!(
            !middle.is_empty(),
            "fixture_ref middle segment must not be empty for {}",
            entry.id
        );
        assert!(
            middle.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "fixture_ref middle segment '{}' must be lowercase alpha or underscore for {}",
            middle,
            entry.id
        );
    }
}

#[test]
fn manifest_json_size_is_reasonable() {
    assert!(
        FORBIDDEN_REGRESSIONS_JSON.len() < 100_000,
        "manifest JSON should be < 100KB, got {} bytes",
        FORBIDDEN_REGRESSIONS_JSON.len()
    );
    assert!(
        FORBIDDEN_REGRESSIONS_JSON.len() > 100,
        "manifest JSON should be > 100 bytes, got {} bytes",
        FORBIDDEN_REGRESSIONS_JSON.len()
    );
}

#[test]
fn manifest_serde_to_pretty_json_has_entries_key() {
    let regressions = parse_regressions();
    let pretty = serde_json::to_string_pretty(&regressions).expect("pretty serialize");
    assert!(
        pretty.contains("\"entries\""),
        "pretty JSON must contain entries key"
    );
    assert!(
        pretty.contains("\"schema_version\""),
        "pretty JSON must contain schema_version key"
    );
}

#[test]
fn all_detection_methods_have_underscore() {
    let regressions = parse_regressions();
    for entry in &regressions.entries {
        assert!(
            entry.detection.contains('_'),
            "detection method '{}' for {} should contain at least one underscore (compound_name)",
            entry.detection,
            entry.id
        );
    }
}

#[test]
fn generated_by_has_at_least_two_segments() {
    let regressions = parse_regressions();
    let segments: Vec<&str> = regressions.generated_by.split('.').collect();
    assert!(
        segments.len() >= 2,
        "generated_by '{}' should have at least 2 dot-separated segments",
        regressions.generated_by
    );
}

#[test]
fn no_duplicate_entry_field_combinations() {
    let regressions = parse_regressions();
    let mut seen = BTreeSet::new();
    for entry in &regressions.entries {
        let key = format!("{}|{}|{}", entry.invariant, entry.severity, entry.detection);
        assert!(
            seen.insert(key.clone()),
            "duplicate invariant+severity+detection combination: {}",
            key
        );
    }
}

#[test]
fn manifest_eq_impl_is_symmetric() {
    let a = parse_regressions();
    let b = parse_regressions();
    assert_eq!(a, b, "Eq must be symmetric");
}
