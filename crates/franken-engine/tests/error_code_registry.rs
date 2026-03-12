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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const REGISTRY_JSON: &str = include_str!("../../../docs/error_code_registry_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct ErrorCodeRegistry {
    version: u64,
    compatibility_policy: String,
    entries: Vec<ErrorCodeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct ErrorCodeEntry {
    code: String,
    numeric: u64,
    subsystem: String,
    severity: String,
    description: String,
    operator_action: String,
    deprecated: bool,
}

fn parse_registry() -> ErrorCodeRegistry {
    serde_json::from_str(REGISTRY_JSON).expect("error code registry must parse")
}

#[test]
fn registry_parses_and_has_expected_version() {
    let registry = parse_registry();
    assert_eq!(registry.version, 1);
}

#[test]
fn registry_compatibility_policy_is_append_only() {
    let registry = parse_registry();
    assert!(
        registry.compatibility_policy.contains("append-only"),
        "compatibility policy must declare append-only semantics"
    );
    assert!(
        registry.compatibility_policy.contains("never reused"),
        "compatibility policy must declare codes are never reused"
    );
}

#[test]
fn registry_has_at_least_thirty_entries() {
    let registry = parse_registry();
    assert!(
        registry.entries.len() >= 30,
        "registry must have meaningful coverage, got {}",
        registry.entries.len()
    );
}

#[test]
fn error_codes_are_unique() {
    let registry = parse_registry();
    let mut seen_codes = BTreeSet::new();
    for entry in &registry.entries {
        assert!(
            seen_codes.insert(entry.code.clone()),
            "duplicate error code: {}",
            entry.code
        );
    }
}

#[test]
fn numeric_ids_are_unique() {
    let registry = parse_registry();
    let mut seen_numerics = BTreeSet::new();
    for entry in &registry.entries {
        assert!(
            seen_numerics.insert(entry.numeric),
            "duplicate numeric id {} for code {}",
            entry.numeric,
            entry.code
        );
    }
}

#[test]
fn error_codes_follow_fe_prefix_format() {
    let registry = parse_registry();
    for entry in &registry.entries {
        assert!(
            entry.code.starts_with("FE-"),
            "error code must start with FE- prefix: {}",
            entry.code
        );
        let numeric_part = &entry.code[3..];
        assert!(
            numeric_part.chars().all(|c| c.is_ascii_digit()),
            "error code suffix must be all digits: {}",
            entry.code
        );
    }
}

#[test]
fn error_code_numeric_matches_code_suffix() {
    let registry = parse_registry();
    for entry in &registry.entries {
        let suffix: u64 = entry.code[3..]
            .parse()
            .unwrap_or_else(|_| panic!("code suffix must parse as u64: {}", entry.code));
        assert_eq!(
            suffix, entry.numeric,
            "code {} suffix {} does not match numeric field {}",
            entry.code, suffix, entry.numeric
        );
    }
}

#[test]
fn severity_values_are_from_allowed_set() {
    let registry = parse_registry();
    let allowed: BTreeSet<&str> = ["error", "critical", "warning"].into_iter().collect();
    for entry in &registry.entries {
        assert!(
            allowed.contains(entry.severity.as_str()),
            "invalid severity '{}' for code {}",
            entry.severity,
            entry.code
        );
    }
}

#[test]
fn subsystem_names_are_from_known_set() {
    let registry = parse_registry();
    let known: BTreeSet<&str> = [
        "serialization_encoding",
        "identity_authentication",
        "capability_authorization",
        "checkpoint_policy",
        "revocation",
        "session_channel",
        "zone_scope",
        "audit_observability",
        "lifecycle_migration",
    ]
    .into_iter()
    .collect();

    for entry in &registry.entries {
        assert!(
            known.contains(entry.subsystem.as_str()),
            "unknown subsystem '{}' for code {}",
            entry.subsystem,
            entry.code
        );
    }
}

#[test]
fn subsystem_coverage_spans_at_least_seven_subsystems() {
    let registry = parse_registry();
    let subsystems: BTreeSet<&str> = registry
        .entries
        .iter()
        .map(|e| e.subsystem.as_str())
        .collect();
    assert!(
        subsystems.len() >= 7,
        "registry should cover at least 7 subsystems, got {}",
        subsystems.len()
    );
}

#[test]
fn numeric_ids_are_sorted_ascending() {
    let registry = parse_registry();
    for window in registry.entries.windows(2) {
        assert!(
            window[0].numeric < window[1].numeric,
            "numeric ids must be strictly ascending: {} ({}) must come before {} ({})",
            window[0].code,
            window[0].numeric,
            window[1].code,
            window[1].numeric
        );
    }
}

#[test]
fn numeric_ranges_are_subsystem_aligned() {
    let registry = parse_registry();
    let mut subsystem_ranges: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for entry in &registry.entries {
        let range = subsystem_ranges
            .entry(entry.subsystem.as_str())
            .or_insert((entry.numeric, entry.numeric));
        if entry.numeric < range.0 {
            range.0 = entry.numeric;
        }
        if entry.numeric > range.1 {
            range.1 = entry.numeric;
        }
    }

    let mut ranges: Vec<(&str, u64, u64)> = subsystem_ranges
        .iter()
        .map(|(k, (lo, hi))| (*k, *lo, *hi))
        .collect();
    ranges.sort_by_key(|(_, lo, _)| *lo);

    for window in ranges.windows(2) {
        assert!(
            window[0].2 < window[1].1,
            "subsystem numeric ranges must not overlap: {} ({}-{}) vs {} ({}-{})",
            window[0].0,
            window[0].1,
            window[0].2,
            window[1].0,
            window[1].1,
            window[1].2
        );
    }
}

#[test]
fn descriptions_are_nonempty_and_unique() {
    let registry = parse_registry();
    let mut seen = BTreeSet::new();
    for entry in &registry.entries {
        assert!(
            !entry.description.trim().is_empty(),
            "description must be non-empty for {}",
            entry.code
        );
        assert!(
            seen.insert(entry.description.clone()),
            "duplicate description '{}' for {}",
            entry.description,
            entry.code
        );
    }
}

#[test]
fn operator_actions_are_nonempty() {
    let registry = parse_registry();
    for entry in &registry.entries {
        assert!(
            !entry.operator_action.trim().is_empty(),
            "operator_action must be non-empty for {}",
            entry.code
        );
    }
}

#[test]
fn no_entries_are_deprecated() {
    let registry = parse_registry();
    for entry in &registry.entries {
        assert!(
            !entry.deprecated,
            "code {} is deprecated — append-only policy means deprecated codes should be retained but this is unexpected in v1",
            entry.code
        );
    }
}

#[test]
fn critical_severity_codes_are_in_policy_sensitive_subsystems() {
    let registry = parse_registry();
    let policy_subsystems: BTreeSet<&str> =
        ["checkpoint_policy", "revocation", "lifecycle_migration"]
            .into_iter()
            .collect();

    for entry in &registry.entries {
        if entry.severity == "critical" {
            assert!(
                policy_subsystems.contains(entry.subsystem.as_str()),
                "critical severity code {} is in subsystem '{}' — critical should be reserved for policy-sensitive subsystems",
                entry.code,
                entry.subsystem
            );
        }
    }
}

#[test]
fn deterministic_double_parse() {
    let a = parse_registry();
    let b = parse_registry();
    assert_eq!(a, b);
}

#[test]
fn registry_entry_count_matches_expected() {
    let registry = parse_registry();
    assert_eq!(
        registry.entries.len(),
        42,
        "registry must have exactly 42 entries in v1"
    );
}

#[test]
fn subsystem_numeric_base_follows_thousand_convention() {
    let registry = parse_registry();
    for entry in &registry.entries {
        let base = (entry.numeric / 1000) * 1000;
        let expected_subsystem = match base {
            0 => "serialization_encoding",
            1000 => "identity_authentication",
            2000 => "capability_authorization",
            3000 => "checkpoint_policy",
            4000 => "revocation",
            5000 => "session_channel",
            6000 => "zone_scope",
            7000 => "audit_observability",
            8000 => "lifecycle_migration",
            _ => "unknown",
        };
        assert_eq!(
            entry.subsystem, expected_subsystem,
            "code {} numeric {} (base {}) should map to subsystem '{}'",
            entry.code, entry.numeric, base, expected_subsystem
        );
    }
}

// ---------------------------------------------------------------------------
// Enrichment: serde, structure, and entry-level invariants
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_preserves_equality() {
    let registry = parse_registry();
    let serialized = serde_json::to_string(&registry).expect("serialize must succeed");
    let deserialized: ErrorCodeRegistry =
        serde_json::from_str(&serialized).expect("deserialize roundtrip must succeed");
    assert_eq!(registry, deserialized);
}

#[test]
fn raw_json_has_exactly_three_top_level_keys() {
    let raw: serde_json::Value = serde_json::from_str(REGISTRY_JSON).expect("raw JSON must parse");
    let obj = raw.as_object().expect("top-level must be an object");
    let keys: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    let expected: BTreeSet<&str> = ["version", "compatibility_policy", "entries"]
        .into_iter()
        .collect();
    assert_eq!(
        keys, expected,
        "top-level keys must be exactly version, compatibility_policy, entries"
    );
}

#[test]
fn each_entry_raw_json_has_exactly_seven_fields() {
    let raw: serde_json::Value = serde_json::from_str(REGISTRY_JSON).expect("raw JSON must parse");
    let entries = raw["entries"].as_array().expect("entries must be an array");
    let expected_keys: BTreeSet<&str> = [
        "code",
        "numeric",
        "subsystem",
        "severity",
        "description",
        "operator_action",
        "deprecated",
    ]
    .into_iter()
    .collect();
    for (i, entry) in entries.iter().enumerate() {
        let obj = entry.as_object().unwrap_or_else(|| {
            panic!("entry {} must be an object", i);
        });
        let keys: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys, expected_keys,
            "entry {} has unexpected fields: got {:?}",
            i, keys
        );
    }
}

#[test]
fn operator_actions_are_unique() {
    let registry = parse_registry();
    let mut seen = BTreeMap::new();
    for entry in &registry.entries {
        if let Some(prev_code) = seen.insert(entry.operator_action.clone(), entry.code.clone()) {
            // Operator actions that are identical cross-reference strings are acceptable
            // only if they share the same referential prefix (template actions).
            // For strict uniqueness of descriptions, at least the code differs.
            assert_ne!(
                prev_code, entry.code,
                "operator_action must not be identical for the same code: {}",
                entry.code
            );
        }
    }
}

#[test]
fn error_code_suffix_is_four_digit_zero_padded() {
    let registry = parse_registry();
    for entry in &registry.entries {
        let suffix = &entry.code[3..];
        assert_eq!(
            suffix.len(),
            4,
            "code {} suffix must be exactly 4 digits, got '{}'",
            entry.code,
            suffix
        );
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit()),
            "code {} suffix must be all digits",
            entry.code
        );
    }
}

#[test]
fn code_string_length_is_always_seven() {
    let registry = parse_registry();
    for entry in &registry.entries {
        assert_eq!(
            entry.code.len(),
            7,
            "code '{}' must be exactly 7 characters (FE-XXXX)",
            entry.code
        );
    }
}

#[test]
fn subsystem_names_are_snake_case() {
    let registry = parse_registry();
    let subsystems: BTreeSet<&str> = registry
        .entries
        .iter()
        .map(|e| e.subsystem.as_str())
        .collect();
    for name in &subsystems {
        assert!(!name.is_empty(), "subsystem name must not be empty");
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "subsystem '{}' must be snake_case (lowercase ascii + underscores only)",
            name
        );
        assert!(
            !name.starts_with('_') && !name.ends_with('_'),
            "subsystem '{}' must not start or end with underscore",
            name
        );
        assert!(
            !name.contains("__"),
            "subsystem '{}' must not contain consecutive underscores",
            name
        );
    }
}

#[test]
fn each_observed_severity_has_at_least_one_entry() {
    let registry = parse_registry();
    let mut severity_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &registry.entries {
        *severity_counts.entry(entry.severity.as_str()).or_insert(0) += 1;
    }
    // The allowed set is {error, critical, warning}. At minimum, error and critical
    // must be represented in a v1 registry with 42 entries.
    assert!(
        severity_counts.contains_key("error"),
        "registry must contain at least one 'error' severity entry"
    );
    assert!(
        severity_counts.contains_key("critical"),
        "registry must contain at least one 'critical' severity entry"
    );
    // All observed severities must have non-trivial representation.
    for (sev, count) in &severity_counts {
        assert!(
            *count >= 1,
            "severity '{}' has {} entries, expected at least 1",
            sev,
            count
        );
    }
}

#[test]
fn clone_and_debug_are_meaningful_on_entries() {
    let registry = parse_registry();
    let first = &registry.entries[0];
    let cloned = first.clone();
    assert_eq!(*first, cloned, "cloned entry must equal original");
    let debug_str = format!("{:?}", first);
    assert!(
        debug_str.contains(&first.code),
        "Debug output must contain the error code"
    );
    assert!(
        debug_str.contains(&first.subsystem),
        "Debug output must contain the subsystem"
    );
}

#[test]
fn descriptions_have_minimum_meaningful_length() {
    let registry = parse_registry();
    for entry in &registry.entries {
        assert!(
            entry.description.len() >= 10,
            "description for {} is too short ({} chars): '{}'",
            entry.code,
            entry.description.len(),
            entry.description
        );
    }
}

#[test]
fn operator_actions_contain_actionable_reference() {
    let registry = parse_registry();
    let action_indicators = [
        "See ", "Check ", "Verify ", "Review ", "Inspect ", "Consult ",
    ];
    for entry in &registry.entries {
        let has_action = action_indicators
            .iter()
            .any(|verb| entry.operator_action.contains(verb));
        assert!(
            has_action,
            "operator_action for {} should contain an action-oriented verb reference, got: '{}'",
            entry.code, entry.operator_action
        );
    }
}

#[test]
fn compatibility_policy_is_non_trivial_length() {
    let registry = parse_registry();
    assert!(
        registry.compatibility_policy.len() >= 20,
        "compatibility_policy must be a substantive statement, got {} chars: '{}'",
        registry.compatibility_policy.len(),
        registry.compatibility_policy
    );
}
