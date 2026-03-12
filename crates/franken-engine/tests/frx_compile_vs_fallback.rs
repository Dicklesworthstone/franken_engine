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

const DECISION_JSON: &str = include_str!("../../../docs/frx_compile_vs_fallback_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompileFallbackDecision {
    schema_version: String,
    generated_by: String,
    rules: Vec<DecisionRule>,
    required_evidence_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DecisionRule {
    rule_id: String,
    condition: String,
    decision: String,
    action: String,
}

fn parse_decision() -> CompileFallbackDecision {
    serde_json::from_str(DECISION_JSON).expect("compile-vs-fallback decision must parse")
}

#[test]
fn decision_parses_with_expected_schema_version() {
    let decision = parse_decision();
    assert_eq!(decision.schema_version, "frx.compile-fallback-decision.v1");
}

#[test]
fn decision_has_expected_generated_by() {
    let decision = parse_decision();
    assert!(
        decision.generated_by.starts_with("bd-"),
        "generated_by must reference a bead: {}",
        decision.generated_by
    );
}

#[test]
fn decision_has_expected_rule_count() {
    let decision = parse_decision();
    assert_eq!(
        decision.rules.len(),
        5,
        "must have exactly 5 decision rules"
    );
}

#[test]
fn rule_ids_are_unique() {
    let decision = parse_decision();
    let mut seen = BTreeSet::new();
    for rule in &decision.rules {
        assert!(
            seen.insert(rule.rule_id.clone()),
            "duplicate rule_id: {}",
            rule.rule_id
        );
    }
}

#[test]
fn rule_ids_follow_cf_prefix_format() {
    let decision = parse_decision();
    for rule in &decision.rules {
        assert!(
            rule.rule_id.starts_with("CF-"),
            "rule_id must start with CF-: {}",
            rule.rule_id
        );
        let suffix = &rule.rule_id[3..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit()),
            "rule_id suffix must be numeric: {}",
            rule.rule_id
        );
    }
}

#[test]
fn rules_are_sorted_by_id() {
    let decision = parse_decision();
    for window in decision.rules.windows(2) {
        assert!(
            window[0].rule_id < window[1].rule_id,
            "rules must be sorted: {} should come before {}",
            window[0].rule_id,
            window[1].rule_id
        );
    }
}

#[test]
fn decision_values_are_from_allowed_set() {
    let decision = parse_decision();
    let allowed: BTreeSet<&str> = ["compile_legal", "fallback_required"].into_iter().collect();
    for rule in &decision.rules {
        assert!(
            allowed.contains(rule.decision.as_str()),
            "invalid decision '{}' for {}: must be compile_legal or fallback_required",
            rule.decision,
            rule.rule_id
        );
    }
}

#[test]
fn exactly_one_compile_legal_rule() {
    let decision = parse_decision();
    let compile_count = decision
        .rules
        .iter()
        .filter(|r| r.decision == "compile_legal")
        .count();
    assert_eq!(
        compile_count, 1,
        "must have exactly one compile_legal rule, got {}",
        compile_count
    );
}

#[test]
fn compile_legal_is_first_rule() {
    let decision = parse_decision();
    assert_eq!(
        decision.rules[0].decision, "compile_legal",
        "first rule must be compile_legal (optimistic path)"
    );
}

#[test]
fn all_conditions_are_nonempty() {
    let decision = parse_decision();
    for rule in &decision.rules {
        assert!(
            !rule.condition.trim().is_empty(),
            "condition must not be empty for {}",
            rule.rule_id
        );
    }
}

#[test]
fn all_actions_are_nonempty_and_unique() {
    let decision = parse_decision();
    let mut seen = BTreeSet::new();
    for rule in &decision.rules {
        assert!(
            !rule.action.trim().is_empty(),
            "action must not be empty for {}",
            rule.rule_id
        );
        assert!(
            seen.insert(rule.action.clone()),
            "duplicate action '{}' for {}",
            rule.action,
            rule.rule_id
        );
    }
}

#[test]
fn actions_follow_snake_case_convention() {
    let decision = parse_decision();
    for rule in &decision.rules {
        assert!(
            rule.action
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "action must be snake_case: {} for {}",
            rule.action,
            rule.rule_id
        );
    }
}

#[test]
fn required_evidence_fields_are_nonempty_and_unique() {
    let decision = parse_decision();
    let mut seen = BTreeSet::new();
    for field in &decision.required_evidence_fields {
        assert!(!field.trim().is_empty(), "evidence field must not be empty");
        assert!(
            seen.insert(field.clone()),
            "duplicate evidence field: {field}"
        );
    }
}

#[test]
fn required_evidence_fields_include_traceability_core() {
    let decision = parse_decision();
    let fields: BTreeSet<&str> = decision
        .required_evidence_fields
        .iter()
        .map(String::as_str)
        .collect();
    for required in ["trace_id", "decision_id", "policy_id"] {
        assert!(
            fields.contains(required),
            "missing core traceability field: {required}"
        );
    }
}

#[test]
fn evidence_fields_follow_snake_case() {
    let decision = parse_decision();
    for field in &decision.required_evidence_fields {
        assert!(
            field
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "evidence field must be snake_case: {field}"
        );
    }
}

#[test]
fn top_level_keys_match_expected_schema() {
    let raw: Value = serde_json::from_str(DECISION_JSON).expect("must parse as Value");
    let obj = raw.as_object().expect("must be a JSON object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "generated_by",
            "rules",
            "required_evidence_fields"
        ])
    );
}

#[test]
fn deterministic_double_parse() {
    let a = parse_decision();
    let b = parse_decision();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Enrichment: serde, structure, and decision semantics
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_preserves_all_fields() {
    let decision = parse_decision();
    let json = serde_json::to_string(&decision).unwrap();
    let reparsed: CompileFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, reparsed);
}

#[test]
fn fallback_rules_outnumber_compile_rules() {
    let decision = parse_decision();
    let fallback_count = decision
        .rules
        .iter()
        .filter(|r| r.decision == "fallback_required")
        .count();
    let compile_count = decision
        .rules
        .iter()
        .filter(|r| r.decision == "compile_legal")
        .count();
    assert!(
        fallback_count > compile_count,
        "fallback rules ({fallback_count}) must outnumber compile rules ({compile_count}) — fail-closed posture"
    );
}

#[test]
fn last_rule_is_fallback_required() {
    let decision = parse_decision();
    let last = decision.rules.last().unwrap();
    assert_eq!(
        last.decision, "fallback_required",
        "last rule must be fallback_required (catch-all / fail-closed)"
    );
}

#[test]
fn conditions_reference_observable_signals() {
    let decision = parse_decision();
    // Each condition should reference at least one signal that operators can observe
    for rule in &decision.rules {
        assert!(
            rule.condition.len() > 10,
            "condition for {} must be descriptive (got {} chars)",
            rule.rule_id,
            rule.condition.len()
        );
    }
}

#[test]
fn rule_ids_are_sequential_from_one() {
    let decision = parse_decision();
    for (i, rule) in decision.rules.iter().enumerate() {
        let expected_id = format!("CF-{:03}", i + 1);
        assert_eq!(
            rule.rule_id, expected_id,
            "rule {} should have id {expected_id}, got {}",
            i, rule.rule_id
        );
    }
}

#[test]
fn raw_json_rules_array_elements_have_four_fields() {
    let raw: Value = serde_json::from_str(DECISION_JSON).unwrap();
    let rules = raw["rules"].as_array().unwrap();
    for (i, rule) in rules.iter().enumerate() {
        let obj = rule.as_object().unwrap();
        assert_eq!(
            obj.len(),
            4,
            "rule {i} must have exactly 4 fields (rule_id, condition, decision, action), got {}",
            obj.len()
        );
    }
}

#[test]
fn required_evidence_fields_count_at_least_five() {
    let decision = parse_decision();
    assert!(
        decision.required_evidence_fields.len() >= 5,
        "must have at least 5 evidence fields for meaningful traceability, got {}",
        decision.required_evidence_fields.len()
    );
}

#[test]
fn schema_version_follows_frx_prefix() {
    let decision = parse_decision();
    assert!(
        decision.schema_version.starts_with("frx."),
        "schema_version must start with frx. prefix: {}",
        decision.schema_version
    );
}

#[test]
fn decision_rule_clone_equality() {
    let decision = parse_decision();
    for rule in &decision.rules {
        let cloned = rule.clone();
        assert_eq!(rule, &cloned);
    }
}

#[test]
fn decision_rule_debug_contains_rule_id() {
    let decision = parse_decision();
    for rule in &decision.rules {
        let debug = format!("{:?}", rule);
        assert!(
            debug.contains(&rule.rule_id),
            "Debug output must contain rule_id"
        );
    }
}

#[test]
fn generated_by_references_valid_bead_hierarchy() {
    let decision = parse_decision();
    let bead_id = &decision.generated_by;
    assert!(bead_id.starts_with("bd-"), "must start with bd-");
    // Should have at least one dot for hierarchical bead
    assert!(
        bead_id.contains('.'),
        "generated_by must be a hierarchical bead id"
    );
}

#[test]
fn conditions_are_distinct_across_rules() {
    let decision = parse_decision();
    let mut conditions = BTreeSet::new();
    for rule in &decision.rules {
        assert!(
            conditions.insert(rule.condition.clone()),
            "duplicate condition for {}: {}",
            rule.rule_id,
            rule.condition
        );
    }
}
