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

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "frx.incremental-adoption-controls.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/frx_incremental_adoption_controls_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdoptionControlsContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    rollout_axes: Vec<String>,
    policy_toggles: BTreeMap<String, PolicyToggle>,
    canary_flow: CanaryFlow,
    migration_diagnostics: Vec<MigrationDiagnostic>,
    required_structured_log_fields: Vec<String>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyToggle {
    required: bool,
    default: bool,
    description: String,
    fallback_route: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryFlow {
    stages: Vec<String>,
    allowed_transitions: Vec<CanaryTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryTransition {
    from: String,
    to: String,
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationDiagnostic {
    diagnostic_code: String,
    compatibility_class: String,
    fallback_route: String,
    remediation_id: String,
    remediation_summary: String,
    owner_lane: String,
    target_milestone: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> AdoptionControlsContract {
    serde_json::from_str(CONTRACT_JSON).expect("incremental adoption controls json must parse")
}

#[test]
fn frx_07_4_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Incremental Adoption Controls v1",
        "## Scope",
        "## Rollout Axes and Opt-In Granularity",
        "## Policy Opt-Out and Force-Fallback Toggles",
        "## Canary and Rollback Flow",
        "## Migration Diagnostics and Remediation UX",
        "## Deterministic Logging and Evidence Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_07_4_contract_is_versioned_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.7.4");
    assert_eq!(contract.generated_by, "bd-mjh3.7.4");
    assert_eq!(contract.track.id, "FRX-07.4");
    assert!(
        contract
            .track
            .name
            .contains("Incremental Adoption Controls")
    );
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_07_4_rollout_axes_and_policy_toggles_are_complete() {
    let contract = parse_contract();

    let axes: BTreeSet<&str> = contract.rollout_axes.iter().map(String::as_str).collect();
    let expected_axes: BTreeSet<&str> = ["file", "component", "route", "policy"]
        .into_iter()
        .collect();
    assert_eq!(axes, expected_axes);

    for toggle_name in [
        "force_fallback",
        "policy_opt_out",
        "denylist_opt_out",
        "canary_pause",
    ] {
        let toggle = contract
            .policy_toggles
            .get(toggle_name)
            .unwrap_or_else(|| panic!("missing policy toggle: {toggle_name}"));
        assert!(toggle.required, "toggle must be required: {toggle_name}");
        assert!(!toggle.description.trim().is_empty());
        assert!(!toggle.fallback_route.trim().is_empty());
    }

    let fallback_routes: BTreeSet<&str> = contract
        .policy_toggles
        .values()
        .map(|toggle| toggle.fallback_route.as_str())
        .collect();
    assert!(fallback_routes.contains("compatibility_fallback"));
    assert!(fallback_routes.contains("deterministic_safe_mode"));
}

#[test]
fn frx_07_4_canary_flow_contains_required_promote_and_rollback_paths() {
    let contract = parse_contract();

    let stages: BTreeSet<&str> = contract
        .canary_flow
        .stages
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = ["shadow", "canary", "ramp", "active"].into_iter().collect();
    assert_eq!(stages, expected);

    let transitions: BTreeSet<(String, String, String)> = contract
        .canary_flow
        .allowed_transitions
        .iter()
        .map(|t| (t.from.clone(), t.to.clone(), t.kind.clone()))
        .collect();

    for expected in [
        ("shadow", "canary", "promote"),
        ("canary", "ramp", "promote"),
        ("ramp", "active", "promote"),
        ("canary", "shadow", "rollback"),
        ("ramp", "canary", "rollback"),
        ("active", "canary", "rollback"),
    ] {
        assert!(
            transitions.contains(&(
                expected.0.to_string(),
                expected.1.to_string(),
                expected.2.to_string()
            )),
            "missing canary transition: {} -> {} ({})",
            expected.0,
            expected.1,
            expected.2
        );
    }
}

#[test]
fn frx_07_4_migration_diagnostics_are_actionable_and_fail_closed() {
    let contract = parse_contract();

    assert!(
        contract.migration_diagnostics.len() >= 3,
        "expected at least three migration diagnostics"
    );

    for diagnostic in &contract.migration_diagnostics {
        assert!(diagnostic.diagnostic_code.starts_with("FRX-MIG-"));
        assert!(!diagnostic.compatibility_class.trim().is_empty());
        assert!(!diagnostic.remediation_id.trim().is_empty());
        assert!(!diagnostic.remediation_summary.trim().is_empty());
        assert!(!diagnostic.owner_lane.trim().is_empty());
        assert!(diagnostic.target_milestone.starts_with("FRX-07."));
        assert!(
            ["compatibility_fallback", "deterministic_safe_mode"]
                .contains(&diagnostic.fallback_route.as_str()),
            "invalid fallback route for diagnostic {}: {}",
            diagnostic.diagnostic_code,
            diagnostic.fallback_route
        );
    }
}

#[test]
fn frx_07_4_contract_matches_runtime_surfaces_and_logging_requirements() {
    let contract = parse_contract();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("run_frx_incremental_adoption_controls_suite.sh ci") }),
        "operator verification must include CI gate command"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| line.contains("frx_incremental_adoption_controls_replay.sh")),
        "operator verification must include replay command"
    );

    let activation =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/activation_lifecycle.rs"))
            .expect("activation_lifecycle source must exist");
    for snippet in [
        "RolloutPhase",
        "Canary",
        "advance_rollout",
        "pub fn rollback",
    ] {
        assert!(
            activation.contains(snippet),
            "activation_lifecycle missing: {snippet}"
        );
    }

    let migration_kit =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/migration_kit.rs"))
            .expect("migration_kit source must exist");
    for snippet in ["MigrationManifest", "CompatibilityReport", "MigrationEvent"] {
        assert!(
            migration_kit.contains(snippet),
            "migration_kit missing: {snippet}"
        );
    }

    let safe_mode =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/safe_mode_fallback.rs"))
            .expect("safe_mode_fallback source must exist");
    for snippet in ["SafeModeManager", "FailureType", "SafeModeEvent"] {
        assert!(
            safe_mode.contains(snippet),
            "safe_mode_fallback missing: {snippet}"
        );
    }
}

#[test]
fn frx_07_4_canary_flow_has_no_self_transitions() {
    let contract = parse_contract();
    for t in &contract.canary_flow.allowed_transitions {
        assert_ne!(
            t.from, t.to,
            "self-transition not allowed: {} -> {}",
            t.from, t.to
        );
    }
}

#[test]
fn frx_07_4_transition_kinds_are_promote_or_rollback() {
    let contract = parse_contract();
    let allowed_kinds: BTreeSet<&str> = ["promote", "rollback"].into_iter().collect();
    for t in &contract.canary_flow.allowed_transitions {
        assert!(
            allowed_kinds.contains(t.kind.as_str()),
            "invalid transition kind: {} (from {} to {})",
            t.kind,
            t.from,
            t.to
        );
    }
}

#[test]
fn frx_07_4_diagnostic_codes_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for d in &contract.migration_diagnostics {
        assert!(
            seen.insert(&d.diagnostic_code),
            "duplicate diagnostic_code: {}",
            d.diagnostic_code
        );
    }
}

#[test]
fn frx_07_4_policy_toggle_defaults_are_consistent() {
    let contract = parse_contract();
    for (name, toggle) in &contract.policy_toggles {
        // required toggles should default to false (opt-in safety)
        if toggle.required {
            assert!(
                !toggle.default,
                "required toggle {} should default to false for safety",
                name
            );
        }
    }
}

#[test]
fn frx_07_4_serde_roundtrip_preserves_contract() {
    let contract = parse_contract();
    let serialized = serde_json::to_string(&contract).expect("serialize");
    let deserialized: AdoptionControlsContract =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(contract, deserialized);
}

#[test]
fn frx_07_4_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn frx_07_4_canary_stages_cover_full_lifecycle() {
    let contract = parse_contract();
    let stages: BTreeSet<&str> = contract
        .canary_flow
        .stages
        .iter()
        .map(String::as_str)
        .collect();
    // every transition endpoint must be a valid stage
    for t in &contract.canary_flow.allowed_transitions {
        assert!(
            stages.contains(t.from.as_str()),
            "transition from unknown stage: {}",
            t.from
        );
        assert!(
            stages.contains(t.to.as_str()),
            "transition to unknown stage: {}",
            t.to
        );
    }
}

#[test]
fn frx_07_4_rollout_axes_are_nonempty_strings() {
    let contract = parse_contract();
    assert!(!contract.rollout_axes.is_empty());
    for axis in &contract.rollout_axes {
        assert!(!axis.trim().is_empty(), "rollout axis must not be empty");
    }
}

#[test]
fn frx_07_4_doc_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn frx_07_4_policy_toggle_names_are_all_present() {
    let contract = parse_contract();
    let toggle_names: BTreeSet<&str> = contract.policy_toggles.keys().map(String::as_str).collect();
    for expected in [
        "force_fallback",
        "policy_opt_out",
        "denylist_opt_out",
        "canary_pause",
    ] {
        assert!(
            toggle_names.contains(expected),
            "missing toggle: {expected}"
        );
    }
}

#[test]
fn frx_07_4_operator_verification_has_json_validation() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty")),
        "operator verification must include JSON validation"
    );
}

#[test]
fn frx_07_4_canary_flow_transitions_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for t in &contract.canary_flow.allowed_transitions {
        assert!(
            seen.insert((&t.from, &t.to, &t.kind)),
            "duplicate transition: {} -> {} ({})",
            t.from,
            t.to,
            t.kind
        );
    }
}

#[test]
fn frx_07_4_remediation_ids_are_nonempty_and_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for d in &contract.migration_diagnostics {
        assert!(
            !d.remediation_id.trim().is_empty(),
            "remediation_id must not be empty for {}",
            d.diagnostic_code
        );
        assert!(
            seen.insert(&d.remediation_id),
            "duplicate remediation_id: {}",
            d.remediation_id
        );
    }
}

#[test]
fn frx_07_4_contract_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
}

#[test]
fn frx_07_4_contract_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn frx_07_4_contract_has_nonempty_generated_by() {
    let contract = parse_contract();
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn frx_07_4_contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn frx_07_4_contract_has_nonempty_track_id() {
    let contract = parse_contract();
    assert!(!contract.track.id.trim().is_empty());
}

#[test]
fn frx_07_4_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

// ---------- enrichment: deeper edge-case and structural tests ----------

#[test]
fn frx_07_4_canary_flow_promote_chain_reaches_active() {
    // Verify the promote transitions form a path from shadow to active
    let contract = parse_contract();
    let promotes: BTreeMap<&str, &str> = contract
        .canary_flow
        .allowed_transitions
        .iter()
        .filter(|t| t.kind == "promote")
        .map(|t| (t.from.as_str(), t.to.as_str()))
        .collect();
    // Walk the promote chain from "shadow"
    let mut current = "shadow";
    let mut steps = 0;
    while current != "active" {
        current = promotes
            .get(current)
            .unwrap_or_else(|| panic!("no promote transition from '{current}'"));
        steps += 1;
        assert!(steps <= 10, "infinite promote chain detected");
    }
    assert!(
        steps >= 2,
        "promote chain must have at least 2 steps (shadow->...->active)"
    );
}

#[test]
fn frx_07_4_every_rollback_target_is_a_prior_promote_stage() {
    // Rollback targets should only go to stages that appear earlier in the promote chain
    let contract = parse_contract();
    let stage_order: BTreeMap<&str, usize> = contract
        .canary_flow
        .stages
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();
    for t in &contract.canary_flow.allowed_transitions {
        if t.kind == "rollback" {
            let from_idx = stage_order.get(t.from.as_str()).expect("from stage");
            let to_idx = stage_order.get(t.to.as_str()).expect("to stage");
            assert!(
                to_idx < from_idx,
                "rollback must go to an earlier stage: {} -> {} but {} >= {}",
                t.from,
                t.to,
                to_idx,
                from_idx
            );
        }
    }
}

#[test]
fn frx_07_4_migration_diagnostics_owner_lanes_are_nonempty_strings() {
    let contract = parse_contract();
    let mut lanes = BTreeSet::new();
    for d in &contract.migration_diagnostics {
        assert!(
            !d.owner_lane.trim().is_empty(),
            "owner_lane must not be empty for {}",
            d.diagnostic_code
        );
        lanes.insert(d.owner_lane.as_str());
    }
    // at least one lane must own diagnostics
    assert!(
        !lanes.is_empty(),
        "expected diagnostics owned by at least 1 lane, got 0"
    );
}

#[test]
fn frx_07_4_serde_roundtrip_via_pretty_print_preserves_contract() {
    let contract = parse_contract();
    let pretty = serde_json::to_string_pretty(&contract).expect("serialize pretty");
    let recovered: AdoptionControlsContract =
        serde_json::from_str(&pretty).expect("deserialize from pretty");
    assert_eq!(contract, recovered);
}

#[test]
fn frx_07_4_required_structured_log_fields_are_unique() {
    let contract = parse_contract();
    let fields = &contract.required_structured_log_fields;
    let unique: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        fields.len(),
        "duplicate structured log fields detected"
    );
}

// ---------- enrichment: additional edge-case tests ----------

#[test]
fn frx_07_4_doc_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "adoption controls doc must not contain unresolved TODO/FIXME/XXX markers"
    );
}

#[test]
fn frx_07_4_all_policy_toggle_fallback_routes_are_known() {
    let contract = parse_contract();
    let known_routes: BTreeSet<&str> = ["compatibility_fallback", "deterministic_safe_mode"]
        .into_iter()
        .collect();
    for (name, toggle) in &contract.policy_toggles {
        assert!(
            known_routes.contains(toggle.fallback_route.as_str()),
            "toggle '{}' has unknown fallback_route '{}', expected one of {:?}",
            name,
            toggle.fallback_route,
            known_routes
        );
    }
}

#[test]
fn frx_07_4_canary_flow_has_at_least_one_rollback_transition() {
    let contract = parse_contract();
    let rollbacks: Vec<_> = contract
        .canary_flow
        .allowed_transitions
        .iter()
        .filter(|t| t.kind == "rollback")
        .collect();
    assert!(
        rollbacks.len() >= 2,
        "canary flow should have at least 2 rollback transitions for safety, got {}",
        rollbacks.len()
    );
}

#[test]
fn frx_07_4_migration_diagnostic_target_milestones_are_nonempty() {
    let contract = parse_contract();
    for d in &contract.migration_diagnostics {
        assert!(
            !d.target_milestone.trim().is_empty(),
            "target_milestone must not be empty for {}",
            d.diagnostic_code
        );
    }
}

#[test]
fn frx_07_4_operator_verification_commands_are_nonempty_strings() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
    for cmd in &contract.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator_verification command must not be blank"
        );
    }
}

// ---------- enrichment: clone and debug ----------

#[test]
fn frx_07_4_contract_clone_independence() {
    let a = parse_contract();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn frx_07_4_contract_debug_is_nonempty() {
    let c = parse_contract();
    assert!(!format!("{c:?}").is_empty());
}

#[test]
fn frx_07_4_policy_toggle_clone_independence() {
    let contract = parse_contract();
    let toggle = contract.policy_toggles.get("force_fallback").unwrap();
    let cloned = toggle.clone();
    assert_eq!(toggle, &cloned);
}

#[test]
fn frx_07_4_canary_transition_clone_independence() {
    let contract = parse_contract();
    let transition = &contract.canary_flow.allowed_transitions[0];
    let cloned = transition.clone();
    assert_eq!(transition, &cloned);
}

#[test]
fn frx_07_4_migration_diagnostic_clone_independence() {
    let contract = parse_contract();
    let diag = &contract.migration_diagnostics[0];
    let cloned = diag.clone();
    assert_eq!(diag, &cloned);
}

// ---------- enrichment: more structural tests ----------

#[test]
fn frx_07_4_rollout_axes_are_unique() {
    let contract = parse_contract();
    let unique: BTreeSet<&str> = contract.rollout_axes.iter().map(String::as_str).collect();
    assert_eq!(unique.len(), contract.rollout_axes.len());
}

#[test]
fn frx_07_4_canary_stages_are_unique() {
    let contract = parse_contract();
    let unique: BTreeSet<&str> = contract
        .canary_flow
        .stages
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(unique.len(), contract.canary_flow.stages.len());
}

#[test]
fn frx_07_4_migration_diagnostics_compatibility_classes_are_nonempty() {
    let contract = parse_contract();
    for d in &contract.migration_diagnostics {
        assert!(!d.compatibility_class.trim().is_empty());
    }
}

#[test]
fn frx_07_4_migration_diagnostics_remediation_summaries_are_meaningful() {
    let contract = parse_contract();
    for d in &contract.migration_diagnostics {
        let word_count = d.remediation_summary.split_whitespace().count();
        assert!(
            word_count >= 3,
            "remediation_summary for {} should have >= 3 words, got {word_count}",
            d.diagnostic_code
        );
    }
}

#[test]
fn frx_07_4_bead_id_starts_with_bd() {
    let contract = parse_contract();
    assert!(contract.bead_id.starts_with("bd-"));
}

#[test]
fn frx_07_4_generated_at_utc_contains_t_separator() {
    let contract = parse_contract();
    assert!(contract.generated_at_utc.contains('T'));
}

#[test]
fn frx_07_4_track_id_starts_with_frx() {
    let contract = parse_contract();
    assert!(contract.track.id.starts_with("FRX-"));
}

#[test]
fn frx_07_4_policy_toggle_count_is_at_least_four() {
    let contract = parse_contract();
    assert!(contract.policy_toggles.len() >= 4);
}

#[test]
fn frx_07_4_canary_stages_count_is_four() {
    let contract = parse_contract();
    assert_eq!(contract.canary_flow.stages.len(), 4);
}

#[test]
fn frx_07_4_doc_word_count_at_least_200() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 200,
        "doc should have >= 200 words, got {word_count}"
    );
}
