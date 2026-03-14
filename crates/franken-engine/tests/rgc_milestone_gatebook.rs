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

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::{Deserialize, Serialize};

const GATEBOOK_SCHEMA_VERSION: &str = "rgc.milestone-gatebook.v1";
const GATEBOOK_JSON: &str = include_str!("../../../docs/rgc_milestone_gatebook_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MilestoneGatebook {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: GateTrack,
    automation: AutomationContract,
    blocker_classes: Vec<BlockerClass>,
    milestones: Vec<MilestoneGate>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AutomationContract {
    ci_contract_version: String,
    required_structured_log_fields: Vec<String>,
    required_artifact_triad: Vec<String>,
    decision_event_required_fields: Vec<String>,
    default_mode: String,
    report_only_transition_rules: Vec<TransitionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TransitionRule {
    milestone: String,
    report_only_until_utc: String,
    fail_closed_after_utc: String,
    transition_predicate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlockerClass {
    class_id: String,
    severity: String,
    predicate: String,
    required_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MilestoneGate {
    milestone: String,
    objective: String,
    gate_owner: String,
    pass_predicates: Vec<PassPredicate>,
    required_artifacts: Vec<String>,
    rollback_triggers: Vec<RollbackTrigger>,
    decision_authority: DecisionAuthority,
    ci_gate: CiGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PassPredicate {
    predicate_id: String,
    description: String,
    metric: String,
    comparator: String,
    threshold: serde_json::Value,
    unit: String,
    source_beads: Vec<String>,
    evaluation_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RollbackTrigger {
    trigger_id: String,
    condition_expression: String,
    required_probe_command: String,
    rollback_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DecisionAuthority {
    primary_role: String,
    secondary_role: String,
    escalation_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CiGate {
    workflow_id: String,
    command: String,
    report_only_until_utc: String,
    fail_closed_after_utc: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_gatebook() -> MilestoneGatebook {
    serde_json::from_str(GATEBOOK_JSON).expect("milestone gatebook json must parse")
}

#[test]
fn rgc_012_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_MILESTONE_GATEBOOK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Milestone Gatebook V1",
        "## Purpose",
        "## Gate Model",
        "## Blocker Classes",
        "## Milestone Stop/Go Matrix",
        "## Rollback Trigger Contract",
        "## CI/Release Automation Contract",
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
fn rgc_012_gatebook_is_versioned_and_track_bound() {
    let gatebook = parse_gatebook();

    assert_eq!(gatebook.schema_version, GATEBOOK_SCHEMA_VERSION);
    assert_eq!(gatebook.bead_id, "bd-1lsy.1.2");
    assert_eq!(gatebook.generated_by, "bd-1lsy.1.2");
    assert_eq!(gatebook.track.id, "RGC-012");
    assert_eq!(gatebook.track.name, "Milestone Gatebook");
    assert!(gatebook.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_012_automation_contract_has_required_fields_and_mode() {
    let gatebook = parse_gatebook();

    assert_eq!(
        gatebook.automation.default_mode,
        "report_only_then_fail_closed"
    );

    let required_log_fields: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();

    let actual_log_fields: BTreeSet<&str> = gatebook
        .automation
        .required_structured_log_fields
        .iter()
        .map(|field| field.as_str())
        .collect();

    assert_eq!(actual_log_fields, required_log_fields);

    let required_artifact_triad: BTreeSet<&str> =
        ["run_manifest.json", "events.jsonl", "commands.txt"]
            .into_iter()
            .collect();
    let actual_artifact_triad: BTreeSet<&str> = gatebook
        .automation
        .required_artifact_triad
        .iter()
        .map(|field| field.as_str())
        .collect();

    assert_eq!(actual_artifact_triad, required_artifact_triad);
    assert_eq!(gatebook.automation.report_only_transition_rules.len(), 5);
}

#[test]
fn rgc_012_blocker_classes_are_fail_closed_ready() {
    let gatebook = parse_gatebook();
    assert!(
        !gatebook.blocker_classes.is_empty(),
        "blocker classes must be non-empty"
    );

    let mut class_ids = BTreeSet::new();

    for class in &gatebook.blocker_classes {
        assert!(!class.class_id.trim().is_empty());
        assert_eq!(class.severity, "blocker");
        assert!(!class.predicate.trim().is_empty());
        assert!(!class.required_evidence.is_empty());
        assert!(class_ids.insert(class.class_id.clone()));
    }
}

#[test]
fn rgc_012_milestones_cover_m1_through_m5() {
    let gatebook = parse_gatebook();

    let expected: BTreeSet<&str> = ["M1", "M2", "M3", "M4", "M5"].into_iter().collect();
    let actual: BTreeSet<&str> = gatebook
        .milestones
        .iter()
        .map(|milestone| milestone.milestone.as_str())
        .collect();

    assert_eq!(actual, expected);
}

#[test]
fn rgc_012_each_milestone_has_objective_predicates_and_ci_gate() {
    let gatebook = parse_gatebook();
    let comparators: BTreeSet<&str> = ["==", ">=", "<=", ">", "<"].into_iter().collect();

    for milestone in &gatebook.milestones {
        assert!(!milestone.objective.trim().is_empty());
        assert!(!milestone.gate_owner.trim().is_empty());
        assert!(
            !milestone.pass_predicates.is_empty(),
            "{} missing pass predicates",
            milestone.milestone
        );

        for predicate in &milestone.pass_predicates {
            assert!(!predicate.predicate_id.trim().is_empty());
            assert!(!predicate.description.trim().is_empty());
            assert!(!predicate.metric.trim().is_empty());
            assert!(comparators.contains(predicate.comparator.as_str()));
            assert!(
                predicate.threshold.is_number(),
                "{} threshold must be numeric",
                predicate.predicate_id
            );
            assert!(!predicate.unit.trim().is_empty());
            assert!(!predicate.source_beads.is_empty());
            assert!(
                predicate
                    .source_beads
                    .iter()
                    .all(|bead_id| bead_id.starts_with("bd-1lsy."))
            );
            assert!(!predicate.evaluation_command.trim().is_empty());
        }

        assert!(!milestone.required_artifacts.is_empty());
        for triad_name in ["run_manifest.json", "events.jsonl", "commands.txt"] {
            assert!(
                milestone
                    .required_artifacts
                    .iter()
                    .any(|artifact| artifact.ends_with(triad_name)),
                "{} missing artifact {}",
                milestone.milestone,
                triad_name
            );
        }

        assert!(
            !milestone.rollback_triggers.is_empty(),
            "{} missing rollback triggers",
            milestone.milestone
        );

        for trigger in &milestone.rollback_triggers {
            assert!(!trigger.trigger_id.trim().is_empty());
            assert!(!trigger.condition_expression.trim().is_empty());
            assert!(!trigger.required_probe_command.trim().is_empty());
            assert!(!trigger.rollback_action.trim().is_empty());
        }

        assert!(!milestone.decision_authority.primary_role.trim().is_empty());
        assert!(
            !milestone
                .decision_authority
                .secondary_role
                .trim()
                .is_empty()
        );
        assert!(!milestone.decision_authority.escalation_roles.is_empty());

        assert!(!milestone.ci_gate.workflow_id.trim().is_empty());
        assert!(!milestone.ci_gate.command.trim().is_empty());
        assert!(milestone.ci_gate.report_only_until_utc.ends_with('Z'));
        assert!(milestone.ci_gate.fail_closed_after_utc.ends_with('Z'));
        assert!(
            milestone.ci_gate.report_only_until_utc < milestone.ci_gate.fail_closed_after_utc,
            "{} has invalid report-only/fail-closed chronology",
            milestone.milestone
        );
    }
}

#[test]
fn rgc_012_transition_rules_align_to_milestones() {
    let gatebook = parse_gatebook();

    let milestone_set: BTreeSet<&str> = gatebook
        .milestones
        .iter()
        .map(|milestone| milestone.milestone.as_str())
        .collect();

    let transition_set: BTreeSet<&str> = gatebook
        .automation
        .report_only_transition_rules
        .iter()
        .map(|rule| rule.milestone.as_str())
        .collect();

    assert_eq!(milestone_set, transition_set);

    for rule in &gatebook.automation.report_only_transition_rules {
        assert!(rule.report_only_until_utc.ends_with('Z'));
        assert!(rule.fail_closed_after_utc.ends_with('Z'));
        assert!(rule.report_only_until_utc < rule.fail_closed_after_utc);
        assert!(!rule.transition_predicate.trim().is_empty());
    }
}

#[test]
fn rgc_012_operator_verification_commands_are_present() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.operator_verification.is_empty());

    let joined = gatebook.operator_verification.join("\n");
    assert!(joined.contains("jq empty docs/rgc_milestone_gatebook_v1.json"));
    assert!(joined.contains("cargo test -p frankenengine-engine --test rgc_milestone_gatebook"));
    assert!(joined.contains("run_phase_a_exit_gate.sh check"));
}

#[test]
fn rgc_012_serde_roundtrip_preserves_gatebook() {
    let gatebook = parse_gatebook();
    let serialized = serde_json::to_string(&gatebook).expect("serialize");
    let deserialized: MilestoneGatebook = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(gatebook, deserialized);
}

#[test]
fn rgc_012_deterministic_double_parse() {
    let a = parse_gatebook();
    let b = parse_gatebook();
    assert_eq!(a, b);
}

#[test]
fn rgc_012_blocker_class_ids_are_unique() {
    let gatebook = parse_gatebook();
    let mut seen = BTreeSet::new();
    for class in &gatebook.blocker_classes {
        assert!(
            seen.insert(&class.class_id),
            "duplicate class_id: {}",
            class.class_id
        );
    }
}

#[test]
fn rgc_012_milestone_predicate_ids_are_unique_within_milestone() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        let mut seen = BTreeSet::new();
        for pred in &milestone.pass_predicates {
            assert!(
                seen.insert(&pred.predicate_id),
                "duplicate predicate_id {} in {}",
                pred.predicate_id,
                milestone.milestone
            );
        }
    }
}

#[test]
fn rgc_012_doc_file_is_nonempty() {
    let path = repo_root().join("docs/RGC_MILESTONE_GATEBOOK_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn rgc_012_rollback_trigger_ids_are_unique_per_milestone() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        let mut seen = BTreeSet::new();
        for trigger in &milestone.rollback_triggers {
            assert!(
                seen.insert(&trigger.trigger_id),
                "duplicate trigger_id {} in {}",
                trigger.trigger_id,
                milestone.milestone
            );
        }
    }
}

#[test]
fn rgc_012_ci_gate_workflow_ids_are_unique() {
    let gatebook = parse_gatebook();
    let mut seen = BTreeSet::new();
    for milestone in &gatebook.milestones {
        assert!(
            seen.insert(&milestone.ci_gate.workflow_id),
            "duplicate ci_gate workflow_id: {}",
            milestone.ci_gate.workflow_id
        );
    }
}

#[test]
fn rgc_012_automation_decision_event_fields_are_nonempty() {
    let gatebook = parse_gatebook();
    assert!(
        !gatebook
            .automation
            .decision_event_required_fields
            .is_empty()
    );
    for field in &gatebook.automation.decision_event_required_fields {
        assert!(
            !field.trim().is_empty(),
            "decision event field must not be empty"
        );
    }
}

#[test]
fn rgc_012_gatebook_has_bead_id() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.bead_id.trim().is_empty());
}

#[test]
fn rgc_012_gatebook_generated_at_utc_ends_with_z() {
    let gatebook = parse_gatebook();
    assert!(gatebook.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_012_operator_verification_commands_are_all_nonempty() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.operator_verification.is_empty());
    for cmd in &gatebook.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

#[test]
fn rgc_012_gatebook_has_nonempty_generated_by() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.generated_by.trim().is_empty());
}

#[test]
fn rgc_012_gatebook_track_fields_are_nonempty() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.track.id.trim().is_empty());
    assert!(!gatebook.track.name.trim().is_empty());
}

#[test]
fn rgc_012_automation_ci_contract_version_is_nonempty() {
    let gatebook = parse_gatebook();
    assert!(!gatebook.automation.ci_contract_version.trim().is_empty());
}

// ---------- additional enrichment tests ----------

#[test]
fn rgc_012_schema_version_follows_dotted_format() {
    let gatebook = parse_gatebook();
    let parts: Vec<&str> = gatebook.schema_version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "schema_version should have at least 3 dot-separated segments, got: {}",
        gatebook.schema_version
    );
    for part in &parts {
        assert!(
            !part.trim().is_empty(),
            "schema_version segment must not be empty"
        );
    }
}

#[test]
fn rgc_012_milestones_are_strictly_ordered_m1_to_m5() {
    let gatebook = parse_gatebook();
    let milestone_names: Vec<&str> = gatebook
        .milestones
        .iter()
        .map(|m| m.milestone.as_str())
        .collect();
    assert_eq!(milestone_names, vec!["M1", "M2", "M3", "M4", "M5"]);
}

#[test]
fn rgc_012_predicate_ids_are_globally_unique() {
    let gatebook = parse_gatebook();
    let mut seen = BTreeSet::new();
    for milestone in &gatebook.milestones {
        for pred in &milestone.pass_predicates {
            assert!(
                seen.insert(&pred.predicate_id),
                "duplicate predicate_id across milestones: {}",
                pred.predicate_id
            );
        }
    }
}

#[test]
fn rgc_012_all_milestone_gate_owners_are_nonempty() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert!(
            !milestone.gate_owner.trim().is_empty(),
            "{} has empty gate_owner",
            milestone.milestone
        );
    }
}

#[test]
fn rgc_012_all_milestone_objectives_are_nonempty() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert!(
            !milestone.objective.trim().is_empty(),
            "{} has empty objective",
            milestone.milestone
        );
    }
}

#[test]
fn rgc_012_transition_rule_milestones_are_unique() {
    let gatebook = parse_gatebook();
    let mut seen = BTreeSet::new();
    for rule in &gatebook.automation.report_only_transition_rules {
        assert!(
            seen.insert(&rule.milestone),
            "duplicate milestone in transition rules: {}",
            rule.milestone
        );
    }
}

#[test]
fn rgc_012_escalation_roles_are_nonempty_for_all_milestones() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert!(
            !milestone.decision_authority.escalation_roles.is_empty(),
            "{} has no escalation roles",
            milestone.milestone
        );
        for role in &milestone.decision_authority.escalation_roles {
            assert!(
                !role.trim().is_empty(),
                "{} has empty escalation role",
                milestone.milestone
            );
        }
    }
}

#[test]
fn rgc_012_ci_gate_commands_reference_scripts() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert!(
            milestone.ci_gate.command.contains("scripts/")
                || milestone.ci_gate.command.contains("cargo"),
            "{} ci_gate command should reference a script or cargo command",
            milestone.milestone
        );
    }
}

#[test]
fn rgc_012_blocker_classes_have_nonempty_required_evidence() {
    let gatebook = parse_gatebook();
    for class in &gatebook.blocker_classes {
        for evidence in &class.required_evidence {
            assert!(
                !evidence.trim().is_empty(),
                "blocker class {} has empty required evidence entry",
                class.class_id
            );
        }
    }
}

#[test]
fn rgc_012_all_rollback_trigger_ids_globally_unique() {
    let gatebook = parse_gatebook();
    let mut seen = BTreeSet::new();
    for milestone in &gatebook.milestones {
        for trigger in &milestone.rollback_triggers {
            assert!(
                seen.insert(&trigger.trigger_id),
                "duplicate rollback trigger_id across milestones: {}",
                trigger.trigger_id
            );
        }
    }
}

// ---------- enrichment batch 2 ----------

#[test]
fn rgc_012_serde_roundtrip_gate_track() {
    let gatebook = parse_gatebook();
    let track = gatebook.track.clone();
    let json = serde_json::to_string(&track).expect("serialize GateTrack");
    let recovered: GateTrack = serde_json::from_str(&json).expect("deserialize GateTrack");
    assert_eq!(track, recovered);
}

#[test]
fn rgc_012_serde_roundtrip_automation_contract() {
    let gatebook = parse_gatebook();
    let auto = gatebook.automation.clone();
    let json = serde_json::to_string(&auto).expect("serialize AutomationContract");
    let recovered: AutomationContract =
        serde_json::from_str(&json).expect("deserialize AutomationContract");
    assert_eq!(auto, recovered);
}

#[test]
fn rgc_012_serde_roundtrip_blocker_class() {
    let gatebook = parse_gatebook();
    let class = gatebook.blocker_classes.first().unwrap().clone();
    let json = serde_json::to_string(&class).expect("serialize BlockerClass");
    let recovered: BlockerClass = serde_json::from_str(&json).expect("deserialize BlockerClass");
    assert_eq!(class, recovered);
}

#[test]
fn rgc_012_serde_roundtrip_milestone_gate() {
    let gatebook = parse_gatebook();
    let gate = gatebook.milestones.first().unwrap().clone();
    let json = serde_json::to_string(&gate).expect("serialize MilestoneGate");
    let recovered: MilestoneGate = serde_json::from_str(&json).expect("deserialize MilestoneGate");
    assert_eq!(gate, recovered);
}

#[test]
fn rgc_012_serde_roundtrip_transition_rule() {
    let gatebook = parse_gatebook();
    let rule = gatebook
        .automation
        .report_only_transition_rules
        .first()
        .unwrap()
        .clone();
    let json = serde_json::to_string(&rule).expect("serialize TransitionRule");
    let recovered: TransitionRule =
        serde_json::from_str(&json).expect("deserialize TransitionRule");
    assert_eq!(rule, recovered);
}

#[test]
fn rgc_012_clone_preserves_equality_for_gatebook() {
    let gatebook = parse_gatebook();
    let cloned = gatebook.clone();
    assert_eq!(gatebook, cloned);
}

#[test]
fn rgc_012_debug_impl_contains_schema_version() {
    let gatebook = parse_gatebook();
    let debug_str = format!("{:?}", gatebook);
    assert!(
        debug_str.contains(GATEBOOK_SCHEMA_VERSION),
        "Debug output should contain schema_version"
    );
}

#[test]
fn rgc_012_debug_impl_contains_milestone_names() {
    let gatebook = parse_gatebook();
    let debug_str = format!("{:?}", gatebook);
    for ms in &["M1", "M2", "M3", "M4", "M5"] {
        assert!(
            debug_str.contains(ms),
            "Debug output should contain milestone {}",
            ms
        );
    }
}

#[test]
fn rgc_012_transition_rules_chronologically_ordered() {
    let gatebook = parse_gatebook();
    let rules = &gatebook.automation.report_only_transition_rules;
    for window in rules.windows(2) {
        assert!(
            window[0].report_only_until_utc < window[1].report_only_until_utc,
            "transition rules should be chronologically ordered: {} vs {}",
            window[0].milestone,
            window[1].milestone
        );
        assert!(
            window[0].fail_closed_after_utc < window[1].fail_closed_after_utc,
            "fail_closed dates should be chronologically ordered: {} vs {}",
            window[0].milestone,
            window[1].milestone
        );
    }
}

#[test]
fn rgc_012_ci_gate_dates_align_with_transition_rules() {
    let gatebook = parse_gatebook();
    let transition_map: std::collections::BTreeMap<&str, &TransitionRule> = gatebook
        .automation
        .report_only_transition_rules
        .iter()
        .map(|r| (r.milestone.as_str(), r))
        .collect();

    for milestone in &gatebook.milestones {
        let rule = transition_map
            .get(milestone.milestone.as_str())
            .unwrap_or_else(|| panic!("no transition rule for milestone {}", milestone.milestone));
        assert_eq!(
            milestone.ci_gate.report_only_until_utc, rule.report_only_until_utc,
            "ci_gate report_only_until mismatch for {}",
            milestone.milestone
        );
        assert_eq!(
            milestone.ci_gate.fail_closed_after_utc, rule.fail_closed_after_utc,
            "ci_gate fail_closed_after mismatch for {}",
            milestone.milestone
        );
    }
}

#[test]
fn rgc_012_exactly_four_blocker_classes() {
    let gatebook = parse_gatebook();
    assert_eq!(
        gatebook.blocker_classes.len(),
        4,
        "expected exactly 4 blocker classes"
    );
}

#[test]
fn rgc_012_blocker_class_ids_match_known_set() {
    let gatebook = parse_gatebook();
    let expected: BTreeSet<&str> = [
        "correctness_regression",
        "security_enforcement_failure",
        "artifact_incompleteness",
        "performance_claim_instability",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<&str> = gatebook
        .blocker_classes
        .iter()
        .map(|c| c.class_id.as_str())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn rgc_012_every_milestone_has_exactly_two_rollback_triggers() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert_eq!(
            milestone.rollback_triggers.len(),
            2,
            "{} should have exactly 2 rollback triggers but has {}",
            milestone.milestone,
            milestone.rollback_triggers.len()
        );
    }
}

#[test]
fn rgc_012_every_milestone_has_exactly_two_pass_predicates() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        assert_eq!(
            milestone.pass_predicates.len(),
            2,
            "{} should have exactly 2 pass predicates but has {}",
            milestone.milestone,
            milestone.pass_predicates.len()
        );
    }
}

#[test]
fn rgc_012_all_source_beads_follow_bead_id_format() {
    let gatebook = parse_gatebook();
    let mut all_beads = BTreeSet::new();
    for milestone in &gatebook.milestones {
        for pred in &milestone.pass_predicates {
            for bead in &pred.source_beads {
                all_beads.insert(bead.as_str());
            }
        }
    }
    assert!(
        !all_beads.is_empty(),
        "should have at least one source bead across all predicates"
    );
    for bead in &all_beads {
        assert!(
            bead.starts_with("bd-"),
            "source bead {} should start with bd-",
            bead
        );
        let dot_count = bead.chars().filter(|c| *c == '.').count();
        assert!(
            dot_count >= 1,
            "source bead {} should have at least one dot-separated segment",
            bead
        );
    }
}

#[test]
fn rgc_012_required_artifacts_reference_milestone_directory() {
    let gatebook = parse_gatebook();
    for milestone in &gatebook.milestones {
        let expected_dir = format!("artifacts/rgc_{}/", milestone.milestone.to_lowercase());
        for artifact in &milestone.required_artifacts {
            assert!(
                artifact.starts_with(&expected_dir),
                "{} artifact {} should start with {}",
                milestone.milestone,
                artifact,
                expected_dir
            );
        }
    }
}

#[test]
fn rgc_012_decision_event_required_fields_match_known_set() {
    let gatebook = parse_gatebook();
    let expected: BTreeSet<&str> = [
        "milestone",
        "gate_id",
        "mode",
        "decision",
        "blocker_classes",
        "rollback_trigger_ids",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<&str> = gatebook
        .automation
        .decision_event_required_fields
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(actual, expected);
}
