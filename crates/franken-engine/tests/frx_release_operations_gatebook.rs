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
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const GATEBOOK_SCHEMA_VERSION: &str = "frx.release-operations-gatebook.v1";
const GATEBOOK_JSON: &str = include_str!("../../../docs/frx_release_operations_gatebook_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseOperationsGatebookContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    consumes_cut_line_artifacts: CutLineConsumption,
    release_packet_channels: Vec<ReleasePacketChannel>,
    stage_checklists: Vec<StageChecklist>,
    communication_discipline: CommunicationDiscipline,
    claim_publication_record: ClaimPublicationRecord,
    fail_closed_rules: Vec<String>,
    required_structured_log_fields: Vec<String>,
    prerequisites: Vec<Prerequisite>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CutLineConsumption {
    source_contract: String,
    required_cut_lines: Vec<String>,
    require_signed_decisions: bool,
    require_monotonic_stage_progression: bool,
    fail_closed_on_missing_stage_decision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleasePacketChannel {
    channel_id: String,
    source_bead: String,
    required: bool,
    signed_required: bool,
    max_age_ns: u64,
    failure_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StageChecklist {
    stage: String,
    min_cut_line: String,
    required_channels: Vec<String>,
    required_checklist_items: Vec<String>,
    publication_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommunicationDiscipline {
    incident_response: IncidentResponse,
    rollback_communications: RollbackCommunications,
    publication_communications: PublicationCommunications,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IncidentResponse {
    required_fields: Vec<String>,
    require_escalation_acknowledgement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RollbackCommunications {
    required_fields: Vec<String>,
    require_operator_acknowledgement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicationCommunications {
    required_fields: Vec<String>,
    require_signed_statement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClaimPublicationRecord {
    required_fields: Vec<String>,
    require_reproducibility_bundle_links: bool,
    require_release_packet_digest: bool,
    block_on_incomplete_record: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Prerequisite {
    bead_id: String,
    reason: String,
    status: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ReleaseOperationsGatebookContract {
    serde_json::from_str(GATEBOOK_JSON).expect("release operations gatebook JSON must parse")
}

#[test]
fn frx_09_2_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_RELEASE_OPERATIONS_GATEBOOK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# FRX Release Operations Gatebook and Publication Workflow V1",
        "## Scope",
        "## FRX-12 Consumption Contract",
        "## Release Packet Channels",
        "## Stage Checklists and Publication Workflow",
        "## Incident-Response and Rollback Communication Discipline",
        "## Claim Publication and Reproducibility Linkage",
        "## Fail-Closed Validation Rules",
        "## Deterministic Logging and Artifact Contract",
        "## Dependencies and Prerequisites",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "fail-closed",
        "release packet",
        "cut-line",
        "rollback",
        "publication",
        "reproducibility",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "missing required phrase in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_09_2_contract_is_machine_readable_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, GATEBOOK_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.9.2");
    assert_eq!(contract.generated_by, "bd-mjh3.9.2");
    assert_eq!(contract.track.id, "FRX-09.2");
    assert!(contract.track.name.contains("Release Operations"));
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_09_2_cut_line_consumption_and_channels_are_fail_closed() {
    let contract = parse_contract();

    let expected_cut_lines: BTreeSet<&str> =
        ["C0", "C1", "C2", "C3", "C4", "C5"].into_iter().collect();
    let observed_cut_lines: BTreeSet<&str> = contract
        .consumes_cut_line_artifacts
        .required_cut_lines
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(observed_cut_lines, expected_cut_lines);

    assert!(
        contract
            .consumes_cut_line_artifacts
            .source_contract
            .contains("cut-line-automation")
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .require_signed_decisions
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .require_monotonic_stage_progression
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .fail_closed_on_missing_stage_decision
    );

    let mut channel_ids = HashSet::new();
    for channel in &contract.release_packet_channels {
        assert!(channel_ids.insert(channel.channel_id.as_str()));
        assert!(
            channel.required,
            "channel must be required: {}",
            channel.channel_id
        );
        assert!(
            channel.signed_required,
            "channel must require signatures: {}",
            channel.channel_id
        );
        assert!(channel.max_age_ns > 0);
        assert_eq!(channel.failure_code, "FE-FRX-09-2-RELEASE-OPS-0001");
        assert!(channel.source_bead.starts_with("bd-mjh3."));
    }

    for required in [
        "cut_line_decision_bundle",
        "ga_readiness_claim_bundle",
        "proof_carrying_artifact_gate",
        "pilot_rollout_harness",
        "tail_latency_memory_hardening",
        "observability_demotion",
        "catastrophic_tail_tournament",
        "twin_rollback_synthesizer",
        "test_evidence_integrator",
    ] {
        assert!(
            channel_ids.contains(required),
            "missing required channel: {required}"
        );
    }
}

#[test]
fn frx_09_2_stage_checklists_are_progressive_and_complete() {
    let contract = parse_contract();

    assert_eq!(contract.stage_checklists.len(), 3);

    let mut seen_stages = HashSet::new();
    let channel_ids: HashSet<&str> = contract
        .release_packet_channels
        .iter()
        .map(|channel| channel.channel_id.as_str())
        .collect();

    for checklist in &contract.stage_checklists {
        assert!(seen_stages.insert(checklist.stage.as_str()));
        assert!(
            matches!(checklist.stage.as_str(), "alpha" | "beta" | "ga"),
            "unexpected stage {}",
            checklist.stage
        );
        assert!(
            matches!(checklist.min_cut_line.as_str(), "C2" | "C3" | "C4"),
            "unexpected cut-line {}",
            checklist.min_cut_line
        );
        assert!(!checklist.required_channels.is_empty());
        assert!(!checklist.required_checklist_items.is_empty());
        assert!(!checklist.publication_mode.trim().is_empty());

        for channel in &checklist.required_channels {
            assert!(
                channel_ids.contains(channel.as_str()),
                "stage {} references unknown channel {}",
                checklist.stage,
                channel
            );
        }
    }

    let alpha = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "alpha")
        .expect("alpha checklist missing");
    let beta = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "beta")
        .expect("beta checklist missing");
    let ga = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "ga")
        .expect("ga checklist missing");

    assert_eq!(alpha.min_cut_line, "C2");
    assert_eq!(beta.min_cut_line, "C3");
    assert_eq!(ga.min_cut_line, "C4");

    assert!(
        ga.required_channels.len() >= beta.required_channels.len()
            && beta.required_channels.len() >= alpha.required_channels.len(),
        "required channel sets must grow or stay equal as stages progress"
    );
}

#[test]
fn frx_09_2_communication_and_publication_contracts_are_explicit() {
    let contract = parse_contract();

    let incident_fields: BTreeSet<&str> = contract
        .communication_discipline
        .incident_response
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "incident_id",
        "severity",
        "decision_id",
        "owner",
        "escalation_path",
        "first_response_deadline_s",
    ] {
        assert!(
            incident_fields.contains(field),
            "missing incident field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .incident_response
            .require_escalation_acknowledgement
    );

    let rollback_fields: BTreeSet<&str> = contract
        .communication_discipline
        .rollback_communications
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "rollback_id",
        "trigger_signal",
        "rollback_command",
        "safe_mode_target",
        "eta_recovery_s",
    ] {
        assert!(
            rollback_fields.contains(field),
            "missing rollback field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .rollback_communications
            .require_operator_acknowledgement
    );

    let publication_fields: BTreeSet<&str> = contract
        .communication_discipline
        .publication_communications
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "claim_id",
        "release_stage",
        "bundle_digest",
        "public_statement_ref",
    ] {
        assert!(
            publication_fields.contains(field),
            "missing publication communication field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .publication_communications
            .require_signed_statement
    );

    let claim_fields: BTreeSet<&str> = contract
        .claim_publication_record
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "claim_id",
        "stage_gate_decision_id",
        "reproducibility_bundle_id",
        "evidence_bundle_ids",
        "release_packet_digest",
        "replay_command",
        "publication_timestamp_utc",
        "signer",
        "signature_ref",
    ] {
        assert!(
            claim_fields.contains(field),
            "missing claim publication field {field}"
        );
    }

    assert!(
        contract
            .claim_publication_record
            .require_reproducibility_bundle_links
    );
    assert!(
        contract
            .claim_publication_record
            .require_release_packet_digest
    );
    assert!(contract.claim_publication_record.block_on_incomplete_record);
}

#[test]
fn frx_09_2_fail_closed_rules_and_logging_fields_are_complete() {
    let contract = parse_contract();

    let rules: BTreeSet<&str> = contract
        .fail_closed_rules
        .iter()
        .map(String::as_str)
        .collect();
    for required_rule in [
        "missing_required_channel",
        "stale_channel_artifact",
        "missing_or_invalid_signature",
        "stage_checklist_failure",
        "missing_publication_record_field",
        "release_packet_digest_mismatch",
    ] {
        assert!(rules.contains(required_rule));
    }

    let log_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "release_stage",
        "publication_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
    }
}

#[test]
fn frx_09_2_prerequisites_and_operator_verification_are_declared() {
    let contract = parse_contract();

    assert_eq!(contract.prerequisites.len(), 6);
    let prerequisite_ids: BTreeSet<&str> = contract
        .prerequisites
        .iter()
        .map(|entry| entry.bead_id.as_str())
        .collect();
    let expected_ids: BTreeSet<&str> = [
        "bd-mjh3.20.6",
        "bd-mjh3.12.7",
        "bd-mjh3.12.5",
        "bd-mjh3.5.4",
        "bd-mjh3.9.1",
        "bd-mjh3.6.4",
    ]
    .into_iter()
    .collect();
    assert_eq!(prerequisite_ids, expected_ids);

    let statuses: BTreeSet<&str> = contract
        .prerequisites
        .iter()
        .map(|entry| entry.status.as_str())
        .collect();
    assert!(statuses.contains("closed"));
    assert!(statuses.contains("in_progress"));
    assert!(statuses.contains("open"));

    for entry in &contract.prerequisites {
        assert!(!entry.reason.trim().is_empty());
    }

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("run_frx_release_operations_gatebook_suite.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("frx_release_operations_gatebook_replay.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry == "jq empty docs/frx_release_operations_gatebook_v1.json")
    );
}

#[test]
fn frx_09_2_serde_roundtrip_preserves_contract() {
    let contract = parse_contract();
    let serialized = serde_json::to_string(&contract).expect("serialize");
    let deserialized: ReleaseOperationsGatebookContract =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(contract, deserialized);
}

#[test]
fn frx_09_2_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn frx_09_2_fail_closed_rules_are_nonempty() {
    let contract = parse_contract();
    assert!(!contract.fail_closed_rules.is_empty());
    for rule in &contract.fail_closed_rules {
        assert!(
            !rule.trim().is_empty(),
            "fail-closed rule must not be empty"
        );
    }
}

#[test]
fn frx_09_2_channel_failure_codes_are_consistent() {
    let contract = parse_contract();
    for channel in &contract.release_packet_channels {
        assert!(
            channel.failure_code.starts_with("FE-FRX-"),
            "failure code must start with FE-FRX-: {}",
            channel.failure_code
        );
    }
}

#[test]
fn frx_09_2_doc_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/FRX_RELEASE_OPERATIONS_GATEBOOK_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn frx_09_2_prerequisite_beads_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for p in &contract.prerequisites {
        assert!(
            seen.insert(&p.bead_id),
            "duplicate prerequisite bead_id: {}",
            p.bead_id
        );
    }
}

#[test]
fn frx_09_2_release_packet_channel_ids_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for channel in &contract.release_packet_channels {
        assert!(
            seen.insert(&channel.channel_id),
            "duplicate channel_id: {}",
            channel.channel_id
        );
    }
}

#[test]
fn frx_09_2_stage_checklist_stages_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for checklist in &contract.stage_checklists {
        assert!(
            seen.insert(&checklist.stage),
            "duplicate stage: {}",
            checklist.stage
        );
    }
}

#[test]
fn frx_09_2_structured_log_fields_are_nonempty_and_unique() {
    let contract = parse_contract();
    assert!(!contract.required_structured_log_fields.is_empty());
    let mut seen = BTreeSet::new();
    for field in &contract.required_structured_log_fields {
        assert!(!field.trim().is_empty(), "log field must not be empty");
        assert!(
            seen.insert(field),
            "duplicate structured log field: {}",
            field
        );
    }
}

#[test]
fn frx_09_2_contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn frx_09_2_contract_generated_at_utc_ends_with_z() {
    let contract = parse_contract();
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_09_2_contract_has_nonempty_schema_version() {
    let contract = parse_contract();
    assert!(!contract.schema_version.trim().is_empty());
}

#[test]
fn frx_09_2_contract_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, GATEBOOK_SCHEMA_VERSION);
}

#[test]
fn frx_09_2_deterministic_triple_parse() {
    let a = parse_contract();
    let b = parse_contract();
    let c = parse_contract();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn frx_09_2_contract_has_nonempty_generated_by() {
    let contract = parse_contract();
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn frx_09_2_contract_has_nonempty_track_id() {
    let contract = parse_contract();
    assert!(!contract.track.id.trim().is_empty());
}

#[test]
fn frx_09_2_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_RELEASE_OPERATIONS_GATEBOOK_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn frx_09_2_operator_verification_commands_are_all_nonempty() {
    let contract = parse_contract();
    assert!(!contract.operator_verification.is_empty());
    for cmd in &contract.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

// ---------- enrichment: deeper structural and edge-case checks ----------

#[test]
fn frx_09_2_ga_stage_requires_all_channels() {
    let contract = parse_contract();
    let ga = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "ga")
        .expect("ga checklist must exist");
    let all_channel_ids: BTreeSet<&str> = contract
        .release_packet_channels
        .iter()
        .map(|ch| ch.channel_id.as_str())
        .collect();
    let ga_channel_ids: BTreeSet<&str> = ga.required_channels.iter().map(String::as_str).collect();
    assert_eq!(
        ga_channel_ids, all_channel_ids,
        "GA stage must require every declared release packet channel"
    );
}

#[test]
fn frx_09_2_alpha_stage_channels_are_subset_of_beta() {
    let contract = parse_contract();
    let alpha = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "alpha")
        .expect("alpha checklist");
    let beta = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "beta")
        .expect("beta checklist");
    let alpha_set: BTreeSet<&str> = alpha.required_channels.iter().map(String::as_str).collect();
    let beta_set: BTreeSet<&str> = beta.required_channels.iter().map(String::as_str).collect();
    assert!(
        alpha_set.is_subset(&beta_set),
        "alpha required_channels must be a subset of beta required_channels"
    );
}

#[test]
fn frx_09_2_channel_max_age_ns_are_all_positive_and_bounded() {
    let contract = parse_contract();
    for channel in &contract.release_packet_channels {
        assert!(
            channel.max_age_ns > 0 && channel.max_age_ns <= 86_400_000_000_000,
            "channel {} max_age_ns must be > 0 and <= 24h in nanoseconds, got {}",
            channel.channel_id,
            channel.max_age_ns
        );
    }
}

#[test]
fn frx_09_2_prerequisite_statuses_are_in_allowed_set() {
    let contract = parse_contract();
    let allowed: BTreeSet<&str> = ["open", "in_progress", "closed"].into_iter().collect();
    for p in &contract.prerequisites {
        assert!(
            allowed.contains(p.status.as_str()),
            "prerequisite {} has unexpected status '{}'; allowed: {:?}",
            p.bead_id,
            p.status,
            allowed
        );
    }
}

#[test]
fn frx_09_2_serde_roundtrip_via_pretty_print_preserves_contract() {
    let contract = parse_contract();
    let pretty = serde_json::to_string_pretty(&contract).expect("pretty serialize");
    let deserialized: ReleaseOperationsGatebookContract =
        serde_json::from_str(&pretty).expect("deserialize from pretty");
    assert_eq!(contract, deserialized);
}

#[test]
fn frx_09_2_beta_stage_channels_are_subset_of_ga() {
    let contract = parse_contract();
    let beta = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "beta")
        .expect("beta checklist");
    let ga = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "ga")
        .expect("ga checklist");
    let beta_set: BTreeSet<&str> = beta.required_channels.iter().map(String::as_str).collect();
    let ga_set: BTreeSet<&str> = ga.required_channels.iter().map(String::as_str).collect();
    assert!(
        beta_set.is_subset(&ga_set),
        "beta required_channels must be a subset of GA required_channels"
    );
}

#[test]
fn frx_09_2_all_prerequisite_reasons_are_nonempty() {
    let contract = parse_contract();
    for p in &contract.prerequisites {
        assert!(
            !p.reason.trim().is_empty(),
            "prerequisite {} must have a non-empty reason",
            p.bead_id
        );
        assert!(
            !p.bead_id.trim().is_empty(),
            "prerequisite bead_id must not be empty"
        );
    }
}

#[test]
fn frx_09_2_claim_publication_record_requires_bundle_links_and_digest() {
    let contract = parse_contract();
    assert!(
        contract
            .claim_publication_record
            .require_reproducibility_bundle_links,
        "claim_publication_record must require reproducibility bundle links"
    );
    assert!(
        contract
            .claim_publication_record
            .require_release_packet_digest,
        "claim_publication_record must require release packet digest"
    );
    assert!(
        contract.claim_publication_record.block_on_incomplete_record,
        "claim_publication_record must block on incomplete record"
    );
}

#[test]
fn frx_09_2_stage_checklist_publication_modes_are_valid() {
    let contract = parse_contract();
    let allowed_modes: BTreeSet<&str> = ["internal_only", "internal_and_external", "full_public"]
        .into_iter()
        .collect();
    for checklist in &contract.stage_checklists {
        assert!(
            allowed_modes.contains(checklist.publication_mode.as_str()),
            "stage {} has unexpected publication_mode '{}'; allowed: {:?}",
            checklist.stage,
            checklist.publication_mode,
            allowed_modes
        );
    }
}

#[test]
fn frx_09_2_contract_track_name_contains_release_operations() {
    let contract = parse_contract();
    assert!(
        contract.track.name.contains("Release Operations"),
        "track.name must contain 'Release Operations', got '{}'",
        contract.track.name
    );
}

#[test]
fn frx_09_2_clone_equality_for_all_sub_structs() {
    let contract = parse_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
    assert_eq!(contract.track, cloned.track);
    assert_eq!(
        contract.consumes_cut_line_artifacts,
        cloned.consumes_cut_line_artifacts
    );
    assert_eq!(
        contract.release_packet_channels,
        cloned.release_packet_channels
    );
    assert_eq!(contract.stage_checklists, cloned.stage_checklists);
    assert_eq!(
        contract.communication_discipline,
        cloned.communication_discipline
    );
    assert_eq!(
        contract.claim_publication_record,
        cloned.claim_publication_record
    );
    assert_eq!(contract.prerequisites, cloned.prerequisites);
}

#[test]
fn frx_09_2_debug_format_contains_schema_version() {
    let contract = parse_contract();
    let debug_str = format!("{contract:?}");
    assert!(
        debug_str.contains("frx.release-operations-gatebook.v1"),
        "Debug output must contain the schema version string"
    );
}

#[test]
fn frx_09_2_channel_source_beads_all_start_with_bd_mjh3() {
    let contract = parse_contract();
    for channel in &contract.release_packet_channels {
        assert!(
            channel.source_bead.starts_with("bd-mjh3."),
            "channel '{}' source_bead '{}' must start with 'bd-mjh3.'",
            channel.channel_id,
            channel.source_bead
        );
    }
}

#[test]
fn frx_09_2_all_required_channels_are_signed() {
    let contract = parse_contract();
    for channel in &contract.release_packet_channels {
        if channel.required {
            assert!(
                channel.signed_required,
                "required channel '{}' must also have signed_required=true",
                channel.channel_id
            );
        }
    }
}

#[test]
fn frx_09_2_incident_response_required_fields_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for field in &contract
        .communication_discipline
        .incident_response
        .required_fields
    {
        assert!(
            seen.insert(field.as_str()),
            "duplicate incident_response field: {}",
            field
        );
    }
    assert!(
        !seen.is_empty(),
        "incident_response required_fields must not be empty"
    );
}

#[test]
fn frx_09_2_rollback_communications_required_fields_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for field in &contract
        .communication_discipline
        .rollback_communications
        .required_fields
    {
        assert!(
            seen.insert(field.as_str()),
            "duplicate rollback_communications field: {}",
            field
        );
    }
    assert!(
        !seen.is_empty(),
        "rollback_communications required_fields must not be empty"
    );
}

#[test]
fn frx_09_2_publication_communications_required_fields_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for field in &contract
        .communication_discipline
        .publication_communications
        .required_fields
    {
        assert!(
            seen.insert(field.as_str()),
            "duplicate publication_communications field: {}",
            field
        );
    }
    assert!(
        !seen.is_empty(),
        "publication_communications required_fields must not be empty"
    );
}

#[test]
fn frx_09_2_claim_publication_record_required_fields_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for field in &contract.claim_publication_record.required_fields {
        assert!(
            seen.insert(field.as_str()),
            "duplicate claim_publication_record field: {}",
            field
        );
    }
    assert!(
        !seen.is_empty(),
        "claim_publication_record required_fields must not be empty"
    );
}

#[test]
fn frx_09_2_stage_checklist_required_checklist_items_are_unique_per_stage() {
    let contract = parse_contract();
    for checklist in &contract.stage_checklists {
        let mut seen = BTreeSet::new();
        for item in &checklist.required_checklist_items {
            assert!(
                seen.insert(item.as_str()),
                "stage '{}' has duplicate checklist item: {}",
                checklist.stage,
                item
            );
        }
        assert!(
            !seen.is_empty(),
            "stage '{}' must have at least one checklist item",
            checklist.stage
        );
    }
}

#[test]
fn frx_09_2_fail_closed_rules_count_at_least_six() {
    let contract = parse_contract();
    assert!(
        contract.fail_closed_rules.len() >= 6,
        "must have at least 6 fail-closed rules, got {}",
        contract.fail_closed_rules.len()
    );
}

#[test]
fn frx_09_2_structured_log_fields_count_at_least_eleven() {
    let contract = parse_contract();
    assert!(
        contract.required_structured_log_fields.len() >= 11,
        "must have at least 11 required structured log fields, got {}",
        contract.required_structured_log_fields.len()
    );
}

#[test]
fn frx_09_2_channel_count_is_nine() {
    let contract = parse_contract();
    assert_eq!(
        contract.release_packet_channels.len(),
        9,
        "expected exactly 9 release packet channels"
    );
}

#[test]
fn frx_09_2_cut_line_source_contract_is_nonempty() {
    let contract = parse_contract();
    assert!(
        !contract
            .consumes_cut_line_artifacts
            .source_contract
            .trim()
            .is_empty(),
        "source_contract must not be empty"
    );
}

#[test]
fn frx_09_2_cut_line_required_lines_are_all_c_prefixed() {
    let contract = parse_contract();
    for cut_line in &contract.consumes_cut_line_artifacts.required_cut_lines {
        assert!(
            cut_line.starts_with('C'),
            "cut-line '{}' must start with 'C'",
            cut_line
        );
    }
}

#[test]
fn frx_09_2_prerequisite_bead_ids_follow_bd_prefix_convention() {
    let contract = parse_contract();
    for p in &contract.prerequisites {
        assert!(
            p.bead_id.starts_with("bd-"),
            "prerequisite bead_id '{}' must start with 'bd-'",
            p.bead_id
        );
    }
}

#[test]
fn frx_09_2_track_id_matches_frx_09_2() {
    let contract = parse_contract();
    assert_eq!(
        contract.track.id, "FRX-09.2",
        "track id must be exactly 'FRX-09.2'"
    );
}

#[test]
fn frx_09_2_serde_json_value_roundtrip_preserves_all_keys() {
    let contract = parse_contract();
    let value: serde_json::Value =
        serde_json::to_value(&contract).expect("serialize to serde_json::Value");
    let expected_keys: BTreeSet<&str> = [
        "schema_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "track",
        "consumes_cut_line_artifacts",
        "release_packet_channels",
        "stage_checklists",
        "communication_discipline",
        "claim_publication_record",
        "fail_closed_rules",
        "required_structured_log_fields",
        "prerequisites",
        "operator_verification",
    ]
    .into_iter()
    .collect();
    let actual_keys: BTreeSet<&str> = value
        .as_object()
        .expect("top-level must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_keys, expected_keys, "top-level JSON keys mismatch");
}

#[test]
fn frx_09_2_operator_verification_count_at_least_three() {
    let contract = parse_contract();
    assert!(
        contract.operator_verification.len() >= 3,
        "must have at least 3 operator verification entries, got {}",
        contract.operator_verification.len()
    );
}

#[test]
fn frx_09_2_generated_by_matches_bead_id() {
    let contract = parse_contract();
    assert_eq!(
        contract.generated_by, contract.bead_id,
        "generated_by must equal bead_id"
    );
}

#[test]
fn frx_09_2_alpha_checklist_items_contain_canary_scope_and_halt_conditions() {
    let contract = parse_contract();
    let alpha = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "alpha")
        .expect("alpha checklist must exist");
    let items: BTreeSet<&str> = alpha
        .required_checklist_items
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        items.contains("canary_scope_defined"),
        "alpha checklist must include canary_scope_defined"
    );
    assert!(
        items.contains("halt_conditions_declared"),
        "alpha checklist must include halt_conditions_declared"
    );
}

#[test]
fn frx_09_2_ga_checklist_items_contain_release_packet_digest_verified() {
    let contract = parse_contract();
    let ga = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "ga")
        .expect("ga checklist must exist");
    let items: BTreeSet<&str> = ga
        .required_checklist_items
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        items.contains("release_packet_digest_verified"),
        "ga checklist must include release_packet_digest_verified"
    );
    assert!(
        items.contains("claim_registry_linkage_complete"),
        "ga checklist must include claim_registry_linkage_complete"
    );
}

#[test]
fn frx_09_2_beta_checklist_items_contain_rollback_drill_and_oncall_readiness() {
    let contract = parse_contract();
    let beta = contract
        .stage_checklists
        .iter()
        .find(|c| c.stage == "beta")
        .expect("beta checklist must exist");
    let items: BTreeSet<&str> = beta
        .required_checklist_items
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        items.contains("rollback_drill_passed"),
        "beta checklist must include rollback_drill_passed"
    );
    assert!(
        items.contains("oncall_readiness_attested"),
        "beta checklist must include oncall_readiness_attested"
    );
}
