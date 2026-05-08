use std::{fs, path::PathBuf};

use frankenengine_engine::shadow_decision_composer::{
    AdvisoryRecommendation, ExistingAutopilotOutput, JournalSourceEvent, MutationPolicy,
    ShadowDecision, ShadowDecisionComposerInput, ShadowTruthState, compose_shadow_decision,
    write_shadow_decision_artifacts,
};
use serde_json::{Value, json};

const NOW_EPOCH_SECONDS: i64 = 1_778_123_000;

#[test]
fn shadow_decision_composer_covers_operator_conditions() {
    for case in composer_cases() {
        let output_dir = output_dir_for(case.case_id);
        let mut input = input_for_case(case.case_id, case.events, &output_dir);
        if let Some(max_recommendations) = case.max_recommendations {
            input.max_recommendations = max_recommendations;
        }

        let artifacts = compose_shadow_decision(&input).expect(case.case_id);
        let repeated_artifacts = compose_shadow_decision(&input).expect(case.case_id);
        assert_eq!(artifacts.shadow_status, repeated_artifacts.shadow_status);
        assert_eq!(
            artifacts.recommendations,
            repeated_artifacts.recommendations
        );

        assert_eq!(artifacts.shadow_status.truth_state, case.truth_state);
        assert_eq!(artifacts.shadow_status.decision, case.decision);
        assert_eq!(artifacts.recommendations.truth_state, case.truth_state);
        assert_eq!(artifacts.recommendations.decision, case.decision);
        assert!(has_action(
            &artifacts.shadow_status.advisory_recommendations,
            case.required_action,
        ));
        if let Some(required_error_code) = case.required_error_code {
            assert!(
                artifacts
                    .shadow_status
                    .error_codes
                    .iter()
                    .any(|code| code == required_error_code),
                "{} missing {required_error_code}",
                case.case_id
            );
        }

        assert_advisory_only(&artifacts.shadow_status.mutation_policy);
        assert_eq!(
            artifacts.shadow_status.mutation_policy,
            artifacts.recommendations.mutation_policy
        );
        assert_sorted_and_bounded(
            &artifacts.shadow_status.advisory_recommendations,
            input.max_recommendations,
        );
        for recommendation in &artifacts.shadow_status.advisory_recommendations {
            assert!(!recommendation.executes_mutation);
            assert!(recommendation.remediation_only);
            assert!(!recommendation.command_text.trim().is_empty());
            assert!(!recommendation.source_event_ids.is_empty());
            assert!(!recommendation.source_hashes.is_empty());
            assert!(!recommendation.source_collected_epoch_seconds.is_empty());
        }

        write_shadow_decision_artifacts(&output_dir, &artifacts).expect(case.case_id);
        assert_nonempty(output_dir.join("shadow_status.json"));
        assert_nonempty(output_dir.join("recommendations.json"));
        assert_nonempty(output_dir.join("operator_notice.md"));
        let status_json =
            fs::read_to_string(output_dir.join("shadow_status.json")).expect("status artifact");
        let status_value: Value = serde_json::from_str(&status_json).expect("status json");
        assert_eq!(
            status_value["mutation_policy"]["runs_rch"],
            Value::Bool(false)
        );
        assert_eq!(
            status_value["mutation_policy"]["mutates_br"],
            Value::Bool(false)
        );
    }
}

#[test]
fn shadow_decision_composer_rejects_output_paths_outside_directory() {
    let output_dir = output_dir_for("outside-output-dir");
    let mut input = input_for_case("outside-output-dir", base_events(), &output_dir);
    input.artifact_paths.shadow_status_json = std::env::temp_dir()
        .join(format!(
            "franken-engine-shadow-decision-outside-{}-shadow_status.json",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned();

    let artifacts = compose_shadow_decision(&input).expect("compose outside path case");
    let error = write_shadow_decision_artifacts(&output_dir, &artifacts)
        .expect_err("outside artifact path should be rejected");
    assert!(error.to_string().contains("outside output dir"));
}

struct ComposerCase {
    case_id: &'static str,
    events: Vec<JournalSourceEvent>,
    truth_state: ShadowTruthState,
    decision: ShadowDecision,
    required_action: &'static str,
    required_error_code: Option<&'static str>,
    max_recommendations: Option<usize>,
}

fn composer_cases() -> Vec<ComposerCase> {
    vec![
        ComposerCase {
            case_id: "healthy_idle_queue",
            events: base_events(),
            truth_state: ShadowTruthState::Confirmed,
            decision: ShadowDecision::Pass,
            required_action: "observe_idle_queue",
            required_error_code: None,
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "active_owned_lane",
            events: with_br_payload(json!({
                "ready": [],
                "in_progress": {
                    "issues": [{
                        "id": "bd-djejh.4",
                        "assignee": "CyanWolf",
                        "updated_epoch_seconds": NOW_EPOCH_SECONDS - 30
                    }]
                }
            })),
            truth_state: ShadowTruthState::Confirmed,
            decision: ShadowDecision::Pass,
            required_action: "continue_owned_lane",
            required_error_code: None,
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "stalled_agent_lane",
            events: with_br_payload(json!({
                "ready": [],
                "in_progress": {
                    "issues": [{
                        "id": "bd-stalled",
                        "assignee": "OldAgent",
                        "updated_epoch_seconds": NOW_EPOCH_SECONDS - 7_200
                    }]
                }
            })),
            truth_state: ShadowTruthState::Degraded,
            decision: ShadowDecision::Degraded,
            required_action: "review_stalled_bead",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "stale_reservation",
            events: with_agent_mail_payload(json!({
                "active_reservations": [{
                    "path": "scripts/example.sh",
                    "holder": "OldAgent",
                    "stale": true,
                    "expires_epoch_seconds": NOW_EPOCH_SECONDS - 1
                }]
            })),
            truth_state: ShadowTruthState::Degraded,
            decision: ShadowDecision::Degraded,
            required_action: "review_stale_reservation",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "contradictory_ownership",
            events: with_source_error(
                "br_queue",
                "FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP",
            ),
            truth_state: ShadowTruthState::Blocked,
            decision: ShadowDecision::FailClosed,
            required_action: "reconcile_bead_ownership",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "agent_mail_degraded",
            events: with_source_error("agent_mail", "FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"),
            truth_state: ShadowTruthState::Degraded,
            decision: ShadowDecision::Degraded,
            required_action: "refresh_degraded_sources",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "dirty_worktree",
            events: with_git_payload(json!({
                "dirty": true,
                "lines": ["## main...origin/main", " M scripts/example.sh"]
            })),
            truth_state: ShadowTruthState::Degraded,
            decision: ShadowDecision::Degraded,
            required_action: "inspect_dirty_worktree",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "rch_fallback_contamination",
            events: with_rch_fallback(),
            truth_state: ShadowTruthState::Contaminated,
            decision: ShadowDecision::FailClosed,
            required_action: "rerun_rch_remote_proof",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "missing_no_mock_proof",
            events: with_artifacts_payload(json!({ "no_mock_proof_artifacts": [] })),
            truth_state: ShadowTruthState::Degraded,
            decision: ShadowDecision::Degraded,
            required_action: "request_no_mock_proof",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"),
            max_recommendations: None,
        },
        ComposerCase {
            case_id: "bounded_recommendations",
            events: with_many_degraded_inputs(),
            truth_state: ShadowTruthState::Contaminated,
            decision: ShadowDecision::FailClosed,
            required_action: "observe_idle_queue",
            required_error_code: Some("FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"),
            max_recommendations: Some(3),
        },
    ]
}

fn input_for_case(
    case_id: &str,
    events: Vec<JournalSourceEvent>,
    output_dir: &PathBuf,
) -> ShadowDecisionComposerInput {
    let mut input = ShadowDecisionComposerInput::new(
        format!("shadow-run-{case_id}"),
        format!("fixture-{case_id}"),
        NOW_EPOCH_SECONDS,
        events,
        output_dir,
    );
    input.existing_autopilot_outputs = vec![ExistingAutopilotOutput {
        path: format!("fixture/{case_id}/existing_autopilot.json"),
        schema_version: "franken-engine.swarm-autopilot-recommendation-bundle.v1".to_string(),
        content_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
    }];
    input
}

fn base_events() -> Vec<JournalSourceEvent> {
    vec![
        source(
            "br_queue",
            "br-queue-base",
            "br_queue_snapshot_json",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            80,
            json!({ "ready": [], "in_progress": { "issues": [] } }),
        ),
        source(
            "bv_robot_plan",
            "bv-plan-base",
            "bv_robot_plan_json",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            79,
            json!({ "actionable_tracks": [] }),
        ),
        source(
            "agent_mail",
            "agent-mail-base",
            "agent_mail_snapshot_json",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            78,
            json!({ "active_reservations": [] }),
        ),
        source(
            "rch_status",
            "rch-status-base",
            "rch_status_snapshot_json",
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            77,
            json!({ "remote_ok": true }),
        ),
        source(
            "git_state",
            "git-state-base",
            "git_state_snapshot_json",
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            76,
            json!({ "dirty": false, "lines": ["## main...origin/main"] }),
        ),
        source(
            "artifact_bundles",
            "artifact-bundles-base",
            "artifact_bundle_snapshot_json",
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            75,
            json!({ "no_mock_proof_artifacts": ["artifacts/no_mock/proof.json"] }),
        ),
    ]
}

fn source(
    source_key: &str,
    source_id: &str,
    source_kind: &str,
    content_hash: &str,
    age_seconds: i64,
    payload: Value,
) -> JournalSourceEvent {
    JournalSourceEvent {
        source_key: Some(source_key.to_string()),
        source_id: Some(source_id.to_string()),
        source_kind: Some(source_kind.to_string()),
        schema_version: Some(
            "franken-engine.swarm-autopilot-shadow-source-snapshot.v1".to_string(),
        ),
        content_hash: Some(content_hash.to_string()),
        collected_epoch_seconds: Some(NOW_EPOCH_SECONDS - age_seconds),
        freshness_window_seconds: Some(300),
        fresh: Some(true),
        degraded: Some(false),
        raw_payload_ref: Some(format!("fixture/{source_key}.json")),
        payload: Some(payload),
        ..JournalSourceEvent::default()
    }
}

fn with_br_payload(payload: Value) -> Vec<JournalSourceEvent> {
    with_payload("br_queue", payload)
}

fn with_agent_mail_payload(payload: Value) -> Vec<JournalSourceEvent> {
    with_payload("agent_mail", payload)
}

fn with_git_payload(payload: Value) -> Vec<JournalSourceEvent> {
    with_payload("git_state", payload)
}

fn with_artifacts_payload(payload: Value) -> Vec<JournalSourceEvent> {
    with_payload("artifact_bundles", payload)
}

fn with_payload(source_key: &str, payload: Value) -> Vec<JournalSourceEvent> {
    let mut events = base_events();
    event_mut(&mut events, source_key).payload = Some(payload);
    events
}

fn with_source_error(source_key: &str, error_code: &str) -> Vec<JournalSourceEvent> {
    let mut events = base_events();
    let event = event_mut(&mut events, source_key);
    event.degraded = Some(true);
    event.error_codes = vec![error_code.to_string()];
    events
}

fn with_rch_fallback() -> Vec<JournalSourceEvent> {
    let mut events =
        with_source_error("rch_status", "FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK");
    event_mut(&mut events, "rch_status").local_fallback_contamination = true;
    events
}

fn with_many_degraded_inputs() -> Vec<JournalSourceEvent> {
    let mut events = with_rch_fallback();
    event_mut(&mut events, "git_state").payload =
        Some(json!({ "dirty": true, "lines": [" M scripts/example.sh"] }));
    event_mut(&mut events, "artifact_bundles").payload =
        Some(json!({ "no_mock_proof_artifacts": [] }));
    let mail = event_mut(&mut events, "agent_mail");
    mail.degraded = Some(true);
    mail.error_codes = vec!["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE".to_string()];
    mail.payload = Some(json!({
        "active_reservations": [{
            "path": "scripts/example.sh",
            "holder": "OldAgent",
            "stale": true
        }]
    }));
    events
}

fn event_mut<'a>(
    events: &'a mut [JournalSourceEvent],
    source_key: &str,
) -> &'a mut JournalSourceEvent {
    events
        .iter_mut()
        .find(|event| event.source_key.as_deref() == Some(source_key))
        .expect("fixture source key")
}

fn has_action(recommendations: &[AdvisoryRecommendation], action_class: &str) -> bool {
    recommendations
        .iter()
        .any(|recommendation| recommendation.action_class == action_class)
}

fn assert_advisory_only(policy: &MutationPolicy) {
    assert!(policy.advisory_only);
    assert!(policy.proof_only);
    assert!(!policy.mutates_br);
    assert!(!policy.reassigns_beads);
    assert!(!policy.releases_reservations);
    assert!(!policy.sends_agent_mail);
    assert!(!policy.runs_cargo);
    assert!(!policy.runs_rch);
    assert!(!policy.mutates_git);
    assert!(!policy.mutates_remote_workers);
    assert!(!policy.changes_live_queue_policy);
    assert!(!policy.writes_outside_output_dir);
}

fn assert_sorted_and_bounded(recommendations: &[AdvisoryRecommendation], max: usize) {
    assert!(recommendations.len() <= max);
    for pair in recommendations.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        assert!(
            (left.rank, left.recommendation_id.as_str())
                <= (right.rank, right.recommendation_id.as_str())
        );
    }
}

fn assert_nonempty(path: PathBuf) {
    let metadata = fs::metadata(path).expect("artifact metadata");
    assert!(metadata.len() > 0);
}

fn output_dir_for(case_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "franken-engine-shadow-decision-composer-rust-{}-{case_id}",
        std::process::id()
    ))
}
