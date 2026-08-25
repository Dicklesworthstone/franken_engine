//! bd-nil04: authoritative no-mock shadow-daemon lifecycle drill harness.
//!
//! Consumes a REAL journal capture harvested by
//! `scripts/e2e/shadow_daemon_no_mock_drill.sh` (live `br`/`bv`/Agent Mail/
//! `rch`/`git` state from this repository at drill time) and drives the REAL
//! advisory decision composer over it. No scenario fixtures, no inline-python
//! composition: this is the lane the synthetic drill deliberately refuses to
//! fake (`EXIT_SYNTHETIC_EVIDENCE`).
//!
//! Machinery assertions are verdict-independent: the drill proves the
//! lifecycle machinery is real and deterministic on true inputs — it does not
//! require the repository to be in any particular health state.

use frankenengine_engine::shadow_decision_composer::{
    JournalSourceEvent, MutationPolicy, ShadowDecisionComposerInput, ShadowTruthState,
    compose_shadow_decision,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Required environment-provided directories; the wrapper always sets both.
fn capture_dir() -> PathBuf {
    std::env::var("SHADOW_NO_MOCK_CAPTURE_DIR")
        .expect("SHADOW_NO_MOCK_CAPTURE_DIR must point at the harvested capture directory")
        .into()
}

fn output_root() -> PathBuf {
    std::env::var("SHADOW_NO_MOCK_OUTPUT_ROOT")
        .expect("SHADOW_NO_MOCK_OUTPUT_ROOT must point at the drill evidence directory")
        .into()
}

fn read_trimmed(path: &PathBuf, what: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("drill capture must contain {what} at {path:?}: {error}"))
        .trim()
        .to_string()
}

#[test]
fn authoritative_no_mock_lifecycle_drill_bd_nil04() {
    let capture = capture_dir();
    let output_root = output_root();

    // --- Load the real capture -------------------------------------------------
    let journal_raw = std::fs::read(capture.join("journal.json"))
        .expect("real journal capture must exist; run scripts/e2e/shadow_daemon_no_mock_drill.sh");
    let events: Vec<JournalSourceEvent> = serde_json::from_slice(&journal_raw)
        .expect("captured journal must deserialize into JournalSourceEvent records");

    let source_keys: Vec<String> = events
        .iter()
        .filter_map(|event| event.source_key.clone())
        .collect();
    for required in [
        "br_queue",
        "bv_robot_plan",
        "agent_mail",
        "rch_status",
        "git_state",
        "artifact_bundles",
    ] {
        assert!(
            source_keys.iter().any(|key| key == required),
            "authoritative capture must contain the `{required}` source"
        );
    }

    let revision = read_trimmed(&capture.join("source_revision.txt"), "the captured HEAD");
    let epoch: i64 = read_trimmed(
        &capture.join("generated_epoch_seconds.txt"),
        "the capture epoch",
    )
    .parse()
    .expect("capture epoch must be an integer");
    let run_id = read_trimmed(&capture.join("shadow_run_id.txt"), "the drill run id");

    // --- Compose twice from identical inputs -----------------------------------
    let out_one = output_root.join("composition_1");
    let out_two = output_root.join("composition_2");
    let input_one = ShadowDecisionComposerInput::new(
        run_id.clone(),
        revision.clone(),
        epoch,
        events.clone(),
        &out_one,
    );
    let input_two =
        ShadowDecisionComposerInput::new(run_id, revision, epoch, events.clone(), &out_two);

    let first =
        compose_shadow_decision(&input_one).expect("composition must succeed on the real capture");
    let second =
        compose_shadow_decision(&input_two).expect("repeat composition must succeed identically");

    // Determinism modulo the output-root path that legitimately differs.
    let redacted = |value: &serde_json::Value| -> serde_json::Value {
        fn strip(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    map.remove("artifact_paths");
                    for (_, child) in map.iter_mut() {
                        strip(child);
                    }
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
                _ => {}
            }
        }
        let mut value = value.clone();
        strip(&mut value);
        value
    };
    let first_json = serde_json::json!({
        "status": &first.shadow_status,
        "recommendations": &first.recommendations,
        "notice": &first.operator_notice_md,
        "events": &first.events_jsonl,
        "commands": &first.commands_txt,
        "report": &first.report_md,
    });
    let second_json = serde_json::json!({
        "status": &second.shadow_status,
        "recommendations": &second.recommendations,
        "notice": &second.operator_notice_md,
        "events": &second.events_jsonl,
        "commands": &second.commands_txt,
        "report": &second.report_md,
    });
    assert_eq!(
        redacted(&first_json),
        redacted(&second_json),
        "composition must be byte-stable across repeated runs on identical inputs"
    );

    // --- Advisory-only mutation policy is stamped everywhere -------------------
    let advisory = MutationPolicy::advisory_only();
    assert_eq!(
        first.shadow_status.mutation_policy, advisory,
        "status artifact must carry exactly the immutable advisory-only policy"
    );
    assert_eq!(
        first.recommendations.mutation_policy, advisory,
        "recommendation bundle must carry exactly the immutable advisory-only policy"
    );
    assert!(!advisory.mutates_br && !advisory.reassigns_beads);
    for recommendation in &first.recommendations.recommendations {
        assert!(
            !recommendation.executes_mutation,
            "recommendation {} claims executable mutation",
            recommendation.recommendation_id
        );
    }
    for claim in &first.shadow_status.rejected_mutation_claims {
        assert!(
            !claim.executed,
            "rejected mutation claim {} must record executed=false",
            claim.claim_id
        );
    }

    // --- Derived error codes agree with the captured reality -------------------
    let event_with_key = |key: &str| {
        events
            .iter()
            .find(|event| event.source_key.as_deref() == Some(key))
            .expect("source presence checked above")
    };
    let payload_value = |event: &JournalSourceEvent| {
        event
            .normalized_payload
            .clone()
            .or_else(|| event.payload.clone())
            .expect("captured sources must carry their payload")
    };

    let git_payload = payload_value(event_with_key("git_state"));
    let dirty_worktree = git_payload
        .get("dirty")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    assert_eq!(
        dirty_worktree,
        first
            .shadow_status
            .error_codes
            .iter()
            .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE"),
        "dirty-worktree error code must track the captured git state exactly"
    );

    let artifact_payload = payload_value(event_with_key("artifact_bundles"));
    let has_no_mock_artifacts = artifact_payload
        .get("no_mock_proof_artifacts")
        .and_then(|value| value.as_array())
        .is_some_and(|items| !items.is_empty());
    if !has_no_mock_artifacts {
        assert!(
            first
                .shadow_status
                .error_codes
                .iter()
                .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"),
            "an empty no-mock proof set must surface its dedicated error code"
        );
    }

    if dirty_worktree || !has_no_mock_artifacts {
        assert_ne!(
            first.recommendations.truth_state,
            ShadowTruthState::Confirmed,
            "a degraded capture must never compose into a Confirmed truth state"
        );
    }

    // --- Evidence bundle -------------------------------------------------------
    assert!(!first.events_jsonl.is_empty());
    assert!(!first.commands_txt.is_empty());
    assert!(!first.report_md.is_empty());
    assert!(!first.operator_notice_md.is_empty());

    let evidence = serde_json::json!({
        "drill": "authoritative_no_mock_lifecycle",
        "bead": "bd-nil04",
        "shadow_run_id": &first.shadow_status.shadow_run_id,
        "source_revision": &first.shadow_status.source_revision,
        "generated_epoch_seconds": first.shadow_status.generated_epoch_seconds,
        "truth_state": &first.recommendations.truth_state,
        "decision": &first.recommendations.decision,
        "recommendation_count": first.recommendations.recommendations.len(),
        "all_recommendations_advisory": first
            .recommendations
            .recommendations
            .iter()
            .all(|item| !item.executes_mutation),
        "determinism": "byte-identical-across-repeat-composition",
    });
    std::fs::write(
        output_root.join("drill_evidence.json"),
        serde_json::to_string_pretty(&evidence).expect("evidence serializes") + "\n",
    )
    .expect("evidence bundle writes");

    // Keep the per-source hashes visible in the transcript for the operator log.
    let hashes: BTreeMap<String, Option<String>> = events
        .iter()
        .map(|event| {
            (
                event.source_key.clone().unwrap_or_default(),
                event.content_hash.clone(),
            )
        })
        .collect();
    println!("authoritative drill composed {:#?}", hashes);
}
