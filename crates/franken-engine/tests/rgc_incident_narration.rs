//! RGC incident-narration gate lane (bd-cixqu.24.3, Track X.3).
//!
//! The load-bearing contract: replaying a decision must regenerate the
//! narration receipt (bd-cixqu.24.2) with byte-identical
//! `narrative_text_canonical` — otherwise the narration is storytelling, not
//! reproducible evidence. These lanes drive the real constrained-grammar
//! canonicalizer and the real Ed25519 receipt plumbing (no fixtures):
//!
//! 1. identical replay passes (original vs regenerated receipt + narration);
//! 2. an intentionally perturbed decision input diverges and the check
//!    reports a diff (first divergence byte, both hashes);
//! 3. the gate lane prints a single-line JSON verdict marker
//!    (`RGC_INCIDENT_NARRATION_VERDICT: {...}`) carrying the original and
//!    replayed narration hashes plus the verdict, which
//!    `scripts/run_rgc_incident_narration.sh` extracts into
//!    `incident_narration_report.json` per the bd-cixqu.45 logging
//!    discipline.

use frankenengine_engine::galaxy_brain_explainability::{
    CounterfactualOutcome, DecisionDomain, DecisionExplanation, ExplanationBuilder,
    NarrationReceipt, NarrationReplayVerdict, NarrativeGrammarPolicy, VerbosityLevel,
    narration_replay_check,
};
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId, RegimeLabel};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn gate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x24;
    bytes[31] = 0x03;
    SigningKey::from_bytes(bytes).expect("non-zero key")
}

fn counterfactual(lane: &str, delta: i64, guardrail: bool) -> CounterfactualOutcome {
    CounterfactualOutcome {
        action: LaneAction::RouteTo(LaneId(lane.to_string())),
        predicted_loss_millionths: 150_000 + delta,
        loss_delta_millionths: delta,
        would_trigger_guardrail: guardrail,
        narrative: format!("counterfactual lane {lane}"),
    }
}

/// The fixed incident decision this gate narrates. `perturb_loss_millionths`
/// is the intentional-divergence knob: zero reproduces the original decision
/// input exactly.
fn incident_decision(perturb_loss_millionths: i64) -> DecisionExplanation {
    ExplanationBuilder::new(
        "rgc-narration-incident-1".to_string(),
        SecurityEpoch::from_raw(24),
        DecisionDomain::Security,
    )
    .verbosity(VerbosityLevel::GalaxyBrain)
    .regime(RegimeLabel::Attack)
    .chosen(
        LaneAction::RouteTo(LaneId("containment".to_string())),
        250_000 + perturb_loss_millionths,
    )
    .rationale("quarantine the exfiltrating extension".to_string())
    .counterfactual(counterfactual("allow", 300_000, true))
    .counterfactual(counterfactual("sandbox", -40_000, false))
    .counterfactual(counterfactual("terminate", 90_000, false))
    .posterior("compromise".to_string(), 810_000)
    .posterior("benign_drift".to_string(), 90_000)
    .confidence(910_000)
    .build()
    .expect("builder should produce a valid value")
}

fn policy() -> NarrativeGrammarPolicy {
    NarrativeGrammarPolicy::default()
}

#[test]
fn replaying_the_same_decision_regenerates_byte_identical_narration() {
    let key = gate_signing_key();
    let original = NarrationReceipt::from_explanation(&incident_decision(0), policy(), &key)
        .expect("original receipt builds");
    original
        .verify(&key.verification_key())
        .expect("original receipt verifies");

    // Replay: rebuild the decision from the same fixed inputs and regenerate
    // both the narration and the full receipt.
    let replayed_narrative = incident_decision(0).constrained_narrative(policy());
    let verdict = narration_replay_check(&original, &replayed_narrative);
    assert!(
        verdict.is_identical(),
        "replayed narration must be byte-identical: {verdict:?}"
    );

    // Ed25519 (RFC 8032) is deterministic: the fully regenerated receipt is
    // equal down to the signature.
    let regenerated = NarrationReceipt::from_explanation(&incident_decision(0), policy(), &key)
        .expect("regenerated receipt builds");
    assert_eq!(regenerated, original);
}

#[test]
fn perturbed_decision_input_diverges_and_reports_a_diff() {
    let key = gate_signing_key();
    let original = NarrationReceipt::from_explanation(&incident_decision(0), policy(), &key)
        .expect("original receipt builds");
    let perturbed_narrative = incident_decision(1).constrained_narrative(policy());
    match narration_replay_check(&original, &perturbed_narrative) {
        NarrationReplayVerdict::Divergent {
            original_hash,
            replayed_hash,
            first_divergence_index,
            original_len,
            replayed_len,
        } => {
            assert_ne!(original_hash, replayed_hash);
            assert!(first_divergence_index < original_len.max(replayed_len));
        }
        identical => panic!("perturbed input must diverge, got {identical:?}"),
    }
}

#[test]
fn incident_narration_gate_emits_verdict_marker() {
    let key = gate_signing_key();
    let original = NarrationReceipt::from_explanation(&incident_decision(0), policy(), &key)
        .expect("original receipt builds");
    let report = original
        .verify(&key.verification_key())
        .expect("original receipt verifies");

    let replayed = incident_decision(0).constrained_narrative(policy());
    let identical_verdict = narration_replay_check(&original, &replayed);

    let perturbed = incident_decision(1).constrained_narrative(policy());
    let perturbed_verdict = narration_replay_check(&original, &perturbed);

    // Both lanes must hold for the gate to pass.
    assert!(identical_verdict.is_identical());
    assert!(!perturbed_verdict.is_identical());

    // bd-cixqu.45 logging discipline: original vs replayed narration hashes
    // and the gate verdict, as a single machine-extractable line.
    let marker = serde_json::json!({
        "schema_version": "franken-engine.rgc-incident-narration-verdict.v1",
        "decision_id": original.decision_id,
        "original_narrative_hash": original.narrative_content_hash,
        "replayed_narrative_hash": replayed.content_hash,
        "identical_replay": identical_verdict.is_identical(),
        "perturbation_detected": !perturbed_verdict.is_identical(),
        "perturbed_verdict": perturbed_verdict,
        "receipt_content_hash": report.content_hash_hex,
        "receipt_canonical_byte_len": report.canonical_byte_len,
        "receipt_signature_valid": report.signature_valid,
        "gate_verdict": "pass",
    });
    println!(
        "RGC_INCIDENT_NARRATION_VERDICT: {}",
        serde_json::to_string(&marker).expect("marker serializes")
    );
}
