//! Proof-spine claim gate: claim state as a mechanical consequence of live
//! proof.json producer artifacts (bd-fqlfw.6.5, E6.T5).
//!
//! Layer over the strict E6.T1 producer contract in [`crate::proof_schema`]:
//! each [`ProofProducerArtifact`] is classified into the five-way taxonomy
//! (Proven / Counterexample / Unknown / Unavailable / FixtureOnly, plus
//! Invalid for integrity failures), and a per-claim decision is derived
//! fail-closed from the classified artifact set:
//!
//! - a claim promotes to OBSERVED only on at least one integrity-checked
//!   `Passed` artifact from that claim's registered producer tool;
//! - fixture-only artifacts are rejected as backing evidence (mirrors the
//!   `MockCertificate` treatment) and can never promote;
//! - a counterexample or an artifact integrity failure (hash mismatch,
//!   malformed body) demotes a currently-OBSERVED claim;
//! - the v2-deferred claims (FE-CLAIM-018..021, per bd-cixqu.7.17) stay
//!   HYPOTHESIS via `Unavailable` even if an artifact fabricates `Passed`
//!   for them — there is no registered producer that may promote them.
//!
//! Consumers (the E6.TEST capstone gate and the claim-to-proof matrix
//! tooling) get precise failure modes ("producer did not run", "backend
//! unavailable", "counterexample found", "artifact hash mismatch") instead
//! of a bare boolean.

use serde::{Deserialize, Serialize};

use crate::proof_schema::{
    ProofCheckerResult, ProofProducerArtifact, ProofSignatureOrContentHash,
    validate_proof_producer_artifact,
};
use crate::signature_preimage::SIGNATURE_LEN;

/// Claims the proof-spine v1 may promote, with the producer tool that is
/// registered to back each of them.
pub const PROOF_SPINE_V1_REGISTERED_PRODUCERS: [(&str, &str); 2] = [
    ("FE-CLAIM-016", "lean4"),
    ("FE-CLAIM-017", "translation-validator"),
];

/// Claims explicitly deferred to proof-spine v2 (bd-cixqu.7.17): they stay
/// HYPOTHESIS via `Unavailable` and no artifact may promote them.
pub const PROOF_SPINE_V2_DEFERRED_CLAIMS: [&str; 4] = [
    "FE-CLAIM-018",
    "FE-CLAIM-019",
    "FE-CLAIM-020",
    "FE-CLAIM-021",
];

/// Registered producer tool for a claim, if the spine knows the claim.
pub fn registered_producer_tool(claim_id: &str) -> Option<&'static str> {
    PROOF_SPINE_V1_REGISTERED_PRODUCERS
        .iter()
        .find(|(claim, _)| *claim == claim_id)
        .map(|(_, tool)| *tool)
}

/// True when the claim is deferred to proof-spine v2.
pub fn is_v2_deferred_claim(claim_id: &str) -> bool {
    PROOF_SPINE_V2_DEFERRED_CLAIMS.contains(&claim_id)
}

/// Five-way classification of a producer artifact, plus `Invalid` for
/// artifacts whose integrity or structure fails independent of the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "class")]
pub enum ProofArtifactClass {
    /// Integrity-checked `Passed` verdict from the producer.
    Proven,
    /// The checker found a real counterexample or proof failure.
    Counterexample { reason: String },
    /// The checker ran but produced no verdict.
    Unknown { reason: String },
    /// The backend could not run to a verdict.
    Unavailable { reason: String },
    /// Fixture-only backend; may never promote a real claim.
    FixtureOnly { reason: String },
    /// The artifact itself is untrustworthy: hash mismatch, malformed body,
    /// or structural contract violation.
    Invalid { reason: String },
}

/// Classify one producer artifact. Integrity is checked before the verdict
/// is honoured: a tampered artifact is `Invalid` even if it says `Passed`.
pub fn classify_proof_artifact(artifact: &ProofProducerArtifact) -> ProofArtifactClass {
    if let Some(reason) = integrity_failure_reason(artifact) {
        return ProofArtifactClass::Invalid { reason };
    }
    match &artifact.checker_result {
        ProofCheckerResult::Passed => match validate_proof_producer_artifact(artifact) {
            Ok(()) => ProofArtifactClass::Proven,
            Err(err) => ProofArtifactClass::Invalid {
                reason: format!("passed verdict with invalid artifact body: {err:?}"),
            },
        },
        ProofCheckerResult::Failed { reason } => ProofArtifactClass::Counterexample {
            reason: reason.clone(),
        },
        ProofCheckerResult::Inconclusive { reason } => ProofArtifactClass::Unknown {
            reason: reason.clone(),
        },
        ProofCheckerResult::Unavailable { reason } => ProofArtifactClass::Unavailable {
            reason: reason.clone(),
        },
        ProofCheckerResult::FixtureOnly { reason } => ProofArtifactClass::FixtureOnly {
            reason: reason.clone(),
        },
    }
}

fn integrity_failure_reason(artifact: &ProofProducerArtifact) -> Option<String> {
    match &artifact.signature_or_content_hash {
        ProofSignatureOrContentHash::ContentHash(observed) => {
            let expected = artifact.content_hash();
            if !observed.constant_time_eq(&expected) {
                return Some(
                    "artifact hash mismatch: content commitment does not \
                     match the recomputed body hash"
                        .to_string(),
                );
            }
        }
        ProofSignatureOrContentHash::Signature { signature, .. } => {
            if signature.len() != SIGNATURE_LEN {
                return Some(format!(
                    "artifact signature has invalid length {}",
                    signature.len()
                ));
            }
            if signature.iter().all(|byte| *byte == 0) {
                return Some("artifact signature is all zeroes".to_string());
            }
        }
    }
    None
}

/// Precise failure mode attached to a non-promoting finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "failure")]
pub enum ClaimSpineFailure {
    /// No producer artifact references the claim at all.
    ProducerDidNotRun { expected_tool: String },
    /// The backend could not run to a verdict.
    BackendUnavailable { producer: String, reason: String },
    /// The checker ran but produced no verdict.
    VerdictUnknown { producer: String, reason: String },
    /// A real counterexample was found.
    CounterexampleFound { producer: String, reason: String },
    /// A fixture-only artifact was rejected as backing evidence.
    FixtureOnlyRejected { producer: String, reason: String },
    /// Hash mismatch or malformed artifact body.
    ArtifactIntegrityFailure { producer: String, reason: String },
    /// The artifact's producer tool is not registered for this claim.
    UnregisteredProducer {
        producer: String,
        expected_tool: String,
    },
    /// The claim is deferred to proof-spine v2 and may not promote.
    V2Deferred { claim_id: String },
}

/// Per-artifact finding recorded in the claim verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSpineFinding {
    /// `tool_identity` display string of the producer.
    pub producer: String,
    /// Theorem or validator ID from the artifact.
    pub theorem_or_validator_id: String,
    /// Classification of the artifact.
    pub class: ProofArtifactClass,
    /// Failure mode, absent when the artifact backs promotion.
    pub failure: Option<ClaimSpineFailure>,
}

/// Final gate action for a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSpineAction {
    /// Live artifact state supports OBSERVED wording.
    PromoteObserved,
    /// The claim must stay (or return to) HYPOTHESIS/TARGETED wording.
    StayHypothesis,
    /// The claim was OBSERVED but its artifact state regressed: demote.
    Demote,
}

/// Deterministic per-claim verdict derived from live artifact state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSpineVerdict {
    /// Claim under decision.
    pub claim_id: String,
    /// Final action.
    pub action: ClaimSpineAction,
    /// Per-artifact findings (order follows the input artifact order).
    pub findings: Vec<ClaimSpineFinding>,
    /// One-line operator-facing explanation of the action.
    pub explanation: String,
}

/// Decide the gate action for `claim_id` from the live artifact set.
///
/// `currently_observed` is the claim's present matrix state; it selects
/// between `StayHypothesis` (never promoted) and `Demote` (regression) when
/// the artifact state does not support OBSERVED.
pub fn decide_claim_state(
    claim_id: &str,
    currently_observed: bool,
    artifacts: &[ProofProducerArtifact],
) -> ClaimSpineVerdict {
    if is_v2_deferred_claim(claim_id) {
        return decide_v2_deferred(claim_id, currently_observed, artifacts);
    }

    let expected_tool = registered_producer_tool(claim_id);
    let mut findings = Vec::new();
    let mut proven_backing = 0usize;
    let mut hard_failure = false;

    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.claim_ids.iter().any(|claim| claim == claim_id))
    {
        let producer = artifact.tool_identity.to_string();
        let class = classify_proof_artifact(artifact);

        let unregistered = expected_tool
            .is_some_and(|expected| artifact.tool_identity.tool_name != expected)
            .then(|| ClaimSpineFailure::UnregisteredProducer {
                producer: producer.clone(),
                expected_tool: expected_tool.unwrap_or_default().to_string(),
            });

        let failure = match (&class, unregistered) {
            // An unregistered producer can never back promotion, whatever
            // its verdict says.
            (_, Some(failure)) => Some(failure),
            (ProofArtifactClass::Proven, None) => {
                proven_backing += 1;
                None
            }
            (ProofArtifactClass::Counterexample { reason }, None) => {
                hard_failure = true;
                Some(ClaimSpineFailure::CounterexampleFound {
                    producer: producer.clone(),
                    reason: reason.clone(),
                })
            }
            (ProofArtifactClass::Unknown { reason }, None) => {
                Some(ClaimSpineFailure::VerdictUnknown {
                    producer: producer.clone(),
                    reason: reason.clone(),
                })
            }
            (ProofArtifactClass::Unavailable { reason }, None) => {
                Some(ClaimSpineFailure::BackendUnavailable {
                    producer: producer.clone(),
                    reason: reason.clone(),
                })
            }
            (ProofArtifactClass::FixtureOnly { reason }, None) => {
                Some(ClaimSpineFailure::FixtureOnlyRejected {
                    producer: producer.clone(),
                    reason: reason.clone(),
                })
            }
            (ProofArtifactClass::Invalid { reason }, None) => {
                hard_failure = true;
                Some(ClaimSpineFailure::ArtifactIntegrityFailure {
                    producer: producer.clone(),
                    reason: reason.clone(),
                })
            }
        };

        findings.push(ClaimSpineFinding {
            producer,
            theorem_or_validator_id: artifact.theorem_or_validator_id.clone(),
            class,
            failure,
        });
    }

    if findings.is_empty() {
        let expected = expected_tool.unwrap_or("unregistered").to_string();
        let action = non_promoting_action(currently_observed);
        return ClaimSpineVerdict {
            claim_id: claim_id.to_string(),
            action,
            findings: vec![ClaimSpineFinding {
                producer: expected.clone(),
                theorem_or_validator_id: String::new(),
                class: ProofArtifactClass::Unavailable {
                    reason: "no producer artifact present".to_string(),
                },
                failure: Some(ClaimSpineFailure::ProducerDidNotRun {
                    expected_tool: expected,
                }),
            }],
            explanation: format!(
                "{claim_id}: producer did not run — no live artifact references the claim"
            ),
        };
    }

    // Promotion requires at least one integrity-checked Passed artifact from
    // the registered producer and no counterexample / integrity failure.
    let (action, explanation) = if hard_failure {
        (
            non_promoting_action(currently_observed),
            format!(
                "{claim_id}: counterexample or artifact integrity failure — \
                 OBSERVED wording is not supported"
            ),
        )
    } else if proven_backing > 0 {
        (
            ClaimSpineAction::PromoteObserved,
            format!(
                "{claim_id}: {proven_backing} integrity-checked Proven artifact(s) \
                 from the registered producer"
            ),
        )
    } else {
        (
            non_promoting_action(currently_observed),
            format!(
                "{claim_id}: no Proven backing artifact (unavailable / unknown / \
                 fixture-only artifacts cannot promote)"
            ),
        )
    };

    ClaimSpineVerdict {
        claim_id: claim_id.to_string(),
        action,
        findings,
        explanation,
    }
}

fn decide_v2_deferred(
    claim_id: &str,
    currently_observed: bool,
    artifacts: &[ProofProducerArtifact],
) -> ClaimSpineVerdict {
    let mut findings: Vec<ClaimSpineFinding> = artifacts
        .iter()
        .filter(|artifact| artifact.claim_ids.iter().any(|claim| claim == claim_id))
        .map(|artifact| ClaimSpineFinding {
            producer: artifact.tool_identity.to_string(),
            theorem_or_validator_id: artifact.theorem_or_validator_id.clone(),
            class: classify_proof_artifact(artifact),
            failure: Some(ClaimSpineFailure::V2Deferred {
                claim_id: claim_id.to_string(),
            }),
        })
        .collect();
    if findings.is_empty() {
        findings.push(ClaimSpineFinding {
            producer: "none".to_string(),
            theorem_or_validator_id: String::new(),
            class: ProofArtifactClass::Unavailable {
                reason: "proof-spine v2 deferred; no real producer exists".to_string(),
            },
            failure: Some(ClaimSpineFailure::V2Deferred {
                claim_id: claim_id.to_string(),
            }),
        });
    }
    // A v2-deferred claim that somehow reads OBSERVED is a regression: demote.
    let action = non_promoting_action(currently_observed);
    ClaimSpineVerdict {
        claim_id: claim_id.to_string(),
        action,
        findings,
        explanation: format!(
            "{claim_id}: deferred to proof-spine v2 (bd-cixqu.7.17) — stays \
             HYPOTHESIS via Unavailable; artifacts cannot promote it"
        ),
    }
}

fn non_promoting_action(currently_observed: bool) -> ClaimSpineAction {
    if currently_observed {
        ClaimSpineAction::Demote
    } else {
        ClaimSpineAction::StayHypothesis
    }
}

/// Decide every claim the spine knows about (v1 registered + v2 deferred)
/// against one artifact pool. `observed_claims` lists claims whose current
/// matrix wording is OBSERVED.
pub fn decide_all_spine_claims(
    observed_claims: &[&str],
    artifacts: &[ProofProducerArtifact],
) -> Vec<ClaimSpineVerdict> {
    let mut verdicts = Vec::new();
    for (claim_id, _tool) in PROOF_SPINE_V1_REGISTERED_PRODUCERS {
        let currently_observed = observed_claims.contains(&claim_id);
        verdicts.push(decide_claim_state(claim_id, currently_observed, artifacts));
    }
    for claim_id in PROOF_SPINE_V2_DEFERRED_CLAIMS {
        let currently_observed = observed_claims.contains(&claim_id);
        verdicts.push(decide_claim_state(claim_id, currently_observed, artifacts));
    }
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::proof_schema::{ProofToolIdentity, proof_schema_version_current};
    use crate::security_epoch::SecurityEpoch;
    use std::collections::BTreeMap;

    fn artifact(
        claim_id: &str,
        tool_name: &str,
        checker_result: ProofCheckerResult,
    ) -> ProofProducerArtifact {
        let mut input_artifact_hashes = BTreeMap::new();
        input_artifact_hashes.insert("input.lean".to_string(), ContentHash::compute(b"input"));
        let mut output_artifact_hashes = BTreeMap::new();
        output_artifact_hashes.insert("build.log".to_string(), ContentHash::compute(b"output"));
        let mut artifact = ProofProducerArtifact {
            schema_version: proof_schema_version_current(),
            claim_ids: vec![claim_id.to_string()],
            theorem_or_validator_id: "test::theorem".to_string(),
            input_artifact_hashes,
            output_artifact_hashes,
            command: "test-command".to_string(),
            tool_identity: ProofToolIdentity {
                tool_name: tool_name.to_string(),
                tool_version: "1.0".to_string(),
                tool_invocation_id: "invocation-1".to_string(),
            },
            checker_result,
            counterexample_artifacts: BTreeMap::new(),
            timestamp_ticks: 7,
            logical_epoch: SecurityEpoch::from_raw(1),
            signature_or_content_hash: ProofSignatureOrContentHash::ContentHash(
                ContentHash::from_bytes([0u8; 32]),
            ),
        };
        artifact.signature_or_content_hash =
            ProofSignatureOrContentHash::ContentHash(artifact.content_hash());
        artifact
    }

    fn lean_passed() -> ProofProducerArtifact {
        artifact("FE-CLAIM-016", "lean4", ProofCheckerResult::Passed)
    }

    // -- classification ----------------------------------------------------

    #[test]
    fn classifies_passed_as_proven() {
        assert_eq!(
            classify_proof_artifact(&lean_passed()),
            ProofArtifactClass::Proven
        );
    }

    #[test]
    fn classifies_failed_as_counterexample() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Failed {
                reason: "theorem disproved".to_string(),
            },
        );
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Counterexample { ref reason } if reason == "theorem disproved"
        ));
    }

    #[test]
    fn classifies_inconclusive_as_unknown() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Inconclusive {
                reason: "solver timeout".to_string(),
            },
        );
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Unknown { .. }
        ));
    }

    #[test]
    fn classifies_unavailable_as_unavailable() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Unavailable {
                reason: "lake not installed".to_string(),
            },
        );
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Unavailable { .. }
        ));
    }

    #[test]
    fn classifies_fixture_only_as_fixture_only() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::FixtureOnly {
                reason: "hardcoded fixture".to_string(),
            },
        );
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::FixtureOnly { .. }
        ));
    }

    #[test]
    fn hash_mismatch_is_invalid_even_when_passed() {
        let mut a = lean_passed();
        a.signature_or_content_hash =
            ProofSignatureOrContentHash::ContentHash(ContentHash::from_bytes([0xEE; 32]));
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Invalid { ref reason } if reason.contains("hash mismatch")
        ));
    }

    #[test]
    fn tampered_body_is_invalid_even_when_passed() {
        let mut a = lean_passed();
        // Change the body after committing the hash.
        a.command = "tampered-command".to_string();
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Invalid { .. }
        ));
    }

    #[test]
    fn zero_signature_is_invalid() {
        let mut a = lean_passed();
        a.signature_or_content_hash = ProofSignatureOrContentHash::Signature {
            signer_key_id: crate::engine_object_id::EngineObjectId([1u8; 32]),
            signature: vec![0u8; SIGNATURE_LEN],
        };
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Invalid { ref reason } if reason.contains("all zeroes")
        ));
    }

    #[test]
    fn passed_with_malformed_body_is_invalid() {
        let mut a = lean_passed();
        a.command = String::new();
        a.signature_or_content_hash = ProofSignatureOrContentHash::ContentHash(a.content_hash());
        assert!(matches!(
            classify_proof_artifact(&a),
            ProofArtifactClass::Invalid { ref reason }
                if reason.contains("invalid artifact body")
        ));
    }

    // -- decision matrix ---------------------------------------------------

    #[test]
    fn proven_promotes_fe_claim_016() {
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[lean_passed()]);
        assert_eq!(verdict.action, ClaimSpineAction::PromoteObserved);
        assert!(verdict.findings.iter().all(|f| f.failure.is_none()));
    }

    #[test]
    fn counterexample_demotes_observed_claim() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Failed {
                reason: "disproved".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", true, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::CounterexampleFound { .. })
        ));
    }

    #[test]
    fn counterexample_blocks_unobserved_claim() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Failed {
                reason: "disproved".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
    }

    #[test]
    fn counterexample_beats_proven_in_the_same_pool() {
        let failed = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Failed {
                reason: "disproved".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", true, &[lean_passed(), failed]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
    }

    #[test]
    fn unavailable_stays_hypothesis() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Unavailable {
                reason: "toolchain missing".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::BackendUnavailable { .. })
        ));
    }

    #[test]
    fn unknown_stays_hypothesis() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::Inconclusive {
                reason: "timeout".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::VerdictUnknown { .. })
        ));
    }

    #[test]
    fn fixture_only_is_rejected_for_observed() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::FixtureOnly {
                reason: "fixture backend".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::FixtureOnlyRejected { .. })
        ));
    }

    #[test]
    fn fixture_regression_demotes_observed_claim() {
        let a = artifact(
            "FE-CLAIM-016",
            "lean4",
            ProofCheckerResult::FixtureOnly {
                reason: "regressed to fixture".to_string(),
            },
        );
        let verdict = decide_claim_state("FE-CLAIM-016", true, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
    }

    #[test]
    fn hash_mismatch_demotes_observed_claim() {
        let mut a = lean_passed();
        a.signature_or_content_hash =
            ProofSignatureOrContentHash::ContentHash(ContentHash::from_bytes([0xEE; 32]));
        let verdict = decide_claim_state("FE-CLAIM-016", true, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::ArtifactIntegrityFailure { .. })
        ));
    }

    #[test]
    fn missing_artifact_reports_producer_did_not_run() {
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::ProducerDidNotRun { ref expected_tool })
                if expected_tool == "lean4"
        ));
    }

    #[test]
    fn missing_artifact_demotes_when_currently_observed() {
        let verdict = decide_claim_state("FE-CLAIM-016", true, &[]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
    }

    #[test]
    fn unregistered_producer_cannot_promote() {
        let a = artifact("FE-CLAIM-016", "rogue-tool", ProofCheckerResult::Passed);
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::UnregisteredProducer { .. })
        ));
    }

    #[test]
    fn translation_validator_promotes_fe_claim_017() {
        let a = artifact(
            "FE-CLAIM-017",
            "translation-validator",
            ProofCheckerResult::Passed,
        );
        let verdict = decide_claim_state("FE-CLAIM-017", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::PromoteObserved);
    }

    #[test]
    fn artifact_for_other_claim_is_ignored() {
        let verdict = decide_claim_state("FE-CLAIM-017", false, &[lean_passed()]);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::ProducerDidNotRun { .. })
        ));
    }

    // -- v2 deferral -------------------------------------------------------

    #[test]
    fn v2_deferred_claims_stay_hypothesis_without_artifacts() {
        for claim_id in PROOF_SPINE_V2_DEFERRED_CLAIMS {
            let verdict = decide_claim_state(claim_id, false, &[]);
            assert_eq!(
                verdict.action,
                ClaimSpineAction::StayHypothesis,
                "{claim_id}"
            );
            assert!(matches!(
                verdict.findings[0].failure,
                Some(ClaimSpineFailure::V2Deferred { .. })
            ));
        }
    }

    #[test]
    fn fabricated_proven_cannot_promote_v2_deferred_claim() {
        let a = artifact(
            "FE-CLAIM-018",
            "z3-policy-theorem",
            ProofCheckerResult::Passed,
        );
        let verdict = decide_claim_state("FE-CLAIM-018", false, &[a]);
        assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::V2Deferred { .. })
        ));
    }

    #[test]
    fn v2_deferred_claim_reading_observed_is_demoted() {
        let verdict = decide_claim_state("FE-CLAIM-019", true, &[]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
    }

    // -- whole-spine sweep ---------------------------------------------------

    #[test]
    fn decide_all_spine_claims_covers_v1_and_v2() {
        let verdicts = decide_all_spine_claims(&[], &[lean_passed()]);
        assert_eq!(
            verdicts.len(),
            PROOF_SPINE_V1_REGISTERED_PRODUCERS.len() + PROOF_SPINE_V2_DEFERRED_CLAIMS.len()
        );
        let claim_016 = verdicts
            .iter()
            .find(|v| v.claim_id == "FE-CLAIM-016")
            .expect("FE-CLAIM-016 verdict");
        assert_eq!(claim_016.action, ClaimSpineAction::PromoteObserved);
        for deferred in PROOF_SPINE_V2_DEFERRED_CLAIMS {
            let verdict = verdicts
                .iter()
                .find(|v| v.claim_id == deferred)
                .expect("deferred verdict");
            assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
        }
    }

    #[test]
    fn registry_lookups_are_consistent() {
        assert_eq!(registered_producer_tool("FE-CLAIM-016"), Some("lean4"));
        assert_eq!(
            registered_producer_tool("FE-CLAIM-017"),
            Some("translation-validator")
        );
        assert_eq!(registered_producer_tool("FE-CLAIM-018"), None);
        assert!(is_v2_deferred_claim("FE-CLAIM-018"));
        assert!(!is_v2_deferred_claim("FE-CLAIM-016"));
    }

    #[test]
    fn verdict_serializes_round_trip() {
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[lean_passed()]);
        let json = serde_json::to_string(&verdict).expect("serialize");
        let back: ClaimSpineVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, verdict);
    }

    #[test]
    fn explanation_names_the_claim() {
        let verdict = decide_claim_state("FE-CLAIM-016", false, &[]);
        assert!(verdict.explanation.contains("FE-CLAIM-016"));
    }
}
