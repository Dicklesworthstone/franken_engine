//! Counterfactual policy-generation guard (Track S — bead bd-cixqu.19.5).
//!
//! Track S replay lets an operator substitute an alternate policy snapshot over
//! recorded fleet traces to answer "what if we had run policy X?". A policy
//! snapshot carries a *generation* — a monotone schema epoch — and a content
//! hash of its sealed bytes. Substituting a snapshot from a different generation
//! under the wrong schema would silently re-interpret recorded bytes
//! incorrectly. That is exactly the class of bug [`SchemaId`] was designed to
//! prevent project-wide.
//!
//! This module fail-closes that surface. A substituted snapshot is admitted only
//! when **all** of the following hold:
//!
//! 1. its generation is **not newer** than the current accepted generation
//!    (a future generation was sealed under a schema the recording never used);
//! 2. its generation has **not been retired**;
//! 3. its schema id **matches** the baseline the traces were recorded under;
//! 4. its bytes **hash to** the declared content hash (no post-seal mutation).
//!
//! Every admission/rejection produces a structured [`GenerationGuardEvent`] that
//! serialises to one `events.jsonl` line per the bd-cixqu.45 logging discipline,
//! carrying the rejected `policy_id`, the expected generation, and the actual
//! generation.

use crate::counterfactual_evaluator::{CounterfactualError, PolicyId};
use crate::engine_object_id::SchemaId;
use crate::hash_tiers::ContentHash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// A monotone generation/schema epoch carried by a policy snapshot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct PolicyGeneration(pub u64);

impl PolicyGeneration {
    /// Construct a generation from a raw epoch value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw epoch value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The generation lineage a fleet replay run was recorded under. A substituted
/// snapshot is checked against this lineage before it is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGenerationLineage {
    /// The current accepted generation — the one the traces were recorded under.
    pub current_generation: PolicyGeneration,
    /// Generations that have been retired and must never be re-substituted.
    pub retired_generations: BTreeSet<u64>,
    /// The schema id the baseline traces were recorded under.
    pub baseline_schema_id: SchemaId,
}

impl PolicyGenerationLineage {
    /// Construct a lineage with no retired generations.
    pub fn new(current_generation: PolicyGeneration, baseline_schema_id: SchemaId) -> Self {
        Self {
            current_generation,
            retired_generations: BTreeSet::new(),
            baseline_schema_id,
        }
    }

    /// Builder: mark a generation as retired.
    pub fn with_retired(mut self, generation: u64) -> Self {
        self.retired_generations.insert(generation);
        self
    }

    /// Whether the given generation has been retired.
    pub fn is_retired(&self, generation: PolicyGeneration) -> bool {
        self.retired_generations.contains(&generation.value())
    }
}

/// A substituted policy snapshot's verifiable identity: the claim the operator
/// makes about the snapshot. The actual sealed bytes are supplied separately to
/// [`verify_substituted_policy`] so the guard can recompute the content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstitutedPolicyClaim {
    /// The alternate policy identifier.
    pub policy_id: PolicyId,
    /// The generation the snapshot claims to belong to.
    pub claimed_generation: PolicyGeneration,
    /// The schema id the snapshot claims to conform to.
    pub claimed_schema_id: SchemaId,
    /// The content hash the snapshot was sealed with.
    pub declared_content_hash: ContentHash,
}

impl SubstitutedPolicyClaim {
    /// Construct a claim. `policy_bytes` is hashed to derive the declared
    /// content hash, modelling a freshly, honestly-sealed snapshot.
    pub fn sealed(
        policy_id: PolicyId,
        claimed_generation: PolicyGeneration,
        claimed_schema_id: SchemaId,
        policy_bytes: &[u8],
    ) -> Self {
        Self {
            policy_id,
            claimed_generation,
            claimed_schema_id,
            declared_content_hash: ContentHash::compute(policy_bytes),
        }
    }

    /// Construct a claim with an explicit declared hash (used to model snapshots
    /// whose bytes were mutated after sealing).
    pub fn with_declared_hash(
        policy_id: PolicyId,
        claimed_generation: PolicyGeneration,
        claimed_schema_id: SchemaId,
        declared_content_hash: ContentHash,
    ) -> Self {
        Self {
            policy_id,
            claimed_generation,
            claimed_schema_id,
            declared_content_hash,
        }
    }
}

/// The outcome of admitting a substituted policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationAcceptance {
    /// The admitted policy identifier.
    pub policy_id: PolicyId,
    /// The admitted generation.
    pub generation: PolicyGeneration,
    /// The content hash that was recomputed and matched the declared hash.
    pub verified_content_hash: ContentHash,
}

/// Stable machine-readable reason code for a rejection outcome.
fn rejection_code(err: &CounterfactualError) -> &'static str {
    match err {
        CounterfactualError::IncompatibleGeneration { .. } => "incompatible_generation",
        CounterfactualError::RetiredGeneration { .. } => "retired_generation",
        CounterfactualError::PolicySchemaMismatch { .. } => "policy_schema_mismatch",
        CounterfactualError::PolicyContentHashMismatch { .. } => "policy_content_hash_mismatch",
        _ => "rejected",
    }
}

/// Verify a substituted policy snapshot against the recorded generation lineage,
/// fail-closing on any incompatibility.
///
/// `policy_bytes` are the actual sealed bytes of the snapshot; they must hash to
/// the claim's declared content hash. The four invariants are checked in the
/// order documented at the module level so that the most fundamental
/// incompatibility (a future generation) is reported first.
pub fn verify_substituted_policy(
    claim: &SubstitutedPolicyClaim,
    policy_bytes: &[u8],
    lineage: &PolicyGenerationLineage,
) -> Result<GenerationAcceptance, CounterfactualError> {
    // (1) Future generation: bytes were sealed under a schema the recording
    //     never used. This is the silent-reinterpretation hazard.
    if claim.claimed_generation > lineage.current_generation {
        return Err(CounterfactualError::IncompatibleGeneration {
            expected: lineage.current_generation.value(),
            actual: claim.claimed_generation.value(),
        });
    }

    // (2) Retired generation: fail-closed.
    if lineage.is_retired(claim.claimed_generation) {
        return Err(CounterfactualError::RetiredGeneration {
            generation: claim.claimed_generation.value(),
        });
    }

    // (3) Schema mismatch: a snapshot from a compatible generation but under the
    //     wrong schema id is still re-interpreting bytes incorrectly.
    if claim.claimed_schema_id != lineage.baseline_schema_id {
        return Err(CounterfactualError::PolicySchemaMismatch {
            policy_id: claim.policy_id.0.clone(),
            expected: lineage.baseline_schema_id.to_string(),
            actual: claim.claimed_schema_id.to_string(),
        });
    }

    // (4) Mutated bytes: the recomputed content hash must match the declared one.
    let actual_hash = ContentHash::compute(policy_bytes);
    if actual_hash != claim.declared_content_hash {
        return Err(CounterfactualError::PolicyContentHashMismatch {
            policy_id: claim.policy_id.0.clone(),
            expected: claim.declared_content_hash.to_hex(),
            actual: actual_hash.to_hex(),
        });
    }

    Ok(GenerationAcceptance {
        policy_id: claim.policy_id.clone(),
        generation: claim.claimed_generation,
        verified_content_hash: actual_hash,
    })
}

/// A structured admission/rejection event, emitted as one JSONL line per the
/// bd-cixqu.45 logging discipline. Every rejection records the rejected
/// `policy_id`, the expected generation, and the actual (claimed) generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationGuardEvent {
    /// Event kind: `counterfactual_policy_admitted` or
    /// `counterfactual_policy_rejected`.
    pub event: String,
    /// The policy identifier under evaluation.
    pub policy_id: String,
    /// The current accepted generation the snapshot was checked against.
    pub expected_generation: u64,
    /// The generation the snapshot claims.
    pub actual_generation: u64,
    /// Whether the snapshot was admitted.
    pub admitted: bool,
    /// Machine-readable outcome code (`admitted` or a rejection reason code).
    pub outcome: String,
    /// Human-readable detail (the error display, or the verified content hash).
    pub detail: String,
}

impl GenerationGuardEvent {
    /// Build an admission event.
    pub fn admitted(acceptance: &GenerationAcceptance, lineage: &PolicyGenerationLineage) -> Self {
        Self {
            event: "counterfactual_policy_admitted".to_string(),
            policy_id: acceptance.policy_id.0.clone(),
            expected_generation: lineage.current_generation.value(),
            actual_generation: acceptance.generation.value(),
            admitted: true,
            outcome: "admitted".to_string(),
            detail: format!(
                "verified_content_hash={}",
                acceptance.verified_content_hash.to_hex()
            ),
        }
    }

    /// Build a rejection event from the claim, the lineage, and the error.
    pub fn rejected(
        claim: &SubstitutedPolicyClaim,
        lineage: &PolicyGenerationLineage,
        err: &CounterfactualError,
    ) -> Self {
        Self {
            event: "counterfactual_policy_rejected".to_string(),
            policy_id: claim.policy_id.0.clone(),
            expected_generation: lineage.current_generation.value(),
            actual_generation: claim.claimed_generation.value(),
            admitted: false,
            outcome: rejection_code(err).to_string(),
            detail: err.to_string(),
        }
    }

    /// Serialise this event to a single JSONL line (no trailing newline).
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("GenerationGuardEvent is always serialisable")
    }
}

/// Verify a snapshot and return both the result and the structured event that
/// should be appended to `events.jsonl`, regardless of outcome.
pub fn verify_logged(
    claim: &SubstitutedPolicyClaim,
    policy_bytes: &[u8],
    lineage: &PolicyGenerationLineage,
) -> (
    Result<GenerationAcceptance, CounterfactualError>,
    GenerationGuardEvent,
) {
    match verify_substituted_policy(claim, policy_bytes, lineage) {
        Ok(acceptance) => {
            let event = GenerationGuardEvent::admitted(&acceptance, lineage);
            (Ok(acceptance), event)
        }
        Err(err) => {
            let event = GenerationGuardEvent::rejected(claim, lineage, &err);
            (Err(err), event)
        }
    }
}

/// Append a structured event as one line to an `events.jsonl` file, creating it
/// if absent. This is the production-shaped logging sink the bd-cixqu.45
/// discipline expects a gate run to emit.
pub fn append_event_line(path: &Path, event: &GenerationGuardEvent) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", event.to_jsonl())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE_BYTES: &[u8] = b"baseline-policy-definition-v1";

    fn baseline_schema() -> SchemaId {
        SchemaId::from_definition(b"track-s.substituted-policy.schema.v1")
    }

    fn other_schema() -> SchemaId {
        SchemaId::from_definition(b"track-s.substituted-policy.schema.v2")
    }

    fn lineage_gen(current: u64) -> PolicyGenerationLineage {
        PolicyGenerationLineage::new(PolicyGeneration::new(current), baseline_schema())
    }

    fn claim_at(generation: u64, bytes: &[u8]) -> SubstitutedPolicyClaim {
        SubstitutedPolicyClaim::sealed(
            PolicyId("alt-policy".to_string()),
            PolicyGeneration::new(generation),
            baseline_schema(),
            bytes,
        )
    }

    // ── Happy path ────────────────────────────────────────────────────────

    #[test]
    fn generation_guard_admits_same_generation_unmutated() {
        let lineage = lineage_gen(7);
        let claim = claim_at(7, BASELINE_BYTES);
        let acceptance = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage)
            .expect("same-generation, unmutated snapshot must be admitted");
        assert_eq!(acceptance.generation, PolicyGeneration::new(7));
        assert_eq!(acceptance.policy_id.0, "alt-policy");
        assert_eq!(
            acceptance.verified_content_hash,
            ContentHash::compute(BASELINE_BYTES)
        );
    }

    #[test]
    fn generation_guard_admits_older_compatible_generation() {
        // An older (already-superseded) generation is still a generation the
        // recording's bytes can be interpreted under, so it is admitted.
        let lineage = lineage_gen(9);
        let claim = claim_at(3, BASELINE_BYTES);
        assert!(verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).is_ok());
    }

    #[test]
    fn generation_guard_admits_generation_zero_genesis() {
        let lineage = lineage_gen(0);
        let claim = claim_at(0, BASELINE_BYTES);
        assert!(verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).is_ok());
    }

    // ── Future generation (IncompatibleGeneration) ──────────────────────────

    #[test]
    fn generation_guard_rejects_future_generation() {
        let lineage = lineage_gen(5);
        let claim = claim_at(6, BASELINE_BYTES);
        let err = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err();
        assert_eq!(
            err,
            CounterfactualError::IncompatibleGeneration {
                expected: 5,
                actual: 6
            }
        );
    }

    #[test]
    fn generation_guard_rejects_far_future_generation() {
        let lineage = lineage_gen(1);
        let claim = claim_at(u64::MAX, BASELINE_BYTES);
        let err = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err();
        assert_eq!(
            err,
            CounterfactualError::IncompatibleGeneration {
                expected: 1,
                actual: u64::MAX
            }
        );
    }

    #[test]
    fn generation_guard_off_by_one_future_is_rejected() {
        let lineage = lineage_gen(100);
        let admitted = claim_at(100, BASELINE_BYTES);
        let rejected = claim_at(101, BASELINE_BYTES);
        assert!(verify_substituted_policy(&admitted, BASELINE_BYTES, &lineage).is_ok());
        assert!(matches!(
            verify_substituted_policy(&rejected, BASELINE_BYTES, &lineage),
            Err(CounterfactualError::IncompatibleGeneration { .. })
        ));
    }

    // ── Retired generation (RetiredGeneration) ──────────────────────────────

    #[test]
    fn generation_guard_rejects_retired_generation() {
        let lineage = lineage_gen(9).with_retired(4);
        let claim = claim_at(4, BASELINE_BYTES);
        let err = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err();
        assert_eq!(
            err,
            CounterfactualError::RetiredGeneration { generation: 4 }
        );
    }

    #[test]
    fn generation_guard_rejects_each_of_several_retired_generations() {
        let lineage = lineage_gen(20)
            .with_retired(2)
            .with_retired(5)
            .with_retired(11);
        for retired in [2u64, 5, 11] {
            let claim = claim_at(retired, BASELINE_BYTES);
            assert_eq!(
                verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err(),
                CounterfactualError::RetiredGeneration {
                    generation: retired
                }
            );
        }
    }

    #[test]
    fn generation_guard_future_check_precedes_retired_check() {
        // A retired generation that is also in the future reports the future
        // incompatibility first (the more fundamental hazard).
        let lineage = lineage_gen(3).with_retired(8);
        let claim = claim_at(8, BASELINE_BYTES);
        assert_eq!(
            verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err(),
            CounterfactualError::IncompatibleGeneration {
                expected: 3,
                actual: 8
            }
        );
    }

    #[test]
    fn generation_guard_admits_unretired_neighbour_of_retired() {
        let lineage = lineage_gen(9).with_retired(4);
        let claim = claim_at(5, BASELINE_BYTES);
        assert!(verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).is_ok());
    }

    // ── Schema mismatch (PolicySchemaMismatch) ──────────────────────────────

    #[test]
    fn generation_guard_rejects_schema_mismatch() {
        let lineage = lineage_gen(7);
        let claim = SubstitutedPolicyClaim::sealed(
            PolicyId("alt-policy".to_string()),
            PolicyGeneration::new(7),
            other_schema(),
            BASELINE_BYTES,
        );
        let err = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap_err();
        match err {
            CounterfactualError::PolicySchemaMismatch {
                policy_id,
                expected,
                actual,
            } => {
                assert_eq!(policy_id, "alt-policy");
                assert_eq!(expected, baseline_schema().to_string());
                assert_eq!(actual, other_schema().to_string());
                assert_ne!(expected, actual);
            }
            other => panic!("expected PolicySchemaMismatch, got {other:?}"),
        }
    }

    // ── Mutated bytes (PolicyContentHashMismatch) ───────────────────────────

    #[test]
    fn generation_guard_rejects_mutated_bytes() {
        let lineage = lineage_gen(7);
        // Sealed under the honest baseline bytes, but a different byte string is
        // presented at verification time.
        let claim = claim_at(7, BASELINE_BYTES);
        let mutated = b"baseline-policy-definition-v1-TAMPERED";
        let err = verify_substituted_policy(&claim, mutated, &lineage).unwrap_err();
        match err {
            CounterfactualError::PolicyContentHashMismatch {
                policy_id,
                expected,
                actual,
            } => {
                assert_eq!(policy_id, "alt-policy");
                assert_eq!(expected, ContentHash::compute(BASELINE_BYTES).to_hex());
                assert_eq!(actual, ContentHash::compute(mutated).to_hex());
                assert_ne!(expected, actual);
            }
            other => panic!("expected PolicyContentHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn generation_guard_rejects_single_bit_mutation() {
        let lineage = lineage_gen(7);
        let claim = claim_at(7, BASELINE_BYTES);
        let mut mutated = BASELINE_BYTES.to_vec();
        mutated[0] ^= 0x01;
        assert!(matches!(
            verify_substituted_policy(&claim, &mutated, &lineage),
            Err(CounterfactualError::PolicyContentHashMismatch { .. })
        ));
    }

    #[test]
    fn generation_guard_declared_hash_mismatch_with_truthful_bytes() {
        // The snapshot was sealed with a lie: declared hash points elsewhere
        // even though the presented bytes are themselves coherent.
        let lineage = lineage_gen(7);
        let claim = SubstitutedPolicyClaim::with_declared_hash(
            PolicyId("alt-policy".to_string()),
            PolicyGeneration::new(7),
            baseline_schema(),
            ContentHash::compute(b"a-different-policy"),
        );
        assert!(matches!(
            verify_substituted_policy(&claim, BASELINE_BYTES, &lineage),
            Err(CounterfactualError::PolicyContentHashMismatch { .. })
        ));
    }

    // ── Check ordering: schema precedes content hash ────────────────────────

    #[test]
    fn generation_guard_schema_check_precedes_content_hash() {
        let lineage = lineage_gen(7);
        // Wrong schema AND mutated bytes — schema mismatch is reported first.
        let claim = SubstitutedPolicyClaim::with_declared_hash(
            PolicyId("alt-policy".to_string()),
            PolicyGeneration::new(7),
            other_schema(),
            ContentHash::compute(b"whatever"),
        );
        assert!(matches!(
            verify_substituted_policy(&claim, b"something-else", &lineage),
            Err(CounterfactualError::PolicySchemaMismatch { .. })
        ));
    }

    // ── Structured events ───────────────────────────────────────────────────

    #[test]
    fn generation_guard_event_records_rejection_fields() {
        let lineage = lineage_gen(5);
        let claim = claim_at(6, BASELINE_BYTES);
        let (result, event) = verify_logged(&claim, BASELINE_BYTES, &lineage);
        assert!(result.is_err());
        assert!(!event.admitted);
        assert_eq!(event.event, "counterfactual_policy_rejected");
        assert_eq!(event.policy_id, "alt-policy");
        assert_eq!(event.expected_generation, 5);
        assert_eq!(event.actual_generation, 6);
        assert_eq!(event.outcome, "incompatible_generation");
    }

    #[test]
    fn generation_guard_event_records_admission_fields() {
        let lineage = lineage_gen(5);
        let claim = claim_at(5, BASELINE_BYTES);
        let (result, event) = verify_logged(&claim, BASELINE_BYTES, &lineage);
        assert!(result.is_ok());
        assert!(event.admitted);
        assert_eq!(event.event, "counterfactual_policy_admitted");
        assert_eq!(event.outcome, "admitted");
        assert_eq!(event.expected_generation, 5);
        assert_eq!(event.actual_generation, 5);
    }

    #[test]
    fn generation_guard_event_outcome_codes_are_distinct() {
        let lineage = lineage_gen(9).with_retired(2);
        let retired = claim_at(2, BASELINE_BYTES);
        let (_, ev_retired) = verify_logged(&retired, BASELINE_BYTES, &lineage);
        assert_eq!(ev_retired.outcome, "retired_generation");

        let future = claim_at(10, BASELINE_BYTES);
        let (_, ev_future) = verify_logged(&future, BASELINE_BYTES, &lineage);
        assert_eq!(ev_future.outcome, "incompatible_generation");
    }

    #[test]
    fn generation_guard_event_jsonl_round_trips() {
        let lineage = lineage_gen(5);
        let claim = claim_at(6, BASELINE_BYTES);
        let (_, event) = verify_logged(&claim, BASELINE_BYTES, &lineage);
        let line = event.to_jsonl();
        assert!(!line.contains('\n'));
        let parsed: GenerationGuardEvent =
            serde_json::from_str(&line).expect("event JSONL must round-trip");
        assert_eq!(parsed, event);
    }

    #[test]
    fn generation_guard_appends_events_to_jsonl_file() {
        let dir = std::env::temp_dir().join(format!(
            "cf_gen_guard_{}_{}",
            std::process::id(),
            BASELINE_BYTES.len()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&path);

        let lineage = lineage_gen(5);
        for generation in [5u64, 6, 5] {
            let claim = claim_at(generation, BASELINE_BYTES);
            let (_, event) = verify_logged(&claim, BASELINE_BYTES, &lineage);
            append_event_line(&path, &event).unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let _: GenerationGuardEvent =
                serde_json::from_str(line).expect("each line is a valid event");
        }
        let _ = std::fs::remove_file(&path);
    }

    // ── Type plumbing / serde of supporting types ───────────────────────────

    #[test]
    fn policy_generation_ordering_is_numeric() {
        assert!(PolicyGeneration::new(3) < PolicyGeneration::new(4));
        assert_eq!(PolicyGeneration::new(7).value(), 7);
        assert_eq!(PolicyGeneration::default(), PolicyGeneration::new(0));
    }

    #[test]
    fn policy_generation_lineage_serde_round_trip() {
        let lineage = lineage_gen(9).with_retired(2).with_retired(5);
        let json = serde_json::to_string(&lineage).unwrap();
        let back: PolicyGenerationLineage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lineage);
        assert!(back.is_retired(PolicyGeneration::new(2)));
        assert!(!back.is_retired(PolicyGeneration::new(3)));
    }

    #[test]
    fn substituted_policy_claim_serde_round_trip() {
        let claim = claim_at(4, BASELINE_BYTES);
        let json = serde_json::to_string(&claim).unwrap();
        let back: SubstitutedPolicyClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(back, claim);
    }

    #[test]
    fn acceptance_carries_verified_hash() {
        let lineage = lineage_gen(7);
        let claim = claim_at(7, BASELINE_BYTES);
        let acceptance = verify_substituted_policy(&claim, BASELINE_BYTES, &lineage).unwrap();
        // The verified hash is the recomputed hash, equal to the declared hash.
        assert_eq!(
            acceptance.verified_content_hash,
            claim.declared_content_hash
        );
    }

    #[test]
    fn rejection_code_covers_all_track_s_variants() {
        assert_eq!(
            rejection_code(&CounterfactualError::IncompatibleGeneration {
                expected: 1,
                actual: 2
            }),
            "incompatible_generation"
        );
        assert_eq!(
            rejection_code(&CounterfactualError::RetiredGeneration { generation: 1 }),
            "retired_generation"
        );
        assert_eq!(
            rejection_code(&CounterfactualError::PolicySchemaMismatch {
                policy_id: "p".into(),
                expected: "a".into(),
                actual: "b".into()
            }),
            "policy_schema_mismatch"
        );
        assert_eq!(
            rejection_code(&CounterfactualError::PolicyContentHashMismatch {
                policy_id: "p".into(),
                expected: "a".into(),
                actual: "b".into()
            }),
            "policy_content_hash_mismatch"
        );
        // Non-Track-S variants fall through to the generic code.
        assert_eq!(rejection_code(&CounterfactualError::EmptyBatch), "rejected");
    }

    #[test]
    fn display_messages_are_non_empty_for_track_s_variants() {
        let variants = [
            CounterfactualError::IncompatibleGeneration {
                expected: 1,
                actual: 2,
            },
            CounterfactualError::RetiredGeneration { generation: 3 },
            CounterfactualError::PolicySchemaMismatch {
                policy_id: "p".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            CounterfactualError::PolicyContentHashMismatch {
                policy_id: "p".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
