//! S.5 — Negative test: counterfactual replay refuses an incompatible policy
//! generation (bead bd-cixqu.19.5, Track S).
//!
//! Track S allows substituting an alternative policy snapshot during fleet
//! replay. A policy snapshot carries a generation/schema id; substituting a
//! snapshot from a different generation under the wrong schema would silently
//! re-interpret recorded bytes incorrectly — exactly the bug `SchemaId` was
//! designed to prevent project-wide. This suite proves the counterfactual
//! surface fail-closes that hazard and, per the bd-cixqu.45 logging discipline,
//! emits a structured `events.jsonl` line on every rejection carrying the
//! rejected `policy_id`, the expected generation, and the actual generation.

use frankenengine_engine::counterfactual_evaluator::{CounterfactualError, PolicyId};
use frankenengine_engine::counterfactual_generation_guard::{
    GenerationGuardEvent, PolicyGeneration, PolicyGenerationLineage, SubstitutedPolicyClaim,
    append_event_line, verify_logged, verify_substituted_policy,
};
use frankenengine_engine::engine_object_id::SchemaId;
use frankenengine_engine::hash_tiers::ContentHash;

const BASELINE_BYTES: &[u8] = b"track-s.baseline-policy.bytes.v1";

fn baseline_schema() -> SchemaId {
    SchemaId::from_definition(b"track-s.substituted-policy.schema.v1")
}

fn future_schema() -> SchemaId {
    SchemaId::from_definition(b"track-s.substituted-policy.schema.v2")
}

/// A lineage whose traces were recorded under `current` and the baseline schema.
fn lineage(current: u64) -> PolicyGenerationLineage {
    PolicyGenerationLineage::new(PolicyGeneration::new(current), baseline_schema())
}

/// An honestly-sealed claim at `generation` over the baseline schema/bytes.
fn sealed_claim(name: &str, generation: u64) -> SubstitutedPolicyClaim {
    SubstitutedPolicyClaim::sealed(
        PolicyId(name.to_string()),
        PolicyGeneration::new(generation),
        baseline_schema(),
        BASELINE_BYTES,
    )
}

// ───────────────────────── REJECT: future generation ─────────────────────────

#[test]
fn s5_rejects_future_generation_by_one() {
    let err =
        verify_substituted_policy(&sealed_claim("p", 6), BASELINE_BYTES, &lineage(5)).unwrap_err();
    assert_eq!(
        err,
        CounterfactualError::IncompatibleGeneration {
            expected: 5,
            actual: 6
        }
    );
}

#[test]
fn s5_rejects_far_future_generation() {
    let err = verify_substituted_policy(&sealed_claim("p", 1_000_000), BASELINE_BYTES, &lineage(3))
        .unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::IncompatibleGeneration {
            expected: 3,
            actual: 1_000_000
        }
    ));
}

#[test]
fn s5_rejects_u64_max_generation() {
    let err = verify_substituted_policy(&sealed_claim("p", u64::MAX), BASELINE_BYTES, &lineage(42))
        .unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::IncompatibleGeneration { actual, .. } if actual == u64::MAX
    ));
}

#[test]
fn s5_future_generation_boundary_admit_vs_reject() {
    // current == claim -> admit; current + 1 -> reject.
    assert!(
        verify_substituted_policy(&sealed_claim("p", 50), BASELINE_BYTES, &lineage(50)).is_ok()
    );
    assert!(matches!(
        verify_substituted_policy(&sealed_claim("p", 51), BASELINE_BYTES, &lineage(50)),
        Err(CounterfactualError::IncompatibleGeneration { .. })
    ));
}

// ───────────────────────── REJECT: retired generation ────────────────────────

#[test]
fn s5_rejects_retired_generation() {
    let lin = lineage(9).with_retired(4);
    let err = verify_substituted_policy(&sealed_claim("p", 4), BASELINE_BYTES, &lin).unwrap_err();
    assert_eq!(
        err,
        CounterfactualError::RetiredGeneration { generation: 4 }
    );
}

#[test]
fn s5_rejects_each_retired_generation_in_set() {
    let lin = lineage(30).with_retired(3).with_retired(7).with_retired(19);
    for retired in [3u64, 7, 19] {
        assert_eq!(
            verify_substituted_policy(&sealed_claim("p", retired), BASELINE_BYTES, &lin)
                .unwrap_err(),
            CounterfactualError::RetiredGeneration {
                generation: retired
            }
        );
    }
}

#[test]
fn s5_admits_generation_adjacent_to_retired() {
    let lin = lineage(9).with_retired(4);
    assert!(verify_substituted_policy(&sealed_claim("p", 3), BASELINE_BYTES, &lin).is_ok());
    assert!(verify_substituted_policy(&sealed_claim("p", 5), BASELINE_BYTES, &lin).is_ok());
}

#[test]
fn s5_future_takes_precedence_over_retired() {
    // A generation that is both retired and in the future is reported as the
    // future incompatibility (the more fundamental hazard).
    let lin = lineage(3).with_retired(8);
    assert_eq!(
        verify_substituted_policy(&sealed_claim("p", 8), BASELINE_BYTES, &lin).unwrap_err(),
        CounterfactualError::IncompatibleGeneration {
            expected: 3,
            actual: 8
        }
    );
}

// ───────────────────────── REJECT: schema mismatch ───────────────────────────

#[test]
fn s5_rejects_wrong_schema_same_generation() {
    let claim = SubstitutedPolicyClaim::sealed(
        PolicyId("p".to_string()),
        PolicyGeneration::new(7),
        future_schema(),
        BASELINE_BYTES,
    );
    match verify_substituted_policy(&claim, BASELINE_BYTES, &lineage(7)).unwrap_err() {
        CounterfactualError::PolicySchemaMismatch {
            policy_id,
            expected,
            actual,
        } => {
            assert_eq!(policy_id, "p");
            assert_eq!(expected, baseline_schema().to_string());
            assert_eq!(actual, future_schema().to_string());
        }
        other => panic!("expected PolicySchemaMismatch, got {other:?}"),
    }
}

// ───────────────────── REJECT: matching id, mutated bytes ─────────────────────

#[test]
fn s5_rejects_mutated_bytes_same_id() {
    // Sealed honestly over BASELINE_BYTES, but tampered bytes are presented.
    let claim = sealed_claim("p", 7);
    let tampered = b"track-s.baseline-policy.bytes.v1.TAMPERED";
    match verify_substituted_policy(&claim, tampered, &lineage(7)).unwrap_err() {
        CounterfactualError::PolicyContentHashMismatch {
            policy_id,
            expected,
            actual,
        } => {
            assert_eq!(policy_id, "p");
            assert_eq!(expected, ContentHash::compute(BASELINE_BYTES).to_hex());
            assert_eq!(actual, ContentHash::compute(tampered).to_hex());
            assert_ne!(expected, actual);
        }
        other => panic!("expected PolicyContentHashMismatch, got {other:?}"),
    }
}

#[test]
fn s5_rejects_single_bit_flip() {
    let claim = sealed_claim("p", 7);
    let mut tampered = BASELINE_BYTES.to_vec();
    *tampered.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_substituted_policy(&claim, &tampered, &lineage(7)),
        Err(CounterfactualError::PolicyContentHashMismatch { .. })
    ));
}

#[test]
fn s5_rejects_declared_hash_pointing_elsewhere() {
    let claim = SubstitutedPolicyClaim::with_declared_hash(
        PolicyId("p".to_string()),
        PolicyGeneration::new(7),
        baseline_schema(),
        ContentHash::compute(b"some-other-policy"),
    );
    assert!(matches!(
        verify_substituted_policy(&claim, BASELINE_BYTES, &lineage(7)),
        Err(CounterfactualError::PolicyContentHashMismatch { .. })
    ));
}

// ───────────────────────────── PASS: valid substitution ──────────────────────

#[test]
fn s5_admits_valid_same_generation_substitution() {
    let acceptance =
        verify_substituted_policy(&sealed_claim("good", 7), BASELINE_BYTES, &lineage(7)).unwrap();
    assert_eq!(acceptance.policy_id.0, "good");
    assert_eq!(acceptance.generation, PolicyGeneration::new(7));
    assert_eq!(
        acceptance.verified_content_hash,
        ContentHash::compute(BASELINE_BYTES)
    );
}

#[test]
fn s5_admits_older_compatible_generation() {
    assert!(
        verify_substituted_policy(&sealed_claim("good", 2), BASELINE_BYTES, &lineage(8)).is_ok()
    );
}

#[test]
fn s5_admits_genesis_generation() {
    assert!(
        verify_substituted_policy(&sealed_claim("good", 0), BASELINE_BYTES, &lineage(0)).is_ok()
    );
}

// ───────────────────── Logging discipline: events.jsonl ──────────────────────

#[test]
fn s5_rejection_event_carries_required_fields() {
    let lin = lineage(5);
    let claim = sealed_claim("rej-policy", 9);
    let (result, event) = verify_logged(&claim, BASELINE_BYTES, &lin);
    assert!(result.is_err());
    assert_eq!(event.event, "counterfactual_policy_rejected");
    assert!(!event.admitted);
    // Per bd-cixqu.45: rejected policy_id, expected generation, actual generation.
    assert_eq!(event.policy_id, "rej-policy");
    assert_eq!(event.expected_generation, 5);
    assert_eq!(event.actual_generation, 9);
    assert_eq!(event.outcome, "incompatible_generation");
}

#[test]
fn s5_events_jsonl_round_trips_per_line() {
    let lin = lineage(5).with_retired(2);
    let claims = [
        sealed_claim("a", 6), // future -> reject
        sealed_claim("b", 2), // retired -> reject
        sealed_claim("c", 5), // valid -> admit
    ];
    for claim in &claims {
        let (_, event) = verify_logged(claim, BASELINE_BYTES, &lin);
        let line = event.to_jsonl();
        assert!(!line.contains('\n'));
        let parsed: GenerationGuardEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, event);
    }
}

#[test]
fn s5_writes_structured_events_jsonl_file() {
    let dir = std::env::temp_dir().join(format!("s5_cf_events_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&path);

    let lin = lineage(5).with_retired(2);
    // future-reject, retired-reject, schema-reject, mutated-reject, valid-admit.
    let schema_bad = SubstitutedPolicyClaim::sealed(
        PolicyId("schema-bad".to_string()),
        PolicyGeneration::new(5),
        future_schema(),
        BASELINE_BYTES,
    );
    let mutated = sealed_claim("mutated", 5);

    let (_, e1) = verify_logged(&sealed_claim("future", 6), BASELINE_BYTES, &lin);
    let (_, e2) = verify_logged(&sealed_claim("retired", 2), BASELINE_BYTES, &lin);
    let (_, e3) = verify_logged(&schema_bad, BASELINE_BYTES, &lin);
    let (_, e4) = verify_logged(&mutated, b"different-bytes-entirely", &lin);
    let (_, e5) = verify_logged(&sealed_claim("good", 5), BASELINE_BYTES, &lin);
    for ev in [&e1, &e2, &e3, &e4, &e5] {
        append_event_line(&path, ev).unwrap();
    }

    let contents = std::fs::read_to_string(&path).unwrap();
    let events: Vec<GenerationGuardEvent> = contents
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid event line"))
        .collect();
    assert_eq!(events.len(), 5);

    let outcomes: Vec<&str> = events.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        vec![
            "incompatible_generation",
            "retired_generation",
            "policy_schema_mismatch",
            "policy_content_hash_mismatch",
            "admitted",
        ]
    );
    // Exactly one admission; four fail-closed rejections.
    assert_eq!(events.iter().filter(|e| e.admitted).count(), 1);
    assert_eq!(events.iter().filter(|e| !e.admitted).count(), 4);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn s5_admission_event_fields() {
    let (result, event) = verify_logged(&sealed_claim("good", 5), BASELINE_BYTES, &lineage(5));
    assert!(result.is_ok());
    assert!(event.admitted);
    assert_eq!(event.event, "counterfactual_policy_admitted");
    assert_eq!(event.outcome, "admitted");
    assert_eq!(event.expected_generation, 5);
    assert_eq!(event.actual_generation, 5);
}
